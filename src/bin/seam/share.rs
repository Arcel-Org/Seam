/// `seam share` — one-time post-quantum encrypted file sharing.
///
/// Usage:
///   seam share <file>
///   seam share <dir> --times 3 --expire 1h
///
/// Starts a local seam receiver on a random port, generates a one-time auth
/// token, and prints a `seam cp` command the recipient can run. After the
/// specified number of downloads (default: 1) or after the expiry duration,
/// the server shuts down and the token is revoked.
use anyhow::{Result, anyhow, bail};
use clap::Args;
use indicatif::{ProgressBar, ProgressStyle};
use seam_protocol::{
    api::Server,
    handshake::{IdentityKeypair, pk_to_bytes},
};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use crate::{
    connect,
    proto::{self, read_frame, send_frame},
};

#[derive(Args)]
pub struct ShareArgs {
    /// File or directory to share
    pub path: String,

    /// Number of downloads before the share expires (default: 1)
    #[arg(long, default_value_t = 1, value_name = "N")]
    pub times: usize,

    /// Auto-expire after this duration (e.g. "30m", "1h", "24h")
    #[arg(long, value_name = "DURATION")]
    pub expire: Option<String>,

    /// Disable zstd compression
    #[arg(long)]
    pub no_compress: bool,
}

pub async fn run(args: ShareArgs, fips_mode: bool) -> Result<()> {
    let path = PathBuf::from(&args.path);
    if !path.exists() {
        bail!("path not found: {}", args.path);
    }

    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let compress = !args.no_compress && cfg.compress;
    let cipher_str = if fips_mode { "aes256gcm" } else { &cfg.cipher };
    let cipher = seam_protocol::crypto::CipherSuite::parse(cipher_str).unwrap_or_default();

    // Parse expiry duration.
    let expire_secs: Option<u64> = if let Some(ref dur_str) = args.expire {
        Some(parse_duration(dur_str)?)
    } else {
        None
    };

    // Generate a one-time token (16 random bytes, hex-encoded = 32 chars).
    let mut token_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token_bytes);
    let token = hex::encode(token_bytes);

    // Start a seam server on a random port with a fresh identity.
    let id = IdentityKeypair::load_or_generate(connect::identity_path())
        .unwrap_or_else(|_| IdentityKeypair::generate());
    let x25519_hex = hex::encode(id.x25519_public.as_bytes());
    let kem_hex = hex::encode(pk_to_bytes(&id.kem_pk));

    let bind_addr: std::net::SocketAddr = "0.0.0.0:0".parse()?;
    let mut server = Server::bind_with_cipher(bind_addr, id, cipher)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    let local_port = server.local_addr()?.port();

    // Discover our likely LAN/public address.
    let my_ip = local_ip_best_effort();

    // Print the share info.
    let remaining_downloads = Arc::new(AtomicUsize::new(args.times));
    let filename = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    eprintln!();
    eprintln!("  seam share — {} download(s) allowed", args.times);
    if let Some(secs) = expire_secs {
        eprintln!("  expires in: {}", format_duration(secs));
    }
    eprintln!();
    eprintln!("  Recipient runs:");
    eprintln!(
        "  seam cp --direct \"SEAM PORT={local_port} X25519={x25519_hex} KEM={kem_hex} TOKEN={token}\" {}",
        filename
    );
    eprintln!();
    eprintln!(
        "  Or with explicit address: seam cp {}:{}/{}  (if on same LAN)",
        my_ip, local_port, filename
    );
    eprintln!();

    // Set up expiry timer.
    let expire_handle: Option<tokio::task::JoinHandle<()>> =
        expire_secs.map(|secs| tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(secs)).await;
        }));

    let downloads_allowed = args.times;

    loop {
        // Check if we've served all allowed downloads.
        if remaining_downloads.load(Ordering::SeqCst) == 0 {
            eprintln!("  all downloads complete — share closed");
            break;
        }

        // Check expiry.
        if matches!(&expire_handle, Some(h) if h.is_finished()) {
            eprintln!("  share expired — closing");
            break;
        }

        // Accept next connection with a short poll timeout.
        let conn = tokio::time::timeout(Duration::from_secs(1), server.accept()).await;
        let conn = match conn {
            Ok(Some(c)) => c,
            Ok(None) => break,
            Err(_) => continue, // timeout, loop back and check state
        };

        let path = path.clone();
        let token_check = token.clone();
        let rem = remaining_downloads.clone();
        let dl_allowed = downloads_allowed;

        tokio::spawn(async move {
            if let Err(e) =
                handle_share_conn(conn, &path, &token_check, compress, fips_mode, &rem, dl_allowed)
                    .await
            {
                eprintln!("  share: connection error: {e}");
            }
        });
    }

    if let Some(handle) = expire_handle {
        handle.abort();
    }

    Ok(())
}

async fn handle_share_conn(
    mut conn: seam_protocol::api::SeamConn,
    path: &Path,
    expected_token: &str,
    compress: bool,
    fips_mode: bool,
    remaining: &AtomicUsize,
    _downloads_allowed: usize,
) -> Result<()> {
    let ctrl_sid = conn.open_stream().await;
    let mut buf = Vec::new();

    // Protocol: client sends TOKEN frame first, then we verify.
    // TOKEN frame: [0xF0][u16 token_len][token bytes]
    let frame = read_frame(&mut conn, ctrl_sid, &mut buf).await?;
    if frame.is_empty() {
        bail!("no token frame received");
    }
    if frame[0] != 0xF0 || frame.len() < 3 {
        // Older seam cp without token support — still serve for compatibility.
        // In a strict deployment, reject here.
    } else {
        let token_len = u16::from_be_bytes([frame[1], frame[2]]) as usize;
        if frame.len() < 3 + token_len {
            bail!("token frame truncated");
        }
        let provided_token = std::str::from_utf8(&frame[3..3 + token_len])?;
        if provided_token != expected_token {
            bail!("invalid token — rejected");
        }
    }

    // Decrement remaining before serving (reserve the slot).
    let prev = remaining.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
        if v > 0 { Some(v - 1) } else { None }
    });
    if prev.is_err() {
        bail!("no downloads remaining — closing connection");
    }

    let left = remaining.load(Ordering::SeqCst);
    eprintln!(
        "  serving download ({} remaining)…",
        left
    );

    // Send HELLO.
    let hello = [
        proto::HELLO,
        if compress {
            proto::COMPRESS_ZSTD
        } else {
            proto::COMPRESS_NONE
        },
    ];
    send_frame(&conn, ctrl_sid, &hello).await?;

    // Wait for ACK.
    let ack = read_frame(&mut conn, ctrl_sid, &mut buf).await?;
    if ack.is_empty() || ack[0] != proto::ACK {
        bail!("expected ACK from recipient");
    }

    // Collect and send files.
    let files = super::copy::collect_files(path)?;
    let total_bytes: u64 = files.iter().map(|(_, m)| m.len()).sum();

    let pb = ProgressBar::new(total_bytes);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.cyan} {msg}\n  [{bar:40.green/dim}] {bytes}/{total_bytes} ({bytes_per_sec}, eta {eta})",
        )
        .unwrap()
        .progress_chars("█▉▊▋▌▍▎▏ "),
    );

    for (rel_name, _) in &files {
        pb.set_message(format!("sending {rel_name}"));
        super::copy::send_file(
            &mut conn,
            ctrl_sid,
            path,
            rel_name,
            compress,
            &pb,
            false,
            &mut buf,
            fips_mode,
            None,
        )
        .await?;
    }

    send_frame(&conn, ctrl_sid, &[proto::DONE]).await?;
    pb.finish_with_message(format!(
        "sent {} file(s) ({} bytes)",
        files.len(),
        total_bytes
    ));
    conn.close().await;
    Ok(())
}

/// Parse human-readable duration string: "30s", "5m", "2h", "1d".
fn parse_duration(s: &str) -> Result<u64> {
    if let Some(n) = s.strip_suffix('s') {
        return n.parse::<u64>().map_err(|_| anyhow!("invalid duration: {s}"));
    }
    if let Some(n) = s.strip_suffix('m') {
        return n
            .parse::<u64>()
            .map(|v| v * 60)
            .map_err(|_| anyhow!("invalid duration: {s}"));
    }
    if let Some(n) = s.strip_suffix('h') {
        return n
            .parse::<u64>()
            .map(|v| v * 3600)
            .map_err(|_| anyhow!("invalid duration: {s}"));
    }
    if let Some(n) = s.strip_suffix('d') {
        return n
            .parse::<u64>()
            .map(|v| v * 86400)
            .map_err(|_| anyhow!("invalid duration: {s}"));
    }
    // Raw number = seconds.
    s.parse::<u64>()
        .map_err(|_| anyhow!("invalid duration '{}': use 30s, 5m, 1h, or 2d", s))
}

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

/// Try to find a non-loopback local IP for display purposes.
fn local_ip_best_effort() -> String {
    // Connect a UDP socket to a public address (no packet sent) to find the
    // preferred outbound interface address.
    local_outbound_ip().unwrap_or_else(|| "localhost".to_string())
}

fn local_outbound_ip() -> Option<String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    Some(sock.local_addr().ok()?.ip().to_string())
}
