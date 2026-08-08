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
        "  seam cp --direct \"SEAM PORT={local_port} X25519={x25519_hex} KEM={kem_hex} TOKEN={token}\" share:/{filename} ./"
    );
    eprintln!();
    eprintln!(
        "  Or with explicit address: seam cp {}:{}/{}  (if on same LAN)",
        my_ip, local_port, filename
    );
    eprintln!();

    // Set up expiry timer.
    let expire_handle: Option<tokio::task::JoinHandle<()>> = expire_secs.map(|secs| {
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(secs)).await;
        })
    });

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
            if let Err(e) = handle_share_conn(
                conn,
                &path,
                &token_check,
                compress,
                fips_mode,
                &rem,
                dl_allowed,
            )
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
    // The client speaks first (TOKEN), so it opens the stream; we wait for
    // it rather than opening our own — a locally-opened stream here would
    // be a completely different stream from the one the client is actually
    // writing to (stream IDs are independently allocated per role), so we'd
    // wait forever for a TOKEN frame that arrives on a stream we're not
    // watching. This was the reason `seam share` never worked at all,
    // token check aside — see connect::wait_for_stream's other callers
    // (recv.rs, ls.rs, mount.rs) for the same client-speaks-first pattern.
    let ctrl_sid = proto::wait_for_stream(&mut conn).await?;
    let mut buf = Vec::new();

    // Protocol: client must send a TOKEN frame first — this is the entire
    // access-control mechanism `seam share --times`/`--expire` promises, so
    // there is no "serve anyway for compatibility" fallback: anything other
    // than a valid, matching TOKEN frame is rejected outright.
    let frame = read_frame(&mut conn, ctrl_sid, &mut buf).await?;
    if frame.is_empty() || frame[0] != proto::TOKEN || frame.len() < 3 {
        bail!("expected TOKEN frame — rejected");
    }
    let token_len = u16::from_be_bytes([frame[1], frame[2]]) as usize;
    if frame.len() < 3 + token_len {
        bail!("token frame truncated");
    }
    let provided_token = std::str::from_utf8(&frame[3..3 + token_len])?;
    if !constant_time_eq(provided_token.as_bytes(), expected_token.as_bytes()) {
        bail!("invalid token — rejected");
    }

    // Decrement remaining before serving (reserve the slot).
    let prev = remaining.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
        if v > 0 { Some(v - 1) } else { None }
    });
    if prev.is_err() {
        bail!("no downloads remaining — closing connection");
    }

    let left = remaining.load(Ordering::SeqCst);
    eprintln!("  serving download ({} remaining)…", left);

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
            &mut conn, ctrl_sid, path, rel_name, compress, &pb, false, &mut buf, fips_mode, None,
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

/// Constant-time byte comparison — avoids leaking how many leading bytes of
/// the token matched via a timing side-channel (a plain `!=` short-circuits
/// on the first differing byte).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Parse human-readable duration string: "30s", "5m", "2h", "1d".
fn parse_duration(s: &str) -> Result<u64> {
    if let Some(n) = s.strip_suffix('s') {
        return n
            .parse::<u64>()
            .map_err(|_| anyhow!("invalid duration: {s}"));
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

#[cfg(test)]
mod tests {
    use super::*;
    use seam_protocol::api::{Client, Server};
    use seam_protocol::handshake::IdentityKeypair;

    async fn make_pair() -> (
        seam_protocol::api::SeamConn,
        seam_protocol::api::SeamConn,
    ) {
        let server_id = IdentityKeypair::generate();
        let server_x25519 = server_id.x25519_public.to_bytes();
        let server_kem_pk = server_id.kem_pk.clone();
        let mut server = Server::bind("127.0.0.1:0".parse().unwrap(), server_id)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();
        tokio::join!(
            async { server.accept().await.unwrap() },
            async {
                let client_id = IdentityKeypair::generate();
                let mut client = Client::bind("127.0.0.1:0".parse().unwrap(), client_id)
                    .await
                    .unwrap();
                client
                    .connect(
                        server_addr,
                        &server_x25519,
                        &server_kem_pk,
                        Default::default(),
                    )
                    .await
                    .unwrap()
            }
        )
    }

    async fn send_token(
        conn: &seam_protocol::api::SeamConn,
        sid: seam_protocol::session::stream::StreamId,
        token: &[u8],
    ) -> Result<()> {
        let mut frame = vec![proto::TOKEN];
        frame.extend_from_slice(&(token.len() as u16).to_be_bytes());
        frame.extend_from_slice(token);
        send_frame(conn, sid, &frame).await
    }

    /// End-to-end: a client that sends the correct TOKEN frame first gets
    /// served the real file content, checksum and all.
    #[tokio::test]
    async fn valid_token_allows_download() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("secret.txt"), b"top secret payload").unwrap();
        let path = dir.path().join("secret.txt");

        let (server_conn, mut client_conn) = make_pair().await;
        let remaining = AtomicUsize::new(1);

        let server_task = tokio::spawn(async move {
            handle_share_conn(server_conn, &path, "correct-token", false, false, &remaining, 1)
                .await
        });

        let sid = client_conn.open_stream().await;
        send_token(&client_conn, sid, b"correct-token").await.unwrap();

        let mut buf = Vec::new();
        let hello = read_frame(&mut client_conn, sid, &mut buf).await.unwrap();
        assert_eq!(hello[0], proto::HELLO);
        send_frame(&client_conn, sid, &[proto::ACK]).await.unwrap();

        let info = read_frame(&mut client_conn, sid, &mut buf).await.unwrap();
        assert_eq!(info[0], proto::FILE_INFO);
        let size = u64::from_be_bytes(info[1..9].try_into().unwrap());
        let mut received = Vec::new();
        while (received.len() as u64) < size {
            let d = read_frame(&mut client_conn, sid, &mut buf).await.unwrap();
            assert_eq!(d[0], proto::DATA);
            received.extend_from_slice(&d[1..]);
        }
        let cksum = read_frame(&mut client_conn, sid, &mut buf).await.unwrap();
        assert_eq!(cksum[0], proto::CHECKSUM);
        // send_file (server side) waits for this ACK before returning.
        send_frame(&client_conn, sid, &[proto::ACK]).await.unwrap();
        let done = read_frame(&mut client_conn, sid, &mut buf).await.unwrap();
        assert_eq!(done[0], proto::DONE);

        assert_eq!(received, b"top secret payload");
        server_task.await.unwrap().unwrap();
    }

    /// Regression test for the auth-bypass: a client that skips the TOKEN
    /// frame entirely (sending a plain HELLO first, as a normal `seam cp`
    /// client — or an attacker — would) must be rejected, not served
    /// "for compatibility".
    #[tokio::test]
    async fn missing_token_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("secret.txt"), b"top secret payload").unwrap();
        let path = dir.path().join("secret.txt");

        let (server_conn, client_conn) = make_pair().await;
        let remaining = AtomicUsize::new(1);

        let server_task = tokio::spawn(async move {
            handle_share_conn(server_conn, &path, "correct-token", false, false, &remaining, 1)
                .await
        });

        let sid = client_conn.open_stream().await;
        send_frame(&client_conn, sid, &[proto::HELLO, proto::COMPRESS_NONE])
            .await
            .unwrap();

        let result = server_task.await.unwrap();
        assert!(
            result.is_err(),
            "connection without a TOKEN frame must be rejected, not served"
        );
    }

    /// A syntactically valid TOKEN frame with the wrong token must also be
    /// rejected.
    #[tokio::test]
    async fn wrong_token_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("secret.txt"), b"top secret payload").unwrap();
        let path = dir.path().join("secret.txt");

        let (server_conn, client_conn) = make_pair().await;
        let remaining = AtomicUsize::new(1);

        let server_task = tokio::spawn(async move {
            handle_share_conn(server_conn, &path, "correct-token", false, false, &remaining, 1)
                .await
        });

        let sid = client_conn.open_stream().await;
        send_token(&client_conn, sid, b"wrong-token").await.unwrap();

        let result = server_task.await.unwrap();
        assert!(result.is_err(), "wrong token must be rejected");
    }

    #[test]
    fn constant_time_eq_matches_regular_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
    }
}
