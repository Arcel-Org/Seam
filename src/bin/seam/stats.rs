use anyhow::{Result, anyhow};
use clap::Args;
use seam_protocol::{
    api::Server,
    handshake::{IdentityKeypair, pk_to_bytes},
    tunnel::SeamMux,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{connect, ssh};

// ── Client args ───────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct StatsArgs {
    /// Remote target: user@host
    pub remote: String,
    /// SSH port for the bootstrap connection
    #[arg(short = 'p', long)]
    pub port: Option<u16>,
    /// Measurement duration in seconds
    #[arg(long, default_value_t = 5)]
    pub duration: u64,
    /// Skip SSH bootstrap; use this pre-started SEAM line directly.
    #[arg(long)]
    pub direct: Option<String>,
}

// ── Server args ───────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct StatsRecvArgs {
    /// UDP port to listen on (0 = OS-assigned)
    #[arg(long, default_value_t = 0)]
    pub port: u16,
}

// ── Snapshot taken before the measurement ────────────────────────────────────

struct PreSnapshot {
    srtt: std::time::Duration,
    path_mtu: usize,
    cwnd_bytes: u64,
}

// Simple protocol byte written by the client to signal which direction a stream carries.
const DIR_DOWNLOAD: u8 = 0x01; // server → client
const DIR_UPLOAD: u8 = 0x02; // client → server

// ── Client ────────────────────────────────────────────────────────────────────

pub async fn run(args: StatsArgs) -> Result<()> {
    let remote_label = args.remote.clone();
    let duration_secs = args.duration;
    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher = seam_protocol::crypto::CipherSuite::parse(&cfg.cipher).unwrap_or_default();

    let (conn, _child) = if let Some(direct) = args.direct {
        let (port, x25519, kem_pk) = connect::parse_seam_line(&direct)?;
        let conn = connect::dial("127.0.0.1", port, x25519, kem_pk, cipher).await?;
        (conn, None)
    } else {
        let (user, host) = ssh::parse_userhost(&args.remote);
        let remote = ssh::RemoteInfo {
            host: host.clone(),
            user,
            ssh_port: args.port,
        };
        let subcmd = "_stats-recv --port 0".to_string();
        let (conn, child) = connect::bootstrap_and_connect(&remote, &host, &subcmd, cipher).await?;
        (conn, Some(child))
    };

    // Snapshot connection state before the measurement window.
    let (srtt, path_mtu, cwnd_bytes) = conn.connection_metrics().await;
    let pre = PreSnapshot {
        srtt,
        path_mtu,
        cwnd_bytes,
    };

    let mux = SeamMux::new(conn);

    // Open two streams: one for download (server→client) and one for upload (client→server).
    let mut dl_stream = mux.open_stream().await;
    let mut ul_stream = mux.open_stream().await;

    // Tell the server which direction each stream carries.
    dl_stream.write_all(&[DIR_DOWNLOAD]).await?;
    ul_stream.write_all(&[DIR_UPLOAD]).await?;

    eprint!("\nmeasuring connection to {remote_label} for {duration_secs}s  ");

    let start = std::time::Instant::now();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(duration_secs);

    let ul_buf = vec![0u8; 64 * 1024];
    let mut bytes_recv: u64 = 0;
    let mut bytes_sent: u64 = 0;
    let mut dl_buf = vec![0u8; 32 * 1024];
    let mut dl_done = false;
    let mut ul_done = false;

    loop {
        if dl_done && ul_done {
            break;
        }
        tokio::select! {
            result = dl_stream.read(&mut dl_buf), if !dl_done => {
                match result {
                    Ok(0) | Err(_) => dl_done = true,
                    Ok(n) => bytes_recv += n as u64,
                }
            }
            result = ul_stream.write_all(&ul_buf), if !ul_done => {
                match result {
                    Ok(()) => bytes_sent += ul_buf.len() as u64,
                    Err(_) => ul_done = true,
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                break;
            }
        }
    }
    let elapsed = start.elapsed();
    eprintln!();

    print_stats(&remote_label, &pre, bytes_recv, bytes_sent, elapsed);
    Ok(())
}

fn print_stats(
    remote: &str,
    pre: &PreSnapshot,
    bytes_recv: u64,
    bytes_sent: u64,
    elapsed: std::time::Duration,
) {
    let secs = elapsed.as_secs_f64().max(0.001);
    let dl_mib = (bytes_recv as f64) / (1024.0 * 1024.0) / secs;
    let ul_mib = (bytes_sent as f64) / (1024.0 * 1024.0) / secs;
    let rtt_ms = pre.srtt.as_secs_f64() * 1000.0;
    let cwnd_kib = pre.cwnd_bytes / 1024;

    eprintln!();
    eprintln!("  {}", "─".repeat(52));
    eprintln!("  Connection statistics: {remote}");
    eprintln!("  {}", "─".repeat(52));
    eprintln!("  {:<28} {:.1} ms", "Smoothed RTT:", rtt_ms);
    eprintln!(
        "  {:<28} {:.1} MiB/s  ({} MiB in {:.1}s)",
        "Download (recv):",
        dl_mib,
        bytes_recv / (1024 * 1024),
        secs,
    );
    eprintln!(
        "  {:<28} {:.1} MiB/s  ({} MiB in {:.1}s)",
        "Upload (sent):",
        ul_mib,
        bytes_sent / (1024 * 1024),
        secs,
    );
    eprintln!("  {:<28} {} bytes", "Path MTU:", pre.path_mtu);
    eprintln!("  {:<28} {} KiB", "cwnd:", cwnd_kib);
    eprintln!("  {}", "─".repeat(52));
    eprintln!();
}

// ── Server ────────────────────────────────────────────────────────────────────

pub async fn run_recv(args: StatsRecvArgs) -> Result<()> {
    let id = IdentityKeypair::generate();
    let x25519_hex = hex::encode(id.x25519_public.as_bytes());
    let kem_hex = hex::encode(pk_to_bytes(&id.kem_pk));

    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher = seam_protocol::crypto::CipherSuite::parse(&cfg.cipher).unwrap_or_default();
    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;
    let mut server = Server::bind_with_cipher(addr, id, cipher)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    let port = server.local_addr()?.port();

    println!("SEAM PORT={port} X25519={x25519_hex} KEM={kem_hex}");

    let conn = server
        .accept()
        .await
        .ok_or_else(|| anyhow!("no connection"))?;
    let mux = SeamMux::new(conn);

    // Accept both streams the client opens (download + upload direction bytes).
    // Each stream starts with one direction byte.
    for _ in 0..2 {
        let mux = mux.clone();
        tokio::spawn(async move {
            let Some(mut stream) = mux.accept_stream().await else {
                return;
            };
            let mut dir = [0u8; 1];
            if stream.read_exact(&mut dir).await.is_err() {
                return;
            }
            match dir[0] {
                DIR_DOWNLOAD => {
                    // Server→client: saturate the stream with zeros.
                    let buf = vec![0u8; 64 * 1024];
                    loop {
                        if stream.write_all(&buf).await.is_err() {
                            break;
                        }
                    }
                }
                DIR_UPLOAD => {
                    // Client→server: drain and discard.
                    let mut sink = vec![0u8; 64 * 1024];
                    while stream.read(&mut sink).await.map(|n| n > 0).unwrap_or(false) {}
                }
                _ => {}
            }
        });
    }

    // Keep the mux alive until both spawns finish (connection drop signals shutdown).
    tokio::time::sleep(std::time::Duration::from_secs(300)).await;
    Ok(())
}
