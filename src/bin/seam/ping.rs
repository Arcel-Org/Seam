use anyhow::{Result, anyhow};
use clap::Args;
use seam_protocol::{
    api::Server,
    handshake::{IdentityKeypair, pk_to_bytes},
    tunnel::SeamMux,
};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{connect, ssh};

#[derive(Args)]
pub struct PingArgs {
    /// Remote target: user@host
    pub remote: String,
    /// SSH port
    #[arg(short = 'p', long)]
    pub port: Option<u16>,
    /// Number of pings to send (0 = continuous until Ctrl-C)
    #[arg(short = 'n', long, default_value_t = 5)]
    pub count: u32,
    /// Interval between pings in milliseconds
    #[arg(short = 'i', long, default_value_t = 1000)]
    pub interval: u64,
}

#[derive(Args)]
pub struct PingRecvArgs {
    #[arg(long, default_value_t = 0)]
    pub port: u16,
}

/// Shared ping statistics used by the Ctrl-C handler for continuous mode.
#[derive(Default)]
struct PingStats {
    rtts: Vec<f64>,
    lost: u32,
    sent: u32,
}

fn print_summary(remote: &str, stats: &PingStats) {
    let sent = stats.sent;
    let received = stats.rtts.len() as u32;
    let lost = stats.lost;
    eprintln!();
    eprintln!("--- {remote} ping statistics ---");
    eprintln!(
        "{sent} sent, {received} received, {lost} lost ({:.0}% loss)",
        if sent > 0 { (lost as f64 / sent as f64) * 100.0 } else { 0.0 }
    );
    if !stats.rtts.is_empty() {
        let min = stats.rtts.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = stats.rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let avg = stats.rtts.iter().sum::<f64>() / stats.rtts.len() as f64;
        let variance = stats.rtts.iter().map(|r| (r - avg).powi(2)).sum::<f64>()
            / stats.rtts.len() as f64;
        let stddev = variance.sqrt();
        eprintln!("rtt min/avg/max/stddev = {min:.2}/{avg:.2}/{max:.2}/{stddev:.2} ms");
    }
}

pub async fn run(args: PingArgs) -> Result<()> {
    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher = seam_protocol::crypto::CipherSuite::parse(&cfg.cipher).unwrap_or_default();

    let (user, host) = ssh::parse_userhost(&args.remote);
    let remote = ssh::RemoteInfo { host: host.clone(), user, ssh_port: args.port };
    let (conn, _child) = connect::bootstrap_and_connect(&remote, &host, "_ping-recv --port 0", cipher).await?;
    let mux = SeamMux::new(conn);

    let count = args.count;
    let interval_ms = args.interval;
    let continuous = count == 0;

    // Shared stats — written by the ping loop, read by the Ctrl-C handler.
    let stats = Arc::new(Mutex::new(PingStats::default()));

    // Install Ctrl-C handler in continuous mode: print statistics and exit.
    if continuous {
        let stats_ctrlc = Arc::clone(&stats);
        let remote_name = args.remote.clone();
        ctrlc::set_handler(move || {
            let s = stats_ctrlc.lock().unwrap();
            print_summary(&remote_name, &s);
            std::process::exit(0);
        })?;
    }

    eprintln!("PING {} over Seam (post-quantum UDP){}", args.remote,
        if continuous { " — continuous, Ctrl-C for statistics" } else { "" });

    let mut seq: u32 = 0;
    loop {
        let t0 = std::time::Instant::now();
        let mut stream = mux.open_stream().await;

        // Write 4-byte payload: seq
        let payload = seq.to_be_bytes();
        if stream.write_all(&payload).await.is_err() {
            eprintln!("seq={seq} send failed");
            let mut s = stats.lock().unwrap();
            s.lost += 1;
            s.sent += 1;
        } else {
            let mut reply = [0u8; 4];
            let read_result = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                stream.read_exact(&mut reply),
            ).await;
            let rtt = t0.elapsed().as_secs_f64() * 1000.0;
            let mut s = stats.lock().unwrap();
            s.sent += 1;
            match read_result {
                Ok(Ok(_)) if reply == payload => {
                    eprintln!("seq={seq} rtt={rtt:.2}ms");
                    s.rtts.push(rtt);
                }
                Ok(Ok(_)) => {
                    eprintln!("seq={seq} reply mismatch");
                    s.lost += 1;
                }
                _ => {
                    eprintln!("seq={seq} timeout");
                    s.lost += 1;
                }
            }
        }
        drop(stream);

        seq += 1;
        if count > 0 && seq >= count { break; }
        if interval_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;
        }
    }

    // Print summary for finite-count mode (continuous mode exits via Ctrl-C handler).
    let s = stats.lock().unwrap();
    print_summary(&args.remote, &s);
    Ok(())
}

pub async fn run_recv(args: PingRecvArgs) -> Result<()> {
    let id = IdentityKeypair::generate();
    let x25519_hex = hex::encode(id.x25519_public.as_bytes());
    let kem_hex = hex::encode(pk_to_bytes(&id.kem_pk));

    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher = seam_protocol::crypto::CipherSuite::parse(&cfg.cipher).unwrap_or_default();
    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;
    let mut server = Server::bind_with_cipher(addr, id, cipher).await.map_err(|e| anyhow!("{e}"))?;
    let udp_port = server.local_addr()?.port();

    println!("SEAM PORT={udp_port} X25519={x25519_hex} KEM={kem_hex}");

    let conn = server.accept().await.ok_or_else(|| anyhow!("no connection"))?;
    let mux = SeamMux::new(conn);

    // Accept ping streams and echo back
    loop {
        let Some(mut stream) = mux.accept_stream().await else { break };
        tokio::spawn(async move {
            let mut buf = [0u8; 4];
            if stream.read_exact(&mut buf).await.is_ok() {
                let _ = stream.write_all(&buf).await;
            }
        });
    }
    Ok(())
}
