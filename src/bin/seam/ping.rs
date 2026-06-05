use anyhow::{Result, anyhow};
use clap::Args;
use seam_protocol::{
    api::Server,
    handshake::{IdentityKeypair, pk_to_bytes},
    tunnel::SeamMux,
};
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

pub async fn run(args: PingArgs) -> Result<()> {
    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher = seam_protocol::crypto::CipherSuite::parse(&cfg.cipher).unwrap_or_default();

    let (user, host) = ssh::parse_userhost(&args.remote);
    let remote = ssh::RemoteInfo { host: host.clone(), user, ssh_port: args.port };
    let (conn, _child) = connect::bootstrap_and_connect(&remote, &host, "_ping-recv --port 0", cipher).await?;
    let mux = SeamMux::new(conn);

    let count = args.count;
    let interval_ms = args.interval;
    let mut seq: u32 = 0;
    let mut rtts: Vec<f64> = Vec::new();
    let mut lost: u32 = 0;

    eprintln!("PING {} over Seam (post-quantum UDP)", args.remote);

    loop {
        let t0 = std::time::Instant::now();
        let mut stream = mux.open_stream().await;

        // Write 4-byte payload: seq
        let payload = seq.to_be_bytes();
        if stream.write_all(&payload).await.is_err() {
            eprintln!("seq={seq} send failed");
            lost += 1;
        } else {
            let mut reply = [0u8; 4];
            let read_result = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                stream.read_exact(&mut reply),
            ).await;
            let rtt = t0.elapsed().as_secs_f64() * 1000.0;
            match read_result {
                Ok(Ok(_)) if reply == payload => {
                    eprintln!("seq={seq} rtt={rtt:.2}ms");
                    rtts.push(rtt);
                }
                Ok(Ok(_)) => {
                    eprintln!("seq={seq} reply mismatch");
                    lost += 1;
                }
                _ => {
                    eprintln!("seq={seq} timeout");
                    lost += 1;
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

    // Summary
    let sent = seq;
    let received = rtts.len() as u32;
    eprintln!();
    eprintln!("--- {} ping statistics ---", args.remote);
    eprintln!("{sent} sent, {received} received, {lost} lost ({:.0}% loss)",
        if sent > 0 { (lost as f64 / sent as f64) * 100.0 } else { 0.0 });
    if !rtts.is_empty() {
        let min = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
        let variance = rtts.iter().map(|r| (r - avg).powi(2)).sum::<f64>() / rtts.len() as f64;
        let stddev = variance.sqrt();
        eprintln!("rtt min/avg/max/stddev = {min:.2}/{avg:.2}/{max:.2}/{stddev:.2} ms");
    }
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
