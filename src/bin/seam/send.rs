use anyhow::{Result, bail};
use clap::Args;
use indicatif::ProgressBar;
use seam_protocol::{
    api::Server,
    handshake::{IdentityKeypair, pk_to_bytes},
};
use std::path::PathBuf;

use crate::{
    copy::{collect_files, send_file},
    proto,
};

#[derive(Args)]
pub struct SendArgs {
    /// Source path (file or directory) to send
    pub src: PathBuf,
    /// UDP port to listen on (0 = OS-assigned)
    #[arg(long, default_value_t = 0)]
    pub port: u16,
    /// Exit after one transfer
    #[arg(long)]
    pub once: bool,
    /// Disable zstd compression (on by default)
    #[arg(long)]
    pub no_compress: bool,
}

pub async fn run(args: SendArgs) -> Result<()> {
    let compress = !args.no_compress;
    let src = &args.src;
    if !src.exists() {
        bail!("source not found: {}", src.display());
    }

    let id = IdentityKeypair::generate();
    let x25519_hex = hex::encode(id.x25519_public.as_bytes());
    let kem_hex = hex::encode(pk_to_bytes(&id.kem_pk));

    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher = seam_protocol::crypto::CipherSuite::parse(&cfg.cipher).unwrap_or_default();
    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;
    let mut server = Server::bind_with_cipher(addr, id, cipher)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let port = server.local_addr()?.port();

    println!("SEAM PORT={port} X25519={x25519_hex} KEM={kem_hex}");

    let mut conn = server
        .accept()
        .await
        .ok_or_else(|| anyhow::anyhow!("no connection"))?;

    let ctrl_sid = conn.open_stream().await;
    let mut buf = Vec::new();

    // Send HELLO
    let hello = [
        proto::HELLO,
        if compress {
            proto::COMPRESS_ZSTD
        } else {
            proto::COMPRESS_NONE
        },
    ];
    proto::send_frame(&conn, ctrl_sid, &hello).await?;

    let ack = proto::read_frame(&mut conn, ctrl_sid, &mut buf).await?;
    if ack.is_empty() || ack[0] != proto::ACK {
        bail!("expected ACK from receiver");
    }

    let files = collect_files(src)?;
    let total_bytes: u64 = files.iter().map(|(_, meta)| meta.len()).sum();

    let pb = ProgressBar::new(total_bytes);
    pb.set_style(
        indicatif::ProgressStyle::with_template(
            "{spinner:.cyan} {msg}\n  [{bar:40.green/dim}] {bytes}/{total_bytes} ({bytes_per_sec}, eta {eta})",
        )
        .unwrap()
        .progress_chars("█▉▊▋▌▍▎▏ "),
    );

    let send_start = std::time::Instant::now();
    for (rel_name, _meta) in &files {
        pb.set_message(format!("sending {rel_name}"));
        send_file(
            &mut conn, ctrl_sid, src, rel_name, compress, &pb, true, &mut buf, false,
        )
        .await?;
    }

    proto::send_frame(&conn, ctrl_sid, &[proto::DONE]).await?;
    conn.close().await;

    let send_secs = send_start.elapsed().as_secs_f64().max(0.001);
    let send_mib_s = (total_bytes as f64) / (1024.0 * 1024.0) / send_secs;
    pb.finish_with_message(format!(
        "done — {} file(s), {} MiB in {:.1}s ({:.1} MiB/s)",
        files.len(),
        total_bytes / (1024 * 1024),
        send_secs,
        send_mib_s,
    ));
    Ok(())
}
