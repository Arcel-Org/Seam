use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use clap::Args;
use indicatif::{ProgressBar, ProgressStyle};
use seam_protocol::{
    api::Client,
    handshake::{IdentityKeypair, pk_from_bytes},
};

use crate::{
    proto::{self, read_frame, send_frame, COMPRESS_NONE, COMPRESS_ZSTD},
    ssh,
};

const CHUNK: usize = 32 * 1024;
const ZSTD_LEVEL: i32 = 3;

#[derive(Args)]
pub struct CopyArgs {
    /// Source path (local file or directory)
    pub src: String,
    /// Destination — remote: `user@host:/path`, or local `/path` when --direct is set
    pub dest: String,
    /// Disable zstd compression (on by default)
    #[arg(long)]
    pub no_compress: bool,
    /// Skip SSH bootstrap; use this pre-started SEAM connection line directly.
    /// Format: "SEAM PORT=<n> X25519=<hex> KEM=<hex>"
    /// Useful for testing: start `seam recv /dest --port 0 --once` manually first.
    #[arg(long)]
    pub direct: Option<String>,
}

pub async fn run(args: CopyArgs) -> Result<()> {
    let compress = !args.no_compress;

    let src_path = PathBuf::from(&args.src);
    if !src_path.exists() {
        bail!("source not found: {}", args.src);
    }

    // ── Resolve connection info ───────────────────────────────────────────────

    // `_ssh_child` keeps the SSH session alive for the duration of the transfer.
    // Dropping it would kill the SSH tunnel and the remote receiver.
    let (ready_line, host, _ssh_child) = if let Some(direct) = args.direct {
        // --direct: caller already started the receiver, just parse the line.
        (direct, "127.0.0.1".to_string(), None)
    } else {
        if ssh::parse_remote(&args.src).is_some() {
            bail!("remote source not yet supported — use: seam cp /local user@host:/remote");
        }
        let (remote, remote_path) = ssh::parse_remote(&args.dest)
            .ok_or_else(|| anyhow::anyhow!("DEST must be remote (user@host:/path) or use --direct"))?;

        let seam_bin = match remote.seam_path() {
            Some(p) => p,
            None => {
                eprintln!("seam not found on {} — bootstrapping…", remote.target());
                remote.bootstrap_copy_self()?
            }
        };

        eprintln!("starting receiver on {}:{}", remote.target(), remote_path);
        let (line, child) = remote.start_receiver(&seam_bin, &remote_path)?;
        let h = remote.host.clone();
        (line, h, Some(child))
    };

    // ── Parse SEAM line ───────────────────────────────────────────────────────

    let (port, x25519_bytes, kem_pk) = parse_ready(&ready_line)?;

    let server_addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .context("invalid server address")?;

    // ── Connect via Seam (post-quantum UDP handshake) ─────────────────────────

    let id = IdentityKeypair::generate();
    let mut client = Client::bind("0.0.0.0:0".parse()?, id)
        .await
        .map_err(|e| anyhow::anyhow!("bind: {e}"))?;

    eprintln!("connecting to {}…", server_addr);
    let mut conn = client
        .connect(server_addr, &x25519_bytes, &kem_pk)
        .await
        .map_err(|e| anyhow::anyhow!("connect: {e}"))?;
    eprintln!("connected — post-quantum handshake complete");

    // ── Protocol ──────────────────────────────────────────────────────────────

    let ctrl_sid = conn.open_stream().await;

    // HELLO
    let hello = [proto::HELLO, if compress { COMPRESS_ZSTD } else { COMPRESS_NONE }];
    send_frame(&conn, ctrl_sid, &hello).await?;

    // Wait for ACK
    let mut buf = Vec::new();
    let ack = read_frame(&mut conn, ctrl_sid, &mut buf).await?;
    if ack.is_empty() || ack[0] != proto::ACK {
        bail!("expected ACK from receiver");
    }

    // ── Send files ────────────────────────────────────────────────────────────

    let files = collect_files(&src_path)?;
    let total_bytes: u64 = files.iter().map(|(_, meta)| meta.len()).sum();

    let pb = ProgressBar::new(total_bytes);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.cyan} {msg}\n  [{bar:40.green/dim}] {bytes}/{total_bytes} ({bytes_per_sec}, eta {eta})",
        )
        .unwrap()
        .progress_chars("█▉▊▋▌▍▎▏ "),
    );

    for (rel_name, _meta) in &files {
        pb.set_message(format!("sending {rel_name}"));
        send_file(&conn, ctrl_sid, &src_path, rel_name, compress, &pb).await?;
    }

    send_frame(&conn, ctrl_sid, &[proto::DONE]).await?;
    conn.close().await;

    pb.finish_with_message(format!(
        "done — {} file(s), {} bytes",
        files.len(),
        total_bytes
    ));
    Ok(())
}

fn collect_files(src: &Path) -> Result<Vec<(String, std::fs::Metadata)>> {
    let mut out = Vec::new();
    if src.is_file() {
        let name = src.file_name().unwrap().to_string_lossy().to_string();
        out.push((name, src.metadata()?));
    } else {
        for entry in walkdir::WalkDir::new(src).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let rel = entry
                    .path()
                    .strip_prefix(src)
                    .unwrap()
                    .to_string_lossy()
                    .to_string();
                out.push((rel, entry.metadata()?));
            }
        }
    }
    Ok(out)
}

async fn send_file(
    conn: &seam_protocol::api::SeamConn,
    ctrl_sid: seam_protocol::session::stream::StreamId,
    base: &Path,
    rel: &str,
    compress: bool,
    pb: &ProgressBar,
) -> Result<()> {
    use std::io::Read;

    let path = if base.is_file() {
        base.to_path_buf()
    } else {
        base.join(rel)
    };
    let size = path.metadata()?.len();

    // FILE_INFO: [type][u64 size][u16 name_len][name bytes][u32 mode]
    let name_bytes = rel.as_bytes();
    let mut info = Vec::with_capacity(1 + 8 + 2 + name_bytes.len() + 4);
    info.push(proto::FILE_INFO);
    info.extend_from_slice(&size.to_be_bytes());
    info.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    info.extend_from_slice(name_bytes);
    info.extend_from_slice(&0u32.to_be_bytes());
    send_frame(conn, ctrl_sid, &info).await?;

    let mut file = std::fs::File::open(&path)?;
    let mut chunk = vec![0u8; CHUNK];
    loop {
        let n = file.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        let raw = &chunk[..n];
        let payload = if compress {
            zstd::encode_all(raw, ZSTD_LEVEL)?
        } else {
            raw.to_vec()
        };
        let mut frame = Vec::with_capacity(1 + payload.len());
        frame.push(proto::DATA);
        frame.extend_from_slice(&payload);
        send_frame(conn, ctrl_sid, &frame).await?;
        pb.inc(n as u64);
        // Brief pause to pace sending at ~10 MB/s so the receiver's kernel
        // UDP buffer doesn't overflow. TODO: remove once CC on_ack() is wired.
        let delay_us = (frame.len() as u64 * 100) / 1024; // ~10 MB/s
        tokio::time::sleep(tokio::time::Duration::from_micros(delay_us)).await;
        // Drive retransmits and flush pending ACKs for received packets.
        let _ = conn.tick().await;
    }
    Ok(())
}

fn parse_ready(
    line: &str,
) -> Result<(u16, [u8; 32], pqcrypto_kyber::kyber768::PublicKey)> {
    let mut port = None;
    let mut x25519 = None;
    let mut kem = None;

    for part in line.split_whitespace().skip(1) {
        if let Some(v) = part.strip_prefix("PORT=") {
            port = Some(v.parse::<u16>().context("bad PORT")?);
        } else if let Some(v) = part.strip_prefix("X25519=") {
            let bytes = hex::decode(v).context("bad X25519 hex")?;
            x25519 = Some(
                bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("X25519 must be 32 bytes"))?,
            );
        } else if let Some(v) = part.strip_prefix("KEM=") {
            let bytes = hex::decode(v).context("bad KEM hex")?;
            kem = Some(
                pk_from_bytes(&bytes)
                    .ok_or_else(|| anyhow::anyhow!("invalid KEM public key"))?,
            );
        }
    }

    Ok((
        port.ok_or_else(|| anyhow::anyhow!("missing PORT in SEAM line"))?,
        x25519.ok_or_else(|| anyhow::anyhow!("missing X25519 in SEAM line"))?,
        kem.ok_or_else(|| anyhow::anyhow!("missing KEM in SEAM line"))?,
    ))
}
