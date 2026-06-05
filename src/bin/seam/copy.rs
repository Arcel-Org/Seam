use anyhow::{Result, bail};
use clap::Args;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};

use crate::{
    connect,
    proto::{self, read_frame, send_frame},
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
    /// Disable zstd compression (on by default, overrides config)
    #[arg(long)]
    pub no_compress: bool,
    /// Resume partial transfers (receiver tells sender existing file size)
    #[arg(long)]
    pub resume: bool,
    /// Skip SSH bootstrap; use this pre-started SEAM connection line directly.
    /// Format: "SEAM PORT=<n> X25519=<hex> KEM=<hex>"
    /// Useful for testing: start `seam recv /dest --port 0 --once` manually first.
    #[arg(long)]
    pub direct: Option<String>,
}

pub async fn run(args: CopyArgs) -> Result<()> {
    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let compress = if args.no_compress {
        false
    } else {
        cfg.compress
    };
    let cipher = seam_protocol::crypto::CipherSuite::parse(&cfg.cipher).unwrap_or_default();

    // ── Resolve direction and connection info ─────────────────────────────────

    let src_remote = ssh::parse_remote(&args.src);
    let dst_remote = ssh::parse_remote(&args.dest);

    let (is_pull, ready_line, host, dest_path, _ssh_child) = if let Some(direct) = args.direct {
        // --direct: caller already started the peer, just parse the line.
        let is_pull = src_remote.is_some();
        (
            is_pull,
            direct,
            "127.0.0.1".to_string(),
            PathBuf::from(&args.dest),
            None,
        )
    } else {
        match (src_remote, dst_remote) {
            (Some(_), Some(_)) => {
                bail!(
                    "both source and destination cannot be remote — use an intermediate local path"
                )
            }
            (Some((remote, src_path)), None) => {
                // Pull: remote sends, we receive.
                let dest = PathBuf::from(&args.dest);
                if dest.exists() && dest.is_file() {
                    bail!("destination must be a directory when pulling from remote");
                }
                let seam_bin = match remote.seam_path() {
                    Some(p) => p,
                    None => {
                        eprintln!("seam not found on {} — bootstrapping…", remote.target());
                        remote.bootstrap_copy_self()?
                    }
                };
                let subcmd = format!(
                    "_send {} --port 0 --once{}",
                    connect::shell_quote(&src_path),
                    if args.no_compress {
                        " --no-compress"
                    } else {
                        ""
                    }
                );
                eprintln!("starting sender on {}:{}", remote.target(), src_path);
                let (line, child) = remote.start_remote_seam(&seam_bin, &subcmd)?;
                let h = remote.host.clone();
                (true, line, h, dest, Some(child))
            }
            (None, Some((remote, remote_path))) => {
                // Push: we send, remote receives.
                let src = PathBuf::from(&args.src);
                if !src.exists() {
                    bail!("source not found: {}", args.src);
                }
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
                (false, line, h, PathBuf::from(remote_path), Some(child))
            }
            (None, None) => {
                bail!("at least one of source or destination must be remote (user@host:/path)")
            }
        }
    };

    // ── Parse SEAM line and connect ───────────────────────────────────────────

    let (port, x25519_bytes, kem_pk) = connect::parse_seam_line(&ready_line)?;

    eprintln!("connecting to {}:{}…", host, port);
    let mut conn = connect::dial(&host, port, x25519_bytes, kem_pk, cipher).await?;
    eprintln!("connected — post-quantum handshake complete");

    let ctrl_sid = conn.open_stream().await;
    let mut buf = Vec::new();

    if is_pull {
        // ── Pull protocol: remote sends HELLO, we ACK, then receive files ────
        let hello = read_frame(&mut conn, ctrl_sid, &mut buf).await?;
        if hello.is_empty() || hello[0] != proto::HELLO {
            bail!("expected HELLO from remote sender");
        }
        let compress = hello.len() > 1 && hello[1] == proto::COMPRESS_ZSTD;
        send_frame(&conn, ctrl_sid, &[proto::ACK]).await?;

        std::fs::create_dir_all(&dest_path)?;
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::with_template("{spinner:.cyan} {msg}  {bytes}").unwrap());

        loop {
            let frame = read_frame(&mut conn, ctrl_sid, &mut buf).await?;
            if frame.is_empty() {
                bail!("empty frame");
            }
            match frame[0] {
                proto::FILE_INFO => {
                    receive_file(
                        &mut conn,
                        ctrl_sid,
                        &frame,
                        &dest_path,
                        compress,
                        &mut buf,
                        &pb,
                        args.resume,
                    )
                    .await?;
                }
                proto::DONE => break,
                t => bail!("unexpected frame type 0x{:02x}", t),
            }
        }
        pb.finish_with_message(format!("done — received to {}", dest_path.display()));
    } else {
        // ── Push protocol: we send HELLO, wait for ACK, then send files ────────
        let src_path = PathBuf::from(&args.src);
        let hello = [
            proto::HELLO,
            if compress {
                proto::COMPRESS_ZSTD
            } else {
                proto::COMPRESS_NONE
            },
        ];
        send_frame(&conn, ctrl_sid, &hello).await?;

        let ack = read_frame(&mut conn, ctrl_sid, &mut buf).await?;
        if ack.is_empty() || ack[0] != proto::ACK {
            bail!("expected ACK from receiver");
        }

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
            send_file(
                &mut conn,
                ctrl_sid,
                &src_path,
                rel_name,
                compress,
                &pb,
                args.resume,
                &mut buf,
            )
            .await?;
        }

        send_frame(&conn, ctrl_sid, &[proto::DONE]).await?;
        pb.finish_with_message(format!(
            "done — {} file(s), {} bytes",
            files.len(),
            total_bytes
        ));
    }

    conn.close().await;
    Ok(())
}

pub fn collect_files(src: &Path) -> Result<Vec<(String, std::fs::Metadata)>> {
    let mut out = Vec::new();
    if src.is_file() {
        let name = src.file_name().unwrap().to_string_lossy().to_string();
        out.push((name, src.metadata()?));
    } else {
        for entry in walkdir::WalkDir::new(src)
            .into_iter()
            .filter_map(|e| e.ok())
        {
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

#[allow(clippy::too_many_arguments)]
pub async fn send_file(
    conn: &mut seam_protocol::api::SeamConn,
    ctrl_sid: seam_protocol::session::stream::StreamId,
    base: &Path,
    rel: &str,
    compress: bool,
    pb: &ProgressBar,
    resume: bool,
    buf: &mut Vec<u8>,
) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom};

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
    let mut sent: u64 = 0;

    // If resume is enabled, wait for the receiver to tell us where to start.
    if resume {
        let resp = read_frame(conn, ctrl_sid, buf).await?;
        if !resp.is_empty() && resp[0] == proto::RESUME && resp.len() >= 9 {
            let offset = u64::from_be_bytes(resp[1..9].try_into()?);
            if offset > 0 && offset < size {
                file.seek(SeekFrom::Start(offset))?;
                sent = offset;
                pb.inc(offset);
            }
        }
    }

    let mut chunk = vec![0u8; CHUNK];
    while sent < size {
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
        sent += n as u64;
        let _ = conn.tick().await;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn receive_file(
    conn: &mut seam_protocol::api::SeamConn,
    ctrl_sid: seam_protocol::session::stream::StreamId,
    info_frame: &[u8],
    dest: &Path,
    compress: bool,
    buf: &mut Vec<u8>,
    pb: &ProgressBar,
    resume: bool,
) -> Result<()> {
    use std::io::{Seek, SeekFrom, Write};

    if info_frame.len() < 11 {
        bail!("FILE_INFO too short");
    }
    let size = u64::from_be_bytes(info_frame[1..9].try_into()?);
    let name_len = u16::from_be_bytes(info_frame[9..11].try_into()?) as usize;
    if info_frame.len() < 11 + name_len {
        bail!("FILE_INFO name truncated");
    }
    let name = String::from_utf8(info_frame[11..11 + name_len].to_vec())?;

    // Reject path traversal and absolute paths.
    if name.contains("..") || std::path::Path::new(&name).is_absolute() {
        bail!("refusing dangerous filename: {name}");
    }

    let out_path = dest.join(&name);
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let existing = out_path.metadata().map(|m| m.len()).unwrap_or(0);
    let resume_from = if resume && existing > 0 && existing < size {
        let mut resume_frame = Vec::with_capacity(1 + 8);
        resume_frame.push(proto::RESUME);
        resume_frame.extend_from_slice(&existing.to_be_bytes());
        send_frame(conn, ctrl_sid, &resume_frame).await?;
        existing
    } else {
        0
    };

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(resume_from == 0)
        .open(&out_path)?;
    if resume_from > 0 {
        file.seek(SeekFrom::Start(resume_from))?;
    }

    pb.set_message(format!("receiving {name}"));

    let mut received: u64 = resume_from;
    while received < size {
        let data_frame = read_frame(conn, ctrl_sid, buf).await?;
        if data_frame.is_empty() || data_frame[0] != proto::DATA {
            bail!("expected DATA frame");
        }
        let raw = &data_frame[1..];
        let chunk_len = if compress {
            let decoded = zstd::decode_all(raw)?;
            let n = decoded.len() as u64;
            file.write_all(&decoded)?;
            received += n;
            n
        } else {
            let n = raw.len() as u64;
            file.write_all(raw)?;
            received += n;
            n
        };
        pb.inc(chunk_len);
        let _ = conn.tick().await;
    }
    eprintln!("received: {name} ({size} bytes)");
    Ok(())
}
