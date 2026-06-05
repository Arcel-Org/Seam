use anyhow::{Result, bail};
use clap::Args;
use seam_protocol::{
    api::{SeamConn, Server},
    handshake::{IdentityKeypair, pk_to_bytes},
    session::stream::StreamId,
};
use std::path::PathBuf;

use crate::proto::{self, read_frame, send_frame, wait_for_stream};

#[derive(Args)]
pub struct RecvArgs {
    /// Destination directory for received files
    pub dest: PathBuf,
    /// UDP port to listen on (0 = OS-assigned)
    #[arg(long, default_value_t = 0)]
    pub port: u16,
    /// Exit after one transfer
    #[arg(long)]
    pub once: bool,
}

pub async fn run(args: RecvArgs) -> Result<()> {
    let id = IdentityKeypair::generate();
    let x25519_hex = hex::encode(id.x25519_public.as_bytes());
    let kem_hex = hex::encode(pk_to_bytes(&id.kem_pk));

    let cfg = super::config::Config::load().ok().unwrap_or_default();
    // Check FIPS mode from env/config (CLI flag is inherited via global flag)
    let fips_mode = super::config::Config::effective_fips_mode(cfg.fips_mode, false);
    let cipher_str = if fips_mode { "aes256gcm" } else { &cfg.cipher };
    let cipher = seam_protocol::crypto::CipherSuite::parse(cipher_str).unwrap_or_default();
    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;
    let mut server = Server::bind_with_cipher(addr, id, cipher)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let port = server.local_addr()?.port();

    // Sender reads this line over SSH to get connection info.
    println!("SEAM PORT={port} X25519={x25519_hex} KEM={kem_hex}");

    let mut conn = server
        .accept()
        .await
        .ok_or_else(|| anyhow::anyhow!("no connection"))?;

    std::fs::create_dir_all(&args.dest)?;
    receive_transfer(&mut conn, &args.dest, fips_mode).await?;
    conn.close().await;
    Ok(())
}

async fn receive_transfer(
    conn: &mut SeamConn,
    dest: &std::path::Path,
    fips_mode: bool,
) -> Result<()> {
    let mut buf: Vec<u8> = Vec::new();

    let ctrl_sid = wait_for_stream(conn).await?;
    // Flush ACKs queued during stream-open handshake.
    let _ = conn.tick().await;

    // HELLO
    let hello = read_frame(conn, ctrl_sid, &mut buf).await?;
    let _ = conn.tick().await;
    if hello.is_empty() || hello[0] != proto::HELLO {
        bail!(
            "expected HELLO, got {:02x}",
            hello.first().copied().unwrap_or(0)
        );
    }
    let compress = hello.len() > 1 && hello[1] == proto::COMPRESS_ZSTD;

    // ACK — send_frame calls flush(), so ACKs go out here too.
    send_frame(conn, ctrl_sid, &[proto::ACK]).await?;

    // File receive loop
    loop {
        let frame = read_frame(conn, ctrl_sid, &mut buf).await?;
        // Flush ACKs for all packets received while assembling this frame.
        let _ = conn.tick().await;

        if frame.is_empty() {
            bail!("empty frame");
        }
        match frame[0] {
            proto::FILE_INFO => {
                receive_file(conn, ctrl_sid, &frame, dest, compress, &mut buf, fips_mode).await?;
            }
            proto::DONE => break,
            t => bail!("unexpected frame type 0x{:02x}", t),
        }
    }
    Ok(())
}

async fn receive_file(
    conn: &mut SeamConn,
    ctrl_sid: StreamId,
    info_frame: &[u8],
    dest: &std::path::Path,
    compress: bool,
    buf: &mut Vec<u8>,
    fips_mode: bool,
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

    // ── Partial-file resume using .seam-partial staging ──────────────────────
    // We write to `<name>.seam-partial` during transfer and atomically rename
    // to the final name on successful checksum verification. This ensures:
    //   1. The output file is never left in a partial/corrupt state.
    //   2. If a previous transfer was interrupted, we resume from the partial.
    //   3. On checksum mismatch we delete the partial and signal the sender.
    let partial_path = {
        let mut p = out_path.clone();
        let mut fname = p.file_name().unwrap_or_default().to_owned();
        fname.push(".seam-partial");
        p.set_file_name(fname);
        p
    };

    // Check whether a compatible partial exists for resuming.
    let partial_size = partial_path.metadata().map(|m| m.len()).unwrap_or(0);
    let resume_from = if partial_size > 0 && partial_size < size {
        eprintln!("  resuming {name}: found {partial_size} of {size} bytes in partial file");
        let mut resume_frame = Vec::with_capacity(1 + 8);
        resume_frame.push(proto::RESUME);
        resume_frame.extend_from_slice(&partial_size.to_be_bytes());
        send_frame(conn, ctrl_sid, &resume_frame).await?;
        partial_size
    } else {
        // No usable partial — sender will send from byte 0.
        if partial_path.exists() {
            // Stale or complete-but-unfinished partial — remove it.
            let _ = std::fs::remove_file(&partial_path);
        }
        0
    };

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(resume_from == 0)
        .open(&partial_path)?;
    if resume_from > 0 {
        file.seek(SeekFrom::Start(resume_from))?;
    }

    use crate::copy::IncrementalHasher;
    let mut hasher = IncrementalHasher::new(fips_mode);
    let algo_name = if fips_mode { "SHA-256" } else { "BLAKE3" };
    let mut received: u64 = resume_from;
    while received < size {
        let data_frame = read_frame(conn, ctrl_sid, buf).await?;
        let _ = conn.tick().await;

        if data_frame.is_empty() || data_frame[0] != proto::DATA {
            bail!("expected DATA frame");
        }
        let raw = &data_frame[1..];
        if compress {
            let decoded = zstd::decode_all(raw)?;
            hasher.update(&decoded);
            file.write_all(&decoded)?;
            received += decoded.len() as u64;
        } else {
            hasher.update(raw);
            file.write_all(raw)?;
            received += raw.len() as u64;
        }
    }
    // Flush and sync before verifying integrity.
    file.flush()?;
    drop(file);

    // Verify checksum sent by the sender (SHA-256 in FIPS mode, BLAKE3 otherwise).
    let cksum_frame = read_frame(conn, ctrl_sid, buf).await?;
    if cksum_frame.len() == 33 && cksum_frame[0] == proto::CHECKSUM {
        let expected = &cksum_frame[1..33];
        let actual = hasher.finalize();
        if actual == expected {
            // ── Atomic promotion: partial → final path ────────────────────────
            std::fs::rename(&partial_path, &out_path)?;
            send_frame(conn, ctrl_sid, &[proto::ACK]).await?;
            eprintln!(
                "received: {name} ({size} bytes) [{algo_name} OK: {}]",
                hex::encode(&expected[..8])
            );
        } else {
            // ── Checksum mismatch: remove corrupted partial ───────────────────
            // Do NOT keep the partial — it is corrupt. The caller will need to
            // restart the transfer from byte 0 on the next attempt.
            let _ = std::fs::remove_file(&partial_path);
            bail!(
                "{algo_name} integrity check FAILED for {name}: expected {} got {} — partial deleted, retry transfer",
                hex::encode(expected),
                hex::encode(actual)
            );
        }
    } else {
        // Older peer without checksum support — promote the partial anyway.
        std::fs::rename(&partial_path, &out_path)?;
        eprintln!("received: {name} ({size} bytes) [no integrity check]");
    }
    Ok(())
}
