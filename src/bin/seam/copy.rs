use anyhow::{Result, bail};
use clap::Args;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::Digest as _;
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
    /// Limit transfer bandwidth to at most RATE Mbps (token-bucket throttle).
    ///
    /// Prevents seam cp from saturating network links during business hours.
    /// Example: --rate 10  (limits to 10 Mbps ≈ 1.25 MB/s)
    #[arg(long, value_name = "Mbps")]
    pub rate: Option<f64>,
}

// ── Token-bucket rate limiter (same algorithm as bench --bw-cap) ──────────────

/// A simple token-bucket rate limiter.
/// Tokens refill at `rate_bytes_per_sec` continuously. `consume(n)` sleeps if
/// the bucket is empty, producing back-pressure on the sender.
pub struct TokenBucket {
    capacity: u64,
    tokens: u64,
    rate_bps: u64,
    last_refill: std::time::Instant,
}

impl TokenBucket {
    pub fn new(rate_mbps: f64) -> Self {
        let rate_bps = (rate_mbps * 1_000_000.0 / 8.0) as u64; // Mbps → bytes/s
        // Burst: allow up to 1 ms worth of data to smooth scheduler jitter.
        let capacity = (rate_bps / 1000).max(65536);
        Self {
            capacity,
            tokens: capacity,
            rate_bps,
            last_refill: std::time::Instant::now(),
        }
    }

    pub async fn consume(&mut self, bytes: u64) {
        // Refill tokens since last call.
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let new_tokens = (elapsed * self.rate_bps as f64) as u64;
        self.tokens = (self.tokens + new_tokens).min(self.capacity);
        self.last_refill = now;

        if self.tokens >= bytes {
            self.tokens -= bytes;
        } else {
            // Need to wait for enough tokens.
            let deficit = bytes - self.tokens;
            self.tokens = 0;
            let wait_secs = deficit as f64 / self.rate_bps as f64;
            let wait = std::time::Duration::from_secs_f64(wait_secs);
            tokio::time::sleep(wait).await;
        }
    }
}

pub async fn run(args: CopyArgs, fips_mode: bool) -> Result<()> {
    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let compress = if args.no_compress {
        false
    } else {
        cfg.compress
    };

    // ── Rate limiter ──────────────────────────────────────────────────────────
    let mut rate_limiter = args.rate.map(|mbps| {
        eprintln!("cp: bandwidth cap: {mbps} Mbps");
        TokenBucket::new(mbps)
    });
    // In FIPS mode, always use AES-256-GCM regardless of config.
    let cipher_str = if fips_mode { "aes256gcm" } else { &cfg.cipher };
    let cipher = seam_protocol::crypto::CipherSuite::parse(cipher_str).unwrap_or_default();

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
                let recv_subcmd = format!(
                    "recv {} --port 0 --once{}",
                    connect::shell_quote(&remote_path),
                    if fips_mode { " --fips-mode" } else { "" }
                );
                let (line, child) = remote.start_remote_seam(&seam_bin, &recv_subcmd)?;
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
        let pull_start = std::time::Instant::now();
        let mut files_received: u64 = 0;
        let mut bytes_received: u64 = 0;

        loop {
            let frame = read_frame(&mut conn, ctrl_sid, &mut buf).await?;
            if frame.is_empty() {
                bail!("empty frame");
            }
            match frame[0] {
                proto::FILE_INFO => {
                    let before = pb.position();
                    receive_file(
                        &mut conn,
                        ctrl_sid,
                        &frame,
                        &dest_path,
                        compress,
                        &mut buf,
                        &pb,
                        args.resume,
                        fips_mode,
                    )
                    .await?;
                    bytes_received += pb.position() - before;
                    files_received += 1;
                }
                proto::DONE => break,
                t => bail!("unexpected frame type 0x{:02x}", t),
            }
        }
        let pull_secs = pull_start.elapsed().as_secs_f64().max(0.001);
        let pull_mib_s = (bytes_received as f64) / (1024.0 * 1024.0) / pull_secs;
        pb.finish_with_message(format!(
            "done — {} file(s), {} MiB in {:.1}s ({:.1} MiB/s) → {}",
            files_received,
            bytes_received / (1024 * 1024),
            pull_secs,
            pull_mib_s,
            dest_path.display(),
        ));
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

        let push_start = std::time::Instant::now();
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
                fips_mode,
                rate_limiter.as_mut(),
            )
            .await?;
        }

        send_frame(&conn, ctrl_sid, &[proto::DONE]).await?;
        let push_secs = push_start.elapsed().as_secs_f64().max(0.001);
        let push_mib_s = (total_bytes as f64) / (1024.0 * 1024.0) / push_secs;
        pb.finish_with_message(format!(
            "done — {} file(s), {} MiB in {:.1}s ({:.1} MiB/s)",
            files.len(),
            total_bytes / (1024 * 1024),
            push_secs,
            push_mib_s,
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

/// Stateful hasher wrapper to allow incremental hashing with either algorithm.
pub enum IncrementalHasher {
    Blake3(blake3::Hasher),
    Sha256(sha2::Sha256),
}

impl IncrementalHasher {
    pub fn new(fips_mode: bool) -> Self {
        if fips_mode {
            Self::Sha256(sha2::Sha256::new())
        } else {
            Self::Blake3(blake3::Hasher::new())
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Blake3(h) => { h.update(data); }
            Self::Sha256(h) => { sha2::Digest::update(h, data); }
        }
    }

    pub fn finalize(self) -> [u8; 32] {
        match self {
            Self::Blake3(h) => *h.finalize().as_bytes(),
            Self::Sha256(h) => sha2::Digest::finalize(h).into(),
        }
    }
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
    fips_mode: bool,
    mut rate_limiter: Option<&mut TokenBucket>,
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

    let mut hasher = IncrementalHasher::new(fips_mode);
    let mut chunk = vec![0u8; CHUNK];
    while sent < size {
        let n = file.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        let raw = &chunk[..n];
        // Hash the pre-compression bytes so both sides hash the same content.
        hasher.update(raw);
        let payload = if compress {
            zstd::encode_all(raw, ZSTD_LEVEL)?
        } else {
            raw.to_vec()
        };
        // Apply rate limiting (token-bucket back-pressure) before sending.
        if let Some(ref mut tb) = rate_limiter {
            tb.consume(n as u64).await;
        }
        let mut frame = Vec::with_capacity(1 + payload.len());
        frame.push(proto::DATA);
        frame.extend_from_slice(&payload);
        send_frame(conn, ctrl_sid, &frame).await?;
        pb.inc(n as u64);
        sent += n as u64;
        let _ = conn.tick().await;
    }

    // Send checksum (SHA-256 in FIPS mode, BLAKE3 otherwise) for end-to-end integrity.
    let digest = hasher.finalize();
    let mut cksum_frame = Vec::with_capacity(1 + 32);
    cksum_frame.push(proto::CHECKSUM);
    cksum_frame.extend_from_slice(&digest);
    send_frame(conn, ctrl_sid, &cksum_frame).await?;

    // Wait for receiver ACK / error.
    let reply = read_frame(conn, ctrl_sid, buf).await?;
    if reply.is_empty() || reply[0] != proto::ACK {
        let algo = if fips_mode { "SHA-256" } else { "BLAKE3" };
        bail!("integrity check failed for {rel}: receiver reported {algo} hash mismatch");
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
    // When --resume is set, we write to `<name>.seam-partial` and atomically
    // rename to the final filename on checksum success. On mismatch we delete
    // the partial so the next attempt starts clean. This prevents the output
    // file from being replaced with corrupt data on failed transfers — critical
    // for large files over satellite/HF radio links.
    let partial_path = {
        let mut p = out_path.clone();
        let mut fname = p.file_name().unwrap_or_default().to_owned();
        fname.push(".seam-partial");
        p.set_file_name(fname);
        p
    };

    let resume_from = if resume {
        // Check for an existing partial from a previous interrupted transfer.
        let partial_size = partial_path.metadata().map(|m| m.len()).unwrap_or(0);
        if partial_size > 0 && partial_size < size {
            pb.set_message(format!("resuming {name} from byte {partial_size}"));
            let mut resume_frame = Vec::with_capacity(1 + 8);
            resume_frame.push(proto::RESUME);
            resume_frame.extend_from_slice(&partial_size.to_be_bytes());
            send_frame(conn, ctrl_sid, &resume_frame).await?;
            pb.inc(partial_size);
            partial_size
        } else {
            // No usable partial — clean up any stale one and start fresh.
            if partial_path.exists() {
                let _ = std::fs::remove_file(&partial_path);
            }
            0
        }
    } else {
        0
    };

    // Write to the partial staging file (or directly to the output if not resuming).
    let write_path = if resume { &partial_path } else { &out_path };
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(resume_from == 0)
        .open(write_path)?;
    if resume_from > 0 {
        file.seek(SeekFrom::Start(resume_from))?;
    }

    pb.set_message(format!("receiving {name}"));

    let mut hasher = IncrementalHasher::new(fips_mode);
    let algo_name = if fips_mode { "SHA-256" } else { "BLAKE3" };
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
            hasher.update(&decoded);
            file.write_all(&decoded)?;
            received += n;
            n
        } else {
            let n = raw.len() as u64;
            hasher.update(raw);
            file.write_all(raw)?;
            received += n;
            n
        };
        pb.inc(chunk_len);
        let _ = conn.tick().await;
    }
    // Flush before checksum verification.
    file.flush()?;
    drop(file);

    // Verify checksum sent by the sender (SHA-256 in FIPS mode, BLAKE3 otherwise).
    let cksum_frame = read_frame(conn, ctrl_sid, buf).await?;
    if cksum_frame.len() == 33 && cksum_frame[0] == proto::CHECKSUM {
        let expected = &cksum_frame[1..33];
        let actual = hasher.finalize();
        if actual == expected {
            if resume {
                // Atomically promote partial → final path.
                std::fs::rename(&partial_path, &out_path)?;
            }
            send_frame(conn, ctrl_sid, &[proto::ACK]).await?;
            eprintln!("received: {name} ({size} bytes) [{algo_name} OK: {}]",
                hex::encode(&expected[..8]));
        } else {
            if resume {
                // Delete corrupt partial — next attempt will restart from byte 0.
                let _ = std::fs::remove_file(&partial_path);
            }
            bail!("{algo_name} integrity check FAILED for {name}: expected {} got {} — {}",
                hex::encode(expected),
                hex::encode(actual),
                if resume { "partial deleted, retry transfer" } else { "receiver reported mismatch" });
        }
    } else {
        // Older peer without checksum support — promote partial if present.
        if resume && partial_path.exists() {
            std::fs::rename(&partial_path, &out_path)?;
        }
        eprintln!("received: {name} ({size} bytes) [no integrity check]");
    }
    Ok(())
}
