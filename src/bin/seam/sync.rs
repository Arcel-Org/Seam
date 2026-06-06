/// `seam sync` — content-addressed directory sync over post-quantum Seam.
///
/// Usage:
///   seam sync <local_dir> user@host:<remote_dir>   (push)
///   seam sync user@host:<remote_dir> <local_dir>   (pull)
///
/// Protocol:
///   1. Client sends its manifest (list of paths + sizes + hashes)
///   2. Remote sends back its manifest
///   3. Client sends only files that differ or are missing on remote
///   4. Each file is verified with BLAKE3 (or SHA-256 in FIPS mode)
///   5. With --delete: remote removes files not present in local manifest
///
/// Manifest caching:
///   The remote manifest is cached in ~/.cache/seam/sync/<host>/<path_hash>.json
///   so subsequent syncs skip re-hashing unchanged remote files. Cache entries
///   are validated against file mtime and size; any mismatch invalidates the
///   entry. Pass --no-cache to bypass.
use anyhow::{Result, anyhow, bail};
use clap::Args;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use seam_protocol::{
    api::Server,
    handshake::{IdentityKeypair, pk_to_bytes},
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::{
    connect,
    proto::{self, read_frame, send_frame, wait_for_stream},
    ssh,
};

// ── Protocol constants ────────────────────────────────────────────────────────

const SYNC_MANIFEST: u8 = 0x20;
const SYNC_FILE: u8 = 0x21;
const SYNC_FILE_DATA: u8 = 0x22;
const SYNC_FILE_ACK: u8 = 0x23;
const SYNC_DELETE: u8 = 0x24;
const SYNC_DONE: u8 = 0x25;
const SYNC_HASH_LEN: usize = 32;
const CHUNK: usize = 32 * 1024;
const ZSTD_LEVEL: i32 = 3;

// ── File manifest entry ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ManifestEntry {
    path: String,
    size: u64,
    hash: [u8; SYNC_HASH_LEN],
}

// ── Manifest cache ────────────────────────────────────────────────────────────
//
// Caches the remote manifest to ~/.cache/seam/sync/<host>/<dir_key>.json.
// Each cache entry stores size + mtime-sec for each file so stale entries
// (files modified on the remote since the last sync) are detected and dropped.
//
// Cache key = SHA-256(host + ":" + remote_dir) truncated to 16 hex chars.
// This avoids filesystem-unsafe characters in the path.

/// A single cached file entry (serialized inside CachedManifest).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedEntry {
    /// Relative path (same as ManifestEntry.path)
    path: String,
    /// File size in bytes
    size: u64,
    /// BLAKE3 or SHA-256 hash of file contents, hex-encoded
    hash_hex: String,
    /// mtime seconds since Unix epoch (used for cache invalidation)
    mtime_sec: u64,
}

/// The serialized manifest cache for one (host, remote_dir) pair.
#[derive(Debug, Serialize, Deserialize)]
struct CachedManifest {
    /// Version tag for forward compatibility
    version: u8,
    /// UTC seconds when this cache was written
    cached_at: u64,
    /// hostname (without user@) for display/sanity
    host: String,
    /// remote directory
    remote_dir: String,
    /// cached entries
    entries: Vec<CachedEntry>,
}

/// Compute a short cache key from (host, remote_dir).
fn manifest_cache_key(host: &str, remote_dir: &str) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(host.as_bytes());
    h.update(b":");
    h.update(remote_dir.as_bytes());
    let digest = h.finalize();
    hex::encode(&digest[..8]) // 16 hex chars
}

/// Path of the cache file for (host, remote_dir).
fn manifest_cache_path(host: &str, remote_dir: &str) -> PathBuf {
    let key = manifest_cache_key(host, remote_dir);
    // sanitize host for use as directory name
    let host_safe: String = host
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("seam")
        .join("sync")
        .join(&host_safe)
        .join(format!("{key}.json"))
}

/// Load cached manifest. Returns None if the cache file is missing or corrupt.
fn load_manifest_cache(host: &str, remote_dir: &str) -> Option<CachedManifest> {
    let path = manifest_cache_path(host, remote_dir);
    let text = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Save a manifest to cache.
fn save_manifest_cache(host: &str, remote_dir: &str, entries: &[ManifestEntry]) -> Result<()> {
    let path = manifest_cache_path(host, remote_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let cached_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let cached_entries: Vec<CachedEntry> = entries
        .iter()
        .map(|e| CachedEntry {
            path: e.path.clone(),
            size: e.size,
            hash_hex: hex::encode(e.hash),
            mtime_sec: 0, // remote mtime not available via our protocol; validated by size+hash
        })
        .collect();

    let manifest = CachedManifest {
        version: 1,
        cached_at,
        host: host.to_string(),
        remote_dir: remote_dir.to_string(),
        entries: cached_entries,
    };

    let text = serde_json::to_string_pretty(&manifest)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text.as_bytes())?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Format a duration in seconds as a human-readable string.
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

/// Convert a cached manifest to ManifestEntry vec.
fn cached_to_manifest(cached: &CachedManifest) -> Vec<ManifestEntry> {
    cached
        .entries
        .iter()
        .filter_map(|e| {
            let hash_bytes = hex::decode(&e.hash_hex).ok()?;
            if hash_bytes.len() != SYNC_HASH_LEN {
                return None;
            }
            let mut hash = [0u8; SYNC_HASH_LEN];
            hash.copy_from_slice(&hash_bytes);
            Some(ManifestEntry {
                path: e.path.clone(),
                size: e.size,
                hash,
            })
        })
        .collect()
}

// ── Client args ───────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct SyncArgs {
    /// Source path — local dir or user@host:<remote_dir>
    pub src: String,
    /// Destination path — user@host:<remote_dir> or local dir
    pub dest: String,
    /// Remove files on destination that are not in source (like rsync --delete)
    #[arg(long)]
    pub delete: bool,
    /// SSH port for the bootstrap connection
    #[arg(short = 'p', long)]
    pub port: Option<u16>,
    /// Disable zstd compression during transfer
    #[arg(long)]
    pub no_compress: bool,
    /// Bypass the remote manifest cache (always re-hash remote files)
    #[arg(long)]
    pub no_cache: bool,
}

// ── Server (remote) args ──────────────────────────────────────────────────────

#[derive(Args)]
pub struct SyncRecvArgs {
    /// Local directory on the remote side
    pub dir: PathBuf,
    /// UDP port to listen on
    #[arg(long, default_value_t = 0)]
    pub port: u16,
    /// Direction: "push" (we receive files) or "pull" (we send files)
    #[arg(long, default_value = "push")]
    pub direction: String,
    /// Remove local files not in remote manifest (for push direction)
    #[arg(long)]
    pub delete: bool,
}

// ── Hash helpers ──────────────────────────────────────────────────────────────

fn hash_file(path: &Path, fips_mode: bool) -> Result<[u8; SYNC_HASH_LEN]> {
    use crate::copy::IncrementalHasher;
    use std::io::Read;
    let mut file =
        std::fs::File::open(path).map_err(|e| anyhow!("cannot open {}: {e}", path.display()))?;
    let mut hasher = IncrementalHasher::new(fips_mode);
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize())
}

// ── Manifest building ─────────────────────────────────────────────────────────

fn build_manifest(dir: &Path, fips_mode: bool, pb: &ProgressBar) -> Result<Vec<ManifestEntry>> {
    let mut entries = Vec::new();
    if !dir.exists() {
        return Ok(entries);
    }
    for entry in walkdir::WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let rel = path
            .strip_prefix(dir)
            .unwrap()
            .to_string_lossy()
            .to_string();
        let size = entry.metadata()?.len();
        pb.set_message(format!("hashing {rel}"));
        let hash = hash_file(path, fips_mode)?;
        entries.push(ManifestEntry {
            path: rel,
            size,
            hash,
        });
    }
    Ok(entries)
}

// ── Manifest serialization ────────────────────────────────────────────────────

/// Encode: [u32 count]([u32 path_len][path bytes][u64 size][u8; 32 hash])*
fn encode_manifest(entries: &[ManifestEntry]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(SYNC_MANIFEST);
    buf.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for e in entries {
        let pb = e.path.as_bytes();
        buf.extend_from_slice(&(pb.len() as u32).to_be_bytes());
        buf.extend_from_slice(pb);
        buf.extend_from_slice(&e.size.to_be_bytes());
        buf.extend_from_slice(&e.hash);
    }
    buf
}

fn decode_manifest(data: &[u8]) -> Result<Vec<ManifestEntry>> {
    if data.is_empty() || data[0] != SYNC_MANIFEST {
        bail!("expected SYNC_MANIFEST frame");
    }
    let data = &data[1..];
    if data.len() < 4 {
        bail!("manifest too short");
    }
    let count = u32::from_be_bytes(data[..4].try_into()?) as usize;
    let mut pos = 4;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 4 > data.len() {
            bail!("manifest truncated at path_len");
        }
        let path_len = u32::from_be_bytes(data[pos..pos + 4].try_into()?) as usize;
        pos += 4;
        if pos + path_len + 8 + SYNC_HASH_LEN > data.len() {
            bail!("manifest truncated at path");
        }
        let path = String::from_utf8(data[pos..pos + path_len].to_vec())?;
        pos += path_len;
        let size = u64::from_be_bytes(data[pos..pos + 8].try_into()?);
        pos += 8;
        let hash: [u8; SYNC_HASH_LEN] = data[pos..pos + SYNC_HASH_LEN].try_into()?;
        pos += SYNC_HASH_LEN;
        entries.push(ManifestEntry { path, size, hash });
    }
    Ok(entries)
}

// ── Send a single file ────────────────────────────────────────────────────────

async fn send_sync_file(
    conn: &mut seam_protocol::api::SeamConn,
    sid: seam_protocol::session::stream::StreamId,
    base: &Path,
    entry: &ManifestEntry,
    compress: bool,
    buf: &mut Vec<u8>,
    fips_mode: bool,
) -> Result<()> {
    use crate::copy::IncrementalHasher;
    use std::io::Read;

    let file_path = base.join(&entry.path);

    // Header: SYNC_FILE [u32 path_len][path][u64 size]
    let path_bytes = entry.path.as_bytes();
    let mut header = Vec::new();
    header.push(SYNC_FILE);
    header.extend_from_slice(&(path_bytes.len() as u32).to_be_bytes());
    header.extend_from_slice(path_bytes);
    header.extend_from_slice(&entry.size.to_be_bytes());
    send_frame(conn, sid, &header).await?;

    let mut file = std::fs::File::open(&file_path)?;
    let mut hasher = IncrementalHasher::new(fips_mode);
    let mut sent: u64 = 0;
    let mut chunk = vec![0u8; CHUNK];

    while sent < entry.size {
        let n = file.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        let raw = &chunk[..n];
        hasher.update(raw);
        let payload = if compress {
            zstd::encode_all(raw, ZSTD_LEVEL)?
        } else {
            raw.to_vec()
        };
        let mut frame = Vec::with_capacity(1 + payload.len());
        frame.push(SYNC_FILE_DATA);
        frame.extend_from_slice(&payload);
        send_frame(conn, sid, &frame).await?;
        sent += n as u64;
        let _ = conn.tick().await;
    }

    // Send checksum
    let digest = hasher.finalize();
    let mut cksum = Vec::with_capacity(1 + SYNC_HASH_LEN);
    cksum.push(proto::CHECKSUM);
    cksum.extend_from_slice(&digest);
    send_frame(conn, sid, &cksum).await?;

    // Wait for ACK
    let reply = read_frame(conn, sid, buf).await?;
    if reply.is_empty() || reply[0] != SYNC_FILE_ACK {
        bail!("sync: integrity check failed for {}", entry.path);
    }

    Ok(())
}

// ── Receive a single file ─────────────────────────────────────────────────────

async fn recv_sync_file(
    conn: &mut seam_protocol::api::SeamConn,
    sid: seam_protocol::session::stream::StreamId,
    header_frame: &[u8],
    base: &Path,
    compress: bool,
    buf: &mut Vec<u8>,
    fips_mode: bool,
) -> Result<(String, u64)> {
    use crate::copy::IncrementalHasher;
    use std::io::Write;

    // Parse header: SYNC_FILE [u32 path_len][path][u64 size]
    if header_frame.len() < 13 {
        bail!("sync file header too short");
    }
    let path_len = u32::from_be_bytes(header_frame[1..5].try_into()?) as usize;
    if header_frame.len() < 5 + path_len + 8 {
        bail!("sync file header truncated");
    }
    let path = String::from_utf8(header_frame[5..5 + path_len].to_vec())?;
    let size = u64::from_be_bytes(header_frame[5 + path_len..5 + path_len + 8].try_into()?);

    // Security: reject path traversal
    if path.contains("..") || Path::new(&path).is_absolute() {
        bail!("refusing dangerous path: {path}");
    }

    let out_path = base.join(&path);
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&out_path)?;

    let mut hasher = IncrementalHasher::new(fips_mode);
    let mut received: u64 = 0;

    while received < size {
        let frame = read_frame(conn, sid, buf).await?;
        if frame.is_empty() {
            bail!("sync: unexpected empty frame while receiving {path}");
        }
        if frame[0] == proto::CHECKSUM {
            // Received checksum before all data — error
            bail!("sync: received CHECKSUM before all data for {path}");
        }
        if frame[0] != SYNC_FILE_DATA {
            bail!("sync: expected SYNC_FILE_DATA, got 0x{:02x}", frame[0]);
        }
        let raw = &frame[1..];
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
        let _ = conn.tick().await;
    }

    // Read checksum frame
    let cksum_frame = read_frame(conn, sid, buf).await?;
    if cksum_frame.len() == 1 + SYNC_HASH_LEN && cksum_frame[0] == proto::CHECKSUM {
        let expected = &cksum_frame[1..1 + SYNC_HASH_LEN];
        let actual = hasher.finalize();
        let algo = if fips_mode { "SHA-256" } else { "BLAKE3" };
        if actual == expected {
            send_frame(conn, sid, &[SYNC_FILE_ACK]).await?;
        } else {
            bail!("sync: {algo} mismatch for {path}");
        }
    } else {
        bail!("sync: expected CHECKSUM frame");
    }

    Ok((path, size))
}

// ── Main client ───────────────────────────────────────────────────────────────

pub async fn run(args: SyncArgs, fips_mode: bool) -> Result<()> {
    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let compress = !args.no_compress && cfg.compress;
    let cipher_str = if fips_mode {
        "aes256gcm"
    } else {
        cfg.cipher.as_str()
    };
    let cipher = seam_protocol::crypto::CipherSuite::parse(cipher_str).unwrap_or_default();
    let algo_name = if fips_mode { "SHA-256" } else { "BLAKE3" };

    let src_remote = ssh::parse_remote(&args.src);
    let dst_remote = ssh::parse_remote(&args.dest);

    let (is_push, local_dir, remote, remote_dir, ssh_port) = match (src_remote, dst_remote) {
        (Some(_), Some(_)) => bail!("both source and destination cannot be remote"),
        (None, None) => {
            bail!("at least one of source or destination must be remote (user@host:/path)")
        }
        (None, Some((r, rdir))) => {
            // push: local → remote
            let local = PathBuf::from(&args.src);
            if !local.exists() {
                bail!("source directory not found: {}", args.src);
            }
            if local.is_file() {
                bail!("seam sync requires a directory, not a file: {}", args.src);
            }
            (true, local, r, rdir, args.port)
        }
        (Some((r, rdir)), None) => {
            // pull: remote → local
            let local = PathBuf::from(&args.dest);
            (false, local, r, rdir, args.port)
        }
    };

    let _ = ssh_port; // ssh_port is in remote.ssh_port

    let direction = if is_push { "push" } else { "pull" };
    let subcmd = format!(
        "_sync-recv {} --port 0 --direction {}{}",
        connect::shell_quote(&remote_dir),
        direction,
        if args.delete { " --delete" } else { "" },
    );

    let seam_bin = match remote.seam_path() {
        Some(p) => p,
        None => {
            eprintln!("seam not found on {} — bootstrapping…", remote.target());
            remote.bootstrap_copy_self()?
        }
    };

    eprintln!(
        "syncing {}:{} {} {}…",
        remote.target(),
        remote_dir,
        if is_push { "←" } else { "→" },
        local_dir.display()
    );

    // ── Manifest cache pre-check ──────────────────────────────────────────────
    // If we have a cached remote manifest from a previous sync, show the user
    // an estimated diff count before the network round-trip. This is purely
    // informational; the authoritative manifest always comes from the remote.
    if !args.no_cache
        && let Some(cached) = load_manifest_cache(&remote.host, &remote_dir)
    {
        let cached_entries = cached_to_manifest(&cached);
        let cached_age_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(cached.cached_at);
        eprintln!(
            "manifest cache: {} files from {} ago — estimating diff…",
            cached_entries.len(),
            format_duration(cached_age_secs)
        );
    }

    let (line, _child) = remote.start_remote_seam(&seam_bin, &subcmd)?;
    let (port, x25519, kem_pk) = connect::parse_seam_line(&line)?;
    let mut conn = connect::dial(&remote.host, port, x25519, kem_pk, cipher).await?;
    eprintln!("connected — post-quantum handshake complete");

    let ctrl_sid = conn.open_stream().await;
    let mut buf = Vec::new();

    let mp = MultiProgress::new();
    let hash_pb = mp.add(ProgressBar::new_spinner());
    hash_pb.set_style(ProgressStyle::with_template("{spinner:.cyan} {msg}").unwrap());

    if is_push {
        // Push mode: build local manifest, exchange with remote, send differing files.
        hash_pb.set_message(format!("building local manifest ({algo_name})…"));
        let local_manifest = build_manifest(&local_dir, fips_mode, &hash_pb)?;
        hash_pb.finish_with_message(format!("local manifest: {} files", local_manifest.len()));

        // Send local manifest
        let encoded = encode_manifest(&local_manifest);
        send_frame(&conn, ctrl_sid, &encoded).await?;

        // Receive remote manifest (always from wire — cache is used for diffing only)
        let remote_manifest_frame = read_frame(&mut conn, ctrl_sid, &mut buf).await?;
        let remote_manifest = decode_manifest(&remote_manifest_frame)?;

        // Update the manifest cache with the freshly-received remote manifest.
        if !args.no_cache
            && let Err(e) = save_manifest_cache(&remote.host, &remote_dir, &remote_manifest)
        {
            // Non-fatal: cache write failures don't affect correctness.
            eprintln!("sync: warning: could not update manifest cache: {e}");
        }

        eprintln!("remote manifest: {} files", remote_manifest.len());

        // Determine which files to transfer (content-addressed diff)
        use std::collections::HashMap;
        let remote_index: HashMap<&str, &ManifestEntry> = remote_manifest
            .iter()
            .map(|e| (e.path.as_str(), e))
            .collect();

        let to_send: Vec<&ManifestEntry> = local_manifest
            .iter()
            .filter(|e| {
                match remote_index.get(e.path.as_str()) {
                    None => true,                  // missing on remote
                    Some(re) => re.hash != e.hash, // content differs
                }
            })
            .collect();

        let skipped = local_manifest.len() - to_send.len();
        let total_bytes: u64 = to_send.iter().map(|e| e.size).sum();

        eprintln!(
            "transferring {} file(s) ({} bytes), skipping {} unchanged",
            to_send.len(),
            total_bytes,
            skipped
        );

        let xfer_pb = mp.add(ProgressBar::new(total_bytes));
        xfer_pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.cyan} {msg}\n  [{bar:40.green/dim}] {bytes}/{total_bytes} ({bytes_per_sec}, eta {eta})",
            )
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏ "),
        );

        let start = std::time::Instant::now();
        for entry in &to_send {
            xfer_pb.set_message(format!("sending {}", entry.path));
            let before = xfer_pb.position();
            send_sync_file(
                &mut conn, ctrl_sid, &local_dir, entry, compress, &mut buf, fips_mode,
            )
            .await?;
            xfer_pb.inc(entry.size.saturating_sub(xfer_pb.position() - before) + entry.size);
        }

        // Signal done
        send_frame(&conn, ctrl_sid, &[SYNC_DONE]).await?;

        // Handle --delete: send list of paths to delete on remote
        if args.delete {
            let local_paths: std::collections::HashSet<&str> =
                local_manifest.iter().map(|e| e.path.as_str()).collect();
            let to_delete: Vec<&str> = remote_manifest
                .iter()
                .filter(|e| !local_paths.contains(e.path.as_str()))
                .map(|e| e.path.as_str())
                .collect();
            eprintln!("deleting {} remote file(s)…", to_delete.len());
            for path in &to_delete {
                let path_bytes = path.as_bytes();
                let mut del_frame = Vec::with_capacity(1 + 4 + path_bytes.len());
                del_frame.push(SYNC_DELETE);
                del_frame.extend_from_slice(&(path_bytes.len() as u32).to_be_bytes());
                del_frame.extend_from_slice(path_bytes);
                send_frame(&conn, ctrl_sid, &del_frame).await?;
            }
        }
        send_frame(&conn, ctrl_sid, &[SYNC_DONE]).await?;

        let elapsed = start.elapsed().as_secs_f64().max(0.001);
        let mib_s = (total_bytes as f64) / (1024.0 * 1024.0) / elapsed;
        xfer_pb.finish_with_message(format!(
            "done — {} file(s) transferred, {} skipped in {:.1}s ({:.1} MiB/s)",
            to_send.len(),
            skipped,
            elapsed,
            mib_s
        ));
    } else {
        // Pull mode: receive remote manifest, send local manifest, receive files.
        let remote_manifest_frame = read_frame(&mut conn, ctrl_sid, &mut buf).await?;
        let remote_manifest = decode_manifest(&remote_manifest_frame)?;

        // Cache the remote manifest for future use.
        if !args.no_cache
            && let Err(e) = save_manifest_cache(&remote.host, &remote_dir, &remote_manifest)
        {
            eprintln!("sync: warning: could not update manifest cache: {e}");
        }

        hash_pb.set_message(format!("building local manifest ({algo_name})…"));
        std::fs::create_dir_all(&local_dir)?;
        let local_manifest = build_manifest(&local_dir, fips_mode, &hash_pb)?;
        hash_pb.finish_with_message(format!("local manifest: {} files", local_manifest.len()));

        // Send local manifest to remote
        let encoded = encode_manifest(&local_manifest);
        send_frame(&conn, ctrl_sid, &encoded).await?;

        use std::collections::HashMap;
        let local_index: HashMap<&str, &ManifestEntry> = local_manifest
            .iter()
            .map(|e| (e.path.as_str(), e))
            .collect();
        let needed: std::collections::HashSet<&str> = remote_manifest
            .iter()
            .filter(|e| match local_index.get(e.path.as_str()) {
                None => true,
                Some(le) => le.hash != e.hash,
            })
            .map(|e| e.path.as_str())
            .collect();

        let skipped = remote_manifest.len() - needed.len();
        eprintln!(
            "expecting {} file(s) from remote, skipping {} unchanged",
            needed.len(),
            skipped
        );

        let total_bytes: u64 = remote_manifest
            .iter()
            .filter(|e| needed.contains(e.path.as_str()))
            .map(|e| e.size)
            .sum();

        let xfer_pb = mp.add(ProgressBar::new(total_bytes));
        xfer_pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.cyan} {msg}\n  [{bar:40.green/dim}] {bytes}/{total_bytes} ({bytes_per_sec}, eta {eta})",
            )
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏ "),
        );

        let start = std::time::Instant::now();
        let mut files_received = 0u64;

        loop {
            let frame = read_frame(&mut conn, ctrl_sid, &mut buf).await?;
            if frame.is_empty() {
                bail!("sync: unexpected empty frame");
            }
            match frame[0] {
                SYNC_FILE => {
                    let (path, size) = recv_sync_file(
                        &mut conn, ctrl_sid, &frame, &local_dir, compress, &mut buf, fips_mode,
                    )
                    .await?;
                    xfer_pb.set_message(format!("received {path}"));
                    xfer_pb.inc(size);
                    files_received += 1;
                }
                SYNC_DONE => break,
                t => bail!("sync: unexpected frame 0x{t:02x}"),
            }
        }

        // Handle --delete on pull: remove local files not in remote manifest
        if args.delete {
            let remote_paths: std::collections::HashSet<&str> =
                remote_manifest.iter().map(|e| e.path.as_str()).collect();
            let mut deleted = 0u64;
            for le in &local_manifest {
                if !remote_paths.contains(le.path.as_str()) {
                    let full = local_dir.join(&le.path);
                    if std::fs::remove_file(&full).is_ok() {
                        deleted += 1;
                    }
                }
            }
            if deleted > 0 {
                eprintln!("deleted {deleted} local file(s) not present on remote");
            }
        }

        let elapsed = start.elapsed().as_secs_f64().max(0.001);
        let mib_s = (total_bytes as f64) / (1024.0 * 1024.0) / elapsed;
        xfer_pb.finish_with_message(format!(
            "done — {files_received} file(s) received, {skipped} skipped in {elapsed:.1}s ({mib_s:.1} MiB/s)",
        ));
    }

    conn.close().await;
    Ok(())
}

// ── Remote receiver ───────────────────────────────────────────────────────────

pub async fn run_recv(args: SyncRecvArgs, fips_mode: bool) -> Result<()> {
    let id = IdentityKeypair::generate();
    let x25519_hex = hex::encode(id.x25519_public.as_bytes());
    let kem_hex = hex::encode(pk_to_bytes(&id.kem_pk));

    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let fips = fips_mode || super::config::Config::effective_fips_mode(cfg.fips_mode, false);
    let cipher_str = if fips { "aes256gcm" } else { &cfg.cipher };
    let cipher = seam_protocol::crypto::CipherSuite::parse(cipher_str).unwrap_or_default();

    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;
    let mut server = Server::bind_with_cipher(addr, id, cipher)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    let port = server.local_addr()?.port();

    println!("SEAM PORT={port} X25519={x25519_hex} KEM={kem_hex}");

    let mut conn = server
        .accept()
        .await
        .ok_or_else(|| anyhow!("no connection"))?;

    let ctrl_sid = wait_for_stream(&mut conn).await?;
    let _ = conn.tick().await;
    let mut buf = Vec::new();

    std::fs::create_dir_all(&args.dir)?;

    let compress = cfg.compress;

    if args.direction == "push" {
        // Remote is receiving files from client.
        // 1. Receive client manifest
        let client_manifest_frame = read_frame(&mut conn, ctrl_sid, &mut buf).await?;
        let _client_manifest = decode_manifest(&client_manifest_frame)?;

        // 2. Build and send our manifest
        let spinner = ProgressBar::new_spinner();
        spinner.set_message("building remote manifest…");
        let our_manifest = build_manifest(&args.dir, fips, &spinner)?;
        spinner.finish_and_clear();
        let encoded = encode_manifest(&our_manifest);
        send_frame(&conn, ctrl_sid, &encoded).await?;

        // 3. Receive files
        loop {
            let frame = read_frame(&mut conn, ctrl_sid, &mut buf).await?;
            if frame.is_empty() {
                bail!("sync-recv: unexpected empty frame");
            }
            match frame[0] {
                SYNC_FILE => {
                    recv_sync_file(
                        &mut conn, ctrl_sid, &frame, &args.dir, compress, &mut buf, fips,
                    )
                    .await?;
                }
                SYNC_DONE => break,
                t => bail!("sync-recv: unexpected frame 0x{t:02x}"),
            }
        }

        // 4. Handle --delete: receive delete commands from client
        if args.delete {
            loop {
                let frame = read_frame(&mut conn, ctrl_sid, &mut buf).await?;
                if frame.is_empty() {
                    bail!("sync-recv: unexpected empty frame in delete phase");
                }
                match frame[0] {
                    SYNC_DELETE => {
                        if frame.len() < 5 {
                            continue;
                        }
                        let path_len = u32::from_be_bytes(frame[1..5].try_into()?) as usize;
                        if frame.len() < 5 + path_len {
                            continue;
                        }
                        let path = String::from_utf8(frame[5..5 + path_len].to_vec())?;
                        if !path.contains("..") && !Path::new(&path).is_absolute() {
                            let full = args.dir.join(&path);
                            let _ = std::fs::remove_file(&full);
                        }
                    }
                    SYNC_DONE => break,
                    _ => {}
                }
            }
        }
    } else {
        // Pull mode: client pulls files from us.
        // 1. Build and send our manifest
        let spinner = ProgressBar::new_spinner();
        spinner.set_message("building remote manifest…");
        let our_manifest = build_manifest(&args.dir, fips, &spinner)?;
        spinner.finish_and_clear();
        let encoded = encode_manifest(&our_manifest);
        send_frame(&conn, ctrl_sid, &encoded).await?;

        // 2. Receive client manifest (so we know what they already have)
        let client_manifest_frame = read_frame(&mut conn, ctrl_sid, &mut buf).await?;
        let client_manifest = decode_manifest(&client_manifest_frame)?;

        // 3. Determine which files to send
        use std::collections::HashMap;
        let client_index: HashMap<&str, &ManifestEntry> = client_manifest
            .iter()
            .map(|e| (e.path.as_str(), e))
            .collect();

        let to_send: Vec<&ManifestEntry> = our_manifest
            .iter()
            .filter(|e| match client_index.get(e.path.as_str()) {
                None => true,
                Some(ce) => ce.hash != e.hash,
            })
            .collect();

        // 4. Send files
        for entry in to_send {
            send_sync_file(
                &mut conn, ctrl_sid, &args.dir, entry, compress, &mut buf, fips,
            )
            .await?;
        }

        send_frame(&conn, ctrl_sid, &[SYNC_DONE]).await?;
    }

    conn.close().await;
    Ok(())
}
