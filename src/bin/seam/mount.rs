/// `seam mount` — mount a remote Seam filesystem via FUSE.
///
/// When compiled with the `fuse` feature (`--features fuse`), this command
/// mounts a remote directory at a local mount point using FUSE. Without the
/// feature, it returns a helpful error.
///
/// Protocol: the client bootstraps a persistent `_mount-recv` process on the
/// remote (over SSH, like every other `seam` command) and keeps one
/// connection open for the life of the mount. Each FUSE callback issues one
/// request (STAT_PATH/LS_PATH/GET_PATH) on a fresh stream and waits for the
/// full response before returning — see `proto.rs` for the wire format.
/// File reads buffer the whole file in memory on `open()`; there is no
/// partial/streaming read yet, so this isn't suited to very large files.
/// Read-only: writes are not implemented (fuser's default handlers return
/// ENOSYS for anything this filesystem doesn't override).
///
/// Usage:
///   seam mount user@host:/remote/path /local/mountpoint
use anyhow::Result;
use clap::Args;

use crate::proto;

// ── Public argument structs (always compiled) ────────────────────────────────

#[derive(Args)]
pub struct MountArgs {
    /// Remote source: user@host:/path
    pub remote: String,
    /// Local mount point
    pub mountpoint: String,
    /// Read-only mount
    #[arg(long)]
    pub read_only: bool,
    /// SSH port for the bootstrap connection
    #[arg(short = 'p', long)]
    pub port: Option<u16>,
}

#[derive(Args)]
pub struct MountRecvArgs {
    /// UDP port to listen on (0 = OS-assigned)
    #[arg(long, default_value_t = 0)]
    pub port: u16,
    /// Root path to export
    pub root: String,
}

// ── Client entry point ───────────────────────────────────────────────────────

pub async fn run(args: MountArgs) -> Result<()> {
    #[cfg(feature = "fuse")]
    {
        run_fuse(args).await
    }
    #[cfg(not(feature = "fuse"))]
    {
        let _ = args;
        anyhow::bail!(
            "seam was not compiled with FUSE support (enable the 'fuse' feature).\n\
             Rebuild with: cargo build --features fuse"
        );
    }
}

// ── Remote entry point (persistent handler, started via SSH bootstrap) ──────
// Not gated behind `feature = "fuse"`: the machine serving files for a mount
// doesn't need FUSE itself, only the client mounting them does.

pub async fn run_recv(args: MountRecvArgs) -> Result<()> {
    use seam_protocol::{
        api::Server,
        handshake::{IdentityKeypair, pk_to_bytes},
    };

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

    let root = std::path::PathBuf::from(&args.root);

    // One request in flight at a time by construction: the client never
    // opens a second stream before the first request's response completes
    // (see mount.rs's client-side helpers), so we never need to demultiplex
    // concurrent streams here — wait for one, fully service it, repeat.
    loop {
        let sid = match proto::wait_for_stream(&mut conn).await {
            Ok(s) => s,
            Err(_) => break,
        };
        let mut buf = Vec::new();
        let frame = match proto::read_frame(&mut conn, sid, &mut buf).await {
            Ok(f) => f,
            Err(_) => continue,
        };
        if frame.is_empty() {
            continue;
        }
        let result = match frame[0] {
            proto::STAT_PATH => handle_stat_path(&mut conn, sid, &root, &frame[1..]).await,
            proto::LS_PATH => handle_ls_path(&mut conn, sid, &root, &frame[1..]).await,
            proto::GET_PATH => handle_get_path(&mut conn, sid, &root, &frame[1..]).await,
            _ => Ok(()),
        };
        if let Err(e) = result {
            eprintln!("mount-recv: request failed: {e}");
        }
    }
    Ok(())
}

/// Reject any requested path that isn't textually under `root`, and any
/// path containing a `..` component. Not a rigorous canonicalization, but
/// matches the same heuristic `recv.rs::receive_file` already uses for
/// filenames — both ends of a `seam mount` session are the same trusted SSH
/// user, so this is defense-in-depth against a client-side bug constructing
/// a bad path, not a hard security boundary.
fn validate_path(root: &std::path::Path, requested: &str) -> Result<std::path::PathBuf> {
    if requested.contains("..") {
        anyhow::bail!("refusing path containing '..': {requested}");
    }
    let root_str = root.to_string_lossy();
    if !requested.starts_with(root_str.as_ref()) {
        anyhow::bail!("path {requested} escapes mount root {root_str}");
    }
    Ok(std::path::PathBuf::from(requested))
}

fn build_entry_frame(name: &str, size: u64, mode: u32) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let mut frame = Vec::with_capacity(3 + name_bytes.len() + 8 + 4);
    frame.push(proto::ENTRY);
    frame.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    frame.extend_from_slice(name_bytes);
    frame.extend_from_slice(&size.to_be_bytes());
    frame.extend_from_slice(&mode.to_be_bytes());
    frame
}

#[cfg(unix)]
fn file_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode()
}
#[cfg(not(unix))]
fn file_mode(_meta: &std::fs::Metadata) -> u32 {
    0o644
}

async fn handle_stat_path(
    conn: &mut seam_protocol::api::SeamConn,
    sid: seam_protocol::session::stream::StreamId,
    root: &std::path::Path,
    path_bytes: &[u8],
) -> Result<()> {
    let path_str = String::from_utf8_lossy(path_bytes).into_owned();
    let path = match validate_path(root, &path_str) {
        Ok(p) => p,
        Err(_) => {
            proto::send_frame(conn, sid, &[proto::DONE]).await?;
            return Ok(());
        }
    };
    if let Ok(meta) = std::fs::metadata(&path) {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let frame = build_entry_frame(&name, meta.len(), file_mode(&meta));
        proto::send_frame(conn, sid, &frame).await?;
    }
    proto::send_frame(conn, sid, &[proto::DONE]).await?;
    Ok(())
}

async fn handle_ls_path(
    conn: &mut seam_protocol::api::SeamConn,
    sid: seam_protocol::session::stream::StreamId,
    root: &std::path::Path,
    path_bytes: &[u8],
) -> Result<()> {
    let path_str = String::from_utf8_lossy(path_bytes).into_owned();
    let path = match validate_path(root, &path_str) {
        Ok(p) => p,
        Err(_) => {
            proto::send_frame(conn, sid, &[proto::DONE]).await?;
            return Ok(());
        }
    };
    if let Ok(read_dir) = std::fs::read_dir(&path) {
        for entry in read_dir.flatten() {
            if let Ok(meta) = entry.metadata() {
                let name = entry.file_name().to_string_lossy().into_owned();
                let frame = build_entry_frame(&name, meta.len(), file_mode(&meta));
                proto::send_frame(conn, sid, &frame).await?;
            }
        }
    }
    proto::send_frame(conn, sid, &[proto::DONE]).await?;
    Ok(())
}

const GET_CHUNK: usize = 32 * 1024;

async fn handle_get_path(
    conn: &mut seam_protocol::api::SeamConn,
    sid: seam_protocol::session::stream::StreamId,
    root: &std::path::Path,
    path_bytes: &[u8],
) -> Result<()> {
    use std::io::Read;

    let path_str = String::from_utf8_lossy(path_bytes).into_owned();
    let path = validate_path(root, &path_str)?;
    let meta = std::fs::metadata(&path)?;
    let size = meta.len();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name_bytes = name.as_bytes();

    // FILE_INFO: [type][u64 size][u16 name_len][name][u32 mode] — same
    // layout `copy.rs::send_file` uses.
    let mut info = Vec::with_capacity(1 + 8 + 2 + name_bytes.len() + 4);
    info.push(proto::FILE_INFO);
    info.extend_from_slice(&size.to_be_bytes());
    info.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    info.extend_from_slice(name_bytes);
    info.extend_from_slice(&0u32.to_be_bytes());
    proto::send_frame(conn, sid, &info).await?;

    let mut file = std::fs::File::open(&path)?;
    let mut hasher = blake3::Hasher::new();
    let mut chunk = vec![0u8; GET_CHUNK];
    let mut sent = 0u64;
    while sent < size {
        let n = file.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        hasher.update(&chunk[..n]);
        let mut frame = Vec::with_capacity(1 + n);
        frame.push(proto::DATA);
        frame.extend_from_slice(&chunk[..n]);
        proto::send_frame(conn, sid, &frame).await?;
        sent += n as u64;
    }
    let digest = hasher.finalize();
    let mut cksum_frame = Vec::with_capacity(33);
    cksum_frame.push(proto::CHECKSUM);
    cksum_frame.extend_from_slice(digest.as_bytes());
    proto::send_frame(conn, sid, &cksum_frame).await?;
    Ok(())
}

// ── FUSE implementation (only compiled when the `fuse` feature is enabled) ──

#[cfg(feature = "fuse")]
async fn run_fuse(args: MountArgs) -> Result<()> {
    let mountpoint = std::path::PathBuf::from(&args.mountpoint);
    if !mountpoint.exists() {
        std::fs::create_dir_all(&mountpoint)?;
    }

    let (remote_info, remote_root) = crate::ssh::parse_remote(&args.remote)
        .ok_or_else(|| anyhow::anyhow!("expected user@host:/path, got {:?}", args.remote))?;
    let mut remote_root = remote_root.trim_end_matches('/').to_string();
    if remote_root.is_empty() {
        remote_root = "/".to_string();
    }
    let remote_info = crate::ssh::RemoteInfo {
        ssh_port: args.port,
        ..remote_info
    };

    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher = seam_protocol::crypto::CipherSuite::parse(&cfg.cipher).unwrap_or_default();

    let subcmd = format!(
        "_mount-recv {} --port 0",
        crate::connect::shell_quote(&remote_root)
    );
    eprintln!(
        "mount: connecting to {} → {}",
        args.remote,
        mountpoint.display()
    );
    let (conn, _ssh_child) =
        crate::connect::bootstrap_and_connect(&remote_info, &remote_info.host, &subcmd, cipher)
            .await?;
    eprintln!("mount: connected, mounting at {}", mountpoint.display());

    let rt = tokio::runtime::Handle::current();
    let conn = std::sync::Arc::new(tokio::sync::Mutex::new(conn));

    // FUSE activity is sporadic (bursts of access separated by long idle
    // gaps), unlike e.g. `seam cp`'s continuous transfer loop — without a
    // background ticker, nothing would call `conn.tick()` (which drives
    // keepalive Ping/Pong and retransmission) between bursts.
    {
        let conn = conn.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                interval.tick().await;
                let c = conn.lock().await;
                let _ = c.tick().await;
            }
        });
    }

    let fs = SeamFS {
        conn,
        rt,
        inodes: std::sync::Mutex::new(InodeTable::new(remote_root)),
        open_files: std::sync::Mutex::new(std::collections::HashMap::new()),
        next_fh: std::sync::atomic::AtomicU64::new(1),
    };

    let mut mount_options = vec![
        fuser::MountOption::FSName("seam".to_string()),
        fuser::MountOption::AutoUnmount,
    ];
    if args.read_only {
        mount_options.push(fuser::MountOption::RO);
    }
    let mut config = fuser::Config::default();
    config.mount_options = mount_options;

    // fuser::mount2 blocks the calling thread for the life of the mount;
    // run it on the blocking pool so it doesn't stall the tokio runtime
    // that the FUSE callbacks themselves need to `block_on` into.
    tokio::task::spawn_blocking(move || fuser::mount2(fs, &mountpoint, &config))
        .await
        .map_err(|e| anyhow::anyhow!("mount task panicked: {e}"))?
        .map_err(|e| anyhow::anyhow!("FUSE mount failed: {e}"))?;

    Ok(())
}

#[cfg(feature = "fuse")]
struct RemoteEntry {
    name: String,
    size: u64,
    mode: u32,
}

#[cfg(feature = "fuse")]
fn parse_entry(frame: &[u8]) -> Result<RemoteEntry> {
    if frame.len() < 3 {
        anyhow::bail!("ENTRY frame too short");
    }
    let name_len = u16::from_be_bytes(frame[1..3].try_into()?) as usize;
    if frame.len() < 3 + name_len + 8 + 4 {
        anyhow::bail!("ENTRY frame truncated");
    }
    let name = String::from_utf8_lossy(&frame[3..3 + name_len]).into_owned();
    let size = u64::from_be_bytes(frame[3 + name_len..3 + name_len + 8].try_into()?);
    let mode = u32::from_be_bytes(frame[3 + name_len + 8..3 + name_len + 12].try_into()?);
    Ok(RemoteEntry { name, size, mode })
}

#[cfg(feature = "fuse")]
async fn stat_path(
    conn: &mut seam_protocol::api::SeamConn,
    path: &str,
) -> Result<Option<RemoteEntry>> {
    let sid = conn.open_stream().await;
    let mut req = vec![proto::STAT_PATH];
    req.extend_from_slice(path.as_bytes());
    proto::send_frame(conn, sid, &req).await?;
    let mut buf = Vec::new();
    let frame = proto::read_frame(conn, sid, &mut buf).await?;
    match frame.first() {
        Some(&proto::ENTRY) => Ok(Some(parse_entry(&frame)?)),
        _ => Ok(None),
    }
}

#[cfg(feature = "fuse")]
async fn ls_path(conn: &mut seam_protocol::api::SeamConn, path: &str) -> Result<Vec<RemoteEntry>> {
    let sid = conn.open_stream().await;
    let mut req = vec![proto::LS_PATH];
    req.extend_from_slice(path.as_bytes());
    proto::send_frame(conn, sid, &req).await?;
    let mut buf = Vec::new();
    let mut entries = Vec::new();
    loop {
        let frame = proto::read_frame(conn, sid, &mut buf).await?;
        match frame.first() {
            Some(&proto::ENTRY) => entries.push(parse_entry(&frame)?),
            _ => break,
        }
    }
    Ok(entries)
}

#[cfg(feature = "fuse")]
async fn get_path(conn: &mut seam_protocol::api::SeamConn, path: &str) -> Result<Vec<u8>> {
    let sid = conn.open_stream().await;
    let mut req = vec![proto::GET_PATH];
    req.extend_from_slice(path.as_bytes());
    proto::send_frame(conn, sid, &req).await?;
    let mut buf = Vec::new();
    let info = proto::read_frame(conn, sid, &mut buf).await?;
    if info.is_empty() || info[0] != proto::FILE_INFO || info.len() < 11 {
        anyhow::bail!("expected FILE_INFO response for {path}");
    }
    let size = u64::from_be_bytes(info[1..9].try_into()?);

    let mut content = Vec::with_capacity(size as usize);
    while (content.len() as u64) < size {
        let data_frame = proto::read_frame(conn, sid, &mut buf).await?;
        if data_frame.is_empty() || data_frame[0] != proto::DATA {
            anyhow::bail!("expected DATA frame for {path}");
        }
        content.extend_from_slice(&data_frame[1..]);
    }

    let cksum_frame = proto::read_frame(conn, sid, &mut buf).await?;
    if cksum_frame.len() == 33 && cksum_frame[0] == proto::CHECKSUM {
        let expected = &cksum_frame[1..33];
        let actual = blake3::hash(&content);
        if actual.as_bytes() != expected {
            anyhow::bail!("checksum mismatch fetching {path}");
        }
    }
    Ok(content)
}

/// path <-> inode table. Inode 1 is always the mount root; everything else
/// is allocated lazily as `lookup`/`readdir` see new paths, and kept for the
/// life of the mount (no eviction — fine for interactive browsing, would
/// grow unbounded on a mount that churns through huge directory trees).
#[cfg(feature = "fuse")]
struct InodeTable {
    next_ino: u64,
    ino_to_path: std::collections::HashMap<u64, String>,
    path_to_ino: std::collections::HashMap<String, u64>,
}

#[cfg(feature = "fuse")]
impl InodeTable {
    fn new(root_path: String) -> Self {
        let mut ino_to_path = std::collections::HashMap::new();
        let mut path_to_ino = std::collections::HashMap::new();
        ino_to_path.insert(1, root_path.clone());
        path_to_ino.insert(root_path, 1);
        Self {
            next_ino: 2,
            ino_to_path,
            path_to_ino,
        }
    }

    fn path_for(&self, ino: fuser::INodeNo) -> Option<String> {
        self.ino_to_path.get(&ino.0).cloned()
    }

    fn ino_for_path(&mut self, path: &str) -> u64 {
        if let Some(&ino) = self.path_to_ino.get(path) {
            return ino;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.ino_to_path.insert(ino, path.to_string());
        self.path_to_ino.insert(path.to_string(), ino);
        ino
    }
}

#[cfg(feature = "fuse")]
fn join_path(parent: &str, name: &str) -> String {
    if parent.ends_with('/') {
        format!("{parent}{name}")
    } else {
        format!("{parent}/{name}")
    }
}

#[cfg(feature = "fuse")]
fn mode_to_kind_and_perm(mode: u32) -> (fuser::FileType, u16) {
    let kind = if mode & 0o170000 == 0o040000 {
        fuser::FileType::Directory
    } else {
        fuser::FileType::RegularFile
    };
    let perm = (mode & 0o7777) as u16;
    (kind, perm)
}

#[cfg(feature = "fuse")]
fn make_attr(ino: fuser::INodeNo, entry: &RemoteEntry) -> fuser::FileAttr {
    let (kind, perm) = mode_to_kind_and_perm(entry.mode);
    let perm = if perm != 0 {
        perm
    } else if kind == fuser::FileType::Directory {
        0o755
    } else {
        0o644
    };
    let now = std::time::SystemTime::now();
    fuser::FileAttr {
        ino,
        size: entry.size,
        blocks: entry.size.div_ceil(512),
        atime: now,
        mtime: now,
        ctime: now,
        crtime: now,
        kind,
        perm,
        nlink: if kind == fuser::FileType::Directory {
            2
        } else {
            1
        },
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
        rdev: 0,
        blksize: 512,
        flags: 0,
    }
}

#[cfg(feature = "fuse")]
struct SeamFS {
    conn: std::sync::Arc<tokio::sync::Mutex<seam_protocol::api::SeamConn>>,
    rt: tokio::runtime::Handle,
    inodes: std::sync::Mutex<InodeTable>,
    /// fh -> whole file content, populated on `open`, dropped on `release`.
    open_files: std::sync::Mutex<std::collections::HashMap<u64, Vec<u8>>>,
    next_fh: std::sync::atomic::AtomicU64,
}

#[cfg(feature = "fuse")]
impl SeamFS {
    fn block_on_conn<F, T>(
        &self,
        f: impl FnOnce(std::sync::Arc<tokio::sync::Mutex<seam_protocol::api::SeamConn>>) -> F,
    ) -> T
    where
        F: std::future::Future<Output = T>,
    {
        self.rt.block_on(f(self.conn.clone()))
    }
}

#[cfg(feature = "fuse")]
impl fuser::Filesystem for SeamFS {
    fn lookup(
        &self,
        _req: &fuser::Request,
        parent: fuser::INodeNo,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        let parent_path = { self.inodes.lock().unwrap().path_for(parent) };
        let Some(parent_path) = parent_path else {
            reply.error(fuser::Errno::ENOENT);
            return;
        };
        let Some(name_str) = name.to_str() else {
            reply.error(fuser::Errno::EINVAL);
            return;
        };
        let child_path = join_path(&parent_path, name_str);

        let result = self.block_on_conn(|conn| async move {
            let mut c = conn.lock().await;
            stat_path(&mut c, &child_path).await
        });

        match result {
            Ok(Some(entry)) => {
                let ino = {
                    self.inodes
                        .lock()
                        .unwrap()
                        .ino_for_path(&join_path(&parent_path, name_str))
                };
                let attr = make_attr(fuser::INodeNo(ino), &entry);
                reply.entry(
                    &std::time::Duration::from_secs(1),
                    &attr,
                    fuser::Generation(0),
                );
            }
            Ok(None) => reply.error(fuser::Errno::ENOENT),
            Err(_) => reply.error(fuser::Errno::EIO),
        }
    }

    fn getattr(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        _fh: Option<fuser::FileHandle>,
        reply: fuser::ReplyAttr,
    ) {
        let path = { self.inodes.lock().unwrap().path_for(ino) };
        let Some(path) = path else {
            reply.error(fuser::Errno::ENOENT);
            return;
        };

        let result = self.block_on_conn(|conn| async move {
            let mut c = conn.lock().await;
            stat_path(&mut c, &path).await
        });

        match result {
            Ok(Some(entry)) => {
                let attr = make_attr(ino, &entry);
                reply.attr(&std::time::Duration::from_secs(1), &attr);
            }
            Ok(None) => reply.error(fuser::Errno::ENOENT),
            Err(_) => reply.error(fuser::Errno::EIO),
        }
    }

    fn readdir(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        _fh: fuser::FileHandle,
        offset: u64,
        mut reply: fuser::ReplyDirectory,
    ) {
        let path = { self.inodes.lock().unwrap().path_for(ino) };
        let Some(path) = path else {
            reply.error(fuser::Errno::ENOENT);
            return;
        };

        let entries = self.block_on_conn(|conn| {
            let path = path.clone();
            async move {
                let mut c = conn.lock().await;
                ls_path(&mut c, &path).await
            }
        });
        let entries = match entries {
            Ok(e) => e,
            Err(_) => {
                reply.error(fuser::Errno::EIO);
                return;
            }
        };

        // ".." reuses this directory's own inode rather than the true
        // parent's — a cosmetic simplification (most tools resolve ".."
        // by path, not by raw inode lookup).
        let mut all: Vec<(u64, fuser::FileType, String)> = vec![
            (ino.0, fuser::FileType::Directory, ".".to_string()),
            (ino.0, fuser::FileType::Directory, "..".to_string()),
        ];
        {
            let mut table = self.inodes.lock().unwrap();
            for entry in &entries {
                let child_path = join_path(&path, &entry.name);
                let child_ino = table.ino_for_path(&child_path);
                let (kind, _) = mode_to_kind_and_perm(entry.mode);
                all.push((child_ino, kind, entry.name.clone()));
            }
        }

        for (i, (e_ino, kind, name)) in all.iter().enumerate().skip(offset as usize) {
            if reply.add(fuser::INodeNo(*e_ino), (i + 1) as u64, *kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn open(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        _flags: fuser::OpenFlags,
        reply: fuser::ReplyOpen,
    ) {
        let path = { self.inodes.lock().unwrap().path_for(ino) };
        let Some(path) = path else {
            reply.error(fuser::Errno::ENOENT);
            return;
        };

        let content = self.block_on_conn(|conn| {
            let path = path.clone();
            async move {
                let mut c = conn.lock().await;
                get_path(&mut c, &path).await
            }
        });

        match content {
            Ok(bytes) => {
                let fh = self
                    .next_fh
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.open_files.lock().unwrap().insert(fh, bytes);
                reply.opened(fuser::FileHandle(fh), fuser::FopenFlags::empty());
            }
            Err(_) => reply.error(fuser::Errno::EIO),
        }
    }

    fn read(
        &self,
        _req: &fuser::Request,
        _ino: fuser::INodeNo,
        fh: fuser::FileHandle,
        offset: u64,
        size: u32,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: fuser::ReplyData,
    ) {
        let files = self.open_files.lock().unwrap();
        let Some(content) = files.get(&fh.0) else {
            reply.error(fuser::Errno::EBADF);
            return;
        };
        let offset = offset as usize;
        if offset >= content.len() {
            reply.data(&[]);
            return;
        }
        let end = (offset + size as usize).min(content.len());
        reply.data(&content[offset..end]);
    }

    fn release(
        &self,
        _req: &fuser::Request,
        _ino: fuser::INodeNo,
        fh: fuser::FileHandle,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        self.open_files.lock().unwrap().remove(&fh.0);
        reply.ok();
    }
}

#[cfg(all(test, feature = "fuse"))]
mod tests {
    use super::*;
    use seam_protocol::api::{Client, Server};
    use seam_protocol::handshake::IdentityKeypair;

    /// Drives the same STAT_PATH/LS_PATH/GET_PATH request/response logic
    /// `run_recv`'s loop and the client-side `stat_path`/`ls_path`/`get_path`
    /// helpers use in production, over a real Client/Server pair on
    /// loopback — the same "test the reusable core directly, skip the SSH
    /// bootstrap/CLI wrapper" pattern `recv.rs`'s tests use. This is the
    /// part that can actually be exercised in a sandboxed environment
    /// without a real FUSE mount (no `/dev/fuse` device here).
    #[tokio::test]
    async fn stat_ls_get_path_roundtrip() {
        let root_dir = tempfile::tempdir().unwrap();
        std::fs::write(root_dir.path().join("hello.txt"), b"hello mount world").unwrap();
        std::fs::create_dir(root_dir.path().join("sub")).unwrap();
        std::fs::write(root_dir.path().join("sub").join("nested.txt"), b"nested").unwrap();
        let root = root_dir.path().to_path_buf();
        let root_str = root.to_string_lossy().into_owned();

        let server_id = IdentityKeypair::generate();
        let server_x25519 = server_id.x25519_public.to_bytes();
        let server_kem_pk = server_id.kem_pk.clone();
        let mut server = Server::bind("127.0.0.1:0".parse().unwrap(), server_id)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        let (server_conn, mut client_conn) =
            tokio::join!(async { server.accept().await.unwrap() }, async {
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
            });

        // Mirrors run_recv's request loop, serving exactly the 4 requests
        // this test makes.
        let server_task = tokio::spawn(async move {
            let mut conn = server_conn;
            for _ in 0..4 {
                let sid = proto::wait_for_stream(&mut conn).await.unwrap();
                let mut buf = Vec::new();
                let frame = proto::read_frame(&mut conn, sid, &mut buf).await.unwrap();
                match frame[0] {
                    proto::STAT_PATH => handle_stat_path(&mut conn, sid, &root, &frame[1..])
                        .await
                        .unwrap(),
                    proto::LS_PATH => handle_ls_path(&mut conn, sid, &root, &frame[1..])
                        .await
                        .unwrap(),
                    proto::GET_PATH => handle_get_path(&mut conn, sid, &root, &frame[1..])
                        .await
                        .unwrap(),
                    t => panic!("unexpected request type 0x{t:02x}"),
                }
            }
        });

        // stat_path on the root itself must report a directory.
        let root_entry = stat_path(&mut client_conn, &root_str)
            .await
            .unwrap()
            .expect("root should exist");
        assert_eq!(
            mode_to_kind_and_perm(root_entry.mode).0,
            fuser::FileType::Directory
        );

        // stat_path on a path that doesn't exist must return None, not error.
        let missing = stat_path(&mut client_conn, &format!("{root_str}/nope"))
            .await
            .unwrap();
        assert!(missing.is_none());

        // ls_path on the root lists both entries.
        let entries = ls_path(&mut client_conn, &root_str).await.unwrap();
        let mut names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["hello.txt", "sub"]);

        // get_path fetches the exact file content, checksum-verified.
        let content = get_path(&mut client_conn, &format!("{root_str}/hello.txt"))
            .await
            .unwrap();
        assert_eq!(content, b"hello mount world");

        server_task.await.unwrap();
    }

    /// A path escaping the mount root (or containing `..`) must be refused
    /// rather than served — see `validate_path`.
    #[test]
    fn validate_path_rejects_traversal_and_escape() {
        let root = std::path::Path::new("/mnt/data");
        assert!(validate_path(root, "/mnt/data/file.txt").is_ok());
        assert!(validate_path(root, "/mnt/data/../etc/passwd").is_err());
        assert!(validate_path(root, "/etc/passwd").is_err());
    }
}
