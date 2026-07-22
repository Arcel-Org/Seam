/// `seam mount` — mount a remote Seam filesystem via FUSE.
///
/// When compiled with the `fuse` feature (`--features fuse`), this command
/// mounts a remote directory at a local mount point using FUSE. Without the
/// feature, it returns a helpful error.
///
/// Usage:
///   seam mount user@host:/remote/path /local/mountpoint
use anyhow::{Result, bail};
use clap::Args;

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
        bail!(
            "seam was not compiled with FUSE support (enable the 'fuse' feature).\n\
             Rebuild with: cargo build --features fuse"
        );
    }
}

// ── FUSE implementation (only compiled when the `fuse` feature is enabled) ──

#[cfg(feature = "fuse")]
async fn run_fuse(args: MountArgs) -> Result<()> {
    use std::ffi::OsStr;

    let mountpoint = std::path::PathBuf::from(&args.mountpoint);
    if !mountpoint.exists() {
        std::fs::create_dir_all(&mountpoint)?;
    }

    eprintln!(
        "mount: connecting to {} → {}",
        args.remote,
        mountpoint.display()
    );
    eprintln!(
        "warning: seam mount's filesystem is not yet implemented — it will \
         mount successfully but always present as an empty directory. \
         Use `seam cp`/`seam sync`/`seam watch` for real file transfer."
    );

    let fs = SeamFS::new(args.remote.clone());
    let mut options = vec![
        fuser::MountOption::FSName("seam".to_string()),
        fuser::MountOption::AutoUnmount,
    ];
    if args.read_only {
        options.push(fuser::MountOption::RO);
    }

    fuser::mount2(fs, &mountpoint, &options)
        .map_err(|e| anyhow::anyhow!("FUSE mount failed: {e}"))?;

    Ok(())
}

#[cfg(feature = "fuse")]
struct SeamFS {
    remote: String,
}

#[cfg(feature = "fuse")]
impl SeamFS {
    fn new(remote: String) -> Self {
        Self { remote }
    }
}

#[cfg(feature = "fuse")]
impl fuser::Filesystem for SeamFS {
    fn lookup(
        &mut self,
        _req: &fuser::Request<'_>,
        _parent: u64,
        _name: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        reply.error(libc::ENOENT);
    }

    fn getattr(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        _fh: Option<u64>,
        reply: fuser::ReplyAttr,
    ) {
        if ino == fuser::FUSE_ROOT_ID {
            let now = std::time::SystemTime::now();
            let attr = fuser::FileAttr {
                ino: fuser::FUSE_ROOT_ID,
                size: 0,
                blocks: 0,
                atime: now,
                mtime: now,
                ctime: now,
                crtime: now,
                kind: fuser::FileType::Directory,
                perm: 0o755,
                nlink: 2,
                uid: unsafe { libc::getuid() },
                gid: unsafe { libc::getgid() },
                rdev: 0,
                blksize: 512,
                flags: 0,
            };
            reply.attr(&std::time::Duration::from_secs(1), &attr);
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn readdir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: fuser::ReplyDirectory,
    ) {
        if ino != fuser::FUSE_ROOT_ID {
            reply.error(libc::ENOENT);
            return;
        }
        let entries = [
            (fuser::FUSE_ROOT_ID, fuser::FileType::Directory, "."),
            (fuser::FUSE_ROOT_ID, fuser::FileType::Directory, ".."),
        ];
        for (i, (ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(*ino, (i + 1) as i64, *kind, name) {
                break;
            }
        }
        reply.ok();
    }
}
