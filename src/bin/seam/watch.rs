/// `seam watch` — continuous directory sync with filesystem event watching.
///
/// Usage:
///   seam watch <local-dir> user@host:<remote-dir>
///
/// Watches `local-dir` for filesystem changes (using the `notify` crate) and
/// syncs changed files to the remote in real-time. Changes are debounced with
/// a 100ms window so rapid edits are batched. Displays a live TUI showing
/// which files are being synced.
use anyhow::{Result, anyhow, bail};
use clap::Args;
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use seam_protocol::api::SeamConn;
use seam_protocol::crypto::CipherSuite;
use seam_protocol::session::stream::StreamId;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use crate::{connect, proto, ssh};

#[derive(Args)]
pub struct WatchArgs {
    /// Local directory to watch for changes
    pub local: String,

    /// Remote destination: user@host:/remote/dir
    pub remote: String,

    /// Debounce window in milliseconds (batch rapid changes)
    #[arg(long, default_value_t = 100)]
    pub debounce_ms: u64,

    /// Disable zstd compression
    #[arg(long)]
    pub no_compress: bool,

    /// SSH port for bootstrap connection
    #[arg(long)]
    pub ssh_port: Option<u16>,

    /// Show verbose sync log
    #[arg(long)]
    pub verbose: bool,
}

/// A Seam connection to the remote receiver kept alive for the whole `seam
/// watch` session. Every sync batch reuses the same connection (and control
/// stream) instead of re-bootstrapping over SSH and redoing the post-quantum
/// handshake for every debounce cycle.
struct PersistentPush {
    conn: SeamConn,
    ctrl_sid: StreamId,
    // Kept alive for the session's duration — dropping it kills the SSH
    // channel and the remote `recv` process.
    _remote_process: Child,
}

impl PersistentPush {
    async fn connect(
        remote: &ssh::RemoteInfo,
        remote_path: &str,
        cipher: CipherSuite,
        fips_mode: bool,
    ) -> Result<Self> {
        // No `--once`: the remote receiver stays up and accepts further
        // HELLO/file rounds on this same connection for subsequent batches.
        let subcmd = format!(
            "recv {} --port 0{}",
            connect::shell_quote(remote_path),
            if fips_mode { " --fips-mode" } else { "" }
        );
        let (conn, remote_process) =
            connect::bootstrap_and_connect(remote, &remote.host, &subcmd, cipher).await?;
        eprintln!("  persistent session established — further syncs reuse this connection");
        let ctrl_sid = conn.open_stream().await;

        Ok(Self {
            conn,
            ctrl_sid,
            _remote_process: remote_process,
        })
    }

    async fn push_batch(
        &mut self,
        base: &Path,
        files: &[(String, std::fs::Metadata)],
        compress: bool,
        fips_mode: bool,
    ) -> Result<()> {
        super::copy::push_files(
            &mut self.conn,
            self.ctrl_sid,
            base,
            files,
            compress,
            false, // resume: watch always sends the current file contents
            1,     // parallel: batches are many small files, not one big one
            fips_mode,
            None, // rate limiting isn't exposed on `seam watch` today
        )
        .await
    }

    async fn close(self) {
        // Tell the remote receiver we're done for good, in place of the next
        // HELLO, so it exits right away instead of only noticing once its
        // connection-idle timeout eventually fires.
        let _ = proto::send_frame(&self.conn, self.ctrl_sid, &[proto::BYE]).await;
        self.conn.close().await;
    }
}

pub async fn run(args: WatchArgs, fips_mode: bool) -> Result<()> {
    let local_path = PathBuf::from(&args.local);
    if !local_path.exists() || !local_path.is_dir() {
        bail!("local path must be an existing directory: {}", args.local);
    }

    let (mut remote_info, remote_path) = ssh::parse_remote(&args.remote)
        .ok_or_else(|| anyhow!("invalid remote spec: {} (use user@host:/path)", args.remote))?;
    if args.ssh_port.is_some() {
        remote_info.ssh_port = args.ssh_port;
    }

    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let compress = !args.no_compress && cfg.compress;
    let cipher_str = if fips_mode { "aes256gcm" } else { &cfg.cipher };
    let cipher = CipherSuite::parse(cipher_str).unwrap_or_default();

    eprintln!(
        "watching {} → {}:{}",
        local_path.display(),
        remote_info.target(),
        remote_path
    );
    eprintln!("  debounce: {}ms  compress: {compress}", args.debounce_ms);
    eprintln!("  Ctrl-C to stop");
    eprintln!();

    // Shared queue of changed paths (relative to local_path).
    // The watcher thread pushes to this; the sync loop drains it.
    let pending: Arc<StdMutex<HashMap<PathBuf, Instant>>> = Arc::new(StdMutex::new(HashMap::new()));
    let pending_watcher = pending.clone();
    let local_path_clone = local_path.clone();

    // Set up the filesystem watcher.
    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher = RecommendedWatcher::new(tx, notify::Config::default())
        .map_err(|e| anyhow!("watcher init failed: {e}"))?;
    watcher
        .watch(&local_path, RecursiveMode::Recursive)
        .map_err(|e| anyhow!("watch failed: {e}"))?;

    // Spawn a thread to forward events into the pending map.
    let debounce_ms = args.debounce_ms;
    std::thread::spawn(move || {
        for res in rx {
            match res {
                Ok(event) => {
                    // Only care about create/modify/remove events.
                    let is_relevant = matches!(
                        event.kind,
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                    );
                    if !is_relevant {
                        continue;
                    }
                    let mut map = pending_watcher.lock().unwrap();
                    for path in event.paths {
                        // Only track files (not directories).
                        if path.is_file() {
                            let rel = match path.strip_prefix(&local_path_clone) {
                                Ok(r) => r.to_path_buf(),
                                Err(_) => continue,
                            };
                            map.insert(rel, Instant::now());
                        }
                    }
                }
                Err(e) => eprintln!("  watch error: {e}"),
            }
        }
    });

    // Establish the persistent connection up front so the first sync cycle
    // doesn't pay bootstrap+handshake latency in the middle of a batch.
    let mut session =
        Some(PersistentPush::connect(&remote_info, &remote_path, cipher, fips_mode).await?);

    // Sync loop: check for debounced changes, sync them over the persistent connection.
    let debounce = Duration::from_millis(debounce_ms);
    let mut sync_count: u64 = 0;

    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\n  shutting down…");
                if let Some(s) = session.take() {
                    s.close().await;
                }
                return Ok(());
            }
        }

        // Collect files that have been stable for debounce_ms.
        let ready: Vec<PathBuf> = {
            let mut map = pending.lock().unwrap();
            let now = Instant::now();
            let ready: Vec<PathBuf> = map
                .iter()
                .filter(|&(_, ts)| now.duration_since(*ts) >= debounce)
                .map(|(p, _)| p.clone())
                .collect();
            for p in &ready {
                map.remove(p);
            }
            ready
        };

        if ready.is_empty() {
            continue;
        }

        sync_count += 1;
        let n = ready.len();
        eprintln!("  [sync #{sync_count}] {} file(s) changed:", n);
        for p in &ready {
            eprintln!("    ~ {}", p.display());
        }

        let batch: Vec<(String, std::fs::Metadata)> = ready
            .iter()
            .filter_map(|rel| {
                let src = local_path.join(rel);
                match src.metadata() {
                    Ok(meta) if meta.is_file() => Some((rel.to_string_lossy().to_string(), meta)),
                    _ => {
                        eprintln!("    (deleted, skipping: {})", rel.display());
                        None
                    }
                }
            })
            .collect();

        if batch.is_empty() {
            continue;
        }

        if session.is_none() {
            match PersistentPush::connect(&remote_info, &remote_path, cipher, fips_mode).await {
                Ok(s) => session = Some(s),
                Err(e) => {
                    eprintln!("    ERROR reconnecting: {e} — will retry next sync");
                    continue;
                }
            }
        }

        let sess = session.as_mut().expect("session established above");
        match sess
            .push_batch(&local_path, &batch, compress, fips_mode)
            .await
        {
            Ok(()) => {
                if args.verbose {
                    for (name, _) in &batch {
                        eprintln!("    OK: {name}");
                    }
                }
            }
            Err(e) => {
                eprintln!("    ERROR syncing batch: {e} — will reconnect next sync");
                if let Some(s) = session.take() {
                    s.close().await;
                }
            }
        }
    }
}
