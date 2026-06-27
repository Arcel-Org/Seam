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
use seam_protocol::crypto::CipherSuite;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use crate::ssh;

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

pub async fn run(args: WatchArgs, fips_mode: bool) -> Result<()> {
    let local_path = PathBuf::from(&args.local);
    if !local_path.exists() || !local_path.is_dir() {
        bail!("local path must be an existing directory: {}", args.local);
    }

    let (remote_info, remote_path) = ssh::parse_remote(&args.remote)
        .ok_or_else(|| anyhow!("invalid remote spec: {} (use user@host:/path)", args.remote))?;

    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let compress = !args.no_compress && cfg.compress;
    let cipher_str = if fips_mode { "aes256gcm" } else { &cfg.cipher };
    let _cipher = CipherSuite::parse(cipher_str).unwrap_or_default();

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

    // Sync loop: check for debounced changes, sync them via seam cp.
    let debounce = Duration::from_millis(debounce_ms);
    let mut sync_count: u64 = 0;

    loop {
        tokio::time::sleep(Duration::from_millis(50)).await;

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

        // For each changed file, sync it via seam cp (push mode).
        // We re-use the SSH bootstrap for each batch. For production use,
        // a persistent connection pool would be more efficient.
        // TODO: maintain a persistent Seam session across batches.
        for rel in &ready {
            let src = local_path.join(rel);
            if !src.exists() {
                eprintln!("    (deleted, skipping: {})", rel.display());
                continue;
            }

            let dest_spec = format!(
                "{}:{}/{}",
                remote_info.target(),
                remote_path.trim_end_matches('/'),
                rel.display()
            );

            let copy_args = super::copy::CopyArgs {
                src: src.to_string_lossy().to_string(),
                dest: dest_spec,
                no_compress: !compress,
                resume: false,
                direct: None,
                rate: None,
                multipath: None,
                multipath_redundant: false,
                parallel: 1,
            };

            if let Err(e) = super::copy::run(copy_args, fips_mode).await {
                eprintln!("    ERROR syncing {}: {e}", rel.display());
            } else if args.verbose {
                eprintln!("    OK: {}", rel.display());
            }
        }
    }
}
