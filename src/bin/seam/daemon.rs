use anyhow::{Result, anyhow, bail};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Args)]
pub struct DaemonArgs {
    #[command(subcommand)]
    pub cmd: DaemonCmd,
}

#[derive(Subcommand)]
pub enum DaemonCmd {
    /// Start the Seam daemon in the background
    Start,
    /// Stop the running Seam daemon
    Stop,
    /// Show status of the running Seam daemon
    Status,
    /// Internal: run as the background daemon worker (do not invoke directly)
    #[command(name = "_worker", hide = true)]
    Worker,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op")]
enum DaemonRequest {
    #[serde(rename = "stop")]
    Stop,
    #[serde(rename = "status")]
    Status,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
enum DaemonResponse {
    #[serde(rename = "ok")]
    Ok { message: String },
    #[serde(rename = "status")]
    Status {
        pid: u32,
        connections: Vec<ConnectionInfo>,
    },
    #[serde(rename = "error")]
    Error { message: String },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ConnectionInfo {
    name: String,
    host: String,
    connected: bool,
}

#[derive(Deserialize, Default)]
struct DaemonConfig {
    #[serde(default)]
    connections: Vec<DaemonConnectionEntry>,
}

#[derive(Deserialize)]
struct DaemonConnectionEntry {
    name: String,
    host: String,
}

fn socket_path() -> PathBuf {
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/run/user/{uid}/seam-daemon.sock"))
}

fn pid_path() -> PathBuf {
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/run/user/{uid}/seam-daemon.pid"))
}

fn config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("seam")
        .join("daemon.toml")
}

pub async fn run(args: DaemonArgs) -> Result<()> {
    match args.cmd {
        DaemonCmd::Start => start_daemon().await,
        DaemonCmd::Stop => send_request(DaemonRequest::Stop).await,
        DaemonCmd::Status => status().await,
        DaemonCmd::Worker => run_daemon_server().await,
    }
}

/// Probe whether a daemon is already listening on `sock_path`.
///
/// Returns `Some(pid)` if a connection succeeds — `pid` is read from
/// `pid_file` when it exists and parses cleanly, `None` otherwise (a running
/// daemon whose PID we simply couldn't determine still counts as running).
/// Returns the outer `None` (plain "not running") when the connect attempt
/// fails or times out.
///
/// Takes explicit paths (rather than calling [`socket_path`]/[`pid_path`]
/// internally) so tests can point it at an isolated tempdir instead of the
/// real per-user runtime directory.
async fn probe_daemon_at(
    sock_path: &std::path::Path,
    pid_file: &std::path::Path,
) -> Option<Option<u32>> {
    let connect = tokio::net::UnixStream::connect(sock_path);
    match tokio::time::timeout(std::time::Duration::from_millis(500), connect).await {
        Ok(Ok(_stream)) => {
            let pid = std::fs::read_to_string(pid_file)
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok());
            Some(pid)
        }
        _ => None,
    }
}

/// Probe whether a daemon is already listening on the real daemon socket for
/// this user.
async fn probe_existing_daemon() -> Option<Option<u32>> {
    probe_daemon_at(&socket_path(), &pid_path()).await
}

async fn start_daemon() -> Result<()> {
    // Refuse to spawn a second daemon on top of one that's already running:
    // run_daemon_server() unconditionally unlinks and rebinds the socket, so
    // a second `seam daemon start` would silently steal the socket out from
    // under the first (still-alive) daemon, orphaning it — and overwrite the
    // pid file so `seam daemon stop` could no longer reach the orphan either.
    if let Some(pid) = probe_existing_daemon().await {
        match pid {
            Some(pid) => {
                eprintln!("seam daemon already running (pid {pid}) — use `seam daemon stop` first")
            }
            None => eprintln!("seam daemon already running — use `seam daemon stop` first"),
        }
        bail!("daemon already running");
    }

    // Spawn a new detached process rather than fork()-in-async.
    // fork() inside a tokio runtime leaves the child with corrupted
    // thread-pool state; spawning a fresh process avoids that entirely.
    let exe =
        std::env::current_exe().map_err(|e| anyhow!("cannot locate current executable: {e}"))?;

    let child = std::process::Command::new(&exe)
        .args(["daemon", "_worker"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| anyhow!("failed to spawn daemon worker: {e}"))?;

    let pid = child.id();
    std::fs::write(pid_path(), format!("{pid}\n"))?;
    println!("seam daemon started (pid {pid})");
    println!("  socket: {}", socket_path().display());
    Ok(())
}

async fn run_daemon_server() -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    let sock_path = socket_path();
    // Remove stale socket
    let _ = std::fs::remove_file(&sock_path);

    let listener = UnixListener::bind(&sock_path)
        .map_err(|e| anyhow!("bind Unix socket {}: {e}", sock_path.display()))?;

    // Load daemon config
    let config: DaemonConfig = if config_path().exists() {
        let text = std::fs::read_to_string(config_path())?;
        toml::from_str(&text).unwrap_or_default()
    } else {
        DaemonConfig::default()
    };

    let connections: std::sync::Arc<tokio::sync::Mutex<Vec<ConnectionInfo>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(
            config
                .connections
                .iter()
                .map(|e| ConnectionInfo {
                    name: e.name.clone(),
                    host: e.host.clone(),
                    connected: false,
                })
                .collect(),
        ));

    let pid = std::process::id();

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => break,
        };
        let conns = connections.clone();
        tokio::spawn(async move {
            let (reader, mut writer) = tokio::io::split(stream);
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let req: DaemonRequest = match serde_json::from_str(&line) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let resp = match req {
                    DaemonRequest::Stop => {
                        let resp = DaemonResponse::Ok {
                            message: "daemon stopping".into(),
                        };
                        let _ = writer
                            .write_all(
                                format!("{}\n", serde_json::to_string(&resp).unwrap()).as_bytes(),
                            )
                            .await;
                        std::process::exit(0);
                    }
                    DaemonRequest::Status => {
                        let conns_snap = conns.lock().await.clone();
                        DaemonResponse::Status {
                            pid,
                            connections: conns_snap,
                        }
                    }
                };
                let line = format!("{}\n", serde_json::to_string(&resp).unwrap());
                let _ = writer.write_all(line.as_bytes()).await;
            }
        });
    }
    Ok(())
}

async fn send_request(req: DaemonRequest) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    let sock_path = socket_path();
    let stream = UnixStream::connect(&sock_path)
        .await
        .map_err(|_| anyhow!("daemon not running (no socket at {})", sock_path.display()))?;

    let (reader, mut writer) = tokio::io::split(stream);
    let req_line = format!("{}\n", serde_json::to_string(&req)?);
    writer.write_all(req_line.as_bytes()).await?;

    let mut lines = BufReader::new(reader).lines();
    if let Ok(Some(line)) = lines.next_line().await {
        let resp: DaemonResponse =
            serde_json::from_str(&line).map_err(|e| anyhow!("invalid response: {e}"))?;
        match resp {
            DaemonResponse::Ok { message } => println!("{message}"),
            DaemonResponse::Error { message } => bail!("{message}"),
            DaemonResponse::Status { .. } => {}
        }
    }
    Ok(())
}

async fn status() -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    let sock_path = socket_path();
    let stream = UnixStream::connect(&sock_path)
        .await
        .map_err(|_| anyhow!("daemon not running (no socket at {})", sock_path.display()))?;

    let (reader, mut writer) = tokio::io::split(stream);
    let req = DaemonRequest::Status;
    let req_line = format!("{}\n", serde_json::to_string(&req)?);
    writer.write_all(req_line.as_bytes()).await?;

    let mut lines = BufReader::new(reader).lines();
    if let Ok(Some(line)) = lines.next_line().await {
        let resp: DaemonResponse =
            serde_json::from_str(&line).map_err(|e| anyhow!("invalid response: {e}"))?;
        match resp {
            DaemonResponse::Status { pid, connections } => {
                println!("seam daemon running (pid {pid})");
                if connections.is_empty() {
                    println!("  no configured connections");
                } else {
                    for c in &connections {
                        let status = if c.connected {
                            "connected"
                        } else {
                            "disconnected"
                        };
                        println!("  {} → {}  [{}]", c.name, c.host, status);
                    }
                }
            }
            DaemonResponse::Ok { message } => println!("{message}"),
            DaemonResponse::Error { message } => bail!("{message}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for the "seam daemon start" double-spawn bug: previously
    /// `start_daemon()` never checked whether a daemon was already listening before
    /// spawning a new worker, so running it twice let the second worker's
    /// `run_daemon_server()` unlink and rebind the socket out from under the first
    /// (still-alive) daemon, orphaning it. `probe_daemon_at()` is the check that
    /// now guards against that — verify it detects a listener on the socket path
    /// and reports the pid recorded in the pid file.
    #[tokio::test]
    async fn probe_daemon_at_detects_listener_and_reads_pid() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("seam-daemon.sock");
        let pid_file = dir.path().join("seam-daemon.pid");
        std::fs::write(&pid_file, "4242\n").unwrap();

        let _listener = tokio::net::UnixListener::bind(&sock_path).unwrap();

        let result = probe_daemon_at(&sock_path, &pid_file).await;

        assert_eq!(
            result,
            Some(Some(4242)),
            "must detect the running listener and parse the pid file"
        );
    }

    /// When no daemon is listening (stale or missing socket path), the probe must
    /// report "not running" so `start_daemon()` proceeds with a normal spawn.
    #[tokio::test]
    async fn probe_daemon_at_reports_none_when_nothing_listening() {
        let dir = tempfile::tempdir().unwrap();
        // Path that exists in a real dir but has no listener bound to it.
        let sock_path = dir.path().join("seam-daemon.sock");
        let pid_file = dir.path().join("seam-daemon.pid");

        let result = probe_daemon_at(&sock_path, &pid_file).await;

        assert_eq!(result, None, "no listener means no daemon is running");
    }

    /// If the pid file is missing or unparsable, the daemon should still be reported
    /// as running (connection succeeded) — just without a pid to print.
    #[tokio::test]
    async fn probe_daemon_at_running_with_unreadable_pid_file() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("seam-daemon.sock");
        // Deliberately do not create a pid file at all.
        let pid_file = dir.path().join("does-not-exist.pid");

        let _listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
        let result = probe_daemon_at(&sock_path, &pid_file).await;

        assert_eq!(result, Some(None), "running daemon with no readable pid");
    }
}
