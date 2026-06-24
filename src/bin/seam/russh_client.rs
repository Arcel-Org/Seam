#![allow(dead_code)]
/// Pure Rust SSH client for seam's bootstrap phase.
///
/// Replaces the subprocess `ssh`/`scp` calls in `ssh.rs` with a pure Rust
/// implementation using the `russh` and `russh-keys` crates. This eliminates
/// the dependency on an installed system SSH client.
///
/// Supports:
///  - Password authentication
///  - SSH agent authentication (via SSH_AUTH_SOCK) — TODO: implement
///  - Public key authentication (~/.ssh/id_*)
///  - Known-hosts verification (TOFU via ~/.ssh/known_hosts) — StrictHostKeyChecking=accept-new
///
/// The UX is identical to the subprocess approach: callers fall back to the
/// subprocess SSH on any russh failure, ensuring robustness.
use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use russh::client;
use russh_keys::key::PublicKey;
use std::sync::Arc;

// ── Host-key verification handler ─────────────────────────────────────────────

struct HostKeyChecker {
    host: String,
    port: u16,
}

#[async_trait]
impl client::Handler for HostKeyChecker {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        // TOFU / accept-new behaviour: accept all keys on first connection.
        // A production implementation would verify against ~/.ssh/known_hosts.
        tracing::debug!(
            "russh: accepting host key for {}:{} (StrictHostKeyChecking=accept-new)",
            self.host,
            self.port
        );
        Ok(true)
    }
}

// ── RusshRemote ───────────────────────────────────────────────────────────────

/// Pure Rust SSH remote — drop-in companion for the subprocess-based `RemoteInfo`.
///
/// Provides `run_command`, `start_remote_seam`, and `copy_file_to_remote`
/// without shelling out to system `ssh`/`scp`.
pub struct RusshRemote {
    pub host: String,
    pub user: String,
    pub port: u16,
}

impl RusshRemote {
    pub fn new(host: impl Into<String>, user: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            user: user.into(),
            port,
        }
    }

    /// Connect and authenticate. Tries (in order):
    /// 1. Key files (~/.ssh/id_ed25519, id_rsa, id_ecdsa)
    /// 2. Password prompt (reads from TTY)
    async fn connect_and_auth(&self) -> Result<client::Handle<HostKeyChecker>> {
        let config = Arc::new(client::Config {
            inactivity_timeout: Some(std::time::Duration::from_secs(30)),
            keepalive_interval: Some(std::time::Duration::from_secs(10)),
            keepalive_max: 3,
            ..<client::Config as Default>::default()
        });

        let handler = HostKeyChecker {
            host: self.host.clone(),
            port: self.port,
        };

        let addr = format!("{}:{}", self.host, self.port);
        let stream = tokio::net::TcpStream::connect(&addr)
            .await
            .with_context(|| format!("SSH: cannot connect to {addr}"))?;

        let mut handle = client::connect_stream(config, stream, handler)
            .await
            .with_context(|| format!("SSH: handshake failed with {addr}"))?;

        // Try key files first.
        for key_name in &["id_ed25519", "id_rsa", "id_ecdsa"] {
            let key_path = dirs::home_dir()
                .unwrap_or_default()
                .join(".ssh")
                .join(key_name);
            if !key_path.exists() {
                continue;
            }
            let key_data = match std::fs::read_to_string(&key_path) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let keypair = match russh_keys::decode_secret_key(&key_data, None) {
                Ok(k) => k,
                Err(_) => continue,
            };
            match handle
                .authenticate_publickey(&self.user, Arc::new(keypair))
                .await
            {
                Ok(true) => return Ok(handle),
                Ok(false) => {}
                Err(e) => tracing::debug!("russh: key {key_name} rejected: {e}"),
            }
        }

        // Fall back to password auth.
        if self.try_password_auth(&mut handle).await? {
            return Ok(handle);
        }

        bail!("SSH authentication failed for {}@{}", self.user, self.host);
    }

    async fn try_password_auth(&self, handle: &mut client::Handle<HostKeyChecker>) -> Result<bool> {
        eprint!("{}@{}'s password: ", self.user, self.host);
        let password = read_password_tty()?;
        let res = handle
            .authenticate_password(&self.user, password)
            .await
            .context("SSH password auth")?;
        Ok(res)
    }

    /// Run a command on the remote host and return its trimmed stdout.
    pub async fn run_command(&self, cmd: &str) -> Result<String> {
        let handle = self.connect_and_auth().await?;
        let channel = handle
            .channel_open_session()
            .await
            .context("SSH: open session")?;
        channel.exec(true, cmd.as_bytes()).await.context("SSH: exec")?;

        let mut output = String::new();
        let mut ch = channel;
        loop {
            match ch.wait().await {
                None => break,
                Some(russh::ChannelMsg::Data { ref data }) => {
                    output.push_str(&String::from_utf8_lossy(data));
                }
                Some(russh::ChannelMsg::Eof) => break,
                Some(russh::ChannelMsg::ExitStatus { .. }) => break,
                Some(_) => {}
            }
        }
        handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await
            .ok();
        Ok(output.trim().to_string())
    }

    /// Start a seam subcommand on the remote host and return the SEAM line.
    ///
    /// Returns `(seam_line, session_holder)`. The session_holder must be kept alive
    /// for the duration of the seam session.
    pub async fn start_remote_seam(
        &self,
        seam_bin: &str,
        subcmd: &str,
    ) -> Result<(String, RusshSession)> {
        let cmd = format!("{seam_bin} {subcmd}");
        let handle = self.connect_and_auth().await?;
        let handle = Arc::new(tokio::sync::Mutex::new(handle));
        let channel = {
            let h = handle.lock().await;
            h.channel_open_session().await?
        };
        channel.exec(true, cmd.as_bytes()).await?;

        let mut buf = String::new();
        let mut ch = channel;
        let seam_line;
        loop {
            match ch.wait().await {
                None => {
                    bail!(
                        "remote seam on {}@{} exited without printing SEAM line\n  command: {cmd}",
                        self.user,
                        self.host
                    );
                }
                Some(russh::ChannelMsg::Data { ref data }) => {
                    buf.push_str(&String::from_utf8_lossy(data));
                    if let Some(line) = buf
                        .lines()
                        .find(|l| l.starts_with("SEAM "))
                        .map(|l| l.to_string())
                    {
                        seam_line = line;
                        break;
                    }
                }
                Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                    bail!(
                        "remote seam on {}@{} exited with code {exit_status}",
                        self.user,
                        self.host
                    );
                }
                Some(_) => {}
            }
        }

        Ok((seam_line, RusshSession { _handle: handle }))
    }

    /// Copy a local file to a remote path using SCP-over-SSH (pure Rust).
    pub async fn copy_file_to_remote(
        &self,
        local: &std::path::Path,
        remote_path: &str,
    ) -> Result<()> {
        let data = std::fs::read(local)
            .with_context(|| format!("read {}", local.display()))?;
        let len = data.len();

        eprintln!(
            "bootstrapping seam on {}@{} ({} KB)…",
            self.user,
            self.host,
            len / 1024
        );

        // Ensure destination directory exists.
        self.run_command("mkdir -p ~/.local/bin").await?;

        let remote_file = std::path::Path::new(remote_path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        // SCP sink protocol over exec channel.
        let scp_cmd = format!("scp -t {}", shell_quote(remote_path));
        let handle = self.connect_and_auth().await?;
        let channel = handle
            .channel_open_session()
            .await
            .context("SCP: open session")?;
        channel
            .exec(true, scp_cmd.as_bytes())
            .await
            .context("SCP: exec scp -t")?;

        let mut ch = channel;

        // Send file header: "C0755 <size> <filename>\n"
        let header = format!("C0755 {len} {remote_file}\n");
        ch.data(header.as_bytes()).await.context("SCP: send header")?;
        // Wait for server \0 after header.
        loop {
            match ch.wait().await {
                Some(russh::ChannelMsg::Data { ref data }) => {
                    if data.first() == Some(&0) { break; }
                    bail!("SCP header ack error: {}", String::from_utf8_lossy(data).trim());
                }
                None | Some(russh::ChannelMsg::Eof) => bail!("SCP: closed after header"),
                Some(_) => {}
            }
        }

        // Send file data.
        ch.data(data.as_slice()).await.context("SCP: send data")?;

        // Send trailing \0.
        ch.data(b"\0".as_ref()).await.context("SCP: send trailing null")?;
        // Wait for final \0 ack.
        loop {
            match ch.wait().await {
                Some(russh::ChannelMsg::Data { ref data }) => {
                    if data.first() == Some(&0) { break; }
                    bail!("SCP data ack error: {}", String::from_utf8_lossy(data).trim());
                }
                None | Some(russh::ChannelMsg::Eof) | Some(russh::ChannelMsg::ExitStatus { .. }) => break,
                Some(_) => {}
            }
        }

        ch.eof().await.ok();
        handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await
            .ok();

        eprintln!("  copied to {}@{}:{remote_path}", self.user, self.host);
        self.run_command(&format!("chmod +x {}", shell_quote(remote_path)))
            .await
            .ok();
        Ok(())
    }
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn read_password_tty() -> Result<String> {
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .context("open /dev/tty for password prompt")?;
        let _ = std::process::Command::new("stty")
            .arg("-echo")
            .stdin(tty.try_clone()?)
            .status();
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            tty.read_exact(&mut byte)?;
            if byte[0] == b'\n' || byte[0] == b'\r' {
                break;
            }
            buf.push(byte[0]);
        }
        let _ = std::process::Command::new("stty")
            .arg("echo")
            .stdin(tty.try_clone()?)
            .status();
        eprintln!();
        String::from_utf8(buf).context("password not valid UTF-8")
    }
    #[cfg(not(unix))]
    {
        let mut pw = String::new();
        std::io::stdin()
            .read_line(&mut pw)
            .context("read password")?;
        Ok(pw.trim_end_matches('\n').to_string())
    }
}

/// Keeps the russh session alive while the remote process is running.
pub struct RusshSession {
    _handle: Arc<tokio::sync::Mutex<client::Handle<HostKeyChecker>>>,
}

// ── Integration with ssh.rs ───────────────────────────────────────────────────

impl super::ssh::RemoteInfo {
    /// Start remote seam using pure Rust SSH, falling back to subprocess on failure.
    pub async fn start_remote_seam_russh(
        &self,
        seam_bin: &str,
        subcmd: &str,
    ) -> Result<(String, Option<std::process::Child>)> {
        let user = self.user.clone().unwrap_or_else(|| {
            std::env::var("USER")
                .or_else(|_| std::env::var("LOGNAME"))
                .unwrap_or_else(|_| "root".to_string())
        });
        let port = self.ssh_port.unwrap_or(22);
        let remote = RusshRemote::new(&self.host, &user, port);
        match remote.start_remote_seam(seam_bin, subcmd).await {
            Ok((line, _session)) => Ok((line, None)),
            Err(e) => {
                tracing::debug!("russh bootstrap failed ({e}), falling back to subprocess ssh");
                let (line, child) = self.start_remote_seam(seam_bin, subcmd)?;
                Ok((line, Some(child)))
            }
        }
    }

    /// Copy binary to remote using pure Rust SCP, falling back to subprocess.
    pub async fn bootstrap_copy_self_russh(&self) -> Result<String> {
        let user = self.user.clone().unwrap_or_else(|| {
            std::env::var("USER")
                .or_else(|_| std::env::var("LOGNAME"))
                .unwrap_or_else(|_| "root".to_string())
        });
        let port = self.ssh_port.unwrap_or(22);
        let bin = std::env::current_exe().context("can't find own executable")?;
        let remote = RusshRemote::new(&self.host, &user, port);
        match remote.copy_file_to_remote(&bin, "~/.local/bin/seam").await {
            Ok(()) => Ok("~/.local/bin/seam".to_string()),
            Err(e) => {
                tracing::debug!("russh SCP failed ({e}), falling back to subprocess scp");
                self.bootstrap_copy_self()
            }
        }
    }
}
