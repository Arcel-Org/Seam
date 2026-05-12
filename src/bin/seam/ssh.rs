use anyhow::{Context, Result, bail};
use std::io::BufRead;
use std::process::{Child, Command, Stdio};

pub struct RemoteInfo {
    pub host: String,
    pub user: Option<String>,
    pub ssh_port: Option<u16>,
}

impl RemoteInfo {
    pub fn target(&self) -> String {
        match &self.user {
            Some(u) => format!("{}@{}", u, self.host),
            None => self.host.clone(),
        }
    }

    /// SSH args for quick non-interactive checks (BatchMode=yes, no password prompt).
    fn ssh_base_batch(&self) -> Vec<String> {
        let mut args = vec![
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
            "-o".into(),
            "ConnectTimeout=10".into(),
        ];
        if let Some(p) = self.ssh_port {
            args.push("-p".into());
            args.push(p.to_string());
        }
        args.push(self.target());
        args
    }

    /// SSH args for interactive operations (allows password prompts).
    fn ssh_base(&self) -> Vec<String> {
        let mut args = vec![
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
            "-o".into(),
            "ConnectTimeout=10".into(),
        ];
        if let Some(p) = self.ssh_port {
            args.push("-p".into());
            args.push(p.to_string());
        }
        args.push(self.target());
        args
    }

    pub fn run_command(&self, cmd: &str) -> Result<String> {
        let mut args = self.ssh_base_batch();
        args.push(cmd.to_string());
        let out = Command::new("ssh")
            .args(&args)
            .output()
            .context("ssh command failed")?;
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// Check if seam is available on remote. Returns path if found.
    pub fn seam_path(&self) -> Option<String> {
        let result = self
            .run_command("which seam 2>/dev/null || ls ~/.local/bin/seam 2>/dev/null")
            .ok()?;
        let path = result.trim().to_string();
        if path.is_empty() { None } else { Some(path) }
    }

    /// Bootstrap by copying the local seam binary to remote via SSH + scp.
    pub fn bootstrap_copy_self(&self) -> Result<String> {
        let bin = std::env::current_exe().context("can't find own executable")?;
        let binary_len = bin.metadata().context("stat own binary")?.len();

        eprintln!(
            "bootstrapping seam on {} ({} KB)…",
            self.target(),
            binary_len / 1024
        );

        // Ensure destination directory exists (interactive SSH, shows auth prompts).
        let mkdir_status = Command::new("ssh")
            .args(self.ssh_base())
            .arg("mkdir -p ~/.local/bin")
            .status()
            .context("ssh mkdir failed — check SSH access to remote")?;
        if !mkdir_status.success() {
            bail!(
                "failed to create ~/.local/bin on {} (exit {})",
                self.target(),
                mkdir_status.code().unwrap_or(-1)
            );
        }

        // Copy binary with scp (handles auth, shows progress, preserves permissions).
        let mut scp_args: Vec<String> = vec![
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
            "-o".into(),
            "ConnectTimeout=10".into(),
        ];
        if let Some(p) = self.ssh_port {
            scp_args.push("-P".into());
            scp_args.push(p.to_string());
        }
        scp_args.push(
            bin.to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 exe path"))?
                .to_string(),
        );
        scp_args.push(format!("{}:.local/bin/seam", self.target()));

        let scp_status = Command::new("scp")
            .args(&scp_args)
            .status()
            .context("scp failed — is scp installed on this machine?")?;
        if !scp_status.success() {
            bail!("scp failed (exit {})", scp_status.code().unwrap_or(-1));
        }

        // Ensure the binary is executable (scp preserves perms but be explicit).
        Command::new("ssh")
            .args(self.ssh_base())
            .arg("chmod +x ~/.local/bin/seam")
            .status()
            .context("chmod +x failed")?;

        Ok("~/.local/bin/seam".to_string())
    }

    /// Start any seam subcommand on remote via SSH.
    ///
    /// Returns the SEAM connection-info line AND the live SSH child process.
    /// The caller MUST keep `Child` alive for the duration of the session —
    /// dropping it kills the SSH session and the remote worker.
    pub fn start_remote_seam(&self, seam_bin: &str, subcmd: &str) -> Result<(String, Child)> {
        let cmd = format!("{seam_bin} {subcmd}");

        let mut ssh_args = self.ssh_base();
        ssh_args.push(cmd);

        let mut child = Command::new("ssh")
            .args(&ssh_args)
            .stdout(Stdio::piped())
            // Inherit stderr so the user sees remote errors / auth prompts.
            .stderr(Stdio::inherit())
            .spawn()
            .context("ssh spawn failed")?;

        let stdout = child.stdout.take().expect("stdout piped");
        let reader = std::io::BufReader::new(stdout);

        for line in reader.lines() {
            let line = line.context("reading ssh output")?;
            if line.starts_with("SEAM ") {
                return Ok((line, child));
            }
        }

        bail!(
            "remote seam on {} exited without printing SEAM line — \
             is seam installed and in PATH on the remote?",
            self.target()
        );
    }

    /// Start `seam recv` on remote via SSH.
    pub fn start_receiver(&self, seam_bin: &str, dest: &str) -> Result<(String, Child)> {
        self.start_remote_seam(seam_bin, &format!("recv {} --port 0 --once", dest))
    }
}

/// Parse `"user@host:/path"` or `"host:/path"` into `(RemoteInfo, remote_path)`.
/// Respects `~/.ssh/config` via `ssh -G` when no explicit user/port is given.
pub fn parse_remote(s: &str) -> Option<(RemoteInfo, String)> {
    let colon_pos = s.find(':')?;
    let host_part = &s[..colon_pos];
    let path = s[colon_pos + 1..].to_string();

    // Single-letter prefix = Windows drive letter, not a remote spec.
    if host_part.len() == 1 {
        return None;
    }

    let (explicit_user, host) = if let Some(at) = host_part.find('@') {
        (
            Some(host_part[..at].to_string()),
            host_part[at + 1..].to_string(),
        )
    } else {
        (None, host_part.to_string())
    };

    let (cfg_user, cfg_port, cfg_hostname) = resolve_ssh_config(&host);
    let user = explicit_user.or(cfg_user);
    let ssh_port = cfg_port;
    let host = cfg_hostname.unwrap_or(host);

    Some((
        RemoteInfo {
            host,
            user,
            ssh_port,
        },
        path,
    ))
}

/// Run `ssh -G <host>` to resolve Host/User/Port from the user's SSH config.
fn resolve_ssh_config(host: &str) -> (Option<String>, Option<u16>, Option<String>) {
    let out = match Command::new("ssh").args(["-G", host]).output() {
        Ok(o) if o.status.success() => o,
        _ => return (None, None, None),
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut user = None;
    let mut port = None;
    let mut hostname = None;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("hostname ") {
            hostname = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("user ") {
            user = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("port ") {
            port = v.parse().ok();
        }
    }
    (user, port, hostname)
}
