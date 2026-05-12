use anyhow::{Context, Result, bail};
use std::io::BufRead;
use std::io::Write;
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

    fn ssh_base(&self) -> Vec<String> {
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

    pub fn run_command(&self, cmd: &str) -> Result<String> {
        let mut args = self.ssh_base();
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

    /// Bootstrap by copying the local seam binary to remote via SSH pipe.
    pub fn bootstrap_copy_self(&self) -> Result<String> {
        let bin = std::env::current_exe().context("can't find own executable")?;
        let binary = std::fs::read(&bin).context("can't read own executable")?;

        eprintln!(
            "bootstrapping seam on {} ({} KB)…",
            self.target(),
            binary.len() / 1024
        );

        let dest = "~/.local/bin/seam";
        let cmd = format!("mkdir -p ~/.local/bin && cat > {dest} && chmod +x {dest}");

        let mut ssh_args = self.ssh_base();
        ssh_args.push(cmd);

        let mut child = Command::new("ssh")
            .args(&ssh_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("ssh spawn failed")?;

        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(&binary)
            .context("write binary to ssh stdin")?;
        drop(child.stdin.take());

        let status = child.wait().context("ssh wait failed")?;
        if !status.success() {
            bail!(
                "bootstrap copy failed (exit {})",
                status.code().unwrap_or(-1)
            );
        }

        Ok(dest.to_string())
    }

    /// Start `seam recv` on remote via SSH.
    ///
    /// Returns the SEAM connection-info line AND the live SSH child process.
    /// The caller MUST keep `Child` alive for the duration of the transfer —
    /// dropping it kills the SSH session and the remote receiver.
    pub fn start_receiver(&self, seam_bin: &str, dest: &str) -> Result<(String, Child)> {
        let cmd = format!("{seam_bin} recv {dest} --port 0 --once 2>/dev/null");

        let mut ssh_args = self.ssh_base();
        ssh_args.push(cmd);

        let mut child = Command::new("ssh")
            .args(&ssh_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
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
            "receiver on {} exited without printing SEAM line",
            self.target()
        );
    }
}

/// Parse `"user@host:/path"` or `"host:/path"` into `(RemoteInfo, remote_path)`.
pub fn parse_remote(s: &str) -> Option<(RemoteInfo, String)> {
    let colon_pos = s.find(':')?;
    let host_part = &s[..colon_pos];
    let path = s[colon_pos + 1..].to_string();

    // Single-letter prefix = Windows drive letter, not a remote spec.
    if host_part.len() == 1 {
        return None;
    }

    let (user, host) = if let Some(at) = host_part.find('@') {
        (
            Some(host_part[..at].to_string()),
            host_part[at + 1..].to_string(),
        )
    } else {
        (None, host_part.to_string())
    };

    Some((
        RemoteInfo {
            host,
            user,
            ssh_port: None,
        },
        path,
    ))
}
