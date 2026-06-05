/// seam shell — execute a single command on a remote host over a post-quantum
/// Seam channel and stream the combined stdout/stderr back to the caller.
///
/// Usage:
///   seam shell user@host -- ls -la /etc
///   seam shell user@host -- /usr/bin/uptime
///
/// The remote end runs `seam _shell-recv`, which spawns the requested command
/// and bridges its stdio over the Seam stream.  The local side inherits the
/// remote exit code and forwards it to the OS via `std::process::exit`.
///
/// Security properties:
///   • Channel encrypted with Noise_XX + ML-KEM-768 (post-quantum KEM)
///   • Ephemeral keys per session — no persistent server identity required
///   • Zero plaintext over UDP — all traffic is AEAD-encrypted
///   • Suitable for environments where SSH traffic is blocked or logged
use anyhow::{Result, anyhow, bail};
use clap::Args;
use seam_protocol::{
    api::Server,
    handshake::{IdentityKeypair, pk_to_bytes},
    tunnel::SeamMux,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{connect, ssh};

// ── Wire protocol ─────────────────────────────────────────────────────────────
//
// After the Seam stream is established the receiver writes a single-byte
// STATUS frame when the command exits:
//
//   [0x01][exit_code: u8]   — SHELL_EXIT: command finished
//   [0x02][msg_len: u16 BE][msg bytes]  — SHELL_ERR: spawn failed
//
// All other bytes on the stream are raw stdout/stderr from the command.

const SHELL_EXIT: u8 = 0x01;
const SHELL_ERR: u8 = 0x02;

// ── Client args ───────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct ShellArgs {
    /// Remote target: user@host
    pub remote: String,
    /// SSH port for bootstrap
    #[arg(short = 'p', long)]
    pub port: Option<u16>,
    /// Command and arguments to run on the remote host (everything after --)
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

// ── Server args ───────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct ShellRecvArgs {
    /// UDP port to listen on (0 = OS-assigned)
    #[arg(long, default_value_t = 0)]
    pub port: u16,
    /// Command to execute (everything after --)
    #[arg(last = true)]
    pub command: Vec<String>,
}

// ── Client ────────────────────────────────────────────────────────────────────

pub async fn run(args: ShellArgs) -> Result<()> {
    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher = seam_protocol::crypto::CipherSuite::parse(&cfg.cipher).unwrap_or_default();

    let (user, host) = ssh::parse_userhost(&args.remote);
    let remote = ssh::RemoteInfo {
        host: host.clone(),
        user,
        ssh_port: args.port,
    };

    // Build the remote sub-command: `_shell-recv --port 0 -- CMD [ARGS...]`
    let mut subcmd = "_shell-recv --port 0 --".to_string();
    for arg in &args.command {
        subcmd.push(' ');
        subcmd.push_str(&connect::shell_quote(arg));
    }

    let (conn, _child) =
        connect::bootstrap_and_connect(&remote, &host, &subcmd, cipher).await?;

    let mux = SeamMux::new(conn);
    let mut stream = mux.open_stream().await;

    // Stream remote output to local stdout until we see SHELL_EXIT / SHELL_ERR.
    let mut stdout = tokio::io::stdout();
    let mut exit_code: i32 = 0;

    // Read byte-by-byte to detect protocol frames without missing output bytes.
    // In practice the remote buffers output in 4 KiB chunks so this is fast.
    let mut buf = Vec::with_capacity(4096);
    'outer: loop {
        let mut byte = [0u8; 1];
        match stream.read_exact(&mut byte).await {
            Err(_) => break, // stream closed — remote side exited
            Ok(_) => {}
        }

        match byte[0] {
            SHELL_EXIT => {
                // Read exit code byte
                let mut code = [0u8; 1];
                if stream.read_exact(&mut code).await.is_ok() {
                    exit_code = code[0] as i32;
                }
                // Flush any remaining buffered output
                if !buf.is_empty() {
                    stdout.write_all(&buf).await?;
                    buf.clear();
                }
                stdout.flush().await?;
                break 'outer;
            }
            SHELL_ERR => {
                // Read 2-byte message length then the message
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    bail!("shell: truncated error frame");
                }
                let msg_len = u16::from_be_bytes(len_buf) as usize;
                let mut msg = vec![0u8; msg_len];
                stream.read_exact(&mut msg).await.ok();
                bail!(
                    "remote command failed to start: {}",
                    String::from_utf8_lossy(&msg)
                );
            }
            b => {
                // Regular output byte — buffer and periodically flush.
                buf.push(b);
                if buf.len() >= 4096 {
                    stdout.write_all(&buf).await?;
                    buf.clear();
                }
            }
        }
    }

    stdout.flush().await?;
    std::process::exit(exit_code);
}

// ── Server (hidden, invoked via SSH bootstrap) ────────────────────────────────

pub async fn run_recv(args: ShellRecvArgs) -> Result<()> {
    if args.command.is_empty() {
        bail!("_shell-recv: no command specified");
    }

    let id = IdentityKeypair::generate();
    let x25519_hex = hex::encode(id.x25519_public.as_bytes());
    let kem_hex = hex::encode(pk_to_bytes(&id.kem_pk));

    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher = seam_protocol::crypto::CipherSuite::parse(&cfg.cipher).unwrap_or_default();
    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;
    let mut server =
        Server::bind_with_cipher(addr, id, cipher).await.map_err(|e| anyhow!("{e}"))?;
    let port = server.local_addr()?.port();

    // Emit the SEAM handshake line over stdout so the SSH parent can parse it.
    println!("SEAM PORT={port} X25519={x25519_hex} KEM={kem_hex}");

    let conn = server
        .accept()
        .await
        .ok_or_else(|| anyhow!("_shell-recv: no connection"))?;
    let mux = SeamMux::new(conn);
    let mut stream = mux
        .accept_stream()
        .await
        .ok_or_else(|| anyhow!("_shell-recv: no stream"))?;

    // Spawn the requested command.
    use tokio::process::Command;

    let spawn_result = Command::new(&args.command[0])
        .args(&args.command[1..])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    let mut child = match spawn_result {
        Ok(c) => c,
        Err(e) => {
            // Send SHELL_ERR frame so the client gets a meaningful message.
            let msg = e.to_string();
            let msg_bytes = msg.as_bytes();
            let len = (msg_bytes.len().min(65535)) as u16;
            let mut frame = Vec::with_capacity(3 + len as usize);
            frame.push(SHELL_ERR);
            frame.extend_from_slice(&len.to_be_bytes());
            frame.extend_from_slice(&msg_bytes[..len as usize]);
            stream.write_all(&frame).await.ok();
            stream.flush().await.ok();
            return Ok(());
        }
    };

    // Stream stdout and stderr to the Seam stream concurrently.
    let mut child_stdout = child.stdout.take().unwrap();
    let mut child_stderr = child.stderr.take().unwrap();

    // We read from both stdout and stderr and write to the single Seam stream.
    // Use select! to interleave without blocking.
    let mut out_buf = vec![0u8; 4096];
    let mut err_buf = vec![0u8; 4096];
    let mut stdout_done = false;
    let mut stderr_done = false;

    loop {
        if stdout_done && stderr_done {
            break;
        }
        tokio::select! {
            n = child_stdout.read(&mut out_buf), if !stdout_done => {
                match n {
                    Ok(0) | Err(_) => { stdout_done = true; }
                    Ok(n) => {
                        if stream.write_all(&out_buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            n = child_stderr.read(&mut err_buf), if !stderr_done => {
                match n {
                    Ok(0) | Err(_) => { stderr_done = true; }
                    Ok(n) => {
                        if stream.write_all(&err_buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }

    // Wait for the process and send exit code.
    let status = child.wait().await?;
    let code = status.code().unwrap_or(1) as u8;
    stream.write_all(&[SHELL_EXIT, code]).await.ok();
    stream.flush().await.ok();

    Ok(())
}
