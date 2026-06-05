/// seam shell — execute a single command on a remote host over a post-quantum
/// Seam channel and stream the combined stdout/stderr back to the caller.
///
/// Usage:
///   seam shell user@host -- ls -la /etc
///   seam shell user@host -- /usr/bin/uptime
///   echo "hello" | seam shell user@host -- cat
///
/// The remote end runs `seam _shell-recv`, which spawns the requested command
/// and bridges its stdio over the Seam stream.  The local side inherits the
/// remote exit code and forwards it to the OS via `std::process::exit`.
///
/// Wire protocol:
///   Client → Server stream (stdin pipe):
///     [0x10][len: u16 BE][data bytes]  — SHELL_STDIN: stdin chunk
///     [0x11]                            — SHELL_STDIN_EOF: stdin closed
///   Server → Client stream (output + control):
///     [0x01][exit_code: u8]            — SHELL_EXIT: command finished
///     [0x02][msg_len: u16 BE][msg]     — SHELL_ERR: spawn failed
///     All other bytes are raw stdout/stderr from the command.
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

// ── Wire protocol constants ───────────────────────────────────────────────────

/// Server → Client: command exited. Next byte is the exit code (u8).
const SHELL_EXIT: u8 = 0x01;
/// Server → Client: command failed to spawn. Next 2 bytes are msg_len (u16 BE),
/// followed by msg_len bytes of error text.
const SHELL_ERR: u8 = 0x02;
/// Client → Server: stdin data chunk. Next 2 bytes are length (u16 BE),
/// followed by that many bytes of stdin data.
const SHELL_STDIN: u8 = 0x10;
/// Client → Server: stdin EOF — remote process will see EOF on its stdin.
const SHELL_STDIN_EOF: u8 = 0x11;

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
    // Open a single bidirectional stream: client sends stdin frames, server
    // sends stdout/stderr bytes plus the SHELL_EXIT / SHELL_ERR control frames.
    let mut stream = mux.open_stream().await;

    // ── Stdin forwarding ─────────────────────────────────────────────────────
    // Detect whether stdin is a pipe/file (non-interactive).  If it is, spawn
    // a task that reads stdin and sends SHELL_STDIN frames to the remote.
    // On TTY we skip this so interactive use still works naturally.
    #[cfg(unix)]
    let stdin_is_pipe = {
        use std::os::unix::io::AsRawFd;
        let fd = std::io::stdin().as_raw_fd();
        !is_tty(fd)
    };
    #[cfg(not(unix))]
    let stdin_is_pipe = false;

    let exit_code: i32;

    if stdin_is_pipe {
        // Split the stream so we can write stdin frames while reading output.
        // SeamMux streams are already Send, so we use a channel to coordinate.
        use tokio::sync::mpsc;

        let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(16);

        // Task: read raw stdin and forward as SHELL_STDIN frames.
        let stdin_fwd = tokio::spawn(async move {
            let mut raw_stdin = tokio::io::stdin();
            let mut buf = vec![0u8; 4096];
            loop {
                match raw_stdin.read(&mut buf).await {
                    Ok(0) | Err(_) => {
                        let _ = stdin_tx.send(vec![]).await; // empty = EOF sentinel
                        break;
                    }
                    Ok(n) => {
                        // SHELL_STDIN: [0x10][len u16 BE][data]
                        let chunk = buf[..n].to_vec();
                        if stdin_tx.send(chunk).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let mut stdout = tokio::io::stdout();
        let mut out_buf = Vec::with_capacity(4096);
        exit_code = 'reader: loop {
            // Interleave stdin writes and output reads.
            tokio::select! {
                chunk = stdin_rx.recv() => {
                    match chunk {
                        Some(data) if data.is_empty() => {
                            // EOF sentinel — send SHELL_STDIN_EOF
                            stream.write_all(&[SHELL_STDIN_EOF]).await.ok();
                            stream.flush().await.ok();
                        }
                        Some(data) => {
                            let len = (data.len() as u16).to_be_bytes();
                            let mut frame = Vec::with_capacity(3 + data.len());
                            frame.push(SHELL_STDIN);
                            frame.extend_from_slice(&len);
                            frame.extend_from_slice(&data);
                            if stream.write_all(&frame).await.is_err() {
                                break 'reader 1;
                            }
                        }
                        None => {
                            // Channel closed — stdin task done
                            stream.write_all(&[SHELL_STDIN_EOF]).await.ok();
                            stream.flush().await.ok();
                        }
                    }
                }
                result = stream.read_u8() => {
                    match result {
                        Err(_) => break 'reader 0,
                        Ok(SHELL_EXIT) => {
                            let code = stream.read_u8().await.unwrap_or(1);
                            if !out_buf.is_empty() {
                                stdout.write_all(&out_buf).await.ok();
                                out_buf.clear();
                            }
                            stdout.flush().await.ok();
                            break 'reader code as i32;
                        }
                        Ok(SHELL_ERR) => {
                            let mut len_buf = [0u8; 2];
                            stream.read_exact(&mut len_buf).await.ok();
                            let msg_len = u16::from_be_bytes(len_buf) as usize;
                            let mut msg = vec![0u8; msg_len];
                            stream.read_exact(&mut msg).await.ok();
                            eprintln!(
                                "remote command failed to start: {}",
                                String::from_utf8_lossy(&msg)
                            );
                            break 'reader 1;
                        }
                        Ok(b) => {
                            out_buf.push(b);
                            if out_buf.len() >= 4096 {
                                stdout.write_all(&out_buf).await.ok();
                                out_buf.clear();
                            }
                        }
                    }
                }
            }
        };
        stdin_fwd.abort();
        stdout.flush().await.ok();
    } else {
        // Non-pipe path: no stdin forwarding (original behavior).
        let mut stdout = tokio::io::stdout();
        let mut buf = Vec::with_capacity(4096);
        exit_code = 'outer: loop {
            let mut byte = [0u8; 1];
            match stream.read_exact(&mut byte).await {
                Err(_) => break 0,
                Ok(_) => {}
            }
            match byte[0] {
                SHELL_EXIT => {
                    let mut code = [0u8; 1];
                    let ec = if stream.read_exact(&mut code).await.is_ok() {
                        code[0] as i32
                    } else {
                        0
                    };
                    if !buf.is_empty() {
                        stdout.write_all(&buf).await?;
                        buf.clear();
                    }
                    stdout.flush().await?;
                    break 'outer ec;
                }
                SHELL_ERR => {
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
                    buf.push(b);
                    if buf.len() >= 4096 {
                        stdout.write_all(&buf).await?;
                        buf.clear();
                    }
                }
            }
        };
        stdout.flush().await?;
    }

    std::process::exit(exit_code);
}

/// Returns true if the given file descriptor is a terminal (not a pipe/file).
#[cfg(unix)]
fn is_tty(fd: i32) -> bool {
    unsafe extern "C" {
        fn isatty(fd: i32) -> i32;
    }
    // SAFETY: isatty is a standard POSIX function with no undefined behavior.
    unsafe { isatty(fd) == 1 }
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
        .stdin(std::process::Stdio::piped())
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

    // Stream stdout and stderr to the Seam stream concurrently, and forward
    // any SHELL_STDIN frames from the stream to the child's stdin.
    let mut child_stdout = child.stdout.take().unwrap();
    let mut child_stderr = child.stderr.take().unwrap();
    let mut child_stdin = child.stdin.take();

    let mut out_buf = vec![0u8; 4096];
    let mut err_buf = vec![0u8; 4096];
    let mut stdout_done = false;
    let mut stderr_done = false;

    // We interleave three sources:
    //   1. child stdout → stream
    //   2. child stderr → stream
    //   3. stream → child stdin (SHELL_STDIN / SHELL_STDIN_EOF frames)
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
            byte = stream.read_u8(), if child_stdin.is_some() => {
                match byte {
                    Err(_) => {
                        // Stream closed by client — drop stdin so the child sees EOF.
                        child_stdin = None;
                    }
                    Ok(SHELL_STDIN) => {
                        // Read 2-byte length, then data.
                        let mut len_buf = [0u8; 2];
                        if stream.read_exact(&mut len_buf).await.is_err() {
                            child_stdin = None;
                            continue;
                        }
                        let data_len = u16::from_be_bytes(len_buf) as usize;
                        let mut data = vec![0u8; data_len];
                        if stream.read_exact(&mut data).await.is_err() {
                            child_stdin = None;
                            continue;
                        }
                        if let Some(ref mut stdin_w) = child_stdin {
                            if stdin_w.write_all(&data).await.is_err() {
                                child_stdin = None;
                            }
                        }
                    }
                    Ok(SHELL_STDIN_EOF) | Ok(_) => {
                        // EOF signaled — drop stdin so child gets EOF.
                        child_stdin = None;
                    }
                }
            }
        }
    }

    // Ensure child stdin is closed so the child process exits cleanly.
    drop(child_stdin);

    // Wait for the process and send exit code.
    let status = child.wait().await?;
    let code = status.code().unwrap_or(1) as u8;
    stream.write_all(&[SHELL_EXIT, code]).await.ok();
    stream.flush().await.ok();

    Ok(())
}
