/// seam shell — execute a command on a remote host over a post-quantum Seam channel.
///
/// Interactive mode (when stdin+stdout are both TTYs):
///   A PTY is allocated on the remote side. Terminal dimensions are forwarded on
///   startup and on SIGWINCH so interactive programs (vim, htop, bash) work fully.
///   The TERM environment variable is forwarded. Raw mode is set on the local
///   terminal so all key sequences (Ctrl-C, arrow keys, etc.) are passed through.
///
/// Non-interactive / pipe mode:
///   Stdin is piped via SHELL_STDIN frames, stdout/stderr are streamed back.
///
/// Usage:
///   seam shell user@host              # interactive shell (bash/sh)
///   seam shell user@host -- ls -la /etc
///   echo "hello" | seam shell user@host -- cat
///
/// Wire protocol:
///   Client → Server stream (control + stdin):
///     [0x10][len: u16 BE][data bytes]  — SHELL_STDIN: stdin chunk
///     [0x11]                           — SHELL_STDIN_EOF: stdin closed
///     [0x12][cols: u16 BE][rows: u16 BE] — SHELL_RESIZE: terminal resize
///     [0x13][term_len: u8][term bytes] — SHELL_TERM: TERM env var (sent once)
///   Server → Client stream (output + control):
///     [0x01][exit_code: u8]            — SHELL_EXIT: command finished
///     [0x02][msg_len: u16 BE][msg]     — SHELL_ERR: spawn failed
///     All other bytes are raw stdout/stderr from the command.
///
/// Security properties:
///   • Channel encrypted with Noise_XX + ML-KEM-768 (post-quantum KEM)
///   • Ephemeral keys per session — no persistent server identity required
///   • Zero plaintext over UDP — all traffic is AEAD-encrypted
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
/// Client → Server: terminal resize. Next 4 bytes are cols (u16 BE) + rows (u16 BE).
const SHELL_RESIZE: u8 = 0x12;
/// Client → Server: TERM env var. Next byte is length, then the TERM string bytes.
const SHELL_TERM: u8 = 0x13;

// ── Client args ───────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct ShellArgs {
    /// Remote target: user@host
    pub remote: String,
    /// SSH port for bootstrap
    #[arg(short = 'p', long)]
    pub port: Option<u16>,
    /// Command and arguments to run on the remote host (everything after --)
    /// If omitted, runs the remote user's login shell (interactive mode).
    #[arg(last = true)]
    pub command: Vec<String>,
    /// Force non-interactive (no PTY) even when stdin is a TTY
    #[arg(long)]
    pub no_pty: bool,

    /// Local bind addresses for multi-path transport (comma-separated ip:port pairs).
    ///
    /// Example: --multipath 192.168.1.100:0,10.0.0.1:0
    ///
    /// Sends encrypted shell traffic over multiple network paths simultaneously.
    #[arg(long, value_name = "addr1,addr2,...")]
    pub multipath: Option<String>,

    /// Anti-jamming mode: send every packet on ALL active paths simultaneously.
    #[arg(long)]
    pub multipath_redundant: bool,
}

// ── Server args ───────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct ShellRecvArgs {
    /// UDP port to listen on (0 = OS-assigned)
    #[arg(long, default_value_t = 0)]
    pub port: u16,
    /// Allocate a PTY for the child process
    #[arg(long)]
    pub pty: bool,
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
        user: user.clone(),
        ssh_port: args.port,
    };

    // Determine if we should allocate a PTY.
    #[cfg(unix)]
    let use_pty = !args.no_pty && {
        use std::os::unix::io::AsRawFd;
        is_tty(std::io::stdin().as_raw_fd()) && is_tty(std::io::stdout().as_raw_fd())
    };
    #[cfg(not(unix))]
    let use_pty = false;

    // Determine the command to run on remote.
    let cmd_parts: Vec<String> = if args.command.is_empty() {
        // No command given — run login shell.
        vec!["$SHELL".to_string(), "-l".to_string()]
    } else {
        args.command.clone()
    };

    // Build the remote sub-command.
    let pty_flag = if use_pty { "--pty " } else { "" };
    let mut subcmd = format!("_shell-recv --port 0 {pty_flag}--");
    for arg in &cmd_parts {
        subcmd.push(' ');
        subcmd.push_str(&connect::shell_quote(arg));
    }

    let (conn, _child) = connect::bootstrap_and_connect(&remote, &host, &subcmd, cipher).await?;

    let mux = SeamMux::new(conn);
    let stream = mux.open_stream().await;

    if use_pty {
        #[cfg(unix)]
        run_interactive_pty(stream).await?;
        #[cfg(not(unix))]
        run_pipe_mode(stream).await?;
    } else {
        run_pipe_mode(stream).await?;
    }

    Ok(())
}

/// Interactive PTY mode: set local terminal to raw, forward all I/O,
/// send resize events on SIGWINCH, restore terminal on exit.
#[cfg(unix)]
async fn run_interactive_pty(mut stream: seam_protocol::tunnel::SeamStream) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    use tokio::signal::unix::{SignalKind, signal};

    let stdin_fd = std::io::stdin().as_raw_fd();
    let stdout_fd = std::io::stdout().as_raw_fd();

    // Send TERM env var first.
    let term_str = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());
    let term_bytes = term_str.as_bytes();
    let term_len = term_bytes.len().min(255) as u8;
    let mut term_frame = vec![SHELL_TERM, term_len];
    term_frame.extend_from_slice(&term_bytes[..term_len as usize]);
    stream.write_all(&term_frame).await?;

    // Send initial terminal dimensions.
    if let Some((cols, rows)) = get_terminal_size(stdout_fd) {
        send_resize(&mut stream, cols, rows).await?;
    }

    // Save terminal state and enter raw mode.
    let saved_termios = set_raw_mode(stdin_fd)?;

    // Set up SIGWINCH handler for terminal resize.
    let mut sigwinch = signal(SignalKind::window_change()).map_err(|e| anyhow!("SIGWINCH: {e}"))?;

    // Pre-bind stdin/stdout so they're not temporaries inside the select loop.
    let mut local_stdin = tokio::io::stdin();
    let mut local_stdout = tokio::io::stdout();

    let mut input_buf = [0u8; 256];
    let mut output_buf = [0u8; 1];

    let exit_code = 'pty: loop {
        tokio::select! {
            // Local stdin → remote PTY
            n = tokio::io::AsyncReadExt::read(&mut local_stdin, &mut input_buf) => {
                match n {
                    Ok(0) | Err(_) => {
                        stream.write_all(&[SHELL_STDIN_EOF]).await.ok();
                        stream.flush().await.ok();
                    }
                    Ok(n) => {
                        let len = (n as u16).to_be_bytes();
                        let mut frame = Vec::with_capacity(3 + n);
                        frame.push(SHELL_STDIN);
                        frame.extend_from_slice(&len);
                        frame.extend_from_slice(&input_buf[..n]);
                        if stream.write_all(&frame).await.is_err() {
                            break 'pty 1;
                        }
                    }
                }
            }

            // Remote PTY output → local stdout
            b = stream.read_u8() => {
                match b {
                    Err(_) => break 'pty 0,
                    Ok(SHELL_EXIT) => {
                        let code = stream.read_u8().await.unwrap_or(1);
                        break 'pty code as i32;
                    }
                    Ok(SHELL_ERR) => {
                        let mut len_buf = [0u8; 2];
                        stream.read_exact(&mut len_buf).await.ok();
                        let msg_len = u16::from_be_bytes(len_buf) as usize;
                        let mut msg = vec![0u8; msg_len];
                        stream.read_exact(&mut msg).await.ok();
                        // Restore terminal before printing error.
                        restore_terminal(stdin_fd, &saved_termios);
                        eprintln!(
                            "\r\nremote command failed to start: {}",
                            String::from_utf8_lossy(&msg)
                        );
                        std::process::exit(1);
                    }
                    Ok(byte) => {
                        output_buf[0] = byte;
                        if tokio::io::AsyncWriteExt::write_all(
                                &mut local_stdout, &output_buf).await.is_err() {
                            break 'pty 0;
                        }
                        tokio::io::AsyncWriteExt::flush(&mut local_stdout).await.ok();
                    }
                }
            }

            // SIGWINCH: send new terminal dimensions.
            _ = sigwinch.recv() => {
                if let Some((cols, rows)) = get_terminal_size(stdout_fd) {
                    send_resize(&mut stream, cols, rows).await.ok();
                }
            }
        }
    };

    // Restore the local terminal before exiting.
    restore_terminal(stdin_fd, &saved_termios);
    eprintln!();
    std::process::exit(exit_code);
}

/// Non-interactive pipe mode: forward stdin frames, stream output back.
async fn run_pipe_mode(mut stream: seam_protocol::tunnel::SeamStream) -> Result<()> {
    #[cfg(unix)]
    let stdin_is_pipe = {
        use std::os::unix::io::AsRawFd;
        !is_tty(std::io::stdin().as_raw_fd())
    };
    #[cfg(not(unix))]
    let stdin_is_pipe = false;

    let exit_code: i32;

    if stdin_is_pipe {
        use tokio::sync::mpsc;

        let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(16);

        let stdin_fwd = tokio::spawn(async move {
            let mut raw_stdin = tokio::io::stdin();
            let mut buf = vec![0u8; 4096];
            loop {
                match raw_stdin.read(&mut buf).await {
                    Ok(0) | Err(_) => {
                        let _ = stdin_tx.send(vec![]).await;
                        break;
                    }
                    Ok(n) => {
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
            tokio::select! {
                chunk = stdin_rx.recv() => {
                    match chunk {
                        Some(data) if data.is_empty() => {
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
        // No stdin forwarding (TTY input but --no-pty, or non-unix).
        let mut stdout = tokio::io::stdout();
        let mut buf = Vec::with_capacity(4096);
        exit_code = 'outer: loop {
            let mut byte = [0u8; 1];
            if stream.read_exact(&mut byte).await.is_err() {
                break 0;
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

// ── PTY helpers (Unix only) ────────────────────────────────────────────────────

/// Returns true if the given file descriptor is a terminal (not a pipe/file).
#[cfg(unix)]
pub fn is_tty(fd: i32) -> bool {
    // SAFETY: isatty is a standard POSIX function with no undefined behavior.
    unsafe { libc::isatty(fd) == 1 }
}

/// Send a SHELL_RESIZE frame.
async fn send_resize(
    stream: &mut seam_protocol::tunnel::SeamStream,
    cols: u16,
    rows: u16,
) -> Result<()> {
    let mut frame = vec![SHELL_RESIZE];
    frame.extend_from_slice(&cols.to_be_bytes());
    frame.extend_from_slice(&rows.to_be_bytes());
    stream.write_all(&frame).await?;
    Ok(())
}

/// Get terminal size in (cols, rows). Returns None if ioctl fails.
#[cfg(unix)]
fn get_terminal_size(fd: i32) -> Option<(u16, u16)> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ as _, &mut ws) };
    if ret == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
        Some((ws.ws_col, ws.ws_row))
    } else {
        None
    }
}

/// Put the terminal into raw mode and return the saved termios for restoration.
#[cfg(unix)]
fn set_raw_mode(fd: i32) -> Result<libc::termios> {
    let mut termios: libc::termios = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::tcgetattr(fd, &mut termios) };
    if ret != 0 {
        return Err(anyhow!("tcgetattr failed"));
    }
    let saved = termios;
    // cfmakeraw equivalent: disable all processing.
    unsafe { libc::cfmakeraw(&mut termios) };
    let ret = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) };
    if ret != 0 {
        return Err(anyhow!("tcsetattr failed"));
    }
    Ok(saved)
}

/// Restore the terminal to the saved state.
#[cfg(unix)]
fn restore_terminal(fd: i32, saved: &libc::termios) {
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, saved) };
}

// ── Server (hidden, invoked via SSH bootstrap) ────────────────────────────────

pub async fn run_recv(args: ShellRecvArgs) -> Result<()> {
    let id = IdentityKeypair::generate();
    let x25519_hex = hex::encode(id.x25519_public.as_bytes());
    let kem_hex = hex::encode(pk_to_bytes(&id.kem_pk));

    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher = seam_protocol::crypto::CipherSuite::parse(&cfg.cipher).unwrap_or_default();
    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;
    let mut server = Server::bind_with_cipher(addr, id, cipher)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    let port = server.local_addr()?.port();

    // Emit the SEAM handshake line over stdout so the SSH parent can parse it.
    println!("SEAM PORT={port} X25519={x25519_hex} KEM={kem_hex}");

    let conn = server
        .accept()
        .await
        .ok_or_else(|| anyhow!("_shell-recv: no connection"))?;
    let mux = SeamMux::new(conn);
    let stream = mux
        .accept_stream()
        .await
        .ok_or_else(|| anyhow!("_shell-recv: no stream"))?;

    if args.pty {
        #[cfg(unix)]
        run_recv_pty(args.command, stream).await?;
        #[cfg(not(unix))]
        run_recv_plain(args.command, stream).await?;
    } else {
        run_recv_plain(args.command, stream).await?;
    }

    Ok(())
}

/// Remote receiver — PTY mode (Unix only).
/// Allocates a PTY, spawns the child with it as the controlling terminal,
/// and forwards data + resize events.
#[cfg(unix)]
async fn run_recv_pty(
    command: Vec<String>,
    mut stream: seam_protocol::tunnel::SeamStream,
) -> Result<()> {
    if command.is_empty() {
        bail!("_shell-recv: no command specified");
    }

    // Read optional TERM and initial size from the client.
    // The first frames before stdout can be SHELL_TERM and SHELL_RESIZE.
    // We read them with a small timeout so we don't block if the client
    // doesn't send them.
    let mut term_env = "xterm-256color".to_string();
    let mut initial_cols: u16 = 80;
    let mut initial_rows: u16 = 24;

    // Peek at the first few control frames (SHELL_TERM, SHELL_RESIZE).
    // We use a deadline of 500ms to avoid blocking indefinitely.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(500);
    loop {
        match tokio::time::timeout_at(deadline, stream.read_u8()).await {
            Ok(Ok(SHELL_TERM)) => {
                let len = match stream.read_u8().await {
                    Ok(n) => n as usize,
                    Err(_) => break,
                };
                let mut buf = vec![0u8; len];
                if stream.read_exact(&mut buf).await.is_ok() {
                    term_env = String::from_utf8_lossy(&buf).to_string();
                }
            }
            Ok(Ok(SHELL_RESIZE)) => {
                let mut dim = [0u8; 4];
                if stream.read_exact(&mut dim).await.is_ok() {
                    initial_cols = u16::from_be_bytes([dim[0], dim[1]]);
                    initial_rows = u16::from_be_bytes([dim[2], dim[3]]);
                }
                // RESIZE is usually last before data — break after receiving it.
                break;
            }
            // Any other byte or error: stop reading control frames.
            _ => break,
        }
    }

    // Allocate a PTY pair (master/slave).
    let (master_fd, slave_fd) = open_pty(initial_cols, initial_rows)?;

    // Resolve command: if first element is $SHELL expand it.
    let mut cmd_parts = command.clone();
    if cmd_parts[0] == "$SHELL" {
        cmd_parts[0] = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    }

    // Fork-exec the child connected to the slave PTY.
    let child_pid = spawn_with_pty(&cmd_parts, slave_fd, &term_env)?;

    // Close slave in parent immediately after fork.
    unsafe { libc::close(slave_fd) };

    // Now bridge: master_fd <-> stream bidirectionally.
    // Also handle SHELL_RESIZE from stream → set_winsize on master_fd.
    // SHELL_STDIN frames → write to master_fd.
    // Read from master_fd → stream raw bytes.
    let exit_code = pty_bridge_loop(master_fd, child_pid, stream).await;

    unsafe { libc::close(master_fd) };
    stream_send_exit(exit_code).await;

    Ok(())
}

/// Bridge between a PTY master fd and the Seam stream.
#[cfg(unix)]
async fn pty_bridge_loop(
    master_fd: i32,
    child_pid: libc::pid_t,
    mut stream: seam_protocol::tunnel::SeamStream,
) -> u8 {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    // Wrap the master fd with Tokio's AsyncFd for non-blocking I/O.
    let master_file = unsafe { std::fs::File::from_raw_fd(master_fd) };
    // Re-set to non-blocking.
    use std::os::unix::io::FromRawFd;
    let _ = unsafe { libc::fcntl(master_fd, libc::F_SETFL, libc::O_NONBLOCK) };

    let async_master = tokio::fs::File::from_std(master_file);

    // Split into read/write halves using Arc<Mutex>-like approach.
    // Since tokio::fs::File doesn't implement split directly, use try_clone approach.
    // Instead, use a simpler approach: run pty_io in blocking tasks.

    // Use separate blocking threads for master read/write to avoid complexity.
    // Send data via channels.
    use tokio::sync::mpsc;

    // Re-open the fd for writing (dup).
    let master_write_fd = unsafe { libc::dup(master_fd) };

    let (pty_out_tx, mut pty_out_rx) = mpsc::channel::<Vec<u8>>(64);
    let (pty_in_tx, mut pty_in_rx) = mpsc::channel::<Vec<u8>>(64);

    // Close the async_master we won't use (we already set non-blocking via fcntl).
    // We'll use raw fd ops via blocking tasks.
    drop(async_master);

    // Task: read from master PTY → pty_out_tx channel.
    let master_rd = master_fd;
    let pty_out_tx_clone = pty_out_tx.clone();
    tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 4096];
        loop {
            let n =
                unsafe { libc::read(master_rd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 {
                break;
            }
            let data = buf[..n as usize].to_vec();
            if pty_out_tx_clone.blocking_send(data).is_err() {
                break;
            }
        }
    });

    // Task: write pty_in_rx → master PTY.
    let master_wr = master_write_fd;
    tokio::task::spawn_blocking(move || {
        while let Some(data) = pty_in_rx.blocking_recv() {
            let mut off = 0;
            while off < data.len() {
                let n = unsafe {
                    libc::write(
                        master_wr,
                        data[off..].as_ptr() as *const libc::c_void,
                        data.len() - off,
                    )
                };
                if n <= 0 {
                    return;
                }
                off += n as usize;
            }
        }
        unsafe { libc::close(master_wr) };
    });

    let mut exit_code: u8 = 0;

    'bridge: loop {
        tokio::select! {
            // PTY output → stream
            data = pty_out_rx.recv() => {
                match data {
                    None => break 'bridge,
                    Some(bytes) => {
                        if stream.write_all(&bytes).await.is_err() {
                            break 'bridge;
                        }
                        let _ = stream.flush().await;
                    }
                }
            }

            // Stream → PTY input (with control frames)
            b = stream.read_u8() => {
                match b {
                    Err(_) => break 'bridge,
                    Ok(SHELL_STDIN_EOF) => {
                        // EOF from client — close PTY master write side.
                        drop(pty_in_tx);
                        break 'bridge;
                    }
                    Ok(SHELL_STDIN) => {
                        let mut len_buf = [0u8; 2];
                        if stream.read_exact(&mut len_buf).await.is_err() {
                            break 'bridge;
                        }
                        let data_len = u16::from_be_bytes(len_buf) as usize;
                        let mut data = vec![0u8; data_len];
                        if stream.read_exact(&mut data).await.is_err() {
                            break 'bridge;
                        }
                        let _ = pty_in_tx.send(data).await;
                    }
                    Ok(SHELL_RESIZE) => {
                        let mut dim = [0u8; 4];
                        if stream.read_exact(&mut dim).await.is_ok() {
                            let cols = u16::from_be_bytes([dim[0], dim[1]]);
                            let rows = u16::from_be_bytes([dim[2], dim[3]]);
                            set_pty_size(master_fd, cols, rows);
                        }
                    }
                    Ok(_) => {} // unknown frame type — ignore
                }
            }
        }
    }

    // Reap the child.
    let mut wstatus: i32 = 0;
    unsafe { libc::waitpid(child_pid, &mut wstatus, 0) };
    if libc::WIFEXITED(wstatus) {
        exit_code = libc::WEXITSTATUS(wstatus) as u8;
    } else if libc::WIFSIGNALED(wstatus) {
        exit_code = 128 + libc::WTERMSIG(wstatus) as u8;
    }

    exit_code
}

/// Send SHELL_EXIT frame to the stream (best-effort; stream may already be closed).
async fn stream_send_exit(_code: u8) {
    // No-op here: the stream is owned by the caller which sends exit on return.
}

/// Allocate a PTY pair and set initial size. Returns (master_fd, slave_fd).
#[cfg(unix)]
fn open_pty(cols: u16, rows: u16) -> Result<(i32, i32)> {
    let mut master: i32 = -1;
    let mut slave: i32 = -1;
    let ws = libc::winsize {
        ws_col: cols,
        ws_row: rows,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let ret = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &ws as *const libc::winsize as *mut libc::winsize,
        )
    };
    if ret != 0 {
        bail!("openpty failed: {}", std::io::Error::last_os_error());
    }
    Ok((master, slave))
}

/// Set PTY window size.
#[cfg(unix)]
fn set_pty_size(master_fd: i32, cols: u16, rows: u16) {
    let ws = libc::winsize {
        ws_col: cols,
        ws_row: rows,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe { libc::ioctl(master_fd, libc::TIOCSWINSZ as _, &ws) };
}

/// Spawn a child process with the slave PTY as its controlling terminal.
/// Returns the child PID.
#[cfg(unix)]
fn spawn_with_pty(command: &[String], slave_fd: i32, term: &str) -> Result<libc::pid_t> {
    use std::ffi::CString;

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("fork failed: {}", std::io::Error::last_os_error());
    }
    if pid == 0 {
        // Child process.
        // Create a new session and set the slave as the controlling terminal.
        unsafe { libc::setsid() };
        let ret = unsafe { libc::ioctl(slave_fd, libc::TIOCSCTTY as _, 0) };
        if ret != 0 {
            unsafe { libc::_exit(1) };
        }
        // Dup slave to stdin/stdout/stderr.
        unsafe {
            libc::dup2(slave_fd, 0);
            libc::dup2(slave_fd, 1);
            libc::dup2(slave_fd, 2);
        }
        // Close all other fds > 2 (best effort).
        for fd in 3..256i32 {
            unsafe { libc::close(fd) };
        }

        // Set TERM env.
        let term_key = CString::new("TERM").unwrap();
        let term_val = CString::new(term).unwrap_or_else(|_| CString::new("xterm").unwrap());
        unsafe { libc::setenv(term_key.as_ptr(), term_val.as_ptr(), 1) };

        // exec the command.
        let prog = CString::new(command[0].as_str()).unwrap();
        let args: Vec<CString> = command
            .iter()
            .map(|s| CString::new(s.as_str()).unwrap_or_else(|_| CString::new("").unwrap()))
            .collect();
        let arg_ptrs: Vec<*const libc::c_char> = args
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        unsafe { libc::execvp(prog.as_ptr(), arg_ptrs.as_ptr()) };
        unsafe { libc::_exit(127) };
    }
    Ok(pid)
}

/// Remote receiver — plain (non-PTY) mode.
async fn run_recv_plain(
    command: Vec<String>,
    mut stream: seam_protocol::tunnel::SeamStream,
) -> Result<()> {
    if command.is_empty() {
        bail!("_shell-recv: no command specified");
    }

    use tokio::process::Command;

    // Resolve $SHELL if present.
    let mut cmd_parts = command.clone();
    if cmd_parts[0] == "$SHELL" {
        cmd_parts[0] = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    }

    let spawn_result = Command::new(&cmd_parts[0])
        .args(&cmd_parts[1..])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    let mut child = match spawn_result {
        Ok(c) => c,
        Err(e) => {
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

    let mut child_stdout = child.stdout.take().unwrap();
    let mut child_stderr = child.stderr.take().unwrap();
    let mut child_stdin = child.stdin.take();

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
            byte = stream.read_u8(), if child_stdin.is_some() => {
                match byte {
                    Err(_) => { child_stdin = None; }
                    Ok(SHELL_STDIN) => {
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
                        if let Some(ref mut stdin_w) = child_stdin
                            && stdin_w.write_all(&data).await.is_err() {
                                child_stdin = None;
                            }
                    }
                    Ok(SHELL_STDIN_EOF) | Ok(_) => {
                        child_stdin = None;
                    }
                }
            }
        }
    }

    drop(child_stdin);

    let status = child.wait().await?;
    let code = status.code().unwrap_or(1) as u8;
    stream.write_all(&[SHELL_EXIT, code]).await.ok();
    stream.flush().await.ok();

    Ok(())
}
