/// `seam serve` — persistent standalone Seam server daemon.
///
/// Starts a Seam server that accepts multiple concurrent client connections
/// without requiring SSH on the remote host. Unlike the SSH-bootstrap model
/// (where a new server process is spawned per-session by `ssh user@host seam _xxx-recv`),
/// this daemon stays alive and handles all arriving connections.
///
/// Usage:
///   seam serve --port 2222
///   seam serve --port 2222 --bind 0.0.0.0
///   seam serve --port 2222 --no-shell
///
/// Each accepted connection is handled in its own task. Incoming Seam streams
/// carry a one-byte service tag that identifies the requested service:
///   0x01 — Shell: execute a command (pty or pipe) and stream I/O
///   0x02 — Forward: connect to a TCP destination and bridge bidirectionally
///   0x03 — Info: return JSON metadata (version, cipher, build info)
///
/// This enables seam as a standalone daemon for air-gapped servers where SSH
/// is not available, and for environments where per-session SSH launch is
/// too slow or not permitted (containers, embedded systems, DoD environments).
///
/// Security:
///   • Post-quantum Noise_XX + ML-KEM-768 handshake; all data AEAD encrypted
///   • Server identity key is loaded from ~/.config/seam/identity (persistent)
///   • Client must complete the cryptographic handshake before any data is
///     processed; unauthenticated packets are rejected by the Noise layer
///   • Optional FIPS-140 mode (forces AES-256-GCM)
use anyhow::{Result, anyhow};
use clap::Args;
use seam_protocol::{
    api::Server,
    handshake::{IdentityKeypair, pk_to_bytes},
    tunnel::SeamMux,
};
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::connect;

// ── Service tag constants ─────────────────────────────────────────────────────

/// Shell service: [pty:u8][cmd_count:u8]([len:u8][bytes]...)
pub const SVC_SHELL: u8 = 0x01;
/// Forward service: length-prefixed host:port header (same as _forward-recv).
pub const SVC_FORWARD: u8 = 0x02;
/// Info service: no payload; server writes JSON and closes.
pub const SVC_INFO: u8 = 0x03;

// ── Wire protocol re-exports (shell constants used by serve clients) ──────────

/// Shell exit frame tag (server → client).
const SHELL_EXIT: u8 = 0x01;
/// Shell error frame tag (server → client).
const SHELL_ERR: u8 = 0x02;
/// Shell stdin data frame tag (client → server).
const SHELL_STDIN: u8 = 0x10;
/// Shell stdin EOF frame tag (client → server).
const SHELL_STDIN_EOF: u8 = 0x11;
/// Terminal resize frame tag (client → server).
const SHELL_RESIZE: u8 = 0x12;
/// TERM env frame tag (client → server).
const SHELL_TERM: u8 = 0x13;

// ── Args ──────────────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct ServeArgs {
    /// UDP port to listen on
    #[arg(short = 'p', long, default_value_t = 2222)]
    pub port: u16,

    /// Address to bind on (use 0.0.0.0 to accept from all interfaces)
    #[arg(short = 'b', long, default_value = "0.0.0.0")]
    pub bind: String,

    /// Maximum concurrent client connections (0 = unlimited)
    #[arg(long, default_value_t = 64)]
    pub max_connections: usize,

    /// Disable the shell service (only forward and info available)
    #[arg(long)]
    pub no_shell: bool,

    /// Print the SEAM handshake line to stdout (for SSH-bootstrap integration)
    #[arg(long, hide = true)]
    pub print_seam_line: bool,
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run(args: ServeArgs, fips_mode: bool) -> Result<()> {
    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher_str = if fips_mode { "aes256gcm" } else { cfg.cipher.as_str() };
    let cipher = seam_protocol::crypto::CipherSuite::parse(cipher_str).unwrap_or_default();

    // Load (or generate) a persistent server identity key so clients can pin it.
    let id_path = connect::identity_path();
    let id = IdentityKeypair::load_or_generate(id_path)
        .unwrap_or_else(|e| {
            eprintln!("warning: could not load identity ({e}) — using ephemeral key");
            IdentityKeypair::generate()
        });

    let x25519_hex = hex::encode(id.x25519_public.as_bytes());
    let kem_hex = hex::encode(pk_to_bytes(&id.kem_pk));

    let bind_str = format!("{}:{}", args.bind, args.port);
    let addr: std::net::SocketAddr = bind_str
        .parse()
        .map_err(|e| anyhow!("invalid bind address {bind_str}: {e}"))?;

    let mut server = Server::bind_with_cipher(addr, id, cipher)
        .await
        .map_err(|e| anyhow!("bind {bind_str}: {e}"))?;

    let actual_addr = server.local_addr()?;
    let actual_port = actual_addr.port();

    // In SSH-bootstrap integration mode, emit the SEAM line and we're done
    // signalling; the main loop below continues accepting connections.
    if args.print_seam_line {
        println!("SEAM PORT={actual_port} X25519={x25519_hex} KEM={kem_hex}");
    } else {
        eprintln!();
        eprintln!("  seam serve — post-quantum Seam daemon  v{}", env!("CARGO_PKG_VERSION"));
        eprintln!("  Listening:   udp://{actual_addr}");
        eprintln!("  X25519 key:  {x25519_hex}");
        eprintln!("  KEM key:     {}…", &kem_hex[..32]);
        if fips_mode {
            eprintln!("  Cipher:      AES-256-GCM (FIPS mode)");
        } else {
            eprintln!("  Cipher:      {cipher_str}");
        }
        if args.no_shell {
            eprintln!("  Shell:       disabled");
        }
        eprintln!();
        eprintln!("  Connect (SSH bootstrap):  seam shell user@<host> -p {actual_port}");
        eprintln!("  Port forward:             seam forward 8080:localhost:80 user@<host> -p {actual_port}");
        eprintln!();
        eprintln!("  Pin this server identity with --tofu on first connect.");
        eprintln!();
    }

    let active = Arc::new(AtomicUsize::new(0));
    let max_conn = args.max_connections;
    let no_shell = args.no_shell;

    loop {
        let conn = match server.accept().await {
            Some(c) => c,
            None => {
                eprintln!("serve: server socket closed — exiting");
                break;
            }
        };

        let peer = conn.remote_addr().await;
        let current = active.fetch_add(1, Ordering::Relaxed) + 1;

        if max_conn > 0 && current > max_conn {
            eprintln!("serve: connection limit {max_conn} reached — dropping {peer}");
            active.fetch_sub(1, Ordering::Relaxed);
            drop(conn);
            continue;
        }

        tracing::info!("serve: connection from {peer} (active: {current})");
        eprintln!("serve: new connection from {peer}  [{current} active]");

        let active_clone = active.clone();
        tokio::spawn(async move {
            let mux = SeamMux::new(conn);
            serve_connection(mux, peer, no_shell).await;
            let remaining = active_clone.fetch_sub(1, Ordering::Relaxed) - 1;
            eprintln!("serve: {peer} disconnected  [{remaining} active]");
        });
    }

    Ok(())
}

// ── Per-connection dispatch ────────────────────────────────────────────────────

async fn serve_connection(
    mux: Arc<SeamMux>,
    peer: std::net::SocketAddr,
    no_shell: bool,
) {
    // Accept streams from this client indefinitely.
    loop {
        let stream = match mux.accept_stream().await {
            Some(s) => s,
            None => break,
        };

        let peer_copy = peer;
        let no_shell_copy = no_shell;
        tokio::spawn(async move {
            if let Err(e) = dispatch_stream(stream, peer_copy, no_shell_copy).await {
                eprintln!("serve: stream from {peer_copy}: {e}");
            }
        });
    }
}

async fn dispatch_stream(
    mut stream: seam_protocol::tunnel::SeamStream,
    peer: std::net::SocketAddr,
    no_shell: bool,
) -> Result<()> {
    let svc = stream.read_u8().await
        .map_err(|e| anyhow!("reading service tag from {peer}: {e}"))?;

    match svc {
        SVC_SHELL => {
            if no_shell {
                let msg = b"shell service is disabled on this server";
                let len = msg.len() as u16;
                let mut frame = vec![SHELL_ERR];
                frame.extend_from_slice(&len.to_be_bytes());
                frame.extend_from_slice(msg);
                stream.write_all(&frame).await.ok();
                return Ok(());
            }
            tracing::info!("serve: {peer} → shell");
            serve_shell(stream, peer).await
        }
        SVC_FORWARD => {
            tracing::info!("serve: {peer} → forward");
            serve_forward(stream, peer).await
        }
        SVC_INFO => {
            tracing::info!("serve: {peer} → info");
            serve_info(stream).await
        }
        tag => {
            eprintln!("serve: unknown service 0x{tag:02x} from {peer}");
            Ok(())
        }
    }
}

// ── Shell service ─────────────────────────────────────────────────────────────

async fn serve_shell(
    mut stream: seam_protocol::tunnel::SeamStream,
    peer: std::net::SocketAddr,
) -> Result<()> {
    // Sub-header: [use_pty: u8][cmd_count: u8] then for each: [len: u8][bytes...]
    let use_pty = stream.read_u8().await? != 0;
    let cmd_count = stream.read_u8().await? as usize;

    let mut command: Vec<String> = Vec::with_capacity(cmd_count.min(64));
    for _ in 0..cmd_count {
        let len = stream.read_u8().await? as usize;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        command.push(String::from_utf8_lossy(&buf).to_string());
    }

    // Default to login shell if no command given.
    if command.is_empty() {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        command = vec![shell, "-l".to_string()];
    }

    eprintln!("serve: {peer} shell {:?}  pty={use_pty}", command);

    if use_pty {
        #[cfg(unix)]
        serve_shell_pty(command, stream).await?;
        #[cfg(not(unix))]
        serve_shell_plain(command, stream).await?;
    } else {
        serve_shell_plain(command, stream).await?;
    }

    Ok(())
}

/// Shell via PTY (Unix only).
#[cfg(unix)]
async fn serve_shell_pty(
    command: Vec<String>,
    mut stream: seam_protocol::tunnel::SeamStream,
) -> Result<()> {
    use tokio::sync::mpsc;

    // Read optional TERM and initial dimensions from client control frames.
    let mut term_env = "xterm-256color".to_string();
    let mut initial_cols: u16 = 80;
    let mut initial_rows: u16 = 24;

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(500);
    loop {
        match tokio::time::timeout_at(deadline, stream.read_u8()).await {
            Ok(Ok(SHELL_TERM)) => {
                let len = stream.read_u8().await.unwrap_or(0) as usize;
                let mut buf = vec![0u8; len];
                stream.read_exact(&mut buf).await.ok();
                term_env = String::from_utf8_lossy(&buf).to_string();
            }
            Ok(Ok(SHELL_RESIZE)) => {
                let mut dim = [0u8; 4];
                stream.read_exact(&mut dim).await.ok();
                initial_cols = u16::from_be_bytes([dim[0], dim[1]]);
                initial_rows = u16::from_be_bytes([dim[2], dim[3]]);
                break;
            }
            _ => break,
        }
    }

    // Allocate PTY.
    let mut master: i32 = -1;
    let mut slave: i32 = -1;
    let ws = libc::winsize {
        ws_col: initial_cols,
        ws_row: initial_rows,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let ret = unsafe {
        libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null(), &ws)
    };
    if ret != 0 {
        return Err(anyhow!("openpty failed: {}", std::io::Error::last_os_error()));
    }

    // Resolve $SHELL.
    let mut cmd = command;
    if cmd[0] == "$SHELL" {
        cmd[0] = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    }

    // Fork+exec child.
    let child_pid = fork_exec_pty(&cmd, slave, &term_env)?;
    unsafe { libc::close(slave) };

    // Non-blocking master.
    unsafe { libc::fcntl(master, libc::F_SETFL, libc::O_NONBLOCK) };

    let master_wr = unsafe { libc::dup(master) };

    let (pty_out_tx, pty_out_rx) = mpsc::channel::<Vec<u8>>(64);
    let (pty_in_tx, mut pty_in_rx) = mpsc::channel::<Vec<u8>>(64);

    // Read master → channel.
    let out_tx = pty_out_tx;
    let master_rd = master;
    tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe {
                libc::read(master_rd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
            };
            if n <= 0 { break; }
            if out_tx.blocking_send(buf[..n as usize].to_vec()).is_err() { break; }
        }
    });

    // Write channel → master.
    tokio::task::spawn_blocking(move || {
        while let Some(data) = pty_in_rx.blocking_recv() {
            let mut off = 0;
            while off < data.len() {
                let n = unsafe {
                    libc::write(master_wr, data[off..].as_ptr() as *const libc::c_void, data.len() - off)
                };
                if n <= 0 { return; }
                off += n as usize;
            }
        }
        unsafe { libc::close(master_wr) };
    });

    let exit_code = run_pty_bridge(master, child_pid, stream, pty_out_rx, pty_in_tx).await;
    unsafe { libc::close(master) };

    // Note: stream is moved into bridge; the bridge sends the exit frame.
    let _ = exit_code;
    Ok(())
}

#[cfg(unix)]
async fn run_pty_bridge(
    master_fd: i32,
    child_pid: libc::pid_t,
    mut stream: seam_protocol::tunnel::SeamStream,
    mut pty_out_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    pty_in_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
) -> u8 {
    let mut exit_code = 0u8;

    'bridge: loop {
        tokio::select! {
            data = pty_out_rx.recv() => {
                match data {
                    None => break 'bridge,
                    Some(bytes) => {
                        if stream.write_all(&bytes).await.is_err() { break 'bridge; }
                        stream.flush().await.ok();
                    }
                }
            }
            b = stream.read_u8() => {
                match b {
                    Err(_) => break 'bridge,
                    Ok(SHELL_STDIN_EOF) => {
                        drop(pty_in_tx);
                        break 'bridge;
                    }
                    Ok(SHELL_STDIN) => {
                        let mut len_buf = [0u8; 2];
                        if stream.read_exact(&mut len_buf).await.is_err() { break 'bridge; }
                        let n = u16::from_be_bytes(len_buf) as usize;
                        let mut data = vec![0u8; n];
                        if stream.read_exact(&mut data).await.is_err() { break 'bridge; }
                        pty_in_tx.send(data).await.ok();
                    }
                    Ok(SHELL_RESIZE) => {
                        let mut dim = [0u8; 4];
                        if stream.read_exact(&mut dim).await.is_ok() {
                            let ws = libc::winsize {
                                ws_col: u16::from_be_bytes([dim[0], dim[1]]),
                                ws_row: u16::from_be_bytes([dim[2], dim[3]]),
                                ws_xpixel: 0, ws_ypixel: 0,
                            };
                            unsafe { libc::ioctl(master_fd, libc::TIOCSWINSZ, &ws) };
                        }
                    }
                    Ok(_) => {}
                }
            }
        }
    }

    // Reap child.
    let mut wstatus = 0i32;
    unsafe { libc::waitpid(child_pid, &mut wstatus, 0) };
    if libc::WIFEXITED(wstatus) {
        exit_code = libc::WEXITSTATUS(wstatus) as u8;
    } else if libc::WIFSIGNALED(wstatus) {
        exit_code = 128 + libc::WTERMSIG(wstatus) as u8;
    }

    stream.write_all(&[SHELL_EXIT, exit_code]).await.ok();
    stream.flush().await.ok();
    exit_code
}

#[cfg(unix)]
fn fork_exec_pty(command: &[String], slave_fd: i32, term: &str) -> Result<libc::pid_t> {
    use std::ffi::CString;

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(anyhow!("fork: {}", std::io::Error::last_os_error()));
    }
    if pid == 0 {
        unsafe {
            libc::setsid();
            libc::ioctl(slave_fd, libc::TIOCSCTTY, 0);
            libc::dup2(slave_fd, 0);
            libc::dup2(slave_fd, 1);
            libc::dup2(slave_fd, 2);
            for fd in 3..256i32 { libc::close(fd); }
        }
        let k = std::ffi::CString::new("TERM").unwrap();
        let v = CString::new(term).unwrap_or_else(|_| CString::new("xterm").unwrap());
        unsafe { libc::setenv(k.as_ptr(), v.as_ptr(), 1) };

        let prog = CString::new(command[0].as_str()).unwrap();
        let args: Vec<CString> = command.iter()
            .map(|s| CString::new(s.as_str()).unwrap_or_else(|_| CString::new("").unwrap()))
            .collect();
        let ptrs: Vec<*const libc::c_char> = args.iter().map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        unsafe { libc::execvp(prog.as_ptr(), ptrs.as_ptr()); libc::_exit(127) };
    }
    Ok(pid)
}

/// Plain (non-PTY) shell service.
async fn serve_shell_plain(
    command: Vec<String>,
    mut stream: seam_protocol::tunnel::SeamStream,
) -> Result<()> {
    use tokio::process::Command;

    let mut cmd = command;
    if cmd[0] == "$SHELL" {
        cmd[0] = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    }

    let spawn_result = Command::new(&cmd[0])
        .args(&cmd[1..])
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
            let mut frame = vec![SHELL_ERR];
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
        if stdout_done && stderr_done { break; }
        tokio::select! {
            n = child_stdout.read(&mut out_buf), if !stdout_done => {
                match n {
                    Ok(0) | Err(_) => { stdout_done = true; }
                    Ok(n) => { if stream.write_all(&out_buf[..n]).await.is_err() { break; } }
                }
            }
            n = child_stderr.read(&mut err_buf), if !stderr_done => {
                match n {
                    Ok(0) | Err(_) => { stderr_done = true; }
                    Ok(n) => { if stream.write_all(&err_buf[..n]).await.is_err() { break; } }
                }
            }
            byte = stream.read_u8(), if child_stdin.is_some() => {
                match byte {
                    Err(_) => { child_stdin = None; }
                    Ok(SHELL_STDIN) => {
                        let mut len_buf = [0u8; 2];
                        if stream.read_exact(&mut len_buf).await.is_err() { child_stdin = None; continue; }
                        let n = u16::from_be_bytes(len_buf) as usize;
                        let mut data = vec![0u8; n];
                        if stream.read_exact(&mut data).await.is_err() { child_stdin = None; continue; }
                        if let Some(ref mut w) = child_stdin {
                            if w.write_all(&data).await.is_err() { child_stdin = None; }
                        }
                    }
                    Ok(SHELL_STDIN_EOF) | Ok(_) => { child_stdin = None; }
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

// ── Forward service ───────────────────────────────────────────────────────────

async fn serve_forward(
    mut stream: seam_protocol::tunnel::SeamStream,
    peer: std::net::SocketAddr,
) -> Result<()> {
    // Same header format as _forward-recv: [u32 header_len][u16 host_len][host][u16 port]
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await
        .map_err(|e| anyhow!("forward header from {peer}: {e}"))?;
    let header_len = u32::from_be_bytes(len_buf) as usize;
    if header_len < 4 || header_len > 4096 {
        return Err(anyhow!("invalid forward header length {header_len} from {peer}"));
    }

    let mut header = vec![0u8; header_len];
    stream.read_exact(&mut header).await
        .map_err(|e| anyhow!("reading forward header from {peer}: {e}"))?;

    if header.len() < 4 {
        return Err(anyhow!("forward header too short"));
    }
    let host_len = u16::from_be_bytes([header[0], header[1]]) as usize;
    if header.len() < 2 + host_len + 2 {
        return Err(anyhow!("forward header truncated"));
    }
    let host = std::str::from_utf8(&header[2..2 + host_len])
        .map_err(|_| anyhow!("invalid UTF-8 in forward host"))?
        .to_string();
    let port = u16::from_be_bytes([header[2 + host_len], header[2 + host_len + 1]]);
    let target = format!("{host}:{port}");

    eprintln!("serve: {peer} forward → {target}");

    match tokio::net::TcpStream::connect(&target).await {
        Ok(mut tcp) => {
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
        }
        Err(e) => {
            eprintln!("serve: cannot connect to {target}: {e}");
        }
    }

    Ok(())
}

// ── Info service ──────────────────────────────────────────────────────────────

async fn serve_info(mut stream: seam_protocol::tunnel::SeamStream) -> Result<()> {
    let info = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "transport": "Noise_XX + ML-KEM-768",
        "cipher": "negotiated per-connection",
        "services": ["shell", "forward", "info"],
        "pty": cfg!(unix),
    });
    let json = serde_json::to_string_pretty(&info)?;
    stream.write_all(json.as_bytes()).await.ok();
    Ok(())
}
