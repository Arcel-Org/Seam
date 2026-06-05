use std::io::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use clap::Args;
use seam_protocol::{
    api::Server,
    handshake::{IdentityKeypair, pk_to_bytes},
    tunnel::SeamMux,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::{connect, ssh};

// ── Protocol frame tags ───────────────────────────────────────────────────────

const TUNNEL_STATUS_TAG: u8 = 0x20;
const TUNNEL_CLOSE_TAG: u8 = 0x21;
const TUNNEL_CLOSE_ACK_TAG: u8 = 0x22;

// ── Timing constants ──────────────────────────────────────────────────────────

const TUNNEL_STATUS_INTERVAL: Duration = Duration::from_secs(5);
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const RECONNECT_BASE_MS: u64 = 100;
const RECONNECT_CAP_MS: u64 = 30_000;

// ── Shared stats ──────────────────────────────────────────────────────────────

#[derive(Default)]
struct TunnelStats {
    connections_served: AtomicU64,
    connections_active: AtomicU32,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

// ── Status frame (server → client, tag 0x20) ─────────────────────────────────

struct TunnelStatusFrame {
    connections_active: u32,
    bytes_in: u64,
    bytes_out: u64,
    uptime_seconds: u64,
}

impl TunnelStatusFrame {
    fn encode(&self) -> [u8; 29] {
        let mut buf = [0u8; 29];
        buf[0] = TUNNEL_STATUS_TAG;
        buf[1..5].copy_from_slice(&self.connections_active.to_le_bytes());
        buf[5..13].copy_from_slice(&self.bytes_in.to_le_bytes());
        buf[13..21].copy_from_slice(&self.bytes_out.to_le_bytes());
        buf[21..29].copy_from_slice(&self.uptime_seconds.to_le_bytes());
        buf
    }

    fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 29 || data[0] != TUNNEL_STATUS_TAG {
            return None;
        }
        Some(Self {
            connections_active: u32::from_le_bytes(data[1..5].try_into().ok()?),
            bytes_in: u64::from_le_bytes(data[5..13].try_into().ok()?),
            bytes_out: u64::from_le_bytes(data[13..21].try_into().ok()?),
            uptime_seconds: u64::from_le_bytes(data[21..29].try_into().ok()?),
        })
    }
}

// ── Client args ───────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct TunnelArgs {
    /// Local port(s) to expose. Example: seam tunnel 8080 8443 3000
    #[arg(required = true, num_args = 1..)]
    pub ports: Vec<u16>,

    /// Remote host: user@host (SSH bootstrap target)
    pub remote: String,

    /// SSH port for the bootstrap connection
    #[arg(short = 'p', long)]
    pub port: Option<u16>,

    /// Session label shown in server-side logs
    #[arg(long, value_name = "LABEL")]
    pub name: Option<String>,

    /// Request a specific subdomain from the relay (relay may reject if taken)
    #[arg(long, value_name = "NAME")]
    pub subdomain: Option<String>,

    /// HTTP mode: inspect Host header for virtual hosting
    #[arg(long, conflicts_with = "tcp")]
    pub http: bool,

    /// Raw TCP passthrough (default)
    #[arg(long)]
    pub tcp: bool,

    /// Log each request method+path+status+latency to stdout (HTTP mode only)
    #[arg(long)]
    pub inspect: bool,

    /// Skip SSH bootstrap; connect to this pre-started SEAM line directly
    #[arg(long, value_name = "SEAM_LINE")]
    pub direct: Option<String>,
}

// ── Server args ───────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct TunnelRecvArgs {
    /// Remote host to forward TCP connections to
    pub remote_host: String,
    /// Remote port to forward TCP connections to
    pub remote_port: u16,
    /// UDP port to listen on (0 = OS-assigned)
    #[arg(long, default_value_t = 0)]
    pub port: u16,
    /// Session label (logged server-side)
    #[arg(long)]
    pub name: Option<String>,
}

// ── Tunnel mode ───────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum TunnelMode {
    Tcp,
    Http { inspect: bool },
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

fn parse_http_request_line(buf: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(buf).ok()?;
    let first = text.lines().next()?;
    let mut parts = first.splitn(3, ' ');
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    Some((method, path))
}

fn parse_http_status(buf: &[u8]) -> String {
    std::str::from_utf8(buf)
        .ok()
        .and_then(|s| s.lines().next())
        .and_then(|l| l.splitn(3, ' ').nth(1))
        .unwrap_or("???")
        .to_string()
}

// ── Terminal status line ──────────────────────────────────────────────────────

fn print_status(stats: &TunnelStats, start: Instant) {
    let served = stats.connections_served.load(Ordering::Relaxed);
    let active = stats.connections_active.load(Ordering::Relaxed);
    let uptime = start.elapsed().as_secs();
    let line = format!("  [{uptime:>6}s] {served} connections served  {active} active\r");
    let _ = std::io::stderr().write_all(line.as_bytes());
    let _ = std::io::stderr().flush();
}

// ── Client entry point ────────────────────────────────────────────────────────

pub async fn run(args: TunnelArgs) -> Result<()> {
    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher = seam_protocol::crypto::CipherSuite::parse(&cfg.cipher).unwrap_or_default();

    let mode = if args.http {
        TunnelMode::Http {
            inspect: args.inspect,
        }
    } else {
        TunnelMode::Tcp
    };

    let name = args.name.clone().unwrap_or_else(|| "default".to_string());

    let relay_display = {
        let r = &args.remote;
        if let Some(at) = r.find('@') {
            format!("{}", &r[at + 1..])
        } else {
            r.clone()
        }
    };

    let stats = Arc::new(TunnelStats::default());
    let start = Instant::now();

    // ── Ctrl-C → graceful shutdown ─────────────────────────────────────────────
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let shutdown_tx = Arc::new(shutdown_tx);
    {
        let tx = shutdown_tx.clone();
        let _ = ctrlc::set_handler(move || {
            let _ = tx.send(true);
        });
    }

    // ── Header ────────────────────────────────────────────────────────────────
    eprintln!();
    eprintln!("  Seam Tunnel active");
    for &lp in &args.ports {
        eprintln!("  Local:  http://localhost:{lp}");
    }
    if let Some(ref sub) = args.subdomain {
        eprintln!("  Remote: seam://{sub}.{relay_display} (forwarded)");
    } else {
        eprintln!("  Remote: seam://{relay_display} (forwarded)");
    }
    eprintln!("  PQ:     ML-KEM-768 + X25519 hybrid \u{2713}");
    eprintln!("  Hops:   1");
    eprintln!(
        "  Mode:   {}{}",
        match mode {
            TunnelMode::Tcp => "TCP",
            TunnelMode::Http { .. } => "HTTP",
        },
        if args.inspect { " (inspect)" } else { "" },
    );
    eprintln!("  Name:   {name}");
    eprintln!();
    eprintln!("  Press Ctrl+C to stop.");
    eprintln!();

    // ── One forwarding task per port ──────────────────────────────────────────
    let mut handles = Vec::new();
    for &local_port in &args.ports {
        let remote = args.remote.clone();
        let ssh_port = args.port;
        let direct = args.direct.clone();
        let name_c = name.clone();
        let cipher_c = cipher;
        let stats_c = Arc::clone(&stats);
        let mut srx = shutdown_rx.clone();

        handles.push(tokio::spawn(async move {
            run_port_forward(
                local_port,
                &remote,
                ssh_port,
                direct.as_deref(),
                &name_c,
                cipher_c,
                mode,
                stats_c,
                &mut srx,
            )
            .await
        }));
    }

    // ── Live status ticker ────────────────────────────────────────────────────
    {
        let stats_c = Arc::clone(&stats);
        let mut srx = shutdown_rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {
                        print_status(&stats_c, start);
                    }
                    _ = srx.changed() => break,
                }
            }
        });
    }

    // Wait for Ctrl-C
    {
        let mut srx = shutdown_rx.clone();
        srx.changed().await.ok();
    }

    eprintln!("\n  Shutting down…");
    let deadline = tokio::time::sleep(GRACEFUL_SHUTDOWN_TIMEOUT);
    tokio::pin!(deadline);
    for h in handles {
        tokio::select! {
            _ = h => {}
            _ = &mut deadline => break,
        }
    }

    let total = stats.connections_served.load(Ordering::Relaxed);
    eprintln!("  Tunnel closed. {total} total connections served.");
    Ok(())
}

// ── Per-port forwarding loop with auto-reconnect ─────────────────────────────

async fn run_port_forward(
    local_port: u16,
    remote: &str,
    ssh_port: Option<u16>,
    direct: Option<&str>,
    name: &str,
    cipher: seam_protocol::crypto::CipherSuite,
    mode: TunnelMode,
    stats: Arc<TunnelStats>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", local_port)).await?;
    let actual_port = listener.local_addr()?.port();
    let mut backoff_ms = RECONNECT_BASE_MS;
    let mut attempt: u32 = 0;

    loop {
        let mux = match connect_mux(remote, ssh_port, direct, name, cipher).await {
            Ok(m) => {
                if attempt > 0 {
                    eprintln!("\n  [:{actual_port}] reconnected after {attempt} attempt(s)");
                }
                backoff_ms = RECONNECT_BASE_MS;
                attempt = 0;
                m
            }
            Err(e) => {
                attempt += 1;
                eprintln!(
                    "\n  [:{actual_port}] connect failed (attempt {attempt}): {e}  — retry in {backoff_ms}ms"
                );
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(backoff_ms)) => {}
                    _ = shutdown_rx.changed() => return Ok(()),
                }
                backoff_ms = (backoff_ms * 2).min(RECONNECT_CAP_MS);
                continue;
            }
        };

        let dropped = serve_loop(&listener, mux, mode, Arc::clone(&stats), shutdown_rx).await;

        if *shutdown_rx.borrow() {
            return Ok(());
        }

        if dropped {
            attempt += 1;
            eprintln!("\n  [:{actual_port}] tunnel dropped — reconnecting in {backoff_ms}ms…");
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(backoff_ms)) => {}
                _ = shutdown_rx.changed() => return Ok(()),
            }
            backoff_ms = (backoff_ms * 2).min(RECONNECT_CAP_MS);
        } else {
            return Ok(());
        }
    }
}

async fn connect_mux(
    remote: &str,
    ssh_port: Option<u16>,
    direct: Option<&str>,
    name: &str,
    cipher: seam_protocol::crypto::CipherSuite,
) -> Result<Arc<SeamMux>> {
    if let Some(line) = direct {
        let (port, x25519, kem_pk) = connect::parse_seam_line(line)?;
        let conn = connect::dial("127.0.0.1", port, x25519, kem_pk, cipher).await?;
        return Ok(SeamMux::new(conn));
    }

    let (user, host) = if let Some(at) = remote.find('@') {
        (Some(remote[..at].to_string()), remote[at + 1..].to_string())
    } else {
        (None, remote.to_string())
    };

    let remote_info = ssh::RemoteInfo {
        host: host.clone(),
        user,
        ssh_port,
    };
    let subcmd = format!(
        "_tunnel-recv localhost 0 --port 0 --name {}",
        connect::shell_quote(name)
    );
    let (conn, _child) =
        connect::bootstrap_and_connect(&remote_info, &host, &subcmd, cipher).await?;

    // _child is intentionally moved here and dropped when mux closes.
    let mux = SeamMux::new(conn);
    Ok(mux)
}

/// Returns `true` if the mux dropped unexpectedly (should reconnect).
async fn serve_loop(
    listener: &TcpListener,
    mux: Arc<SeamMux>,
    mode: TunnelMode,
    stats: Arc<TunnelStats>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> bool {
    // Drain server-initiated control streams (status frames) in background.
    {
        let mux_ctrl = mux.clone();
        let stats_c = Arc::clone(&stats);
        tokio::spawn(async move {
            drain_control_streams(mux_ctrl, stats_c).await;
        });
    }

    loop {
        let result = tokio::select! {
            r = listener.accept() => r,
            _ = shutdown_rx.changed() => return false,
        };

        let (tcp, peer) = match result {
            Ok(v) => v,
            Err(e) => {
                eprintln!("\n  accept: {e}");
                return true;
            }
        };

        tracing::debug!("tunnel: connection from {peer}");
        let mux_c = mux.clone();
        let stats_c = Arc::clone(&stats);

        tokio::spawn(async move {
            stats_c.connections_active.fetch_add(1, Ordering::Relaxed);
            stats_c.connections_served.fetch_add(1, Ordering::Relaxed);
            match mode {
                TunnelMode::Tcp => {
                    let mut seam = mux_c.open_stream().await;
                    let _ = bridge_counted(tcp, &mut seam, &stats_c).await;
                }
                TunnelMode::Http { inspect } => {
                    bridge_http(tcp, mux_c, inspect, &stats_c).await;
                }
            }
            stats_c.connections_active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

/// Reads server-initiated streams and processes TUNNEL_STATUS frames.
async fn drain_control_streams(mux: Arc<SeamMux>, stats: Arc<TunnelStats>) {
    loop {
        let mut stream = match mux.accept_stream().await {
            Some(s) => s,
            None => break,
        };

        let stats_c = Arc::clone(&stats);
        tokio::spawn(async move {
            let mut buf = [0u8; 29];
            if stream.read_exact(&mut buf).await.is_err() {
                return;
            }
            if let Some(frame) = TunnelStatusFrame::decode(&buf) {
                // Apply server stats to local view (server is authoritative for its counters).
                stats_c
                    .connections_active
                    .store(frame.connections_active, Ordering::Relaxed);
                stats_c.bytes_in.store(frame.bytes_in, Ordering::Relaxed);
                stats_c.bytes_out.store(frame.bytes_out, Ordering::Relaxed);
                tracing::debug!(
                    "tunnel status: active={} bytes_in={} bytes_out={} uptime={}s",
                    frame.connections_active,
                    frame.bytes_in,
                    frame.bytes_out,
                    frame.uptime_seconds,
                );
            }
        });
    }
}

async fn bridge_counted(
    mut tcp: tokio::net::TcpStream,
    seam: &mut seam_protocol::tunnel::SeamStream,
    stats: &Arc<TunnelStats>,
) -> std::io::Result<()> {
    let (mut tr, mut tw) = tcp.split();
    let (mut sr, mut sw) = tokio::io::split(seam);

    let stats_in = Arc::clone(stats);
    let s2t = async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = sr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            stats_in.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
            tw.write_all(&buf[..n]).await?;
        }
        let _ = tw.shutdown().await;
        Ok::<(), std::io::Error>(())
    };

    let stats_out = Arc::clone(stats);
    let t2s = async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = tr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            stats_out.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
            sw.write_all(&buf[..n]).await?;
        }
        Ok::<(), std::io::Error>(())
    };

    let _ = tokio::join!(s2t, t2s);
    Ok(())
}

async fn bridge_http(
    mut tcp: tokio::net::TcpStream,
    mux: Arc<SeamMux>,
    inspect: bool,
    stats: &Arc<TunnelStats>,
) {
    let req_start = Instant::now();
    let mut hdr = vec![0u8; 4096];
    let n = match tcp.read(&mut hdr).await {
        Ok(0) | Err(_) => return,
        Ok(n) => n,
    };
    let (method, path) =
        parse_http_request_line(&hdr[..n]).unwrap_or_else(|| ("TCP".to_string(), "-".to_string()));

    let mut seam = mux.open_stream().await;
    if seam.write_all(&hdr[..n]).await.is_err() {
        return;
    }
    stats.bytes_out.fetch_add(n as u64, Ordering::Relaxed);

    if inspect {
        let mut resp = vec![0u8; 4096];
        let rn = seam.read(&mut resp).await.unwrap_or(0);
        if rn > 0 {
            stats.bytes_in.fetch_add(rn as u64, Ordering::Relaxed);
            let status = parse_http_status(&resp[..rn]);
            let ms = req_start.elapsed().as_millis();
            eprintln!("\n  {method} {path} → {status} ({ms}ms)");
            if tcp.write_all(&resp[..rn]).await.is_err() {
                return;
            }
        }
    }

    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut seam).await;
}

// ── Server (remote receiver) ──────────────────────────────────────────────────

pub async fn run_recv(args: TunnelRecvArgs) -> Result<()> {
    if args.remote_host.is_empty() {
        bail!("remote_host must not be empty");
    }

    let label = args.name.as_deref().unwrap_or("default");
    eprintln!(
        "tunnel-recv: session={label} target={}:{}",
        args.remote_host, args.remote_port
    );

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

    println!("SEAM PORT={port} X25519={x25519_hex} KEM={kem_hex}");

    let conn = server
        .accept()
        .await
        .ok_or_else(|| anyhow!("no connection"))?;
    let mux = SeamMux::new(conn);

    let stats = Arc::new(TunnelStats::default());
    let start = Instant::now();

    // ── Periodic status broadcaster → client ──────────────────────────────────
    {
        let mux_s = mux.clone();
        let stats_s = Arc::clone(&stats);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(TUNNEL_STATUS_INTERVAL).await;
                let frame = TunnelStatusFrame {
                    connections_active: stats_s.connections_active.load(Ordering::Relaxed),
                    bytes_in: stats_s.bytes_in.load(Ordering::Relaxed),
                    bytes_out: stats_s.bytes_out.load(Ordering::Relaxed),
                    uptime_seconds: start.elapsed().as_secs(),
                }
                .encode();
                let mut ctrl = mux_s.open_stream().await;
                if ctrl.write_all(&frame).await.is_err() {
                    break;
                }
                let _ = ctrl.shutdown().await;
            }
        });
    }

    // ── Accept multiplexed streams ────────────────────────────────────────────
    loop {
        let stream = match mux.accept_stream().await {
            Some(s) => s,
            None => break,
        };

        let stats_c = Arc::clone(&stats);
        let target = format!("{}:{}", args.remote_host, args.remote_port);

        tokio::spawn(async move {
            handle_recv_stream(stream, &target, stats_c).await;
        });
    }

    Ok(())
}

async fn handle_recv_stream(
    mut stream: seam_protocol::tunnel::SeamStream,
    target: &str,
    stats: Arc<TunnelStats>,
) {
    let mut peek = [0u8; 1];
    if stream.read_exact(&mut peek).await.is_err() {
        return;
    }

    if peek[0] == TUNNEL_CLOSE_TAG {
        let _ = stream.write_all(&[TUNNEL_CLOSE_ACK_TAG]).await;
        let _ = stream.shutdown().await;
        eprintln!("tunnel-recv: client requested graceful close");
        return;
    }

    // Regular data stream: the peeked byte is the first data byte.
    stats.connections_active.fetch_add(1, Ordering::Relaxed);
    stats.connections_served.fetch_add(1, Ordering::Relaxed);

    match tokio::net::TcpStream::connect(target).await {
        Ok(mut tcp) => {
            let _ = tcp.write_all(&peek).await;
            let _ = bridge_recv(&mut stream, &mut tcp, &stats).await;
        }
        Err(e) => {
            eprintln!("tunnel-recv: connect {target}: {e}");
        }
    }

    stats.connections_active.fetch_sub(1, Ordering::Relaxed);
}

async fn bridge_recv(
    seam: &mut seam_protocol::tunnel::SeamStream,
    tcp: &mut tokio::net::TcpStream,
    stats: &Arc<TunnelStats>,
) -> std::io::Result<()> {
    let (mut sr, mut sw) = tokio::io::split(seam);
    let (mut tr, mut tw) = tcp.split();

    let stats_out = Arc::clone(stats);
    let s2t = async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = sr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            stats_out.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
            tw.write_all(&buf[..n]).await?;
        }
        Ok::<(), std::io::Error>(())
    };

    let stats_in = Arc::clone(stats);
    let t2s = async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = tr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            stats_in.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
            sw.write_all(&buf[..n]).await?;
        }
        Ok::<(), std::io::Error>(())
    };

    let _ = tokio::join!(s2t, t2s);
    Ok(())
}
