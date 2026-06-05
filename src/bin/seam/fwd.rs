use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{Result, anyhow};
use clap::Args;
use seam_protocol::{
    api::Server,
    handshake::{IdentityKeypair, pk_to_bytes},
    tunnel::SeamMux,
};
use tokio::net::TcpListener;

use crate::{connect, ssh};

// ── Client args ───────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct FwdArgs {
    /// Reverse tunnel spec: user@host:REMOTE_PORT  (remote listens on REMOTE_PORT)
    pub remote_spec: String,
    /// Local port to forward connections to (on this machine)
    pub local_port: u16,
    /// SSH port for the bootstrap connection
    #[arg(short = 'p', long)]
    pub port: Option<u16>,
    /// Local host to forward connections to (default: 127.0.0.1)
    #[arg(long, default_value = "127.0.0.1")]
    pub local_host: String,
}

// ── Server args ───────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct FwdRecvArgs {
    /// TCP port the remote side should listen on (0 = OS-assigned)
    #[arg(long, default_value_t = 0)]
    pub listen_port: u16,
    /// UDP port for the Seam server (0 = OS-assigned)
    #[arg(long, default_value_t = 0)]
    pub port: u16,
}

// ── Parse fwd spec ────────────────────────────────────────────────────────────

/// Parse `user@host:RPORT` → `(user, host, remote_port)`.
fn parse_fwd_spec(spec: &str) -> Result<(Option<String>, String, u16)> {
    let (userhost, port_str) = spec
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("fwd spec must be user@host:REMOTE_PORT"))?;

    let remote_port: u16 = port_str
        .parse()
        .map_err(|_| anyhow!("invalid remote port: {port_str}"))?;

    let (user, host) = if let Some(at) = userhost.find('@') {
        (
            Some(userhost[..at].to_string()),
            userhost[at + 1..].to_string(),
        )
    } else {
        (None, userhost.to_string())
    };

    Ok((user, host, remote_port))
}

// ── Client (initiating side) ──────────────────────────────────────────────────

pub async fn run(args: FwdArgs) -> Result<()> {
    let (user, host, remote_port) = parse_fwd_spec(&args.remote_spec)?;
    let local_host = args.local_host.clone();
    let local_port = args.local_port;
    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher = seam_protocol::crypto::CipherSuite::parse(&cfg.cipher).unwrap_or_default();

    let remote = ssh::RemoteInfo {
        host: host.clone(),
        user: user.clone(),
        ssh_port: args.port,
    };

    // Start the remote receiver: it will listen on TCP :remote_port and wait for
    // the Seam client (us) to connect, then forward accepted TCP connections back.
    let subcmd = format!("_fwd-recv --listen-port {} --port 0", remote_port);
    let (conn, _child) = connect::bootstrap_and_connect(&remote, &host, &subcmd, cipher).await?;

    let mux = SeamMux::new(conn);

    eprintln!(
        "reverse tunnel ready: {}{}:{} → {}:{}",
        user.as_deref().map(|u| format!("{u}@")).unwrap_or_default(),
        host,
        remote_port,
        local_host,
        local_port,
    );
    eprintln!(
        "  (connections on remote :{remote_port} forwarded to local {local_host}:{local_port})"
    );

    // The remote side pushes streams to us whenever a TCP connection is accepted.
    // We accept each stream and connect it to local_host:local_port.
    // consecutive_failures tracks repeated local connect failures; after 5 in a row
    // we back off briefly to avoid spamming logs and burning CPU.
    let consecutive_failures: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));

    loop {
        let stream = match mux.accept_stream().await {
            Some(s) => s,
            None => break,
        };
        let target = format!("{local_host}:{local_port}");
        let failures = Arc::clone(&consecutive_failures);
        tokio::spawn(async move {
            // Back off if local target has been repeatedly unreachable.
            let fail_count = failures.load(Ordering::Relaxed);
            if fail_count > 0 {
                let delay = Duration::from_millis(match fail_count {
                    1..=2 => 100,
                    3..=5 => 500,
                    _ => 2000,
                });
                tokio::time::sleep(delay).await;
            }

            match tokio::net::TcpStream::connect(&target).await {
                Ok(mut tcp) => {
                    failures.store(0, Ordering::Relaxed);
                    let mut s = stream;
                    let _ = tokio::io::copy_bidirectional(&mut s, &mut tcp).await;
                }
                Err(e) => {
                    let n = failures.fetch_add(1, Ordering::Relaxed) + 1;
                    eprintln!("fwd: could not connect to local {target}: {e} (failure #{n})");
                    // Dropping stream signals EOF to the remote side.
                    drop(stream);
                }
            }
        });
    }

    Ok(())
}

// ── Remote receiver ───────────────────────────────────────────────────────────

pub async fn run_recv(args: FwdRecvArgs) -> Result<()> {
    // Start the Seam server so the client can connect back.
    let id = IdentityKeypair::generate();
    let x25519_hex = hex::encode(id.x25519_public.as_bytes());
    let kem_hex = hex::encode(pk_to_bytes(&id.kem_pk));

    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher = seam_protocol::crypto::CipherSuite::parse(&cfg.cipher).unwrap_or_default();
    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;
    let mut server = Server::bind_with_cipher(addr, id, cipher)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    let udp_port = server.local_addr()?.port();

    // Bind the TCP listener before announcing — so the port is ready when the
    // client connects.
    let tcp_listener = TcpListener::bind(("0.0.0.0", args.listen_port))
        .await
        .map_err(|e| anyhow!("failed to bind TCP :{}: {e}", args.listen_port))?;
    let actual_tcp_port = tcp_listener.local_addr()?.port();

    // Announce both UDP seam port and the TCP listen port.
    println!("SEAM PORT={udp_port} X25519={x25519_hex} KEM={kem_hex} TCP={actual_tcp_port}");

    let conn = server
        .accept()
        .await
        .ok_or_else(|| anyhow!("no connection"))?;
    let mux = SeamMux::new(conn);
    eprintln!("reverse tunnel receiver ready on TCP :{actual_tcp_port}");

    // Accept TCP connections from the outside world and open Seam streams back
    // to the originating client for each one.
    loop {
        let (mut tcp, peer) = match tcp_listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("tcp accept error: {e}");
                continue;
            }
        };
        tracing::debug!("fwd-recv: new TCP connection from {peer}");
        let mux = mux.clone();
        tokio::spawn(async move {
            let mut seam = mux.open_stream().await;
            let _ = tokio::io::copy_bidirectional(&mut seam, &mut tcp).await;
        });
    }
}

// ── We need to handle the extra TCP= field in the SEAM line ─────────────────
// The client uses connect::parse_seam_line which ignores unknown fields, so
// the extra TCP= field is silently skipped. That's fine — we derive the
// remote TCP port from args, not from the SEAM line.
