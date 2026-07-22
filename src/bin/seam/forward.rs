/// `seam forward` — local port forwarding over a post-quantum Seam tunnel.
///
/// Usage: `seam forward <local_port>:<remote_host>:<remote_port> user@host`
///
/// Binds 0.0.0.0:<local_port> locally. For each incoming TCP connection,
/// opens a new Seam stream to the remote, sends a header frame identifying
/// the destination (<remote_host>:<remote_port>), and the remote side
/// connects TCP to that destination and bridges bidirectionally.
///
/// Multi-hop usage:
///   seam forward 8080:localhost:80 --via jumphost user@air-gapped
///
/// The relay (jumphost) opens its own Seam connection to the target, bridging
/// the two Seam legs. This enables reaching air-gapped nodes that are only
/// reachable from a relay host — a critical use case for DoD environments.
///
/// This is the primary primitive for tunneling any TCP service (HTTP, database,
/// RDP, etc.) over post-quantum encrypted Seam transport.
use anyhow::{Result, anyhow, bail};
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
pub struct ForwardArgs {
    /// Forward spec: LOCAL_PORT:REMOTE_HOST:REMOTE_PORT
    /// Example: 8080:localhost:80  — binds local :8080, forwards to remote's localhost:80
    pub spec: String,
    /// Remote host: user@host (SSH bootstrap target)
    pub remote: String,
    /// SSH port for the bootstrap connection
    #[arg(short = 'p', long)]
    pub port: Option<u16>,
    /// Bind local port on 0.0.0.0 instead of 127.0.0.1 (allow remote clients)
    #[arg(long)]
    pub bind_all: bool,
    /// Route through an intermediate Seam relay node.
    ///
    /// Example: --via user@jumphost
    ///
    /// The relay opens its own Seam connection to the final target, creating
    /// a two-hop encrypted tunnel. Both hops are independently post-quantum
    /// encrypted. Critical for reaching air-gapped nodes.
    #[arg(long, value_name = "user@relay")]
    pub via: Option<String>,

    /// NOT YET IMPLEMENTED — parses but has no effect. See architecture.md#multi-path-transport.
    #[arg(long, value_name = "addr1,addr2,...")]
    pub multipath: Option<String>,

    /// NOT YET IMPLEMENTED — parses but has no effect. See architecture.md#multi-path-transport.
    #[arg(long)]
    pub multipath_redundant: bool,
}

// ── Server (remote receiver) args ─────────────────────────────────────────────

#[derive(Args)]
pub struct ForwardRecvArgs {
    /// UDP port to listen on (0 = OS-assigned)
    #[arg(long, default_value_t = 0)]
    pub port: u16,
}

// ── Multi-hop relay receiver args ─────────────────────────────────────────────

/// Hidden: runs on the relay node, bridges client ↔ target.
#[derive(Args)]
pub struct ForwardHopRecvArgs {
    /// UDP port to listen on (0 = OS-assigned)
    #[arg(long, default_value_t = 0)]
    pub port: u16,
    /// Final target: user@host
    #[arg(long)]
    pub target: String,
    /// SSH port for the target bootstrap
    #[arg(long)]
    pub target_port: Option<u16>,
}

// ── Parse forward spec ────────────────────────────────────────────────────────

/// Parse `LOCAL_PORT:REMOTE_HOST:REMOTE_PORT` → `(local_port, remote_host, remote_port)`.
fn parse_forward_spec(spec: &str) -> Result<(u16, String, u16)> {
    let (local_str, rest) = spec
        .split_once(':')
        .ok_or_else(|| anyhow!("forward spec must be LOCAL_PORT:REMOTE_HOST:REMOTE_PORT"))?;
    let local_port: u16 = local_str
        .parse()
        .map_err(|_| anyhow!("invalid local port: {local_str}"))?;

    let (remote_host, remote_port_str) = rest
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("forward spec must be LOCAL_PORT:REMOTE_HOST:REMOTE_PORT"))?;
    if remote_host.is_empty() {
        bail!("remote_host must not be empty in forward spec");
    }
    let remote_port: u16 = remote_port_str
        .parse()
        .map_err(|_| anyhow!("invalid remote port: {remote_port_str}"))?;

    Ok((local_port, remote_host.to_string(), remote_port))
}

// ── Client (initiating side) ──────────────────────────────────────────────────

pub async fn run(args: ForwardArgs, fips_mode: bool) -> Result<()> {
    connect::warn_if_multipath_requested(&args.multipath, args.multipath_redundant);
    let (local_port, remote_host, remote_port) = parse_forward_spec(&args.spec)?;

    let (user, host) = if let Some(at) = args.remote.find('@') {
        (
            Some(args.remote[..at].to_string()),
            args.remote[at + 1..].to_string(),
        )
    } else {
        (None, args.remote.clone())
    };

    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher_str = if fips_mode {
        "aes256gcm"
    } else {
        cfg.cipher.as_str()
    };
    let cipher = seam_protocol::crypto::CipherSuite::parse(cipher_str).unwrap_or_default();

    if let Some(via) = args.via.as_ref() {
        // ── Multi-hop mode ────────────────────────────────────────────────────
        // Client → relay → target
        // The relay runs `_forward-hop-recv` which bridges client streams to
        // a fresh Seam connection it opens to the target.
        let (relay_user, relay_host) = if let Some(at) = via.find('@') {
            (Some(via[..at].to_string()), via[at + 1..].to_string())
        } else {
            (None, via.clone())
        };

        let relay_remote = ssh::RemoteInfo {
            host: relay_host.clone(),
            user: relay_user,
            ssh_port: args.port,
        };

        // Encode target in the relay subcmd.
        let target_arg = connect::shell_quote(&args.remote);
        let target_port_arg = match args.port {
            Some(p) => format!("--target-port {p} "),
            None => String::new(),
        };
        let subcmd = format!("_forward-hop-recv --port 0 --target {target_arg} {target_port_arg}");

        eprintln!(
            "multi-hop forward: local:{local_port} → relay:{relay_host} → {host}:{remote_host}:{remote_port}"
        );
        if fips_mode {
            eprintln!("  FIPS mode: AES-256-GCM transport");
        }

        let (conn, _child) =
            connect::bootstrap_and_connect(&relay_remote, &relay_host, &subcmd, cipher).await?;
        let mux = SeamMux::new(conn);

        let bind_addr = if args.bind_all {
            format!("0.0.0.0:{local_port}")
        } else {
            format!("127.0.0.1:{local_port}")
        };
        let listener = TcpListener::bind(&bind_addr)
            .await
            .map_err(|e| anyhow!("cannot bind {bind_addr}: {e}"))?;
        let actual_port = listener.local_addr()?.port();

        eprintln!(
            "forward ready (via relay): {}:{actual_port} → {}:{remote_host}:{remote_port}",
            if args.bind_all {
                "0.0.0.0"
            } else {
                "127.0.0.1"
            },
            relay_host,
        );

        loop {
            let (mut tcp, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("forward: accept error: {e}");
                    continue;
                }
            };
            tracing::debug!("forward: new TCP connection from {peer}");

            let mux = mux.clone();
            let rhost = remote_host.clone();
            let rport = remote_port;
            tokio::spawn(async move {
                let mut seam = mux.open_stream().await;

                // The relay's hop-recv expects the same header as _forward-recv:
                // a length-prefixed [u16 host_len][host][u16 port] frame.
                // However here we're talking to the relay, which will forward to target.
                // The relay already knows the target from its command line args;
                // we still send a host:port header because the relay may serve
                // multiple clients routing to different destinations in the future.
                let host_bytes = rhost.as_bytes();
                let mut header = Vec::with_capacity(2 + host_bytes.len() + 2);
                header.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
                header.extend_from_slice(host_bytes);
                header.extend_from_slice(&rport.to_be_bytes());

                let mut framed = Vec::with_capacity(4 + header.len());
                framed.extend_from_slice(&(header.len() as u32).to_be_bytes());
                framed.extend_from_slice(&header);

                use tokio::io::AsyncWriteExt;
                if let Err(e) = seam.write_all(&framed).await {
                    eprintln!("forward: failed to send hop header: {e}");
                    return;
                }

                let _ = tokio::io::copy_bidirectional(&mut tcp, &mut seam).await;
            });
        }
    } else {
        // ── Direct (single-hop) mode ──────────────────────────────────────────
        let remote = ssh::RemoteInfo {
            host: host.clone(),
            user: user.clone(),
            ssh_port: args.port,
        };

        let subcmd = "_forward-recv --port 0".to_string();
        let (conn, _child) =
            connect::bootstrap_and_connect(&remote, &host, &subcmd, cipher).await?;
        let mux = SeamMux::new(conn);

        let bind_addr = if args.bind_all {
            format!("0.0.0.0:{local_port}")
        } else {
            format!("127.0.0.1:{local_port}")
        };
        let listener = TcpListener::bind(&bind_addr)
            .await
            .map_err(|e| anyhow!("cannot bind {bind_addr}: {e}"))?;
        let actual_port = listener.local_addr()?.port();

        eprintln!(
            "forward ready: {}:{actual_port} → {}{}:{}:{}",
            if args.bind_all {
                "0.0.0.0"
            } else {
                "127.0.0.1"
            },
            user.as_deref().map(|u| format!("{u}@")).unwrap_or_default(),
            host,
            remote_host,
            remote_port,
        );
        if fips_mode {
            eprintln!("  FIPS mode: AES-256-GCM transport");
        }

        loop {
            let (mut tcp, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("forward: accept error: {e}");
                    continue;
                }
            };
            tracing::debug!("forward: new TCP connection from {peer}");

            let mux = mux.clone();
            let rhost = remote_host.clone();
            let rport = remote_port;
            tokio::spawn(async move {
                let mut seam = mux.open_stream().await;

                let host_bytes = rhost.as_bytes();
                let mut header = Vec::with_capacity(2 + host_bytes.len() + 2);
                header.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
                header.extend_from_slice(host_bytes);
                header.extend_from_slice(&rport.to_be_bytes());

                let mut framed = Vec::with_capacity(4 + header.len());
                framed.extend_from_slice(&(header.len() as u32).to_be_bytes());
                framed.extend_from_slice(&header);

                use tokio::io::AsyncWriteExt;
                if let Err(e) = seam.write_all(&framed).await {
                    eprintln!("forward: failed to send header: {e}");
                    return;
                }

                let _ = tokio::io::copy_bidirectional(&mut tcp, &mut seam).await;
            });
        }
    }
}

// ── Direct remote receiver ────────────────────────────────────────────────────

pub async fn run_recv(args: ForwardRecvArgs) -> Result<()> {
    let id = IdentityKeypair::generate();
    let x25519_hex = hex::encode(id.x25519_public.as_bytes());
    let kem_hex = hex::encode(pk_to_bytes(&id.kem_pk));

    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let fips_mode = super::config::Config::effective_fips_mode(cfg.fips_mode, false);
    let cipher_str = if fips_mode { "aes256gcm" } else { &cfg.cipher };
    let cipher = seam_protocol::crypto::CipherSuite::parse(cipher_str).unwrap_or_default();

    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;
    let mut server = Server::bind_with_cipher(addr, id, cipher)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    let udp_port = server.local_addr()?.port();

    println!("SEAM PORT={udp_port} X25519={x25519_hex} KEM={kem_hex}");

    let conn = server
        .accept()
        .await
        .ok_or_else(|| anyhow!("no connection"))?;
    let mux = SeamMux::new(conn);
    eprintln!("forward receiver ready");

    loop {
        let mut stream = match mux.accept_stream().await {
            Some(s) => s,
            None => break,
        };

        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;

            let mut len_buf = [0u8; 4];
            if stream.read_exact(&mut len_buf).await.is_err() {
                return;
            }
            let header_len = u32::from_be_bytes(len_buf) as usize;
            if !(4..=4096).contains(&header_len) {
                eprintln!("forward-recv: invalid header length {header_len}");
                return;
            }

            let mut header = vec![0u8; header_len];
            if stream.read_exact(&mut header).await.is_err() {
                return;
            }

            if header.len() < 4 {
                eprintln!("forward-recv: header too short");
                return;
            }
            let host_len = u16::from_be_bytes([header[0], header[1]]) as usize;
            if header.len() < 2 + host_len + 2 {
                eprintln!("forward-recv: header truncated");
                return;
            }
            let host = match std::str::from_utf8(&header[2..2 + host_len]) {
                Ok(h) => h.to_string(),
                Err(_) => {
                    eprintln!("forward-recv: invalid UTF-8 in host");
                    return;
                }
            };
            let port = u16::from_be_bytes([header[2 + host_len], header[2 + host_len + 1]]);
            let target = format!("{host}:{port}");

            tracing::debug!("forward-recv: connecting to {target}");
            match tokio::net::TcpStream::connect(&target).await {
                Ok(mut tcp) => {
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
                }
                Err(e) => {
                    eprintln!("forward-recv: cannot connect to {target}: {e}");
                }
            }
        });
    }

    Ok(())
}

// ── Multi-hop relay receiver ──────────────────────────────────────────────────
//
// Runs on the relay node. Accepts streams from the client and for each one
// opens its own Seam connection to the final target (via SSH bootstrap),
// then bridges the two Seam streams bidirectionally.

pub async fn run_hop_recv(args: ForwardHopRecvArgs) -> Result<()> {
    let id = IdentityKeypair::generate();
    let x25519_hex = hex::encode(id.x25519_public.as_bytes());
    let kem_hex = hex::encode(pk_to_bytes(&id.kem_pk));

    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let fips_mode = super::config::Config::effective_fips_mode(cfg.fips_mode, false);
    let cipher_str = if fips_mode { "aes256gcm" } else { &cfg.cipher };
    let cipher = seam_protocol::crypto::CipherSuite::parse(cipher_str).unwrap_or_default();

    // Bind and emit SEAM line for the client.
    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;
    let mut server = Server::bind_with_cipher(addr, id, cipher)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    let udp_port = server.local_addr()?.port();
    println!("SEAM PORT={udp_port} X25519={x25519_hex} KEM={kem_hex}");

    // Accept the single client connection (one hop-recv per client session).
    let conn = server
        .accept()
        .await
        .ok_or_else(|| anyhow!("hop-recv: no connection from client"))?;
    let mux = SeamMux::new(conn);
    eprintln!(
        "hop-recv: client connected; bridging to target {}",
        args.target
    );

    // Now establish our own connection to the final target (via SSH bootstrap).
    let (target_user, target_host) = if let Some(at) = args.target.find('@') {
        (
            Some(args.target[..at].to_string()),
            args.target[at + 1..].to_string(),
        )
    } else {
        (None, args.target.clone())
    };

    let target_remote = ssh::RemoteInfo {
        host: target_host.clone(),
        user: target_user,
        ssh_port: args.target_port,
    };

    // Bootstrap a _forward-recv on the target.
    let target_subcmd = "_forward-recv --port 0".to_string();
    let (target_conn, _target_child) =
        connect::bootstrap_and_connect(&target_remote, &target_host, &target_subcmd, cipher)
            .await
            .map_err(|e| anyhow!("hop-recv: cannot reach target {}: {e}", args.target))?;

    let target_mux = SeamMux::new(target_conn);
    eprintln!("hop-recv: target {} connected; relay active", args.target);

    // For each client stream, open a new stream to the target and bridge.
    loop {
        let mut client_stream = match mux.accept_stream().await {
            Some(s) => s,
            None => break,
        };

        let target_mux = target_mux.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;

            // Read the forward header the client sends (so we can log the destination).
            let mut len_buf = [0u8; 4];
            if client_stream.read_exact(&mut len_buf).await.is_err() {
                return;
            }
            let header_len = u32::from_be_bytes(len_buf) as usize;
            if !(4..=4096).contains(&header_len) {
                eprintln!("hop-recv: invalid header length {header_len}");
                return;
            }
            let mut header = vec![0u8; header_len];
            if client_stream.read_exact(&mut header).await.is_err() {
                return;
            }

            // Parse dest for logging, then re-frame and forward to target.
            let dest_str = if header.len() >= 4 {
                let host_len = u16::from_be_bytes([header[0], header[1]]) as usize;
                if header.len() >= 2 + host_len + 2 {
                    let h = String::from_utf8_lossy(&header[2..2 + host_len]).to_string();
                    let p = u16::from_be_bytes([header[2 + host_len], header[2 + host_len + 1]]);
                    format!("{h}:{p}")
                } else {
                    "?".into()
                }
            } else {
                "?".into()
            };

            tracing::info!("hop-recv: bridging stream → {dest_str}");
            eprintln!("hop-recv: bridging → {dest_str}");

            // Open stream to target and re-send the header.
            let mut target_stream = target_mux.open_stream().await;
            use tokio::io::AsyncWriteExt;
            let mut framed = Vec::with_capacity(4 + header.len());
            framed.extend_from_slice(&(header.len() as u32).to_be_bytes());
            framed.extend_from_slice(&header);
            if target_stream.write_all(&framed).await.is_err() {
                eprintln!("hop-recv: failed to send header to target");
                return;
            }

            // Bridge the two Seam streams bidirectionally.
            let _ = tokio::io::copy_bidirectional(&mut client_stream, &mut target_stream).await;
        });
    }

    Ok(())
}
