/// `seam route` — multi-hop routing through intermediate Seam relay nodes.
///
/// Usage:
///   seam route --via relay1.example.com --via relay2.example.com user@dest shell "uptime"
///   seam route --via relay1.example.com user@dest cp /local/file :/remote/path
///
/// Builds a chain: local → relay1 → relay2 → dest.
/// Each hop opens a Seam tunnel through the current hop, then establishes
/// the next Seam connection through that tunnel.
///
/// Each intermediate node must have `seam serve` running (or be reachable via SSH).
use anyhow::{Result, anyhow, bail};
use clap::Args;
use seam_protocol::{
    api::Server,
    crypto::CipherSuite,
    handshake::{IdentityKeypair, pk_from_bytes, pk_to_bytes},
    tunnel::SeamMux,
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{connect, ssh};

#[derive(Args)]
pub struct RouteArgs {
    /// Intermediate relay nodes (repeatable): --via relay1 --via relay2 …
    #[arg(long = "via", value_name = "HOST")]
    pub via: Vec<String>,

    /// Final destination: user@host
    pub dest: String,

    /// Subcommand to run at the destination (shell, cp, etc.)
    #[arg(trailing_var_arg = true)]
    pub subcmd: Vec<String>,

    /// SSH port for initial bootstrap (first hop)
    #[arg(long)]
    pub ssh_port: Option<u16>,
}

pub async fn run(args: RouteArgs, fips_mode: bool) -> Result<()> {
    if args.via.is_empty() {
        bail!("--via must be specified at least once (use `seam shell` for direct connections)");
    }

    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher_str = if fips_mode { "aes256gcm" } else { &cfg.cipher };
    let cipher = CipherSuite::parse(cipher_str).unwrap_or_default();

    eprintln!("route: {} hop(s) → {}", args.via.len(), args.dest);
    for (i, hop) in args.via.iter().enumerate() {
        eprintln!("  hop {}: {hop}", i + 1);
    }
    eprintln!("  dest: {}", args.dest);

    // Step 1: Connect to first relay via SSH bootstrap.
    let first_hop = &args.via[0];
    let (user, host) = ssh::parse_userhost(first_hop);
    let remote = ssh::RemoteInfo {
        host: host.clone(),
        user,
        ssh_port: args.ssh_port,
    };

    eprintln!("  bootstrapping first hop ({first_hop})…");
    let subcmd = "_route-hop-recv --port 0".to_string();
    let (first_conn, _child) =
        connect::bootstrap_and_connect(&remote, &host, &subcmd, cipher).await?;
    let first_mux = Arc::new(SeamMux::new(first_conn));

    // Step 2: For each subsequent hop, open a stream and request forwarding.
    // The relay binds a local UDP proxy and returns the proxy port + next relay's keys.
    let mut current_mux = first_mux;
    let mut current_host = host.clone();

    for hop in &args.via[1..] {
        eprintln!("  chaining through {hop}…");
        let mut stream = current_mux.open_stream().await;

        // Send hop request: [u16 host_len][host bytes][u16 port]
        // Port 0 means default (relay will start _route-hop-recv on the remote and proxy).
        let hop_bytes = hop.as_bytes();
        let host_len = hop_bytes.len() as u16;
        stream.write_all(&host_len.to_be_bytes()).await?;
        stream.write_all(hop_bytes).await?;
        stream.write_all(&0u16.to_be_bytes()).await?; // port hint = 0

        // Read response: [u8 status] then if ok: [u16 proxy_port][u16 x25519_len][x25519][u16 kem_len][kem]
        let mut status = [0u8; 1];
        stream.read_exact(&mut status).await?;
        if status[0] != 1 {
            bail!("relay {current_host} failed to forward to {hop}");
        }

        let mut port_buf = [0u8; 2];
        stream.read_exact(&mut port_buf).await?;
        let proxy_port = u16::from_be_bytes(port_buf);

        let mut x25519_len_buf = [0u8; 2];
        stream.read_exact(&mut x25519_len_buf).await?;
        let x25519_len = u16::from_be_bytes(x25519_len_buf) as usize;
        // X25519 public key is always exactly 32 bytes.
        if x25519_len != 32 {
            bail!("relay returned invalid X25519 key length {x25519_len} (expected 32)");
        }
        let mut x25519_bytes = vec![0u8; x25519_len];
        stream.read_exact(&mut x25519_bytes).await?;
        let x25519: [u8; 32] = x25519_bytes
            .try_into()
            .map_err(|_| anyhow!("relay returned invalid X25519 key"))?;

        let mut kem_len_buf = [0u8; 2];
        stream.read_exact(&mut kem_len_buf).await?;
        let kem_len = u16::from_be_bytes(kem_len_buf) as usize;
        // ML-KEM-768 public key is 1184 bytes; cap well above that to prevent DoS.
        if kem_len > 2048 {
            bail!("relay returned oversized KEM key ({kem_len} bytes)");
        }
        let mut kem_bytes = vec![0u8; kem_len];
        stream.read_exact(&mut kem_bytes).await?;
        let kem_pk = pk_from_bytes(&kem_bytes)
            .ok_or_else(|| anyhow!("relay returned invalid KEM public key"))?;

        // Connect to next relay via the proxy on current_host.
        eprintln!("  connecting through proxy {current_host}:{proxy_port}…");
        let next_conn = connect::dial(&current_host, proxy_port, x25519, kem_pk, cipher).await?;
        current_mux = Arc::new(SeamMux::new(next_conn));
        current_host = {
            let (_, h) = ssh::parse_userhost(hop);
            h
        };
    }

    // At this point current_mux is a Seam connection to the last relay.
    // Connect to the final destination through it.
    eprintln!("  forwarding to destination {}…", args.dest);
    let mut dest_stream = current_mux.open_stream().await;

    let (dest_user, dest_host_raw) = ssh::parse_userhost(&args.dest);
    let dest_hop = format!(
        "{}{dest_host_raw}",
        dest_user
            .as_ref()
            .map(|u| format!("{u}@"))
            .unwrap_or_default()
    );
    let hop_bytes = dest_hop.as_bytes();
    let host_len = hop_bytes.len() as u16;
    dest_stream.write_all(&host_len.to_be_bytes()).await?;
    dest_stream.write_all(hop_bytes).await?;
    dest_stream.write_all(&0u16.to_be_bytes()).await?;

    let mut status = [0u8; 1];
    dest_stream.read_exact(&mut status).await?;
    if status[0] != 1 {
        bail!("last relay failed to forward to {}", args.dest);
    }

    let mut port_buf = [0u8; 2];
    dest_stream.read_exact(&mut port_buf).await?;
    let proxy_port = u16::from_be_bytes(port_buf);

    let mut x25519_len_buf = [0u8; 2];
    dest_stream.read_exact(&mut x25519_len_buf).await?;
    let x25519_len = u16::from_be_bytes(x25519_len_buf) as usize;
    let mut x25519_bytes = vec![0u8; x25519_len];
    dest_stream.read_exact(&mut x25519_bytes).await?;
    let x25519: [u8; 32] = x25519_bytes
        .try_into()
        .map_err(|_| anyhow!("relay returned invalid X25519 key for dest"))?;

    let mut kem_len_buf = [0u8; 2];
    dest_stream.read_exact(&mut kem_len_buf).await?;
    let kem_len = u16::from_be_bytes(kem_len_buf) as usize;
    let mut kem_bytes = vec![0u8; kem_len];
    dest_stream.read_exact(&mut kem_bytes).await?;
    let kem_pk = pk_from_bytes(&kem_bytes)
        .ok_or_else(|| anyhow!("relay returned invalid KEM public key for dest"))?;

    eprintln!("  connecting to destination through proxy {current_host}:{proxy_port}…");
    let dest_conn = connect::dial(&current_host, proxy_port, x25519, kem_pk, cipher).await?;
    let _dest_mux = Arc::new(SeamMux::new(dest_conn));

    if args.subcmd.is_empty() {
        eprintln!(
            "route to {} via {} established.",
            args.dest,
            args.via.join(" → ")
        );
        return Ok(());
    }

    let subcmd_str = args.subcmd.join(" ");
    eprintln!("  executing at destination: {subcmd_str}");

    let subcmd_name = args.subcmd[0].as_str();
    let remaining: Vec<String> = args.subcmd[1..].to_vec();

    match subcmd_name {
        "shell" | "sh" => {
            super::shell::run_with_mux((*_dest_mux).clone(), remaining, false).await
        }
        "pipe" => {
            super::pipe::run_with_mux((*_dest_mux).clone(), remaining).await
        }
        other => {
            bail!(
                "subcommand '{other}' is not supported through multi-hop routes. \
                 Supported subcommands: shell, sh, pipe."
            );
        }
    }
}

// ── Relay-side receiver ───────────────────────────────────────────────────────

#[derive(Args)]
pub struct RouteHopRecvArgs {
    /// UDP port to listen on (0 = OS-assigned)
    #[arg(long, default_value_t = 0)]
    pub port: u16,
}

pub async fn run_hop_recv(args: RouteHopRecvArgs) -> Result<()> {
    let id = IdentityKeypair::generate();
    let x25519_hex = hex::encode(id.x25519_public.as_bytes());
    let kem_hex = hex::encode(pk_to_bytes(&id.kem_pk));

    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let fips_mode = super::config::Config::effective_fips_mode(cfg.fips_mode, false);
    let cipher_str = if fips_mode { "aes256gcm" } else { &cfg.cipher };
    let cipher = CipherSuite::parse(cipher_str).unwrap_or_default();

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

    loop {
        let stream = match mux.accept_stream().await {
            Some(s) => s,
            None => break,
        };

        tokio::spawn(handle_hop_stream(stream, cipher));
    }

    Ok(())
}

/// Handle a single hop-forward request on a relay node.
///
/// Protocol:
///   Client → relay: [u16 host_len][host bytes][u16 port_hint]
///   Relay → client: [u8 status: 0=fail 1=ok]
///                   if ok: [u16 proxy_port][u16 x25519_len][x25519][u16 kem_len][kem]
///
/// The relay SSH-bootstraps to `next_host`, starts `_route-hop-recv` there to get
/// a SEAM line, then binds a local UDP proxy socket.  All UDP traffic arriving at
/// the proxy is forwarded to the next relay's UDP port, and responses are forwarded
/// back.  The client connects to `relay_ip:proxy_port` using the next relay's keys.
async fn handle_hop_stream(mut stream: seam_protocol::tunnel::SeamStream, cipher: CipherSuite) {
    if let Err(e) = do_handle_hop_stream(&mut stream, cipher).await {
        tracing::warn!("route-hop-recv: {e}");
        // Signal failure to client.
        let _ = stream.write_all(&[0u8]).await;
    }
}

async fn do_handle_hop_stream(
    stream: &mut seam_protocol::tunnel::SeamStream,
    _cipher: CipherSuite,
) -> Result<()> {
    use tokio::net::UdpSocket;

    // Read request: [u16 host_len][host][u16 port_hint]
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    let host_len = u16::from_be_bytes(buf) as usize;
    if host_len == 0 || host_len > 512 {
        bail!("invalid host_len {host_len}");
    }
    let mut host_bytes = vec![0u8; host_len];
    stream.read_exact(&mut host_bytes).await?;
    let next_host = std::str::from_utf8(&host_bytes)
        .map_err(|_| anyhow!("non-UTF8 host"))?
        .to_string();
    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    // port_hint is advisory; _route-hop-recv uses --port 0 (OS-assigned).

    // Bootstrap Seam on the next hop via SSH.
    let (user, host) = ssh::parse_userhost(&next_host);
    let remote = ssh::RemoteInfo {
        host: host.clone(),
        user,
        ssh_port: None,
    };
    let seam_bin = match remote.seam_path() {
        Some(p) => p,
        None => remote
            .bootstrap_copy_self()
            .map_err(|e| anyhow!("bootstrap to {next_host} failed: {e}"))?,
    };
    let (line, _child) = remote
        .start_remote_seam(&seam_bin, "_route-hop-recv --port 0")
        .map_err(|e| anyhow!("remote seam on {next_host} failed: {e}"))?;

    // Parse the SEAM line from the next relay.
    let (next_port, x25519, kem_pk) = connect::parse_seam_line(&line)
        .map_err(|e| anyhow!("bad SEAM line from {next_host}: {e}"))?;
    let next_addr: std::net::SocketAddr = format!("{host}:{next_port}").parse()?;

    // Bind a local UDP proxy socket. Forward client ↔ next_relay without decryption.
    let proxy_sock = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| anyhow!("bind proxy socket: {e}"))?,
    );
    let proxy_port = proxy_sock.local_addr()?.port();

    // Spawn the bidirectional UDP proxy task.
    tokio::spawn(udp_proxy(proxy_sock, next_addr));

    // Send success response: [1][proxy_port][x25519_len][x25519][kem_len][kem]
    let x25519_bytes = x25519;
    let kem_bytes = pk_to_bytes(&kem_pk);
    let mut resp = Vec::new();
    resp.push(1u8); // success
    resp.extend_from_slice(&proxy_port.to_be_bytes());
    resp.extend_from_slice(&(x25519_bytes.len() as u16).to_be_bytes());
    resp.extend_from_slice(&x25519_bytes);
    resp.extend_from_slice(&(kem_bytes.len() as u16).to_be_bytes());
    resp.extend_from_slice(&kem_bytes);
    stream.write_all(&resp).await?;

    tracing::info!(
        next_host = %next_host,
        proxy_port,
        "route-hop-recv: proxy established"
    );
    Ok(())
}

/// Bidirectional UDP proxy: forward packets between the client (first sender) and next_relay.
///
/// The proxy learns the client's address on the first received packet. All subsequent
/// packets from the client are forwarded to next_relay, and packets from next_relay
/// are forwarded back to the client.
async fn udp_proxy(sock: Arc<tokio::net::UdpSocket>, next_relay: std::net::SocketAddr) {
    let mut buf = vec![0u8; 65535];
    let mut client_addr: Option<std::net::SocketAddr> = None;

    loop {
        let (n, from) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => break,
        };
        let data = &buf[..n];

        if from == next_relay {
            // Packet from next relay → forward to client.
            if let Some(ca) = client_addr {
                let _ = sock.send_to(data, ca).await;
            }
        } else {
            // Packet from client → record address and forward to next relay.
            client_addr = Some(from);
            let _ = sock.send_to(data, next_relay).await;
        }
    }
}
