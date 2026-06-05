/// `seam forward` — local port forwarding over a post-quantum Seam tunnel.
///
/// Usage: `seam forward <local_port>:<remote_host>:<remote_port> user@host`
///
/// Binds 0.0.0.0:<local_port> locally. For each incoming TCP connection,
/// opens a new Seam stream to the remote, sends a header frame identifying
/// the destination (<remote_host>:<remote_port>), and the remote side
/// connects TCP to that destination and bridges bidirectionally.
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
}

// ── Server (remote receiver) args ─────────────────────────────────────────────

#[derive(Args)]
pub struct ForwardRecvArgs {
    /// UDP port to listen on (0 = OS-assigned)
    #[arg(long, default_value_t = 0)]
    pub port: u16,
}

// ── Parse forward spec ────────────────────────────────────────────────────────

/// Parse `LOCAL_PORT:REMOTE_HOST:REMOTE_PORT` → `(local_port, remote_host, remote_port)`.
fn parse_forward_spec(spec: &str) -> Result<(u16, String, u16)> {
    // Split at first colon to get local port
    let (local_str, rest) = spec
        .split_once(':')
        .ok_or_else(|| anyhow!("forward spec must be LOCAL_PORT:REMOTE_HOST:REMOTE_PORT"))?;
    let local_port: u16 = local_str
        .parse()
        .map_err(|_| anyhow!("invalid local port: {local_str}"))?;

    // Split at last colon to get remote port (remote_host may contain colons for IPv6)
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
    let (local_port, remote_host, remote_port) = parse_forward_spec(&args.spec)?;

    // Parse user@host from the remote argument.
    let (user, host) = if let Some(at) = args.remote.find('@') {
        (
            Some(args.remote[..at].to_string()),
            args.remote[at + 1..].to_string(),
        )
    } else {
        (None, args.remote.clone())
    };

    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher_str = if fips_mode { "aes256gcm" } else { cfg.cipher.as_str() };
    let cipher = seam_protocol::crypto::CipherSuite::parse(cipher_str).unwrap_or_default();

    let remote = ssh::RemoteInfo {
        host: host.clone(),
        user: user.clone(),
        ssh_port: args.port,
    };

    // Bootstrap the remote receiver. It will start a Seam server and wait for us.
    let subcmd = format!("_forward-recv --port 0");
    let (conn, _child) = connect::bootstrap_and_connect(&remote, &host, &subcmd, cipher).await?;
    let mux = SeamMux::new(conn);

    let bind_addr = if args.bind_all {
        format!("0.0.0.0:{local_port}")
    } else {
        format!("127.0.0.1:{local_port}")
    };
    let listener = TcpListener::bind(&bind_addr).await
        .map_err(|e| anyhow!("cannot bind {bind_addr}: {e}"))?;
    let actual_port = listener.local_addr()?.port();

    eprintln!(
        "forward ready: {}:{actual_port} → {}{}:{}:{}",
        if args.bind_all { "0.0.0.0" } else { "127.0.0.1" },
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

            // Send header frame: [u16 host_len][host bytes][u16 port]
            let host_bytes = rhost.as_bytes();
            let mut header = Vec::with_capacity(2 + host_bytes.len() + 2);
            header.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
            header.extend_from_slice(host_bytes);
            header.extend_from_slice(&rport.to_be_bytes());

            // Write the header as a length-prefixed frame so the receiver can parse it.
            let mut framed = Vec::with_capacity(4 + header.len());
            framed.extend_from_slice(&(header.len() as u32).to_be_bytes());
            framed.extend_from_slice(&header);

            // Use the SeamMux stream as a raw AsyncWrite for the header.
            use tokio::io::AsyncWriteExt;
            if let Err(e) = seam.write_all(&framed).await {
                eprintln!("forward: failed to send header: {e}");
                return;
            }

            let _ = tokio::io::copy_bidirectional(&mut tcp, &mut seam).await;
        });
    }
}

// ── Remote receiver ───────────────────────────────────────────────────────────

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

    // Accept Seam streams from the client. Each stream begins with a header frame
    // identifying the destination host:port to connect to.
    loop {
        let mut stream = match mux.accept_stream().await {
            Some(s) => s,
            None => break,
        };

        tokio::spawn(async move {
            // Read the length-prefixed header frame.
            use tokio::io::AsyncReadExt;

            let mut len_buf = [0u8; 4];
            if stream.read_exact(&mut len_buf).await.is_err() {
                return;
            }
            let header_len = u32::from_be_bytes(len_buf) as usize;
            if header_len < 4 || header_len > 4096 {
                eprintln!("forward-recv: invalid header length {header_len}");
                return;
            }

            let mut header = vec![0u8; header_len];
            if stream.read_exact(&mut header).await.is_err() {
                return;
            }

            // Parse: [u16 host_len][host bytes][u16 port]
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
