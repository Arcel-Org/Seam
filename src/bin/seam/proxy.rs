/// `seam proxy` — SOCKS5 proxy over a post-quantum Seam tunnel.
///
/// Usage: `seam proxy user@host --port 1080`
///
/// Binds a local SOCKS5 server on 127.0.0.1:<port>.  Each incoming SOCKS5
/// connection is proxied over the Seam tunnel to the remote host, which resolves
/// and connects to the target address on behalf of the client.
///
/// This enables routing arbitrary TCP traffic through post-quantum Seam without
/// knowing destinations in advance — useful for browser proxying, `curl`, etc.
///
/// SOCKS5 RFC: https://www.rfc-editor.org/rfc/rfc1928
use anyhow::{Result, anyhow, bail};
use clap::Args;
use seam_protocol::{
    api::Server,
    handshake::{IdentityKeypair, pk_to_bytes},
    tunnel::SeamMux,
};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

use crate::{connect, ssh};

// ── SOCKS5 constants ──────────────────────────────────────────────────────────

const SOCKS5_VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const AUTH_NONE_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

// ── Client args ───────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct ProxyArgs {
    /// Remote host: user@host (SSH bootstrap target)
    pub remote: String,
    /// Local SOCKS5 port to bind (default: 1080)
    #[arg(short = 'p', long, default_value_t = 1080)]
    pub port: u16,
    /// Bind on 0.0.0.0 instead of 127.0.0.1 (allow remote clients — use with caution)
    #[arg(long)]
    pub bind_all: bool,
    /// SSH port for the bootstrap connection
    #[arg(long)]
    pub ssh_port: Option<u16>,
}

// ── Server (remote receiver) args ─────────────────────────────────────────────

#[derive(Args)]
pub struct ProxyRecvArgs {
    /// UDP port to listen on (0 = OS-assigned)
    #[arg(long, default_value_t = 0)]
    pub port: u16,
}

// ── Client side ───────────────────────────────────────────────────────────────

pub async fn run(args: ProxyArgs, fips_mode: bool) -> Result<()> {
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

    let remote = ssh::RemoteInfo {
        host: host.clone(),
        user: user.clone(),
        ssh_port: args.ssh_port,
    };

    let subcmd = "_proxy-recv --port 0".to_string();
    let (conn, _child) = connect::bootstrap_and_connect(&remote, &host, &subcmd, cipher).await?;
    let mux: Arc<SeamMux> = SeamMux::new(conn);

    let bind_addr = if args.bind_all {
        format!("0.0.0.0:{}", args.port)
    } else {
        format!("127.0.0.1:{}", args.port)
    };
    let listener = TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| anyhow!("cannot bind SOCKS5 listener {bind_addr}: {e}"))?;
    let actual_port = listener.local_addr()?.port();

    eprintln!(
        "SOCKS5 proxy ready on {}:{actual_port} → {}{}",
        if args.bind_all {
            "0.0.0.0"
        } else {
            "127.0.0.1"
        },
        user.as_deref().map(|u| format!("{u}@")).unwrap_or_default(),
        host,
    );
    if fips_mode {
        eprintln!("  FIPS mode: AES-256-GCM transport");
    }
    eprintln!("  Configure your browser / tools: SOCKS5 proxy 127.0.0.1:{actual_port}");
    eprintln!("  Press Ctrl-C to stop.");

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("proxy: accept error: {e}");
                continue;
            }
        };
        tracing::debug!("proxy: new SOCKS5 client from {peer}");

        let mux: Arc<SeamMux> = mux.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_socks5_client(tcp, mux).await {
                tracing::debug!("proxy: client {peer} error: {e}");
            }
        });
    }
}

/// Handle a single SOCKS5 client: negotiate, parse request, open Seam stream, bridge.
async fn handle_socks5_client(mut tcp: TcpStream, mux: Arc<SeamMux>) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // ── Phase 1: Method negotiation ───────────────────────────────────────────
    // Client sends: [VER(1)][NMETHODS(1)][METHODS(nmethods)]
    let mut header = [0u8; 2];
    tcp.read_exact(&mut header).await?;
    if header[0] != SOCKS5_VERSION {
        bail!("not a SOCKS5 client (version byte 0x{:02x})", header[0]);
    }
    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    tcp.read_exact(&mut methods).await?;

    // We only support NO_AUTH (0x00).
    if !methods.contains(&NO_AUTH) {
        tcp.write_all(&[SOCKS5_VERSION, AUTH_NONE_ACCEPTABLE])
            .await?;
        bail!("client requires authentication, which we don't support");
    }
    tcp.write_all(&[SOCKS5_VERSION, NO_AUTH]).await?;

    // ── Phase 2: Request ──────────────────────────────────────────────────────
    // Client sends: [VER(1)][CMD(1)][RSV(1)][ATYP(1)][DST.ADDR(var)][DST.PORT(2)]
    let mut req_head = [0u8; 4];
    tcp.read_exact(&mut req_head).await?;
    if req_head[0] != SOCKS5_VERSION {
        bail!("SOCKS5 request version mismatch");
    }
    if req_head[1] != CMD_CONNECT {
        socks5_reply(&mut tcp, REP_CMD_NOT_SUPPORTED).await?;
        bail!("only CONNECT is supported (got CMD 0x{:02x})", req_head[1]);
    }

    let atyp = req_head[3];
    let target_host: String = match atyp {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            tcp.read_exact(&mut addr).await?;
            std::net::Ipv4Addr::from(addr).to_string()
        }
        ATYP_DOMAIN => {
            let len = tcp.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            tcp.read_exact(&mut domain).await?;
            String::from_utf8(domain).map_err(|_| anyhow!("invalid domain encoding"))?
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            tcp.read_exact(&mut addr).await?;
            std::net::Ipv6Addr::from(addr).to_string()
        }
        _ => {
            socks5_reply(&mut tcp, REP_ATYP_NOT_SUPPORTED).await?;
            bail!("unsupported ATYP 0x{:02x}", atyp);
        }
    };
    let target_port = tcp.read_u16().await?;

    tracing::debug!("proxy: CONNECT {target_host}:{target_port}");

    // ── Phase 3: Open Seam stream and send connect request ────────────────────
    let mut seam = mux.open_stream().await;

    // Header: [u16 host_len][host bytes][u16 port]
    let host_bytes = target_host.as_bytes();
    let mut header = Vec::with_capacity(2 + host_bytes.len() + 2);
    header.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    header.extend_from_slice(host_bytes);
    header.extend_from_slice(&target_port.to_be_bytes());

    // Length-prefix the header frame.
    let mut framed = Vec::with_capacity(4 + header.len());
    framed.extend_from_slice(&(header.len() as u32).to_be_bytes());
    framed.extend_from_slice(&header);

    seam.write_all(&framed).await?;

    // ── Phase 4: Wait for remote connect result ───────────────────────────────
    // Remote sends 1 byte: REP_SUCCESS or REP_GENERAL_FAILURE
    let mut rep = [0u8; 1];
    seam.read_exact(&mut rep).await?;
    if rep[0] != REP_SUCCESS {
        socks5_reply(&mut tcp, REP_GENERAL_FAILURE).await?;
        bail!("remote could not connect to {target_host}:{target_port}");
    }

    // ── Phase 5: Tell client we're connected ─────────────────────────────────
    // Reply: [VER(1)][REP(1)][RSV(1)][ATYP(1)][BND.ADDR(4)][BND.PORT(2)]
    // We use 0.0.0.0:0 as the bound address (we don't expose it).
    let mut reply = vec![SOCKS5_VERSION, REP_SUCCESS, 0x00, ATYP_IPV4];
    reply.extend_from_slice(&[0u8; 4]); // BND.ADDR = 0.0.0.0
    reply.extend_from_slice(&[0u8; 2]); // BND.PORT = 0
    tcp.write_all(&reply).await?;

    // ── Phase 6: Bridge ───────────────────────────────────────────────────────
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut seam).await;
    Ok(())
}

/// Write a minimal SOCKS5 error reply (no bound address information).
async fn socks5_reply(tcp: &mut TcpStream, rep: u8) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut reply = vec![SOCKS5_VERSION, rep, 0x00, ATYP_IPV4];
    reply.extend_from_slice(&[0u8; 4]); // BND.ADDR
    reply.extend_from_slice(&[0u8; 2]); // BND.PORT
    tcp.write_all(&reply).await?;
    Ok(())
}

// ── Remote receiver ───────────────────────────────────────────────────────────

pub async fn run_recv(args: ProxyRecvArgs) -> Result<()> {
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
    eprintln!("proxy receiver ready — forwarding SOCKS5 requests");

    loop {
        let mut stream = match mux.accept_stream().await {
            Some(s) => s,
            None => break,
        };

        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            // Read the length-prefixed header frame.
            let mut len_buf = [0u8; 4];
            if stream.read_exact(&mut len_buf).await.is_err() {
                return;
            }
            let header_len = u32::from_be_bytes(len_buf) as usize;
            if header_len < 4 || header_len > 4096 {
                eprintln!("proxy-recv: invalid header length {header_len}");
                return;
            }

            let mut header = vec![0u8; header_len];
            if stream.read_exact(&mut header).await.is_err() {
                return;
            }

            // Parse: [u16 host_len][host bytes][u16 port]
            if header.len() < 4 {
                eprintln!("proxy-recv: header too short");
                return;
            }
            let host_len = u16::from_be_bytes([header[0], header[1]]) as usize;
            if header.len() < 2 + host_len + 2 {
                eprintln!("proxy-recv: header truncated");
                return;
            }
            let host = match std::str::from_utf8(&header[2..2 + host_len]) {
                Ok(h) => h.to_string(),
                Err(_) => {
                    eprintln!("proxy-recv: invalid UTF-8 in host");
                    return;
                }
            };
            let port = u16::from_be_bytes([header[2 + host_len], header[2 + host_len + 1]]);
            let target = format!("{host}:{port}");

            tracing::debug!("proxy-recv: connecting to {target}");
            match tokio::net::TcpStream::connect(&target).await {
                Ok(mut tcp) => {
                    // Signal success to the client side.
                    if stream.write_all(&[REP_SUCCESS]).await.is_err() {
                        return;
                    }
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
                }
                Err(e) => {
                    eprintln!("proxy-recv: cannot connect to {target}: {e}");
                    let _ = stream.write_all(&[REP_GENERAL_FAILURE]).await;
                }
            }
        });
    }

    Ok(())
}
