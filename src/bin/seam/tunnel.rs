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
pub struct TunnelArgs {
    /// Tunnel spec: LOCAL_PORT:user@host:REMOTE_PORT  or  LOCAL_PORT:user@host:REMOTE_HOST:REMOTE_PORT
    pub spec: String,
    /// SSH port for the bootstrap connection
    #[arg(short = 'p', long)]
    pub port: Option<u16>,
    /// Skip SSH bootstrap; use this pre-started SEAM line directly.
    #[arg(long)]
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
}

// ── Parse tunnel spec ─────────────────────────────────────────────────────────

/// Parse `LOCAL:user@host:RPORT` or `LOCAL:user@host:RHOST:RPORT`.
///
/// Returns `(local_port, user, host, remote_host, remote_port)`.
fn parse_tunnel_spec(spec: &str) -> Result<(u16, Option<String>, String, String, u16)> {
    // Split off the local port at the first ':'
    let (local_str, rest) = spec
        .split_once(':')
        .ok_or_else(|| anyhow!("tunnel spec must be LOCAL:user@host:RPORT"))?;
    let local_port: u16 = local_str
        .parse()
        .map_err(|_| anyhow!("invalid local port: {local_str}"))?;

    // Next token is user@host — find the second ':' (after user@host)
    // user@host may contain '@' but not ':'.
    let (userhost, remainder) = rest
        .split_once(':')
        .ok_or_else(|| anyhow!("tunnel spec missing remote port"))?;

    let (user, host) = if let Some(at) = userhost.find('@') {
        (
            Some(userhost[..at].to_string()),
            userhost[at + 1..].to_string(),
        )
    } else {
        (None, userhost.to_string())
    };

    // remainder is either "RPORT" or "RHOST:RPORT"
    let (remote_host, remote_port) = if let Some((rhost, rport_str)) = remainder.split_once(':') {
        let rport: u16 = rport_str
            .parse()
            .map_err(|_| anyhow!("invalid remote port: {rport_str}"))?;
        (rhost.to_string(), rport)
    } else {
        let rport: u16 = remainder
            .parse()
            .map_err(|_| anyhow!("invalid remote port: {remainder}"))?;
        ("localhost".to_string(), rport)
    };

    Ok((local_port, user, host, remote_host, remote_port))
}

// ── Client ────────────────────────────────────────────────────────────────────

pub async fn run(args: TunnelArgs) -> Result<()> {
    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher = seam_protocol::crypto::CipherSuite::parse(&cfg.cipher).unwrap_or_default();
    let (local_port, user, host, remote_host, remote_port, _child, mux) =
        if let Some(direct) = args.direct {
            // --direct: parse local spec differently — need local port from args.spec
            let local_port: u16 = args
                .spec
                .parse()
                .map_err(|_| anyhow!("with --direct, spec should be just LOCAL_PORT"))?;
            let (port, x25519, kem_pk) = connect::parse_seam_line(&direct)?;
            let conn = connect::dial("127.0.0.1", port, x25519, kem_pk, cipher).await?;
            let mux = SeamMux::new(conn);
            (
                local_port,
                None,
                "127.0.0.1".to_string(),
                "localhost".to_string(),
                0u16,
                None,
                mux,
            )
        } else {
            let (local_port, user, host, remote_host, remote_port) = parse_tunnel_spec(&args.spec)?;
            let remote = ssh::RemoteInfo {
                host: host.clone(),
                user: user.clone(),
                ssh_port: args.port,
            };
            let subcmd = format!(
                "_tunnel-recv {} {} --port 0",
                connect::shell_quote(&remote_host),
                remote_port
            );
            let (conn, child) = connect::bootstrap_and_connect(&remote, &host, &subcmd, cipher).await?;
            let mux = SeamMux::new(conn);
            (
                local_port,
                user,
                host,
                remote_host,
                remote_port,
                Some(child),
                mux,
            )
        };

    let listener = TcpListener::bind(("127.0.0.1", local_port)).await?;
    let actual_port = listener.local_addr()?.port();
    eprintln!(
        "tunnel ready: 127.0.0.1:{actual_port} → {}{}:{}",
        user.as_deref().map(|u| format!("{u}@")).unwrap_or_default(),
        host,
        remote_port
    );
    eprintln!("  (forwarding to {}:{})", remote_host, remote_port);

    // Keep _child alive for the duration
    let _ssh_child = _child;

    loop {
        let (mut tcp, _) = listener.accept().await?;
        let mux = mux.clone();
        tokio::spawn(async move {
            let mut seam = mux.open_stream().await;
            let _ = tokio::io::copy_bidirectional(&mut tcp, &mut seam).await;
        });
    }
}

// ── Server ────────────────────────────────────────────────────────────────────

pub async fn run_recv(args: TunnelRecvArgs) -> Result<()> {
    if args.remote_host.is_empty() {
        bail!("remote_host must not be empty");
    }

    let id = IdentityKeypair::generate();
    let x25519_hex = hex::encode(id.x25519_public.as_bytes());
    let kem_hex = hex::encode(pk_to_bytes(&id.kem_pk));

    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;
    let mut server = Server::bind(addr, id).await.map_err(|e| anyhow!("{e}"))?;
    let port = server.local_addr()?.port();

    println!("SEAM PORT={port} X25519={x25519_hex} KEM={kem_hex}");

    let conn = server
        .accept()
        .await
        .ok_or_else(|| anyhow!("no connection"))?;
    let mux = SeamMux::new(conn);
    eprintln!("tunnel receiver ready");

    loop {
        let stream = match mux.accept_stream().await {
            Some(s) => s,
            None => break,
        };
        let target = format!("{}:{}", args.remote_host, args.remote_port);
        tokio::spawn(async move {
            if let Ok(mut tcp) = tokio::net::TcpStream::connect(&target).await {
                let mut s = stream;
                let _ = tokio::io::copy_bidirectional(&mut s, &mut tcp).await;
            }
        });
    }

    Ok(())
}
