/// `seam punch` — UDP hole punching and STUN external address discovery.
///
/// Usage:
///   seam punch --stun stun.l.google.com:19302
///   seam punch --peer 203.0.113.5:4433 --stun stun.l.google.com:19302
///
/// Without --peer: just discovers and prints the external address via STUN.
/// With --peer: attempts UDP hole punching to the peer's external address.
use anyhow::{Result, anyhow};
use clap::Args;
use seam_protocol::transport::nat::{HolePuncher, StunClient};

const DEFAULT_STUN: &str = "stun.l.google.com:19302";

#[derive(Args)]
pub struct PunchArgs {
    /// Peer external address to punch a hole to (e.g. 203.0.113.5:4433).
    ///
    /// If omitted, only discovers the local external address via STUN.
    #[arg(long, value_name = "ADDR")]
    pub peer: Option<String>,

    /// STUN server to use for external address discovery.
    ///
    /// Default: stun.l.google.com:19302 (Google's public STUN server).
    /// Configurable in ~/.config/seam/config.toml: stun_server = "..."
    #[arg(long, default_value = DEFAULT_STUN, value_name = "HOST:PORT")]
    pub stun: String,
}

pub async fn run(args: PunchArgs) -> Result<()> {
    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let stun_server = cfg
        .stun_server
        .as_deref()
        .unwrap_or(&args.stun)
        .to_string();

    if args.peer.is_none() {
        // Discover-only mode.
        eprintln!("discovering external address via STUN ({stun_server})…");
        let client = StunClient::new(&stun_server);
        let (external, local) = client
            .discover_external_addr()
            .await
            .map_err(|e| anyhow!("STUN discovery failed: {e}"))?;
        println!("local:    {local}");
        println!("external: {external}");
        eprintln!(
            "\nShare your external address with the peer, then both run:\n  seam punch --peer <their-external-addr> --stun {stun_server}"
        );
        return Ok(());
    }

    let peer_str = args.peer.unwrap();
    let peer_addr: std::net::SocketAddr = peer_str
        .parse()
        .map_err(|_| anyhow!("invalid peer address: {peer_str} (use IP:PORT)"))?;

    eprintln!("discovering external address via STUN ({stun_server})…");
    let puncher = HolePuncher::new(&stun_server);

    // First show our own external address so the peer can configure theirs.
    let stun_client = StunClient::new(&stun_server);
    match stun_client.discover_external_addr().await {
        Ok((ext, local)) => {
            eprintln!("local:    {local}");
            eprintln!("external: {ext}");
        }
        Err(e) => {
            eprintln!("warning: STUN discovery failed: {e}");
        }
    }

    eprintln!("punching hole to {peer_addr}…");
    match puncher.punch(peer_addr).await {
        Ok((_sock, our_ext, verified_peer)) => {
            println!("hole punch SUCCESS");
            println!("our external: {our_ext}");
            println!("verified peer: {verified_peer}");
            eprintln!("\nDirect UDP path established. You can now use:");
            eprintln!(
                "  seam ping <seam-server-at-{verified_peer}> (if remote runs seam serve)"
            );
        }
        Err(e) => {
            eprintln!("hole punch FAILED: {e}");
            eprintln!("  Both peers must run this command simultaneously.");
            eprintln!("  Check that the STUN server is reachable and that UDP is not blocked.");
            return Err(e);
        }
    }
    Ok(())
}
