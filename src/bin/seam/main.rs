mod audit;
mod bench;
mod completions;
mod tui;
mod config;
mod connect;
mod copy;
mod doctor;
mod forward;
mod fwd;
mod health;
mod key;
mod known_hosts;
mod ls;
mod perf;
mod ping;
mod pipe;
mod proto;
mod proxy;
mod recv;
mod scan;
mod send;
mod serve;
mod shell;
mod ssh;
mod stats;
mod sync;
mod tunnel;
mod update;
mod version;

use anyhow::Result;
use clap::{Parser, Subcommand};


#[derive(Parser)]
#[command(name = "seam", version, about, long_about = None, disable_help_subcommand = true)]
pub struct Cli {
    /// Increase verbosity (repeat for more: -v, -vv, -vvv)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    /// AEAD cipher suite for packet encryption.
    ///
    /// "chacha20poly1305" (default) — excellent cross-platform performance.
    /// "aes256gcm" — NSA CNSA 2.0 compliant, required for NSS/DoD deployments;
    ///               hardware-accelerated on AES-NI CPUs.
    ///
    /// Overrides the "cipher" value in ~/.config/seam/config.toml.
    #[arg(long, global = true, value_name = "SUITE",
          value_parser = ["chacha20poly1305", "aes256gcm"])]
    pub cipher: Option<String>,

    /// Enable FIPS-140 compliant mode (also: SEAM_FIPS_MODE=1 or fips_mode=true in config).
    ///
    /// Forces AES-256-GCM cipher (FIPS 197). Rejects ChaCha20-Poly1305 with an error.
    /// Uses SHA-256 (FIPS 180-4) instead of BLAKE3 for file integrity checksums.
    /// Prints compliance algorithm banner on startup.
    ///
    /// Required for: NIST FIPS 140-3, NSA CNSA 2.0, DoD IL2+ deployments.
    #[arg(long, global = true)]
    pub fips_mode: bool,

    /// Trust-On-First-Use: pin the server's identity key on first connection.
    ///
    /// On first connect to a host the X25519 public key fingerprint is stored in
    /// ~/.config/seam/known_hosts. Subsequent connections verify the key matches.
    /// A mismatch aborts with a prominent warning (like SSH's REMOTE HOST IDENTIFICATION
    /// HAS CHANGED). Critical for preventing relay man-in-the-middle attacks.
    #[arg(long, global = true)]
    pub tofu: bool,

    /// Bypass server identity pinning verification (INSECURE).
    ///
    /// Skips comparison against ~/.config/seam/known_hosts entirely.
    /// Prints a loud warning. Only use for testing or when you cannot obtain
    /// the server's pinned key through another channel.
    #[arg(long, global = true)]
    pub insecure_ignore_pin: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Copy files to/from a remote host (like scp, but post-quantum UDP)
    #[command(name = "cp")]
    Copy(copy::CopyArgs),

    /// Bidirectional pipe (like netcat, but post-quantum encrypted)
    #[command(name = "pipe")]
    Pipe(pipe::PipeArgs),

    /// Forward a local TCP port through a post-quantum Seam tunnel to a remote destination
    #[command(name = "forward")]
    Forward(forward::ForwardArgs),

    /// Sync a local directory to/from a remote host over post-quantum Seam
    #[command(name = "sync")]
    Sync(sync::SyncArgs),

    /// Forward a TCP port over a post-quantum tunnel (like ssh -L)
    #[command(name = "tunnel")]
    Tunnel(tunnel::TunnelArgs),

    /// Reverse port forward: remote listens, connections forwarded to local (like ssh -R)
    #[command(name = "fwd")]
    Fwd(fwd::FwdArgs),

    /// Measure transfer throughput to a remote host
    #[command(name = "bench")]
    Bench(bench::BenchArgs),

    /// Run local in-process cryptographic performance self-test
    #[command(name = "perf")]
    Perf(perf::PerfArgs),

    /// Measure round-trip latency to a remote host (like ping, but post-quantum encrypted)
    #[command(name = "ping")]
    Ping(ping::PingArgs),

    /// Show local identity key public components
    #[command(name = "key")]
    Key(key::KeyArgs),

    /// Show connection statistics (RTT, throughput, MTU, cwnd)
    #[command(name = "stats")]
    Stats(stats::StatsArgs),

    /// Update seam to the latest release
    #[command(name = "update")]
    Update(update::UpdateArgs),

    /// Manage seam configuration
    #[command(name = "config")]
    Config(config::ConfigArgs),

    /// Execute a single command on a remote host over a post-quantum Seam channel
    #[command(name = "shell")]
    Shell(shell::ShellArgs),

    /// List files on a remote host
    #[command(name = "ls")]
    Ls(ls::LsArgs),

    /// Check system readiness and diagnose common problems
    #[command(name = "doctor")]
    Doctor(doctor::DoctorArgs),

    /// Show version, build metadata, and supported cipher suites
    #[command(name = "version")]
    Version(version::VersionArgs),

    /// Generate shell completion scripts
    #[command(name = "completions")]
    Completions(completions::CompletionsArgs),

    /// Run a local SOCKS5 proxy server, tunneling all connections over post-quantum Seam
    #[command(name = "proxy")]
    Proxy(proxy::ProxyArgs),

    /// View and query the local audit log (NIST AU-2/AU-12)
    #[command(name = "audit")]
    Audit(audit::AuditArgs),

    /// Start a persistent Seam server daemon (no SSH required on remote)
    #[command(name = "serve")]
    Serve(serve::ServeArgs),

    /// Check the health of a remote seam serve instance
    #[command(name = "health")]
    Health(health::HealthArgs),

    /// Scan TCP ports on a target host or CIDR range through a post-quantum Seam tunnel
    #[command(name = "scan")]
    Scan(scan::ScanArgs),

    // Hidden internal subcommands — started by SSH bootstrap, not for direct use
    #[command(name = "_forward-recv", hide = true)]
    ForwardRecv(forward::ForwardRecvArgs),
    #[command(name = "_forward-hop-recv", hide = true)]
    ForwardHopRecv(forward::ForwardHopRecvArgs),
    #[command(name = "_sync-recv", hide = true)]
    SyncRecv(sync::SyncRecvArgs),
    #[command(name = "_shell-recv", hide = true)]
    ShellRecv(shell::ShellRecvArgs),
    #[command(name = "recv", hide = true)]
    Recv(recv::RecvArgs),
    #[command(name = "_send", hide = true)]
    Send(send::SendArgs),
    #[command(name = "_ls-recv", hide = true)]
    LsRecv(ls::LsRecvArgs),
    #[command(name = "_pipe-recv", hide = true)]
    PipeRecv(pipe::PipeRecvArgs),
    #[command(name = "_tunnel-recv", hide = true)]
    TunnelRecv(tunnel::TunnelRecvArgs),
    #[command(name = "_bench-recv", hide = true)]
    BenchRecv(bench::BenchRecvArgs),
    #[command(name = "_fwd-recv", hide = true)]
    FwdRecv(fwd::FwdRecvArgs),
    #[command(name = "_stats-recv", hide = true)]
    StatsRecv(stats::StatsRecvArgs),
    #[command(name = "_ping-recv", hide = true)]
    PingRecv(ping::PingRecvArgs),
    #[command(name = "_proxy-recv", hide = true)]
    ProxyRecv(proxy::ProxyRecvArgs),
}


#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let subscriber = tracing_subscriber::fmt()
        .with_max_level(match cli.verbose {
            0 => tracing::Level::WARN,
            1 => tracing::Level::INFO,
            2 => tracing::Level::DEBUG,
            _ => tracing::Level::TRACE,
        })
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    // ── Resolve FIPS mode (CLI > env > config) ────────────────────────────────
    let cfg_fips = config::Config::load()
        .ok()
        .map(|c| c.fips_mode)
        .unwrap_or(false);
    let fips_active = config::Config::effective_fips_mode(cfg_fips, cli.fips_mode);

    if fips_active {
        eprintln!("FIPS mode active: {}", config::Config::fips_banner());
        // Enforce AES-256-GCM: reject explicit chacha20poly1305 flag in FIPS mode.
        if cli.cipher.as_deref() == Some("chacha20poly1305") {
            anyhow::bail!(
                "FIPS mode is active: ChaCha20-Poly1305 is not FIPS-approved.\n\
                 Use --cipher aes256gcm or remove --cipher to use the FIPS-required AES-256-GCM."
            );
        }
    }

    // ── Resolve TOFU pin policy ───────────────────────────────────────────────
    let pin_policy = if cli.insecure_ignore_pin {
        known_hosts::PinPolicy::InsecureIgnore
    } else if cli.tofu {
        known_hosts::PinPolicy::TrustOnFirstUse
    } else {
        known_hosts::PinPolicy::Enforce
    };
    // Make pin policy available globally via thread-local (accessed by connect::dial).
    connect::set_pin_policy(pin_policy);

    // ── Audit log helper ──────────────────────────────────────────────────────
    // Logs invocation at start and exit code at end. Hidden internal subcommands
    // (_shell-recv, _send, recv, etc.) are excluded — they run on the remote side
    // and are not client-initiated operations.
    macro_rules! audited {
        ($subcmd:expr, $remote:expr, $args_list:expr, $body:expr) => {{
            let _ts = audit::now_rfc3339();
            let _result: Result<()> = $body;
            audit::log(&audit::AuditEntry {
                ts: _ts,
                subcommand: $subcmd,
                remote: $remote,
                args: $args_list,
                exit_code: Some(if _result.is_ok() { 0 } else { 1 }),
                bytes_tx: None,
                fips_mode: fips_active,
                pid: std::process::id(),
            });
            _result
        }};
    }

    match cli.command {
        None => tui::run(),
        Some(Commands::Forward(args)) => {
            let remote = args.remote.clone();
            audited!(
                "forward",
                &remote,
                vec![],
                forward::run(args, fips_active).await
            )
        }
        Some(Commands::Sync(args)) => {
            let remote = if args.dest.contains('@') {
                args.dest.clone()
            } else {
                args.src.clone()
            };
            audited!("sync", &remote, vec![], sync::run(args, fips_active).await)
        }
        Some(Commands::Copy(args)) => {
            let remote = if args.dest.contains('@') {
                args.dest.clone()
            } else {
                args.src.clone()
            };
            audited!("cp", &remote, vec![], copy::run(args, fips_active).await)
        }
        Some(Commands::Pipe(args)) => {
            let remote = args.remote.clone();
            audited!("pipe", &remote, vec![], pipe::run(args).await)
        }
        Some(Commands::Tunnel(args)) => {
            let remote = args.remote.clone();
            audited!("tunnel", &remote, vec![], tunnel::run(args).await)
        }
        Some(Commands::Fwd(args)) => {
            let remote = args.remote_spec.clone();
            audited!("fwd", &remote, vec![], fwd::run(args).await)
        }
        Some(Commands::Bench(args)) => {
            let remote = args.remote.clone();
            audited!("bench", &remote, vec![], bench::run(args).await)
        }
        Some(Commands::Perf(args)) => audited!("perf", "", vec![], perf::run(args)),
        Some(Commands::Ping(args)) => {
            let remote = args.remote.clone();
            audited!("ping", &remote, vec![], ping::run(args).await)
        }
        Some(Commands::Key(args)) => audited!("key", "", vec![], key::run(args)),
        Some(Commands::Stats(args)) => {
            let remote = args.remote.clone();
            audited!("stats", &remote, vec![], stats::run(args).await)
        }
        Some(Commands::Update(args)) => audited!("update", "", vec![], update::run(args)),
        Some(Commands::Config(args)) => audited!("config", "", vec![], config::run(args)),
        Some(Commands::Shell(args)) => {
            let remote = args.remote.clone();
            audited!("shell", &remote, vec![], shell::run(args).await)
        }
        Some(Commands::Ls(args)) => {
            let remote = args.remote.clone();
            audited!("ls", &remote, vec![], ls::run(args).await)
        }
        Some(Commands::Doctor(args)) => audited!("doctor", "", vec![], doctor::run(args)),
        Some(Commands::Version(args)) => audited!("version", "", vec![], version::run(args)),
        Some(Commands::Completions(args)) => completions::run(args),
        Some(Commands::Proxy(args)) => {
            let remote = args.remote.clone();
            audited!(
                "proxy",
                &remote,
                vec![],
                proxy::run(args, fips_active).await
            )
        }
        Some(Commands::Audit(args)) => audit::run(args),
        Some(Commands::Serve(args)) => {
            let addr_str = format!("{}:{}", args.bind, args.port);
            audited!(
                "serve",
                &addr_str,
                vec![],
                serve::run(args, fips_active).await
            )
        }
        Some(Commands::Health(args)) => {
            let remote = args.remote.clone();
            audited!(
                "health",
                &remote,
                vec![],
                health::run(args, fips_active).await
            )
        }
        Some(Commands::Scan(args)) => {
            let target = args.target.clone();
            audited!("scan", &target, vec![], scan::run_scan(args).await)
        }
        // Hidden internal subcommands — not audited (remote side, not client-initiated)
        Some(Commands::ForwardRecv(args)) => forward::run_recv(args).await,
        Some(Commands::ForwardHopRecv(args)) => forward::run_hop_recv(args).await,
        Some(Commands::SyncRecv(args)) => sync::run_recv(args, fips_active).await,
        Some(Commands::ShellRecv(args)) => shell::run_recv(args).await,
        Some(Commands::Recv(args)) => recv::run(args).await,
        Some(Commands::Send(args)) => send::run(args).await,
        Some(Commands::LsRecv(args)) => ls::run_recv(args).await,
        Some(Commands::PipeRecv(args)) => pipe::run_recv(args).await,
        Some(Commands::TunnelRecv(args)) => tunnel::run_recv(args).await,
        Some(Commands::BenchRecv(args)) => bench::run_recv(args).await,
        Some(Commands::FwdRecv(args)) => fwd::run_recv(args).await,
        Some(Commands::StatsRecv(args)) => stats::run_recv(args).await,
        Some(Commands::PingRecv(args)) => ping::run_recv(args).await,
        Some(Commands::ProxyRecv(args)) => proxy::run_recv(args).await,
    }
}
