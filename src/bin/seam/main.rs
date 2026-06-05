mod bench;
mod completions;
mod config;
mod connect;
mod copy;
mod doctor;
mod forward;
mod fwd;
mod key;
mod known_hosts;
mod ls;
mod ping;
mod pipe;
mod proto;
mod proxy;
mod recv;
mod send;
mod shell;
mod ssh;
mod stats;
mod sync;
mod tunnel;
mod update;
mod version;

use anyhow::Result;
use clap::{Parser, Subcommand};

const VERSION: &str = env!("CARGO_PKG_VERSION");

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

    // Hidden internal subcommands — started by SSH bootstrap, not for direct use
    #[command(name = "_forward-recv", hide = true)]
    ForwardRecv(forward::ForwardRecvArgs),
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

fn print_splash() {
    eprintln!();
    eprintln!("  ┌──────────────────────────────────────────────────────────┐");
    eprintln!("  │  seam v{VERSION:<51}│");
    eprintln!("  │  post-quantum encrypted communications over UDP          │");
    eprintln!("  │  Noise_XX + ML-KEM-768 · ChaCha20-Poly1305 · ARQ + FEC  │");
    eprintln!("  └──────────────────────────────────────────────────────────┘");
    eprintln!();
    eprintln!("  Commands");
    eprintln!("    cp       Copy files               seam cp ./file user@host:/path");
    eprintln!("    sync     Directory sync            seam sync ./dir user@host:/path");
    eprintln!("    forward  TCP port forward          seam forward 8080:localhost:80 user@host");
    eprintln!("    pipe     Bidirectional pipe        seam pipe user@host -- bash");
    eprintln!("    tunnel   TCP port forward (legacy) seam tunnel 8080:user@host:3000");
    eprintln!("    fwd      Reverse port forward      seam fwd user@host:3000 8080");
    eprintln!("    shell    Run remote command         seam shell user@host -- ls -la");
    eprintln!("    bench    Measure throughput        seam bench user@host");
    eprintln!("    proxy    SOCKS5 proxy                seam proxy user@host --port 1080");
    eprintln!("    ping     Latency measurement        seam ping user@host");
    eprintln!("    key      Show identity public key    seam key");
    eprintln!("    stats    Connection statistics     seam stats user@host");
    eprintln!("    ls       List remote files         seam ls user@host:/path");
    eprintln!("    doctor   System readiness check    seam doctor");
    eprintln!("    version  Version & cipher info      seam version");
    eprintln!("    update   Self-update               seam update");
    eprintln!();
    eprintln!("  Run  seam <command> --help  for flags and options.");
    eprintln!();
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
    let cfg_fips = config::Config::load().ok().map(|c| c.fips_mode).unwrap_or(false);
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

    match cli.command {
        None => {
            print_splash();
            Ok(())
        }
        Some(Commands::Forward(args)) => forward::run(args, fips_active).await,
        Some(Commands::Sync(args)) => sync::run(args, fips_active).await,
        Some(Commands::Copy(args)) => copy::run(args, fips_active).await,
        Some(Commands::Pipe(args)) => pipe::run(args).await,
        Some(Commands::Tunnel(args)) => tunnel::run(args).await,
        Some(Commands::Fwd(args)) => fwd::run(args).await,
        Some(Commands::Bench(args)) => bench::run(args).await,
        Some(Commands::Ping(args)) => ping::run(args).await,
        Some(Commands::Key(args)) => key::run(args),
        Some(Commands::Stats(args)) => stats::run(args).await,
        Some(Commands::Update(args)) => update::run(args),
        Some(Commands::Config(args)) => config::run(args),
        Some(Commands::Shell(args)) => shell::run(args).await,
        Some(Commands::Ls(args)) => ls::run(args).await,
        Some(Commands::Doctor(args)) => doctor::run(args),
        Some(Commands::Version(args)) => version::run(args),
        Some(Commands::Completions(args)) => completions::run(args),
        Some(Commands::Proxy(args)) => proxy::run(args, fips_active).await,
        Some(Commands::ForwardRecv(args)) => forward::run_recv(args).await,
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
