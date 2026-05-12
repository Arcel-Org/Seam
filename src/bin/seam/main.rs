mod bench;
mod completions;
mod config;
mod connect;
mod copy;
mod doctor;
mod ls;
mod pipe;
mod proto;
mod recv;
mod send;
mod ssh;
mod tunnel;
mod update;

use anyhow::Result;
use clap::{Parser, Subcommand};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name = "seam", version, about, long_about = None, disable_help_subcommand = true)]
pub struct Cli {
    /// Increase verbosity (repeat for more: -v, -vv)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

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

    /// Forward a TCP port over a post-quantum tunnel (like ssh -L)
    #[command(name = "tunnel")]
    Tunnel(tunnel::TunnelArgs),

    /// Measure transfer throughput to a remote host
    #[command(name = "bench")]
    Bench(bench::BenchArgs),

    /// Update seam to the latest release
    #[command(name = "update")]
    Update(update::UpdateArgs),

    /// Manage seam configuration
    #[command(name = "config")]
    Config(config::ConfigArgs),

    /// List files on a remote host
    #[command(name = "ls")]
    Ls(ls::LsArgs),

    /// Generate shell completion scripts
    #[command(name = "completions")]
    Completions(completions::CompletionsArgs),

    // Hidden internal subcommands — started by SSH bootstrap, not for direct use
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
    eprintln!("    pipe     Bidirectional pipe        seam pipe user@host -- bash");
    eprintln!("    tunnel   TCP port forward          seam tunnel 8080:user@host:3000");
    eprintln!("    bench    Measure throughput        seam bench user@host");
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

    match cli.command {
        None => {
            print_splash();
            Ok(())
        }
        Some(Commands::Copy(args)) => copy::run(args).await,
        Some(Commands::Pipe(args)) => pipe::run(args).await,
        Some(Commands::Tunnel(args)) => tunnel::run(args).await,
        Some(Commands::Bench(args)) => bench::run(args).await,
        Some(Commands::Update(args)) => update::run(args),
        Some(Commands::Config(args)) => config::run(args),
        Some(Commands::Ls(args)) => ls::run(args).await,
        Some(Commands::Completions(args)) => completions::run(args),
        Some(Commands::Recv(args)) => recv::run(args).await,
        Some(Commands::Send(args)) => send::run(args).await,
        Some(Commands::LsRecv(args)) => ls::run_recv(args).await,
        Some(Commands::PipeRecv(args)) => pipe::run_recv(args).await,
        Some(Commands::TunnelRecv(args)) => tunnel::run_recv(args).await,
        Some(Commands::BenchRecv(args)) => bench::run_recv(args).await,
    }
}
