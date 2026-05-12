mod copy;
mod proto;
mod recv;
mod ssh;
mod update;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "seam", version, about = "Post-quantum encrypted file transfer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Copy files over post-quantum Seam transport
    #[command(name = "cp")]
    Copy(copy::CopyArgs),
    #[command(name = "recv", hide = true)]
    Recv(recv::RecvArgs),
    /// Update seam to the latest release
    #[command(name = "update")]
    Update(update::UpdateArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::Copy(args) => copy::run(args).await,
        Commands::Recv(args) => recv::run(args).await,
        Commands::Update(args) => update::run(args),
    }
}
