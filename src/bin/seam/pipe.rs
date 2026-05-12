use anyhow::{Result, anyhow};
use clap::Args;
use seam_protocol::{
    api::Server,
    handshake::{IdentityKeypair, pk_to_bytes},
    tunnel::SeamMux,
};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{connect, ssh};

// ── Stdio wrapper ─────────────────────────────────────────────────────────────

struct Stdio {
    stdin: tokio::io::Stdin,
    stdout: tokio::io::Stdout,
}

impl Stdio {
    fn new() -> Self {
        Self {
            stdin: tokio::io::stdin(),
            stdout: tokio::io::stdout(),
        }
    }
}

impl AsyncRead for Stdio {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdin).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stdio {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stdout).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdout).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdout).poll_shutdown(cx)
    }
}

impl Unpin for Stdio {}

// ── Client args ───────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct PipeArgs {
    /// Remote target: user@host
    pub remote: String,
    /// SSH port
    #[arg(short = 'p', long)]
    pub port: Option<u16>,
    /// Skip SSH bootstrap; use this pre-started SEAM line directly.
    #[arg(long)]
    pub direct: Option<String>,
    /// Command (and args) to run on the remote end (everything after --)
    #[arg(last = true)]
    pub command: Vec<String>,
}

// ── Server args ───────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct PipeRecvArgs {
    /// UDP port to listen on (0 = OS-assigned)
    #[arg(long, default_value_t = 0)]
    pub port: u16,
    /// Command to run (everything after --)
    #[arg(last = true)]
    pub command: Vec<String>,
}

// ── Client ────────────────────────────────────────────────────────────────────

pub async fn run(args: PipeArgs) -> Result<()> {
    let (conn, _child) = if let Some(direct) = args.direct {
        let (port, x25519, kem_pk) = connect::parse_seam_line(&direct)?;
        let conn = connect::dial("127.0.0.1", port, x25519, kem_pk).await?;
        (conn, None)
    } else {
        // Parse user@host (no path — pipe doesn't use a path)
        let (user, host) = if let Some(at) = args.remote.find('@') {
            (
                Some(args.remote[..at].to_string()),
                args.remote[at + 1..].to_string(),
            )
        } else {
            (None, args.remote.clone())
        };
        let remote = ssh::RemoteInfo {
            host: host.clone(),
            user,
            ssh_port: args.port,
        };

        // Build remote subcmd: `_pipe-recv [-- COMMAND ARGS...]`
        let mut subcmd = "_pipe-recv --port 0".to_string();
        if !args.command.is_empty() {
            subcmd.push_str(" --");
            for arg in &args.command {
                subcmd.push(' ');
                subcmd.push_str(&connect::shell_quote(arg));
            }
        }

        let (conn, child) = connect::bootstrap_and_connect(&remote, &host, &subcmd).await?;
        (conn, Some(child))
    };

    let mux = SeamMux::new(conn);
    let mut stream = mux.open_stream().await;
    let mut stdio = Stdio::new();
    tokio::io::copy_bidirectional(&mut stream, &mut stdio).await?;
    Ok(())
}

// ── Server ────────────────────────────────────────────────────────────────────

pub async fn run_recv(args: PipeRecvArgs) -> Result<()> {
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
    let mut stream = mux
        .accept_stream()
        .await
        .ok_or_else(|| anyhow!("no stream"))?;

    if args.command.is_empty() {
        // Raw stdio pipe
        let mut stdio = Stdio::new();
        tokio::io::copy_bidirectional(&mut stream, &mut stdio).await?;
    } else {
        use tokio::process::Command;

        let mut child = Command::new(&args.command[0])
            .args(&args.command[1..])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()?;

        let mut child_stdin = child.stdin.take().unwrap();
        let mut child_stdout = child.stdout.take().unwrap();

        let (mut stream_read, mut stream_write) = tokio::io::split(stream);

        let t1 = tokio::io::copy(&mut child_stdout, &mut stream_write);
        let t2 = tokio::io::copy(&mut stream_read, &mut child_stdin);

        let _ = tokio::join!(t1, t2);
        child.wait().await?;
    }
    Ok(())
}
