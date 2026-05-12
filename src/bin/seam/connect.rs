use anyhow::{Context, Result};
use seam_protocol::{
    api::{Client, SeamConn},
    handshake::{IdentityKeypair, pk_from_bytes},
};
use std::net::SocketAddr;
use std::process::Child;

use crate::ssh::RemoteInfo;

/// Shell-quote a single argument (for SSH command construction).
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub fn parse_seam_line(line: &str) -> Result<(u16, [u8; 32], seam_protocol::handshake::hybrid_keys::KemPublicKey)> {
    let mut port = None;
    let mut x25519 = None;
    let mut kem = None;

    for part in line.split_whitespace().skip(1) {
        if let Some(v) = part.strip_prefix("PORT=") {
            port = Some(v.parse::<u16>().context("bad PORT")?);
        } else if let Some(v) = part.strip_prefix("X25519=") {
            let bytes = hex::decode(v).context("bad X25519 hex")?;
            x25519 = Some(
                bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("X25519 must be 32 bytes"))?,
            );
        } else if let Some(v) = part.strip_prefix("KEM=") {
            let bytes = hex::decode(v).context("bad KEM hex")?;
            kem = Some(
                pk_from_bytes(&bytes).ok_or_else(|| anyhow::anyhow!("invalid KEM public key"))?,
            );
        }
    }

    Ok((
        port.ok_or_else(|| anyhow::anyhow!("missing PORT in SEAM line"))?,
        x25519.ok_or_else(|| anyhow::anyhow!("missing X25519 in SEAM line"))?,
        kem.ok_or_else(|| anyhow::anyhow!("missing KEM in SEAM line"))?,
    ))
}

fn identity_path() -> std::path::PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("seam")
        .join("identity")
}

pub async fn dial(
    host: &str,
    port: u16,
    x25519: [u8; 32],
    kem_pk: seam_protocol::handshake::hybrid_keys::KemPublicKey,
) -> Result<SeamConn> {
    let server_addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .context("bad address")?;
    let id = IdentityKeypair::load_or_generate(identity_path())
        .unwrap_or_else(|_| IdentityKeypair::generate());
    let mut client = Client::bind("0.0.0.0:0".parse()?, id)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let conn = client
        .connect(server_addr, &x25519, &kem_pk)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(conn)
}

pub async fn bootstrap_and_connect(
    remote: &RemoteInfo,
    host: &str,
    subcmd: &str,
) -> Result<(SeamConn, Child)> {
    let seam_bin = match remote.seam_path() {
        Some(p) => p,
        None => {
            eprintln!("seam not found on {} — bootstrapping…", remote.target());
            remote.bootstrap_copy_self()?
        }
    };
    eprintln!("starting remote worker on {}…", remote.target());
    let (line, child) = remote.start_remote_seam(&seam_bin, subcmd)?;
    let (port, x25519, kem_pk) = parse_seam_line(&line)?;
    eprintln!("connecting (post-quantum handshake)…");
    let conn = dial(host, port, x25519, kem_pk).await?;
    eprintln!("connected");
    Ok((conn, child))
}
