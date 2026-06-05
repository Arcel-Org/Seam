use anyhow::{Context, Result};
use seam_protocol::{
    api::{Client, SeamConn},
    crypto::CipherSuite,
    handshake::{IdentityKeypair, pk_from_bytes},
};
use std::cell::Cell;
use std::net::SocketAddr;
use std::process::Child;

use crate::{known_hosts::PinPolicy, ssh::RemoteInfo};

// Thread-local storage for the pin policy set by main() before any command runs.
thread_local! {
    static PIN_POLICY: Cell<PinPolicy> = const { Cell::new(PinPolicy::Enforce) };
}

/// Set the global TOFU pin policy for this process. Called once from main().
pub fn set_pin_policy(policy: PinPolicy) {
    PIN_POLICY.with(|p| p.set(policy));
}

fn current_pin_policy() -> PinPolicy {
    PIN_POLICY.with(|p| p.get())
}

/// Shell-quote a single argument (for SSH command construction).
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub fn parse_seam_line(
    line: &str,
) -> Result<(
    u16,
    [u8; 32],
    seam_protocol::handshake::hybrid_keys::KemPublicKey,
)> {
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

pub fn identity_path() -> std::path::PathBuf {
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
    cipher: CipherSuite,
) -> Result<SeamConn> {
    // ── TOFU server identity pinning ─────────────────────────────────────────
    // Verify (or pin) the server's X25519 public key before completing the
    // cryptographic handshake.  This prevents relay MITM: even if an attacker
    // intercepts the SSH bootstrap and substitutes their own key, the pinned
    // fingerprint check will abort the connection.
    let policy = current_pin_policy();
    crate::known_hosts::verify_or_pin(host, &x25519, policy)?;

    let server_addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .context("bad address")?;
    let id = IdentityKeypair::load_or_generate(identity_path()).unwrap_or_else(|e| {
        eprintln!("warning: could not load identity key ({e}) — using ephemeral key");
        eprintln!("         run: seam doctor  to diagnose");
        IdentityKeypair::generate()
    });
    let mut client = Client::bind("0.0.0.0:0".parse()?, id)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let conn = client
        .connect(server_addr, &x25519, &kem_pk, cipher)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(conn)
}

pub async fn bootstrap_and_connect(
    remote: &RemoteInfo,
    host: &str,
    subcmd: &str,
    cipher: CipherSuite,
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
    let conn = dial(host, port, x25519, kem_pk, cipher).await?;
    eprintln!("connected");
    Ok((conn, child))
}
