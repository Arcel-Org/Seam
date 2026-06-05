use anyhow::{Result, bail};
use clap::Args;
use seam_protocol::{
    api::Server,
    handshake::{IdentityKeypair, pk_to_bytes},
};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::{connect, proto, ssh};

#[derive(Args)]
pub struct LsArgs {
    /// Remote path: user@host:/path
    pub remote: String,
    /// SSH port for the bootstrap connection
    #[arg(short = 'p', long)]
    pub port: Option<u16>,
    /// Skip SSH bootstrap; use this pre-started SEAM line directly.
    #[arg(long)]
    pub direct: Option<String>,
}

#[derive(Args)]
pub struct LsRecvArgs {
    /// Path to list on the remote side
    pub path: String,
    /// UDP port to listen on (0 = OS-assigned)
    #[arg(long, default_value_t = 0)]
    pub port: u16,
}

pub async fn run(args: LsArgs) -> Result<()> {
    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher = seam_protocol::crypto::CipherSuite::parse(&cfg.cipher).unwrap_or_default();
    let (conn, _child) = if let Some(direct) = args.direct {
        let (port, x25519, kem_pk) = connect::parse_seam_line(&direct)?;
        let conn = connect::dial("127.0.0.1", port, x25519, kem_pk, cipher).await?;
        (conn, None)
    } else {
        let (user, host) = ssh::parse_userhost(args.remote.split(':').next().unwrap_or(&args.remote));
        let remote = ssh::RemoteInfo {
            host: host.clone(),
            user,
            ssh_port: args.port,
        };
        let remote_path = ssh::parse_remote(&args.remote)
            .map(|(_, p)| p)
            .unwrap_or_default();
        let subcmd = format!("_ls-recv {} --port 0", connect::shell_quote(&remote_path));
        let (conn, child) = connect::bootstrap_and_connect(&remote, &host, &subcmd, cipher).await?;
        (conn, Some(child))
    };

    let mut conn = conn;
    let ctrl_sid = conn.open_stream().await;
    let mut buf = Vec::new();

    // Send LS request
    proto::send_frame(&conn, ctrl_sid, &[proto::LS]).await?;

    // Read entries until DONE
    loop {
        let frame = proto::read_frame(&mut conn, ctrl_sid, &mut buf).await?;
        if frame.is_empty() {
            bail!("empty frame");
        }
        match frame[0] {
            proto::ENTRY => {
                if frame.len() < 15 {
                    continue;
                }
                let name_len = u16::from_be_bytes(frame[1..3].try_into()?) as usize;
                if frame.len() < 3 + name_len + 8 + 4 {
                    continue;
                }
                let name = String::from_utf8_lossy(&frame[3..3 + name_len]);
                let size = u64::from_be_bytes(frame[3 + name_len..3 + name_len + 8].try_into()?);
                let mode =
                    u32::from_be_bytes(frame[3 + name_len + 8..3 + name_len + 8 + 4].try_into()?);
                let mode_str = mode_to_str(mode);
                let size_str = human_size(size);
                println!("{mode_str} {size_str:>10}  {name}");
            }
            proto::DONE => break,
            t => bail!("unexpected frame type 0x{:02x}", t),
        }
    }
    conn.close().await;
    Ok(())
}

pub async fn run_recv(args: LsRecvArgs) -> Result<()> {
    let id = IdentityKeypair::generate();
    let x25519_hex = hex::encode(id.x25519_public.as_bytes());
    let kem_hex = hex::encode(pk_to_bytes(&id.kem_pk));

    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher = seam_protocol::crypto::CipherSuite::parse(&cfg.cipher).unwrap_or_default();
    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;
    let mut server = Server::bind_with_cipher(addr, id, cipher)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let port = server.local_addr()?.port();

    println!("SEAM PORT={port} X25519={x25519_hex} KEM={kem_hex}");

    let mut conn = server
        .accept()
        .await
        .ok_or_else(|| anyhow::anyhow!("no connection"))?;

    let ctrl_sid = proto::wait_for_stream(&mut conn).await?;
    let mut buf = Vec::new();

    // Wait for LS request
    let req = proto::read_frame(&mut conn, ctrl_sid, &mut buf).await?;
    if req.is_empty() || req[0] != proto::LS {
        bail!("expected LS request");
    }

    let path = std::path::Path::new(&args.path);
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let name_bytes = name.as_bytes();
            let mut frame = Vec::with_capacity(3 + name_bytes.len() + 8 + 4);
            frame.push(proto::ENTRY);
            frame.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
            frame.extend_from_slice(name_bytes);
            frame.extend_from_slice(&meta.len().to_be_bytes());
            frame.extend_from_slice(&file_mode(&meta).to_be_bytes());
            proto::send_frame(&conn, ctrl_sid, &frame).await?;
        }
    } else if path.is_file() {
        let meta = path.metadata()?;
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let name_bytes = name.as_bytes();
        let mut frame = Vec::with_capacity(3 + name_bytes.len() + 8 + 4);
        frame.push(proto::ENTRY);
        frame.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        frame.extend_from_slice(name_bytes);
        frame.extend_from_slice(&meta.len().to_be_bytes());
        frame.extend_from_slice(&file_mode(&meta).to_be_bytes());
        proto::send_frame(&conn, ctrl_sid, &frame).await?;
    }

    proto::send_frame(&conn, ctrl_sid, &[proto::DONE]).await?;
    conn.close().await;
    Ok(())
}

#[cfg(unix)]
fn file_mode(meta: &std::fs::Metadata) -> u32 {
    meta.permissions().mode()
}

#[cfg(not(unix))]
fn file_mode(_meta: &std::fs::Metadata) -> u32 {
    0o644
}

fn mode_to_str(mode: u32) -> String {
    let mut out = String::with_capacity(10);
    out.push(if mode & 0o040000 == 0o040000 {
        'd'
    } else {
        '-'
    });
    out.push(if mode & 0o400 != 0 { 'r' } else { '-' });
    out.push(if mode & 0o200 != 0 { 'w' } else { '-' });
    out.push(if mode & 0o100 != 0 { 'x' } else { '-' });
    out.push(if mode & 0o040 != 0 { 'r' } else { '-' });
    out.push(if mode & 0o020 != 0 { 'w' } else { '-' });
    out.push(if mode & 0o010 != 0 { 'x' } else { '-' });
    out.push(if mode & 0o004 != 0 { 'r' } else { '-' });
    out.push(if mode & 0o002 != 0 { 'w' } else { '-' });
    out.push(if mode & 0o001 != 0 { 'x' } else { '-' });
    out
}

fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    if bytes == 0 {
        return "0 B".into();
    }
    let exp = (bytes as f64).log(1024.0).min(UNITS.len() as f64 - 1.0) as usize;
    let value = bytes as f64 / 1024f64.powi(exp as i32);
    if exp == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.1} {}", value, UNITS[exp])
    }
}
