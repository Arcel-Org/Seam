use anyhow::Result;
use clap::Args;
use seam_protocol::handshake::IdentityKeypair;

#[derive(Args)]
pub struct DoctorArgs {}

pub fn run(_args: DoctorArgs) -> Result<()> {
    let mut ok = true;
    let version = env!("CARGO_PKG_VERSION");

    eprintln!("  ┌──────────────────────────────────────────────────────────┐");
    eprintln!("  │  seam doctor  (v{version:<43})│");
    eprintln!("  └──────────────────────────────────────────────────────────┘");
    eprintln!();

    // ── 1. Binary location ──────────────────────────────────────────────
    match std::env::current_exe() {
        Ok(p) => eprintln!("  ✓  binary: {}", p.display()),
        Err(e) => {
            eprintln!("  ✗  cannot locate own binary: {e}");
            ok = false;
        }
    }

    // ── 2. PATH ─────────────────────────────────────────────────────────
    if which::which("seam").is_ok() {
        eprintln!("  ✓  seam in PATH");
    } else {
        eprintln!("  !  seam not found in PATH — add ~/.local/bin to your shell profile");
    }

    // ── 3. SSH availability ─────────────────────────────────────────────
    if which::which("ssh").is_ok() {
        eprintln!("  ✓  ssh found");
    } else {
        eprintln!("  ✗  ssh not found — required for bootstrap");
        ok = false;
    }

    // ── 4. SSH config parsing ───────────────────────────────────────────
    let test_host = "github.com";
    match std::process::Command::new("ssh")
        .args(["-G", test_host])
        .output()
    {
        Ok(out) if out.status.success() => {
            eprintln!("  ✓  ssh -G works (config parsing available)");
        }
        _ => {
            eprintln!("  !  ssh -G failed — ~/.ssh/config aliases may not resolve");
        }
    }

    // ── 5. Identity key ─────────────────────────────────────────────────
    let id_path = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("seam")
        .join("identity");
    if id_path.exists() {
        match std::fs::read(&id_path) {
            Ok(bytes) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(m) = std::fs::metadata(&id_path) {
                        let mode = m.permissions().mode() & 0o777;
                        if mode != 0o600 {
                            eprintln!(
                                "  !  identity key permissions 0o{:o} — should be 0o600",
                                mode
                            );
                            eprintln!("     fix with: chmod 600 {}", id_path.display());
                        }
                    }
                }
                match IdentityKeypair::from_bytes(&bytes) {
                    Some(id) => {
                        let x25519_hex =
                            hex::encode(id.x25519_public.as_bytes());
                        eprintln!(
                            "  ✓  identity key at {} (X25519: {}…)",
                            id_path.display(),
                            &x25519_hex[..12]
                        );
                    }
                    None => {
                        eprintln!(
                            "  ✗  identity key at {} is corrupt or wrong version",
                            id_path.display()
                        );
                        eprintln!("     delete it to generate a fresh key on next use");
                        ok = false;
                    }
                }
            }
            Err(e) => {
                eprintln!("  ✗  cannot read identity key: {e}");
                ok = false;
            }
        }
    } else {
        eprintln!("  ·  no persistent identity key — one will be generated on first use");
    }

    // ── 6. Config file ──────────────────────────────────────────────────
    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cfg_path = super::config::Config::config_path();
    if cfg_path.exists() {
        eprintln!("  ✓  config at {}", cfg_path.display());
        let cipher = &cfg.cipher;
        if cipher == "aes256gcm" {
            if is_aes_ni_available() {
                eprintln!("  ✓  cipher: aes256gcm (AES-NI detected — hardware accelerated)");
            } else {
                eprintln!("  !  cipher: aes256gcm but no AES-NI detected — software fallback may be slow");
                eprintln!("     consider: seam config set cipher chacha20poly1305");
            }
        } else {
            eprintln!("  ✓  cipher: {} (default)", cipher);
        }
    } else {
        eprintln!("  ·  no config file — using defaults ({})", cfg_path.display());
    }

    // ── 7. UDP socket buffer sizes ──────────────────────────────────────
    match try_udp_buffer_test() {
        Some((rx, tx)) => {
            eprintln!("  ✓  UDP socket buffers: rx={} B, tx={} B", rx, tx);
            if rx < 2_097_152 || tx < 2_097_152 {
                eprintln!("     consider: sysctl -w net.core.rmem_max=8388608");
                eprintln!("               sysctl -w net.core.wmem_max=8388608");
            }
        }
        None => {
            eprintln!("  !  could not test UDP socket buffers");
        }
    }

    // ── 7.5. UDP loopback self-test ──────────────────────────────────────────
    match try_udp_loopback_echo() {
        Ok(rtt_us) => eprintln!("  ✓  UDP loopback self-test passed (RTT: {}µs)", rtt_us),
        Err(e) => {
            eprintln!("  !  UDP loopback self-test failed: {e}");
            eprintln!("     Seam requires UDP. Check firewall rules if this is unexpected.");
        }
    }

    // ── 8. MTU / fragmentation ──────────────────────────────────────────
    eprintln!();
    eprintln!("  Tips");
    eprintln!("    • UDP fragmentation can hurt performance on WAN links.");
    eprintln!("    • If you see packet loss under load, check:  ip link show  (mtu)");
    eprintln!("    • seam auto-probes path MTU; minimum safe MTU is 1280 B.");

    eprintln!();
    if ok {
        eprintln!("  All critical checks passed.");
    } else {
        eprintln!("  Some checks failed — see ✗ items above.");
        std::process::exit(1);
    }
    Ok(())
}

/// Returns true if AES-NI hardware acceleration is available on this CPU.
/// On non-x86 platforms always returns true (NEON/ARMv8 crypto is always present
/// when the binary is compiled for that target, so ChaCha vs AES is less critical).
fn is_aes_ni_available() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        is_x86_feature_detected!("aes")
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        true
    }
}

fn try_udp_loopback_echo() -> anyhow::Result<u128> {
    use std::net::UdpSocket;
    use std::time::Instant;

    let server = UdpSocket::bind("127.0.0.1:0")?;
    let server_addr = server.local_addr()?;
    server.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;

    let client = UdpSocket::bind("127.0.0.1:0")?;
    client.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;

    let t0 = Instant::now();
    client.send_to(b"SEAM_DOCTOR_PING", server_addr)?;

    let mut buf = [0u8; 32];
    let (n, peer) = server.recv_from(&mut buf)?;
    server.send_to(&buf[..n], peer)?;

    client.recv_from(&mut buf)?;
    Ok(t0.elapsed().as_micros())
}

fn try_udp_buffer_test() -> Option<(usize, usize)> {
    use socket2::{Domain, Socket, Type};
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, None).ok()?;
    let _ = sock.set_recv_buffer_size(8 * 1024 * 1024);
    let _ = sock.set_send_buffer_size(8 * 1024 * 1024);
    let rx = sock.recv_buffer_size().ok()?;
    let tx = sock.send_buffer_size().ok()?;
    Some((rx, tx))
}
