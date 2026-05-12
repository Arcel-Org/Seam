use anyhow::Result;
use clap::Args;

#[derive(Args)]
pub struct DoctorArgs {}

#[allow(dead_code)]
pub fn run(_args: DoctorArgs) -> Result<()> {
    let mut ok = true;

    eprintln!("  ┌──────────────────────────────────────────────────────────┐");
    eprintln!("  │  seam doctor                                             │");
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
        match std::fs::metadata(&id_path) {
            Ok(m) => {
                let perms = m.permissions();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = perms.mode() & 0o777;
                    if mode == 0o600 {
                        eprintln!("  ✓  identity key at {} (mode 0o600)", id_path.display());
                    } else {
                        eprintln!(
                            "  !  identity key at {} (mode 0o{:o} — should be 0o600)",
                            id_path.display(),
                            mode
                        );
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = perms;
                    eprintln!("  ✓  identity key at {}", id_path.display());
                }
            }
            Err(e) => {
                eprintln!("  !  cannot read identity key: {e}");
            }
        }
    } else {
        eprintln!("  !  no persistent identity key — one will be generated on first use");
    }

    // ── 6. UDP socket buffer sizes ──────────────────────────────────────
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

    // ── 7. MTU / fragmentation ──────────────────────────────────────────
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

#[allow(dead_code)]
fn try_udp_buffer_test() -> Option<(usize, usize)> {
    use socket2::{Domain, Socket, Type};
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, None).ok()?;
    let _ = sock.set_recv_buffer_size(8 * 1024 * 1024);
    let _ = sock.set_send_buffer_size(8 * 1024 * 1024);
    let rx = sock.recv_buffer_size().ok()?;
    let tx = sock.send_buffer_size().ok()?;
    Some((rx, tx))
}
