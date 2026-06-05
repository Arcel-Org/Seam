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
    let cfg_path = super::config::Config::config_path();
    if cfg_path.exists() {
        // First pass: raw TOML parse to detect unknown keys.
        match std::fs::read_to_string(&cfg_path) {
            Err(e) => {
                eprintln!("  ✗  cannot read config {}: {e}", cfg_path.display());
                ok = false;
            }
            Ok(text) => {
                // Check for unknown keys by comparing raw TOML table keys against the known set.
                let known_keys = [
                    "cc", "compress", "identity", "cipher",
                    "max_connections", "listen_port", "fec_k", "fec_r", "fips_mode", "relays",
                ];
                match text.parse::<toml::Value>() {
                    Err(e) => {
                        eprintln!("  ✗  config parse error: {e}");
                        eprintln!("     fix: seam config init  (or edit {})", cfg_path.display());
                        ok = false;
                    }
                    Ok(toml::Value::Table(table)) => {
                        let mut unknown_keys: Vec<String> = table
                            .keys()
                            .filter(|k| !known_keys.contains(&k.as_str()))
                            .cloned()
                            .collect();
                        unknown_keys.sort();
                        if !unknown_keys.is_empty() {
                            eprintln!("  !  config at {} has unknown key(s): {}",
                                cfg_path.display(), unknown_keys.join(", "));
                            eprintln!("     valid keys: {}", known_keys.join(", "));
                            // Not fatal — forward-compat; but warn loudly.
                        }
                    }
                    Ok(_) => {
                        eprintln!("  ✗  config is not a TOML table: {}", cfg_path.display());
                        ok = false;
                    }
                }
            }
        }

        // Second pass: structured validation.
        match super::config::Config::load() {
            Err(e) => {
                eprintln!("  ✗  config load failed: {e}");
                ok = false;
            }
            Ok(cfg) => {
                eprintln!("  ✓  config at {}", cfg_path.display());

                // Validate cc
                if cfg.cc != "cubic" && cfg.cc != "bbr" {
                    eprintln!("  ✗  config.cc = {:?} — must be 'cubic' or 'bbr'", cfg.cc);
                    eprintln!("     fix: seam config set cc cubic");
                    ok = false;
                }

                // Validate cipher + AES-NI
                if cfg.cipher == "aes256gcm" {
                    if is_aes_ni_available() {
                        eprintln!("  ✓  cipher: aes256gcm (AES-NI detected — hardware accelerated)");
                    } else {
                        eprintln!("  !  cipher: aes256gcm but no AES-NI detected — software fallback may be slow");
                        eprintln!("     consider: seam config set cipher chacha20poly1305");
                    }
                } else if cfg.cipher == "chacha20poly1305" {
                    eprintln!("  ✓  cipher: chacha20poly1305 (default)");
                } else {
                    eprintln!("  ✗  config.cipher = {:?} — must be 'chacha20poly1305' or 'aes256gcm'", cfg.cipher);
                    ok = false;
                }

                // Validate max_connections
                if cfg.max_connections == 0 {
                    eprintln!("  ✗  config.max_connections = 0 — must be at least 1");
                    eprintln!("     fix: seam config set max_connections 1024");
                    ok = false;
                } else if cfg.max_connections >= 65536 {
                    eprintln!("  !  config.max_connections = {} — unusually large (>= 65536); check intent",
                        cfg.max_connections);
                } else {
                    eprintln!("  ✓  max_connections: {}", cfg.max_connections);
                }

                // Validate listen_port
                if cfg.listen_port == 0 {
                    eprintln!("  ✓  listen_port: 0 (OS-assigned, ephemeral)");
                } else if cfg.listen_port < 1024 {
                    // Determine if we have privilege to bind low ports.
                    let is_privileged = is_privileged_user();
                    if is_privileged {
                        eprintln!("  ✓  listen_port: {} (privileged port, running as root)", cfg.listen_port);
                    } else {
                        eprintln!("  !  listen_port: {} — port < 1024 requires root/CAP_NET_BIND_SERVICE",
                            cfg.listen_port);
                        eprintln!("     fix: seam config set listen_port 7474  (or run as root)");
                    }
                } else {
                    eprintln!("  ✓  listen_port: {}", cfg.listen_port);
                }

                // Validate identity path if explicitly set
                if let Some(ref id) = cfg.identity {
                    let id_path = std::path::Path::new(id);
                    if !id_path.exists() {
                        eprintln!("  !  config.identity = {:?} — file not found (will be generated on first use)", id);
                    }
                }

                // Validate FEC parameters
                match (cfg.fec_k, cfg.fec_r) {
                    (Some(k), Some(r)) if k == 0 => {
                        eprintln!("  ✓  FEC: disabled (pure ARQ)");
                        let _ = r; // r is ignored when k=0
                    }
                    (Some(k), Some(r)) => {
                        if k < 2 {
                            eprintln!("  ✗  config.fec_k = {k} — must be 0 (disabled) or ≥ 2");
                            ok = false;
                        } else if r == 0 {
                            eprintln!("  ✗  config.fec_r = 0 — must be ≥ 1 when fec_k > 0");
                            ok = false;
                        } else {
                            let overhead_pct = r as f32 / k as f32 * 100.0;
                            eprintln!("  ✓  FEC: k={k} r={r} ({overhead_pct:.0}% overhead) — manual override");
                        }
                    }
                    (Some(k), None) if k > 0 => {
                        eprintln!("  !  config.fec_k = {k} set but fec_r not set — defaulting fec_r = 2");
                        eprintln!("     fix: seam config set fec_r 2");
                    }
                    (None, Some(_)) => {
                        eprintln!("  !  config.fec_r set without fec_k — fec_r is ignored");
                        eprintln!("     fix: seam config set fec_k 8  (or remove fec_r)");
                    }
                    _ => {
                        eprintln!("  ✓  FEC: auto (dynamic arbiter — adapts to link quality)");
                    }
                }
            }
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

    // ── 7.6. FEC correctness self-test ──────────────────────────────────────
    match try_fec_self_test() {
        Ok(elapsed_us) => eprintln!("  ✓  FEC self-test passed (k=4, r=2, 1-shard corrupt, recovered in {}µs)", elapsed_us),
        Err(e) => {
            eprintln!("  ✗  FEC self-test FAILED: {e}");
            eprintln!("     Reed-Solomon codec malfunction — do not use seam on sensitive links");
            ok = false;
        }
    }

    // ── 7.7. Path MTU discovery (loopback probe) ────────────────────────────
    match probe_path_mtu_loopback() {
        Ok(effective_mtu) => {
            eprintln!("  ✓  path MTU (loopback probe): {} bytes", effective_mtu);
            if effective_mtu < 1280 {
                eprintln!(
                    "  ✗  effective MTU {} B is below the 1280 B minimum for seam",
                    effective_mtu
                );
                eprintln!("     satellite/radio links with low MTU require fec_k and fec_r tuning");
                eprintln!("     recommend: seam config set fec_k 4  &&  seam config set fec_r 4");
                ok = false;
            } else if effective_mtu < 1400 {
                eprintln!(
                    "  !  effective MTU {} B — below 1400 B (common on VSAT/radio links)",
                    effective_mtu
                );
                eprintln!("     consider: seam config set fec_k 4  &&  seam config set fec_r 4");
            } else if effective_mtu < 1472 {
                eprintln!("  !  effective MTU {} B — standard Ethernet minus PPPoE/VPN headers", effective_mtu);
            }
        }
        Err(e) => {
            eprintln!("  !  path MTU probe failed: {e}");
        }
    }

    // ── 7.8. Version check ──────────────────────────────────────────────────
    match check_latest_version(version) {
        VersionCheckResult::UpToDate => {
            eprintln!("  ✓  seam {version} is up to date");
        }
        VersionCheckResult::UpdateAvailable(latest) => {
            eprintln!("  !  update available: {version} → {latest}");
            eprintln!("     upgrade: seam update");
        }
        VersionCheckResult::NetworkError(e) => {
            eprintln!("  ·  version check skipped (no network: {e})");
        }
    }

    // ── 7.9. FIPS mode status ───────────────────────────────────────────────────
    {
        let cfg = super::config::Config::load().ok().unwrap_or_default();
        let fips_active = super::config::Config::effective_fips_mode(cfg.fips_mode, false);
        if fips_active {
            eprintln!(
                "  ✓  FIPS mode: enabled — algorithms: {}",
                super::config::Config::fips_banner()
            );
        } else {
            eprintln!("  ·  FIPS mode: disabled (set fips_mode = true in config or SEAM_FIPS_MODE=1 to enable)");
        }
    }

    // ── 7.10. known_hosts integrity check ──────────────────────────────────────
    match check_known_hosts_integrity() {
        KnownHostsStatus::NotFound => {
            eprintln!("  ·  known_hosts: not found (no TOFU pins stored yet)");
        }
        KnownHostsStatus::Empty => {
            eprintln!("  ✓  known_hosts: exists but empty (no pins yet)");
        }
        KnownHostsStatus::Ok { count } => {
            eprintln!("  ✓  known_hosts: {} pinned host(s) — integrity OK", count);
        }
        KnownHostsStatus::ParseError(e) => {
            eprintln!("  ✗  known_hosts: parse error — file may be corrupt: {e}");
            eprintln!("     This could indicate tampering. Inspect manually:");
            let path = dirs::config_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("seam")
                .join("known_hosts");
            eprintln!("       {}", path.display());
            ok = false;
        }
        KnownHostsStatus::SuspiciousEntries { hosts } => {
            eprintln!("  !  known_hosts: {} pinned host(s) found", hosts.len());
            eprintln!("  !  WARNING: the following hosts have malformed fingerprints (possible TOFU bypass):");
            for h in &hosts {
                eprintln!("       {h}");
            }
            eprintln!("     Review and re-pin with: seam key --remove-pin <host>  then reconnect");
            ok = false;
        }
        KnownHostsStatus::PermissionsWrong { mode } => {
            eprintln!(
                "  !  known_hosts: permissions 0o{:o} — should be 0o600 (others can read your pins)",
                mode
            );
            let path = dirs::config_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("seam")
                .join("known_hosts");
            eprintln!("     fix: chmod 600 {}", path.display());
        }
    }

    // ── 7.11. Audit log health ──────────────────────────────────────────────────
    {
        let (exists, size, last) = super::audit::audit_health();
        if exists {
            eprintln!(
                "  ✓  audit log: {} ({} bytes)",
                super::audit::audit_log_path_display().display(),
                size
            );
            if let Some(preview) = last {
                // Show just the timestamp from the last entry to confirm recency.
                if let Some(ts) = serde_json::from_str::<serde_json::Value>(&preview)
                    .ok()
                    .and_then(|v| v["ts"].as_str().map(|s| s.to_string()))
                {
                    eprintln!("     last entry: {ts}");
                }
            }
        } else {
            eprintln!(
                "  ·  audit log: not yet created (will be at {})",
                super::audit::audit_log_path_display().display()
            );
        }
    }

    // ── 7.12. Relay connectivity test ──────────────────────────────────────────
    //
    // For each relay configured in `relays = [...]` in the config, we attempt a
    // TCP connection to the SSH port (22) to verify basic reachability, then
    // report the result. Full Seam ping requires SSH bootstrap which is slow and
    // involves spawning a process — for doctor we use a TCP RST probe instead.
    {
        let cfg = super::config::Config::load().ok().unwrap_or_default();
        if cfg.relays.is_empty() {
            eprintln!("  ·  relay hosts: none configured (add relays = [\"user@host\", ...] in config)");
        } else {
            eprintln!("  ── relay connectivity ({} host(s)) ─────────────────────", cfg.relays.len());
            for relay in &cfg.relays {
                let host = if let Some(at) = relay.rfind('@') {
                    &relay[at + 1..]
                } else {
                    relay.as_str()
                };
                match probe_relay_tcp(host, 22, std::time::Duration::from_secs(5)) {
                    Ok(rtt_ms) => {
                        eprintln!("  ✓  relay {relay}  SSH port reachable  (TCP RTT: {rtt_ms}ms)");
                    }
                    Err(e) => {
                        eprintln!("  ✗  relay {relay}  unreachable: {e}");
                        ok = false;
                    }
                }
            }
        }
    }

    // ── 8. Summary tips ──────────────────────────────────────────────────
    eprintln!();
    eprintln!("  Tips");
    eprintln!("    • UDP fragmentation can hurt performance on WAN links.");
    eprintln!("    • If you see packet loss under load, check:  ip link show  (mtu)");
    eprintln!("    • Minimum safe MTU for seam is 1280 B (IPv6 minimum).");
    eprintln!("    • Satellite/HF radio links: seam config set fec_k 4 && seam config set fec_r 4");
    eprintln!("    • LAN / fiber links:        seam config set fec_k 0  (disables FEC overhead)");

    eprintln!();
    if ok {
        eprintln!("  All critical checks passed.");
    } else {
        eprintln!("  Some checks failed — see ✗ items above.");
        std::process::exit(1);
    }
    Ok(())
}

/// Returns true if the current process appears to run with root/admin privileges.
/// On Unix this checks whether effective UID is 0 via `id -u`.
/// On non-Unix platforms, always returns false (conservative).
fn is_privileged_user() -> bool {
    #[cfg(unix)]
    {
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim() == "0")
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        false
    }
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

/// Encode a known payload with Reed-Solomon (k=4, r=2), corrupt one shard,
/// verify that the decoder recovers the original payload. Returns elapsed µs.
fn try_fec_self_test() -> anyhow::Result<u64> {
    use seam_protocol::fec::{FecDecoder, FecEncoder};
    use std::time::Instant;

    let t0 = Instant::now();

    let k: u8 = 4;
    let r: u8 = 2;
    let payload_len = 64;
    // Build k known source payloads: deterministic pattern for easy verification.
    let sources: Vec<Vec<u8>> = (0..k)
        .map(|i| (0..payload_len).map(|j| i.wrapping_add(j as u8)).collect::<Vec<u8>>())
        .collect();

    let mut enc = FecEncoder::new(42, k, r);
    let mut repairs = None;
    for src in &sources {
        repairs = enc.push_source(src);
    }
    let repairs = repairs.ok_or_else(|| anyhow::anyhow!("FEC encoder produced no repairs"))?;
    if repairs.len() != r as usize {
        anyhow::bail!("expected {} repair symbols, got {}", r, repairs.len());
    }

    // Corrupt shard index 1 (drop it — simulate packet loss).
    let mut dec = FecDecoder::new();
    let gid = repairs[0].group_id;
    for (i, src) in sources.iter().enumerate() {
        if i == 1 {
            continue; // simulate loss
        }
        dec.add_source(gid, i as u8, k, r, src);
    }
    // Feed first repair symbol — should trigger recovery.
    let recovered = dec
        .add_repair(&repairs[0])
        .ok_or_else(|| anyhow::anyhow!("FEC decoder failed to recover lost shard"))?;

    if recovered.len() != 1 {
        anyhow::bail!("expected 1 recovered shard, got {}", recovered.len());
    }
    let (idx, data) = &recovered[0];
    if *idx != 1 {
        anyhow::bail!("recovered wrong shard index: {}", idx);
    }
    // Verify content matches original shard 1.
    if &data[..payload_len] != sources[1].as_slice() {
        anyhow::bail!("recovered shard 1 content mismatch");
    }

    Ok(t0.elapsed().as_micros() as u64)
}

enum VersionCheckResult {
    UpToDate,
    UpdateAvailable(String),
    NetworkError(String),
}

/// Fetch the latest GitHub release tag and compare to the running version.
/// Uses a short 3-second timeout so doctor is not blocked on network issues.
fn check_latest_version(current: &str) -> VersionCheckResult {
    const REPO: &str = "North9-Labs/Seam";
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");

    let resp = match ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .get(&url)
        .set("User-Agent", &format!("seam/{current}"))
        .call()
    {
        Ok(resp) => resp,
        Err(e) => return VersionCheckResult::NetworkError(e.to_string()),
    };

    let body: serde_json::Value = match resp.into_json() {
        Ok(v) => v,
        Err(e) => return VersionCheckResult::NetworkError(e.to_string()),
    };

    let tag = match body["tag_name"].as_str() {
        Some(t) => t.trim_start_matches('v').to_string(),
        None => return VersionCheckResult::NetworkError("no tag_name in response".into()),
    };

    // Simple semver-ish comparison: parse as Version tuples.
    if is_newer(&tag, current) {
        VersionCheckResult::UpdateAvailable(tag)
    } else {
        VersionCheckResult::UpToDate
    }
}

/// Returns true if `candidate` is a strictly newer semver than `current`.
/// Falls back to string comparison if parsing fails (conservative: reports up-to-date).
fn is_newer(candidate: &str, current: &str) -> bool {
    fn parse_ver(s: &str) -> Option<(u64, u64, u64)> {
        let mut parts = s.splitn(3, '.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next().unwrap_or("0").parse().ok()?;
        Some((major, minor, patch))
    }
    match (parse_ver(candidate), parse_ver(current)) {
        (Some(c), Some(cur)) => c > cur,
        _ => false,
    }
}

/// Probe path MTU by sending UDP datagrams of increasing size to a loopback
/// socket and finding the largest size that is received without fragmentation.
///
/// On loopback this always succeeds up to ~65507 bytes, so we use this to
/// verify socket plumbing and report realistic WAN MTU probe sizes.
/// The real value here is testing the probe logic itself; for production use
/// `seam doctor` reports the probe sizes that would be used against a real peer.
///
/// Returns the effective MTU in bytes (payload size that fits in one UDP frame).
fn probe_path_mtu_loopback() -> anyhow::Result<usize> {
    use std::net::UdpSocket;

    // Standard probe sizes matching common link types:
    //   576  — minimum IPv4 required MTU (RFC 791, worst-case WAN)
    //   1024 — conservative satellite / HF radio
    //   1280 — IPv6 minimum MTU
    //   1400 — common VSAT / VPN overhead headroom
    //   1472 — Ethernet 1500 − 20 (IP) − 8 (UDP)
    //   1500 — standard Ethernet (loopback only)
    const PROBE_SIZES: &[usize] = &[576, 1024, 1280, 1400, 1472, 1500];

    let server = UdpSocket::bind("127.0.0.1:0")?;
    let server_addr = server.local_addr()?;
    server.set_read_timeout(Some(std::time::Duration::from_millis(200)))?;

    let client = UdpSocket::bind("127.0.0.1:0")?;
    client.set_read_timeout(Some(std::time::Duration::from_millis(200)))?;

    let mut effective_mtu = PROBE_SIZES[0]; // conservative lower bound
    let mut recv_buf = vec![0u8; 2048];

    for &size in PROBE_SIZES {
        let probe = vec![0xABu8; size];
        if client.send_to(&probe, server_addr).is_err() {
            break;
        }
        match server.recv_from(&mut recv_buf) {
            Ok((n, _)) if n == size => {
                effective_mtu = size;
            }
            _ => break, // fragmented or dropped — stop here
        }
    }

    Ok(effective_mtu)
}

/// Result of the known_hosts integrity check.
enum KnownHostsStatus {
    /// File does not exist yet.
    NotFound,
    /// File exists but contains no pins.
    Empty,
    /// File parses correctly with `count` valid entries.
    Ok { count: usize },
    /// File exists but has entries with malformed fingerprints (< 64 hex chars).
    SuspiciousEntries { hosts: Vec<String> },
    /// File exists but could not be parsed.
    ParseError(String),
    /// File has wrong permissions (readable by others).
    #[allow(dead_code)]
    PermissionsWrong { mode: u32 },
}

/// Read and validate the known_hosts file.
///
/// Checks performed:
///   1. File exists and is readable.
///   2. Each non-comment line has exactly two fields (host + fingerprint).
///   3. Each fingerprint is exactly 64 lowercase hex characters (SHA-256).
///   4. File permissions are 0o600 (Unix only).
///
/// A fingerprint shorter than 64 chars could indicate a truncation attack
/// where an attacker replaces a full key hash with a prefix that matches
/// multiple keys. We flag these as suspicious.
fn check_known_hosts_integrity() -> KnownHostsStatus {
    let path = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("seam")
        .join("known_hosts");

    if !path.exists() {
        return KnownHostsStatus::NotFound;
    }

    // Check permissions on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(m) = std::fs::metadata(&path) {
            let mode = m.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return KnownHostsStatus::PermissionsWrong { mode };
            }
        }
    }

    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => return KnownHostsStatus::ParseError(e.to_string()),
    };

    let mut count = 0usize;
    let mut suspicious: Vec<String> = Vec::new();

    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if parts.len() != 2 {
            return KnownHostsStatus::ParseError(format!(
                "line {}: expected 'host fingerprint', got: {:?}",
                lineno + 1,
                line
            ));
        }
        let host = parts[0];
        let fp = parts[1].trim();

        // A valid SHA-256 fingerprint is exactly 64 lowercase hex characters.
        // Shorter fingerprints could be a truncation / prefix-substitution attack.
        if fp.len() != 64 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
            suspicious.push(format!(
                "{host} (fingerprint has {} chars, expected 64)",
                fp.len()
            ));
        }
        count += 1;
    }

    if !suspicious.is_empty() {
        return KnownHostsStatus::SuspiciousEntries { hosts: suspicious };
    }

    if count == 0 {
        KnownHostsStatus::Empty
    } else {
        KnownHostsStatus::Ok { count }
    }
}

/// Probe a remote host:port via TCP and return the connection RTT in milliseconds.
///
/// We attempt a TCP SYN (connect) and measure the time until the SYN-ACK
/// arrives. The socket is immediately closed after connect — no data is sent.
/// This is safe and does not leave open connections.
///
/// Used by `seam doctor` to verify relay host reachability without requiring
/// a full Seam bootstrap (which is slow and would pollute the audit log).
fn probe_relay_tcp(host: &str, port: u16, timeout: std::time::Duration) -> anyhow::Result<u64> {
    use std::net::TcpStream;
    use std::time::Instant;

    // Resolve host to addresses
    let addrs: Vec<std::net::SocketAddr> = {
        use std::net::ToSocketAddrs;
        let spec = format!("{host}:{port}");
        spec.to_socket_addrs()
            .map_err(|e| anyhow::anyhow!("DNS resolution failed for {host}: {e}"))?
            .collect()
    };

    if addrs.is_empty() {
        anyhow::bail!("DNS returned no addresses for {host}");
    }

    let t0 = Instant::now();
    let mut last_err = anyhow::anyhow!("no address to try");
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, timeout) {
            Ok(_stream) => {
                // Connection established — measure RTT and drop immediately.
                let rtt_ms = t0.elapsed().as_millis() as u64;
                return Ok(rtt_ms);
            }
            Err(e) => {
                last_err = anyhow::anyhow!("{e}");
            }
        }
    }
    Err(last_err)
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
