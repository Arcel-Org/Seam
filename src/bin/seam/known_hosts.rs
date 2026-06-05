/// TOFU (Trust-On-First-Use) server identity pinning for Seam.
///
/// On the first connection to a host, the server's X25519 public key fingerprint
/// is saved in `~/.config/seam/known_hosts`. On subsequent connections the stored
/// fingerprint is compared to what the server presents; a mismatch is a fatal error
/// unless `--insecure-ignore-pin` is explicitly passed.
///
/// The format is one entry per line:
///   `<host> <sha256-fingerprint-hex>`
///
/// This is intentionally simple and human-readable, like SSH known_hosts.
use anyhow::{bail, Result};
use sha2::Digest as _;
use std::collections::HashMap;
use std::path::PathBuf;

/// SHA-256 fingerprint of a 32-byte X25519 public key, returned as lowercase hex.
pub fn fingerprint(x25519_pub: &[u8; 32]) -> String {
    let hash = sha2::Sha256::digest(x25519_pub);
    hex::encode(hash)
}

/// Short fingerprint for display (first 16 hex chars = 8 bytes).
pub fn short_fp(fp: &str) -> &str {
    &fp[..fp.len().min(32)]
}

fn known_hosts_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("seam")
        .join("known_hosts")
}

/// Load all pinned entries from disk. Missing file → empty map.
fn load_pins() -> HashMap<String, String> {
    let path = known_hosts_path();
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return HashMap::new(),
    };
    let mut map = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, ' ');
        if let (Some(host), Some(fp)) = (parts.next(), parts.next()) {
            map.insert(host.to_string(), fp.trim().to_string());
        }
    }
    map
}

/// Atomically write the full pin table back to disk.
fn save_pins(pins: &HashMap<String, String>) -> Result<()> {
    let path = known_hosts_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut text = String::from(
        "# Seam known_hosts — DO NOT EDIT manually unless you know what you are doing.\n\
         # Format: <host> <sha256-of-x25519-public-key-hex>\n",
    );
    let mut entries: Vec<_> = pins.iter().collect();
    entries.sort_by_key(|(h, _)| h.as_str());
    for (host, fp) in entries {
        text.push_str(&format!("{host} {fp}\n"));
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &text)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Policy for how to handle key pinning on this connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinPolicy {
    /// Default: enforce TOFU on first-use, verify on subsequent connections.
    Enforce,
    /// --trust-on-first-use: same as Enforce but prints a clear "pinning key" message.
    TrustOnFirstUse,
    /// --insecure-ignore-pin: skip verification entirely (with loud warning).
    InsecureIgnore,
}

/// Verify (and optionally pin) the server's X25519 public key for `host`.
///
/// Returns `Ok(())` if:
///   - key matches existing pin, or
///   - no pin exists and we just saved one (TOFU), or
///   - policy is `InsecureIgnore`.
///
/// Returns `Err(...)` if the key does not match an existing pin.
pub fn verify_or_pin(host: &str, x25519_pub: &[u8; 32], policy: PinPolicy) -> Result<()> {
    if policy == PinPolicy::InsecureIgnore {
        eprintln!(
            "WARNING: --insecure-ignore-pin set — skipping server identity verification for {host}"
        );
        eprintln!("         This connection is vulnerable to relay MITM attacks.");
        return Ok(());
    }

    let fp = fingerprint(x25519_pub);
    let mut pins = load_pins();

    match pins.get(host) {
        Some(pinned) => {
            if pinned == &fp {
                eprintln!(
                    "  server identity OK: {} [{}…]",
                    host,
                    short_fp(&fp)
                );
                Ok(())
            } else {
                // Key mismatch — potential MITM.
                eprintln!();
                eprintln!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
                eprintln!("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @");
                eprintln!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
                eprintln!("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
                eprintln!("Someone could be eavesdropping on you right now (man-in-the-middle attack)!");
                eprintln!("It is also possible that the server key has legitimately changed.");
                eprintln!();
                eprintln!("Host:          {host}");
                eprintln!("Pinned key:    SHA256:{pinned}");
                eprintln!("Offered key:   SHA256:{fp}");
                eprintln!();
                eprintln!(
                    "To update the pin (ONLY if you trust this is a legitimate key change):"
                );
                eprintln!(
                    "  seam key --remove-pin {host}  # or edit {}",
                    known_hosts_path().display()
                );
                eprintln!(
                    "To bypass verification (INSECURE): use --insecure-ignore-pin"
                );
                eprintln!();
                bail!(
                    "server identity mismatch for {host}: remote host identification has changed"
                );
            }
        }
        None => {
            // First time we've seen this host — pin it now (TOFU).
            let msg = if policy == PinPolicy::TrustOnFirstUse {
                format!("  pinning server key for {host}: SHA256:{fp}")
            } else {
                format!("  first connection to {host} — pinning server key: SHA256:{}…", short_fp(&fp))
            };
            eprintln!("{msg}");
            eprintln!("  Stored in: {}", known_hosts_path().display());
            pins.insert(host.to_string(), fp);
            if let Err(e) = save_pins(&pins) {
                eprintln!("  warning: could not save pin ({e}) — continuing without persistence");
            }
            Ok(())
        }
    }
}

/// Remove a pinned entry for `host`. Returns true if an entry was removed.
pub fn remove_pin(host: &str) -> Result<bool> {
    let mut pins = load_pins();
    let removed = pins.remove(host).is_some();
    if removed {
        save_pins(&pins)?;
        println!("removed pin for {host}");
    } else {
        println!("no pin found for {host}");
    }
    Ok(removed)
}

/// List all currently pinned hosts.
pub fn list_pins() -> Vec<(String, String)> {
    let mut entries: Vec<_> = load_pins().into_iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_deterministic() {
        let key = [42u8; 32];
        assert_eq!(fingerprint(&key), fingerprint(&key));
        assert_eq!(fingerprint(&key).len(), 64); // 32 bytes hex
    }

    #[test]
    fn fingerprint_differs_for_different_keys() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }
}
