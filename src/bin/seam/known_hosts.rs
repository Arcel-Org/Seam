/// TOFU (Trust-On-First-Use) server identity pinning for Seam.
///
/// On the first connection to a host, the server's public key fingerprints
/// are saved in `~/.config/seam/known_hosts`. On subsequent connections the stored
/// fingerprints are compared to what the server presents; a mismatch is a fatal error
/// unless `--insecure-ignore-pin` is explicitly passed.
///
/// The format is one entry per line (v1 — classical only):
///   `<host> <sha256-x25519-hex>`
///
/// Extended format (v2 — hybrid, quantum-resistant):
///   `<host> <sha256-x25519-hex> mldsa65:<sha256-mldsa-pk-hex>`
///
/// This is intentionally simple and human-readable, like SSH known_hosts.
use anyhow::{Result, bail};
use sha2::Digest as _;
use std::collections::HashMap;
use std::path::PathBuf;

/// SHA-256 fingerprint of a 32-byte X25519 public key, returned as lowercase hex.
pub fn fingerprint(x25519_pub: &[u8; 32]) -> String {
    let hash = sha2::Sha256::digest(x25519_pub);
    hex::encode(hash)
}

/// SHA-256 fingerprint of an ML-DSA-65 verify key, returned as lowercase hex.
/// This is quantum-resistant: a quantum adversary cannot forge it.
#[allow(dead_code)]
pub fn mldsa_fingerprint(mldsa_pk: &[u8]) -> String {
    let hash = sha2::Sha256::digest(mldsa_pk);
    hex::encode(hash)
}

/// Short fingerprint for display (first 16 hex chars = 8 bytes).
pub fn short_fp(fp: &str) -> &str {
    &fp[..fp.len().min(32)]
}

fn known_hosts_path() -> PathBuf {
    // Test-only override so unit tests never touch the real user config dir.
    if let Ok(p) = std::env::var("SEAM_KNOWN_HOSTS_PATH") {
        return PathBuf::from(p);
    }
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
    // Use a PID-suffixed temp name so two concurrent `seam` processes racing
    // this function never write/rename the same temp file out from under
    // each other; the rename itself is still atomic per-process.
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, &text)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Hold an exclusive, cross-process advisory lock for the duration of `f`,
/// serializing the load-modify-save cycle in [`verify_or_pin`] and
/// [`remove_pin`].
///
/// Without this, two `seam` processes racing a first-time connection to the
/// same host can both observe "no pin yet", each independently accept
/// whatever key they were offered (including a MITM'd one), and then
/// silently clobber each other's pin on save — with neither ever seeing the
/// "REMOTE HOST IDENTIFICATION HAS CHANGED" warning, since that check only
/// fires against a pin that was already on disk when `load_pins` ran.
/// Locking makes the whole check-then-pin sequence atomic across processes.
#[cfg(unix)]
fn with_pins_lock<R>(f: impl FnOnce() -> Result<R>) -> Result<R> {
    use std::os::fd::AsRawFd;

    let lock_path = known_hosts_path().with_extension("lock");
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)?;
    // SAFETY: lock_file owns a valid, open fd for the duration of this call;
    // flock is released automatically when it's dropped/closed below.
    let rc = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        // Locking failed (e.g. unsupported filesystem) — fall back to
        // best-effort unlocked operation rather than hard-failing.
        return f();
    }
    let result = f();
    unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_UN) };
    result
}

#[cfg(not(unix))]
fn with_pins_lock<R>(f: impl FnOnce() -> Result<R>) -> Result<R> {
    f()
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
    with_pins_lock(|| verify_or_pin_locked(host, &fp, policy))
}

fn verify_or_pin_locked(host: &str, fp: &str, policy: PinPolicy) -> Result<()> {
    let mut pins = load_pins();

    match pins.get(host) {
        Some(pinned) => {
            if pinned == fp {
                eprintln!("  server identity OK: {} [{}…]", host, short_fp(fp));
                Ok(())
            } else {
                // Key mismatch — potential MITM.
                eprintln!();
                eprintln!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
                eprintln!("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @");
                eprintln!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
                eprintln!("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
                eprintln!(
                    "Someone could be eavesdropping on you right now (man-in-the-middle attack)!"
                );
                eprintln!("It is also possible that the server key has legitimately changed.");
                eprintln!();
                eprintln!("Host:          {host}");
                eprintln!("Pinned key:    SHA256:{pinned}");
                eprintln!("Offered key:   SHA256:{fp}");
                eprintln!();
                eprintln!("To update the pin (ONLY if you trust this is a legitimate key change):");
                eprintln!(
                    "  seam key --remove-pin {host}  # or edit {}",
                    known_hosts_path().display()
                );
                eprintln!("To bypass verification (INSECURE): use --insecure-ignore-pin");
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
                format!(
                    "  first connection to {host} — pinning server key: SHA256:{}…",
                    short_fp(fp)
                )
            };
            eprintln!("{msg}");
            eprintln!("  Stored in: {}", known_hosts_path().display());
            pins.insert(host.to_string(), fp.to_string());
            if let Err(e) = save_pins(&pins) {
                eprintln!("  warning: could not save pin ({e}) — continuing without persistence");
            }
            Ok(())
        }
    }
}

/// Remove a pinned entry for `host`. Returns true if an entry was removed.
pub fn remove_pin(host: &str) -> Result<bool> {
    with_pins_lock(|| {
        let mut pins = load_pins();
        let removed = pins.remove(host).is_some();
        if removed {
            save_pins(&pins)?;
            println!("removed pin for {host}");
        } else {
            println!("no pin found for {host}");
        }
        Ok(removed)
    })
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

    // SEAM_KNOWN_HOSTS_PATH is process-global; serialize the tests that touch it
    // so they can't interleave under cargo's default parallel test runner.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn concurrent_first_pin_is_serialized_and_not_corrupted() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        // SAFETY: single-threaded within this test under ENV_LOCK; no other
        // thread reads/writes SEAM_KNOWN_HOSTS_PATH concurrently.
        unsafe { std::env::set_var("SEAM_KNOWN_HOSTS_PATH", &path) };

        // 16 threads race to be the first to pin distinct keys for the same
        // host. Exactly one may win the TOFU pin; every other racer must see
        // that pin already committed (via the lock) and correctly reject its
        // own differing key as a mismatch — never silently overwrite it.
        let mut handles = Vec::new();
        for i in 0..16u8 {
            handles.push(std::thread::spawn(move || {
                let key = [i; 32];
                verify_or_pin("race-host", &key, PinPolicy::Enforce).is_ok()
            }));
        }
        let successes: usize = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count();
        assert_eq!(
            successes, 1,
            "exactly one racer should win the first-pin race"
        );

        // The file must parse cleanly (no torn/interleaved writes) and pin
        // exactly one of the 16 candidate keys, proving the load-check-save
        // cycle was serialized rather than raced.
        let pins = load_pins();
        assert_eq!(pins.len(), 1);
        let pinned = pins.get("race-host").unwrap();
        let candidates: Vec<String> = (0..16u8).map(|i| fingerprint(&[i; 32])).collect();
        assert!(candidates.contains(pinned));

        unsafe { std::env::remove_var("SEAM_KNOWN_HOSTS_PATH") };
    }

    #[test]
    fn mismatched_key_after_pin_is_rejected() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        unsafe { std::env::set_var("SEAM_KNOWN_HOSTS_PATH", &path) };

        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        verify_or_pin("stable-host", &key_a, PinPolicy::Enforce).unwrap();
        let err = verify_or_pin("stable-host", &key_b, PinPolicy::Enforce).unwrap_err();
        assert!(err.to_string().contains("identity mismatch"));
        // Re-verifying with the originally pinned key still succeeds.
        verify_or_pin("stable-host", &key_a, PinPolicy::Enforce).unwrap();

        unsafe { std::env::remove_var("SEAM_KNOWN_HOSTS_PATH") };
    }
}
