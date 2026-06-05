/// `seam version` — print version, build metadata, and supported cipher suites.
///
/// Designed for ops/audit workflows where operators need a machine-readable or
/// human-readable snapshot of the binary's capabilities (analogous to
/// `openssl version -a` or `ssh -V`).
use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
pub struct VersionArgs {
    /// Output in machine-readable JSON format (for scripting / audit pipelines).
    #[arg(long)]
    json: bool,
}

/// Compile-time build date sourced from the environment (set by CI).
/// Falls back to "unknown" if the variable was not set at build time.
const BUILD_DATE: &str = match option_env!("SEAM_BUILD_DATE") {
    Some(d) => d,
    None => "unknown",
};

/// Noise handshake pattern used for authentication and key agreement.
const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Supported AEAD cipher suites (in preference order).
const CIPHER_SUITES: &[(&str, &str)] = &[
    (
        "chacha20poly1305",
        "ChaCha20-Poly1305 — default, cross-platform, no hardware requirement",
    ),
    (
        "aes256gcm",
        "AES-256-GCM — NSA CNSA 2.0 / DoD compliant, hardware-accelerated on AES-NI",
    ),
];

/// KEM algorithm used for post-quantum key exchange.
const KEM_ALGORITHM: &str = "ML-KEM-768 (FIPS 203, CRYSTALS-Kyber)";

/// Hybrid key exchange construction.
const HYBRID_KE: &str = "X25519 + ML-KEM-768 (hybrid post-quantum)";

/// Identity signature algorithm (quantum-resistant identity proofs).
const IDENTITY_SIG: &str = "ML-DSA-65 (FIPS 204, CRYSTALS-Dilithium3) — quantum-resistant identity";

/// Double ratchet description for per-epoch forward secrecy.
const DOUBLE_RATCHET: &str =
    "Double ratchet: per-epoch forward secrecy (epoch: 1000 packets / 30s)";

pub fn run(args: VersionArgs) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");

    // Load config to show active TAR features.
    let cfg = super::config::Config::load().unwrap_or_default();
    // We don't have fips_active here without plumbing it through, so we
    // use the config's fips_mode field as the effective value.
    let fips_active = cfg.fips_mode;
    let padding_active = cfg.effective_traffic_padding(fips_active);
    let cover_active = cfg.cover_traffic_kbps > 0;
    let jitter_active = cfg.timing_jitter_ms > 0;
    let obfuscate_active = cfg.obfuscate;

    // Build a summary of active TAR features for display.
    let tar_features: Vec<&str> = {
        let mut v = Vec::new();
        if padding_active {
            v.push("size-class padding");
        }
        if cover_active {
            v.push("cover traffic");
        }
        if jitter_active {
            v.push("timing jitter");
        }
        if obfuscate_active {
            v.push("header obfuscation");
        }
        v
    };
    let tar_summary = if tar_features.is_empty() {
        "none (all disabled)".to_string()
    } else {
        tar_features.join(", ")
    };

    if args.json {
        // Machine-readable output for audit pipelines and automated checks.
        let suites_json: Vec<String> = CIPHER_SUITES
            .iter()
            .map(|(id, _)| format!("\"{}\"", id))
            .collect();
        let tar_json = serde_json::json!({
            "size_class_padding": padding_active,
            "cover_traffic_kbps": cfg.cover_traffic_kbps,
            "timing_jitter_ms": cfg.timing_jitter_ms,
            "header_obfuscation": obfuscate_active,
        });
        println!(
            r#"{{
  "version": "{version}",
  "build_date": "{BUILD_DATE}",
  "noise_pattern": "{NOISE_PATTERN}",
  "kem": "{KEM_ALGORITHM}",
  "hybrid_ke": "{HYBRID_KE}",
  "identity_sig": "{IDENTITY_SIG}",
  "double_ratchet": "{DOUBLE_RATCHET}",
  "cipher_suites": [{suites}],
  "traffic_analysis_resistance": {tar}
}}"#,
            version = version,
            BUILD_DATE = BUILD_DATE,
            NOISE_PATTERN = NOISE_PATTERN,
            KEM_ALGORITHM = KEM_ALGORITHM,
            HYBRID_KE = HYBRID_KE,
            IDENTITY_SIG = IDENTITY_SIG,
            DOUBLE_RATCHET = DOUBLE_RATCHET,
            suites = suites_json.join(", "),
            tar = tar_json,
        );
    } else {
        println!("seam {version}");
        println!("Build date   : {BUILD_DATE}");
        println!("Noise pattern: {NOISE_PATTERN}");
        println!("KEM          : {KEM_ALGORITHM}");
        println!("Key exchange : {HYBRID_KE}");
        println!("Identity sig : {IDENTITY_SIG}");
        println!("Ratchet      : {DOUBLE_RATCHET}");
        println!("Cipher suites:");
        for (id, desc) in CIPHER_SUITES {
            println!("  {id:<22} {desc}");
        }
        println!();
        println!("Traffic analysis resistance: {tar_summary}");
        if padding_active {
            println!("  size-class padding : enabled (256/512/1024/1400 byte classes)");
        }
        if cover_active {
            println!(
                "  cover traffic      : {} kbps constant rate",
                cfg.cover_traffic_kbps
            );
        }
        if jitter_active {
            println!(
                "  timing jitter      : 0–{} ms per-packet delay",
                cfg.timing_jitter_ms
            );
        }
        if obfuscate_active {
            println!("  header obfuscation : enabled (XOR with per-session secret)");
        }
    }

    Ok(())
}
