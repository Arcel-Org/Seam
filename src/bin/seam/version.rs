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

pub fn run(args: VersionArgs) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");

    if args.json {
        // Machine-readable output for audit pipelines and automated checks.
        let suites_json: Vec<String> = CIPHER_SUITES
            .iter()
            .map(|(id, _)| format!("\"{}\"", id))
            .collect();
        println!(
            r#"{{
  "version": "{version}",
  "build_date": "{BUILD_DATE}",
  "noise_pattern": "{NOISE_PATTERN}",
  "kem": "{KEM_ALGORITHM}",
  "hybrid_ke": "{HYBRID_KE}",
  "cipher_suites": [{suites}]
}}"#,
            version = version,
            BUILD_DATE = BUILD_DATE,
            NOISE_PATTERN = NOISE_PATTERN,
            KEM_ALGORITHM = KEM_ALGORITHM,
            HYBRID_KE = HYBRID_KE,
            suites = suites_json.join(", "),
        );
    } else {
        println!("seam {version}");
        println!("Build date   : {BUILD_DATE}");
        println!("Noise pattern: {NOISE_PATTERN}");
        println!("KEM          : {KEM_ALGORITHM}");
        println!("Key exchange : {HYBRID_KE}");
        println!("Cipher suites:");
        for (id, desc) in CIPHER_SUITES {
            println!("  {id:<22} {desc}");
        }
    }

    Ok(())
}
