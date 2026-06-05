use anyhow::Result;
use clap::{Args, Subcommand};
use fips204::traits::SerDes as _;
use seam_protocol::handshake::{IdentityKeypair, MLDSA_PK_LEN, pk_to_bytes};

#[derive(Args)]
pub struct KeyArgs {
    /// Output format: text (default) or json
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// List all TOFU-pinned server keys from ~/.config/seam/known_hosts.
    #[arg(long)]
    pub list_pins: bool,

    /// Remove the TOFU pin for HOST from ~/.config/seam/known_hosts.
    ///
    /// Use this after a legitimate server key rotation so seam will accept
    /// the new key on the next connection (and re-pin it via TOFU).
    #[arg(long, value_name = "HOST")]
    pub remove_pin: Option<String>,

    #[command(subcommand)]
    pub command: Option<KeyCommand>,
}

#[derive(Subcommand)]
pub enum KeyCommand {
    /// Show the current identity key's public fingerprints (no private material exposed).
    #[command(name = "show")]
    Show,

    /// Rotate the identity keypair: back up old key and generate a new one.
    ///
    /// Backs up the existing key to ~/.config/seam/identity.key.backup.<timestamp>,
    /// writes a new keypair to ~/.config/seam/identity.key, prints old and new
    /// fingerprints, and warns you to update peer known_hosts entries.
    #[command(name = "rotate")]
    Rotate,
}

pub fn run(args: KeyArgs) -> Result<()> {
    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let id_path = cfg.identity_path();

    if args.list_pins {
        let pins = super::known_hosts::list_pins();
        if pins.is_empty() {
            println!("no pinned server keys (use --tofu when connecting to pin on first use)");
        } else {
            println!("pinned server keys (~/.config/seam/known_hosts):");
            for (host, fp) in &pins {
                println!("  {host}  SHA256:{fp}");
            }
        }
        return Ok(());
    }

    if let Some(host) = args.remove_pin {
        super::known_hosts::remove_pin(&host)?;
        return Ok(());
    }

    match args.command {
        Some(KeyCommand::Rotate) => rotate_key(&id_path, &args.format),
        Some(KeyCommand::Show) | None => show_key(&id_path, &args.format),
    }
}

/// Print the current identity key's public components without exposing private material.
fn show_key(id_path: &std::path::Path, format: &str) -> Result<()> {
    let id = if id_path.exists() {
        let bytes = std::fs::read(id_path)?;
        IdentityKeypair::from_bytes(&bytes)
            .ok_or_else(|| anyhow::anyhow!("identity key at {} is corrupt", id_path.display()))?
    } else {
        let id = IdentityKeypair::generate();
        if let Some(parent) = id_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(id_path, id.to_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(id_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(id_path, perms)?;
        }
        eprintln!("generated new identity key at {}", id_path.display());
        id
    };

    let x25519 = hex::encode(id.x25519_public.as_bytes());
    let kem = hex::encode(pk_to_bytes(&id.kem_pk));
    let mldsa_pk_bytes: [u8; MLDSA_PK_LEN] = id.mldsa_pk.clone().into_bytes();
    let mldsa_pk_hex = hex::encode(&mldsa_pk_bytes);
    let mldsa_fp = id.mldsa_fingerprint();

    match format {
        "json" => {
            println!("{{");
            println!("  \"x25519\": \"{x25519}\",");
            println!("  \"ml_kem_768\": \"{kem}\",");
            println!("  \"ml_dsa_65\": \"{mldsa_pk_hex}\",");
            println!("  \"ml_dsa_65_fingerprint\": \"SHA256:{mldsa_fp}\",");
            println!("  \"path\": \"{}\"", id_path.display());
            println!("}}");
        }
        _ => {
            println!("identity key: {}", id_path.display());
            println!();
            println!("  X25519 public key:          {x25519}");
            println!("  ML-KEM-768 public key:      {kem}");
            println!("  ML-DSA-65 public key:       {mldsa_pk_hex}");
            println!("  ML-DSA-65 fingerprint:      SHA256:{mldsa_fp}");
            println!();
            println!("  X25519 (32 bytes)     — classical key agreement");
            println!("  ML-KEM-768 (1184 B)   — post-quantum key encapsulation (FIPS 203)");
            println!("  ML-DSA-65 (1952 B)    — quantum-resistant identity signature (FIPS 204)");
            println!();
            println!("Use X25519 and ML-KEM-768 keys when configuring a Seamless relay.");
            println!("The ML-DSA-65 fingerprint identifies this node to quantum-resistant peers.");
        }
    }
    Ok(())
}

/// Rotate the identity keypair.
///
/// 1. Back up the existing key (if any) to `~/.config/seam/identity.key.backup.<timestamp>`.
/// 2. Generate a new keypair and write it to `<path>` with mode 0o600.
/// 3. Print old and new public keys (or just the new key if no old key existed).
fn rotate_key(id_path: &std::path::Path, format: &str) -> Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};

    if let Some(parent) = id_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let old_id: Option<IdentityKeypair> = if id_path.exists() {
        let bytes = std::fs::read(id_path)?;
        let id = IdentityKeypair::from_bytes(&bytes).ok_or_else(|| {
            anyhow::anyhow!(
                "existing identity key at {} is corrupt — cannot rotate safely.\n\
                 Delete it manually and run `seam key` to generate a fresh key.",
                id_path.display()
            )
        })?;

        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let ts = fmt_timestamp_utc(secs);
        let backup_name = format!(
            "{}.backup.{ts}",
            id_path.file_name().unwrap_or_default().to_string_lossy()
        );
        let backup_path = id_path.with_file_name(backup_name);

        std::fs::write(&backup_path, &bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&backup_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&backup_path, perms)?;
        }
        eprintln!("backed up old identity key → {}", backup_path.display());
        Some(id)
    } else {
        eprintln!("no existing identity key found — generating fresh key");
        None
    };

    let new_id = IdentityKeypair::generate();
    std::fs::write(id_path, new_id.to_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(id_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(id_path, perms)?;
    }

    let new_x25519 = hex::encode(new_id.x25519_public.as_bytes());
    let new_kem = hex::encode(pk_to_bytes(&new_id.kem_pk));
    let new_mldsa_pk_bytes: [u8; MLDSA_PK_LEN] = new_id.mldsa_pk.clone().into_bytes();
    let new_mldsa_fp = new_id.mldsa_fingerprint();

    match format {
        "json" => {
            print!("{{");
            if let Some(ref old) = old_id {
                let old_x25519 = hex::encode(old.x25519_public.as_bytes());
                let old_kem = hex::encode(pk_to_bytes(&old.kem_pk));
                let old_mldsa_fp = old.mldsa_fingerprint();
                println!();
                println!("  \"old\": {{");
                println!("    \"x25519\": \"{old_x25519}\",");
                println!("    \"ml_kem_768\": \"{old_kem}\",");
                println!("    \"ml_dsa_65_fingerprint\": \"SHA256:{old_mldsa_fp}\"");
                println!("  }},");
            }
            println!();
            println!("  \"new\": {{");
            println!("    \"x25519\": \"{new_x25519}\",");
            println!("    \"ml_kem_768\": \"{new_kem}\",");
            println!(
                "    \"ml_dsa_65\": \"{}\",",
                hex::encode(&new_mldsa_pk_bytes)
            );
            println!("    \"ml_dsa_65_fingerprint\": \"SHA256:{new_mldsa_fp}\"");
            println!("  }},");
            println!("  \"path\": \"{}\"", id_path.display());
            println!("}}");
        }
        _ => {
            println!("key rotation complete — {}", id_path.display());
            println!();
            if let Some(ref old) = old_id {
                let old_x25519 = hex::encode(old.x25519_public.as_bytes());
                let old_kem = hex::encode(pk_to_bytes(&old.kem_pk));
                let old_mldsa_fp = old.mldsa_fingerprint();
                println!("  OLD fingerprint (backed up)");
                println!("  x25519              {old_x25519}");
                println!("  ml-kem-768          {old_kem}");
                println!("  ml-dsa-65 fp        SHA256:{old_mldsa_fp}");
                println!();
            }
            println!("  NEW fingerprint (now active)");
            println!("  x25519              {new_x25519}");
            println!("  ml-kem-768          {new_kem}");
            println!("  ml-dsa-65 fp        SHA256:{new_mldsa_fp}");
            println!();
            println!("WARNING: Update your known_hosts on peer systems with the new public key.");
            println!("Old key backup is retained for audit purposes.");
        }
    }
    Ok(())
}

/// Format a Unix timestamp as a compact UTC string: `YYYYMMDDTHHMMSSZ`.
fn fmt_timestamp_utc(secs: u64) -> String {
    let mut days = (secs / 86400) as u32;
    let time_of_day = (secs % 86400) as u32;
    let hh = time_of_day / 3600;
    let mm = (time_of_day % 3600) / 60;
    let ss = time_of_day % 60;

    let mut year = 1970u32;
    loop {
        let leap = is_leap(year);
        let days_in_year = if leap { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let leap = is_leap(year);
    let month_days: [u32; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u32;
    for &md in &month_days {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    let day = days + 1;
    format!("{year:04}{month:02}{day:02}T{hh:02}{mm:02}{ss:02}Z")
}

fn is_leap(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}
