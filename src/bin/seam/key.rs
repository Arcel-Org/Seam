use anyhow::Result;
use clap::Args;
use seam_protocol::handshake::{IdentityKeypair, pk_to_bytes};

#[derive(Args)]
pub struct KeyArgs {
    /// Output format: text (default) or json
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Rotate the identity keypair: back up old key with a timestamp suffix and generate a new one.
    ///
    /// The old key is saved as `identity.YYYYMMDDTHHMMSSZ` next to the current identity file.
    /// Both old and new public keys are printed so you can update relay configurations.
    /// After rotation, update all peer configurations with the new public key.
    #[arg(long)]
    pub rotate: bool,
}

pub fn run(args: KeyArgs) -> Result<()> {
    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let id_path = cfg.identity_path();

    if args.rotate {
        return rotate_key(&id_path, &args.format);
    }

    let id = if id_path.exists() {
        let bytes = std::fs::read(&id_path)?;
        IdentityKeypair::from_bytes(&bytes)
            .ok_or_else(|| anyhow::anyhow!("identity key at {} is corrupt", id_path.display()))?
    } else {
        // Generate + save so subsequent commands have a stable key
        let id = IdentityKeypair::generate();
        if let Some(parent) = id_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&id_path, id.to_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&id_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&id_path, perms)?;
        }
        eprintln!("generated new identity key at {}", id_path.display());
        id
    };

    let x25519 = hex::encode(id.x25519_public.as_bytes());
    let kem = hex::encode(pk_to_bytes(&id.kem_pk));

    match args.format.as_str() {
        "json" => {
            println!("{{");
            println!("  \"x25519\": \"{x25519}\",");
            println!("  \"kem\": \"{kem}\",");
            println!("  \"path\": \"{}\"", id_path.display());
            println!("}}");
        }
        _ => {
            println!("identity key: {}", id_path.display());
            println!();
            println!("  x25519  {x25519}");
            println!("  kem     {kem}");
            println!();
            println!("Use these with --x25519 and --kem when configuring a Seamless relay.");
        }
    }
    Ok(())
}

/// Rotate the identity keypair.
///
/// 1. Back up the existing key (if any) to `<path>.YYYYMMDDTHHMMSSZ`.
/// 2. Generate a new keypair and write it to `<path>` with mode 0o600.
/// 3. Print old and new public keys (or just the new key if no old key existed).
fn rotate_key(id_path: &std::path::Path, format: &str) -> Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Ensure parent dir exists.
    if let Some(parent) = id_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Load and back up the existing key (if present).
    let old_id: Option<IdentityKeypair> = if id_path.exists() {
        let bytes = std::fs::read(id_path)?;
        let id = IdentityKeypair::from_bytes(&bytes).ok_or_else(|| {
            anyhow::anyhow!(
                "existing identity key at {} is corrupt — cannot rotate safely.\n\
                 Delete it manually and run `seam key` to generate a fresh key.",
                id_path.display()
            )
        })?;

        // Build timestamp suffix: YYYYMMDDTHHMMSSZ
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let ts = fmt_timestamp_utc(secs);
        let backup_path = id_path.with_file_name(format!(
            "{}.{}",
            id_path.file_name().unwrap_or_default().to_string_lossy(),
            ts
        ));

        // Atomic backup: copy bytes then set perms.
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

    // Generate and write new keypair.
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

    match format {
        "json" => {
            print!("{{");
            if let Some(ref old) = old_id {
                let old_x25519 = hex::encode(old.x25519_public.as_bytes());
                let old_kem = hex::encode(pk_to_bytes(&old.kem_pk));
                println!();
                println!("  \"old\": {{");
                println!("    \"x25519\": \"{old_x25519}\",");
                println!("    \"kem\": \"{old_kem}\"");
                println!("  }},");
            }
            println!();
            println!("  \"new\": {{");
            println!("    \"x25519\": \"{new_x25519}\",");
            println!("    \"kem\": \"{new_kem}\"");
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
                println!("  OLD (backed up)");
                println!("  x25519  {old_x25519}");
                println!("  kem     {old_kem}");
                println!();
            }
            println!("  NEW (now active)");
            println!("  x25519  {new_x25519}");
            println!("  kem     {new_kem}");
            println!();
            println!("ACTION REQUIRED: update all peer configurations with the new public key.");
            println!("Old key backup is retained for audit purposes.");
        }
    }
    Ok(())
}

/// Format a Unix timestamp as a compact UTC string: `YYYYMMDDTHHMMSSZ`.
/// Pure Rust, no external crate needed.
fn fmt_timestamp_utc(secs: u64) -> String {
    // Days since 1970-01-01
    let mut days = (secs / 86400) as u32;
    let time_of_day = (secs % 86400) as u32;
    let hh = time_of_day / 3600;
    let mm = (time_of_day % 3600) / 60;
    let ss = time_of_day % 60;

    // Gregorian calendar decomposition (works until 2099).
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
    let month_days: [u32; 12] = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
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
