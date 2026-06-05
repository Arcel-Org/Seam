use anyhow::Result;
use clap::Args;
use seam_protocol::handshake::{IdentityKeypair, pk_to_bytes};

#[derive(Args)]
pub struct KeyArgs {
    /// Output format: text (default) or json
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

pub fn run(args: KeyArgs) -> Result<()> {
    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let id_path = cfg.identity_path();

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
