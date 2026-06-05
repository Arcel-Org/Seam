use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub cmd: ConfigCmd,
}

#[derive(Subcommand)]
pub enum ConfigCmd {
    /// Print the full effective configuration (alias: show)
    #[command(alias = "show")]
    List,
    /// Get a single config value
    Get {
        /// Key name: cc, compress, identity, cipher, max_connections, listen_port
        key: String,
    },
    /// Set a config value and persist
    Set {
        /// Key name: cc, compress, identity, cipher, max_connections, listen_port
        key: String,
        /// New value
        value: String,
    },
    /// Create a default config file if it does not exist
    Init,
}

pub fn run(args: ConfigArgs) -> Result<()> {
    match args.cmd {
        ConfigCmd::List => print(),
        ConfigCmd::Get { key } => get(&key),
        ConfigCmd::Set { key, value } => set(&key, &value),
        ConfigCmd::Init => init(),
    }
}

/// Seam user configuration, persisted in `~/.config/seam/config.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// Default congestion controller: "cubic" or "bbr".
    #[serde(default = "default_cc")]
    pub cc: String,
    /// Enable zstd compression by default for `cp`.
    #[serde(default = "default_true")]
    pub compress: bool,
    /// Path to persistent identity key (relative to home or absolute).
    #[serde(default)]
    pub identity: Option<String>,
    /// AEAD cipher suite: "chacha20poly1305" (default) or "aes256gcm" (CNSA 2.0).
    /// Set to "aes256gcm" for NSS/DoD deployments that require CNSA 2.0 compliance.
    #[serde(default = "default_cipher")]
    pub cipher: String,
    /// Maximum simultaneous connections the server endpoint will accept.
    /// New connections are silently dropped once this limit is reached.
    /// Default: 1024.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Default UDP listen port for server subcommands (recv, bench-recv, etc.).
    /// 0 = OS-assigned (ephemeral). Set a fixed port for firewall-friendly deployments.
    #[serde(default)]
    pub listen_port: u16,
    /// FEC source symbols per group (k). 0 = disabled (pure ARQ).
    /// Tune for the link type:
    ///   LAN / fiber:      fec_k = 0  (no FEC overhead)
    ///   Mobile / WiFi:    fec_k = 8, fec_r = 2
    ///   Satellite / HF:   fec_k = 4, fec_r = 4
    /// When set, overrides the dynamic FEC arbiter.
    #[serde(default)]
    pub fec_k: Option<u8>,
    /// FEC repair symbols per group (r). Only used when fec_k > 0.
    /// Overhead = fec_r / fec_k. Must be ≥ 1 when fec_k > 0.
    #[serde(default)]
    pub fec_r: Option<u8>,
    /// Enable FIPS-140 compliant mode.
    /// When true: forces AES-256-GCM cipher, uses SHA-256 instead of BLAKE3 for
    /// file integrity checks. Also settable via SEAM_FIPS_MODE=1 env var or
    /// --fips-mode CLI flag. Required for NIST FIPS 140-3 / CNSA 2.0 deployments.
    #[serde(default)]
    pub fips_mode: bool,
    /// List of relay/infrastructure hosts to ping in `seam doctor`.
    ///
    /// Each entry is a `user@host` or `host` string. `seam doctor` will attempt
    /// a Seam ping to each relay and report RTT. Gives ops a single command to
    /// verify the health of their entire Seam infrastructure.
    ///
    /// Example in config.toml:
    ///   relays = ["ops@relay1.example.com", "ops@relay2.example.com"]
    #[serde(default)]
    pub relays: Vec<String>,
}

fn default_cc() -> String {
    "cubic".into()
}
fn default_true() -> bool {
    true
}
fn default_cipher() -> String {
    "chacha20poly1305".into()
}
fn default_max_connections() -> usize {
    1024
}

impl Default for Config {
    fn default() -> Self {
        Self {
            cc: default_cc(),
            compress: default_true(),
            identity: None,
            cipher: default_cipher(),
            max_connections: default_max_connections(),
            listen_port: 0,
            fec_k: None,
            fec_r: None,
            fips_mode: false,
            relays: Vec::new(),
        }
    }
}

impl Config {
    /// Resolve effective FIPS mode: config file < env var < CLI flag.
    /// Returns true if FIPS mode should be active.
    pub fn effective_fips_mode(config_fips: bool, cli_fips: bool) -> bool {
        cli_fips
            || std::env::var("SEAM_FIPS_MODE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
            || config_fips
    }

    /// Print the FIPS mode banner and return the algorithm list string.
    pub fn fips_banner() -> &'static str {
        "AES-256-GCM (FIPS 197), ML-KEM-768 (FIPS 203), X25519 (SP 800-186), SHA-256 (FIPS 180-4)"
    }
}

impl Config {
    pub fn config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("seam")
            .join("config.toml")
    }

    /// Load config from disk, or return defaults if the file does not exist.
    pub fn load() -> Result<Self> {
        let path = Self::config_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("read config {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("parse config {}", path.display()))?;
        Ok(cfg)
    }

    /// Save current config to disk atomically (write tmp then rename).
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create config dir {}", parent.display()))?;
        }
        let text = toml::to_string_pretty(self).context("serialize config")?;
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, &text).with_context(|| format!("write config tmp {}", tmp.display()))?;
        std::fs::rename(&tmp, &path).with_context(|| format!("atomic rename config {}", path.display()))?;
        Ok(())
    }

    /// Resolve the identity key path, falling back to the default location.
    pub fn identity_path(&self) -> PathBuf {
        self.identity
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                dirs::config_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("seam")
                    .join("identity")
            })
    }
}

/// Print the current effective configuration.
pub fn print() -> Result<()> {
    let cfg = Config::load()?;
    println!("# config path: {}", Config::config_path().display());
    println!();
    println!("cc              = {}", cfg.cc);
    println!("compress        = {}", cfg.compress);
    println!(
        "identity        = {}",
        cfg.identity
            .as_ref()
            .unwrap_or(&cfg.identity_path().display().to_string())
    );
    println!("cipher          = {}", cfg.cipher);
    println!("max_connections = {}", cfg.max_connections);
    println!(
        "listen_port     = {}",
        if cfg.listen_port == 0 {
            "0 (OS-assigned)".to_string()
        } else {
            cfg.listen_port.to_string()
        }
    );
    println!(
        "fec_k           = {}",
        cfg.fec_k.map(|v| v.to_string()).unwrap_or_else(|| "auto".into())
    );
    println!(
        "fec_r           = {}",
        cfg.fec_r.map(|v| v.to_string()).unwrap_or_else(|| "auto".into())
    );
    println!("fips_mode       = {}", cfg.fips_mode);
    if cfg.relays.is_empty() {
        println!("relays          = []");
    } else {
        println!("relays          = [{}]", cfg.relays.iter().map(|r| format!("{r:?}")).collect::<Vec<_>>().join(", "));
    }
    Ok(())
}

/// Get a single key.
pub fn get(key: &str) -> Result<()> {
    let cfg = Config::load()?;
    match key {
        "cc" => println!("{}", cfg.cc),
        "compress" => println!("{}", cfg.compress),
        "identity" => println!("{}", cfg.identity_path().display()),
        "cipher" => println!("{}", cfg.cipher),
        "max_connections" => println!("{}", cfg.max_connections),
        "listen_port" => println!("{}", cfg.listen_port),
        "fec_k" => println!("{}", cfg.fec_k.map(|v| v.to_string()).unwrap_or_else(|| "auto".into())),
        "fec_r" => println!("{}", cfg.fec_r.map(|v| v.to_string()).unwrap_or_else(|| "auto".into())),
        "fips_mode" => println!("{}", cfg.fips_mode),
        "relays" => {
            for r in &cfg.relays {
                println!("{r}");
            }
        }
        _ => bail!(
            "unknown config key: {key}\n  valid keys: cc, compress, identity, cipher, max_connections, listen_port, fec_k, fec_r, fips_mode, relays"
        ),
    }
    Ok(())
}

/// Set a single key and persist.
pub fn set(key: &str, value: &str) -> Result<()> {
    let mut cfg = Config::load()?;
    match key {
        "cc" => {
            if value != "cubic" && value != "bbr" {
                bail!("cc must be 'cubic' or 'bbr'");
            }
            cfg.cc = value.into();
        }
        "compress" => {
            cfg.compress = value.parse().context("compress must be true or false")?;
        }
        "identity" => {
            cfg.identity = Some(value.into());
        }
        "cipher" => {
            if value != "chacha20poly1305" && value != "aes256gcm" {
                bail!("cipher must be 'chacha20poly1305' or 'aes256gcm'");
            }
            cfg.cipher = value.into();
        }
        "max_connections" => {
            let n: usize = value
                .parse()
                .context("max_connections must be a positive integer")?;
            if n == 0 {
                bail!("max_connections must be at least 1");
            }
            cfg.max_connections = n;
        }
        "listen_port" => {
            let p: u16 = value
                .parse()
                .context("listen_port must be 0–65535")?;
            cfg.listen_port = p;
        }
        "fec_k" => {
            if value == "auto" || value == "0" {
                if value == "0" {
                    cfg.fec_k = Some(0);
                } else {
                    cfg.fec_k = None;
                }
            } else {
                let k: u8 = value.parse().context("fec_k must be 0–255 or 'auto'")?;
                if k == 1 {
                    bail!("fec_k must be 0 (disabled/auto) or ≥ 2");
                }
                cfg.fec_k = Some(k);
            }
        }
        "fec_r" => {
            if value == "auto" {
                cfg.fec_r = None;
            } else {
                let r: u8 = value.parse().context("fec_r must be 1–255 or 'auto'")?;
                if r == 0 {
                    bail!("fec_r must be ≥ 1 when set (or use 'auto')");
                }
                cfg.fec_r = Some(r);
            }
        }
        "fips_mode" => {
            cfg.fips_mode = value.parse().context("fips_mode must be true or false")?;
        }
        "relays" => {
            // value is a comma-separated list of user@host entries, or a single entry.
            // Special case: empty string clears the list.
            if value.trim().is_empty() {
                cfg.relays = Vec::new();
            } else {
                let entries: Vec<String> = value.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                cfg.relays = entries;
            }
        }
        _ => bail!(
            "unknown config key: {key}\n  valid keys: cc, compress, identity, cipher, max_connections, listen_port, fec_k, fec_r, fips_mode, relays"
        ),
    }
    cfg.save()?;
    println!("{key} = {value}");
    Ok(())
}

/// Initialise a default config file if it does not exist.
pub fn init() -> Result<()> {
    let path = Config::config_path();
    if path.exists() {
        println!("config already exists at {}", path.display());
        return Ok(());
    }
    Config::default().save()?;
    println!("created default config at {}", path.display());
    Ok(())
}
