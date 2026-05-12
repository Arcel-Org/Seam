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
    /// Print the full effective configuration
    List,
    /// Get a single config value
    Get {
        /// Key name: cc, compress, identity
        key: String,
    },
    /// Set a config value and persist
    Set {
        /// Key name: cc, compress, identity
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
}

fn default_cc() -> String {
    "cubic".into()
}
fn default_true() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            cc: default_cc(),
            compress: default_true(),
            identity: None,
        }
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

    /// Save current config to disk, creating parent directories if needed.
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create config dir {}", parent.display()))?;
        }
        let text = toml::to_string_pretty(self).context("serialize config")?;
        std::fs::write(&path, text).with_context(|| format!("write config {}", path.display()))?;
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
    println!("cc        = {}", cfg.cc);
    println!("compress  = {}", cfg.compress);
    println!(
        "identity  = {}",
        cfg.identity
            .as_ref()
            .unwrap_or(&cfg.identity_path().display().to_string())
    );
    Ok(())
}

/// Get a single key.
pub fn get(key: &str) -> Result<()> {
    let cfg = Config::load()?;
    match key {
        "cc" => println!("{}", cfg.cc),
        "compress" => println!("{}", cfg.compress),
        "identity" => println!("{}", cfg.identity_path().display()),
        _ => bail!("unknown config key: {key}\n  valid keys: cc, compress, identity"),
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
        _ => bail!("unknown config key: {key}\n  valid keys: cc, compress, identity"),
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
