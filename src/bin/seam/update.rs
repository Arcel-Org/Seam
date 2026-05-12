use anyhow::{Context, Result, bail};
use clap::Args;
use serde::Deserialize;

const REPO: &str = "North9-Labs/Seam";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Args)]
pub struct UpdateArgs {
    /// Only check for updates, don't install
    #[arg(long)]
    pub check: bool,
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

pub fn run(args: UpdateArgs) -> Result<()> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let release: Release = ureq::get(&url)
        .set("User-Agent", &format!("seam/{CURRENT_VERSION}"))
        .call()
        .context("fetch releases")?
        .into_json()
        .context("parse releases")?;

    let latest = release.tag_name.trim_start_matches('v');
    if latest == CURRENT_VERSION {
        println!("seam {CURRENT_VERSION} is up to date");
        return Ok(());
    }
    println!("update available: {CURRENT_VERSION} → {latest}");

    if args.check {
        return Ok(());
    }

    let target = current_target();
    let asset = release
        .assets
        .iter()
        .find(|a| a.name.contains(&target) && a.name.ends_with(".tar.gz"))
        .ok_or_else(|| anyhow::anyhow!("no release asset for target {target}"))?;

    println!("downloading {}…", asset.name);

    let resp = ureq::get(&asset.browser_download_url)
        .set("User-Agent", &format!("seam/{CURRENT_VERSION}"))
        .call()
        .context("download binary")?;

    let tmpdir = tempfile::tempdir().context("tempdir")?;
    let archive_path = tmpdir.path().join("seam.tar.gz");
    let mut archive = std::fs::File::create(&archive_path)?;
    std::io::copy(&mut resp.into_reader(), &mut archive)?;

    // Extract
    let archive = std::fs::File::open(&archive_path)?;
    let gz = flate2::read::GzDecoder::new(archive);
    let mut tar_archive = tar::Archive::new(gz);
    let bin_path = tmpdir.path().join("seam");
    for entry in tar_archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        if path.file_name().map(|n| n == "seam").unwrap_or(false) {
            entry.unpack(&bin_path)?;
            break;
        }
    }

    if !bin_path.exists() {
        bail!("seam binary not found in archive");
    }

    // Replace self
    let current_exe = std::env::current_exe()?;
    // Write to temp in same dir, then rename (atomic on same filesystem)
    let tmp_new = current_exe.with_extension("new");
    std::fs::copy(&bin_path, &tmp_new)?;
    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&tmp_new)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&tmp_new, perms)?;
    }
    std::fs::rename(&tmp_new, &current_exe).context("replace binary")?;

    println!("updated to seam {latest}");
    Ok(())
}

fn current_target() -> String {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    match os {
        "linux" => format!("{arch}-unknown-linux-musl"),
        "macos" => format!("{arch}-apple-darwin"),
        other => format!("{arch}-{other}"),
    }
}
