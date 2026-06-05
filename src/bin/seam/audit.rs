/// Append-only audit log for Seam operations.
///
/// Every Seam command invocation is recorded to:
///   `~/.local/share/seam/audit.jsonl`
///
/// Each record is a single JSON object on one line (JSONL format), containing:
///   - `ts`         — ISO-8601 UTC timestamp of invocation
///   - `subcommand` — e.g. "cp", "shell", "sync"
///   - `remote`     — remote host if applicable (empty string if local-only)
///   - `args`       — sanitised argument list (passwords/keys redacted)
///   - `exit_code`  — integer exit code (0 = success, null = unknown/in-progress)
///   - `bytes_tx`   — bytes transferred (for cp/sync; null otherwise)
///   - `fips_mode`  — boolean, whether FIPS mode was active
///   - `pid`        — process ID for cross-referencing with server-side logs
///
/// The file is opened with O_APPEND so concurrent writes are safe on POSIX
/// systems (each write is ≤ PIPE_BUF = 4096 bytes, which is atomic on Linux).
///
/// Government/DoD rationale: NIST SP 800-53 AU-2 / AU-12 require that all
/// privileged operations are auditable. Client-side logs complement the
/// server-side tracing spans already emitted by seam server components.
use anyhow::Result;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::path::PathBuf;

// ── seam audit subcommand ─────────────────────────────────────────────────────

#[derive(Args)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub cmd: AuditCmd,
}

#[derive(Subcommand)]
pub enum AuditCmd {
    /// Show recent audit log entries (default: last 20)
    Show {
        /// Number of entries to show (0 = all)
        #[arg(short = 'n', long, default_value_t = 20)]
        lines: usize,
        /// Filter entries on or after this date (YYYY-MM-DD or RFC3339)
        #[arg(long, value_name = "DATE")]
        since: Option<String>,
        /// Filter entries for a specific remote host (substring match)
        #[arg(long, value_name = "HOST")]
        host: Option<String>,
        /// Output raw JSONL instead of formatted table
        #[arg(long)]
        json: bool,
    },
    /// Remove all entries from the audit log (prompts for confirmation)
    Clear {
        /// Skip confirmation prompt (dangerous — use in scripts)
        #[arg(long)]
        yes: bool,
    },
}

/// A deserialized audit entry for querying.
#[derive(Debug, Deserialize)]
struct AuditRecord {
    ts: String,
    subcommand: String,
    remote: String,
    #[serde(default)]
    exit_code: Option<i32>,
    #[serde(default)]
    bytes_tx: Option<u64>,
    #[serde(default)]
    fips_mode: bool,
    /// PID from log entry (used in JSON output mode)
    #[serde(default)]
    #[allow(dead_code)]
    pid: u32,
}

pub fn run(args: AuditArgs) -> Result<()> {
    match args.cmd {
        AuditCmd::Show {
            lines,
            since,
            host,
            json,
        } => show(lines, since.as_deref(), host.as_deref(), json),
        AuditCmd::Clear { yes } => clear(yes),
    }
}

fn show(
    limit: usize,
    since: Option<&str>,
    host_filter: Option<&str>,
    raw_json: bool,
) -> Result<()> {
    let path = audit_log_path();
    if !path.exists() {
        println!("Audit log not found: {}", path.display());
        println!("No operations have been recorded yet.");
        return Ok(());
    }

    let text = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("cannot read audit log: {e}"))?;

    // Parse --since as a date/datetime prefix for lexicographic comparison.
    // RFC3339 timestamps sort lexicographically, so prefix comparison works.
    let since_prefix = since.map(|s| {
        // Accept YYYY-MM-DD (10 chars) or full RFC3339. Normalize to at least YYYY-MM-DD.
        if s.len() == 10 && s.chars().nth(4) == Some('-') {
            s.to_string()
        } else {
            s.to_string()
        }
    });

    // Collect all matching records. We load all lines and filter, then take last N.
    let mut records: Vec<(String, AuditRecord)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let rec: AuditRecord = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(_) => continue, // skip malformed lines
        };

        // Apply --since filter
        if let Some(ref prefix) = since_prefix {
            if !rec.ts.starts_with(prefix.as_str()) && rec.ts.as_str() < prefix.as_str() {
                continue;
            }
        }

        // Apply --host filter (substring match on remote field)
        if let Some(hf) = host_filter {
            if !rec.remote.contains(hf) {
                continue;
            }
        }

        records.push((line.to_string(), rec));
    }

    // Take the last `limit` entries (or all if limit==0).
    let start = if limit > 0 && records.len() > limit {
        records.len() - limit
    } else {
        0
    };
    let records = &records[start..];

    if records.is_empty() {
        println!("No audit entries match the given filters.");
        return Ok(());
    }

    if raw_json {
        for (raw, _) in records {
            println!("{raw}");
        }
        return Ok(());
    }

    // Formatted table output.
    println!(
        "{:<25} {:<10} {:<28} {:<6} {:<10} {}",
        "timestamp", "command", "remote", "exit", "bytes_tx", "fips"
    );
    println!("{}", "-".repeat(90));
    for (_, rec) in records {
        let exit = match rec.exit_code {
            Some(0) => "ok".to_string(),
            Some(n) => format!("err({n})"),
            None => "-".to_string(),
        };
        let bytes = match rec.bytes_tx {
            Some(b) => format_bytes(b),
            None => "-".to_string(),
        };
        let fips = if rec.fips_mode { "yes" } else { "no" };
        // Truncate remote to fit column
        let remote_disp = if rec.remote.len() > 28 {
            format!("{}…", &rec.remote[..27])
        } else {
            rec.remote.clone()
        };
        println!(
            "{:<25} {:<10} {:<28} {:<6} {:<10} {}",
            rec.ts, rec.subcommand, remote_disp, exit, bytes, fips
        );
    }
    println!();
    println!(
        "  {} entries shown  |  log: {}",
        records.len(),
        path.display()
    );
    Ok(())
}

fn format_bytes(b: u64) -> String {
    if b >= 1_073_741_824 {
        format!("{:.1}G", b as f64 / 1_073_741_824.0)
    } else if b >= 1_048_576 {
        format!("{:.1}M", b as f64 / 1_048_576.0)
    } else if b >= 1024 {
        format!("{:.1}K", b as f64 / 1024.0)
    } else {
        format!("{b}B")
    }
}

fn clear(yes: bool) -> Result<()> {
    let path = audit_log_path();
    if !path.exists() {
        println!("Audit log does not exist — nothing to clear.");
        return Ok(());
    }

    let meta = std::fs::metadata(&path)?;
    let size = meta.len();
    let line_count = std::fs::read_to_string(&path)
        .map(|s| s.lines().count())
        .unwrap_or(0);

    if !yes {
        eprintln!(
            "This will permanently delete {} entries ({} bytes) from:",
            line_count, size
        );
        eprintln!("  {}", path.display());
        eprint!("Type 'yes' to confirm: ");
        use std::io::BufRead;
        let stdin = std::io::stdin();
        let line = stdin
            .lock()
            .lines()
            .next()
            .and_then(|l| l.ok())
            .unwrap_or_default();
        if line.trim() != "yes" {
            eprintln!("Aborted — audit log unchanged.");
            return Ok(());
        }
    }

    // Atomic clear: write empty file via tmp then rename.
    let tmp = path.with_extension("jsonl.clearing");
    std::fs::write(&tmp, b"")?;
    std::fs::rename(&tmp, &path)?;

    println!(
        "Audit log cleared ({} entries, {} bytes removed).",
        line_count, size
    );
    Ok(())
}

// ── Internal audit infrastructure (used by main.rs) ──────────────────────────

/// A single audit log entry.
#[derive(Serialize)]
pub struct AuditEntry<'a> {
    /// ISO-8601 UTC timestamp (RFC 3339).
    pub ts: String,
    /// Seam subcommand name.
    pub subcommand: &'a str,
    /// Remote host (user@host or host), empty string if not applicable.
    pub remote: &'a str,
    /// Sanitised arguments (no secrets).
    pub args: Vec<&'a str>,
    /// Exit code — None while in-progress, Some after completion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Bytes transferred (cp, sync). None for commands that don't transfer data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_tx: Option<u64>,
    /// Whether FIPS mode was active for this invocation.
    pub fips_mode: bool,
    /// PID for correlating with server-side logs.
    pub pid: u32,
}

fn audit_log_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("seam")
        .join("audit.jsonl")
}

/// Append a single audit entry to the JSONL log file.
///
/// Failures are silently ignored — audit logging must never block or crash
/// the main operation. Administrators should check `seam doctor` for log
/// health.
pub fn log(entry: &AuditEntry<'_>) {
    match append_entry(entry) {
        Ok(()) => {}
        Err(e) => {
            // Non-fatal: warn to stderr only. Do not abort the operation.
            eprintln!("audit: warning: could not write audit log: {e}");
        }
    }
}

fn append_entry(entry: &AuditEntry<'_>) -> anyhow::Result<()> {
    let path = audit_log_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut line = serde_json::to_string(entry)?;
    line.push('\n');

    // O_APPEND ensures atomic writes ≤ PIPE_BUF on POSIX.
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;

    file.write_all(line.as_bytes())?;
    Ok(())
}

/// Return the current UTC time formatted as RFC 3339.
pub fn now_rfc3339() -> String {
    // Use std::time::SystemTime — no chrono dependency needed.
    let secs_since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Manual RFC 3339 formatting to avoid adding chrono as a dependency.
    // Converts Unix timestamp to YYYY-MM-DDTHH:MM:SSZ.
    let s = secs_since_epoch;
    let sec = s % 60;
    let min = (s / 60) % 60;
    let hour = (s / 3600) % 24;
    let days = s / 86400; // days since 1970-01-01

    // Gregorian calendar computation.
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, min, sec
    )
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    // "civil_from_days" — public domain.
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Return the audit log path for display purposes (e.g., in seam doctor).
pub fn audit_log_path_display() -> PathBuf {
    audit_log_path()
}

/// Check audit log health. Returns (exists, size_bytes, last_entry_preview).
pub fn audit_health() -> (bool, u64, Option<String>) {
    let path = audit_log_path();
    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(_) => return (false, 0, None),
    };
    let size = meta.len();
    if size == 0 {
        return (true, 0, None);
    }
    // Read the last line for a preview.
    let last = read_last_line(&path);
    (true, size, last)
}

fn read_last_line(path: &std::path::Path) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    let size = f.metadata().ok()?.len();
    if size == 0 {
        return None;
    }
    // Read up to 2048 bytes from the end to find the last newline.
    let seek_pos = size.saturating_sub(2048);
    f.seek(SeekFrom::Start(seek_pos)).ok()?;
    let mut tail = String::new();
    f.read_to_string(&mut tail).ok()?;
    // Find the last complete line.
    let trimmed = tail.trim_end_matches('\n');
    trimmed.rsplit('\n').next().map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_format_looks_right() {
        let ts = now_rfc3339();
        // Must be: YYYY-MM-DDTHH:MM:SSZ (20 chars)
        assert_eq!(ts.len(), 20, "unexpected timestamp length: {ts}");
        assert!(ts.ends_with('Z'));
        assert!(ts.contains('T'));
        // Year must start with "20"
        assert!(ts.starts_with("20"), "unexpected year: {ts}");
    }

    #[test]
    fn days_to_ymd_epoch() {
        // Unix epoch = 1970-01-01
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn days_to_ymd_known_date() {
        // 2024-03-15 = 19797 days since epoch (verified)
        let (y, m, d) = days_to_ymd(19797);
        assert_eq!((y, m, d), (2024, 3, 15));
    }
}
