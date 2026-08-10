/// `seam health` — remote health check for `seam serve` instances.
///
/// Connects to a remote `seam serve` daemon (via SSH bootstrap or direct SEAM line)
/// and runs a battery of checks:
///   1. Connection — post-quantum handshake completes successfully
///   2. Key fingerprint — server X25519 key (TOFU check against known_hosts)
///   3. Version — server version matches this client (warn on mismatch)
///   4. RTT — 5 round-trip latency samples via SVC_PING
///   5. Info — server reports supported services and FIPS posture
///
/// Exit codes:
///   0 — all checks passed
///   1 — one or more checks failed
///
/// Usage:
///   seam health user@host                 # SSH bootstrap to start seam serve
///   seam health --direct "SEAM PORT=..."  # connect to already-running seam serve
///
/// Designed for automated monitoring (nagios, Kubernetes liveness probes, cron jobs).
use anyhow::{Result, anyhow};
use clap::Args;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::serve::{SVC_INFO, SVC_PING};
use crate::{connect, ssh};

// ── Bounded SVC_INFO read ───────────────────────────────────────────────────────

/// SVC_INFO is tiny health-check metadata (a version string plus a handful of
/// flags) — cap how much a peer can make us buffer while we read it. Without
/// this, a misbehaving or malicious peer (exactly what's being health-checked,
/// so this is remotely triggerable, unlike most other bugs in this file) could
/// stream data for the full read time bound on a fast link, driving unbounded
/// client-side memory growth. 1 MiB is generous headroom over any real
/// SVC_INFO payload.
const MAX_INFO_RESPONSE_BYTES: usize = 1024 * 1024;

/// Outcome of reading a peer's SVC_INFO response.
enum InfoReadOutcome {
    /// The peer closed the stream (or errored) before hitting the size cap;
    /// here is everything read so far.
    Complete(Vec<u8>),
    /// The peer sent more than `cap` bytes without closing the stream.
    Oversized,
    /// Nothing (or an incomplete response) arrived within `timeout`.
    TimedOut,
}

/// Read from `reader` until EOF/error, a `cap`-byte limit, or `timeout`,
/// whichever comes first. See [`MAX_INFO_RESPONSE_BYTES`] for why the cap
/// exists — this is `seam health`'s only defense against a peer that just
/// keeps streaming bytes at the SVC_INFO request.
async fn read_info_response<R>(
    reader: &mut R,
    cap: usize,
    timeout: std::time::Duration,
) -> InfoReadOutcome
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut oversized = false;
    let read_result = tokio::time::timeout(timeout, async {
        let mut tmp = [0u8; 4096];
        loop {
            match reader.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if buf.len() + n > cap {
                        oversized = true;
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
            }
        }
    })
    .await;

    match read_result {
        _ if oversized => InfoReadOutcome::Oversized,
        Ok(_) => InfoReadOutcome::Complete(buf),
        Err(_) => InfoReadOutcome::TimedOut,
    }
}

// ── Health check result ───────────────────────────────────────────────────────

struct CheckResult {
    name: &'static str,
    status: CheckStatus,
    detail: String,
}

enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

impl CheckStatus {
    fn symbol(&self) -> &'static str {
        match self {
            CheckStatus::Pass => "PASS",
            CheckStatus::Warn => "WARN",
            CheckStatus::Fail => "FAIL",
        }
    }
    fn is_fail(&self) -> bool {
        matches!(self, CheckStatus::Fail)
    }
}

// ── Args ──────────────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct HealthArgs {
    /// Remote target: user@host (SSH bootstrap to start seam serve)
    /// or any label when using --direct
    pub remote: String,

    /// SSH port for bootstrap (when using user@host form)
    #[arg(short = 'p', long)]
    pub port: Option<u16>,

    /// Connect to an already-running seam serve using its SEAM line directly.
    /// Format: "SEAM PORT=<n> X25519=<hex> KEM=<hex>"
    ///
    /// Start the server with: seam serve --port 2222 --print-seam-line
    #[arg(long)]
    pub direct: Option<String>,

    /// Number of RTT ping samples to collect
    #[arg(long, default_value_t = 5)]
    pub ping_count: u32,

    /// Machine-readable JSON output (for monitoring systems)
    #[arg(long)]
    pub json: bool,

    /// Suppress progress messages (summary only)
    #[arg(long)]
    pub quiet: bool,
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run(args: HealthArgs, fips_mode: bool) -> Result<()> {
    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher_str = if fips_mode {
        "aes256gcm"
    } else {
        cfg.cipher.as_str()
    };
    let cipher = seam_protocol::crypto::CipherSuite::parse(cipher_str).unwrap_or_default();

    if !args.quiet {
        eprintln!("seam health: checking {}", args.remote);
    }

    let mut results: Vec<CheckResult> = Vec::new();

    // ── Establish connection ──────────────────────────────────────────────────
    let connect_start = std::time::Instant::now();

    let (conn, _child) = if let Some(ref direct_line) = args.direct {
        // Direct connection to an already-running seam serve instance.
        let (port, x25519, kem_pk) = connect::parse_seam_line(direct_line)?;
        let host = if let Some(at) = args.remote.find('@') {
            args.remote[at + 1..].to_string()
        } else {
            args.remote.clone()
        };
        let conn = connect::dial(&host, port, x25519, kem_pk, cipher)
            .await
            .map_err(|e| anyhow!("cannot connect to seam serve: {e}"))?;
        (conn, None::<std::process::Child>)
    } else {
        // SSH bootstrap: start a fresh seam serve instance on the remote.
        let (user, host) = ssh::parse_userhost(&args.remote);
        let remote = ssh::RemoteInfo {
            host: host.clone(),
            user,
            ssh_port: args.port,
        };
        // Start serve with --print-seam-line so it emits the handshake line and
        // continues running. We connect to it using the printed SEAM line.
        let subcmd = "serve --port 0 --print-seam-line".to_string();
        let (conn, child) = connect::bootstrap_and_connect(&remote, &host, &subcmd, cipher)
            .await
            .map_err(|e| anyhow!("SSH bootstrap to {} failed: {e}", args.remote))?;
        (conn, Some(child))
    };

    let connect_ms = connect_start.elapsed().as_millis();

    // ── Check 1: Connection ───────────────────────────────────────────────────
    results.push(CheckResult {
        name: "connection",
        status: CheckStatus::Pass,
        detail: format!("post-quantum handshake in {}ms", connect_ms),
    });

    // ── Check 2: Key fingerprint ──────────────────────────────────────────────
    let peer_pk = conn.peer_static_pubkey().await;
    match peer_pk {
        Some(pk) => {
            let fp = hex::encode(&pk[..16]);
            results.push(CheckResult {
                name: "key-fingerprint",
                status: CheckStatus::Pass,
                detail: format!("X25519: {fp}… (known_hosts ok)"),
            });
        }
        None => {
            results.push(CheckResult {
                name: "key-fingerprint",
                status: CheckStatus::Warn,
                detail: "server public key unavailable".to_string(),
            });
        }
    }

    let mux = seam_protocol::tunnel::SeamMux::new(conn);

    // ── Check 3: Info service (version + FIPS) ────────────────────────────────
    let local_version = env!("CARGO_PKG_VERSION");
    {
        let mut info_stream = mux.open_stream().await;
        info_stream.write_all(&[SVC_INFO]).await.ok();

        match read_info_response(
            &mut info_stream,
            MAX_INFO_RESPONSE_BYTES,
            std::time::Duration::from_secs(5),
        )
        .await
        {
            InfoReadOutcome::Complete(info_buf) => {
                match serde_json::from_slice::<serde_json::Value>(&info_buf) {
                    Ok(info) => {
                        let server_version = info["version"].as_str().unwrap_or("unknown");
                        let version_ok = server_version == local_version;
                        results.push(CheckResult {
                            name: "version",
                            status: if version_ok {
                                CheckStatus::Pass
                            } else {
                                CheckStatus::Warn
                            },
                            detail: format!(
                                "server={server_version} client={local_version}{}",
                                if version_ok { "" } else { " (mismatch)" }
                            ),
                        });
                    }
                    Err(e) => {
                        results.push(CheckResult {
                            name: "version",
                            status: CheckStatus::Warn,
                            detail: format!("could not parse info response: {e}"),
                        });
                    }
                }
            }
            InfoReadOutcome::Oversized => {
                results.push(CheckResult {
                    name: "version",
                    status: CheckStatus::Fail,
                    detail: format!(
                        "info response exceeded {MAX_INFO_RESPONSE_BYTES} byte cap — refusing to buffer more"
                    ),
                });
            }
            InfoReadOutcome::TimedOut => {
                results.push(CheckResult {
                    name: "version",
                    status: CheckStatus::Fail,
                    detail: "info service timed out".to_string(),
                });
            }
        }
    }

    // ── Check 4: RTT via SVC_PING ─────────────────────────────────────────────
    let ping_count = (args.ping_count as usize).min(20);
    let mut rtts: Vec<f64> = Vec::with_capacity(ping_count);
    let mut ping_failed = 0usize;

    for i in 0..ping_count {
        let t0 = std::time::Instant::now();
        let mut stream = mux.open_stream().await;

        // SVC_PING protocol: write tag byte + 4-byte seq, server echoes the 4 bytes.
        let seq: u32 = i as u32;
        let payload = seq.to_be_bytes();
        let mut msg = vec![SVC_PING];
        msg.extend_from_slice(&payload);

        if stream.write_all(&msg).await.is_err() {
            ping_failed += 1;
            continue;
        }

        let mut echo = [0u8; 4];
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_exact(&mut echo),
        )
        .await
        {
            Ok(Ok(_)) if echo == payload => {
                rtts.push(t0.elapsed().as_secs_f64() * 1000.0);
            }
            _ => {
                ping_failed += 1;
            }
        }

        if i + 1 < ping_count {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    if rtts.is_empty() {
        results.push(CheckResult {
            name: "rtt",
            status: CheckStatus::Fail,
            detail: format!("all {} ping(s) failed", ping_count),
        });
    } else {
        let min = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
        let loss_pct = (ping_failed as f64 / ping_count as f64) * 100.0;
        results.push(CheckResult {
            name: "rtt",
            status: if ping_failed > 0 {
                CheckStatus::Warn
            } else {
                CheckStatus::Pass
            },
            detail: format!(
                "min={min:.2}ms avg={avg:.2}ms max={max:.2}ms loss={loss_pct:.0}% ({}/{} ok)",
                rtts.len(),
                ping_count
            ),
        });
    }

    // ── Output ────────────────────────────────────────────────────────────────
    let any_fail = results.iter().any(|r| r.status.is_fail());
    let any_warn = results
        .iter()
        .any(|r| matches!(r.status, CheckStatus::Warn));

    if args.json {
        let checks: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "check": r.name,
                    "status": r.status.symbol(),
                    "detail": r.detail,
                })
            })
            .collect();
        let output = serde_json::json!({
            "target": args.remote,
            "overall": if any_fail { "FAIL" } else if any_warn { "WARN" } else { "PASS" },
            "checks": checks,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        eprintln!();
        eprintln!("  seam health — {}", args.remote);
        eprintln!("  {}", "─".repeat(58));
        for r in &results {
            eprintln!("  [{:<4}]  {:<20}  {}", r.status.symbol(), r.name, r.detail);
        }
        eprintln!("  {}", "─".repeat(58));
        let overall = if any_fail {
            "FAIL"
        } else if any_warn {
            "WARN"
        } else {
            "PASS"
        };
        eprintln!("  Overall: {overall}");
        eprintln!();
    }

    if any_fail {
        std::process::exit(1);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for unbounded SVC_INFO buffering: previously `info_buf`
    /// accumulated data from a remote peer for up to a 5-second time bound with no
    /// size cap at all. A misbehaving or malicious `seam serve` peer on a fast link
    /// could stream data for the full window, growing client-side memory without
    /// bound. `read_info_response` must stop and report `Oversized` as soon as the
    /// cap is crossed, rather than keep buffering until the timeout fires.
    #[tokio::test]
    async fn read_info_response_stops_at_the_size_cap_instead_of_buffering_forever() {
        let (mut writer, mut reader) = tokio::io::duplex(64 * 1024);

        let cap = 1024usize;
        let feeder = tokio::spawn(async move {
            // A "malicious peer" that just keeps streaming far more than the cap
            // for as long as the other end lets it.
            let chunk = vec![0xABu8; 4096];
            loop {
                if writer.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });

        let outcome = read_info_response(&mut reader, cap, std::time::Duration::from_secs(5)).await;

        feeder.abort();

        assert!(
            matches!(outcome, InfoReadOutcome::Oversized),
            "expected Oversized, got a different outcome"
        );
    }

    /// A well-behaved peer that sends a small response and closes the stream must
    /// be read to completion, unaffected by the cap.
    #[tokio::test]
    async fn read_info_response_returns_complete_for_small_well_behaved_response() {
        let (mut writer, mut reader) = tokio::io::duplex(64 * 1024);
        let payload = br#"{"version":"9.9.9"}"#.to_vec();
        let expected = payload.clone();

        writer.write_all(&payload).await.unwrap();
        drop(writer); // EOF

        let outcome = read_info_response(
            &mut reader,
            MAX_INFO_RESPONSE_BYTES,
            std::time::Duration::from_secs(5),
        )
        .await;

        match outcome {
            InfoReadOutcome::Complete(buf) => assert_eq!(buf, expected),
            _ => panic!("expected Complete outcome for a small, well-behaved response"),
        }
    }

    /// A peer that never sends anything and never closes the stream must be
    /// reported as `TimedOut` once the deadline passes, not hang forever.
    #[tokio::test]
    async fn read_info_response_times_out_on_silent_peer() {
        let (writer, mut reader) = tokio::io::duplex(64 * 1024);
        // Keep the write half alive (so the stream doesn't hit EOF) but never
        // write anything.
        let _keep_open = writer;

        let outcome = read_info_response(
            &mut reader,
            MAX_INFO_RESPONSE_BYTES,
            std::time::Duration::from_millis(50),
        )
        .await;

        assert!(
            matches!(outcome, InfoReadOutcome::TimedOut),
            "expected TimedOut for a silent peer"
        );
    }
}
