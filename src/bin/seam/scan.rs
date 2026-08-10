use anyhow::Result;
use clap::Args;
use serde::Serialize;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

#[derive(Args)]
pub struct ScanArgs {
    /// Target host or CIDR range (e.g. 192.168.1.1 or 10.0.0.0/24)
    pub target: String,

    /// Port specification: comma-separated ports or ranges (e.g. 22,80,443,8080-8090)
    #[arg(long, default_value = "22,80,443,8080,8443")]
    pub ports: String,

    /// Connection timeout per port in milliseconds
    #[arg(long, default_value_t = 2000)]
    pub timeout: u64,

    /// Maximum concurrent probes
    #[arg(long, default_value_t = 100)]
    pub concurrency: usize,

    /// Route TCP probes through a Seam relay (host:port)
    #[arg(long)]
    pub via: Option<String>,

    /// Output results as JSONL (one JSON object per line)
    #[arg(long)]
    pub json: bool,
}

/// Hard cap on `targets.len() * ports.len()` for a single `seam scan` invocation.
///
/// The `Semaphore` in `run_scan` only throttles how many probes run
/// *concurrently* — it does nothing to stop `Vec::with_capacity(total_probes)`
/// and the `tokio::spawn` loop from trying to allocate/schedule millions of
/// tasks up front for something like a wide CIDR range combined with a large
/// port list. This is user-self-inflicted (not a remote-attacker vector) but
/// still a real "one CLI invocation exhausts memory" bug, so we fail fast
/// with a clear message instead.
const MAX_TOTAL_PROBES: usize = 500_000;

#[derive(Serialize)]
struct ScanResult {
    host: String,
    port: u16,
    open: bool,
    latency_ms: Option<u64>,
    banner: Option<String>,
}

pub fn parse_ports(spec: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            let start: u16 = start.trim().parse().unwrap_or(0);
            let end: u16 = end.trim().parse().unwrap_or(0);
            if start <= end {
                for p in start..=end {
                    ports.push(p);
                }
            }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

pub fn parse_targets(target: &str) -> Vec<IpAddr> {
    if let Some((base, prefix_len)) = target.split_once('/') {
        let prefix: u8 = prefix_len.parse().unwrap_or(32);
        if let Ok(base_ip) = base.parse::<IpAddr>() {
            return expand_cidr(base_ip, prefix);
        }
    }
    if let Ok(ip) = target.parse::<IpAddr>() {
        return vec![ip];
    }
    // Try DNS resolution
    use std::net::ToSocketAddrs;
    if let Ok(mut addrs) = (target, 0u16).to_socket_addrs()
        && let Some(addr) = addrs.next()
    {
        return vec![addr.ip()];
    }
    vec![]
}

/// Hard cap on how many addresses a single CIDR expansion will materialize.
///
/// Without this, `seam scan 10.0.0.0/8` expands to ~16.7M addresses with no
/// limit, allocating a giant `Vec<IpAddr>` for a single CLI invocation —
/// `run_scan`'s total-probe cap (`MAX_TOTAL_PROBES`) is expected to reject
/// scans that large anyway, but that check only runs *after* `expand_cidr`
/// has already returned, so this cap makes sure the oversized `Vec` is never
/// actually allocated in the first place.
const MAX_CIDR_HOSTS: u64 = 1_048_576; // 2^20 — a /12 IPv4 network

fn expand_cidr(base: IpAddr, prefix: u8) -> Vec<IpAddr> {
    match base {
        IpAddr::V4(v4) => {
            // Use u64 throughout: host_bits can be 32 (a /0 network), and
            // shifting a u32 left by 32 panics in debug builds / is not
            // well-defined for our purposes in release builds.
            let base_addr = u64::from(u32::from(v4));
            let prefix = u32::from(prefix.min(32));
            let host_bits = 32 - prefix;
            let mask: u64 = if host_bits >= 32 {
                0
            } else {
                (!0u64 << host_bits) & 0xFFFF_FFFF
            };
            let network = base_addr & mask;
            let count: u64 = 1u64 << host_bits;
            let (start, end) = if host_bits > 0 {
                (network + 1, network + count - 1)
            } else {
                (network, network)
            };
            let total_hosts = end - start + 1;
            if total_hosts > MAX_CIDR_HOSTS {
                eprintln!(
                    "warning: /{prefix} network has {total_hosts} hosts; \
                     truncating to the first {MAX_CIDR_HOSTS} addresses \
                     (use a narrower range to scan the rest)"
                );
            }
            (start..=end)
                .take(MAX_CIDR_HOSTS as usize)
                .map(|n| IpAddr::V4(std::net::Ipv4Addr::from(n as u32)))
                .collect()
        }
        IpAddr::V6(_) => vec![base],
    }
}

pub async fn probe_port(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
) -> (bool, Option<u64>, Option<String>) {
    let addr = std::net::SocketAddr::new(ip, port);
    let t0 = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let latency_ms = t0.elapsed().as_millis() as u64;
            let banner = grab_banner(&mut stream).await;
            (true, Some(latency_ms), banner)
        }
        _ => (false, None, None),
    }
}

async fn grab_banner(stream: &mut TcpStream) -> Option<String> {
    let mut buf = vec![0u8; 256];
    match tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let raw = &buf[..n];
            let banner = String::from_utf8_lossy(raw)
                .trim_end_matches(|c: char| c.is_whitespace() || c == '\0')
                .replace('\n', " ")
                .replace('\r', "")
                .chars()
                .filter(|c| c.is_ascii_graphic() || *c == ' ')
                .take(120)
                .collect::<String>();
            if banner.is_empty() {
                None
            } else {
                Some(banner)
            }
        }
        _ => None,
    }
}

pub async fn run_scan(args: ScanArgs) -> Result<()> {
    if args.via.is_some() {
        eprintln!("Note: --via relay routing not yet implemented; probing directly.");
    }

    let ports = parse_ports(&args.ports);
    let targets = parse_targets(&args.target);

    if targets.is_empty() {
        anyhow::bail!("could not resolve target: {}", args.target);
    }
    if ports.is_empty() {
        anyhow::bail!("no valid ports specified");
    }

    let total_probes = match targets.len().checked_mul(ports.len()) {
        Some(n) if n <= MAX_TOTAL_PROBES => n,
        _ => anyhow::bail!(
            "refusing to scan {} host(s) × {} port(s) — exceeds the {MAX_TOTAL_PROBES}-probe \
             safety cap for a single `seam scan` invocation; narrow the target range or port list",
            targets.len(),
            ports.len()
        ),
    };
    if !args.json {
        eprintln!(
            "Scanning {} host{}, {} port{} ({} total probes)",
            targets.len(),
            if targets.len() == 1 { "" } else { "s" },
            ports.len(),
            if ports.len() == 1 { "" } else { "s" },
            total_probes
        );
        eprintln!("{:<20} {:<8} {:<12} BANNER", "HOST", "PORT", "LATENCY");
        eprintln!("{}", "-".repeat(60));
    }

    let timeout = Duration::from_millis(args.timeout);
    let sem = Arc::new(Semaphore::new(args.concurrency));

    let t_start = Instant::now();
    let mut tasks = Vec::with_capacity(total_probes);

    for ip in &targets {
        for &port in &ports {
            let ip = *ip;
            let sem = Arc::clone(&sem);
            tasks.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let (open, latency_ms, banner) = probe_port(ip, port, timeout).await;
                (ip, port, open, latency_ms, banner)
            }));
        }
    }

    let mut open_count = 0usize;

    // Collect results as they complete
    for task in tasks {
        let (ip, port, open, latency_ms, banner) = task.await?;
        if open {
            open_count += 1;
            if args.json {
                let result = ScanResult {
                    host: ip.to_string(),
                    port,
                    open: true,
                    latency_ms,
                    banner: banner.clone(),
                };
                println!("{}", serde_json::to_string(&result)?);
            } else {
                let lat = latency_ms.map(|ms| format!("{}ms", ms)).unwrap_or_default();
                let ban = banner.as_deref().unwrap_or("");
                println!("{:<20} {:<8} {:<12} {}", ip, port, lat, ban);
            }
        }
    }

    let elapsed = t_start.elapsed().as_secs_f64();
    if args.json {
        // print final summary as a comment-style JSON object
        let summary = serde_json::json!({
            "summary": true,
            "hosts": targets.len(),
            "open_ports": open_count,
            "elapsed_s": format!("{:.1}", elapsed)
        });
        eprintln!("{}", summary);
    } else {
        eprintln!();
        eprintln!(
            "Scan complete: {} host{}, {} open port{} found in {:.1}s",
            targets.len(),
            if targets.len() == 1 { "" } else { "s" },
            open_count,
            if open_count == 1 { "" } else { "s" },
            elapsed
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for unbounded CIDR expansion: `seam scan 10.0.0.0/8` used to
    /// expand to ~16.7M addresses with no cap, allocating a giant `Vec<IpAddr>` for
    /// a single CLI invocation. `expand_cidr` must now stop materializing addresses
    /// once it hits `MAX_CIDR_HOSTS`, regardless of how large the requested network is.
    #[test]
    fn expand_cidr_caps_huge_ranges_instead_of_materializing_them() {
        let base: IpAddr = "10.0.0.0".parse().unwrap();
        let addrs = expand_cidr(base, 8); // /8 = ~16.7M hosts uncapped
        assert_eq!(addrs.len(), MAX_CIDR_HOSTS as usize);
    }

    /// A `/0` network means host_bits == 32; naively computing `1u32 << 32` (or
    /// `!0u32 << 32`) panics in debug builds. Regression test for that edge case —
    /// it must be capped like any other oversized range, not panic.
    #[test]
    fn expand_cidr_handles_prefix_zero_without_panicking() {
        let base: IpAddr = "0.0.0.0".parse().unwrap();
        let addrs = expand_cidr(base, 0);
        assert_eq!(addrs.len(), MAX_CIDR_HOSTS as usize);
    }

    /// Small, everyday CIDR ranges must still expand exactly as before — only
    /// oversized ranges get truncated. (Matches pre-existing behavior: the
    /// network address is excluded but the broadcast address is not, so a /24
    /// yields 255 addresses: .1 through .255.)
    #[test]
    fn expand_cidr_small_range_is_unaffected() {
        let base: IpAddr = "192.168.1.0".parse().unwrap();
        let addrs = expand_cidr(base, 24);
        assert_eq!(addrs.len(), 255);
        assert_eq!(addrs[0], "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(addrs[254], "192.168.1.255".parse::<IpAddr>().unwrap());
    }

    /// Regression test for the missing probe-count cap: a wide target list crossed
    /// with a large port list used to drive `Vec::with_capacity` and a `tokio::spawn`
    /// loop with no sanity check, however large `targets.len() * ports.len()` got.
    /// `run_scan` must reject (fast, before allocating/spawning anything) once that
    /// product would exceed `MAX_TOTAL_PROBES`.
    #[tokio::test]
    async fn run_scan_rejects_probe_count_over_the_safety_cap() {
        // MAX_CIDR_HOSTS (1,048,576) targets × 1 port already exceeds
        // MAX_TOTAL_PROBES (500,000) on its own — no network I/O required to hit
        // the cap, so this test runs fast and deterministically.
        let args = ScanArgs {
            target: "10.0.0.0/8".to_string(),
            ports: "22".to_string(),
            timeout: 100,
            concurrency: 10,
            via: None,
            json: true,
        };
        let err = run_scan(args)
            .await
            .expect_err("scan exceeding the total-probe cap must be rejected");
        assert!(
            err.to_string().contains("safety cap"),
            "unexpected error message: {err}"
        );
    }

    /// A scan comfortably within the cap must not be rejected by the cap check
    /// itself (it may still fail/short-circuit for other reasons, e.g. no open
    /// ports, but must not hit the probe-count guard).
    #[test]
    fn small_scan_is_within_probe_cap() {
        let targets = parse_targets("127.0.0.1");
        let ports = parse_ports("22,80,443");
        assert!(targets.len() * ports.len() <= MAX_TOTAL_PROBES);
    }
}
