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

fn expand_cidr(base: IpAddr, prefix: u8) -> Vec<IpAddr> {
    match base {
        IpAddr::V4(v4) => {
            let base_u32 = u32::from(v4);
            let prefix = prefix.min(32);
            let host_bits = 32 - prefix;
            let network = base_u32 & (!0u32 << host_bits);
            let count = 1u32 << host_bits;
            let (start, end) = if host_bits > 0 {
                (network + 1, network + count - 1)
            } else {
                (network, network)
            };
            (start..=end)
                .map(|n| IpAddr::V4(std::net::Ipv4Addr::from(n)))
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

    let total_probes = targets.len() * ports.len();
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
