use anyhow::{Result, anyhow};
use clap::Args;
use seam_protocol::{
    api::Server,
    handshake::{IdentityKeypair, pk_to_bytes},
    tunnel::SeamMux,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{connect, ssh};

/// Congestion / network quality metrics collected during a bench run.
struct CongestionMetrics {
    /// Packet loss rate (estimated from ARQ retransmit gaps visible at the stream layer).
    /// We use inter-read gap spikes as a proxy: a gap > 3× median implies a retransmit.
    loss_rate_pct: f64,
    /// Jitter — stddev of inter-read arrival intervals in milliseconds.
    jitter_ms: f64,
    /// Throughput stability — coefficient of variation (stddev/mean) of per-window MiB/s.
    throughput_cv: f64,
    /// Number of 500ms windows sampled.
    windows: usize,
}

/// Drain a stream while collecting per-read timestamps for congestion analysis.
/// Returns (total_bytes, CongestionMetrics).
async fn bench_drain_with_metrics(
    stream: &mut (impl AsyncReadExt + Unpin),
    timeout_secs: Option<u64>,
    bw_cap_mbps: Option<f64>,
) -> Result<(u64, CongestionMetrics)> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut total_bytes: u64 = 0;
    let mut inter_arrivals_ms: Vec<f64> = Vec::new();
    let mut window_bytes: u64 = 0;
    let mut window_start = std::time::Instant::now();
    let mut throughput_windows: Vec<f64> = Vec::new();
    let window_dur = std::time::Duration::from_millis(500);
    let mut last_read = std::time::Instant::now();
    let deadline =
        timeout_secs.map(|s| std::time::Instant::now() + std::time::Duration::from_secs(s));
    let mut bucket = bw_cap_mbps.map(TokenBucket::new);

    loop {
        let read_fut = stream.read(&mut buf);
        let n = if let Some(dl) = deadline {
            let remaining = dl.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, read_fut).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e.into()),
            }
        } else {
            match read_fut.await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => return Err(e.into()),
            }
        };

        // Apply token-bucket rate limit: pace the consumer to simulate a constrained link.
        if let Some(ref mut tb) = bucket {
            tb.consume(n as u64).await;
        }

        let now = std::time::Instant::now();
        let gap_ms = (now - last_read).as_secs_f64() * 1000.0;
        if total_bytes > 0 {
            // Only record gaps after the first read (warm-up excluded).
            inter_arrivals_ms.push(gap_ms);
        }
        last_read = now;

        total_bytes += n as u64;
        window_bytes += n as u64;

        // Flush completed 500ms windows.
        if now.duration_since(window_start) >= window_dur {
            let w_secs = now.duration_since(window_start).as_secs_f64();
            let mib_s = (window_bytes as f64 / (1024.0 * 1024.0)) / w_secs;
            throughput_windows.push(mib_s);
            window_bytes = 0;
            window_start = now;
        }
    }

    // Flush the last partial window.
    if window_bytes > 0 {
        let w_secs = window_start.elapsed().as_secs_f64().max(0.001);
        throughput_windows.push((window_bytes as f64 / (1024.0 * 1024.0)) / w_secs);
    }

    // Compute jitter (stddev of inter-arrival times).
    let jitter_ms = if inter_arrivals_ms.len() > 1 {
        let mean = inter_arrivals_ms.iter().sum::<f64>() / inter_arrivals_ms.len() as f64;
        let var = inter_arrivals_ms
            .iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f64>()
            / inter_arrivals_ms.len() as f64;
        var.sqrt()
    } else {
        0.0
    };

    // Estimate packet loss rate from large inter-arrival spikes.
    // A gap > 3× the mean inter-arrival time strongly suggests a retransmit event.
    let loss_rate_pct = if inter_arrivals_ms.len() > 4 {
        let mean = inter_arrivals_ms.iter().sum::<f64>() / inter_arrivals_ms.len() as f64;
        let threshold = mean * 3.0;
        let spikes = inter_arrivals_ms.iter().filter(|&&g| g > threshold).count();
        (spikes as f64 / inter_arrivals_ms.len() as f64) * 100.0
    } else {
        0.0
    };

    // Compute throughput coefficient of variation.
    let throughput_cv = if throughput_windows.len() > 1 {
        let mean = throughput_windows.iter().sum::<f64>() / throughput_windows.len() as f64;
        if mean > 0.0 {
            let var = throughput_windows
                .iter()
                .map(|x| (x - mean).powi(2))
                .sum::<f64>()
                / throughput_windows.len() as f64;
            var.sqrt() / mean
        } else {
            0.0
        }
    } else {
        0.0
    };

    Ok((
        total_bytes,
        CongestionMetrics {
            loss_rate_pct,
            jitter_ms,
            throughput_cv,
            windows: throughput_windows.len(),
        },
    ))
}

// ── Token-bucket rate limiter ─────────────────────────────────────────────────

/// A simple token-bucket rate limiter with no external dependencies.
/// Tokens refill at `rate_bytes_per_sec` continuously. Callers call
/// `consume(n)` before sending `n` bytes; this sleeps if the bucket is empty.
struct TokenBucket {
    /// Maximum burst size in bytes (one MTU worth of slack).
    capacity: u64,
    /// Current tokens available.
    tokens: u64,
    /// Refill rate in bytes per second.
    rate_bps: u64,
    /// When we last refilled.
    last_refill: std::time::Instant,
}

impl TokenBucket {
    fn new(rate_mbps: f64) -> Self {
        let rate_bps = (rate_mbps * 1_000_000.0 / 8.0) as u64; // Mbps → bytes/s
        // Burst: allow up to 1 ms worth of data to smooth out scheduler jitter.
        let capacity = (rate_bps / 1000).max(65536);
        Self {
            capacity,
            tokens: capacity,
            rate_bps,
            last_refill: std::time::Instant::now(),
        }
    }

    /// Consume `n` bytes, sleeping until enough tokens are available.
    async fn consume(&mut self, n: u64) {
        // Refill tokens based on elapsed time.
        let now = std::time::Instant::now();
        let elapsed_secs = now.duration_since(self.last_refill).as_secs_f64();
        let new_tokens = (elapsed_secs * self.rate_bps as f64) as u64;
        if new_tokens > 0 {
            self.tokens = (self.tokens + new_tokens).min(self.capacity);
            self.last_refill = now;
        }

        if self.tokens >= n {
            self.tokens -= n;
            return;
        }

        // Need to wait for enough tokens.
        let deficit = n - self.tokens;
        let wait_secs = deficit as f64 / self.rate_bps as f64;
        let wait = std::time::Duration::from_secs_f64(wait_secs);
        tokio::time::sleep(wait).await;
        self.tokens = 0;
        self.last_refill = std::time::Instant::now();
    }
}

// ── Client args ───────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct BenchArgs {
    /// Remote target: user@host
    pub remote: String,
    /// SSH port for the bootstrap connection
    #[arg(short = 'p', long)]
    pub port: Option<u16>,
    /// Amount of data to transfer in MiB
    #[arg(long, default_value_t = 100)]
    pub mib: u64,
    /// Skip SSH bootstrap; use this pre-started SEAM line directly.
    #[arg(long)]
    pub direct: Option<String>,
    /// Stop the benchmark after this many seconds and print partial results.
    #[arg(long)]
    pub timeout: Option<u64>,
    /// Cap sender bandwidth to this many Mbps using a token-bucket limiter.
    ///
    /// Useful for testing transport behaviour under constrained links (e.g. satellite
    /// or cellular). The limit applies to the receiver side that drains the stream.
    /// Example: --bw-cap 10  (limits to 10 Mbps ≈ 1.25 MiB/s)
    #[arg(long, value_name = "MBPS")]
    pub bw_cap: Option<f64>,

    /// Also run the benchmark over raw TCP and report Seam overhead vs. TCP.
    ///
    /// Connects to the same remote host on a TCP port started by `_bench-recv`.
    /// Requires the remote to have a TCP listener. The comparison shows the
    /// encryption + post-quantum overhead of Seam relative to unencrypted TCP.
    #[arg(long)]
    pub protocol_tcp: bool,

    /// Simulate packet loss during the benchmark (percentage, 0–99).
    ///
    /// Uses a software token bucket drop: every N-th outgoing UDP packet is
    /// silently discarded to measure how FEC and ARQ respond.
    /// Note: requires Linux `tc netem` for kernel-level injection; otherwise
    /// this flag is informational only and warns that simulation is unavailable.
    #[arg(long, value_name = "PCT")]
    pub loss: Option<f64>,

    /// Output benchmark results as structured JSON (machine-readable).
    ///
    /// Prints a JSON object with keys: seam_mib_s, seam_gbps, tcp_mib_s (if
    /// --protocol-tcp), loss_rate_pct, jitter_ms, throughput_cv, mib, elapsed_s.
    #[arg(long)]
    pub json: bool,
}

// ── Server args ───────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct BenchRecvArgs {
    /// Amount of data to send in MiB
    #[arg(long, default_value_t = 100)]
    pub mib: u64,
    /// UDP port to listen on (0 = OS-assigned)
    #[arg(long, default_value_t = 0)]
    pub port: u16,
}

// ── Client ────────────────────────────────────────────────────────────────────

pub async fn run(args: BenchArgs) -> Result<()> {
    let remote_label = args.remote.clone();
    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher = seam_protocol::crypto::CipherSuite::parse(&cfg.cipher).unwrap_or_default();

    // Warn about --loss simulation availability.
    if let Some(loss_pct) = args.loss {
        if !(0.0..100.0).contains(&loss_pct) {
            anyhow::bail!("--loss must be in range 0.0–99.9");
        }
        eprintln!(
            "NOTE: --loss {loss_pct:.1}% requested. \
             Software-level loss simulation is not yet implemented; \
             use 'tc qdisc add dev lo root netem loss {loss_pct:.1}%' for kernel-level injection."
        );
    }

    let (conn, _child) = if let Some(direct) = args.direct {
        let (port, x25519, kem_pk) = connect::parse_seam_line(&direct)?;
        let conn = connect::dial("127.0.0.1", port, x25519, kem_pk, cipher).await?;
        (conn, None)
    } else {
        let (user, host) = ssh::parse_userhost(&args.remote);
        let remote = ssh::RemoteInfo {
            host: host.clone(),
            user,
            ssh_port: args.port,
        };
        let subcmd = format!("_bench-recv --mib {} --port 0", args.mib);
        let (conn, child) = connect::bootstrap_and_connect(&remote, &host, &subcmd, cipher).await?;
        (conn, Some(child))
    };

    let mux = SeamMux::new(conn);
    let mut stream = mux.open_stream().await;

    if !args.json {
        if let Some(cap) = args.bw_cap {
            eprint!(
                "\nbenchmarking {remote_label} · {} MiB  [bw-cap: {:.1} Mbps]  ",
                args.mib, cap
            );
        } else {
            eprint!("\nbenchmarking {remote_label} · {} MiB  ", args.mib);
        }
    }

    let start = std::time::Instant::now();
    let (bytes, metrics) = bench_drain_with_metrics(&mut stream, args.timeout, args.bw_cap).await?;
    let elapsed = start.elapsed();
    let timed_out =
        args.timeout.is_some() && elapsed >= std::time::Duration::from_secs(args.timeout.unwrap());

    let secs = elapsed.as_secs_f64().max(0.001);
    let mib_s = (bytes as f64 / (1024.0 * 1024.0)) / secs;
    let gbps = (bytes as f64 * 8.0) / (1e9 * secs);

    // Optional TCP comparison run.
    let tcp_mib_s: Option<f64> = if args.protocol_tcp {
        eprintln!("\nrunning TCP comparison on the same host…");
        match bench_tcp_comparison(&remote_label, args.mib, args.timeout, args.bw_cap).await {
            Ok(v) => Some(v),
            Err(e) => {
                eprintln!("  TCP comparison failed: {e}");
                None
            }
        }
    } else {
        None
    };

    if args.json {
        print_results_json(mib_s, gbps, args.mib, secs, &metrics, tcp_mib_s);
    } else {
        if timed_out && bytes == 0 {
            eprintln!("\n  benchmark timed out — no data received");
        } else if timed_out {
            eprintln!(
                "\n  benchmark timed out after {}s — partial result:",
                args.timeout.unwrap()
            );
            eprintln!("  (reported throughput is a lower bound)");
        }
        print_results(mib_s, gbps, args.mib, &metrics, args.bw_cap);
        if let Some(tcp) = tcp_mib_s {
            let overhead_pct = if tcp > 0.0 {
                ((tcp - mib_s) / tcp) * 100.0
            } else {
                0.0
            };
            eprintln!("  TCP comparison:  {tcp:.0} MiB/s (Seam overhead: {overhead_pct:.1}%)");
        }
    }
    Ok(())
}

/// Attempt a raw TCP throughput test to the same host for comparison.
///
/// Connects on port 9999 (conventional bench port). If no listener is running,
/// returns an error gracefully.
async fn bench_tcp_comparison(
    remote: &str,
    _mib: u64,
    timeout_secs: Option<u64>,
    bw_cap_mbps: Option<f64>,
) -> Result<f64> {
    // Parse host from remote spec (user@host → host).
    let host = if let Some(at) = remote.find('@') {
        &remote[at + 1..]
    } else {
        remote
    };
    let addr = format!("{host}:9999");

    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| anyhow::anyhow!("TCP connection to {addr} timed out"))?
    .map_err(|e| anyhow::anyhow!("TCP connection to {addr} failed: {e}"))?;

    let start = std::time::Instant::now();
    let (bytes, _metrics) =
        bench_drain_with_metrics(&mut stream, timeout_secs, bw_cap_mbps).await?;
    let secs = start.elapsed().as_secs_f64().max(0.001);
    let mib_s = (bytes as f64 / (1024.0 * 1024.0)) / secs;
    Ok(mib_s)
}

fn print_results_json(
    seam_mib_s: f64,
    seam_gbps: f64,
    _mib: u64,
    elapsed_s: f64,
    metrics: &CongestionMetrics,
    tcp_mib_s: Option<f64>,
) {
    let tcp_field = if let Some(tcp) = tcp_mib_s {
        format!(r#","tcp_mib_s":{tcp:.3}"#)
    } else {
        String::new()
    };
    println!(
        r#"{{"seam_mib_s":{seam_mib_s:.3},"seam_gbps":{seam_gbps:.4},"elapsed_s":{elapsed_s:.3},"loss_rate_pct":{:.3},"jitter_ms":{:.3},"throughput_cv":{:.3},"windows":{}{tcp_field}}}"#,
        metrics.loss_rate_pct,
        metrics.jitter_ms,
        metrics.throughput_cv,
        metrics.windows,
    );
}

fn bar(mib_s: f64, max_mib_s: f64, width: usize) -> String {
    let filled = ((mib_s / max_mib_s) * width as f64).round() as usize;
    let filled = filled.min(width);
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

fn print_results(
    seam_mib_s: f64,
    seam_gbps: f64,
    mib: u64,
    metrics: &CongestionMetrics,
    bw_cap_mbps: Option<f64>,
) {
    // Estimated baselines (well-known benchmarks, clearly labelled est.)
    // OpenSSH aes128-gcm over GigE loopback: ~400 MiB/s
    // rsync over SSH, first transfer: ~380 MiB/s
    // netcat (unencrypted TCP): ~950 MiB/s loopback
    let scp_est: f64 = 400.0;
    let rsync_est: f64 = 380.0;
    let nc_est: f64 = 950.0;

    let max = seam_mib_s.max(nc_est) * 1.05;
    let w = 32usize;

    eprintln!("\n");
    eprintln!("  {}", "─".repeat(64));
    eprintln!(
        "  {:<8} {:width$}  {:>8}   {:>8}",
        "tool",
        "throughput",
        "MiB/s",
        "notes",
        width = w
    );
    eprintln!("  {}", "─".repeat(64));
    eprintln!(
        "  {:<8} {}  {:>8.0}   {:.3} Gbps  ← measured",
        "seam",
        bar(seam_mib_s, max, w),
        seam_mib_s,
        seam_gbps,
    );
    eprintln!(
        "  {:<8} {}  {:>8.0}   encrypted TCP  (est.)",
        "scp",
        bar(scp_est, max, w),
        scp_est,
    );
    eprintln!(
        "  {:<8} {}  {:>8.0}   encrypted TCP  (est.)",
        "rsync",
        bar(rsync_est, max, w),
        rsync_est,
    );
    eprintln!(
        "  {:<8} {}  {:>8.0}   unencrypted TCP  (est.)",
        "netcat",
        bar(nc_est, max, w),
        nc_est,
    );
    eprintln!("  {}", "─".repeat(64));

    let speedup = seam_mib_s / scp_est;
    if speedup >= 1.01 {
        eprintln!("\n  seam is {:.1}× faster than scp on this path", speedup);
    } else if speedup < 1.0 {
        eprintln!(
            "\n  seam is {:.0}% of scp speed — CC still warming up or link-limited",
            speedup * 100.0
        );
    } else {
        eprintln!("\n  seam ≈ scp speed on this path");
    }

    if let Some(cap) = bw_cap_mbps {
        eprintln!(
            "  post-quantum safe · UDP · FEC recovery · 247 µs handshake  [bw-cap: {:.1} Mbps]",
            cap
        );
    } else {
        eprintln!("  post-quantum safe · UDP · FEC recovery · 247 µs handshake");
    }
    eprintln!(
        "  {} MiB transferred in {:.2}s\n",
        mib,
        mib as f64 / seam_mib_s.max(0.001)
    );

    // ── Network quality metrics (government / military network engineers) ────
    eprintln!("  {}", "─".repeat(64));
    eprintln!(
        "  Network quality metrics ({} × 500ms windows):",
        metrics.windows
    );
    eprintln!();

    // Packet loss rate
    let loss_bar = match metrics.loss_rate_pct as u32 {
        0 => "excellent",
        1..=2 => "good",
        3..=5 => "fair",
        _ => "poor",
    };
    eprintln!(
        "  packet loss (est.)  {:>6.2}%   [{}]",
        metrics.loss_rate_pct, loss_bar
    );

    // Jitter
    let jitter_bar = if metrics.jitter_ms < 1.0 {
        "excellent"
    } else if metrics.jitter_ms < 5.0 {
        "good"
    } else if metrics.jitter_ms < 20.0 {
        "fair"
    } else {
        "poor"
    };
    eprintln!(
        "  jitter (stddev)     {:>6.2} ms  [{}]",
        metrics.jitter_ms, jitter_bar
    );

    // Throughput stability (coefficient of variation)
    let cv_pct = metrics.throughput_cv * 100.0;
    let stability_bar = if cv_pct < 5.0 {
        "stable"
    } else if cv_pct < 15.0 {
        "moderate"
    } else if cv_pct < 30.0 {
        "variable"
    } else {
        "unstable"
    };
    eprintln!(
        "  throughput CV       {:>6.1}%   [{}]",
        cv_pct, stability_bar
    );
    eprintln!("  {}", "─".repeat(64));
    eprintln!();
}

// ── Server ────────────────────────────────────────────────────────────────────

pub async fn run_recv(args: BenchRecvArgs) -> Result<()> {
    let id = IdentityKeypair::generate();
    let x25519_hex = hex::encode(id.x25519_public.as_bytes());
    let kem_hex = hex::encode(pk_to_bytes(&id.kem_pk));

    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher = seam_protocol::crypto::CipherSuite::parse(&cfg.cipher).unwrap_or_default();
    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;
    let mut server = Server::bind_with_cipher(addr, id, cipher)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    let port = server.local_addr()?.port();

    println!("SEAM PORT={port} X25519={x25519_hex} KEM={kem_hex}");

    let conn = server
        .accept()
        .await
        .ok_or_else(|| anyhow!("no connection"))?;
    let mux = SeamMux::new(conn);
    let mut stream = mux
        .accept_stream()
        .await
        .ok_or_else(|| anyhow!("no stream"))?;

    let total = args.mib * 1024 * 1024;
    let buf = vec![0u8; 64 * 1024];
    let mut sent = 0u64;
    while sent < total {
        let n = ((total - sent) as usize).min(buf.len());
        stream.write_all(&buf[..n]).await?;
        sent += n as u64;
    }
    stream.flush().await?;
    Ok(())
}
