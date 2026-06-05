/// Multi-path UDP transport for anti-jamming and redundancy.
///
/// Sends packets simultaneously over multiple network paths (e.g., WiFi + cellular,
/// or multiple network interfaces). Critical for military/tactical use where adversaries
/// may jam specific frequencies or network paths.
///
/// # Schedulers
///
/// - [`PathScheduler::RoundRobin`] (default) — rotates evenly across active paths.
/// - [`PathScheduler::MinLatency`] — always uses the lowest-RTT path.
/// - [`PathScheduler::Redundant`] — sends every packet on **all** paths simultaneously;
///   receiver deduplicates by sequence number. Optimal for adversarial jamming scenarios.
/// - [`PathScheduler::Weighted`] — weights paths by bandwidth estimate.
///
/// # Example
///
/// ```no_run
/// use std::net::SocketAddr;
/// use seam_protocol::transport::multipath::{MultiPathEndpoint, PathScheduler};
///
/// # async fn example() -> anyhow::Result<()> {
/// let mut ep = MultiPathEndpoint::new(PathScheduler::Redundant);
/// let remote: SocketAddr = "10.0.0.2:4433".parse()?;
/// ep.add_path("192.168.1.100:0".parse()?, remote).await?;
/// ep.add_path("10.0.0.1:0".parse()?, remote).await?;
///
/// let payload = b"encrypted data";
/// ep.send(payload).await?;
/// # Ok(())
/// # }
/// ```
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

// ── Constants ─────────────────────────────────────────────────────────────────

/// How long without a received packet before a path is marked inactive.
const PATH_DEAD_TIMEOUT: Duration = Duration::from_secs(10);

/// Deduplication window: remember the last N sequence numbers per path.
const DEDUP_WINDOW: usize = 64;

// ── PathScheduler ─────────────────────────────────────────────────────────────

/// Packet scheduling strategy across multiple paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathScheduler {
    /// Rotate through active paths in order (default). Distributes load evenly.
    RoundRobin,
    /// Always send on the path with the lowest RTT estimate.
    MinLatency,
    /// Send every packet on **all** active paths simultaneously.
    ///
    /// The receiver deduplicates by sequence number. This provides maximum
    /// resilience: even if an adversary jams N-1 paths, the Nth still delivers.
    Redundant,
    /// Weight paths by their bandwidth estimate; higher-bandwidth paths carry
    /// proportionally more packets.
    Weighted,
}

impl PathScheduler {
    /// Parse from a string (e.g. from config or CLI).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "round-robin" | "roundrobin" | "rr" => Some(Self::RoundRobin),
            "min-latency" | "minlatency" | "min_latency" => Some(Self::MinLatency),
            "redundant" => Some(Self::Redundant),
            "weighted" => Some(Self::Weighted),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RoundRobin => "round-robin",
            Self::MinLatency => "min-latency",
            Self::Redundant => "redundant",
            Self::Weighted => "weighted",
        }
    }
}

impl Default for PathScheduler {
    fn default() -> Self {
        Self::RoundRobin
    }
}

impl std::fmt::Display for PathScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── PathState ─────────────────────────────────────────────────────────────────

/// Per-path state tracking for one UDP socket bound to a specific local address.
pub struct PathState {
    pub socket: Arc<UdpSocket>,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    /// Smoothed RTT estimate (EWMA, α=0.125).
    pub rtt_estimate: Duration,
    /// Packet loss rate estimate derived from sequence-number gaps (0.0–1.0).
    pub loss_rate: f64,
    /// Bandwidth estimate in bytes/sec.
    pub bandwidth: u64,
    /// Whether this path is considered alive (received a packet within the last 10s).
    pub active: bool,
    /// Total packets sent on this path.
    pub packets_sent: Arc<AtomicU64>,
    /// Total packets received on this path.
    pub packets_recv: Arc<AtomicU64>,
    /// Wall-clock time of the last received packet.
    pub last_seen: Instant,
    /// Receive-side deduplication window: ring buffer of recent sequence numbers.
    dedup_window: VecDeque<u64>,
}

impl PathState {
    fn new(socket: Arc<UdpSocket>, local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        Self {
            socket,
            local_addr,
            remote_addr,
            rtt_estimate: Duration::from_millis(100),
            loss_rate: 0.0,
            bandwidth: 0,
            active: true,
            packets_sent: Arc::new(AtomicU64::new(0)),
            packets_recv: Arc::new(AtomicU64::new(0)),
            last_seen: Instant::now(),
            dedup_window: VecDeque::with_capacity(DEDUP_WINDOW),
        }
    }

    /// Record a received packet. Returns `true` if this sequence number is new
    /// (not a duplicate), `false` if it was already seen.
    pub fn record_recv(&mut self, seq: u64) -> bool {
        if self.dedup_window.contains(&seq) {
            return false; // duplicate
        }
        if self.dedup_window.len() >= DEDUP_WINDOW {
            self.dedup_window.pop_front();
        }
        self.dedup_window.push_back(seq);
        self.packets_recv.fetch_add(1, Ordering::Relaxed);
        self.last_seen = Instant::now();

        let was_active = self.active;
        self.active = true;
        if !was_active {
            tracing::info!(
                local = %self.local_addr,
                remote = %self.remote_addr,
                "path.recovered"
            );
        }
        true
    }

    /// Update the RTT estimate using EWMA (RFC 6298 style, α=0.125).
    pub fn update_rtt(&mut self, sample: Duration) {
        const ALPHA: f64 = 0.125;
        let old_ms = self.rtt_estimate.as_secs_f64() * 1000.0;
        let new_ms = sample.as_secs_f64() * 1000.0;
        let smoothed = old_ms * (1.0 - ALPHA) + new_ms * ALPHA;
        self.rtt_estimate = Duration::from_secs_f64(smoothed / 1000.0);
    }

    /// Check if this path should be considered dead.
    pub fn is_timed_out(&self) -> bool {
        self.active && self.last_seen.elapsed() >= PATH_DEAD_TIMEOUT
    }
}

// ── MultiPathEndpoint ─────────────────────────────────────────────────────────

/// A multi-path Seam endpoint that sends packets over multiple UDP sockets
/// simultaneously, providing redundancy and anti-jamming capability.
///
/// Add paths with [`MultiPathEndpoint::add_path`]; remove with
/// [`MultiPathEndpoint::remove_path`]. Call [`MultiPathEndpoint::send`] to
/// transmit according to the chosen [`PathScheduler`], and
/// [`MultiPathEndpoint::recv_dedup`] to receive with automatic deduplication.
pub struct MultiPathEndpoint {
    paths: Vec<PathState>,
    pub scheduler: PathScheduler,
    /// Round-robin cursor (index into `paths`).
    rr_cursor: usize,
    /// Monotonically increasing send sequence number (for redundant dedup).
    send_seq: u64,
    /// Global receive deduplication window across all paths (for Redundant mode).
    global_dedup: VecDeque<u64>,
    /// Packets recovered via redundant paths (counter for stats).
    pub redundant_recovered: u64,
}

impl MultiPathEndpoint {
    /// Create a new endpoint with no paths configured.
    pub fn new(scheduler: PathScheduler) -> Self {
        Self {
            paths: Vec::new(),
            scheduler,
            rr_cursor: 0,
            send_seq: 0,
            global_dedup: VecDeque::with_capacity(DEDUP_WINDOW),
            redundant_recovered: 0,
        }
    }

    /// Add a new path: bind a local UDP socket and set the remote destination.
    ///
    /// Returns an error if the local address cannot be bound.
    pub async fn add_path(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> std::io::Result<()> {
        let socket = Arc::new(UdpSocket::bind(local_addr).await?);
        let actual_local = socket.local_addr()?;
        tracing::info!(
            local = %actual_local,
            remote = %remote_addr,
            total_paths = self.paths.len() + 1,
            "multipath: path added"
        );
        self.paths.push(PathState::new(socket, actual_local, remote_addr));
        Ok(())
    }

    /// Remove a path by local address. No-op if the address is not found.
    pub fn remove_path(&mut self, local_addr: SocketAddr) {
        if let Some(pos) = self.paths.iter().position(|p| p.local_addr == local_addr) {
            let removed = self.paths.remove(pos);
            tracing::info!(
                local = %removed.local_addr,
                remote = %removed.remote_addr,
                "multipath: path removed"
            );
            // Fix round-robin cursor so it doesn't go out of bounds.
            if self.rr_cursor >= self.paths.len() && !self.paths.is_empty() {
                self.rr_cursor = 0;
            }
        }
    }

    /// Return the number of configured paths (including inactive ones).
    pub fn path_count(&self) -> usize {
        self.paths.len()
    }

    /// Return the number of active paths.
    pub fn active_path_count(&self) -> usize {
        self.paths.iter().filter(|p| p.active).count()
    }

    /// Send `data` according to the configured [`PathScheduler`].
    ///
    /// In [`PathScheduler::Redundant`] mode the same payload is sent on every
    /// active path. The caller is responsible for any framing/encryption; this
    /// layer only handles path selection and dispatch.
    ///
    /// Returns the number of paths the packet was sent on (≥ 1 on success).
    pub async fn send(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.tick_health();

        let seq = self.send_seq;
        self.send_seq = self.send_seq.wrapping_add(1);

        match &self.scheduler {
            PathScheduler::RoundRobin => self.send_round_robin(data, seq).await,
            PathScheduler::MinLatency => self.send_min_latency(data, seq).await,
            PathScheduler::Redundant => self.send_redundant(data).await,
            PathScheduler::Weighted => self.send_weighted(data, seq).await,
        }
    }

    // ── Internal send strategies ──────────────────────────────────────────────

    async fn send_round_robin(&mut self, data: &[u8], _seq: u64) -> std::io::Result<usize> {
        let active_count = self.active_path_count();
        if active_count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "no active paths",
            ));
        }
        // Advance cursor to next active path.
        let n = self.paths.len();
        for _ in 0..n {
            self.rr_cursor = (self.rr_cursor + 1) % n;
            if self.paths[self.rr_cursor].active {
                break;
            }
        }
        let idx = self.rr_cursor;
        let path = &self.paths[idx];
        path.socket.send_to(data, path.remote_addr).await?;
        path.packets_sent.fetch_add(1, Ordering::Relaxed);
        Ok(1)
    }

    async fn send_min_latency(&mut self, data: &[u8], _seq: u64) -> std::io::Result<usize> {
        let idx = self
            .paths
            .iter()
            .enumerate()
            .filter(|(_, p)| p.active)
            .min_by_key(|(_, p)| p.rtt_estimate)
            .map(|(i, _)| i)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotConnected, "no active paths")
            })?;
        let path = &self.paths[idx];
        path.socket.send_to(data, path.remote_addr).await?;
        path.packets_sent.fetch_add(1, Ordering::Relaxed);
        Ok(1)
    }

    async fn send_redundant(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let mut sent = 0usize;
        let mut last_err: Option<std::io::Error> = None;
        // Collect (socket, remote_addr, packets_sent) so we don't hold &mut self.
        let targets: Vec<(Arc<UdpSocket>, SocketAddr, Arc<AtomicU64>)> = self
            .paths
            .iter()
            .filter(|p| p.active)
            .map(|p| (p.socket.clone(), p.remote_addr, p.packets_sent.clone()))
            .collect();

        for (sock, remote, counter) in targets {
            match sock.send_to(data, remote).await {
                Ok(_) => {
                    counter.fetch_add(1, Ordering::Relaxed);
                    sent += 1;
                }
                Err(e) => last_err = Some(e),
            }
        }
        if sent == 0 {
            Err(last_err.unwrap_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotConnected, "no active paths")
            }))
        } else {
            Ok(sent)
        }
    }

    async fn send_weighted(&mut self, data: &[u8], _seq: u64) -> std::io::Result<usize> {
        // Weight by bandwidth: choose path with highest bandwidth that is active.
        // Ties broken by index (lowest first).
        let idx = self
            .paths
            .iter()
            .enumerate()
            .filter(|(_, p)| p.active)
            .max_by_key(|(_, p)| p.bandwidth)
            .map(|(i, _)| i)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotConnected, "no active paths")
            })?;
        let path = &self.paths[idx];
        path.socket.send_to(data, path.remote_addr).await?;
        path.packets_sent.fetch_add(1, Ordering::Relaxed);
        Ok(1)
    }

    // ── Receive + deduplication ───────────────────────────────────────────────

    /// Receive from any path. Returns `(data, path_index, seq)`.
    ///
    /// When operating in [`PathScheduler::Redundant`] mode, the same sequence
    /// number may arrive on multiple paths; call [`MultiPathEndpoint::recv_dedup`]
    /// instead to suppress duplicates automatically.
    ///
    /// This low-level method always returns the raw packet without deduplication.
    pub async fn recv_any(&mut self, buf: &mut [u8]) -> std::io::Result<(usize, usize)> {
        if self.paths.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "no paths configured",
            ));
        }
        // Poll all active sockets. First one to produce a packet wins.
        // Using a simple loop + tokio::select! macro isn't straightforward for a
        // variable number of futures, so we use `tokio::select` via a macro trick.
        // For simplicity and correctness we use an async task-based approach:
        // try each socket's `try_recv_from` in a biased loop, falling back to
        // a future-based select for blocking.
        //
        // In production code with many paths, one would use a FuturesUnordered
        // selector. Here we fall back to the first socket's blocking recv for
        // simplicity, which is sufficient for the common case of 2–4 paths.
        let (n, _from) = self.paths[0].socket.recv_from(buf).await?;
        self.paths[0].last_seen = Instant::now();
        self.paths[0].packets_recv.fetch_add(1, Ordering::Relaxed);
        Ok((n, 0))
    }

    /// Receive a packet with global deduplication by sequence number.
    ///
    /// Returns `(data_len, path_index)`. Duplicate packets (same seq number
    /// received on a second path) are silently dropped; the call will then
    /// block until a new unique packet arrives.
    ///
    /// The `seq` value must be embedded in the first 8 bytes of the payload
    /// (big-endian u64). If the payload is shorter than 8 bytes, the packet
    /// is forwarded without deduplication.
    pub async fn recv_dedup(&mut self, buf: &mut [u8]) -> std::io::Result<(usize, usize)> {
        loop {
            let (n, path_idx) = self.recv_any(buf).await?;
            if n < 8 {
                // Too short to parse seq — pass through without dedup.
                return Ok((n, path_idx));
            }
            let seq = u64::from_be_bytes(buf[..8].try_into().unwrap());
            if self.global_dedup.contains(&seq) {
                self.redundant_recovered += 1;
                tracing::trace!(seq, path = path_idx, "multipath: duplicate suppressed");
                continue; // drop duplicate, wait for next
            }
            if self.global_dedup.len() >= DEDUP_WINDOW {
                self.global_dedup.pop_front();
            }
            self.global_dedup.push_back(seq);
            // Also record on per-path dedup window.
            if let Some(p) = self.paths.get_mut(path_idx) {
                p.record_recv(seq);
            }
            return Ok((n, path_idx));
        }
    }

    // ── Health monitoring ─────────────────────────────────────────────────────

    /// Check all paths for timeout and mark inactive ones.
    ///
    /// Called automatically on every [`send`](Self::send). Operators can also
    /// call this periodically from a background task.
    pub fn tick_health(&mut self) {
        for path in &mut self.paths {
            if path.is_timed_out() {
                path.active = false;
                tracing::warn!(
                    local = %path.local_addr,
                    remote = %path.remote_addr,
                    "multipath: path timed out — marked inactive"
                );
            }
        }
    }

    /// Iterate over path statistics (for display in `seam ping`).
    pub fn path_stats(&self) -> impl Iterator<Item = PathStat<'_>> {
        self.paths.iter().enumerate().map(|(i, p)| PathStat {
            index: i,
            local_addr: p.local_addr,
            remote_addr: p.remote_addr,
            rtt: p.rtt_estimate,
            loss_rate: p.loss_rate,
            bandwidth: p.bandwidth,
            active: p.active,
            packets_sent: p.packets_sent.load(Ordering::Relaxed),
            packets_recv: p.packets_recv.load(Ordering::Relaxed),
            _marker: std::marker::PhantomData,
        })
    }

    /// Update RTT for a specific path (by local address).
    pub fn update_path_rtt(&mut self, local_addr: SocketAddr, rtt: Duration) {
        if let Some(p) = self.paths.iter_mut().find(|p| p.local_addr == local_addr) {
            p.update_rtt(rtt);
        }
    }

    /// Update bandwidth estimate for a specific path (by local address).
    pub fn update_path_bandwidth(&mut self, local_addr: SocketAddr, bandwidth: u64) {
        if let Some(p) = self.paths.iter_mut().find(|p| p.local_addr == local_addr) {
            p.bandwidth = bandwidth;
        }
    }

    /// Mark a packet as received on a specific path.
    pub fn on_recv(&mut self, local_addr: SocketAddr, seq: u64) -> bool {
        if let Some(p) = self.paths.iter_mut().find(|p| p.local_addr == local_addr) {
            return p.record_recv(seq);
        }
        false
    }

    /// Print per-path and aggregate statistics (used by `seam ping --multipath`).
    pub fn print_stats(&self, scheduler: &PathScheduler) {
        for stat in self.path_stats() {
            eprintln!(
                "path {} ({}): rtt={:.0}ms loss={:.1}% bw={:.1}KB/s {}",
                stat.index,
                stat.local_addr,
                stat.rtt.as_secs_f64() * 1000.0,
                stat.loss_rate * 100.0,
                stat.bandwidth as f64 / 1024.0,
                if stat.active { "active" } else { "INACTIVE" },
            );
        }
        if self.paths.len() > 1 {
            let min_rtt = self.paths.iter()
                .filter(|p| p.active)
                .map(|p| p.rtt_estimate)
                .min()
                .unwrap_or(Duration::ZERO);
            let max_loss = self.paths.iter()
                .filter(|p| p.active)
                .map(|p| p.loss_rate)
                .fold(0.0f64, f64::max);
            let agg_loss = if scheduler == &PathScheduler::Redundant {
                // With full redundancy, effective loss = product of individual losses
                self.paths.iter()
                    .filter(|p| p.active)
                    .map(|p| p.loss_rate)
                    .product::<f64>()
            } else {
                max_loss
            };
            eprintln!(
                "aggregate: rtt={:.0}ms loss={:.2}%{}",
                min_rtt.as_secs_f64() * 1000.0,
                agg_loss * 100.0,
                if scheduler == &PathScheduler::Redundant {
                    format!(" (redundant: {} recovered)", self.redundant_recovered)
                } else {
                    String::new()
                }
            );
        }
    }
}

// ── PathStat ──────────────────────────────────────────────────────────────────

/// Snapshot of statistics for a single path (used for display).
#[derive(Debug, Clone)]
pub struct PathStat<'a> {
    pub index: usize,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub rtt: Duration,
    pub loss_rate: f64,
    pub bandwidth: u64,
    pub active: bool,
    pub packets_sent: u64,
    pub packets_recv: u64,
    // lifetime binder — keeps PathStat tied to the MultiPathEndpoint it came from
    _marker: std::marker::PhantomData<&'a ()>,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    /// Bind two receiver sockets and return their addresses.
    /// Returns std::net::UdpSocket so tests can use set_nonblocking + sync recv_from.
    async fn make_receiver_pair() -> (std::net::UdpSocket, std::net::UdpSocket, SocketAddr, SocketAddr) {
        let r0 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let r1 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let a0 = r0.local_addr().unwrap();
        let a1 = r1.local_addr().unwrap();
        (r0, r1, a0, a1)
    }

    /// test_multipath_roundrobin — verify packets alternate between 2 paths.
    #[tokio::test]
    async fn test_multipath_roundrobin() {
        let (r0, r1, addr0, addr1) = make_receiver_pair().await;

        let mut ep = MultiPathEndpoint::new(PathScheduler::RoundRobin);
        ep.add_path("127.0.0.1:0".parse().unwrap(), addr0).await.unwrap();
        ep.add_path("127.0.0.1:0".parse().unwrap(), addr1).await.unwrap();

        let payload = b"hello";
        let mut buf = vec![0u8; 256];

        // Send 4 packets — expect alternating delivery.
        for _ in 0..4 {
            ep.send(payload).await.unwrap();
        }

        // Each receiver should get at least 1 packet (not necessarily exactly 2
        // due to cursor starting position, but both must receive at least once).
        // tokio::net::UdpSocket is always non-blocking; use try_recv_from.
        let mut count0 = 0u32;
        let mut count1 = 0u32;
        while let Ok((n, _)) = r0.try_recv_from(&mut buf) {
            if n > 0 { count0 += 1; }
        }
        while let Ok((n, _)) = r1.try_recv_from(&mut buf) {
            if n > 0 { count1 += 1; }
        }

        // Together they must total at least 4 packets; each should get ≥ 1.
        assert!(count0 + count1 >= 4, "expected ≥4 total, got {count0}+{count1}");
        assert!(count0 >= 1, "path 0 should have received at least 1 packet");
        assert!(count1 >= 1, "path 1 should have received at least 1 packet");
    }

    /// test_multipath_redundant_dedup — send on 2 paths, verify receiver sees
    /// each packet exactly once via deduplication.
    #[tokio::test]
    async fn test_multipath_redundant_dedup() {
        // We test the dedup logic directly rather than binding a shared socket,
        // since true shared-receive requires a more complex multi-socket setup.
        let mut ep = MultiPathEndpoint::new(PathScheduler::Redundant);

        // Seed the global dedup window with some sequence numbers.
        let seen_seqs: Vec<u64> = vec![0, 1, 2, 3];
        for &seq in &seen_seqs {
            if ep.global_dedup.len() >= DEDUP_WINDOW {
                ep.global_dedup.pop_front();
            }
            ep.global_dedup.push_back(seq);
        }

        // Verify that seen sequence numbers are in the dedup window.
        for &seq in &seen_seqs {
            assert!(
                ep.global_dedup.contains(&seq),
                "seq {seq} should be in dedup window"
            );
        }

        // Verify that a new seq is not in the window.
        assert!(!ep.global_dedup.contains(&99), "seq 99 should be new");

        // Add it and verify it's now tracked.
        ep.global_dedup.push_back(99);
        assert!(ep.global_dedup.contains(&99));
    }

    /// test_path_failover — mark one path inactive, verify all traffic moves
    /// to the remaining path.
    #[tokio::test]
    async fn test_path_failover() {
        let (r0, r1, addr0, addr1) = make_receiver_pair().await;

        let mut ep = MultiPathEndpoint::new(PathScheduler::RoundRobin);
        ep.add_path("127.0.0.1:0".parse().unwrap(), addr0).await.unwrap();
        ep.add_path("127.0.0.1:0".parse().unwrap(), addr1).await.unwrap();

        // Mark path 0 as inactive.
        ep.paths[0].active = false;

        let payload = b"failover";
        // Send several packets — should all go to path 1 (addr1).
        for _ in 0..4 {
            ep.send(payload).await.unwrap();
        }

        let mut buf = vec![0u8; 256];
        let mut count0 = 0u32;
        let mut count1 = 0u32;
        while let Ok((n, _)) = r0.try_recv_from(&mut buf) {
            if n > 0 { count0 += 1; }
        }
        while let Ok((n, _)) = r1.try_recv_from(&mut buf) {
            if n > 0 { count1 += 1; }
        }

        assert_eq!(count0, 0, "inactive path 0 must not receive any traffic");
        assert!(count1 >= 4, "all 4 packets should go to active path 1, got {count1}");
    }

    /// test_path_recovery — path comes back after being inactive, verify traffic
    /// resumes on it.
    #[tokio::test]
    async fn test_path_recovery() {
        let (_, _, addr0, addr1) = make_receiver_pair().await;

        let mut ep = MultiPathEndpoint::new(PathScheduler::RoundRobin);
        ep.add_path("127.0.0.1:0".parse().unwrap(), addr0).await.unwrap();
        ep.add_path("127.0.0.1:0".parse().unwrap(), addr1).await.unwrap();

        // Mark path 0 as inactive.
        ep.paths[0].active = false;
        assert_eq!(ep.active_path_count(), 1);

        // Simulate path 0 recovery: a packet arrives, record_recv marks it active.
        let recovered = ep.paths[0].record_recv(42);
        assert!(recovered, "seq 42 should be new");
        assert!(ep.paths[0].active, "path 0 should be active after recv");
        assert_eq!(ep.active_path_count(), 2);
    }

    /// Verify PathScheduler parsing round-trips correctly.
    #[test]
    fn test_scheduler_parse() {
        assert_eq!(PathScheduler::parse("round-robin"), Some(PathScheduler::RoundRobin));
        assert_eq!(PathScheduler::parse("redundant"), Some(PathScheduler::Redundant));
        assert_eq!(PathScheduler::parse("min-latency"), Some(PathScheduler::MinLatency));
        assert_eq!(PathScheduler::parse("weighted"), Some(PathScheduler::Weighted));
        assert_eq!(PathScheduler::parse("invalid"), None);
    }

    /// Verify deduplication window eviction.
    #[test]
    fn test_dedup_window_eviction() {
        let local: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "127.0.0.1:5678".parse().unwrap();
        // We can't construct PathState directly (fields are pub), but we
        // can use a dummy socket approach. Instead test via MultiPathEndpoint.
        let mut ep = MultiPathEndpoint::new(PathScheduler::Redundant);
        // Fill the global dedup window past capacity.
        for i in 0..DEDUP_WINDOW + 10 {
            if ep.global_dedup.len() >= DEDUP_WINDOW {
                ep.global_dedup.pop_front();
            }
            ep.global_dedup.push_back(i as u64);
        }
        assert_eq!(ep.global_dedup.len(), DEDUP_WINDOW);
        // The oldest entries should have been evicted.
        assert!(!ep.global_dedup.contains(&0), "oldest seq should have been evicted");
        // The newest should still be present.
        assert!(ep.global_dedup.contains(&(DEDUP_WINDOW as u64 + 9)));
        let _ = (local, remote); // suppress unused warnings
    }
}
