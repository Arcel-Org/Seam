/// Traffic Analysis Resistance (TAR) — packet shaping, cover traffic, timing jitter,
/// and protocol fingerprint obfuscation.
///
/// Five mechanisms:
///
/// 1. **Fixed packet-size padding** — after AEAD encryption pad ciphertext to the
///    next size class boundary (Small/Medium/Large/Jumbo). The receiver strips
///    padding after decryption using a length field preserved in the session header.
///    Disable with `no_padding = true` for performance-sensitive paths.
///
/// 2. **Constant-rate cover traffic** — `CoverTrafficTask` maintains a target kbps by
///    injecting encrypted random-byte `CoverPacket` frames when real data rate is
///    below the target. Cover packets are identical in size to real packets.
///
/// 3. **Timing jitter** — random delay (0 to N ms) before each send breaks
///    timing-correlation attacks. Tradeoff: increases latency.
///
/// 4. **Protocol fingerprint obfuscation** — XOR the first 8 bytes of each packet
///    with a per-session secret so packets look like random bytes to naive DPI.
///
/// 5. **Config integration** — all features exposed as `TarConfig` (derived from CLI
///    flags and the persistent config file).
use std::time::{Duration, Instant};

// ── Packet size classes ────────────────────────────────────────────────────

/// Fixed wire-size targets used when padding is enabled.
///
/// Payload thresholds (after AEAD encryption overhead of 32B header + 16B tag):
///   Small  → padded wire size = 256   (payload ≤ 208)
///   Medium → padded wire size = 512   (payload ≤ 464)
///   Large  → padded wire size = 1024  (payload ≤ 976)
///   Jumbo  → padded wire size = 1400  (payload ≤ 1352, just under typical MTU)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketSizeClass {
    Small = 256,
    Medium = 512,
    Large = 1024,
    Jumbo = 1400,
}

impl PacketSizeClass {
    /// Return the smallest size class whose wire size accommodates `wire_len`.
    pub fn classify(wire_len: usize) -> Self {
        if wire_len <= 256 {
            Self::Small
        } else if wire_len <= 512 {
            Self::Medium
        } else if wire_len <= 1024 {
            Self::Large
        } else {
            Self::Jumbo
        }
    }

    /// Wire size for this class.
    pub fn wire_size(self) -> usize {
        self as usize
    }
}

// ── Padding ────────────────────────────────────────────────────────────────

/// Pad `packet` (already AEAD-encrypted, including header) to the next size class
/// boundary with random bytes using the provided LCG state.
///
/// Returns the padded buffer.  The receiver does not need to know the padding
/// length because the Seam session layer already carries a plaintext-length field
/// in every packet's encrypted payload; the padding is simply discarded.
///
/// If `packet` already exceeds the Jumbo boundary, it is returned unchanged (the
/// caller may split or fragment as appropriate).
pub fn pad_to_size_class(packet: Vec<u8>, lcg: &mut u64) -> Vec<u8> {
    let class = PacketSizeClass::classify(packet.len());
    let target = class.wire_size();
    if packet.len() >= target {
        return packet;
    }
    let mut out = packet;
    out.reserve(target - out.len());
    while out.len() < target {
        *lcg = lcg
            .wrapping_mul(6364136223846793005)
            .wrapping_add(0x14057b7ef767814f);
        let rand_byte = ((*lcg >> 33) & 0xFF) as u8;
        out.push(rand_byte);
    }
    out
}

// ── Cover traffic ──────────────────────────────────────────────────────────

/// Configuration for the constant-rate cover traffic generator.
#[derive(Debug, Clone, Copy)]
pub struct CoverTrafficConfig {
    /// Target bit rate in kbps.  0 = disabled.
    pub target_kbps: u32,
    /// Fixed wire size for cover packets (should match size-class boundaries).
    pub packet_size: u16,
}

impl CoverTrafficConfig {
    pub fn disabled() -> Self {
        Self {
            target_kbps: 0,
            packet_size: 1024,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.target_kbps > 0
    }

    /// Compute the inter-packet interval required to sustain `target_kbps`.
    /// Returns `None` when disabled.
    pub fn inter_packet_interval(&self) -> Option<Duration> {
        if self.target_kbps == 0 {
            return None;
        }
        // kbps → bytes/s → bytes per packet → packets/s → interval
        let bytes_per_sec = (self.target_kbps as u64) * 1000 / 8;
        if bytes_per_sec == 0 {
            return None;
        }
        let pkt_size = self.packet_size as u64;
        // packets_per_sec = bytes_per_sec / pkt_size
        // interval_ns = 1e9 / packets_per_sec = pkt_size * 1e9 / bytes_per_sec
        let interval_ns = pkt_size.saturating_mul(1_000_000_000) / bytes_per_sec;
        Some(Duration::from_nanos(interval_ns))
    }
}

/// Sliding-window real-traffic rate tracker (100ms window).
///
/// Used by the cover-traffic task to decide whether to inject a cover packet.
pub struct RateTracker {
    window: Duration,
    samples: std::collections::VecDeque<(Instant, usize)>,
}

impl RateTracker {
    pub fn new() -> Self {
        Self {
            window: Duration::from_millis(100),
            samples: std::collections::VecDeque::with_capacity(64),
        }
    }

    /// Record that `bytes` of real traffic was just sent.
    pub fn record(&mut self, bytes: usize) {
        let now = Instant::now();
        self.samples.push_back((now, bytes));
        // Purge expired samples.
        let cutoff = now - self.window;
        while self
            .samples
            .front()
            .map(|(t, _)| *t < cutoff)
            .unwrap_or(false)
        {
            self.samples.pop_front();
        }
    }

    /// Current bytes-per-second rate over the sliding window.
    pub fn rate_bps(&self) -> f64 {
        let total: usize = self.samples.iter().map(|(_, b)| b).sum();
        if self.samples.is_empty() {
            return 0.0;
        }
        let window_secs = self.window.as_secs_f64();
        total as f64 / window_secs
    }
}

impl Default for RateTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ── Timing jitter ──────────────────────────────────────────────────────────

/// Configuration for per-packet random timing delay.
#[derive(Debug, Clone, Copy)]
pub struct JitterConfig {
    /// Maximum jitter in milliseconds.  0 = disabled.
    ///
    /// Tradeoff: higher jitter → stronger timing-correlation resistance but
    /// higher latency.  Recommended:
    ///   Interactive (shell):  max_jitter_ms ≤ 10
    ///   File transfer (cp):   max_jitter_ms up to 50
    pub max_jitter_ms: u32,
}

impl JitterConfig {
    pub fn disabled() -> Self {
        Self { max_jitter_ms: 0 }
    }

    pub fn is_enabled(&self) -> bool {
        self.max_jitter_ms > 0
    }

    /// Sample a random jitter delay [0, max_jitter_ms) using an LCG.
    pub fn sample_delay(&self, lcg: &mut u64) -> Duration {
        if self.max_jitter_ms == 0 {
            return Duration::ZERO;
        }
        *lcg = lcg
            .wrapping_mul(6364136223846793005)
            .wrapping_add(0x14057b7ef767814f);
        let ms = (*lcg >> 33) % (self.max_jitter_ms as u64);
        Duration::from_millis(ms)
    }
}

// ── Protocol fingerprint obfuscation ──────────────────────────────────────

/// XOR the first 8 bytes of a packet with bytes derived from `session_secret`
/// to make headers look random to DPI engines.
///
/// The transformation is self-inverse (applying it twice returns the original),
/// so both sender and receiver call the same function.
///
/// `session_secret` MUST be per-session (derived from handshake keys) so each
/// session uses different obfuscation bytes and there is no fixed magic number.
pub fn obfuscate_header(packet: &mut [u8], session_secret: &[u8; 32]) {
    let n = packet.len().min(8);
    for i in 0..n {
        packet[i] ^= session_secret[i];
    }
}

/// Derive an 8-byte obfuscation mask from the session's BLAKE3 key material.
///
/// We take bytes [24..32] of the 32-byte session secret to produce a mask
/// that is not directly the encryption key, ensuring key separation.
pub fn derive_obfuscation_secret(session_key: &[u8; 32]) -> [u8; 32] {
    // BLAKE3 keyed with a domain-separation constant.
    let mut out = [0u8; 32];
    let keyed = blake3::keyed_hash(session_key, b"seam.tar.obfuscate.v1");
    out.copy_from_slice(keyed.as_bytes());
    out
}

// ── Unified TAR configuration ──────────────────────────────────────────────

/// Traffic Analysis Resistance configuration — applied at the connection level.
#[derive(Debug, Clone)]
pub struct TarConfig {
    /// When `false` packets are padded to size-class boundaries (default).
    pub no_padding: bool,
    /// Cover traffic configuration.
    pub cover: CoverTrafficConfig,
    /// Per-packet timing jitter.
    pub jitter: JitterConfig,
    /// Obfuscate packet headers to defeat DPI fingerprinting.
    pub obfuscate: bool,
}

impl TarConfig {
    pub fn disabled() -> Self {
        Self {
            no_padding: true,
            cover: CoverTrafficConfig::disabled(),
            jitter: JitterConfig::disabled(),
            obfuscate: false,
        }
    }

    /// Defaults for FIPS-mode deployments (padding on, others off).
    pub fn fips_defaults() -> Self {
        Self {
            no_padding: false,
            cover: CoverTrafficConfig::disabled(),
            jitter: JitterConfig::disabled(),
            obfuscate: false,
        }
    }

    pub fn padding_enabled(&self) -> bool {
        !self.no_padding
    }
}

impl Default for TarConfig {
    fn default() -> Self {
        Self::disabled()
    }
}

// ── Per-connection TAR state ───────────────────────────────────────────────

/// Mutable TAR state carried inside a `Connection`.
pub struct TarState {
    pub config: TarConfig,
    /// LCG for padding random bytes and jitter sampling.
    lcg: u64,
    /// Rate tracker for cover-traffic decisions.
    pub rate_tracker: RateTracker,
    /// Obfuscation key derived from the session handshake secret.
    obfuscation_secret: Option<[u8; 32]>,
    /// When cover traffic is enabled: time of the next required cover packet.
    pub next_cover_at: Option<Instant>,
}

impl TarState {
    pub fn new(config: TarConfig) -> Self {
        Self {
            config,
            lcg: 0x517cc1b727220a95_u64,
            rate_tracker: RateTracker::new(),
            obfuscation_secret: None,
            next_cover_at: None,
        }
    }

    /// Called after the handshake completes to install the session secret.
    pub fn set_session_secret(&mut self, session_key: &[u8; 32]) {
        if self.config.obfuscate {
            self.obfuscation_secret = Some(derive_obfuscation_secret(session_key));
        }
        // Initialise cover traffic schedule.
        if let Some(interval) = self.config.cover.inter_packet_interval() {
            self.next_cover_at = Some(Instant::now() + interval);
        }
    }

    /// Apply size-class padding to `packet` (in-place via replacement) if enabled.
    pub fn maybe_pad(&mut self, packet: Vec<u8>) -> Vec<u8> {
        if self.config.padding_enabled() {
            pad_to_size_class(packet, &mut self.lcg)
        } else {
            packet
        }
    }

    /// Apply header obfuscation to `packet` (XOR first 8 bytes) if enabled.
    pub fn maybe_obfuscate(&self, packet: &mut Vec<u8>) {
        if let Some(ref secret) = self.obfuscation_secret {
            obfuscate_header(packet, secret);
        }
    }

    /// Apply header de-obfuscation to an incoming `packet` if enabled.
    /// Since obfuscation is self-inverse, this is the same operation.
    pub fn maybe_deobfuscate(&self, packet: &mut [u8]) {
        if let Some(ref secret) = self.obfuscation_secret {
            obfuscate_header(packet, secret);
        }
    }

    /// Sample the jitter delay for the next outgoing packet.
    pub fn jitter_delay(&mut self) -> Duration {
        self.config.jitter.sample_delay(&mut self.lcg)
    }

    /// Record that `bytes` of real traffic was sent; advances rate tracker and
    /// cover traffic schedule.
    pub fn on_real_send(&mut self, bytes: usize) {
        self.rate_tracker.record(bytes);
        // Push the next cover packet deadline forward to avoid a burst.
        if let (Some(interval), Some(ref mut next)) = (
            self.config.cover.inter_packet_interval(),
            self.next_cover_at.as_mut(),
        ) {
            **next = Instant::now() + interval;
        }
    }

    /// Returns `true` if a cover packet should be injected right now.
    pub fn should_send_cover(&self) -> bool {
        match self.next_cover_at {
            None => false,
            Some(t) => Instant::now() >= t,
        }
    }

    /// Advance the cover traffic schedule after a cover packet is sent.
    pub fn mark_cover_sent(&mut self) {
        if let Some(interval) = self.config.cover.inter_packet_interval() {
            self.next_cover_at = Some(Instant::now() + interval);
        }
    }

    /// Build a cover packet payload (random bytes, size matching config).
    pub fn cover_payload(&mut self) -> Vec<u8> {
        let size = self.config.cover.packet_size as usize;
        let mut payload = vec![0u8; size];
        for byte in payload.iter_mut() {
            self.lcg = self
                .lcg
                .wrapping_mul(6364136223846793005)
                .wrapping_add(0x14057b7ef767814f);
            *byte = (self.lcg >> 33) as u8;
        }
        payload
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_class_classify_boundaries() {
        assert_eq!(PacketSizeClass::classify(1), PacketSizeClass::Small);
        assert_eq!(PacketSizeClass::classify(256), PacketSizeClass::Small);
        assert_eq!(PacketSizeClass::classify(257), PacketSizeClass::Medium);
        assert_eq!(PacketSizeClass::classify(512), PacketSizeClass::Medium);
        assert_eq!(PacketSizeClass::classify(513), PacketSizeClass::Large);
        assert_eq!(PacketSizeClass::classify(1024), PacketSizeClass::Large);
        assert_eq!(PacketSizeClass::classify(1025), PacketSizeClass::Jumbo);
        assert_eq!(PacketSizeClass::classify(1400), PacketSizeClass::Jumbo);
        assert_eq!(PacketSizeClass::classify(9999), PacketSizeClass::Jumbo);
    }

    #[test]
    fn pad_to_size_class_reaches_boundary() {
        let mut lcg = 0xdeadbeef_u64;
        let pkt = vec![0xAAu8; 100];
        let padded = pad_to_size_class(pkt, &mut lcg);
        assert_eq!(padded.len(), 256, "100 bytes should pad to Small (256)");
        assert_eq!(
            &padded[..100],
            &[0xAAu8; 100],
            "original bytes must be preserved"
        );
    }

    #[test]
    fn pad_to_size_class_no_shrink() {
        let mut lcg = 1u64;
        let big = vec![0u8; 5000];
        let out = pad_to_size_class(big.clone(), &mut lcg);
        assert_eq!(out.len(), big.len(), "oversized packet must not be shrunk");
    }

    #[test]
    fn pad_preserves_prefix() {
        let mut lcg = 42u64;
        let pkt = vec![1u8, 2, 3, 4, 5];
        let padded = pad_to_size_class(pkt, &mut lcg);
        assert_eq!(padded[..5], [1, 2, 3, 4, 5]);
        assert_eq!(padded.len(), 256);
    }

    #[test]
    fn obfuscate_is_self_inverse() {
        let secret = [0x42u8; 32];
        let original = vec![0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        let mut pkt = original.clone();
        obfuscate_header(&mut pkt, &secret);
        assert_ne!(pkt, original, "obfuscation should change bytes");
        obfuscate_header(&mut pkt, &secret);
        assert_eq!(pkt, original, "double-obfuscation must restore original");
    }

    #[test]
    fn obfuscate_no_fixed_magic() {
        // With different secrets, the first 8 bytes must differ.
        let secret_a = [0xAAu8; 32];
        let secret_b = [0xBBu8; 32];
        let pkt_base = vec![0u8; 16];
        let mut pkt_a = pkt_base.clone();
        let mut pkt_b = pkt_base.clone();
        obfuscate_header(&mut pkt_a, &secret_a);
        obfuscate_header(&mut pkt_b, &secret_b);
        assert_ne!(&pkt_a[..8], &pkt_b[..8]);
    }

    #[test]
    fn derive_obfuscation_secret_deterministic() {
        let key = [0x11u8; 32];
        let s1 = derive_obfuscation_secret(&key);
        let s2 = derive_obfuscation_secret(&key);
        assert_eq!(s1, s2);
    }

    #[test]
    fn derive_obfuscation_secret_differs_from_key() {
        let key = [0x77u8; 32];
        let secret = derive_obfuscation_secret(&key);
        assert_ne!(
            &secret[..],
            &key[..],
            "derived secret must differ from raw key"
        );
    }

    #[test]
    fn jitter_config_within_bounds() {
        let cfg = JitterConfig { max_jitter_ms: 50 };
        let mut lcg = 0xdeadbeef_u64;
        for _ in 0..200 {
            let d = cfg.sample_delay(&mut lcg);
            assert!(d < Duration::from_millis(50), "jitter exceeded max: {d:?}");
        }
    }

    #[test]
    fn jitter_config_disabled_is_zero() {
        let cfg = JitterConfig::disabled();
        let mut lcg = 1u64;
        assert_eq!(cfg.sample_delay(&mut lcg), Duration::ZERO);
    }

    #[test]
    fn cover_traffic_interval_calculation() {
        let cfg = CoverTrafficConfig {
            target_kbps: 100,
            packet_size: 1024,
        };
        let interval = cfg.inter_packet_interval().unwrap();
        // 100 kbps = 12500 B/s; packet = 1024 B; interval = 1024/12500 s ≈ 81.92ms
        let expected_ns = 1024u64 * 1_000_000_000 / 12500;
        assert_eq!(interval.as_nanos() as u64, expected_ns);
    }

    #[test]
    fn cover_traffic_disabled_no_interval() {
        let cfg = CoverTrafficConfig::disabled();
        assert!(cfg.inter_packet_interval().is_none());
    }

    #[test]
    fn rate_tracker_computes_rate() {
        let mut rt = RateTracker::new();
        // 12500 bytes in 100ms window → 125000 B/s
        rt.record(12500);
        let rate = rt.rate_bps();
        assert!(rate > 0.0);
    }

    #[test]
    fn tar_state_padding_enabled_by_default_when_config_says_so() {
        let cfg = TarConfig {
            no_padding: false,
            cover: CoverTrafficConfig::disabled(),
            jitter: JitterConfig::disabled(),
            obfuscate: false,
        };
        let mut state = TarState::new(cfg);
        let pkt = vec![0xFFu8; 50];
        let padded = state.maybe_pad(pkt);
        assert_eq!(padded.len(), 256);
    }

    #[test]
    fn tar_state_no_padding_when_disabled() {
        let mut state = TarState::new(TarConfig::disabled());
        let pkt = vec![0xFFu8; 50];
        let out = state.maybe_pad(pkt.clone());
        assert_eq!(out.len(), pkt.len());
    }

    #[test]
    fn tar_state_cover_payload_correct_size() {
        let cfg = TarConfig {
            no_padding: true,
            cover: CoverTrafficConfig {
                target_kbps: 10,
                packet_size: 512,
            },
            jitter: JitterConfig::disabled(),
            obfuscate: false,
        };
        let mut state = TarState::new(cfg);
        let payload = state.cover_payload();
        assert_eq!(payload.len(), 512);
    }
}
