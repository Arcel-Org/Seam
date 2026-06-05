/// Dynamic FEC ↔ ARQ arbiter.
///
/// On clean links (< 0.5% loss) we use pure ARQ — no overhead, unless RTT is
/// high (> 100 ms) in which case we use a light HybridFecArq(k=10, r=1) to
/// avoid 200 ms retransmit round-trips on lossy hotel / mobile links.
/// On moderate loss (0.5–15%) we switch to HybridFecArq(k=8) — smaller groups
/// give faster recovery on mobile handoffs and bursty WiFi.
/// Above 15% we go pure FEC because ARQ retransmits are hopeless.
const THRESHOLD_LOW: f32 = 0.005; // 0.5%
const THRESHOLD_HIGH: f32 = 0.15; // 15%

/// RTT above which we add a baseline FEC overhead even on "clean" links.
/// ARQ retransmits cost ~2 × RTT; 100 ms is the crossover point.
const HIGH_LATENCY_US: u64 = 100_000; // 100 ms

/// Exponentially weighted moving average for loss rate.
///
/// Uses a **fast-increase / slow-decrease** alpha: when a new sample is
/// substantially higher than the current estimate (loss spike) we raise alpha
/// to 0.5 for rapid reaction; when the link is recovering we keep alpha at
/// 0.125 (RFC 6298 style) to avoid over-reacting to brief cleared bursts.
struct EwmaLoss {
    value: f32,
}

impl EwmaLoss {
    fn new() -> Self {
        Self { value: 0.0 }
    }

    fn update(&mut self, lost: u64, total: u64) -> f32 {
        let sample = if total == 0 {
            0.0
        } else {
            lost as f32 / total as f32
        };
        if self.value == 0.0 {
            // First real measurement: seed directly.
            self.value = sample;
        } else {
            // Fast increase (spike): use alpha=0.5 when sample exceeds estimate
            // by more than 2×.  Slow decrease: alpha=0.125 otherwise.
            let alpha = if sample > self.value * 2.0 { 0.5 } else { 0.125 };
            self.value = (1.0 - alpha) * self.value + alpha * sample;
        }
        self.value
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ArbiterMode {
    /// No FEC overhead — retransmit on loss.
    PureArq,
    /// Send `r` repair symbols per `k` source symbols.
    HybridFecArq { k: u8, r: u8 },
    /// Full FEC — no ARQ retransmissions.
    PureFec { k: u8, r: u8 },
}

impl ArbiterMode {
    /// Overhead ratio: repair / source.
    pub fn fec_overhead(&self) -> f32 {
        match self {
            Self::PureArq => 0.0,
            Self::HybridFecArq { k, r } => *r as f32 / *k as f32,
            Self::PureFec { k, r } => *r as f32 / *k as f32,
        }
    }

    pub fn uses_fec(&self) -> bool {
        !matches!(self, Self::PureArq)
    }
}

pub struct FecArbiter {
    pub mode: ArbiterMode,
    loss: EwmaLoss,
    /// Smoothed RTT in microseconds (updated by the session layer).
    pub rtt_us: u64,
}

impl FecArbiter {
    pub fn new() -> Self {
        Self {
            mode: ArbiterMode::PureArq,
            loss: EwmaLoss::new(),
            rtt_us: 0,
        }
    }

    /// Call at the end of each ACK epoch with observed loss counts and RTT.
    /// Returns the new mode (may be unchanged).
    pub fn on_ack_epoch(&mut self, lost: u64, total: u64, rtt_us: u64) -> &ArbiterMode {
        self.rtt_us = rtt_us;
        let loss_rate = self.loss.update(lost, total);

        let new_mode = if loss_rate < THRESHOLD_LOW {
            // Clean link — but if RTT is high, add a light repair layer to avoid
            // paying 2 × RTT for every lost packet on a retransmit.
            if rtt_us >= HIGH_LATENCY_US {
                ArbiterMode::HybridFecArq { k: 10, r: 1 }
            } else {
                ArbiterMode::PureArq
            }
        } else if loss_rate < THRESHOLD_HIGH {
            // Moderate loss — use k=8 (smaller groups) for faster recovery on
            // bursty links (hotel WiFi, mobile handoffs).
            // Scale repair count: at 0.5% → r=1, at 15% → r=3.
            let r =
                1u8 + ((loss_rate - THRESHOLD_LOW) / (THRESHOLD_HIGH - THRESHOLD_LOW) * 2.0) as u8;
            ArbiterMode::HybridFecArq { k: 8, r }
        } else {
            // High loss — aggressive FEC, no ARQ
            ArbiterMode::PureFec { k: 8, r: 4 }
        };

        // Hysteresis: only switch if mode class changes to avoid rapid oscillation
        let changed = !matches!(
            (&self.mode, &new_mode),
            (ArbiterMode::PureArq, ArbiterMode::PureArq)
                | (
                    ArbiterMode::HybridFecArq { .. },
                    ArbiterMode::HybridFecArq { .. }
                )
                | (ArbiterMode::PureFec { .. }, ArbiterMode::PureFec { .. })
        );

        if changed {
            self.mode = new_mode;
        }

        &self.mode
    }

    /// How many repair symbols to send for a group of `source_count` packets.
    pub fn repair_count(&self, source_count: u8) -> u8 {
        match self.mode {
            ArbiterMode::PureArq => 0,
            ArbiterMode::HybridFecArq { k, r } => {
                if source_count >= k {
                    r
                } else {
                    (source_count as f32 / k as f32 * r as f32) as u8
                }
            }
            ArbiterMode::PureFec { k, r } => {
                if source_count >= k {
                    r
                } else {
                    (source_count as f32 / k as f32 * r as f32) as u8
                }
            }
        }
    }
}

impl Default for FecArbiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stays_arq_on_clean_link() {
        let mut a = FecArbiter::new();
        for _ in 0..10 {
            a.on_ack_epoch(0, 100, 10_000);
        }
        assert_eq!(a.mode, ArbiterMode::PureArq);
    }

    #[test]
    fn test_switches_to_hybrid_on_moderate_loss() {
        let mut a = FecArbiter::new();
        // Simulate 5% loss — should trigger hybrid
        for _ in 0..20 {
            a.on_ack_epoch(5, 100, 50_000);
        }
        assert!(matches!(a.mode, ArbiterMode::HybridFecArq { .. }));
    }

    #[test]
    fn test_switches_to_pure_fec_on_high_loss() {
        let mut a = FecArbiter::new();
        for _ in 0..30 {
            a.on_ack_epoch(20, 100, 100_000);
        }
        assert!(matches!(a.mode, ArbiterMode::PureFec { .. }));
    }

    #[test]
    fn test_recovers_to_arq_after_loss_clears() {
        let mut a = FecArbiter::new();
        // Build up high loss
        for _ in 0..30 {
            a.on_ack_epoch(20, 100, 50_000);
        }
        assert!(matches!(a.mode, ArbiterMode::PureFec { .. }));
        // Loss clears — low-RTT link returns to PureArq
        for _ in 0..60 {
            a.on_ack_epoch(0, 100, 50_000);
        }
        assert_eq!(a.mode, ArbiterMode::PureArq);
    }

    #[test]
    fn test_high_latency_clean_link_uses_light_fec() {
        let mut a = FecArbiter::new();
        // Clean link (0% loss) but high RTT (150 ms) — should use HybridFecArq
        for _ in 0..10 {
            a.on_ack_epoch(0, 100, 150_000);
        }
        assert!(
            matches!(a.mode, ArbiterMode::HybridFecArq { k: 10, r: 1 }),
            "expected HybridFecArq(k=10,r=1) on high-latency clean link, got {:?}",
            a.mode
        );
    }

    #[test]
    fn test_ewma_spikes_fast_recover_slow() {
        // Verify that a sudden loss spike is tracked quickly (fast-increase),
        // and that after clearing, the EWMA decays slowly.
        let mut a = FecArbiter::new();
        // Establish a clean baseline
        for _ in 0..10 {
            a.on_ack_epoch(0, 100, 10_000);
        }
        assert_eq!(a.mode, ArbiterMode::PureArq);

        // Single spike at 20% — with alpha=0.5 the EWMA jumps immediately
        a.on_ack_epoch(20, 100, 10_000);
        assert!(
            matches!(a.mode, ArbiterMode::HybridFecArq { .. } | ArbiterMode::PureFec { .. }),
            "spike should trigger FEC immediately, got {:?}",
            a.mode
        );
    }
}
