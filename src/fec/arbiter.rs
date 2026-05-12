/// Dynamic FEC ↔ ARQ arbiter.
///
/// On clean links (< 1% loss) we use pure ARQ — no overhead.
/// On moderate loss (1–15%) we switch to hybrid: FEC repair symbols
/// are sent alongside data so the receiver reconstructs without a
/// retransmission RTT.
/// Above 15% we go pure FEC because ARQ retransmits are hopeless.
const THRESHOLD_LOW: f32 = 0.01; // 1%
const THRESHOLD_HIGH: f32 = 0.15; // 15%

/// Exponentially weighted moving average for loss rate.
struct EwmaLoss {
    value: f32,
    alpha: f32,
}

impl EwmaLoss {
    fn new() -> Self {
        Self {
            value: 0.0,
            alpha: 0.125,
        } // RFC 6298 style
    }

    fn update(&mut self, lost: u64, total: u64) -> f32 {
        let sample = if total == 0 {
            0.0
        } else {
            lost as f32 / total as f32
        };
        if self.value == 0.0 {
            self.value = sample;
        } else {
            self.value = (1.0 - self.alpha) * self.value + self.alpha * sample;
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
            ArbiterMode::PureArq
        } else if loss_rate < THRESHOLD_HIGH {
            // Scale repair count with loss rate: at 1% → r=1, at 15% → r=3
            let r =
                1u8 + ((loss_rate - THRESHOLD_LOW) / (THRESHOLD_HIGH - THRESHOLD_LOW) * 2.0) as u8;
            ArbiterMode::HybridFecArq { k: 10, r }
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
        // Loss clears
        for _ in 0..60 {
            a.on_ack_epoch(0, 100, 50_000);
        }
        assert_eq!(a.mode, ArbiterMode::PureArq);
    }
}
