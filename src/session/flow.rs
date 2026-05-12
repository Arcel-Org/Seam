use crate::error::SeamError;

/// Credit-based flow control window (like QUIC's MAX_DATA / MAX_STREAM_DATA).
/// The sender may not transmit beyond `limit` total bytes.
pub struct FlowWindow {
    /// Total bytes the remote has permitted us to send.
    limit: u64,
    /// Total bytes we have consumed (sent or received).
    consumed: u64,
}

impl FlowWindow {
    pub fn new(initial_limit: u64) -> Self {
        Self { limit: initial_limit, consumed: 0 }
    }

    /// Try to reserve `n` bytes. Returns Ok(()) if within limit.
    pub fn reserve(&mut self, n: u64) -> Result<(), SeamError> {
        if self.consumed + n > self.limit {
            Err(SeamError::FlowControlBlocked {
                available: self.limit.saturating_sub(self.consumed),
                requested: n,
            })
        } else {
            self.consumed += n;
            Ok(())
        }
    }

    /// Remote has extended the limit.
    pub fn update_limit(&mut self, new_limit: u64) {
        if new_limit > self.limit {
            self.limit = new_limit;
        }
    }

    pub fn available(&self) -> u64 {
        self.limit.saturating_sub(self.consumed)
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_within_limit_reduces_available() {
        let mut flow = FlowWindow::new(100);
        flow.reserve(40).unwrap();
        assert_eq!(flow.available(), 60);
    }

    #[test]
    fn reserve_over_limit_returns_blocked_error_with_remaining_credit() {
        let mut flow = FlowWindow::new(10);
        flow.reserve(7).unwrap();
        let err = flow.reserve(5).unwrap_err();
        assert!(matches!(
            err,
            SeamError::FlowControlBlocked {
                available: 3,
                requested: 5
            }
        ));
        assert_eq!(flow.available(), 3);
    }

    #[test]
    fn update_limit_only_grows_limit() {
        let mut flow = FlowWindow::new(50);
        flow.reserve(20).unwrap();
        flow.update_limit(40);
        assert_eq!(flow.available(), 30);
        flow.update_limit(90);
        assert_eq!(flow.available(), 70);
    }
}
