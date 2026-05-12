use crate::error::SeamError;

pub struct ReplayWindow {
    base_seq: u64,
    bitmap: [u64; 16], // 1024-bit window
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            base_seq: 0,
            bitmap: [0u64; 16],
        }
    }

    pub fn check_and_insert(&mut self, seq: u64) -> Result<(), SeamError> {
        if seq < self.base_seq {
            return Err(SeamError::TooOld(seq));
        }

        let offset = seq - self.base_seq;

        // Slide window forward if needed
        if offset >= 1024 {
            let slide = offset - 1023;
            if slide >= 1024 {
                self.bitmap = [0u64; 16];
            } else {
                // Shift bitmap left by `slide` bits
                let word_shift = (slide / 64) as usize;
                let bit_shift = (slide % 64) as u32;
                let mut new_bitmap = [0u64; 16];
                for (i, slot) in new_bitmap.iter_mut().enumerate() {
                    let src = i + word_shift;
                    if src < 16 {
                        *slot = self.bitmap[src] >> bit_shift;
                        if bit_shift > 0 && src + 1 < 16 {
                            *slot |= self.bitmap[src + 1] << (64 - bit_shift);
                        }
                    }
                }
                self.bitmap = new_bitmap;
            }
            self.base_seq += slide;
        }

        let bit_pos = (seq - self.base_seq) as usize;
        let word = bit_pos / 64;
        let bit = bit_pos % 64;

        if self.bitmap[word] & (1u64 << bit) != 0 {
            return Err(SeamError::Replay(seq));
        }

        self.bitmap[word] |= 1u64 << bit;
        Ok(())
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accepts_new_packets() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_insert(0).is_ok());
        assert!(w.check_and_insert(1).is_ok());
        assert!(w.check_and_insert(500).is_ok());
    }

    #[test]
    fn test_replay_rejected() {
        let mut w = ReplayWindow::new();
        w.check_and_insert(42).unwrap();
        assert!(matches!(w.check_and_insert(42), Err(SeamError::Replay(42))));
    }

    #[test]
    fn test_too_old_rejected() {
        let mut w = ReplayWindow::new();
        // Force window to slide past 0
        w.check_and_insert(2000).unwrap();
        assert!(matches!(w.check_and_insert(0), Err(SeamError::TooOld(0))));
    }

    #[test]
    fn test_window_sliding() {
        let mut w = ReplayWindow::new();
        for i in 0u64..1030 {
            assert!(w.check_and_insert(i).is_ok(), "failed at {i}");
        }
        // 0 is now outside the window
        assert!(matches!(w.check_and_insert(0), Err(SeamError::TooOld(0))));
        // 1030 should still be accepted
        assert!(w.check_and_insert(1030).is_ok());
    }
}
