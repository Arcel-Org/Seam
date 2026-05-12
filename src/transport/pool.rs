/// Lock-free-ish buffer pool for packet-sized allocations.
///
/// Reduces allocator pressure on the hot send/receive path. A pool holds up
/// to `max_pool_size` `Vec<u8>` of fixed capacity; acquiring a buffer pops
/// from the pool (or allocates fresh), releasing pushes back if the pool
/// isn't full (or drops if it is).
///
/// Uses a `Mutex<Vec<_>>` for simplicity; on hot paths the contention is
/// negligible because each call holds the lock only long enough to push/pop
/// a single pointer-sized value. If this becomes a bottleneck, swap to
/// `crossbeam_queue::ArrayQueue` (lock-free MPMC).
use std::sync::{Arc, Mutex};

pub struct BufferPool {
    inner: Arc<Mutex<Vec<Vec<u8>>>>,
    buf_capacity: usize,
    max_pool_size: usize,
}

impl BufferPool {
    pub fn new(buf_capacity: usize, max_pool_size: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::with_capacity(max_pool_size))),
            buf_capacity,
            max_pool_size,
        }
    }

    /// Acquire a zeroed-length buffer with at least `buf_capacity` capacity.
    pub fn acquire(&self) -> Vec<u8> {
        if let Ok(mut pool) = self.inner.lock()
            && let Some(mut buf) = pool.pop()
        {
            buf.clear();
            if buf.capacity() >= self.buf_capacity {
                return buf;
            }
        }
        Vec::with_capacity(self.buf_capacity)
    }

    /// Return a buffer to the pool. Dropped if the pool is at capacity.
    pub fn release(&self, buf: Vec<u8>) {
        if buf.capacity() < self.buf_capacity {
            return;
        }
        if let Ok(mut pool) = self.inner.lock()
            && pool.len() < self.max_pool_size
        {
            pool.push(buf);
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|p| p.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clone_handle(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            buf_capacity: self.buf_capacity,
            max_pool_size: self.max_pool_size,
        }
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        // Default: 1500-byte buffers, up to 256 pooled (~384 KiB retained)
        Self::new(1500, 256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_release_cycle() {
        let pool = BufferPool::new(1400, 4);
        assert_eq!(pool.len(), 0);
        let mut buf = pool.acquire();
        assert!(buf.capacity() >= 1400);
        buf.extend_from_slice(&[1u8; 100]);
        pool.release(buf);
        assert_eq!(pool.len(), 1);

        let buf2 = pool.acquire();
        assert_eq!(buf2.len(), 0, "acquired buffer should be empty (reused)");
    }

    #[test]
    fn pool_caps_at_max_size() {
        let pool = BufferPool::new(256, 2);
        pool.release(vec![0u8; 0].tap_resize(256));
        pool.release(vec![0u8; 0].tap_resize(256));
        pool.release(vec![0u8; 0].tap_resize(256)); // exceeds max
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn undersized_buffer_rejected() {
        let pool = BufferPool::new(1400, 4);
        pool.release(Vec::with_capacity(100));
        assert_eq!(pool.len(), 0);
    }

    trait VecExt {
        fn tap_resize(self, cap: usize) -> Self;
    }
    impl VecExt for Vec<u8> {
        fn tap_resize(mut self, cap: usize) -> Self {
            self.reserve(cap.saturating_sub(self.capacity()));
            self
        }
    }
}
