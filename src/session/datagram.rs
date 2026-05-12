use bytes::Bytes;
/// Unreliable datagram queue. Per RFC 9221 for QUIC.
///
/// Datagrams are:
/// - **Unreliable**: not retransmitted on loss
/// - **Unordered**: delivered to the app in receive order (not sender order)
/// - **Bounded**: max size ≤ MTU − overhead (no fragmentation)
/// - **Flow-controlled**: bounded queue; oldest-dropped when full
///
/// Use cases: real-time media (video/voice), gaming state updates, telemetry,
/// anything where retransmit latency is worse than the loss itself.
use std::collections::VecDeque;

/// Maximum allowed datagram payload size. Leaves headroom for header+tag
/// within a typical MTU.
pub const MAX_DATAGRAM_SIZE: usize = 1200;

/// Default maximum queued datagrams per direction before oldest-drop.
pub const DEFAULT_QUEUE_DEPTH: usize = 64;

pub struct DatagramQueue {
    send_queue: VecDeque<Bytes>,
    recv_queue: VecDeque<Bytes>,
    max_size: usize,
    max_queue_depth: usize,
    /// Monotonically counted drops (for stats).
    pub dropped: u64,
}

impl DatagramQueue {
    pub fn new() -> Self {
        Self {
            send_queue: VecDeque::with_capacity(DEFAULT_QUEUE_DEPTH),
            recv_queue: VecDeque::with_capacity(DEFAULT_QUEUE_DEPTH),
            max_size: MAX_DATAGRAM_SIZE,
            max_queue_depth: DEFAULT_QUEUE_DEPTH,
            dropped: 0,
        }
    }

    pub fn with_limits(max_size: usize, max_queue_depth: usize) -> Self {
        Self {
            send_queue: VecDeque::with_capacity(max_queue_depth),
            recv_queue: VecDeque::with_capacity(max_queue_depth),
            max_size,
            max_queue_depth,
            dropped: 0,
        }
    }

    /// Queue a datagram for sending. Returns `Err(size)` if too large.
    /// Drops oldest on queue overflow.
    pub fn send(&mut self, data: Bytes) -> Result<(), usize> {
        if data.len() > self.max_size {
            return Err(data.len());
        }
        while self.send_queue.len() >= self.max_queue_depth {
            self.send_queue.pop_front();
            self.dropped += 1;
        }
        self.send_queue.push_back(data);
        Ok(())
    }

    /// Pop the next datagram to send on the wire (FIFO).
    pub fn poll_send(&mut self) -> Option<Bytes> {
        self.send_queue.pop_front()
    }

    /// Enqueue a received datagram for the application to read.
    /// Drops oldest if queue is full.
    pub fn receive(&mut self, data: Bytes) {
        if data.len() > self.max_size {
            return;
        }
        while self.recv_queue.len() >= self.max_queue_depth {
            self.recv_queue.pop_front();
            self.dropped += 1;
        }
        self.recv_queue.push_back(data);
    }

    /// Read the next received datagram (FIFO).
    pub fn recv(&mut self) -> Option<Bytes> {
        self.recv_queue.pop_front()
    }

    pub fn send_pending(&self) -> usize {
        self.send_queue.len()
    }
    pub fn recv_pending(&self) -> usize {
        self.recv_queue.len()
    }
}

impl Default for DatagramQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_recv_fifo() {
        let mut q = DatagramQueue::new();
        q.send(Bytes::from_static(b"a")).unwrap();
        q.send(Bytes::from_static(b"b")).unwrap();
        assert_eq!(&q.poll_send().unwrap()[..], b"a");
        assert_eq!(&q.poll_send().unwrap()[..], b"b");
        assert!(q.poll_send().is_none());
    }

    #[test]
    fn oversized_datagram_rejected() {
        let mut q = DatagramQueue::with_limits(100, 10);
        assert!(q.send(Bytes::from(vec![0u8; 200])).is_err());
    }

    #[test]
    fn overflow_drops_oldest() {
        let mut q = DatagramQueue::with_limits(100, 2);
        q.send(Bytes::from_static(b"1")).unwrap();
        q.send(Bytes::from_static(b"2")).unwrap();
        q.send(Bytes::from_static(b"3")).unwrap(); // evicts "1"
        assert_eq!(q.dropped, 1);
        assert_eq!(&q.poll_send().unwrap()[..], b"2");
        assert_eq!(&q.poll_send().unwrap()[..], b"3");
    }

    #[test]
    fn recv_fifo() {
        let mut q = DatagramQueue::new();
        q.receive(Bytes::from_static(b"x"));
        q.receive(Bytes::from_static(b"y"));
        assert_eq!(&q.recv().unwrap()[..], b"x");
        assert_eq!(&q.recv().unwrap()[..], b"y");
    }
}
