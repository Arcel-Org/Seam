use crate::error::SeamError;
use bytes::{Bytes, BytesMut};
use std::collections::BTreeMap;

pub type StreamId = u32;

/// State of a single reliable ordered byte stream.
/// Stream priority: 0 = highest (urgent/control), 7 = lowest (bulk background).
pub type Priority = u8;
pub const PRIORITY_HIGH: Priority = 0;
pub const PRIORITY_DEFAULT: Priority = 4;
pub const PRIORITY_LOW: Priority = 7;

pub struct Stream {
    pub id: StreamId,
    /// Lower value = higher priority. Drives flush scheduling order.
    pub priority: Priority,
    // Send side
    send_buf: BytesMut,
    send_offset: u64,         // next byte offset to write into the wire
    send_unacked_offset: u64, // oldest byte not yet ACKed
    /// Per-stream send limit (bytes). Once we have sent `send_max_data` bytes
    /// no more data is emitted until the peer advances the window.
    send_max_data: u64,
    // Receive side
    recv_offset: u64,               // next expected byte offset
    recv_buf: BTreeMap<u64, Bytes>, // out-of-order segments keyed by offset
    /// Per-stream receive limit (bytes). Attempting to buffer beyond this
    /// is rejected to prevent unbounded memory growth per stream.
    recv_max_data: u64,
    recv_buffered: u64,
    fin_received: Option<u64>,
    fin_sent: bool,
    fin_flushed: bool, // true once a FIN DATA frame has been emitted
}

impl Stream {
    /// Default per-stream window: 256 MiB.
    /// TODO: shrink once MAX_STREAM_DATA messages are implemented to extend windows dynamically.
    pub const DEFAULT_WINDOW: u64 = 256 << 20;

    pub fn new(id: StreamId) -> Self {
        Self {
            id,
            priority: PRIORITY_DEFAULT,
            send_buf: BytesMut::new(),
            send_offset: 0,
            send_unacked_offset: 0,
            send_max_data: Self::DEFAULT_WINDOW,
            recv_offset: 0,
            recv_buf: BTreeMap::new(),
            recv_max_data: Self::DEFAULT_WINDOW,
            recv_buffered: 0,
            fin_received: None,
            fin_sent: false,
            fin_flushed: false,
        }
    }

    /// Extend the per-stream send window (peer sent MAX_STREAM_DATA).
    pub fn extend_send_window(&mut self, new_limit: u64) {
        if new_limit > self.send_max_data {
            self.send_max_data = new_limit;
        }
    }

    /// Current send window remaining (bytes the sender may still put on the wire).
    pub fn send_window_remaining(&self) -> u64 {
        self.send_max_data.saturating_sub(self.send_offset)
    }

    /// Configure this stream's receive-side limit.
    pub fn set_recv_limit(&mut self, limit: u64) {
        self.recv_max_data = limit;
    }

    // ── Send side ────────────────────────────────────────────────────────────

    /// Buffer data to send. Returns the offset at which this data starts.
    pub fn write(&mut self, data: &[u8]) -> Result<u64, SeamError> {
        if self.fin_sent {
            return Err(SeamError::StreamFinished(self.id));
        }
        // Enforce per-stream send window
        if self.send_offset.saturating_add(data.len() as u64) > self.send_max_data {
            return Err(SeamError::FlowControlBlocked {
                available: self.send_max_data.saturating_sub(self.send_offset),
                requested: data.len() as u64,
            });
        }
        let offset = self.send_offset;
        self.send_buf.extend_from_slice(data);
        self.send_offset += data.len() as u64;
        Ok(offset)
    }

    /// Mark the stream as finished on the send side.
    pub fn finish(&mut self) {
        self.fin_sent = true;
    }

    /// True when a FIN DATA frame should be emitted in the next flush.
    pub fn should_send_fin(&self) -> bool {
        self.fin_sent && !self.fin_flushed && self.send_buf.is_empty()
    }

    /// Call after the FIN frame has been encoded and queued.
    pub fn mark_fin_flushed(&mut self) {
        self.fin_flushed = true;
    }

    /// Current send offset (total bytes written to this stream).
    pub fn send_offset(&self) -> u64 {
        self.send_offset
    }

    /// Pop up to `max_bytes` of unsent data for packetisation.
    /// Returns (offset, data) where offset is the stream byte position of the chunk.
    pub fn poll_send(&mut self, max_bytes: usize) -> Option<(u64, Bytes)> {
        if self.send_buf.is_empty() {
            return None;
        }
        let take = self.send_buf.len().min(max_bytes);
        // The start of send_buf in the stream is (send_offset - send_buf.len()).
        let offset = self.send_offset - self.send_buf.len() as u64;
        let data = self.send_buf.split_to(take).freeze();
        Some((offset, data))
    }

    /// Called when the remote ACKs bytes up to `acked_offset` (exclusive).
    pub fn on_ack(&mut self, acked_offset: u64) {
        if acked_offset > self.send_unacked_offset {
            self.send_unacked_offset = acked_offset;
        }
    }

    // ── Receive side ─────────────────────────────────────────────────────────

    /// Deliver an incoming segment. Buffers out-of-order segments.
    /// Returns FlowControlBlocked if the segment would exceed the receive window.
    pub fn receive(&mut self, offset: u64, data: Bytes, is_fin: bool) -> Result<(), SeamError> {
        if is_fin {
            self.fin_received = Some(offset + data.len() as u64);
        }
        if data.is_empty() {
            return Ok(());
        }
        // Drop already-consumed data
        if offset + data.len() as u64 <= self.recv_offset {
            return Ok(());
        }
        // Per-stream recv window: reject if the highest-offset byte would
        // exceed the limit (prevents unbounded buffering by a hostile peer).
        let high_offset = offset + data.len() as u64;
        if high_offset > self.recv_max_data {
            return Err(SeamError::FlowControlBlocked {
                available: self.recv_max_data.saturating_sub(self.recv_offset),
                requested: high_offset.saturating_sub(self.recv_offset),
            });
        }
        self.recv_buffered = self.recv_buffered.saturating_add(data.len() as u64);
        self.recv_buf.insert(offset, data);
        Ok(())
    }

    /// Read up to `max_bytes` of contiguous in-order data into `out`.
    /// Returns bytes read.
    pub fn read(&mut self, out: &mut Vec<u8>, max_bytes: usize) -> usize {
        let mut read = 0;
        while read < max_bytes {
            let Some((&offset, _)) = self.recv_buf.iter().next() else {
                break;
            };
            if offset > self.recv_offset {
                // Gap — waiting for earlier segment
                break;
            }
            let data = self.recv_buf.remove(&offset).unwrap();
            let skip = (self.recv_offset - offset) as usize;
            let slice = &data[skip..];
            let take = slice.len().min(max_bytes - read);
            out.extend_from_slice(&slice[..take]);
            self.recv_offset += take as u64;
            read += take;
        }
        read
    }

    pub fn is_recv_finished(&self) -> bool {
        self.fin_received
            .map_or(false, |fin_off| self.recv_offset >= fin_off)
    }

    pub fn is_send_finished(&self) -> bool {
        self.fin_sent && self.send_unacked_offset >= self.send_offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_in_order() {
        let mut s = Stream::new(1);
        s.write(b"hello world").unwrap();
        let (off, data) = s.poll_send(64).unwrap();
        assert_eq!(off, 0);
        s.receive(0, data, false).unwrap();
        let mut out = Vec::new();
        let n = s.read(&mut out, 64);
        assert_eq!(n, 11);
        assert_eq!(&out, b"hello world");
    }

    #[test]
    fn test_stream_out_of_order() {
        let mut s = Stream::new(2);
        // Deliver second segment before first
        s.receive(5, Bytes::from_static(b" world"), false).unwrap();
        let mut out = Vec::new();
        // Nothing readable yet
        assert_eq!(s.read(&mut out, 64), 0);
        // Deliver first segment
        s.receive(0, Bytes::from_static(b"hello"), false).unwrap();
        let n = s.read(&mut out, 64);
        assert_eq!(n, 11);
        assert_eq!(&out, b"hello world");
    }
}
