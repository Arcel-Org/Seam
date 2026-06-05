pub mod ack;
pub mod arq;
pub mod datagram;
pub mod flow;
pub mod rack;
pub mod stream;

use bytes::Bytes;
use std::collections::HashMap;
use std::time::Duration;

/// A packet produced by [`Session::flush`], tagged so the connection layer can
/// exempt control packets (ACK, MaxData) from congestion-control accounting.
pub struct TaggedPacket {
    pub is_control: bool,
    pub bytes: Vec<u8>,
}

use crate::{
    crypto::{decoder::PacketDecoder, encoder::PacketEncoder},
    error::SeamError,
    packet::PktType,
    session::{
        ack::{AckRanges, parse_ack_frame},
        arq::ArqTracker,
        datagram::DatagramQueue,
        flow::FlowWindow,
        stream::{PRIORITY_DEFAULT, Priority, Stream, StreamId},
    },
};

/// Events the session layer surfaces to the application.
#[derive(Debug)]
pub enum SessionEvent {
    NewStream(StreamId),
    DataAvailable(StreamId),
    StreamFinished(StreamId),
    DatagramReceived,
    /// Encrypted session ticket received from the server (for 0-RTT resumption).
    SessionTicket(Vec<u8>),
    Closed,
}

/// Which side of the connection this session represents. Controls stream-id
/// allocation so client and server can initiate streams concurrently without
/// collisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Initiator (uses odd stream IDs: 1, 3, 5 …).
    Client,
    /// Responder (uses even stream IDs: 2, 4, 6 …).
    Server,
}

impl Role {
    /// Parity bit of locally-initiated stream IDs (Client=1 odd, Server=0 even).
    fn local_parity(self) -> u32 {
        match self {
            Role::Client => 1,
            Role::Server => 0,
        }
    }
}

/// Resource limits enforced at the session layer to resist DoS.
#[derive(Debug, Clone)]
pub struct SessionLimits {
    pub max_streams: u32,
    pub max_datagram_size: usize,
    pub max_datagram_queue: usize,
    pub max_in_flight_packets: usize,
    pub max_recv_buffer_per_stream: u64,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            max_streams: 1024,
            max_datagram_size: 1200,
            max_datagram_queue: 64,
            max_in_flight_packets: 10_000,
            max_recv_buffer_per_stream: 4 * 1024 * 1024, // 4 MiB
        }
    }
}

// 16 MiB — replenished dynamically via MaxData frames. Control packets are
// exempt from congestion-control bytes_in_flight, so MaxData reliably extends
// the window before the sender stalls.
const DEFAULT_WINDOW: u64 = 16 << 20;
const MAX_PAYLOAD: usize = 1400; // conservative MTU

pub struct Session {
    pub id: u64,
    pub role: Role,
    encoder: PacketEncoder,
    decoder: PacketDecoder,
    streams: HashMap<StreamId, Stream>,
    next_stream_id: StreamId,
    send_window: FlowWindow,
    recv_window: FlowWindow,
    /// Total application bytes received so far (for recv window accounting).
    recv_consumed: u64,
    /// If Some(limit), flush() will emit a MaxData packet with this new limit.
    pending_max_data: Option<u64>,
    /// If true, the next flush() will emit a Pong frame.
    pending_pong: bool,
    /// If true, the next flush() will emit a Ping frame.
    pending_ping: bool,
    arq: ArqTracker,
    datagrams: DatagramQueue,
    limits: SessionLimits,
    /// Packet numbers received from peer, to be ACKed in range form.
    ack_ranges: AckRanges,
    /// Accumulated CC feedback from the last ACK frame: (bytes_acked, rtt_sample).
    /// Consumed by `drain_cc_ack()`.
    pending_cc_ack: Option<(u64, Duration)>,
}

impl Session {
    pub fn new(id: u64, encoder: PacketEncoder, decoder: PacketDecoder) -> Self {
        Self::with_limits(id, Role::Client, encoder, decoder, SessionLimits::default())
    }

    pub fn with_role(id: u64, role: Role, encoder: PacketEncoder, decoder: PacketDecoder) -> Self {
        Self::with_limits(id, role, encoder, decoder, SessionLimits::default())
    }

    pub fn with_limits(
        id: u64,
        role: Role,
        encoder: PacketEncoder,
        decoder: PacketDecoder,
        limits: SessionLimits,
    ) -> Self {
        let datagrams =
            DatagramQueue::with_limits(limits.max_datagram_size, limits.max_datagram_queue);
        let next_stream_id = match role {
            Role::Client => 1,
            Role::Server => 2,
        };
        Self {
            id,
            role,
            encoder,
            decoder,
            streams: HashMap::new(),
            next_stream_id,
            send_window: FlowWindow::new(DEFAULT_WINDOW),
            recv_window: FlowWindow::new(DEFAULT_WINDOW),
            recv_consumed: 0,
            pending_max_data: None,
            pending_pong: false,
            pending_ping: false,
            datagrams,
            limits,
            ack_ranges: AckRanges::new(),
            arq: ArqTracker::new(),
            pending_cc_ack: None,
        }
    }

    // ── Stream management ────────────────────────────────────────────────────

    /// Open a locally-initiated stream.
    pub fn open_stream(&mut self) -> StreamId {
        self.open_stream_with_priority(PRIORITY_DEFAULT)
    }

    /// Open a stream with explicit priority (0 = highest, 7 = lowest).
    /// Returns an error if the connection-wide stream limit would be exceeded.
    pub fn open_stream_with_priority(&mut self, priority: Priority) -> StreamId {
        self.try_open_stream_with_priority(priority)
            .expect("stream limit exceeded")
    }

    /// Fallible variant; returns None if max_streams would be exceeded.
    pub fn try_open_stream_with_priority(&mut self, priority: Priority) -> Option<StreamId> {
        if self.streams.len() as u32 >= self.limits.max_streams {
            return None;
        }
        let id = self.next_stream_id;
        self.next_stream_id += 2;
        let mut s = Stream::new(id);
        s.priority = priority;
        self.streams.insert(id, s);
        Some(id)
    }

    /// Convenience alias: open a stream that will be *pushed* to the remote peer.
    /// On a server-role session this allocates an even stream ID (2, 4, 6 …).
    /// On a client-role session this allocates an odd stream ID (1, 3, 5 …) —
    /// use `open_stream` directly; `push_stream` is just a semantic marker.
    pub fn push_stream(&mut self) -> StreamId {
        self.open_stream()
    }

    // ── Datagrams (unreliable) ───────────────────────────────────────────────

    /// Queue an unreliable datagram for sending.
    /// Returns an error if the payload exceeds max_datagram_size.
    pub fn send_datagram(&mut self, data: Bytes) -> Result<(), SeamError> {
        self.datagrams
            .send(data)
            .map_err(|sz| SeamError::BufferTooSmall {
                need: sz,
                have: self.limits.max_datagram_size,
            })
    }

    /// Read the next received datagram, if any.
    pub fn recv_datagram(&mut self) -> Option<Bytes> {
        self.datagrams.recv()
    }

    pub fn datagram_stats(&self) -> (usize, usize, u64) {
        (
            self.datagrams.send_pending(),
            self.datagrams.recv_pending(),
            self.datagrams.dropped,
        )
    }

    pub fn limits(&self) -> &SessionLimits {
        &self.limits
    }

    /// Accept a remotely-initiated stream (called when a Data frame arrives for an unknown id).
    fn get_or_create_stream(&mut self, id: StreamId) -> &mut Stream {
        self.streams.entry(id).or_insert_with(|| Stream::new(id))
    }

    // ── Sending ──────────────────────────────────────────────────────────────

    /// Write `data` into a stream's send buffer.
    pub fn send(&mut self, stream_id: StreamId, data: &[u8]) -> Result<(), SeamError> {
        let _span = tracing::trace_span!(
            "seam.stream.send",
            stream_id,
            bytes = data.len(),
            session_id = self.id,
        )
        .entered();
        self.send_window.reserve(data.len() as u64)?;
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(SeamError::UnknownStream(stream_id))?;
        stream.write(data)?;
        Ok(())
    }

    /// Mark a stream as finished (no more data will be sent). The next flush
    /// will emit a zero-byte FIN DATA frame to signal EOF to the remote peer.
    pub fn finish_stream(&mut self, stream_id: StreamId) {
        if let Some(s) = self.streams.get_mut(&stream_id) {
            s.finish();
        }
    }

    /// Packetise pending stream data into wire packets.
    /// Streams are drained in priority order (0 = highest). Within the same
    /// priority, streams are served round-robin by insertion order.
    /// Control packets (ACK, MaxData) are tagged so the connection layer can
    /// send them even when the congestion window is exhausted.
    pub fn flush(&mut self) -> Result<Vec<TaggedPacket>, SeamError> {
        let mut packets: Vec<TaggedPacket> = Vec::new();
        // Collect and sort by priority (stable sort preserves insertion order within same priority)
        let mut stream_ids: Vec<StreamId> = self.streams.keys().copied().collect();
        stream_ids.sort_by_key(|id| self.streams[id].priority);

        for sid in stream_ids {
            loop {
                let stream = self.streams.get_mut(&sid).unwrap();
                let Some((offset, chunk)) = stream.poll_send(MAX_PAYLOAD - 14) else {
                    break;
                };

                // Frame: type(1) + flags(1) + len(2) + stream_id(4) + offset(8) = 16 bytes header
                let mut frame = Vec::with_capacity(16 + chunk.len());
                frame.push(0x01u8); // FrameType::Stream
                frame.push(0u8); // flags (bit 0 = FIN)
                frame.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
                frame.extend_from_slice(&sid.to_le_bytes());
                frame.extend_from_slice(&offset.to_le_bytes());
                frame.extend_from_slice(&chunk);

                let mut out = vec![0u8; 32 + frame.len() + 16];
                let pkt_num = self.encoder.peek_next_pkt_num();
                let n = self.encoder.encode(PktType::Data, &frame, &mut out)?;
                out.truncate(n);

                self.arq.on_sent(pkt_num, bytes::Bytes::from(frame));
                packets.push(TaggedPacket {
                    is_control: false,
                    bytes: out,
                });
            }

            // After draining data, emit a zero-byte FIN frame if the stream is finished.
            let stream = self.streams.get_mut(&sid).unwrap();
            if stream.should_send_fin() {
                stream.mark_fin_flushed();
                let fin_offset = stream.send_offset();
                let mut frame = Vec::with_capacity(16);
                frame.push(0x01u8); // FrameType::Stream
                frame.push(0x01u8); // FIN flag
                frame.extend_from_slice(&(0u16).to_le_bytes()); // zero data
                frame.extend_from_slice(&sid.to_le_bytes());
                frame.extend_from_slice(&fin_offset.to_le_bytes());

                let mut out = vec![0u8; 32 + frame.len() + 16];
                let pkt_num = self.encoder.peek_next_pkt_num();
                let n = self.encoder.encode(PktType::Data, &frame, &mut out)?;
                out.truncate(n);
                self.arq.on_sent(pkt_num, bytes::Bytes::from(frame));
                packets.push(TaggedPacket {
                    is_control: false,
                    bytes: out,
                });
            }
        }

        // Drain queued datagrams: one per wire packet, encrypted as PktType::Datagram.
        // Datagrams are NOT tracked by ARQ — they are not retransmitted.
        while let Some(dg) = self.datagrams.poll_send() {
            let mut out = vec![0u8; 32 + dg.len() + 16];
            let n = self.encoder.encode(PktType::Datagram, &dg, &mut out)?;
            out.truncate(n);
            packets.push(TaggedPacket {
                is_control: false,
                bytes: out,
            });
        }

        // Emit a consolidated ACK frame if we owe the peer one.
        if self.ack_ranges.has_pending_ack() {
            let frame = self.ack_ranges.build_frame();
            let mut out = vec![0u8; 32 + frame.len() + 16];
            let n = self.encoder.encode(PktType::Ack, &frame, &mut out)?;
            out.truncate(n);
            packets.push(TaggedPacket {
                is_control: true,
                bytes: out,
            });
        }

        // Emit a MaxData frame if the receive window needs extending.
        if let Some(new_limit) = self.pending_max_data.take() {
            let frame = new_limit.to_be_bytes().to_vec();
            let mut out = vec![0u8; 32 + frame.len() + 16];
            let n = self.encoder.encode(PktType::MaxData, &frame, &mut out)?;
            out.truncate(n);
            packets.push(TaggedPacket {
                is_control: true,
                bytes: out,
            });
            self.recv_window.update_limit(new_limit);
        }

        // Emit a Pong in response to the peer's Ping.
        if self.pending_pong {
            self.pending_pong = false;
            let mut out = vec![0u8; 32 + 16];
            let n = self.encoder.encode(PktType::Pong, b"", &mut out)?;
            out.truncate(n);
            packets.push(TaggedPacket {
                is_control: true,
                bytes: out,
            });
        }

        // Emit a Ping if the application asked for one (keepalive).
        if self.pending_ping {
            self.pending_ping = false;
            let mut out = vec![0u8; 32 + 16];
            let n = self.encoder.encode(PktType::Ping, b"", &mut out)?;
            out.truncate(n);
            packets.push(TaggedPacket {
                is_control: true,
                bytes: out,
            });
        }

        Ok(packets)
    }

    /// Does the session owe the peer an ACK frame?
    pub fn has_pending_ack(&self) -> bool {
        self.ack_ranges.has_pending_ack()
    }

    /// Does the session need to send a MaxData window-update to the peer?
    pub fn has_pending_max_data(&self) -> bool {
        self.pending_max_data.is_some()
    }

    /// Queue a Ping frame for the next flush.
    pub fn ping(&mut self) {
        self.pending_ping = true;
    }

    // ── Receiving ────────────────────────────────────────────────────────────

    /// Process an incoming wire packet. Returns events.
    pub fn receive_packet(&mut self, buf: &mut [u8]) -> Result<Vec<SessionEvent>, SeamError> {
        let _span = tracing::trace_span!(
            "seam.stream.recv",
            bytes = buf.len(),
            session_id = self.id,
        )
        .entered();
        let (pkt_type, pkt_num, payload) = self.decoder.decode(buf)?;
        let mut events = Vec::new();

        // An "ack-eliciting" packet triggers an ACK to the peer. ACK frames
        // themselves are NOT ack-eliciting (prevents infinite ACK chatter).
        // Pong is also non-ack-eliciting so a Ping/Pong pair doesn't spiral.
        let ack_eliciting = !matches!(
            pkt_type,
            PktType::Ack | PktType::Chaff | PktType::PathProbe | PktType::MaxData | PktType::Pong
        );
        self.ack_ranges.on_received(pkt_num, ack_eliciting);

        match pkt_type {
            PktType::Data => {
                let ev = self.handle_data_frame(payload.to_vec())?;
                events.extend(ev);
            }
            PktType::Ack => {
                self.handle_ack_frame(payload)?;
            }
            PktType::MaxData if payload.len() >= 8 => {
                let new_limit = u64::from_be_bytes(payload[..8].try_into().unwrap());
                self.send_window.update_limit(new_limit);
            }
            PktType::MaxData => {}
            PktType::Ping => {
                self.pending_pong = true;
            }
            PktType::Pong => {
                // No-op: receipt resets the connection-level idle timer.
            }
            PktType::SessionTicket => {
                events.push(SessionEvent::SessionTicket(payload.to_vec()));
            }
            PktType::Close => {
                events.push(SessionEvent::Closed);
            }
            PktType::Datagram => {
                self.datagrams.receive(Bytes::copy_from_slice(payload));
                events.push(SessionEvent::DatagramReceived);
            }
            _ => {}
        }
        Ok(events)
    }

    fn handle_data_frame(&mut self, frame: Vec<u8>) -> Result<Vec<SessionEvent>, SeamError> {
        // Parse: type(1) + flags(1) + len(2) + stream_id(4) + offset(8) + data
        if frame.len() < 16 {
            return Ok(vec![]);
        }
        let data_len = u16::from_le_bytes([frame[2], frame[3]]) as usize;
        let stream_id = u32::from_le_bytes([frame[4], frame[5], frame[6], frame[7]]);
        let offset = u64::from_le_bytes(frame[8..16].try_into().unwrap());
        let is_fin = frame[1] & 0x01 != 0;

        if frame.len() < 16 + data_len {
            return Ok(vec![]);
        }
        let data = bytes::Bytes::copy_from_slice(&frame[16..16 + data_len]);

        let mut events = Vec::new();
        let is_new = !self.streams.contains_key(&stream_id);
        if is_new {
            // Remotely-initiated streams must have opposite parity from local streams.
            // Client opens odd IDs; server opens even IDs. Reject violations to prevent
            // ID-space collisions and detect misbehaving peers early.
            if stream_id % 2 == self.role.local_parity() {
                return Err(SeamError::ProtocolViolation(format!(
                    "stream {stream_id} parity matches local role {:?}; remote must use opposite parity",
                    self.role
                )));
            }
            events.push(SessionEvent::NewStream(stream_id));
        }
        // Track receive-side consumption and schedule a MaxData when the peer's
        // send window is 50% consumed, so it doesn't stall waiting for credits.
        self.recv_consumed += data_len as u64;
        if self.recv_consumed * 2 > self.recv_window.limit() && self.pending_max_data.is_none() {
            self.pending_max_data = Some(self.recv_consumed + DEFAULT_WINDOW);
        }

        let stream = self.get_or_create_stream(stream_id);
        stream.receive(offset, data, is_fin)?;
        events.push(SessionEvent::DataAvailable(stream_id));
        if is_fin || stream.is_recv_finished() {
            events.push(SessionEvent::StreamFinished(stream_id));
        }
        Ok(events)
    }

    fn handle_ack_frame(&mut self, frame: &[u8]) -> Result<(), SeamError> {
        let Some((_largest, _delay_us, ranges)) = parse_ack_frame(frame) else {
            return Ok(());
        };
        // Each (start, end) is inclusive. ACK every packet number in the range.
        // Accumulate bytes_acked and pick the best (non-zero) RTT sample.
        let mut total_bytes: u64 = 0;
        let mut rtt_sample: Option<Duration> = None;
        for (start, end) in ranges {
            for pn in start..=end {
                if let Some((rtt, bytes)) = self.arq.on_ack(pn) {
                    total_bytes += bytes as u64;
                    // Prefer a genuine RTT sample over a Karn-excluded zero.
                    if rtt > Duration::ZERO {
                        rtt_sample = Some(rtt);
                    } else if rtt_sample.is_none() {
                        // No real sample yet; keep None so CC gets a real value later.
                    }
                }
            }
        }
        if total_bytes > 0 {
            // Use best available RTT; fall back to a conservative 100 ms if none.
            let rtt = rtt_sample.unwrap_or(Duration::from_millis(100));
            // Merge with any already-pending CC feedback (e.g. multiple ACK frames).
            self.pending_cc_ack = Some(match self.pending_cc_ack.take() {
                Some((prev_bytes, prev_rtt)) => (prev_bytes + total_bytes, prev_rtt.min(rtt)),
                None => (total_bytes, rtt),
            });
        }
        Ok(())
    }

    /// Drain accumulated congestion-control feedback from the last ACK frame(s).
    /// Returns `Some((bytes_acked, rtt))` if new feedback is available, `None` otherwise.
    /// The caller (connection layer) should pass these to `cc.on_ack(bytes, rtt)`.
    pub fn drain_cc_ack(&mut self) -> Option<(u64, Duration)> {
        self.pending_cc_ack.take()
    }

    // ── Read ─────────────────────────────────────────────────────────────────

    pub fn read(
        &mut self,
        stream_id: StreamId,
        out: &mut Vec<u8>,
        max: usize,
    ) -> Result<usize, SeamError> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(SeamError::UnknownStream(stream_id))?;
        Ok(stream.read(out, max))
    }

    // ── Transport helpers ────────────────────────────────────────────────────

    /// Encode a single non-stream packet (e.g. Chaff, PathProbe) using session keys.
    pub fn encode_raw(
        &self,
        pkt_type: PktType,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, SeamError> {
        self.encoder.encode(pkt_type, payload, out)
    }

    pub fn arq_in_flight(&self) -> usize {
        self.arq.in_flight_count()
    }

    pub fn srtt_us(&self) -> u64 {
        self.arq.srtt().as_micros() as u64
    }

    /// Drain ARQ packets that have exceeded their RTO. Returns (pkt_num, data) pairs.
    pub fn drain_retransmits(&mut self) -> Vec<(u64, bytes::Bytes)> {
        self.arq.drain_expired()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{decoder::PacketDecoder, encoder::PacketEncoder, keys::PacketKeys};

    fn make_session_pair() -> (Session, Session) {
        let secret = [0x42u8; 32];
        let keys_a = PacketKeys::derive_from_secret(&secret);
        let keys_b = PacketKeys::derive_from_secret(&secret);
        let client = Session::with_role(
            1,
            Role::Client,
            PacketEncoder::new(keys_a.clone(), 1),
            PacketDecoder::new(keys_b.clone()),
        );
        let server = Session::with_role(
            1,
            Role::Server,
            PacketEncoder::new(keys_b, 1),
            PacketDecoder::new(keys_a),
        );
        (client, server)
    }

    #[test]
    fn server_push_stream_allocates_even_ids() {
        let (_, mut server) = make_session_pair();
        let id1 = server.push_stream();
        let id2 = server.push_stream();
        assert_eq!(id1 % 2, 0, "server push_stream should allocate even IDs");
        assert_eq!(id2 % 2, 0);
        assert_eq!(id1, 2);
        assert_eq!(id2, 4);
    }

    #[test]
    fn client_open_stream_allocates_odd_ids() {
        let (mut client, _) = make_session_pair();
        let id1 = client.open_stream();
        let id2 = client.open_stream();
        assert_eq!(id1 % 2, 1, "client open_stream should allocate odd IDs");
        assert_eq!(id2 % 2, 1);
        assert_eq!(id1, 1);
        assert_eq!(id2, 3);
    }

    #[test]
    fn server_push_data_received_as_new_stream_by_client() {
        let (mut client, mut server) = make_session_pair();

        // Server opens a push stream and sends data
        let sid = server.push_stream(); // stream 2 (even, server-initiated)
        server.send(sid, b"pushed from server").unwrap();
        let pkts = server.flush().unwrap();
        assert!(!pkts.is_empty());

        // Client receives the packet
        let events = client.receive_packet(&mut pkts[0].bytes.clone()).unwrap();
        let has_new = events
            .iter()
            .any(|e| matches!(e, SessionEvent::NewStream(2)));
        assert!(
            has_new,
            "client should see NewStream(2) for server-pushed stream"
        );

        let mut out = Vec::new();
        let n = client.read(sid, &mut out, 256).unwrap();
        assert_eq!(&out[..n], b"pushed from server");
    }

    #[test]
    fn wrong_parity_stream_id_rejected() {
        let (mut client, mut server) = make_session_pair();

        // Client opens stream 1 and sends — this is valid (client initiates odd ID)
        let sid = client.open_stream();
        assert_eq!(sid, 1);
        client.send(sid, b"ping").unwrap();
        let pkts = client.flush().unwrap();

        // Server receives it fine (server role, parity=0; stream 1 has parity 1 — remote ✓)
        let events = server.receive_packet(&mut pkts[0].bytes.clone()).unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, SessionEvent::NewStream(1)))
        );

        // Now craft a frame as if the server received a NEW stream with even ID 2 from the client.
        // This would be a protocol violation: server (local_parity=0) receiving a new stream
        // with even ID looks like the server itself initiated it, not the client.
        let sid2 = server.push_stream(); // allocates stream 2 on server side
        server.send(sid2, b"bad frame").unwrap();
        let _bad_pkts = server.flush().unwrap();

        // Send that back to the server itself — server receiving its own even-ID stream
        // as if it's new (it already knows about stream 2, so it won't trigger the check).
        // Instead test via client: client (local_parity=1) should reject new stream with odd ID
        // (client wouldn't have opened stream 3 yet, and receiving it would be a violation).
        // We achieve this by having the client send stream 3 to server, then server echoes
        // it back to client — but client already knows about stream 1. So let's test directly:
        // open stream 3 on client, send to server; server relays back to a fresh client.
        let (mut client2, mut server2) = make_session_pair();
        let bad_sid = client2.open_stream(); // stream 1
        assert_eq!(bad_sid, 1);
        client2.send(bad_sid, b"data").unwrap();
        let bad_pkts2 = client2.flush().unwrap();
        // server2 receives stream 1 fine (opposite parity)
        let evs = server2
            .receive_packet(&mut bad_pkts2[0].bytes.clone())
            .unwrap();
        assert!(evs.iter().any(|e| matches!(e, SessionEvent::NewStream(1))));

        // Now manufacture a violation: server2 (local_parity=0) receiving a NEW even-ID stream.
        // We reuse the server push packet from the other pair — server received its own packet.
        // Actually the simplest check: route bad_pkts (server→client path) to another server2.
        // server2 would decrypt it wrong (different keys). Skip that.
        // The cleanest direct unit test: use same-key pair where sender and receiver share keys.
        let secret = [0xDEu8; 32];
        let keys = PacketKeys::derive_from_secret(&secret);
        let mut sender = Session::with_role(
            99,
            Role::Client, // sends odd IDs
            PacketEncoder::new(keys.clone(), 99),
            PacketDecoder::new(keys.clone()),
        );
        let mut receiver = Session::with_role(
            99,
            Role::Client, // also client role — will reject odd-ID NEW streams from "peer"
            PacketEncoder::new(keys.clone(), 99),
            PacketDecoder::new(keys.clone()),
        );
        // sender opens stream 1 (odd) and sends; receiver (client) sees a NEW stream 1
        // with same parity as its own local_parity(1) → violation
        let vsid = sender.open_stream();
        assert_eq!(vsid, 1);
        sender.send(vsid, b"violation").unwrap();
        let vpkts = sender.flush().unwrap();
        let result = receiver.receive_packet(&mut vpkts[0].bytes.clone());
        assert!(
            matches!(result, Err(SeamError::ProtocolViolation(_))),
            "should reject stream with same parity as receiver's local role: {result:?}"
        );
    }
}
