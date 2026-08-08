use anyhow::{Result, bail};
use seam_protocol::session::stream::StreamId;
use seam_protocol::{SeamError, api::SeamConn, session::SessionEvent};

pub const HELLO: u8 = 0x01;
pub const FILE_INFO: u8 = 0x02;
pub const DATA: u8 = 0x03;
pub const DONE: u8 = 0x04;
pub const ACK: u8 = 0x05;
pub const RESUME: u8 = 0x06;
pub const LS: u8 = 0x07;
pub const ENTRY: u8 = 0x08;
/// BLAKE3 checksum frame: [type(1)][hash(32)]
/// Sent by the sender after all DATA frames for a file to allow the receiver
/// to verify end-to-end integrity. Receiver replies with ACK on match, or
/// returns an error if the hash does not match.
pub const CHECKSUM: u8 = 0x09;
/// PARALLEL_INIT frame: [type(1)][n_chunks(1)]
/// Sent by the sender on the control stream to announce a parallel multi-stream transfer.
/// The sender opens n_chunks additional streams and sends one chunk per stream.
/// Each chunk stream carries: [FILE_INFO frame][DATA frames...][CHECKSUM frame]
/// After all chunks are confirmed, the sender sends DONE on the control stream.
pub const PARALLEL_INIT: u8 = 0x0a;
/// CHUNK_INFO frame: [type(1)][chunk_index(1)][n_chunks(1)][offset(8)][chunk_size(8)][name_len(2)][name]
/// Sent on each chunk stream to identify which byte range to write.
pub const CHUNK_INFO: u8 = 0x0b;
/// BYE frame: sent on the control stream in place of the next HELLO to end a
/// persistent multi-round session (e.g. `seam watch` shutting down). Lets the
/// receiver exit immediately instead of waiting on connection-idle detection.
pub const BYE: u8 = 0x0c;
/// LS_PATH frame: [type(1)][path bytes]
/// Sent by `seam mount`'s client on a freshly-opened stream to list a
/// directory at an arbitrary remote path (unlike LS, whose target path is
/// fixed for the lifetime of the bootstrap process). Response is zero or
/// more ENTRY frames followed by DONE, same as LS.
pub const LS_PATH: u8 = 0x0d;
/// GET_PATH frame: [type(1)][path bytes]
/// Sent by `seam mount`'s client to fetch a file's full contents by path.
/// Response is FILE_INFO, then DATA frames until FILE_INFO's declared size
/// is reached, then CHECKSUM (BLAKE3) — the same framing `seam cp` uses for
/// a push, minus the leading HELLO/ACK negotiation (mount reads are
/// uncompressed and don't need a compression-preference handshake).
pub const GET_PATH: u8 = 0x0e;
/// STAT_PATH frame: [type(1)][path bytes]
/// Sent by `seam mount`'s client for a single-path metadata lookup
/// (getattr/lookup) without listing the whole containing directory.
/// Response is one ENTRY frame then DONE on success, or just DONE if the
/// path doesn't exist.
pub const STAT_PATH: u8 = 0x0f;

pub const COMPRESS_NONE: u8 = 0;
pub const COMPRESS_ZSTD: u8 = 1;

pub async fn send_frame(conn: &SeamConn, sid: StreamId, payload: &[u8]) -> Result<()> {
    let len = payload.len() as u32;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    // Retry on flow-control backpressure. MaxData from receiver arrives shortly.
    loop {
        match conn.write(sid, &frame).await {
            Ok(()) => return Ok(()),
            Err(SeamError::FlowControlBlocked { .. }) => {
                tokio::time::sleep(tokio::time::Duration::from_millis(2)).await;
            }
            Err(e) => return Err(anyhow::anyhow!("{e}")),
        }
    }
}

/// How often to drive `conn.tick()` while waiting for incoming frames.
///
/// `tick()` is what actually retransmits packets that missed their
/// congestion-window slot (`Connection::flush` silently drops any
/// stream/FIN packet that doesn't currently fit under `cc.available()` —
/// ARQ still believes it was sent and will retry it via RTO, but only once
/// something calls `tick()` again). The only other place that calls `tick()`
/// is the *sending* side's per-chunk loop in `copy.rs`; a receiver (or a
/// sender that has finished sending and is just waiting for the final ACK)
/// never calls it otherwise. For a burst that overflows the initial
/// congestion window and completes in well under one RTO (300ms) — e.g. any
/// multi-packet file on a fast/local link — nothing would ever retry the
/// dropped packet, and both sides would wait for each other forever. Ticking
/// here on an interval closes that gap for every caller of `read_frame`.
const TICK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

/// Read a complete frame, accumulating into `buf` as needed.
pub async fn read_frame(conn: &mut SeamConn, sid: StreamId, buf: &mut Vec<u8>) -> Result<Vec<u8>> {
    let mut ticker = tokio::time::interval(TICK_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        if buf.len() >= 4 {
            let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
            if buf.len() >= 4 + len {
                let frame = buf[4..4 + len].to_vec();
                buf.drain(..4 + len);
                return Ok(frame);
            }
        }
        tokio::select! {
            event = conn.read_event() => {
                match event {
                    Some(SessionEvent::DataAvailable(s)) if s == sid => {
                        let data = conn
                            .read(s, 65536)
                            .await
                            .map_err(|e| anyhow::anyhow!("{e}"))?;
                        buf.extend_from_slice(&data);
                    }
                    Some(SessionEvent::StreamFinished(s)) if s == sid => {
                        bail!("stream {s} closed before frame complete");
                    }
                    Some(SessionEvent::Closed) | None => bail!("connection closed"),
                    _ => {}
                }
            }
            _ = ticker.tick() => {
                let _ = conn.tick().await;
            }
        }
    }
}

/// Like `read_frame`, but distinguishes a clean end-of-session from a real
/// error: returns `Ok(None)` if the peer closes the connection at a frame
/// boundary (no partial frame buffered). Used by persistent multi-round
/// receivers (e.g. `seam watch`'s reused connection) to tell "sender is done
/// for good" apart from "sender disconnected mid-transfer".
pub async fn read_frame_opt(
    conn: &mut SeamConn,
    sid: StreamId,
    buf: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>> {
    let mut ticker = tokio::time::interval(TICK_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        if buf.len() >= 4 {
            let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
            if buf.len() >= 4 + len {
                let frame = buf[4..4 + len].to_vec();
                buf.drain(..4 + len);
                return Ok(Some(frame));
            }
        }
        let event = tokio::select! {
            event = conn.read_event() => event,
            _ = ticker.tick() => {
                let _ = conn.tick().await;
                continue;
            }
        };
        match event {
            Some(SessionEvent::DataAvailable(s)) if s == sid => {
                let data = conn
                    .read(s, 65536)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                buf.extend_from_slice(&data);
            }
            Some(SessionEvent::StreamFinished(s)) if s == sid => {
                if buf.is_empty() {
                    return Ok(None);
                }
                bail!("stream {s} closed before frame complete");
            }
            Some(SessionEvent::Closed) | None => {
                if buf.is_empty() {
                    return Ok(None);
                }
                bail!("connection closed before frame complete");
            }
            _ => {}
        }
    }
}

/// Wait for the control stream to open (NewStream event), return its ID.
pub async fn wait_for_stream(conn: &mut SeamConn) -> Result<StreamId> {
    loop {
        match conn.read_event().await {
            Some(SessionEvent::NewStream(sid)) => return Ok(sid),
            Some(SessionEvent::Closed) | None => bail!("connection closed before stream opened"),
            _ => {}
        }
    }
}
