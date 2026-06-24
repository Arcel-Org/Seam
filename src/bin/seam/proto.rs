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

/// Read a complete frame, accumulating into `buf` as needed.
pub async fn read_frame(conn: &mut SeamConn, sid: StreamId, buf: &mut Vec<u8>) -> Result<Vec<u8>> {
    loop {
        if buf.len() >= 4 {
            let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
            if buf.len() >= 4 + len {
                let frame = buf[4..4 + len].to_vec();
                buf.drain(..4 + len);
                return Ok(frame);
            }
        }
        match conn.read_event().await {
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
