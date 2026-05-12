use anyhow::{Result, bail};
use seam_protocol::session::stream::StreamId;
use seam_protocol::{SeamError, api::SeamConn, session::SessionEvent};

pub const HELLO: u8 = 0x01;
pub const FILE_INFO: u8 = 0x02;
pub const DATA: u8 = 0x03;
pub const DONE: u8 = 0x04;
pub const ACK: u8 = 0x05;
pub const _ERR: u8 = 0x06;

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
