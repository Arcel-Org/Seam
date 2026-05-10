//! High-level mux / stream adapters that expose Seam connections as
//! AsyncRead + AsyncWrite byte streams.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Semaphore};

use crate::{
    api::{SeamConn, SeamConnWriter},
    session::{stream::StreamId, SessionEvent},
};

struct MuxState {
    // Data senders for all active streams (both local and remote-initiated).
    stream_senders: HashMap<StreamId, mpsc::UnboundedSender<Bytes>>,
    // Pre-created receivers for remote-initiated streams not yet claimed by accept_stream().
    // Created when NewStream arrives so DataAvailable data is never dropped.
    pending_receivers: HashMap<StreamId, mpsc::UnboundedReceiver<Bytes>>,
    // Ordered queue of stream IDs ready to be returned by accept_stream().
    pending_streams: VecDeque<StreamId>,
}

/// Multiplexer over a `SeamConn`. Lets you open and accept `SeamStream`s.
///
/// Typically created with `SeamMux::new(conn)` after a successful handshake.
pub struct SeamMux {
    writer: Arc<SeamConnWriter>,
    state: Arc<Mutex<MuxState>>,
    pending_sem: Arc<Semaphore>,
}

impl SeamMux {
    pub fn new(conn: SeamConn) -> Arc<Self> {
        let (writer, events) = conn.split();
        let writer = Arc::new(writer);
        let state = Arc::new(Mutex::new(MuxState {
            stream_senders: HashMap::new(),
            pending_receivers: HashMap::new(),
            pending_streams: VecDeque::new(),
        }));
        let pending_sem = Arc::new(Semaphore::new(0));

        let mux = Arc::new(Self {
            writer: writer.clone(),
            state: state.clone(),
            pending_sem: pending_sem.clone(),
        });

        tokio::spawn(event_loop(events, writer, state, pending_sem));
        mux
    }

    /// Open a locally-initiated stream.
    pub async fn open_stream(&self) -> SeamStream {
        let sid = self.writer.open_stream().await;
        let (data_tx, data_rx) = mpsc::unbounded_channel::<Bytes>();
        let (write_tx, write_rx) = mpsc::unbounded_channel::<Bytes>();
        self.state.lock().unwrap().stream_senders.insert(sid, data_tx);
        tokio::spawn(stream_write_loop(sid, self.writer.clone(), write_rx));
        SeamStream { sid, write_tx: Some(write_tx), data_rx, read_buf: BytesMut::new() }
    }

    /// Wait for the remote peer to push a new stream.
    /// Returns `None` when the connection is closed.
    pub async fn accept_stream(&self) -> Option<SeamStream> {
        let permit = self.pending_sem.acquire().await.ok()?;
        permit.forget();
        let (sid, data_rx) = {
            let mut s = self.state.lock().unwrap();
            let sid = s.pending_streams.pop_front()?;
            let data_rx = s.pending_receivers.remove(&sid)?;
            (sid, data_rx)
        };
        let (write_tx, write_rx) = mpsc::unbounded_channel::<Bytes>();
        tokio::spawn(stream_write_loop(sid, self.writer.clone(), write_rx));
        Some(SeamStream { sid, write_tx: Some(write_tx), data_rx, read_buf: BytesMut::new() })
    }
}

async fn event_loop(
    mut events: mpsc::UnboundedReceiver<SessionEvent>,
    writer: Arc<SeamConnWriter>,
    state: Arc<Mutex<MuxState>>,
    pending_sem: Arc<Semaphore>,
) {
    while let Some(event) = events.recv().await {
        match event {
            SessionEvent::NewStream(sid) => {
                // Pre-create the data channel so DataAvailable data is never dropped
                // even if accept_stream() hasn't been called yet.
                let (data_tx, data_rx) = mpsc::unbounded_channel::<Bytes>();
                {
                    let mut s = state.lock().unwrap();
                    s.stream_senders.insert(sid, data_tx);
                    s.pending_receivers.insert(sid, data_rx);
                    s.pending_streams.push_back(sid);
                }
                pending_sem.add_permits(1);
            }
            SessionEvent::DataAvailable(sid) => {
                let data = writer.read(sid, 65536).await.unwrap_or_default();
                if !data.is_empty() {
                    let tx = state.lock().unwrap().stream_senders.get(&sid).cloned();
                    if let Some(tx) = tx {
                        let _ = tx.send(Bytes::from(data));
                    }
                }
            }
            SessionEvent::StreamFinished(sid) => {
                // Drop sender to signal EOF to the reader.
                state.lock().unwrap().stream_senders.remove(&sid);
            }
            SessionEvent::Closed => {
                pending_sem.close();
                break;
            }
            SessionEvent::DatagramReceived => {}
        }
    }
}

async fn stream_write_loop(
    sid: StreamId,
    writer: Arc<SeamConnWriter>,
    mut rx: mpsc::UnboundedReceiver<Bytes>,
) {
    while let Some(data) = rx.recv().await {
        if writer.write(sid, &data).await.is_err() {
            break;
        }
    }
    // Channel closed = caller is done writing. Send a FIN to signal EOF to the remote peer.
    writer.send_fin(sid).await;
}

/// A single multiplexed stream. Implements `AsyncRead + AsyncWrite + Unpin`.
pub struct SeamStream {
    #[allow(dead_code)]
    sid: StreamId,
    write_tx: Option<mpsc::UnboundedSender<Bytes>>,
    data_rx: mpsc::UnboundedReceiver<Bytes>,
    read_buf: BytesMut,
}

impl AsyncRead for SeamStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.read_buf.is_empty() {
            let n = buf.remaining().min(this.read_buf.len());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf.advance(n);
            return Poll::Ready(Ok(()));
        }
        match this.data_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = buf.remaining().min(data.len());
                buf.put_slice(&data[..n]);
                if data.len() > n {
                    this.read_buf.extend_from_slice(&data[n..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for SeamStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.write_tx.as_ref() {
            Some(tx) => match tx.send(Bytes::copy_from_slice(buf)) {
                Ok(()) => Poll::Ready(Ok(buf.len())),
                Err(_) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "stream closed"))),
            },
            None => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "stream shut down"))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Drop the write channel sender. The stream_write_loop will see the channel
        // close and send a FIN DATA frame to the remote peer, signalling EOF.
        self.get_mut().write_tx = None;
        Poll::Ready(Ok(()))
    }
}

impl Unpin for SeamStream {}
