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
    stream_senders: HashMap<StreamId, mpsc::UnboundedSender<Bytes>>,
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
        self.make_stream(sid)
    }

    /// Wait for the remote peer to push a new stream.
    /// Returns `None` when the connection is closed.
    pub async fn accept_stream(&self) -> Option<SeamStream> {
        let permit = self.pending_sem.acquire().await.ok()?;
        permit.forget();
        let sid = self.state.lock().unwrap().pending_streams.pop_front()?;
        Some(self.make_stream(sid))
    }

    fn make_stream(&self, sid: StreamId) -> SeamStream {
        let (data_tx, data_rx) = mpsc::unbounded_channel::<Bytes>();
        let (write_tx, write_rx) = mpsc::unbounded_channel::<Bytes>();
        self.state.lock().unwrap().stream_senders.insert(sid, data_tx);
        tokio::spawn(stream_write_loop(sid, self.writer.clone(), write_rx));
        SeamStream { sid, write_tx, data_rx, read_buf: BytesMut::new() }
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
                state.lock().unwrap().pending_streams.push_back(sid);
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
}

/// A single multiplexed stream. Implements `AsyncRead + AsyncWrite + Unpin`.
pub struct SeamStream {
    #[allow(dead_code)]
    sid: StreamId,
    write_tx: mpsc::UnboundedSender<Bytes>,
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
        match self.write_tx.send(Bytes::copy_from_slice(buf)) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Unpin for SeamStream {}
