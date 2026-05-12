//! High-level Client / Server API.
//!
//! These types wrap the lower-level [`Connection`] and [`Endpoint`] machinery
//! behind an ergonomic interface:
//!
//! ```no_run
//! # use seam_protocol::{api::{Client, Server}, handshake::IdentityKeypair};
//! # async fn example() -> Result<(), seam_protocol::SeamError> {
//! // Server side
//! let id = IdentityKeypair::generate();
//! let mut server = Server::bind("0.0.0.0:4433".parse().unwrap(), id).await?;
//! let conn = server.accept().await.unwrap();
//!
//! // Client side
//! let id = IdentityKeypair::generate();
//! let client = Client::bind("0.0.0.0:0".parse().unwrap(), id).await?;
//! // let conn = client.connect(server_addr, &x25519, &kem_pk).await?;
//! # Ok(())
//! # }
//! ```

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::{
    error::SeamError,
    handshake::{CookieFactory, IdentityKeypair},
    session::SessionEvent,
    session::stream::StreamId,
    transport::connection::Connection,
};

const MAX_UDP: usize = 65535;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

fn set_socket_buffers(socket: &UdpSocket, size: i32) {
    let fd = socket.as_raw_fd();
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &size as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &size as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
    }
}

pub(crate) type SharedConn = Arc<Mutex<Connection>>;

// ── SeamConnWriter ────────────────────────────────────────────────────────────

/// Shareable write half of a [`SeamConn`], produced by [`SeamConn::split`].
///
/// Holds an `Arc<Mutex<Connection>>` so it can be cloned and shared across
/// tasks. Use [`SeamMux`](crate::tunnel::SeamMux) unless you need raw access.
pub struct SeamConnWriter {
    pub(crate) inner: SharedConn,
}

impl SeamConnWriter {
    /// Open a locally-initiated stream. Returns the new stream ID.
    pub async fn open_stream(&self) -> StreamId {
        self.inner
            .lock()
            .await
            .session
            .as_mut()
            .expect("not established")
            .open_stream()
    }

    /// Open a stream for server-push (semantic alias for `open_stream`).
    pub async fn push_stream(&self) -> StreamId {
        self.inner
            .lock()
            .await
            .session
            .as_mut()
            .expect("not established")
            .push_stream()
    }

    /// Write `data` into stream `sid` and flush to the network.
    pub async fn write(&self, sid: StreamId, data: &[u8]) -> Result<(), SeamError> {
        let mut g = self.inner.lock().await;
        g.session
            .as_mut()
            .ok_or_else(|| SeamError::HandshakeFailed("not connected".into()))?
            .send(sid, data)?;
        g.flush().await
    }

    /// Read buffered bytes from stream `sid` (up to `max`).
    pub async fn read(&self, sid: StreamId, max: usize) -> Result<Vec<u8>, SeamError> {
        let mut g = self.inner.lock().await;
        let mut out = Vec::new();
        if let Some(session) = g.session.as_mut() {
            let _ = session.read(sid, &mut out, max); // ignore UnknownStream (stream may not have data yet)
        }
        Ok(out)
    }

    /// Mark stream `sid` as finished and flush a FIN DATA frame to the peer.
    /// The peer will see EOF on its read side for this stream.
    pub async fn send_fin(&self, sid: StreamId) {
        let mut g = self.inner.lock().await;
        if let Some(session) = g.session.as_mut() {
            session.finish_stream(sid);
        }
        let _ = g.flush().await;
    }
}

// ── SeamConn ──────────────────────────────────────────────────────────────────

/// An established Seam connection. Provides stream I/O and datagram sending.
pub struct SeamConn {
    pub(crate) inner: SharedConn,
    pub(crate) events: mpsc::UnboundedReceiver<SessionEvent>,
}

impl SeamConn {
    /// Open a locally-initiated stream. Returns the new stream ID.
    pub async fn open_stream(&self) -> StreamId {
        self.inner
            .lock()
            .await
            .session
            .as_mut()
            .expect("not established")
            .open_stream()
    }

    /// Open a stream for server-push (semantic alias for `open_stream`).
    /// On a server-role connection this allocates even stream IDs.
    pub async fn push_stream(&self) -> StreamId {
        self.inner
            .lock()
            .await
            .session
            .as_mut()
            .expect("not established")
            .push_stream()
    }

    /// Write `data` into stream `sid` and flush to the network.
    pub async fn write(&self, sid: StreamId, data: &[u8]) -> Result<(), SeamError> {
        let mut guard = self.inner.lock().await;
        guard
            .session
            .as_mut()
            .expect("not established")
            .send(sid, data)?;
        guard.flush().await
    }

    /// Read buffered bytes from stream `sid` (up to `max`).
    /// Returns immediately with whatever is buffered; use [`read_event`] to
    /// wait until `DataAvailable` before calling this.
    pub async fn read(&self, sid: StreamId, max: usize) -> Result<Vec<u8>, SeamError> {
        let mut guard = self.inner.lock().await;
        let mut out = Vec::new();
        guard
            .session
            .as_mut()
            .expect("not established")
            .read(sid, &mut out, max)?;
        Ok(out)
    }

    /// Wait for the next session event (stream data, datagram, close, …).
    pub async fn read_event(&mut self) -> Option<SessionEvent> {
        self.events.recv().await
    }

    /// Send an unreliable datagram (≤ max_datagram_size, default 1200 B).
    pub async fn send_datagram(&self, data: Bytes) -> Result<(), SeamError> {
        let mut guard = self.inner.lock().await;
        guard
            .session
            .as_mut()
            .expect("not established")
            .send_datagram(data)?;
        guard.flush().await
    }

    /// Drain the next received datagram, if any.
    pub async fn recv_datagram(&self) -> Option<Bytes> {
        self.inner.lock().await.session.as_mut()?.recv_datagram()
    }

    /// Initiate a graceful close.
    pub async fn close(&self) {
        self.inner.lock().await.close();
    }

    /// Remote peer address.
    pub async fn remote_addr(&self) -> SocketAddr {
        self.inner.lock().await.remote
    }

    /// Session ID (shared with the peer after handshake).
    pub async fn session_id(&self) -> u64 {
        self.inner
            .lock()
            .await
            .session
            .as_ref()
            .map(|s| s.id)
            .unwrap_or(0)
    }

    /// Flush pending stream data and background operations (retransmits, chaff, probes).
    pub async fn tick(&self) -> Result<(), SeamError> {
        let mut guard = self.inner.lock().await;
        guard.flush().await?;
        guard.retransmit_expired().await?;
        guard.maybe_send_chaff().await?;
        guard.maybe_send_probe().await
    }

    /// Split into a shareable writer and an exclusive event receiver.
    /// Use `SeamMux::new(conn)` instead unless you need raw access.
    pub fn split(self) -> (SeamConnWriter, mpsc::UnboundedReceiver<SessionEvent>) {
        (SeamConnWriter { inner: self.inner }, self.events)
    }
}

// ── Client ────────────────────────────────────────────────────────────────────

/// A client endpoint. Binds one UDP socket and can open connections to servers.
pub struct Client {
    socket: Arc<UdpSocket>,
    identity: Arc<IdentityKeypair>,
    _recv_task: Option<JoinHandle<()>>,
}

impl Client {
    /// Bind to `local_addr` and prepare to connect.
    pub async fn bind(
        local_addr: SocketAddr,
        identity: IdentityKeypair,
    ) -> Result<Self, SeamError> {
        let socket = UdpSocket::bind(local_addr)
            .await
            .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
        set_socket_buffers(&socket, 8 * 1024 * 1024);
        let socket = Arc::new(socket);
        Ok(Self {
            socket,
            identity: Arc::new(identity),
            _recv_task: None,
        })
    }

    /// Connect to a server at `remote`. Drives the 1.5-RTT cookie + noise handshake
    /// to completion before returning, then spawns a background recv loop.
    pub async fn connect(
        &mut self,
        remote: SocketAddr,
        server_x25519: &[u8; 32],
        server_kem_pk: &pqcrypto_kyber::kyber768::PublicKey,
    ) -> Result<SeamConn, SeamError> {
        let (mut conn, events) = Connection::connect(
            self.socket.clone(),
            remote,
            &self.identity,
            server_x25519,
            server_kem_pk,
        )
        .await?;

        // Drive handshake: receive packets until Established.
        let mut buf = vec![0u8; MAX_UDP];
        while !conn.is_established() {
            let (n, _) = tokio::time::timeout(HANDSHAKE_TIMEOUT, self.socket.recv_from(&mut buf))
                .await
                .map_err(|_| SeamError::HandshakeFailed("handshake timed out".into()))?
                .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
            conn.on_packet(&mut buf[..n].to_vec()).await?;
        }

        let inner: SharedConn = Arc::new(Mutex::new(conn));

        // Spawn ongoing recv loop for data after handshake.
        let socket_clone = self.socket.clone();
        let inner_clone = inner.clone();
        let handle = tokio::spawn(client_recv_loop(socket_clone, inner_clone));
        self._recv_task = Some(handle);

        Ok(SeamConn { inner, events })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

async fn client_recv_loop(socket: Arc<UdpSocket>, conn: SharedConn) {
    let mut buf = vec![0u8; MAX_UDP];
    loop {
        let (n, _) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => break,
        };
        let mut pkt = buf[..n].to_vec();
        let mut guard = conn.lock().await;
        if guard.is_closed() {
            break;
        }
        let _ = guard.on_packet(&mut pkt).await;
    }
}

// ── Server ────────────────────────────────────────────────────────────────────

/// A server endpoint. Binds a UDP socket, handles DDoS-resistant cookie
/// challenges, and surfaces fully-established connections via [`accept`].
pub struct Server {
    socket: Arc<UdpSocket>,
    accept_rx: mpsc::UnboundedReceiver<SeamConn>,
    _recv_task: JoinHandle<()>,
}

impl Server {
    /// Bind to `local_addr` and start accepting connections.
    pub async fn bind(
        local_addr: SocketAddr,
        identity: IdentityKeypair,
    ) -> Result<Self, SeamError> {
        let socket = UdpSocket::bind(local_addr)
            .await
            .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
        set_socket_buffers(&socket, 8 * 1024 * 1024);
        let socket = Arc::new(socket);

        let identity = Arc::new(identity);

        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
        let cookie_factory = Arc::new(CookieFactory::new(secret));

        let (accept_tx, accept_rx) = mpsc::unbounded_channel();

        let recv_task = tokio::spawn(server_recv_loop(
            socket.clone(),
            identity,
            cookie_factory,
            accept_tx,
        ));

        Ok(Self {
            socket,
            accept_rx,
            _recv_task: recv_task,
        })
    }

    /// Wait for the next fully-established inbound connection.
    /// Returns `None` if the server socket has been dropped.
    pub async fn accept(&mut self) -> Option<SeamConn> {
        self.accept_rx.recv().await
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

async fn server_recv_loop(
    socket: Arc<UdpSocket>,
    identity: Arc<IdentityKeypair>,
    cookie_factory: Arc<CookieFactory>,
    accept_tx: mpsc::UnboundedSender<SeamConn>,
) {
    let mut buf = vec![0u8; MAX_UDP];
    // Per-remote connection table.
    let mut conns: HashMap<SocketAddr, SharedConn> = HashMap::new();
    // Event receivers, held until the connection establishes.
    let mut pending_events: HashMap<SocketAddr, mpsc::UnboundedReceiver<SessionEvent>> =
        HashMap::new();
    // Addresses already delivered to the accept channel.
    let mut delivered: HashSet<SocketAddr> = HashSet::new();

    loop {
        let (n, remote) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => break,
        };

        let mut pkt = buf[..n].to_vec();

        if let Some(conn) = conns.get(&remote) {
            let was_established = conn.lock().await.is_established();
            {
                let _ = conn.lock().await.on_packet(&mut pkt).await;
            }
            let is_established = conn.lock().await.is_established();

            if !was_established && is_established && !delivered.contains(&remote) {
                delivered.insert(remote);
                if let Some(events) = pending_events.remove(&remote) {
                    let _ = accept_tx.send(SeamConn {
                        inner: conn.clone(),
                        events,
                    });
                }
            }

            if conn.lock().await.is_closed() {
                conns.remove(&remote);
                delivered.remove(&remote);
            }
        } else {
            // Unknown remote — issue stateless cookie challenge (no heap allocation until
            // the cookie is echoed back and verified in a subsequent packet).
            let (new_conn, events) = match Connection::accept_challenge(
                socket.clone(),
                remote,
                identity.clone(),
                cookie_factory.clone(),
            )
            .await
            {
                Ok(v) => v,
                Err(_) => continue,
            };
            let shared: SharedConn = Arc::new(Mutex::new(new_conn));
            pending_events.insert(remote, events);
            conns.insert(remote, shared);
        }
    }
}
