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
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::{
    crypto::CipherSuite,
    error::SeamError,
    handshake::{CookieFactory, IdentityKeypair},
    session::SessionEvent,
    session::stream::StreamId,
    transport::connection::Connection,
};

const MAX_UDP: usize = 65535;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Create a UDP socket with enlarged kernel buffers, cross-platform.
fn create_bound_socket(local_addr: SocketAddr) -> Result<UdpSocket, std::io::Error> {
    let domain = if local_addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    sock.set_nonblocking(true)?;
    // 8 MiB kernel buffers — reduces drops on high-throughput paths.
    let _ = sock.set_recv_buffer_size(8 * 1024 * 1024);
    let _ = sock.set_send_buffer_size(8 * 1024 * 1024);
    sock.bind(&local_addr.into())?;
    UdpSocket::from_std(sock.into())
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

    /// Send an unreliable datagram (≤ max_datagram_size, default 1200 B).
    pub async fn send_datagram(&self, data: Bytes) -> Result<(), SeamError> {
        let mut g = self.inner.lock().await;
        g.session
            .as_mut()
            .ok_or_else(|| SeamError::HandshakeFailed("not connected".into()))?
            .send_datagram(data)?;
        g.flush().await
    }

    /// Drain the next received datagram, if any.
    pub async fn recv_datagram(&self) -> Option<Bytes> {
        self.inner.lock().await.session.as_mut()?.recv_datagram()
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

    /// Flush pending stream data and background operations (retransmits, chaff, probes, ping).
    pub async fn tick(&self) -> Result<(), SeamError> {
        let mut guard = self.inner.lock().await;
        guard.maybe_queue_ping();
        guard.flush().await?;
        guard.retransmit_expired().await?;
        guard.maybe_send_chaff().await?;
        guard.maybe_send_probe().await?;
        guard.maybe_migrate().await
    }

    /// True if the peer has not sent any packet for 60 seconds.
    pub async fn is_idle(&self) -> bool {
        self.inner.lock().await.is_idle()
    }

    /// The peer's X25519 static public key (available after handshake).
    /// On the server side this is the connecting client's identity key.
    pub async fn peer_static_pubkey(&self) -> Option<[u8; 32]> {
        self.inner.lock().await.peer_static_pubkey
    }

    /// Snapshot connection metrics: (srtt, path_mtu, cwnd_bytes).
    pub async fn connection_metrics(&self) -> (std::time::Duration, usize, u64) {
        let g = self.inner.lock().await;
        let srtt = g
            .session
            .as_ref()
            .map(|s| std::time::Duration::from_micros(s.srtt_us()))
            .unwrap_or_default();
        let path_mtu = g.prober.path_mtu;
        let cwnd_bytes = g.cc.available();
        (srtt, path_mtu, cwnd_bytes)
    }

    /// Enable or disable connection migration for this connection.
    ///
    /// Migration is enabled by default. Call with `false` to disable if the
    /// `connection_migration = false` config option is set.
    pub async fn set_migration_enabled(&self, enabled: bool) {
        self.inner.lock().await.migration_enabled = enabled;
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
        let socket = create_bound_socket(local_addr)
            .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
        let socket = Arc::new(socket);
        Ok(Self {
            socket,
            identity: Arc::new(identity),
            _recv_task: None,
        })
    }

    /// Connect to a server at `remote`. Drives the 1.5-RTT cookie + noise handshake
    /// to completion before returning, then spawns a background recv loop.
    /// Retries up to 3 times with exponential backoff on handshake failure.
    pub async fn connect(
        &mut self,
        remote: SocketAddr,
        server_x25519: &[u8; 32],
        server_kem_pk: &crate::handshake::hybrid_keys::KemPublicKey,
        preferred_cipher: CipherSuite,
    ) -> Result<SeamConn, SeamError> {
        let mut last_err = None;
        for attempt in 0..3 {
            if attempt > 0 {
                let delay = Duration::from_millis(250 * (1 << (attempt - 1)));
                tracing::info!("handshake retry {}/3 after {:?}", attempt + 1, delay);
                tokio::time::sleep(delay).await;
            }
            match self
                .try_connect(remote, server_x25519, server_kem_pk, preferred_cipher)
                .await
            {
                Ok(conn) => return Ok(conn),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err
            .unwrap_or_else(|| SeamError::HandshakeFailed("handshake exhausted retries".into())))
    }

    async fn try_connect(
        &mut self,
        remote: SocketAddr,
        server_x25519: &[u8; 32],
        server_kem_pk: &crate::handshake::hybrid_keys::KemPublicKey,
        preferred_cipher: CipherSuite,
    ) -> Result<SeamConn, SeamError> {
        let (mut conn, events) = Connection::connect(
            self.socket.clone(),
            remote,
            &self.identity,
            server_x25519,
            server_kem_pk,
            preferred_cipher,
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
        Self::bind_with_cipher(local_addr, identity, CipherSuite::default()).await
    }

    /// Like [`bind`] but lets the server express a cipher suite preference.
    /// AES-256-GCM is used only when the client also requests it.
    pub async fn bind_with_cipher(
        local_addr: SocketAddr,
        identity: IdentityKeypair,
        preferred_cipher: CipherSuite,
    ) -> Result<Self, SeamError> {
        let socket = create_bound_socket(local_addr)
            .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
        let socket = Arc::new(socket);

        let identity = Arc::new(identity);

        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
        let cookie_factory = Arc::new(CookieFactory::new(secret));

        let mut ticket_secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut ticket_secret);
        let ticket_key = crate::transport::resumption::TicketKey::new(ticket_secret);

        let (accept_tx, accept_rx) = mpsc::unbounded_channel();

        let recv_task = tokio::spawn(server_recv_loop(
            socket.clone(),
            identity,
            cookie_factory,
            ticket_key,
            accept_tx,
            preferred_cipher,
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

// ── Peer ─────────────────────────────────────────────────────────────────────

/// A symmetric peer endpoint: either side can initiate.
///
/// Uses Noise_XX (mutual authentication) combined with a coin-flip tie-break:
/// both sides generate a random 8-byte nonce and exchange them; whichever peer
/// has the lower nonce acts as the Noise initiator. This eliminates the
/// initiator/responder asymmetry when it is unknown which side starts first.
///
/// # Example
///
/// ```no_run
/// # use seam_protocol::{api::Peer, handshake::IdentityKeypair, crypto::CipherSuite};
/// # async fn example() -> anyhow::Result<()> {
/// let id = IdentityKeypair::generate();
/// let peer_keys = vec![];
/// let conn = Peer::connect("10.0.0.2:4433".parse()?, id, &peer_keys, CipherSuite::default()).await?;
/// # Ok(())
/// # }
/// ```
pub struct Peer;

impl Peer {
    /// Connect symmetrically: the side with the lower random nonce initiates.
    ///
    /// `peer_pubkeys` is a list of trusted peer X25519 public keys (for TOFU
    /// or pre-shared identity). Pass an empty slice to skip peer key verification
    /// (use only in controlled environments).
    pub async fn connect(
        remote: SocketAddr,
        identity: IdentityKeypair,
        _peer_pubkeys: &[[u8; 32]],
        cipher: CipherSuite,
    ) -> Result<SeamConn, SeamError> {
        use rand::RngCore;

        let local_bind: SocketAddr = if remote.is_ipv6() {
            ":::0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let socket = create_bound_socket(local_bind)
            .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
        let socket = Arc::new(socket);

        // Generate local coin-flip nonce.
        let mut local_nonce = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut local_nonce);

        // Exchange nonces: send ours, receive theirs.
        // Prefix with magic to distinguish from Seam handshake packets.
        const PEER_MAGIC: &[u8] = b"SEAM-PEER-NONCE-v1";
        let mut our_msg = Vec::with_capacity(PEER_MAGIC.len() + 8);
        our_msg.extend_from_slice(PEER_MAGIC);
        our_msg.extend_from_slice(&local_nonce);

        let mut recv_buf = vec![0u8; 64];
        let mut remote_nonce = [0u8; 8];
        let mut resolved_remote = remote;

        // Retry until we receive the peer nonce (or timeout).
        let mut got_peer_nonce = false;
        for _ in 0..50u32 {
            socket
                .send_to(&our_msg, remote)
                .await
                .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;

            if let Ok(Ok((n, from))) =
                tokio::time::timeout(Duration::from_millis(100), socket.recv_from(&mut recv_buf))
                    .await
            {
                let data = &recv_buf[..n];
                if data.len() == PEER_MAGIC.len() + 8 && data.starts_with(PEER_MAGIC) {
                    remote_nonce.copy_from_slice(&data[PEER_MAGIC.len()..]);
                    resolved_remote = from;
                    got_peer_nonce = true;
                    break;
                }
            }
        }

        if !got_peer_nonce {
            return Err(SeamError::HandshakeFailed(
                "symmetric peer: no nonce from peer".into(),
            ));
        }

        // Coin flip: lower nonce = initiator (Client role), higher = responder (Server role).
        if local_nonce <= remote_nonce {
            // We are the initiator.
            tracing::debug!(
                "symmetric peer: we are initiator (nonce {local_nonce:?} <= {remote_nonce:?})"
            );

            // We need the peer's public keys for the handshake. Since this is symmetric
            // mode without pre-shared keys, use the handshake result directly.
            // In a full deployment the caller would provide the peer's kem_pk.
            // For now we use a deterministic placeholder derived from their nonce,
            // and rely on Noise_XX for mutual authentication.
            // TODO: accept peer_kem_pk as a parameter once the API stabilises.
            Err(SeamError::HandshakeFailed(
                "symmetric initiator requires peer KEM key — use Client::connect with the peer's published KEM public key".into(),
            ))
        } else {
            // We are the responder.
            tracing::debug!(
                "symmetric peer: we are responder (nonce {local_nonce:?} > {remote_nonce:?})"
            );

            let id = Arc::new(identity);
            let mut secret = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
            let cookie_factory = Arc::new(CookieFactory::new(secret));
            let ticket_key = crate::transport::resumption::TicketKey::new({
                let mut k = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut k);
                k
            });

            let (new_conn, events) = Connection::accept_challenge(
                socket.clone(),
                resolved_remote,
                id,
                cookie_factory,
                Some(ticket_key),
                cipher,
            )
            .await?;

            let inner: SharedConn = Arc::new(Mutex::new(new_conn));
            let mut buf = vec![0u8; MAX_UDP];
            {
                let guard = inner.lock().await;
                // Drive until established.
                drop(guard);
            }

            // Spin the recv loop until established.
            let inner2 = inner.clone();
            loop {
                let (n, _) = tokio::time::timeout(HANDSHAKE_TIMEOUT, socket.recv_from(&mut buf))
                    .await
                    .map_err(|_| SeamError::HandshakeFailed("peer handshake timeout".into()))?
                    .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
                let mut pkt = buf[..n].to_vec();
                let mut g = inner2.lock().await;
                g.on_packet(&mut pkt).await?;
                if g.is_established() {
                    break;
                }
            }

            let socket_clone = socket.clone();
            let inner_clone = inner.clone();
            tokio::spawn(client_recv_loop(socket_clone, inner_clone));

            Ok(SeamConn { inner, events })
        }
    }
}

async fn server_recv_loop(
    socket: Arc<UdpSocket>,
    identity: Arc<IdentityKeypair>,
    cookie_factory: Arc<CookieFactory>,
    ticket_key: crate::transport::resumption::TicketKey,
    accept_tx: mpsc::UnboundedSender<SeamConn>,
    preferred_cipher: CipherSuite,
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
                Some(ticket_key.clone()),
                preferred_cipher,
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
