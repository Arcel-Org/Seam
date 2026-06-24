/// UDP Endpoint: binds a socket, runs the recv loop, dispatches packets to connections.
///
/// Server-side DDoS protection flow:
///   Unknown remote → send stateless cookie challenge (no heap allocation)
///   Cookie echo received → verify → allocate Connection → process msg1
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::{
    crypto::CipherSuite,
    error::SeamError,
    handshake::{CookieFactory, IdentityKeypair},
    session::SessionEvent,
    transport::connection::Connection,
};

const MAX_UDP: usize = 65535;

/// Default maximum number of simultaneous connections an endpoint will accept.
///
/// When this limit is reached the server sends a stateless cookie challenge as
/// usual but drops the connection after cookie verification, effectively silently
/// rejecting the new session without revealing internal resource state.  Operators
/// can raise or lower this via [`EndpointConfig::max_connections`].
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;

pub type SharedConn = Arc<Mutex<Connection>>;

/// Configuration knobs for [`Endpoint::bind_with_config`].
#[derive(Debug, Clone)]
pub struct EndpointConfig {
    /// Maximum number of simultaneous connections (server-side).
    /// New connections are silently dropped once this limit is reached.
    /// Default: [`DEFAULT_MAX_CONNECTIONS`].
    pub max_connections: usize,
    /// Maximum new connections per second from a single IP (token-bucket rate limiter).
    /// Default: 10.
    pub max_new_conns_per_sec_per_ip: u32,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_new_conns_per_sec_per_ip: 10,
        }
    }
}

pub struct Endpoint {
    socket: Arc<UdpSocket>,
    identity: Arc<IdentityKeypair>,
    #[allow(dead_code)]
    cookie_factory: Arc<CookieFactory>,
    conns: Arc<Mutex<HashMap<SocketAddr, SharedConn>>>,
    /// Newly-accepted server connections are sent here.
    pub accept_rx: mpsc::UnboundedReceiver<SharedConn>,
    _recv_task: JoinHandle<()>,
}

impl Endpoint {
    pub async fn bind(
        local_addr: SocketAddr,
        identity: IdentityKeypair,
    ) -> Result<Self, SeamError> {
        Self::bind_with_config(local_addr, identity, EndpointConfig::default()).await
    }

    /// Bind with explicit configuration (e.g. custom `max_connections` limit).
    pub async fn bind_with_config(
        local_addr: SocketAddr,
        identity: IdentityKeypair,
        config: EndpointConfig,
    ) -> Result<Self, SeamError> {
        let socket = Arc::new(
            UdpSocket::bind(local_addr)
                .await
                .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?,
        );
        let identity = Arc::new(identity);

        // Random cookie secret derived from a fresh OS random key
        let mut cookie_secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut cookie_secret);
        let cookie_factory = Arc::new(CookieFactory::new(cookie_secret));

        let conns: Arc<Mutex<HashMap<SocketAddr, SharedConn>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let (accept_tx, accept_rx) = mpsc::unbounded_channel();

        let recv_task = tokio::spawn(recv_loop(
            socket.clone(),
            identity.clone(),
            cookie_factory.clone(),
            conns.clone(),
            accept_tx,
            config.max_connections,
            config.max_new_conns_per_sec_per_ip,
        ));

        Ok(Self {
            socket,
            identity,
            cookie_factory,
            conns,
            accept_rx,
            _recv_task: recv_task,
        })
    }

    /// Connect to a remote server.
    pub async fn connect(
        &self,
        remote: SocketAddr,
        server_x25519: &[u8; 32],
        server_kem_pk: &crate::handshake::hybrid_keys::KemPublicKey,
        preferred_cipher: CipherSuite,
    ) -> Result<(SharedConn, mpsc::UnboundedReceiver<SessionEvent>), SeamError> {
        let (conn, rx) = Connection::connect(
            self.socket.clone(),
            remote,
            &self.identity,
            server_x25519,
            server_kem_pk,
            preferred_cipher,
        )
        .await?;

        let shared = Arc::new(Mutex::new(conn));
        self.conns.lock().await.insert(remote, shared.clone());
        Ok((shared, rx))
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

async fn recv_loop(
    socket: Arc<UdpSocket>,
    identity: Arc<IdentityKeypair>,
    cookie_factory: Arc<CookieFactory>,
    conns: Arc<Mutex<HashMap<SocketAddr, SharedConn>>>,
    accept_tx: mpsc::UnboundedSender<SharedConn>,
    max_connections: usize,
    max_new_conns_per_sec_per_ip: u32,
) {
    let mut buf = vec![0u8; MAX_UDP];
    // Per-IP token-bucket rate limiter state: ip → (tokens, last_refill).
    let mut ip_rate: HashMap<std::net::IpAddr, (f64, std::time::Instant)> = HashMap::new();
    let mut last_cleanup = std::time::Instant::now();
    loop {
        let (n, remote) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => break,
        };
        let pkt = buf[..n].to_vec();

        let conn = {
            let mut map = conns.lock().await;
            if let Some(c) = map.get(&remote) {
                c.clone()
            } else {
                // Enforce connection limit before allocating any per-connection state.
                // We silently drop the packet rather than sending an ICMP-unreachable or
                // any application-level error that could be used to fingerprint the server.
                if map.len() >= max_connections {
                    tracing::warn!(
                        remote = %remote,
                        current = map.len(),
                        max = max_connections,
                        "connection limit reached — dropping new connection"
                    );
                    continue;
                }

                // Per-IP rate limiting: token bucket — max N new connections per second.
                {
                    let ip = remote.ip();
                    let now = std::time::Instant::now();
                    // Periodic cleanup of stale entries (every 60 s).
                    if now.duration_since(last_cleanup).as_secs() >= 60 {
                        ip_rate.retain(|_, (_, t)| now.duration_since(*t).as_secs() < 120);
                        last_cleanup = now;
                    }
                    let rate = max_new_conns_per_sec_per_ip as f64;
                    let entry = ip_rate.entry(ip).or_insert((rate, now));
                    let elapsed = now.duration_since(entry.1).as_secs_f64();
                    entry.0 = (entry.0 + elapsed * rate).min(rate);
                    entry.1 = now;
                    if entry.0 < 1.0 {
                        tracing::warn!(
                            remote = %remote,
                            "per-IP rate limit exceeded — dropping"
                        );
                        continue;
                    }
                    entry.0 -= 1.0;
                }

                // Unknown remote → issue stateless cookie challenge (no state allocated yet)
                let (new_conn, _events) = match Connection::accept_challenge(
                    socket.clone(),
                    remote,
                    identity.clone(),
                    cookie_factory.clone(),
                    None,
                    Default::default(),
                )
                .await
                {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let shared = Arc::new(Mutex::new(new_conn));
                map.insert(remote, shared.clone());
                let _ = accept_tx.send(shared.clone());
                shared
            }
        };

        let mut pkt_mut = pkt;
        let mut guard = conn.lock().await;
        let _ = guard.on_packet(&mut pkt_mut).await;

        // Remove fully closed connections
        if guard.is_closed() {
            drop(guard);
            conns.lock().await.remove(&remote);
        }
    }
}
