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
    error::SeamError,
    handshake::{CookieFactory, IdentityKeypair},
    session::SessionEvent,
    transport::connection::Connection,
};

const MAX_UDP: usize = 65535;

pub type SharedConn = Arc<Mutex<Connection>>;

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
    ) -> Result<(SharedConn, mpsc::UnboundedReceiver<SessionEvent>), SeamError> {
        let (conn, rx) = Connection::connect(
            self.socket.clone(),
            remote,
            &self.identity,
            server_x25519,
            server_kem_pk,
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
) {
    let mut buf = vec![0u8; MAX_UDP];
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
                // Unknown remote → issue stateless cookie challenge (no state allocated yet)
                let (new_conn, _events) = match Connection::accept_challenge(
                    socket.clone(),
                    remote,
                    identity.clone(),
                    cookie_factory.clone(),
                    None,
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
