/// Connection state machine: drives handshake, session, FEC, congestion, chaff, probing.
///
/// Server-side handshake flow (DDoS-resistant):
///   1. ServerWaitCookie  — server sends stateless cookie challenge (zero state)
///   2. ServerWaitMsg1    — client echoes valid cookie; server reads Noise msg1
///   3. ServerWaitMsg3    — server sends msg2; awaits msg3
///   4. Established
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::handshake::hybrid_keys::KemPublicKey;

use crate::{
    crypto::{CipherSuite, decoder::PacketDecoder, encoder::PacketEncoder},
    error::SeamError,
    fec::{ArbiterMode, FecArbiter, FecDecoder, FecEncoder},
    handshake::{
        CookieFactory, IdentityKeypair,
        state::{ClientHandshake, HandshakeResult, ServerHandshake},
    },
    packet::PktType,
    session::{Session, SessionEvent},
    transport::{
        BbrController, RttEstimator,
        cc::CongestionControl,
        chaff::ChaffScheduler,
        default_cc,
        probe::PathProber,
        tar::{TarConfig, TarState},
    },
};

// ── Wire framing for pre-session packets ─────────────────────────────────────
// Initial (cookie request):   type(1) = 0x10
// CookieChallenge:            type(1) = 0x11  + cookie(32)
// CookieEcho (msg1 wrapper):  type(1) = 0x12  + cookie(32) + msg1_len(2) + msg1
// All other handshake bytes are passed directly through the Noise state machine.

const PKT_COOKIE_REQ: u8 = 0x10;
const PKT_COOKIE_CHALLENGE: u8 = 0x11;
const PKT_COOKIE_ECHO: u8 = 0x12;
const PKT_HANDSHAKE_MSG: u8 = 0x13;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnPhase {
    /// Client: sent cookie request, waiting for challenge.
    ClientWaitChallenge,
    /// Client: sent cookie echo (msg1), waiting for msg2.
    ClientWaitMsg2,
    /// Server: sent challenge, waiting for client cookie echo + msg1.
    ServerWaitCookie,
    /// Server: read msg1, sent msg2, waiting for msg3.
    ServerWaitMsg3,
    Established,
    Draining,
    Closed,
}

pub struct Connection {
    pub remote: SocketAddr,
    pub phase: ConnPhase,
    socket: Arc<UdpSocket>,

    // Handshake state
    client_hs: Option<ClientHandshake>,
    server_hs: Option<ServerHandshake>,
    server_identity: Option<Arc<IdentityKeypair>>,
    cookie_factory: Option<Arc<CookieFactory>>,
    /// Cipher suite agreed during the handshake; valid from ServerWaitMsg3 onward.
    agreed_cipher: CipherSuite,
    /// Server's preferred cipher suite — used when creating ServerHandshake during msg1 processing.
    server_preferred_cipher: CipherSuite,

    // Post-established
    pub session: Option<Session>,
    fec_arbiter: FecArbiter,
    fec_enc: Option<FecEncoder>,
    #[allow(dead_code)]
    fec_dec: FecDecoder,
    fec_group_id: u32,
    pub cc: Box<dyn CongestionControl>,
    /// Advisory BBR controller — provides pacing guidance and richer introspection
    /// alongside the primary `cc` (trait-based) controller.
    pub bbr: BbrController,
    /// RFC 6298 RTT estimator used by the BBR advisory layer.
    pub rtt_est: RttEstimator,
    pub chaff: ChaffScheduler,
    pub prober: PathProber,

    event_tx: mpsc::UnboundedSender<SessionEvent>,
    send_counter: u64,
    /// Server's KEM public key, held by client during cookie handshake.
    _server_kem_pk: Option<KemPublicKey>,

    // Keepalive
    last_recv: Instant,
    last_send: Instant,

    // Resumption
    pub ticket_key: Option<crate::transport::resumption::TicketKey>,

    /// Peer's X25519 static public key, available after handshake completion.
    /// On the server side this is the client's identity key.
    pub peer_static_pubkey: Option<[u8; 32]>,

    /// Traffic analysis resistance state (padding, cover traffic, jitter, obfuscation).
    pub tar: TarState,

    /// Whether connection migration is enabled (from config).
    pub migration_enabled: bool,
    /// Pending PATH_CHALLENGE probes keyed by nonce: socket bound on new local addr.
    migration_sockets: HashMap<u64, Arc<UdpSocket>>,
}

impl Connection {
    // ── Constructors ─────────────────────────────────────────────────────────

    /// Initiate an outbound connection. Sends a cookie request to start the
    /// 1.5-RTT handshake: CookieRequest → CookieChallenge → CookieEcho(msg1)
    /// → msg2 → msg3 → Established.
    pub async fn connect(
        socket: Arc<UdpSocket>,
        remote: SocketAddr,
        local_identity: &IdentityKeypair,
        server_x25519: &[u8; 32],
        server_kem_pk: &KemPublicKey,
        preferred_cipher: CipherSuite,
    ) -> Result<(Self, mpsc::UnboundedReceiver<SessionEvent>), SeamError> {
        tracing::debug!(
            remote = %remote,
            cipher = ?preferred_cipher,
            "seam.handshake.client: initiating — sending cookie request"
        );

        // Send cookie request (single byte)
        socket
            .send_to(&[PKT_COOKIE_REQ], remote)
            .await
            .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;

        let client_hs =
            ClientHandshake::new_with_cipher(local_identity, server_x25519, preferred_cipher)?;

        let (tx, rx) = mpsc::unbounded_channel();
        let mut conn = Self::new_base(socket, remote, ConnPhase::ClientWaitChallenge, tx);
        conn.client_hs = Some(client_hs);
        // Stash server KEM PK so we can use it in write_msg1 when the challenge arrives
        conn._server_kem_pk = Some(server_kem_pk.clone());
        Ok((conn, rx))
    }

    /// Prepare a server-side connection (call when any packet arrives from an unknown remote).
    /// Immediately sends a cookie challenge — no state allocated until cookie is verified.
    pub async fn accept_challenge(
        socket: Arc<UdpSocket>,
        remote: SocketAddr,
        server_identity: Arc<IdentityKeypair>,
        cookie_factory: Arc<CookieFactory>,
        ticket_key: Option<crate::transport::resumption::TicketKey>,
        preferred_cipher: CipherSuite,
    ) -> Result<(Self, mpsc::UnboundedReceiver<SessionEvent>), SeamError> {
        tracing::debug!(
            remote = %remote,
            cipher = ?preferred_cipher,
            "seam.handshake.server: issuing stateless cookie challenge"
        );

        // Send stateless cookie challenge
        let addr_bytes = remote.to_string();
        let cookie = cookie_factory.generate(addr_bytes.as_bytes());
        let mut challenge = vec![PKT_COOKIE_CHALLENGE];
        challenge.extend_from_slice(&cookie);
        socket
            .send_to(&challenge, remote)
            .await
            .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;

        let (tx, rx) = mpsc::unbounded_channel();
        let mut conn = Self::new_base(socket, remote, ConnPhase::ServerWaitCookie, tx);
        conn.server_identity = Some(server_identity);
        conn.cookie_factory = Some(cookie_factory);
        conn.ticket_key = ticket_key;
        conn.server_preferred_cipher = preferred_cipher;
        Ok((conn, rx))
    }

    fn new_base(
        socket: Arc<UdpSocket>,
        remote: SocketAddr,
        phase: ConnPhase,
        event_tx: mpsc::UnboundedSender<SessionEvent>,
    ) -> Self {
        Self::new_base_with_tar(socket, remote, phase, event_tx, TarConfig::disabled())
    }

    fn new_base_with_tar(
        socket: Arc<UdpSocket>,
        remote: SocketAddr,
        phase: ConnPhase,
        event_tx: mpsc::UnboundedSender<SessionEvent>,
        tar_config: TarConfig,
    ) -> Self {
        Self {
            remote,
            phase,
            socket,
            client_hs: None,
            server_hs: None,
            server_identity: None,
            cookie_factory: None,
            agreed_cipher: CipherSuite::default(),
            server_preferred_cipher: CipherSuite::default(),
            _server_kem_pk: None,
            session: None,
            fec_arbiter: FecArbiter::new(),
            fec_enc: None,
            fec_dec: FecDecoder::new(),
            fec_group_id: 0,
            cc: default_cc(),
            bbr: BbrController::new(),
            rtt_est: RttEstimator::new(),
            chaff: ChaffScheduler::new(),
            prober: PathProber::new(),
            event_tx,
            send_counter: 0,
            last_recv: Instant::now(),
            last_send: Instant::now(),
            ticket_key: None,
            peer_static_pubkey: None,
            tar: TarState::new(tar_config),
            migration_enabled: true,
            migration_sockets: HashMap::new(),
        }
    }

    async fn finish_handshake(&mut self, result: HandshakeResult) {
        tracing::info!(
            session_id = result.session_id,
            cipher = ?result.cipher_suite,
            remote = %self.remote,
            "seam.handshake.complete: post-quantum handshake established"
        );

        let enc = PacketEncoder::new(result.keys.clone(), result.session_id);
        let dec = PacketDecoder::new(result.keys.clone());
        // Client-initiated connections take the Client role; server connections
        // use the Server role so they allocate even stream IDs on push.
        let role = if self.server_identity.is_some() {
            crate::session::Role::Server
        } else {
            crate::session::Role::Client
        };
        self.session = Some(Session::with_role(result.session_id, role, enc, dec));
        self.peer_static_pubkey = Some(result.peer_static_pubkey);
        self.phase = ConnPhase::Established;
        self.chaff.enable();
        self.server_identity = None;
        self.cookie_factory = None;
        self._server_kem_pk = None;

        // Install session secret into TAR state for obfuscation key derivation
        // and cover traffic schedule initialisation.
        self.tar.set_session_secret(&result.keys.enc_key);

        // Server: issue and send an encrypted session ticket for 0-RTT resumption.
        if let Some(tk) = &self.ticket_key {
            let ticket = tk.issue(result.session_id, &result.keys);
            if let Some(session) = self.session.as_mut() {
                let mut out = vec![0u8; 32 + ticket.len() + 16];
                if let Ok(n) = session.encode_raw(PktType::SessionTicket, &ticket, &mut out) {
                    out.truncate(n);
                    let _ = self.socket.send_to(&out, self.remote).await;
                }
            }
        }
    }

    // ── Ingress ──────────────────────────────────────────────────────────────

    pub async fn on_packet(&mut self, buf: &mut [u8]) -> Result<(), SeamError> {
        if buf.is_empty() {
            return Ok(());
        }
        match self.phase {
            ConnPhase::ClientWaitChallenge => self.client_rx_challenge(buf).await?,
            ConnPhase::ClientWaitMsg2 => self.client_rx_msg2(buf).await?,
            ConnPhase::ServerWaitCookie => self.server_rx_cookie_echo(buf).await?,
            ConnPhase::ServerWaitMsg3 => self.server_rx_msg3(buf).await?,
            ConnPhase::Established => self.on_data_packet(buf).await?,
            ConnPhase::Draining | ConnPhase::Closed => {}
        }
        Ok(())
    }

    // Client received cookie challenge → echo it back with msg1
    async fn client_rx_challenge(&mut self, buf: &[u8]) -> Result<(), SeamError> {
        if buf.len() < 1 + 32 || buf[0] != PKT_COOKIE_CHALLENGE {
            return Err(SeamError::HandshakeFailed(
                "expected cookie challenge".into(),
            ));
        }
        let cookie: [u8; 32] = buf[1..33].try_into().expect("verified: buf.len() >= 33");

        let hs = self
            .client_hs
            .as_mut()
            .ok_or_else(|| SeamError::HandshakeFailed("no client hs".into()))?;
        let kem_pk = self
            ._server_kem_pk
            .as_ref()
            .ok_or_else(|| SeamError::HandshakeFailed("no server kem pk".into()))?;
        let mut msg1 = Vec::new();
        hs.write_msg1(kem_pk, &mut msg1)?;

        // CookieEcho = type(1) + cookie(32) + msg1_len(2) + msg1
        let mut echo = vec![PKT_COOKIE_ECHO];
        echo.extend_from_slice(&cookie);
        echo.extend_from_slice(&(msg1.len() as u16).to_le_bytes());
        echo.extend_from_slice(&msg1);
        self.socket
            .send_to(&echo, self.remote)
            .await
            .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
        self.phase = ConnPhase::ClientWaitMsg2;
        Ok(())
    }

    // Client received msg2 → write msg3 → established
    async fn client_rx_msg2(&mut self, buf: &[u8]) -> Result<(), SeamError> {
        let payload = strip_type(buf, PKT_HANDSHAKE_MSG)?;
        let hs = self
            .client_hs
            .as_mut()
            .ok_or_else(|| SeamError::HandshakeFailed("no client hs".into()))?;
        let (server_kem_pk, agreed_cipher) = hs.read_msg2(payload)?;

        let hs = self
            .client_hs
            .take()
            .expect("client_hs verified Some above");
        let mut msg3 = Vec::new();
        let result = hs.write_msg3_and_finish(&server_kem_pk, agreed_cipher, &mut msg3)?;

        let mut pkt = vec![PKT_HANDSHAKE_MSG];
        pkt.extend_from_slice(&msg3);
        self.socket
            .send_to(&pkt, self.remote)
            .await
            .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
        self.finish_handshake(result).await;
        Ok(())
    }

    // Server received cookie echo — verify cookie, then process msg1, send msg2
    async fn server_rx_cookie_echo(&mut self, buf: &[u8]) -> Result<(), SeamError> {
        if buf.len() < 1 + 32 + 2 || buf[0] != PKT_COOKIE_ECHO {
            return Err(SeamError::HandshakeFailed("expected cookie echo".into()));
        }
        let cookie: &[u8; 32] = buf[1..33].try_into().expect("verified: buf.len() >= 33");
        let addr_bytes = self.remote.to_string();

        let factory = self
            .cookie_factory
            .as_ref()
            .ok_or_else(|| SeamError::HandshakeFailed("no cookie factory".into()))?;
        if !factory.verify(addr_bytes.as_bytes(), cookie) {
            return Err(SeamError::HandshakeFailed("invalid cookie".into()));
        }

        let msg1_len = u16::from_le_bytes([buf[33], buf[34]]) as usize;
        if buf.len() < 35 + msg1_len {
            return Err(SeamError::HandshakeFailed("truncated msg1".into()));
        }
        let msg1 = &buf[35..35 + msg1_len];

        // Allocate server handshake state only after cookie is verified
        let identity = self
            .server_identity
            .as_ref()
            .ok_or_else(|| SeamError::HandshakeFailed("no server identity".into()))?;
        let mut server_hs =
            ServerHandshake::new_with_cipher(identity, self.server_preferred_cipher)?;
        let agreed_cipher = server_hs.read_msg1(msg1)?;
        self.agreed_cipher = agreed_cipher;

        let mut msg2 = Vec::new();
        server_hs.write_msg2(&identity.kem_pk, agreed_cipher, &mut msg2)?;

        let mut pkt = vec![PKT_HANDSHAKE_MSG];
        pkt.extend_from_slice(&msg2);
        self.socket
            .send_to(&pkt, self.remote)
            .await
            .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;

        self.server_hs = Some(server_hs);
        self.phase = ConnPhase::ServerWaitMsg3;
        Ok(())
    }

    // Server received msg3 → finish
    async fn server_rx_msg3(&mut self, buf: &[u8]) -> Result<(), SeamError> {
        let payload = strip_type(buf, PKT_HANDSHAKE_MSG)?;
        let hs = self
            .server_hs
            .take()
            .ok_or_else(|| SeamError::HandshakeFailed("no server hs".into()))?;
        let identity = self
            .server_identity
            .as_ref()
            .ok_or_else(|| SeamError::HandshakeFailed("no server identity".into()))?;
        let result = hs.read_msg3_and_finish(&identity.kem_sk, self.agreed_cipher, payload)?;
        self.finish_handshake(result).await;
        Ok(())
    }

    async fn on_data_packet(&mut self, buf: &mut [u8]) -> Result<(), SeamError> {
        self.last_recv = Instant::now();
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| SeamError::HandshakeFailed("no session".into()))?;

        // Peek at the packet type before full decode for migration handling.
        // PathChallenge and PathResponse are decoded normally by the session but
        // then handled here so the main match arm below can just ignore them.
        let events = session.receive_packet(buf)?;

        // Check whether the session surfaced PathChallenge/PathResponse events.
        // (These are encoded as regular encrypted packets by the peer, decoded by
        // the session layer, and forwarded as raw payload events.)
        for ev in events {
            if let crate::session::SessionEvent::PathChallengeReceived(nonce) = ev {
                self.send_path_response(nonce).await?;
                continue;
            }
            if let crate::session::SessionEvent::PathResponseReceived(nonce) = ev {
                self.on_path_response(nonce).await;
                continue;
            }
            let _ = self.event_tx.send(ev);
        }
        // Feed ACK feedback into both controllers.
        if let Some((bytes, rtt)) = self.session.as_mut().and_then(|s| s.drain_cc_ack()) {
            // Trait-based primary controller (CUBIC / AIMD / Bbr via trait).
            self.cc.on_ack(bytes, rtt);
            // Advisory BBR controller with RFC 6298 RTT tracking.
            if rtt > Duration::ZERO {
                self.rtt_est.update(rtt);
            }
            let effective_rtt = if rtt > Duration::ZERO {
                rtt
            } else {
                self.rtt_est.srtt()
            };
            let prev_state = self.bbr.state();
            self.bbr
                .on_ack(bytes as usize, effective_rtt, Instant::now());
            if self.bbr.state() != prev_state {
                tracing::debug!(
                    "BBR advisory: {:?} → {:?} (pacing={:.0} B/s, cwnd={})",
                    prev_state,
                    self.bbr.state(),
                    self.bbr.pacing_rate(),
                    self.bbr.cwnd(),
                );
            }
        }
        // Immediately flush a MaxData window-update if one was queued during
        // packet processing, so the sender's flow-control window is replenished
        // without waiting for the application to call tick().
        if self
            .session
            .as_ref()
            .map(|s| s.has_pending_max_data())
            .unwrap_or(false)
        {
            self.flush().await?;
        }
        Ok(())
    }

    // ── Egress ───────────────────────────────────────────────────────────────

    pub async fn flush(&mut self) -> Result<(), SeamError> {
        let session = match self.session.as_mut() {
            Some(s) => s,
            None => return Ok(()),
        };

        let packets = session.flush()?;
        if packets.is_empty() {
            return Ok(());
        }

        let (fec_k, fec_r) = match self.fec_arbiter.mode {
            ArbiterMode::HybridFecArq { k, r } | ArbiterMode::PureFec { k, r } => {
                (Some(k), Some(r))
            }
            ArbiterMode::PureArq => (None, None),
        };

        for tp in packets {
            self.last_send = Instant::now();

            // ── TAR: apply timing jitter before each data send ────────────────
            let jitter = self.tar.jitter_delay();
            if !jitter.is_zero() {
                tokio::time::sleep(jitter).await;
            }

            // ── TAR: pad and obfuscate ─────────────────────────────────────────
            let mut wire_bytes = self.tar.maybe_pad(tp.bytes.clone());
            self.tar.maybe_obfuscate(&mut wire_bytes);

            let size = wire_bytes.len() as u64;

            if tp.is_control {
                // ACK / MaxData — always send, do not count against CC or FEC.
                self.socket
                    .send_to(&wire_bytes, self.remote)
                    .await
                    .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
                self.send_counter += 1;
                continue;
            }

            // Honour the congestion window: if there is no room, stop sending data.
            // Both the primary trait-based controller and the advisory BBR must permit.
            if self.cc.available() < size || !self.bbr.should_send(self.bbr.inflight()) {
                break;
            }
            self.socket
                .send_to(&wire_bytes, self.remote)
                .await
                .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
            self.cc.on_send(size);
            self.bbr.on_send(size as usize);
            self.tar.on_real_send(wire_bytes.len());
            self.send_counter += 1;

            if let (Some(k), Some(r)) = (fec_k, fec_r) {
                let gid = self.fec_group_id;
                let enc = self
                    .fec_enc
                    .get_or_insert_with(|| FecEncoder::new(gid, k, r));
                if enc.group_id != gid {
                    *enc = FecEncoder::new(gid, k, r);
                }
                if let Some(repairs) = enc.push_source(&tp.bytes) {
                    self.fec_group_id = self.fec_group_id.wrapping_add(1);
                    for rep in &repairs {
                        let _ = self.socket.send_to(&rep.to_bytes(), self.remote).await;
                    }
                }
            }
        }
        Ok(())
    }

    /// Inject a cover traffic packet if the TAR cover-traffic schedule requires one.
    ///
    /// Cover packets are encrypted random bytes sent as `PktType::Chaff` frames
    /// and silently discarded by the receiver.  They are indistinguishable in size
    /// and encryption from real data packets, defeating constant-rate analysis.
    pub async fn maybe_send_cover(&mut self) -> Result<(), SeamError> {
        if !self.tar.should_send_cover() {
            return Ok(());
        }
        let session = match self.session.as_mut() {
            Some(s) => s,
            None => return Ok(()),
        };
        let payload = self.tar.cover_payload();
        // Encode as a Chaff frame — receiver discards it without delivering to app.
        let mut out = vec![0u8; 32 + payload.len() + 16];
        if let Ok(n) = session.encode_raw(PktType::Chaff, &payload, &mut out) {
            out.truncate(n);
            // Apply the same obfuscation as real packets so cover and real traffic
            // are indistinguishable to an observer.
            self.tar.maybe_obfuscate(&mut out);
            self.socket
                .send_to(&out, self.remote)
                .await
                .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
            self.tar.mark_cover_sent();
            self.send_counter += 1;
        }
        Ok(())
    }

    /// De-obfuscate an incoming packet's header (if obfuscation is enabled).
    ///
    /// Must be called before passing the buffer to `on_packet`.
    pub fn deobfuscate_incoming(&self, buf: &mut [u8]) {
        self.tar.maybe_deobfuscate(buf);
    }

    pub async fn maybe_send_chaff(&mut self) -> Result<(), SeamError> {
        if !self.chaff.should_send() {
            return Ok(());
        }
        let session = match self.session.as_mut() {
            Some(s) => s,
            None => return Ok(()),
        };
        let payload = ChaffScheduler::payload(self.send_counter);
        let padded = self.chaff.pad_to_mtu(&payload, self.prober.path_mtu);
        let mut out = vec![0u8; 32 + padded.len() + 16];
        let n = session.encode_raw(PktType::Chaff, &padded, &mut out)?;
        out.truncate(n);
        self.socket
            .send_to(&out, self.remote)
            .await
            .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
        self.chaff.mark_sent(self.send_counter);
        self.send_counter += 1;
        Ok(())
    }

    pub async fn maybe_send_probe(&mut self) -> Result<(), SeamError> {
        if !self.prober.should_probe() {
            return Ok(());
        }
        let (_, payload) = self.prober.build_probe();
        let session = match self.session.as_mut() {
            Some(s) => s,
            None => return Ok(()),
        };
        let mut out = vec![0u8; 32 + payload.len() + 16];
        let n = session.encode_raw(PktType::PathProbe, &payload, &mut out)?;
        out.truncate(n);
        self.socket
            .send_to(&out, self.remote)
            .await
            .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
        Ok(())
    }

    /// Attempt connection migration when the current path appears dead.
    ///
    /// Enumerates local network interfaces, binds a temporary socket on each,
    /// sends an encrypted PATH_CHALLENGE to the peer's remote address, and waits
    /// for a PATH_RESPONSE.  When `on_path_response` is called and a match is found
    /// the session's active socket is replaced with the new one.
    ///
    /// Only called when `migration_enabled` is true and `prober.should_migrate()`.
    pub async fn maybe_migrate(&mut self) -> Result<(), SeamError> {
        if !self.migration_enabled || self.phase != ConnPhase::Established {
            return Ok(());
        }
        if !self.prober.should_migrate() {
            return Ok(());
        }
        if !self.migration_sockets.is_empty() {
            // Already have outstanding challenges — don't stack more until they resolve.
            return Ok(());
        }

        let local_ips = enumerate_local_ips();
        if local_ips.is_empty() {
            return Ok(());
        }

        tracing::info!(
            remote = %self.remote,
            timeouts = self.prober.consecutive_timeouts,
            "migration: current path appears dead — probing {} alternate local address(es)",
            local_ips.len()
        );

        for local_ip in local_ips {
            let bind_addr: SocketAddr = SocketAddr::new(local_ip, 0);
            let sock = match UdpSocket::bind(bind_addr).await {
                Ok(s) => Arc::new(s),
                Err(_) => continue,
            };

            let nonce: u64 = {
                use rand::RngCore;
                rand::rngs::OsRng.next_u64()
            };

            // Build and send an encrypted PATH_CHALLENGE from this new socket.
            if let Some(session) = self.session.as_ref() {
                let payload = nonce.to_le_bytes();
                let mut out = vec![0u8; 32 + payload.len() + 16];
                if let Ok(n) = session.encode_raw(PktType::PathChallenge, &payload, &mut out) {
                    out.truncate(n);
                    let _ = sock.send_to(&out, self.remote).await;
                    tracing::debug!(
                        local = %sock.local_addr().unwrap_or(bind_addr),
                        remote = %self.remote,
                        nonce,
                        "migration: sent PATH_CHALLENGE"
                    );
                    self.migration_sockets.insert(nonce, sock);
                }
            }
        }

        Ok(())
    }

    /// Send a PATH_RESPONSE echoing the peer's challenge nonce back on the current socket.
    async fn send_path_response(&mut self, nonce: u64) -> Result<(), SeamError> {
        if let Some(session) = self.session.as_ref() {
            let payload = nonce.to_le_bytes();
            let mut out = vec![0u8; 32 + payload.len() + 16];
            if let Ok(n) = session.encode_raw(PktType::PathResponse, &payload, &mut out) {
                out.truncate(n);
                let _ = self
                    .socket
                    .send_to(&out, self.remote)
                    .await
                    .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
                tracing::debug!(remote = %self.remote, nonce, "migration: sent PATH_RESPONSE");
            }
        }
        Ok(())
    }

    /// Called when a PATH_RESPONSE arrives on the current socket.
    /// If the nonce matches one of our pending challenges, adopt the corresponding
    /// new local socket as the active transport socket.
    async fn on_path_response(&mut self, nonce: u64) {
        if let Some(new_sock) = self.migration_sockets.remove(&nonce) {
            let new_local = new_sock.local_addr().ok();
            let old_local = self.socket.local_addr().ok();
            self.socket = new_sock;
            // Clear remaining outstanding challenges — migration succeeded.
            self.migration_sockets.clear();
            self.prober.reset_migration_state();
            tracing::info!(
                old_local = ?old_local,
                new_local = ?new_local,
                remote = %self.remote,
                "migration: path migrated successfully"
            );
        }
    }

    pub async fn retransmit_expired(&mut self) -> Result<(), SeamError> {
        let session = match self.session.as_mut() {
            Some(s) => s,
            None => return Ok(()),
        };
        let expired = session.drain_retransmits();
        if !expired.is_empty() {
            self.cc.on_timeout();
        }
        for (_, data) in expired {
            self.socket
                .send_to(&data, self.remote)
                .await
                .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
        }
        Ok(())
    }

    pub fn tick_fec(&mut self) {
        if let Some(session) = &self.session {
            let in_flight = session.arq_in_flight() as u64;
            let rtt_us = session.srtt_us();
            self.fec_arbiter.on_ack_epoch(0, in_flight.max(1), rtt_us);
        }
    }

    // ── Keepalive ────────────────────────────────────────────────────────────
    //
    // Keepalive strategy:
    //   • Every 25 s of send-side silence, queue a Ping frame.
    //   • If no packet is received from the peer for 30 s (one missed pong + margin),
    //     declare the connection idle and close it.
    //   • This prevents zombie connections from holding max_connections slots, which
    //     is critical on satellite / HF radio links where NAT mappings can silently die.

    const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(25);
    const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

    /// If the connection has been idle on the send side, queue a Ping frame.
    #[allow(clippy::collapsible_if)]
    pub fn maybe_queue_ping(&mut self) {
        if self.phase != ConnPhase::Established {
            return;
        }
        if self.last_send.elapsed() >= Self::KEEPALIVE_INTERVAL {
            if let Some(s) = self.session.as_mut() {
                s.ping();
                tracing::debug!(
                    remote = %self.remote,
                    idle_secs = self.last_recv.elapsed().as_secs(),
                    "keepalive: queued Ping frame"
                );
            }
        }
    }

    /// True if no packet has been received from the peer for too long.
    ///
    /// Called by the application tick loop. When this returns `true` the caller
    /// should close the connection and log a warning so the operator can see that
    /// the remote went silent (likely a dead NAT mapping or crashed peer).
    pub fn is_idle(&self) -> bool {
        self.phase == ConnPhase::Established && self.last_recv.elapsed() >= Self::IDLE_TIMEOUT
    }

    pub fn is_established(&self) -> bool {
        self.phase == ConnPhase::Established
    }
    pub fn is_closed(&self) -> bool {
        matches!(self.phase, ConnPhase::Closed | ConnPhase::Draining)
    }
    pub fn close(&mut self) {
        self.phase = ConnPhase::Draining;
    }

    /// Allow overriding the CC implementation (e.g. for testing or ML controller).
    pub fn set_congestion_controller(&mut self, cc: Box<dyn CongestionControl>) {
        self.cc = cc;
    }

    /// Replace the traffic analysis resistance configuration.
    ///
    /// Must be called before `finish_handshake` if you need the session secret
    /// to be derived for obfuscation.  Safe to call at any time for non-obfuscation
    /// settings (padding, jitter, cover traffic).
    pub fn set_tar_config(&mut self, config: TarConfig) {
        self.tar = TarState::new(config);
    }

    /// Initiate an outbound connection with traffic analysis resistance settings.
    pub async fn connect_with_tar(
        socket: Arc<UdpSocket>,
        remote: SocketAddr,
        local_identity: &IdentityKeypair,
        server_x25519: &[u8; 32],
        server_kem_pk: &KemPublicKey,
        preferred_cipher: CipherSuite,
        tar_config: TarConfig,
    ) -> Result<(Self, mpsc::UnboundedReceiver<SessionEvent>), SeamError> {
        tracing::debug!(
            remote = %remote,
            cipher = ?preferred_cipher,
            "seam.handshake.client: initiating with TAR — sending cookie request"
        );

        socket
            .send_to(&[PKT_COOKIE_REQ], remote)
            .await
            .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;

        let client_hs =
            ClientHandshake::new_with_cipher(local_identity, server_x25519, preferred_cipher)?;

        let (tx, rx) = mpsc::unbounded_channel();
        let mut conn = Self::new_base_with_tar(
            socket,
            remote,
            ConnPhase::ClientWaitChallenge,
            tx,
            tar_config,
        );
        conn.client_hs = Some(client_hs);
        conn._server_kem_pk = Some(server_kem_pk.clone());
        Ok((conn, rx))
    }
}

fn strip_type(buf: &[u8], expected: u8) -> Result<&[u8], SeamError> {
    if buf.is_empty() || buf[0] != expected {
        return Err(SeamError::HandshakeFailed(format!(
            "expected pkt type 0x{expected:02x}, got 0x{:02x}",
            buf.first().copied().unwrap_or(0xff)
        )));
    }
    Ok(&buf[1..])
}

/// Enumerate routable local IP addresses using the `libc` getifaddrs interface.
///
/// Returns only unicast addresses (IPv4 and IPv6, excluding loopback and link-local).
/// Falls back to an empty list on platforms where getifaddrs is unavailable.
fn enumerate_local_ips() -> Vec<std::net::IpAddr> {
    #[cfg(unix)]
    {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let mut addrs = Vec::new();
        unsafe {
            let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut ifap) != 0 {
                return addrs;
            }
            let mut ifa = ifap;
            while !ifa.is_null() {
                let ifa_ref = &*ifa;
                if ifa_ref.ifa_addr.is_null() {
                    ifa = ifa_ref.ifa_next;
                    continue;
                }
                let sa_family = (*ifa_ref.ifa_addr).sa_family as i32;
                let flags = ifa_ref.ifa_flags as i32;
                // Skip loopback and interfaces that are not up.
                if flags & libc::IFF_LOOPBACK != 0 || flags & libc::IFF_UP == 0 {
                    ifa = ifa_ref.ifa_next;
                    continue;
                }
                match sa_family {
                    libc::AF_INET => {
                        let sin = &*(ifa_ref.ifa_addr as *const libc::sockaddr_in);
                        let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                        if !ip.is_loopback() && !ip.is_link_local() {
                            addrs.push(IpAddr::V4(ip));
                        }
                    }
                    libc::AF_INET6 => {
                        let sin6 = &*(ifa_ref.ifa_addr as *const libc::sockaddr_in6);
                        let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                        // Skip loopback (::1) and link-local (fe80::/10).
                        let is_link_local =
                            ip.octets()[0] == 0xfe && (ip.octets()[1] & 0xc0 == 0x80);
                        if !(ip.is_loopback() || is_link_local) {
                            addrs.push(IpAddr::V6(ip));
                        }
                    }
                    _ => {}
                }
                ifa = ifa_ref.ifa_next;
            }
            libc::freeifaddrs(ifap);
        }
        addrs
    }
    #[cfg(not(unix))]
    {
        Vec::new()
    }
}
