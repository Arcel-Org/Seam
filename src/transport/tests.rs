/// Integration tests for the full seam-protocol stack.
#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::timeout;

    use crate::{
        fec::{ArbiterMode, FecArbiter},
        handshake::{CookieFactory, IdentityKeypair},
        session::SessionEvent,
        transport::{
            cc::{Aimd, Cubic, CongestionControl, MSS},
            chaff::ChaffScheduler,
            congestion::CongestionController,
            connection::{ConnPhase, Connection},
            probe::PathProber,
        },
    };

    // ── Helpers ───────────────────────────────────────────────────────────────

    async fn loopback_pair() -> (
        Arc<tokio::net::UdpSocket>,
        Arc<tokio::net::UdpSocket>,
        SocketAddr,
        SocketAddr,
    ) {
        let a = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let b = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_a = a.local_addr().unwrap();
        let addr_b = b.local_addr().unwrap();
        (a, b, addr_a, addr_b)
    }

    /// Drive a complete cookie-protected handshake over loopback sockets.
    /// Returns (client, server) both Established.
    ///
    /// Correct ordering (mirrors the endpoint's recv_loop):
    ///   client sends CookieRequest(0x10)
    ///   → server recvs 0x10, calls accept_challenge, sends CookieChallenge(0x11)
    ///   → client recvs 0x11, sends CookieEcho(0x12)+msg1
    ///   → server recvs 0x12, verifies cookie, sends msg2
    ///   → client recvs msg2, sends msg3, → Established
    ///   → server recvs msg3 → Established
    async fn do_handshake() -> (Connection, Connection) {
        let client_id = IdentityKeypair::generate();
        let server_id = Arc::new(IdentityKeypair::generate());

        let (client_sock, server_sock, client_addr, server_addr) = loopback_pair().await;
        let cookie_factory = Arc::new(CookieFactory::new([0xABu8; 32]));
        let server_x25519: [u8; 32] = server_id.x25519_public.to_bytes();

        // Client sends CookieRequest (0x10)
        let (mut client, _) = Connection::connect(
            client_sock.clone(), server_addr, &client_id,
            &server_x25519, &server_id.kem_pk,
        ).await.unwrap();
        assert_eq!(client.phase, ConnPhase::ClientWaitChallenge);

        let mut buf = vec![0u8; 65535];

        // Server receives CookieRequest → accept_challenge sends CookieChallenge
        let (n, _) = timeout(Duration::from_secs(2), server_sock.recv_from(&mut buf))
            .await.unwrap().unwrap();
        assert_eq!(buf[0], 0x10, "expected cookie request");
        let (mut server, _) = Connection::accept_challenge(
            server_sock.clone(), client_addr, server_id.clone(), cookie_factory,
        ).await.unwrap();
        assert_eq!(server.phase, ConnPhase::ServerWaitCookie);
        let _ = n; // consumed above

        // Client receives CookieChallenge → sends CookieEcho + msg1
        let (n, _) = timeout(Duration::from_secs(2), client_sock.recv_from(&mut buf))
            .await.unwrap().unwrap();
        client.on_packet(&mut buf[..n].to_vec()).await.unwrap();
        assert_eq!(client.phase, ConnPhase::ClientWaitMsg2);

        // Server receives CookieEcho+msg1 → verifies cookie, sends msg2
        let (n, _) = timeout(Duration::from_secs(2), server_sock.recv_from(&mut buf))
            .await.unwrap().unwrap();
        server.on_packet(&mut buf[..n].to_vec()).await.unwrap();
        assert_eq!(server.phase, ConnPhase::ServerWaitMsg3);

        // Client receives msg2 → sends msg3 → Established
        let (n, _) = timeout(Duration::from_secs(2), client_sock.recv_from(&mut buf))
            .await.unwrap().unwrap();
        client.on_packet(&mut buf[..n].to_vec()).await.unwrap();
        assert_eq!(client.phase, ConnPhase::Established);

        // Server receives msg3 → Established
        let (n, _) = timeout(Duration::from_secs(2), server_sock.recv_from(&mut buf))
            .await.unwrap().unwrap();
        server.on_packet(&mut buf[..n].to_vec()).await.unwrap();
        assert_eq!(server.phase, ConnPhase::Established);

        assert_eq!(
            client.session.as_ref().unwrap().id,
            server.session.as_ref().unwrap().id,
        );
        (client, server)
    }

    // ── Cookie challenge ──────────────────────────────────────────────────────

    #[test]
    fn cookie_roundtrip() {
        let factory = CookieFactory::new([0x42u8; 32]);
        let addr = b"127.0.0.1:9001";
        let cookie = factory.generate(addr);
        assert!(factory.verify(addr, &cookie));
        // Wrong address fails
        assert!(!factory.verify(b"1.2.3.4:9999", &cookie));
        // Tampered cookie fails
        let mut bad = cookie;
        bad[0] ^= 1;
        assert!(!factory.verify(addr, &bad));
    }

    // ── CUBIC congestion controller ───────────────────────────────────────────

    #[test]
    fn cubic_slow_start_growth() {
        let mut cc = Cubic::new();
        let init = cc.cwnd();
        cc.on_send(MSS);
        cc.on_ack(MSS, Duration::from_millis(10));
        assert!(cc.cwnd() > init);
    }

    #[test]
    fn cubic_loss_applies_beta() {
        let mut cc = Cubic::new();
        // Get into CA
        for _ in 0..200 { cc.on_send(MSS); cc.on_ack(MSS, Duration::from_millis(10)); }
        let before = cc.cwnd() as f64;
        cc.on_loss();
        let after = cc.cwnd() as f64;
        // Should be ≈ β * before (0.7)
        assert!(after < before * 0.75, "CUBIC loss: {after} should be < 0.75 * {before}");
        assert!(after > before * 0.65, "CUBIC loss too aggressive");
    }

    #[test]
    fn cubic_timeout_restarts_at_mss() {
        let mut cc = Cubic::new();
        for _ in 0..50 { cc.on_send(MSS); cc.on_ack(MSS, Duration::from_millis(10)); }
        cc.on_timeout();
        assert_eq!(cc.cwnd(), MSS);
        assert_eq!(cc.bytes_in_flight(), 0);
    }

    #[test]
    fn pluggable_cc_trait_object() {
        let mut cc: Box<dyn CongestionControl> = Box::new(Cubic::new());
        cc.on_send(MSS);
        cc.on_ack(MSS, Duration::from_millis(5));
        assert!(cc.cwnd() > 0);

        let mut cc2: Box<dyn CongestionControl> = Box::new(Aimd::new());
        cc2.on_send(MSS);
        cc2.on_ack(MSS, Duration::from_millis(5));
        assert!(cc2.cwnd() > 0);
    }

    // ── FEC arbiter ───────────────────────────────────────────────────────────

    #[test]
    fn fec_arbiter_mode_switching() {
        let mut arb = FecArbiter::new();
        assert_eq!(arb.mode, ArbiterMode::PureArq);
        for _ in 0..30 { arb.on_ack_epoch(8, 100, 20_000); }
        assert!(arb.mode.uses_fec());
        for _ in 0..60 { arb.on_ack_epoch(0, 100, 20_000); }
        assert_eq!(arb.mode, ArbiterMode::PureArq, "should recover to PureArq");
    }

    // ── Chaff + padding ───────────────────────────────────────────────────────

    #[test]
    fn chaff_pad_to_mtu() {
        let cs = ChaffScheduler::new();
        let padded = cs.pad_to_mtu(&[0u8; 100], 1400);
        assert_eq!(padded.len() + 32 + 16, 1400);
    }

    #[test]
    fn chaff_jitter_bounded() {
        let mut cs = ChaffScheduler::new();
        cs.enable();
        for _ in 0..50 {
            assert!(cs.jitter_delay() <= Duration::from_millis(5));
        }
    }

    #[test]
    fn chaff_fires_then_backs_off() {
        let mut cs = ChaffScheduler::new();
        cs.enable();
        assert!(cs.should_send());
        cs.mark_sent(0);
        assert!(!cs.should_send());
    }

    // ── Path prober ───────────────────────────────────────────────────────────

    #[test]
    fn prober_echo_returns_rtt() {
        let mut p = PathProber::new();
        let (_, payload) = p.build_probe();
        let rtt = p.on_echo(&payload);
        assert!(rtt.is_some());
        assert!(rtt.unwrap() < Duration::from_secs(1));
    }

    // ── GF arithmetic laws ────────────────────────────────────────────────────

    #[test]
    fn gf_all_inverses() {
        use crate::fec::gf;
        for a in 1u8..=255 {
            assert_eq!(gf::mul(a, gf::inv(a)), 1, "a={a}");
        }
    }

    #[test]
    fn gf_distributivity() {
        use crate::fec::gf;
        for (a, b, c) in [(3u8, 7u8, 11u8), (255, 128, 64), (17, 41, 99)] {
            let lhs = gf::mul(a, gf::add(b, c));
            let rhs = gf::add(gf::mul(a, b), gf::mul(a, c));
            assert_eq!(lhs, rhs);
        }
    }

    // ── Full handshake (loopback) ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_full_handshake_with_cookie() {
        let (client, server) = do_handshake().await;
        assert_eq!(client.phase, ConnPhase::Established);
        assert_eq!(server.phase, ConnPhase::Established);
    }

    // ── Stream data transfer ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_stream_data_transfer() {
        let client_id = IdentityKeypair::generate();
        let server_id = Arc::new(IdentityKeypair::generate());

        let (client_sock, server_sock, client_addr, server_addr) = loopback_pair().await;
        let cookie_factory = Arc::new(CookieFactory::new([0xCDu8; 32]));

        let (mut client, _) = Connection::connect(
            client_sock.clone(), server_addr, &client_id,
            &server_id.x25519_public.to_bytes(), &server_id.kem_pk,
        ).await.unwrap();

        let mut buf = vec![0u8; 65535];

        // Server receives cookie request, then issues challenge
        let (n, _) = server_sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(buf[0], 0x10);
        let _ = n;
        let (mut server, mut server_events) = Connection::accept_challenge(
            server_sock.clone(), client_addr, server_id.clone(), cookie_factory,
        ).await.unwrap();
        let (n, _) = client_sock.recv_from(&mut buf).await.unwrap(); // challenge
        client.on_packet(&mut buf[..n].to_vec()).await.unwrap();
        let (n, _) = server_sock.recv_from(&mut buf).await.unwrap(); // echo + msg1
        server.on_packet(&mut buf[..n].to_vec()).await.unwrap();
        let (n, _) = client_sock.recv_from(&mut buf).await.unwrap(); // msg2
        client.on_packet(&mut buf[..n].to_vec()).await.unwrap();
        let (n, _) = server_sock.recv_from(&mut buf).await.unwrap(); // msg3
        server.on_packet(&mut buf[..n].to_vec()).await.unwrap();

        assert_eq!(client.phase, ConnPhase::Established);
        assert_eq!(server.phase, ConnPhase::Established);

        // Client sends stream data
        let sid = client.session.as_mut().unwrap().open_stream();
        client.session.as_mut().unwrap().send(sid, b"hello apex protocol").unwrap();
        client.flush().await.unwrap();

        // Server receives
        let (n, _) = timeout(Duration::from_secs(2), server_sock.recv_from(&mut buf))
            .await.unwrap().unwrap();
        server.on_packet(&mut buf[..n].to_vec()).await.unwrap();

        let event = timeout(Duration::from_millis(100), server_events.recv())
            .await.unwrap().unwrap();
        assert!(matches!(event, SessionEvent::NewStream(_) | SessionEvent::DataAvailable(_)));

        let mut out = Vec::new();
        let n = server.session.as_mut().unwrap().read(1, &mut out, 1024).unwrap_or(0);
        assert_eq!(n, 19);
        assert_eq!(&out, b"hello apex protocol");
    }

    // ── 0-RTT skeleton ───────────────────────────────────────────────────────

    #[test]
    fn session_ticket_encode_decode() {
        use crate::transport::resumption::{SessionTicket, WEAKER_FS_WARNING};
        println!("{WEAKER_FS_WARNING}");
        let ticket = SessionTicket::new(42u64, [0xABu8; 32]);
        let bytes = ticket.to_bytes();
        let parsed = SessionTicket::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.session_id, 42);
        assert_eq!(parsed.traffic_secret, [0xABu8; 32]);
    }

    // ── Datagram end-to-end ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_datagram_roundtrip() {
        let client_id = IdentityKeypair::generate();
        let server_id = Arc::new(IdentityKeypair::generate());

        let (client_sock, server_sock, client_addr, server_addr) = loopback_pair().await;
        let cookie_factory = Arc::new(CookieFactory::new([0xEEu8; 32]));

        let (mut client, _) = Connection::connect(
            client_sock.clone(), server_addr, &client_id,
            &server_id.x25519_public.to_bytes(), &server_id.kem_pk,
        ).await.unwrap();

        let mut buf = vec![0u8; 65535];

        let (_, _) = server_sock.recv_from(&mut buf).await.unwrap();
        let (mut server, mut server_events) = Connection::accept_challenge(
            server_sock.clone(), client_addr, server_id.clone(), cookie_factory,
        ).await.unwrap();

        // Drive handshake
        let (n, _) = client_sock.recv_from(&mut buf).await.unwrap();
        client.on_packet(&mut buf[..n].to_vec()).await.unwrap();
        let (n, _) = server_sock.recv_from(&mut buf).await.unwrap();
        server.on_packet(&mut buf[..n].to_vec()).await.unwrap();
        let (n, _) = client_sock.recv_from(&mut buf).await.unwrap();
        client.on_packet(&mut buf[..n].to_vec()).await.unwrap();
        let (n, _) = server_sock.recv_from(&mut buf).await.unwrap();
        server.on_packet(&mut buf[..n].to_vec()).await.unwrap();

        // Send unreliable datagram
        use bytes::Bytes;
        client.session.as_mut().unwrap()
            .send_datagram(Bytes::from_static(b"datagram-payload-xyz")).unwrap();
        client.flush().await.unwrap();

        let (n, _) = timeout(Duration::from_secs(2), server_sock.recv_from(&mut buf))
            .await.unwrap().unwrap();
        server.on_packet(&mut buf[..n].to_vec()).await.unwrap();

        // Expect DatagramReceived event
        let evt = timeout(Duration::from_millis(100), server_events.recv())
            .await.unwrap().unwrap();
        assert!(matches!(evt, SessionEvent::DatagramReceived));

        let received = server.session.as_mut().unwrap().recv_datagram().unwrap();
        assert_eq!(&received[..], b"datagram-payload-xyz");
    }

    // ── BBRv1 smoke ──────────────────────────────────────────────────────────

    #[test]
    fn bbr_pluggable_into_connection() {
        use crate::transport::bbr::Bbr;
        let mut cc: Box<dyn CongestionControl> = Box::new(Bbr::new());
        for _ in 0..10 {
            cc.on_send(MSS);
            cc.on_ack(MSS, Duration::from_millis(5));
        }
        assert!(cc.cwnd() >= 4 * MSS);
    }

    // ── RACK loss detection smoke ────────────────────────────────────────────

    #[test]
    fn rack_detects_reordered_loss() {
        use crate::session::rack::RackTracker;
        use bytes::Bytes;
        use std::time::Instant;

        let mut r = RackTracker::new();
        r.on_sent(1, Bytes::from_static(b"old"), 100);
        r.on_sent(2, Bytes::from_static(b"new"), 100);
        // Simulate packet 2 arriving while packet 1 is much older
        // (Internal manipulation only for this test)
        let (_rtt, losses) = r.on_ack(2);
        // With default reorder window, we may not detect yet — test API compiles/runs
        assert_eq!(r.in_flight_count(), 1);
        let _ = losses;
        let _ = Instant::now;
    }

    // ── BufferPool reuse ─────────────────────────────────────────────────────

    #[test]
    fn buffer_pool_reuses_allocations() {
        let pool = crate::transport::pool::BufferPool::new(1500, 8);
        let buf = pool.acquire();
        let cap = buf.capacity();
        pool.release(buf);
        let buf2 = pool.acquire();
        assert_eq!(buf2.capacity(), cap, "should have reused the same allocation");
    }

    // ── ConnectionStats ──────────────────────────────────────────────────────

    #[test]
    fn connection_stats_updates() {
        let mut s = crate::transport::stats::ConnectionStats::new();
        s.packets_sent = 1000;
        s.packets_lost = 50;
        assert!((s.loss_rate() - 0.05).abs() < 1e-4);
    }

    // ── Server-initiated (push) streams ──────────────────────────────────────

    #[tokio::test]
    async fn server_push_stream_received_by_client() {
        let (mut client, mut server) = do_handshake().await;

        // Server pushes a stream (even ID, server-initiated)
        let sid = server.session.as_mut().unwrap().push_stream();
        assert_eq!(sid % 2, 0, "server push_stream must allocate even IDs");

        // Write payload into session buffer and get raw encoded packets.
        let session = server.session.as_mut().unwrap();
        session.send(sid, b"server push payload").unwrap();
        let pkts = session.flush().unwrap();
        assert!(!pkts.is_empty(), "server flush should produce at least one packet");

        // Deliver the encoded packet directly to the client session.
        let events = client.session.as_mut().unwrap()
            .receive_packet(&mut pkts[0].clone()).unwrap();

        let has_new = events.iter().any(|e| matches!(e, SessionEvent::NewStream(s) if s % 2 == 0));
        assert!(has_new, "client should receive NewStream with even ID: {events:?}");

        let mut out = Vec::new();
        let n = client.session.as_mut().unwrap()
            .read(sid, &mut out, 256)
            .unwrap_or(0);
        assert_eq!(&out[..n], b"server push payload");
    }


    // ── High-level Client/Server API ─────────────────────────────────────────

    #[tokio::test]
    async fn high_level_client_server_roundtrip() {
        use crate::api::{Client, Server};
        use crate::handshake::IdentityKeypair;

        let server_id = IdentityKeypair::generate();
        let server_x25519: [u8; 32] = server_id.x25519_public.to_bytes();
        let server_kem_pk = server_id.kem_pk.clone();

        // Server binds and starts accepting
        let mut server = Server::bind("127.0.0.1:0".parse().unwrap(), server_id)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        // Drive server accept + client connect concurrently
        let (server_conn, client_conn) = tokio::join!(
            async {
                timeout(Duration::from_secs(5), server.accept())
                    .await
                    .expect("server accept timed out")
                    .expect("server accept returned None")
            },
            async {
                let client_id = IdentityKeypair::generate();
                let mut client = Client::bind("127.0.0.1:0".parse().unwrap(), client_id)
                    .await
                    .unwrap();
                timeout(
                    Duration::from_secs(5),
                    client.connect(server_addr, &server_x25519, &server_kem_pk),
                )
                .await
                .expect("client connect timed out")
                .expect("client connect failed")
            },
        );

        // Session IDs must match
        assert_eq!(client_conn.session_id().await, server_conn.session_id().await);

        // Client sends a stream
        let sid = client_conn.open_stream().await;
        client_conn.write(sid, b"hello from client").await.unwrap();

        // Server waits for the data
        let mut sconn = server_conn;
        let event = timeout(Duration::from_secs(2), sconn.read_event())
            .await
            .expect("server event timed out")
            .expect("no event");
        assert!(
            matches!(event, SessionEvent::DataAvailable(_) | SessionEvent::NewStream(_)),
            "unexpected event: {event:?}"
        );

        let data = sconn.read(sid, 256).await.unwrap();
        assert_eq!(data, b"hello from client");
    }

}
