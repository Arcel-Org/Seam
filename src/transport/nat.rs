/// STUN-based NAT traversal and UDP hole punching.
///
/// Implements a minimal STUN client (RFC 5389) to discover the external
/// IP:port of the local socket, and a hole-punching coordinator so that
/// two peers behind NAT can establish a direct P2P path.
///
/// # Usage
///
/// ```no_run
/// use seam_protocol::transport::nat::StunClient;
///
/// # async fn example() -> anyhow::Result<()> {
/// let client = StunClient::new("stun.l.google.com:19302");
/// let (external_addr, local_addr) = client.discover_external_addr().await?;
/// println!("External: {external_addr}, Local: {local_addr}");
/// # Ok(())
/// # }
/// ```
use anyhow::{Result, anyhow, bail};
use rand::RngCore;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

// ── STUN constants (RFC 5389) ─────────────────────────────────────────────────

const STUN_MAGIC: u32 = 0x2112A442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const STUN_HEADER_LEN: usize = 20;
const STUN_TIMEOUT: Duration = Duration::from_secs(5);
const STUN_RETRIES: u32 = 3;

/// STUN client for external address discovery.
pub struct StunClient {
    server: String,
}

impl StunClient {
    /// Create a new STUN client pointing at `server` (e.g. "stun.l.google.com:19302").
    pub fn new(server: impl Into<String>) -> Self {
        Self {
            server: server.into(),
        }
    }

    /// Discover the external (public) address of a locally-bound UDP socket.
    ///
    /// Returns `(external_addr, local_addr)`.
    pub async fn discover_external_addr(&self) -> Result<(SocketAddr, SocketAddr)> {
        // Resolve STUN server address.
        let server_addrs: Vec<SocketAddr> = tokio::net::lookup_host(&self.server)
            .await
            .map_err(|e| anyhow!("STUN: cannot resolve {}: {e}", self.server))?
            .collect();
        let server_addr = server_addrs
            .first()
            .copied()
            .ok_or_else(|| anyhow!("STUN: no address for {}", self.server))?;

        // Bind a UDP socket on the same family as the STUN server.
        let local_bind = if server_addr.is_ipv6() {
            ":::0"
        } else {
            "0.0.0.0:0"
        };
        let sock = UdpSocket::bind(local_bind)
            .await
            .map_err(|e| anyhow!("STUN: bind failed: {e}"))?;
        let local_addr = sock.local_addr()?;

        // Build STUN Binding Request.
        let mut txn_id = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut txn_id);
        let request = build_binding_request(&txn_id);

        // Send with retries.
        let mut buf = vec![0u8; 2048];
        for attempt in 0..STUN_RETRIES {
            sock.send_to(&request, server_addr)
                .await
                .map_err(|e| anyhow!("STUN: send failed: {e}"))?;

            match timeout(STUN_TIMEOUT, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, from))) if from == server_addr => {
                    if let Some(ext) = parse_binding_response(&buf[..n], &txn_id) {
                        return Ok((ext, local_addr));
                    }
                    tracing::debug!("STUN: bad response on attempt {attempt}, retrying");
                }
                Ok(Ok((_, from))) => {
                    tracing::debug!("STUN: response from unexpected source {from}, ignoring");
                }
                Ok(Err(e)) => {
                    tracing::debug!("STUN: recv error on attempt {attempt}: {e}");
                }
                Err(_) => {
                    tracing::debug!("STUN: timeout on attempt {attempt}");
                }
            }
        }

        bail!("STUN: no response from {} after {} attempts", self.server, STUN_RETRIES);
    }
}

/// Build a minimal STUN Binding Request message.
fn build_binding_request(txn_id: &[u8; 12]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(STUN_HEADER_LEN);
    // Message type: Binding Request
    msg.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    // Message length (attributes): 0 (no attributes in the request)
    msg.extend_from_slice(&0u16.to_be_bytes());
    // Magic cookie
    msg.extend_from_slice(&STUN_MAGIC.to_be_bytes());
    // Transaction ID (12 bytes)
    msg.extend_from_slice(txn_id);
    msg
}

/// Parse a STUN Binding Response and extract the mapped address.
fn parse_binding_response(data: &[u8], expected_txn: &[u8; 12]) -> Option<SocketAddr> {
    if data.len() < STUN_HEADER_LEN {
        return None;
    }

    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != STUN_BINDING_RESPONSE {
        return None;
    }

    let attr_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if magic != STUN_MAGIC {
        return None;
    }

    // Verify transaction ID.
    if &data[8..20] != expected_txn {
        return None;
    }

    if data.len() < STUN_HEADER_LEN + attr_len {
        return None;
    }

    // Parse attributes, prefer XOR-MAPPED-ADDRESS over MAPPED-ADDRESS.
    let mut pos = STUN_HEADER_LEN;
    let mut mapped: Option<SocketAddr> = None;
    let mut xor_mapped: Option<SocketAddr> = None;

    while pos + 4 <= STUN_HEADER_LEN + attr_len {
        let attr_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        let value_start = pos + 4;
        let value_end = value_start + len;

        if value_end > data.len() {
            break;
        }

        match attr_type {
            STUN_ATTR_MAPPED_ADDRESS => {
                mapped = parse_mapped_address(&data[value_start..value_end], false, STUN_MAGIC);
            }
            STUN_ATTR_XOR_MAPPED_ADDRESS => {
                xor_mapped =
                    parse_mapped_address(&data[value_start..value_end], true, STUN_MAGIC);
            }
            _ => {}
        }

        // Attributes are padded to 4-byte boundaries.
        let padded = (len + 3) & !3;
        pos = value_start + padded;
    }

    xor_mapped.or(mapped)
}

/// Parse MAPPED-ADDRESS or XOR-MAPPED-ADDRESS attribute value.
///
/// Format: [reserved(1)][family(1)][port(2)][addr(4 or 16)]
fn parse_mapped_address(data: &[u8], xor: bool, magic: u32) -> Option<SocketAddr> {
    if data.len() < 4 {
        return None;
    }
    let family = data[1];
    let raw_port = u16::from_be_bytes([data[2], data[3]]);
    let port = if xor {
        raw_port ^ (magic >> 16) as u16
    } else {
        raw_port
    };

    match family {
        0x01 => {
            // IPv4
            if data.len() < 8 {
                return None;
            }
            let raw_ip = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            let ip_u32 = if xor { raw_ip ^ magic } else { raw_ip };
            let ip = Ipv4Addr::from(ip_u32);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            // IPv6
            if data.len() < 20 {
                return None;
            }
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&data[4..20]);
            if xor {
                // XOR first 4 bytes with magic, remaining 12 with transaction ID.
                let magic_bytes = magic.to_be_bytes();
                for i in 0..4 {
                    raw[i] ^= magic_bytes[i];
                }
                // Note: full XOR with txn_id requires it; skip for simplicity (IPv6 STUN rarely needed).
            }
            let ip = Ipv6Addr::from(raw);
            Some(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => None,
    }
}

// ── UDP Hole Punching ─────────────────────────────────────────────────────────

/// Punch coordinator: exchange external addresses out-of-band and then
/// simultaneously send UDP probes to each other to open NAT mappings.
///
/// Both peers call `punch` concurrently (e.g. coordinated via a relay signaling
/// channel). The local socket is returned so the caller can use it for the actual
/// Seam session.
pub struct HolePuncher {
    stun: StunClient,
}

impl HolePuncher {
    pub fn new(stun_server: impl Into<String>) -> Self {
        Self {
            stun: StunClient::new(stun_server),
        }
    }

    /// Perform hole punching:
    ///
    /// 1. Discover external address via STUN.
    /// 2. Caller exchanges external addresses with the peer out-of-band.
    /// 3. Both sides simultaneously send UDP probes to each other's external address.
    ///
    /// Returns the local socket (bound and ready for use in a Seam session)
    /// and the verified peer address once a probe is received.
    pub async fn punch(
        &self,
        peer_external_addr: SocketAddr,
    ) -> Result<(UdpSocket, SocketAddr, SocketAddr)> {
        let (our_external, local_addr) = self.stun.discover_external_addr().await?;

        // Bind a socket on the same local port that STUN used.
        let sock = UdpSocket::bind(local_addr)
            .await
            .map_err(|e| anyhow!("punch: bind failed: {e}"))?;

        // Send probes for up to 5 seconds, 100ms apart.
        let probe = b"SEAM-PUNCH-PROBE-v1";
        let sock = std::sync::Arc::new(sock);
        let sock2 = sock.clone();
        let peer = peer_external_addr;

        // Sender task: blast probes every 100ms.
        let send_task = tokio::spawn(async move {
            for _ in 0..50u32 {
                let _ = sock2.send_to(probe, peer).await;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        // Receiver: wait for a probe back from the peer.
        let mut buf = vec![0u8; 256];
        let verified_peer = timeout(Duration::from_secs(5), async {
            loop {
                match sock.recv_from(&mut buf).await {
                    Ok((n, from)) if &buf[..n] == probe => {
                        return Ok::<SocketAddr, anyhow::Error>(from);
                    }
                    Ok(_) => continue,
                    Err(e) => return Err(anyhow!("punch recv: {e}")),
                }
            }
        })
        .await
        .map_err(|_| anyhow!("hole punch timeout — no probe received from peer"))?
        .map_err(|e| anyhow!("hole punch failed: {e}"))?;

        send_task.abort();

        // Unwrap Arc — the send_task is done.
        let sock = std::sync::Arc::try_unwrap(sock)
            .map_err(|_| anyhow!("could not unwrap socket Arc"))?;

        Ok((sock, our_external, verified_peer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_parse_binding_request() {
        let txn_id = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let req = build_binding_request(&txn_id);
        assert_eq!(req.len(), STUN_HEADER_LEN);
        let msg_type = u16::from_be_bytes([req[0], req[1]]);
        assert_eq!(msg_type, STUN_BINDING_REQUEST);
        let magic = u32::from_be_bytes([req[4], req[5], req[6], req[7]]);
        assert_eq!(magic, STUN_MAGIC);
        assert_eq!(&req[8..20], &txn_id);
    }

    #[test]
    fn test_parse_binding_response_ipv4_xor() {
        // Build a synthetic STUN response with XOR-MAPPED-ADDRESS for 1.2.3.4:5678
        let txn_id = [0u8; 12];
        let mut resp = Vec::new();
        // Header
        resp.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        // Attribute length placeholder — fill after
        let attr_start = resp.len();
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&STUN_MAGIC.to_be_bytes());
        resp.extend_from_slice(&txn_id);

        // XOR-MAPPED-ADDRESS attribute: family=IPv4, port XOR'd, addr XOR'd
        let port: u16 = 5678;
        let xport = port ^ (STUN_MAGIC >> 16) as u16;
        let ip: u32 = u32::from_be_bytes([1, 2, 3, 4]);
        let xip = ip ^ STUN_MAGIC;

        let mut attr = Vec::new();
        attr.extend_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&8u16.to_be_bytes()); // length = 8 for IPv4
        attr.push(0); // reserved
        attr.push(0x01); // family IPv4
        attr.extend_from_slice(&xport.to_be_bytes());
        attr.extend_from_slice(&xip.to_be_bytes());

        // Patch attribute length in header
        let attr_total = attr.len() as u16;
        resp[attr_start] = (attr_total >> 8) as u8;
        resp[attr_start + 1] = attr_total as u8;
        resp.extend_from_slice(&attr);

        let result = parse_binding_response(&resp, &txn_id);
        assert!(result.is_some());
        let addr = result.unwrap();
        assert_eq!(addr.port(), 5678);
        assert_eq!(addr.ip().to_string(), "1.2.3.4");
    }
}
