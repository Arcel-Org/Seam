use crate::error::SeamError;

pub const HEADER_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const MIN_PACKET_LEN: usize = HEADER_LEN + TAG_LEN;

/// Minimum output buffer size for encoding `plaintext_len` bytes.
pub fn encode_buf_len(plaintext_len: usize) -> usize {
    HEADER_LEN + plaintext_len + TAG_LEN
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PktType {
    Initial = 0x00,
    Handshake = 0x01,
    Data = 0x02,
    Ack = 0x03,
    FecRepair = 0x04,
    Chaff = 0x05,
    PathProbe = 0x06,
    Close = 0x07,
    /// Unreliable, out-of-order application datagram. No retransmission,
    /// no reordering, not FEC-protected by default. Analogous to QUIC
    /// DATAGRAM frame (RFC 9221).
    Datagram = 0x08,
    /// Signals the peer to roll traffic keys forward by one epoch.
    KeyUpdate = 0x09,
    /// Extends the peer's send-side flow-control window. Payload: 8-byte BE u64 new limit.
    MaxData = 0x0A,
    /// Keepalive ping — elicits a Pong from the peer.
    Ping = 0x0B,
    /// Keepalive pong — response to Ping, resets idle timer.
    Pong = 0x0C,
    /// Encrypted session ticket for 0-RTT resumption.
    SessionTicket = 0x0D,
}

impl TryFrom<u8> for PktType {
    type Error = SeamError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x00 => Ok(Self::Initial),
            0x01 => Ok(Self::Handshake),
            0x02 => Ok(Self::Data),
            0x03 => Ok(Self::Ack),
            0x04 => Ok(Self::FecRepair),
            0x05 => Ok(Self::Chaff),
            0x06 => Ok(Self::PathProbe),
            0x07 => Ok(Self::Close),
            0x08 => Ok(Self::Datagram),
            0x09 => Ok(Self::KeyUpdate),
            0x0A => Ok(Self::MaxData),
            0x0B => Ok(Self::Ping),
            0x0C => Ok(Self::Pong),
            0x0D => Ok(Self::SessionTicket),
            other => Err(SeamError::InvalidPktType(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_buf_len_accounts_for_header_and_tag() {
        assert_eq!(encode_buf_len(0), MIN_PACKET_LEN);
        assert_eq!(encode_buf_len(128), HEADER_LEN + 128 + TAG_LEN);
    }

    #[test]
    fn pkt_type_try_from_accepts_all_defined_values() {
        let cases = [
            (0x00, PktType::Initial),
            (0x01, PktType::Handshake),
            (0x02, PktType::Data),
            (0x03, PktType::Ack),
            (0x04, PktType::FecRepair),
            (0x05, PktType::Chaff),
            (0x06, PktType::PathProbe),
            (0x07, PktType::Close),
            (0x08, PktType::Datagram),
            (0x09, PktType::KeyUpdate),
            (0x0A, PktType::MaxData),
            (0x0B, PktType::Ping),
            (0x0C, PktType::Pong),
            (0x0D, PktType::SessionTicket),
        ];
        for (raw, expected) in cases {
            assert_eq!(PktType::try_from(raw).unwrap(), expected);
        }
    }

    #[test]
    fn pkt_type_try_from_rejects_unknown_values() {
        assert!(matches!(
            PktType::try_from(0xFF),
            Err(SeamError::InvalidPktType(0xFF))
        ));
    }
}
