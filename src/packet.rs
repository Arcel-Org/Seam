use crate::error::ApexError;

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
    Initial   = 0x00,
    Handshake = 0x01,
    Data      = 0x02,
    Ack       = 0x03,
    FecRepair = 0x04,
    Chaff     = 0x05,
    PathProbe = 0x06,
    Close     = 0x07,
    /// Unreliable, out-of-order application datagram. No retransmission,
    /// no reordering, not FEC-protected by default. Analogous to QUIC
    /// DATAGRAM frame (RFC 9221).
    Datagram  = 0x08,
    /// Signals the peer to roll traffic keys forward by one epoch.
    KeyUpdate = 0x09,
}

impl TryFrom<u8> for PktType {
    type Error = ApexError;
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
            other => Err(ApexError::InvalidPktType(other)),
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
        ];
        for (raw, expected) in cases {
            assert_eq!(PktType::try_from(raw).unwrap(), expected);
        }
    }

    #[test]
    fn pkt_type_try_from_rejects_unknown_values() {
        assert!(matches!(
            PktType::try_from(0xFF),
            Err(ApexError::InvalidPktType(0xFF))
        ));
    }
}
