#[derive(thiserror::Error, Debug)]
pub enum SeamError {
    #[error("authentication failed")]
    AuthFailed,
    #[error("replay detected: packet {0} already received")]
    Replay(u64),
    #[error("packet too old: {0}")]
    TooOld(u64),
    #[error("buffer too small: need {need}, have {have}")]
    BufferTooSmall { need: usize, have: usize },
    #[error("invalid packet type: {0}")]
    InvalidPktType(u8),
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),
    #[error("flow control blocked: requested {requested} but only {available} available")]
    FlowControlBlocked { available: u64, requested: u64 },
    #[error("unknown stream {0}")]
    UnknownStream(u32),
    #[error("stream {0} is already finished")]
    StreamFinished(u32),
    #[error("protocol violation: {0}")]
    ProtocolViolation(String),
    #[error("packet too large: {have} bytes exceeds maximum {max}")]
    PacketTooLarge { have: usize, max: usize },
}
