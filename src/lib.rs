// Copyright (c) 2025 Arcel
// SPDX-License-Identifier: AGPL-3.0-only

pub mod api;
pub mod bufpool;
pub mod crypto;
pub mod error;
pub mod fec;
pub mod handshake;
pub mod packet;
pub mod session;
pub mod transport;
pub mod tunnel;

// Re-export stream priority constants for external use
pub use session::stream::{PRIORITY_DEFAULT, PRIORITY_HIGH, PRIORITY_LOW, Priority};

pub use crypto::CipherSuite;
pub use crypto::decoder::PacketDecoder;
pub use crypto::encoder::PacketEncoder;
pub use crypto::keys::PacketKeys;
pub use error::SeamError;
pub use packet::PktType;
