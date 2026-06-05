pub mod bandwidth;
pub mod bbr;
pub mod cc;
pub mod chaff;
pub mod congestion;
pub mod connection;
pub mod endpoint;
pub mod multipath;
pub mod pacer;
pub mod pool;
pub mod probe;
pub mod resumption;
pub mod rtt;
pub mod stats;
pub mod tar;
mod tests;

pub use bandwidth::BandwidthEstimator;
pub use bbr::Bbr;
pub use cc::{Aimd, CongestionControl, Cubic};
pub use congestion::{BbrController, BbrState, WindowedMaxFilter};
pub use rtt::RttEstimator;

/// Create the default congestion controller, respecting the `SEAM_CC`
/// environment variable (`bbr` or `cubic`).
pub fn default_cc() -> Box<dyn CongestionControl> {
    match std::env::var("SEAM_CC").as_deref() {
        Ok("bbr") => Box::new(Bbr::new()),
        _ => Box::new(Cubic::new()),
    }
}
pub use chaff::ChaffScheduler;
pub use connection::{ConnPhase, Connection};
pub use endpoint::{DEFAULT_MAX_CONNECTIONS, Endpoint, EndpointConfig};
pub use pacer::Pacer;
pub use pool::BufferPool;
pub use probe::PathProber;
pub use resumption::{SessionTicket, TicketKey, WEAKER_FS_WARNING};
pub use stats::ConnectionStats;
pub use tar::{
    CoverTrafficConfig, JitterConfig, PacketSizeClass, TarConfig, TarState,
    derive_obfuscation_secret, obfuscate_header, pad_to_size_class,
};
pub use multipath::{MultiPathEndpoint, PathScheduler, PathStat};
