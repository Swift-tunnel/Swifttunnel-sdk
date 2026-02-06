//! VPN Module for SwiftTunnel SDK
//!
//! V3 relay-only implementation. Routes game traffic through optimized
//! server paths without encryption for minimum latency.
//!
//! ## Architecture
//!
//! - relay.rs: UDP relay client (session-based packet forwarding)
//! - config.rs: VPN configuration fetching from API
//! - servers.rs: Server list, caching, and latency measurement
//! - connection.rs: V3 connection state machine and lifecycle

pub mod relay;
pub mod config;
pub mod servers;
pub mod connection;

pub use relay::{UdpRelay, RelayContext};
pub use config::{fetch_vpn_config, update_latency, VpnConfigRequest};
pub use servers::{
    ServerList, DynamicServerInfo, DynamicGamingRegion,
    ServerListSource, load_server_list, measure_latency,
};
pub use connection::{VpnConnection, ConnectionState};
