//! VPN Connection Manager (V3 SDK)
//!
//! Manages the lifecycle of V3 relay connections, coordinating:
//! - Configuration fetching from API
//! - UDP relay creation
//! - Split tunnel setup via ndisapi
//! - Connection state tracking with callbacks
//!
//! V3 only - no WireGuard, no Wintun adapter, no route management.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use crate::auth::types::VpnConfig;
use super::config::fetch_vpn_config;
use super::relay::UdpRelay;

/// Refresh interval for process scanning (ms)
const REFRESH_INTERVAL_MS: u64 = 50;

/// VPN connection state
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    FetchingConfig,
    Connecting,
    ConfiguringSplitTunnel,
    Connected {
        since: Instant,
        server_region: String,
        server_endpoint: String,
        split_tunnel_active: bool,
        tunneled_processes: Vec<String>,
    },
    Disconnecting,
    Error(String),
}

impl ConnectionState {
    pub fn is_connected(&self) -> bool {
        matches!(self, ConnectionState::Connected { .. })
    }

    pub fn is_connecting(&self) -> bool {
        matches!(
            self,
            ConnectionState::FetchingConfig
                | ConnectionState::Connecting
                | ConnectionState::ConfiguringSplitTunnel
        )
    }

    pub fn is_error(&self) -> bool {
        matches!(self, ConnectionState::Error(_))
    }

    pub fn error_message(&self) -> Option<&str> {
        match self {
            ConnectionState::Error(msg) => Some(msg),
            _ => None,
        }
    }

    pub fn status_text(&self) -> &'static str {
        match self {
            ConnectionState::Disconnected => "Disconnected",
            ConnectionState::FetchingConfig => "Fetching configuration...",
            ConnectionState::Connecting => "Connecting to server...",
            ConnectionState::ConfiguringSplitTunnel => "Configuring split tunnel...",
            ConnectionState::Connected { .. } => "Connected",
            ConnectionState::Disconnecting => "Disconnecting...",
            ConnectionState::Error(_) => "Error",
        }
    }

    /// Convert to FFI-friendly integer code
    pub fn as_code(&self) -> i32 {
        match self {
            ConnectionState::Disconnected => 0,
            ConnectionState::FetchingConfig => 1,
            ConnectionState::Connecting => 2,
            ConnectionState::ConfiguringSplitTunnel => 3,
            ConnectionState::Connected { .. } => 4,
            ConnectionState::Disconnecting => 5,
            ConnectionState::Error(_) => -1,
        }
    }
}

impl Default for ConnectionState {
    fn default() -> Self {
        ConnectionState::Disconnected
    }
}

/// VPN Connection manager (V3 relay only)
pub struct VpnConnection {
    state: Arc<Mutex<ConnectionState>>,
    relay: Option<Arc<UdpRelay>>,
    split_tunnel: Option<Arc<Mutex<crate::split_tunnel::SplitTunnelDriver>>>,
    config: Option<VpnConfig>,
    process_monitor_stop: Arc<AtomicBool>,
}

impl VpnConnection {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ConnectionState::Disconnected)),
            relay: None,
            split_tunnel: None,
            config: None,
            process_monitor_stop: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn state(&self) -> ConnectionState {
        self.state.lock().await.clone()
    }

    pub fn state_handle(&self) -> Arc<Mutex<ConnectionState>> {
        Arc::clone(&self.state)
    }

    /// Get the current config ID (for latency updates)
    pub fn get_config_id(&self) -> Option<String> {
        self.config.as_ref().map(|c| c.id.clone())
    }

    /// Get relay statistics (packets_sent, packets_received)
    pub fn relay_stats(&self) -> Option<(u64, u64)> {
        self.relay.as_ref().map(|r| r.stats())
    }

    async fn set_state(&self, state: ConnectionState) {
        log::info!("Connection state: {:?}", state);
        let code = state.as_code();
        if let Some(msg) = state.error_message() {
            crate::callbacks::fire_error(code, msg);
        }
        *self.state.lock().await = state;
        crate::callbacks::fire_state_change(code);
    }

    /// Connect to VPN server using V3 relay
    ///
    /// # Arguments
    /// * `access_token` - Bearer token for API authentication
    /// * `region` - Server region to connect to
    /// * `tunnel_apps` - Apps that SHOULD use VPN (games). Everything else bypasses.
    pub async fn connect(
        &mut self,
        access_token: &str,
        region: &str,
        tunnel_apps: Vec<String>,
    ) -> Result<(), crate::error::SdkError> {
        {
            let state = self.state.lock().await;
            if state.is_connected() {
                return Err(crate::error::SdkError::Vpn("Already connected".to_string()));
            }
            if state.is_connecting() {
                return Err(crate::error::SdkError::Vpn("Connection in progress".to_string()));
            }
        }

        log::info!("Starting V3 relay connection to region: {}", region);
        log::info!("Apps to tunnel: {:?}", tunnel_apps);

        // Step 1: Fetch configuration
        self.set_state(ConnectionState::FetchingConfig).await;
        let config = match fetch_vpn_config(access_token, region).await {
            Ok(c) => c,
            Err(e) => {
                self.set_state(ConnectionState::Error(e.to_string())).await;
                return Err(e);
            }
        };

        log::info!("V3: Server endpoint: {}", config.endpoint);
        self.config = Some(config.clone());

        // Step 2: Create UDP relay
        self.set_state(ConnectionState::Connecting).await;

        let vpn_ip = config.endpoint.split(':').next().unwrap_or(&config.endpoint);
        let relay_addr: SocketAddr = format!("{}:51821", vpn_ip)
            .parse()
            .map_err(|e| {
                let err = crate::error::SdkError::Vpn(format!("Invalid relay address: {}", e));
                // State update handled below
                err
            })?;

        log::info!("V3: Creating UDP relay to {}", relay_addr);

        let relay = match UdpRelay::new(relay_addr) {
            Ok(r) => Arc::new(r),
            Err(e) => {
                self.set_state(ConnectionState::Error(e.to_string())).await;
                return Err(e);
            }
        };

        self.relay = Some(Arc::clone(&relay));

        // Step 3: Configure split tunneling
        self.set_state(ConnectionState::ConfiguringSplitTunnel).await;

        let (tunneled_processes, split_tunnel_active) = if !tunnel_apps.is_empty() {
            match self.setup_split_tunnel(&config, &relay, tunnel_apps.clone()).await {
                Ok(processes) => {
                    log::info!("V3 split tunnel setup succeeded");
                    (processes, true)
                }
                Err(e) => {
                    log::error!("V3 split tunnel setup FAILED: {}", e);
                    self.cleanup().await;
                    self.set_state(ConnectionState::Error(format!(
                        "Split tunnel failed: {}",
                        e
                    ))).await;
                    return Err(e);
                }
            }
        } else {
            log::warn!("No tunnel apps specified");
            (Vec::new(), false)
        };

        // Step 4: Mark as connected
        self.set_state(ConnectionState::Connected {
            since: Instant::now(),
            server_region: config.region.clone(),
            server_endpoint: config.endpoint.clone(),
            split_tunnel_active,
            tunneled_processes,
        }).await;

        log::info!("V3 connected successfully (no encryption, lowest latency)");
        Ok(())
    }

    /// Setup V3 split tunneling - ndisapi + UDP relay
    async fn setup_split_tunnel(
        &mut self,
        _config: &VpnConfig,
        relay: &Arc<UdpRelay>,
        tunnel_apps: Vec<String>,
    ) -> Result<Vec<String>, crate::error::SdkError> {
        log::info!("Setting up V3 split tunnel...");

        // Check if driver is available
        if !crate::split_tunnel::SplitTunnelDriver::check_driver_available() {
            return Err(crate::error::SdkError::SplitTunnel(
                "Windows Packet Filter driver not available".to_string()
            ));
        }

        let mut driver = crate::split_tunnel::SplitTunnelDriver::new(tunnel_apps.clone());

        // Initialize driver (checks ndisapi availability)
        driver.initialize().map_err(|e| {
            crate::error::SdkError::SplitTunnel(format!("Failed to initialize driver: {}", e))
        })?;
        log::info!("V3: Split tunnel driver initialized");

        // Configure with tunnel apps (finds physical adapter)
        driver.configure(tunnel_apps.clone()).map_err(|e| {
            crate::error::SdkError::SplitTunnel(format!("Failed to configure split tunnel: {}", e))
        })?;
        log::info!("V3: Split tunnel configured");

        // Set relay context from the UdpRelay
        let relay_ctx = crate::split_tunnel::SplitTunnelDriver::relay_context_from_udp_relay(relay)
            .map_err(|e| {
                crate::error::SdkError::SplitTunnel(format!("Failed to create relay context: {}", e))
            })?;
        driver.set_relay_context(relay_ctx);
        log::info!("V3: UDP relay context set");

        // Start packet interception + ETW watcher
        driver.start().map_err(|e| {
            crate::error::SdkError::SplitTunnel(format!("Failed to start split tunnel: {}", e))
        })?;
        log::info!("V3: Split tunnel started");

        let running = driver.get_tunneled_processes();
        if !running.is_empty() {
            log::info!("V3: Currently tunneling: {:?}", running);
        }

        let driver = Arc::new(Mutex::new(driver));
        self.split_tunnel = Some(Arc::clone(&driver));

        // Start process monitor
        self.process_monitor_stop.store(false, Ordering::SeqCst);
        let stop_flag = Arc::clone(&self.process_monitor_stop);
        let state_handle = Arc::clone(&self.state);

        tokio::spawn(async move {
            log::info!("V3: Process monitor started ({}ms refresh)", REFRESH_INTERVAL_MS);

            loop {
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }

                tokio::time::sleep(Duration::from_millis(REFRESH_INTERVAL_MS)).await;

                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }

                let driver_guard = driver.lock().await;
                // Drain ETW events and refresh process cache
                driver_guard.drain_etw_events();
                driver_guard.refresh_processes();
                let running_names = driver_guard.get_tunneled_processes();
                drop(driver_guard);

                let mut state = state_handle.lock().await;
                if let ConnectionState::Connected {
                    ref mut tunneled_processes,
                    ..
                } = *state {
                    if *tunneled_processes != running_names {
                        if !running_names.is_empty() && tunneled_processes.is_empty() {
                            log::info!("V3: Game detected, relaying: {:?}", running_names);
                        } else if running_names.is_empty() && !tunneled_processes.is_empty() {
                            log::info!("V3: All games exited");
                        }
                        *tunneled_processes = running_names;
                    }
                }
            }

            log::info!("V3: Process monitor stopped");
        });

        log::info!("V3 split tunnel configured - game traffic relayed via UDP");
        Ok(running)
    }

    /// Disconnect from VPN
    pub async fn disconnect(&mut self) -> Result<(), crate::error::SdkError> {
        log::info!("Disconnecting VPN");
        self.set_state(ConnectionState::Disconnecting).await;
        self.cleanup().await;
        self.set_state(ConnectionState::Disconnected).await;
        log::info!("VPN disconnected");
        Ok(())
    }

    async fn cleanup(&mut self) {
        // Stop process monitor
        self.process_monitor_stop.store(true, Ordering::SeqCst);

        // Stop relay
        if let Some(ref relay) = self.relay {
            relay.stop();
        }
        self.relay = None;

        // Close split tunnel
        if let Some(ref driver) = self.split_tunnel {
            let mut guard = driver.lock().await;
            guard.close();
        }
        self.split_tunnel = None;

        self.config = None;
    }

    pub fn config(&self) -> Option<&VpnConfig> {
        self.config.as_ref()
    }

    pub fn is_split_tunnel_active(&self) -> bool {
        self.split_tunnel.is_some()
    }

    /// Add an app to the tunnel list while connected
    pub async fn add_tunnel_app(&mut self, exe_name: &str) -> Result<(), crate::error::SdkError> {
        if let Some(ref driver) = self.split_tunnel {
            let mut guard = driver.lock().await;
            if let Some(config) = guard.config.as_mut() {
                config.tunnel_apps.insert(exe_name.to_lowercase());
            }
            guard.refresh_exclusions()
                .map_err(|e| crate::error::SdkError::SplitTunnel(e.to_string()))?;
            Ok(())
        } else {
            Err(crate::error::SdkError::SplitTunnel("Split tunnel not active".to_string()))
        }
    }

    /// Remove an app from the tunnel list while connected
    pub async fn remove_tunnel_app(&mut self, exe_name: &str) -> Result<(), crate::error::SdkError> {
        if let Some(ref driver) = self.split_tunnel {
            let mut guard = driver.lock().await;
            if let Some(config) = guard.config.as_mut() {
                config.tunnel_apps.remove(&exe_name.to_lowercase());
            }
            guard.refresh_exclusions()
                .map_err(|e| crate::error::SdkError::SplitTunnel(e.to_string()))?;
            Ok(())
        } else {
            Err(crate::error::SdkError::SplitTunnel("Split tunnel not active".to_string()))
        }
    }
}

impl Default for VpnConnection {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for VpnConnection {
    fn drop(&mut self) {
        self.process_monitor_stop.store(true, Ordering::SeqCst);

        if let Some(ref relay) = self.relay {
            relay.stop();
        }
        if let Some(ref driver) = self.split_tunnel {
            if let Ok(mut guard) = driver.try_lock() {
                let _ = guard.close();
            }
        }
    }
}
