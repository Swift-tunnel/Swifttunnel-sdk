//! VPN Connection Manager (V3 SDK)
//!
//! Manages V3 relay lifecycle:
//! - Config fetch
//! - UDP relay creation
//! - Split tunnel setup (ndisapi)
//! - Optional auto-routing

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::sync::Mutex;

use crate::auth::types::VpnConfig;
use crate::callbacks::{fire_auto_routing_event, fire_error, fire_state_change};

use super::auto_routing::{AutoRouter, AutoRoutingEvent};
use super::config::fetch_vpn_config;
use super::geolocation::lookup_game_server_region;
use super::relay::UdpRelay;

const REFRESH_INTERVAL_MS: u64 = 50;

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

async fn ping_and_select_best(
    candidates: &[(String, SocketAddr)],
) -> Option<(String, SocketAddr, u32)> {
    let mut tasks = Vec::new();
    for (region, addr) in candidates {
        let region = region.clone();
        let addr = *addr;
        tasks.push(tokio::spawn(async move {
            let endpoint = addr.to_string();
            super::servers::measure_latency(&endpoint)
                .await
                .map(|ms| (region, addr, ms))
        }));
    }

    let mut best: Option<(String, SocketAddr, u32)> = None;
    for task in tasks {
        if let Ok(Some((region, addr, ms))) = task.await {
            if best.as_ref().map_or(true, |(_, _, best_ms)| ms < *best_ms) {
                best = Some((region, addr, ms));
            }
        }
    }
    best
}

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

pub struct VpnConnection {
    state: Arc<Mutex<ConnectionState>>,
    relay: Option<Arc<UdpRelay>>,
    split_tunnel: Option<Arc<Mutex<crate::split_tunnel::SplitTunnelDriver>>>,
    config: Option<VpnConfig>,
    process_monitor_stop: Arc<AtomicBool>,
    auto_router: Option<Arc<AutoRouter>>,
}

impl VpnConnection {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ConnectionState::Disconnected)),
            relay: None,
            split_tunnel: None,
            config: None,
            process_monitor_stop: Arc::new(AtomicBool::new(false)),
            auto_router: None,
        }
    }

    pub async fn state(&self) -> ConnectionState {
        self.state.lock().await.clone()
    }

    pub fn state_handle(&self) -> Arc<Mutex<ConnectionState>> {
        Arc::clone(&self.state)
    }

    pub fn get_config_id(&self) -> Option<String> {
        self.config.as_ref().map(|c| c.id.clone())
    }

    pub fn relay_stats(&self) -> Option<(u64, u64)> {
        self.relay.as_ref().map(|r| r.stats())
    }

    pub fn auto_routing_snapshot(&self) -> Option<serde_json::Value> {
        let router = self.auto_router.as_ref()?;
        let events = router
            .recent_events(20)
            .into_iter()
            .map(|e: AutoRoutingEvent| {
                json!({
                    "type": e.event_type,
                    "timestamp_ms": e.timestamp_ms,
                    "from_region": e.from_region,
                    "to_region": e.to_region,
                    "game_server_region": e.game_server_region,
                    "reason": e.reason,
                    "location": e.location,
                    "relay_addr": e.relay_addr,
                })
            })
            .collect::<Vec<_>>();

        Some(json!({
            "enabled": router.is_enabled(),
            "current_region": router.current_region(),
            "game_region": router.current_game_region().map(|r| r.display_name().to_string()),
            "bypassed": router.is_bypassed(),
            "pending_lookups": router.pending_lookup_count(),
            "events": events,
        }))
    }

    async fn set_state(&self, state: ConnectionState) {
        log::info!("Connection state: {:?}", state);
        let code = state.as_code();
        if let Some(msg) = state.error_message() {
            fire_error(code, msg);
        }
        *self.state.lock().await = state;
        fire_state_change(code);
    }

    pub async fn connect(
        &mut self,
        access_token: &str,
        region: &str,
        tunnel_apps: Vec<String>,
    ) -> Result<(), crate::error::SdkError> {
        self.connect_ex(
            access_token,
            region,
            tunnel_apps,
            false,
            Vec::new(),
            Vec::new(),
        )
        .await
    }

    pub async fn connect_ex(
        &mut self,
        access_token: &str,
        region: &str,
        tunnel_apps: Vec<String>,
        auto_routing_enabled: bool,
        available_servers: Vec<(String, SocketAddr, Option<u32>)>,
        whitelisted_regions: Vec<String>,
    ) -> Result<(), crate::error::SdkError> {
        {
            let state = self.state.lock().await;
            if state.is_connected() {
                return Err(crate::error::SdkError::Vpn("Already connected".to_string()));
            }
            if state.is_connecting() {
                return Err(crate::error::SdkError::Vpn(
                    "Connection in progress".to_string(),
                ));
            }
        }

        self.set_state(ConnectionState::FetchingConfig).await;
        let config = match fetch_vpn_config(access_token, region).await {
            Ok(c) => c,
            Err(e) => {
                self.set_state(ConnectionState::Error(e.to_string())).await;
                return Err(e);
            }
        };

        self.config = Some(config.clone());

        self.set_state(ConnectionState::Connecting).await;
        let vpn_ip = config
            .endpoint
            .split(':')
            .next()
            .unwrap_or(&config.endpoint);
        let relay_addr: SocketAddr = format!("{}:51821", vpn_ip)
            .parse()
            .map_err(|e| crate::error::SdkError::Vpn(format!("Invalid relay address: {}", e)))?;

        let relay = Arc::new(UdpRelay::new(relay_addr)?);
        self.relay = Some(Arc::clone(&relay));

        self.set_state(ConnectionState::ConfiguringSplitTunnel)
            .await;

        let (tunneled_processes, split_tunnel_active) = if !tunnel_apps.is_empty() {
            match self
                .setup_split_tunnel(
                    &config,
                    &relay,
                    tunnel_apps.clone(),
                    auto_routing_enabled,
                    available_servers,
                    whitelisted_regions,
                )
                .await
            {
                Ok(processes) => (processes, true),
                Err(e) => {
                    self.cleanup().await;
                    self.set_state(ConnectionState::Error(format!(
                        "Split tunnel failed: {}",
                        e
                    )))
                    .await;
                    return Err(e);
                }
            }
        } else {
            (Vec::new(), false)
        };

        self.set_state(ConnectionState::Connected {
            since: Instant::now(),
            server_region: config.region.clone(),
            server_endpoint: config.endpoint.clone(),
            split_tunnel_active,
            tunneled_processes,
        })
        .await;

        Ok(())
    }

    async fn setup_split_tunnel(
        &mut self,
        config: &VpnConfig,
        relay: &Arc<UdpRelay>,
        tunnel_apps: Vec<String>,
        auto_routing_enabled: bool,
        available_servers: Vec<(String, SocketAddr, Option<u32>)>,
        whitelisted_regions: Vec<String>,
    ) -> Result<Vec<String>, crate::error::SdkError> {
        if !crate::split_tunnel::SplitTunnelDriver::check_driver_available() {
            return Err(crate::error::SdkError::SplitTunnel(
                "Windows Packet Filter driver not available".to_string(),
            ));
        }

        let mut driver = crate::split_tunnel::SplitTunnelDriver::new(tunnel_apps.clone());
        driver.initialize().map_err(|e| {
            crate::error::SdkError::SplitTunnel(format!("Failed to initialize driver: {}", e))
        })?;
        driver.configure(tunnel_apps.clone()).map_err(|e| {
            crate::error::SdkError::SplitTunnel(format!("Failed to configure split tunnel: {}", e))
        })?;

        let relay_ctx =
            crate::split_tunnel::SplitTunnelDriver::relay_context_from_udp_relay(relay)?;
        driver.set_relay_context(relay_ctx);

        let auto_router = Arc::new(AutoRouter::new(auto_routing_enabled, &config.region));
        auto_router.set_current_relay(relay.relay_addr(), &config.region);
        auto_router.set_available_servers(available_servers.clone());
        if !whitelisted_regions.is_empty() {
            auto_router.set_whitelisted_regions(whitelisted_regions);
        }

        if auto_routing_enabled {
            if available_servers.is_empty() {
                let reason =
                    "Auto-routing enabled but no available servers; continuing without switching"
                        .to_string();
                auto_router.push_degraded_event(reason.clone());
                auto_router.set_enabled(false);
                fire_auto_routing_event(
                    &json!({
                        "type": "degraded",
                        "timestamp_ms": now_millis(),
                        "from_region": config.region,
                        "to_region": config.region,
                        "game_server_region": "Unknown",
                        "location": null,
                        "relay_addr": relay.relay_addr().to_string(),
                        "reason": reason,
                    })
                    .to_string(),
                );
            } else {
                let (lookup_tx, mut lookup_rx) =
                    tokio::sync::mpsc::unbounded_channel::<std::net::Ipv4Addr>();
                auto_router.set_lookup_channel(lookup_tx);

                let router_for_lookup = Arc::clone(&auto_router);
                let relay_for_lookup = Arc::clone(relay);
                tokio::spawn(async move {
                    while let Some(ip) = lookup_rx.recv().await {
                        match lookup_game_server_region(ip).await {
                            Some((region, location)) => {
                                let old_region = router_for_lookup.current_region();
                                let candidates =
                                    router_for_lookup.get_candidates_for_region(&region);

                                if let Some(candidates) = candidates {
                                    let best = ping_and_select_best(&candidates).await;
                                    let selected = best
                                        .map(|(r, a, _)| (r, a))
                                        .unwrap_or_else(|| candidates[0].clone());

                                    if let Some((new_addr, new_region)) = router_for_lookup
                                        .commit_switch(
                                            region.clone(),
                                            selected.0,
                                            selected.1,
                                            Some(location.clone()),
                                        )
                                    {
                                        relay_for_lookup.switch_relay(new_addr);
                                        let _ = relay_for_lookup.send_keepalive_burst();
                                        fire_auto_routing_event(
                                            &json!({
                                                "type": "relay_switched",
                                                "timestamp_ms": now_millis(),
                                                "from_region": old_region,
                                                "to_region": new_region,
                                                "game_server_region": region.display_name(),
                                                "location": location,
                                                "relay_addr": new_addr.to_string(),
                                                "reason": format!(
                                                    "Game server moved to {}",
                                                    region.display_name()
                                                ),
                                            })
                                            .to_string(),
                                        );
                                    }
                                }
                                router_for_lookup.clear_pending_lookup(ip);
                            }
                            None => {
                                router_for_lookup.clear_pending_lookup(ip);
                            }
                        }
                    }
                });
            }
        }

        driver.set_auto_router(Arc::clone(&auto_router));
        self.auto_router = Some(Arc::clone(&auto_router));

        driver.start().map_err(|e| {
            crate::error::SdkError::SplitTunnel(format!("Failed to start split tunnel: {}", e))
        })?;

        let running = driver.get_tunneled_processes();
        let driver = Arc::new(Mutex::new(driver));
        self.split_tunnel = Some(Arc::clone(&driver));

        self.process_monitor_stop.store(false, Ordering::SeqCst);
        let stop_flag = Arc::clone(&self.process_monitor_stop);
        let state_handle = Arc::clone(&self.state);
        let auto_router_for_monitor = self.auto_router.clone();

        tokio::spawn(async move {
            while !stop_flag.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(REFRESH_INTERVAL_MS)).await;
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }

                let driver_guard = driver.lock().await;
                driver_guard.drain_etw_events();
                driver_guard.refresh_processes();
                let running_names = driver_guard.get_tunneled_processes();
                drop(driver_guard);

                let mut state = state_handle.lock().await;
                if let ConnectionState::Connected {
                    ref mut tunneled_processes,
                    ref mut server_region,
                    ..
                } = *state
                {
                    if *tunneled_processes != running_names {
                        *tunneled_processes = running_names;
                    }

                    if let Some(ref auto_router) = auto_router_for_monitor {
                        let routed_region = auto_router.current_region();
                        if !routed_region.is_empty() && *server_region != routed_region {
                            *server_region = routed_region;
                        }
                    }
                }
            }
        });

        Ok(running)
    }

    pub async fn disconnect(&mut self) -> Result<(), crate::error::SdkError> {
        self.set_state(ConnectionState::Disconnecting).await;
        self.cleanup().await;
        self.set_state(ConnectionState::Disconnected).await;
        Ok(())
    }

    async fn cleanup(&mut self) {
        self.process_monitor_stop.store(true, Ordering::SeqCst);

        if let Some(ref relay) = self.relay {
            relay.stop();
        }
        self.relay = None;

        if let Some(ref auto_router) = self.auto_router {
            auto_router.reset();
        }
        self.auto_router = None;

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

    pub async fn add_tunnel_app(&mut self, _exe_name: &str) -> Result<(), crate::error::SdkError> {
        Err(crate::error::SdkError::SplitTunnel(
            "Dynamic tunnel app updates are not supported in this SDK build".to_string(),
        ))
    }

    pub async fn remove_tunnel_app(
        &mut self,
        _exe_name: &str,
    ) -> Result<(), crate::error::SdkError> {
        Err(crate::error::SdkError::SplitTunnel(
            "Dynamic tunnel app updates are not supported in this SDK build".to_string(),
        ))
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
                guard.close();
            }
        }
    }
}
