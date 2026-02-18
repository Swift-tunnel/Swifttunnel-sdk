//! VPN Connection Manager (V3 SDK)
//!
//! Manages V3 relay lifecycle:
//! - Relay endpoint resolution
//! - Relay auth ticket bootstrap
//! - Split tunnel setup (ndisapi)
//! - Optional auto-routing

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::sync::Mutex;

use crate::auth::client::AuthClient;
use crate::auth::types::VpnConfig;
use crate::callbacks::{fire_auto_routing_event, fire_error, fire_state_change};

use super::auto_routing::{AutoRouter, AutoRoutingEvent};
use super::geolocation::lookup_game_server_region;
use super::relay::{RelayAuthAckStatus, UdpRelay};
use super::servers::measure_latency_icmp;

const REFRESH_INTERVAL_MS: u64 = 50;
const AUTO_ROUTING_PING_SAMPLES: usize = 5;

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn normalize_region(region: &str) -> String {
    let trimmed = region.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "america" | "us" | "usa" => "america".to_string(),
        _ => trimmed,
    }
}

fn pick_lowest_latency_server<'a>(
    candidates: impl Iterator<Item = &'a (String, SocketAddr, Option<u32>)>,
) -> Option<&'a (String, SocketAddr, Option<u32>)> {
    candidates.min_by_key(|(_, _, latency_ms)| latency_ms.unwrap_or(u32::MAX))
}

pub(crate) fn relay_candidates_for_region(
    selected_region: &str,
    available_servers: &[(String, SocketAddr, Option<u32>)],
    forced_server: Option<&str>,
) -> Vec<(String, SocketAddr, Option<u32>)> {
    if let Some(pinned) = forced_server {
        if let Some((region, relay_addr, latency_ms)) = available_servers
            .iter()
            .find(|(region, _, _)| region == pinned)
        {
            return vec![(region.clone(), *relay_addr, *latency_ms)];
        }
    }

    if selected_region == "america" {
        let mut us_candidates = available_servers
            .iter()
            .filter(|(region, _, _)| region.starts_with("us-"))
            .map(|(region, relay_addr, latency_ms)| (region.clone(), *relay_addr, *latency_ms))
            .collect::<Vec<_>>();
        if !us_candidates.is_empty() {
            return us_candidates;
        }
    }

    let exact = available_servers
        .iter()
        .filter(|(region, _, _)| region == selected_region)
        .map(|(region, relay_addr, latency_ms)| (region.clone(), *relay_addr, *latency_ms))
        .collect::<Vec<_>>();
    if !exact.is_empty() {
        return exact;
    }

    let prefix = format!("{selected_region}-");
    available_servers
        .iter()
        .filter(|(region, _, _)| region.starts_with(&prefix))
        .map(|(region, relay_addr, latency_ms)| (region.clone(), *relay_addr, *latency_ms))
        .collect()
}

fn should_probe_candidates(candidates: &[(String, SocketAddr, Option<u32>)]) -> bool {
    candidates.len() > 1
        && candidates
            .iter()
            .any(|(_, _, latency_ms)| latency_ms.is_none())
}

fn average_probe_latency(samples: &[u32]) -> Option<u32> {
    if samples.is_empty() {
        return None;
    }

    let total: u64 = samples.iter().map(|v| *v as u64).sum();
    Some((total / samples.len() as u64) as u32)
}

fn resolve_relay_server_from_candidates(
    candidates: &[(String, SocketAddr, Option<u32>)],
    probe_result: Option<(String, SocketAddr, u32)>,
) -> Option<(String, SocketAddr)> {
    if candidates.is_empty() {
        return None;
    }

    if candidates.len() == 1 {
        let (region, relay_addr, _) = &candidates[0];
        return Some((region.clone(), *relay_addr));
    }

    if should_probe_candidates(candidates) {
        if let Some((region, relay_addr, _)) = probe_result {
            return Some((region, relay_addr));
        }
    }

    pick_lowest_latency_server(candidates.iter())
        .map(|(region, relay_addr, _)| (region.clone(), *relay_addr))
}

async fn resolve_relay_server_for_region_with_probing(
    selected_region: &str,
    available_servers: &[(String, SocketAddr, Option<u32>)],
    forced_server: Option<&str>,
) -> Option<(String, SocketAddr)> {
    let candidates = relay_candidates_for_region(selected_region, available_servers, forced_server);
    let probe_result = if should_probe_candidates(&candidates) {
        let probe_targets = candidates
            .iter()
            .map(|(region, relay_addr, _)| (region.clone(), *relay_addr))
            .collect::<Vec<_>>();
        ping_and_select_best(&probe_targets).await
    } else {
        None
    };

    resolve_relay_server_from_candidates(&candidates, probe_result)
}

async fn ping_and_select_best(
    candidates: &[(String, SocketAddr)],
) -> Option<(String, SocketAddr, u32)> {
    let mut tasks = Vec::new();
    for (region, addr) in candidates {
        let region = region.clone();
        let addr = *addr;
        tasks.push(tokio::spawn(async move {
            let ip = addr.ip().to_string();
            let result = tokio::task::spawn_blocking(move || {
                let mut samples = Vec::with_capacity(AUTO_ROUTING_PING_SAMPLES);
                for _ in 0..AUTO_ROUTING_PING_SAMPLES {
                    if let Some(ms) = measure_latency_icmp(&ip) {
                        samples.push(ms);
                    }
                }
                average_probe_latency(&samples).map(|avg| (avg, samples.len()))
            })
            .await;

            match result {
                Ok(Some((avg_ms, _))) => Some((region, addr, avg_ms)),
                _ => None,
            }
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

async fn resolve_custom_relay_addr(custom: &str) -> Result<SocketAddr, crate::error::SdkError> {
    let (host, port_str) = custom.rsplit_once(':').ok_or_else(|| {
        crate::error::SdkError::InvalidParam(format!(
            "custom_relay_server '{}' must be host:port",
            custom
        ))
    })?;

    let port: u16 = port_str.parse().map_err(|e| {
        crate::error::SdkError::InvalidParam(format!(
            "Invalid port in custom_relay_server '{}': {}",
            custom, e
        ))
    })?;

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    let mut addrs = tokio::net::lookup_host(format!("{}:{}", host, port))
        .await
        .map_err(|e| {
            crate::error::SdkError::Network(format!(
                "Failed to resolve custom_relay_server '{}': {}",
                custom, e
            ))
        })?;
    addrs.next().ok_or_else(|| {
        crate::error::SdkError::Network(format!(
            "DNS resolution returned no addresses for '{}'",
            custom
        ))
    })
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
        assigned_ip: String,
        relay_auth_mode: String,
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
            ConnectionState::FetchingConfig => "Resolving relay endpoint...",
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
            None,
            false,
            Vec::new(),
            Vec::new(),
            HashMap::new(),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn connect_ex(
        &mut self,
        access_token: &str,
        region: &str,
        tunnel_apps: Vec<String>,
        custom_relay_server: Option<String>,
        auto_routing_enabled: bool,
        available_servers: Vec<(String, SocketAddr, Option<u32>)>,
        whitelisted_regions: Vec<String>,
        forced_servers: HashMap<String, String>,
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
        let normalized_region = normalize_region(region);

        let (resolved_server_region, default_relay_addr): (String, Option<SocketAddr>) =
            if available_servers.is_empty() {
                if custom_relay_server.is_some() {
                    (normalized_region.clone(), None)
                } else {
                    let err = crate::error::SdkError::Config(
                        "Selected region is unavailable in server list".to_string(),
                    );
                    self.set_state(ConnectionState::Error(err.to_string()))
                        .await;
                    return Err(err);
                }
            } else {
                let forced_for_region = forced_servers.get(&normalized_region).map(|s| s.as_str());
                let selected = resolve_relay_server_for_region_with_probing(
                    &normalized_region,
                    &available_servers,
                    forced_for_region,
                )
                .await;

                match selected {
                    Some((server_region, relay_addr)) => (server_region, Some(relay_addr)),
                    None => {
                        let err = crate::error::SdkError::Config(format!(
                            "Selected region '{}' is unavailable in server list",
                            normalized_region
                        ));
                        self.set_state(ConnectionState::Error(err.to_string()))
                            .await;
                        return Err(err);
                    }
                }
            };

        self.set_state(ConnectionState::Connecting).await;
        let relay_addr = if let Some(custom) = custom_relay_server.as_deref() {
            match resolve_custom_relay_addr(custom).await {
                Ok(addr) => addr,
                Err(err) => {
                    self.set_state(ConnectionState::Error(err.to_string()))
                        .await;
                    return Err(err);
                }
            }
        } else {
            match default_relay_addr {
                Some(addr) => addr,
                None => {
                    let err = crate::error::SdkError::Config(
                        "No relay endpoint available for selected region".to_string(),
                    );
                    self.set_state(ConnectionState::Error(err.to_string()))
                        .await;
                    return Err(err);
                }
            }
        };

        let relay = match UdpRelay::new(relay_addr) {
            Ok(relay) => Arc::new(relay),
            Err(err) => {
                self.set_state(ConnectionState::Error(err.to_string()))
                    .await;
                return Err(err);
            }
        };
        self.relay = Some(Arc::clone(&relay));

        let mut relay_auth_mode = if custom_relay_server.is_some() {
            "custom_legacy".to_string()
        } else {
            "legacy_fallback".to_string()
        };

        if custom_relay_server.is_none() {
            let auth_client = AuthClient::new();
            let session_id_hex = relay.session_id_hex();
            match auth_client
                .get_relay_ticket(access_token, &resolved_server_region, &session_id_hex)
                .await
            {
                Ok(ticket) => match relay.authenticate_with_ticket(&ticket.token) {
                    Ok(Some(RelayAuthAckStatus::Ok)) => {
                        relay_auth_mode = "authenticated".to_string();
                    }
                    Ok(Some(status)) => {
                        if ticket.auth_required {
                            let err = crate::error::SdkError::Vpn(format!(
                                "Relay authentication required but failed ({})",
                                status.as_str()
                            ));
                            self.set_state(ConnectionState::Error(err.to_string()))
                                .await;
                            return Err(err);
                        }
                    }
                    Ok(None) => {
                        if ticket.auth_required {
                            let err = crate::error::SdkError::Vpn(
                                "Relay authentication required but relay did not acknowledge auth hello"
                                    .to_string(),
                            );
                            self.set_state(ConnectionState::Error(err.to_string()))
                                .await;
                            return Err(err);
                        }
                    }
                    Err(e) => {
                        if ticket.auth_required {
                            self.set_state(ConnectionState::Error(e.to_string())).await;
                            return Err(e);
                        }
                    }
                },
                Err(e) => {
                    log::warn!(
                        "Relay ticket unavailable for '{}' ({}), using legacy fallback mode",
                        resolved_server_region,
                        e
                    );
                }
            }
        }

        self.set_state(ConnectionState::ConfiguringSplitTunnel)
            .await;

        let config = VpnConfig {
            region: resolved_server_region.clone(),
            endpoint: relay_addr.to_string(),
            assigned_ip: "V3-Relay".to_string(),
            ..Default::default()
        };
        self.config = Some(config.clone());

        let (tunneled_processes, split_tunnel_active) = if !tunnel_apps.is_empty() {
            match self
                .setup_split_tunnel(
                    &config,
                    &relay,
                    tunnel_apps.clone(),
                    auto_routing_enabled,
                    available_servers,
                    whitelisted_regions,
                    forced_servers,
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
            server_region: resolved_server_region,
            server_endpoint: relay_addr.to_string(),
            assigned_ip: "V3-Relay".to_string(),
            relay_auth_mode,
            split_tunnel_active,
            tunneled_processes,
        })
        .await;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn setup_split_tunnel(
        &mut self,
        config: &VpnConfig,
        relay: &Arc<UdpRelay>,
        tunnel_apps: Vec<String>,
        auto_routing_enabled: bool,
        available_servers: Vec<(String, SocketAddr, Option<u32>)>,
        whitelisted_regions: Vec<String>,
        forced_servers: HashMap<String, String>,
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
        auto_router.set_forced_servers(forced_servers);
        if !whitelisted_regions.is_empty() {
            auto_router.set_whitelisted_regions(whitelisted_regions);
        }

        if auto_routing_enabled {
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

                            if let Some(target_region) = region.best_swifttunnel_region() {
                                let forced_server =
                                    router_for_lookup.forced_server_for_region(target_region);
                                let available_servers =
                                    router_for_lookup.available_servers_snapshot();
                                if let Some((selected_region, selected_addr)) =
                                    resolve_relay_server_for_region_with_probing(
                                        target_region,
                                        &available_servers,
                                        forced_server.as_deref(),
                                    )
                                    .await
                                {
                                    if let Some((new_addr, new_region)) = router_for_lookup
                                        .commit_switch(
                                            region.clone(),
                                            selected_region,
                                            selected_addr,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_servers() -> Vec<(String, SocketAddr, Option<u32>)> {
        vec![
            (
                "us-east-nj".to_string(),
                "108.61.7.6:51821".parse().unwrap(),
                Some(35),
            ),
            (
                "us-central-tx".to_string(),
                "45.77.55.34:51821".parse().unwrap(),
                Some(45),
            ),
            (
                "us-west-sj".to_string(),
                "149.28.232.77:51821".parse().unwrap(),
                Some(75),
            ),
            (
                "tokyo-02".to_string(),
                "45.32.253.124:51821".parse().unwrap(),
                Some(95),
            ),
        ]
    }

    #[test]
    fn relay_candidates_exact_and_prefix_match() {
        let servers = sample_servers();
        let tokyo_candidates = relay_candidates_for_region("tokyo", &servers, None);
        assert_eq!(tokyo_candidates.len(), 1);
        assert_eq!(tokyo_candidates[0].0, "tokyo-02");

        let east_candidates = relay_candidates_for_region("us-east", &servers, None);
        assert_eq!(east_candidates.len(), 1);
        assert_eq!(east_candidates[0].0, "us-east-nj");
    }

    #[test]
    fn relay_candidates_support_legacy_america_alias() {
        let servers = sample_servers();
        let us_candidates = relay_candidates_for_region("america", &servers, None);

        assert_eq!(us_candidates.len(), 3);
        assert!(us_candidates
            .iter()
            .all(|(region, _, _)| region.starts_with("us-")));
    }

    #[test]
    fn relay_candidates_honor_forced_server() {
        let servers = sample_servers();
        let forced = relay_candidates_for_region("us-east", &servers, Some("us-west-sj"));

        assert_eq!(forced.len(), 1);
        assert_eq!(forced[0].0, "us-west-sj");
    }

    #[test]
    fn resolve_candidates_prefers_probe_result_when_needed() {
        let candidates = vec![
            (
                "us-east-nj".to_string(),
                "108.61.7.6:51821".parse().unwrap(),
                None,
            ),
            (
                "us-central-tx".to_string(),
                "45.77.55.34:51821".parse().unwrap(),
                None,
            ),
        ];
        let probe = Some((
            "us-central-tx".to_string(),
            "45.77.55.34:51821".parse().unwrap(),
            31,
        ));

        let selected = resolve_relay_server_from_candidates(&candidates, probe).unwrap();
        assert_eq!(selected.0, "us-central-tx");
    }

    #[test]
    fn resolve_candidates_fallbacks_to_lowest_cached_latency() {
        let candidates = vec![
            (
                "us-east-nj".to_string(),
                "108.61.7.6:51821".parse().unwrap(),
                Some(40),
            ),
            (
                "us-central-tx".to_string(),
                "45.77.55.34:51821".parse().unwrap(),
                Some(55),
            ),
        ];

        let selected = resolve_relay_server_from_candidates(&candidates, None).unwrap();
        assert_eq!(selected.0, "us-east-nj");
    }

    #[test]
    fn custom_relay_requires_host_and_port() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(resolve_custom_relay_addr("relay.example.com"))
            .unwrap_err();
        assert!(matches!(err, crate::error::SdkError::InvalidParam(_)));
    }
}
