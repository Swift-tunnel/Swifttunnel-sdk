//! Auto routing: detect game-server region changes and switch relay dynamically.

use super::geolocation::RobloxRegion;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MIN_SWITCH_INTERVAL: Duration = Duration::from_secs(10);
const MAX_SWITCHES_PER_MINUTE: u32 = 3;
const MAX_EVENT_LOG: usize = 20;

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone)]
pub struct AutoRoutingEvent {
    pub timestamp_ms: u64,
    pub event_type: String,
    pub from_region: String,
    pub to_region: String,
    pub game_server_region: String,
    pub reason: String,
    pub location: Option<String>,
    pub relay_addr: Option<String>,
}

#[derive(Debug)]
pub enum AutoRoutingAction {
    NoAction,
}

pub struct AutoRouter {
    enabled: AtomicBool,
    current_game_region: RwLock<Option<RobloxRegion>>,
    current_relay_addr: RwLock<Option<SocketAddr>>,
    current_st_region: RwLock<String>,
    last_switch_time: RwLock<Instant>,
    switches_this_minute: RwLock<(u32, Instant)>,
    seen_game_servers: RwLock<HashSet<Ipv4Addr>>,
    available_servers: RwLock<Vec<(String, SocketAddr, Option<u32>)>>,
    event_log: RwLock<VecDeque<AutoRoutingEvent>>,
    lookup_sender: RwLock<Option<tokio::sync::mpsc::UnboundedSender<Ipv4Addr>>>,
    pending_lookups: RwLock<HashSet<Ipv4Addr>>,
    pending_any: AtomicBool,
    whitelisted_regions: RwLock<HashSet<String>>,
    auto_routing_bypassed: AtomicBool,
    forced_servers: RwLock<HashMap<String, String>>,
}

impl AutoRouter {
    pub fn new(enabled: bool, initial_region: &str) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            current_game_region: RwLock::new(None),
            current_relay_addr: RwLock::new(None),
            current_st_region: RwLock::new(initial_region.to_string()),
            last_switch_time: RwLock::new(Instant::now() - MIN_SWITCH_INTERVAL),
            switches_this_minute: RwLock::new((0, Instant::now())),
            seen_game_servers: RwLock::new(HashSet::new()),
            available_servers: RwLock::new(Vec::new()),
            event_log: RwLock::new(VecDeque::new()),
            lookup_sender: RwLock::new(None),
            pending_lookups: RwLock::new(HashSet::new()),
            pending_any: AtomicBool::new(false),
            whitelisted_regions: RwLock::new(HashSet::new()),
            auto_routing_bypassed: AtomicBool::new(false),
            forced_servers: RwLock::new(HashMap::new()),
        }
    }

    pub fn set_lookup_channel(&self, sender: tokio::sync::mpsc::UnboundedSender<Ipv4Addr>) {
        *self.lookup_sender.write() = Some(sender);
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    pub fn set_whitelisted_regions(&self, regions: Vec<String>) {
        *self.whitelisted_regions.write() = regions.into_iter().collect();
    }

    /// Set forced servers (region_id -> server_id).
    pub fn set_forced_servers(&self, servers: HashMap<String, String>) {
        *self.forced_servers.write() = servers;
    }

    pub fn set_available_servers(&self, servers: Vec<(String, SocketAddr, Option<u32>)>) {
        *self.available_servers.write() = servers;
    }

    pub fn available_servers_snapshot(&self) -> Vec<(String, SocketAddr, Option<u32>)> {
        self.available_servers.read().clone()
    }

    pub fn forced_server_for_region(&self, region_id: &str) -> Option<String> {
        self.forced_servers.read().get(region_id).cloned()
    }

    pub fn set_current_relay(&self, addr: SocketAddr, region: &str) {
        *self.current_relay_addr.write() = Some(addr);
        *self.current_st_region.write() = region.to_string();
    }

    pub fn current_game_region(&self) -> Option<RobloxRegion> {
        self.current_game_region.read().clone()
    }

    pub fn current_region(&self) -> String {
        self.current_st_region.read().clone()
    }

    pub fn is_bypassed(&self) -> bool {
        self.auto_routing_bypassed.load(Ordering::Acquire)
    }

    pub fn pending_lookup_count(&self) -> usize {
        self.pending_lookups.read().len()
    }

    pub fn recent_events(&self, max: usize) -> Vec<AutoRoutingEvent> {
        self.event_log
            .read()
            .iter()
            .rev()
            .take(max)
            .cloned()
            .collect()
    }

    fn log_event(&self, event: AutoRoutingEvent) {
        let mut log = self.event_log.write();
        log.push_back(event);
        if log.len() > MAX_EVENT_LOG {
            log.pop_front();
        }
    }

    fn is_region_whitelisted(&self, region: &RobloxRegion) -> bool {
        self.whitelisted_regions
            .read()
            .contains(region.display_name())
    }

    pub fn evaluate_game_server(&self, game_server_ip: Ipv4Addr) -> AutoRoutingAction {
        if !self.is_enabled() {
            return AutoRoutingAction::NoAction;
        }

        let is_new_ip = match self.seen_game_servers.try_write() {
            Some(mut seen) => seen.insert(game_server_ip),
            None => return AutoRoutingAction::NoAction,
        };
        if !is_new_ip {
            return AutoRoutingAction::NoAction;
        }

        if let Some(mut pending) = self.pending_lookups.try_write() {
            pending.insert(game_server_ip);
            self.pending_any.store(true, Ordering::Release);
        }
        if let Some(sender) = self.lookup_sender.read().as_ref() {
            let _ = sender.send(game_server_ip);
        }

        AutoRoutingAction::NoAction
    }

    pub fn is_lookup_pending(&self, ip: Ipv4Addr) -> bool {
        if !self.pending_any.load(Ordering::Acquire) {
            return false;
        }
        self.pending_lookups.read().contains(&ip)
    }

    pub fn clear_pending_lookup(&self, ip: Ipv4Addr) {
        let mut pending = self.pending_lookups.write();
        pending.remove(&ip);
        self.pending_any
            .store(!pending.is_empty(), Ordering::Release);
    }

    pub fn get_candidates_for_region(
        &self,
        game_region: &RobloxRegion,
    ) -> Option<Vec<(String, SocketAddr)>> {
        if *game_region == RobloxRegion::Unknown {
            return None;
        }

        if self.is_region_whitelisted(game_region) {
            self.auto_routing_bypassed.store(true, Ordering::Release);
            *self.current_game_region.write() = Some(game_region.clone());
            self.log_event(AutoRoutingEvent {
                timestamp_ms: now_millis(),
                event_type: "bypassed".to_string(),
                from_region: self.current_st_region.read().clone(),
                to_region: "BYPASS".to_string(),
                game_server_region: game_region.display_name().to_string(),
                reason: format!(
                    "{} is whitelisted - using direct connection",
                    game_region.display_name()
                ),
                location: None,
                relay_addr: None,
            });
            return None;
        }

        self.auto_routing_bypassed.store(false, Ordering::Release);

        let best_st_region = game_region.best_swifttunnel_region()?;
        let forced_server = self.forced_server_for_region(best_st_region);
        let current_st_region = self.current_st_region.read().clone();
        if current_st_region == best_st_region
            || current_st_region.starts_with(&format!("{}-", best_st_region))
        {
            *self.current_game_region.write() = Some(game_region.clone());
            return None;
        }

        let servers = self.available_servers.read();
        let mut candidates_with_latency: Vec<&(String, SocketAddr, Option<u32>)> = if best_st_region
            == "america"
        {
            servers
                .iter()
                .filter(|(region, _, _)| region.starts_with("us-"))
                .collect()
        } else {
            let prefix = format!("{}-", best_st_region);
            servers
                .iter()
                .filter(|(region, _, _)| region == best_st_region || region.starts_with(&prefix))
                .collect()
        };

        if let Some(pinned) = forced_server {
            candidates_with_latency.retain(|(region, _, _)| region == &pinned);
        }

        candidates_with_latency.sort_by_key(|(_, _, latency)| latency.unwrap_or(u32::MAX));
        let candidates = candidates_with_latency
            .into_iter()
            .map(|(region, addr, _)| (region.clone(), *addr))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            None
        } else {
            Some(candidates)
        }
    }

    pub fn commit_switch(
        &self,
        game_region: RobloxRegion,
        selected_region: String,
        selected_addr: SocketAddr,
        location: Option<String>,
    ) -> Option<(SocketAddr, String)> {
        let current_st_region = self.current_st_region.read().clone();
        if self.record_switch(
            &current_st_region,
            &selected_region,
            &game_region,
            selected_addr,
            location,
        ) {
            Some((selected_addr, selected_region))
        } else {
            None
        }
    }

    fn record_switch(
        &self,
        from_region: &str,
        to_region: &str,
        game_region: &RobloxRegion,
        new_addr: SocketAddr,
        location: Option<String>,
    ) -> bool {
        if *self.current_st_region.read() == to_region {
            return false;
        }

        let now = Instant::now();
        if now.duration_since(*self.last_switch_time.read()) < MIN_SWITCH_INTERVAL {
            return false;
        }

        let mut window = self.switches_this_minute.write();
        if now.duration_since(window.1) > Duration::from_secs(60) {
            *window = (0, now);
        }
        if window.0 >= MAX_SWITCHES_PER_MINUTE {
            return false;
        }
        window.0 += 1;
        drop(window);

        *self.last_switch_time.write() = now;
        *self.current_st_region.write() = to_region.to_string();
        *self.current_relay_addr.write() = Some(new_addr);
        *self.current_game_region.write() = Some(game_region.clone());

        self.log_event(AutoRoutingEvent {
            timestamp_ms: now_millis(),
            event_type: "relay_switched".to_string(),
            from_region: from_region.to_string(),
            to_region: to_region.to_string(),
            game_server_region: game_region.display_name().to_string(),
            reason: format!(
                "Game server moved to {} - switching from {} to {}",
                game_region.display_name(),
                from_region,
                to_region
            ),
            location,
            relay_addr: Some(new_addr.to_string()),
        });

        true
    }

    pub fn push_degraded_event(&self, reason: String) {
        self.log_event(AutoRoutingEvent {
            timestamp_ms: now_millis(),
            event_type: "degraded".to_string(),
            from_region: self.current_st_region.read().clone(),
            to_region: self.current_st_region.read().clone(),
            game_server_region: "Unknown".to_string(),
            reason,
            location: None,
            relay_addr: self.current_relay_addr.read().map(|a| a.to_string()),
        });
    }

    pub fn reset(&self) {
        *self.current_game_region.write() = None;
        *self.current_relay_addr.write() = None;
        self.seen_game_servers.write().clear();
        self.pending_lookups.write().clear();
        self.pending_any.store(false, Ordering::Release);
        self.auto_routing_bypassed.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_servers() -> Vec<(String, SocketAddr, Option<u32>)> {
        vec![
            (
                "singapore".to_string(),
                "54.255.205.216:51821".parse().unwrap(),
                None,
            ),
            (
                "us-east-nj".to_string(),
                "108.61.7.6:51821".parse().unwrap(),
                None,
            ),
            (
                "tokyo-02".to_string(),
                "45.32.253.124:51821".parse().unwrap(),
                None,
            ),
        ]
    }

    #[test]
    fn test_auto_router_disabled() {
        let router = AutoRouter::new(false, "singapore");
        router.set_available_servers(make_servers());
        let action = router.evaluate_game_server(Ipv4Addr::new(128, 116, 102, 1));
        assert!(matches!(action, AutoRoutingAction::NoAction));
    }

    #[test]
    fn test_duplicate_ip_suppressed_and_pending_lookup_clears() {
        let router = AutoRouter::new(true, "singapore");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        router.set_lookup_channel(tx);

        let ip = Ipv4Addr::new(128, 116, 102, 1);
        router.evaluate_game_server(ip);
        router.evaluate_game_server(ip);

        assert_eq!(router.pending_lookup_count(), 1);
        assert!(router.is_lookup_pending(ip));
        assert_eq!(rx.try_recv().unwrap(), ip);
        assert!(rx.try_recv().is_err());

        router.clear_pending_lookup(ip);
        assert!(!router.is_lookup_pending(ip));
        assert_eq!(router.pending_lookup_count(), 0);
    }

    #[test]
    fn test_pending_any_fast_path_flag_tracks_pending_set() {
        let router = AutoRouter::new(true, "singapore");
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        router.set_lookup_channel(tx);

        let ip = Ipv4Addr::new(128, 116, 102, 7);
        assert!(!router
            .pending_any
            .load(std::sync::atomic::Ordering::Acquire));
        router.evaluate_game_server(ip);
        assert!(router
            .pending_any
            .load(std::sync::atomic::Ordering::Acquire));

        router.clear_pending_lookup(ip);
        assert!(!router
            .pending_any
            .load(std::sync::atomic::Ordering::Acquire));
    }

    #[test]
    fn test_get_candidates_and_commit_switch() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");

        let candidates = router.get_candidates_for_region(&RobloxRegion::UsEast);
        assert!(candidates.is_some());
        let candidates = candidates.unwrap();
        assert_eq!(candidates[0].0, "us-east-nj");
        let result = router.commit_switch(
            RobloxRegion::UsEast,
            candidates[0].0.clone(),
            candidates[0].1,
            Some("Ashburn, US".to_string()),
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_same_region_no_switch() {
        let router = AutoRouter::new(true, "us-east-nj");
        router.set_available_servers(make_servers());
        router.set_current_relay("108.61.7.6:51821".parse().unwrap(), "us-east-nj");

        let candidates = router.get_candidates_for_region(&RobloxRegion::UsEast);
        assert!(candidates.is_none());
        assert_eq!(router.current_game_region(), Some(RobloxRegion::UsEast));
    }

    #[test]
    fn test_rate_limits_enforced() {
        let router = AutoRouter::new(true, "singapore");
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");

        let sequence = vec![
            (
                RobloxRegion::UsEast,
                "us-east-nj".to_string(),
                "108.61.7.6:51821",
            ),
            (
                RobloxRegion::Tokyo,
                "tokyo-02".to_string(),
                "45.32.253.124:51821",
            ),
            (
                RobloxRegion::Singapore,
                "singapore".to_string(),
                "54.255.205.216:51821",
            ),
            (
                RobloxRegion::UsEast,
                "us-east-nj".to_string(),
                "108.61.7.6:51821",
            ),
        ];

        for (idx, (game_region, region, addr_str)) in sequence.into_iter().enumerate() {
            *router.last_switch_time.write() = Instant::now() - MIN_SWITCH_INTERVAL;
            let addr: SocketAddr = addr_str.parse().unwrap();
            let switched = router.commit_switch(game_region, region, addr, None);
            if idx < MAX_SWITCHES_PER_MINUTE as usize {
                assert!(switched.is_some(), "switch {} should be allowed", idx + 1);
            } else {
                assert!(
                    switched.is_none(),
                    "switch {} should be rate-limited",
                    idx + 1
                );
            }
        }
    }

    #[test]
    fn test_whitelisted_region_bypasses_vpn() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_whitelisted_regions(vec!["US East".to_string()]);
        let candidates = router.get_candidates_for_region(&RobloxRegion::UsEast);
        assert!(candidates.is_none());
        assert!(router.is_bypassed());

        let candidates2 = router.get_candidates_for_region(&RobloxRegion::Tokyo);
        assert!(!router.is_bypassed());
        assert!(candidates2.is_some());
    }

    #[test]
    fn test_forced_server_overrides_candidate_list() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_forced_servers(HashMap::from([(
            "us-east".to_string(),
            "us-east-nj".to_string(),
        )]));

        let candidates = router
            .get_candidates_for_region(&RobloxRegion::UsEast)
            .expect("candidates");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, "us-east-nj");
    }
}
