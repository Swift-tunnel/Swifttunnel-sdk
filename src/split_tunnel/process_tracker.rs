//! Process Tracker - Maps network connections to process IDs
//!
//! Uses Windows IP Helper APIs (GetExtendedTcpTable, GetExtendedUdpTable) to
//! track which processes own which network connections. This allows us to
//! determine which packets belong to which applications for split tunneling.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use crate::error::SdkError;

#[cfg(windows)]
use windows::Win32::NetworkManagement::IpHelper::*;
#[cfg(windows)]
use windows::Win32::Foundation::*;

/// Protocol type for connection tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Connection key for cache lookup
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    pub local_ip: Ipv4Addr,
    pub local_port: u16,
    pub protocol: Protocol,
}

impl ConnectionKey {
    pub fn new(local_ip: Ipv4Addr, local_port: u16, protocol: Protocol) -> Self {
        Self {
            local_ip,
            local_port,
            protocol,
        }
    }
}

/// Statistics about the process tracker
#[derive(Debug, Clone)]
pub struct TrackerStats {
    pub tcp_connections: usize,
    pub udp_connections: usize,
    pub stale_connections: usize,
    pub tracked_pids: usize,
}

/// Process tracker that maps network connections to PIDs
pub struct ProcessTracker {
    /// Cache: (local_ip, local_port, protocol) -> PID
    connection_cache: HashMap<ConnectionKey, u32>,
    /// Apps that should be tunneled (exe names, lowercase)
    tunnel_apps: HashSet<String>,
    /// PID -> exe name cache
    pid_names: HashMap<u32, String>,
    /// Recently seen connections (kept for 5 seconds after disappearing)
    stale_connections: HashMap<ConnectionKey, (u32, std::time::Instant)>,
    /// Stale entry timeout
    stale_timeout: std::time::Duration,
}

impl ProcessTracker {
    /// Create a new process tracker
    pub fn new(tunnel_apps: Vec<String>) -> Self {
        Self {
            connection_cache: HashMap::with_capacity(1024),
            tunnel_apps: tunnel_apps.into_iter().map(|s| s.to_lowercase()).collect(),
            pid_names: HashMap::with_capacity(256),
            stale_connections: HashMap::with_capacity(256),
            stale_timeout: std::time::Duration::from_secs(5),
        }
    }

    /// Update the list of apps to tunnel
    pub fn set_tunnel_apps(&mut self, apps: Vec<String>) {
        self.tunnel_apps = apps.into_iter().map(|s| s.to_lowercase()).collect();
    }

    /// Get the current tunnel apps
    pub fn tunnel_apps(&self) -> &HashSet<String> {
        &self.tunnel_apps
    }

    /// Get current connections (for cache refresher to read)
    pub fn connections(&self) -> &HashMap<ConnectionKey, u32> {
        &self.connection_cache
    }

    /// Get current PID names (for cache refresher to read)
    pub fn pid_names(&self) -> &HashMap<u32, String> {
        &self.pid_names
    }

    /// Refresh the connection-to-PID mappings
    pub fn refresh(&mut self) -> Result<(), SdkError> {
        // Clear stale entries older than timeout
        let now = std::time::Instant::now();
        self.stale_connections
            .retain(|_, (_, timestamp)| now.duration_since(*timestamp) < self.stale_timeout);

        // Move current cache to stale before refreshing
        let old_cache = std::mem::take(&mut self.connection_cache);
        for (key, pid) in old_cache {
            self.stale_connections.insert(key, (pid, now));
        }

        // Refresh tables
        self.refresh_tcp_table()?;
        self.refresh_udp_table()?;

        Ok(())
    }

    /// Get names of currently running tunnel apps
    pub fn get_running_tunnel_apps(&self) -> Vec<String> {
        let mut running = Vec::new();
        for (_pid, name) in &self.pid_names {
            let name_lower = name.to_lowercase();
            if self.tunnel_apps.contains(&name_lower) {
                running.push(name.clone());
            }
        }
        running.sort();
        running.dedup();
        running
    }

    /// Refresh TCP connection table
    #[cfg(windows)]
    fn refresh_tcp_table(&mut self) -> Result<(), SdkError> {
        unsafe {
            let mut size: u32 = 0;
            let result = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                2, // AF_INET
                TCP_TABLE_CLASS(TCP_TABLE_OWNER_PID_ALL.0),
                0,
            );

            if result != ERROR_INSUFFICIENT_BUFFER.0 && result != NO_ERROR.0 {
                return Err(SdkError::SplitTunnel(format!(
                    "GetExtendedTcpTable size query failed: 0x{:08X}",
                    result
                )));
            }

            if size == 0 {
                return Ok(());
            }

            let mut buffer = vec![0u8; size as usize];
            let result = GetExtendedTcpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                2,
                TCP_TABLE_CLASS(TCP_TABLE_OWNER_PID_ALL.0),
                0,
            );

            if result != NO_ERROR.0 {
                return Err(SdkError::SplitTunnel(format!(
                    "GetExtendedTcpTable failed: 0x{:08X}",
                    result
                )));
            }

            let header_size = std::mem::size_of::<u32>();
            if buffer.len() < header_size {
                return Ok(());
            }

            let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let num_entries = table.dwNumEntries as usize;

            let entry_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
            let max_entries = buffer.len().saturating_sub(header_size) / entry_size;
            let safe_entries = num_entries.min(max_entries);

            let entries = std::slice::from_raw_parts(table.table.as_ptr(), safe_entries);

            for entry in entries {
                let local_ip = Ipv4Addr::from(entry.dwLocalAddr.to_ne_bytes());
                let local_port = u16::from_be(entry.dwLocalPort as u16);
                let pid = entry.dwOwningPid;

                let key = ConnectionKey::new(local_ip, local_port, Protocol::Tcp);
                self.connection_cache.insert(key, pid);
            }
        }

        Ok(())
    }

    /// Refresh UDP endpoint table
    #[cfg(windows)]
    fn refresh_udp_table(&mut self) -> Result<(), SdkError> {
        unsafe {
            let mut size: u32 = 0;
            let result = GetExtendedUdpTable(
                None,
                &mut size,
                false,
                2, // AF_INET
                UDP_TABLE_CLASS(UDP_TABLE_OWNER_PID.0),
                0,
            );

            if result != ERROR_INSUFFICIENT_BUFFER.0 && result != NO_ERROR.0 {
                return Err(SdkError::SplitTunnel(format!(
                    "GetExtendedUdpTable size query failed: 0x{:08X}",
                    result
                )));
            }

            if size == 0 {
                return Ok(());
            }

            let mut buffer = vec![0u8; size as usize];
            let result = GetExtendedUdpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                2,
                UDP_TABLE_CLASS(UDP_TABLE_OWNER_PID.0),
                0,
            );

            if result != NO_ERROR.0 {
                return Err(SdkError::SplitTunnel(format!(
                    "GetExtendedUdpTable failed: 0x{:08X}",
                    result
                )));
            }

            let header_size = std::mem::size_of::<u32>();
            if buffer.len() < header_size {
                return Ok(());
            }

            let table = &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
            let num_entries = table.dwNumEntries as usize;

            let entry_size = std::mem::size_of::<MIB_UDPROW_OWNER_PID>();
            let max_entries = buffer.len().saturating_sub(header_size) / entry_size;
            let safe_entries = num_entries.min(max_entries);

            let entries = std::slice::from_raw_parts(table.table.as_ptr(), safe_entries);

            for entry in entries {
                let local_ip = Ipv4Addr::from(entry.dwLocalAddr.to_ne_bytes());
                let local_port = u16::from_be(entry.dwLocalPort as u16);
                let pid = entry.dwOwningPid;

                let key = ConnectionKey::new(local_ip, local_port, Protocol::Udp);
                self.connection_cache.insert(key, pid);
            }
        }

        Ok(())
    }

    #[cfg(not(windows))]
    fn refresh_tcp_table(&mut self) -> Result<(), SdkError> {
        Ok(())
    }

    #[cfg(not(windows))]
    fn refresh_udp_table(&mut self) -> Result<(), SdkError> {
        Ok(())
    }

    /// Get statistics about the cache
    pub fn stats(&self) -> TrackerStats {
        TrackerStats {
            tcp_connections: self
                .connection_cache
                .keys()
                .filter(|k| k.protocol == Protocol::Tcp)
                .count(),
            udp_connections: self
                .connection_cache
                .keys()
                .filter(|k| k.protocol == Protocol::Udp)
                .count(),
            stale_connections: self.stale_connections.len(),
            tracked_pids: self.pid_names.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_key() {
        let key1 = ConnectionKey::new(Ipv4Addr::new(192, 168, 1, 1), 8080, Protocol::Tcp);
        let key2 = ConnectionKey::new(Ipv4Addr::new(192, 168, 1, 1), 8080, Protocol::Tcp);
        let key3 = ConnectionKey::new(Ipv4Addr::new(192, 168, 1, 1), 8080, Protocol::Udp);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_tracker_creation() {
        let tracker = ProcessTracker::new(vec!["robloxplayerbeta.exe".to_string()]);
        assert!(tracker.tunnel_apps.contains("robloxplayerbeta.exe"));
    }
}
