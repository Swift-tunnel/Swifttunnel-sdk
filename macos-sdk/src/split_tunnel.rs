//! macOS split tunnel backend.
//!
//! The Rust SDK keeps auth, relay selection, relay telemetry, and the public C
//! ABI. A Swift `NETransparentProxyProvider` bridges per-flow UDP payloads to
//! this module over a localhost UDP socket:
//!
//! - Swift -> Rust: open flow, outbound datagram, close flow
//! - Rust -> Swift: inbound datagram from relay
//!
//! Rust reconstructs the inner IPv4+UDP packet before handing it to
//! `UdpRelay`, which keeps the relay protocol unchanged.

use std::collections::{BTreeSet, HashMap};
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::Serialize;

use crate::callbacks::fire_process_detected;
use crate::error::SdkError;

const BRIDGE_MAGIC: &[u8; 4] = b"STB1";
const FRAME_OPEN_FLOW: u8 = 1;
const FRAME_OUTBOUND_DATAGRAM: u8 = 2;
const FRAME_CLOSE_FLOW: u8 = 3;
const FRAME_INBOUND_DATAGRAM: u8 = 4;
const LOOPBACK_HOST: &str = "127.0.0.1";
const HELPER_ENV_VAR: &str = "SWIFTTUNNEL_MACOS_HELPER";
const HELPER_PRODUCT_NAME: &str = "swifttunnel-macos-helper";
const PROVIDER_BUNDLE_ID: &str = "net.swifttunnel.macos.transparent-proxy.extension";
const MANAGER_DESCRIPTION: &str = "SwiftTunnel Transparent Proxy";
const SOCKET_READ_TIMEOUT: Duration = Duration::from_millis(200);
const IP_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

#[derive(Clone)]
pub struct ThroughputStats {
    pub bytes_tx: Arc<std::sync::atomic::AtomicU64>,
    pub bytes_rx: Arc<std::sync::atomic::AtomicU64>,
    pub started_at: Instant,
}

impl Default for ThroughputStats {
    fn default() -> Self {
        Self {
            bytes_tx: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            bytes_rx: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            started_at: Instant::now(),
        }
    }
}

impl ThroughputStats {
    pub fn add_tx(&self, bytes: u64) {
        self.bytes_tx.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_rx(&self, bytes: u64) {
        self.bytes_rx.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn get_bytes_tx(&self) -> u64 {
        self.bytes_tx.load(Ordering::Relaxed)
    }

    pub fn get_bytes_rx(&self) -> u64 {
        self.bytes_rx.load(Ordering::Relaxed)
    }
}

pub struct RelayForwardContext {
    pub relay: Arc<crate::vpn::UdpRelay>,
}

#[derive(Clone)]
struct FlowRegistration {
    extension_addr: SocketAddr,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    app_identifier: Option<String>,
    process_name: Option<String>,
}

impl FlowRegistration {
    fn display_name(&self) -> Option<String> {
        self.process_name
            .clone()
            .filter(|value| !value.is_empty())
            .or_else(|| {
                self.app_identifier
                    .clone()
                    .filter(|value| !value.is_empty())
            })
    }

    fn flow_key(&self) -> Option<FlowKey> {
        FlowKey::from_endpoints(self.local_addr, self.remote_addr)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
}

impl FlowKey {
    fn from_endpoints(local_addr: SocketAddr, remote_addr: SocketAddr) -> Option<Self> {
        Some(Self {
            local_ip: match local_addr.ip() {
                IpAddr::V4(value) => value,
                IpAddr::V6(_) => return None,
            },
            local_port: local_addr.port(),
            remote_ip: match remote_addr.ip() {
                IpAddr::V4(value) => value,
                IpAddr::V6(_) => return None,
            },
            remote_port: remote_addr.port(),
        })
    }
}

#[derive(Default)]
struct BridgeMaps {
    flows_by_id: HashMap<u64, FlowRegistration>,
    tuple_to_flow: HashMap<FlowKey, u64>,
    process_refcounts: HashMap<String, usize>,
}

struct BridgeRuntime {
    port: u16,
    stop_flag: Arc<AtomicBool>,
    receiver_thread: Option<JoinHandle<()>>,
    inbound_thread: Option<JoinHandle<()>>,
    maps: Arc<Mutex<BridgeMaps>>,
    throughput: ThroughputStats,
}

impl BridgeRuntime {
    fn start(
        relay: Arc<crate::vpn::UdpRelay>,
        auto_router: Option<Arc<crate::vpn::auto_routing::AutoRouter>>,
    ) -> Result<Self, SdkError> {
        let listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| {
            SdkError::SplitTunnel(format!("Failed to bind macOS bridge socket: {}", e))
        })?;
        listener
            .set_read_timeout(Some(SOCKET_READ_TIMEOUT))
            .map_err(|e| {
                SdkError::SplitTunnel(format!("Failed to set macOS bridge read timeout: {}", e))
            })?;

        let port = listener
            .local_addr()
            .map_err(|e| {
                SdkError::SplitTunnel(format!("Failed to read macOS bridge socket addr: {}", e))
            })?
            .port();

        let send_socket = listener.try_clone().map_err(|e| {
            SdkError::SplitTunnel(format!("Failed to clone macOS bridge socket: {}", e))
        })?;
        let stop_flag = Arc::new(AtomicBool::new(false));
        let maps = Arc::new(Mutex::new(BridgeMaps::default()));
        let throughput = ThroughputStats::default();

        let receiver_stop = Arc::clone(&stop_flag);
        let receiver_maps = Arc::clone(&maps);
        let receiver_throughput = throughput.clone();
        let receiver_relay = Arc::clone(&relay);
        let receiver_auto_router = auto_router.clone();
        let receiver_thread = std::thread::Builder::new()
            .name("macos-flow-bridge-rx".into())
            .spawn(move || {
                let mut buffer = [0u8; 65535];

                while !receiver_stop.load(Ordering::Acquire) {
                    let received = match listener.recv_from(&mut buffer) {
                        Ok(value) => value,
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) =>
                        {
                            continue;
                        }
                        Err(e) => {
                            log::warn!("macOS bridge receive loop failed: {}", e);
                            continue;
                        }
                    };

                    let (len, extension_addr) = received;
                    let Some(frame) = BridgeFrame::decode(&buffer[..len]) else {
                        log::debug!("Ignoring malformed macOS bridge frame ({} bytes)", len);
                        continue;
                    };

                    match frame {
                        BridgeFrame::OpenFlow {
                            flow_id,
                            local_addr,
                            remote_addr,
                            app_identifier,
                            process_name,
                        } => {
                            let registration = FlowRegistration {
                                extension_addr,
                                local_addr,
                                remote_addr,
                                app_identifier,
                                process_name,
                            };
                            register_flow(&receiver_maps, flow_id, registration);
                        }
                        BridgeFrame::OutboundDatagram {
                            flow_id,
                            remote_addr,
                            payload,
                        } => {
                            if let Err(err) = handle_outbound_datagram(
                                &receiver_maps,
                                flow_id,
                                remote_addr,
                                &payload,
                                &receiver_relay,
                                receiver_auto_router.as_ref(),
                                &receiver_throughput,
                            ) {
                                log::warn!(
                                    "macOS bridge outbound datagram handling failed for flow {}: {}",
                                    flow_id,
                                    err
                                );
                            }
                        }
                        BridgeFrame::CloseFlow { flow_id } => {
                            unregister_flow(&receiver_maps, flow_id);
                        }
                        BridgeFrame::InboundDatagram { .. } => {}
                    }
                }
            })
            .map_err(|e| SdkError::SplitTunnel(format!("Failed to start macOS bridge rx: {}", e)))?;

        let inbound_stop = Arc::clone(&stop_flag);
        let inbound_maps = Arc::clone(&maps);
        let inbound_throughput = throughput.clone();
        let inbound_thread = std::thread::Builder::new()
            .name("macos-flow-bridge-inbound".into())
            .spawn(move || {
                let mut relay_buffer = [0u8; 65535];

                while !inbound_stop.load(Ordering::Acquire) {
                    match relay.receive_inbound(&mut relay_buffer) {
                        Ok(Some(len)) => {
                            let packet = &relay_buffer[..len];
                            let Some(parsed) = ParsedInboundPacket::parse(packet) else {
                                log::debug!(
                                    "Ignoring malformed relay response packet ({} bytes)",
                                    len
                                );
                                continue;
                            };

                            let mapped_flow = {
                                let maps = inbound_maps.lock();
                                maps.tuple_to_flow
                                    .get(&parsed.flow_key)
                                    .and_then(|flow_id| {
                                        maps.flows_by_id
                                            .get(flow_id)
                                            .cloned()
                                            .map(|registration| (*flow_id, registration))
                                    })
                            };

                            let Some((flow_id, registration)) = mapped_flow else {
                                log::debug!(
                                    "No matching flow for relay response {}:{} -> {}:{}",
                                    parsed.flow_key.remote_ip,
                                    parsed.flow_key.remote_port,
                                    parsed.flow_key.local_ip,
                                    parsed.flow_key.local_port
                                );
                                continue;
                            };

                            let Ok(frame) = BridgeFrame::encode_inbound_datagram(
                                flow_id,
                                SocketAddr::from((
                                    parsed.flow_key.remote_ip,
                                    parsed.flow_key.remote_port,
                                )),
                                parsed.payload,
                            ) else {
                                continue;
                            };

                            if let Err(err) =
                                send_socket.send_to(&frame, registration.extension_addr)
                            {
                                log::warn!(
                                    "Failed to forward relay response to extension for flow {}: {}",
                                    flow_id,
                                    err
                                );
                                continue;
                            }

                            inbound_throughput.add_rx(parsed.payload.len() as u64);
                        }
                        Ok(None) => {}
                        Err(err) => {
                            log::warn!("Relay inbound loop failed: {}", err);
                        }
                    }
                }
            })
            .map_err(|e| {
                SdkError::SplitTunnel(format!("Failed to start macOS bridge inbound: {}", e))
            })?;

        Ok(Self {
            port,
            stop_flag,
            receiver_thread: Some(receiver_thread),
            inbound_thread: Some(inbound_thread),
            maps,
            throughput,
        })
    }

    fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::Release);
        if let Some(handle) = self.receiver_thread.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.inbound_thread.take() {
            let _ = handle.join();
        }
    }

    fn tunneled_processes(&self) -> Vec<String> {
        self.maps
            .lock()
            .process_refcounts
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

#[derive(Debug)]
enum BridgeFrame {
    OpenFlow {
        flow_id: u64,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        app_identifier: Option<String>,
        process_name: Option<String>,
    },
    OutboundDatagram {
        flow_id: u64,
        remote_addr: SocketAddr,
        payload: Vec<u8>,
    },
    CloseFlow {
        flow_id: u64,
    },
    InboundDatagram {
        flow_id: u64,
        remote_addr: SocketAddr,
        payload: Vec<u8>,
    },
}

impl BridgeFrame {
    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 5 || &bytes[..4] != BRIDGE_MAGIC {
            return None;
        }

        let mut cursor = 5usize;
        match bytes[4] {
            FRAME_OPEN_FLOW => {
                let flow_id = take_u64(bytes, &mut cursor)?;
                let local_addr = take_socket_addr(bytes, &mut cursor)?;
                let remote_addr = take_socket_addr(bytes, &mut cursor)?;
                let app_identifier = take_optional_string(bytes, &mut cursor)?;
                let process_name = take_optional_string(bytes, &mut cursor)?;
                Some(Self::OpenFlow {
                    flow_id,
                    local_addr,
                    remote_addr,
                    app_identifier,
                    process_name,
                })
            }
            FRAME_OUTBOUND_DATAGRAM => {
                let flow_id = take_u64(bytes, &mut cursor)?;
                let remote_addr = take_socket_addr(bytes, &mut cursor)?;
                let payload_len = take_u16(bytes, &mut cursor)? as usize;
                let payload = take_bytes(bytes, &mut cursor, payload_len)?.to_vec();
                Some(Self::OutboundDatagram {
                    flow_id,
                    remote_addr,
                    payload,
                })
            }
            FRAME_CLOSE_FLOW => {
                let flow_id = take_u64(bytes, &mut cursor)?;
                Some(Self::CloseFlow { flow_id })
            }
            FRAME_INBOUND_DATAGRAM => {
                let flow_id = take_u64(bytes, &mut cursor)?;
                let remote_addr = take_socket_addr(bytes, &mut cursor)?;
                let payload_len = take_u16(bytes, &mut cursor)? as usize;
                let payload = take_bytes(bytes, &mut cursor, payload_len)?.to_vec();
                Some(Self::InboundDatagram {
                    flow_id,
                    remote_addr,
                    payload,
                })
            }
            _ => None,
        }
    }

    fn encode_inbound_datagram(
        flow_id: u64,
        remote_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<Vec<u8>, SdkError> {
        if payload.len() > u16::MAX as usize {
            return Err(SdkError::SplitTunnel(format!(
                "Inbound payload too large for bridge frame: {} bytes",
                payload.len()
            )));
        }

        let mut frame = Vec::with_capacity(5 + 8 + 32 + 2 + payload.len());
        frame.extend_from_slice(BRIDGE_MAGIC);
        frame.push(FRAME_INBOUND_DATAGRAM);
        frame.extend_from_slice(&flow_id.to_be_bytes());
        push_socket_addr(&mut frame, remote_addr)?;
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        Ok(frame)
    }
}

#[derive(Debug, Clone, Copy)]
struct ParsedInboundPacket<'a> {
    flow_key: FlowKey,
    payload: &'a [u8],
}

impl<'a> ParsedInboundPacket<'a> {
    fn parse(packet: &'a [u8]) -> Option<Self> {
        if packet.len() < IP_HEADER_LEN + UDP_HEADER_LEN {
            return None;
        }
        if (packet[0] >> 4) != 4 {
            return None;
        }

        let header_len = (packet[0] & 0x0F) as usize * 4;
        if header_len < IP_HEADER_LEN || packet.len() < header_len + UDP_HEADER_LEN {
            return None;
        }
        if packet[9] != 17 {
            return None;
        }

        let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        let udp_start = header_len;
        let src_port = u16::from_be_bytes([packet[udp_start], packet[udp_start + 1]]);
        let dst_port = u16::from_be_bytes([packet[udp_start + 2], packet[udp_start + 3]]);
        let payload = &packet[udp_start + UDP_HEADER_LEN..];
        let flow_key = FlowKey {
            local_ip: dst_ip,
            local_port: dst_port,
            remote_ip: src_ip,
            remote_port: src_port,
        };
        Some(Self { flow_key, payload })
    }
}

fn register_flow(maps: &Arc<Mutex<BridgeMaps>>, flow_id: u64, registration: FlowRegistration) {
    let mut fire_add = None;
    let mut fire_remove = None;

    {
        let mut maps = maps.lock();

        if let Some(previous) = maps.flows_by_id.remove(&flow_id) {
            if let Some(key) = previous.flow_key() {
                maps.tuple_to_flow.remove(&key);
            }
            if let Some(name) = previous.display_name() {
                fire_remove = decrement_process_refcount(&mut maps.process_refcounts, &name);
            }
        }

        if let Some(key) = registration.flow_key() {
            maps.tuple_to_flow.insert(key, flow_id);
        }
        if let Some(name) = registration.display_name() {
            fire_add = increment_process_refcount(&mut maps.process_refcounts, &name);
        }
        maps.flows_by_id.insert(flow_id, registration);
    }

    if let Some(name) = fire_remove {
        fire_process_detected(&name, false);
    }
    if let Some(name) = fire_add {
        fire_process_detected(&name, true);
    }
}

fn unregister_flow(maps: &Arc<Mutex<BridgeMaps>>, flow_id: u64) {
    let removed_name = {
        let mut maps = maps.lock();
        let Some(previous) = maps.flows_by_id.remove(&flow_id) else {
            return;
        };
        if let Some(key) = previous.flow_key() {
            maps.tuple_to_flow.remove(&key);
        }
        previous
            .display_name()
            .and_then(|name| decrement_process_refcount(&mut maps.process_refcounts, &name))
    };

    if let Some(name) = removed_name {
        fire_process_detected(&name, false);
    }
}

fn handle_outbound_datagram(
    maps: &Arc<Mutex<BridgeMaps>>,
    flow_id: u64,
    remote_addr: SocketAddr,
    payload: &[u8],
    relay: &crate::vpn::UdpRelay,
    auto_router: Option<&Arc<crate::vpn::auto_routing::AutoRouter>>,
    throughput: &ThroughputStats,
) -> Result<(), SdkError> {
    let registration = {
        let mut maps = maps.lock();
        let Some(current) = maps.flows_by_id.get(&flow_id).cloned() else {
            return Ok(());
        };
        let mut updated = current.clone();
        if updated.remote_addr != remote_addr {
            if let Some(old_key) = current.flow_key() {
                maps.tuple_to_flow.remove(&old_key);
            }
            updated.remote_addr = remote_addr;
            if let Some(new_key) = updated.flow_key() {
                maps.tuple_to_flow.insert(new_key, flow_id);
            }
            maps.flows_by_id.insert(flow_id, updated.clone());
        }
        updated
    };

    let remote_ip = match remote_addr.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return Ok(()),
    };
    let local_ip = match registration.local_addr.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return Ok(()),
    };

    if let Some(router) = auto_router {
        if is_roblox_game_server_ip(remote_ip) {
            router.evaluate_game_server(remote_ip);
        }
    }

    let packet = build_ipv4_udp_packet(
        SocketAddr::from((local_ip, registration.local_addr.port())),
        SocketAddr::from((remote_ip, remote_addr.port())),
        payload,
    )?;
    let _ = relay.forward_outbound(&packet)?;
    throughput.add_tx(packet.len() as u64);
    Ok(())
}

fn increment_process_refcount(counts: &mut HashMap<String, usize>, name: &str) -> Option<String> {
    let entry = counts.entry(name.to_string()).or_insert(0);
    let first = *entry == 0;
    *entry += 1;
    first.then(|| name.to_string())
}

fn decrement_process_refcount(counts: &mut HashMap<String, usize>, name: &str) -> Option<String> {
    let Some(entry) = counts.get_mut(name) else {
        return None;
    };
    if *entry > 1 {
        *entry -= 1;
        return None;
    }
    counts.remove(name);
    Some(name.to_string())
}

fn build_ipv4_udp_packet(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, SdkError> {
    let src_ip = match local_addr.ip() {
        IpAddr::V4(value) => value,
        IpAddr::V6(_) => {
            return Err(SdkError::SplitTunnel(
                "IPv6 local endpoints are not supported by the current relay framing".into(),
            ))
        }
    };
    let dst_ip = match remote_addr.ip() {
        IpAddr::V4(value) => value,
        IpAddr::V6(_) => {
            return Err(SdkError::SplitTunnel(
                "IPv6 remote endpoints are not supported by the current relay framing".into(),
            ))
        }
    };

    let udp_len = UDP_HEADER_LEN + payload.len();
    let total_len = IP_HEADER_LEN + udp_len;
    if total_len > u16::MAX as usize {
        return Err(SdkError::SplitTunnel(format!(
            "UDP payload too large for IPv4 framing: {} bytes",
            payload.len()
        )));
    }

    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src_ip.octets());
    packet[16..20].copy_from_slice(&dst_ip.octets());
    let ip_checksum = calculate_ip_checksum(&packet[..IP_HEADER_LEN]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp_start = IP_HEADER_LEN;
    packet[udp_start..udp_start + 2].copy_from_slice(&local_addr.port().to_be_bytes());
    packet[udp_start + 2..udp_start + 4].copy_from_slice(&remote_addr.port().to_be_bytes());
    packet[udp_start + 4..udp_start + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[udp_start + 6..udp_start + 8].copy_from_slice(&0u16.to_be_bytes());
    packet[udp_start + UDP_HEADER_LEN..].copy_from_slice(payload);

    Ok(packet)
}

fn calculate_ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..header.len()).step_by(2) {
        let word = if i + 1 < header.len() {
            ((header[i] as u32) << 8) | header[i + 1] as u32
        } else {
            (header[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn take_u16(bytes: &[u8], cursor: &mut usize) -> Option<u16> {
    let value = u16::from_be_bytes([*bytes.get(*cursor)?, *bytes.get(*cursor + 1)?]);
    *cursor += 2;
    Some(value)
}

fn take_u64(bytes: &[u8], cursor: &mut usize) -> Option<u64> {
    let slice = take_bytes(bytes, cursor, 8)?;
    Some(u64::from_be_bytes(slice.try_into().ok()?))
}

fn take_bytes<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Option<&'a [u8]> {
    let slice = bytes.get(*cursor..*cursor + len)?;
    *cursor += len;
    Some(slice)
}

fn take_optional_string(bytes: &[u8], cursor: &mut usize) -> Option<Option<String>> {
    let len = take_u16(bytes, cursor)? as usize;
    if len == 0 {
        return Some(None);
    }
    let raw = take_bytes(bytes, cursor, len)?;
    Some(Some(String::from_utf8_lossy(raw).into_owned()))
}

fn take_socket_addr(bytes: &[u8], cursor: &mut usize) -> Option<SocketAddr> {
    let family = *bytes.get(*cursor)?;
    *cursor += 1;
    let port = take_u16(bytes, cursor)?;

    match family {
        4 => {
            let octets: [u8; 4] = take_bytes(bytes, cursor, 4)?.try_into().ok()?;
            Some(SocketAddr::from((Ipv4Addr::from(octets), port)))
        }
        6 => {
            let octets: [u8; 16] = take_bytes(bytes, cursor, 16)?.try_into().ok()?;
            let scope_id = u32::from_be_bytes(take_bytes(bytes, cursor, 4)?.try_into().ok()?);
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(octets),
                port,
                0,
                scope_id,
            )))
        }
        _ => None,
    }
}

fn push_socket_addr(frame: &mut Vec<u8>, addr: SocketAddr) -> Result<(), SdkError> {
    match addr {
        SocketAddr::V4(value) => {
            frame.push(4);
            frame.extend_from_slice(&value.port().to_be_bytes());
            frame.extend_from_slice(&value.ip().octets());
            Ok(())
        }
        SocketAddr::V6(value) => {
            frame.push(6);
            frame.extend_from_slice(&value.port().to_be_bytes());
            frame.extend_from_slice(&value.ip().octets());
            frame.extend_from_slice(&value.scope_id().to_be_bytes());
            Ok(())
        }
    }
}

fn is_roblox_game_server_ip(ip: Ipv4Addr) -> bool {
    const ROBLOX_RANGES: &[(u32, u32)] = &[
        (0x80740000, 0xFFFF8000),
        (0xD1CE2800, 0xFFFFF800),
        (0x678C1C00, 0xFFFFFE00),
        (0x678EDC00, 0xFFFFFE00),
        (0x17ADC000, 0xFFFFFF00),
        (0x8DC10300, 0xFFFFFF00),
        (0xCDC93E00, 0xFFFFFF00),
        (0xCC09B800, 0xFFFFFF00),
        (0xCC0DA800, 0xFFFFFC00),
        (0xCC0DAC00, 0xFFFFFE00),
    ];
    let ip = u32::from(ip);
    ROBLOX_RANGES
        .iter()
        .any(|(network, mask)| (ip & mask) == (network & mask))
}

#[derive(Debug, Serialize)]
struct HelperStartConfig {
    bridge_host: String,
    bridge_port: u16,
    tunnel_app_identifiers: Vec<String>,
    capture_ipv6: bool,
    localized_description: String,
}

fn normalize_tunnel_app_identifier(app: &str) -> Option<String> {
    let trimmed = app.trim();
    if trimmed.is_empty() {
        return None;
    }

    let normalized = match trimmed.to_ascii_lowercase().as_str() {
        "robloxplayerbeta.exe"
        | "robloxplayer.exe"
        | "robloxplayerbeta"
        | "robloxplayer"
        | "robloxplayer.app"
        | "roblox" => "com.roblox.RobloxPlayer",
        _ => trimmed,
    };

    Some(normalized.to_string())
}

fn normalize_tunnel_app_identifiers(apps: &[String]) -> Vec<String> {
    apps.iter()
        .filter_map(|app| normalize_tunnel_app_identifier(app))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

enum HelperInvocation {
    Binary(PathBuf),
    SwiftRun(PathBuf),
}

impl HelperInvocation {
    fn command(&self) -> Command {
        match self {
            Self::Binary(path) => Command::new(path),
            Self::SwiftRun(package_path) => {
                let mut command = Command::new("swift");
                command.args([
                    "run",
                    "--package-path",
                    package_path.to_string_lossy().as_ref(),
                    HELPER_PRODUCT_NAME,
                    "--",
                ]);
                command
            }
        }
    }
}

fn locate_helper() -> Option<HelperInvocation> {
    if let Ok(path) = env::var(HELPER_ENV_VAR) {
        let path = PathBuf::from(path);
        if path.exists() {
            return Some(HelperInvocation::Binary(path));
        }
    }

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    for path in [
        manifest_dir
            .join("apple/.build/release")
            .join(HELPER_PRODUCT_NAME),
        manifest_dir
            .join("apple/.build/debug")
            .join(HELPER_PRODUCT_NAME),
    ] {
        if path.exists() {
            return Some(HelperInvocation::Binary(path));
        }
    }

    let package_path = manifest_dir.join("apple");
    if package_path.join("Package.swift").exists() {
        return Some(HelperInvocation::SwiftRun(package_path));
    }

    None
}

fn run_helper(args: &[&str]) -> Result<String, SdkError> {
    let Some(invocation) = locate_helper() else {
        return Err(SdkError::SplitTunnel(
            "SwiftTunnel macOS helper is not available. Build macos-sdk/apple first or set SWIFTTUNNEL_MACOS_HELPER.".into(),
        ));
    };

    let output = invocation
        .command()
        .args(args)
        .output()
        .map_err(|e| SdkError::SplitTunnel(format!("Failed to launch macOS helper: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Err(SdkError::SplitTunnel(format!(
            "macOS helper command failed ({}): {}{}{}",
            output
                .status
                .code()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "signal".into()),
            stderr,
            if !stderr.is_empty() && !stdout.is_empty() {
                " | "
            } else {
                ""
            },
            stdout
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub struct SplitTunnelDriver {
    tunnel_apps: Vec<String>,
    relay_ctx: Option<Arc<RelayForwardContext>>,
    auto_router: Option<Arc<crate::vpn::auto_routing::AutoRouter>>,
    bridge: Option<BridgeRuntime>,
}

impl SplitTunnelDriver {
    pub fn new(tunnel_apps: Vec<String>) -> Self {
        Self {
            tunnel_apps,
            relay_ctx: None,
            auto_router: None,
            bridge: None,
        }
    }

    pub fn initialize(&mut self) -> Result<(), SdkError> {
        if locate_helper().is_none() {
            return Err(SdkError::SplitTunnel(
                "SwiftTunnel macOS helper is not available".into(),
            ));
        }
        Ok(())
    }

    pub fn check_driver_available() -> bool {
        locate_helper().is_some()
    }

    pub fn configure(&mut self, tunnel_apps: Vec<String>) -> Result<(), SdkError> {
        self.tunnel_apps = tunnel_apps;
        Ok(())
    }

    pub fn set_relay_context(&mut self, ctx: Arc<RelayForwardContext>) {
        self.relay_ctx = Some(ctx);
    }

    pub fn relay_context_from_udp_relay(
        relay: &Arc<crate::vpn::UdpRelay>,
    ) -> Result<Arc<RelayForwardContext>, SdkError> {
        Ok(Arc::new(RelayForwardContext {
            relay: Arc::clone(relay),
        }))
    }

    pub fn set_auto_router(&mut self, router: Arc<crate::vpn::auto_routing::AutoRouter>) {
        self.auto_router = Some(router);
    }

    pub fn switch_relay_addr(&self, new_addr: SocketAddr) -> bool {
        if let Some(ref ctx) = self.relay_ctx {
            ctx.relay.switch_relay(new_addr);
            true
        } else {
            false
        }
    }

    pub fn current_relay_addr(&self) -> Option<SocketAddr> {
        self.relay_ctx.as_ref().map(|ctx| ctx.relay.relay_addr())
    }

    pub fn start(&mut self) -> Result<(), SdkError> {
        let relay = self
            .relay_ctx
            .as_ref()
            .map(|ctx| Arc::clone(&ctx.relay))
            .ok_or_else(|| {
                SdkError::SplitTunnel("Relay context must be configured before start".into())
            })?;

        let bridge = BridgeRuntime::start(relay, self.auto_router.clone())?;
        let helper_config = HelperStartConfig {
            bridge_host: LOOPBACK_HOST.to_string(),
            bridge_port: bridge.port,
            tunnel_app_identifiers: normalize_tunnel_app_identifiers(&self.tunnel_apps),
            capture_ipv6: false,
            localized_description: MANAGER_DESCRIPTION.to_string(),
        };
        let config_json = serde_json::to_string(&helper_config).map_err(|e| {
            SdkError::SplitTunnel(format!("Failed to serialize macOS helper config: {}", e))
        })?;

        if let Err(err) = run_helper(&[
            "start",
            "--provider-bundle-id",
            PROVIDER_BUNDLE_ID,
            "--config-json",
            &config_json,
        ]) {
            let mut bridge = bridge;
            bridge.stop();
            return Err(err);
        }

        self.bridge = Some(bridge);
        Ok(())
    }

    pub fn close(&mut self) {
        let _ = run_helper(&["stop", "--provider-bundle-id", PROVIDER_BUNDLE_ID]);
        if let Some(ref mut bridge) = self.bridge {
            bridge.stop();
        }
        self.bridge = None;
    }

    pub fn is_active(&self) -> bool {
        self.bridge.is_some()
    }

    pub fn get_tunneled_processes(&self) -> Vec<String> {
        self.bridge
            .as_ref()
            .map(|bridge| bridge.tunneled_processes())
            .unwrap_or_default()
    }

    pub fn get_stats(&self) -> (u64, u64) {
        self.bridge
            .as_ref()
            .map(|bridge| {
                (
                    bridge.throughput.get_bytes_tx(),
                    bridge.throughput.get_bytes_rx(),
                )
            })
            .unwrap_or((0, 0))
    }

    pub fn get_throughput_stats(&self) -> ThroughputStats {
        self.bridge
            .as_ref()
            .map(|bridge| bridge.throughput.clone())
            .unwrap_or_default()
    }

    pub fn get_diagnostics(&self) -> (Option<String>, bool, u64, u64) {
        let (tx, rx) = self.get_stats();
        (
            Some("NETransparentProxyProvider".to_string()),
            self.is_active(),
            tx,
            rx,
        )
    }

    pub fn refresh_processes(&self) {}

    pub fn register_process_immediate(&self, _pid: u32, _name: String) {}

    pub fn drain_etw_events(&self) {}

    pub fn get_physical_adapter_name(&self) -> Option<String> {
        Some("NETransparentProxyProvider".to_string())
    }
}

impl Drop for SplitTunnelDriver {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_frame_round_trip_outbound() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(BRIDGE_MAGIC);
        bytes.push(FRAME_OUTBOUND_DATAGRAM);
        bytes.extend_from_slice(&7u64.to_be_bytes());
        push_socket_addr(&mut bytes, "1.2.3.4:4000".parse().unwrap()).unwrap();
        bytes.extend_from_slice(&(3u16).to_be_bytes());
        bytes.extend_from_slice(b"abc");

        match BridgeFrame::decode(&bytes).unwrap() {
            BridgeFrame::OutboundDatagram {
                flow_id,
                remote_addr,
                payload,
            } => {
                assert_eq!(flow_id, 7);
                assert_eq!(remote_addr, "1.2.3.4:4000".parse::<SocketAddr>().unwrap());
                assert_eq!(payload, b"abc");
            }
            _ => panic!("unexpected frame type"),
        }
    }

    #[test]
    fn ipv4_udp_packet_builds_and_parses() {
        let packet = build_ipv4_udp_packet(
            "10.0.0.2:45000".parse().unwrap(),
            "128.116.10.20:50000".parse().unwrap(),
            b"payload",
        )
        .unwrap();

        let parsed = ParsedInboundPacket::parse(
            &build_ipv4_udp_packet(
                "128.116.10.20:50000".parse().unwrap(),
                "10.0.0.2:45000".parse().unwrap(),
                b"payload",
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(packet[0], 0x45);
        assert_eq!(parsed.flow_key.local_ip, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(parsed.flow_key.remote_ip, Ipv4Addr::new(128, 116, 10, 20));
        assert_eq!(parsed.payload, b"payload");
    }

    #[test]
    fn roblox_range_matcher_handles_known_range() {
        assert!(is_roblox_game_server_ip(Ipv4Addr::new(128, 116, 12, 34)));
        assert!(!is_roblox_game_server_ip(Ipv4Addr::new(8, 8, 8, 8)));
    }
}
