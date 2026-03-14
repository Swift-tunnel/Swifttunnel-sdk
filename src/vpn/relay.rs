//! V3 Game Booster Mode - Unencrypted UDP relay with authenticated bootstrap.

use arc_swap::ArcSwap;
use crossbeam_channel as channel;
use std::cell::UnsafeCell;
use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const SESSION_ID_LEN: usize = 8;
const UDP_HEADER_LEN: usize = 8;
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const AUTH_HELLO_FRAME_TYPE: u8 = 0xA1;
const AUTH_ACK_FRAME_TYPE: u8 = 0xA2;
const PING_FRAME_TYPE: u8 = 0xA3;
const PONG_FRAME_TYPE: u8 = 0xA4;
const RTT_REPORT_FRAME_TYPE: u8 = 0xA5;
const PING_FRAME_LEN: usize = SESSION_ID_LEN + 1 + 4 + 8;
const PONG_FRAME_LEN: usize = SESSION_ID_LEN + 1 + 4 + 8 + 8;
const AUTH_HANDSHAKE_TOTAL_TIMEOUT: Duration = Duration::from_millis(1500);
const AUTH_HANDSHAKE_RETRY_DELAY: Duration = Duration::from_millis(250);
const AUTH_HANDSHAKE_ATTEMPTS: usize = 4;

/// Outer path MTU for relay packets (client <-> relay).
const RELAY_PATH_MTU_UPPER_BOUND: usize = 1500;
const RELAY_PATH_MTU_MINIMUM: usize = 576;
const RELAY_PATH_MTU_FALLBACK: usize = 1400;
const RELAY_PATH_MTU_REFRESH_INTERVAL_MS: u64 = 5_000;
const RELAY_PATH_MTU_FALLBACK_RETRY_INTERVAL_MS: u64 = 1_000;
const RELAY_PATH_MTU_POINT_TO_POINT_CEILING: usize = 1492;

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_millis(50);

const OUTBOUND_FRAME_MAX: usize = SESSION_ID_LEN + RELAY_PATH_MTU_UPPER_BOUND;
const OUTBOUND_POOL_SLOTS: usize = 4096;
const OUTBOUND_QUEUE_CAP: usize = 4096;

const PING_INTERVAL: Duration = Duration::from_millis(50);
const PING_IDLE_THRESHOLD: Duration = Duration::from_secs(2);
const PING_IDLE_INTERVAL: Duration = Duration::from_millis(250);
const PING_SAMPLE_WINDOW: usize = 1024;

const RELAY_SWITCH_GRACE_PERIOD: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RelayPathContext {
    pub point_to_point_default_route: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayAuthAckStatus {
    Ok = 0,
    BadFormat = 1,
    BadSignature = 2,
    Expired = 3,
    SidMismatch = 4,
    ServerMismatch = 5,
    AuthDisabled = 6,
}

impl RelayAuthAckStatus {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Ok),
            1 => Some(Self::BadFormat),
            2 => Some(Self::BadSignature),
            3 => Some(Self::Expired),
            4 => Some(Self::SidMismatch),
            5 => Some(Self::ServerMismatch),
            6 => Some(Self::AuthDisabled),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::BadFormat => "bad_format",
            Self::BadSignature => "bad_signature",
            Self::Expired => "expired",
            Self::SidMismatch => "sid_mismatch",
            Self::ServerMismatch => "server_mismatch",
            Self::AuthDisabled => "auth_disabled",
        }
    }
}

// ── Outbound buffer pool ─────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct OutboundJob {
    addr: SocketAddr,
    buf_idx: usize,
    len: usize,
}

struct OutboundPool {
    buffers: Vec<UnsafeCell<[u8; OUTBOUND_FRAME_MAX]>>,
    free_tx: channel::Sender<usize>,
    free_rx: channel::Receiver<usize>,
}

// SAFETY: Each buffer index is exclusively owned between try_acquire() and release().
// The bounded free-list channel is the sole authority for slot ownership.
unsafe impl Sync for OutboundPool {}
unsafe impl Send for OutboundPool {}

impl OutboundPool {
    fn new(slots: usize) -> Self {
        let (free_tx, free_rx) = channel::bounded(slots);
        let mut buffers = Vec::with_capacity(slots);
        for i in 0..slots {
            buffers.push(UnsafeCell::new([0u8; OUTBOUND_FRAME_MAX]));
            free_tx
                .send(i)
                .expect("outbound pool free list must accept initial slots");
        }
        Self {
            buffers,
            free_tx,
            free_rx,
        }
    }

    fn try_acquire(&self) -> Option<usize> {
        self.free_rx.try_recv().ok()
    }

    fn release(&self, idx: usize) {
        let _ = self.free_tx.send(idx);
    }

    unsafe fn buffer_mut(&self, idx: usize) -> &mut [u8; OUTBOUND_FRAME_MAX] {
        &mut *self.buffers[idx].get()
    }

    unsafe fn buffer(&self, idx: usize) -> &[u8; OUTBOUND_FRAME_MAX] {
        &*self.buffers[idx].get()
    }
}

// ── Ping telemetry ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RelayPingSnapshot {
    pub enabled: bool,
    pub sent: u64,
    pub received: u64,
    pub loss_pct: f32,
    pub last_rtt_ms: Option<u32>,
    pub p50_rtt_ms: Option<u32>,
    pub p99_rtt_ms: Option<u32>,
    pub sample_count: usize,
}

struct PingMetrics {
    enabled: AtomicBool,
    sent: AtomicU64,
    received: AtomicU64,
    last_rtt_ms: AtomicU64,
    samples: std::sync::Mutex<VecDeque<u32>>,
}

impl PingMetrics {
    fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
            last_rtt_ms: AtomicU64::new(0),
            samples: std::sync::Mutex::new(VecDeque::with_capacity(PING_SAMPLE_WINDOW)),
        }
    }

    fn record_rtt_ms(&self, rtt_ms: u32) {
        self.received.fetch_add(1, Ordering::Relaxed);
        self.last_rtt_ms.store(rtt_ms as u64, Ordering::Relaxed);

        if let Ok(mut samples) = self.samples.lock() {
            if samples.len() >= PING_SAMPLE_WINDOW {
                samples.pop_front();
            }
            samples.push_back(rtt_ms);
        }
    }

    fn snapshot(&self) -> RelayPingSnapshot {
        let enabled = self.enabled.load(Ordering::Acquire);
        let sent = self.sent.load(Ordering::Relaxed);
        let received = self.received.load(Ordering::Relaxed);
        let loss_pct = if sent == 0 {
            0.0
        } else {
            let lost = sent.saturating_sub(received);
            (lost as f32) * 100.0 / (sent as f32)
        };
        let last_rtt_raw = self.last_rtt_ms.load(Ordering::Relaxed);
        let last_rtt_ms = if last_rtt_raw == 0 {
            None
        } else {
            Some(last_rtt_raw as u32)
        };

        let mut p50_rtt_ms: Option<u32> = None;
        let mut p99_rtt_ms: Option<u32> = None;
        let mut sample_count = 0usize;

        if let Ok(samples) = self.samples.lock() {
            sample_count = samples.len();
            if sample_count > 0 {
                let mut values: Vec<u32> = samples.iter().copied().collect();
                values.sort_unstable();
                let p50_idx = ((values.len() - 1) as f64 * 0.50).floor() as usize;
                let p99_idx = ((values.len() - 1) as f64 * 0.99).floor() as usize;
                p50_rtt_ms = values.get(p50_idx).copied();
                p99_rtt_ms = values.get(p99_idx).copied();
            }
        }

        RelayPingSnapshot {
            enabled,
            sent,
            received,
            loss_pct,
            last_rtt_ms,
            p50_rtt_ms,
            p99_rtt_ms,
            sample_count,
        }
    }
}

// ── MTU helpers ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InitialRelayPathMtu {
    mtu: usize,
    is_fallback: bool,
    point_to_point_clamped: bool,
}

#[inline]
fn clamp_relay_path_mtu(mtu: usize) -> usize {
    mtu.clamp(RELAY_PATH_MTU_MINIMUM, RELAY_PATH_MTU_UPPER_BOUND)
}

#[inline]
fn apply_point_to_point_relay_mtu_ceiling(
    mtu: usize,
    path_context: RelayPathContext,
) -> (usize, bool) {
    if path_context.point_to_point_default_route && mtu > RELAY_PATH_MTU_POINT_TO_POINT_CEILING {
        (RELAY_PATH_MTU_POINT_TO_POINT_CEILING, true)
    } else {
        (mtu, false)
    }
}

#[inline]
fn select_initial_relay_path_mtu_for_context(
    detected_mtu: Option<usize>,
    path_context: RelayPathContext,
) -> InitialRelayPathMtu {
    match detected_mtu {
        Some(mtu) => {
            let mtu = clamp_relay_path_mtu(mtu);
            let (mtu, point_to_point_clamped) =
                apply_point_to_point_relay_mtu_ceiling(mtu, path_context);
            InitialRelayPathMtu {
                mtu,
                is_fallback: false,
                point_to_point_clamped,
            }
        }
        None => {
            let fallback_mtu = clamp_relay_path_mtu(RELAY_PATH_MTU_FALLBACK);
            let (mtu, point_to_point_clamped) =
                apply_point_to_point_relay_mtu_ceiling(fallback_mtu, path_context);
            InitialRelayPathMtu {
                mtu,
                is_fallback: true,
                point_to_point_clamped,
            }
        }
    }
}

#[inline]
fn select_initial_relay_path_mtu(detected_mtu: Option<usize>) -> (usize, bool) {
    let selection =
        select_initial_relay_path_mtu_for_context(detected_mtu, RelayPathContext::default());
    (selection.mtu, selection.is_fallback)
}

#[inline]
fn select_detected_relay_path_mtu(
    link_mtu: usize,
    ip_layer_mtu: Option<usize>,
    is_ppp: bool,
) -> usize {
    let mtu = ip_layer_mtu.unwrap_or(link_mtu);
    if is_ppp {
        mtu.min(RELAY_PATH_MTU_POINT_TO_POINT_CEILING)
    } else {
        mtu
    }
}

fn detect_relay_path_mtu(relay_addr: SocketAddr) -> Option<usize> {
    #[cfg(windows)]
    {
        use windows::Win32::NetworkManagement::IpHelper::{
            GetBestInterfaceEx, GetIfEntry2, GetIpInterfaceEntry, IF_TYPE_PPP, MIB_IF_ROW2,
            MIB_IPINTERFACE_ROW,
        };
        use windows::Win32::Networking::WinSock::{
            AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, SOCKADDR, SOCKADDR_IN,
            SOCKADDR_IN6, SOCKADDR_IN6_0,
        };

        let mut if_index: u32 = 0;

        let rc = match relay_addr {
            SocketAddr::V4(addr) => {
                let ip_octets = addr.ip().octets();
                let sockaddr_in = SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: 0,
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(ip_octets),
                        },
                    },
                    sin_zero: [0; 8],
                };
                unsafe {
                    GetBestInterfaceEx(
                        &sockaddr_in as *const SOCKADDR_IN as *const SOCKADDR,
                        &mut if_index,
                    )
                }
            }
            SocketAddr::V6(addr) => {
                let ip_octets = addr.ip().octets();
                let sockaddr_in6 = SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 { Byte: ip_octets },
                    },
                    Anonymous: SOCKADDR_IN6_0 {
                        sin6_scope_id: addr.scope_id(),
                    },
                };
                unsafe {
                    GetBestInterfaceEx(
                        &sockaddr_in6 as *const SOCKADDR_IN6 as *const SOCKADDR,
                        &mut if_index,
                    )
                }
            }
        };

        if rc != 0 {
            return None;
        }

        let mut row = MIB_IF_ROW2::default();
        row.InterfaceIndex = if_index;
        let rc = unsafe { GetIfEntry2(&mut row) };
        if rc.0 != 0 {
            return None;
        }

        let family = match relay_addr {
            SocketAddr::V4(_) => AF_INET,
            SocketAddr::V6(_) => AF_INET6,
        };
        let mut ip_row = MIB_IPINTERFACE_ROW::default();
        ip_row.InterfaceIndex = if_index;
        ip_row.Family = family;
        let ip_layer_mtu = if unsafe { GetIpInterfaceEntry(&mut ip_row) }.0 == 0 && ip_row.NlMtu > 0
        {
            Some(ip_row.NlMtu as usize)
        } else {
            None
        };

        let detected_mtu =
            select_detected_relay_path_mtu(row.Mtu as usize, ip_layer_mtu, row.Type == IF_TYPE_PPP);
        return Some(detected_mtu);
    }

    #[cfg(not(windows))]
    {
        let _ = relay_addr;
        None
    }
}

// ── Extended stats ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RelayStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub oversize_drops: u64,
    pub outbound_drops: u64,
    pub send_errors: u64,
    pub relay_path_mtu: usize,
}

// ── UdpRelay ─────────────────────────────────────────────────────────────────

pub struct UdpRelay {
    socket: UdpSocket,
    relay_addr: ArcSwap<SocketAddr>,
    previous_relay_addr: ArcSwap<Option<SocketAddr>>,
    switch_time: ArcSwap<Option<Instant>>,
    session_id: [u8; SESSION_ID_LEN],
    stop_flag: Arc<AtomicBool>,
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
    oversize_drops: AtomicU64,
    outbound_drops: AtomicU64,
    send_errors: Arc<AtomicU64>,
    relay_path_mtu: AtomicUsize,
    relay_path_context: RelayPathContext,
    relay_path_mtu_is_fallback: AtomicBool,
    last_mtu_refresh_ms: AtomicU64,
    mtu_detect_failures: AtomicU64,
    point_to_point_mtu_clamp_active: AtomicBool,
    point_to_point_mtu_clamp_events: AtomicU64,
    last_activity: std::sync::Mutex<Instant>,
    sender_handle: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    outbound_pool: Arc<OutboundPool>,
    outbound_tx: channel::Sender<OutboundJob>,
    ping: Arc<PingMetrics>,
}

impl UdpRelay {
    pub fn new(
        relay_addr: SocketAddr,
        relay_qos_enabled: bool,
    ) -> Result<Self, crate::error::SdkError> {
        Self::new_with_path_context(relay_addr, relay_qos_enabled, RelayPathContext::default())
    }

    pub fn new_with_path_context(
        relay_addr: SocketAddr,
        relay_qos_enabled: bool,
        path_context: RelayPathContext,
    ) -> Result<Self, crate::error::SdkError> {
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| {
            crate::error::SdkError::Vpn(format!("Failed to bind UDP socket: {}", e))
        })?;
        socket.set_read_timeout(Some(READ_TIMEOUT)).map_err(|e| {
            crate::error::SdkError::Vpn(format!("Failed to set read timeout: {}", e))
        })?;

        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            let raw = socket.as_raw_socket();
            let buf_size: i32 = 256 * 1024;
            let sock = windows::Win32::Networking::WinSock::SOCKET(raw as usize);

            unsafe {
                let buf_bytes = std::slice::from_raw_parts(&buf_size as *const i32 as *const u8, 4);
                let result = windows::Win32::Networking::WinSock::setsockopt(
                    sock,
                    windows::Win32::Networking::WinSock::SOL_SOCKET,
                    windows::Win32::Networking::WinSock::SO_RCVBUF,
                    Some(buf_bytes),
                );
                if result != 0 {
                    log::warn!("UDP Relay: Failed to set SO_RCVBUF to 256KB, using default");
                }

                let result = windows::Win32::Networking::WinSock::setsockopt(
                    sock,
                    windows::Win32::Networking::WinSock::SOL_SOCKET,
                    windows::Win32::Networking::WinSock::SO_SNDBUF,
                    Some(buf_bytes),
                );
                if result != 0 {
                    log::warn!("UDP Relay: Failed to set SO_SNDBUF to 256KB, using default");
                }
            }

            if relay_qos_enabled {
                let tos: i32 = 46 << 2;
                unsafe {
                    let tos_bytes = std::slice::from_raw_parts(&tos as *const i32 as *const u8, 4);
                    let result = windows::Win32::Networking::WinSock::setsockopt(
                        sock,
                        windows::Win32::Networking::WinSock::IPPROTO_IP.0,
                        windows::Win32::Networking::WinSock::IP_TOS,
                        Some(tos_bytes),
                    );
                    if result != 0 {
                        log::warn!("UDP Relay: Failed to set IP_TOS DSCP EF; continuing");
                    }

                    let result = windows::Win32::Networking::WinSock::setsockopt(
                        sock,
                        windows::Win32::Networking::WinSock::IPPROTO_IPV6.0,
                        windows::Win32::Networking::WinSock::IPV6_TCLASS,
                        Some(tos_bytes),
                    );
                    if result != 0 {
                        log::debug!("UDP Relay: Could not set IPV6_TCLASS DSCP EF");
                    }
                }
            }
        }

        let mut session_id = [0u8; SESSION_ID_LEN];
        getrandom(&mut session_id);

        let stop_flag = Arc::new(AtomicBool::new(false));

        let outbound_pool = Arc::new(OutboundPool::new(OUTBOUND_POOL_SLOTS));
        let (outbound_tx, outbound_rx) = channel::bounded::<OutboundJob>(OUTBOUND_QUEUE_CAP);
        let ping = Arc::new(PingMetrics::new());
        let send_errors = Arc::new(AtomicU64::new(0));

        let sender_socket = socket.try_clone().map_err(|e| {
            crate::error::SdkError::Vpn(format!(
                "Failed to clone UDP socket for sender thread: {}",
                e
            ))
        })?;
        let sender_pool = Arc::clone(&outbound_pool);
        let sender_stop = Arc::clone(&stop_flag);
        let sender_ping = Arc::clone(&ping);
        let sender_send_errors = Arc::clone(&send_errors);
        let sender_session_id = session_id;
        let sender_handle = std::thread::Builder::new()
            .name("udp-relay-sender".to_string())
            .spawn(move || {
                let mut last_relay_addr: Option<SocketAddr> = None;
                let mut last_data_at: Option<Instant> = None;
                let mut ping_seq: u32 = 0;
                let mut next_ping_at = Instant::now() + PING_INTERVAL;

                loop {
                    if sender_stop.load(Ordering::Acquire) {
                        break;
                    }

                    let now = Instant::now();
                    let timeout = next_ping_at
                        .saturating_duration_since(now)
                        .min(Duration::from_millis(50));

                    match outbound_rx.recv_timeout(timeout) {
                        Ok(job) => {
                            last_relay_addr = Some(job.addr);
                            last_data_at = Some(Instant::now());

                            let bytes = unsafe { sender_pool.buffer(job.buf_idx) };
                            if let Err(e) = sender_socket.send_to(&bytes[..job.len], job.addr) {
                                let count = sender_send_errors.fetch_add(1, Ordering::Relaxed) + 1;
                                if count <= 5 || count.is_power_of_two() {
                                    log::warn!(
                                        "UDP Relay: Sender thread send_to error #{} to {}: {}",
                                        count,
                                        job.addr,
                                        e
                                    );
                                }
                            }
                            sender_pool.release(job.buf_idx);
                        }
                        Err(channel::RecvTimeoutError::Timeout) => {}
                        Err(channel::RecvTimeoutError::Disconnected) => break,
                    }

                    let now = Instant::now();
                    if !sender_ping.enabled.load(Ordering::Acquire) {
                        continue;
                    }

                    let Some(relay_addr) = last_relay_addr else {
                        continue;
                    };

                    let Some(last_data_at) = last_data_at else {
                        continue;
                    };

                    if now.duration_since(last_data_at) >= PING_IDLE_THRESHOLD {
                        next_ping_at = now + PING_IDLE_INTERVAL;
                        continue;
                    }

                    if now < next_ping_at {
                        continue;
                    }

                    ping_seq = ping_seq.wrapping_add(1);
                    let client_ts_mono_ms = now_mono_ms();

                    let mut frame = [0u8; PING_FRAME_LEN];
                    frame[..SESSION_ID_LEN].copy_from_slice(&sender_session_id);
                    frame[SESSION_ID_LEN] = PING_FRAME_TYPE;
                    frame[SESSION_ID_LEN + 1..SESSION_ID_LEN + 5]
                        .copy_from_slice(&ping_seq.to_be_bytes());
                    frame[SESSION_ID_LEN + 5..SESSION_ID_LEN + 13]
                        .copy_from_slice(&client_ts_mono_ms.to_be_bytes());

                    if let Err(e) = sender_socket.send_to(&frame, relay_addr) {
                        let count = sender_send_errors.fetch_add(1, Ordering::Relaxed) + 1;
                        if count <= 5 || count.is_power_of_two() {
                            log::warn!(
                                "UDP Relay: Sender thread ping send_to error #{} to {}: {}",
                                count,
                                relay_addr,
                                e
                            );
                        }
                    }
                    sender_ping.sent.fetch_add(1, Ordering::Relaxed);
                    next_ping_at = now + PING_INTERVAL;
                }

                while let Ok(job) = outbound_rx.try_recv() {
                    sender_pool.release(job.buf_idx);
                }
            })
            .map_err(|e| {
                crate::error::SdkError::Vpn(format!(
                    "Failed to spawn udp-relay-sender thread: {}",
                    e
                ))
            })?;

        log::info!(
            "UDP Relay: Created session {:016x} to {} (relay_qos={})",
            u64::from_be_bytes(session_id),
            relay_addr,
            relay_qos_enabled
        );

        let detected_mtu = detect_relay_path_mtu(relay_addr);
        let initial_mtu = select_initial_relay_path_mtu_for_context(detected_mtu, path_context);
        if initial_mtu.is_fallback {
            log::warn!(
                "UDP Relay: MTU probe unavailable for {}; using conservative fallback MTU {} (will retry)",
                relay_addr,
                initial_mtu.mtu
            );
        } else if initial_mtu.point_to_point_clamped {
            let detected_mtu = detected_mtu
                .map(clamp_relay_path_mtu)
                .unwrap_or(RELAY_PATH_MTU_UPPER_BOUND);
            log::warn!(
                "UDP Relay: PPP/point-to-point default route detected; clamping relay path MTU to {} (detected {}, relay {})",
                initial_mtu.mtu,
                detected_mtu,
                relay_addr
            );
        } else {
            log::info!(
                "UDP Relay: Detected relay path MTU {} for {}",
                initial_mtu.mtu,
                relay_addr
            );
        }

        Ok(Self {
            socket,
            relay_addr: ArcSwap::from_pointee(relay_addr),
            previous_relay_addr: ArcSwap::from_pointee(None),
            switch_time: ArcSwap::from_pointee(None),
            session_id,
            stop_flag,
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            oversize_drops: AtomicU64::new(0),
            outbound_drops: AtomicU64::new(0),
            send_errors,
            relay_path_mtu: AtomicUsize::new(initial_mtu.mtu),
            relay_path_context: path_context,
            relay_path_mtu_is_fallback: AtomicBool::new(initial_mtu.is_fallback),
            last_mtu_refresh_ms: AtomicU64::new(if initial_mtu.is_fallback {
                0
            } else {
                now_mono_ms()
            }),
            mtu_detect_failures: AtomicU64::new(0),
            point_to_point_mtu_clamp_active: AtomicBool::new(initial_mtu.point_to_point_clamped),
            point_to_point_mtu_clamp_events: AtomicU64::new(
                if initial_mtu.point_to_point_clamped {
                    1
                } else {
                    0
                },
            ),
            last_activity: std::sync::Mutex::new(Instant::now()),
            sender_handle: std::sync::Mutex::new(Some(sender_handle)),
            outbound_pool,
            outbound_tx,
            ping,
        })
    }

    pub fn session_id_u64(&self) -> u64 {
        u64::from_be_bytes(self.session_id)
    }

    pub fn session_id_hex(&self) -> String {
        format!("{:016x}", self.session_id_u64())
    }

    fn max_inner_packet_len_for_addr(&self, relay_addr: SocketAddr) -> usize {
        let mtu = self.relay_path_mtu.load(Ordering::Relaxed);
        let overhead = if relay_addr.ip().is_ipv4() {
            IPV4_HEADER_LEN + UDP_HEADER_LEN + SESSION_ID_LEN
        } else {
            IPV6_HEADER_LEN + UDP_HEADER_LEN + SESSION_ID_LEN
        };
        mtu.saturating_sub(overhead)
    }

    #[cfg(windows)]
    fn maybe_refresh_relay_path_mtu(&self, relay_addr: SocketAddr) {
        let now = now_mono_ms();
        let refresh_interval_ms = if self.relay_path_mtu_is_fallback.load(Ordering::Acquire) {
            RELAY_PATH_MTU_FALLBACK_RETRY_INTERVAL_MS
        } else {
            RELAY_PATH_MTU_REFRESH_INTERVAL_MS
        };
        let last = self.last_mtu_refresh_ms.load(Ordering::Relaxed);
        if now.saturating_sub(last) < refresh_interval_ms {
            return;
        }

        if self
            .last_mtu_refresh_ms
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        match detect_relay_path_mtu(relay_addr) {
            Some(detected_mtu) => {
                let detected_mtu = clamp_relay_path_mtu(detected_mtu);
                let (mtu, point_to_point_clamped) =
                    apply_point_to_point_relay_mtu_ceiling(detected_mtu, self.relay_path_context);
                let prev = self.relay_path_mtu.swap(mtu, Ordering::Relaxed);
                let was_fallback = self
                    .relay_path_mtu_is_fallback
                    .swap(false, Ordering::AcqRel);
                let was_point_to_point_clamped = self
                    .point_to_point_mtu_clamp_active
                    .swap(point_to_point_clamped, Ordering::AcqRel);
                self.mtu_detect_failures.store(0, Ordering::Relaxed);
                if prev != mtu || was_fallback {
                    if was_fallback {
                        log::info!(
                            "UDP Relay: MTU probe recovered for {}; using detected MTU {}",
                            relay_addr,
                            mtu
                        );
                    } else {
                        log::info!(
                            "UDP Relay: Updated relay path MTU {} -> {} for {}",
                            prev,
                            mtu,
                            relay_addr
                        );
                    }
                }
                if point_to_point_clamped && (!was_point_to_point_clamped || prev != mtu) {
                    let events = self
                        .point_to_point_mtu_clamp_events
                        .fetch_add(1, Ordering::Relaxed)
                        + 1;
                    log::info!(
                        "UDP Relay: PPPoE clamp active (detected MTU {}, clamped to {}, relay {}, event #{})",
                        detected_mtu,
                        mtu,
                        relay_addr,
                        events
                    );
                } else if !point_to_point_clamped && was_point_to_point_clamped {
                    log::info!(
                        "UDP Relay: PPPoE clamp no longer active (detected MTU {}, relay {})",
                        detected_mtu,
                        relay_addr
                    );
                }
            }
            None => {
                let failures = self.mtu_detect_failures.fetch_add(1, Ordering::Relaxed) + 1;
                if self.relay_path_mtu_is_fallback.load(Ordering::Acquire)
                    && (failures <= 5 || failures.is_power_of_two())
                {
                    log::warn!(
                        "UDP Relay: MTU probe failed for {}; keeping fallback MTU {} (attempt #{})",
                        relay_addr,
                        self.relay_path_mtu.load(Ordering::Relaxed),
                        failures
                    );
                }
            }
        }
    }

    #[cfg(not(windows))]
    fn maybe_refresh_relay_path_mtu(&self, _relay_addr: SocketAddr) {}

    #[cfg(test)]
    fn set_relay_path_mtu_for_test(&self, mtu: usize) {
        let mtu = clamp_relay_path_mtu(mtu);
        self.relay_path_mtu.store(mtu, Ordering::Relaxed);
        self.relay_path_mtu_is_fallback
            .store(false, Ordering::Release);
        self.mtu_detect_failures.store(0, Ordering::Relaxed);
        self.point_to_point_mtu_clamp_active
            .store(false, Ordering::Release);
        self.point_to_point_mtu_clamp_events
            .store(0, Ordering::Relaxed);
    }

    fn is_expected_relay_source(&self, from: SocketAddr) -> bool {
        let expected_addr = **self.relay_addr.load();
        if from == expected_addr {
            return true;
        }

        if let (Some(prev), Some(switched_at)) = (
            (**self.previous_relay_addr.load()).as_ref(),
            (**self.switch_time.load()).as_ref(),
        ) {
            return from == *prev && switched_at.elapsed() < RELAY_SWITCH_GRACE_PERIOD;
        }
        false
    }

    pub fn send_auth_hello(&self, token: &str) -> Result<(), crate::error::SdkError> {
        let token_bytes = token.as_bytes();
        if token_bytes.is_empty() || token_bytes.len() > u16::MAX as usize {
            return Err(crate::error::SdkError::Vpn(format!(
                "Invalid relay auth token length: {}",
                token_bytes.len()
            )));
        }

        let mut frame = Vec::with_capacity(SESSION_ID_LEN + 3 + token_bytes.len());
        frame.extend_from_slice(&self.session_id);
        frame.push(AUTH_HELLO_FRAME_TYPE);
        frame.extend_from_slice(&(token_bytes.len() as u16).to_be_bytes());
        frame.extend_from_slice(token_bytes);

        let current_addr = **self.relay_addr.load();
        self.socket.send_to(&frame, current_addr).map_err(|e| {
            crate::error::SdkError::Vpn(format!("Failed to send relay auth hello: {}", e))
        })?;

        Ok(())
    }

    fn wait_for_auth_ack_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Option<RelayAuthAckStatus>, crate::error::SdkError> {
        let deadline = Instant::now() + timeout;
        let mut recv_buf = [0u8; 1600];

        while Instant::now() < deadline {
            match self.socket.recv_from(&mut recv_buf) {
                Ok((len, from)) => {
                    if !self.is_expected_relay_source(from) {
                        continue;
                    }
                    if len < SESSION_ID_LEN + 2 {
                        continue;
                    }
                    if &recv_buf[..SESSION_ID_LEN] != &self.session_id {
                        continue;
                    }
                    if recv_buf[SESSION_ID_LEN] != AUTH_ACK_FRAME_TYPE {
                        continue;
                    }

                    let status_byte = recv_buf[SESSION_ID_LEN + 1];
                    let status = RelayAuthAckStatus::from_u8(status_byte)
                        .unwrap_or(RelayAuthAckStatus::BadFormat);
                    return Ok(Some(status));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                Err(e) => {
                    return Err(crate::error::SdkError::Vpn(format!(
                        "Relay auth ack read failed: {}",
                        e
                    )))
                }
            }
        }

        Ok(None)
    }

    pub fn authenticate_with_ticket(
        &self,
        token: &str,
    ) -> Result<Option<RelayAuthAckStatus>, crate::error::SdkError> {
        let deadline = Instant::now() + AUTH_HANDSHAKE_TOTAL_TIMEOUT;

        for attempt in 0..AUTH_HANDSHAKE_ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(AUTH_HANDSHAKE_RETRY_DELAY);
            }

            self.send_auth_hello(token)?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }

            if let Some(status) = self.wait_for_auth_ack_with_timeout(remaining)? {
                log::info!(
                    "UDP Relay: Auth ack {} for session {:016x}",
                    status.as_str(),
                    self.session_id_u64()
                );
                return Ok(Some(status));
            }
        }

        Ok(None)
    }

    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop_flag)
    }

    pub fn set_ping_enabled(&self, enabled: bool) {
        self.ping.enabled.store(enabled, Ordering::Release);
    }

    pub fn ping_snapshot(&self) -> RelayPingSnapshot {
        self.ping.snapshot()
    }

    pub fn forward_outbound(&self, payload: &[u8]) -> Result<usize, crate::error::SdkError> {
        let current_addr = **self.relay_addr.load();
        self.maybe_refresh_relay_path_mtu(current_addr);
        let max_payload = self.max_inner_packet_len_for_addr(current_addr);

        if payload.len() > max_payload {
            let dropped = self.oversize_drops.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped <= 5 || dropped.is_power_of_two() {
                let mtu = self.relay_path_mtu.load(Ordering::Relaxed);
                let overhead = mtu.saturating_sub(max_payload);
                log::warn!(
                    "UDP Relay: Inner packet too large for encapsulation ({} > {} bytes). \
                    Dropping to avoid fragmentation (relay path MTU {}, overhead {} bytes, relay {}).",
                    payload.len(),
                    max_payload,
                    mtu,
                    overhead,
                    current_addr,
                );
            }
            return Ok(0);
        }

        let total_len = SESSION_ID_LEN + payload.len();

        let Some(buf_idx) = self.outbound_pool.try_acquire() else {
            self.outbound_drops.fetch_add(1, Ordering::Relaxed);
            return Ok(0);
        };

        unsafe {
            let packet = self.outbound_pool.buffer_mut(buf_idx);
            packet[..SESSION_ID_LEN].copy_from_slice(&self.session_id);
            packet[SESSION_ID_LEN..total_len].copy_from_slice(payload);
        }

        let job = OutboundJob {
            addr: current_addr,
            buf_idx,
            len: total_len,
        };
        if self.outbound_tx.try_send(job).is_err() {
            self.outbound_drops.fetch_add(1, Ordering::Relaxed);
            self.outbound_pool.release(buf_idx);
            return Ok(0);
        }

        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut guard) = self.last_activity.lock() {
            *guard = Instant::now();
        }

        Ok(total_len)
    }

    pub fn receive_inbound(
        &self,
        buffer: &mut [u8],
    ) -> Result<Option<usize>, crate::error::SdkError> {
        let mut recv_buf = [0u8; 1600];
        match self.socket.recv_from(&mut recv_buf) {
            Ok((len, from)) => {
                if !self.is_expected_relay_source(from) {
                    return Ok(None);
                }

                if len < SESSION_ID_LEN {
                    return Ok(None);
                }
                if &recv_buf[..SESSION_ID_LEN] != &self.session_id {
                    return Ok(None);
                }

                let payload_len = len - SESSION_ID_LEN;
                if payload_len > buffer.len() {
                    return Ok(None);
                }

                if payload_len >= 1 {
                    match recv_buf[SESSION_ID_LEN] {
                        AUTH_HELLO_FRAME_TYPE | AUTH_ACK_FRAME_TYPE | PING_FRAME_TYPE => {
                            return Ok(None);
                        }
                        PONG_FRAME_TYPE => {
                            if len == PONG_FRAME_LEN && self.ping.enabled.load(Ordering::Acquire) {
                                let client_ts_mono_ms = u64::from_be_bytes([
                                    recv_buf[SESSION_ID_LEN + 5],
                                    recv_buf[SESSION_ID_LEN + 6],
                                    recv_buf[SESSION_ID_LEN + 7],
                                    recv_buf[SESSION_ID_LEN + 8],
                                    recv_buf[SESSION_ID_LEN + 9],
                                    recv_buf[SESSION_ID_LEN + 10],
                                    recv_buf[SESSION_ID_LEN + 11],
                                    recv_buf[SESSION_ID_LEN + 12],
                                ]);
                                let now_ms = now_mono_ms();
                                if now_ms >= client_ts_mono_ms {
                                    let rtt_ms = (now_ms - client_ts_mono_ms) as u32;
                                    self.ping.record_rtt_ms(rtt_ms);

                                    let rtt_us = rtt_ms.saturating_mul(1000);
                                    const RTT_REPORT_LEN: usize = SESSION_ID_LEN + 1 + 4;
                                    if let Some(buf_idx) = self.outbound_pool.try_acquire() {
                                        unsafe {
                                            let pkt = self.outbound_pool.buffer_mut(buf_idx);
                                            pkt[..SESSION_ID_LEN].copy_from_slice(&self.session_id);
                                            pkt[SESSION_ID_LEN] = RTT_REPORT_FRAME_TYPE;
                                            pkt[SESSION_ID_LEN + 1..SESSION_ID_LEN + 5]
                                                .copy_from_slice(&rtt_us.to_be_bytes());
                                        }
                                        let job = OutboundJob {
                                            addr: from,
                                            buf_idx,
                                            len: RTT_REPORT_LEN,
                                        };
                                        if self.outbound_tx.try_send(job).is_err() {
                                            self.outbound_pool.release(buf_idx);
                                        }
                                    }
                                }
                            }
                            return Ok(None);
                        }
                        _ => {}
                    }
                }

                buffer[..payload_len].copy_from_slice(&recv_buf[SESSION_ID_LEN..len]);
                self.packets_received.fetch_add(1, Ordering::Relaxed);
                if let Ok(mut guard) = self.last_activity.lock() {
                    *guard = Instant::now();
                }
                Ok(Some(payload_len))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(None),
            Err(e) => Err(crate::error::SdkError::Vpn(e.to_string())),
        }
    }

    pub fn send_keepalive_now(&self) -> Result<(), crate::error::SdkError> {
        let current_addr = **self.relay_addr.load();
        self.socket
            .send_to(&self.session_id, current_addr)
            .map_err(|e| crate::error::SdkError::Vpn(format!("Failed to send keepalive: {}", e)))?;
        if let Ok(mut guard) = self.last_activity.lock() {
            *guard = Instant::now();
        }
        Ok(())
    }

    pub fn send_keepalive_burst(&self) -> Result<(), crate::error::SdkError> {
        let current_addr = **self.relay_addr.load();
        for i in 0..3 {
            if i > 0 {
                std::thread::sleep(Duration::from_millis(50));
            }
            match self.socket.send_to(&self.session_id, current_addr) {
                Ok(_) => {}
                Err(e) if i == 0 => {
                    return Err(crate::error::SdkError::Vpn(format!(
                        "Keepalive burst failed: {}",
                        e
                    )))
                }
                Err(e) => log::warn!("UDP Relay keepalive burst #{} failed: {}", i + 1, e),
            }
        }
        if let Ok(mut guard) = self.last_activity.lock() {
            *guard = Instant::now();
        }
        Ok(())
    }

    pub fn send_keepalive(&self) -> Result<(), crate::error::SdkError> {
        let should_send = self
            .last_activity
            .lock()
            .map(|guard| guard.elapsed() >= KEEPALIVE_INTERVAL)
            .unwrap_or(true);
        if should_send {
            self.send_keepalive_now()?;
        }
        Ok(())
    }

    pub fn stats(&self) -> (u64, u64) {
        (
            self.packets_sent.load(Ordering::Relaxed),
            self.packets_received.load(Ordering::Relaxed),
        )
    }

    pub fn extended_stats(&self) -> RelayStats {
        RelayStats {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            oversize_drops: self.oversize_drops.load(Ordering::Relaxed),
            outbound_drops: self.outbound_drops.load(Ordering::Relaxed),
            send_errors: self.send_errors.load(Ordering::Relaxed),
            relay_path_mtu: self.relay_path_mtu.load(Ordering::Relaxed),
        }
    }

    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Release);
        let ping = self.ping.snapshot();
        log::info!(
            "UDP Relay: Stopped session {:016x} (sent: {}, recv: {}, oversize_drops: {}, outbound_drops: {}, send_errors: {}, pppoe_clamp_active: {}, pppoe_clamp_events: {}, ping: {}/{} {:.1}% loss)",
            self.session_id_u64(),
            self.packets_sent.load(Ordering::Relaxed),
            self.packets_received.load(Ordering::Relaxed),
            self.oversize_drops.load(Ordering::Relaxed),
            self.outbound_drops.load(Ordering::Relaxed),
            self.send_errors.load(Ordering::Relaxed),
            self.point_to_point_mtu_clamp_active.load(Ordering::Acquire),
            self.point_to_point_mtu_clamp_events.load(Ordering::Relaxed),
            ping.sent,
            ping.received,
            ping.loss_pct,
        );
    }

    pub fn try_clone_socket(&self) -> Result<UdpSocket, crate::error::SdkError> {
        self.socket.try_clone().map_err(|e| {
            crate::error::SdkError::Vpn(format!("Failed to clone relay socket: {}", e))
        })
    }

    pub fn relay_addr(&self) -> SocketAddr {
        **self.relay_addr.load()
    }

    pub fn switch_relay(&self, new_addr: SocketAddr) {
        let old_addr = **self.relay_addr.load();
        self.previous_relay_addr.store(Arc::new(Some(old_addr)));
        self.switch_time.store(Arc::new(Some(Instant::now())));
        self.relay_addr.store(Arc::new(new_addr));
        self.last_mtu_refresh_ms.store(0, Ordering::Relaxed);
        self.maybe_refresh_relay_path_mtu(new_addr);
    }

    pub fn session_id_bytes(&self) -> &[u8; SESSION_ID_LEN] {
        &self.session_id
    }
}

impl Drop for UdpRelay {
    fn drop(&mut self) {
        self.stop();

        let handle = self
            .sender_handle
            .lock()
            .ok()
            .and_then(|mut guard| guard.take());
        if let Some(handle) = handle {
            if let Err(panic) = handle.join() {
                log::error!("UDP Relay: sender thread panicked: {:?}", panic);
            }
        }
    }
}

fn getrandom(buf: &mut [u8]) {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(buf);
}

fn now_mono_ms() -> u64 {
    #[cfg(windows)]
    unsafe {
        return windows::Win32::System::SystemInformation::GetTickCount64();
    }

    #[cfg(not(windows))]
    {
        use std::sync::OnceLock;
        static START: OnceLock<Instant> = OnceLock::new();
        let start = START.get_or_init(Instant::now);
        start.elapsed().as_millis() as u64
    }
}

pub struct RelayContext {
    pub relay: Arc<UdpRelay>,
    pub session_id: [u8; SESSION_ID_LEN],
}

impl RelayContext {
    pub fn new(relay: Arc<UdpRelay>) -> Self {
        let session_id = *relay.session_id_bytes();
        Self { relay, session_id }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RelayAuthAckStatus ──────────────────────────────────────────────

    #[test]
    fn auth_ack_status_from_u8_roundtrip() {
        for val in 0..=6u8 {
            let status = RelayAuthAckStatus::from_u8(val).unwrap();
            assert_eq!(status as u8, val);
        }
    }

    #[test]
    fn auth_ack_status_unknown_returns_none() {
        assert!(RelayAuthAckStatus::from_u8(7).is_none());
        assert!(RelayAuthAckStatus::from_u8(255).is_none());
    }

    // ── Session ID ──────────────────────────────────────────────────────

    #[test]
    fn session_id_generation_is_random() {
        let mut id1 = [0u8; 8];
        let mut id2 = [0u8; 8];
        getrandom(&mut id1);
        getrandom(&mut id2);
        assert_ne!(id1, id2);
    }

    // ── Packet format ───────────────────────────────────────────────────

    #[test]
    fn packet_format_session_id_plus_payload() {
        let session_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let payload = [0u8; 100];

        let mut packet = Vec::new();
        packet.extend_from_slice(&session_id);
        packet.extend_from_slice(&payload);

        assert_eq!(packet.len(), 108);
        assert_eq!(&packet[..8], &session_id);
    }

    // ── MTU pure functions ──────────────────────────────────────────────

    #[test]
    fn select_initial_mtu_prefers_detected_value() {
        let (mtu, fallback) = select_initial_relay_path_mtu(Some(1492));
        assert_eq!(mtu, 1492);
        assert!(!fallback);
    }

    #[test]
    fn select_initial_mtu_clamps_detected_value() {
        let (mtu_low, fallback_low) = select_initial_relay_path_mtu(Some(400));
        assert_eq!(mtu_low, RELAY_PATH_MTU_MINIMUM);
        assert!(!fallback_low);

        let (mtu_high, fallback_high) = select_initial_relay_path_mtu(Some(9000));
        assert_eq!(mtu_high, RELAY_PATH_MTU_UPPER_BOUND);
        assert!(!fallback_high);
    }

    #[test]
    fn select_initial_mtu_conservative_fallback_on_failure() {
        let (mtu, fallback) = select_initial_relay_path_mtu(None);
        assert_eq!(mtu, RELAY_PATH_MTU_FALLBACK);
        assert!(fallback);
    }

    #[test]
    fn select_initial_mtu_pppoe_caps_detected_1500() {
        let selected = select_initial_relay_path_mtu_for_context(
            Some(1500),
            RelayPathContext {
                point_to_point_default_route: true,
            },
        );
        assert_eq!(selected.mtu, RELAY_PATH_MTU_POINT_TO_POINT_CEILING);
        assert!(!selected.is_fallback);
        assert!(selected.point_to_point_clamped);
    }

    #[test]
    fn select_initial_mtu_non_pppoe_keeps_value() {
        let selected = select_initial_relay_path_mtu_for_context(
            Some(1500),
            RelayPathContext {
                point_to_point_default_route: false,
            },
        );
        assert_eq!(selected.mtu, 1500);
        assert!(!selected.is_fallback);
        assert!(!selected.point_to_point_clamped);
    }

    #[test]
    fn select_detected_mtu_prefers_ip_layer() {
        assert_eq!(
            select_detected_relay_path_mtu(1500, Some(1460), false),
            1460
        );
    }

    #[test]
    fn select_detected_mtu_falls_back_to_link() {
        assert_eq!(select_detected_relay_path_mtu(1492, None, false), 1492);
    }

    #[test]
    fn select_detected_mtu_clamps_ppp_to_1492() {
        assert_eq!(
            select_detected_relay_path_mtu(1500, Some(1500), true),
            RELAY_PATH_MTU_POINT_TO_POINT_CEILING
        );
        assert_eq!(select_detected_relay_path_mtu(1492, Some(1460), true), 1460);
    }

    // ── OutboundPool ────────────────────────────────────────────────────

    #[test]
    fn outbound_pool_acquire_release_cycle() {
        let pool = OutboundPool::new(4);
        let idx1 = pool.try_acquire().unwrap();
        let idx2 = pool.try_acquire().unwrap();
        assert_ne!(idx1, idx2);
        pool.release(idx1);
        let idx3 = pool.try_acquire().unwrap();
        assert_eq!(idx3, idx1);
    }

    // ── forward_outbound ────────────────────────────────────────────────

    #[test]
    fn forward_outbound_drops_oversize_payload() {
        let relay = UdpRelay::new("127.0.0.1:51821".parse().unwrap(), false).unwrap();
        relay.set_relay_path_mtu_for_test(1500);
        let max_payload = relay.max_inner_packet_len_for_addr("127.0.0.1:51821".parse().unwrap());
        let payload = vec![0u8; max_payload + 1];
        let sent = relay.forward_outbound(&payload).unwrap();
        assert_eq!(sent, 0);
        assert_eq!(relay.oversize_drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn forward_outbound_allows_max_payload() {
        let relay = UdpRelay::new("127.0.0.1:51821".parse().unwrap(), false).unwrap();
        relay.set_relay_path_mtu_for_test(1500);
        let max_payload = relay.max_inner_packet_len_for_addr("127.0.0.1:51821".parse().unwrap());
        let payload = vec![0u8; max_payload];
        let sent = relay.forward_outbound(&payload).unwrap();
        assert_eq!(sent, SESSION_ID_LEN + max_payload);
    }

    #[test]
    fn forward_outbound_respects_lower_path_mtu() {
        let relay = UdpRelay::new("127.0.0.1:51821".parse().unwrap(), false).unwrap();
        relay.set_relay_path_mtu_for_test(1400);
        let max_payload = relay.max_inner_packet_len_for_addr("127.0.0.1:51821".parse().unwrap());
        assert_eq!(
            max_payload,
            1400 - (IPV4_HEADER_LEN + UDP_HEADER_LEN + SESSION_ID_LEN)
        );

        let payload = vec![0u8; max_payload + 1];
        let sent = relay.forward_outbound(&payload).unwrap();
        assert_eq!(sent, 0);
        assert_eq!(relay.oversize_drops.load(Ordering::Relaxed), 1);
    }

    // ── Ping telemetry ──────────────────────────────────────────────────

    #[test]
    fn receive_inbound_ignores_pong_and_records_ping_stats() {
        let relay = UdpRelay::new("127.0.0.1:51821".parse().unwrap(), false).unwrap();
        relay.set_ping_enabled(true);

        let fake_relay = UdpSocket::bind("127.0.0.1:0").unwrap();
        let fake_addr = fake_relay.local_addr().unwrap();
        relay.switch_relay(fake_addr);

        let local_port = relay
            .try_clone_socket()
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let local_addr = SocketAddr::from(([127, 0, 0, 1], local_port));

        let seq: u32 = 1;
        let client_ts_mono_ms = now_mono_ms();
        let mut frame = [0u8; PONG_FRAME_LEN];
        frame[..SESSION_ID_LEN].copy_from_slice(relay.session_id_bytes());
        frame[SESSION_ID_LEN] = PONG_FRAME_TYPE;
        frame[SESSION_ID_LEN + 1..SESSION_ID_LEN + 5].copy_from_slice(&seq.to_be_bytes());
        frame[SESSION_ID_LEN + 5..SESSION_ID_LEN + 13]
            .copy_from_slice(&client_ts_mono_ms.to_be_bytes());
        frame[SESSION_ID_LEN + 13..SESSION_ID_LEN + 21].copy_from_slice(&0u64.to_be_bytes());

        fake_relay.send_to(&frame, local_addr).unwrap();

        let mut buffer = [0u8; 1600];
        let result = relay.receive_inbound(&mut buffer).unwrap();
        assert_eq!(result, None);

        let snap = relay.ping_snapshot();
        assert!(snap.received >= 1);
    }

    #[test]
    fn ping_metrics_snapshot_percentile_calculation() {
        let metrics = PingMetrics::new();
        metrics.enabled.store(true, Ordering::Release);

        for rtt in 1..=100u32 {
            metrics.record_rtt_ms(rtt);
        }

        let snap = metrics.snapshot();
        assert_eq!(snap.sample_count, 100);
        assert!(snap.received == 100);
        assert_eq!(snap.last_rtt_ms, Some(100));
        assert!(snap.p50_rtt_ms.unwrap() >= 49 && snap.p50_rtt_ms.unwrap() <= 51);
        assert!(snap.p99_rtt_ms.unwrap() >= 98);
    }

    #[test]
    fn ping_metrics_empty_snapshot() {
        let metrics = PingMetrics::new();
        let snap = metrics.snapshot();
        assert!(!snap.enabled);
        assert_eq!(snap.sent, 0);
        assert_eq!(snap.received, 0);
        assert_eq!(snap.loss_pct, 0.0);
        assert_eq!(snap.last_rtt_ms, None);
        assert_eq!(snap.p50_rtt_ms, None);
        assert_eq!(snap.p99_rtt_ms, None);
        assert_eq!(snap.sample_count, 0);
    }

    // ── Extended stats ──────────────────────────────────────────────────

    #[test]
    fn extended_stats_initial_values() {
        let relay = UdpRelay::new("127.0.0.1:51821".parse().unwrap(), false).unwrap();
        let stats = relay.extended_stats();
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.oversize_drops, 0);
        assert_eq!(stats.outbound_drops, 0);
        assert_eq!(stats.send_errors, 0);
    }
}
