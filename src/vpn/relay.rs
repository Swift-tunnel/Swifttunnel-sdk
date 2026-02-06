//! V3 Game Booster Mode - Unencrypted UDP Relay
//!
//! Routes game traffic through optimized paths without encryption overhead.
//! Trades security for performance (like ExitLag/WTFast).
//!
//! Protocol:
//! - Client sends: [8-byte session_id][original UDP payload]
//! - Server forwards payload to game server, tracks session for responses
//! - Server sends back: [8-byte session_id][game server response]
//! - Client strips session_id and injects response to game

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Session ID length in bytes
const SESSION_ID_LEN: usize = 8;

/// Maximum packet size (MTU - IP header - UDP header - session ID)
const MAX_PAYLOAD_SIZE: usize = 1500 - 20 - 8 - SESSION_ID_LEN;

/// Keepalive interval to maintain NAT bindings - 15s is safer for strict NATs
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Read timeout - shorter for tighter packet pickup loop
const READ_TIMEOUT: Duration = Duration::from_micros(100);

/// UDP Relay client for Game Booster mode
pub struct UdpRelay {
    /// Socket for communicating with relay server
    socket: UdpSocket,
    /// Relay server address
    relay_addr: SocketAddr,
    /// Unique session ID for this connection
    session_id: [u8; SESSION_ID_LEN],
    /// Stop flag
    stop_flag: Arc<AtomicBool>,
    /// Packets sent counter
    packets_sent: AtomicU64,
    /// Packets received counter
    packets_received: AtomicU64,
    /// Last activity time for keepalive
    last_activity: std::sync::Mutex<Instant>,
}

impl UdpRelay {
    /// Create a new UDP relay connection to the specified server
    pub fn new(relay_addr: SocketAddr) -> Result<Self, crate::error::SdkError> {
        // Bind to any available port
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| crate::error::SdkError::Vpn(format!("Failed to bind UDP socket: {}", e)))?;

        // Set socket options for low latency
        socket.set_read_timeout(Some(READ_TIMEOUT))
            .map_err(|e| crate::error::SdkError::Vpn(format!("Failed to set read timeout: {}", e)))?;

        // Increase receive buffer to 256KB to handle burst traffic
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            let raw = socket.as_raw_socket();
            let buf_size: i32 = 256 * 1024;
            let result = unsafe {
                windows::Win32::Networking::WinSock::setsockopt(
                    windows::Win32::Networking::WinSock::SOCKET(raw as usize),
                    windows::Win32::Networking::WinSock::SOL_SOCKET,
                    windows::Win32::Networking::WinSock::SO_RCVBUF,
                    Some(std::slice::from_raw_parts(
                        &buf_size as *const i32 as *const u8,
                        4
                    ))
                )
            };
            if result != 0 {
                log::warn!("UDP Relay: Failed to set SO_RCVBUF to 256KB, using default");
            }
        }

        // Generate random session ID
        let mut session_id = [0u8; SESSION_ID_LEN];
        getrandom(&mut session_id);

        log::info!(
            "UDP Relay: Created session {:016x} to {}",
            u64::from_be_bytes(session_id),
            relay_addr
        );

        Ok(Self {
            socket,
            relay_addr,
            session_id,
            stop_flag: Arc::new(AtomicBool::new(false)),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            last_activity: std::sync::Mutex::new(Instant::now()),
        })
    }

    /// Get the session ID as a u64 for logging
    pub fn session_id_u64(&self) -> u64 {
        u64::from_be_bytes(self.session_id)
    }

    /// Get the stop flag for external control
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop_flag)
    }

    /// Forward a packet through the relay (outbound: game client -> relay -> game server)
    ///
    /// Takes the original UDP payload and prepends session ID before sending to relay.
    /// Includes retry logic for transient send failures.
    pub fn forward_outbound(&self, payload: &[u8]) -> Result<usize, crate::error::SdkError> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            log::warn!("UDP Relay: Packet too large ({} > {}), dropping", payload.len(), MAX_PAYLOAD_SIZE);
            return Ok(0);
        }

        // Build packet: [session_id][payload] on the stack (no heap alloc)
        let total_len = SESSION_ID_LEN + payload.len();
        let mut packet = [0u8; SESSION_ID_LEN + 1500];
        packet[..SESSION_ID_LEN].copy_from_slice(&self.session_id);
        packet[SESSION_ID_LEN..total_len].copy_from_slice(payload);

        // Try to send, retry once on WouldBlock
        let sent = match self.socket.send_to(&packet[..total_len], self.relay_addr) {
            Ok(sent) => sent,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_micros(50));
                self.socket.send_to(&packet[..total_len], self.relay_addr)
                    .map_err(|e| crate::error::SdkError::Vpn(format!("Retry send failed: {}", e)))?
            }
            Err(e) => return Err(crate::error::SdkError::Vpn(e.to_string())),
        };

        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut guard) = self.last_activity.lock() {
            *guard = Instant::now();
        }

        Ok(sent)
    }

    /// Receive a packet from the relay (inbound: game server -> relay -> game client)
    ///
    /// Returns the payload with session ID stripped, or None if no packet available.
    pub fn receive_inbound(&self, buffer: &mut [u8]) -> Result<Option<usize>, crate::error::SdkError> {
        let mut recv_buf = [0u8; 1600];

        match self.socket.recv_from(&mut recv_buf) {
            Ok((len, from)) => {
                if from != self.relay_addr {
                    log::warn!("UDP Relay: Received packet from unexpected source {}", from);
                    return Ok(None);
                }

                if len < SESSION_ID_LEN {
                    log::warn!("UDP Relay: Received packet too small ({})", len);
                    return Ok(None);
                }

                if &recv_buf[..SESSION_ID_LEN] != &self.session_id {
                    log::warn!("UDP Relay: Session ID mismatch, ignoring packet");
                    return Ok(None);
                }

                let payload_len = len - SESSION_ID_LEN;
                if payload_len > buffer.len() {
                    log::warn!("UDP Relay: Buffer too small for payload");
                    return Ok(None);
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

    /// Send keepalive to maintain NAT binding
    pub fn send_keepalive(&self) -> Result<(), crate::error::SdkError> {
        let should_send = self.last_activity
            .lock()
            .map(|guard| guard.elapsed() >= KEEPALIVE_INTERVAL)
            .unwrap_or(true);

        if should_send {
            self.socket.send_to(&self.session_id, self.relay_addr)
                .map_err(|e| crate::error::SdkError::Vpn(format!("Failed to send keepalive: {}", e)))?;
            if let Ok(mut guard) = self.last_activity.lock() {
                *guard = Instant::now();
            }
            log::trace!("UDP Relay: Sent keepalive");
        }
        Ok(())
    }

    /// Get statistics (packets_sent, packets_received)
    pub fn stats(&self) -> (u64, u64) {
        (
            self.packets_sent.load(Ordering::Relaxed),
            self.packets_received.load(Ordering::Relaxed),
        )
    }

    /// Stop the relay
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Release);
        log::info!(
            "UDP Relay: Stopped session {:016x} (sent: {}, recv: {})",
            self.session_id_u64(),
            self.packets_sent.load(Ordering::Relaxed),
            self.packets_received.load(Ordering::Relaxed)
        );
    }

    /// Clone the socket for use in inbound receiver thread
    pub fn try_clone_socket(&self) -> Result<UdpSocket, crate::error::SdkError> {
        self.socket.try_clone()
            .map_err(|e| crate::error::SdkError::Vpn(format!("Failed to clone relay socket: {}", e)))
    }

    /// Get the relay server address
    pub fn relay_addr(&self) -> SocketAddr {
        self.relay_addr
    }

    /// Get session ID bytes
    pub fn session_id_bytes(&self) -> &[u8; SESSION_ID_LEN] {
        &self.session_id
    }
}

impl Drop for UdpRelay {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Generate random bytes
fn getrandom(buf: &mut [u8]) {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(buf);
}

/// Context for relay mode in split tunnel interceptor
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
