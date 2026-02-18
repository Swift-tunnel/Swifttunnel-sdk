//! Authentication types for SwiftTunnel SDK

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Authentication state
#[derive(Debug, Clone, PartialEq)]
pub enum AuthState {
    /// Not logged in
    LoggedOut,
    /// Login in progress (email/password)
    LoggingIn,
    /// Waiting for OAuth callback from browser
    AwaitingOAuthCallback(OAuthPendingState),
    /// Logged in with valid tokens
    LoggedIn(AuthSession),
    /// Error state
    Error(String),
}

/// State for pending OAuth authentication
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OAuthPendingState {
    /// Random state parameter for CSRF protection
    pub state: String,
    /// When the OAuth flow was started
    pub started_at: DateTime<Utc>,
}

impl Default for AuthState {
    fn default() -> Self {
        AuthState::LoggedOut
    }
}

/// Authenticated session with tokens
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthSession {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    pub user: UserInfo,
}

impl AuthSession {
    /// Check if the access token has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Check if the token will expire soon (within 5 minutes)
    pub fn expires_soon(&self) -> bool {
        Utc::now() + chrono::Duration::minutes(5) >= self.expires_at
    }
}

/// User information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    /// Whether this user has tester access (gates experimental features).
    #[serde(default)]
    pub is_tester: bool,
}

/// Supabase auth response
#[derive(Debug, Deserialize)]
pub struct SupabaseAuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub expires_at: Option<i64>,
    pub token_type: String,
    pub user: SupabaseUser,
}

/// Supabase user from auth response
#[derive(Debug, Deserialize)]
pub struct SupabaseUser {
    pub id: String,
    pub email: Option<String>,
}

/// VPN configuration from API
///
/// Field names use serde rename to match the API's camelCase response format.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnConfig {
    /// Config ID (UUID from database)
    #[serde(default)]
    pub id: String,
    pub region: String,
    /// Server endpoint (IP:port), API returns as "serverEndpoint"
    #[serde(rename = "serverEndpoint")]
    pub endpoint: String,
    /// Server's WireGuard public key
    pub server_public_key: String,
    /// Client's private key (generated server-side)
    pub private_key: String,
    /// Client's public key
    pub public_key: String,
    /// Assigned IP for the client (e.g., "10.0.42.15/32")
    pub assigned_ip: String,
    /// Allowed IPs to route through VPN (e.g., ["0.0.0.0/0"])
    pub allowed_ips: Vec<String>,
    /// DNS servers to use
    pub dns: Vec<String>,
    /// Whether Phantun (TCP stealth) is available for this server
    #[serde(default)]
    pub phantun_enabled: bool,
    /// Phantun port (typically 443)
    #[serde(default)]
    pub phantun_port: Option<u16>,
}

/// Response from the desktop OAuth exchange API
#[derive(Debug, Clone, Deserialize)]
pub struct ExchangeTokenResponse {
    /// Type of token (always "magiclink")
    #[serde(rename = "type")]
    pub token_type: String,
    /// Magic link token to verify with Supabase
    pub token: String,
    /// User's email address
    pub email: String,
    /// User's ID
    pub user_id: String,
}

/// Response from relay ticket bootstrap endpoint.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayPreflightMode {
    Legacy,
    Enforce,
}

impl Default for RelayPreflightMode {
    fn default() -> Self {
        Self::Legacy
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayQueueFullMode {
    Bypass,
    Drop,
}

impl Default for RelayQueueFullMode {
    fn default() -> Self {
        Self::Bypass
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct RelayConnectionPolicy {
    #[serde(default)]
    pub preflight_mode: RelayPreflightMode,
    #[serde(default)]
    pub queue_full_mode: RelayQueueFullMode,
}

/// Response from relay ticket bootstrap endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct RelayTicketResponse {
    pub token: String,
    pub expires_at: String,
    pub auth_required: bool,
    pub key_id: String,
    #[serde(default)]
    pub connection_policy: Option<RelayConnectionPolicy>,
}

impl RelayTicketResponse {
    pub fn preflight_mode(&self) -> RelayPreflightMode {
        self.connection_policy
            .as_ref()
            .map(|policy| policy.preflight_mode)
            .unwrap_or_default()
    }

    pub fn queue_full_mode(&self) -> RelayQueueFullMode {
        self.connection_policy
            .as_ref()
            .map(|policy| policy.queue_full_mode)
            .unwrap_or_default()
    }
}
