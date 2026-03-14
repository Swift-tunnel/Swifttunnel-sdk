//! Authentication module for SwiftTunnel SDK
//!
//! Handles authentication via Supabase:
//! - Direct email/password sign-in
//! - Google OAuth via localhost callback server
//! - Secure token storage via Keychain/Credential Manager
//! - Token refresh management

pub mod client;
pub mod manager;
pub mod oauth_server;
pub mod storage;
pub mod types;

pub use manager::AuthManager;
pub use oauth_server::{OAuthCallbackData, OAuthServer, OAuthServerResult, DEFAULT_OAUTH_PORT};
pub use types::*;
