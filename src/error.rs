//! SDK error types, error codes, and thread-local last-error storage.

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use thiserror::Error;

// ── Error codes (match old swifttunnel-vpn-native crate) ────────────────────

pub const SUCCESS: i32 = 0;
pub const ERROR_INVALID_PARAM: i32 = -1;
pub const ERROR_NOT_INITIALIZED: i32 = -2;
pub const ERROR_ALREADY_CONNECTED: i32 = -3;
pub const ERROR_NOT_CONNECTED: i32 = -4;
pub const ERROR_INTERNAL: i32 = -5;
pub const ERROR_AUTH: i32 = -6;
pub const ERROR_NETWORK: i32 = -7;
pub const ERROR_CONFIG: i32 = -8;
pub const ERROR_SPLIT_TUNNEL: i32 = -9;
pub const ERROR_VPN: i32 = -10;

// ── SdkError enum ───────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SdkError {
    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Split tunnel error: {0}")]
    SplitTunnel(String),

    #[error("VPN error: {0}")]
    Vpn(String),

    #[error("Invalid parameter: {0}")]
    InvalidParam(String),

    #[error("Not initialized")]
    NotInitialized,

    #[error("Already connected")]
    AlreadyConnected,

    #[error("Not connected")]
    NotConnected,

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Storage error: {0}")]
    Storage(String),
}

impl SdkError {
    /// Map this error to its integer error code for the C API.
    pub fn code(&self) -> i32 {
        match self {
            SdkError::Auth(_) => ERROR_AUTH,
            SdkError::Network(_) => ERROR_NETWORK,
            SdkError::Config(_) => ERROR_CONFIG,
            SdkError::SplitTunnel(_) => ERROR_SPLIT_TUNNEL,
            SdkError::Vpn(_) => ERROR_VPN,
            SdkError::InvalidParam(_) => ERROR_INVALID_PARAM,
            SdkError::NotInitialized => ERROR_NOT_INITIALIZED,
            SdkError::AlreadyConnected => ERROR_ALREADY_CONNECTED,
            SdkError::NotConnected => ERROR_NOT_CONNECTED,
            SdkError::Internal(_) => ERROR_INTERNAL,
            SdkError::Storage(_) => ERROR_INTERNAL,
        }
    }
}

// ── Last-error storage ──────────────────────────────────────────────────────

static LAST_ERROR: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));
static LAST_ERROR_CODE: Lazy<Mutex<i32>> = Lazy::new(|| Mutex::new(SUCCESS));

/// Store an error message (and its code) so it can be retrieved by the FFI caller.
pub fn set_error(msg: impl Into<String>) {
    *LAST_ERROR.lock() = Some(msg.into());
}

/// Store an `SdkError`, recording both the message and code.
pub fn set_sdk_error(err: &SdkError) {
    *LAST_ERROR_CODE.lock() = err.code();
    *LAST_ERROR.lock() = Some(err.to_string());
}

/// Clear the stored error.
pub fn clear_error() {
    *LAST_ERROR.lock() = None;
    *LAST_ERROR_CODE.lock() = SUCCESS;
}

/// Take the last error message, leaving `None` behind.
pub fn take_last_error() -> Option<String> {
    LAST_ERROR.lock().take()
}

/// Return the last error code without clearing it.
pub fn last_error_code() -> i32 {
    *LAST_ERROR_CODE.lock()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_code_mapping_all_variants() {
        assert_eq!(SdkError::Auth("x".into()).code(), ERROR_AUTH);
        assert_eq!(SdkError::Network("x".into()).code(), ERROR_NETWORK);
        assert_eq!(SdkError::Config("x".into()).code(), ERROR_CONFIG);
        assert_eq!(SdkError::SplitTunnel("x".into()).code(), ERROR_SPLIT_TUNNEL);
        assert_eq!(SdkError::Vpn("x".into()).code(), ERROR_VPN);
        assert_eq!(
            SdkError::InvalidParam("x".into()).code(),
            ERROR_INVALID_PARAM
        );
        assert_eq!(SdkError::NotInitialized.code(), ERROR_NOT_INITIALIZED);
        assert_eq!(SdkError::AlreadyConnected.code(), ERROR_ALREADY_CONNECTED);
        assert_eq!(SdkError::NotConnected.code(), ERROR_NOT_CONNECTED);
        assert_eq!(SdkError::Internal("x".into()).code(), ERROR_INTERNAL);
        assert_eq!(SdkError::Storage("x".into()).code(), ERROR_INTERNAL);
    }

    #[test]
    fn set_error_take_last_error_roundtrip() {
        clear_error();
        set_error("test error message");
        let msg = take_last_error();
        assert_eq!(msg.as_deref(), Some("test error message"));
        let msg2 = take_last_error();
        assert_eq!(msg2, None);
    }

    #[test]
    fn set_sdk_error_stores_code_and_message() {
        clear_error();
        let err = SdkError::Vpn("relay failed".into());
        set_sdk_error(&err);
        assert_eq!(last_error_code(), ERROR_VPN);
        let msg = take_last_error().unwrap();
        assert!(msg.contains("relay failed"));
    }

    #[test]
    fn clear_error_resets_state() {
        set_error("leftover");
        *LAST_ERROR_CODE.lock() = -99;
        clear_error();
        assert_eq!(last_error_code(), SUCCESS);
        assert_eq!(take_last_error(), None);
    }

    #[test]
    fn last_error_code_defaults_to_success() {
        clear_error();
        assert_eq!(last_error_code(), SUCCESS);
    }

    #[test]
    fn display_trait_messages() {
        let err = SdkError::Auth("bad token".into());
        assert_eq!(err.to_string(), "Authentication error: bad token");
        let err = SdkError::NotInitialized;
        assert_eq!(err.to_string(), "Not initialized");
    }
}
