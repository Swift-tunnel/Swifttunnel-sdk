//! Authentication manager - handles login/logout and token management for the SDK

use super::client::{is_refresh_token_permanently_invalid, AuthClient};
use super::oauth_server::{OAuthCallbackData, OAuthServer, DEFAULT_OAUTH_PORT};
use super::storage::SecureStorage;
use super::types::{AuthSession, AuthState, OAuthPendingState, UserInfo};
use crate::error::SdkError;
use chrono::{Duration, Utc};
use log::{debug, error, info, warn};
use rand::Rng;
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

const OAUTH_LOGIN_URL: &str = "https://swifttunnel.net/login";
/// Maximum number of token refresh retries.
const MAX_REFRESH_RETRIES: u32 = 3;

/// Percent-encode a string for use in URL query parameters (RFC 3986 unreserved chars).
fn percent_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => result.push_str(&format!("%{:02X}", byte)),
        }
    }
    result
}

/// Authentication manager.
pub struct AuthManager {
    state: Arc<Mutex<AuthState>>,
    storage: SecureStorage,
    client: AuthClient,
    /// Active OAuth server (if awaiting callback).
    oauth_server: Arc<Mutex<Option<OAuthServer>>>,
}

impl AuthManager {
    /// Create a new AuthManager.
    pub fn new() -> Result<Self, SdkError> {
        info!("========================================");
        info!("Initializing AuthManager...");
        let storage = SecureStorage::new()?;
        let client = AuthClient::new();

        info!("Checking for stored session in Windows Credential Manager...");
        let initial_state = match storage.load_session() {
            Ok(Some(session)) => {
                info!("========================================");
                info!("FOUND STORED SESSION!");
                info!("  User email: {}", session.user.email);
                info!("  User ID: {}", session.user.id);
                info!("  Token length: {} chars", session.access_token.len());
                info!(
                    "  Refresh token length: {} chars",
                    session.refresh_token.len()
                );
                info!("  Expires at: {}", session.expires_at);
                info!("  Is expired: {}", session.is_expired());
                info!("  Expires soon: {}", session.expires_soon());
                info!("========================================");
                AuthState::LoggedIn(session)
            }
            Ok(None) => {
                info!("No stored session found in Windows Credential Manager.");
                info!("User needs to log in.");
                AuthState::LoggedOut
            }
            Err(e) => {
                error!("Failed to load stored session: {}. Starting fresh.", e);
                AuthState::LoggedOut
            }
        };

        Ok(Self {
            state: Arc::new(Mutex::new(initial_state)),
            storage,
            client,
            oauth_server: Arc::new(Mutex::new(None)),
        })
    }

    /// Get the current auth state.
    pub fn get_state(&self) -> AuthState {
        self.state.lock().unwrap().clone()
    }

    /// Check if user is logged in.
    pub fn is_logged_in(&self) -> bool {
        matches!(self.get_state(), AuthState::LoggedIn(_))
    }

    /// Get the current user info if logged in.
    pub fn get_user(&self) -> Option<UserInfo> {
        match self.get_state() {
            AuthState::LoggedIn(session) => Some(session.user),
            _ => None,
        }
    }

    /// Sign in with email and password.
    pub async fn sign_in(&self, email: &str, password: &str) -> Result<(), SdkError> {
        info!("Signing in user: {}", email);
        {
            let mut state = self.state.lock().unwrap();
            *state = AuthState::LoggingIn;
        }

        match self.client.sign_in_with_password(email, password).await {
            Ok(response) => {
                let mut user_info = UserInfo {
                    id: response.user.id,
                    email: response.user.email.unwrap_or_else(|| email.to_string()),
                    is_tester: false,
                };

                match self.client.fetch_user_profile(&response.access_token).await {
                    Ok(profile) => {
                        user_info.is_tester = profile.is_tester;
                        info!("User profile fetched: is_tester={}", profile.is_tester);
                    }
                    Err(e) => warn!("Failed to fetch user profile (non-fatal): {}", e),
                }

                let session = AuthSession {
                    access_token: response.access_token,
                    refresh_token: response.refresh_token,
                    expires_at: Utc::now() + Duration::seconds(response.expires_in),
                    user: user_info,
                };

                self.storage.store_session(&session)?;
                {
                    let mut state = self.state.lock().unwrap();
                    *state = AuthState::LoggedIn(session);
                }
                info!("Sign in successful!");
                Ok(())
            }
            Err(e) => {
                error!("Sign in failed: {}", e);
                let mut state = self.state.lock().unwrap();
                *state = AuthState::Error(e.to_string());
                Err(e)
            }
        }
    }

    /// Refresh the access token if needed.
    pub async fn refresh_if_needed(&self) -> Result<(), SdkError> {
        let session = match self.get_state() {
            AuthState::LoggedIn(session) => session,
            _ => return Err(SdkError::Auth("Not authenticated".to_string())),
        };

        if !(session.is_expired() || session.expires_soon()) {
            debug!("Token still valid, no refresh needed");
            return Ok(());
        }

        for attempt in 1..=MAX_REFRESH_RETRIES {
            match self.try_refresh_token(&session).await {
                Ok(new_session) => {
                    if let Err(e) = self.storage.store_session(&new_session) {
                        warn!("Failed to store refreshed session: {}", e);
                    }
                    self.storage.reset_refresh_failures();
                    {
                        let mut state = self.state.lock().unwrap();
                        *state = AuthState::LoggedIn(new_session);
                    }
                    info!("Token refreshed successfully on attempt {}", attempt);
                    return Ok(());
                }
                Err(e) => {
                    let body = e.to_string();
                    if is_refresh_token_permanently_invalid(&body)
                        || body.contains("Session expired, please sign in again")
                    {
                        warn!("Refresh token is permanently invalid - forcing re-login");
                        self.storage.reset_refresh_failures();
                        let _ = self.force_logout();
                        return Err(SdkError::Auth(
                            "Session expired, please sign in again".to_string(),
                        ));
                    }

                    warn!("Token refresh attempt {} failed: {}", attempt, e);
                    if attempt < MAX_REFRESH_RETRIES {
                        let delay = StdDuration::from_secs(1 << (attempt - 1));
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        let failure_count = self.storage.increment_refresh_failures();
        warn!(
            "Token refresh failed after {} attempts (total failures: {})",
            MAX_REFRESH_RETRIES, failure_count
        );

        if failure_count >= 5 || session.is_expired() {
            warn!("Refresh failures exceeded safe threshold - forcing re-login");
            let _ = self.force_logout();
            return Err(SdkError::Auth(
                "Session expired, please sign in again".to_string(),
            ));
        }

        info!("Refresh failed but token not yet expired - continuing with existing session");
        Ok(())
    }

    async fn try_refresh_token(&self, session: &AuthSession) -> Result<AuthSession, SdkError> {
        let refresh_response = self.client.refresh_token(&session.refresh_token).await?;

        let is_tester = match self
            .client
            .fetch_user_profile(&refresh_response.access_token)
            .await
        {
            Ok(profile) => profile.is_tester,
            Err(e) => {
                debug!(
                    "Failed to fetch profile on refresh (keeping old value): {}",
                    e
                );
                session.user.is_tester
            }
        };

        Ok(AuthSession {
            access_token: refresh_response.access_token,
            refresh_token: refresh_response.refresh_token,
            expires_at: Utc::now() + Duration::seconds(refresh_response.expires_in),
            user: UserInfo {
                id: refresh_response.user.id,
                email: refresh_response
                    .user
                    .email
                    .unwrap_or_else(|| session.user.email.clone()),
                is_tester,
            },
        })
    }

    /// Re-fetch user profile and update stored tester status.
    pub async fn refresh_profile(&self) -> Result<(), SdkError> {
        let session = match self.get_state() {
            AuthState::LoggedIn(session) => session,
            _ => return Ok(()),
        };

        let profile = self
            .client
            .fetch_user_profile(&session.access_token)
            .await?;
        if profile.is_tester != session.user.is_tester {
            let updated_session = AuthSession {
                user: UserInfo {
                    is_tester: profile.is_tester,
                    ..session.user
                },
                ..session
            };

            let _ = self.storage.store_session(&updated_session);
            let mut state = self.state.lock().unwrap();
            *state = AuthState::LoggedIn(updated_session);
        }

        Ok(())
    }

    /// Get a valid access token, refreshing if needed.
    pub async fn get_access_token(&self) -> Result<String, SdkError> {
        self.refresh_if_needed().await?;
        match self.get_state() {
            AuthState::LoggedIn(session) => Ok(session.access_token),
            _ => Err(SdkError::Auth("Not authenticated".to_string())),
        }
    }

    /// Log out and clear stored credentials.
    pub fn logout(&self) -> Result<(), SdkError> {
        info!("Logging out");
        self.storage.clear_session()?;
        let mut state = self.state.lock().unwrap();
        *state = AuthState::LoggedOut;
        Ok(())
    }

    fn force_logout(&self) -> Result<(), SdkError> {
        info!("Force logout: clearing invalid session");
        if let Err(e) = self.storage.clear_session() {
            warn!("Failed to clear session during force logout: {}", e);
        }
        let mut state = self.state.lock().unwrap();
        *state = AuthState::LoggedOut;
        Ok(())
    }

    /// Cancel login attempt.
    pub fn cancel_login(&self) {
        info!("Cancelling login");
        let mut state = self.state.lock().unwrap();
        *state = AuthState::LoggedOut;
    }

    /// Clear error state.
    pub fn clear_error(&self) {
        let mut state = self.state.lock().unwrap();
        if matches!(*state, AuthState::Error(_)) {
            *state = AuthState::LoggedOut;
        }
    }

    /// Start Google OAuth sign-in flow using localhost callback server.
    ///
    /// Returns `(oauth_url, state)` so SDK hosts can launch the URL themselves.
    pub fn start_google_sign_in(&self) -> Result<(String, String), SdkError> {
        info!("Starting Google OAuth sign-in flow with localhost server");

        {
            let mut server_guard = self.oauth_server.lock().unwrap();
            if let Some(mut server) = server_guard.take() {
                info!("Stopping previous OAuth server");
                server.stop();
            }
        }

        let oauth_server = OAuthServer::start()
            .map_err(|e| SdkError::Auth(format!("Failed to start OAuth server: {}", e)))?;
        let port = oauth_server.port();
        let state: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let oauth_url = format!(
            "{}?desktop=true&state={}&provider=google&redirect_port={}",
            OAUTH_LOGIN_URL,
            percent_encode(&state),
            if port == 0 { DEFAULT_OAUTH_PORT } else { port }
        );

        {
            let mut server_guard = self.oauth_server.lock().unwrap();
            *server_guard = Some(oauth_server);
        }

        let pending = OAuthPendingState {
            state: state.clone(),
            started_at: Utc::now(),
        };
        let mut auth_state = self.state.lock().unwrap();
        *auth_state = AuthState::AwaitingOAuthCallback(pending);

        Ok((oauth_url, state))
    }

    /// Poll for OAuth callback (non-blocking).
    pub fn poll_oauth_callback(&self) -> Option<OAuthCallbackData> {
        let server_guard = self.oauth_server.lock().unwrap();
        server_guard.as_ref().and_then(|s| s.try_recv_callback())
    }

    /// Get the OAuth server port (if active).
    pub fn get_oauth_port(&self) -> Option<u16> {
        let server_guard = self.oauth_server.lock().unwrap();
        server_guard.as_ref().map(|s| s.port())
    }

    /// Complete OAuth callback: exchange token and verify magic link.
    pub async fn complete_oauth_callback(
        &self,
        exchange_token: &str,
        callback_state: &str,
    ) -> Result<(), SdkError> {
        let expected_state = {
            let state = self.state.lock().unwrap();
            match &*state {
                AuthState::AwaitingOAuthCallback(pending) => {
                    if Utc::now() - pending.started_at > Duration::minutes(10) {
                        return Err(SdkError::Auth(
                            "OAuth flow expired. Please try again.".to_string(),
                        ));
                    }
                    Some(pending.state.clone())
                }
                _ => None,
            }
        };

        let expected_state = match expected_state {
            Some(s) => s,
            None => {
                return Err(SdkError::Auth(
                    "Not waiting for OAuth callback. Please start sign-in again.".to_string(),
                ));
            }
        };

        if callback_state != expected_state {
            {
                let mut state = self.state.lock().unwrap();
                *state = AuthState::Error(
                    "Security error: state mismatch. Please try again.".to_string(),
                );
            }
            self.stop_oauth_server();
            return Err(SdkError::Auth("Security error: state mismatch".to_string()));
        }

        self.stop_oauth_server();
        {
            let mut state = self.state.lock().unwrap();
            *state = AuthState::LoggingIn;
        }

        let exchange_response = match self
            .client
            .exchange_oauth_token(exchange_token, callback_state)
            .await
        {
            Ok(response) => response,
            Err(e) => {
                let mut state = self.state.lock().unwrap();
                *state = AuthState::Error(e.to_string());
                return Err(e);
            }
        };

        let auth_response = match self
            .client
            .verify_magic_link(&exchange_response.email, &exchange_response.token)
            .await
        {
            Ok(response) => response,
            Err(e) => {
                let mut state = self.state.lock().unwrap();
                *state = AuthState::Error(e.to_string());
                return Err(e);
            }
        };

        let is_tester = match self
            .client
            .fetch_user_profile(&auth_response.access_token)
            .await
        {
            Ok(profile) => profile.is_tester,
            Err(e) => {
                warn!(
                    "Failed to fetch user profile after OAuth (non-fatal): {}",
                    e
                );
                false
            }
        };

        let session = AuthSession {
            access_token: auth_response.access_token,
            refresh_token: auth_response.refresh_token,
            expires_at: Utc::now() + Duration::seconds(auth_response.expires_in),
            user: UserInfo {
                id: auth_response.user.id,
                email: auth_response.user.email.unwrap_or(exchange_response.email),
                is_tester,
            },
        };

        self.storage.store_session(&session)?;
        let mut state = self.state.lock().unwrap();
        *state = AuthState::LoggedIn(session);
        Ok(())
    }

    /// Cancel OAuth flow and return to logged out state.
    pub fn cancel_oauth(&self) {
        info!("Cancelling OAuth flow");
        self.stop_oauth_server();
        let mut state = self.state.lock().unwrap();
        if matches!(*state, AuthState::AwaitingOAuthCallback(_)) {
            *state = AuthState::LoggedOut;
        }
    }

    /// Stop the OAuth server if it's running.
    fn stop_oauth_server(&self) {
        let mut server_guard = self.oauth_server.lock().unwrap();
        if let Some(mut server) = server_guard.take() {
            info!("Stopping OAuth server");
            server.stop();
        }
    }

    /// Check if currently awaiting OAuth callback.
    pub fn is_awaiting_oauth(&self) -> bool {
        matches!(self.get_state(), AuthState::AwaitingOAuthCallback(_))
    }

    /// Get pending OAuth state if awaiting callback.
    pub fn get_pending_oauth_state(&self) -> Option<String> {
        match self.get_state() {
            AuthState::AwaitingOAuthCallback(pending) => Some(pending.state),
            _ => None,
        }
    }

    /// Access the underlying auth HTTP client.
    pub fn client(&self) -> &AuthClient {
        &self.client
    }
}

impl Default for AuthManager {
    fn default() -> Self {
        Self::new().expect("Failed to create AuthManager")
    }
}
