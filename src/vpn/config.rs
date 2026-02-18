//! VPN Configuration fetching from API
//!
//! Handles fetching VPN configuration from the SwiftTunnel API.
//! V3 SDK only - no WireGuard key generation or parsing.

use crate::auth::types::VpnConfig;
use serde::{Deserialize, Serialize};

/// API base URL for SwiftTunnel
const API_BASE_URL: &str = "https://swifttunnel.net";

/// Shared HTTP client - reuses connection pool and TLS session cache
fn http_client() -> &'static reqwest::Client {
    use std::sync::OnceLock;
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| reqwest::Client::new())
}

/// Request body for generating VPN config
#[derive(Debug, Clone, Serialize)]
pub struct VpnConfigRequest {
    pub region: String,
}

/// API response wrapper
#[derive(Debug, Deserialize)]
struct ApiResponse<T> {
    #[serde(default)]
    success: bool,
    /// VPN config data (API returns this as "config")
    #[serde(default)]
    config: Option<T>,
    #[serde(default)]
    error: Option<String>,
}

/// Fetch VPN configuration from the API
///
/// # Arguments
/// * `access_token` - Bearer token for authentication
/// * `region` - Server region (e.g., "singapore", "mumbai")
///
/// # Returns
/// * `VpnConfig` containing all necessary connection parameters
pub async fn fetch_vpn_config(
    access_token: &str,
    region: &str,
) -> Result<VpnConfig, crate::error::SdkError> {
    let client = http_client();
    let url = format!("{}/api/vpn/generate-config", API_BASE_URL);

    let request = VpnConfigRequest {
        region: region.to_string(),
    };

    log::info!("Fetching VPN config for region: {}", region);

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", access_token))
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await
        .map_err(|e| crate::error::SdkError::Vpn(format!("Failed to fetch VPN config: {}", e)))?;

    let status = response.status();
    if !status.is_success() {
        let error_text = response.text().await.unwrap_or_default();
        log::error!("API error {}: {}", status, error_text);
        return Err(crate::error::SdkError::Vpn(format!(
            "HTTP {}: {}",
            status, error_text
        )));
    }

    let api_response: ApiResponse<VpnConfig> = response
        .json()
        .await
        .map_err(|e| crate::error::SdkError::Vpn(format!("Failed to parse response: {}", e)))?;

    match api_response.config {
        Some(config) => {
            log::info!("Successfully fetched VPN config for {}", region);
            Ok(config)
        }
        None => {
            let error = api_response
                .error
                .unwrap_or_else(|| "Unknown error".to_string());
            Err(crate::error::SdkError::Vpn(error))
        }
    }
}

/// Update artificial latency setting for a VPN config
///
/// # Arguments
/// * `access_token` - Bearer token for authentication
/// * `config_id` - The VPN config UUID
/// * `latency_ms` - Latency to add (0-100ms)
///
/// # Returns
/// * `Ok(true)` if server applied the latency immediately
/// * `Ok(false)` if latency was saved but will apply on reconnect
pub async fn update_latency(
    access_token: &str,
    config_id: &str,
    latency_ms: u32,
) -> Result<bool, crate::error::SdkError> {
    let client = http_client();
    let url = format!("{}/api/vpn/latency", API_BASE_URL);

    log::info!(
        "Updating latency to {}ms for config {}",
        latency_ms,
        config_id
    );

    let response = client
        .patch(&url)
        .header("Authorization", format!("Bearer {}", access_token))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "configId": config_id,
            "latencyMs": latency_ms
        }))
        .send()
        .await
        .map_err(|e| crate::error::SdkError::Vpn(format!("Failed to update latency: {}", e)))?;

    let status = response.status();
    if !status.is_success() {
        let error_text = response.text().await.unwrap_or_default();
        log::error!("Latency update API error {}: {}", status, error_text);
        return Err(crate::error::SdkError::Vpn(format!(
            "HTTP {}: {}",
            status, error_text
        )));
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct LatencyResponse {
        #[serde(default)]
        server_applied: bool,
    }

    let resp: LatencyResponse = response.json().await.map_err(|e| {
        crate::error::SdkError::Vpn(format!("Failed to parse latency response: {}", e))
    })?;

    if resp.server_applied {
        log::info!("Latency {}ms applied to server immediately", latency_ms);
    } else {
        log::info!("Latency {}ms saved, will apply on reconnect", latency_ms);
    }

    Ok(resp.server_applied)
}
