//! Nextcloud authentication provider.
//!
//! Integrates with Nextcloud's OAuth2/OIDC endpoints for SSO.
//! Users authenticate against their Nextcloud instance and get
//! a better-auth session linked to their Nextcloud account.
//!
//! ## Nextcloud OAuth2 Endpoints
//!
//! - Authorize: `{nextcloud_url}/index.php/apps/oauth2/authorize`
//! - Token: `{nextcloud_url}/index.php/apps/oauth2/api/v1/token`
//! - User Info: `{nextcloud_url}/ocs/v2.php/cloud/user?format=json`
//!
//! ## Setup
//!
//! 1. In Nextcloud, go to Settings → Security → OAuth 2.0 clients
//! 2. Add a new client with your redirect URL
//! 3. Use the client ID and secret in your config
//!
//! ## Authelia Integration
//!
//! If Authelia sits in front of Nextcloud as an OIDC proxy:
//! - Use Authelia's OIDC endpoints instead
//! - Authorize: `{authelia_url}/api/oidc/authorization`
//! - Token: `{authelia_url}/api/oidc/token`
//! - User Info: `{authelia_url}/api/oidc/userinfo`

use serde::{Deserialize, Serialize};

/// Configuration for Nextcloud OAuth provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextcloudProviderConfig {
    /// Nextcloud instance URL (e.g. "https://cloud.example.com").
    pub nextcloud_url: String,
    /// OAuth2 client ID (from Nextcloud settings).
    pub client_id: String,
    /// OAuth2 client secret.
    pub client_secret: String,
    /// Redirect URI (your app's callback URL).
    pub redirect_uri: String,
    /// Scopes to request (default: empty for basic profile).
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// Create a Nextcloud OAuth provider for use with the OAuth plugin.
///
/// Returns an `OAuthProvider` compatible with better-auth's OAuth system.
///
/// ```rust,ignore
/// use better_auth_api::plugins::oauth::OAuthProvider;
/// use better_auth_api::plugins::nextcloud::nextcloud_provider;
///
/// let provider = nextcloud_provider(NextcloudProviderConfig {
///     nextcloud_url: "https://cloud.example.com".into(),
///     client_id: "your-client-id".into(),
///     client_secret: "your-secret".into(),
///     redirect_uri: "https://app.example.com/auth/callback/nextcloud".into(),
///     scopes: vec![],
/// });
/// ```
pub fn nextcloud_provider(config: NextcloudProviderConfig) -> super::oauth::OAuthProvider {
    super::oauth::OAuthProvider {
        client_id: config.client_id,
        client_secret: config.client_secret,
        auth_url: format!(
            "{}/index.php/apps/oauth2/authorize",
            config.nextcloud_url.trim_end_matches('/')
        ),
        token_url: format!(
            "{}/index.php/apps/oauth2/api/v1/token",
            config.nextcloud_url.trim_end_matches('/')
        ),
        user_info_url: format!(
            "{}/ocs/v2.php/cloud/user?format=json",
            config.nextcloud_url.trim_end_matches('/')
        ),
        scopes: config.scopes,
        map_user_info: map_nextcloud_user,
    }
}

/// Configuration for Authelia OIDC provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutheliaProviderConfig {
    /// Authelia instance URL (e.g. "https://auth.example.com").
    pub authelia_url: String,
    /// OIDC client ID.
    pub client_id: String,
    /// OIDC client secret.
    pub client_secret: String,
    /// Redirect URI.
    pub redirect_uri: String,
    /// Scopes (default: ["openid", "profile", "email"]).
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
}

fn default_oidc_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
    ]
}

/// Create an Authelia OIDC provider.
pub fn authelia_provider(config: AutheliaProviderConfig) -> super::oauth::OAuthProvider {
    let base = config.authelia_url.trim_end_matches('/');
    super::oauth::OAuthProvider {
        client_id: config.client_id,
        client_secret: config.client_secret,
        auth_url: format!("{base}/api/oidc/authorization"),
        token_url: format!("{base}/api/oidc/token"),
        user_info_url: format!("{base}/api/oidc/userinfo"),
        scopes: config.scopes,
        map_user_info: map_oidc_user,
    }
}

/// Map Nextcloud OCS user info response to OAuthUserInfo.
///
/// Nextcloud returns:
/// ```json
/// { "ocs": { "data": { "id": "user1", "email": "...", "displayname": "..." } } }
/// ```
fn map_nextcloud_user(
    value: serde_json::Value,
) -> Result<super::oauth::OAuthUserInfo, String> {
    let data = value
        .get("ocs")
        .and_then(|o| o.get("data"))
        .ok_or_else(|| "Missing ocs.data in Nextcloud response".to_string())?;

    Ok(super::oauth::OAuthUserInfo {
        id: data
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        email: data
            .get("email")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        name: data
            .get("displayname")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        image: None, // Nextcloud avatar is at /avatar/{userId}/64
        email_verified: true, // Nextcloud users are always verified
    })
}

/// Map standard OIDC userinfo response to OAuthUserInfo.
///
/// Works with Authelia, Keycloak, Auth0, etc.
fn map_oidc_user(
    value: serde_json::Value,
) -> Result<super::oauth::OAuthUserInfo, String> {
    Ok(super::oauth::OAuthUserInfo {
        id: value
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        email: value
            .get("email")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        name: value
            .get("name")
            .or_else(|| value.get("preferred_username"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        image: value
            .get("picture")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        email_verified: value
            .get("email_verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    })
}
