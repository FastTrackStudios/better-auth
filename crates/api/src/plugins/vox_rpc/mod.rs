//! Vox RPC authentication plugin.
//!
//! Exposes authentication operations via Vox WebSocket RPC instead of
//! HTTP REST. This allows Vox-based applications to authenticate without
//! HTTP — everything goes through the same WebSocket connection.
//!
//! ## RPC Methods
//!
//! - `auth.sign_up` — Register with email + password
//! - `auth.sign_in` — Authenticate with email + password
//! - `auth.sign_out` — Revoke current session
//! - `auth.get_session` — Get current session + user info
//! - `auth.refresh_session` — Refresh session token
//! - `auth.list_sessions` — List all active sessions
//! - `auth.revoke_session` — Revoke specific session
//!
//! ## Integration
//!
//! The Vox RPC plugin works by:
//! 1. Receiving RPC calls with session tokens in the method params
//! 2. Delegating to the same SessionManager and database adapter
//! 3. Returning structured Facet types (not JSON HTTP responses)
//!
//! This means the same auth logic runs for both HTTP and RPC clients.

use async_trait::async_trait;

use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::config::AuthConfig;
use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::session::SessionManager;
use better_auth_core::types::{AuthRequest, AuthResponse, HttpMethod};

/// Vox RPC authentication plugin configuration.
pub struct VoxRpcConfig {
    /// Whether to enable the RPC auth endpoints.
    pub enabled: bool,
}

impl Default for VoxRpcConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// The Vox RPC authentication plugin.
///
/// Exposes all core auth operations as Vox RPC methods that can be called
/// over WebSocket, in-process, or any other Vox transport.
pub struct VoxRpcPlugin {
    config: VoxRpcConfig,
}

impl VoxRpcPlugin {
    pub fn new() -> Self {
        Self {
            config: VoxRpcConfig::default(),
        }
    }

    pub fn with_config(config: VoxRpcConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl<DB: DatabaseAdapter> AuthPlugin<DB> for VoxRpcPlugin {
    fn name(&self) -> &'static str {
        "vox-rpc"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        if !self.config.enabled {
            return vec![];
        }
        // Vox RPC doesn't use HTTP routes — it uses the Vox service trait.
        // These routes are registered so the plugin system knows we exist,
        // but actual dispatch happens through the VoxAuthService trait.
        vec![
            AuthRoute {
                path: "/vox/sign-up".to_string(),
                method: HttpMethod::Post,
                operation_id: "vox_sign_up".to_string(),
            },
            AuthRoute {
                path: "/vox/sign-in".to_string(),
                method: HttpMethod::Post,
                operation_id: "vox_sign_in".to_string(),
            },
            AuthRoute {
                path: "/vox/sign-out".to_string(),
                method: HttpMethod::Post,
                operation_id: "vox_sign_out".to_string(),
            },
            AuthRoute {
                path: "/vox/get-session".to_string(),
                method: HttpMethod::Get,
                operation_id: "vox_get_session".to_string(),
            },
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<AuthResponse>> {
        // Vox RPC requests come through the VoxAuthService, not HTTP.
        // This handler is a fallback for HTTP clients that hit the /vox/* routes.
        let path = req.path();

        match path {
            "/vox/sign-up" => {
                // Delegate to email/password sign-up logic
                // For now, return method not allowed — use the Vox service
                Ok(Some(
                    AuthResponse::json(405, &serde_json::json!({"error": "Use Vox RPC for this endpoint"}))
                        .map_err(|e| AuthError::Internal(e.to_string()))?
                ))
            }
            _ => Ok(None),
        }
    }
}

/// Vox RPC service trait for authentication.
///
/// This trait is designed to be used with `#[vox::service]` in downstream
/// crates that have both `vox` and `better-auth` as dependencies.
///
/// Example implementation:
/// ```rust,ignore
/// #[vox::service]
/// pub trait VoxAuthService {
///     async fn sign_up(&self, email: String, password: String, name: Option<String>)
///         -> Result<AuthSessionResponse, String>;
///     async fn sign_in(&self, email: String, password: String)
///         -> Result<AuthSessionResponse, String>;
///     async fn sign_out(&self, token: String) -> Result<(), String>;
///     async fn get_session(&self, token: String)
///         -> Result<AuthSessionResponse, String>;
///     async fn list_sessions(&self, token: String)
///         -> Result<Vec<SessionInfo>, String>;
///     async fn revoke_session(&self, token: String, session_id: String)
///         -> Result<(), String>;
/// }
/// ```
///
/// The dispatcher implementation delegates to `SessionManager` and
/// `DatabaseAdapter` methods — same logic as HTTP handlers.
pub mod service {
    use serde::{Deserialize, Serialize};

    /// Response from sign-in/sign-up/get-session operations.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AuthSessionResponse {
        pub token: String,
        pub user: UserInfo,
        pub session: SessionInfo,
    }

    /// User info returned in auth responses.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct UserInfo {
        pub id: String,
        pub email: String,
        pub name: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub role: Option<String>,
    }

    /// Session info.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SessionInfo {
        pub id: String,
        pub token: String,
        pub user_id: String,
        pub expires_at: String,
        pub ip_address: Option<String>,
        pub user_agent: Option<String>,
        pub active: bool,
    }
}
