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
//! - `auth.list_sessions` — List all active sessions
//! - `auth.revoke_session` — Revoke specific session
//! - `auth.list_orgs` — List organizations for the current user
//!
//! ## Vox Middleware
//!
//! When the `vox` feature is enabled, the plugin also provides
//! [`VoxAuthMiddleware`] — a Vox `ServerMiddleware` that validates auth
//! tokens from request metadata and injects `AuthenticatedUser` into the
//! per-request extensions bag.
//!
//! ```rust,ignore
//! let auth = Arc::new(/* BetterAuth */);
//! let middleware = VoxAuthMiddleware::new(auth.clone());
//! let dispatcher = MyServiceDispatcher::new(service)
//!     .with_middleware(middleware);
//! ```

use async_trait::async_trait;

use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::entity::AuthUser;
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::{AuthContext, AuthPlugin, AuthRoute};
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
        _ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<AuthResponse>> {
        let path = req.path();
        match path {
            "/vox/sign-up" | "/vox/sign-in" | "/vox/sign-out" | "/vox/get-session" => Ok(Some(
                AuthResponse::json(
                    405,
                    &serde_json::json!({"error": "Use Vox RPC for this endpoint"}),
                )
                .map_err(|e| AuthError::Internal(e.to_string()))?,
            )),
            _ => Ok(None),
        }
    }
}

// ── Vox Server Middleware ───────────────────────────────────────────────────

/// Authenticated user info injected into Vox request extensions.
///
/// Handlers can read this from `context.extensions().get_cloned::<AuthenticatedUser>()`
/// to get the current user. If absent, the request is unauthenticated.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub username: Option<String>,
    pub role: Option<String>,
    pub session_token: String,
    pub active_organization_id: Option<String>,
}

/// Vox server middleware for better-auth authentication.
///
/// Reads the `authorization` metadata key from incoming Vox requests,
/// validates the session token via better-auth's `SessionManager`, and
/// inserts an [`AuthenticatedUser`] into the request extensions.
///
/// # Usage
///
/// ```rust,ignore
/// use better_auth_api::plugins::vox_rpc::VoxAuthMiddleware;
///
/// let middleware = VoxAuthMiddleware::new(
///     auth.session_manager().clone(),
///     auth.database().clone(),
/// );
/// let dispatcher = MyServiceDispatcher::new(service)
///     .with_middleware(middleware);
/// ```
#[cfg(feature = "vox")]
pub struct VoxAuthMiddleware<DB: DatabaseAdapter> {
    session_manager: better_auth_core::session::SessionManager<DB>,
    database: std::sync::Arc<DB>,
}

#[cfg(feature = "vox")]
impl<DB: DatabaseAdapter> VoxAuthMiddleware<DB> {
    pub fn new(
        session_manager: better_auth_core::session::SessionManager<DB>,
        database: std::sync::Arc<DB>,
    ) -> Self {
        Self {
            session_manager,
            database,
        }
    }
}

#[cfg(feature = "vox")]
impl<DB: DatabaseAdapter> vox_types::ServerMiddleware for VoxAuthMiddleware<DB> {
    fn pre<'a>(
        &'a self,
        context: &'a vox_types::RequestContext<'a>,
    ) -> vox_types::BoxMiddlewareFuture<'a> {
        Box::pin(async move {
            // Look for an authorization token in request metadata.
            let token = context
                .metadata()
                .iter()
                .find(|entry| entry.key == "authorization")
                .and_then(|entry| {
                    if let vox_types::MetadataValue::String(value) = &entry.value {
                        let v = value.strip_prefix("Bearer ").unwrap_or(value);
                        Some(v.to_string())
                    } else {
                        None
                    }
                });

            let Some(token) = token else {
                return; // No token — unauthenticated request
            };

            // Validate session
            let session = match self.session_manager.get_session(&token).await {
                Ok(Some(session)) => session,
                _ => return, // Invalid/expired token
            };

            // Look up user
            use better_auth_core::adapters::UserOps as _;
            use better_auth_core::entity::AuthSession as _;
            let user_id = session.user_id().to_string();
            let user = match self.database.get_user_by_id(&user_id).await {
                Ok(Some(user)) => user,
                _ => return,
            };

            // Inject authenticated user into extensions
            let authenticated = AuthenticatedUser {
                user_id: AuthUser::id(&user).to_string(),
                email: AuthUser::email(&user).map(|s| s.to_string()),
                name: AuthUser::name(&user).map(|s| s.to_string()),
                username: AuthUser::username(&user).map(|s| s.to_string()),
                role: AuthUser::role(&user).map(|s| s.to_string()),
                session_token: token,
                active_organization_id: session.active_organization_id().map(|s| s.to_string()),
            };
            context.extensions().insert(authenticated);
        })
    }
}

// ── Vox RPC Response Types ──────────────────────────────────────────────────

/// Response from sign-in/sign-up/get-session operations.
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
