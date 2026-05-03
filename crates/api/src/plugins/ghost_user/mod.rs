//! Ghost User plugin — placeholder accounts that can be claimed.
//!
//! Allows team admins to create "ghost" team members who don't have
//! accounts yet. Ghosts can be:
//! - Assigned to tasks
//! - @mentioned in comments
//! - Listed in team rosters and personnel
//! - Attributed as comment authors (shown as "Name (unclaimed)")
//!
//! ## Lifecycle
//!
//! 1. Admin creates ghost: `POST /ghost-user/create`
//!    → Ghost user with username, name, role
//!
//! 2. Admin invites ghost: `POST /ghost-user/invite`
//!    → Email sent with claim link containing a token
//!
//! 3. Person claims ghost: `POST /ghost-user/claim`
//!    → If they have an account: ghost merges into their account
//!    → If they don't: sign-up flow, then auto-claim
//!
//! 4. All historical references (tasks, comments, mentions) now
//!    point to the real account. The ghost username becomes an alias.
//!
//! ## Multi-org support
//!
//! Ghost users are scoped to an organization. The same person can be
//! a ghost in one org and a real user in another (until they claim).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::types::{AuthRequest, AuthResponse, HttpMethod};

/// Ghost user status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GhostStatus {
    /// Placeholder — no auth account.
    Placeholder,
    /// Invitation sent — awaiting claim.
    Invited,
    /// Claimed — merged into a real account.
    Claimed,
}

/// A ghost user record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostUser {
    pub id: String,
    pub username: String,
    pub name: String,
    pub role: Option<String>,
    pub email: Option<String>,
    pub organization_id: Option<String>,
    pub status: GhostStatus,
    /// Auth user ID — set when claimed.
    pub claimed_by: Option<String>,
    /// Invite token.
    pub invite_token: Option<String>,
    /// Who created this ghost.
    pub created_by: String,
}

pub struct GhostUserPlugin;

impl GhostUserPlugin {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl<DB: DatabaseAdapter> AuthPlugin<DB> for GhostUserPlugin {
    fn name(&self) -> &'static str {
        "ghost-user"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute {
                path: "/ghost-user/create".to_string(),
                method: HttpMethod::Post,
                operation_id: "ghost_user_create".to_string(),
            },
            AuthRoute {
                path: "/ghost-user/invite".to_string(),
                method: HttpMethod::Post,
                operation_id: "ghost_user_invite".to_string(),
            },
            AuthRoute {
                path: "/ghost-user/claim".to_string(),
                method: HttpMethod::Post,
                operation_id: "ghost_user_claim".to_string(),
            },
            AuthRoute {
                path: "/ghost-user/list".to_string(),
                method: HttpMethod::Get,
                operation_id: "ghost_user_list".to_string(),
            },
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<AuthResponse>> {
        match req.path() {
            "/ghost-user/create" => {
                // TODO: Parse body, create ghost user in database
                Ok(Some(
                    AuthResponse::json(501, &serde_json::json!({"error": "Not yet implemented"}))
                        .map_err(|e| AuthError::Internal(e.to_string()))?,
                ))
            }
            "/ghost-user/claim" => {
                // TODO: Validate token, merge ghost into real account
                Ok(Some(
                    AuthResponse::json(501, &serde_json::json!({"error": "Not yet implemented"}))
                        .map_err(|e| AuthError::Internal(e.to_string()))?,
                ))
            }
            _ => Ok(None),
        }
    }
}
