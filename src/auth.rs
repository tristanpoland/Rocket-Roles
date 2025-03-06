//! Authentication and authorization core types and traits

use async_trait::async_trait;
use once_cell::sync::OnceCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Error type for authentication operations
#[derive(Debug)]
pub enum AuthError {
    /// The authentication token is invalid
    InvalidToken(String),
    /// Database connection error
    DatabaseError(String),
    /// User not found
    UserNotFound,
    /// Generic error
    Other(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::InvalidToken(msg) => write!(f, "Invalid token: {}", msg),
            AuthError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            AuthError::UserNotFound => write!(f, "User not found"),
            AuthError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for AuthError {}

/// A permission is a string identifier that represents a single capability
pub type Permission = String;

/// A role is a collection of permissions
#[derive(Debug, Clone)]
pub struct Role {
    /// The name of the role
    pub name: String,
    /// The permissions granted by this role
    pub permissions: HashSet<Permission>,
}

/// User struct containing authentication and authorization information
#[derive(Debug, Clone)]
pub struct User {
    /// The unique identifier for the user
    pub id: String,
    /// The username or display name
    pub username: String,
    /// The roles assigned to this user
    pub roles: Vec<String>,
    /// Direct permissions assigned to this user (in addition to roles)
    pub permissions: HashSet<Permission>,
}

impl User {
    /// Create a new user with the given ID and username
    pub fn new(id: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            username: username.into(),
            roles: Vec::new(),
            permissions: HashSet::new(),
        }
    }

    /// Add a role to the user
    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.roles.push(role.into());
        self
    }

    /// Add multiple roles to the user
    pub fn with_roles(mut self, roles: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.roles.extend(roles.into_iter().map(Into::into));
        self
    }

    /// Add a permission to the user
    pub fn with_permission(mut self, permission: impl Into<String>) -> Self {
        self.permissions.insert(permission.into());
        self
    }

    /// Add multiple permissions to the user
    pub fn with_permissions(mut self, permissions: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.permissions.extend(permissions.into_iter().map(Into::into));
        self
    }

    /// Check if the user has a specific role
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Check if the user has a specific permission
    pub fn has_permission(&self, permission: &str) -> bool {
        // First check direct permissions
        if self.permissions.contains(permission) {
            return true;
        }

        // Then check permissions granted by roles
        let roles = ROLES.get().expect("Roles not initialized");
        for role_name in &self.roles {
            if let Some(role) = roles.get(role_name) {
                if role.permissions.contains(permission) {
                    return true;
                }
            }
        }

        false
    }
    
    /// Get all permissions this user has (direct + from roles)
    pub fn all_permissions(&self) -> HashSet<String> {
        let mut all_perms = self.permissions.clone();
        
        // Add permissions from roles
        if let Some(roles) = ROLES.get() {
            for role_name in &self.roles {
                if let Some(role) = roles.get(role_name) {
                    all_perms.extend(role.permissions.clone());
                }
            }
        }
        
        all_perms
    }
}

/// The `AuthProvider` trait must be implemented by any authentication provider
/// to be used with rocket-easy-auth.
#[async_trait]
pub trait AuthProvider: Send + Sync + 'static {
    /// Validates a token and returns the user if valid
    /// 
    /// # Arguments
    /// 
    /// * `token` - The authentication token to validate
    /// 
    /// # Returns
    /// 
    /// * `Result<User, AuthError>` - The authenticated user or an error
    async fn authenticate_token(&self, token: &str) -> Result<User, AuthError>;
}

/// Rocket request guard for authenticated users
#[rocket::async_trait]
impl<'r> rocket::request::FromRequest<'r> for User {
    type Error = String;

    async fn from_request(request: &'r rocket::request::Request<'_>) -> rocket::request::Outcome<Self, Self::Error> {
        use rocket::http::Status;
        use rocket::request::Outcome;

        // Get the auth header
        let auth_header = match request.headers().get_one("Authorization") {
            Some(header) => header,
            None => {
                return Outcome::Error((
                    Status::Unauthorized,
                    "Authorization header is required".to_string(),
                ));
            }
        };

        // Parse the token (assuming Bearer token)
        let token = if auth_header.starts_with("Bearer ") {
            &auth_header[7..]
        } else {
            return Outcome::Error((
                Status::Unauthorized,
                "Invalid authorization format".to_string(),
            ));
        };

        // Get the configured auth provider and validate token
        let provider = match AUTH_PROVIDER.get() {
            Some(provider) => provider,
            None => {
                return Outcome::Error((
                    Status::InternalServerError,
                    "Auth provider not registered".to_string(),
                ));
            }
        };

        match provider.authenticate_token(token).await {
            Ok(user) => Outcome::Success(user),
            Err(e) => Outcome::Error((
                Status::Unauthorized,
                format!("Authentication failed: {}", e),
            )),
        }
    }
}

// Global instance of the auth provider
static AUTH_PROVIDER: OnceCell<Arc<dyn AuthProvider>> = OnceCell::new();

// Global mapping of role names to their permissions
static ROLES: OnceCell<HashMap<String, Role>> = OnceCell::new();

/// Register an authentication provider for the application
/// 
/// # Arguments
/// 
/// * `provider` - The authentication provider to use
pub fn register_auth_provider(provider: impl AuthProvider) {
    let _ = AUTH_PROVIDER.set(Arc::new(provider));
}

/// Register roles and their permissions
/// 
/// # Arguments
/// 
/// * `roles` - A map of role names to their permissions
pub fn register_roles(roles: HashMap<String, Role>) {
    let _ = ROLES.set(roles);
}

/// Get the current auth provider
/// 
/// # Panics
/// 
/// Panics if no auth provider has been registered
pub(crate) fn get_auth_provider() -> &'static Arc<dyn AuthProvider> {
    AUTH_PROVIDER.get().expect("Auth provider not registered")
}

/// Get the registered roles
/// 
/// # Panics
/// 
/// Panics if roles have not been registered
pub(crate) fn get_roles() -> &'static HashMap<String, Role> {
    ROLES.get().expect("Roles not registered")
}