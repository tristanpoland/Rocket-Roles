//! Example of using rocket-easy-auth with Redis
//! 
//! This is a simplified example that uses Redis for token storage.

use rocket::{get, launch, routes};
use rocket_roles::{
    auth::{AuthProvider, AuthError, User, register_auth_provider},
    define_roles, require_role, require_permission
};
use std::collections::HashSet;
use async_trait::async_trait;

// Define roles and their permissions
define_roles! {
    "admin" => ["manage_users", "view_stats", "configure_system"],
    "customer" => ["view_orders", "place_order"],
    "support" => ["view_tickets", "respond_to_tickets"]
}

// Simplified Redis auth provider
// In a real implementation, you would use a Redis client
struct RedisAuthProvider;

impl RedisAuthProvider {
    fn new() -> Self {
        // In a real implementation, you would initialize Redis connection here
        Self
    }
    
    // In a real implementation, this would query Redis
    async fn get_user_from_token(&self, token: &str) -> Option<User> {
        // Simplified mock implementation
        match token {
            "admin_token" => Some(User::new("1", "admin")
                .with_role("admin")),
            "customer_token" => Some(User::new("2", "customer")
                .with_role("customer")),
            "support_token" => Some(User::new("3", "support")
                .with_role("support")
                .with_permission("view_orders")), // Direct permission
            _ => None,
        }
    }
}

#[async_trait]
impl AuthProvider for RedisAuthProvider {
    async fn authenticate_token(&self, token: &str) -> Result<User, AuthError> {
        match self.get_user_from_token(token).await {
            Some(user) => Ok(user),
            None => Err(AuthError::InvalidToken("Token not found".into())),
        }
    }
}

// Routes protected by roles
#[require_role("admin")]
#[get("/admin/dashboard")]
fn admin_dashboard() -> rocket::response::Response<'static> {
    rocket::response::Response::build()
        .sized_body(std::io::Cursor::new("Welcome to the admin dashboard!"))
        .finalize()
// Routes protected by permissions
#[require_permission("view_orders")]
#[get("/orders")]
fn view_orders() -> rocket::response::Response<'static> {
    rocket::response::Response::build()
        .sized_body(std::io::Cursor::new("Here are your orders"))
        .finalize()
}
    "Here are your orders"
}

// Public route
#[get("/")]
fn index() -> &'static str {
    "Welcome to our store!"
}

#[launch]
fn rocket() -> _ {
    // Create and register auth provider
    let auth_provider = RedisAuthProvider::new();
    register_auth_provider(auth_provider);
    
    // Initialize roles
    initialize_roles();
    
    rocket::build().mount("/", routes![
        admin_dashboard,
        view_orders,
        index,
    ])
}
