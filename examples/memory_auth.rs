//! Example of using rocket-easy-auth with an in-memory provider
//! 
//! This is the simplest possible implementation, suitable for testing.

use rocket::{get, launch, routes};
use rocket_roles::{
    auth::{AuthProvider, AuthError, User, register_auth_provider},
    define_roles, require_role, require_permission
};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use async_trait::async_trait;

// Define roles and their permissions
define_roles! {
    "admin" => ["manage_system", "view_users"],
    "user" => ["view_profile", "edit_profile"]
}

// In-memory auth provider with hardcoded users and tokens
struct MemoryAuthProvider {
    users: RwLock<HashMap<String, User>>,
}

impl MemoryAuthProvider {
    fn new() -> Self {
        let mut users = HashMap::new();
        
        // Add some example users
        users.insert("admin_token".to_string(), 
            User::new("1", "admin")
                .with_role("admin"));
        
        users.insert("user_token".to_string(),
            User::new("2", "regular_user")
                .with_role("user"));
        
        users.insert("special_token".to_string(),
            User::new("3", "special_user")
                .with_role("user")
                .with_permission("special_access"));
        
        Self {
            users: RwLock::new(users)
        }
    }
}

#[async_trait]
impl AuthProvider for MemoryAuthProvider {
    async fn authenticate_token(&self, token: &str) -> Result<User, AuthError> {
        let users = self.users.read().unwrap();
        
        match users.get(token) {
            Some(user) => Ok(user.clone()),
            None => Err(AuthError::InvalidToken("Invalid token".into())),
        }
    }
}

// Routes protected by roles
#[require_role("admin")]
#[get("/admin")]
fn admin_only() -> rocket::Either<&'static str, rocket::Response<'static>> {
    rocket::Either::Left("Welcome, admin!")
}

// Routes protected by permissions
#[require_permission("edit_profile")]
#[get("/profile/edit")]
fn edit_profile() -> rocket::Either<&'static str, rocket::Response<'static>> {
    rocket::Either::Left("Edit your profile here")
}

#[require_permission("special_access")]
#[get("/special")]
fn special_access() -> rocket::Either<&'static str, rocket::Response<'static>> {
    rocket::Either::Left("This is a special area!")
}

// Public route
#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[launch]
fn rocket() -> _ {
    // Create and register auth provider
    let auth_provider = MemoryAuthProvider::new();
    register_auth_provider(auth_provider);
    
    // Initialize roles
    initialize_roles();
    
    rocket::build().mount("/", routes![
        admin_only,
        edit_profile,
        special_access,
        index,
    ])
}
