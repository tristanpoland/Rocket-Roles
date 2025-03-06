//! # Rocket-Easy-Auth
//!
//! A flexible authentication and authorization library for Rocket
//! that allows easy integration with any database backend.
//!
//! ## Features
//!
//! - **Database Agnostic**: Easily connect to any database by implementing a simple trait
//! - **Role-Based Access Control**: Define roles and their permissions with a simple macro
//! - **Permission-Based Guards**: Protect routes with role or permission requirements
//! - **Flexible**: Works with any token-based authentication system
//!
//! ## Quick Start
//!
//! ### 1. Define your roles and permissions
//!
//! ```rust
//! use rocket_roles::define_roles;
//!
//! define_roles! {
//!     "admin" => ["create_user", "delete_user", "view_admin_panel"],
//!     "user" => ["view_profile", "edit_profile"],
//!     "moderator" => ["delete_post", "edit_post", "pin_post"]
//! }
//! ```
//!
//! ### 2. Implement the AuthProvider trait
//!
//! ```rust
//! use rocket_roles::auth::{AuthProvider, AuthError, User};
//! use async_trait::async_trait;
//! use std::collections::HashSet;
//!
//! struct MyAuthProvider {
//!     // Your database connection or client here
//! }
//!
//! #[async_trait]
//! impl AuthProvider for MyAuthProvider {
//!     async fn authenticate_token(&self, token: &str) -> Result<User, AuthError> {
//!         // Validate token and fetch user information from your database
//!         // Return a User object with roles and permissions
//!         
//!         // Example implementation:
//!         if token == "invalid" {
//!             return Err(AuthError::InvalidToken("Token is invalid".into()));
//!         }
//!         
//!         Ok(User {
//!             id: "123".into(),
//!             username: "john_doe".into(),
//!             roles: vec!["user".into()],
//!             permissions: HashSet::from_iter(vec!["custom_permission".into()]),
//!         })
//!     }
//! }
//! ```
//!
//! ### 3. Register your auth provider
//!
//! ```rust
//! use rocket_roles::auth::register_auth_provider;
//!
//! #[launch]
//! fn rocket() -> _ {
//!     // Create your auth provider
//!     let auth_provider = MyAuthProvider::new();
//!     
//!     // Register it
//!     register_auth_provider(auth_provider);
//!     
//!     // Initialize roles
//!     initialize_roles();
//!     
//!     rocket::build().mount("/", routes![/* your routes */])
//! }
//! ```
//!
//! ### 4. Protect your routes
//!
//! ```rust
//! use rocket_roles::{require_role, require_permission};
//! use rocket::get;
//!
//! // Require a specific role
//! #[require_role("admin")]
//! #[get("/admin/dashboard")]
//! fn admin_dashboard() -> &'static str {
//!     "Welcome to the admin dashboard!"
//! }
//!
//! // Require a specific permission
//! #[require_permission("edit_profile")]
//! #[get("/profile/edit")]
//! fn edit_profile() -> &'static str {
//!     "Edit your profile here"
//! }
//! ```

pub mod auth;
pub mod macros;

pub use auth::{AuthProvider, AuthError, User, Role, Permission};
pub use rocket_roles_macros::{define_roles, require_role, require_permission};

// Re-export for convenience
pub use auth::{register_auth_provider, register_roles};
