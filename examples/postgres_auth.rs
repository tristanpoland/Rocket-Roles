//! Example of using rocket-easy-auth with a PostgreSQL database
//! 
//! This example assumes a database with the following schema:
//! 
//! ```sql
//! CREATE TABLE users (
//!     id SERIAL PRIMARY KEY,
//!     username VARCHAR(255) NOT NULL,
//!     password_hash VARCHAR(255) NOT NULL
//! );
//! 
//! CREATE TABLE user_roles (
//!     user_id INTEGER REFERENCES users(id),
//!     role VARCHAR(255) NOT NULL,
//!     PRIMARY KEY (user_id, role)
//! );
//! 
//! CREATE TABLE user_permissions (
//!     user_id INTEGER REFERENCES users(id),
//!     permission VARCHAR(255) NOT NULL,
//!     PRIMARY KEY (user_id, permission)
//! );
//! 
//! CREATE TABLE tokens (
//!     token VARCHAR(255) PRIMARY KEY,
//!     user_id INTEGER REFERENCES users(id),
//!     expires_at TIMESTAMP NOT NULL
//! );
//! ```

use rocket::{get, post, launch, routes};
use rocket::serde::json::Json;
use rocket::serde::Serialize;
use sqlx::{PgPool, postgres::PgPoolOptions};
use rocket_roles::{
    auth::{AuthProvider, AuthError, User, register_auth_provider},
    define_roles, require_role, require_permission
};
use std::collections::HashSet;
use async_trait::async_trait;

// Define roles and their permissions
define_roles! {
    "admin" => ["create_user", "delete_user", "view_admin_panel"],
    "user" => ["view_profile", "edit_profile"],
    "moderator" => ["delete_post", "edit_post", "pin_post"]
}

// PostgreSQL auth provider implementation
struct PostgresAuthProvider {
    pool: PgPool,
}

impl PostgresAuthProvider {
    async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url).await?;
        
        Ok(Self { pool })
    }
}

#[async_trait]
impl AuthProvider for PostgresAuthProvider {
    async fn authenticate_token(&self, token: &str) -> Result<User, AuthError> {
        // Check if token exists and is valid
        let token_record = sqlx::query!(
            r#"
            SELECT user_id FROM tokens
            WHERE token = $1 AND expires_at > NOW()
            "#,
            token
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        
        let user_id = match token_record {
            Some(record) => record.user_id,
            None => return Err(AuthError::InvalidToken("Token expired or invalid".into())),
        };
        
        // Get user information
        let user = sqlx::query!(
            r#"
            SELECT id, username FROM users
            WHERE id = $1
            "#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?
        .ok_or(AuthError::UserNotFound)?;
        
        // Get user roles
        let roles = sqlx::query!(
            r#"
            SELECT role FROM user_roles
            WHERE user_id = $1
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?
        .into_iter()
        .map(|r| r.role)
        .collect();
        
        // Get direct permissions
        let permissions = sqlx::query!(
            r#"
            SELECT permission FROM user_permissions
            WHERE user_id = $1
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?
        .into_iter()
        .map(|p| p.permission)
        .collect::<HashSet<_>>();
        
        Ok(User {
            id: user.id.to_string(),
            username: user.username,
            roles,
            permissions,
        })
    }
}

#[derive(Debug, Serialize)]
struct ApiResponse<T> {
    success: bool,
    message: String,
    data: Option<T>,
}

// Routes protected by roles
#[require_role("admin")]
#[get("/admin")]
fn admin_panel() -> Json<ApiResponse<()>> {
    Json(ApiResponse {
        success: true,
        message: "Welcome to the admin panel".into(),
        data: None,
    })
}

// Routes protected by permissions
#[require_permission("edit_profile")]
#[post("/profile")]
fn edit_profile() -> Json<ApiResponse<()>> {
    Json(ApiResponse {
        success: true,
        message: "Profile updated".into(),
        data: None,
    })
}

// Public route
#[get("/public")]
fn public_route() -> &'static str {
    "This is a public route!"
}

#[launch]
async fn rocket() -> _ {
    // Initialize database connection
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/auth_example".into());
    
    let auth_provider = PostgresAuthProvider::new(&database_url)
        .await
        .expect("Failed to connect to database");
    
    // Register auth provider
    register_auth_provider(auth_provider);
    
    // Initialize roles
    initialize_roles();
    
    rocket::build().mount("/", routes![
        admin_panel,
        edit_profile,
        public_route,
    ])
}
