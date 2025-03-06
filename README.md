# rocket_roles

> **Warning**  
> This library is in early development and the API may change significantly between versions.


A flexible authentication and authorization system for the Rocket web framework in Rust.

[![Crates.io](https://img.shields.io/crates/v/rocket_roles)](https://crates.io/crates/rocket_roles)
[![Documentation](https://docs.rs/rocket_roles/badge.svg)](https://docs.rs/rocket_roles)
[![License](https://img.shields.io/crates/l/rocket_roles)](LICENSE)
[![Build Status](https://github.com/yourusername/rocket_roles/workflows/CI/badge.svg)](https://github.com/yourusername/rocket_roles/actions)

## Features

- **Database Agnostic**: Easily connect to any database by implementing a simple trait
- **Role-Based Access Control**: Define roles and their permissions with a simple macro
- **Permission-Based Guards**: Protect routes with role or permission requirements
- **Flexible**: Works with any token-based authentication system

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
rocket = "0.5.0"
rocket_roles = "0.1.0"
```

## Quick Start

### 1. Define your roles and permissions

```rust
use rocket_roles::define_roles;

define_roles! {
    "admin" => ["create_user", "delete_user", "view_admin_panel"],
    "user" => ["view_profile", "edit_profile"],
    "moderator" => ["delete_post", "edit_post", "pin_post"]
}
```

### 2. Implement the AuthProvider trait

```rust
use rocket_roles::auth::{AuthProvider, AuthError, User};
use async_trait::async_trait;
use std::collections::HashSet;

struct MyAuthProvider {
    // Your database connection or client here
}

#[async_trait]
impl AuthProvider for MyAuthProvider {
    async fn authenticate_token(&self, token: &str) -> Result<User, AuthError> {
        // Validate token and fetch user information from your database
        // Return a User object with roles and permissions
        
        // Example implementation:
        if token == "invalid" {
            return Err(AuthError::InvalidToken("Token is invalid".into()));
        }
        
        Ok(User::new("123", "john_doe")
            .with_role("user")
            .with_permission("custom_permission"))
    }
}
```

### 3. Register your auth provider

```rust
use rocket_roles::auth::register_auth_provider;

#[launch]
fn rocket() -> _ {
    // Create your auth provider
    let auth_provider = MyAuthProvider::new();
    
    // Register it
    register_auth_provider(auth_provider);
    
    // Initialize roles
    initialize_roles();
    
    rocket::build().mount("/", routes![/* your routes */])
}
```

### 4. Protect your routes

```rust
use rocket_roles::{require_role, require_permission};
use rocket::get;

// Require a specific role
#[require_role("admin")]
#[get("/admin/dashboard")]
fn admin_dashboard() -> &'static str {
    "Welcome to the admin dashboard!"
}

// Require a specific permission
#[require_permission("edit_profile")]
#[get("/profile/edit")]
fn edit_profile() -> &'static str {
    "Edit your profile here"
}
```

## Examples

Check out the examples directory for complete working examples:

- [PostgreSQL Authentication Example](examples/postgres_auth.rs)
- [Redis Authentication Example](examples/redis_auth.rs)
- [In-Memory Authentication Example](examples/memory_auth.rs)

## License

MIT
