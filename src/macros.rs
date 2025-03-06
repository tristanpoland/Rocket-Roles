//! Macros for rocket-easy-auth
//! 
//! This module provides additional functionality through macros
//! that are re-exported from the macro crate.

// Re-export macros
pub use rocket_roles_macros::{define_roles, require_role, require_permission};
