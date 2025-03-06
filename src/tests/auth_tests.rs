//! Unit tests for authentication functionality

#[cfg(test)]
mod tests {
    use crate::auth::{User, Role, AuthProvider, AuthError, register_auth_provider, register_roles};
    use async_trait::async_trait;
    use std::collections::{HashMap, HashSet};
    
    // Test user creation and permission checking
    #[test]
    fn test_user_permissions() {
        // Set up roles
        let mut roles = HashMap::new();
        
        let admin_role = Role {
            name: "admin".to_string(),
            permissions: HashSet::from_iter(vec![
                "create_user".to_string(),
                "delete_user".to_string(),
            ]),
        };
        
        let user_role = Role {
            name: "user".to_string(),
            permissions: HashSet::from_iter(vec![
                "view_profile".to_string(),
                "edit_profile".to_string(),
            ]),
        };
        
        roles.insert(admin_role.name.clone(), admin_role);
        roles.insert(user_role.name.clone(), user_role);
        
        register_roles(roles);
        
        // Create a user with admin role
        let admin = User::new("1", "admin")
            .with_role("admin");
        
        // Check permissions
        assert!(admin.has_role("admin"));
        assert!(!admin.has_role("user"));
        assert!(admin.has_permission("create_user"));
        assert!(admin.has_permission("delete_user"));
        assert!(!admin.has_permission("view_profile"));
        
        // Create a user with both admin and user roles
        let super_user = User::new("2", "super")
            .with_roles(vec!["admin", "user"]);
        
        // Check permissions
        assert!(super_user.has_role("admin"));
        assert!(super_user.has_role("user"));
        assert!(super_user.has_permission("create_user"));
        assert!(super_user.has_permission("view_profile"));
        
        // Create a user with direct permissions
        let special = User::new("3", "special")
            .with_permission("special_permission");
        
        // Check permissions
        assert!(special.has_permission("special_permission"));
        assert!(!special.has_permission("create_user"));
    }
    
    // Mock auth provider for testing
    struct MockAuthProvider;
    
    #[async_trait]
    impl AuthProvider for MockAuthProvider {
        async fn authenticate_token(&self, token: &str) -> Result<User, AuthError> {
            match token {
                "valid_token" => Ok(User::new("1", "test_user").with_role("user")),
                _ => Err(AuthError::InvalidToken("Invalid token".to_string())),
            }
        }
    }
    
    // Test token authentication
    #[tokio::test]
    async fn test_token_authentication() {
        let provider = MockAuthProvider;
        register_auth_provider(provider);
        
        // Valid token
        let user = crate::auth::get_auth_provider()
            .authenticate_token("valid_token")
            .await;
        
        assert!(user.is_ok());
        let user = user.unwrap();
        assert_eq!(user.id, "1");
        assert_eq!(user.username, "test_user");
        assert!(user.has_role("user"));
        
        // Invalid token
        let result = crate::auth::get_auth_provider()
            .authenticate_token("invalid_token")
            .await;
        
        assert!(result.is_err());
        match result {
            Err(AuthError::InvalidToken(_)) => (), // Expected
            _ => panic!("Expected InvalidToken error"),
        }
    }
}
