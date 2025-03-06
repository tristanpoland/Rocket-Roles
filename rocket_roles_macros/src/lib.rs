//! Procedural macros for rocket-easy-auth
//!
//! This crate provides the necessary procedural macros for the rocket-easy-auth crate.
//! Users should not use this crate directly, but instead use the re-exports from rocket-easy-auth.

extern crate proc_macro;
use proc_macro::TokenStream;
use quote::{quote, format_ident};
use syn::{parse_macro_input, LitStr, ItemFn, parse::Parse, parse, Token, bracketed, punctuated::Punctuated};

/// Struct to parse roles and permissions from the define_roles macro
struct RoleDefinitions {
    roles: Vec<(String, Vec<String>)>,
}

impl Parse for RoleDefinitions {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut roles = Vec::new();
        
        while !input.is_empty() {
            // Parse role name
            let role_name: LitStr = input.parse()?;
            
            // Parse =>
            input.parse::<Token![=>]>()?;
            
            // Parse permissions array
            let content;
            bracketed!(content in input);
            
            let permissions = Punctuated::<LitStr, Token![,]>::parse_terminated(&content)?
                .into_iter()
                .map(|lit| lit.value())
                .collect();
            
            roles.push((role_name.value(), permissions));
            
            // Parse optional comma
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }
        
        Ok(RoleDefinitions { roles })
    }
}

/// Defines roles and their permissions for the application
///
/// # Example
///
/// ```
/// use rocket_roles::define_roles;
///
/// define_roles! {
///     "admin" => ["create_user", "delete_user", "view_admin_panel"],
///     "user" => ["view_profile", "edit_profile"],
///     "moderator" => ["delete_post", "edit_post", "pin_post"]
/// }
/// ```
///
/// This will generate a function called `initialize_roles` that registers
/// the defined roles and their permissions with the authentication system.
#[proc_macro]
pub fn define_roles(input: TokenStream) -> TokenStream {
    let role_defs = parse_macro_input!(input as RoleDefinitions);
    
    let role_statements = role_defs.roles.iter().map(|(role_name, permissions)| {
        let perm_statements = permissions.iter().map(|perm| {
            quote! {
                permissions.insert(#perm.to_string());
            }
        });
        
        quote! {
            {
                let mut permissions = std::collections::HashSet::new();
                #(#perm_statements)*
                
                roles.insert(
                    #role_name.to_string(),
                    Role {
                        name: #role_name.to_string(),
                        permissions,
                    }
                );
            }
        }
    });
    
    let output = quote! {
        pub fn initialize_roles() {
            use std::collections::{HashMap, HashSet};
            use rocket_roles::auth::{Role, register_roles};
            
            let mut roles = HashMap::new();
            
            #(#role_statements)*
            
            register_roles(roles);
        }
    };
    
    output.into()
}

/// Requires a specific role to access the route
///
/// # Example
///
/// ```
/// use rocket_roles::require_role;
/// use rocket::get;
///
/// #[require_role("admin")]
/// #[get("/admin/dashboard")]
/// fn admin_dashboard() -> &'static str {
///     "Welcome to the admin dashboard!"
/// }
/// ```
#[proc_macro_attribute]
pub fn require_role(attr: TokenStream, item: TokenStream) -> TokenStream {
    let role = parse_macro_input!(attr as LitStr).value();
    let input_fn = parse_macro_input!(item as ItemFn);
    
    let fn_name = &input_fn.sig.ident;
    let fn_args = &input_fn.sig.inputs;
    let fn_output = &input_fn.sig.output;
    let fn_block = &input_fn.block;
    let fn_vis = &input_fn.vis;
    let fn_attrs = &input_fn.attrs;
    
    let output = quote! {
        #(#fn_attrs)*
        #fn_vis fn #fn_name(user: rocket_roles::User, #fn_args) #fn_output {
            // The user is already authenticated by the FromRequest impl
            // Now we just need to check if they have the required role
            if !user.has_role(#role) {
                return rocket::Response::build()
                    .status(rocket::http::Status::Forbidden)
                    .sized_body(None, std::io::Cursor::new(format!("Role '{}' required", #role)))
                    .finalize();
            }
            
            // If authorized, execute the original function
            #fn_block
        }
    };
    
    output.into()
}

/// Requires a specific permission to access the route
///
/// # Example
///
/// ```
/// use rocket_roles::require_permission;
/// use rocket::get;
///
/// #[require_permission("view_admin_panel")]
/// #[get("/admin/dashboard")]
/// fn admin_dashboard() -> &'static str {
///     "Welcome to the admin dashboard!"
/// }
/// ```
#[proc_macro_attribute]
pub fn require_permission(attr: TokenStream, item: TokenStream) -> TokenStream {
    let permission = parse_macro_input!(attr as LitStr).value();
    let input_fn = parse_macro_input!(item as ItemFn);
    
    let fn_name = &input_fn.sig.ident;
    let fn_args = &input_fn.sig.inputs;
    let fn_output = &input_fn.sig.output;
    let fn_block = &input_fn.block;
    let fn_vis = &input_fn.vis;
    let fn_attrs = &input_fn.attrs;
    
    let output = quote! {
        #(#fn_attrs)*
        #fn_vis fn #fn_name(user: rocket_roles::User, #fn_args) #fn_output {
            // The user is already authenticated by the FromRequest impl
            // Now we just need to check if they have the required permission
            if !user.has_permission(#permission) {
                return rocket::Response::build()
                    .status(rocket::http::Status::Forbidden)
                    .sized_body(None, std::io::Cursor::new(format!("Permission '{}' required", #permission)))
                    .finalize();
            }
            
            // If authorized, execute the original function
            #fn_block
        }
    };
    
    output.into()
}