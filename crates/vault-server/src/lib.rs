//! HTTP service: axum-based, listens only on 127.0.0.1:8080, no TLS.
//!
//! All HTTPS is handled by the user's existing Nginx, which reverse-proxies
//! `/keychain/*` to the internal `/vault/*` endpoints.

pub mod auth;
pub mod config;
pub mod error;
pub mod handlers;
pub mod store;
