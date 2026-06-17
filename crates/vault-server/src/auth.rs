//! Bearer token authentication, constant-time compare.

use axum::http::HeaderMap;
use subtle::ConstantTimeEq;

/// Check that the `Authorization: Bearer <token>` header matches `expected`.
/// Uses constant-time comparison.
pub fn check_bearer(headers: Option<&str>, expected: &str) -> bool {
    let h = match headers {
        Some(s) => s,
        None => return false,
    };
    let token = match h.strip_prefix("Bearer ") {
        Some(t) => t,
        None => return false,
    };
    token.as_bytes().ct_eq(expected.as_bytes()).into()
}

/// Extract the `Authorization` header value as an owned `String`.
pub fn auth_header(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_token_matches() {
        assert!(check_bearer(Some("Bearer abc123"), "abc123"));
    }

    #[test]
    fn check_token_rejects_wrong() {
        assert!(!check_bearer(Some("Bearer xyz"), "abc123"));
    }

    #[test]
    fn check_token_rejects_missing_or_malformed() {
        assert!(!check_bearer(None, "x"));
        assert!(!check_bearer(Some(""), "x"));
        assert!(!check_bearer(Some("Basic abc"), "x"));
        assert!(!check_bearer(Some("Bearer"), "x"));
    }
}
