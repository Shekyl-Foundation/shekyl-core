// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! HTTP basic auth for the TCP listener.
//!
//! UDS deployments rely on filesystem permissions and leave auth disabled.
//! TCP / tooling deployments may require `Authorization: Basic …`
//! (`docs/api/wallet_rpc.yaml` servers; `WALLET_REWRITE_PLAN.md` §Phase 4).

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use subtle::ConstantTimeEq;

/// Auth configuration for the RPC listener.
#[derive(Clone)]
pub enum AuthConfig {
    /// No credential check (UDS / `--disable-rpc-login`).
    Disabled,
    /// Require HTTP basic auth with these credentials.
    Basic {
        /// Username.
        username: String,
        /// Password. Compared constant-time against the Authorization
        /// header; treat as a secret under `35-secure-memory.mdc`.
        password: String,
    },
}

/// Manual (not derived) so no `Debug` of server state — `ServerConfig`,
/// `AppState`, a panic message — can ever render the `--rpc-login` password
/// (rule 35: it is a secret; rendering is the one thing Debug must not do).
impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => f.write_str("AuthConfig::Disabled"),
            Self::Basic { username, .. } => f
                .debug_struct("AuthConfig::Basic")
                .field("username", username)
                .field("password", &"<redacted>")
                .finish(),
        }
    }
}

impl AuthConfig {
    /// Build from optional `user:pass` login string.
    ///
    /// `None` or empty → [`AuthConfig::Disabled`]. A string without `:` is
    /// treated as username with empty password.
    pub fn from_rpc_login(login: Option<&str>) -> Self {
        match login {
            None | Some("") => Self::Disabled,
            Some(raw) => {
                let (username, password) = match raw.split_once(':') {
                    Some((u, p)) => (u.to_owned(), p.to_owned()),
                    None => (raw.to_owned(), String::new()),
                };
                Self::Basic { username, password }
            }
        }
    }

    /// Whether a request's `Authorization` header satisfies this config.
    pub fn check(&self, authorization: Option<&str>) -> bool {
        match self {
            Self::Disabled => true,
            Self::Basic { username, password } => {
                let Some(header_val) = authorization else {
                    return false;
                };
                let Some(encoded) = header_val.strip_prefix("Basic ") else {
                    return false;
                };
                let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded.trim())
                else {
                    return false;
                };
                // Compare the full `user:pass` blob constant-time so we do
                // not leak which field mismatched. Length mismatch still
                // short-circuits (inherent to variable-length secrets);
                // content comparison uses `subtle::ConstantTimeEq`.
                let expected = format!("{username}:{password}");
                ct_eq_bytes(&bytes, expected.as_bytes())
            }
        }
    }
}

/// Constant-time equality for equal-length slices; `false` on length mismatch.
fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

/// Axum middleware: reject unauthorized requests with HTTP 401.
pub async fn require_basic_auth(
    axum::extract::State(auth): axum::extract::State<AuthConfig>,
    request: Request,
    next: Next,
) -> Response {
    let header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    if auth.check(header) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                "Basic realm=\"shekyl-wallet-rpc\"",
            )],
            Body::from("unauthorized"),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic_header(user: &str, pass: &str) -> String {
        let enc = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        format!("Basic {enc}")
    }

    #[test]
    fn accepts_matching_credentials() {
        let auth = AuthConfig::Basic {
            username: "alice".into(),
            password: "secret".into(),
        };
        assert!(auth.check(Some(&basic_header("alice", "secret"))));
    }

    #[test]
    fn rejects_wrong_password() {
        let auth = AuthConfig::Basic {
            username: "alice".into(),
            password: "secret".into(),
        };
        assert!(!auth.check(Some(&basic_header("alice", "wrong"))));
    }

    #[test]
    fn rejects_missing_header() {
        let auth = AuthConfig::Basic {
            username: "alice".into(),
            password: "secret".into(),
        };
        assert!(!auth.check(None));
    }
}
