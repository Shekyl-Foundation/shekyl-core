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

/// Auth configuration for the RPC listener.
#[derive(Debug, Clone)]
pub enum AuthConfig {
    /// No credential check (UDS / `--disable-rpc-login`).
    Disabled,
    /// Require HTTP basic auth with these credentials.
    Basic {
        /// Username.
        username: String,
        /// Password.
        password: String,
    },
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
                let Ok(decoded) = String::from_utf8(bytes) else {
                    return false;
                };
                let Some((u, p)) = decoded.split_once(':') else {
                    return false;
                };
                // Phase 4a: byte equality. Constant-time compare is a
                // follow-up when credential material is treated as a
                // long-lived secret under 35-secure-memory.mdc.
                u == username && p == password
            }
        }
    }
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
