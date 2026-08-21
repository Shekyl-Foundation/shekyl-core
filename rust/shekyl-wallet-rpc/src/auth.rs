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
use zeroize::Zeroizing;

/// A `NAME:PASSWORD` credential that **cannot be blank**.
///
/// Constructible only through [`Self::new`], which refuses an empty half,
/// so an [`AuthConfig::Basic`] listener always carries a real secret and the
/// bind seam (`validate_listen`) does not have to inspect it — the
/// guarantee lives in the type, not at every site that reads it. The
/// password is a secret under `35-secure-memory.mdc`: it lives in a
/// `Zeroizing<String>`, every clone (`AppState`, the middleware layer) wipes
/// on drop, and the per-request comparison buffers wipe too.
#[derive(Clone)]
pub struct BasicCredential {
    username: String,
    password: Zeroizing<String>,
}

impl BasicCredential {
    /// Build a credential, refusing a blank user or password. The error
    /// names the flag and never echoes the value (it may hold a partial
    /// secret): `:` used to yield an empty user and password, which
    /// `Authorization: Basic Og==` satisfies, and a value without `:` used
    /// to become a username with an empty password — a typo in a flag must
    /// not become a passwordless listener (rule 82; RT-2).
    pub fn new(username: &str, password: &str) -> Result<Self, String> {
        if username.is_empty() || password.is_empty() {
            return Err(
                "--rpc-login must be NAME:PASSWORD with both halves non-empty (omit the flag \
                 to disable authentication on a loopback bind or, on Unix, a uds:// socket)"
                    .into(),
            );
        }
        Ok(Self {
            username: username.to_owned(),
            password: Zeroizing::new(password.to_owned()),
        })
    }

    /// The user half — an identifier, not a secret.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }
}

/// Manual (not derived): the password is never rendered (rule 35).
impl std::fmt::Debug for BasicCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasicCredential")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Auth configuration for the RPC listener.
#[derive(Clone)]
pub enum AuthConfig {
    /// No credential check (UDS / `--disable-rpc-login`).
    Disabled,
    /// Require HTTP basic auth with this credential.
    Basic(BasicCredential),
}

/// Manual (not derived) so no `Debug` of server state — `ServerConfig`,
/// `AppState`, a panic message — can ever render the `--rpc-login` password
/// (rule 35: it is a secret; rendering is the one thing Debug must not do).
impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => f.write_str("AuthConfig::Disabled"),
            Self::Basic(cred) => f.debug_tuple("AuthConfig::Basic").field(cred).finish(),
        }
    }
}

impl AuthConfig {
    /// Build from the `--rpc-login` value.
    ///
    /// `None` or empty → [`AuthConfig::Disabled`] (the flag was not given).
    /// Otherwise the value is split at the first `:` and handed to
    /// [`BasicCredential::new`], which refuses a blank half — so a value
    /// without `:` (no password) is refused too, rather than becoming a
    /// username with an empty password.
    pub fn from_rpc_login(login: Option<&str>) -> Result<Self, String> {
        let Some(raw) = login.filter(|s| !s.is_empty()) else {
            return Ok(Self::Disabled);
        };
        let (username, password) = raw.split_once(':').unwrap_or((raw, ""));
        BasicCredential::new(username, password).map(Self::Basic)
    }

    /// Whether a request's `Authorization` header satisfies this config.
    pub fn check(&self, authorization: Option<&str>) -> bool {
        match self {
            Self::Disabled => true,
            Self::Basic(cred) => {
                let Some(header_val) = authorization else {
                    return false;
                };
                let Some(encoded) = header_val.strip_prefix("Basic ") else {
                    return false;
                };
                // The decoded attempt carries the client's password; the
                // expected blob carries ours. Both wipe on drop (rule 35).
                let Ok(attempt) = base64::engine::general_purpose::STANDARD
                    .decode(encoded.trim())
                    .map(Zeroizing::new)
                else {
                    return false;
                };
                let expected = Zeroizing::new(
                    format!("{}:{}", cred.username, cred.password.as_str()).into_bytes(),
                );
                // Compare the full `user:pass` blob constant-time so we do
                // not leak which field mismatched. Length mismatch still
                // short-circuits (inherent to variable-length secrets);
                // content comparison uses `subtle::ConstantTimeEq`.
                ct_eq_bytes(&attempt, &expected)
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

    /// The type cannot hold a blank half: the constructor refuses, so no
    /// consumer has to re-check what a `Basic` carries.
    #[test]
    fn credential_cannot_be_blank() {
        for (u, p) in [("", ""), ("alice", ""), ("", "hunter2")] {
            let err = BasicCredential::new(u, p).expect_err("blank half");
            assert!(err.contains("--rpc-login"), "{u:?}:{p:?}: {err}");
            assert!(
                !err.contains("alice") && !err.contains("hunter2"),
                "{u:?}:{p:?}: the value must not be echoed: {err}"
            );
        }
        assert_eq!(
            BasicCredential::new("alice", "hunter2")
                .expect("valid")
                .username(),
            "alice"
        );
    }

    /// The parser refuses every shape that would have produced a blank
    /// credential, and never echoes the value it refused.
    #[test]
    fn rpc_login_parses_name_password_and_refuses_blank_halves() {
        assert!(matches!(
            AuthConfig::from_rpc_login(None),
            Ok(AuthConfig::Disabled)
        ));
        assert!(matches!(
            AuthConfig::from_rpc_login(Some("")),
            Ok(AuthConfig::Disabled)
        ));
        assert!(matches!(
            AuthConfig::from_rpc_login(Some("alice:hunter2")),
            Ok(AuthConfig::Basic { .. })
        ));
        for bad in [":", "alice:", ":hunter2", "alice"] {
            let err = AuthConfig::from_rpc_login(Some(bad)).expect_err(bad);
            assert!(
                err.contains("--rpc-login"),
                "{bad:?}: must name the flag: {err}"
            );
            assert!(
                !err.contains("alice") && !err.contains("hunter2"),
                "{bad:?}: the value must not be echoed: {err}"
            );
        }
    }

    fn basic_header(user: &str, pass: &str) -> String {
        let enc = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        format!("Basic {enc}")
    }

    fn alice() -> AuthConfig {
        AuthConfig::Basic(BasicCredential::new("alice", "secret").expect("valid"))
    }

    #[test]
    fn accepts_matching_credentials() {
        assert!(alice().check(Some(&basic_header("alice", "secret"))));
    }

    #[test]
    fn rejects_wrong_password() {
        assert!(!alice().check(Some(&basic_header("alice", "wrong"))));
    }

    #[test]
    fn rejects_missing_header() {
        assert!(!alice().check(None));
    }

    /// `Debug` of the credential, the config, and anything holding them never
    /// renders the password.
    #[test]
    fn debug_never_renders_the_password() {
        let shown = format!("{:?}", alice());
        assert!(
            shown.contains("alice") && !shown.contains("secret"),
            "{shown}"
        );
    }
}
