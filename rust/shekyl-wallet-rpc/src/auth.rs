// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! HTTP basic auth for the TCP listener.
//!
//! UDS deployments rely on filesystem permissions and leave auth disabled.
//! TCP / tooling deployments may require `Authorization: Basic …`
//! (`docs/api/wallet_rpc.yaml` servers; `WALLET_REWRITE_PLAN.md` §Phase 4).

use std::sync::Arc;

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
/// guarantee lives in the type, not at every site that reads it.
///
/// The password is a secret under `35-secure-memory.mdc`. It is held only
/// as the `user:pass` blob the wire carries, built once into a
/// pre-sized `Zeroizing<Vec<u8>>` (no reallocation, so no unwiped
/// intermediate), and every clone (`AppState`, the middleware layer)
/// wipes on drop. The one copy this type cannot wipe is the process's
/// argv, which is the operating system's.
#[derive(Clone)]
pub struct BasicCredential {
    username: String,
    expected: Zeroizing<Vec<u8>>,
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
        let mut expected = Zeroizing::new(Vec::with_capacity(username.len() + 1 + password.len()));
        expected.extend_from_slice(username.as_bytes());
        expected.push(b':');
        expected.extend_from_slice(password.as_bytes());
        Ok(Self {
            username: username.to_owned(),
            expected,
        })
    }

    /// The user half — an identifier, not a secret.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Whether a decoded `Authorization: Basic` payload is exactly this
    /// credential. The whole `user:pass` blob is compared constant-time so
    /// the response does not leak which half mismatched; a length mismatch
    /// still short-circuits (inherent to variable-length secrets).
    fn matches(&self, attempt: &[u8]) -> bool {
        attempt.len() == self.expected.len() && bool::from(attempt.ct_eq(&self.expected))
    }
}

/// Manual (not derived): the password is never rendered (rule 35).
impl std::fmt::Debug for BasicCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasicCredential")
            .field("username", &self.username)
            .field("expected", &"<redacted>")
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
    /// Build from a `--rpc-login` value that was **given**. The value is
    /// split at the first `:` and handed to [`BasicCredential::new`], which
    /// refuses a blank half — so an empty value, or one without `:` (no
    /// password), is refused rather than becoming "no authentication" or a
    /// username with an empty password. Omission is [`Self::from_cli`]'s
    /// to decide; a value is never silently equal to no value.
    pub fn from_rpc_login(login: &str) -> Result<Self, String> {
        let (username, password) = login.split_once(':').unwrap_or((login, ""));
        BasicCredential::new(username, password).map(Self::Basic)
    }

    /// Build from the binary's flag pair, where **presence** is the signal:
    /// `None` is the flag omitted. `--rpc-login` given together with
    /// `--disable-rpc-login` is refused as a contradiction rather than
    /// resolved by precedence — an operator who wrote both believes a
    /// password is set, and silently running without one is the failure
    /// RT-2 exists to prevent (name the action, not the intent). That holds
    /// for `--rpc-login=` too: an empty value is a value.
    pub fn from_cli(rpc_login: Option<&str>, disable_rpc_login: bool) -> Result<Self, String> {
        match (disable_rpc_login, rpc_login) {
            (true, Some(_)) => Err(
                "--disable-rpc-login and --rpc-login contradict each other; pass one. \
                 --disable-rpc-login is accepted only on a loopback bind or, on Unix, a \
                 uds:// socket"
                    .into(),
            ),
            (_, None) => Ok(Self::Disabled),
            (false, Some(login)) => Self::from_rpc_login(login),
        }
    }

    /// Whether a request's `Authorization` header satisfies this config.
    pub fn check(&self, authorization: Option<&str>) -> bool {
        match self {
            Self::Disabled => true,
            Self::Basic(cred) => {
                let Some(header_val) = authorization else {
                    return false;
                };
                // `credentials = auth-scheme 1*SP token68`; the scheme is
                // case-insensitive (RFC 9110 §11.1).
                let Some((scheme, encoded)) = header_val.split_once(' ') else {
                    return false;
                };
                if !scheme.eq_ignore_ascii_case("basic") {
                    return false;
                }
                // The decoded attempt carries the client's password; it
                // wipes on drop (rule 35).
                let Ok(attempt) = base64::engine::general_purpose::STANDARD
                    .decode(encoded.trim())
                    .map(Zeroizing::new)
                else {
                    return false;
                };
                cred.matches(&attempt)
            }
        }
    }
}

/// Axum middleware: reject unauthorized requests with HTTP 401.
///
/// The state is an `Arc` so each request costs a refcount bump, not a clone
/// of the credential (`from_fn_with_state` clones its state per call, and
/// the `State` extractor clones it again).
pub async fn require_basic_auth(
    axum::extract::State(auth): axum::extract::State<Arc<AuthConfig>>,
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

    /// The parser is the public seam: every shape that would have produced
    /// a blank credential — the empty value included — is refused there,
    /// naming the flag and never echoing the value. (`BasicCredential::new`
    /// is what refuses; the parser only splits, so one table covers both.)
    #[test]
    fn rpc_login_parses_name_password_and_refuses_blank_halves() {
        let Ok(AuthConfig::Basic(cred)) = AuthConfig::from_rpc_login("alice:hunter2") else {
            panic!("NAME:PASSWORD must parse to Basic");
        };
        assert_eq!(cred.username(), "alice");
        for bad in ["", ":", "alice:", ":hunter2", "alice"] {
            let err = AuthConfig::from_rpc_login(bad).expect_err(bad);
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

    /// The flag pair: omission disables, alone or with `--disable-rpc-login`;
    /// a given value must be a credential; a given value together with
    /// `--disable-rpc-login` is a contradiction, refused by name — and
    /// `--rpc-login=` is a given value, not an omission, on both counts. The
    /// edits that turn this red: resolving the pair by precedence, or
    /// treating the empty value as absent.
    #[test]
    fn flag_pair_presence_is_the_signal() {
        assert!(matches!(
            AuthConfig::from_cli(None, false),
            Ok(AuthConfig::Disabled)
        ));
        assert!(matches!(
            AuthConfig::from_cli(None, true),
            Ok(AuthConfig::Disabled)
        ));
        assert!(matches!(
            AuthConfig::from_cli(Some("alice:hunter2"), false),
            Ok(AuthConfig::Basic(_))
        ));
        let empty = AuthConfig::from_cli(Some(""), false).expect_err("an empty value is refused");
        assert!(empty.contains("--rpc-login"), "{empty}");
        for given in ["alice:hunter2", ""] {
            let err = AuthConfig::from_cli(Some(given), true).expect_err("contradiction");
            assert!(
                err.contains("--disable-rpc-login") && err.contains("contradict"),
                "{given:?}: {err}"
            );
            assert!(!err.contains("hunter2"), "{err}");
        }
    }

    fn basic_header(scheme: &str, user: &str, pass: &str) -> String {
        let enc = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        format!("{scheme} {enc}")
    }

    fn alice() -> AuthConfig {
        AuthConfig::Basic(BasicCredential::new("alice", "secret").expect("valid"))
    }

    /// The scheme token is case-insensitive (RFC 9110 §11.1); the payload
    /// is not.
    #[test]
    fn accepts_matching_credentials_under_any_scheme_case() {
        for scheme in ["Basic", "basic", "BASIC"] {
            assert!(
                alice().check(Some(&basic_header(scheme, "alice", "secret"))),
                "{scheme}"
            );
        }
        assert!(!alice().check(Some(&basic_header("Basic", "Alice", "secret"))));
        assert!(!alice().check(Some(&basic_header("Bearer", "alice", "secret"))));
    }

    #[test]
    fn rejects_wrong_password() {
        assert!(!alice().check(Some(&basic_header("Basic", "alice", "wrong"))));
        assert!(!alice().check(Some(&basic_header("Basic", "alice", "secre"))));
        assert!(!alice().check(Some(&basic_header("Basic", "alice", "secret2"))));
    }

    #[test]
    fn rejects_missing_or_malformed_header() {
        assert!(!alice().check(None));
        assert!(!alice().check(Some("Basic")));
        assert!(!alice().check(Some("Basic not-base64!")));
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
