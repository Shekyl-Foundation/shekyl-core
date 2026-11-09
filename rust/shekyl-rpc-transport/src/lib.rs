// Provenance: forked from monero-oxide (Shekyl-Foundation/monero-oxide, fcmp++
// lineage), originally `shekyl-oxide/rpc/simple-request`, last vendored at 2753111c50.
// Relocated to a first-party shekyl-* crate in the shekyl-oxide un-vendor (slice 2); no
// longer upstream-tracked. Implements shekyl-rpc-client's `Rpc` trait over a small
// hyper client (`http_client`, re-absorbed from the external simple-request so it can
// carry an optional SOCKS5h proxy). See docs/design/SHEKYL_OXIDE_UNVENDOR.md.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(unsafe_code)]

use core::future::Future;
use std::{sync::Arc, time::Duration};

use tokio::sync::Mutex;

use digest_auth::{AuthContext, WwwAuthenticateHeader};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{header::HeaderValue, Request, StatusCode};
use zeroize::Zeroizing;

use shekyl_rpc_client::{Rpc, RpcError};

mod http_client;
pub mod listen;
pub mod network_posture;
use http_client::{error_chain, HttpClient, HttpError, TransportTls};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// A failure of the connection itself, classified where it is raised.
///
/// The wallet's [`RpcError`](shekyl_rpc_client::RpcError) still folds this
/// into `ConnectionError`. Callers that can act on the cause — the shell —
/// match the variant instead of searching the sentence.
#[derive(Clone, Debug)]
pub enum TransportFault {
    /// `--proxy` does not parse, or the SOCKS tunnel refused the dial.
    Proxy(String),
    /// The TLS connector could not be built.
    Tls(String),
    /// The daemon did not answer: refused, timed out, or the body could not be read.
    Unreachable(String),
    /// This thread cannot host the client, or the runtime would not start.
    Runtime(String),
}

impl std::fmt::Display for TransportFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proxy(detail)
            | Self::Tls(detail)
            | Self::Unreachable(detail)
            | Self::Runtime(detail) => f.write_str(detail),
        }
    }
}

impl std::error::Error for TransportFault {}

/// Why a post did not return a body.
///
/// [`TransportFault`] is the connection. [`PostFault::Protocol`] is a
/// failure of this side of the request — digest authentication, a header
/// that would not encode — which the wallet still reports as its own
/// [`RpcError`](shekyl_rpc_client::RpcError) variant.
#[derive(Clone, Debug)]
pub enum PostFault {
    /// The connection failed.
    Connection(TransportFault),
    /// Not a connection fault. The wallet keeps this variant.
    Protocol(RpcError),
}

impl PostFault {
    fn from_rpc(error: RpcError) -> Self {
        match error {
            RpcError::ConnectionError(detail) => {
                Self::Connection(TransportFault::Unreachable(detail))
            }
            RpcError::InternalError(detail) => Self::Connection(TransportFault::Runtime(detail)),
            other => Self::Protocol(other),
        }
    }
}

impl From<HttpError> for PostFault {
    fn from(error: HttpError) -> Self {
        Self::Connection(error.fault())
    }
}

impl From<PostFault> for RpcError {
    fn from(fault: PostFault) -> Self {
        match fault {
            PostFault::Connection(TransportFault::Runtime(detail)) => {
                RpcError::InternalError(detail)
            }
            PostFault::Connection(other) => RpcError::ConnectionError(other.to_string()),
            PostFault::Protocol(error) => error,
        }
    }
}

impl std::fmt::Display for PostFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connection(fault) => write!(f, "{fault}"),
            Self::Protocol(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for PostFault {}

#[derive(Clone, Debug)]
enum Authentication {
    // If unauthenticated, use a single pooled client
    Unauthenticated(HttpClient),
    // If authenticated, lock the client per request so the digest-auth nonce
    // count (`nc`) increments monotonically. The daemon's epee-lineage digest
    // state (nonce, nc) lives per *connection*, so the challenge and the
    // request answering it must ride the same pooled connection —
    // `digest_auth_challenge` drains every challenge body precisely so hyper
    // returns that connection to the pool for reuse. A swap the drain cannot
    // prevent (idle timeout, a server-side close) surfaces as an error or a
    // `stale` 401, and the retry below re-obtains a challenge on the fresh
    // connection.
    Authenticated {
        username: Zeroizing<String>,
        password: Zeroizing<String>,
        #[allow(clippy::type_complexity)]
        connection: Arc<Mutex<(Option<(WwwAuthenticateHeader, u64)>, HttpClient)>>,
    },
}

/// An HTTP(S) transport for the RPC.
///
/// Requires tokio.
///
/// Formerly `SimpleRequestRpc`, after the vendored `simple-request` client it
/// wrapped; renamed when that dependency was dropped and its client
/// re-absorbed into `http_client` (see the crate-root provenance note).
#[derive(Clone, Debug)]
pub struct HttpRpc {
    authentication: Authentication,
    /// Credential-free daemon base URL, normalized to no trailing `/`.
    url: String,
    /// Path component of [`Self::url`] (`""` when the URL has none) — the
    /// prefix the digest-auth `uri=` must cover, since the wire path for a
    /// route is `{path_prefix}/{route}`, not `/{route}`.
    path_prefix: String,
    request_timeout: Duration,
}

/// The offline half of construction: the daemon URL parsed and normalized,
/// with any authority credentials split out.
struct ParsedEndpoint {
    /// Credential-free base URL, no trailing `/`.
    url: String,
    /// Path component of `url` (`""` when it has none).
    path_prefix: String,
    /// `(username, password)` from the URL's authority, if present —
    /// already split and shape-checked, so the offline validator and the
    /// constructor share one credential grammar structurally.
    credentials: Option<(Zeroizing<String>, Zeroizing<String>)>,
    /// Whether the client builds a TLS layer. `http://` never loads a
    /// root store (see `HttpClient`).
    tls: TransportTls,
}

/// Locate a URL's authority userinfo '@' — the credential terminator:
/// `(scheme-end offset, absolute '@' index if present)`.
///
/// Credentials live only in the URL's AUTHORITY
/// (`scheme://user:pass@host:port/...`), which RFC 3986 terminates at the
/// first of `/`, `?`, or `#`; an '@' anywhere later (path, query, or
/// fragment — e.g. `?tag=user@host`, with or without a path) is ordinary
/// content. Consulting a whole-URL '@' would misread such a URL as
/// credentialed, so only the authority's own '@' counts (userinfo cannot
/// contain a raw '@', so the authority holds at most one). One grammar, one
/// place: `parse_endpoint` splits credentials with it and
/// [`redacted_endpoint`] redacts with it, so the two can never disagree
/// about what is a credential.
fn authority_at(url: &str) -> (usize, Option<usize>) {
    let after_scheme = url.find("://").map_or(0, |i| i + 3);
    let authority_end = url[after_scheme..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |i| after_scheme + i);
    let at = url[after_scheme..authority_end]
        .find('@')
        .map(|i| after_scheme + i);
    (after_scheme, at)
}

/// Render an endpoint URL with any authority userinfo replaced by
/// `<redacted>`, for logs and `Debug` output: digest credentials may ride
/// in a daemon URL's authority (`user:pass@host`), and no diagnostic path
/// may print them (rule 30). An '@' beyond the authority is ordinary
/// content and is left alone.
#[must_use]
pub fn redacted_endpoint(url: &str) -> String {
    let (after_scheme, at) = authority_at(url);
    match at {
        Some(at) => format!("{}<redacted>{}", &url[..after_scheme], &url[at..]),
        None => url.to_string(),
    }
}

fn parse_endpoint(url: String) -> Result<ParsedEndpoint, RpcError> {
    // See `authority_at`: only the authority's '@' selects the credential
    // split; the rest of the URL is never consulted.
    let (after_scheme, at_in_authority) = authority_at(&url);

    let (mut url, credentials) = if let Some(at) = at_in_authority {
        // Split at the authority's '@': userinfo before it, everything
        // else (scheme included) is the credential-free daemon URL.
        let url_with_credentials = Zeroizing::new(url);
        let userpass = Zeroizing::new(url_with_credentials[after_scheme..at].to_string());
        let url = format!(
            "{}{}",
            &url_with_credentials[..after_scheme],
            &url_with_credentials[at + 1..]
        );
        // The userinfo grammar is `user[:pass]` — a second ':' has no
        // reading, so it refuses HERE (the offline half): deferred to the
        // dialing constructor it would surface as a misdiagnosed "daemon
        // unreachable" at first use. The error never echoes the userinfo.
        let mut parts = userpass.split(':');
        let username = Zeroizing::new(parts.next().unwrap_or("").to_string());
        let password = Zeroizing::new(parts.next().unwrap_or("").to_string());
        if parts.next().is_some() {
            return Err(RpcError::ConnectionError(
                "daemon URL credentials must be user[:pass] — the userinfo holds more than                  one ':'"
                    .to_string(),
            ));
        }
        (url, Some((username, password)))
    } else {
        (url, None)
    };

    // The URL is a *base* that routes are appended to as `{url}/{route}`:
    // strip any trailing '/' so the join yields exactly one separator (a
    // kept trailing slash would put `//route` on the wire, which the
    // daemon's router does not match), then parse to refuse shapes this
    // transport cannot dial and to recover the path prefix for `uri=`.
    while url.ends_with('/') {
        url.pop();
    }
    let parsed: hyper::Uri = url
        .parse()
        .map_err(|e| RpcError::ConnectionError(format!("invalid daemon URL: {e}")))?;
    // The port is optional: an absent port dials the scheme's standard port
    // (80/443), which is the reverse-proxied hosted-daemon shape the path
    // prefix above exists for — not a shape to refuse.
    if !matches!(parsed.scheme_str(), Some("http" | "https")) || parsed.authority().is_none() {
        return Err(RpcError::ConnectionError(
            "daemon URL must be http(s)://host[:port][/path]".to_string(),
        ));
    }
    // `Uri` keeps a query but silently *drops* a fragment, so the fragment
    // check must run on the string: a kept `#...` would swallow the appended
    // route into the fragment when the request URI re-parses.
    if parsed.query().is_some() || url.contains('#') {
        return Err(RpcError::ConnectionError(
            "daemon URL must not carry a query or fragment — it is a base URL routes are \
             appended to"
                .to_string(),
        ));
    }
    // `Uri::path()` is "/" for a path-less URL; the trailing-slash strip
    // above means any real path already ends in a non-'/' character.
    let path_prefix = parsed.path().trim_end_matches('/').to_string();
    let tls = match parsed.scheme_str() {
        Some("https") => TransportTls::On,
        _ => TransportTls::Off,
    };
    Ok(ParsedEndpoint {
        url,
        path_prefix,
        credentials,
        tls,
    })
}

/// Validate a daemon URL and optional proxy **offline** — every construction
/// check short of dialing: the authority credential grammar, the URL shape
/// (http(s) scheme, authority, no query, base-path normalization), the proxy
/// string, and — for an `https://` endpoint only — the TLS root store. Server
/// startup calls this so a malformed
/// `--daemon-address` / `--proxy` refuses loud at launch, instead of
/// surfacing on first use as a misdiagnosed "daemon unreachable" (rule 82:
/// the failure must name its cause). An unreachable-but-well-formed daemon
/// passes — reachability is not a startup requirement.
pub fn validate_endpoint(url: &str, proxy: Option<&str>) -> Result<(), RpcError> {
    let endpoint = parse_endpoint(url.to_owned())?;
    HttpClient::new(proxy, endpoint.tls).map_err(|e| RpcError::ConnectionError(format!("{e}")))?;
    Ok(())
}

impl HttpRpc {
    /// Extract the digest-auth challenge from a 401 response, then drain the
    /// (tiny) response body to its end: hyper returns a connection to the
    /// pool only once its body is fully read, and dropping the body unread
    /// can close the connection — killing the daemon's per-connection digest
    /// session with it, so the authenticated follow-up could never answer
    /// the challenge it was just issued. The drain is best-effort: a failure
    /// means the connection is already gone, which the caller's error/stale
    /// retry path recovers from.
    async fn digest_auth_challenge(
        response: hyper::Response<Incoming>,
    ) -> Result<Option<(WwwAuthenticateHeader, u64)>, RpcError> {
        let challenge = match response.headers().get("www-authenticate") {
            Some(header) => Some((
                digest_auth::parse(header.to_str().map_err(|_| {
                    RpcError::InvalidNode("www-authenticate header wasn't a string".to_string())
                })?)
                .map_err(|_| RpcError::InvalidNode("invalid digest-auth response".to_string()))?,
                0,
            )),
            None => None,
        };
        response.into_body().collect().await.ok();
        Ok(challenge)
    }

    /// The absolute request URI for `route` (the pooled client selects the
    /// connection from its authority; hyper sends origin-form on the wire).
    fn request_target(&self, route: &str) -> String {
        format!("{}/{}", self.url, route)
    }

    /// The wire path for `route` — what hyper's origin-form actually sends,
    /// and therefore what the digest-auth `uri=` must be computed over.
    fn digest_uri(&self, route: &str) -> String {
        format!("{}/{}", self.path_prefix, route)
    }

    /// Create a new HTTP(S) RPC connection.
    ///
    /// A daemon requiring authentication can be used via including the username and password in the
    /// URL.
    pub async fn new(url: String) -> Result<HttpRpc, RpcError> {
        Self::with_options(url, DEFAULT_TIMEOUT, None)
            .await
            .map_err(RpcError::from)
    }

    /// Create a new HTTP(S) RPC connection with a custom timeout.
    ///
    /// A daemon requiring authentication can be used via including the username and password in the
    /// URL.
    pub async fn with_custom_timeout(
        url: String,
        request_timeout: Duration,
    ) -> Result<HttpRpc, RpcError> {
        Self::with_options(url, request_timeout, None)
            .await
            .map_err(RpcError::from)
    }

    /// Create a new HTTP(S) RPC connection routed through a **SOCKS5h** proxy
    /// (`socks5h://`, `socks5://`, or bare `host:port` — the connector always
    /// resolves the daemon hostname *at the proxy*, so the local resolver never
    /// sees it). `proxy = None` behaves exactly like [`new`](Self::new).
    ///
    /// A daemon requiring authentication can be used via including the username and password in the
    /// URL.
    pub async fn with_proxy(url: String, proxy: Option<String>) -> Result<HttpRpc, RpcError> {
        Self::with_options(url, DEFAULT_TIMEOUT, proxy)
            .await
            .map_err(RpcError::from)
    }

    async fn with_options(
        url: String,
        request_timeout: Duration,
        proxy: Option<String>,
    ) -> Result<HttpRpc, PostFault> {
        let ParsedEndpoint {
            url,
            path_prefix,
            credentials,
            tls,
        } = parse_endpoint(url).map_err(PostFault::from_rpc)?;

        let authentication = if let Some((username, password)) = credentials {
            let client = HttpClient::new(proxy.as_deref(), tls)?;
            // Obtain the initial challenge, which also somewhat validates this connection
            let response = client
                .request(
                    Request::post(url.clone())
                        .body(Full::new(Bytes::new()))
                        .map_err(|e| {
                            PostFault::Protocol(RpcError::ConnectionError(format!(
                                "couldn't make request: {e}"
                            )))
                        })?,
                )
                .await?;
            let challenge = Self::digest_auth_challenge(response)
                .await
                .map_err(PostFault::from_rpc)?;
            Authentication::Authenticated {
                username,
                password,
                connection: Arc::new(Mutex::new((challenge, client))),
            }
        } else {
            // Same mapping as the authenticated arm and `validate_endpoint`:
            // a client-construction failure is a config/environment fault
            // (bad --proxy, missing TLS roots), never an internal bug, and
            // its classification must not depend on whether the daemon URL
            // happened to carry credentials.
            Authentication::Unauthenticated(HttpClient::new(proxy.as_deref(), tls)?)
        };

        Ok(HttpRpc {
            authentication,
            url,
            path_prefix,
            request_timeout,
        })
    }
}

impl HttpRpc {
    async fn inner_post(&self, route: &str, body: Vec<u8>) -> Result<Vec<u8>, PostFault> {
        // Route → Content-Type is a shared protocol invariant (which routes are
        // EPEE-binary), so it lives once in `shekyl_rpc_client::content_type_for`.
        let content_type = shekyl_rpc_client::content_type_for(route);
        let request_fn = |uri| {
            Request::post(uri)
                .header("content-type", content_type)
                .body(Full::new(Bytes::from(body.clone())))
                .map_err(|e| {
                    PostFault::Protocol(RpcError::ConnectionError(format!(
                        "couldn't make request: {e}"
                    )))
                })
        };

        async fn body_from_response(
            response: hyper::Response<Incoming>,
        ) -> Result<Vec<u8>, PostFault> {
            // No streaming size cap (matches prior behavior): daemon block
            // responses are large and the node is operator-selected.
            let collected =
                response.into_body().collect().await.map_err(|e| {
                    PostFault::Connection(TransportFault::Unreachable(error_chain(&e)))
                })?;
            Ok(collected.to_bytes().to_vec())
        }

        for attempt in 0..2 {
            return Ok(match &self.authentication {
                Authentication::Unauthenticated(client) => {
                    body_from_response(
                        client
                            .request(request_fn(self.request_target(route))?)
                            .await?,
                    )
                    .await?
                }
                Authentication::Authenticated {
                    username,
                    password,
                    connection,
                } => {
                    let mut connection_lock = connection.lock().await;

                    // Absolute URI: the pooled client picks the connection from
                    // the authority. `hyper` sends origin-form on the wire, so
                    // the digest `uri=` computed over `digest_uri` matches.
                    let mut request = request_fn(self.request_target(route))?;

                    // If we don't have an auth challenge, obtain one
                    if connection_lock.0.is_none() {
                        let response = connection_lock.1.request(request).await?;
                        connection_lock.0 = Self::digest_auth_challenge(response)
                            .await
                            .map_err(PostFault::from_rpc)?;
                        request = request_fn(self.request_target(route))?;
                    }

                    // Insert the challenge response, if we have a challenge
                    if let Some((challenge, cnonce)) = connection_lock.0.as_mut() {
                        // Update the cnonce
                        // Overflow isn't a concern as this is a u64
                        *cnonce += 1;

                        let mut context = AuthContext::new_post::<_, _, _, &[u8]>(
                            <_ as AsRef<str>>::as_ref(username),
                            <_ as AsRef<str>>::as_ref(password),
                            self.digest_uri(route),
                            None,
                        );
                        context.set_custom_cnonce(hex::encode(cnonce.to_le_bytes()));

                        request.headers_mut().insert(
                            "Authorization",
                            HeaderValue::from_str(
                                &challenge
                                    .respond(&context)
                                    .map_err(|_| {
                                        PostFault::Protocol(RpcError::InvalidNode(
                                            "couldn't respond to digest-auth challenge".to_string(),
                                        ))
                                    })?
                                    .to_header_string(),
                            )
                            .map_err(|_| {
                                PostFault::Protocol(RpcError::InternalError(
                  "digest-auth challenge response wasn't a valid string for an HTTP header"
                    .to_string(),
                ))
                            })?,
                        );
                    }

                    let response = connection_lock
                        .1
                        .request(request)
                        .await
                        .map_err(PostFault::from);

                    let (error, is_stale) = match &response {
                        Err(e) => (Some(e.clone()), false),
                        Ok(response) => (
                            None,
                            if response.status() == StatusCode::UNAUTHORIZED {
                                if let Some(header) = response.headers().get("www-authenticate") {
                                    header
                                        .to_str()
                                        .map_err(|_| {
                                            PostFault::Protocol(RpcError::InvalidNode(
                                                "www-authenticate header wasn't a string"
                                                    .to_string(),
                                            ))
                                        })?
                                        .contains("stale")
                                } else {
                                    false
                                }
                            } else {
                                false
                            },
                        ),
                    };

                    // On error or a stale nonce, drop the cached challenge; the
                    // next attempt re-obtains one over the pool (which reopens a
                    // connection as needed).
                    if error.is_some() || is_stale {
                        connection_lock.0 = None;
                        // If we're not already on our second attempt, move to the next loop iteration
                        // (retrying all of this once)
                        if attempt == 0 {
                            continue;
                        }
                        if let Some(e) = error {
                            Err(e)?
                        } else {
                            debug_assert!(is_stale);
                            Err(PostFault::Protocol(RpcError::InvalidNode(
                                "node claimed fresh connection had stale authentication"
                                    .to_string(),
                            )))?
                        }
                    } else {
                        body_from_response(response.expect("no response yet also no error?"))
                            .await?
                    }
                }
            });
        }

        unreachable!()
    }
}

impl Rpc for HttpRpc {
    fn post(
        &self,
        route: &str,
        body: Vec<u8>,
    ) -> impl Send + Future<Output = Result<Vec<u8>, RpcError>> {
        async move {
            match tokio::time::timeout(self.request_timeout, self.inner_post(route, body)).await {
                Ok(result) => result.map_err(RpcError::from),
                // `Elapsed`'s Debug is the unreadable `Elapsed(())`; say what
                // actually happened, with the bound that was exceeded.
                Err(_) => Err(RpcError::ConnectionError(format!(
                    "request timed out after {:?}",
                    self.request_timeout
                ))),
            }
        }
    }
}

/// A daemon client a synchronous caller can hold.
///
/// The renderers and `shekyl-cli` issue a handful of requests and then
/// return to a prompt. One current-thread runtime owns the [`HttpRpc`]
/// for the life of the client, so a call is not inside whatever runtime
/// a wallet session happens to be using.
pub struct SyncDaemon {
    runtime: tokio::runtime::Runtime,
    rpc: HttpRpc,
}

impl SyncDaemon {
    /// Connect to `url` (`http://` or `https://`), optionally through a
    /// SOCKS5h proxy. Nothing is dialed until [`Self::post`].
    ///
    /// # Errors
    ///
    /// The URL or the proxy does not parse, or this thread is already
    /// inside a Tokio runtime (a second runtime there would panic).
    pub fn connect(
        url: String,
        proxy: Option<String>,
        timeout: Duration,
    ) -> Result<Self, PostFault> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(PostFault::Connection(TransportFault::Runtime(
                "the daemon client was constructed inside an async runtime".to_owned(),
            )));
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| PostFault::Connection(TransportFault::Runtime(format!("runtime: {e}"))))?;
        let rpc = runtime.block_on(HttpRpc::with_options(url, timeout, proxy))?;
        Ok(Self { runtime, rpc })
    }

    /// POST `body` to `route` (a leading `/` is ignored) and return the body.
    ///
    /// # Errors
    ///
    /// The transport failed: connect, send, receive, or the request timeout.
    pub fn post(&self, route: &str, body: Vec<u8>) -> Result<Vec<u8>, PostFault> {
        let route = route.trim_start_matches('/');
        self.runtime.block_on(async {
            match tokio::time::timeout(self.rpc.request_timeout, self.rpc.inner_post(route, body))
                .await
            {
                Ok(result) => result,
                Err(_) => Err(PostFault::Connection(TransportFault::Unreachable(format!(
                    "request timed out after {:?}",
                    self.rpc.request_timeout
                )))),
            }
        })
    }

    /// One JSON-RPC call. The envelope is this method's: `id` is `0`, the
    /// same value `shekyl-rpc-client` posts. A refusal is the RW-Q3 error
    /// object, read by [`shekyl_rpc_types::errors::read_error_object`].
    ///
    /// # Errors
    ///
    /// The transport failed, the body is not a JSON-RPC reply, or the daemon
    /// refused.
    pub fn json_rpc<Req, Reply>(&self, method: &str, request: &Req) -> Result<Reply, JsonRpcError>
    where
        Req: serde::Serialize,
        Reply: serde::de::DeserializeOwned,
    {
        let body = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": method,
            "params": request,
        }))
        .map_err(|error| JsonRpcError::Malformed(error.to_string()))?;
        let raw = self
            .post("json_rpc", body)
            .map_err(JsonRpcError::Transport)?;
        let envelope: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|_| JsonRpcError::Malformed(format!("malformed {method} reply")))?;
        if let Some(error) = envelope.get("error") {
            return Err(match shekyl_rpc_types::errors::read_error_object(error) {
                Some(refusal) => JsonRpcError::Refusal(refusal),
                None => JsonRpcError::Malformed(format!("{method} failed")),
            });
        }
        let result = envelope.get("result").cloned().ok_or_else(|| {
            JsonRpcError::Malformed(format!("malformed {method} reply: no result"))
        })?;
        serde_json::from_value(result)
            .map_err(|error| JsonRpcError::Malformed(format!("malformed {method} reply: {error}")))
    }
}

/// A JSON-RPC call that did not return a reply.
#[derive(Debug)]
pub enum JsonRpcError {
    /// The post failed.
    Transport(PostFault),
    /// The daemon refused. The class and the diagnostic are the refusal.
    Refusal(shekyl_rpc_types::errors::RpcError),
    /// The body was not a reply of the requested type.
    Malformed(String),
}

/// A JSON-RPC `result` envelope, for a test that answers a daemon route.
/// `id` is `0`, the same value [`SyncDaemon::json_rpc`] posts.
#[must_use]
pub fn json_rpc_result_body(result: &impl serde::Serialize) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 0,
        "result": result,
    })
    .to_string()
}

impl std::fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(error) => write!(f, "{error}"),
            Self::Refusal(refusal) => write!(f, "{}", refusal.report()),
            Self::Malformed(detail) => write!(f, "{detail}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The credential grammar is authority-scoped end to end: an '@' after
    /// the authority (which terminates at the first of `/`, `?`, or `#` —
    /// including a path-less query or fragment) never selects the
    /// authenticated path. A path '@' constructs unauthenticated; a query
    /// or fragment '@' is refused offline by the base-URL shape check — the
    /// error is the shape rejection, never a credential misparse (which
    /// would have dialed a digest preflight and failed differently).
    #[tokio::test]
    async fn at_outside_the_authority_is_not_credentials() {
        let url = "http://127.0.0.1:1/route@x";
        let rpc = HttpRpc::new(url.to_string())
            .await
            .unwrap_or_else(|e| panic!("{url} must construct unauthenticated: {e}"));
        assert!(
            matches!(rpc.authentication, Authentication::Unauthenticated(_)),
            "{url}: the '@' beyond the authority must not trigger digest auth"
        );
        assert_eq!(rpc.url, url, "{url}: a credential-free URL is untouched");

        for url in [
            "http://127.0.0.1:1/route?tag=user@host",
            "http://127.0.0.1:1?tag=user@host",
            "http://127.0.0.1:1#frag@ment",
        ] {
            let err = HttpRpc::new(url.to_string())
                .await
                .expect_err("a query/fragment daemon URL is not a base URL");
            let rendered = format!("{err}");
            assert!(
                rendered.contains("daemon URL"),
                "{url}: expected the offline shape rejection, got {err:?}"
            );
        }
    }

    /// Credentials in the authority coexist with an '@' later in the URL:
    /// the split consumes only the authority's '@', so parsing succeeds and
    /// the constructor proceeds to the digest preflight (which fails against
    /// the refusing port — proving the parse was clean) with the password
    /// stripped from the dialed URL and absent from the error.
    #[tokio::test]
    async fn credentials_split_at_the_authority_at_only() {
        let err = HttpRpc::new("http://user:hunter2@127.0.0.1:1/x@y".to_string())
            .await
            .expect_err("the preflight against a refusing port must fail");
        assert!(
            matches!(err, RpcError::ConnectionError(_)),
            "expected the preflight's ConnectionError, got {err:?}"
        );
        assert!(
            !format!("{err}").contains("hunter2"),
            "a constructor error must never render the password"
        );
    }

    /// The base-URL join contract: a trailing '/' (or several) normalizes
    /// away so the wire path is `/route` — never `//route` — and a
    /// path-prefixed daemon URL keeps its prefix in both the request target
    /// and the digest `uri=` (which must equal the wire path, or a
    /// credentialed path-prefixed daemon could never authenticate).
    #[tokio::test]
    async fn base_url_normalizes_and_digest_uri_matches_the_wire_path() {
        let rpc = HttpRpc::new("http://127.0.0.1:1/".to_string())
            .await
            .expect("trailing slash constructs");
        assert_eq!(rpc.url, "http://127.0.0.1:1");
        assert_eq!(
            rpc.request_target("json_rpc"),
            "http://127.0.0.1:1/json_rpc"
        );
        assert_eq!(rpc.digest_uri("json_rpc"), "/json_rpc");

        let rpc = HttpRpc::new("http://127.0.0.1:1/prefix/".to_string())
            .await
            .expect("path prefix constructs");
        assert_eq!(
            rpc.request_target("json_rpc"),
            "http://127.0.0.1:1/prefix/json_rpc"
        );
        assert_eq!(rpc.digest_uri("json_rpc"), "/prefix/json_rpc");
    }

    /// Redaction is authority-scoped like the credential split itself: the
    /// userinfo disappears, an '@' beyond the authority is untouched, and a
    /// credential-free URL round-trips unchanged.
    #[test]
    fn redacted_endpoint_strips_exactly_the_authority_userinfo() {
        assert_eq!(
            redacted_endpoint("http://user:hunter2@127.0.0.1:1/x"),
            "http://<redacted>@127.0.0.1:1/x"
        );
        assert_eq!(
            redacted_endpoint("socks5h://user:hunter2@127.0.0.1:9050"),
            "socks5h://<redacted>@127.0.0.1:9050"
        );
        for unchanged in [
            "http://127.0.0.1:1",
            "http://127.0.0.1:1/route?tag=user@host",
            "127.0.0.1:9050",
        ] {
            assert_eq!(redacted_endpoint(unchanged), unchanged);
        }
    }

    /// `validate_endpoint` is the offline startup gate: well-formed
    /// URL + proxy combinations pass without dialing; a malformed proxy or a
    /// URL shape the transport cannot dial refuses with an error naming the
    /// offending input, not a connectivity misdiagnosis.
    #[test]
    fn validate_endpoint_refuses_malformed_configuration_offline() {
        validate_endpoint("http://127.0.0.1:1", None).expect("plain URL");
        validate_endpoint(
            "https://node.example.com:11029/prefix",
            Some("socks5h://127.0.0.1:9050"),
        )
        .expect("URL + proxy");

        let err = validate_endpoint("http://127.0.0.1:1", Some("socks5://127.0.0.1"))
            .expect_err("port-less proxy");
        assert!(
            format!("{err}").contains("--proxy"),
            "names the flag: {err}"
        );

        for url in ["localhost:11028", "ftp://127.0.0.1:1", "http://"] {
            let err = validate_endpoint(url, None).expect_err("bad URL shape");
            assert!(
                format!("{err}").contains("daemon URL"),
                "{url}: names the input: {err}"
            );
        }

        // The credential grammar is part of the offline gate: a userinfo
        // with a second ':' refuses here — not at first use as a
        // misdiagnosed "daemon unreachable" — and the refusal never echoes
        // the credential.
        let err = validate_endpoint("http://user:pa:ss@127.0.0.1:1", None)
            .expect_err("malformed userinfo refuses offline");
        let rendered = format!("{err}");
        assert!(rendered.contains("user[:pass]"), "names the grammar: {err}");
        assert!(
            !rendered.contains("pa:ss"),
            "must not echo the credential: {err}"
        );
    }
}
