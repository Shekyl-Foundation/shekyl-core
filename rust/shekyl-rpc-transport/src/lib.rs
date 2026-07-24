// Provenance: forked from monero-oxide (Shekyl-Foundation/monero-oxide, fcmp++
// lineage), originally `shekyl-oxide/rpc/simple-request`, last vendored at 2753111c50.
// Relocated to a first-party shekyl-* crate in the shekyl-oxide un-vendor (slice 2); no
// longer upstream-tracked. Implements shekyl-rpc-client's `Rpc` trait over a small
// hyper client (`http_client`, re-absorbed from the external simple-request so it can
// carry an optional SOCKS5h proxy). See docs/design/SHEKYL_OXIDE_UNVENDOR.md.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

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
use http_client::HttpClient;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

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
    /// `user:pass` from the URL's authority, if present.
    userpass: Option<Zeroizing<String>>,
}

fn parse_endpoint(url: String) -> Result<ParsedEndpoint, RpcError> {
    // Credentials live only in the URL's AUTHORITY
    // (`scheme://user:pass@host:port/...`), which RFC 3986 terminates at
    // the first of `/`, `?`, or `#`; an '@' anywhere later (path, query,
    // or fragment — e.g. `?tag=user@host`, with or without a path) is
    // ordinary content. Splitting on a whole-URL '@' would misparse such
    // a URL as credentials and issue a digest-auth preflight against
    // garbage, so the split happens at the authority's own '@' (userinfo
    // cannot contain a raw '@', so the authority holds at most one) and
    // the rest of the URL is never consulted.
    let after_scheme = url.find("://").map_or(0, |i| i + 3);
    let authority_end = url[after_scheme..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |i| after_scheme + i);
    let at_in_authority = url[after_scheme..authority_end]
        .find('@')
        .map(|i| after_scheme + i);

    let (mut url, userpass) = if let Some(at) = at_in_authority {
        // Split at the authority's '@': userinfo before it, everything
        // else (scheme included) is the credential-free daemon URL.
        let url_with_credentials = Zeroizing::new(url);
        let userpass = Zeroizing::new(url_with_credentials[after_scheme..at].to_string());
        let url = format!(
            "{}{}",
            &url_with_credentials[..after_scheme],
            &url_with_credentials[at + 1..]
        );
        (url, Some(userpass))
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
    if !matches!(parsed.scheme_str(), Some("http" | "https")) || parsed.authority().is_none() {
        return Err(RpcError::ConnectionError(
            "daemon URL must be http(s)://host:port[/path]".to_string(),
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
    Ok(ParsedEndpoint {
        url,
        path_prefix,
        userpass,
    })
}

/// Validate a daemon URL and optional proxy **offline** — every construction
/// check short of dialing: the authority credential grammar, the URL shape
/// (http(s) scheme, authority, no query, base-path normalization), the proxy
/// string, and the TLS root store. Server startup calls this so a malformed
/// `--daemon-address` / `--proxy` refuses loud at launch, instead of
/// surfacing on first use as a misdiagnosed "daemon unreachable" (rule 82:
/// the failure must name its cause). An unreachable-but-well-formed daemon
/// passes — reachability is not a startup requirement.
pub fn validate_endpoint(url: &str, proxy: Option<&str>) -> Result<(), RpcError> {
    parse_endpoint(url.to_owned())?;
    HttpClient::new(proxy).map_err(|e| RpcError::ConnectionError(format!("{e}")))?;
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
        Self::with_options(url, DEFAULT_TIMEOUT, None).await
    }

    /// Create a new HTTP(S) RPC connection with a custom timeout.
    ///
    /// A daemon requiring authentication can be used via including the username and password in the
    /// URL.
    pub async fn with_custom_timeout(
        url: String,
        request_timeout: Duration,
    ) -> Result<HttpRpc, RpcError> {
        Self::with_options(url, request_timeout, None).await
    }

    /// Create a new HTTP(S) RPC connection routed through a **SOCKS5h** proxy
    /// (`socks5h://`, `socks5://`, or bare `host:port` — the connector always
    /// resolves the daemon hostname *at the proxy*, so the local resolver never
    /// sees it). `proxy = None` behaves exactly like [`new`](Self::new).
    ///
    /// A daemon requiring authentication can be used via including the username and password in the
    /// URL.
    pub async fn with_proxy(url: String, proxy: Option<String>) -> Result<HttpRpc, RpcError> {
        Self::with_options(url, DEFAULT_TIMEOUT, proxy).await
    }

    async fn with_options(
        url: String,
        request_timeout: Duration,
        proxy: Option<String>,
    ) -> Result<HttpRpc, RpcError> {
        let ParsedEndpoint {
            url,
            path_prefix,
            userpass,
        } = parse_endpoint(url)?;

        let authentication =
            if let Some(userpass) = userpass {
                let split_userpass = userpass.split(':').collect::<Vec<_>>();
                if split_userpass.len() > 2 {
                    Err(RpcError::ConnectionError(
                        "invalid amount of passwords".to_string(),
                    ))?;
                }

                let client = HttpClient::new(proxy.as_deref())
                    .map_err(|e| RpcError::ConnectionError(format!("{e}")))?;
                // Obtain the initial challenge, which also somewhat validates this connection
                let response = client
                    .request(
                        Request::post(url.clone())
                            .body(Full::new(Bytes::new()))
                            .map_err(|e| {
                                RpcError::ConnectionError(format!("couldn't make request: {e:?}"))
                            })?,
                    )
                    .await
                    .map_err(|e| RpcError::ConnectionError(format!("{e}")))?;
                let challenge = Self::digest_auth_challenge(response).await?;
                Authentication::Authenticated {
                    username: Zeroizing::new(split_userpass[0].to_string()),
                    password: Zeroizing::new((*split_userpass.get(1).unwrap_or(&"")).to_string()),
                    connection: Arc::new(Mutex::new((challenge, client))),
                }
            } else {
                Authentication::Unauthenticated(HttpClient::new(proxy.as_deref()).map_err(|e| {
                    RpcError::InternalError(format!("couldn't create a client: {e}"))
                })?)
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
    async fn inner_post(&self, route: &str, body: Vec<u8>) -> Result<Vec<u8>, RpcError> {
        // Route → Content-Type is a shared protocol invariant (which routes are
        // EPEE-binary), so it lives once in `shekyl_rpc_client::content_type_for`.
        let content_type = shekyl_rpc_client::content_type_for(route);
        let request_fn = |uri| {
            Request::post(uri)
                .header("content-type", content_type)
                .body(Full::new(Bytes::from(body.clone())))
                .map_err(|e| RpcError::ConnectionError(format!("couldn't make request: {e:?}")))
        };

        async fn body_from_response(
            response: hyper::Response<Incoming>,
        ) -> Result<Vec<u8>, RpcError> {
            // No streaming size cap (matches prior behavior): daemon block
            // responses are large and the node is operator-selected.
            let collected = response
                .into_body()
                .collect()
                .await
                .map_err(|e| RpcError::ConnectionError(format!("{e:?}")))?;
            Ok(collected.to_bytes().to_vec())
        }

        for attempt in 0..2 {
            return Ok(match &self.authentication {
                Authentication::Unauthenticated(client) => {
                    body_from_response(
                        client
                            .request(request_fn(self.request_target(route))?)
                            .await
                            .map_err(|e| RpcError::ConnectionError(format!("{e:?}")))?,
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
                        let response = connection_lock
                            .1
                            .request(request)
                            .await
                            .map_err(|e| RpcError::ConnectionError(format!("{e:?}")))?;
                        connection_lock.0 = Self::digest_auth_challenge(response).await?;
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
                                        RpcError::InvalidNode(
                                            "couldn't respond to digest-auth challenge".to_string(),
                                        )
                                    })?
                                    .to_header_string(),
                            )
                            .map_err(|_| {
                                RpcError::InternalError(
                  "digest-auth challenge response wasn't a valid string for an HTTP header"
                    .to_string(),
                )
                            })?,
                        );
                    }

                    let response = connection_lock
                        .1
                        .request(request)
                        .await
                        .map_err(|e| RpcError::ConnectionError(format!("{e:?}")));

                    let (error, is_stale) = match &response {
                        Err(e) => (Some(e.clone()), false),
                        Ok(response) => (
                            None,
                            if response.status() == StatusCode::UNAUTHORIZED {
                                if let Some(header) = response.headers().get("www-authenticate") {
                                    header
                                        .to_str()
                                        .map_err(|_| {
                                            RpcError::InvalidNode(
                                                "www-authenticate header wasn't a string"
                                                    .to_string(),
                                            )
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
                            Err(RpcError::InvalidNode(
                                "node claimed fresh connection had stale authentication"
                                    .to_string(),
                            ))?
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
            tokio::time::timeout(self.request_timeout, self.inner_post(route, body))
                .await
                .map_err(|e| RpcError::ConnectionError(format!("{e:?}")))?
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
    }
}
