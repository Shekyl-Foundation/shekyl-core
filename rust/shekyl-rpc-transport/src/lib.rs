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
    // count (`nc`) increments monotonically: RFC 7616 scopes `nc` to the nonce,
    // not the connection, so serialized requests over the pool stay valid even
    // when the pool reuses or reopens a connection.
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
#[derive(Clone, Debug)]
pub struct SimpleRequestRpc {
    authentication: Authentication,
    url: String,
    request_timeout: Duration,
}

impl SimpleRequestRpc {
    fn digest_auth_challenge(
        response: &hyper::Response<Incoming>,
    ) -> Result<Option<(WwwAuthenticateHeader, u64)>, RpcError> {
        Ok(
            if let Some(header) = response.headers().get("www-authenticate") {
                Some((
                    digest_auth::parse(header.to_str().map_err(|_| {
                        RpcError::InvalidNode("www-authenticate header wasn't a string".to_string())
                    })?)
                    .map_err(|_| {
                        RpcError::InvalidNode("invalid digest-auth response".to_string())
                    })?,
                    0,
                ))
            } else {
                None
            },
        )
    }

    /// Create a new HTTP(S) RPC connection.
    ///
    /// A daemon requiring authentication can be used via including the username and password in the
    /// URL.
    pub async fn new(url: String) -> Result<SimpleRequestRpc, RpcError> {
        Self::with_options(url, DEFAULT_TIMEOUT, None).await
    }

    /// Create a new HTTP(S) RPC connection with a custom timeout.
    ///
    /// A daemon requiring authentication can be used via including the username and password in the
    /// URL.
    pub async fn with_custom_timeout(
        url: String,
        request_timeout: Duration,
    ) -> Result<SimpleRequestRpc, RpcError> {
        Self::with_options(url, request_timeout, None).await
    }

    /// Create a new HTTP(S) RPC connection routed through a **SOCKS5h** proxy
    /// (`socks5h://`, `socks5://`, or bare `host:port` — the connector always
    /// resolves the daemon hostname *at the proxy*, so the local resolver never
    /// sees it). `proxy = None` behaves exactly like [`new`](Self::new).
    ///
    /// A daemon requiring authentication can be used via including the username and password in the
    /// URL.
    pub async fn with_proxy(
        url: String,
        proxy: Option<String>,
    ) -> Result<SimpleRequestRpc, RpcError> {
        Self::with_options(url, DEFAULT_TIMEOUT, proxy).await
    }

    async fn with_options(
        mut url: String,
        request_timeout: Duration,
        proxy: Option<String>,
    ) -> Result<SimpleRequestRpc, RpcError> {
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

        let authentication = if let Some(at) = at_in_authority {
            // Split at the authority's '@': userinfo before it, everything
            // else (scheme included) is the credential-free daemon URL.
            let url_with_credentials = Zeroizing::new(url);
            let userpass = Zeroizing::new(url_with_credentials[after_scheme..at].to_string());
            url = format!(
                "{}{}",
                &url_with_credentials[..after_scheme],
                &url_with_credentials[at + 1..]
            );

            let split_userpass = userpass.split(':').collect::<Vec<_>>();
            if split_userpass.len() > 2 {
                Err(RpcError::ConnectionError(
                    "invalid amount of passwords".to_string(),
                ))?;
            }

            let client = HttpClient::new(proxy.as_deref())
                .map_err(|e| RpcError::ConnectionError(format!("{e}")))?;
            // Obtain the initial challenge, which also somewhat validates this connection
            let challenge = Self::digest_auth_challenge(
                &client
                    .request(
                        Request::post(url.clone())
                            .body(Full::new(Bytes::new()))
                            .map_err(|e| {
                                RpcError::ConnectionError(format!("couldn't make request: {e:?}"))
                            })?,
                    )
                    .await
                    .map_err(|e| RpcError::ConnectionError(format!("{e}")))?,
            )?;
            Authentication::Authenticated {
                username: Zeroizing::new(split_userpass[0].to_string()),
                password: Zeroizing::new((*split_userpass.get(1).unwrap_or(&"")).to_string()),
                connection: Arc::new(Mutex::new((challenge, client))),
            }
        } else {
            Authentication::Unauthenticated(
                HttpClient::new(proxy.as_deref()).map_err(|e| {
                    RpcError::InternalError(format!("couldn't create a client: {e}"))
                })?,
            )
        };

        Ok(SimpleRequestRpc {
            authentication,
            url,
            request_timeout,
        })
    }
}

impl SimpleRequestRpc {
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
                            .request(request_fn(self.url.clone() + "/" + route)?)
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
                    // the authority. `hyper` sends origin-form (`/route`) on the
                    // wire, so the digest `uri=` computed over the path matches.
                    let mut request = request_fn(self.url.clone() + "/" + route)?;

                    // If we don't have an auth challenge, obtain one
                    if connection_lock.0.is_none() {
                        connection_lock.0 = Self::digest_auth_challenge(
                            &connection_lock
                                .1
                                .request(request)
                                .await
                                .map_err(|e| RpcError::ConnectionError(format!("{e:?}")))?,
                        )?;
                        request = request_fn(self.url.clone() + "/" + route)?;
                    }

                    // Insert the challenge response, if we have a challenge
                    if let Some((challenge, cnonce)) = connection_lock.0.as_mut() {
                        // Update the cnonce
                        // Overflow isn't a concern as this is a u64
                        *cnonce += 1;

                        let mut context = AuthContext::new_post::<_, _, _, &[u8]>(
                            <_ as AsRef<str>>::as_ref(username),
                            <_ as AsRef<str>>::as_ref(password),
                            "/".to_string() + route,
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

impl Rpc for SimpleRequestRpc {
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
    /// authenticated path, so no digest preflight is issued and construction
    /// is offline.
    #[tokio::test]
    async fn at_outside_the_authority_is_not_credentials() {
        for url in [
            "http://127.0.0.1:1/route?tag=user@host",
            "http://127.0.0.1:1?tag=user@host",
            "http://127.0.0.1:1#frag@ment",
        ] {
            let rpc = SimpleRequestRpc::new(url.to_string())
                .await
                .unwrap_or_else(|e| panic!("{url} must construct unauthenticated: {e}"));
            assert!(
                matches!(rpc.authentication, Authentication::Unauthenticated(_)),
                "{url}: the '@' beyond the authority must not trigger digest auth"
            );
            assert_eq!(rpc.url, url, "{url}: a credential-free URL is untouched");
        }
    }

    /// Credentials in the authority coexist with an '@' later in the URL:
    /// the split consumes only the authority's '@', so parsing succeeds and
    /// the constructor proceeds to the digest preflight (which fails against
    /// the refusing port — proving the parse was clean) with the password
    /// stripped from the dialed URL and absent from the error.
    #[tokio::test]
    async fn credentials_split_at_the_authority_at_only() {
        let err = SimpleRequestRpc::new("http://user:hunter2@127.0.0.1:1/x?tag=a@b".to_string())
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
}
