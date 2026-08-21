// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Minimal hyper HTTP(S) client with an **optional SOCKS5h** connector.
//!
//! The direct (no-proxy) path is a port of the vendored `simple-request` client
//! (which this crate was relocated from; see the crate root): a pooled
//! `hyper-util` client over `HttpsConnector<HttpConnector>`, built with the same
//! connector settings. `simple-request`'s connector is private and
//! un-injectable, so proxy support could not be added to it externally —
//! re-absorbing the client here lets us add the one thing it could not do.
//!
//! # Why the proxy is SOCKS5**h**
//!
//! [`SocksConnector`] hands the proxy a `TargetAddr::Domain` (via `tokio-socks`),
//! so the **proxy** resolves the daemon hostname, not the local resolver. A
//! `socks5` (local-resolving) connector would hand the proxy an IP it resolved
//! itself, leaking the hostname in cleartext DNS before the proxy is involved —
//! the exact leak `shekyl-cli::network_posture` warns about. Remote resolution
//! is the only mode built here.
//!
//! This client performs **no** SOCKS authentication: the principal daemon's
//! access control is the operator's own node / the proxy, not a per-connection
//! SOCKS identity. Per-persona SOCKS-username isolation is a *different*
//! transport (`shekyl-p-transport`) and deliberately does not share this one;
//! see the `PersonaIsolatedTransport` pin in engine-core.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::http::uri::Authority;
use hyper::Uri;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;
use tower_service::Service;

/// Errors constructing or using the client.
#[derive(Debug)]
pub(crate) enum HttpError {
    /// The `--proxy` value was not a usable SOCKS5 `host:port`.
    InvalidProxy(String),
    /// The TLS connector could not be built (no roots available).
    Tls(String),
    /// A request failed at the hyper layer.
    Request(String),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProxy(d) => write!(f, "invalid --proxy for the daemon transport: {d}"),
            Self::Tls(d) => write!(f, "TLS connector unavailable: {d}"),
            Self::Request(d) => write!(f, "{d}"),
        }
    }
}

/// Local newtype over a `tokio-socks` stream that grants it the two traits
/// `hyper-util` needs from a connector's output but that a foreign type cannot
/// carry: `Connection` (orphan rule — `Socks5Stream` is foreign, `Connection`
/// is foreign) and, via `TokioIo`, `hyper::rt::{Read, Write}`. `TokioIo<T>`
/// derives `Read`/`Write` from `T: AsyncRead/AsyncWrite` and `Connection` from
/// `T: Connection`, so implementing all three on this wrapper makes
/// `TokioIo<SocksStream>` a valid connector output.
pub(crate) struct SocksStream(Socks5Stream<TcpStream>);

impl AsyncRead for SocksStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // `Socks5Stream<TcpStream>` is `Unpin` (it pins its inner socket itself).
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for SocksStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Connection for SocksStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

/// A `tower` connector that dials the target **through a SOCKS5h proxy**,
/// letting the proxy resolve the hostname (`TargetAddr::Domain`) — never the
/// local resolver.
#[derive(Clone, Debug)]
pub(crate) struct SocksConnector {
    /// `host:port` of the SOCKS proxy (scheme stripped).
    proxy: Arc<str>,
}

impl SocksConnector {
    fn new(proxy: &str) -> Result<Self, HttpError> {
        // Accept `socks5h://host:port`, `socks5://host:port`, or a bare
        // `host:port`. The scheme is advisory — this connector is *always*
        // remote-resolving, so a `socks5://` (local-resolving) label does not
        // weaken it — but every OTHER scheme refuses here: silently speaking
        // SOCKS5 to an `http://` (or `socks4://`) proxy would instead fail on
        // every request with an opaque handshake error, pointing the operator
        // at the network instead of the flag.
        let hostport = match proxy.split_once("://") {
            None => proxy,
            // Scheme comparison is case-insensitive (RFC 3986 §3.1) — the
            // canonical form is lowercase, but `SOCKS5H://` is the same
            // scheme and refusing it would be grammar pedantry, not safety.
            Some((scheme, rest))
                if scheme.eq_ignore_ascii_case("socks5")
                    || scheme.eq_ignore_ascii_case("socks5h") =>
            {
                rest
            }
            Some((scheme, _)) => {
                return Err(HttpError::InvalidProxy(format!(
                    "unsupported scheme {scheme:?} — this transport speaks SOCKS5 only \
                     (socks5h://host:port, socks5://host:port, or bare host:port)"
                )))
            }
        };
        // Userinfo before the grammar check, and never echoed: it may carry a
        // credential, and this client performs no SOCKS authentication anyway
        // (see the module doc — per-persona SOCKS identities are
        // `shekyl-p-transport`'s, deliberately not this transport's).
        if hostport.contains('@') {
            return Err(HttpError::InvalidProxy(
                "userinfo is not accepted — this transport performs no SOCKS authentication"
                    .to_string(),
            ));
        }
        // `Authority` is the exact grammar of what may follow the scheme: the
        // parse rejects a path, query, fragment, or whitespace outright. It
        // accepts a missing port, so that is refused explicitly —
        // `tokio-socks` dials literal `host:port` strings only (the old
        // `contains(':')` check falsely accepted `[::1]`).
        let authority: Authority = hostport.parse().map_err(|_| {
            HttpError::InvalidProxy(format!("expected host:port, got {hostport:?}"))
        })?;
        if authority.port_u16().is_none() {
            return Err(HttpError::InvalidProxy(format!(
                "missing port in {hostport:?} — expected host:port"
            )));
        }
        Ok(Self {
            proxy: authority.as_str().into(),
        })
    }
}

impl Service<Uri> for SocksConnector {
    type Response = TokioIo<SocksStream>;
    type Error = io::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, io::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let proxy = self.proxy.clone();
        Box::pin(async move {
            let host = dst
                .host()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target has no host"))?
                .to_owned();
            let port = dst.port_u16().unwrap_or(match dst.scheme_str() {
                Some("https") => 443,
                _ => 80,
            });
            // `(host, port)` → `TargetAddr::Domain` → the proxy resolves the
            // name (SOCKS5h). Never pass a pre-resolved `SocketAddr` here.
            let stream = Socks5Stream::connect(&*proxy, (host.as_str(), port))
                .await
                .map_err(|e| io::Error::other(format!("socks: {e}")))?;
            Ok(TokioIo::new(SocksStream(stream)))
        })
    }
}

/// Build the direct `HttpConnector` with the same settings `simple-request` used.
fn http_connector() -> HttpConnector {
    let mut http = HttpConnector::new();
    http.set_keepalive(Some(Duration::from_secs(60)));
    http.set_nodelay(true);
    http.set_reuse_address(true);
    // Required so the connector will produce a plaintext stream for `http://`
    // targets when wrapped by `HttpsConnector`.
    http.enforce_http(false);
    http
}

/// The direct connector for a **plaintext** endpoint — no TLS layer wrapped
/// around it. `enforce_http(true)` makes the plaintext choice structural: a
/// client built this way refuses an `https://` request URI outright instead
/// of speaking plaintext to a TLS port.
fn plain_http_connector() -> HttpConnector {
    let mut http = http_connector();
    http.enforce_http(true);
    http
}

/// Wrap `inner` in a rustls HTTPS connector using the system's native roots —
/// the same root strategy `simple-request`'s `tls` feature used (native only;
/// no webpki fallback).
fn https<C>(inner: C) -> Result<HttpsConnector<C>, HttpError>
where
    C: Service<Uri>,
{
    Ok(HttpsConnectorBuilder::new()
        .with_native_roots()
        .map_err(|e| HttpError::Tls(format!("{e:?}")))?
        .https_or_http()
        .enable_http1()
        .wrap_connector(inner))
}

/// A pooled HTTP(S) client — direct or through a SOCKS5h proxy.
///
/// The TLS layer is built **only for an `https://` endpoint**. A plaintext
/// endpoint gets a client with no TLS connector at all, so a host with no
/// native root store (a minimal container image, a freshly provisioned
/// device) can still dial a plaintext daemon — the loopback default — instead
/// of failing at construction with "no native root CA certificates found".
/// Before this split every endpoint paid for roots it would never use.
#[derive(Clone)]
pub(crate) enum HttpClient {
    /// No proxy: connect directly, resolving DNS locally.
    Direct(HyperClient<HttpsConnector<HttpConnector>, Full<Bytes>>),
    /// Through a SOCKS5h proxy: the proxy resolves DNS.
    Socks(HyperClient<HttpsConnector<SocksConnector>, Full<Bytes>>),
    /// Plaintext `http://` endpoint, no proxy: no TLS layer is built.
    PlainDirect(HyperClient<HttpConnector, Full<Bytes>>),
    /// Plaintext `http://` endpoint through a SOCKS5h proxy: no TLS layer.
    PlainSocks(HyperClient<SocksConnector, Full<Bytes>>),
}

impl std::fmt::Debug for HttpClient {
    // Manual (not derived) so `HttpRpc: Debug` does not hinge on the
    // hyper client's Debug bounds; the transport mode is all that's useful here.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Direct(_) => "HttpClient::Direct",
            Self::Socks(_) => "HttpClient::Socks",
            Self::PlainDirect(_) => "HttpClient::PlainDirect",
            Self::PlainSocks(_) => "HttpClient::PlainSocks",
        })
    }
}

impl HttpClient {
    /// Build the client, selecting the SOCKS path when `proxy` is `Some` and
    /// the TLS-wrapped connector only when `tls` is set (an `https://`
    /// endpoint). A plaintext endpoint never loads a root store.
    pub(crate) fn new(proxy: Option<&str>, tls: bool) -> Result<Self, HttpError> {
        // `Builder::pool_idle_timeout` returns `&mut Builder`, so the whole
        // chain must land in one statement (ending in the owning `.build()`).
        match (proxy, tls) {
            (None, true) => Ok(Self::Direct(
                HyperClient::builder(TokioExecutor::new())
                    .pool_idle_timeout(Duration::from_secs(60))
                    .build(https(http_connector())?),
            )),
            (Some(p), true) => Ok(Self::Socks(
                HyperClient::builder(TokioExecutor::new())
                    .pool_idle_timeout(Duration::from_secs(60))
                    .build(https(SocksConnector::new(p)?)?),
            )),
            (None, false) => Ok(Self::PlainDirect(
                HyperClient::builder(TokioExecutor::new())
                    .pool_idle_timeout(Duration::from_secs(60))
                    .build(plain_http_connector()),
            )),
            (Some(p), false) => Ok(Self::PlainSocks(
                HyperClient::builder(TokioExecutor::new())
                    .pool_idle_timeout(Duration::from_secs(60))
                    .build(SocksConnector::new(p)?),
            )),
        }
    }

    /// Send `request` and return the response.
    ///
    /// The request URI must be absolute (carry an authority): the pooled client
    /// selects the connection from it. `hyper` rewrites it to origin-form on the
    /// wire, so a digest-auth `uri=` computed over the path still matches.
    pub(crate) async fn request(
        &self,
        request: hyper::Request<Full<Bytes>>,
    ) -> Result<hyper::Response<Incoming>, HttpError> {
        let res = match self {
            Self::Direct(c) => c.request(request).await,
            Self::Socks(c) => c.request(request).await,
            Self::PlainDirect(c) => c.request(request).await,
            Self::PlainSocks(c) => c.request(request).await,
        };
        res.map_err(|e| HttpError::Request(error_chain(&e)))
    }
}

/// Render an error with its full `source()` chain (`kind: cause: root`).
/// hyper-util's legacy client `Display` prints only the error *kind*
/// (`client error (Connect)`); the actionable cause — "Connection refused",
/// the TLS failure, the SOCKS refusal — lives down the chain, and dropping it
/// makes a down node, a bad proxy, and a broken TLS setup indistinguishable.
/// (`pub(crate)`: `lib.rs` renders hyper body errors through the same chain.)
pub(crate) fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut rendered = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        rendered.push_str(": ");
        rendered.push_str(&cause.to_string());
        source = cause.source();
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plaintext endpoint selects a client with **no TLS layer**, with or
    /// without a proxy. This is the property that keeps a root-store-less
    /// host able to dial a plaintext daemon: the `https()` builder (and its
    /// `with_native_roots()` load) is never reached on this arm. Routing
    /// `tls = false` back through `Direct`/`Socks` turns this red.
    #[test]
    fn plaintext_endpoint_builds_no_tls_layer() {
        assert!(matches!(
            HttpClient::new(None, false).expect("plain direct"),
            HttpClient::PlainDirect(_)
        ));
        assert!(matches!(
            HttpClient::new(Some("127.0.0.1:9050"), false).expect("plain socks"),
            HttpClient::PlainSocks(_)
        ));
    }

    /// The plaintext client's choice is structural, not advisory: handed an
    /// `https://` request URI it refuses at the connector (`enforce_http`)
    /// rather than opening a cleartext socket to a TLS port. The refusal is
    /// the connector's own scheme check, not a connect failure — the target
    /// port is one nothing listens on, so a client that had tried to dial
    /// would have failed differently.
    #[tokio::test]
    async fn plaintext_client_refuses_a_tls_uri() {
        let client = HttpClient::new(None, false).expect("plain direct");
        let err = client
            .request(
                hyper::Request::post("https://127.0.0.1:1/json_rpc")
                    .body(Full::new(Bytes::new()))
                    .expect("request"),
            )
            .await
            .expect_err("an https URI on a plaintext client must refuse");
        assert!(
            format!("{err}").contains("scheme is not http"),
            "expected the connector's scheme refusal, got: {err}"
        );
    }

    #[test]
    fn socks_connector_parses_and_strips_scheme() {
        // Bare host:port, and each socks5 scheme, all accepted and normalized.
        for input in [
            "127.0.0.1:9050",
            "socks5://127.0.0.1:9050",
            "socks5h://127.0.0.1:9050",
        ] {
            let c = SocksConnector::new(input).expect("valid proxy");
            assert_eq!(&*c.proxy, "127.0.0.1:9050");
        }
        // Bracketed IPv6 keeps its brackets (what a `host:port` dial needs).
        let c = SocksConnector::new("socks5h://[::1]:9050").expect("IPv6 proxy");
        assert_eq!(&*c.proxy, "[::1]:9050");
        // Schemes are case-insensitive (RFC 3986 §3.1).
        for input in ["SOCKS5H://127.0.0.1:9050", "Socks5://127.0.0.1:9050"] {
            let c = SocksConnector::new(input).expect("uppercase scheme");
            assert_eq!(&*c.proxy, "127.0.0.1:9050");
        }
    }

    #[test]
    fn socks_connector_rejects_hostless() {
        assert!(SocksConnector::new("socks5://").is_err());
        assert!(SocksConnector::new("9050").is_err());
        assert!(SocksConnector::new("").is_err());
    }

    /// The accepted surface is exactly `[socks5[h]://]host:port` — every
    /// shape that would only fail later (inside the per-request SOCKS
    /// handshake, with an opaque error) refuses at construction instead.
    #[test]
    fn socks_connector_rejects_malformed_and_unsupported_forms() {
        // A ':' with no port after it — the old `contains(':')` check's
        // false accept — and other port-less forms.
        for input in ["[::1]", "socks5h://[::1]", "socks5://host"] {
            assert!(
                SocksConnector::new(input).is_err(),
                "{input:?} has no port and must refuse"
            );
        }
        // Path / query / fragment / whitespace are not part of host:port.
        for input in [
            "socks5h://host:9050/",
            "socks5h://host:9050?x=1",
            "socks5h://host:9050#f",
            "host:9050 ",
        ] {
            assert!(SocksConnector::new(input).is_err(), "{input:?} must refuse");
        }
        // Non-SOCKS5 schemes refuse loudly instead of being spoken SOCKS5 to.
        for input in [
            "http://127.0.0.1:8080",
            "https://127.0.0.1:8080",
            "socks4://127.0.0.1:9050",
            "socks4a://127.0.0.1:9050",
        ] {
            let err = SocksConnector::new(input).expect_err("unsupported scheme");
            assert!(
                format!("{err}").contains("SOCKS5"),
                "{input:?}: the refusal names what is supported: {err}"
            );
        }
        // SOCKS auth is unsupported; the refusal must never echo the
        // credential the userinfo may carry.
        let err = SocksConnector::new("socks5h://user:hunter2@127.0.0.1:9050")
            .expect_err("userinfo refuses");
        assert!(
            !format!("{err}").contains("hunter2"),
            "the error must not render a credential: {err}"
        );
    }

    /// The crate's central privacy property, pinned on the wire: the
    /// connector hands the proxy the daemon *hostname* (SOCKS5 ATYP=DOMAIN,
    /// 0x03) for the proxy to resolve — never an address it resolved
    /// locally (ATYP 0x01/0x04), which is the exact DNS leak this transport
    /// exists to close. A refactor that resolves before
    /// `Socks5Stream::connect` fails here.
    #[tokio::test]
    async fn socks_connector_sends_the_hostname_for_the_proxy_to_resolve() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let proxy_addr = listener.local_addr().expect("addr");
        // A minimal SOCKS5 acceptor: greet, then capture the CONNECT
        // request's address type and target before replying success.
        let acceptor = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept");
            let mut greeting = [0u8; 2];
            s.read_exact(&mut greeting).await.expect("greeting");
            assert_eq!(greeting[0], 5, "SOCKS version");
            let mut methods = vec![0u8; usize::from(greeting[1])];
            s.read_exact(&mut methods).await.expect("methods");
            s.write_all(&[5, 0]).await.expect("no-auth accepted");

            let mut request = [0u8; 4];
            s.read_exact(&mut request).await.expect("request head");
            assert_eq!(request[1], 1, "CONNECT");
            let atyp = request[3];
            // Read the destination per ATYP so every form terminates: were a
            // regression to send IPv4/IPv6 here, misreading its first address
            // byte as a domain length would block this acceptor — and hang
            // the test — on bytes that never come. Completing the handshake
            // instead lets the main body's `atyp == 3` assert fire with its
            // diagnostic.
            let name = match atyp {
                // DOMAIN: length-prefixed name.
                3 => {
                    let mut len = [0u8; 1];
                    s.read_exact(&mut len).await.expect("domain length");
                    let mut name = vec![0u8; usize::from(len[0])];
                    s.read_exact(&mut name).await.expect("domain");
                    name
                }
                // IPv4 / IPv6: fixed-width address.
                1 | 4 => {
                    let mut addr = vec![0u8; if atyp == 1 { 4 } else { 16 }];
                    s.read_exact(&mut addr).await.expect("address");
                    addr
                }
                other => panic!("unknown SOCKS5 ATYP {other:#04x}"),
            };
            let mut port_bytes = [0u8; 2];
            s.read_exact(&mut port_bytes).await.expect("port");
            // Success, bound to 0.0.0.0:0.
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .expect("reply");
            (atyp, name, u16::from_be_bytes(port_bytes))
        });

        let mut connector =
            SocksConnector::new(&proxy_addr.to_string()).expect("proxy addr parses");
        // `.invalid` (RFC 2606): if anything tried to resolve this locally,
        // the resolution itself would fail — the name must reach the proxy.
        let stream = connector
            .call("http://node.invalid:11029".parse().expect("uri"))
            .await
            .expect("handshake completes");
        drop(stream);

        let (atyp, name, port) = acceptor.await.expect("acceptor");
        assert_eq!(atyp, 3, "ATYP must be DOMAIN (0x03), got {atyp:#04x}");
        assert_eq!(name, b"node.invalid");
        assert_eq!(port, 11029);
    }
}
