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
    /// The `--proxy` value was not a usable `host:port` (`scheme://` stripped).
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
#[derive(Clone)]
pub(crate) struct SocksConnector {
    /// `host:port` of the SOCKS proxy (scheme stripped).
    proxy: Arc<str>,
}

impl SocksConnector {
    fn new(proxy: &str) -> Result<Self, HttpError> {
        // Accept `socks5h://h:p`, `socks5://h:p`, or a bare `h:p`; the scheme is
        // advisory here — this connector is *always* remote-resolving, so a
        // `socks5://` (local-resolving) label does not weaken it.
        let hostport = proxy.split_once("://").map_or(proxy, |(_, rest)| rest);
        if hostport.is_empty() || !hostport.contains(':') {
            return Err(HttpError::InvalidProxy(format!(
                "expected host:port, got {proxy:?}"
            )));
        }
        Ok(Self {
            proxy: hostport.into(),
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
#[derive(Clone)]
pub(crate) enum HttpClient {
    /// No proxy: connect directly, resolving DNS locally.
    Direct(HyperClient<HttpsConnector<HttpConnector>, Full<Bytes>>),
    /// Through a SOCKS5h proxy: the proxy resolves DNS.
    Socks(HyperClient<HttpsConnector<SocksConnector>, Full<Bytes>>),
}

impl std::fmt::Debug for HttpClient {
    // Manual (not derived) so `SimpleRequestRpc: Debug` does not hinge on the
    // hyper client's Debug bounds; the transport mode is all that's useful here.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Direct(_) => "HttpClient::Direct",
            Self::Socks(_) => "HttpClient::Socks",
        })
    }
}

impl HttpClient {
    /// Build the client, selecting the SOCKS path when `proxy` is `Some`.
    pub(crate) fn new(proxy: Option<&str>) -> Result<Self, HttpError> {
        // `Builder::pool_idle_timeout` returns `&mut Builder`, so the whole
        // chain must land in one statement (ending in the owning `.build()`).
        match proxy {
            None => Ok(Self::Direct(
                HyperClient::builder(TokioExecutor::new())
                    .pool_idle_timeout(Duration::from_secs(60))
                    .build(https(http_connector())?),
            )),
            Some(p) => Ok(Self::Socks(
                HyperClient::builder(TokioExecutor::new())
                    .pool_idle_timeout(Duration::from_secs(60))
                    .build(https(SocksConnector::new(p)?)?),
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
        };
        res.map_err(|e| HttpError::Request(format!("{e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks_connector_parses_and_strips_scheme() {
        // Bare host:port, and each socks scheme, all accepted and normalized.
        for input in [
            "127.0.0.1:9050",
            "socks5://127.0.0.1:9050",
            "socks5h://127.0.0.1:9050",
        ] {
            let c = SocksConnector::new(input).expect("valid proxy");
            assert_eq!(&*c.proxy, "127.0.0.1:9050");
        }
    }

    #[test]
    fn socks_connector_rejects_hostless() {
        assert!(SocksConnector::new("socks5://").is_err());
        assert!(SocksConnector::new("9050").is_err());
        assert!(SocksConnector::new("").is_err());
    }
}
