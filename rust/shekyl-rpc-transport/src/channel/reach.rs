// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A grammar peer as the route a client dials.
//!
//! An IP may be direct or through a SOCKS proxy. An onion has no direct
//! route, so the proxy is part of the value: an onion without one is not a
//! route. The plaintext HTTP base and the channel [`Leg`] are both read off
//! this value. A caller does not format either again.

use std::net::SocketAddr;

use shekyl_options::{Code, Diagnostic, PeerEndpoint, Source};

use super::Leg;

/// `socks5h://` for `addr`. The proxy resolves names.
#[must_use]
pub fn socks5h_url(addr: SocketAddr) -> String {
    format!("socks5h://{addr}")
}

/// Why [`PeerRoute::reach`] refused a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerRouteError {
    /// An onion was named and no SOCKS proxy was.
    OnionNeedsProxy,
}

impl PeerRouteError {
    /// The grammar refusal. `option` is the peer row (`daemon-endpoint`,
    /// `wallet-rpc-endpoint`). Every table that reaches another computer
    /// names the proxy `daemon-socks`.
    #[must_use]
    pub fn diagnostic(self, option: &str) -> Diagnostic {
        match self {
            Self::OnionNeedsProxy => Diagnostic::new(Code::ValueRequires, Source::Cli)
                .option(option)
                .param("requires", "daemon-socks, to reach an onion"),
        }
    }
}

/// A peer a client can dial. An onion's proxy is part of the value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerRoute {
    /// A literal IP, directly or through `socks`.
    Ip {
        /// The address.
        addr: SocketAddr,
        /// The SOCKS proxy, when the route uses one.
        socks: Option<SocketAddr>,
    },
    /// A v3 onion, reached through `socks`.
    Onion {
        /// The onion host, without a port.
        host: String,
        /// The virtual port.
        port: u16,
        /// The SOCKS proxy, which resolves the name.
        socks: SocketAddr,
    },
}

impl PeerRoute {
    /// The route to `peer`. `socks` is kept for an IP and required for an onion.
    ///
    /// # Errors
    ///
    /// [`PeerRouteError::OnionNeedsProxy`] when `peer` is an onion and
    /// `socks` is unset.
    pub fn reach(peer: &PeerEndpoint, socks: Option<SocketAddr>) -> Result<Self, PeerRouteError> {
        match peer {
            PeerEndpoint::Ip(addr) => Ok(Self::Ip { addr: *addr, socks }),
            PeerEndpoint::Onion { host, port } => {
                let Some(socks) = socks else {
                    return Err(PeerRouteError::OnionNeedsProxy);
                };
                Ok(Self::Onion {
                    host: host.clone(),
                    port: *port,
                    socks,
                })
            }
        }
    }

    /// The channel leg for this route.
    #[must_use]
    pub fn leg(&self) -> Leg {
        match self {
            Self::Ip { addr, socks } => Leg::ip(*addr, *socks),
            Self::Onion { host, port, socks } => Leg::onion(host.clone(), *port, *socks),
        }
    }

    /// `http://` plus the address. Plaintext HTTP. The channel is
    /// [`Self::leg`], not this URL.
    #[must_use]
    pub fn http_base(&self) -> String {
        match self {
            Self::Ip { addr, .. } => format!("http://{addr}"),
            Self::Onion { host, port, .. } => format!("http://{host}:{port}"),
        }
    }

    /// `socks5h://` for this route's proxy.
    #[must_use]
    pub fn socks_url(&self) -> Option<String> {
        self.socks_addr().map(socks5h_url)
    }

    /// The daemon target for this route: the HTTP base and the proxy URL.
    #[must_use]
    pub fn daemon_target(&self) -> crate::DaemonTarget {
        crate::DaemonTarget::Address {
            url: self.http_base(),
            proxy: self.socks_url(),
        }
    }

    fn socks_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Ip { socks, .. } => *socks,
            Self::Onion { socks, .. } => Some(*socks),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socks() -> SocketAddr {
        "127.0.0.1:9050".parse().expect("a proxy")
    }

    /// An IP is direct or proxied. An onion exists only with the proxy, and
    /// the HTTP base and the leg are that one route. Red edit: accept the
    /// onion with no proxy, and `missing` is `Ok`.
    #[test]
    fn an_onion_is_a_route_only_through_the_proxy() {
        let ip = PeerEndpoint::Ip("203.0.113.5:29501".parse().expect("an address"));
        let direct = PeerRoute::reach(&ip, None).expect("an IP needs no proxy");
        assert_eq!(direct.http_base(), "http://203.0.113.5:29501");
        assert!(direct.socks_url().is_none());
        assert!(matches!(direct.leg(), Leg::Ip { proxy: None, .. }));

        let proxied = PeerRoute::reach(&ip, Some(socks())).expect("an IP keeps a proxy");
        assert_eq!(
            proxied.socks_url().as_deref(),
            Some("socks5h://127.0.0.1:9050")
        );
        match proxied.daemon_target() {
            crate::DaemonTarget::Address { url, proxy } => {
                assert_eq!(url, "http://203.0.113.5:29501");
                assert_eq!(proxy.as_deref(), Some("socks5h://127.0.0.1:9050"));
            }
            other => panic!("an IP route is an address, got {other:?}"),
        }

        let onion = PeerEndpoint::Onion {
            host: "gj56z5xbxm7mi6iucpe3apa3raxkkiwub4vbc2who5sm6slpzikuqiyd.onion".to_owned(),
            port: 14021,
        };
        let missing = PeerRoute::reach(&onion, None).expect_err("an onion needs a proxy");
        assert!(missing
            .diagnostic("daemon-endpoint")
            .render()
            .contains("daemon-socks"));
        let reached = PeerRoute::reach(&onion, Some(socks())).expect("through the proxy");
        assert_eq!(
            reached.http_base(),
            "http://gj56z5xbxm7mi6iucpe3apa3raxkkiwub4vbc2who5sm6slpzikuqiyd.onion:14021"
        );
        assert!(matches!(reached.leg(), Leg::Onion { .. }));
    }
}
