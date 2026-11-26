// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Read on-chain persona state from the wallet's operator-owned daemon.
//! The wallet's peer onion service and its per-read circuits have separate lifetimes.

use shekyl_rpc_client::{Rpc, RpcError};
use shekyl_rpc_transport::HttpRpc;
use std::future::Future;
use std::time::Duration;

/// A chain reader selected by the wallet for its persona.
pub(crate) trait WalletChainReader: Rpc {}

#[derive(Clone, Debug)]
pub(crate) struct WalletNodeRpc {
    inner: shekyl_rpc_transport::DaemonTransport,
}

impl WalletChainReader for WalletNodeRpc {}

impl WalletNodeRpc {
    /// Open the wallet’s operator-owned daemon. A remote channel authenticates
    /// its bundle independently of the persona’s Tor service and peer circuits.
    ///
    /// "This computer" is the owner's leg of the node this account runs
    /// (RT-W10 step 5): local by construction. A named address must be
    /// `http://` + a loopback host (`127.0.0.1`, `localhost`, or `[::1]`) +
    /// port, through no proxy. `https` is pointless on loopback and rejected
    /// to keep the accepted-input surface minimal; credentials
    /// (`user:pass@`) are rejected because the underlying digest-auth path
    /// would issue a pre-flight request from inside a constructor documented
    /// as side-effect-bounded.
    pub(crate) async fn new(
        daemon: &shekyl_rpc_transport::DaemonTarget,
        request_timeout: Duration,
    ) -> Result<Self, RpcError> {
        let url = match daemon {
            shekyl_rpc_transport::DaemonTarget::Owner(_)
            | shekyl_rpc_transport::DaemonTarget::ThisComputer { .. }
            | shekyl_rpc_transport::DaemonTarget::Channel { .. } => {
                return Ok(Self {
                    inner: daemon.connect(Some(request_timeout)).await?,
                })
            }
            shekyl_rpc_transport::DaemonTarget::HttpFixture { proxy: Some(_), .. } => {
                return Err(RpcError::ConnectionError(
                    "local-posture transport refuses a proxied daemon address".to_string(),
                ))
            }
            shekyl_rpc_transport::DaemonTarget::HttpFixture {
                url, proxy: None, ..
            } => url.as_str(),
        };
        let Some(host_port) = url.strip_prefix("http://") else {
            return Err(RpcError::ConnectionError(
                "local-posture transport requires an http:// loopback URL".to_string(),
            ));
        };
        // The authority ends at the first of `/`, `?`, or `#` (RFC 3986) —
        // terminating on `/` alone would fold a path-less query or fragment
        // into the authority and misread its content as host or credentials.
        let authority = host_port
            .split_once(['/', '?', '#'])
            .map_or(host_port, |(hp, _)| hp);
        // Refuse credentials before any host parse so a rejected URL's
        // error message can never render a password. Scoped to the
        // AUTHORITY: an '@' in the path, query, or fragment is ordinary URL
        // content (e.g. `?tag=user@host`), and refusing on it would assert
        // credentials that are not there.
        if authority.contains('@') {
            return Err(RpcError::ConnectionError(
                "local-posture transport refuses in-URL credentials".to_string(),
            ));
        }
        let host = if let Some(bracketed) = authority.strip_prefix('[') {
            bracketed.split_once(']').map_or("", |(h, _)| h)
        } else {
            authority.rsplit_once(':').map_or(authority, |(h, _)| h)
        };
        // The loopback pin proper: the one loopback predicate the tree has
        // (`localhost`, and any literal the listen side classifies as
        // loopback, IPv4-mapped spellings included) — a literal allowlist
        // would wrongly refuse legitimate loopback forms like `127.0.0.2`.
        if !shekyl_rpc_transport::network_posture::is_loopback_host(host) {
            return Err(RpcError::ConnectionError(format!(
                "local-posture transport refuses non-loopback host {host:?} \
                 (the shared-network-identity argument only holds on the \
                 wallet's own node)"
            )));
        }
        Ok(Self {
            inner: HttpRpc::with_custom_timeout(url.to_owned(), request_timeout)
                .await?
                .into(),
        })
    }
}

impl Rpc for WalletNodeRpc {
    fn post(
        &self,
        route: &str,
        body: Vec<u8>,
    ) -> impl Send + Future<Output = Result<Vec<u8>, RpcError>> {
        self.inner.post(route, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The local-posture constructor is the structural loopback pin: every
    /// accepted form is genuinely loopback, every refusal is loud, and a
    /// refused URL's error never echoes credentials.
    #[tokio::test(flavor = "multi_thread")]
    async fn local_node_rpc_accepts_only_loopback() {
        for ok in [
            "http://127.0.0.1:48081",
            "http://localhost:48081",
            "http://[::1]:48081",
            "http://127.0.0.1:48081/json_rpc",
            // Loopback is the /8, not one literal address.
            "http://127.0.0.2:48081",
        ] {
            WalletNodeRpc::new(
                &shekyl_rpc_transport::DaemonTarget::fixture_address(ok),
                Duration::from_secs(1),
            )
            .await
            .unwrap_or_else(|e| panic!("loopback URL {ok} must construct: {e}"));
        }

        // '@' beyond the authority is URL content, not credentials — the
        // credential refusal is scoped to the authority. These forms now
        // refuse at the transport's base-URL shape check (a query/fragment
        // daemon URL was never a joinable base), and the pinned property is
        // that the refusal IS that shape check: never the credential
        // refusal, and never an echo of the '@' content.
        for not_credentials in [
            "http://127.0.0.1:48081/json_rpc?tag=user@host",
            "http://127.0.0.1:48081?tag=user@host",
            "http://localhost:48081#frag@ment",
        ] {
            let err = WalletNodeRpc::new(
                &shekyl_rpc_transport::DaemonTarget::fixture_address(not_credentials),
                Duration::from_secs(1),
            )
            .await
            .expect_err("a query/fragment URL is not a joinable base");
            let rendered = format!("{err}");
            assert!(
                rendered.contains("query or fragment"),
                "{not_credentials}: expected the base-URL shape refusal, got {err:?}"
            );
            assert!(
                !rendered.contains("credentials"),
                "{not_credentials}: the '@' must not be misread as credentials: {err:?}"
            );
        }

        for (bad, why) in [
            ("http://192.168.1.10:48081", "LAN host"),
            ("http://example.com:48081", "remote host"),
            ("https://127.0.0.1:48081", "https scheme"),
            ("http://[::1:48081", "malformed IPv6 bracket"),
            ("http://127.0.0.1.evil.test:48081", "loopback-prefixed host"),
        ] {
            let err = WalletNodeRpc::new(
                &shekyl_rpc_transport::DaemonTarget::fixture_address(bad),
                Duration::from_secs(1),
            )
            .await
            .expect_err(why);
            assert!(
                matches!(err, RpcError::ConnectionError(_)),
                "{why}: {err:?}"
            );
        }

        let err = WalletNodeRpc::new(
            &shekyl_rpc_transport::DaemonTarget::fixture_address(
                "http://user:hunter2@127.0.0.1:48081",
            ),
            Duration::from_secs(1),
        )
        .await
        .expect_err("in-URL credentials");
        assert!(
            !format!("{err}").contains("hunter2"),
            "a refused URL's error must never render the password"
        );
    }

    /// Construction against an unreachable loopback port succeeds (no
    /// connect attempt in the constructor) and the delegated `post` surfaces
    /// the failure — exercising the [`Rpc`] impl without a live daemon.
    #[tokio::test(flavor = "multi_thread")]
    async fn local_node_rpc_post_delegates_to_inner_transport() {
        let rpc = WalletNodeRpc::new(
            &shekyl_rpc_transport::DaemonTarget::fixture_address("http://127.0.0.1:1"),
            Duration::from_secs(1),
        )
        .await
        .expect("constructor performs no connect attempt");
        rpc.post("json_rpc", b"{}".to_vec())
            .await
            .expect_err("port 1 refuses; the delegated post must surface it");
    }
}
