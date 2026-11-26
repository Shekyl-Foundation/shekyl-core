// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Read on-chain persona state from the wallet's operator-owned daemon.
//! The wallet's peer onion service and its per-read circuits have separate lifetimes.
//!
//! The reader is the daemon the wallet configured: this computer, or an
//! enrolled channel. A plaintext address is that node only when it is this
//! computer. A channel failure stays a channel failure.

use shekyl_rpc_client::{DaemonFault, Rpc, RpcError};
use shekyl_rpc_transport::{DaemonTarget, DaemonTransport, PlaintextGate};
use std::time::Duration;

/// A chain reader selected by the wallet for its persona.
pub(crate) trait WalletChainReader: Rpc {}

impl WalletChainReader for DaemonTransport {}

/// Why a persona read could not open its daemon.
#[derive(Debug)]
pub(crate) enum ChainOpen {
    /// A plaintext address is not this computer. The address is not carried.
    PlaintextNotLocal,
    /// The enrolled channel, or another classified daemon fault.
    Fault(DaemonFault),
    /// The plaintext URL is not a base this transport can dial. The sentence
    /// is the transport's, which does not echo credentials.
    Unusable(RpcError),
}

impl std::fmt::Display for ChainOpen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PlaintextNotLocal => {
                f.write_str(shekyl_rpc_transport::PLAINTEXT_NOT_THIS_COMPUTER)
            }
            Self::Fault(fault) => fault.fmt(f),
            Self::Unusable(error) => error.fmt(f),
        }
    }
}

impl ChainOpen {
    fn from_channel(fault: shekyl_rpc_transport::channel::ChannelFault) -> Self {
        Self::Fault(RpcError::from(fault).fault())
    }
}

/// Open the daemon a persona read uses.
///
/// An enrolled channel and this computer pass through [`DaemonTarget::connect`].
/// A plaintext address must be this computer; the refusal does not name the
/// address. A channel fault is [`DaemonFault::Channel`], not a loopback refusal.
///
/// # Errors
///
/// [`ChainOpen`].
pub(crate) async fn open_chain_reader(
    daemon: &DaemonTarget,
    request_timeout: Duration,
) -> Result<DaemonTransport, ChainOpen> {
    let resolved = daemon.resolve().map_err(ChainOpen::from_channel)?;
    resolved
        .require_this_computer()
        .map_err(|gate| match gate {
            PlaintextGate::NotThisComputer => ChainOpen::PlaintextNotLocal,
            PlaintextGate::Unusable(error) => ChainOpen::Unusable(error),
        })?;
    resolved.open(Some(request_timeout)).await.map_err(|error| {
        let fault = error.fault();
        match fault {
            DaemonFault::Channel(_) => ChainOpen::Fault(fault),
            _ => ChainOpen::Unusable(error),
        }
    })
}

#[cfg(test)]
mod tests {
    use shekyl_rpc_client::Rpc;

    use super::*;

    /// A plaintext stand-in for this computer is loopback `http` with no
    /// proxy. A refusal never echoes the address or a credential. A query
    /// is the transport's shape check, not a credential check.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_plaintext_persona_reader_accepts_only_this_computer() {
        for ok in [
            "http://127.0.0.1:48081",
            "http://localhost:48081",
            "http://[::1]:48081",
            "http://127.0.0.1:48081/json_rpc",
            "http://127.0.0.2:48081",
        ] {
            open_chain_reader(
                &shekyl_rpc_transport::DaemonTarget::fixture_address(ok),
                Duration::from_secs(1),
            )
            .await
            .unwrap_or_else(|e| panic!("loopback URL {ok} must construct: {e}"));
        }

        for not_credentials in [
            "http://127.0.0.1:48081/json_rpc?tag=user@host",
            "http://127.0.0.1:48081?tag=user@host",
            "http://localhost:48081#frag@ment",
        ] {
            let err = open_chain_reader(
                &shekyl_rpc_transport::DaemonTarget::fixture_address(not_credentials),
                Duration::from_secs(1),
            )
            .await
            .expect_err("a query/fragment URL is not a joinable base");
            let rendered = err.to_string();
            assert!(
                rendered.contains("query or fragment"),
                "{not_credentials}: expected the base-URL shape refusal, got {err:?}"
            );
            assert!(
                !rendered.contains("credentials"),
                "{not_credentials}: the '@' must not be misread as credentials: {err:?}"
            );
            assert!(
                !matches!(err, ChainOpen::PlaintextNotLocal),
                "{not_credentials}: a shape error is not the this-computer refusal"
            );
        }

        for (bad, why) in [
            ("http://192.168.1.10:48081", "LAN host"),
            ("http://example.com:48081", "remote host"),
            ("https://127.0.0.1:48081", "https scheme"),
            ("http://127.0.0.1.evil.test:48081", "loopback-prefixed host"),
        ] {
            let err = open_chain_reader(
                &shekyl_rpc_transport::DaemonTarget::fixture_address(bad),
                Duration::from_secs(1),
            )
            .await
            .expect_err(why);
            assert!(
                matches!(err, ChainOpen::PlaintextNotLocal),
                "{why}: {err:?}"
            );
            assert!(
                !err.to_string().contains(bad),
                "{why}: the refusal must not repeat the address: {err}"
            );
        }

        let malformed = open_chain_reader(
            &shekyl_rpc_transport::DaemonTarget::fixture_address("http://[::1:48081"),
            Duration::from_secs(1),
        )
        .await
        .expect_err("malformed IPv6 bracket");
        assert!(
            matches!(malformed, ChainOpen::Unusable(_)),
            "a URL that does not parse is the transport's shape error: {malformed:?}"
        );

        let err = open_chain_reader(
            &shekyl_rpc_transport::DaemonTarget::fixture_address(
                "http://user:hunter2@127.0.0.1:48081",
            ),
            Duration::from_secs(1),
        )
        .await
        .expect_err("in-URL credentials");
        assert!(
            !err.to_string().contains("hunter2"),
            "a refused URL's error must never render the password"
        );
    }

    /// Opening a loopback plaintext reader does not dial. The post does.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_loopback_reader_post_reaches_the_transport() {
        let rpc = open_chain_reader(
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
