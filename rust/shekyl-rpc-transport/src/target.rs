// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a wallet is configured to reach, read once and opened under one bound.
//!
//! [`DaemonTarget`] is the configuration. [`DaemonTarget::resolve`] reads the
//! bundle, the account key, and a local service record, and produces a
//! [`ResolvedDaemon`] that no longer carries a clock. [`ResolvedDaemon::open`]
//! applies the caller's [`std::time::Duration`] to the owner socket, the
//! enrolled channel, and plaintext alike. A caller that names no bound uses
//! [`local::CALL_WITHIN`].

use std::path::PathBuf;
use std::time::Duration;

use shekyl_rpc_client::RpcError;

use crate::channel::{self, WalletChannel};
use crate::http_client::TransportTls;
use crate::local::{self, LocalRpc};
use crate::{parse_endpoint, redacted_endpoint, DaemonTransport, HttpRpc};

/// What a wallet is configured to reach (`RPC_CHANNEL.md` RT-15): "this
/// computer" when no `daemon-endpoint` is given, otherwise the enrolled node.
/// [`Self::resolve`] is the one reading of that choice. [`Self::connect`]
/// opens it under one call bound.
#[derive(Clone)]
pub enum DaemonTarget {
    /// An already resolved owner rendezvous. A harness supplies its instance here.
    Owner(local::LocalTarget),
    /// An explicitly named, authenticated node.
    Channel {
        /// The wallet network.
        network: shekyl_network::Network,
        /// The endpoint and operator-provided bundle.
        node: channel::RemoteNode,
        /// Account key file, or the account-wide default when unset.
        key_file: Option<PathBuf>,
    },
    /// The node this account runs on this computer, over its owner's leg
    /// ([`local::LocalTarget::this_computer`]). The network is all a wallet
    /// names: where this account's node and the machine's service keep
    /// their rendezvous is this platform's to say, never the wallet's.
    ThisComputer {
        /// The wallet's network: which node's rendezvous.
        network: shekyl_network::Network,
        /// Account key file used when the local node runs as a service.
        key_file: Option<PathBuf>,
    },
    /// Plaintext HTTP. Wallet binaries do not build this: a named node is a
    /// [`Self::Channel`]. The desktop wallet still does, until its channel
    /// migration, and tests use it as a stand-in for this computer.
    Address {
        /// The daemon's base URL; may carry digest credentials.
        url: String,
        /// The SOCKS5h proxy; `None` is direct.
        proxy: Option<String>,
    },
}

/// Why a plaintext address is not a persona's node.
///
/// A persona read uses this computer or an enrolled channel. A plaintext
/// address is accepted only when it is this computer: loopback, direct, and
/// `http`. The refusal names that fact and never the address.
#[derive(Clone, Debug)]
pub enum PlaintextGate {
    /// The address is not this computer: another host, a proxy, or `https`.
    NotThisComputer,
    /// The address is not a base URL this transport can dial.
    Unusable(RpcError),
}

/// The target [`DaemonTarget::resolve`] produces. It names a door and carries
/// no call bound: [`Self::open`] takes the bound, so every door uses it.
pub enum ResolvedDaemon {
    /// An enrolled channel. The target is boxed because it holds the daemon's public bundle.
    Channel(Box<channel::ChannelTarget>),
    /// The owner's socket or pipe.
    Owner(local::LocalTarget),
    /// Plaintext HTTP, as given.
    Address {
        /// The daemon's base URL.
        url: String,
        /// The SOCKS5h proxy; `None` is direct.
        proxy: Option<String>,
    },
}

/// Manual: an address may carry digest credentials in its authority, so it
/// renders through [`redacted_endpoint`], as the proxy does.
impl std::fmt::Debug for DaemonTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Owner(target) => target.fmt(f),
            Self::Channel {
                network,
                node,
                key_file,
            } => f
                .debug_struct("Channel")
                .field("network", network)
                .field("node", node)
                .field("key_file", key_file)
                .finish(),
            Self::ThisComputer { network, key_file } => f
                .debug_struct("ThisComputer")
                .field("network", network)
                .field("key_file", key_file)
                .finish(),
            Self::Address { url, proxy } => f
                .debug_struct("Address")
                .field("url", &redacted_endpoint(url))
                .field("proxy", &proxy.as_deref().map(redacted_endpoint))
                .finish(),
        }
    }
}

/// The sentence a persona read uses when a plaintext address is not this
/// computer. It names no host and no credential.
pub const PLAINTEXT_NOT_THIS_COMPUTER: &str = "This reads your own node. A plaintext address on another computer is not that node. Leave the daemon endpoint unset for this computer, or name the node with its bundle.";

impl DaemonTarget {
    /// A plaintext daemon URL. The desktop wallet still calls this for an
    /// address a person typed. Wallet binaries build a [`Self::Channel`].
    #[must_use]
    pub fn address(url: impl Into<String>) -> Self {
        Self::Address {
            url: url.into(),
            proxy: None,
        }
    }

    /// Construct a direct HTTP peer in a test.
    #[cfg(any(test, feature = "test-override"))]
    #[must_use]
    pub fn fixture_address(url: impl Into<String>) -> Self {
        Self::address(url)
    }

    /// Construct an HTTP test peer with an explicit route.
    #[cfg(any(test, feature = "test-override"))]
    #[must_use]
    pub fn fixture_with_proxy(url: String, proxy: Option<String>) -> Self {
        Self::Address { url, proxy }
    }

    /// Read this target once. A channel or a local service resolves here,
    /// before any dial. An owner socket and a plaintext address do not.
    ///
    /// # Errors
    ///
    /// [`channel::ChannelFault`]: the account key, the bundle, or the local
    /// service record.
    pub fn resolve(&self) -> Result<ResolvedDaemon, channel::ChannelFault> {
        match self {
            Self::Channel {
                network,
                node,
                key_file,
            } => Ok(ResolvedDaemon::Channel(Box::new(channel::account_target(
                *network,
                node.leg.clone(),
                node.bundle()?,
                key_file.as_deref(),
            )?))),
            Self::ThisComputer { network, key_file } => {
                let local = local::LocalTarget::this_computer(*network);
                match local.wallet_channel(*network, key_file.as_deref())? {
                    Some(target) => Ok(ResolvedDaemon::Channel(Box::new(target))),
                    None => Ok(ResolvedDaemon::Owner(local)),
                }
            }
            Self::Owner(target) => Ok(ResolvedDaemon::Owner(target.clone())),
            Self::Address { url, proxy } => Ok(ResolvedDaemon::Address {
                url: url.clone(),
                proxy: proxy.clone(),
            }),
        }
    }

    /// This target's transport. Each call is bounded by `timeout`, or by
    /// [`local::CALL_WITHIN`] when `None`. The same bound reaches the owner
    /// socket, the enrolled channel, and plaintext.
    ///
    /// # Errors
    ///
    /// A named address this transport cannot dial (see
    /// [`HttpRpc::with_proxy`]). "This computer" does not fail here: a node
    /// that is not running, a service, or a failed peer check is the first
    /// call's error. An enrolled channel that is not yet enrolled fails here,
    /// as [`channel::ChannelFault`].
    pub async fn connect(&self, timeout: Option<Duration>) -> Result<DaemonTransport, RpcError> {
        self.resolve()?
            .open(timeout.unwrap_or(local::CALL_WITHIN))
            .await
    }
}

impl ResolvedDaemon {
    /// A plaintext address may stand in for this computer only when it is
    /// loopback, direct, and `http`. A proxy, credentials, or `https` is
    /// [`PlaintextGate::NotThisComputer`]. An enrolled channel and the
    /// owner's socket are the operator's node and pass: the gate refuses
    /// foreign plaintext, not a named channel.
    ///
    /// # Errors
    ///
    /// [`PlaintextGate::NotThisComputer`] or [`PlaintextGate::Unusable`].
    pub fn refuse_foreign_plaintext(&self) -> Result<(), PlaintextGate> {
        let Self::Address { url, proxy } = self else {
            return Ok(());
        };
        if proxy.is_some() {
            return Err(PlaintextGate::NotThisComputer);
        }
        let parsed = parse_endpoint(url.clone()).map_err(PlaintextGate::Unusable)?;
        if parsed.credentials.is_some() || !matches!(parsed.tls, TransportTls::Off) {
            return Err(PlaintextGate::NotThisComputer);
        }
        if crate::network_posture::is_loopback_host(crate::network_posture::host_of(url)) {
            Ok(())
        } else {
            Err(PlaintextGate::NotThisComputer)
        }
    }

    /// Open the resolved target. `within` bounds every subsequent call on
    /// the owner socket, the channel, and plaintext.
    ///
    /// # Errors
    ///
    /// [`RpcError`] from the plaintext client, or a [`channel::ChannelFault`]
    /// carried as [`RpcError::Channel`].
    pub async fn open(self, within: Duration) -> Result<DaemonTransport, RpcError> {
        match self {
            Self::Channel(target) => Ok(DaemonTransport::Channel(WalletChannel::new(
                *target, within,
            ))),
            Self::Owner(target) => Ok(DaemonTransport::ThisComputer(LocalRpc::within(
                target, within,
            ))),
            Self::Address { url, proxy } => Ok(DaemonTransport::Address(
                HttpRpc::with_options(url, within, proxy)
                    .await
                    .map_err(RpcError::from)?,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_network::Network;
    use shekyl_rpc_rendezvous::Instance;

    /// The caller's bound is the owner socket's bound. `None` is
    /// [`local::CALL_WITHIN`], the same default plaintext and the channel use.
    #[tokio::test]
    async fn the_owner_socket_opens_under_the_callers_bound() {
        let dir = tempfile::tempdir().unwrap();
        let target = DaemonTarget::Owner(local::LocalTarget::test_override(
            Network::Regtest,
            &Instance::Default,
            Some(dir.path()),
            None,
        ));
        let asked = Duration::from_secs(10);
        let rpc = target.connect(Some(asked)).await.expect("no dial");
        let DaemonTransport::ThisComputer(local) = rpc else {
            panic!("an owner target opens the owner socket");
        };
        assert_eq!(local.bound(), asked);

        let rpc = target.connect(None).await.expect("no dial");
        let DaemonTransport::ThisComputer(local) = rpc else {
            panic!("an owner target opens the owner socket");
        };
        assert_eq!(local.bound(), local::CALL_WITHIN);
    }
}
