// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a wallet is configured to reach, read once and opened under one bound.
//!
//! [`DaemonTarget`] is the configuration. [`DaemonTarget::resolve`] reads the
//! bundle, the account key, and a local service record, and produces a
//! [`ResolvedDaemon`] that no longer carries a clock. Two jobs open it, and
//! each has its own call. [`ResolvedDaemon::open`] is a wallet session's
//! transport and dials nothing, so a wallet is created and opened while its
//! node is down, on every transport. [`ResolvedDaemon::admit`] is a chain
//! read's transport: an enrolled channel is admitted before it returns, so a
//! key the node does not admit fails as that read. Both apply the caller's
//! [`std::time::Duration`] to the owner socket, the enrolled channel, and
//! plaintext alike. A caller that names no bound uses [`local::CALL_WITHIN`].

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

/// The enrolled channel for a local service, or `None` when the owner
/// rendezvous is the door.
///
/// The owner socket wins when its path exists: the owner dial verifies the
/// peer, including a stale socket. A service record is the door only when
/// that path is absent. The record's channel must be loopback. An unreadable
/// record is a refusal, so a caller cannot fall through to another transport.
///
/// # Errors
///
/// A malformed or unreadable service record, a channel that is not loopback,
/// an unusable bundle, or an account identity that needs enrollment.
pub fn service_channel(
    local: &local::LocalTarget,
    network: shekyl_network::Network,
    key_file: Option<&std::path::Path>,
) -> Result<Option<channel::ChannelTarget>, channel::ChannelFault> {
    if let Some(owner) = local.path() {
        match std::fs::symlink_metadata(owner) {
            Ok(_) => return Ok(None),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(channel::ChannelFault::Local(format!(
                    "cannot inspect the owner rendezvous {}: {error}",
                    owner.display()
                )))
            }
        }
    }
    let Some(record) = local.service()? else {
        return Ok(None);
    };
    let service = record.channel.ok_or_else(|| {
        channel::ChannelFault::Local(
            "the local service has no channel listener. Set rpc-listen on the node to a loopback address"
                .into(),
        )
    })?;
    if !crate::listen::is_loopback_ip(service.address.ip()) {
        return Err(channel::ChannelFault::Local(
            "the service record must name a loopback channel".into(),
        ));
    }
    let bundle = channel::bundle_from_bytes(&service.bundle).ok_or_else(|| {
        channel::ChannelFault::Local("the local service published an invalid channel bundle".into())
    })?;
    channel::account_target(
        network,
        channel::Leg::ip(service.address, None),
        bundle,
        key_file,
    )
    .map(Some)
}

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
                match service_channel(&local, *network, key_file.as_deref())? {
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

    /// This target's transport for a wallet session ([`ResolvedDaemon::open`]).
    /// Each call is bounded by `timeout`, or by [`local::CALL_WITHIN`] when
    /// `None`. The same bound reaches the owner socket, the enrolled channel,
    /// and plaintext.
    ///
    /// Nothing dials here. A node that is not running, a failed peer check,
    /// and a key the node has not enrolled are the first call's error, with
    /// that fault's own remedy.
    ///
    /// # Errors
    ///
    /// A target that does not resolve (an unusable bundle or key, a service
    /// record that cannot be read), or a named address this transport cannot
    /// dial (see [`HttpRpc::with_proxy`]).
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

    /// A wallet session's transport. `within` bounds every call on the owner
    /// socket, the channel, and plaintext.
    ///
    /// Nothing dials, on any transport: an enrolled channel admits its key on
    /// the first call ([`WalletChannel::new`]), as the owner socket and
    /// plaintext dial on theirs. So a wallet is created, opened, and restored
    /// while its node is down, and a fault reaches the call that needed the
    /// node.
    ///
    /// # Errors
    ///
    /// [`RpcError`] from building the plaintext client.
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

    /// A chain read's transport. As [`Self::open`], except that an enrolled
    /// channel is admitted before this returns ([`WalletChannel::admit`]),
    /// under `within`: the read is the call, so a key that is not enrolled, a
    /// bundle that is not this node, and a leg that does not answer fail as
    /// this read, with the channel fault's own remedy. The owner socket and
    /// plaintext have no admission and open as [`Self::open`] does.
    ///
    /// # Errors
    ///
    /// [`RpcError`] from building the plaintext client, or a
    /// [`channel::ChannelFault`] from the admission, carried as
    /// [`RpcError::Channel`].
    pub async fn admit(self, within: Duration) -> Result<DaemonTransport, RpcError> {
        match self {
            Self::Channel(target) => Ok(DaemonTransport::Channel(
                WalletChannel::admit(*target, within).await?,
            )),
            session => session.open(within).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_network::Network;
    use shekyl_rpc_rendezvous::Instance;

    /// A wallet session opens while its node is down, on the channel as on
    /// the owner socket and plaintext; a chain read admits the channel first,
    /// so the leg that does not answer is that read's fault. Red edit: admit
    /// in [`ResolvedDaemon::open`], and a wallet with a channel endpoint can
    /// no longer be created or opened while its node is down.
    #[tokio::test]
    async fn a_session_opens_without_its_node_and_a_chain_read_admits() {
        use shekyl_rpc_channel::handshake::StaticKeypair;
        // A loopback port nothing listens on once the listener is dropped.
        let silent = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("a free loopback port");
        let target = channel::ChannelTarget::new(
            Network::Regtest.network_id(),
            StaticKeypair::generate()
                .expect("a daemon key")
                .public()
                .clone(),
            StaticKeypair::generate().expect("a client key"),
            channel::Leg::ip(silent, None),
        );
        let within = Duration::from_secs(5);

        let session = ResolvedDaemon::Channel(Box::new(target.clone()))
            .open(within)
            .await;
        assert!(
            matches!(session, Ok(DaemonTransport::Channel(_))),
            "a session does not dial"
        );

        let read = ResolvedDaemon::Channel(Box::new(target))
            .admit(within)
            .await;
        assert!(
            matches!(read, Err(RpcError::Channel(..))),
            "a chain read admits, and the silent leg is its fault"
        );
    }

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
