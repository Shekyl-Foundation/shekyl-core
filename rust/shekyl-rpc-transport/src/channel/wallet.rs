// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The wallet's enrolled connection to its operator's node.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use shekyl_network::Network;
use shekyl_rpc_channel::handshake::StaticPublic;
use shekyl_rpc_grants::GrantSet;

use super::{bundle_from_text, read_client_key, ChannelFault, ChannelTarget, Leg, Pool};

/// The account key used by all wallets and by the CLI's enrollment words.
pub fn default_key_file() -> Result<PathBuf, String> {
    shekyl_os_account::per_account_root()
        .map(|root| root.join("rpc-client.key"))
        .ok_or_else(|| "set rpc-key-file: this account has no home directory".to_owned())
}

/// A daemon named by an endpoint and an operator-supplied bundle.
#[derive(Clone, Debug)]
pub struct RemoteNode {
    /// The dial route, independent of the wallet's persona Tor service.
    pub leg: Leg,
    /// The public bundle exported by the node operator.
    pub bundle_file: PathBuf,
}

impl RemoteNode {
    /// Read the pinned bundle without dialing or creating an identity.
    pub fn bundle(&self) -> Result<StaticPublic, ChannelFault> {
        let path = &self.bundle_file;
        let text = std::fs::read_to_string(path).map_err(|e| {
            ChannelFault::Local(format!("daemon-bundle-file {}: {e}", path.display()))
        })?;
        bundle_from_text(&text).ok_or_else(|| ChannelFault::Local(format!(
            "daemon-bundle-file {} is not a public bundle exported by shekyl-cli rpc bundle show", path.display()
        )))
    }
}

/// Load the account identity or create it on first use. A newly created
/// identity stops here, before any network traffic.
pub fn account_target(
    network: Network,
    leg: Leg,
    bundle: StaticPublic,
    key_file: Option<&Path>,
) -> Result<ChannelTarget, ChannelFault> {
    let path = match key_file {
        Some(path) => path.to_owned(),
        None => default_key_file().map_err(ChannelFault::Local)?,
    };
    let key = match read_client_key(&path).map_err(ChannelFault::Local)? {
        Some(key) => key,
        None => match super::key::publish_client_key(&path).map_err(ChannelFault::Local)? {
            Some(key) => {
                return Err(ChannelFault::NotEnrolled {
                    fingerprint: *key.public().fingerprint().as_bytes(),
                })
            }
            None => read_client_key(&path)
                .map_err(ChannelFault::Local)?
                .ok_or_else(|| {
                    ChannelFault::Local(format!(
                        "rpc-key-file {} disappeared during creation",
                        path.display()
                    ))
                })?,
        },
    };
    Ok(ChannelTarget::new(network.network_id(), bundle, key, leg))
}

/// An engine connection. A cancelled exchange drops its lent session:
/// unacknowledged submissions are never replayed by this transport.
#[derive(Clone)]
pub struct WalletChannel {
    pool: Arc<Pool>,
    within: Duration,
}

impl std::fmt::Debug for WalletChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletChannel")
            .field("within", &self.within)
            .finish_non_exhaustive()
    }
}

impl WalletChannel {
    /// Construct a pool that uses the permissions enrolled on the daemon.
    /// The existing wire request mask uses all bits to select the full ceiling.
    pub fn new(target: ChannelTarget, within: Duration) -> Self {
        Self {
            pool: Pool::new(target, GrantSet::ALL),
            within,
        }
    }

    /// One engine POST in a session exclusively lent for this exchange.
    ///
    /// The pool's call bound is this channel's bound. A deadline is
    /// [`ChannelFault::Budget`]. A connection that ends under the call is
    /// rechecked for revocation, and the body is not sent again.
    pub async fn post(&self, route: &str, body: Vec<u8>) -> Result<Vec<u8>, ChannelFault> {
        self.pool.post(route, body, self.within).await
    }

    /// The bound this channel was opened under.
    #[cfg(any(test, feature = "test-override"))]
    #[must_use]
    pub fn bound(&self) -> Duration {
        self.within
    }
}
