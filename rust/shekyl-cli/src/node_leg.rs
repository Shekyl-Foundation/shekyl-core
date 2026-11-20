// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! "This computer"'s node, as the shell's daemon words and the enrollment
//! words reach it (`RPC_CHANNEL.md` RT-15; RT-W10 step 5): one resolver.
//!
//! 1. **This computer's service** (RT-16: "this computer" is the service
//!    when one runs): the service's console leg, at its fixed name in the
//!    service's data directory, as the console key beside it (RT-O37). The
//!    data home is `shekyl-daemon-config`'s and the files' names
//!    `shekyl-rpc-rendezvous`'s, which the daemon uses too; none is
//!    restated here. A console key that is missing, unreadable or damaged,
//!    or a leg this account cannot see, is §4.5's console-key failure, and
//!    no other leg is tried.
//! 2. **This computer's daemon, run as this account:** the owner's leg
//!    (`LocalTarget`), whose failed peer check stays its own error.
//!
//! A node on another host is not this module's: the enrollment words reach
//! one over the channel, and the daemon words over a named address.

use std::path::Path;

use shekyl_daemon_config::{paths, RunMode};
use shekyl_rpc_client::RpcMethod;
use shekyl_rpc_grants::GrantSet;
use shekyl_rpc_transport::channel::{
    bundle_from_bytes, ChannelDaemon, ChannelFault, ChannelTarget, Leg,
};
use shekyl_rpc_transport::local::{LocalFault, LocalTarget};
use shekyl_rpc_transport::JsonRpcError;
use shekyl_wallet_rpc::Network;

/// §4.5's console-key failure, in its words.
pub(crate) const CONSOLE_KEY_FAILURE: &str =
    "This command needs the node's console key, which is missing \
     or cannot be read. Run it as an administrator; if the key is lost, stop the node and reset it \
     with shekyld --rpc-console-key-reset.";

/// The leg a word runs on.
pub(crate) enum NodeLeg {
    /// The owner's leg of a daemon this account runs.
    Owner(LocalTarget),
    /// The channel: a node on another host, or a service's console leg.
    Channel(ChannelDaemon),
}

/// Why a call on a [`NodeLeg`] did not return its reply, each leg's own
/// failure kept: the owner's leg's failed peer check is a security failure
/// a caller reports as one.
#[derive(Debug)]
pub(crate) enum LegError {
    /// The owner's leg.
    Owner(JsonRpcError<LocalFault>),
    /// The channel.
    Channel(JsonRpcError<ChannelFault>),
}

impl std::fmt::Display for LegError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Owner(error) => error.fmt(f),
            Self::Channel(error) => error.fmt(f),
        }
    }
}

impl NodeLeg {
    /// This computer's node: its service's console leg when a service runs
    /// here, otherwise the owner's leg of the daemon this account runs.
    ///
    /// # Errors
    ///
    /// §4.5's console-key failure, or the channel to the console leg.
    pub(crate) fn this_computer(network: Network, request: GrantSet) -> Result<Self, String> {
        if let Some(leg) = service_console(network, request)? {
            return Ok(leg);
        }
        Ok(Self::Owner(LocalTarget::this_computer(network)))
    }

    /// One call of method `M`.
    ///
    /// # Errors
    ///
    /// [`LegError`].
    pub(crate) fn call<M: RpcMethod>(&self, request: &M::Request) -> Result<M::Reply, LegError> {
        match self {
            Self::Owner(target) => target.call::<M>(request).map_err(LegError::Owner),
            Self::Channel(channel) => channel.call::<M>(request).map_err(LegError::Channel),
        }
    }

    /// One call of method `M`, a failure as the text the person reads.
    ///
    /// # Errors
    ///
    /// [`LegError`]'s text.
    pub(crate) fn call_text<M: RpcMethod>(&self, request: &M::Request) -> Result<M::Reply, String> {
        self.call::<M>(request).map_err(|error| error.to_string())
    }

    /// One JSON-RPC call by name, its result decoded as `Reply`.
    ///
    /// # Errors
    ///
    /// [`LegError`].
    pub(crate) fn json_rpc<Req, Reply>(
        &self,
        method: &str,
        request: &Req,
    ) -> Result<Reply, LegError>
    where
        Req: serde::Serialize,
        Reply: serde::de::DeserializeOwned,
    {
        match self {
            Self::Owner(target) => target.json_rpc(method, request).map_err(LegError::Owner),
            Self::Channel(channel) => channel.json_rpc(method, request).map_err(LegError::Channel),
        }
    }
}

/// Whether a service has published its console leg at `place`.
///
/// Not found is the only "no service" answer. Any other failure means the
/// leg cannot be seen, which is §4.5's console-key failure: the owner's
/// leg is not tried in its place.
fn leg_published(place: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(place) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(CONSOLE_KEY_FAILURE.to_owned()),
    }
}

/// This computer's service's console leg, when a service runs here.
fn service_console(network: Network, request: GrantSet) -> Result<Option<NodeLeg>, String> {
    let platform = shekyl_process::platform::current();
    let Ok(root) = paths::root(&platform, RunMode::Service, "rpc") else {
        return Ok(None);
    };
    let dir = paths::data_dir_default(&root, network);
    let place = shekyl_rpc_rendezvous::console_leg_place(&dir);
    if !leg_published(&place)? {
        return Ok(None);
    }
    // A service runs here: from now on, no other leg (§4.5).
    let console = read_console_key(&dir.join(shekyl_rpc_rendezvous::CONSOLE_KEY_FILE))?;
    let daemon = read_console_bytes(&dir.join(shekyl_rpc_rendezvous::CHANNEL_BUNDLE_FILE))
        .ok()
        .and_then(|bytes| bundle_from_bytes(&bytes))
        .ok_or_else(|| CONSOLE_KEY_FAILURE.to_owned())?;
    let leg = console_leg_of(&place)?;
    let target = ChannelTarget::new(network.network_id(), daemon, console, leg);
    ChannelDaemon::connect(&target, request)
        .map(|channel| Some(NodeLeg::Channel(channel)))
        .map_err(|fault| fault.to_string())
}

#[cfg(unix)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "one signature with Windows, whose pipe's name is read from a file"
)]
fn console_leg_of(place: &Path) -> Result<Leg, String> {
    Ok(Leg::Socket(place.to_path_buf()))
}

#[cfg(windows)]
fn console_leg_of(place: &Path) -> Result<Leg, String> {
    let name = read_console_bytes(place)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes.to_vec()).ok())
        .ok_or_else(|| CONSOLE_KEY_FAILURE.to_owned())?;
    Ok(Leg::Pipe(name))
}

/// A service's console file: the owning account, or an administrator of
/// this machine. Anything else, including a file another account can read,
/// is the console-key failure. The bytes are wiped on drop.
fn read_console_bytes(path: &Path) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    shekyl_os_account::private_file::read_console(path)
        .ok()
        .flatten()
        .ok_or_else(|| CONSOLE_KEY_FAILURE.to_owned())
}

/// The console key, read as [`read_console_bytes`].
fn read_console_key(path: &Path) -> Result<shekyl_rpc_channel::handshake::StaticKeypair, String> {
    let bytes = read_console_bytes(path)?;
    shekyl_rpc_channel::handshake::StaticKeypair::from_key_file(&bytes)
        .map_err(|_| CONSOLE_KEY_FAILURE.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A missing leg is no service. A leg this account cannot see is the
    /// console-key failure, so enrollment does not fall through to the owner.
    /// Red edit: treat every `symlink_metadata` error as absent in
    /// `leg_published`, and a mode-000 directory is "no service".
    #[test]
    fn only_a_missing_console_leg_means_no_service() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!leg_published(&dir.path().join("absent")).unwrap());

        let published = dir.path().join("published");
        std::fs::write(&published, b"leg").unwrap();
        assert!(leg_published(&published).unwrap());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if shekyl_os_account::effective_uid() == 0 {
                return;
            }
            let hidden = dir.path().join("hidden");
            std::fs::create_dir(&hidden).unwrap();
            let place = hidden.join("console");
            std::fs::write(&place, b"leg").unwrap();
            std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o000)).unwrap();
            let saw = leg_published(&place);
            std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(
                saw.expect_err("the leg cannot be seen"),
                CONSOLE_KEY_FAILURE
            );
        }
    }
}
