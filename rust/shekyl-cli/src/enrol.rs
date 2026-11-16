// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The enrolment words (`INPUT_GRAMMAR.md` IG-Q87) and this client's
//! channel key (IG-Q109).
//!
//! Enrolment runs over the channel or on the owner's leg, never on a
//! plaintext listener (`RPC_CHANNEL.md` §5): any local account reaches
//! those until RT-W12, and an enrolment made there would outlive them. So
//! these words do not use the shell's daemon client. Each picks its own
//! leg, in this order (Rick, 2026-11-15):
//!
//! 1. **A node on another host:** `daemon-bundle-file` is set. The channel
//!    to `daemon-endpoint` (through `daemon-socks` for an onion), as this
//!    client's key (`rpc-key-file`), which the node has enrolled with an
//!    `enrol` ceiling.
//! 2. **This computer's service** (RT-16: "this computer" is the service
//!    when one runs): the service's console leg, at its fixed name in the
//!    service's data directory, as the console key beside it (RT-O37). The
//!    data home is `shekyl-daemon-config`'s and the files' names
//!    `shekyl-rpc-rendezvous`'s, which the daemon uses too; none is
//!    restated here. A console key that is missing, unreadable or damaged
//!    is §4.5's console-key failure, and no other leg is tried.
//! 3. **This computer's daemon, run as this account:** the owner's leg
//!    (`LocalTarget`).
//!
//! Each word asks for the one grant its method needs, `enrol`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use shekyl_daemon_config::{paths, RunMode};
use shekyl_os_account::private_file;
use shekyl_rpc_channel::handshake::{StaticKeypair, StaticPublic};
use shekyl_rpc_client::{wire, RpcMethod};
use shekyl_rpc_grants::{Grant, GrantSet};
use shekyl_rpc_transport::channel::{ChannelDaemon, ChannelTarget, Leg};
use shekyl_rpc_transport::local::LocalTarget;
use shekyl_rpc_types::hash::HashHex;
use shekyl_rpc_types::kinds::{Bytes, NoParams};
use shekyl_rpc_types::wire::rpc::{ClientCeiling, ClientFingerprint};
use shekyl_wallet_rpc::Network;

use crate::resolve::Enrol;

/// What the enrolment words need from the shell's options.
#[derive(Clone, Debug)]
pub struct EnrolOptions {
    /// The shell's network.
    pub network: Network,
    /// A node on another host, when `daemon-bundle-file` is set.
    pub remote: Option<Remote>,
    /// This client's channel key (`rpc-key-file`).
    pub key_file: PathBuf,
}

/// A node on another host (IG-Q108).
#[derive(Clone, Debug)]
pub struct Remote {
    /// `daemon-endpoint`: an address or an onion, `host:port`.
    pub endpoint: String,
    /// `daemon-socks`.
    pub socks: Option<SocketAddr>,
    /// `daemon-bundle-file`: the node's bundle, as `rpc bundle show` prints
    /// it.
    pub bundle_file: PathBuf,
}

/// §4.5's console-key failure, in its words.
const CONSOLE_KEY_FAILURE: &str = "This command needs the node's console key, which is missing \
     or cannot be read. Run it as an administrator; if the key is lost, stop the node and reset it \
     with shekyld --rpc-console-key-reset.";

/// Run one word.
///
/// # Errors
///
/// What the person reading it can act on.
pub fn run(options: &EnrolOptions, word: &Enrol) -> Result<String, String> {
    match word {
        Enrol::KeyCreate => return key_create(&options.key_file),
        Enrol::KeyShow => return key_show(&options.key_file),
        _ => {}
    }
    let leg = EnrolLeg::resolve(options)?;
    match word {
        Enrol::ClientAdd {
            fingerprint,
            ceiling,
        } => {
            leg.call::<wire::RpcClientAdd>(&ClientCeiling {
                fingerprint: hash(fingerprint)?,
                ceiling: ceiling.clone(),
            })?;
            Ok(format!("enrolled {fingerprint}"))
        }
        Enrol::ClientSet {
            fingerprint,
            ceiling,
        } => {
            leg.call::<wire::RpcClientSet>(&ClientCeiling {
                fingerprint: hash(fingerprint)?,
                ceiling: ceiling.clone(),
            })?;
            Ok(format!("changed {fingerprint}'s ceiling"))
        }
        Enrol::ClientRemove { fingerprint } => {
            leg.call::<wire::RpcClientRemove>(&ClientFingerprint {
                fingerprint: hash(fingerprint)?,
            })?;
            Ok(format!("removed {fingerprint}"))
        }
        Enrol::ClientList => {
            let clients = leg.call::<wire::RpcClientList>(&NoParams)?;
            if clients.is_empty() {
                return Ok("No clients are enrolled.".to_owned());
            }
            Ok(clients
                .iter()
                .map(|client| {
                    let ceiling: Vec<&str> = client.ceiling.iter().map(|g| g.as_str()).collect();
                    format!("{}  {}", client.fingerprint, ceiling.join(", "))
                })
                .collect::<Vec<_>>()
                .join("\n"))
        }
        Enrol::BundleShow => {
            let bundle = leg.call::<wire::RpcBundleShow>(&NoParams)?;
            bundle_text(&bundle.bundle)
        }
        Enrol::KeyCreate | Enrol::KeyShow => unreachable!("answered above"),
    }
}

fn hash(fingerprint: &str) -> Result<HashHex, String> {
    HashHex::from_hex(fingerprint).map_err(|error| error.to_string())
}

/// A bundle as `rpc bundle show` prints it and `daemon-bundle-file` holds
/// it: the `bytes` kind's one encoding (IG-6), base64.
fn bundle_text(bundle: &Bytes) -> Result<String, String> {
    serde_json::to_value(bundle)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| "the bundle could not be encoded".to_owned())
}

/// The daemon's public bundle from its bytes: the X25519 key, then the
/// ML-KEM-768 encapsulation key.
fn bundle_of(bytes: &[u8]) -> Option<StaticPublic> {
    if bytes.len() != shekyl_rpc_channel::X25519_PUBLIC_LEN + shekyl_rpc_channel::MLKEM768_EK_LEN {
        return None;
    }
    let (x25519, mlkem) = bytes.split_at(shekyl_rpc_channel::X25519_PUBLIC_LEN);
    StaticPublic::from_parts(x25519.try_into().ok()?, mlkem.try_into().ok()?).ok()
}

/// The leg one enrolment word runs on.
enum EnrolLeg {
    /// The owner's leg of a daemon this account runs.
    Owner(LocalTarget),
    /// The channel: a node on another host, or a service's console leg.
    Channel(ChannelDaemon),
}

impl EnrolLeg {
    fn resolve(options: &EnrolOptions) -> Result<Self, String> {
        let request = GrantSet::of(&[Grant::Enrol]);
        if let Some(remote) = &options.remote {
            let text = std::fs::read_to_string(&remote.bundle_file).map_err(|error| {
                format!(
                    "the node's bundle {} could not be read: {error}",
                    remote.bundle_file.display()
                )
            })?;
            let daemon =
                serde_json::from_value::<Bytes>(serde_json::Value::String(text.trim().to_owned()))
                    .ok()
                    .and_then(|bytes| bundle_of(&bytes.0))
                    .ok_or_else(|| {
                        format!(
                            "{} does not hold a node's bundle as `rpc bundle show` prints one",
                            remote.bundle_file.display()
                        )
                    })?;
            let key = read_key(&options.key_file)?.ok_or_else(|| {
                format!(
                    "this client has no key at {}; make one with `rpc key create`, then enrol \
                     its fingerprint on the node",
                    options.key_file.display()
                )
            })?;
            let target = ChannelTarget::new(
                options.network.network_id(),
                daemon,
                key,
                Leg::Network {
                    endpoint: remote.endpoint.clone(),
                    socks: remote.socks,
                },
            );
            return ChannelDaemon::connect(&target, request)
                .map(Self::Channel)
                .map_err(|fault| fault.to_string());
        }
        if let Some(leg) = service_console(options.network, request)? {
            return Ok(leg);
        }
        LocalTarget::this_computer(options.network)
            .map(Self::Owner)
            .map_err(|fault| fault.to_string())
    }

    fn call<M: RpcMethod>(&self, request: &M::Request) -> Result<M::Reply, String> {
        match self {
            Self::Owner(target) => target.call::<M>(request).map_err(|error| error.to_string()),
            Self::Channel(channel) => channel
                .call::<M>(request)
                .map_err(|error| error.to_string()),
        }
    }
}

/// This computer's service's console leg, when a service runs here.
fn service_console(network: Network, request: GrantSet) -> Result<Option<EnrolLeg>, String> {
    let platform = shekyl_process::platform::current();
    let Ok(root) = paths::root(&platform, RunMode::Service, "rpc") else {
        return Ok(None);
    };
    let dir = paths::data_dir_default(&root, network);
    let place = shekyl_rpc_rendezvous::console_leg_place(&dir);
    if std::fs::symlink_metadata(&place).is_err() {
        return Ok(None);
    }
    // A service runs here: from now on, no other leg (§4.5).
    let console = read_key(&dir.join(shekyl_rpc_rendezvous::CONSOLE_KEY_FILE))
        .ok()
        .flatten()
        .ok_or_else(|| CONSOLE_KEY_FAILURE.to_owned())?;
    let daemon = std::fs::read(dir.join(shekyl_rpc_rendezvous::CHANNEL_BUNDLE_FILE))
        .ok()
        .and_then(|bytes| bundle_of(&bytes))
        .ok_or_else(|| CONSOLE_KEY_FAILURE.to_owned())?;
    let leg = console_leg_of(&place)?;
    let target = ChannelTarget::new(network.network_id(), daemon, console, leg);
    ChannelDaemon::connect(&target, request)
        .map(|channel| Some(EnrolLeg::Channel(channel)))
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
    let name = private_file::read_private(place)
        .ok()
        .flatten()
        .and_then(|bytes| String::from_utf8(bytes.to_vec()).ok())
        .ok_or_else(|| CONSOLE_KEY_FAILURE.to_owned())?;
    Ok(Leg::Pipe(name))
}

/// This client's key at `path`, checked to be this account's alone.
fn read_key(path: &Path) -> Result<Option<StaticKeypair>, String> {
    let Some(bytes) = private_file::read_private(path).map_err(|error| error.to_string())? else {
        return Ok(None);
    };
    StaticKeypair::from_key_file(&bytes)
        .map(Some)
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// `rpc key create`: a new key at `path`, this account's alone, refused if
/// one is there; its fingerprint, for the node's `rpc client add`.
fn key_create(path: &Path) -> Result<String, String> {
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(format!(
            "{} already holds a key; `rpc key show` prints its fingerprint",
            path.display()
        ));
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    let key = StaticKeypair::generate().map_err(|error| error.to_string())?;
    private_file::write_private(path, &key.to_key_file()).map_err(|error| error.to_string())?;
    Ok(fingerprint_text(&key))
}

/// `rpc key show`: this client's fingerprint.
fn key_show(path: &Path) -> Result<String, String> {
    read_key(path)?
        .map(|key| fingerprint_text(&key))
        .ok_or_else(|| {
            format!(
                "this client has no key at {}; make one with `rpc key create`",
                path.display()
            )
        })
}

/// A fingerprint as `rpc client list` prints one, so the operator pastes
/// it into `rpc client add` unchanged.
fn fingerprint_text(key: &StaticKeypair) -> String {
    hex::encode(key.public().fingerprint().as_bytes())
}
