// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The enrollment words (`INPUT_GRAMMAR.md` IG-Q87) and this client's
//! channel key (IG-Q109).
//!
//! Enrollment runs over the channel or on the owner's leg, never on a
//! plaintext listener (`RPC_CHANNEL.md` §5): any local account reaches
//! those until RT-W12, and an enrollment made there would outlive them. So
//! these words do not use the shell's daemon client. Each picks its own
//! leg, in this order (Rick, 2026-11-15):
//!
//! 1. **A node on another host:** `daemon-bundle-file` is set. The channel
//!    to `daemon-endpoint` (through `daemon-socks` for an onion), as this
//!    client's key (`rpc-key-file`), which the node has enrolled with an
//!    `enroll` ceiling.
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
//! Each word asks for every grant, and the node clamps the request to the
//! key's ceiling. What a key may enroll, change, list or remove is bounded by
//! that effective grant (`RPC_CHANNEL.md` §5, RT-O9.1), so a session asking
//! for `enroll` alone could enroll nothing beyond `enroll`.

use std::path::{Path, PathBuf};

use shekyl_daemon_config::{paths, RunMode};
use shekyl_rpc_client::{wire, RpcMethod};
use shekyl_rpc_grants::GrantSet;
use shekyl_rpc_transport::channel::{
    bundle_from_bytes, bundle_from_text, bundle_text, create_client_key, fingerprint_hex,
    read_client_key, ChannelDaemon, ChannelTarget, Leg,
};
use shekyl_rpc_transport::local::LocalTarget;
use shekyl_rpc_types::hash::HashHex;
use shekyl_rpc_types::kinds::NoParams;
use shekyl_rpc_types::wire::rpc::{ClientCeiling, ClientFingerprint};
use shekyl_wallet_rpc::Network;

use crate::resolve::Enroll;

/// What the enrollment words need from the shell's options.
#[derive(Clone, Debug)]
pub struct EnrollOptions {
    /// The shell's network.
    pub network: Network,
    /// A node on another host, when `daemon-bundle-file` is set.
    pub remote: Option<Remote>,
    /// This client's channel key, `rpc-key-file` as given. Unset, it is
    /// [`default_key_file`]'s, found only by a word that reads the key: a
    /// shell whose account has no home runs every other word.
    pub key_file: Option<PathBuf>,
}

impl EnrollOptions {
    /// This client's channel key file.
    ///
    /// # Errors
    ///
    /// `rpc-key-file` is unset and the account has no home
    /// (`config.path.no-home`).
    fn key_file(&self) -> Result<PathBuf, String> {
        match &self.key_file {
            Some(path) => Ok(path.clone()),
            None => default_key_file(self.network),
        }
    }
}

/// A node on another host (IG-Q108).
#[derive(Clone, Debug)]
pub struct Remote {
    /// The node's channel. Built from a peer-endpoint and, for an onion,
    /// an endpoint (`INPUT_GRAMMAR.md` IG-Q31).
    pub leg: Leg,
    /// `daemon-bundle-file`: the node's bundle, as `rpc bundle show` prints
    /// it.
    pub bundle_file: PathBuf,
}

/// The channel address an enrollment needs when `daemon-bundle-file` is set.
///
/// The CLI's daemon address otherwise defaults to the plaintext RPC port.
/// `rpc-listen` has no default port, so that default is not a channel.
pub const CHANNEL_ADDRESS_REQUIRED: &str = "This command reaches the node over its channel, so it \
     needs the channel's address (--daemon-address): an IP and a port, or an onion and a port. \
     The usual daemon port is the plaintext listener, which is not the channel.";

/// This client's key file when `--rpc-key-file` is unset: the account root
/// and `rpc-shekyl-cli-<network>.key` (IG-Q108). The root is the daemon's
/// (`paths::root`), not a home directory joined by hand.
///
/// # Errors
///
/// The account has no home (`config.path.no-home`).
fn default_key_file(network: Network) -> Result<PathBuf, String> {
    let platform = shekyl_process::platform::current();
    let root = paths::root(&platform, RunMode::User, "rpc-key-file").map_err(|d| d.render())?;
    Ok(root.join(format!("rpc-shekyl-cli-{}.key", network.name())))
}

/// The channel leg for an enrollment on another host.
///
/// `address` is a peer-endpoint and `proxy`, when set, an endpoint: the
/// kinds `daemon-endpoint` and `daemon-socks` have. A URL, a hostname, or
/// an onion without a proxy is refused with that kind's diagnostic.
///
/// # Errors
///
/// The value is not the kind, or the onion has no proxy.
pub fn channel_leg(address: &str, proxy: Option<&str>) -> Result<Leg, String> {
    use shekyl_options::{EndpointRule, Kind, PeerEndpoint, PeerRule, Source, Value};
    let peer = Kind::PeerEndpoint(PeerRule::Any)
        .parse_text(address)
        .map_err(|fault| fault.at("--daemon-address", Source::Cli).render())?;
    let proxy = match proxy {
        None => None,
        Some(text) => match Kind::Endpoint(EndpointRule::Any)
            .parse_text(text)
            .map_err(|fault| fault.at("--proxy", Source::Cli).render())?
        {
            Value::Endpoint(addr) => Some(addr),
            _ => unreachable!("an endpoint kind produces an endpoint"),
        },
    };
    match peer {
        Value::Peer(PeerEndpoint::Ip(addr)) => Ok(Leg::ip(addr, proxy)),
        Value::Peer(PeerEndpoint::Onion { host, port }) => {
            let Some(proxy) = proxy else {
                return Err(shekyl_options::Diagnostic::new(
                    shekyl_options::Code::ValueRequires,
                    shekyl_options::Source::Cli,
                )
                .option("--daemon-address")
                .param("requires", "--proxy, an IP and a port, to reach an onion")
                .render());
            };
            Ok(Leg::onion(host, port, proxy))
        }
        _ => unreachable!("a peer-endpoint kind produces a peer"),
    }
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
pub fn run(options: &EnrollOptions, word: &Enroll) -> Result<String, String> {
    match word {
        Enroll::KeyCreate => return key_create(&options.key_file()?),
        Enroll::KeyShow => return key_show(&options.key_file()?),
        _ => {}
    }
    let leg = EnrolLeg::resolve(options)?;
    match word {
        Enroll::ClientAdd {
            fingerprint,
            ceiling,
        } => {
            leg.call::<wire::RpcClientAdd>(&ClientCeiling {
                fingerprint: hash(fingerprint)?,
                ceiling: ceiling.clone(),
            })?;
            Ok(format!("enrolled {fingerprint}"))
        }
        Enroll::ClientSet {
            fingerprint,
            ceiling,
        } => {
            leg.call::<wire::RpcClientSet>(&ClientCeiling {
                fingerprint: hash(fingerprint)?,
                ceiling: ceiling.clone(),
            })?;
            Ok(format!("changed {fingerprint}'s ceiling"))
        }
        Enroll::ClientRemove { fingerprint } => {
            leg.call::<wire::RpcClientRemove>(&ClientFingerprint {
                fingerprint: hash(fingerprint)?,
            })?;
            Ok(format!("removed {fingerprint}"))
        }
        Enroll::ClientList => {
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
        Enroll::BundleShow => {
            let bundle = leg.call::<wire::RpcBundleShow>(&NoParams)?;
            Ok(bundle_text(&bundle.bundle.0))
        }
        Enroll::KeyCreate | Enroll::KeyShow => unreachable!("answered above"),
    }
}

fn hash(fingerprint: &str) -> Result<HashHex, String> {
    HashHex::from_hex(fingerprint).map_err(|error| error.to_string())
}

/// The leg one enrollment word runs on.
enum EnrolLeg {
    /// The owner's leg of a daemon this account runs.
    Owner(LocalTarget),
    /// The channel: a node on another host, or a service's console leg.
    Channel(ChannelDaemon),
}

impl EnrolLeg {
    fn resolve(options: &EnrollOptions) -> Result<Self, String> {
        let request = GrantSet::ALL;
        if let Some(remote) = &options.remote {
            let text = std::fs::read_to_string(&remote.bundle_file).map_err(|error| {
                format!(
                    "the node's bundle {} could not be read: {error}",
                    remote.bundle_file.display()
                )
            })?;
            let daemon = bundle_from_text(&text).ok_or_else(|| {
                format!(
                    "{} does not hold a node's bundle as `rpc bundle show` prints one",
                    remote.bundle_file.display()
                )
            })?;
            let key_file = options.key_file()?;
            let key = read_client_key(&key_file)?.ok_or_else(|| {
                format!(
                    "this client has no key at {}; make one with `rpc key create`, then enroll \
                     its fingerprint on the node",
                    key_file.display()
                )
            })?;
            let target = ChannelTarget::new(
                options.network.network_id(),
                daemon,
                key,
                remote.leg.clone(),
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
fn service_console(network: Network, request: GrantSet) -> Result<Option<EnrolLeg>, String> {
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

/// `rpc key create`: a new key at `path`, this account's alone, refused if
/// one is there; its fingerprint, for the node's `rpc client add`.
fn key_create(path: &Path) -> Result<String, String> {
    create_client_key(path).map(|key| fingerprint_hex(key.public()))
}

/// `rpc key show`: this client's fingerprint.
fn key_show(path: &Path) -> Result<String, String> {
    read_client_key(path)?
        .map(|key| fingerprint_hex(key.public()))
        .ok_or_else(|| {
            format!(
                "this client has no key at {}; make one with `rpc key create`",
                path.display()
            )
        })
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

    /// The channel leg is a peer-endpoint. A URL and a hostname are refused
    /// by that kind, and an onion without a proxy is refused. Red edit:
    /// strip `://` and a trailing slash in `channel_leg`, and the URL is
    /// dialed.
    #[test]
    fn the_channel_leg_is_a_peer_endpoint() {
        let ip = channel_leg("203.0.113.5:29501", None).expect("an address");
        assert!(matches!(ip, Leg::Ip { proxy: None, .. }));
        let proxied =
            channel_leg("203.0.113.5:29501", Some("127.0.0.1:9050")).expect("through a proxy");
        assert!(matches!(proxied, Leg::Ip { proxy: Some(_), .. }));
        assert!(channel_leg("http://203.0.113.5:29501/json_rpc", None).is_err());
        assert!(channel_leg("node.example:29501", None).is_err());
        assert!(channel_leg("socks5h://127.0.0.1:9050", None).is_err());
        let onion = "gj56z5xbxm7mi6iucpe3apa3raxkkiwub4vbc2who5sm6slpzikuqiyd.onion:14021";
        let missing = channel_leg(onion, None).expect_err("an onion needs a proxy");
        assert!(missing.contains("proxy"), "{missing}");
        assert!(channel_leg(onion, Some("not-an-endpoint")).is_err());
        assert!(channel_leg(onion, Some("127.0.0.1:9050")).is_ok());
    }
}
