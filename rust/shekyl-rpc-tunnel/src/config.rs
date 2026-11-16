// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The tunnel's configuration: the command line and the file read against
//! [`TABLE`], resolved as the daemon resolves its own
//! (`shekyl_daemon_config::resolve`: the file, then the command line, a list
//! replaced whole), and built into what the tunnel does.

use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use shekyl_daemon_config::resolve::{self, chosen_network};
use shekyl_daemon_config::Network;
use shekyl_daemon_config::{file, paths, Logging, Platform, Resolved, RunMode};
use shekyl_options::{read_cli, read_file, Code, Diagnostic, PeerEndpoint, Source, Value};
use shekyl_rpc_channel::handshake::StaticPublic;
use shekyl_rpc_grants::GrantSet;
use shekyl_rpc_types::wire::rpc::CeilingWord;

use crate::table::TABLE;

/// What this run of the tunnel does.
pub enum Action {
    /// `help`.
    Help,
    /// `version`.
    Version,
    /// `rpc-key-create`: make the key at this path.
    KeyCreate(PathBuf),
    /// `rpc-key-show`: print the fingerprint of the key at this path.
    KeyShow(PathBuf),
    /// Serve.
    Run(Box<Config>),
}

/// Where local consumers reach the tunnel.
#[derive(Clone, Debug)]
pub enum Listen {
    /// A loopback address and a port (RT-14).
    Tcp(SocketAddr),
    /// A socket in a directory only this account can enter.
    #[cfg(unix)]
    Socket(PathBuf),
}

/// A tunnel to serve.
pub struct Config {
    /// The node's network.
    pub network: Network,
    /// The node's channel listener, `host:port`.
    pub endpoint: String,
    /// The SOCKS5 proxy, if any.
    pub socks: Option<SocketAddr>,
    /// The node's public bundle.
    pub bundle: StaticPublic,
    /// This tunnel's key file.
    pub key_file: PathBuf,
    /// The grant every session asks for.
    pub request: GrantSet,
    /// The local listener.
    pub listen: Listen,
    /// The logging owner's section.
    pub logging: Logging,
}

fn requires(option: &str, requires: &str) -> Diagnostic {
    Diagnostic::new(Code::ValueRequires, Source::Cli)
        .option(option)
        .param("requires", requires)
}

/// Read the arguments (without the program name) and the configuration
/// file, and decide what this run does.
///
/// # Errors
///
/// Every refusal found, typed (IG-11).
pub fn load<I>(args: I, platform: &Platform) -> Result<Action, Vec<Diagnostic>>
where
    I: IntoIterator<Item = OsString>,
{
    let cli = read_cli(&TABLE, args)?;
    let given = |name: &str| cli.given.iter().any(|g| g.row.name == name);
    if given("help") {
        return Ok(Action::Help);
    }
    if given("version") {
        return Ok(Action::Version);
    }
    let network = chosen_network(&cli);
    let root = paths::root(platform, RunMode::User, "config-file").map_err(|d| vec![d])?;
    let (config_path, named) = match cli.given.iter().find(|g| g.row.name == "config-file") {
        Some(g) => match &g.value {
            Value::Path(path) => (path.clone(), true),
            other => unreachable!("config-file is a path, not {other:?}"),
        },
        None => (
            root.join(format!("shekyl-rpc-tunnel-{}.toml", network.name())),
            false,
        ),
    };
    let key_create = given("rpc-key-create");
    let key_show = given("rpc-key-show");
    let opened = file::open(&config_path, named).map_err(|d| vec![d])?;
    let file_given = match &opened {
        Some(config_file) => read_file(&TABLE, &config_path, &config_file.text)?,
        None => Vec::new(),
    };
    let resolved = resolve::resolve(&TABLE, network, cli, file_given)?;
    let key_file = path_of(&resolved, "rpc-key-file")
        .unwrap_or_else(|| root.join(format!("rpc-shekyl-rpc-tunnel-{}.key", network.name())));
    if key_create {
        return Ok(Action::KeyCreate(key_file));
    }
    if key_show {
        return Ok(Action::KeyShow(key_file));
    }
    build(&resolved, network, &root, key_file).map(|config| Action::Run(Box::new(config)))
}

fn path_of(resolved: &Resolved, name: &str) -> Option<PathBuf> {
    match resolved.get(name) {
        Some(Value::Path(path)) => Some(path.clone()),
        _ => None,
    }
}

fn build(
    resolved: &Resolved,
    network: Network,
    root: &Path,
    key_file: PathBuf,
) -> Result<Config, Vec<Diagnostic>> {
    let mut faults = Vec::new();
    let endpoint = match resolved.get("daemon-endpoint") {
        Some(Value::Peer(PeerEndpoint::Ip(addr))) => Some(addr.to_string()),
        Some(Value::Peer(PeerEndpoint::Onion { host, port })) => Some(format!("{host}:{port}")),
        _ => {
            faults.push(requires(
                "daemon-endpoint",
                "a value: the node's channel listener",
            ));
            None
        }
    };
    let socks = match resolved.get("daemon-socks") {
        Some(Value::Endpoint(addr)) => Some(*addr),
        _ => None,
    };
    if let (Some(endpoint), None) = (&endpoint, socks) {
        if endpoint.parse::<SocketAddr>().is_err() {
            faults.push(requires(
                "daemon-endpoint",
                "daemon-socks, to reach an onion",
            ));
        }
    }
    let bundle = match path_of(resolved, "daemon-bundle-file") {
        None => {
            faults.push(requires(
                "daemon-bundle-file",
                "a value: the node's bundle, as `rpc bundle show` prints it",
            ));
            None
        }
        Some(path) => match std::fs::read_to_string(&path) {
            Err(error) => {
                faults.push(
                    Diagnostic::new(Code::FileUnreadable, Source::Cli)
                        .option("daemon-bundle-file")
                        .param("path", path.display().to_string())
                        .param("error", error.to_string()),
                );
                None
            }
            Ok(text) => match shekyl_rpc_transport::channel::bundle_from_text(&text) {
                Some(bundle) => Some(bundle),
                None => {
                    faults.push(
                        Diagnostic::new(Code::ValueSyntax, Source::Cli)
                            .option("daemon-bundle-file")
                            .param(
                                "found",
                                format!(
                                    "{} does not hold a node's bundle as `rpc bundle show` \
                                     prints one",
                                    path.display()
                                ),
                            ),
                    );
                    None
                }
            },
        },
    };
    let request = grants_asked(resolved.get("rpc-grant"), &mut faults);
    let listen = match (
        resolved.get("listen"),
        path_of(resolved, "listen-socket-file"),
    ) {
        (Some(_), Some(_)) => {
            faults.push(
                Diagnostic::new(Code::ValueConflict, Source::Cli)
                    .option("listen")
                    .param("conflict", "listen-socket-file is set"),
            );
            None
        }
        (Some(Value::Endpoint(addr)), None) => Some(Listen::Tcp(*addr)),
        (_, Some(path)) => socket_listen(path, &mut faults),
        (_, None) => {
            faults.push(requires("listen", "a value, or listen-socket-file"));
            None
        }
    };
    let log_file = path_of(resolved, "log-file").unwrap_or_else(|| {
        root.join("logs")
            .join(format!("shekyl-rpc-tunnel-{}.log", network.name()))
    });
    let logging = match shekyl_daemon_config::logging(resolved, log_file) {
        Ok(logging) => Some(logging),
        Err(mut more) => {
            faults.append(&mut more);
            None
        }
    };
    match (endpoint, bundle, listen, logging, request) {
        (Some(endpoint), Some(bundle), Some(listen), Some(logging), Some(request))
            if faults.is_empty() =>
        {
            Ok(Config {
                network,
                endpoint,
                socks,
                bundle,
                key_file,
                request,
                listen,
                logging,
            })
        }
        _ => Err(faults),
    }
}

/// The grant every session asks for. An absent row is `view`, the table's
/// default. A word [`CeilingWord::from_name`] does not know is a fault, and
/// the list is not applied in part: one unknown word refuses the whole set.
fn grants_asked(value: Option<&Value>, faults: &mut Vec<Diagnostic>) -> Option<GrantSet> {
    let Some(value) = value else {
        return Some(CeilingWord::View.grants());
    };
    let Value::List(words) = value else {
        faults.push(
            Diagnostic::new(Code::ValueSyntax, Source::Cli)
                .option("rpc-grant")
                .param("value", value.render())
                .param("expected", "a list of grants"),
        );
        return None;
    };
    let mut ceiling = Vec::with_capacity(words.len());
    let mut sound = true;
    for word in words {
        let Value::Word(spelling) = word else {
            faults.push(
                Diagnostic::new(Code::ValueSyntax, Source::Cli)
                    .option("rpc-grant")
                    .param("value", word.render())
                    .param("expected", "a grant or a preset"),
            );
            sound = false;
            continue;
        };
        match CeilingWord::from_name(spelling) {
            Some(known) => ceiling.push(known),
            None => {
                faults.push(
                    Diagnostic::new(Code::ValueWord, Source::Cli)
                        .option("rpc-grant")
                        .param("value", *spelling)
                        .param("words", CeilingWord::WORDS.join(", ")),
                );
                sound = false;
            }
        }
    }
    sound.then(|| CeilingWord::expand(&ceiling))
}

#[cfg(unix)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "one signature with Windows, which refuses the row"
)]
fn socket_listen(path: PathBuf, _faults: &mut [Diagnostic]) -> Option<Listen> {
    Some(Listen::Socket(path))
}

#[cfg(windows)]
fn socket_listen(_path: PathBuf, faults: &mut Vec<Diagnostic>) -> Option<Listen> {
    faults.push(
        Diagnostic::new(Code::SocketDirPlatform, Source::Cli)
            .option("listen-socket-file")
            .param("reason", "Windows serves a tunnel's consumers on listen"),
    );
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn platform(home: &Path) -> Platform {
        Platform {
            home: Some(home.to_path_buf()),
            service_parent: None,
            session_dir: None,
            service_rendezvous: None,
        }
    }

    fn args(words: &[&str]) -> Vec<OsString> {
        words.iter().map(OsString::from).collect()
    }

    fn bundle_file(dir: &Path) -> PathBuf {
        let key = shekyl_rpc_channel::handshake::StaticKeypair::generate().unwrap();
        let mut bytes = key.public().x25519().to_vec();
        bytes.extend_from_slice(key.public().mlkem_ek());
        let path = dir.join("node.bundle");
        std::fs::write(&path, shekyl_rpc_transport::channel::bundle_text(&bytes)).unwrap();
        path
    }

    fn codes(diagnostics: &[Diagnostic]) -> Vec<&'static str> {
        diagnostics.iter().map(|d| d.code.as_str()).collect()
    }

    /// A whole configuration builds: the node, its bundle, the grant asked
    /// for (the flag repeated, expanded), the loopback listener and the
    /// key file's default under this account's root. Red edit: read only
    /// the first `rpc-grant` word, and `submit` is lost.
    #[test]
    fn a_whole_configuration_builds() {
        let home = tempfile::tempdir().unwrap();
        let bundle = bundle_file(home.path());
        let action = load(
            args(&[
                "--network",
                "regtest",
                "--daemon-endpoint",
                "203.0.113.5:29501",
                "--daemon-bundle-file",
                bundle.to_str().unwrap(),
                "--rpc-grant",
                "view",
                "--rpc-grant",
                "submit",
                "--listen",
                "127.0.0.1:29600",
            ]),
            &platform(home.path()),
        );
        let Ok(Action::Run(config)) = action else {
            panic!("a configuration");
        };
        assert_eq!(config.endpoint, "203.0.113.5:29501");
        assert!(config.request.names(shekyl_rpc_grants::Grant::Submit));
        assert!(config.request.holds(shekyl_rpc_grants::Grant::Chain));
        assert!(matches!(config.listen, Listen::Tcp(addr) if addr.port() == 29600));
        assert!(config
            .key_file
            .ends_with("rpc-shekyl-rpc-tunnel-regtest.key"));
    }

    /// The required rows are named when absent, together, and both
    /// listeners at once is a conflict. Red edit: drop the `listen` check
    /// in `build`, and a tunnel with no listener builds.
    #[test]
    fn the_required_rows_and_the_listeners_are_refused_by_code() {
        let home = tempfile::tempdir().unwrap();
        let Err(faults) = load(args(&["--network", "regtest"]), &platform(home.path())) else {
            panic!("refused");
        };
        assert_eq!(
            codes(&faults),
            vec!["config.value.requires"; 3],
            "daemon-endpoint, daemon-bundle-file and listen: {faults:?}"
        );
        let bundle = bundle_file(home.path());
        let Err(faults) = load(
            args(&[
                "--daemon-endpoint",
                "127.0.0.1:29501",
                "--daemon-bundle-file",
                bundle.to_str().unwrap(),
                "--listen",
                "127.0.0.1:29600",
                "--listen-socket-file",
                home.path().join("t.sock").to_str().unwrap(),
            ]),
            &platform(home.path()),
        ) else {
            panic!("refused");
        };
        assert_eq!(codes(&faults), vec!["config.value.conflict"]);
    }

    /// The key switches act on the key file without needing the rest of a
    /// configuration. Red edit: check `rpc-key-create` after `build`, and
    /// making a key needs a node.
    #[test]
    fn the_key_switches_need_only_the_key_file() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("k.key");
        let Ok(Action::KeyCreate(got)) = load(
            args(&["--rpc-key-create", "--rpc-key-file", path.to_str().unwrap()]),
            &platform(home.path()),
        ) else {
            panic!("rpc-key-create");
        };
        assert_eq!(got, path);
        assert!(matches!(
            load(args(&["--rpc-key-show"]), &platform(home.path())),
            Ok(Action::KeyShow(_))
        ));
    }

    /// An unknown grant refuses the whole set. A list that also names
    /// `view` does not quietly ask for view alone. Red edit: `filter_map`
    /// unknown words away in `grants_asked`, and this returns `view`.
    #[test]
    fn an_unknown_grant_refuses_the_whole_set() {
        let mut faults = Vec::new();
        let asked = Value::List(vec![Value::Word("view"), Value::Word("not-a-grant")]);
        assert!(grants_asked(Some(&asked), &mut faults).is_none());
        assert_eq!(codes(&faults), vec!["config.value.word"]);
        assert!(grants_asked(None, &mut Vec::new())
            .expect("the default")
            .holds(shekyl_rpc_grants::Grant::Chain));
    }
}
