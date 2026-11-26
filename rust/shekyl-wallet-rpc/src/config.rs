// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The server's configuration: the command line and the file read against
//! [`TABLE`] by the one load (`shekyl_daemon_config::load_table`) and built
//! into what the server takes. Reads no environment (IG-13) and creates
//! nothing.

use std::ffi::OsString;
use std::path::PathBuf;

use shekyl_crypto_pq::wallet_envelope::KdfParams;
use shekyl_daemon_config::announce::effective_configuration;
use shekyl_daemon_config::{load_table, logging_to_named_file, paths, Platform, Resolved, RunMode};
use shekyl_engine_core::{Network, TorFile};
use shekyl_options::{read_cli, Code, Diagnostic, PeerEndpoint, Source, Value};

use crate::auth::{AuthConfig, BasicCredential};
use crate::server::{tcp_listen_posture, ListenAddr, ServerConfig, TOR_FILE_OPTION};
use crate::table::TABLE;
use crate::tenant::DaemonTarget;

/// What this run of the server does.
pub enum Action {
    /// `help`.
    Help,
    /// `version`.
    Version,
    /// `config-verify`: report the configuration and exit.
    Verify(Box<Loaded>),
    /// Serve.
    Serve(Box<Loaded>),
}

/// A configuration the table accepted, built.
pub struct Loaded {
    /// What the server takes.
    pub server: ServerConfig,
    /// The logging owner's section.
    pub logging: shekyl_logging::Config,
    /// The effective-configuration line (IG-14).
    pub effective: String,
    /// The account root and wallet directory to make at start, when the
    /// wallet directory is the default.
    pub default_wallet_dir: Option<(PathBuf, PathBuf)>,
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
    let verify = given("config-verify");
    let loaded = load_table(&TABLE, TABLE.binary, cli, platform)?;
    let effective = effective_configuration(&TABLE, &loaded.resolved, &loaded.config_file);
    let built = build(&loaded.resolved, loaded.network, platform, effective)?;
    Ok(if verify {
        Action::Verify(Box::new(built))
    } else {
        Action::Serve(Box::new(built))
    })
}

fn path_of(resolved: &Resolved, name: &str) -> Option<PathBuf> {
    match resolved.get(name) {
        Some(Value::Path(path)) => Some(path.clone()),
        _ => None,
    }
}

fn secret_of<'a>(resolved: &'a Resolved, name: &str) -> Option<&'a str> {
    match resolved.get(name) {
        Some(Value::Secret(secret)) => Some(secret.expose()),
        _ => None,
    }
}

fn build(
    resolved: &Resolved,
    network: Network,
    platform: &Platform,
    effective: String,
) -> Result<Loaded, Vec<Diagnostic>> {
    let mut faults = Vec::new();
    let listen = listen_of(resolved, &mut faults);
    let auth = auth_of(resolved, &mut faults);
    if let (Some(listen), Some(auth)) = (&listen, &auth) {
        let source = resolved
            .source("rpc-listen")
            .cloned()
            .unwrap_or(Source::Default);
        // The warning is said at start. A refusal is a fault of this load.
        if let Err(fault) = tcp_listen_posture(listen, auth, source) {
            faults.push(fault);
        }
    }
    if let Some(fault) = proxy_without_endpoint(resolved) {
        faults.push(fault);
    }
    let daemon = daemon_of(resolved, network, &mut faults);
    let (wallet_dir, default_wallet_dir) = match path_of(resolved, "wallet-dir") {
        Some(dir) => (Some(dir), None),
        None => match paths::root(platform, RunMode::User, "wallet-dir") {
            Ok(root) => {
                let dir = shekyl_engine_file::paths::wallet_dir_in(&root, network);
                (Some(dir.clone()), Some((root, dir)))
            }
            Err(d) => {
                faults.push(d);
                (None, None)
            }
        },
    };
    let tor_file = match TorFile::from_option(path_of(resolved, TOR_FILE_OPTION)) {
        Ok(tor_file) => Some(tor_file),
        Err(refused) => {
            faults.push(
                Diagnostic::new(Code::ValueSyntax, Source::Cli)
                    .option(TOR_FILE_OPTION)
                    .param("value", refused.to_string())
                    .param("expected", "an absolute path to a file"),
            );
            None
        }
    };
    let logging = match logging_to_named_file(resolved) {
        Ok(logging) => Some(logging),
        Err(mut more) => {
            faults.append(&mut more);
            None
        }
    };
    match (listen, auth, daemon, wallet_dir, tor_file, logging) {
        (
            Some(listen),
            Some(auth),
            Some(daemon),
            Some(wallet_dir),
            Some(tor_file),
            Some(logging),
        ) if faults.is_empty() => Ok(Loaded {
            server: ServerConfig {
                listen,
                wallet_dir,
                network,
                daemon,
                auth,
                kdf: KdfParams::default(),
                tor_file,
            },
            logging,
            effective,
            default_wallet_dir,
        }),
        _ => Err(faults),
    }
}

/// `rpc-listen`, or `rpc-socket-file` in its place. The row has a default,
/// so "both" is a socket file beside a listen address someone gave.
fn listen_of(resolved: &Resolved, faults: &mut Vec<Diagnostic>) -> Option<ListenAddr> {
    let named = !matches!(resolved.source("rpc-listen"), None | Some(Source::Default));
    match (
        path_of(resolved, "rpc-socket-file"),
        resolved.get("rpc-listen"),
    ) {
        (Some(_), Some(_)) if named => {
            faults.push(
                Diagnostic::new(Code::ValueConflict, Source::Cli)
                    .option("rpc-listen")
                    .param("conflict", "rpc-socket-file is set"),
            );
            None
        }
        (Some(path), _) => socket_listen(path, faults),
        (None, Some(Value::Endpoint(addr))) => Some(ListenAddr::Tcp(*addr)),
        (None, _) => {
            faults.push(requires("rpc-listen", "a value, or rpc-socket-file"));
            None
        }
    }
}

#[cfg(unix)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "one signature with Windows, which refuses the row"
)]
fn socket_listen(path: PathBuf, _faults: &mut [Diagnostic]) -> Option<ListenAddr> {
    Some(ListenAddr::Uds(path))
}

#[cfg(windows)]
fn socket_listen(_path: PathBuf, faults: &mut Vec<Diagnostic>) -> Option<ListenAddr> {
    faults.push(
        Diagnostic::new(Code::SocketDirPlatform, Source::Cli)
            .option("rpc-socket-file")
            .param(
                "reason",
                "a Unix socket has no Windows form; the Windows wallet is self-hosted by \
                 shekyl-cli, and a standalone server listens on rpc-listen",
            ),
    );
    None
}

/// `rpc-username` and `rpc-password`: both, or neither (IG-Q29).
fn auth_of(resolved: &Resolved, faults: &mut Vec<Diagnostic>) -> Option<AuthConfig> {
    match (
        secret_of(resolved, "rpc-username"),
        secret_of(resolved, "rpc-password"),
    ) {
        (None, None) => Some(AuthConfig::Disabled),
        (Some(username), Some(password)) => match BasicCredential::new(username, password) {
            Ok(credential) => Some(AuthConfig::Basic(credential)),
            Err(reason) => {
                // The reason names the rows and never echoes the value.
                faults.push(
                    Diagnostic::new(Code::ValueSyntax, Source::Cli)
                        .option("rpc-password")
                        .param("value", "(not shown)")
                        .param("expected", reason),
                );
                None
            }
        },
        (Some(_), None) => {
            faults.push(requires("rpc-username", "rpc-password"));
            None
        }
        (None, Some(_)) => {
            faults.push(requires("rpc-password", "rpc-username"));
            None
        }
    }
}

/// `daemon-socks`, as a transport takes it: the proxy resolves names.
#[must_use]
pub fn socks_of(resolved: &Resolved) -> Option<String> {
    match resolved.get("daemon-socks") {
        Some(Value::Endpoint(addr)) => Some(format!("socks5h://{addr}")),
        _ => None,
    }
}

/// `daemon-socks` set with no `daemon-endpoint`.
///
/// This computer's node is reached on its owner's socket, so the proxy is
/// not a path to it. A caller whose proxy also reaches something else — the
/// CLI's external wallet server — skips this and keeps the target.
#[must_use]
pub fn proxy_without_endpoint(resolved: &Resolved) -> Option<Diagnostic> {
    match (socks_of(resolved), resolved.get("daemon-endpoint")) {
        (Some(_), None) => Some(requires(
            "daemon-socks",
            "daemon-endpoint: this computer's node is reached on its owner's socket, never \
             through a proxy",
        )),
        _ => None,
    }
}

/// `daemon-endpoint` through `daemon-socks`, or "this computer" when unset
/// (`RPC_CHANNEL.md` RT-15). An onion needs the proxy. A proxy with no
/// endpoint is not judged here; the caller applies [`proxy_without_endpoint`]
/// when the proxy has no other job.
pub fn daemon_of(
    resolved: &Resolved,
    network: Network,
    faults: &mut Vec<Diagnostic>,
) -> Option<DaemonTarget> {
    let proxy = socks_of(resolved);
    let url = match resolved.get("daemon-endpoint") {
        None => return Some(DaemonTarget::ThisComputer { network }),
        Some(Value::Peer(PeerEndpoint::Ip(addr))) => format!("http://{addr}"),
        Some(Value::Peer(PeerEndpoint::Onion { host, port })) => {
            if proxy.is_none() {
                faults.push(requires(
                    "daemon-endpoint",
                    "daemon-socks, to reach an onion",
                ));
                return None;
            }
            format!("http://{host}:{port}")
        }
        Some(other) => unreachable!("daemon-endpoint is a peer endpoint, not {other:?}"),
    };
    Some(DaemonTarget::Address { url, proxy })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn platform() -> Platform {
        Platform {
            home: Some(PathBuf::from(if cfg!(windows) {
                r"C:\nonexistent-shekyl-test-home"
            } else {
                "/nonexistent-shekyl-test-home"
            })),
            ..Platform::default()
        }
    }

    fn load_args(list: &[&str]) -> Result<Action, Vec<Diagnostic>> {
        load(list.iter().map(OsString::from), &platform())
    }

    fn served(list: &[&str]) -> Loaded {
        match load_args(list) {
            Ok(Action::Serve(loaded)) => *loaded,
            Ok(_) => panic!("{list:?} is not a serve"),
            Err(faults) => panic!("{list:?} refused: {faults:?}"),
        }
    }

    fn refused(list: &[&str]) -> Vec<Code> {
        match load_args(list) {
            Err(faults) => faults.into_iter().map(|d| d.code).collect(),
            Ok(_) => panic!("{list:?} was accepted"),
        }
    }

    /// With nothing given: loopback, no credentials, this computer's node,
    /// the per-network wallet directory, stderr only at `warn`. No log file
    /// unless one is named (Rick, 2026-11-23). Red edit: give `log-file` a
    /// default path, and the sink is set.
    #[test]
    fn the_defaults_are_loopback_this_computer_and_no_log_file() {
        let loaded = served(&["--network", "testnet"]);
        assert!(
            matches!(loaded.server.listen, ListenAddr::Tcp(addr) if addr.ip().is_loopback()),
            "{:?}",
            loaded.server.listen
        );
        assert!(matches!(loaded.server.auth, AuthConfig::Disabled));
        assert!(matches!(
            loaded.server.daemon,
            DaemonTarget::ThisComputer {
                network: Network::Testnet
            }
        ));
        assert!(loaded
            .server
            .wallet_dir
            .ends_with(std::path::Path::new("wallets").join("testnet")));
        assert!(loaded.default_wallet_dir.is_some());
        assert!(loaded.logging.file_sink.is_none(), "no file unless named");
        assert_eq!(loaded.logging.directive.as_str(), "warn");
        assert!(loaded.effective.starts_with("effective configuration: "));
    }

    /// The old spellings leave no trace (IG-5): each is an unknown name, and
    /// a bare word is not an option.
    #[test]
    fn the_retired_spellings_are_unknown_names() {
        for old in ["--rpc-bind", "--rpc-login", "--daemon-address", "--proxy"] {
            assert_eq!(refused(&[old]), [Code::NameUnknown], "{old}");
        }
        assert_eq!(refused(&["--disable-rpc-login"]), [Code::NameUnknown]);
        assert_eq!(refused(&["serve"]), [Code::CliSyntax]);
    }

    /// A client names no socket of the daemon's: the row is refused with its
    /// reason (`RPC_CHANNEL.md` RT-15; Rick, 2026-11-18).
    #[test]
    fn a_daemon_socket_file_is_refused_with_its_reason() {
        assert_eq!(refused(&["--daemon-socket-file"]), [Code::NameRejected]);
    }

    /// A proxy is the daemon-endpoint's. An onion needs the proxy; an IP
    /// keeps one when given. Red edit: drop the onion's check, and the
    /// second line accepts.
    #[test]
    fn the_daemon_rows_hold_together() {
        assert_eq!(
            refused(&["--daemon-socks", "127.0.0.1:9050"]),
            [Code::ValueRequires]
        );
        let onion = format!("{}.onion:12029", "a".repeat(55) + "d");
        let target = load_args(&["--daemon-endpoint", &onion]);
        if let Err(faults) = target {
            assert!(
                faults
                    .iter()
                    .all(|d| matches!(d.code, Code::ValueRequires | Code::ValueSyntax)),
                "{faults:?}"
            );
        } else {
            panic!("an onion with no proxy was accepted");
        }
        let loaded = served(&[
            "--daemon-endpoint",
            "192.0.2.1:12029",
            "--daemon-socks",
            "127.0.0.1:9050",
        ]);
        match loaded.server.daemon {
            DaemonTarget::Address { url, proxy } => {
                assert_eq!(url, "http://192.0.2.1:12029");
                assert_eq!(proxy.as_deref(), Some("socks5h://127.0.0.1:9050"));
            }
            other => panic!("not an address: {other:?}"),
        }
        assert_eq!(
            refused(&["--daemon-endpoint", "node.example:12029"]),
            [Code::ValueSyntax],
            "a hostname is refused (IG-Q31)"
        );
    }

    /// A socket file replaces the default listen address, and a named listen
    /// address beside it is a conflict.
    #[cfg(unix)]
    #[test]
    fn a_socket_file_replaces_the_default_listen_address() {
        let loaded = served(&["--rpc-socket-file", "/run/user/1000/w/rpc.sock"]);
        assert!(matches!(loaded.server.listen, ListenAddr::Uds(_)));
        assert_eq!(
            refused(&[
                "--rpc-socket-file",
                "/run/user/1000/w/rpc.sock",
                "--rpc-listen",
                "127.0.0.1:29500",
            ]),
            [Code::ValueConflict]
        );
    }

    /// `rpc-username` and `rpc-password` are file-only secrets: neither is
    /// accepted on the command line (IG-Q29), so no password reaches argv.
    #[test]
    fn credentials_are_refused_on_the_command_line() {
        for name in ["--rpc-username", "--rpc-password"] {
            assert_eq!(refused(&[name, "x"]), [Code::ValueSurface], "{name}");
        }
    }

    /// A wildcard listen address is refused at load, including the IPv4-mapped
    /// spelling the classifier folds. An addressed listen with no credentials
    /// is the same refusal family. Red edit: drop the posture call in `build`,
    /// and both lines are accepted.
    #[test]
    fn the_listen_posture_is_refused_at_load() {
        assert_eq!(
            refused(&["--rpc-listen", "0.0.0.0:29500"]),
            [Code::ValueRange]
        );
        assert_eq!(refused(&["--rpc-listen", "[::]:29500"]), [Code::ValueRange]);
        assert_eq!(
            refused(&["--rpc-listen", "[::ffff:0.0.0.0]:29500"]),
            [Code::ValueRange],
            "the mapped wildcard is the wildcard"
        );
        assert_eq!(
            refused(&["--rpc-listen", "192.0.2.1:29500"]),
            [Code::ValueRequires],
            "an addressed listener needs the credential pair"
        );
        let loaded = served(&["--rpc-listen", "127.0.0.1:29500"]);
        assert!(matches!(
            loaded.server.listen,
            ListenAddr::Tcp(addr) if addr.ip().is_loopback()
        ));
    }

    /// `config-verify` is its own action, on the same load a start takes.
    #[test]
    fn config_verify_is_the_same_load() {
        assert!(matches!(
            load_args(&["--config-verify", "--network", "testnet"]),
            Ok(Action::Verify(_))
        ));
        assert!(!refused(&["--config-verify", "--rpc-bind", "x"]).is_empty());
    }
}
