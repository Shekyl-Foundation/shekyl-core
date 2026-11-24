// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The CLI's configuration: the options before the first command word and
//! the file, read against [`TABLE`] by the one load
//! (`shekyl_daemon_config::load_table`) and built into what a run takes.
//! Reads no environment (IG-13) and creates nothing.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use shekyl_daemon_config::announce::effective_configuration;
use shekyl_daemon_config::{load_table, logging_to_named_file, Platform, Resolved};
use shekyl_options::{read_cli_then_words, Code, Diagnostic, PeerEndpoint, Source, Value};
use shekyl_rpc_transport::DaemonTarget;
use shekyl_wallet_rpc::config::{daemon_of, socks_of};
use shekyl_wallet_rpc::server::{TorFile, TOR_FILE_OPTION};
use shekyl_wallet_rpc::Network;

use crate::commands::scripted::PasswordSource;
use crate::enroll::{channel_leg, Remote};
use crate::table::{PASSWORD_STDIN, TABLE};

/// The file suffix of a wallet, as the server names it from a wallet's name.
const WALLET_EXTENSION: &str = "wallet";

/// What this run of the program does.
pub enum Action {
    /// `help`.
    Help,
    /// `version`.
    Version,
    /// `config-verify`: report the configuration and exit.
    Verify(Box<Options>),
    /// A session: the command words, or none for a prompt or a script.
    Run {
        /// The session's options.
        options: Box<Options>,
        /// The logging owner's section.
        logging: Box<shekyl_logging::Config>,
        /// The command after the options, as given.
        words: Vec<String>,
    },
}

/// A configuration the table accepted, built.
pub struct Options {
    /// The network.
    pub network: Network,
    /// `wallet-dir`, or the folder of `wallet-file`.
    pub wallet_dir: Option<PathBuf>,
    /// The wallet to open at start, by the name the server knows it by.
    pub wallet: Option<String>,
    /// The daemon this run reaches.
    pub daemon: DaemonTarget,
    /// An external wallet server's address, as the session dials it.
    pub wallet_rpc: Option<String>,
    /// The SOCKS proxy, as a transport takes it.
    pub socks: Option<String>,
    /// The node on another computer the enrollment words reach.
    pub enroll_remote: Option<Remote>,
    /// `rpc-key-file`.
    pub rpc_key_file: Option<PathBuf>,
    /// `debug`.
    pub debug: bool,
    /// `json`.
    pub json: bool,
    /// `wallet-password-file`.
    pub password: Option<PasswordSource>,
    /// `archival-complete-tree`.
    pub archival_complete_tree: bool,
    /// `archival-acknowledge`.
    pub archival_acknowledge: Option<&'static str>,
    /// `script-file`.
    pub script_file: Option<PathBuf>,
    /// The Tor binary the hosted server runs.
    pub tor_file: TorFile,
    /// The effective-configuration line (IG-14), shown by `config-verify`.
    pub effective: String,
}

fn conflict(option: &str, with: &str) -> Diagnostic {
    Diagnostic::new(Code::ValueConflict, Source::Cli)
        .option(option)
        .param("conflict", with)
}

fn requires(option: &str, requires: &str) -> Diagnostic {
    Diagnostic::new(Code::ValueRequires, Source::Cli)
        .option(option)
        .param("requires", requires)
}

fn path_of(resolved: &Resolved, name: &str) -> Option<PathBuf> {
    match resolved.get(name) {
        Some(Value::Path(path)) => Some(path.clone()),
        _ => None,
    }
}

fn switch_of(resolved: &Resolved, name: &str) -> bool {
    matches!(resolved.get(name), Some(Value::Switch(true)))
}

/// Read the arguments (without the program name) and the configuration
/// file, and decide what this run does. `stdin_is_terminal` decides whether
/// `wallet-password-file stdin` can be read without echoing it.
///
/// # Errors
///
/// Every refusal found, typed (IG-11).
pub fn load<I>(
    args: I,
    platform: &Platform,
    stdin_is_terminal: bool,
) -> Result<Action, Vec<Diagnostic>>
where
    I: IntoIterator<Item = OsString>,
{
    let (cli, words) = read_cli_then_words(&TABLE, args)?;
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
    let mut faults = Vec::new();
    let logging = match logging_to_named_file(&loaded.resolved) {
        Ok(logging) => Some(logging),
        Err(mut more) => {
            faults.append(&mut more);
            None
        }
    };
    let options = build(
        &loaded.resolved,
        loaded.network,
        &words,
        stdin_is_terminal,
        effective,
        &mut faults,
    );
    match (options, logging) {
        (Some(options), Some(logging)) if faults.is_empty() => Ok(if verify {
            Action::Verify(Box::new(options))
        } else {
            Action::Run {
                options: Box::new(options),
                logging: Box::new(logging),
                words,
            }
        }),
        _ => Err(faults),
    }
}

fn build(
    resolved: &Resolved,
    network: Network,
    words: &[String],
    stdin_is_terminal: bool,
    effective: String,
    faults: &mut Vec<Diagnostic>,
) -> Option<Options> {
    let socks = socks_of(resolved);
    let wallet_rpc = wallet_rpc_of(resolved, socks.is_some(), faults);
    let external = wallet_rpc.is_some();
    let (wallet, wallet_dir) = wallet_of(resolved, external, faults);
    let daemon = daemon_of(resolved, network, external, faults);
    let enroll_remote = enroll_remote_of(resolved, faults);
    let script_file = path_of(resolved, "script-file");
    if script_file.is_some() && !words.is_empty() {
        faults.push(conflict("script-file", "a command is given"));
    }
    let password = password_of(
        resolved,
        words.is_empty() && script_file.is_none(),
        stdin_is_terminal,
        faults,
    );
    let archival_complete_tree = switch_of(resolved, "archival-complete-tree");
    if archival_complete_tree && wallet.is_none() {
        faults.push(requires("archival-complete-tree", "wallet-file"));
    }
    let archival_acknowledge = match resolved.get("archival-acknowledge") {
        Some(Value::Word(phrase)) => Some(*phrase),
        _ => None,
    };
    let tor_path = path_of(resolved, TOR_FILE_OPTION);
    if external && tor_path.is_some() {
        faults.push(conflict(
            TOR_FILE_OPTION,
            "an external wallet server is set: that server runs its own Tor, so set it there",
        ));
    }
    let tor_file = match TorFile::from_option(tor_path) {
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
    Some(Options {
        network,
        wallet_dir,
        wallet,
        daemon: daemon?,
        wallet_rpc,
        socks,
        enroll_remote,
        rpc_key_file: path_of(resolved, "rpc-key-file"),
        debug: switch_of(resolved, "debug"),
        json: switch_of(resolved, "json"),
        password,
        archival_complete_tree,
        archival_acknowledge,
        script_file,
        tor_file: tor_file?,
        effective,
    })
}

/// `wallet-rpc-endpoint`, or `wallet-rpc-socket-file` in its place, as the
/// address the session dials.
fn wallet_rpc_of(
    resolved: &Resolved,
    has_socks: bool,
    faults: &mut Vec<Diagnostic>,
) -> Option<String> {
    let socket = path_of(resolved, "wallet-rpc-socket-file");
    match (resolved.get("wallet-rpc-endpoint"), socket) {
        (Some(_), Some(_)) => {
            faults.push(conflict(
                "wallet-rpc-endpoint",
                "wallet-rpc-socket-file is set",
            ));
            None
        }
        (None, None) => None,
        (None, Some(path)) => socket_url(&path, faults),
        (Some(Value::Peer(PeerEndpoint::Ip(addr))), None) => Some(format!("http://{addr}")),
        (Some(Value::Peer(PeerEndpoint::Onion { host, port })), None) => {
            if !has_socks {
                faults.push(requires(
                    "wallet-rpc-endpoint",
                    "daemon-socks, to reach an onion",
                ));
            }
            Some(format!("http://{host}:{port}"))
        }
        (Some(other), None) => unreachable!("wallet-rpc-endpoint is a peer, not {other:?}"),
    }
}

#[cfg(unix)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "one signature with Windows, which refuses the row"
)]
fn socket_url(path: &Path, _faults: &mut [Diagnostic]) -> Option<String> {
    Some(format!("uds://{}", path.display()))
}

#[cfg(windows)]
fn socket_url(_path: &Path, faults: &mut Vec<Diagnostic>) -> Option<String> {
    faults.push(
        Diagnostic::new(Code::SocketDirPlatform, Source::Cli)
            .option("wallet-rpc-socket-file")
            .param(
                "reason",
                "a Unix socket has no Windows form; leave it unset to host the wallet server \
                 here, or name wallet-rpc-endpoint",
            ),
    );
    None
}

/// `wallet-file` as the wallet's name and folder, and `wallet-dir`. The
/// server knows a wallet by its name in one directory, so a path that is
/// not `<dir>/<name>.wallet`, or that disagrees with `wallet-dir`, is
/// refused rather than read as something else.
fn wallet_of(
    resolved: &Resolved,
    external: bool,
    faults: &mut Vec<Diagnostic>,
) -> (Option<String>, Option<PathBuf>) {
    let named_dir = path_of(resolved, "wallet-dir");
    let Some(file) = path_of(resolved, "wallet-file") else {
        return (None, named_dir);
    };
    if external {
        faults.push(conflict(
            "wallet-file",
            "an external wallet server is set: its wallets are on its computer, so use \
             `wallet open <name>`",
        ));
        return (None, named_dir);
    }
    let Some((folder, name)) = wallet_path_parts(&file) else {
        faults.push(
            Diagnostic::new(Code::ValueSyntax, Source::Cli)
                .option("wallet-file")
                .param("value", file.display().to_string())
                .param("expected", "an absolute path ending in <name>.wallet"),
        );
        return (None, named_dir);
    };
    if named_dir.as_ref().is_some_and(|dir| *dir != folder) {
        faults.push(conflict(
            "wallet-file",
            "wallet-dir is set to another folder; set one of them",
        ));
    }
    (Some(name), Some(folder))
}

fn wallet_path_parts(file: &Path) -> Option<(PathBuf, String)> {
    if file.extension()?.to_str()? != WALLET_EXTENSION {
        return None;
    }
    let name = file.file_stem()?.to_str()?;
    if name.is_empty() {
        return None;
    }
    Some((file.parent()?.to_path_buf(), name.to_owned()))
}

/// `daemon-bundle-file`: the node on another computer the enrollment words
/// reach, at `daemon-endpoint` over the channel.
fn enroll_remote_of(resolved: &Resolved, faults: &mut Vec<Diagnostic>) -> Option<Remote> {
    let bundle_file = path_of(resolved, "daemon-bundle-file")?;
    let Some(Value::Peer(peer)) = resolved.get("daemon-endpoint") else {
        faults.push(requires(
            "daemon-bundle-file",
            "daemon-endpoint, the channel's address: the usual daemon port is the plaintext \
             listener, which is not the channel",
        ));
        return None;
    };
    let socks = match resolved.get("daemon-socks") {
        Some(Value::Endpoint(addr)) => Some(*addr),
        _ => None,
    };
    match channel_leg(peer, socks) {
        Ok(leg) => Some(Remote { leg, bundle_file }),
        Err(fault) => {
            faults.push(fault);
            None
        }
    }
}

/// `wallet-password-file`. Standard input is refused when it carries the
/// commands, and at a terminal, where the line would be echoed and the
/// hidden prompt is the way to give a password.
fn password_of(
    resolved: &Resolved,
    stdin_carries_commands: bool,
    stdin_is_terminal: bool,
    faults: &mut Vec<Diagnostic>,
) -> Option<PasswordSource> {
    match resolved.get("wallet-password-file") {
        Some(Value::Path(path)) => Some(PasswordSource::File(path.clone())),
        Some(Value::Word(word)) if *word == PASSWORD_STDIN => {
            if stdin_is_terminal {
                faults.push(conflict(
                    "wallet-password-file",
                    "standard input is a terminal, which would show the password: leave the \
                     option unset and the prompt asks without echoing",
                ));
            } else if stdin_carries_commands {
                faults.push(conflict(
                    "wallet-password-file",
                    "standard input carries the commands: give a command, a script-file, or a \
                     password file",
                ));
            }
            Some(PasswordSource::Stdin)
        }
        _ => None,
    }
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

    fn absolute(tail: &str) -> String {
        if cfg!(windows) {
            format!(r"C:\w\{tail}")
        } else {
            format!("/w/{tail}")
        }
    }

    fn load_args(list: &[&str], terminal: bool) -> Result<Action, Vec<Diagnostic>> {
        load(list.iter().map(OsString::from), &platform(), terminal)
    }

    fn run(list: &[&str]) -> (Options, Vec<String>) {
        match load_args(list, false) {
            Ok(Action::Run { options, words, .. }) => (*options, words),
            Ok(_) => panic!("{list:?}: not a run"),
            Err(faults) => panic!("{list:?}: {faults:?}"),
        }
    }

    fn refused(list: &[&str]) -> Vec<Code> {
        match load_args(list, false) {
            Err(faults) => faults.into_iter().map(|d| d.code).collect(),
            Ok(_) => panic!("{list:?}: accepted"),
        }
    }

    /// The default run is mainnet, this computer's node, no wallet, no log
    /// file. Red edit: default `log-file` to a path, and `a_log_file` in
    /// the shared mapping fails; here the run still names none.
    #[test]
    fn the_defaults_are_this_computers_node_on_mainnet() {
        let (options, words) = run(&[]);
        assert_eq!(options.network, Network::Mainnet);
        assert!(words.is_empty());
        assert!(options.wallet.is_none() && options.wallet_rpc.is_none());
        assert!(matches!(
            options.daemon,
            DaemonTarget::ThisComputer {
                network: Network::Mainnet
            }
        ));
    }

    /// Options end at the first word: a word's own flags are the catalog's,
    /// passed through verbatim.
    #[test]
    fn the_command_follows_the_options_verbatim() {
        let (options, words) = run(&[
            "--network",
            "testnet",
            "wallet",
            "create",
            "w",
            "--mnemonic-file",
            "/m",
        ]);
        assert_eq!(options.network, Network::Testnet);
        assert_eq!(words, ["wallet", "create", "w", "--mnemonic-file", "/m"]);
    }

    /// Every retired spelling is an unknown name: no aliases (IG-5).
    #[test]
    fn the_retired_spellings_are_unknown() {
        for name in [
            "--testnet",
            "--stagenet",
            "--engine-dir",
            "--engine-file",
            "--wallet",
            "--daemon-address",
            "--rpc-url",
            "--proxy",
            "--password-file",
            "--complete-tree-foundation",
            "--acknowledge",
            "--script",
        ] {
            assert_eq!(refused(&[name, "x"]), [Code::NameUnknown], "{name}");
        }
    }

    /// `wallet-file` is `<dir>/<name>.wallet`, and anything else is refused
    /// rather than read as a name. Red edit: drop the extension check, and
    /// the second case opens a wallet called `notes`.
    #[test]
    fn a_wallet_file_is_a_wallet_path_or_refused() {
        let file = absolute("alice.wallet");
        let (options, _) = run(&["--wallet-file", &file]);
        assert_eq!(options.wallet.as_deref(), Some("alice"));
        assert_eq!(
            options.wallet_dir.as_deref(),
            Path::new(&file).parent(),
            "its folder is the wallet directory"
        );

        let other = absolute("notes.txt");
        assert_eq!(refused(&["--wallet-file", &other]), [Code::ValueSyntax]);

        let dir = absolute("elsewhere");
        assert_eq!(
            refused(&["--wallet-file", &file, "--wallet-dir", &dir]),
            [Code::ValueConflict]
        );
        assert_eq!(
            refused(&[
                "--wallet-file",
                &file,
                "--wallet-rpc-endpoint",
                "127.0.0.1:1"
            ]),
            [Code::ValueConflict],
            "an external server's wallets are on its computer"
        );
    }

    /// The daemon rows are the wallet server's: an onion needs the proxy,
    /// and a proxy without an endpoint is refused unless it is for an
    /// external wallet server.
    #[test]
    fn the_daemon_and_server_rows_are_checked() {
        let (options, _) = run(&["--daemon-endpoint", "192.0.2.1:18081"]);
        assert!(matches!(
            options.daemon,
            DaemonTarget::Address { ref url, proxy: None } if url == "http://192.0.2.1:18081"
        ));
        assert_eq!(
            refused(&["--daemon-socks", "127.0.0.1:9050"]),
            [Code::ValueRequires]
        );
        let (external, _) = run(&[
            "--wallet-rpc-endpoint",
            "192.0.2.1:29500",
            "--daemon-socks",
            "127.0.0.1:9050",
        ]);
        assert_eq!(
            external.wallet_rpc.as_deref(),
            Some("http://192.0.2.1:29500")
        );
        assert_eq!(external.socks.as_deref(), Some("socks5h://127.0.0.1:9050"));
        let socket = absolute("s");
        assert_eq!(
            refused(&[
                "--wallet-rpc-endpoint",
                "127.0.0.1:1",
                "--wallet-rpc-socket-file",
                &socket
            ]),
            [Code::ValueConflict]
        );
    }

    /// The Tor binary is the hosted server's, so naming an external server
    /// beside it is refused.
    #[test]
    fn the_tor_file_is_refused_with_an_external_server() {
        let tor = absolute("tor");
        assert_eq!(
            refused(&["--tor-file", &tor, "--wallet-rpc-endpoint", "127.0.0.1:1"]),
            [Code::ValueConflict]
        );
    }

    /// A password on standard input needs standard input to be free and
    /// not a terminal. Red edit: drop the terminal arm, and the last case
    /// accepts a password that would be echoed.
    #[test]
    fn a_password_on_standard_input_is_checked() {
        let (options, _) = run(&["--wallet-password-file", "stdin", "balance"]);
        assert!(matches!(options.password, Some(PasswordSource::Stdin)));
        assert_eq!(
            refused(&["--wallet-password-file", "stdin"]),
            [Code::ValueConflict],
            "standard input is the commands"
        );
        let at_terminal = load_args(&["--wallet-password-file", "stdin", "balance"], true);
        let Err(faults) = at_terminal else {
            panic!("a terminal must refuse it");
        };
        assert_eq!(faults[0].code, Code::ValueConflict);
    }

    /// A script file and a command are two sources for one session, and the
    /// archival bond needs the wallet it posts from.
    #[test]
    fn the_session_rows_are_checked() {
        let script = absolute("s.txt");
        assert_eq!(
            refused(&["--script-file", &script, "balance"]),
            [Code::ValueConflict]
        );
        assert_eq!(
            refused(&["--archival-complete-tree"]),
            [Code::ValueRequires]
        );
    }

    /// The enrollment words' remote leg needs the channel's address.
    #[test]
    fn a_bundle_needs_the_channels_address() {
        let bundle = absolute("bundle");
        assert_eq!(
            refused(&["--daemon-bundle-file", &bundle]),
            [Code::ValueRequires]
        );
        let (options, _) = run(&[
            "--daemon-bundle-file",
            &bundle,
            "--daemon-endpoint",
            "192.0.2.1:18090",
        ]);
        assert!(options.enroll_remote.is_some());
    }

    /// The daemon's rejected row names its reason.
    #[test]
    fn the_rejected_rows_are_refused() {
        let path = absolute("x");
        assert_eq!(
            refused(&["--daemon-socket-file", &path]),
            [Code::NameRejected]
        );
        assert_eq!(refused(&["--daemon-ca-cert", &path]), [Code::NameRejected]);
    }
}
