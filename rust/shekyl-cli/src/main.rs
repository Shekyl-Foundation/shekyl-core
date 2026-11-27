// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! shekyl-cli: interactive CLI wallet for Shekyl.
//!
//! Thin REPL frontend over the native `shekyl-wallet-rpc` JSON-RPC surface
//! (Shape B, `docs/V3_WALLET_DECISION_LOG.md` 2026-04-25). By default the
//! CLI self-hosts an in-process RPC server over a private UDS socket;
//! `wallet-rpc-endpoint` or `wallet-rpc-socket-file` connects to an external
//! `shekyl-wallet-rpc` instead. Its options are `INPUT_GRAMMAR.md` §12.1
//! ([`shekyl_cli::table`]); they end at the first command word. There is no
//! wallet2 / FFI path.
#![deny(unsafe_code)]

use std::io::Write as _;

use shekyl_cli::config::{self, Action, Options};
use shekyl_cli::outcome::{refusal, Presentation, Render, Transcript};
use shekyl_cli::table::TABLE;
use shekyl_cli::{commands, daemon, prompt_password, rpc_client};
use shekyl_daemon_config::exit::{EXIT_FAILED, EXIT_REFUSED};
use shekyl_rpc_transport::network_posture::{self, ProxyResolution};
use shekyl_rpc_transport::DaemonTarget;
use shekyl_wallet_rpc::Network;

const PROGRAM: &str = "shekyl-cli";

/// The note `--help` prints above the options.
const HELP_NOTE: &str = "Shekyl wallet. Options come before the command; `shekyl-cli help` lists \
                         the commands. Values come from the command line, then the \
                         configuration file, then the defaults.";

/// The daemon connection this invocation opens: where it dials, and how the
/// transport that dials it resolves a hostname under `daemon-socks` — which is
/// what decides whether the DNS-leak half of the disclosure is true of it.
/// Named for the endpoint, not the daemon: the `daemon` module beside it
/// holds the client that dials this.
struct DaemonEndpoint {
    target: DaemonTarget,
    resolution: ProxyResolution,
}

/// Every endpoint this invocation opens, decided once from the options.
///
/// The wallet server and the daemon are separately configurable, and the
/// session, the disclosure and the daemon client all need to know which are
/// dialed.
enum Endpoints {
    /// An external wallet-RPC server does the wallet work. The session
    /// additionally opens its own daemon client.
    External { url: String, daemon: DaemonEndpoint },
    /// The default: a wallet-RPC server hosted in this process, scanning
    /// over its own daemon connection.
    SelfHosted {
        network: Network,
        daemon: DaemonEndpoint,
    },
}

impl Endpoints {
    /// The session's direct daemon client honors the proxy's scheme, and
    /// the options only ever name `socks5h://`, so the proxy resolves names
    /// on every path.
    fn of(options: &Options) -> Self {
        let daemon = DaemonEndpoint {
            target: options.daemon.clone(),
            resolution: ProxyResolution::HonorsScheme,
        };
        match &options.wallet_rpc {
            Some(url) => Self::External {
                url: url.clone(),
                daemon,
            },
            None => Self::SelfHosted {
                network: options.network,
                daemon,
            },
        }
    }

    /// The daemon this run dials.
    fn daemon(&self) -> &DaemonEndpoint {
        match self {
            Self::External { daemon, .. } | Self::SelfHosted { daemon, .. } => daemon,
        }
    }
}

fn presentation_for(interactive: bool, json: bool, debug: bool) -> Presentation {
    Presentation {
        transcript: if interactive {
            Transcript::Interactive
        } else {
            Transcript::Scripted
        },
        render: if json { Render::Json } else { Render::Human },
        debug,
    }
}

/// Tell the operator about a failure that happened before a command printer
/// ran, then stop. One envelope, the same one the command loop uses.
fn stop(
    presentation: &Presentation,
    command: &str,
    error: shekyl_cli::outcome::CommandFailed,
) -> ! {
    commands::publish_failure(presentation, command, error);
    std::process::exit(1);
}

/// Stop a session that already owns a server. `process::exit` skips
/// destructors, so the server is shut down before the envelope is the last
/// thing the process does.
fn stop_session(
    rpc: rpc_client::RpcSession,
    presentation: &Presentation,
    command: &str,
    error: shekyl_cli::outcome::CommandFailed,
) -> ! {
    let close = rpc.shutdown();
    // The failure is on standard error, which a closed standard output does
    // not close. Then the closed-output line, if a write there has failed.
    commands::publish_failure(presentation, command, error);
    rpc_client::exit_if_output_closed(close);
    std::process::exit(1);
}

/// The first statement is the process hardening (rule 35, DC-Q21), as in
/// `shekyld`: no core and no same-account tracer, before an argument is
/// read, a wallet opened, or a password asked for. A process that cannot
/// apply it says so on standard error and exits 1 without starting.
fn main() {
    if let Err(e) = shekyl_process::harden::harden_process() {
        // A closed standard error must not turn the refusal into a panic.
        drop(writeln!(
            std::io::stderr(),
            "{PROGRAM}: process hardening {e}; not starting"
        ));
        std::process::exit(EXIT_FAILED);
    }
    let platform = shekyl_process::platform::current();
    let stdin_is_terminal = std::io::IsTerminal::is_terminal(&std::io::stdin());
    let action = match config::load(std::env::args_os().skip(1), &platform, stdin_is_terminal) {
        Ok(action) => action,
        Err(faults) => {
            for fault in &faults {
                shekyl_cli::err_line!("{PROGRAM}: {}", fault.render());
            }
            std::process::exit(EXIT_REFUSED);
        }
    };
    match action {
        Action::Help => shekyl_cli::out_inline!(
            "{}",
            shekyl_options::help(
                &TABLE,
                PROGRAM,
                shekyl_version::RELEASE_NAME,
                shekyl_version::VERSION_FULL,
                HELP_NOTE,
            )
        ),
        Action::Version => {
            shekyl_cli::out_line!("{PROGRAM} {}", shekyl_version::VERSION_FULL);
        }
        Action::Verify(options) => verify(&options),
        Action::Run {
            options,
            logging,
            words,
        } => session(&options, *logging, words),
    }
    // A session path shuts down before it returns and exits there when the
    // output closed. This is the path that had no session, or a write that
    // failed after the session was already gone. No wallet was open on it.
    rpc_client::exit_if_output_closed(rpc_client::WalletClose::NotOpen);
}

/// `config-verify` (IG-Q63): the checks a start makes, connecting to nothing
/// and creating nothing. The effective configuration is on standard output,
/// the only place the CLI shows it, and the exposure warnings a start would
/// give are on standard error.
fn verify(options: &Options) {
    if let DaemonTarget::Address { url, proxy } = &options.daemon {
        if let Err(e) = shekyl_rpc_transport::validate_endpoint(url, proxy.as_deref()) {
            shekyl_cli::err_line!("{PROGRAM}: {e}");
            std::process::exit(EXIT_REFUSED);
        }
    }
    disclose_network_posture(options, &Endpoints::of(options));
    shekyl_cli::out_line!("{PROGRAM}: configuration verified");
    shekyl_cli::out_line!("{PROGRAM}: {}", options.effective);
}

/// One session: the command words, a script file, standard input, or the
/// prompt. Only a terminal with no command and no script file is a
/// conversation.
fn session(options: &Options, logging: shekyl_logging::Config, words: Vec<String>) {
    let scripted = presentation_for(false, options.json, options.debug);
    let source = if words.is_empty() {
        match &options.script_file {
            Some(path) => match std::fs::read_to_string(path) {
                Ok(text) => {
                    commands::CommandSource::File(text.lines().map(str::to_owned).collect())
                }
                Err(error) => stop(
                    &scripted,
                    "script",
                    refusal(format!("cannot read script {}: {error}", path.display())),
                ),
            },
            None if !std::io::IsTerminal::is_terminal(&std::io::stdin()) => {
                commands::CommandSource::Stdin
            }
            None => commands::CommandSource::Terminal,
        }
    } else {
        commands::CommandSource::One(words)
    };
    let presentation = presentation_for(
        matches!(source, commands::CommandSource::Terminal),
        options.json,
        options.debug,
    );
    if let Err(error) = run_session(&presentation, options, logging, source) {
        stop(&presentation, "session", refusal(error.to_string()));
    }
}

/// Disclose network exposure for every endpoint this invocation will actually
/// use — the §15 asymmetric warn-only rule (WI-4 §15, 2026-07-23) and, for the
/// daemon, the §1 operator statement (`RPC_TRANSPORT_POSTURE.md`, RT-W7).
/// Warns on a clear-network endpoint and on a daemon that is not loopback,
/// silent otherwise, and **never** emits an assurance; see `network_posture`
/// for why the asymmetry is load-bearing.
///
/// Both endpoints are checked because they are separately configurable and
/// carry different exposure: a wallet-RPC endpoint reaches a server that sees
/// balances, addresses, and commands, a daemon endpoint reaches a node.
///
/// Called after the session is built and before the daemon client: what is
/// said is what this run is *configured to dial*, said while the operator
/// can still fix it (rule 82). The session comes first so that an address
/// the session itself refused is never announced — the self-hosted server
/// validates the daemon endpoint as it starts, the same order
/// `shekyl-wallet-rpc` keeps in `arm_server`. The `DaemonClient` comes after,
/// deliberately: it can fail for reasons that are not the endpoint's (an
/// unusable proxy), and such a failure reports itself without retracting
/// what the configured address would expose — a disclosure withheld until
/// every dial succeeded would go missing exactly when a misconfigured run
/// most needs it.
fn disclose_network_posture(options: &Options, endpoints: &Endpoints) {
    // The module says what is true; this binary says it on stderr, where
    // the operator who typed the option is looking.
    fn say(warnings: impl IntoIterator<Item = String>) {
        for warning in warnings {
            shekyl_cli::err_line!("{warning}");
        }
    }

    if let Endpoints::External { url, .. } = endpoints {
        // A socket is not a network path, and the far end of an address is
        // a wallet server, not a daemon: the path disclosure alone.
        if rpc_client::is_supported_rpc_url(url) {
            say(network_posture::disclose(
                "wallet-RPC endpoint",
                url,
                options.socks.as_deref(),
                ProxyResolution::HonorsScheme,
            ));
        }
    }

    // "This computer" is no network path: nothing to disclose.
    if let DaemonEndpoint {
        target: DaemonTarget::Address { url, proxy },
        resolution,
    } = endpoints.daemon()
    {
        say(network_posture::daemon_disclosures(
            "daemon endpoint",
            url,
            proxy.as_deref(),
            *resolution,
        ));
    }
}

/// Build the wallet-RPC session: an external server when one is named,
/// otherwise a self-hosted in-process server.
fn build_session(
    options: &Options,
    endpoints: &Endpoints,
) -> Result<rpc_client::RpcSession, Box<dyn std::error::Error>> {
    match endpoints {
        Endpoints::External { url, .. } => Ok(rpc_client::RpcSession::connect(
            url,
            options.socks.as_deref(),
            options.debug,
        )?),
        Endpoints::SelfHosted { network, daemon } => {
            let Some(wallet_dir) = options.wallet_dir.clone() else {
                return Err(
                    "a self-hosted run has no wallet directory; the load resolves it".into(),
                );
            };
            host_session(
                wallet_dir,
                *network,
                daemon.target.clone(),
                options.tor_file.clone(),
                options.debug,
                shekyl_os_account::per_account_root().as_deref(),
            )
        }
    }
}

/// A self-hosted session's start, everything `build_session` does past
/// reading the flags: the per-account root `root` is made first, as the
/// daemon makes it, so whatever is made in it after has the root's
/// protections (`None`: the account has no home). The wallet directory, the
/// per-network default or an explicit `wallet-dir`, is not made here: it
/// is made only when a wallet is created or restored in it
/// (`RpcSession::make_wallet_dir`), so a word that makes no wallet makes no
/// folder.
fn host_session(
    wallet_dir: std::path::PathBuf,
    network: Network,
    daemon: DaemonTarget,
    tor_file: shekyl_wallet_rpc::server::TorFile,
    debug: bool,
    root: Option<&std::path::Path>,
) -> Result<rpc_client::RpcSession, Box<dyn std::error::Error>> {
    if let Some(root) = root {
        shekyl_os_account::ensure_per_account_root(root)
            .map_err(|e| format!("cannot create {}: {e}", root.display()))?;
    }
    rpc_client::RpcSession::host_in_process(wallet_dir, network, daemon, tor_file, debug)
}

/// The daemon-down hint (CU-1, CLI_USABILITY.md §CU-5 F1): when this run
/// dials this machine's daemon, a refused connection names the invocation
/// that would start one — `shekyld --network testnet` — instead of a bare
/// "connection refused". A remote daemon gets no hint: "start it" copy for
/// a machine the operator may not control would mislead.
fn daemon_down_hint(network: Network, target: &DaemonTarget) -> Option<String> {
    // Mainnet is the daemon's default network, so its invocation is flagless.
    let flag = match network {
        Network::Mainnet => String::new(),
        other => format!(" --network {other}"),
    };
    match target {
        DaemonTarget::ThisComputer { .. } => Some(format!(
            "Start the {network} daemon with: shekyld{flag} (this shell reaches it on its own \
             socket)."
        )),
        // Same classification as the startup disclosure: a substring match
        // on "127.0.0.1" would accept 127.0.0.1.evil.com and miss
        // 127.0.0.0/8. Loopback-only hint — "start shekyld" is true of this
        // machine, not of a remote node the operator named.
        DaemonTarget::Address { url, .. } if daemon::is_loopback_endpoint(url) => Some(format!(
            "Start the {network} daemon with: shekyld{flag} (its RPC answers on port {port}).",
            port = network.ports().rpc,
        )),
        DaemonTarget::Address { .. } => None,
    }
}

fn run_session(
    presentation: &Presentation,
    options: &Options,
    logging: shekyl_logging::Config,
    source: commands::CommandSource,
) -> Result<(), Box<dyn std::error::Error>> {
    let _guard = shekyl_logging::init(logging)?;

    let endpoints = Endpoints::of(options);
    let rpc = build_session(options, &endpoints)?;
    disclose_network_posture(options, &endpoints);

    let network = options.network;
    let target = &endpoints.daemon().target;
    let daemon_client =
        match daemon::DaemonClient::new(target.clone(), daemon_down_hint(network, target), network)
        {
            Ok(dc) => Some(dc),
            Err(daemon::DaemonError::NotConfigured) => None,
            Err(e) => {
                shekyl_cli::err_line!("Warning: daemon client init failed: {e}");
                None
            }
        };

    // F1 at startup (CLI_USABILITY.md §CU-5): a dead local daemon is the
    // most common first-run state; disclose it now rather than at the first
    // command that needs it. Loopback only — probing a remote daemon at
    // startup would spend a Tor circuit on a courtesy check.
    if let Some(ref dc) = daemon_client {
        if dc.is_loopback() {
            if let Err(e) = dc.daemon_status() {
                if matches!(e, daemon::DaemonError::ConnectionRefused { .. }) {
                    shekyl_cli::err_line!("Note: {e}");
                }
            }
        }
    }

    let rpc = match &options.wallet {
        Some(filename) => open_at_start(rpc, presentation, options, filename),
        None => rpc,
    };

    let enroll = shekyl_cli::enroll::EnrollOptions {
        network,
        remote: options.enroll_remote.clone(),
        key_file: options.rpc_key_file.clone(),
    };
    commands::run(
        rpc,
        daemon_client.as_ref(),
        &enroll,
        options.password.as_ref(),
        network,
        *presentation,
        source,
    )
}

/// `wallet-file`: open the wallet before the first command, and post the
/// archival bond when `archival-complete-tree` is set. A failure ends the
/// session here.
fn open_at_start(
    rpc: rpc_client::RpcSession,
    presentation: &Presentation,
    options: &Options,
    filename: &str,
) -> rpc_client::RpcSession {
    if !presentation.interactive() && options.password.is_none() {
        stop_session(
            rpc,
            presentation,
            "wallet open",
            refusal(
                "A script must set wallet-password-file with wallet-file. \
                 Stdin is the script, not the password.",
            ),
        );
    }
    if options.archival_complete_tree {
        if let Err(error) =
            commands::accept_foundation_terms(presentation, options.archival_acknowledge)
        {
            stop_session(rpc, presentation, "archival-complete-tree", error);
        }
    }
    let password = match &options.password {
        Some(source) => match source.read() {
            Ok(password) => password,
            Err(error) => stop_session(rpc, presentation, "wallet open", error),
        },
        None => match prompt_password("Wallet password: ") {
            Ok(password) => password,
            Err(error) => stop_session(
                rpc,
                presentation,
                "wallet open",
                refusal(format!("Failed to read password: {error}")),
            ),
        },
    };
    if !commands::publish_wallet_open(presentation, &rpc, filename, &password) {
        drop(password);
        rpc_client::exit_if_output_closed(rpc.shutdown());
        std::process::exit(EXIT_FAILED);
    }
    if options.archival_complete_tree {
        let sealed = commands::publish_foundation_stake(presentation, &rpc, &password);
        drop(password);
        if !sealed {
            rpc_client::exit_if_output_closed(rpc.shutdown());
            std::process::exit(EXIT_FAILED);
        }
    }
    rpc
}

// The binary's tests sit beside this file (`main_tests.rs`) so the
// session and the command loop stay the body of `main.rs`.
#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
