// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! shekyl-cli: interactive CLI wallet for Shekyl.
//!
//! Thin REPL frontend over the native `shekyl-wallet-rpc` JSON-RPC surface
//! (Shape B, `docs/V3_WALLET_DECISION_LOG.md` 2026-04-25). By default the
//! CLI self-hosts an in-process RPC server over a private UDS socket;
//! `--rpc-url` connects to an external `shekyl-wallet-rpc` daemon instead.
//! There is no wallet2 / FFI path.
#![deny(unsafe_code)]

use std::io::Write as _;

use clap::{Parser, Subcommand};
use shekyl_cli::outcome::{refusal, Presentation, Render, Transcript};
use shekyl_cli::{commands, daemon, prompt_password, rpc_client};
use shekyl_rpc_transport::network_posture::{self, ProxyResolution};
use shekyl_rpc_transport::DaemonTarget;
use shekyl_wallet_rpc::Network;

#[derive(Parser)]
#[command(
    name = "shekyl-cli",
    about = "Shekyl interactive CLI wallet",
    version = shekyl_version::VERSION_FULL,
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    repl: ReplArgs,
}

#[derive(Subcommand)]
enum Commands {
    /// Offline check that the embedded ADDRESS_DERIVATION_V3 corpus matches
    /// the compile-time manifest hash pin (release / genesis tooling).
    DerivationFreezeSelfCheck,

    /// Non-interactively create a wallet, writing its one-time seed backup to
    /// a file (for scripting / automation). Connection flags (--network,
    /// --testnet, --wallet-dir, --rpc-url, …) are global: they parse before
    /// or after the subcommand name.
    Create(commands::scripted::CreateArgs),

    /// Non-interactively restore a wallet from a seed file (for scripting /
    /// automation). Connection flags are global: before or after the
    /// subcommand name.
    Restore(commands::scripted::RestoreArgs),

    /// One wallet command, in the same words as the prompt. Parsed by the
    /// prompt grammar, not a second flag set.
    #[command(external_subcommand)]
    Words(Vec<String>),
}

/// Shared connection flags. Every arg is `global`, so they parse before or
/// after a subcommand name (CU-1: `shekyl-cli create w --testnet` works).
#[derive(Parser)]
pub struct ReplArgs {
    /// Daemon address (host:port or full URL). Default: this machine's
    /// daemon at the RPC port for the selected network. With --rpc-url the
    /// self-hosted wallet RPC is not started, but the REPL still queries the
    /// daemon at this address directly.
    #[arg(long, global = true)]
    daemon_address: Option<String>,

    /// Connect to an external shekyl-wallet-rpc daemon instead of
    /// self-hosting one (http://host:port, or uds:///path/to.sock on Unix).
    /// The URL names the server; calls go to its /json_rpc.
    #[arg(long, global = true)]
    rpc_url: Option<String>,

    /// Network the self-hosted wallet server binds to: mainnet, testnet,
    /// stagenet. With --rpc-url that server is not started, and the flag is
    /// then read only to supply the default daemon port (so a run that names
    /// its own --daemon-address never consults it).
    #[arg(long, global = true, default_value = "mainnet")]
    network: String,

    /// Use the test network (same as --network testnet, and the same flag
    /// shekyld takes). No flag means mainnet — the network is never
    /// remembered between runs.
    #[arg(long, global = true, conflicts_with_all = ["network", "stagenet"])]
    testnet: bool,

    /// Use the staging network (same as --network stagenet).
    #[arg(long, global = true, conflicts_with = "network")]
    stagenet: bool,

    /// Directory for wallet files. Default: ~/.shekyl/wallets/<network>/
    /// (created on demand), so wallets on different networks never share a
    /// directory. Ignored with --rpc-url.
    #[arg(long, global = true, alias = "engine-dir")]
    wallet_dir: Option<String>,

    /// Open this wallet immediately on startup.
    #[arg(long, global = true, alias = "engine-file")]
    wallet: Option<String>,

    /// SOCKS proxy for the wallet's daemon connections — the self-hosted
    /// block scan and the REPL's direct daemon queries (e.g.
    /// socks5h://127.0.0.1:9050). Prefer `socks5h://`: the scan resolves the
    /// daemon hostname at the proxy regardless, but the direct queries honor
    /// the scheme, and `socks5://` resolves it locally (a DNS leak).
    #[arg(long, global = true)]
    proxy: Option<String>,

    /// The node's public bundle, as `rpc bundle show` prints it on that
    /// node. Set, the enrollment words reach the node at --daemon-address
    /// over the channel, as this client's key (--rpc-key-file). The address
    /// is required then: it is the channel listener, and the usual daemon
    /// port is the plaintext listener. Unset, the enrollment words reach
    /// this computer's node (`INPUT_GRAMMAR.md` IG-Q108).
    #[arg(long, global = true, value_name = "PATH")]
    daemon_bundle_file: Option<std::path::PathBuf>,

    /// This client's channel key, readable by this account alone (made with
    /// `rpc key create`). Default: the account root and
    /// `rpc-shekyl-cli-<network>.key` (IG-Q108, IG-Q109).
    #[arg(long, global = true, value_name = "PATH")]
    rpc_key_file: Option<std::path::PathBuf>,

    /// Show structured RPC error details (error.data) on failures.
    #[arg(long, global = true, default_value_t = false)]
    pub debug: bool,

    /// Read the wallet password from this file when `--wallet` is set.
    /// Required when stdin is not a terminal. The file is left as it is;
    /// the password read from it is wiped from memory once the wallet opens.
    #[arg(long, global = true, value_name = "PATH")]
    password_file: Option<std::path::PathBuf>,

    /// Post a Foundation CompleteTree bond before the prompt. Hidden: this
    /// is an unbounded-disk, non-earning posture, not a normal command.
    #[arg(long, global = true, hide = true)]
    complete_tree_foundation: bool,

    /// The exact phrase `serve without reward`, required with
    /// `--complete-tree-foundation` when stdin is not a terminal.
    #[arg(long, global = true, hide = true, value_name = "PHRASE")]
    acknowledge: Option<String>,

    /// Print one JSON object per command instead of human text.
    /// Seeds and passwords are never included.
    #[arg(long, global = true, default_value_t = false)]
    json: bool,

    /// Run the commands in this file as one wallet session. `#` starts a
    /// comment. The first failure stops the file.
    #[arg(long, global = true, value_name = "PATH")]
    script: Option<std::path::PathBuf>,
}

impl ReplArgs {
    /// The selected network's name: `--testnet` / `--stagenet` shorthand
    /// first (clap rejects combining them with `--network`), else the
    /// `--network` value as typed. Not yet validated — [`parse_network`]
    /// does that where a `Network` is actually needed.
    fn network_name(&self) -> &str {
        if self.testnet {
            "testnet"
        } else if self.stagenet {
            "stagenet"
        } else {
            &self.network
        }
    }

    /// The daemon this invocation dials (`RPC_CHANNEL.md` RT-15; RT-W10
    /// step 5): `--daemon-address` as given, through `--proxy`; or, with no
    /// address, "this computer", the node this account runs on the selected
    /// network, reached on its own leg and never through a proxy. With
    /// `--rpc-url` the proxy is that server's, so it does not reach this
    /// computer's node; in a self-hosted run it can only be the daemon's, and
    /// is refused without an address. The network is parsed **here**, which
    /// is why this is only called for a run that opens a daemon connection:
    /// an unknown network must not fail a run that never needed one. Failing
    /// here is before anything is dialed.
    fn daemon_target(&self) -> Result<DaemonTarget, String> {
        if let Some(address) = &self.daemon_address {
            return Ok(DaemonTarget::Address {
                url: daemon::daemon_url(address),
                proxy: self.proxy.clone(),
            });
        }
        if self.rpc_url.is_none() && self.proxy.is_some() {
            return Err(
                "--proxy needs --daemon-address: without one the daemon is this computer's \
                 node, reached on its own socket, never through a proxy"
                    .to_owned(),
            );
        }
        Ok(DaemonTarget::ThisComputer {
            network: parse_network(self.network_name())?,
        })
    }

    /// The node on another host the enrollment words reach, when
    /// `--daemon-bundle-file` is set (IG-Q108). These are flags the person
    /// typed, so a bad combination fails here, before a session or a wallet
    /// opens; the key's default path is left to the words that read it.
    fn enroll_remote(&self) -> Result<Option<shekyl_cli::enroll::Remote>, String> {
        let Some(bundle_file) = &self.daemon_bundle_file else {
            return Ok(None);
        };
        let Some(address) = &self.daemon_address else {
            return Err(shekyl_cli::enroll::CHANNEL_ADDRESS_REQUIRED.to_owned());
        };
        Ok(Some(shekyl_cli::enroll::Remote {
            leg: shekyl_cli::enroll::channel_leg(address, self.proxy.as_deref())?,
            bundle_file: bundle_file.clone(),
        }))
    }

    /// The wallet-file directory: `--wallet-dir` as given, else
    /// `network`'s default `wallets/<network>/` in this account's
    /// per-account root (CU-1; rule 83 IG-13: `~/.shekyl`, or
    /// `%LOCALAPPDATA%\Shekyl` on Windows, read from the account interface,
    /// never `HOME`; `shekyl_engine_file::paths::wallet_dir_in` names it) —
    /// so a testnet wallet file can never collide with a mainnet one, the
    /// Electrum isolation shape. Only consulted for a self-hosted session
    /// (`--rpc-url` stores wallets server-side). The network is the parsed
    /// one, not the flag's text.
    fn resolved_wallet_dir(&self, network: Network) -> Result<std::path::PathBuf, String> {
        if let Some(dir) = &self.wallet_dir {
            return Ok(std::path::PathBuf::from(dir));
        }
        let root = shekyl_os_account::per_account_root()
            .ok_or("this account has no home folder; pass --wallet-dir explicitly")?;
        Ok(shekyl_engine_file::paths::wallet_dir_in(&root, network))
    }
}

/// The daemon connection this invocation opens: where it dials, and how the
/// transport that dials it resolves a hostname under `--proxy` — which is
/// what decides whether the DNS-leak half of the disclosure is true of it.
/// Named for the endpoint, not the daemon: the `daemon` module beside it
/// holds the client that dials this.
struct DaemonEndpoint {
    target: DaemonTarget,
    resolution: ProxyResolution,
}

/// Every endpoint this invocation opens, decided once from the flags.
///
/// `--rpc-url` and `--daemon-address` are separately configurable and the
/// mode decides which are dialed; three things need that answer (the
/// session, the disclosure, and the REPL's daemon client), and deriving it
/// three times is how a run came to resolve — and fail on — a daemon
/// address it never used.
enum Endpoints {
    /// `--rpc-url`: an external wallet-RPC server does the wallet work. The
    /// REPL additionally opens its own daemon client, so it carries a
    /// daemon; a scripted run opens no daemon of its own and therefore
    /// never consults `--network`.
    External {
        url: String,
        daemon: Option<DaemonEndpoint>,
    },
    /// The default: a wallet-RPC server hosted in this process, scanning
    /// over its own daemon connection.
    SelfHosted {
        network: Network,
        daemon: DaemonEndpoint,
    },
}

impl Endpoints {
    /// Resolve the flags for a run. `opens_direct_daemon` is `true` for the
    /// REPL, which builds a `DaemonClient` of its own in addition to the
    /// session.
    ///
    /// The proxy resolution follows the transport that will dial: the
    /// in-process server's bulk scan hands the hostname to the proxy
    /// regardless of scheme (`AlwaysRemote`), while the REPL's ureq client
    /// honors it (`socks5://` resolves locally — the leak). Where both open
    /// they share an endpoint and a proxy, and the scheme-honoring one
    /// decides.
    fn resolve(cli: &ReplArgs, opens_direct_daemon: bool) -> Result<Self, String> {
        let resolution = if opens_direct_daemon {
            ProxyResolution::HonorsScheme
        } else {
            ProxyResolution::AlwaysRemote
        };
        let daemon = |cli: &ReplArgs| -> Result<DaemonEndpoint, String> {
            Ok(DaemonEndpoint {
                target: cli.daemon_target()?,
                resolution,
            })
        };
        match &cli.rpc_url {
            Some(url) => Ok(Self::External {
                url: url.clone(),
                daemon: opens_direct_daemon.then(|| daemon(cli)).transpose()?,
            }),
            None => Ok(Self::SelfHosted {
                network: parse_network(cli.network_name())?,
                daemon: daemon(cli)?,
            }),
        }
    }

    /// The daemon this run dials, if it dials one.
    fn daemon(&self) -> Option<&DaemonEndpoint> {
        match self {
            Self::External { daemon, .. } => daemon.as_ref(),
            Self::SelfHosted { daemon, .. } => Some(daemon),
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
    rpc.shutdown();
    stop(presentation, command, error);
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
            "shekyl-cli: process hardening {e}; not starting"
        ));
        std::process::exit(1);
    }
    let cli = Cli::parse();
    let json = cli.repl.json;
    let debug = cli.repl.debug;
    // Create, restore, a one-shot, and a script file are not a conversation.
    // Only a terminal with no command and no script file is.
    let scripted = presentation_for(false, json, debug);
    if cli.repl.script.is_some() && cli.command.is_some() {
        stop(
            &scripted,
            "session",
            refusal("Pass either --script or a subcommand, not both."),
        );
    }
    let (presentation, outcome) = match &cli.command {
        Some(Commands::DerivationFreezeSelfCheck) => {
            run_derivation_freeze_self_check();
            return;
        }
        Some(Commands::Create(args)) => (
            scripted,
            run_scripted(&cli.repl, |rpc| {
                commands::scripted::present_create(&scripted, rpc, args)
            }),
        ),
        Some(Commands::Restore(args)) => (
            scripted,
            run_scripted(&cli.repl, |rpc| {
                commands::scripted::present_restore(&scripted, rpc, args)
            }),
        ),
        Some(Commands::Words(words)) => (
            scripted,
            run_repl_command(
                &scripted,
                &cli.repl,
                commands::CommandSource::One(words.clone()),
            ),
        ),
        None => {
            let source = match &cli.repl.script {
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
            };
            let presentation = presentation_for(
                matches!(source, commands::CommandSource::Terminal),
                json,
                debug,
            );
            let outcome = run_repl_command(&presentation, &cli.repl, source);
            (presentation, outcome)
        }
    };
    if let Err(error) = outcome {
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
/// carry different exposure: `--rpc-url` reaches a wallet-RPC server (which
/// sees balances, addresses, and commands), a daemon address reaches a node.
/// With `--rpc-url` set the REPL has two distinct live endpoints and both are
/// disclosed; a scripted run against an external server opens no daemon of
/// its own ([`Endpoints`]) and says nothing about one.
///
/// Called after the session is built and before the REPL's daemon client:
/// what is said is what this run is *configured to dial*, said while the
/// operator can still fix it (rule 82). The session comes first so that an
/// address the session itself refused is never announced — the self-hosted
/// server validates the daemon endpoint as it starts, the same order
/// `shekyl-wallet-rpc` keeps in `run_server`. The REPL's `DaemonClient`
/// comes after, deliberately: it can fail for reasons that are not the
/// endpoint's (an unusable `--proxy`), and such a
/// failure reports itself without retracting what the configured address
/// would expose — a disclosure withheld until every dial succeeded would
/// go missing exactly when a misconfigured run most needs it.
fn disclose_network_posture(cli: &ReplArgs, endpoints: &Endpoints) {
    // The module says what is true; this binary says it on stderr, where
    // the operator who typed the flag is looking.
    fn say(warnings: impl IntoIterator<Item = String>) {
        for warning in warnings {
            eprintln!("{warning}");
        }
    }

    let proxy = cli.proxy.as_deref();
    if let Endpoints::External { url, .. } = endpoints {
        // Only disclose a --rpc-url that connect() will accept: an
        // unsupported scheme is rejected before any endpoint is opened, so
        // warning about it would contradict "endpoints actually used". The
        // far end is a wallet server, not a daemon: the path disclosure alone.
        if rpc_client::is_supported_rpc_url(url) {
            say(network_posture::disclose(
                "wallet-RPC endpoint",
                url,
                proxy,
                ProxyResolution::HonorsScheme,
            ));
        }
    }

    // "This computer" is no network path: nothing to disclose.
    if let Some(DaemonEndpoint {
        target: DaemonTarget::Address { url, proxy },
        resolution,
    }) = endpoints.daemon()
    {
        say(network_posture::daemon_disclosures(
            "daemon address",
            url,
            proxy.as_deref(),
            *resolution,
        ));
    }
}

/// Build the wallet-RPC session from the shared connection flags: an external
/// daemon when `--rpc-url` is set, otherwise a self-hosted in-process server.
fn build_session(
    cli: &ReplArgs,
    endpoints: &Endpoints,
) -> Result<rpc_client::RpcSession, Box<dyn std::error::Error>> {
    match endpoints {
        Endpoints::External { url, .. } => Ok(rpc_client::RpcSession::connect(
            url,
            cli.proxy.as_deref(),
            cli.debug,
        )?),
        Endpoints::SelfHosted { network, daemon } => host_session(
            cli.resolved_wallet_dir(*network)?,
            *network,
            daemon.target.clone(),
            cli.debug,
            shekyl_os_account::per_account_root().as_deref(),
        ),
    }
}

/// A self-hosted session's start, everything `build_session` does past
/// reading the flags: the per-account root `root` is made first, as the
/// daemon makes it, so whatever is made in it after has the root's
/// protections (`None`: the account has no home). The wallet directory, the
/// per-network default or an explicit `--wallet-dir`, is not made here: it
/// is made only when a wallet is created or restored in it
/// (`RpcSession::make_wallet_dir`), so a word that makes no wallet makes no
/// folder.
fn host_session(
    wallet_dir: std::path::PathBuf,
    network: Network,
    daemon: DaemonTarget,
    debug: bool,
    root: Option<&std::path::Path>,
) -> Result<rpc_client::RpcSession, Box<dyn std::error::Error>> {
    if let Some(root) = root {
        shekyl_os_account::ensure_per_account_root(root)
            .map_err(|e| format!("cannot create {}: {e}", root.display()))?;
    }
    rpc_client::RpcSession::host_in_process(wallet_dir, network, daemon, debug)
}

/// Run one non-interactive subcommand against a fresh session and translate a
/// failure into a non-zero exit (so automation sees the error), tearing the
/// session down either way.
fn run_scripted<F>(conn: &ReplArgs, publish: F) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnOnce(&rpc_client::RpcSession) -> bool,
{
    let _guard = shekyl_logging::init(shekyl_logging::Config::stderr_only(tracing::Level::WARN))?;
    let endpoints = Endpoints::resolve(conn, false)?;
    let rpc = build_session(conn, &endpoints)?;
    disclose_network_posture(conn, &endpoints);
    let ok = publish(&rpc);
    rpc.shutdown();
    if !ok {
        // The command printer already wrote the envelope or the human line.
        std::process::exit(1);
    }
    Ok(())
}

fn run_derivation_freeze_self_check() {
    match shekyl_crypto_pq::address_derivation_freeze::address_derivation_manifest_self_check() {
        Ok(()) => println!("ADDRESS_DERIVATION_V3 corpus OK"),
        Err(e) => {
            eprintln!("derivation freeze self-check failed: {e}");
            std::process::exit(1);
        }
    }
}

/// Parse the `--network` flag. Unknown values fail loud rather than
/// defaulting to mainnet.
fn parse_network(s: &str) -> Result<Network, String> {
    s.parse::<Network>()
        .map_err(|e| format!("invalid --network: {e}"))
}

/// The daemon-down hint (CU-1, CLI_USABILITY.md §CU-5 F1): when this run
/// dials this machine's daemon, a refused connection names the invocation
/// that would start one — `shekyld --network testnet` — instead of a bare
/// "connection refused". A remote daemon gets no hint: "start it" copy for
/// a machine the operator may not control would mislead.
fn daemon_down_hint(cli: &ReplArgs, target: &DaemonTarget) -> Option<String> {
    let network = parse_network(cli.network_name()).ok()?;
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

fn run_repl_command(
    presentation: &Presentation,
    cli: &ReplArgs,
    source: commands::CommandSource,
) -> Result<(), Box<dyn std::error::Error>> {
    let _guard = shekyl_logging::init(shekyl_logging::Config::stderr_only(tracing::Level::WARN))?;

    let enroll_remote = cli.enroll_remote()?;
    let endpoints = Endpoints::resolve(cli, true)?;
    let rpc = build_session(cli, &endpoints)?;
    disclose_network_posture(cli, &endpoints);

    // No daemon endpoint, no daemon client — the REPL always resolves one,
    // so this reads as the total form of "dial what was resolved" rather
    // than as a case that happens here.
    let network = parse_network(cli.network_name())?;
    let daemon_client = endpoints.daemon().and_then(|daemon| {
        match daemon::DaemonClient::new(
            daemon.target.clone(),
            daemon_down_hint(cli, &daemon.target),
            network,
        ) {
            Ok(dc) => Some(dc),
            Err(daemon::DaemonError::NotConfigured) => None,
            Err(e) => {
                eprintln!("Warning: daemon client init failed: {e}");
                None
            }
        }
    });

    // F1 at startup (CLI_USABILITY.md §CU-5): a dead local daemon is the
    // most common first-run state; disclose it now rather than at the first
    // command that needs it. Loopback only — probing a remote daemon at
    // startup would spend a Tor circuit on a courtesy check.
    if let Some(ref dc) = daemon_client {
        if dc.is_loopback() {
            if let Err(e) = dc.daemon_status() {
                if matches!(e, daemon::DaemonError::ConnectionRefused { .. }) {
                    eprintln!("Note: {e}");
                }
            }
        }
    }

    if cli.complete_tree_foundation && cli.wallet.is_none() {
        stop_session(
            rpc,
            presentation,
            "complete-tree-foundation",
            refusal(
                "--complete-tree-foundation needs --wallet <name>. \
                 Unbounded disk, no reward. Nothing was written.",
            ),
        );
    }

    if let Some(ref filename) = cli.wallet {
        if !presentation.interactive() && cli.password_file.is_none() {
            stop_session(
                rpc,
                presentation,
                "wallet open",
                refusal(
                    "A script must pass --password-file with --wallet. \
                     Stdin is the script, not the password.",
                ),
            );
        }
        if cli.complete_tree_foundation {
            if let Err(error) =
                commands::accept_foundation_terms(presentation, cli.acknowledge.as_deref())
            {
                stop_session(rpc, presentation, "complete-tree-foundation", error);
            }
        }
        let password = match &cli.password_file {
            Some(path) => match commands::scripted::read_password_file(path) {
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
            rpc.shutdown();
            std::process::exit(1);
        }
        if cli.complete_tree_foundation {
            let sealed = commands::publish_foundation_stake(presentation, &rpc, &password);
            drop(password);
            if !sealed {
                rpc.shutdown();
                std::process::exit(1);
            }
        }
    }

    let enroll = shekyl_cli::enroll::EnrollOptions {
        network,
        remote: enroll_remote,
        key_file: cli.rpc_key_file.clone(),
    };
    commands::run(
        rpc,
        daemon_client.as_ref(),
        &enroll,
        network,
        *presentation,
        source,
    )
}

// The binary's tests sit beside this file (`main_tests.rs`) so the
// session and the command loop stay the body of `main.rs`.
#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
