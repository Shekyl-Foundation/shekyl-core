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

use clap::{Parser, Subcommand};
use shekyl_cli::{commands, daemon, prompt_password, rpc_client};
use shekyl_rpc_transport::network_posture::{self, ProxyResolution};
use shekyl_wallet_rpc::Network;

#[derive(Parser)]
#[command(name = "shekyl-cli", about = "Shekyl interactive CLI wallet", version)]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    repl: ReplArgs,
}

#[derive(Subcommand)]
enum Commands {
    /// Offline check that the embedded ADDRESS_DERIVATION_V2 corpus matches
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
    /// directory. Ignored with --rpc-url. (--engine-dir is a hidden alias,
    /// CU-2.)
    #[arg(long, global = true, alias = "engine-dir")]
    wallet_dir: Option<String>,

    /// Open this wallet immediately on startup. (--engine-file is a hidden
    /// alias, CU-2.)
    #[arg(long, global = true, alias = "engine-file")]
    wallet: Option<String>,

    /// SOCKS proxy for the wallet's daemon connections — the self-hosted
    /// block scan and the REPL's direct daemon queries (e.g.
    /// socks5h://127.0.0.1:9050). Prefer `socks5h://`: the scan resolves the
    /// daemon hostname at the proxy regardless, but the direct queries honor
    /// the scheme, and `socks5://` resolves it locally (a DNS leak).
    #[arg(long, global = true)]
    proxy: Option<String>,

    /// Path to PEM CA certificate for self-signed daemon TLS.
    /// Only needed for https:// daemon addresses with custom CAs.
    #[arg(long, global = true)]
    daemon_ca_cert: Option<String>,

    /// Show structured RPC error details (error.data) on failures.
    #[arg(long, global = true, default_value_t = false)]
    pub debug: bool,
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

    /// The daemon address this invocation dials: the flag as given, or the
    /// loopback daemon at the selected network's RPC port — the wallet knows
    /// the protocol's ports so the operator need not. The network is parsed
    /// **here**, which is why this is only called for a run that opens a
    /// daemon connection: an unknown network must not fail a run that never
    /// needed a default port. Failing here is before anything is dialed.
    fn daemon_address(&self) -> Result<String, String> {
        match &self.daemon_address {
            Some(given) => Ok(given.clone()),
            None => Ok(format!(
                "127.0.0.1:{}",
                parse_network(self.network_name())?.daemon_rpc_port()
            )),
        }
    }

    /// The wallet-file directory: `--wallet-dir` as given, else the
    /// per-network default `~/.shekyl/wallets/<network>/` (CU-1) — so a
    /// testnet wallet file can never collide with a mainnet one, the
    /// Electrum isolation shape. Only consulted for a self-hosted session
    /// (`--rpc-url` stores wallets server-side).
    fn resolved_wallet_dir(&self) -> Result<std::path::PathBuf, String> {
        if let Some(dir) = &self.wallet_dir {
            return Ok(std::path::PathBuf::from(dir));
        }
        let home = dirs::home_dir()
            .ok_or("cannot determine the home directory; pass --wallet-dir explicitly")?;
        Ok(home
            .join(".shekyl")
            .join("wallets")
            .join(self.network_name()))
    }
}

/// The daemon connection this invocation opens: where it dials, and how the
/// transport that dials it resolves a hostname under `--proxy` — which is
/// what decides whether the DNS-leak half of the disclosure is true of it.
/// Named for the endpoint, not the daemon: the `daemon` module beside it
/// holds the client that dials this.
struct DaemonEndpoint {
    address: String,
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
                address: cli.daemon_address()?,
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::DerivationFreezeSelfCheck) => {
            run_derivation_freeze_self_check();
            Ok(())
        }
        Some(Commands::Create(args)) => {
            run_scripted(&cli.repl, |rpc| commands::scripted::run_create(rpc, args))
        }
        Some(Commands::Restore(args)) => {
            run_scripted(&cli.repl, |rpc| commands::scripted::run_restore(rpc, args))
        }
        None => run_repl(&cli.repl),
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
/// endpoint's (an unusable `--proxy` or `--daemon-ca-cert`), and such a
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

    if let Some(daemon) = endpoints.daemon() {
        say(network_posture::daemon_disclosures(
            "daemon address",
            &daemon.address,
            proxy,
            daemon.resolution,
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
        Endpoints::SelfHosted { network, daemon } => {
            let wallet_dir = cli.resolved_wallet_dir()?;
            // The per-network default is created on demand; an explicit
            // --wallet-dir is also created rather than failing on a path the
            // operator clearly intends to use.
            std::fs::create_dir_all(&wallet_dir)
                .map_err(|e| format!("cannot create wallet dir {}: {e}", wallet_dir.display()))?;
            Ok(rpc_client::RpcSession::host_in_process(
                wallet_dir,
                *network,
                daemon::daemon_url(&daemon.address),
                cli.proxy.clone(),
                cli.debug,
            )?)
        }
    }
}

/// Run one non-interactive subcommand against a fresh session and translate a
/// failure into a non-zero exit (so automation sees the error), tearing the
/// session down either way.
fn run_scripted<F>(conn: &ReplArgs, run: F) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnOnce(&rpc_client::RpcSession) -> Result<(), Box<dyn std::error::Error>>,
{
    let _guard = shekyl_logging::init(shekyl_logging::Config::stderr_only(tracing::Level::WARN))?;
    let endpoints = Endpoints::resolve(conn, false)?;
    let rpc = build_session(conn, &endpoints)?;
    disclose_network_posture(conn, &endpoints);
    let outcome = run(&rpc);
    rpc.shutdown();
    if let Err(e) = outcome {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
    Ok(())
}

fn run_derivation_freeze_self_check() {
    match shekyl_crypto_pq::address_derivation_freeze::address_derivation_manifest_self_check() {
        Ok(()) => println!("ADDRESS_DERIVATION_V2 corpus OK"),
        Err(e) => {
            eprintln!("derivation freeze self-check failed: {e}");
            std::process::exit(1);
        }
    }
}

/// Parse the `--network` flag. Unknown values fail loud rather than
/// defaulting to mainnet.
fn parse_network(s: &str) -> Result<Network, String> {
    match s {
        "mainnet" => Ok(Network::Mainnet),
        "testnet" => Ok(Network::Testnet),
        "stagenet" => Ok(Network::Stagenet),
        other => Err(format!(
            "invalid --network '{other}': expected mainnet, testnet, or stagenet"
        )),
    }
}

/// The daemon-down hint (CU-1, CLI_USABILITY.md §CU-5 F1): when this run
/// dials a **loopback** daemon, a refused connection names the invocation
/// that would start one — `shekyld --testnet` and the port — instead of a
/// bare "connection refused". A remote daemon gets no hint: "start it" copy
/// for a machine the operator may not control would mislead.
fn daemon_down_hint(cli: &ReplArgs, address: &str) -> Option<String> {
    let loopback = ["127.0.0.1", "localhost", "[::1]"]
        .iter()
        .any(|h| address.contains(h));
    if !loopback {
        return None;
    }
    let network = parse_network(cli.network_name()).ok()?;
    let flag = match network {
        Network::Mainnet => "",
        Network::Testnet => " --testnet",
        Network::Stagenet => " --stagenet",
    };
    Some(format!(
        "Start the {name} daemon with: shekyld{flag} (its RPC answers on port {port}).",
        name = cli.network_name(),
        port = network.daemon_rpc_port(),
    ))
}

fn run_repl(cli: &ReplArgs) -> Result<(), Box<dyn std::error::Error>> {
    let _guard = shekyl_logging::init(shekyl_logging::Config::stderr_only(tracing::Level::WARN))?;

    let endpoints = Endpoints::resolve(cli, true)?;
    let rpc = build_session(cli, &endpoints)?;
    disclose_network_posture(cli, &endpoints);

    // No daemon endpoint, no daemon client — the REPL always resolves one,
    // so this reads as the total form of "dial what was resolved" rather
    // than as a case that happens here.
    let daemon_client = endpoints.daemon().and_then(|daemon| {
        match daemon::DaemonClient::new(
            &daemon.address,
            cli.proxy.as_deref(),
            cli.daemon_ca_cert.as_deref(),
            daemon_down_hint(cli, &daemon.address),
        ) {
            Ok(dc) => Some(dc),
            Err(daemon::DaemonError::NotConfigured) => None,
            Err(e) => {
                eprintln!("Warning: daemon client init failed: {e}");
                None
            }
        }
    });

    if let Some(ref filename) = cli.wallet {
        // The password lives in this inner scope and nowhere else, so it is
        // wiped before the match below — which can reach `process::exit`, and
        // `exit` bypasses Drop. A `Zeroizing` still in scope at that call is a
        // secret that never gets wiped at all. Scoping keeps that structural:
        // the compiler ends the lifetime here, so a later branch added to the
        // match cannot extend a secret's life past the exit by accident.
        let opened = {
            let password = prompt_password("Wallet password: ")?;
            rpc.call(
                "open_wallet",
                rpc_client::params::NamedPassword {
                    name: filename,
                    password: &password,
                },
            )
        };
        match opened {
            Ok(_) => {
                rpc.set_open(filename);
                println!("Opened wallet: {filename}");
            }
            Err(e) => {
                rpc.report("Failed to open wallet", &e);
                rpc.shutdown();
                std::process::exit(1);
            }
        }
    }

    commands::repl(rpc, daemon_client.as_ref(), cli.network_name())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default daemon address follows `--network`: the wallet knows the
    /// daemon's ports so the operator need not; a given address is taken as
    /// given; an unknown network fails before anything is dialed.
    #[test]
    fn the_default_daemon_address_follows_the_network() {
        let args = |argv: &[&str]| ReplArgs::try_parse_from(argv).expect("parses");
        assert_eq!(
            args(&["shekyl-cli"]).daemon_address().unwrap(),
            "127.0.0.1:11029"
        );
        assert_eq!(
            args(&["shekyl-cli", "--network", "testnet"])
                .daemon_address()
                .unwrap(),
            "127.0.0.1:12029"
        );
        assert_eq!(
            args(&["shekyl-cli", "--network", "stagenet"])
                .daemon_address()
                .unwrap(),
            "127.0.0.1:13029"
        );
        assert_eq!(
            args(&[
                "shekyl-cli",
                "--network",
                "testnet",
                "--daemon-address",
                "node.example.com:11029"
            ])
            .daemon_address()
            .unwrap(),
            "node.example.com:11029"
        );
        assert!(args(&["shekyl-cli", "--network", "bogus"])
            .daemon_address()
            .is_err());
    }

    /// A scripted run against an external wallet-RPC server opens no daemon
    /// of its own, so it never consults `--network` — the flag's own help
    /// says the server it configures is not started. The edit that turns
    /// this red is resolving the daemon unconditionally (which is what
    /// `--network` parsing hangs off): `Endpoints::resolve` then fails on a
    /// network this run had no use for.
    #[test]
    fn a_scripted_external_run_resolves_no_daemon_and_no_network() {
        let args = |argv: &[&str]| ReplArgs::try_parse_from(argv).expect("parses");
        let external = args(&[
            "shekyl-cli",
            "--rpc-url",
            "http://127.0.0.1:29500",
            "--network",
            "bogus",
        ]);

        let scripted = Endpoints::resolve(&external, false)
            .expect("no daemon is opened, so the network is never parsed");
        assert!(scripted.daemon().is_none(), "no daemon endpoint is dialed");

        // The REPL *does* open a daemon client, and with no --daemon-address
        // the port has to come from the network — so there the bad value is
        // fatal, at the point it is actually needed.
        assert!(Endpoints::resolve(&external, true).is_err());

        // ...and naming the daemon removes even that need.
        let named = args(&[
            "shekyl-cli",
            "--rpc-url",
            "http://127.0.0.1:29500",
            "--network",
            "bogus",
            "--daemon-address",
            "127.0.0.1:11029",
        ]);
        let repl = Endpoints::resolve(&named, true).expect("the daemon is named");
        assert_eq!(repl.daemon().expect("a daemon").address, "127.0.0.1:11029");
    }

    /// `--testnet` / `--stagenet` are the same flags `shekyld` takes and mean
    /// `--network testnet` / `--network stagenet`. Combining spellings is a
    /// parse error, not a precedence rule — a run that says two networks
    /// must not silently pick one (CU-1).
    #[test]
    fn testnet_and_stagenet_flags_select_the_network() {
        let args = |argv: &[&str]| ReplArgs::try_parse_from(argv).expect("parses");
        assert_eq!(
            args(&["shekyl-cli", "--testnet"]).daemon_address().unwrap(),
            "127.0.0.1:12029"
        );
        assert_eq!(
            args(&["shekyl-cli", "--stagenet"])
                .daemon_address()
                .unwrap(),
            "127.0.0.1:13029"
        );
        assert!(
            ReplArgs::try_parse_from(["shekyl-cli", "--testnet", "--network", "testnet"]).is_err()
        );
        assert!(
            ReplArgs::try_parse_from(["shekyl-cli", "--stagenet", "--network", "stagenet"])
                .is_err()
        );
        assert!(ReplArgs::try_parse_from(["shekyl-cli", "--testnet", "--stagenet"]).is_err());
    }

    /// Connection flags are global (CU-1): they parse after a subcommand
    /// name, so `shekyl-cli create w --seed-out s --testnet` works instead
    /// of demanding the flags come first.
    #[test]
    fn connection_flags_parse_after_a_subcommand() {
        let cli = Cli::try_parse_from([
            "shekyl-cli",
            "create",
            "w",
            "--seed-out",
            "/tmp/seed.txt",
            "--testnet",
        ])
        .expect("global connection flags parse after the subcommand");
        assert!(cli.repl.testnet);
        assert!(matches!(cli.command, Some(Commands::Create(_))));
    }

    /// The default wallet dir is per-network (`~/.shekyl/wallets/<network>/`,
    /// CU-1) so wallets on different networks never share a directory; an
    /// explicit `--wallet-dir` is taken as given.
    #[test]
    fn the_default_wallet_dir_is_per_network() {
        let args = |argv: &[&str]| ReplArgs::try_parse_from(argv).expect("parses");
        let dir = args(&["shekyl-cli", "--testnet"])
            .resolved_wallet_dir()
            .unwrap();
        assert!(
            dir.ends_with(".shekyl/wallets/testnet"),
            "got {}",
            dir.display()
        );
        let mainnet = args(&["shekyl-cli"]).resolved_wallet_dir().unwrap();
        assert!(
            mainnet.ends_with(".shekyl/wallets/mainnet"),
            "got {}",
            mainnet.display()
        );
        assert_eq!(
            args(&["shekyl-cli", "--engine-dir", "/tmp/wallets"])
                .resolved_wallet_dir()
                .unwrap(),
            std::path::PathBuf::from("/tmp/wallets")
        );
    }

    /// The daemon-down hint (F1) fires for loopback endpoints only and names
    /// the network-matched `shekyld` invocation plus its port; a remote
    /// daemon gets no "start it" copy.
    #[test]
    fn the_daemon_down_hint_is_loopback_only_and_names_the_network() {
        let args = |argv: &[&str]| ReplArgs::try_parse_from(argv).expect("parses");
        let testnet = args(&["shekyl-cli", "--testnet"]);
        let hint = daemon_down_hint(&testnet, "127.0.0.1:12029").expect("loopback gets a hint");
        assert!(hint.contains("shekyld --testnet"), "got {hint}");
        assert!(hint.contains("12029"), "got {hint}");
        assert!(daemon_down_hint(&testnet, "node.example.com:12029").is_none());

        let mainnet_hint =
            daemon_down_hint(&args(&["shekyl-cli"]), "127.0.0.1:11029").expect("hint");
        assert!(mainnet_hint.contains("shekyld"), "got {mainnet_hint}");
        assert!(
            !mainnet_hint.contains("--"),
            "mainnet is flagless: {mainnet_hint}"
        );
    }
}
