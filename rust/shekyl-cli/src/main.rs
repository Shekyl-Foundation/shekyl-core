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
    /// --engine-dir, --rpc-url, …) must come BEFORE the subcommand name.
    Create(commands::scripted::CreateArgs),

    /// Non-interactively restore a wallet from a seed file (for scripting /
    /// automation). Connection flags must come BEFORE the subcommand name.
    Restore(commands::scripted::RestoreArgs),
}

#[derive(Parser)]
pub struct ReplArgs {
    /// Daemon address (host:port or full URL). Default: this machine's
    /// daemon at the RPC port for --network. With --rpc-url the self-hosted
    /// wallet RPC is not started, but the REPL still queries the daemon at
    /// this address directly.
    #[arg(long)]
    daemon_address: Option<String>,

    /// Connect to an external shekyl-wallet-rpc daemon instead of
    /// self-hosting one (http://host:port, or uds:///path/to.sock on Unix).
    #[arg(long)]
    rpc_url: Option<String>,

    /// Network type: mainnet, testnet, stagenet. Ignored with --rpc-url.
    #[arg(long, default_value = "mainnet")]
    network: String,

    /// Directory for wallet files. Ignored with --rpc-url.
    #[arg(long, default_value = ".")]
    engine_dir: String,

    /// Open a wallet immediately on startup
    #[arg(long)]
    engine_file: Option<String>,

    /// SOCKS proxy for the wallet's daemon connections — the self-hosted
    /// block scan and the REPL's direct daemon queries (e.g.
    /// socks5h://127.0.0.1:9050). Prefer `socks5h://`: the scan resolves the
    /// daemon hostname at the proxy regardless, but the direct queries honor
    /// the scheme, and `socks5://` resolves it locally (a DNS leak).
    #[arg(long)]
    proxy: Option<String>,

    /// Path to PEM CA certificate for self-signed daemon TLS.
    /// Only needed for https:// daemon addresses with custom CAs.
    #[arg(long)]
    daemon_ca_cert: Option<String>,

    /// Show structured RPC error details (error.data) on failures.
    #[arg(long, default_value_t = false)]
    pub debug: bool,
}

impl ReplArgs {
    /// The daemon address this invocation dials: the flag as given, or the
    /// loopback daemon at `--network`'s RPC port — the wallet knows the
    /// protocol's ports so the operator need not. An unknown `--network`
    /// fails here, before anything is dialed.
    fn daemon_address(&self) -> Result<String, String> {
        match &self.daemon_address {
            Some(given) => Ok(given.clone()),
            None => Ok(format!(
                "127.0.0.1:{}",
                parse_network(&self.network)?.daemon_rpc_port()
            )),
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
/// sees balances, addresses, and commands), `--daemon-address` reaches a node.
/// `opens_direct_daemon` is `true` for the REPL, which builds its own
/// `DaemonClient` from `--daemon-address` **in addition to** the RPC session —
/// so with `--rpc-url` set the REPL has two distinct live endpoints, and both
/// must be disclosed; a scripted run against an external server opens no
/// daemon endpoint of its own and says nothing about one.
///
/// Called after the session is built, so what is said is about an endpoint
/// this run will use: the self-hosted server has validated the daemon
/// endpoint by then and a refused address is never announced (the same
/// order `shekyl-wallet-rpc` keeps in `run_server`).
fn disclose_network_posture(cli: &ReplArgs, daemon_address: &str, opens_direct_daemon: bool) {
    // The module says what is true; this binary says it on stderr, where
    // the operator who typed the flag is looking.
    fn say(warnings: impl IntoIterator<Item = String>) {
        for warning in warnings {
            eprintln!("{warning}");
        }
    }

    let proxy = cli.proxy.as_deref();
    if let Some(url) = &cli.rpc_url {
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

    // Which daemon transport this run opens decides how a hostname resolves
    // under --proxy, and so whether the DNS-leak half of the disclosure is
    // true. The in-process server's bulk scan honors --proxy with SOCKS5h
    // semantics regardless of scheme — it never resolves the daemon hostname
    // locally. The REPL *additionally* opens a direct ureq daemon client on
    // the same address, and that client does honor the scheme (socks5:// =
    // local resolve). So: the REPL discloses as scheme-honoring; a scripted
    // self-hosted run as always-remote (warning there would assert a lookup
    // no opened transport performs — §15 warns only on established
    // weaknesses); a scripted run against an external server opens no
    // daemon endpoint at all. One disclosure covers both REPL transports,
    // since they share endpoint and proxy.
    let daemon = match (&cli.rpc_url, opens_direct_daemon) {
        (_, true) => Some(ProxyResolution::HonorsScheme),
        (None, false) => Some(ProxyResolution::AlwaysRemote),
        (Some(_), false) => None,
    };
    if let Some(resolution) = daemon {
        say(network_posture::daemon_disclosures(
            "daemon address",
            daemon_address,
            proxy,
            resolution,
        ));
    }
}

/// Build the wallet-RPC session from the shared connection flags: an external
/// daemon when `--rpc-url` is set, otherwise a self-hosted in-process server.
fn build_session(
    cli: &ReplArgs,
    daemon_address: &str,
) -> Result<rpc_client::RpcSession, Box<dyn std::error::Error>> {
    match &cli.rpc_url {
        Some(url) => Ok(rpc_client::RpcSession::connect(
            url,
            cli.proxy.as_deref(),
            cli.debug,
        )?),
        None => {
            let network = parse_network(&cli.network)?;
            Ok(rpc_client::RpcSession::host_in_process(
                std::path::PathBuf::from(&cli.engine_dir),
                network,
                daemon::daemon_url(daemon_address),
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
    let daemon_address = conn.daemon_address()?;
    let rpc = build_session(conn, &daemon_address)?;
    disclose_network_posture(conn, &daemon_address, false);
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

fn run_repl(cli: &ReplArgs) -> Result<(), Box<dyn std::error::Error>> {
    let _guard = shekyl_logging::init(shekyl_logging::Config::stderr_only(tracing::Level::WARN))?;

    let daemon_address = cli.daemon_address()?;
    let rpc = build_session(cli, &daemon_address)?;
    disclose_network_posture(cli, &daemon_address, true);

    let daemon_client = match daemon::DaemonClient::new(
        &daemon_address,
        cli.proxy.as_deref(),
        cli.daemon_ca_cert.as_deref(),
    ) {
        Ok(dc) => Some(dc),
        Err(daemon::DaemonError::NotConfigured) => None,
        Err(e) => {
            eprintln!("Warning: daemon client init failed: {e}");
            None
        }
    };

    if let Some(ref filename) = cli.engine_file {
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

    commands::repl(rpc, daemon_client.as_ref())
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
}
