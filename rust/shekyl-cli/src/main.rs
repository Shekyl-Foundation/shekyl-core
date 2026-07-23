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
    /// Offline check that the embedded ADDRESS_DERIVATION_V1 corpus matches
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
    /// Daemon address the self-hosted wallet RPC connects to
    /// (host:port or full URL). Ignored with --rpc-url.
    #[arg(long, default_value = "localhost:11028")]
    daemon_address: String,

    /// Connect to an external shekyl-wallet-rpc daemon instead of
    /// self-hosting one (http://host:port or uds:///path/to.sock).
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

    /// SOCKS5 proxy for direct daemon queries (e.g. socks5://127.0.0.1:9050).
    /// Uses distinct SOCKS auth for Tor stream isolation.
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::DerivationFreezeSelfCheck) => run_derivation_freeze_self_check(),
        Some(Commands::Create(args)) => {
            run_scripted(&cli.repl, |rpc| commands::scripted::run_create(rpc, args))
        }
        Some(Commands::Restore(args)) => {
            run_scripted(&cli.repl, |rpc| commands::scripted::run_restore(rpc, args))
        }
        None => run_repl(cli.repl),
    }
}

/// Build the wallet-RPC session from the shared connection flags: an external
/// daemon when `--rpc-url` is set, otherwise a self-hosted in-process server.
fn build_session(cli: &ReplArgs) -> Result<rpc_client::RpcSession, Box<dyn std::error::Error>> {
    match &cli.rpc_url {
        Some(url) => Ok(rpc_client::RpcSession::connect(url, cli.debug)?),
        None => {
            let network = parse_network(&cli.network)?;
            Ok(rpc_client::RpcSession::host_in_process(
                std::path::PathBuf::from(&cli.engine_dir),
                network,
                daemon_url(&cli.daemon_address),
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
    let rpc = build_session(conn)?;
    let outcome = run(&rpc);
    rpc.shutdown();
    if let Err(e) = outcome {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
    Ok(())
}

fn run_derivation_freeze_self_check() -> Result<(), Box<dyn std::error::Error>> {
    match shekyl_crypto_pq::address_derivation_freeze::address_derivation_manifest_self_check() {
        Ok(()) => {
            println!("ADDRESS_DERIVATION_V1 corpus OK");
            Ok(())
        }
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

/// Normalize a daemon address to the URL form the wallet RPC expects.
fn daemon_url(daemon_address: &str) -> String {
    if daemon_address.contains("://") {
        daemon_address.to_owned()
    } else {
        format!("http://{daemon_address}")
    }
}

fn run_repl(cli: ReplArgs) -> Result<(), Box<dyn std::error::Error>> {
    let _guard = shekyl_logging::init(shekyl_logging::Config::stderr_only(tracing::Level::WARN))?;

    let rpc = build_session(&cli)?;

    let daemon_client = match daemon::DaemonClient::new(
        &cli.daemon_address,
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
        let mut password = prompt_password("Wallet password: ")?;
        let opened = rpc.call(
            "open_wallet",
            serde_json::json!({ "name": filename, "password": password }),
        );
        zeroize::Zeroize::zeroize(&mut password);
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

    commands::repl(rpc, daemon_client)
}
