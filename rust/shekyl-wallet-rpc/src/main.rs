// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Standalone `shekyl-wallet-rpc` binary (Phase 4 Engine-native server).
//!
//! Distinct from the C++ `wallet_rpc_server` binary still built as
//! `shekyl-wallet-rpc` — until Phase 5 deletion, operators must not confuse
//! the two. This binary is the Shekyl-native contract in
//! `docs/api/wallet_rpc.yaml`. (The third name in this space, the
//! transitional `shekyl-engine-rpc` wallet2-FFI bridge, is deleted.)

use std::path::PathBuf;
use std::str::FromStr;

use clap::Parser;
use shekyl_crypto_pq::wallet_envelope::KdfParams;
use shekyl_engine_core::Network;
use shekyl_wallet_rpc::{run_server, AuthConfig, ListenAddr, ServerConfig};

#[derive(Parser, Debug)]
#[command(
    name = "shekyl-wallet-rpc",
    about = "Shekyl-native wallet JSON-RPC server (Phase 4)"
)]
struct Cli {
    /// Directory for wallet files.
    #[arg(long = "wallet-dir", default_value = ".")]
    wallet_dir: PathBuf,

    /// Listen address: `HOST:PORT` (TCP) or `uds:///path/to.sock` (Unix only;
    /// refused on Windows, where the wallet is self-hosted by shekyl-cli).
    /// Default is loopback TCP; UDS is the recommended local deployment.
    /// Wildcard addresses (0.0.0.0, ::) are refused — bind one specific
    /// interface — and any non-loopback address requires --rpc-login.
    #[arg(long = "rpc-bind", default_value = "127.0.0.1:29500")]
    rpc_bind: String,

    /// HTTP basic auth as `user:pass`. Empty / omitted disables auth, which
    /// is accepted only on loopback or a UDS socket (filesystem permissions
    /// carry the authorization there); a non-loopback --rpc-bind refuses to
    /// start without it.
    #[arg(long = "rpc-login", default_value = "")]
    rpc_login: String,

    /// Disable RPC login even if `--rpc-login` is set. Refused on a
    /// non-loopback --rpc-bind.
    #[arg(long = "disable-rpc-login", default_value_t = false)]
    disable_rpc_login: bool,

    /// Daemon JSON-RPC base URL (used by refresh / send; lifecycle holds it).
    #[arg(long = "daemon-address", default_value = "http://127.0.0.1:28581")]
    daemon_address: String,

    /// SOCKS5h proxy for the daemon connection (e.g. socks5h://127.0.0.1:9050).
    /// The proxy resolves the daemon hostname, so it never reaches the local
    /// resolver. Omit for a direct connection.
    #[arg(long = "proxy")]
    proxy: Option<String>,

    /// Network every create/open binds to: mainnet | testnet | stagenet.
    #[arg(long = "network", default_value = "mainnet")]
    network: String,

    /// Optional file sink for `tracing` events.
    #[arg(long = "log-file")]
    log_file: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();

    let config = if let Some(ref path) = cli.log_file {
        if path.exists() && path.is_dir() {
            return Err(format!(
                "--log-file {} points at an existing directory; \
                 pass a file path (e.g. {}/wallet-rpc.log)",
                path.display(),
                path.display(),
            )
            .into());
        }
        let directory = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), PathBuf::from);
        let filename_prefix = path
            .file_name()
            .ok_or("--log-file must name a file, not a directory")?
            .to_str()
            .ok_or("--log-file filename must be valid UTF-8")?
            .to_owned();
        let sink = shekyl_logging::FileSink::unrotated(directory, filename_prefix);
        shekyl_logging::Config::with_file_sink(tracing::Level::INFO, sink)
    } else {
        shekyl_logging::Config::stderr_only(tracing::Level::INFO)
    };
    let _guard = shekyl_logging::init(config)?;

    let listen = ListenAddr::parse(&cli.rpc_bind)?;
    let auth = if cli.disable_rpc_login || cli.rpc_login.is_empty() {
        AuthConfig::Disabled
    } else {
        AuthConfig::from_rpc_login(Some(&cli.rpc_login))
    };

    let network = Network::from_str(&cli.network)
        .map_err(|e| format!("invalid --network '{}': {e}", cli.network))?;

    let server = ServerConfig {
        listen,
        wallet_dir: cli.wallet_dir,
        network,
        daemon_address: cli.daemon_address,
        proxy: cli.proxy,
        auth,
        kdf: KdfParams::default(),
    };

    // `run_server` blocks until its listener fails or the process is
    // killed. Ctrl-C cancels the future (Phase 4a); a later sub-PR can
    // wire `AppState::shutdown` to signal handlers for drain.
    run_server(server).await
}
