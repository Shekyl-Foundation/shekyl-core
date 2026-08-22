// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Standalone `shekyl-wallet-rpc` binary: the Engine-native wallet JSON-RPC
//! server, serving the contract in `docs/api/wallet_rpc.yaml`. It is the
//! only binary of that name — the C++ `wallet_rpc_server` it replaced was
//! deleted with `src/wallet/` (`a9dc5e4db`), and the transitional
//! `shekyl-engine-rpc` wallet2-FFI bridge before it. The flag reference is
//! `docs/EXECUTABLES.md` §3; the listen posture is
//! `docs/design/RPC_TRANSPORT_POSTURE.md`.

use std::path::PathBuf;
use std::str::FromStr;

use clap::builder::TypedValueParser as _;
use clap::Parser;
use shekyl_crypto_pq::wallet_envelope::KdfParams;
use shekyl_engine_core::Network;
use shekyl_wallet_rpc::{run_server, AuthConfig, ListenAddr, ServerConfig};
use zeroize::Zeroizing;

/// No `Debug`: `rpc_login` is a secret (rule 35), and a derived `Debug` on
/// the struct that holds it is exactly the render path the credential
/// types below refuse to offer.
#[derive(Parser)]
#[command(
    name = "shekyl-wallet-rpc",
    about = "Shekyl-native wallet JSON-RPC server (Phase 4)"
)]
struct Cli {
    /// Directory for wallet files.
    #[arg(long = "wallet-dir", default_value = ".")]
    wallet_dir: PathBuf,

    /// Listen address: a numeric `IP:PORT` (TCP — `127.0.0.1:29500`,
    /// `[::1]:29500`; hostnames are not resolved) or `uds:///path/to.sock`
    /// (Unix only; refused on Windows, where the wallet is self-hosted by
    /// shekyl-cli). Default is loopback TCP; UDS is the recommended local
    /// deployment. Wildcard addresses (0.0.0.0, ::, [::]) are refused — bind
    /// a specific IP address — and any non-loopback address requires
    /// --rpc-login.
    #[arg(long = "rpc-bind", default_value = "127.0.0.1:29500")]
    rpc_bind: String,

    /// HTTP basic auth as `NAME:PASSWORD`, both halves non-empty (anything
    /// else given — an empty value included — is refused by name). Omitted
    /// disables auth, which is accepted only on loopback or a UDS socket
    /// (filesystem permissions carry the authorization there); a
    /// non-loopback --rpc-bind refuses to start without it. Contradicts
    /// --disable-rpc-login: pass one.
    #[arg(
        long = "rpc-login",
        // No default: presence is the signal, so `--rpc-login=` is a given
        // (and refused) value rather than an omission. Parsed straight into
        // a wiping buffer (rule 35): the `String` clap produces is moved,
        // not copied, into the `Zeroizing`. argv itself and clap's
        // transient copies are the OS's and clap's — the residual.
        value_parser = clap::builder::StringValueParser::new().map(Zeroizing::new),
    )]
    rpc_login: Option<Zeroizing<String>>,

    /// Run without authentication. Accepted only on a loopback --rpc-bind
    /// or a UDS socket; refused off loopback, and refused together with
    /// --rpc-login (the pair is a contradiction, not a precedence).
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
    let auth = AuthConfig::from_cli(
        cli.rpc_login.as_deref().map(String::as_str),
        cli.disable_rpc_login,
    )?;
    // The credential now lives only in `auth`; wipe the flag's copy here
    // rather than at process exit.
    drop(cli.rpc_login);

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
