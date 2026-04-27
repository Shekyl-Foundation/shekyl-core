// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! shekyl-cli: interactive CLI engine for Shekyl.
//!
//! Thin REPL frontend over `shekyl-engine-rpc` (library mode). Uses the same
//! Rust engine stack as the GUI: wallet2 via FFI for lifecycle, Rust scanner
//! for reads, and native-sign for transaction construction.

pub mod commands;
pub mod daemon;
pub mod display;
pub mod errors;
pub mod resolve;
pub mod session;
pub mod validate;
mod engine;

use clap::Parser;

#[derive(Parser)]
#[command(name = "shekyl-cli", about = "Shekyl interactive CLI engine", version)]
pub struct Cli {
    /// Daemon address (host:port or full URL)
    #[arg(long, default_value = "localhost:11028")]
    daemon_address: String,

    /// Daemon login (user:password)
    #[arg(long, default_value = "")]
    daemon_login: String,

    /// Trust the daemon (skip proof verification for faster sync)
    #[arg(long, default_value_t = false)]
    trusted_daemon: bool,

    /// Network type: mainnet, testnet, stagenet
    #[arg(long, default_value = "mainnet")]
    network: String,

    /// Directory for engine files
    #[arg(long, default_value = ".")]
    engine_dir: String,

    /// Open an engine file immediately on startup
    #[arg(long)]
    engine_file: Option<String>,

    /// SOCKS5 proxy for daemon connections (e.g. socks5://127.0.0.1:9050).
    /// Uses distinct SOCKS auth for Tor stream isolation.
    #[arg(long)]
    proxy: Option<String>,

    /// Path to PEM CA certificate for self-signed daemon TLS.
    /// Only needed for https:// daemon addresses with custom CAs.
    #[arg(long)]
    daemon_ca_cert: Option<String>,

    /// Show raw error details. Output goes to stderr (if TTY) or
    /// ~/.shekyl/debug.log (0600) when stderr is piped.
    #[arg(long, default_value_t = false)]
    pub debug: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // stderr-only, WARN default. CLI never writes a file sink: this is an
    // interactive TTY tool and surprise `~/.shekyl/logs/` writes would be
    // a footgun. Users who want a file redirect `2>` themselves.
    let _guard = shekyl_logging::init(shekyl_logging::Config::stderr_only(tracing::Level::WARN))?;

    let cli = Cli::parse();

    let nettype = match cli.network.as_str() {
        "testnet" => 1u8,
        "stagenet" => 2u8,
        _ => 0u8,
    };

    let (daemon_user, daemon_pass) = if cli.daemon_login.contains(':') {
        let mut parts = cli.daemon_login.splitn(2, ':');
        (
            parts.next().unwrap_or("").to_string(),
            parts.next().unwrap_or("").to_string(),
        )
    } else {
        (cli.daemon_login, String::new())
    };

    let ctx = engine::EngineContext::new(
        nettype,
        &cli.daemon_address,
        &daemon_user,
        &daemon_pass,
        cli.trusted_daemon,
        &cli.engine_dir,
    )?;

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
        let password = prompt_password("Engine password: ")?;
        ctx.open(filename, &password)?;
        println!("Opened engine: {filename}");
    }

    commands::repl(ctx, daemon_client, cli.debug)
}

pub fn prompt_password(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    rpassword::prompt_password(prompt).map_err(Into::into)
}
