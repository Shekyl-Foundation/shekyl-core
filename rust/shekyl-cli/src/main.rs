// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! shekyl-cli: interactive CLI wallet for Shekyl.
//!
//! Thin REPL frontend over `shekyl-wallet-rpc` (library mode). Uses the same
//! Rust wallet stack as the GUI: wallet2 via FFI for lifecycle, Rust scanner
//! for reads, and native-sign for transaction construction.

mod commands;
mod wallet;

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "shekyl-cli",
    about = "Shekyl interactive CLI wallet",
    version
)]
struct Cli {
    /// Daemon address (host:port)
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

    /// Directory for wallet files
    #[arg(long, default_value = ".")]
    wallet_dir: String,

    /// Open a wallet file immediately on startup
    #[arg(long)]
    wallet_file: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("warn".parse()?))
        .init();

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

    let ctx = wallet::WalletContext::new(
        nettype,
        &cli.daemon_address,
        &daemon_user,
        &daemon_pass,
        cli.trusted_daemon,
        &cli.wallet_dir,
    )?;

    if let Some(ref filename) = cli.wallet_file {
        let password = prompt_password("Wallet password: ")?;
        ctx.open(filename, &password)?;
        println!("Opened wallet: {filename}");
    }

    commands::repl(ctx)
}

pub fn prompt_password(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    rpassword::prompt_password(prompt).map_err(Into::into)
}
