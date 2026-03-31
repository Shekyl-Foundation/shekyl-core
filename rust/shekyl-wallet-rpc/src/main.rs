// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Standalone shekyl-wallet-rpc binary (Rust implementation).
//!
//! Drop-in replacement for the C++ shekyl-wallet-rpc. Accepts the same CLI
//! flags used by the GUI wallet: --wallet-dir, --rpc-bind-port, --daemon-address,
//! --disable-rpc-login, --non-interactive.

use clap::Parser;
use shekyl_wallet_rpc::ServerConfig;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "shekyl-wallet-rpc", about = "Shekyl wallet RPC server (Rust)")]
struct Cli {
    /// Directory for wallet files
    #[arg(long = "wallet-dir", default_value = ".")]
    wallet_dir: String,

    /// RPC bind port
    #[arg(long = "rpc-bind-port", default_value = "11030")]
    rpc_bind_port: u16,

    /// RPC bind IP
    #[arg(long = "rpc-bind-ip", default_value = "127.0.0.1")]
    rpc_bind_ip: String,

    /// Daemon address (host:port)
    #[arg(long = "daemon-address", default_value = "")]
    daemon_address: String,

    /// Daemon username
    #[arg(long = "daemon-login", default_value = "")]
    daemon_login: String,

    /// Disable RPC login (ignored for compatibility)
    #[arg(long = "disable-rpc-login", default_value_t = false)]
    disable_rpc_login: bool,

    /// Non-interactive mode (ignored for compatibility)
    #[arg(long = "non-interactive", default_value_t = false)]
    non_interactive: bool,

    /// Trust the daemon (skip proof verification)
    #[arg(long = "trusted-daemon", default_value_t = false)]
    trusted_daemon: bool,

    /// Network type: mainnet, testnet, stagenet
    #[arg(long = "network", default_value = "mainnet")]
    network: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
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

    let bind_address = format!("{}:{}", cli.rpc_bind_ip, cli.rpc_bind_port);

    let config = ServerConfig {
        bind_address,
        wallet_dir: cli.wallet_dir,
        daemon_address: cli.daemon_address,
        daemon_username: daemon_user,
        daemon_password: daemon_pass,
        nettype,
        trusted_daemon: cli.trusted_daemon,
    };

    shekyl_wallet_rpc::run_server(config).await
}
