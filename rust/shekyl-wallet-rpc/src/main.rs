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

use std::path::PathBuf;

use clap::Parser;
use shekyl_wallet_rpc::ServerConfig;

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

    /// Optional file sink for `tracing` events. When omitted, logs go to
    /// stderr only. When supplied, events are *also* written (never
    /// rotated) to this path; the parent directory is created with
    /// `0700` perms and the file with `0600` perms on POSIX.
    #[arg(long = "log-file")]
    log_file: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // INFO default, stderr always, file sink only when --log-file is
    // supplied. Matches the plan: wallet-rpc never creates a default
    // `~/.shekyl/logs/` file on the user's behalf; operators opt in
    // explicitly and own the path.
    let config = if let Some(ref path) = cli.log_file {
        // Reject paths that clearly can't name a log file before we
        // surface a deeper `Is a directory` / `No such file` error
        // from `OpenOptions::open`. The operator-facing message here
        // tells them exactly which invariant they broke.
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
        // Refuse non-UTF-8 filename components rather than silently
        // lossy-converting them via `to_string_lossy()`: the replaced
        // bytes would point `tracing_appender` at a *different* file
        // than the one the operator named.
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
