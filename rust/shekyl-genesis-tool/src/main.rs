// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `geblock` — genesis build/verify CLI. Thin clap dispatcher; all logic
//! lives in the `shekyl_genesis_tool` library so the integration tests can
//! drive it directly.
//!
//! Contract inherited from the retired C++ `genesis_builder`: the built
//! genesis tx hex goes to **stdout**, every diagnostic goes to **stderr**.

#![deny(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

use clap::{Parser, Subcommand};
use shekyl_address::Network;
use shekyl_genesis_tool::builder::{build_genesis_tx, genesis_block};
use shekyl_genesis_tool::config_pin::{load_config_pins, verify_networks};
use shekyl_genesis_tool::recipients::{load_and_validate, GENESIS_RECIPIENT_COUNT};
use shekyl_genesis_tool::wallets::{generate_wallets, write_custody_files};
use shekyl_genesis_tool::GenesisToolError;

/// Genesis build/verify tool — deterministic Rust replacement for the
/// retired C++ genesis_builder.
#[derive(Parser)]
#[command(name = "geblock", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate the genesis wallet set (exactly five): custody files (seeds,
    /// 0600) plus a ready-to-commit recipients-JSON skeleton (addresses only).
    /// Count is consensus policy (`GENESIS_RECIPIENT_COUNT`), not a flag.
    GenWallets {
        /// Target network: mainnet | testnet | stagenet.
        #[arg(long, value_parser = parse_network)]
        network: Network,
        /// New output directory on user-secured storage (must not already
        /// exist). Refused inside any git tree; published atomically as 0700.
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Build the genesis coinbase tx from a recipients file; hex to stdout.
    Build {
        /// Target network: mainnet | testnet | stagenet.
        #[arg(long, value_parser = parse_network)]
        network: Network,
        /// Recipients file (default: <repo>/config/genesis_recipients.<net>.json).
        #[arg(long)]
        recipients: Option<PathBuf>,
    },
    /// Rebuild all three networks from the recipients files and byte-compare
    /// against the GENESIS_TX pins in src/cryptonote_config.h.
    Verify {
        /// Path to cryptonote_config.h (default: <repo>/src/cryptonote_config.h).
        #[arg(long)]
        config: Option<PathBuf>,
        /// Directory holding genesis_recipients.<net>.json (default: <repo>/config).
        #[arg(long)]
        recipients_dir: Option<PathBuf>,
    },
    /// Print the genesis block id + tx hash for a network (v9 header, nonce
    /// from cryptonote_config.h).
    BlockId {
        /// Target network: mainnet | testnet | stagenet.
        #[arg(long, value_parser = parse_network)]
        network: Network,
        /// Recipients file (default: <repo>/config/genesis_recipients.<net>.json).
        #[arg(long)]
        recipients: Option<PathBuf>,
        /// Path to cryptonote_config.h, read for GENESIS_NONCE
        /// (default: <repo>/src/cryptonote_config.h).
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

/// Clap value parser: delegates to [`Network::from_str`] (case-insensitive).
fn parse_network(s: &str) -> Result<Network, String> {
    Network::from_str(s)
}

/// Repo root as seen at compile time (`rust/shekyl-genesis-tool` → repo).
/// Correct for `cargo run` and locally built binaries; a binary copied to
/// another machine needs the explicit path flags.
fn default_repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn default_config_h(explicit: Option<PathBuf>) -> PathBuf {
    explicit.unwrap_or_else(|| default_repo_root().join("src/cryptonote_config.h"))
}

fn default_recipients(explicit: Option<PathBuf>, net: Network) -> PathBuf {
    explicit.unwrap_or_else(|| {
        default_repo_root()
            .join("config")
            .join(format!("genesis_recipients.{}.json", net.as_str()))
    })
}

fn run(cmd: Cmd) -> Result<(), GenesisToolError> {
    match cmd {
        Cmd::GenWallets { network, out_dir } => {
            let wallets = generate_wallets(network)?;
            let skeleton = write_custody_files(&out_dir, network, &wallets)?;
            for w in &wallets {
                println!("wallet {:02}: {}", w.index, w.address);
            }
            eprintln!(
                "\n{count} fresh {net} wallet(s) written to {dir}\n\
                 - custody files hold the ONLY copy of each seed; move them to \
                 offline storage now\n\
                 - restore-verify each wallet from its seed before committing \
                 to the allocation\n\
                 - recipients skeleton (addresses only, safe to commit): {skel}",
                count = GENESIS_RECIPIENT_COUNT,
                net = network.as_str(),
                dir = out_dir.display(),
                skel = skeleton.display(),
            );
            Ok(())
        }
        Cmd::Build {
            network,
            recipients,
        } => {
            let path = default_recipients(recipients, network);
            let recipients = load_and_validate(&path, network)?;
            let built = build_genesis_tx(network, &recipients)?;
            eprintln!(
                "genesis coinbase [{net}]: {n} outputs, tx hash {hash}, {len} hex chars",
                net = network.as_str(),
                n = recipients.len(),
                hash = hex::encode(built.tx_hash),
                len = built.hex.len(),
            );
            println!("{}", built.hex);
            Ok(())
        }
        Cmd::Verify {
            config,
            recipients_dir,
        } => {
            let config = default_config_h(config);
            let dir = recipients_dir.unwrap_or_else(|| default_repo_root().join("config"));
            let outcomes = verify_networks(&config, &dir)?;
            let mut all_ok = true;
            for o in &outcomes {
                if o.matches {
                    eprintln!(
                        "{net}: OK ({len} hex chars)",
                        net = o.network.as_str(),
                        len = o.pinned_len
                    );
                } else {
                    all_ok = false;
                    match o.first_mismatch {
                        Some(at) => eprintln!(
                            "{net}: MISMATCH at hex offset {at} (built {b} chars, pinned {p})",
                            net = o.network.as_str(),
                            b = o.built_len,
                            p = o.pinned_len,
                        ),
                        None => eprintln!(
                            "{net}: MISMATCH — length differs (built {b} chars, pinned {p})",
                            net = o.network.as_str(),
                            b = o.built_len,
                            p = o.pinned_len,
                        ),
                    }
                }
            }
            if all_ok {
                Ok(())
            } else {
                Err(GenesisToolError::Invalid(
                    "genesis verification failed: rebuilt hex does not match the \
                     cryptonote_config.h pin(s)"
                        .into(),
                ))
            }
        }
        Cmd::BlockId {
            network,
            recipients,
            config,
        } => {
            let rec_path = default_recipients(recipients, network);
            let recipients = load_and_validate(&rec_path, network)?;
            let built = build_genesis_tx(network, &recipients)?;
            let pins = load_config_pins(&default_config_h(config))?;
            let nonce = pins.for_network(network).genesis_nonce;
            let tx_hash = built.tx_hash;
            let block = genesis_block(built.tx, nonce)?;
            println!(
                "network={net} nonce={nonce} tx_hash={hash} block_id={id}",
                net = network.as_str(),
                hash = hex::encode(tx_hash),
                id = hex::encode(block.hash()),
            );
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.cmd) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("geblock: {e}");
            ExitCode::FAILURE
        }
    }
}
