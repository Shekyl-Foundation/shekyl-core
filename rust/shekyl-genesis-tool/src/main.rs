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
use shekyl_genesis_tool::builder::build_genesis_tx;
use shekyl_genesis_tool::recipients::{load_and_validate, GENESIS_RECIPIENT_COUNT};
use shekyl_genesis_tool::table::{
    mint_time, recorded_timestamp, verify, write_pins, write_regtest_recipients, Rebuilt,
};
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
        /// Target network: mainnet | testnet | stagenet | regtest.
        #[arg(long, value_parser = parse_network)]
        network: Network,
        /// New output directory on user-secured storage (must not already
        /// exist). Refused inside any git tree; published atomically as 0700.
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Build the genesis coinbase tx from a recipients file; hex to stdout.
    Build {
        /// Target network: mainnet | testnet | stagenet | regtest.
        #[arg(long, value_parser = parse_network)]
        network: Network,
        /// Recipients file (default: <repo>/config/genesis_recipients.<net>.json).
        #[arg(long)]
        recipients: Option<PathBuf>,
    },
    /// Mint the named networks' genesis now: stamp each with the clock's
    /// current second and write its pins
    /// (rust/shekyl-network/genesis/<net>.{tx.hex,timestamp,hash}). The
    /// other networks keep theirs. A mint is a regenesis of that network.
    Mint {
        /// A network to mint: mainnet | testnet | stagenet | regtest; repeat
        /// for each. There is no default: every network is named.
        #[arg(long = "network", value_parser = parse_network, required = true)]
        networks: Vec<Network>,
    },
    /// Rebuild every network's genesis from its recipients file at its
    /// recorded mint time and write the network table's pins. Never reads
    /// the clock: a network with no recorded mint time is refused.
    Pin,
    /// Rebuild every network's genesis from its recipients file at its
    /// recorded mint time and compare it with the network table this binary
    /// was compiled with.
    Verify,
    /// Write regtest's recipients file from its committed test seeds.
    RegtestRecipients,
}

/// Clap value parser: delegates to [`Network::from_str`] (one spelling
/// per network).
fn parse_network(s: &str) -> Result<Network, String> {
    Network::from_str(s).map_err(|e| e.to_string())
}

/// Repo root as seen at compile time (`rust/shekyl-genesis-tool` → repo).
/// Correct for `cargo run` and locally built binaries; a binary copied to
/// another machine needs the explicit path flags.
fn default_repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn default_recipients(explicit: Option<PathBuf>, net: Network) -> PathBuf {
    explicit.unwrap_or_else(|| {
        default_repo_root()
            .join("config")
            .join(format!("genesis_recipients.{}.json", net.name()))
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
                net = network.name(),
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
                net = network.name(),
                n = recipients.len(),
                hash = hex::encode(built.tx_hash),
                len = built.hex.len(),
            );
            println!("{}", built.hex);
            Ok(())
        }
        Cmd::Mint { networks } => {
            let root = default_repo_root();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| GenesisToolError::Invalid("the clock is before 1970".into()))?
                .as_secs();
            let timestamp = mint_time(now)?;
            for net in networks {
                report_pinned(net, &write_pins(&root, net, timestamp)?);
            }
            eprintln!("rebuild to compile the new pins into the table");
            Ok(())
        }
        Cmd::Pin => {
            let root = default_repo_root();
            for net in Network::ALL {
                let timestamp = recorded_timestamp(&root, net)?;
                report_pinned(net, &write_pins(&root, net, timestamp)?);
            }
            eprintln!("rebuild to compile the new pins into the table");
            Ok(())
        }
        Cmd::Verify => {
            let root = default_repo_root();
            let mut all_ok = true;
            for net in Network::ALL {
                let check = verify(&root, net)?;
                let ok = check.tx_matches && check.timestamp_matches && check.hash_matches;
                all_ok &= ok;
                eprintln!(
                    "{net}: {verdict}",
                    net = check.network,
                    verdict = if ok {
                        "OK"
                    } else if !check.tx_matches {
                        "MISMATCH (transaction)"
                    } else if !check.timestamp_matches {
                        "MISMATCH (mint time: rebuild to compile the recorded one)"
                    } else {
                        "MISMATCH (block hash)"
                    },
                );
            }
            if all_ok {
                Ok(())
            } else {
                Err(GenesisToolError::Invalid(
                    "the network table's genesis is not what the recipients files rebuild".into(),
                ))
            }
        }
        Cmd::RegtestRecipients => {
            let path = write_regtest_recipients(&default_repo_root())?;
            eprintln!("wrote {}", path.display());
            Ok(())
        }
    }
}

/// One network's freshly written pins, to stdout: the mint time those
/// pins record, and the block hash.
fn report_pinned(net: Network, rebuilt: &Rebuilt) {
    println!(
        "{net}: mint time {ts}, block {hash}{provisional}",
        ts = rebuilt.timestamp.get(),
        hash = hex::encode(rebuilt.block_hash),
        provisional = if net.genesis().provisional() {
            " (provisional: rebuilt from recipients that are not final)"
        } else {
            ""
        },
    );
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
