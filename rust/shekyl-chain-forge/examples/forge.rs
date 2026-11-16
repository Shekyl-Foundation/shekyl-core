// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The chain forge (`CHAIN_FORGE.md` §11.1): a plan in, a forged chain out.
//!
//! ```text
//! cargo run --release -p shekyl-chain-forge --example forge -- \
//!     --plan rust/shekyl-chain-forge/plans/small.toml --out <dir> \
//!     [--hashers N] [--swap S1,S5] [--stop-at <committed blocks.txt>]
//!     [--live-producer] [--start-spread-ms N]
//! cargo run -p shekyl-chain-forge --example forge -- --diff <old blocks.txt> <new blocks.txt>
//! ```
//!
//! `--diff` prints the first block where two ledgers differ, the line a
//! regeneration's pull request names (`CHAIN_FORGE.md` §9), and exits 1 if
//! they differ.
//!
//! ```text
//! ```
//!
//! A cargo example, not a binary (`CF-R8`): it builds against the crate's
//! dev-dependencies (the scenario driver, the harness spender, the seeded
//! entry points), and the release build never asks for examples. `--swap`
//! names sources to draw from the OS instead of the plan's seed, a negative
//! control's run; `--stop-at` ends the run at the first block that differs
//! from a committed ledger. The time each half took is printed, not
//! written: the manifest holds nothing that varies between forgings.

#![deny(unsafe_code)]

#[allow(
    dead_code,
    reason = "the runnable uses the executor's forging; the tests use the rest"
)]
#[path = "../executor/mod.rs"]
mod executor;

use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::process::ExitCode;

use executor::seeds::Source;
use executor::{forge, Options, Outcome, ProducerOptions};
use shekyl_chain_forge::{sha256_hex, BlocksTxt, Plan, PlanRef};

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("forge: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let [flag, old, new] = args.as_slice() {
        if flag == "--diff" {
            return diff(old, new);
        }
    }
    let mut plan_path = None;
    let mut out = None;
    let mut hashers = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
    let mut swapped = BTreeSet::new();
    let mut stop_at = None;
    let mut live_producer = false;
    let mut start_spread_ms: Option<u64> = None;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or(format!("{flag} takes a value"));
        match flag.as_str() {
            "--plan" => plan_path = Some(PathBuf::from(value()?)),
            "--out" => out = Some(PathBuf::from(value()?)),
            "--hashers" => {
                hashers = value()?
                    .parse()
                    .map_err(|_| "--hashers is a count".to_owned())?;
            }
            "--swap" => {
                for name in value()?.split(',') {
                    swapped.insert(Source::named(name).ok_or(format!("no source {name}"))?);
                }
            }
            "--stop-at" => stop_at = Some(PathBuf::from(value()?)),
            "--live-producer" => live_producer = true,
            "--start-spread-ms" => {
                start_spread_ms = Some(
                    value()?
                        .parse()
                        .map_err(|_| "--start-spread-ms is a count".to_owned())?,
                );
            }
            other => return Err(format!("unknown flag {other}")),
        }
    }
    let plan_path = plan_path.ok_or("--plan is required")?;
    let out = out.ok_or("--out is required")?;
    let bytes = std::fs::read(&plan_path).map_err(|e| format!("{}: {e}", plan_path.display()))?;
    let text = std::str::from_utf8(&bytes).map_err(|e| format!("the plan: {e}"))?;
    let plan = Plan::parse(text).map_err(|e| e.to_string())?;
    let plan_ref = PlanRef {
        path: repository_path(&plan_path)?,
        sha256: sha256_hex(&bytes),
    };
    let stop_at_difference = match stop_at {
        None => None,
        Some(path) => {
            let text =
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            Some(BlocksTxt::parse(&text).map_err(|e| e.to_string())?)
        }
    };
    let options = Options {
        swapped,
        stop_at_difference,
        hashers: NonZeroUsize::new(hashers).ok_or("--hashers is at least one")?,
        producer: ProducerOptions {
            live: live_producer,
            start_spread: start_spread_ms.map(std::time::Duration::from_millis),
        },
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("the runtime: {e}"))?;
    let started = std::time::Instant::now();
    let outcome = runtime
        .block_on(forge(&plan, plan_ref, &out, options))
        .map_err(|e| e.to_string())?;
    let took = started.elapsed();
    match outcome {
        Outcome::Forged(forged) => {
            eprintln!(
                "forged {}: {} block(s) in blocks.txt, tip {}, {} transaction(s), in {:.1} s",
                forged.manifest.chain,
                forged.blocks.lines().len(),
                forged.manifest.tip_height,
                forged.manifest.transactions,
                took.as_secs_f64(),
            );
            for file in executor::FILES {
                let path = out.join(file);
                let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
                eprintln!("  {} {file}", sha256_hex(&bytes));
            }
            Ok(ExitCode::SUCCESS)
        }
        Outcome::Differed { blocks, difference } => {
            eprintln!(
                "differs from the committed ledger after {} block(s): {difference} ({:.1} s)",
                blocks.lines().len(),
                took.as_secs_f64()
            );
            Ok(ExitCode::from(3))
        }
    }
}

/// The first block where the ledgers at `old` and `new` differ.
fn diff(old: &str, new: &str) -> Result<ExitCode, String> {
    let read = |path: &str| {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        BlocksTxt::parse(&text).map_err(|e| format!("{path}: {e}"))
    };
    match read(old)?.first_difference(&read(new)?) {
        None => {
            println!("the ledgers are the same chain");
            Ok(ExitCode::SUCCESS)
        }
        Some(difference) => {
            println!("first differing block (old, new): {difference}");
            Ok(ExitCode::from(1))
        }
    }
}

/// `path` from the repository root, `/`-separated: the manifest names the
/// plan the same way from every checkout and working directory.
fn repository_path(path: &std::path::Path) -> Result<String, String> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|e| format!("the repository root: {e}"))?;
    let path = path
        .canonicalize()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let relative = path
        .strip_prefix(&root)
        .map_err(|_| format!("{} is outside the repository", path.display()))?;
    Ok(relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/"))
}
