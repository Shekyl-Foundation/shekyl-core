// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The DRS-E2 replay driver — the ingest pipeline's first source, as a
//! binary (`DRS_E2_REPLAY_DRIVER.md` §1.1, RD-Q1, RD-Q7).
//!
//! Two commands, matching the two artifacts:
//!
//! - `fetch` — build a corpus from an **unpruned** daemon over
//!   `/get_blocks_by_height.bin` (zero C++; the writer verifies every
//!   record and refuses a pruned answer by height, RD-F15);
//! - `replay` — run a corpus through `form → validate → connect` against a
//!   redb store, borrowing the passed-through facts from a trace and
//!   digesting at its checkpoints; `--fixed-difficulty n` is accepted with
//!   `--chain regtest` only, exactly as `shekyld --regtest` binds it
//!   (RD-Q7; refused elsewhere by construction, `ChainRules::new`).
//!
//! The trace comes from `shekyl-e2-trace-export` (the C++ harvest shim).
//! Everything this binary composes is library code in
//! `shekyl-chain-ingest`; nothing lives only here (RD-Q1).

#![deny(unsafe_code)]

use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::num::NonZeroU128;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};
use shekyl_address::Network;
use shekyl_chain_ingest::corpus::{CorpusReader, CorpusWriter};
use shekyl_chain_ingest::fetch::fetch_corpus;
use shekyl_chain_ingest::grader::{grade_run, Register};
use shekyl_chain_ingest::metrics::Metrics;
use shekyl_chain_ingest::pipeline::{run, PipelineConfig};
use shekyl_chain_ingest::schedule::{Chain, ChainRules};
use shekyl_chain_ingest::substrate::ChainSubstrate;
use shekyl_chain_ingest::trace::Trace;
use shekyl_chain_store::codec::SettlementEpochBlocks;
use shekyl_chain_store::store::ChainStore;
use shekyl_pow_randomx::CacheStore;
use shekyl_rpc_transport::HttpRpc;
use shekyl_types::BlockHeight;

/// The chain a corpus is from — `Network` plus regtest, which the address
/// crate cannot name (slice 2 F10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum ChainArg {
    Mainnet,
    Testnet,
    Stagenet,
    Regtest,
}

impl From<ChainArg> for Chain {
    fn from(c: ChainArg) -> Self {
        match c {
            ChainArg::Mainnet => Chain::Public(Network::Mainnet),
            ChainArg::Testnet => Chain::Public(Network::Testnet),
            ChainArg::Stagenet => Chain::Public(Network::Stagenet),
            ChainArg::Regtest => Chain::Regtest,
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "shekyl-chain-replay",
    about = "DRS-E2 replay driver: fetch a corpus, replay it through the ingest pipeline"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Build a corpus from an unpruned daemon.
    Fetch {
        /// Daemon base URL, e.g. `http://127.0.0.1:38081`.
        #[arg(long)]
        daemon: String,
        /// First height.
        #[arg(long, default_value_t = 0)]
        from: u64,
        /// One past the last height.
        #[arg(long)]
        to: u64,
        /// Heights per request.
        #[arg(long, default_value_t = 100)]
        batch: usize,
        /// Where to write the corpus.
        #[arg(long)]
        out: PathBuf,
    },
    /// Replay a corpus against a store, grading digests where the trace
    /// has checkpoints.
    Replay {
        /// The corpus (`fetch`'s output).
        #[arg(long)]
        corpus: PathBuf,
        /// The trace (`shekyl-e2-trace-export`'s output).
        #[arg(long)]
        trace: PathBuf,
        /// The redb store directory (created if absent, appended to if not).
        #[arg(long)]
        store: PathBuf,
        /// Which chain's rules the corpus is judged under.
        #[arg(long, value_enum)]
        chain: ChainArg,
        /// Fix the difficulty target, as `shekyld --regtest --fixed-difficulty n`
        /// does. Accepted with `--chain regtest` only.
        #[arg(long)]
        fixed_difficulty: Option<NonZeroU128>,
        /// Settlement epoch in blocks the store is sealed under.
        #[arg(long, default_value_t = 10_000)]
        settlement_epoch_blocks: u64,
        /// Blocks formed ahead of the writer at once.
        #[arg(long, default_value_t = PipelineConfig::default().window)]
        window: usize,
        /// The CSR-3a register as `scripts/ci/export_conformance_register.py`
        /// emits it. With it, the run is graded (RD-Q6) and exits non-zero on
        /// an unadjudicated disagreement (§1.3).
        #[arg(long)]
        register: Option<PathBuf>,
        /// Where to write the graded-run artifact (JSON). Requires `--register`.
        #[arg(long, requires = "register")]
        grade_out: Option<PathBuf>,
        /// Where to write the RandomX measurement (JSON; RD-F11).
        #[arg(long)]
        metrics_out: Option<PathBuf>,
    },
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    match real_main(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("shekyl-chain-replay: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn real_main(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Fetch {
            daemon,
            from,
            to,
            batch,
            out,
        } => {
            let rpc = HttpRpc::new(daemon).await?;
            let mut writer = CorpusWriter::new(
                BufWriter::new(File::create(&out)?),
                BlockHeight::from_raw(from),
            )?;
            let written = fetch_corpus(&rpc, from..to, batch, &mut writer).await?;
            writer.finish()?;
            eprintln!("fetched {written} block(s) into {}", out.display());
            Ok(())
        }
        Command::Replay {
            corpus,
            trace,
            store,
            chain,
            fixed_difficulty,
            settlement_epoch_blocks,
            window,
            register,
            grade_out,
            metrics_out,
        } => {
            let rules = ChainRules::new(chain.into(), fixed_difficulty)?;
            let epoch = SettlementEpochBlocks::new(settlement_epoch_blocks)
                .ok_or("--settlement-epoch-blocks must be non-zero")?;
            let trace = Arc::new(Trace::read(BufReader::new(File::open(&trace)?))?);
            let mut source = CorpusReader::open(BufReader::new(File::open(&corpus)?))?;
            let store = ChainStore::create(&store, epoch)?;
            let metrics = Arc::new(Metrics::new());
            let substrate = Arc::new(ChainSubstrate::new(
                Arc::new(CacheStore::new()),
                Arc::clone(&metrics),
            ));
            let report = run(
                &mut source,
                substrate,
                metrics,
                rules,
                store,
                trace,
                PipelineConfig { window },
            )
            .await?;
            eprintln!(
                "connected {} block(s), popped {}, {} checkpoint(s) digested{}",
                report.connected.len(),
                report.popped,
                report.checkpoints.len(),
                report
                    .refused
                    .as_ref()
                    .map_or(String::new(), |(h, why)| format!(
                        "; refused at height {h}: {why:?}"
                    )),
            );
            for (height, ours, theirs) in &report.checkpoints {
                let verdict = if ours == theirs { "MATCH" } else { "DIVERGE" };
                eprintln!("checkpoint after height {height}: digest {verdict}");
            }
            eprintln!(
                "randomx light mode: {} hash(es), mean {:?} ns; {} derive(s), mean {:?} ns; {} block(s) formed, mean {:?} ns",
                report.metrics.hashes,
                report.metrics.hash_ns_mean,
                report.metrics.cache_derives,
                report.metrics.derive_ns_mean,
                report.metrics.blocks_formed,
                report.metrics.form_ns_mean,
            );
            if let Some(out) = metrics_out {
                std::fs::write(&out, report.metrics.to_json()?)?;
                eprintln!("metrics artifact → {}", out.display());
            }
            if let Some(register) = register {
                let register = Register::from_json(&std::fs::read_to_string(&register)?)?;
                let graded = grade_run(&register, &report.observations);
                eprintln!(
                    "graded: {} row(s); {} derived-and-conformant, {} borrowed, {} not exercised, \
                     {} owed reviewed-divergence, {} unadjudicated",
                    graded.rows.len(),
                    graded.derived_and_conformant,
                    graded.borrowed,
                    graded.not_exercised,
                    graded.owed_reviewed_divergence.len(),
                    graded.unadjudicated.len(),
                );
                if let Some(out) = grade_out {
                    std::fs::write(&out, graded.to_json()?)?;
                    eprintln!("graded artifact → {}", out.display());
                }
                for u in &graded.unadjudicated {
                    eprintln!(
                        "UNADJUDICATED {} ({:?}): {:?}",
                        u.id, u.clause, u.acceptance
                    );
                }
                if !graded.passes() {
                    return Err("the run has unadjudicated disagreements (§1.3)".into());
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_difficulty_parses_and_the_chain_enum_maps() {
        let cli = Cli::try_parse_from([
            "shekyl-chain-replay",
            "replay",
            "--corpus",
            "c",
            "--trace",
            "t",
            "--store",
            "s",
            "--chain",
            "regtest",
            "--fixed-difficulty",
            "7",
        ])
        .expect("parses");
        let Command::Replay {
            chain,
            fixed_difficulty,
            ..
        } = cli.command
        else {
            panic!("replay");
        };
        assert_eq!(Chain::from(chain), Chain::Regtest);
        assert_eq!(fixed_difficulty, NonZeroU128::new(7));
        // Zero is not a difficulty: the type refuses it at parse time.
        assert!(Cli::try_parse_from([
            "shekyl-chain-replay",
            "replay",
            "--corpus",
            "c",
            "--trace",
            "t",
            "--store",
            "s",
            "--chain",
            "regtest",
            "--fixed-difficulty",
            "0",
        ])
        .is_err());
    }

    #[test]
    fn the_flag_off_regtest_is_refused_where_the_rules_are_built() {
        let refused = ChainRules::new(Chain::Public(Network::Testnet), NonZeroU128::new(7));
        assert!(refused.is_err());
        let ok = ChainRules::new(Chain::Regtest, NonZeroU128::new(7)).expect("regtest");
        assert_eq!(
            ok.in_force(BlockHeight::from_raw(3)),
            shekyl_chain_rules::RuleSet::fakechain(NonZeroU128::new(7).expect("nz"))
        );
    }
}
