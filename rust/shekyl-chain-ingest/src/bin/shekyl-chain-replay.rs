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
//!   digesting at its checkpoint; `--fixed-difficulty n` is accepted with
//!   `--chain regtest` only, exactly as `shekyld --regtest` binds it
//!   (RD-Q7; refused elsewhere by construction, `ChainRules::new`).
//!
//! The trace comes from `shekyl-e2-trace-export` (the C++ harvest shim).
//! Everything this binary composes is library code in
//! `shekyl-chain-ingest`; nothing lives only here (RD-Q1).
//!
//! # Exit status
//!
//! Non-zero on any fault, and on any **disagreement** the run itself
//! reports — a refusal, a DIVERGE at the checkpoint — unless a register was
//! given, in which case the grade decides (§1.3: the success condition is
//! *no unadjudicated disagreement*, and with no register nothing is
//! adjudicated). The metrics artifact is written on every path that ran
//! the pipeline, a late fault included: hours of hashing are the
//! measurement RD-F11 asked for whether or not the run finished.

#![deny(unsafe_code)]

use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::num::{NonZeroU128, NonZeroUsize};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use shekyl_archival_retention::constants::SETTLEMENT_EPOCH_BLOCKS;
use shekyl_chain_ingest::corpus::{CorpusNet, CorpusReader, CorpusWriter};
use shekyl_chain_ingest::fetch::fetch_corpus;
use shekyl_chain_ingest::grader::{grade_run, Register};
use shekyl_chain_ingest::metrics::Metrics;
use shekyl_chain_ingest::pipeline::{run, Disagreement, PipelineConfig, RunReport};
use shekyl_chain_ingest::schedule::ChainRules;
use shekyl_chain_ingest::substrate::ProductionSubstrate;
use shekyl_chain_ingest::trace::Trace;
use shekyl_chain_store::codec::SettlementEpochBlocks;
use shekyl_chain_store::store::ChainStore;
use shekyl_pow_randomx::CacheStore;
use shekyl_rpc_transport::HttpRpc;
use shekyl_types::BlockHeight;

/// Heights per `/get_blocks_by_height.bin` request: a 2301-block regtest
/// fetch is a few dozen round trips, and one reply stays well under the
/// daemon's response cap at mainnet block weights.
const DEFAULT_FETCH_BATCH: NonZeroUsize = match NonZeroUsize::new(100) {
    Some(n) => n,
    None => unreachable!(),
};

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
        /// Which chain the daemon serves; written into the corpus header
        /// and checked by `replay --chain`.
        #[arg(long, value_enum)]
        chain: CorpusNet,
        /// First height.
        #[arg(long, default_value_t = 0)]
        from: u64,
        /// One past the last height.
        #[arg(long)]
        to: u64,
        /// Heights per request (non-zero).
        #[arg(long, default_value_t = DEFAULT_FETCH_BATCH)]
        batch: NonZeroUsize,
        /// Where to write the corpus.
        #[arg(long)]
        out: PathBuf,
    },
    /// Replay a corpus against a store, grading the digest at the trace's
    /// checkpoint.
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
        /// Which chain's rules the corpus is judged under; must be the
        /// chain the corpus is tagged with.
        #[arg(long, value_enum)]
        chain: CorpusNet,
        /// Fix the difficulty target, as `shekyld --regtest --fixed-difficulty n`
        /// does. Accepted with `--chain regtest` only.
        #[arg(long)]
        fixed_difficulty: Option<NonZeroU128>,
        /// Blocks formed ahead of the writer at once (non-zero).
        #[arg(long, default_value_t = PipelineConfig::DEFAULT_WINDOW)]
        window: NonZeroUsize,
        /// `form` workers hashing at once (non-zero). Defaults to the host's
        /// parallelism; more than that thrashes RandomX's scratchpads and
        /// inflates the per-hash figure the metrics artifact records.
        #[arg(long, default_value_t = PipelineConfig::default_hashers())]
        hashers: NonZeroUsize,
        /// The CSR-3a register as `scripts/ci/export_conformance_register.py`
        /// emits it. With it, the run is graded (RD-Q6) and the grade decides
        /// the exit status; without it, any disagreement the run reports
        /// does.
        #[arg(long)]
        register: Option<PathBuf>,
        /// Where to write the graded-run artifact (JSON). Requires `--register`.
        #[arg(long, requires = "register")]
        grade_out: Option<PathBuf>,
        /// Where to write the RandomX measurement (JSON; RD-F11). Written
        /// even when the run faults.
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

type Failure = Box<dyn std::error::Error>;

async fn real_main(cli: Cli) -> Result<(), Failure> {
    match cli.command {
        Command::Fetch {
            daemon,
            chain,
            from,
            to,
            batch,
            out,
        } => fetch(daemon, chain, from..to, batch, &out).await,
        Command::Replay {
            corpus,
            trace,
            store,
            chain,
            fixed_difficulty,
            window,
            hashers,
            register,
            grade_out,
            metrics_out,
        } => {
            replay(Replay {
                corpus,
                trace,
                store,
                chain,
                rules: ChainRules::new(chain.into(), fixed_difficulty)?,
                cfg: PipelineConfig { window, hashers },
                register,
                grade_out,
                metrics_out,
            })
            .await
        }
    }
}

async fn fetch(
    daemon: String,
    chain: CorpusNet,
    heights: std::ops::Range<u64>,
    batch: NonZeroUsize,
    out: &std::path::Path,
) -> Result<(), Failure> {
    let rpc = HttpRpc::new(daemon).await?;
    let mut writer = CorpusWriter::create(
        BufWriter::new(File::create(out)?),
        chain,
        BlockHeight::from_raw(heights.start),
    )?;
    let written = fetch_corpus(&rpc, heights, batch, &mut writer).await?;
    writer.finish()?;
    eprintln!("fetched {written} block(s) into {}", out.display());
    Ok(())
}

/// A replay's inputs, resolved from the command line.
struct Replay {
    corpus: PathBuf,
    trace: PathBuf,
    store: PathBuf,
    chain: CorpusNet,
    rules: ChainRules,
    cfg: PipelineConfig,
    register: Option<PathBuf>,
    grade_out: Option<PathBuf>,
    metrics_out: Option<PathBuf>,
}

/// The register is read and checked **before** the run: a register that
/// does not parse is discovered in milliseconds, not after every block has
/// connected.
fn register_first(path: Option<&std::path::Path>) -> Result<Option<Register>, Failure> {
    path.map(|p| Ok(Register::from_json(&std::fs::read_to_string(p)?)?))
        .transpose()
}

async fn replay(replay: Replay) -> Result<(), Failure> {
    let register = register_first(replay.register.as_deref())?;
    // The settlement epoch is a consensus constant, not a knob: a store
    // sealed under another epoch would be another chain.
    let epoch = SettlementEpochBlocks::new(SETTLEMENT_EPOCH_BLOCKS)
        .expect("the consensus settlement epoch is non-zero");
    let trace = Arc::new(Trace::read(BufReader::new(File::open(&replay.trace)?))?);
    let mut source = CorpusReader::open(BufReader::new(File::open(&replay.corpus)?))?;
    if source.net() != replay.chain {
        return Err(format!(
            "the corpus is tagged {:?} but --chain says {:?}",
            source.net(),
            replay.chain
        )
        .into());
    }
    let store = ChainStore::create(&replay.store, epoch)?;
    let metrics = Arc::new(Metrics::new());
    let substrate = Arc::new(ProductionSubstrate::new(
        Arc::new(CacheStore::new()),
        Arc::clone(&metrics),
    ));
    let outcome = run(
        &mut source,
        substrate,
        Arc::clone(&metrics),
        replay.rules,
        store,
        trace,
        replay.cfg,
    )
    .await;

    // The measurement is written whether or not the run finished.
    let measured = metrics.snapshot();
    eprintln!(
        "randomx light mode: {} hash(es), mean {:?} ns; {} derive(s), mean {:?} ns; {} block(s) formed, mean {:?} ns; {:?}",
        measured.hashes,
        measured.hash_ns_mean,
        measured.cache_derives,
        measured.derive_ns_mean,
        measured.blocks_formed,
        measured.form_ns_mean,
        measured.concurrency,
    );
    if let Some(out) = &replay.metrics_out {
        std::fs::write(out, measured.to_json()?)?;
        eprintln!("metrics artifact → {}", out.display());
    }
    let report = outcome?;

    eprintln!(
        "connected {} block(s), popped {}, {} checkpoint digested",
        report.connected.len(),
        report.popped(),
        usize::from(report.checkpoint.is_some()),
    );
    for disagreement in report.disagreements() {
        match disagreement {
            Disagreement::Refused { height, verdict } => {
                eprintln!("refused at height {height}: {verdict:?}");
            }
            Disagreement::Diverged { at } => {
                eprintln!("checkpoint after height {at}: digest DIVERGE");
            }
        }
    }
    if let Some(checkpoint) = &report.checkpoint {
        if checkpoint.identical() {
            eprintln!("checkpoint after height {}: digest MATCH", checkpoint.at);
        }
    }

    match register {
        Some(register) => grade(&register, &report, replay.grade_out.as_deref()),
        None => ungraded(&report),
    }
}

/// Graded: the register adjudicates, and the grade decides.
fn grade(
    register: &Register,
    report: &RunReport,
    grade_out: Option<&std::path::Path>,
) -> Result<(), Failure> {
    let graded = grade_run(register, &report.observations());
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
        std::fs::write(out, graded.to_json()?)?;
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
    Ok(())
}

/// Ungraded: nothing adjudicates, so any disagreement is open.
fn ungraded(report: &RunReport) -> Result<(), Failure> {
    let open = report.disagreements().count();
    if open > 0 {
        return Err(
            format!("{open} disagreement(s) and no --register to adjudicate them (§1.3)").into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use shekyl_address::Network;
    use shekyl_chain_ingest::schedule::Chain;

    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from([&["shekyl-chain-replay"], args].concat())
    }

    #[test]
    fn fixed_difficulty_parses_and_the_chain_flag_is_the_corpus_tag() {
        let cli = parse(&[
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
            window,
            hashers,
            ..
        } = cli.command
        else {
            panic!("replay");
        };
        assert_eq!(chain, CorpusNet::Fakechain, "--chain regtest is the tag");
        assert_eq!(Chain::from(chain), Chain::Regtest);
        assert_eq!(fixed_difficulty, NonZeroU128::new(7));
        assert_eq!(window, PipelineConfig::DEFAULT_WINDOW);
        assert_eq!(hashers, PipelineConfig::default_hashers());
        // Zero is not a difficulty, a window, a hasher count or a batch:
        // the types refuse each at parse time.
        for (flag, value) in [
            ("--fixed-difficulty", "0"),
            ("--window", "0"),
            ("--hashers", "0"),
        ] {
            assert!(
                parse(&[
                    "replay", "--corpus", "c", "--trace", "t", "--store", "s", "--chain",
                    "regtest", flag, value,
                ])
                .is_err(),
                "{flag} {value}"
            );
        }
        assert!(parse(&[
            "fetch", "--daemon", "d", "--chain", "testnet", "--to", "3", "--out", "o", "--batch",
            "0",
        ])
        .is_err());
        assert!(
            parse(&[
                "fetch",
                "--daemon",
                "d",
                "--chain",
                "fakechain",
                "--to",
                "3",
                "--out",
                "o"
            ])
            .is_err(),
            "the flag spells the daemon's word, not the tag's"
        );
    }

    #[test]
    fn the_flag_off_regtest_is_refused_where_the_rules_are_built() {
        let refused = ChainRules::new(Chain::Public(Network::Testnet), NonZeroU128::new(7));
        assert!(refused.is_err());
        let ok = ChainRules::new(Chain::Regtest, NonZeroU128::new(7)).expect("regtest");
        assert_eq!(
            ok.in_force(BlockHeight::from_raw(3)),
            shekyl_chain_rules::RuleSet::fakechain(NonZeroU128::new(7), shekyl_chain_rules::D_MAX)
        );
    }

    #[test]
    fn an_unparseable_register_is_refused_before_anything_runs() {
        let dir =
            std::env::temp_dir().join(format!("shekyl-replay-preflight-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let register = dir.join("register.json");
        std::fs::write(&register, "{\"schema_version\": \"nope\"}").expect("write");
        assert!(register_first(Some(&register)).is_err());
        assert!(register_first(None).expect("absent is fine").is_none());
        let _gone = std::fs::remove_dir_all(&dir);
    }
}
