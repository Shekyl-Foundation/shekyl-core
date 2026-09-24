// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The captured chains replay — the real-chain witness for the validator's
//! verification-era rows (`CHAIN_RULES_SLICE_6.md` §5.2; `50-testing.mdc`,
//! *a fixture that constructs the state a rule reads back is not a test of
//! the rule*).
//!
//! Each directory under `tests/vectors/` is one regtest chain a live
//! `shekyld` built and accepted, captured whole as the DRS-E2 replay pair
//! by `engine::regtest_e2e::maybe_capture_chain_vector`: `corpus.e2` (every
//! block and every listed transaction's **full** bytes, RD-F15-verified
//! against the headers) and `trace.e2` (the passed-through facts and the
//! daemon's logical-state digest at the tip). These tests connect every
//! chain through `form → validate → connect` against a **real** `redb`
//! store — the same `pipeline::run` the replay binary composes — and hold
//! the store's digest to the daemon's. The spent set, the reference
//! heights, `height_of` are derived by the code that derives them in
//! production; nothing is served to a rule as given.
//!
//! **What the substrate is here, said plainly.** The default lane runs the
//! chains under `MockSubstrate` — the always-satisfying longhash — because
//! RandomX light mode costs ~0.6 s a block and the depth-3 chain is ~750
//! blocks. That mocks exactly one thing: CEN-D2's hash. D1/D2 are **not**
//! this test's subject and are not witnessed by it; their real-substrate
//! witness is `replays_every_captured_chain_under_the_production_substrate`
//! below, `#[ignore]`d for the live lane, and E2's own replay gate. Every
//! other row a captured chain exercises — the whole of 4.A–4.H and, as
//! they land, 4.I — is judged against real state under both.
//!
//! A chain that fails to replay is a **finding**, never a fixture error:
//! either the daemon that built it and this validator disagree (E2's
//! subject — grade it), or a rule landed that the chain's real spend now
//! trips (the cascade slice 5 §5.1 named — the fixture was right; the
//! rule is what moved).

use std::num::{NonZeroU128, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use shekyl_chain_rules::harness::MockSubstrate;
use shekyl_chain_rules::Substrate;

use crate::corpus::CorpusReader;
use crate::metrics::Metrics;
use crate::pipeline::{run, PipelineConfig, RunReport};
use crate::schedule::ChainRules;
use crate::substrate::ProductionSubstrate;
use crate::test_support::{cleanup, open_store, tmp};
use crate::trace::Trace;
use shekyl_pow_randomx::CacheStore;

/// `manifest.json`, as the capture writes it (format 2).
#[derive(Deserialize, Debug)]
struct Manifest {
    format_version: u32,
    shape: String,
    generator: String,
    tip_height: u64,
    block_count: u64,
    spend_txid: Option<String>,
    fixed_difficulty: u128,
}

/// Every captured chain, in name order. **Fails on an empty set** (rule
/// 47): a directory that vanished, or a rename that no longer matches,
/// must not read as "every chain replays".
fn captured_chains() -> Vec<(PathBuf, Manifest)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    let mut found: Vec<(PathBuf, Manifest)> = std::fs::read_dir(&root)
        .unwrap_or_else(|e| panic!("tests/vectors/ must exist: {e}"))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|p| p.join("manifest.json").is_file())
        .map(|p| {
            let text = std::fs::read_to_string(p.join("manifest.json")).expect("read manifest");
            let manifest: Manifest = serde_json::from_str(&text)
                .unwrap_or_else(|e| panic!("{}: manifest does not parse: {e}", p.display()));
            assert_eq!(
                manifest.format_version,
                2,
                "{}: capture format {} is not the one this test reads",
                p.display(),
                manifest.format_version
            );
            (p, manifest)
        })
        .collect();
    found.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(
        !found.is_empty(),
        "no captured chains under {} — the witness has no subject",
        root.display()
    );
    found
}

/// Replay one captured chain through the production pipeline against a
/// fresh store; return the report.
async fn replay<S>(dir: &Path, manifest: &Manifest, substrate: Arc<S>) -> RunReport
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: Send + std::fmt::Debug + 'static,
{
    let corpus = std::fs::read(dir.join("corpus.e2")).expect("read corpus.e2");
    let trace = std::fs::read(dir.join("trace.e2")).expect("read trace.e2");
    let mut source =
        CorpusReader::open(std::io::Cursor::new(corpus.as_slice())).expect("open corpus");
    let trace = Arc::new(Trace::read(std::io::Cursor::new(trace.as_slice())).expect("read trace"));
    let rules = ChainRules::Regtest {
        fixed_difficulty: Some(
            NonZeroU128::new(manifest.fixed_difficulty).expect("a regtest difficulty is non-zero"),
        ),
    };
    let path = tmp(&format!("vectors-{}", manifest.shape));
    let report = run(
        &mut source,
        substrate,
        Arc::new(Metrics::new()),
        rules,
        open_store(&path),
        trace,
        PipelineConfig {
            window: NonZeroUsize::new(64).expect("non-zero"),
            hashers: NonZeroUsize::new(4).expect("non-zero"),
        },
    )
    .await
    .unwrap_or_else(|e| panic!("{}: the captured chain must replay: {e:?}", manifest.shape));
    cleanup(&path);
    report
}

/// What every replay must show, whichever substrate judged the hashes.
fn hold(dir: &Path, manifest: &Manifest, report: &RunReport) {
    assert!(
        report.refused.is_none(),
        "{} ({}): the daemon accepted every block of this chain and the validator refused one — \
         {:?}. A finding: either E2's subject (the two disagree; grade it) or a rule landed \
         that the chain's real spend trips (slice 5 §5.1's cascade — the rule moved, not the \
         fixture)",
        manifest.shape,
        manifest.generator,
        report.refused
    );
    assert_eq!(
        report.connected.len() as u64,
        manifest.block_count,
        "{}: connected {} of {} blocks (tip {}) — {}",
        manifest.shape,
        report.connected.len(),
        manifest.block_count,
        manifest.tip_height,
        dir.display()
    );
    let checkpoint = report.checkpoint.as_ref().unwrap_or_else(|| {
        panic!(
            "{}: the trace carries the daemon's digest at the tip",
            manifest.shape
        )
    });
    assert!(
        checkpoint.identical(),
        "{}: the store's logical state after height {} differs from the daemon's — DIVERGE, \
         ours {:?} theirs {:?}",
        manifest.shape,
        checkpoint.at,
        checkpoint.ours,
        checkpoint.theirs
    );
    if let Some(txid) = &manifest.spend_txid {
        assert_eq!(
            txid.len(),
            64,
            "{}: spend_txid is a 32-byte hex hash",
            manifest.shape
        );
    }
}

/// Every captured chain connects whole against a real store and matches the
/// daemon's digest at its tip — under the mock longhash (D2 is not this
/// test's subject; see the module doc).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_captured_chain_replays_and_matches_the_daemons_digest() {
    // The mock's default clock is 2023 (`MockSubstrate::CLOCK`, chosen for
    // hand-built fixture headers); these blocks were mined in 2026, and
    // CEN-C1 refused block 1 as future-dated the first time this ran. The
    // clock here is the REAL one — only the hash is mocked, and the doc
    // above says so.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_secs();
    let substrate = Arc::new(MockSubstrate {
        clock: shekyl_types::Timestamp::from_raw(now),
        longhash: MockSubstrate::always_satisfies,
    });
    for (dir, manifest) in captured_chains() {
        let report = replay(&dir, &manifest, Arc::clone(&substrate)).await;
        hold(&dir, &manifest, &report);
        eprintln!(
            "{}: {} blocks connected, digest MATCH at {}, rows exercised: {}",
            manifest.shape,
            report.connected.len(),
            manifest.tip_height,
            report.exercised.len()
        );
    }
}

/// The same, with RandomX judging every block — the D1/D2 witness. Slow
/// (~0.6 s a block in light mode; the depth-3 chain alone is minutes), so
/// it runs in the live lane, not on every `cargo test`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real RandomX over every captured chain; minutes. Run in the live lane: cargo test -p shekyl-chain-ingest --features pipeline -- --ignored replays_every_captured_chain_under_the_production_substrate"]
async fn replays_every_captured_chain_under_the_production_substrate() {
    let metrics = Arc::new(Metrics::new());
    let substrate = Arc::new(ProductionSubstrate::new(
        Arc::new(CacheStore::new()),
        Arc::clone(&metrics),
    ));
    for (dir, manifest) in captured_chains() {
        let report = replay(&dir, &manifest, substrate.clone()).await;
        hold(&dir, &manifest, &report);
    }
}
