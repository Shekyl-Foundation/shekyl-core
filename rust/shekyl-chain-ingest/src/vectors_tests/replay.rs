// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Replay a captured chain and keep the store.
//!
//! [`super::replay_under`] drops the store after the report. The relay-floor
//! witness reads the connected chain, so it needs the store, the path and
//! the rules the run judged under.

#![cfg(test)]

use std::num::{NonZeroU128, NonZeroUsize};
use std::path::PathBuf;
use std::sync::Arc;

use shekyl_chain_rules::{FakechainSchedule, SettlementEpochBlocks, Substrate};
use shekyl_chain_store::apply_policy::ApplyPolicy;
use shekyl_types::{BlockCount, BlockHeight};

use crate::corpus::CorpusReader;
use crate::metrics::Metrics;
use crate::pipeline::{run, PipelineConfig, RunReport};
use crate::schedule::ChainRules;
use crate::test_support::{open_store_under, tmp};
use crate::trace::Trace;

use super::{Manifest, UntilRetiredJoin};

/// [`super::replay_under`] without the cleanup: the replayed store stays at
/// the returned path, under the returned rules, for a test that reads the
/// chain the run connected. The caller removes it. `tag` names the store's
/// path: tests run concurrently in one process, so two replays of one
/// shape must not share a path.
pub(crate) async fn replay_keeping_store<S>(
    dir: &std::path::Path,
    manifest: &Manifest,
    substrate: Arc<S>,
    policy: ApplyPolicy,
    tag: &str,
) -> (Result<RunReport, String>, PathBuf, ChainRules)
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: Send + std::fmt::Debug + 'static,
{
    let corpus = std::fs::read(dir.join("corpus.e2")).expect("read corpus.e2");
    let trace = std::fs::read(dir.join("trace.e2")).expect("read trace.e2");
    let mut source = UntilRetiredJoin::new(
        CorpusReader::open(std::io::Cursor::new(corpus.as_slice())).expect("open corpus"),
    );
    let trace = Arc::new(Trace::read(std::io::Cursor::new(trace.as_slice())).expect("read trace"));
    let schedule = FakechainSchedule::new(
        SettlementEpochBlocks::new(manifest.settlement_epoch_blocks)
            .expect("a captured chain's epoch is non-zero"),
        BlockCount::from_raw(manifest.reorg_cap_blocks),
    )
    .unwrap_or_else(|e| {
        panic!(
            "{}: the manifest's pair is not a schedule: {e}",
            manifest.shape
        )
    });
    let rules = ChainRules::Regtest {
        fixed_difficulty: Some(
            NonZeroU128::new(manifest.fixed_difficulty).expect("a regtest difficulty is non-zero"),
        ),
        schedule,
    };
    let path = tmp(&format!("vectors-{}-{tag}", manifest.shape));
    // The store runs the pair the chain was mined under, read off the same
    // rule set `connect` judges by — not the production epoch the other
    // tests' stores pin, which `connect` would refuse at block 0.
    let store = open_store_under(&path, &rules.in_force(BlockHeight::from_raw(0)), policy);
    let report = run(
        &mut source,
        substrate,
        Arc::new(Metrics::new()),
        rules,
        store,
        trace,
        PipelineConfig {
            window: NonZeroUsize::new(64).expect("non-zero"),
            hashers: NonZeroUsize::new(4).expect("non-zero"),
        },
    )
    .await
    .map_err(|e| format!("{e:?}"));
    if report.is_ok() {
        source.finish(&manifest.shape);
    }
    (report, path, rules)
}
