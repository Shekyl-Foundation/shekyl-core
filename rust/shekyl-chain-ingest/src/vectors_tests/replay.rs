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

use std::num::NonZeroU128;
use std::path::PathBuf;
use std::sync::Arc;

use shekyl_chain_rules::{FakechainSchedule, SettlementEpochBlocks, Substrate};
use shekyl_chain_store::apply_policy::ApplyPolicy;
use shekyl_types::{BlockCount, BlockHeight};

use crate::corpus::CorpusReader;
use crate::metrics::Metrics;
use crate::pipeline::{run, PipelineConfig, RunReport};
use crate::schedule::ChainRules;
use crate::source::Source;
use crate::test_support::{open_store_under, tmp};
use crate::trace::Trace;

use super::{Manifest, UntilRetiredJoin};

/// Hasher count the captured-chain tests pin, so one chain is the same run
/// on every host. The host's parallelism would make the width, and the
/// metrics, a property of the machine (rule 76).
pub(crate) const CAPTURED_REPLAY_HASHERS: std::num::NonZeroUsize =
    match std::num::NonZeroUsize::new(4) {
        Some(n) => n,
        None => unreachable!(),
    };

/// The rule set the daemon mined `manifest` under: fixed difficulty and
/// the `(SEB, cap)` pair the manifest records.
pub(crate) fn rules_for(manifest: &Manifest) -> ChainRules {
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
    ChainRules::Regtest {
        fixed_difficulty: Some(
            NonZeroU128::new(manifest.fixed_difficulty).expect("a regtest difficulty is non-zero"),
        ),
        schedule,
    }
}

/// Replay `source` against `trace` and keep the store and the source.
///
/// The store stays at the returned path, under the returned rules, for a
/// test that reads the chain the run connected. The caller removes it.
/// `tag` names the store's path: tests run concurrently in one process, so
/// two replays of one shape must not share a path. The source comes back so
/// a wrapper that still has to `finish` it — [`UntilRetiredJoin`] is not
/// part of [`Source`] — can.
pub(crate) async fn replay_open<S, Src>(
    manifest: &Manifest,
    substrate: Arc<S>,
    policy: ApplyPolicy,
    tag: &str,
    mut source: Src,
    trace: Arc<Trace>,
) -> (Result<RunReport, String>, PathBuf, ChainRules, Src)
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: Send + std::fmt::Debug + 'static,
    Src: Source,
    Src::Fault: std::fmt::Debug,
{
    let rules = rules_for(manifest);
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
            window: PipelineConfig::DEFAULT_WINDOW,
            hashers: CAPTURED_REPLAY_HASHERS,
            digest_each_commit: false,
        },
    )
    .await
    .map_err(|e| format!("{e:?}"));
    (report, path, rules, source)
}

/// [`super::replay_under`] without the cleanup: the committed corpus and
/// its committed trace, read up to a retired keyless join.
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
    let source = UntilRetiredJoin::new(
        CorpusReader::open(std::io::Cursor::new(corpus.as_slice())).expect("open corpus"),
    );
    let trace = Arc::new(Trace::read(std::io::Cursor::new(trace.as_slice())).expect("read trace"));
    let (report, path, rules, source) =
        replay_open(manifest, substrate, policy, tag, source, trace).await;
    if report.is_ok() {
        source.finish(&manifest.shape);
    }
    (report, path, rules)
}
