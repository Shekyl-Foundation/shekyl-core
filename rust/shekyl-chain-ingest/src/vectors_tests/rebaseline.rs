// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The re-baseline's own witness: a captured chain replayed against the
//! trace [`crate::rebaseline::trace_of`] writes from a replay of the same
//! chain compares at every height and at the checkpoint, and agrees.

use std::num::NonZeroUsize;
use std::sync::Arc;

use shekyl_chain_store::apply_policy::ApplyPolicy;
use shekyl_types::BlockHeight;

use super::replay::rules_for;
use super::retired_keyless_join::UntilRetiredJoin;
use super::{captured_chains, mock_with_the_real_clock};
use crate::corpus::CorpusReader;
use crate::metrics::Metrics;
use crate::pipeline::{run, PipelineConfig, RunReport};
use crate::rebaseline::trace_of;
use crate::test_support::{cleanup, open_store_under, tmp};
use crate::trace::Trace;

async fn replay_against(
    corpus: &[u8],
    manifest: &super::Manifest,
    trace: Trace,
    tag: &str,
) -> (RunReport, std::path::PathBuf) {
    let rules = rules_for(manifest);
    let path = tmp(&format!("rebaseline-{}-{tag}", manifest.shape));
    let store = open_store_under(
        &path,
        &rules.in_force(BlockHeight::from_raw(0)),
        ApplyPolicy::Full,
    );
    let mut source = UntilRetiredJoin::new(
        CorpusReader::open(std::io::Cursor::new(corpus)).expect("open corpus"),
    );
    let report = run(
        &mut source,
        mock_with_the_real_clock(),
        Arc::new(Metrics::new()),
        rules,
        store,
        Arc::new(trace),
        PipelineConfig {
            window: NonZeroUsize::new(64).expect("non-zero"),
            hashers: NonZeroUsize::new(4).expect("non-zero"),
        },
    )
    .await
    .expect("the captured chain replays");
    (report, path)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chain_replays_against_its_own_rust_baseline() {
    let (dir, manifest) = captured_chains()
        .into_iter()
        .find(|(_, m)| m.shape == "spend-1in-2out")
        .expect("the spend-1in-2out chain is captured");
    let corpus = std::fs::read(dir.join("corpus.e2")).expect("read corpus.e2");

    // The baseline: nothing compared, then the store written out.
    let (first, path) = replay_against(&corpus, &manifest, Trace::empty(), "write").await;
    assert!(
        first.refused.is_none(),
        "the chain connects whole: {:?}",
        first.refused
    );
    assert_eq!(first.roots.compared(), 0, "an empty trace compares nothing");
    let store = shekyl_chain_store::store::ChainStore::open_read_only(
        &path,
        shekyl_chain_store::store::Horizons::under(
            &rules_for(&manifest).in_force(BlockHeight::from_raw(0)),
        )
        .expect("horizons"),
    )
    .expect("reopen");
    let bytes = trace_of(&store.begin_read().expect("read"), Vec::new()).expect("trace");
    drop(store);
    cleanup(&path);
    let trace =
        Trace::read(std::io::Cursor::new(bytes.as_slice())).expect("the baseline reads back");

    // The replay against it: every height compared, every oracle agrees.
    let (second, path) = replay_against(&corpus, &manifest, trace, "check").await;
    cleanup(&path);
    let connected = u64::try_from(second.connected.len()).expect("small");
    assert_eq!(connected, manifest.block_count, "the whole chain connects");
    assert_eq!(
        second.roots.compared(),
        connected,
        "a root compared at every height"
    );
    assert_eq!(
        second.weights.compared(),
        connected,
        "weights compared at every height"
    );
    assert_eq!(
        second.emission.compared(),
        connected,
        "emission compared at every height"
    );
    let checkpoint = second
        .checkpoint
        .as_ref()
        .expect("the checkpoint was compared");
    assert!(checkpoint.identical(), "the digest reproduces");
    let archival = second
        .archival
        .as_ref()
        .expect("the archival rows were compared");
    assert!(archival.identical(), "the archival rows reproduce");
    assert_eq!(
        second.disagreements().count(),
        0,
        "no disagreement anywhere"
    );
}
