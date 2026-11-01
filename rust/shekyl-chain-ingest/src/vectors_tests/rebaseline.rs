// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The re-baseline's own witness: every captured chain that reads whole,
//! replayed against the trace [`crate::rebaseline::trace_of`] writes from a
//! replay of the same chain, compares at every height and at the checkpoint,
//! and agrees. `spend-1in-2out` alone would leave an empty archival snapshot
//! compared with itself; `bond-post` is the chain whose snapshot is not.

use std::sync::Arc;

use shekyl_chain_store::apply_policy::ApplyPolicy;
use shekyl_chain_store::store::{ChainStore, Horizons};
use shekyl_types::BlockHeight;

use super::replay::replay_open;
use super::retired_keyless_join::UntilRetiredJoin;
use super::{
    captured_chains, mock_with_the_real_clock, retired_keyless_join, Manifest,
    RETIRED_KEYLESS_JOINS,
};
use crate::corpus::CorpusReader;
use crate::pipeline::RunReport;
use crate::rebaseline::trace_of;
use crate::test_support::cleanup;
use crate::trace::Trace;

/// The chains a replay reads to the tip: every capture whose retired-join
/// record is absent. The set is asserted, not discovered (rule 47).
fn chains_read_whole() -> Vec<(std::path::PathBuf, Manifest)> {
    let captured = captured_chains();
    let captured_len = captured.len();
    let whole: Vec<_> = captured
        .into_iter()
        .filter(|(_, manifest)| retired_keyless_join(&manifest.shape).is_none())
        .collect();
    assert!(
        !whole.is_empty(),
        "a chain read whole is the subject of the round-trip"
    );
    assert!(
        whole
            .iter()
            .any(|(_, manifest)| manifest.shape == "bond-post"),
        "bond-post reads whole: its JoinMarket carries a key"
    );
    assert_eq!(
        whole.len() + RETIRED_KEYLESS_JOINS.len(),
        captured_len,
        "every captured chain is either read whole or named in RETIRED_KEYLESS_JOINS"
    );
    whole
}

async fn replay_corpus(
    corpus: &[u8],
    manifest: &Manifest,
    trace: Trace,
    tag: &str,
) -> (RunReport, std::path::PathBuf) {
    let source = UntilRetiredJoin::new(
        CorpusReader::open(std::io::Cursor::new(corpus)).expect("open corpus"),
    );
    let (report, path, _rules, source) = replay_open(
        manifest,
        mock_with_the_real_clock(),
        ApplyPolicy::Full,
        tag,
        source,
        Arc::new(trace),
    )
    .await;
    let report = report.expect("the captured chain replays");
    source.finish(&manifest.shape);
    (report, path)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chain_replays_against_its_own_rust_baseline() {
    for (dir, manifest) in chains_read_whole() {
        let corpus = std::fs::read(dir.join("corpus.e2")).expect("read corpus.e2");

        // The baseline: nothing compared, then the store written out.
        let (first, path) = replay_corpus(&corpus, &manifest, Trace::empty(), "write").await;
        assert!(
            first.refused.is_none(),
            "{}: the chain connects whole: {:?}",
            manifest.shape,
            first.refused
        );
        assert_eq!(
            first.roots.compared(),
            0,
            "{}: an empty trace compares nothing",
            manifest.shape
        );
        let store = ChainStore::open_read_only(
            &path,
            Horizons::under(
                &super::replay::rules_for(&manifest).in_force(BlockHeight::from_raw(0)),
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
        let (second, path) = replay_corpus(&corpus, &manifest, trace, "check").await;
        cleanup(&path);
        let connected = u64::try_from(second.connected.len()).expect("small");
        assert_eq!(
            connected, manifest.block_count,
            "{}: the whole chain connects",
            manifest.shape
        );
        assert_eq!(
            second.roots.compared(),
            connected,
            "{}: a root compared at every height",
            manifest.shape
        );
        assert_eq!(
            second.weights.compared(),
            connected,
            "{}: weights compared at every height",
            manifest.shape
        );
        assert_eq!(
            second.emission.compared(),
            connected,
            "{}: emission compared at every height",
            manifest.shape
        );
        let checkpoint = second
            .checkpoint
            .as_ref()
            .unwrap_or_else(|| panic!("{}: the checkpoint was compared", manifest.shape));
        assert!(
            checkpoint.identical(),
            "{}: the digest reproduces",
            manifest.shape
        );
        let archival = second
            .archival
            .as_ref()
            .unwrap_or_else(|| panic!("{}: the archival rows were compared", manifest.shape));
        assert!(
            archival.identical(),
            "{}: the archival rows reproduce",
            manifest.shape
        );
        assert_eq!(
            second.disagreements().count(),
            0,
            "{}: no disagreement anywhere",
            manifest.shape
        );
    }
}
