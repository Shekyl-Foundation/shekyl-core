// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! An emission claim's block connected (`BENCHMARK_ALIGNMENT.md` BA-T2's
//! emission-claim shape, counted as BA-T41's connect row counts a block).
//!
//! A claim's own verification, its backing proof and its two signatures, is
//! `validate`'s, not `form`'s, and it needs a store holding a settled epoch:
//! a chain through a closed shard, a join, a served epoch and its slash
//! pass. No committed fixture holds one. The row starts from Chain L's
//! `first-settled-epoch` snapshot (`CHAIN_FORGE.md` §8, `CF-4b`): the store a
//! production replay of the pinned chain left at height 1,799, opened as a
//! copy and refused if a byte moved. The subject is the block the corpus
//! writes next, Chain L's first emission claim, at height 1,800.
//!
//! Setup never replays. It opens the snapshot the cache already holds, which
//! `chain_l::the_first_settled_epoch_snapshot_builds_and_opens` (`shekyl-chain-ingest`,
//! ignored) builds; `nightly.yml`'s `bench-full` runs that step first. It
//! then judges the subject once and discards the batch, so the count reads
//! the drawable memo a running node holds, as the fixture rows' history
//! leaves it (`BlockPath::rehearse`).
//!
//! The nightly capture's (`NIGHTLY_BENCHES`): the snapshot is a 34 MB store
//! and Chain L is fetched by its pin, which a pull request's capture does
//! not do.

use std::hint::black_box;
use std::path::{Path, PathBuf};

use gungraun::{library_benchmark, library_benchmark_group, main};
use shekyl_chain_forge::hosted;
use shekyl_chain_ingest::bench_support::{BlockPath, Claimed};
use shekyl_chain_ingest::snapshot::{
    cache_root, extend_at, forged_rules, open_copy, sealed, ChainFiles, SnapshotKey,
};
use shekyl_chain_ingest::source::SequenceNo;
use shekyl_chain_rules::StructurallyValid;

/// The snapshot the row starts from.
const SNAPSHOT_EVENT: &str = "first-settled-epoch";
/// The event the subject block carries.
const SUBJECT_EVENT: &str = "first-claim";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Chain L at its first settled epoch, and the claim's block formed.
fn before_connect_claim() -> (BlockPath, StructurallyValid, Claimed) {
    let fetched = hosted::open("chain-l").unwrap_or_else(|fault| panic!("{fault}"));
    let manifest = fetched.manifest().unwrap_or_else(|fault| panic!("{fault}"));
    let record = |event: &str| {
        SequenceNo::from_raw(
            manifest
                .events
                .iter()
                .find(|named| named.name == event)
                .unwrap_or_else(|| panic!("Chain L's manifest records no `{event}`"))
                .record,
        )
    };
    let (at, subject_at) = (record(SNAPSHOT_EVENT), record(SUBJECT_EVENT));
    assert_eq!(
        subject_at.to_raw(),
        at.to_raw() + 1,
        "the claim is the record after the snapshot"
    );
    let rules = forged_rules(
        manifest.schedule.settlement_epoch_blocks,
        manifest.schedule.reorg_cap_blocks,
    );
    let (corpus, trace) = (fetched.corpus(), fetched.trace());
    let expected = ChainFiles {
        corpus: &corpus,
        trace: &trace,
        record: at,
        rules,
    }
    .expected_digest()
    .unwrap_or_else(|fault| panic!("the `{SNAPSHOT_EVENT}` snapshot: {fault}"));
    let key = SnapshotKey::at(&fetched.pin().digest, SNAPSHOT_EVENT, &repo_root())
        .unwrap_or_else(|fault| panic!("the consensus trees: {fault}"));
    let dir = sealed(&cache_root(), &key).unwrap_or_else(|| {
        panic!(
            "no `{}` snapshot in the cache: build it first with \
             `cargo test --release -p shekyl-chain-ingest --lib -- --ignored --exact \
             chain_l::the_first_settled_epoch_snapshot_builds_and_opens`",
            key.name()
        )
    });
    let mut chain = BlockPath::resumed(
        |to| {
            open_copy(&dir, &key, &expected, &rules, to)
                .unwrap_or_else(|fault| panic!("the `{SNAPSHOT_EVENT}` snapshot: {fault}"));
        },
        rules,
    );
    let subject = extend_at(&corpus, subject_at);
    assert_eq!(
        subject.block.header.previous,
        *chain.hashes().last().expect("the snapshot holds a chain"),
        "the claim's block extends the snapshot's tip"
    );
    let claimed = chain.claims(&subject);
    chain.rehearse(&subject, &claimed);
    let formed = chain.form(subject, &claimed);
    (chain, formed, claimed)
}

#[library_benchmark]
#[bench::first_claim(setup = before_connect_claim)]
fn crypto_bench_block_connect_emission_claim(
    (mut chain, formed, claimed): (BlockPath, StructurallyValid, Claimed),
) -> (BlockPath, Claimed) {
    chain.connect(black_box(formed), &claimed);
    (chain, claimed)
}

library_benchmark_group!(
    name = emission_claim_group;
    benchmarks = crypto_bench_block_connect_emission_claim
);

main!(library_benchmark_groups = emission_claim_group);
