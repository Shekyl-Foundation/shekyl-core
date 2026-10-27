// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-H19's verification cost on the Rust path, at the captured chains'
//! own densities.
//!
//! A measurement, not a gate: wall time on a shared box (rule 76 — shape
//! data, not a floor). Run in release:
//! `cargo test --release -p shekyl-chain-ingest --features pipeline --lib
//! h19_batch_cost_at_the_captured_densities -- --ignored --nocapture`.

// Test-only by its parent (`vectors_tests`, gated at `lib.rs`). The inner
// attribute is this file's own declaration of that fact, for the
// debug-macro lint (`build.yml`), which scans each file for its own
// marker. The lines it prints are the measurement's report, not
// production output.
#![cfg(test)]

use std::time::Instant;

use shekyl_chain_rules::{BatchOutcome, ListedProofs};

use super::{captured_chains, retired_keyless_join};
use crate::corpus::CorpusReader;
use crate::source::{IngestEvent, Source};

/// Odd, so the middle sample of a sorted run is the median.
const SAMPLES: usize = 7;

/// Every block's proofs assembled by [`ListedProofs`] — the fold's own
/// list, not a second walk — and timed at [`ListedProofs::batch_outcome`].
/// Prints, per chain, how many blocks carry proofs, how many proofs and
/// commitments each such block holds, and the batch's median and worst
/// wall time. Also asserts every captured block's batch verifies: a
/// C++-accepted proof the Rust verifier refused would be an E2 finding.
///
/// The timer includes the seed's cSHAKE and the entry slice the batch
/// borrows. Reassembly from the wire stays outside it.
#[test]
#[ignore = "a measurement; run by nightly.yml's chain-ingest-ignored job"]
fn h19_batch_cost_at_the_captured_densities() {
    for (dir, manifest) in captured_chains() {
        let corpus = std::fs::read(dir.join("corpus.e2")).expect("read corpus");
        let mut reader =
            CorpusReader::open(std::io::Cursor::new(corpus.as_slice())).expect("open corpus");
        let (mut blocks, mut proofs_per_block, mut commitments, mut times) =
            (0usize, Vec::new(), Vec::new(), Vec::new());
        // A chain carrying a retired keyless JoinMarket is read up to it, as
        // the replay reads it (`retired_keyless_join`).
        let stop = retired_keyless_join(&manifest.shape).map(|r| r.at);
        loop {
            let sequenced = match reader.next() {
                Ok(Some(sequenced)) => sequenced,
                Ok(None) => break,
                Err(fault) if stop.is_some() => {
                    println!("h19-cost {}: read up to {stop:?} ({fault})", manifest.shape);
                    break;
                }
                Err(fault) => panic!("read the corpus: {fault}"),
            };
            let IngestEvent::Extend(candidate) = sequenced.event else {
                continue;
            };
            blocks += 1;
            let listed = ListedProofs::assemble(&candidate)
                .expect("a captured block assembles: one proof per transaction");
            if listed.is_empty() {
                continue;
            }
            let mut runs: Vec<u128> = (0..SAMPLES)
                .map(|_| {
                    let started = Instant::now();
                    assert_eq!(
                        listed.batch_outcome(),
                        BatchOutcome::Verified,
                        "a captured block's batch verifies"
                    );
                    started.elapsed().as_micros()
                })
                .collect();
            runs.sort_unstable();
            times.push(runs[SAMPLES / 2]);
            proofs_per_block.push(listed.len());
            commitments.extend(listed.commitment_counts());
        }
        times.sort_unstable();
        let median = times.get(times.len() / 2).copied().unwrap_or(0);
        let worst = times.last().copied().unwrap_or(0);
        let total: u128 = times.iter().sum();
        println!(
            "h19-cost {}: {blocks} blocks, {} carry proofs (proofs/block max {}), commitments/proof {:?}; \
             batch per proof-carrying block median {median} µs, max {worst} µs; \
             whole chain {total} µs = {} µs/block",
            manifest.shape,
            times.len(),
            proofs_per_block.iter().max().copied().unwrap_or(0),
            {
                let mut counts = commitments.clone();
                counts.sort_unstable();
                counts.dedup();
                counts
            },
            total / u128::try_from(blocks.max(1)).expect("fits"),
        );
    }
}
