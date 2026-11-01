// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-I4 on a captured regtest chain, under that chain's own rules.
//!
//! The input cap binds every network (rule 71; `CHAIN_RULES_SLICE_6.md`
//! §5.4). The mutation family's harness chain judges `TooManyInputs` under
//! the genesis rules, which an exemption keyed on the test networks would
//! not reach. This test applies the same mutation to the captured
//! `spend-1in-2out` chain — a regtest chain, replayed under its own
//! `FakechainSchedule` — so an exemption restored for the test networks
//! refuses on a later row here and fails.

use std::path::Path;
use std::sync::Arc;

use shekyl_chain_rules::CenRow;
use shekyl_chain_store::apply_policy::ApplyPolicy;
use shekyl_types::{BlockCount, BlockHeight};
use shekyl_wire::Input;

use super::replay::replay_open;
use super::retired_keyless_join::UntilRetiredJoin;
use super::{captured_chains, mock_with_the_real_clock};
use crate::corpus::CorpusReader;
use crate::mutation::{Environment, Mutated, Mutation};
use crate::source::{IngestEvent, Source};
use crate::test_support::cleanup;
use crate::trace::Trace;

/// The height of the first block in `dir`'s corpus that lists a spend.
fn first_spend_height(dir: &Path) -> BlockHeight {
    let corpus = std::fs::read(dir.join("corpus.e2")).expect("read corpus.e2");
    let mut reader =
        CorpusReader::open(std::io::Cursor::new(corpus.as_slice())).expect("open corpus");
    let mut height = reader.first_height();
    while let Some(event) = reader.next().expect("corpus reads") {
        if let IngestEvent::Extend(candidate) = event.event {
            let spends = candidate.transactions.iter().any(|tx| {
                tx.prefix
                    .inputs
                    .iter()
                    .any(|input| matches!(input, Input::ToKey { .. }))
            });
            if spends {
                return height;
            }
            height = height
                .checked_add(BlockCount::ONE)
                .expect("a corpus height stays in range");
        }
    }
    panic!("{}: the corpus lists no spend", dir.display());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_ninth_input_is_refused_on_a_captured_regtest_chain() {
    let (dir, manifest) = captured_chains()
        .into_iter()
        .find(|(_, m)| m.shape == "spend-1in-2out")
        .expect("the spend-1in-2out chain is captured");
    let at = first_spend_height(&dir);
    let substrate = mock_with_the_real_clock();
    let corpus = std::fs::read(dir.join("corpus.e2")).expect("read corpus.e2");
    let trace = std::fs::read(dir.join("trace.e2")).expect("read trace.e2");
    let source = Mutated::new(
        UntilRetiredJoin::new(
            CorpusReader::open(std::io::Cursor::new(corpus.as_slice())).expect("open corpus"),
        ),
        at,
        Mutation::TooManyInputs,
        Environment {
            clock: substrate.clock,
            pow: None,
            overweight: None,
            twins: &[],
            resigned: None,
        },
    );
    let (report, path, _rules, _source) = replay_open(
        &manifest,
        substrate,
        ApplyPolicy::Full,
        "too-many-inputs",
        source,
        Arc::new(Trace::read(std::io::Cursor::new(trace.as_slice())).expect("read trace")),
    )
    .await;
    cleanup(&path);
    let report = report.expect("the mutated chain runs to its refusal");
    let (height, verdict) = report
        .refused
        .expect("a spend over the input cap on a regtest chain is refused");
    assert_eq!(height, at, "refused at the mutated block");
    assert_eq!(
        verdict.rule,
        CenRow::I4,
        "refused on {}: the input cap binds the test networks too (rule 71)",
        verdict.rule.as_str()
    );
    assert_eq!(
        u64::try_from(report.connected.len()).expect("small"),
        at.to_raw(),
        "everything below the mutated block connected"
    );
}
