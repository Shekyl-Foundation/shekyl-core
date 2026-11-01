// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-I4 on a captured regtest chain, under that chain's own rules.
//!
//! The C++ exempted Fakechain from the input cap; the Rust rule binds every
//! network (rule 71; `CHAIN_RULES_SLICE_6.md` §5.4). The mutation family's
//! harness chain judges `TooManyInputs` under the genesis rules, which an
//! exemption keyed on the test networks would not reach. This test applies
//! the same mutation to the captured `spend-1in-2out` chain — a regtest
//! chain, replayed under its own `FakechainSchedule` — so an exemption
//! restored for the test networks refuses on a later row here and fails.

use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;

use shekyl_chain_rules::CenRow;
use shekyl_chain_store::apply_policy::ApplyPolicy;
use shekyl_types::BlockHeight;
use shekyl_wire::Input;

use super::replay::rules_for;
use super::retired_keyless_join::UntilRetiredJoin;
use super::{captured_chains, mock_with_the_real_clock};
use crate::corpus::CorpusReader;
use crate::metrics::Metrics;
use crate::mutation::{Environment, Mutated, Mutation};
use crate::pipeline::{run, PipelineConfig};
use crate::source::{IngestEvent, Source};
use crate::test_support::{cleanup, open_store_under, tmp};
use crate::trace::Trace;

/// The height of the first block in `dir`'s corpus that lists a spend.
fn first_spend_height(dir: &Path) -> BlockHeight {
    let corpus = std::fs::read(dir.join("corpus.e2")).expect("read corpus.e2");
    let mut reader =
        CorpusReader::open(std::io::Cursor::new(corpus.as_slice())).expect("open corpus");
    let mut height = reader.first_height().to_raw();
    while let Some(event) = reader.next().expect("corpus reads") {
        if let IngestEvent::Extend(candidate) = event.event {
            let spends = candidate.transactions.iter().any(|tx| {
                tx.prefix
                    .inputs
                    .iter()
                    .any(|input| matches!(input, Input::ToKey { .. }))
            });
            if spends {
                return BlockHeight::from_raw(height);
            }
            height += 1;
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
    let mut source = Mutated::new(
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
    let rules = rules_for(&manifest);
    let path = tmp("vectors-too-many-inputs");
    let store = open_store_under(
        &path,
        &rules.in_force(BlockHeight::from_raw(0)),
        ApplyPolicy::Full,
    );
    let report = run(
        &mut source,
        substrate,
        Arc::new(Metrics::new()),
        rules,
        store,
        Arc::new(Trace::read(std::io::Cursor::new(trace.as_slice())).expect("read trace")),
        PipelineConfig {
            window: NonZeroUsize::new(64).expect("non-zero"),
            hashers: NonZeroUsize::new(4).expect("non-zero"),
        },
    )
    .await
    .expect("the mutated chain runs to its refusal");
    cleanup(&path);
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
