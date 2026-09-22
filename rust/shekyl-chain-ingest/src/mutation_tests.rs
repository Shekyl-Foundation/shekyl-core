// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The mutation family against the pipeline (`DRS_E2_REPLAY_DRIVER.md`
//! §3.10). One run per mutation; the assertion's branch is chosen by the
//! expected row's **census status**, so a ported row turns a pinned gap red.

use std::num::{NonZeroU128, NonZeroUsize};
use std::sync::Arc;

use shekyl_chain_rules::harness::{Faulted, MockSubstrate};
use shekyl_chain_rules::{Candidate, CenRow, Locus, RowStatus};
use shekyl_chain_store::store::{StoreError, StoreInvariant};
use shekyl_difficulty::Difficulty;
use shekyl_types::{BlockHash, PowHash};
use shekyl_wire::{Block, Transaction};

use crate::connector::RunFault;
use crate::metrics::Metrics;
use crate::mutation::{Environment, Mutated, Mutation, MutationFault, Pow, Unmutable};
use crate::pipeline::{run, PipelineConfig, PipelineFault, RunReport};
use crate::schedule::ChainRules;
use crate::source::{IngestEvent, Source};
use crate::test_support::{
    block_with_nonce, chain_listing, chain_listing_with, cleanup, h, key_image, open_store, spend,
    tmp, trace_of, Family, Scripted,
};

const GENESIS_RULES: ChainRules = ChainRules::Regtest {
    fixed_difficulty: None,
};

/// D1's target for the mined chain: half of all hashes pass.
const MINED_DIFFICULTY: u128 = 2;

fn mined_rules() -> ChainRules {
    ChainRules::Regtest {
        fixed_difficulty: Some(NonZeroU128::new(MINED_DIFFICULTY).expect("non-zero")),
    }
}

/// A seed-sensitive mock longhash: `keccak256(blob ‖ seed)`. Deterministic,
/// fails the target about half the time at difficulty 2, and — unlike
/// `always_satisfies` — distinguishes seeds, which is what D1-under-a-wrong-
/// seed needs.
fn seeded_keccak(blob: &[u8], seed: &BlockHash) -> PowHash {
    let mut preimage = blob.to_vec();
    preimage.extend_from_slice(seed.as_bytes());
    PowHash::from_bytes(shekyl_crypto_hash::keccak256(&preimage))
}

/// [`seeded_keccak`] in the shape `MockSubstrate::longhash` takes — the
/// `Result` is the fn pointer's, as `always_satisfies` says of its own.
#[allow(clippy::unnecessary_wraps)]
fn seeded_keccak_substrate(blob: &[u8], seed: &BlockHash) -> Result<PowHash, Faulted> {
    Ok(seeded_keccak(blob, seed))
}

/// The seed the chain holds for `height` under D3's schedule on a short
/// chain: the null hash for genesis, block 0's id after.
fn true_seed(chain: &[(Block, Vec<Transaction>)], height: u64) -> BlockHash {
    if height == 0 {
        BlockHash::NULL
    } else {
        chain[0].0.hash()
    }
}

/// A chain of `n` blocks mined against [`seeded_keccak`] at
/// [`MINED_DIFFICULTY`]: every block's longhash under the true seed
/// satisfies the target.
fn mined_chain(n: u64) -> Vec<(Block, Vec<Transaction>)> {
    let listed = (0..n)
        .map(|hh| {
            if hh == 0 {
                Vec::new()
            } else {
                vec![spend(key_image(Family::Main, hh))]
            }
        })
        .collect();
    let difficulty = Difficulty::from_raw(MINED_DIFFICULTY);
    let mut genesis_hash = BlockHash::NULL;
    chain_listing_with(listed, |height, previous, txs| {
        let seed = if height == 0 {
            BlockHash::NULL
        } else {
            genesis_hash
        };
        let mut nonce = 0u32;
        loop {
            let block = block_with_nonce(height, previous, txs, nonce);
            if shekyl_difficulty::check_hash(
                seeded_keccak(&block.pow_blob(), &seed).as_bytes(),
                difficulty,
            ) {
                if height == 0 {
                    genesis_hash = block.hash();
                }
                return block;
            }
            nonce += 1;
        }
    })
}

fn candidate(b: &Block, txs: &[Transaction]) -> Candidate {
    Candidate::new(b.clone(), txs.to_vec())
}

fn scripted(chain: &[(Block, Vec<Transaction>)]) -> Scripted {
    Scripted::new(
        chain
            .iter()
            .map(|(b, txs)| IngestEvent::Extend(Box::new(candidate(b, txs))))
            .collect(),
    )
}

/// How one mutated run ended.
enum Outcome {
    Report(Box<RunReport>),
    Fault(PipelineFault<MutationFault<std::convert::Infallible>, Faulted>),
}

/// Replay `chain` with `mutation` applied at `at`, under `rules` and the
/// given substrate.
async fn judge(
    name: &str,
    chain: &[(Block, Vec<Transaction>)],
    at: u64,
    mutation: Mutation,
    rules: ChainRules,
    substrate: MockSubstrate,
    pow: Option<Pow<'_>>,
) -> Outcome {
    let path = tmp(&format!("mutation-{name}"));
    let env = Environment {
        clock: substrate.clock,
        pow,
    };
    let mut source = Mutated::new(scripted(chain), h(at), mutation, env);
    let trace = Arc::new(trace_of(chain, false));
    let out = run(
        &mut source,
        Arc::new(substrate),
        Arc::new(Metrics::new()),
        rules,
        open_store(&path),
        trace,
        PipelineConfig {
            window: NonZeroUsize::new(4).expect("non-zero"),
            hashers: NonZeroUsize::new(2).expect("non-zero"),
        },
    )
    .await;
    cleanup(&path);
    match out {
        Ok(report) => Outcome::Report(Box::new(report)),
        Err(fault) => Outcome::Fault(fault),
    }
}

/// The assertion §3.10 states: on an `Implemented` row the run refuses
/// exactly that row at `at` after connecting everything below it; on a
/// `Pending` row the family pins today's shape, per mutation.
fn assert_lands(mutation: Mutation, at: u64, outcome: &Outcome) {
    let expected = mutation.expected();
    match expected.status() {
        RowStatus::Implemented => {
            let Outcome::Report(report) = outcome else {
                panic!("{mutation}: the run faulted instead of refusing");
            };
            let (height, verdict) = report
                .refused
                .unwrap_or_else(|| panic!("{mutation}: the mutated block was not refused"));
            assert_eq!(height, h(at), "{mutation}: refused at the wrong height");
            assert_eq!(
                verdict.rule,
                expected,
                "{mutation}: refused on {} — a rule other than the one the mutation \
                 violates fired, which is a finding on its own",
                verdict.rule.as_str()
            );
            assert_eq!(verdict.locus, Locus::Block, "{mutation}: locus");
            assert_eq!(
                report.connected.len(),
                usize::try_from(at).expect("small"),
                "{mutation}: everything below the mutation connected"
            );
        }
        RowStatus::Pending => assert_pinned_gap(mutation, at, outcome),
        other => panic!("{mutation}: no family member expects a {other:?} row"),
    }
}

/// §3.10's last column: what Rust does today with a violation whose row is
/// not ported. Each arm is a pin with the census as its falsifier — when
/// the row flips to `Implemented`, `assert_lands` takes the other branch
/// and this arm is never reached again.
fn assert_pinned_gap(mutation: Mutation, at: u64, outcome: &Outcome) {
    match (mutation, outcome) {
        (Mutation::WrongReward | Mutation::ReorderedBodies, Outcome::Report(report)) => {
            assert_eq!(
                report.refused,
                None,
                "{mutation}: {} is Pending, so the block connects today; a refusal here means \
                 the row landed — flip the census, not this test",
                mutation.expected().as_str()
            );
            assert_eq!(
                report.connected.len(),
                usize::try_from(at + 1).expect("small"),
                "{mutation}: the mutated block connected"
            );
        }
        // The validator has no I7, so the double spend reaches `connect`,
        // where SI-1 is the belt: the run halts. C2-R8's taxonomy — a belt
        // firing is the validator's hole — observed, not accepted.
        (Mutation::DoubleSpend, Outcome::Fault(fault)) => {
            assert!(
                matches!(
                    fault,
                    PipelineFault::Connector(RunFault::Store(StoreError::InvariantViolated(
                        StoreInvariant::KeyImageNotFresh
                    )))
                ),
                "{mutation}: expected the SI-1 halt while I7 is Pending, got {fault}"
            );
        }
        (_, Outcome::Report(report)) => {
            panic!("{mutation}: unexpected report while its row is Pending: {report:?}")
        }
        (_, Outcome::Fault(fault)) => {
            panic!("{mutation}: unexpected fault while its row is Pending: {fault}")
        }
    }
}

// ---------------------------------------------------------------------------
// The family, one run each
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_family_lands_on_its_named_rows() {
    // Every mutation runs; a mutation missing here is a compile error via
    // the exhaustive match in `setup`, and `Mutation::ALL` is the order.
    for mutation in Mutation::ALL {
        let (at, outcome) = setup_and_judge(mutation).await;
        assert_lands(mutation, at, &outcome);
    }
}

/// Where a mutation lands: block 2, so blocks 0 and 1 are below it (a spend
/// to reuse, a median to fall under). A mutation whose row is
/// `Implemented` sits under block 3 as well, so the run's end is the
/// refusal and not the chain's. A mutation whose row is `Pending`
/// **connects**, and a connected block's hash is not the hash its successor
/// was built on — so it sits at the tip, or block 3 would orphan on A2 and
/// the pin would read a real gap as a refusal.
const AT: u64 = 2;

/// A four-block chain for refusals (block 3 above the mutation), three for
/// pins (the mutation is the tip).
fn chain_len(mutation: Mutation) -> u64 {
    match mutation.expected().status() {
        RowStatus::Pending => AT + 1,
        _ => AT + 2,
    }
}

async fn setup_and_judge(mutation: Mutation) -> (u64, Outcome) {
    let n = chain_len(mutation);
    let outcome = match mutation {
        Mutation::PowUnderWrongSeed => {
            let chain = mined_chain(n);
            let substrate = MockSubstrate {
                clock: MockSubstrate::CLOCK,
                longhash: seeded_keccak_substrate,
            };
            let pow = Pow {
                longhash: &seeded_keccak,
                difficulty: Difficulty::from_raw(MINED_DIFFICULTY),
                true_seed: true_seed(&chain, AT),
                wrong_seed: BlockHash::from_bytes([0xbb; 32]),
                nonce_budget: 1 << 16,
            };
            judge(
                "pow-wrong-seed",
                &chain,
                AT,
                mutation,
                mined_rules(),
                substrate,
                Some(pow),
            )
            .await
        }
        Mutation::ReorderedBodies => {
            // Block 2 lists two bodies so there is something to swap.
            let mut listed = vec![
                Vec::new(),
                vec![spend(key_image(Family::Main, 1))],
                vec![
                    spend(key_image(Family::Main, 2)),
                    spend(key_image(Family::Fork, 2)),
                ],
            ];
            listed.truncate(usize::try_from(n).expect("small"));
            let chain = chain_listing(listed);
            judge(
                "reordered-bodies",
                &chain,
                AT,
                mutation,
                GENESIS_RULES,
                MockSubstrate::default(),
                None,
            )
            .await
        }
        Mutation::HeaderVersion
        | Mutation::Orphan
        | Mutation::WrongRoot
        | Mutation::FutureTimestamp
        | Mutation::StaleTimestamp
        | Mutation::WrongReward
        | Mutation::DoubleSpend => {
            let chain = crate::test_support::chain(n);
            judge(
                &format!("{mutation:?}").to_lowercase(),
                &chain,
                AT,
                mutation,
                GENESIS_RULES,
                MockSubstrate::default(),
                None,
            )
            .await
        }
    };
    (AT, outcome)
}

/// The mined chain itself replays clean under the seeded hasher — so a D1
/// refusal in the family is the mutation's, not the fixture's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_mined_chain_replays_clean_under_the_seeded_hasher() {
    let path = tmp("mutation-mined-clean");
    let chain = mined_chain(4);
    let mut source = scripted(&chain);
    let report = run(
        &mut source,
        Arc::new(MockSubstrate {
            clock: MockSubstrate::CLOCK,
            longhash: seeded_keccak_substrate,
        }),
        Arc::new(Metrics::new()),
        mined_rules(),
        open_store(&path),
        Arc::new(trace_of(&chain, false)),
        PipelineConfig::default(),
    )
    .await
    .expect("a mined chain is a valid chain");
    assert_eq!(report.refused, None);
    assert_eq!(report.connected.len(), 4);
    assert!(
        report.exercised.contains("CEN-D1"),
        "D1 was judged, not skipped"
    );
    cleanup(&path);
}

// ---------------------------------------------------------------------------
// The wrapper's own contract
// ---------------------------------------------------------------------------

fn env() -> Environment<'static> {
    Environment {
        clock: MockSubstrate::CLOCK,
        pow: None,
    }
}

fn drain<S: Source>(source: &mut S) -> Result<usize, S::Fault> {
    let mut n = 0;
    while source.next()?.is_some() {
        n += 1;
    }
    Ok(n)
}

#[test]
fn the_wrapper_keeps_numbering_and_heights_and_mutates_exactly_one_block() {
    let chain = crate::test_support::chain(3);
    let mut source = Mutated::new(scripted(&chain), h(1), Mutation::Orphan, env());
    assert_eq!(source.first_height(), h(0));
    let mut seen = Vec::new();
    while let Some(ev) = source.next().expect("no fault") {
        seen.push(ev);
    }
    assert_eq!(seen.len(), 3);
    for (i, ev) in seen.iter().enumerate() {
        assert_eq!(ev.seq.to_raw(), i as u64, "numbering is the inner source's");
    }
    let block_at = |i: usize| match &seen[i].event {
        IngestEvent::Extend(c) => c.block.clone(),
        IngestEvent::Rewind { .. } => panic!("Extend-only"),
    };
    assert_eq!(block_at(0), chain[0].0, "below: untouched");
    assert_eq!(block_at(2), chain[2].0, "above: untouched");
    assert_ne!(block_at(1).header.previous, chain[1].0.header.previous);
    assert_eq!(
        block_at(1).header.timestamp,
        chain[1].0.header.timestamp,
        "one violation"
    );
}

#[test]
fn a_rewind_from_the_inner_source_is_a_wrapper_fault() {
    let chain = crate::test_support::chain(2);
    let events = vec![
        IngestEvent::Extend(Box::new(candidate(&chain[0].0, &chain[0].1))),
        IngestEvent::Rewind { to: h(0) },
    ];
    let mut source = Mutated::new(Scripted::new(events), h(0), Mutation::WrongRoot, env());
    source.next().expect("block 0 mutated");
    match source.next() {
        Err(MutationFault::Rewind { to }) => assert_eq!(to, h(0)),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_mutation_height_the_chain_never_reaches_is_a_fault_not_a_clean_replay() {
    let chain = crate::test_support::chain(2);
    let mut source = Mutated::new(scripted(&chain), h(5), Mutation::Orphan, env());
    match drain(&mut source) {
        Err(MutationFault::NeverReached { at, last }) => {
            assert_eq!((at, last), (h(5), h(2)));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_candidate_that_cannot_carry_the_mutation_names_why() {
    // Block 1 of `chain(2)` lists one body: nothing to reorder.
    let chain = crate::test_support::chain(2);
    let mut source = Mutated::new(scripted(&chain), h(1), Mutation::ReorderedBodies, env());
    source.next().expect("block 0");
    match source.next() {
        Err(MutationFault::Unmutable {
            mutation: Mutation::ReorderedBodies,
            at,
            cause: Unmutable::TooFewBodies { listed: 1 },
        }) => assert_eq!(at, h(1)),
        other => panic!("{other:?}"),
    }
    // Genesis has nothing spent before it: no double spend to stage.
    let mut source = Mutated::new(scripted(&chain), h(0), Mutation::DoubleSpend, env());
    match source.next() {
        Err(MutationFault::Unmutable {
            cause: Unmutable::NothingSpentBefore,
            ..
        }) => {}
        other => panic!("{other:?}"),
    }
    // PoW without the leg.
    let mut source = Mutated::new(scripted(&chain), h(0), Mutation::PowUnderWrongSeed, env());
    match source.next() {
        Err(MutationFault::Unmutable {
            cause: Unmutable::NoPowEnvironment,
            ..
        }) => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn every_mutation_names_a_row_and_the_pending_ones_are_the_three_the_plan_lists() {
    let pending: Vec<CenRow> = Mutation::ALL
        .iter()
        .map(|m| m.expected())
        .filter(|row| row.status() == RowStatus::Pending)
        .collect();
    // §3.10's table at the pin. When an E6 slice ports one of these, this
    // line and the family's pinned-gap arm both go red together — the plan's
    // table is then updated with the row, not the test loosened.
    assert_eq!(pending, vec![CenRow::F13, CenRow::G2, CenRow::I7]);
    for m in Mutation::ALL {
        assert!(
            m.to_string().contains(m.expected().as_str()),
            "{m}: Display names the row"
        );
    }
}
