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
use shekyl_chain_rules::{seed_height, Candidate, Locus, RowStatus, TxSlot};
use shekyl_difficulty::{check_hash, Difficulty};
use shekyl_types::{BlockHash, CurveTreeRoot, PowHash};
use shekyl_wire::{Block, Transaction};

use shekyl_harness_spender::{Linked, MinerWallet, Spender};

use crate::archival_driver::ENDPOINT;
use crate::metrics::Metrics;
use crate::mutation::{
    first_nonce, Environment, ExpectedPlace, Mutated, Mutation, MutationFault, Overweight, Pow,
    Resigned, UNHELD_REFERENCE,
};
use crate::pipeline::{run, PipelineConfig, PipelineFault, RunReport};
use crate::scenario_archival::{complete_tree, Persona};
use crate::schedule::ChainRules;
use crate::source::IngestEvent;
use crate::test_support::{
    bare_chain, block_with_nonce, chain, cleanup, h, open_store, tmp, trace_of, Family, Growing,
    Scripted, FIRST_SPEND_HEIGHT,
};

const GENESIS_RULES: ChainRules = ChainRules::Regtest {
    fixed_difficulty: None,
    schedule: shekyl_chain_rules::FakechainSchedule::PRODUCTION,
};

/// D1's target for the mined chain: half of all hashes pass.
const MINED_DIFFICULTY: u128 = 2;

/// Nonces the fixture will try. At difficulty 2 a hash meets the target
/// about half the time, so a valid block is a few tries; the wrong-seed
/// nonce (pass one seed, fail the other) is about one in four.
const NONCE_BUDGET: u32 = 1 << 16;

/// A seed the chain does not hold. Distinct from the null hash (genesis's
/// seed) and from any block id the fixture mines.
const WRONG_SEED: [u8; 32] = [0xbb; 32];

fn mined_rules() -> ChainRules {
    ChainRules::Regtest {
        fixed_difficulty: Some(NonZeroU128::new(MINED_DIFFICULTY).expect("non-zero")),
        schedule: shekyl_chain_rules::FakechainSchedule::PRODUCTION,
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

/// The seed CEN-D3 names for `height`, read from blocks already built.
/// `hash_at` is the block id at a height the schedule selects; that height
/// is below `height`, or absent at genesis.
fn seed_for(height: u64, hash_at: impl Fn(u64) -> BlockHash) -> BlockHash {
    match seed_height(h(height)) {
        None => BlockHash::NULL,
        Some(at) => hash_at(at.to_raw()),
    }
}

/// The first nonce in [`NONCE_BUDGET`] whose longhash under `seed` meets
/// [`MINED_DIFFICULTY`].
fn nonce_meeting_target(
    seed: &BlockHash,
    root: CurveTreeRoot,
    height: u64,
    previous: BlockHash,
    txs: &[Transaction],
    reward: u64,
) -> u32 {
    let difficulty = Difficulty::from_raw(MINED_DIFFICULTY);
    first_nonce(NONCE_BUDGET, |nonce| {
        let block = block_with_nonce(root, height, previous, txs, reward, nonce);
        check_hash(seeded_keccak(&block.pow_blob(), seed).as_bytes(), difficulty)
    })
    .unwrap_or_else(|| {
        panic!(
            "no nonce in 0..{NONCE_BUDGET} satisfies difficulty {MINED_DIFFICULTY} under the true seed"
        )
    })
}

/// A chain of `n` blocks mined against [`seeded_keccak`] at
/// [`MINED_DIFFICULTY`]: every block's longhash under the true seed
/// satisfies the target. The seed is [`seed_height`]'s, the same function
/// the pipeline claims with.
fn mined_chain(n: u64) -> Vec<(Block, Vec<Transaction>)> {
    // The same listing as `test_support::chain`: each block spends the
    // coinbase that matured for it, nothing below the first.
    let mut growing = Growing::new();
    for _ in 0..n {
        let listed = growing.spend_matured(Family::Main).into_iter().collect();
        let seed = seed_for(growing.height().to_raw(), |at| {
            growing.hashes()[usize::try_from(at).expect("seed height fits an index")]
        });
        growing.extend_with(listed, |root, height, previous, txs, reward| {
            let nonce = nonce_meeting_target(&seed, root, height, previous, txs, reward);
            block_with_nonce(root, height, previous, txs, reward, nonce)
        });
    }
    growing.finish()
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

/// The optional legs of an [`Environment`], as one run supplies them.
#[derive(Default)]
struct Legs<'a> {
    pow: Option<Pow<'a>>,
    overweight: Option<Overweight<'a>>,
    twins: &'a [Transaction],
    resigned: Option<Resigned<'a>>,
}

/// The wallet-made bodies the three spend mutations take
/// ([`Environment::resigned`]), built over `chain` below `at` for the
/// block connecting at `at`: a respend of block 0's coinbase (spent at
/// `FIRST_SPEND_HEIGHT`, below `at`), and two spends of the coinbase the
/// block at `at` would spend, one naming the unheld reference and one
/// naming the parent — each signed after its name moved.
struct ResignedBodies {
    respend: Transaction,
    unknown_reference: Transaction,
    reference_too_recent: Transaction,
}

impl ResignedBodies {
    fn over(chain: &[(Block, Vec<Transaction>)], at: u64) -> Self {
        assert!(
            at > FIRST_SPEND_HEIGHT,
            "block 0's coinbase is spent below {at}"
        );
        let below: Vec<Linked<'_>> = chain[..usize::try_from(at).expect("small")]
            .iter()
            .map(|(block, listed)| Linked::new(block, listed))
            .collect();
        let spender = Spender::over(&below);
        let wallet = MinerWallet::harness();
        let fee = Family::Main.fee();
        let matured = h(at - FIRST_SPEND_HEIGHT);
        let parent = chain[usize::try_from(at - 1).expect("small")].0.hash();
        Self {
            respend: spender.spend_coinbase(wallet, h(0), h(at), fee),
            unknown_reference: spender.spend_coinbase_referencing(
                wallet,
                matured,
                h(at),
                fee,
                UNHELD_REFERENCE,
            ),
            reference_too_recent: spender.spend_coinbase_referencing(
                wallet,
                matured,
                h(at),
                fee,
                parent,
            ),
        }
    }

    fn legs(&self) -> Resigned<'_> {
        Resigned {
            respend: &self.respend,
            unknown_reference: &self.unknown_reference,
            reference_too_recent: &self.reference_too_recent,
        }
    }
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
    legs: Legs<'_>,
) -> Outcome {
    let path = tmp(&format!("mutation-{name}"));
    let env = Environment {
        clock: substrate.clock,
        pow: legs.pow,
        overweight: legs.overweight,
        twins: legs.twins,
        resigned: legs.resigned,
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
            let report = match outcome {
                Outcome::Report(report) => report,
                Outcome::Fault(fault) => {
                    panic!("{mutation}: the run faulted instead of refusing: {fault}")
                }
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
            assert_place(mutation, verdict.locus);
            assert_eq!(
                report.connected.len(),
                usize::try_from(at).expect("small"),
                "{mutation}: everything below the mutation connected"
            );
        }
        // No family member names a pending row since E6 slice 7 wave B
        // landed F18 (the last one, `WrongReward`'s). A mutation written
        // for an unported row re-adds the pinned-gap arm — a `match` over
        // `Mutation` naming what Rust does today, the shape `WrongReward`
        // carried from increment 3 to wave B — rather than loosening this.
        RowStatus::Pending => panic!(
            "{mutation}: {} is Pending and the family has no pin for it; pin today's shape \
             per mutation (the arm deleted with wave B), never a guessed verdict",
            expected.as_str()
        ),
        other => panic!("{mutation}: no family member expects a {other:?} row"),
    }
}

/// The place [`Mutation::expected_place`] names. [`ExpectedPlace::Unnamed`]
/// fails here on purpose: a port must name the locus, not inherit `Block`.
fn assert_place(mutation: Mutation, locus: Locus) {
    match mutation.expected_place() {
        ExpectedPlace::Block => assert_eq!(locus, Locus::Block, "{mutation}: place"),
        ExpectedPlace::Miner => assert_eq!(
            locus,
            Locus::Tx {
                slot: TxSlot::Miner
            },
            "{mutation}: §3.10 names the miner transaction"
        ),
        ExpectedPlace::Input => assert!(
            matches!(locus, Locus::Input { .. }),
            "{mutation}: §3.10 names an input, got {locus}"
        ),
        ExpectedPlace::Listed => assert!(
            matches!(
                locus,
                Locus::Tx {
                    slot: TxSlot::Listed(_)
                }
            ),
            "{mutation}: §3.10 names a listed transaction, got {locus}"
        ),
        ExpectedPlace::Unnamed => panic!(
            "{mutation}: {} is Implemented and expected_place is still Unnamed. \
             Name the locus on the mutation when the row is ported.",
            mutation.expected().as_str()
        ),
    }
}

// The pinned-gap arm — §3.10's last column, what Rust did with a violation
// whose row was not ported — went with its last member. `DoubleSpend`
// pinned the SI-1 halt while I7 was Pending (C2-R8's taxonomy — a belt
// firing is the validator's hole — observed, not accepted); E6 slice 6
// commit 4 ported I7. `ReorderedBodies` pinned "connects" while G2 was
// Pending; slice 7 commit 6 ported G2. `WrongReward` pinned "connects"
// while F18 was Pending; slice 7 wave B ported F18 and the arm is gone.

// ---------------------------------------------------------------------------
// The family, one run each
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_family_lands_on_its_named_rows() {
    // Every mutation runs; a mutation missing here is a compile error via
    // the exhaustive match in `setup`, and `Mutation::ALL` is the order.
    for mutation in Mutation::ALL {
        let (outcome, at) = setup_and_judge(mutation).await;
        assert_lands(mutation, at, &outcome);
    }
}

/// Where a mutation lands: the block after the first spend block, so the
/// blocks below it hold a spend to reuse and a median to fall under. The
/// mutated block is the tip. (Block 2 until slice 6 commit 5: CEN-I11 put
/// the first admissible spend at `FIRST_SPEND_HEIGHT`, and `DoubleSpend`
/// needs one beneath it.)
///
/// A pending row connects, and a successor built on the pre-mutation hash
/// orphans on CEN-A2, so the pin would read a gap as a refusal. An
/// implemented row stops the run at the refusal, so a successor would not
/// be judged either. One length covers both.
///
/// `OverweightBlock` lands higher ([`setup_and_judge`] returns the height
/// with the outcome): its filler is as many real spends as twice the zone
/// holds, each of a coinbase that has matured and no block spent, and
/// those exist only once the chain is that many blocks past the first
/// spending height.
const AT: u64 = FIRST_SPEND_HEIGHT + 1;
const CHAIN_LEN: u64 = AT + 1;

async fn setup_and_judge(mutation: Mutation) -> (Outcome, u64) {
    let n = CHAIN_LEN;
    match mutation {
        Mutation::PowUnderWrongSeed => {
            let chain = mined_chain(n);
            let substrate = MockSubstrate {
                clock: MockSubstrate::CLOCK,
                longhash: seeded_keccak_substrate,
            };
            let pow = Pow {
                longhash: &seeded_keccak,
                difficulty: Difficulty::from_raw(MINED_DIFFICULTY),
                true_seed: seed_for(AT, |at| {
                    chain[usize::try_from(at).expect("seed height fits an index")]
                        .0
                        .hash()
                }),
                wrong_seed: BlockHash::from_bytes(WRONG_SEED),
                nonce_budget: NONCE_BUDGET,
            };
            let outcome = judge(
                "pow-wrong-seed",
                &chain,
                AT,
                mutation,
                mined_rules(),
                substrate,
                Legs {
                    pow: Some(pow),
                    ..Legs::default()
                },
            )
            .await;
            (outcome, AT)
        }
        // Block `AT` lists two bodies so there is something to swap: real
        // spends of the two coinbases matured for it — blocks 0's and 1's
        // (`AT = FIRST_SPEND_HEIGHT + 1`). `chain(n)` would have spent
        // block 0's at `FIRST_SPEND_HEIGHT`, so the block there lists
        // nothing instead, and both are unspent at `AT`.
        Mutation::ReorderedBodies => {
            let mut growing = Growing::over(&chain(FIRST_SPEND_HEIGHT));
            growing.extend(Vec::new(), 7);
            let two = vec![
                growing.spend_of(0, Family::Main),
                growing.spend_of(1, Family::Main),
            ];
            growing.extend(two, 7);
            let chain = growing.finish();
            assert_eq!(chain.len() as u64, n, "the reordered block is the tip");
            let outcome = judge(
                "reordered-bodies",
                &chain,
                AT,
                mutation,
                GENESIS_RULES,
                MockSubstrate::default(),
                Legs::default(),
            )
            .await;
            (outcome, AT)
        }
        // A chain whose block `AT` lists one archival body of the kind the
        // mutation duplicates, beside (or riding) the spend `chain(n)`
        // would list. The serve credit's twin is the body itself,
        // `unlock_time` moved; the bond post's is signed over its content,
        // so the run supplies a second valid body with the same key — a
        // second **join** for the persona (a Release over no record is
        // J16's in the slot loop, before G10). A credit names a persona
        // with a record read off the view before its block (CEN-J4), so
        // the block below `AT` lists the persona's join; the credit's
        // epoch is past the join's (CEN-J5). (G9's pair is the driver's —
        // `Mutation` docs.)
        //
        // The joins are **real**: the persona's post through the
        // production constructor, riding the block's own coinbase spend
        // (`Growing::spend_of_posting`), its funding half proven over the
        // wallet-side tree — since slice 6 row 6 CEN-J27 judges a bond
        // post's funding spend as I13/I15 judge a regular spend's, and a
        // fixture join is refused there before G10 is reached. The twin
        // spends the coinbase that matured one block earlier and no block
        // spent (block `AT − 1` lists nothing in that case), so both joins
        // are admissible at `AT` alone and G10 counts the second. The
        // credit is the one fixture body left: a serve-credit-only
        // transaction has no funding spend (CEN-H20) and J27 is vacuous on
        // it. (*Was:* fixture joins with filler proofs, anchored where
        // listed; green while the funding half was unjudged on the class.)
        Mutation::DuplicateServeCredit | Mutation::DuplicateBondPost => {
            let persona = Persona::at(1);
            let mut growing = Growing::over(&chain(AT - 1));
            // Block `AT − 1`: the first spendable coinbase, posting the
            // join the credit will be judged against — or nothing, so that
            // coinbase stays for the bond post's twin.
            let below: Vec<Transaction> = match mutation {
                Mutation::DuplicateServeCredit => vec![growing.spend_of_posting(
                    AT - 1 - FIRST_SPEND_HEIGHT,
                    Family::Main,
                    Some(&persona.join(complete_tree(), ENDPOINT)),
                )],
                _ => Vec::new(),
            };
            growing.extend(below, 7);
            // Block `AT`, and the twin built at its height before it is
            // extended (the spender anchors at the connecting height).
            let (at_block, twins): (Vec<Transaction>, Vec<Transaction>) = match mutation {
                Mutation::DuplicateServeCredit => (
                    vec![
                        growing
                            .spend_matured(Family::Main)
                            .expect("a coinbase has matured for AT"),
                        growing.anchored(persona.serve_credit(7, 11)),
                    ],
                    Vec::new(),
                ),
                _ => (
                    vec![growing.spend_of_posting(
                        AT - FIRST_SPEND_HEIGHT,
                        Family::Main,
                        Some(&persona.join(complete_tree(), ENDPOINT)),
                    )],
                    vec![growing.spend_of_posting(
                        AT - 1 - FIRST_SPEND_HEIGHT,
                        Family::Main,
                        Some(&persona.join(complete_tree(), ENDPOINT)),
                    )],
                ),
            };
            growing.extend(at_block, 7);
            let chain = growing.finish();
            assert_eq!(chain.len() as u64, n, "the mutated block is the tip");
            let outcome = judge(
                &format!("{mutation:?}").to_lowercase(),
                &chain,
                AT,
                mutation,
                GENESIS_RULES,
                MockSubstrate::default(),
                Legs {
                    twins: &twins,
                    ..Legs::default()
                },
            )
            .await;
            (outcome, AT)
        }
        // Spare valid spends at the mutated block, until it passes twice
        // the zone — the median in force on a young chain (CEN-G6's floor
        // arm). Each is a real spend of its own coinbase: the filler must
        // pass every rule before G6 in the judging order — the spend rows
        // judge each body before the block's weight is read — so a
        // refusal here is the weight's and not a filler's.
        Mutation::OverweightBlock => {
            let bound = 2 * shekyl_economics::FULL_REWARD_ZONE;
            // The count is derived from a real spend's weight, not pinned:
            // one more than the bound holds, and one spare, as the
            // supplier's contract has it (`Overweight` docs).
            let mut growing = Growing::over(&bare_chain(FIRST_SPEND_HEIGHT + 1));
            let one = growing.spend_of(0, Family::Fork).weight() as u64;
            let count = bound / one + 2;
            // `count` spends of `count` distinct coinbases, blocks
            // `0..count`, all matured for one connecting height: the
            // youngest, block `count − 1`'s, matures at
            // `count − 1 + FIRST_SPEND_HEIGHT`, so that is the mutated
            // block's height — and the chain lists nothing, so every one
            // of them is unspent there.
            let at = count - 1 + FIRST_SPEND_HEIGHT;
            while growing.height() < h(at) {
                growing.extend(Vec::new(), 7);
            }
            // Proven in parallel: each spend is independent of the others,
            // and `count` of them in sequence is over a minute.
            let coinbases: Vec<u64> = (0..count).collect();
            let workers = std::thread::available_parallelism().map_or(1, usize::from);
            let per = coinbases.len().div_ceil(workers).max(1);
            let bodies: Vec<Transaction> = std::thread::scope(|scope| {
                let growing = &growing;
                let handles: Vec<_> = coinbases
                    .chunks(per)
                    .map(|chunk| {
                        scope.spawn(move || {
                            chunk
                                .iter()
                                .map(|&k| growing.spend_of(k, Family::Fork))
                                .collect::<Vec<_>>()
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .flat_map(|handle| handle.join().expect("a spend proves"))
                    .collect()
            });
            // The block the mutation overfills, listing nothing itself.
            growing.extend(Vec::new(), 7);
            let chain = growing.finish();
            assert_eq!(chain.len() as u64, at + 1, "the mutated block is the tip");
            let outcome = judge(
                "overweight-block",
                &chain,
                at,
                mutation,
                GENESIS_RULES,
                MockSubstrate::default(),
                Legs {
                    overweight: Some(Overweight {
                        bodies: &bodies,
                        bound,
                    }),
                    ..Legs::default()
                },
            )
            .await;
            (outcome, at)
        }
        // `chain(n)` lists one spend per block from `FIRST_SPEND_HEIGHT`:
        // one body to drop, substitute or double at `AT`, and one below it
        // to re-list.
        Mutation::HeaderVersion
        | Mutation::Orphan
        | Mutation::WrongRoot
        | Mutation::WrongAttestationRoot
        | Mutation::FutureTimestamp
        | Mutation::StaleTimestamp
        | Mutation::WrongReward
        | Mutation::MissingBody
        | Mutation::SubstitutedBody
        | Mutation::RelistedTransaction
        | Mutation::DoubledListing
        | Mutation::ForgedSignature => {
            let chain = chain(n);
            let outcome = judge(
                &format!("{mutation:?}").to_lowercase(),
                &chain,
                AT,
                mutation,
                GENESIS_RULES,
                MockSubstrate::default(),
                Legs::default(),
            )
            .await;
            (outcome, AT)
        }
        // The three spend mutations take their wallet-made bodies from the
        // caller (`Environment::resigned`), built over the chain below.
        Mutation::DoubleSpend | Mutation::UnknownReference | Mutation::ReferenceTooRecent => {
            let chain = chain(n);
            let bodies = ResignedBodies::over(&chain, AT);
            let outcome = judge(
                &format!("{mutation:?}").to_lowercase(),
                &chain,
                AT,
                mutation,
                GENESIS_RULES,
                MockSubstrate::default(),
                Legs {
                    resigned: Some(bodies.legs()),
                    ..Legs::default()
                },
            )
            .await;
            (outcome, AT)
        }
    }
}

/// The mined chain itself replays clean under the seeded hasher — so a D1
/// refusal in the family is the mutation's, not the fixture's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_mined_chain_replays_clean_under_the_seeded_hasher() {
    let path = tmp("mutation-mined-clean");
    // The family's own length, so the clean replay covers the spend blocks
    // the mutations are staged over.
    let chain = mined_chain(CHAIN_LEN);
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
    assert_eq!(
        report.connected.len(),
        usize::try_from(CHAIN_LEN).expect("small")
    );
    assert!(
        report.exercised.contains("CEN-D1"),
        "D1 was judged, not skipped"
    );
    cleanup(&path);
}

/// Numbering, one mutated block, and the faults raised before a row is judged.
#[path = "mutation_source_tests.rs"]
mod mutation_source_tests;
