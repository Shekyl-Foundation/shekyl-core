// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.G's body rows, held at their loci.
//!
//! CEN-G2 — the declared list and the carried bodies: both arms, the
//! *first* mismatch and only it, the agreeing block recorded, the rule's
//! place in `form`. CEN-G1 — a re-listed and a doubled transaction, both at
//! the slot; and **the ordering pin**: a re-listed *spend* is refused on G1,
//! not I7 — the assertion is the row, so a G1 moved after the slot loop
//! goes red here rather than passing on the wrong refusal. CEN-G7/G9/G10 —
//! the second occurrence named, the admitted pair (G9) and the mixed kinds
//! (G10) as controls, an unparseable vin left to its own row.

use super::*;
use crate::block::Candidate;
use crate::fault::FormAttempt;
use crate::harness::fixture::{
    self, anchored_on, candidate, candidate_on, listed, listed_on, point_at, spend, spendable_chain,
};
use crate::harness::{assert_refused, defined, formed_on, judged, Faulted, MockSubstrate};
use crate::rule_set::RuleSet;
use crate::trust::Trust;
use crate::validate::{form, validate};
use shekyl_archival_retention::{HoldingsDescriptor, HoldingsKind, ShardSet};
use shekyl_crypto_pq::multisig::{SINGLE_KEY_CANONICAL_LEN, SINGLE_SIG_CANONICAL_LEN};
use shekyl_types::{BlockHash, KeyImage};
use shekyl_wire::{BondPost, BondPostKind, Holdings};

/// Three distinct listed bodies, the header declaring exactly them.
fn three_bodies() -> Candidate {
    candidate(vec![listed([1; 32]), listed([2; 32]), listed([3; 32])])
}

fn check(candidate: &Candidate) -> Verdict<()> {
    G2::check(&FormContext::new(candidate, &RuleSet::GENESIS))
}

/// The stage, so the rule's position in it is under test too.
fn form_judges(candidate: Candidate) -> Verdict<RuleCoverage> {
    match form(
        candidate,
        &RuleSet::GENESIS,
        &MockSubstrate::default(),
        BlockHash::NULL,
        FormAttempt::FIRST,
    ) {
        Ok(Ok(formed)) => Ok(*formed.coverage()),
        Ok(Err(refused)) => Err(refused),
        Err(Faulted) => unreachable!("the default MockSubstrate never faults"),
    }
}

use crate::coverage::RuleCoverage;

#[test]
fn cen_g2_an_agreeing_block_passes_and_is_recorded() {
    check(&three_bodies()).expect("declared == carried");
    let coverage = form_judges(three_bodies()).expect("form admits it");
    assert!(coverage.contains(CenRow::G2), "G2 recorded as evaluated");
    // And the empty body: no hashes, no bodies, agreeing vacuously.
    check(&candidate(Vec::new())).expect("an empty list agrees with itself");
}

#[test]
fn cen_g2_a_length_mismatch_is_refused_at_the_block() {
    // One body dropped, its hash still declared (`MissingBody`).
    let mut missing = three_bodies();
    missing.transactions.pop();
    assert_refused(check(&missing), CenRow::G2, Locus::Block);
    // One body more than declared — the other direction of the same arm.
    let mut extra = three_bodies();
    extra.transactions.push(listed([4; 32]));
    assert_refused(check(&extra), CenRow::G2, Locus::Block);
    // A declared hash with no body at all.
    let mut none = candidate(Vec::new());
    none.block.transaction_hashes.push(listed([9; 32]).hash());
    assert_refused(check(&none), CenRow::G2, Locus::Block);
}

#[test]
fn cen_g2_the_first_mismatching_index_is_the_locus_and_only_it() {
    // Swap the first two (`ReorderedBodies`): index 0 disagrees first.
    let mut reordered = three_bodies();
    reordered.transactions.swap(0, 1);
    assert_refused(
        check(&reordered),
        CenRow::G2,
        Locus::Tx {
            slot: TxSlot::Listed(0),
        },
    );
    // Substitute the body at index 1 with one the header never lists
    // (`SubstitutedBody`): index 0 agrees, so the locus is 1 — the rule
    // computed the first mismatch, not "a mismatch exists".
    let mut substituted = three_bodies();
    substituted.transactions[1] = listed([7; 32]);
    assert_refused(
        check(&substituted),
        CenRow::G2,
        Locus::Tx {
            slot: TxSlot::Listed(1),
        },
    );
    // Two disagreeing slots: still the first.
    let mut two = three_bodies();
    two.transactions[1] = listed([7; 32]);
    two.transactions[2] = listed([8; 32]);
    assert_refused(
        check(&two),
        CenRow::G2,
        Locus::Tx {
            slot: TxSlot::Listed(1),
        },
    );
}

#[test]
fn cen_g2_length_is_judged_before_any_index() {
    // Shorter *and* disagreeing at index 0: the length arm speaks, so the
    // index arm never reads past the shorter list.
    let mut both = three_bodies();
    both.transactions.pop();
    both.transactions.swap(0, 1);
    assert_refused(check(&both), CenRow::G2, Locus::Block);
}

// --- CEN-G1 ---------------------------------------------------------------

/// Judge through both stages on `chain`; a refusal is the verdict.
fn judge_on(chain: &crate::harness::MockChain, candidate: Candidate) -> Verdict<()> {
    chain.with_view(|view| {
        judged(validate(
            formed_on(chain, candidate),
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .map(|_valid| ())
    })
}

/// Run one view-bound rule on its own against `chain`.
fn check_alone_on<R: BlockRule>(
    chain: &crate::harness::MockChain,
    candidate: &Candidate,
) -> Verdict<()> {
    let formed = formed_on(chain, candidate.clone());
    chain.with_view(|view| {
        defined(R::check(
            &BlockContext::for_tests(&formed, chain.tip(), None),
            &view,
        ))
    })
}

#[test]
fn cen_g1_a_transaction_already_on_the_chain_is_refused_at_its_slot() {
    let base = spendable_chain();
    let recorded = listed_on(&base, point_at(20));
    let chain = base.with_transaction(recorded.hash());
    // At slot 1, behind a fresh body at slot 0: the slot named is the one
    // whose hash the rule looked up.
    let block = candidate_on(
        &chain,
        vec![listed_on(&chain, point_at(21)), recorded.clone()],
    );
    assert_refused(
        check_alone_on::<G1>(&chain, &block),
        CenRow::G1,
        Locus::Tx {
            slot: TxSlot::Listed(1),
        },
    );
    // The same body against a chain that never recorded it passes.
    let fresh = spendable_chain();
    let block = candidate_on(&fresh, vec![listed_on(&fresh, point_at(21)), recorded]);
    check_alone_on::<G1>(&fresh, &block).expect("an unrecorded identity passes G1");
}

#[test]
fn cen_g1_the_same_transaction_listed_twice_is_refused_at_the_second_listing() {
    let chain = spendable_chain();
    let body = listed_on(&chain, point_at(30));
    let mut block = candidate_on(&chain, vec![listed_on(&chain, point_at(31)), body.clone()]);
    // The header lists it twice and the block carries it twice (G2 agrees):
    // the intra-block arm, refused at the second occurrence.
    block.transactions.push(body.clone());
    block.block.transaction_hashes.push(body.hash());
    assert_refused(
        check_alone_on::<G1>(&chain, &block),
        CenRow::G1,
        Locus::Tx {
            slot: TxSlot::Listed(2),
        },
    );
}

/// **The ordering pin (slice 7 Q8).** A re-listed spend trips G1's chain
/// arm *and* I7 (its key image is spent): if G1 ran after the slot loop, I7
/// would refuse first at `Locus::Input` and G1 would have no witness on any
/// spend. Through the whole pipeline, the row must be G1 at the slot. The
/// control is the shape that separates the two rows: a *different* body
/// spending the same image is I7's alone.
#[test]
fn cen_g1_refuses_a_relisted_spend_before_i7_can() {
    let base = spendable_chain();
    let recorded = listed_on(&base, point_at(40));
    let chain = base
        .with_key_image(KeyImage::from_bytes(point_at(40)))
        .with_transaction(recorded.hash());
    // Re-listed: the recorded body itself, its image spent — G1 at the slot.
    let relisted = candidate_on(&chain, vec![listed_on(&chain, point_at(41)), recorded]);
    assert_refused(
        judge_on(&chain, relisted),
        CenRow::G1,
        Locus::Tx {
            slot: TxSlot::Listed(1),
        },
    );
    // Control: a *different* body spending the spent image (three outputs
    // where the recorded one has two, so a different identity) is not on
    // the chain — G1 passes it — and I7 refuses at the input, as before G1
    // existed. The two rows share a trigger and are told apart by this.
    let respent = candidate_on(
        &chain,
        vec![
            listed_on(&chain, point_at(41)),
            anchored_on(&chain, spend(point_at(40), 3)),
        ],
    );
    assert_refused(
        judge_on(&chain, respent),
        CenRow::I7,
        Locus::Input {
            slot: TxSlot::Listed(1),
            input: 0,
        },
    );
}

/// The intra-block arm's ordering twin: a spend listed twice is G1's at the
/// second slot, not L1's at the input — L1 runs after the loop.
#[test]
fn cen_g1_refuses_a_doubled_spend_before_l1_can() {
    let chain = spendable_chain();
    let body = listed_on(&chain, point_at(50));
    let mut block = candidate_on(&chain, vec![body.clone()]);
    block.transactions.push(body.clone());
    block.block.transaction_hashes.push(body.hash());
    assert_refused(
        judge_on(&chain, block),
        CenRow::G1,
        Locus::Tx {
            slot: TxSlot::Listed(1),
        },
    );
}

// --- CEN-G7 / G9 / G10 ---------------------------------------------------

/// A parseable serve-credit vin (the kept half, `RF-D1`) for `(P, shard, E)`.
fn serve_credit_vin(p: [u8; 32], shard_id: u64, settlement_epoch: u64) -> Input {
    let kept = ArchivalServeCreditResponse {
        p_canonical_id: p,
        shard_id,
        settlement_epoch,
        ed25519_countersignature: [0x5c; 64],
    };
    Input::ServeCredit {
        canonical_bytes: kept.serialize().expect("a kept half serializes"),
    }
}

/// A parseable emission vin for `p_pubkey` claiming `epochs` — the
/// `emission_wire` round-trip shape, one work claim and one amount per
/// epoch. `P_canonical_id` is derived from the pubkey by the rule, as the
/// C++ extractor does.
fn emission_vin(p_pubkey_fill: u8, epochs: &[u64]) -> Input {
    use shekyl_archival_retention::{
        ArchivalRewardEmissionVin, MembershipOnlyBacking, ShardWorkEntry, WorkEpochClaim,
    };
    let vin = ArchivalRewardEmissionVin {
        p_pubkey: vec![p_pubkey_fill; SINGLE_KEY_CANONICAL_LEN],
        holdings: HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::new(vec![7]).expect("one shard"),
        },
        settlement_epochs: epochs.to_vec(),
        work_claim: epochs
            .iter()
            .map(|&epoch| WorkEpochClaim {
                epoch,
                shard_entries: vec![ShardWorkEntry {
                    shard_id: 7,
                    serve_credit_bit: true,
                    scarcity_micro: 1_000,
                }],
            })
            .collect(),
        backing: MembershipOnlyBacking {
            proof: vec![0xee; 64],
            pseudo_out: [0x22; 32],
            backing_pubkey: vec![0xb2; SINGLE_KEY_CANONICAL_LEN],
            tree_depth: 3,
        },
        reward_amount_plain: epochs.iter().map(|_| 1_000_000).collect(),
        auth_backing: vec![0xc3; SINGLE_SIG_CANONICAL_LEN],
        auth_claim: vec![0xd4; SINGLE_SIG_CANONICAL_LEN],
    };
    Input::ArchivalRewardEmission {
        canonical_bytes: vin.serialize().expect("an emission vin serializes"),
    }
}

/// A bond post for the persona tagged `p`, of `kind` — the persona's key
/// and its recompute (CEN-J11's pair), so what G10 counts is a post the
/// form rows admit.
fn bond_post_vin(p: [u8; 32], kind: BondPostKind) -> Input {
    let who = fixture::persona(p);
    Input::BondPost(Box::new(BondPost {
        hybrid_public_key: who.identity,
        p_canonical_id: who.id,
        kind,
        holdings: Holdings::CompleteTree,
        bonded_total_atomic: 0,
        bond_credit: 0,
        bond_debit: 0,
    }))
}

/// A body carrying exactly `inputs`, distinct from every other by its
/// inputs alone — the archival rows read inputs and nothing else.
fn body_with(inputs: Vec<Input>) -> Transaction {
    let mut tx = listed([0x77; 32]);
    tx.prefix.inputs = inputs;
    tx
}

const P1: [u8; 32] = [0xa1; 32];
const P2: [u8; 32] = [0xa2; 32];

#[test]
fn cen_g7_a_repeated_serve_credit_key_is_refused_at_the_second_vin() {
    let chain = spendable_chain();
    // Two bodies; the second's second vin repeats (P1, 7, 11).
    let block = candidate_on(
        &chain,
        vec![
            body_with(vec![serve_credit_vin(P1, 7, 11)]),
            body_with(vec![
                serve_credit_vin(P1, 8, 11),
                serve_credit_vin(P1, 7, 11),
            ]),
        ],
    );
    assert_refused(
        check_alone_on::<G7>(&chain, &block),
        CenRow::G7,
        Locus::Input {
            slot: TxSlot::Listed(1),
            input: 1,
        },
    );
    // Distinct keys — another shard, another epoch, another P — pass.
    let block = candidate_on(
        &chain,
        vec![
            body_with(vec![serve_credit_vin(P1, 7, 11)]),
            body_with(vec![
                serve_credit_vin(P1, 8, 11),
                serve_credit_vin(P1, 7, 12),
                serve_credit_vin(P2, 7, 11),
            ]),
        ],
    );
    check_alone_on::<G7>(&chain, &block).expect("distinct (P, shard, E) keys pass G7");
}

#[test]
fn cen_g7_an_unparseable_vin_has_no_key_and_is_another_rows_refusal() {
    let chain = spendable_chain();
    let opaque = || Input::ServeCredit {
        canonical_bytes: vec![shekyl_wire::transaction::TAG_INPUT_SERVE_CREDIT, 0x52, 0x52],
    };
    // Two identical unparseable vins: not a G7 collision (CEN-J1's, pending).
    let block = candidate_on(
        &chain,
        vec![body_with(vec![opaque()]), body_with(vec![opaque()])],
    );
    check_alone_on::<G7>(&chain, &block).expect("no key, no collision");
}

#[test]
fn cen_g9_a_repeated_claim_pair_is_refused_and_the_admitted_pair_passes() {
    let chain = spendable_chain();
    // Two claims by one P for one epoch, from two bodies: refused at the
    // second body's vin.
    let block = candidate_on(
        &chain,
        vec![
            body_with(vec![emission_vin(0xa1, &[11, 12])]),
            body_with(vec![emission_vin(0xa1, &[12])]),
        ],
    );
    assert_refused(
        check_alone_on::<G9>(&chain, &block),
        CenRow::G9,
        Locus::Input {
            slot: TxSlot::Listed(1),
            input: 0,
        },
    );
    // **The admitted pair**: one P, two claims for *different* epochs — and
    // two Ps for one epoch — pass. Without this control the rule could be
    // satisfied by refusing every second claim.
    let block = candidate_on(
        &chain,
        vec![
            body_with(vec![emission_vin(0xa1, &[11])]),
            body_with(vec![emission_vin(0xa1, &[12])]),
            body_with(vec![emission_vin(0xa2, &[11])]),
        ],
    );
    check_alone_on::<G9>(&chain, &block).expect("distinct (P, E) pairs pass G9");
}

#[test]
fn cen_g10_two_bond_posts_for_one_p_are_refused_whatever_their_kinds() {
    let chain = spendable_chain();
    let join = || BondPostKind::JoinMarket {
        bond_spend_pk: vec![0xb3; SINGLE_KEY_CANONICAL_LEN],
        endpoint: [0xe0; shekyl_wire::transaction::BOND_POST_ENDPOINT_LEN],
    };
    // Mixed kinds — a JoinMarket and a Release for one P — still two posts.
    let block = candidate_on(
        &chain,
        vec![
            body_with(vec![bond_post_vin(P1, join())]),
            body_with(vec![
                bond_post_vin(P2, join()),
                bond_post_vin(P1, BondPostKind::Other(2)),
            ]),
        ],
    );
    assert_refused(
        check_alone_on::<G10>(&chain, &block),
        CenRow::G10,
        Locus::Input {
            slot: TxSlot::Listed(1),
            input: 1,
        },
    );
    // One post per P passes.
    let block = candidate_on(
        &chain,
        vec![
            body_with(vec![bond_post_vin(P1, join())]),
            body_with(vec![bond_post_vin(P2, BondPostKind::Other(2))]),
        ],
    );
    check_alone_on::<G10>(&chain, &block).expect("one bond post per P passes G10");
}

#[test]
fn the_archival_rows_are_vacuous_on_a_block_of_spends() {
    // The corpus's common case: no archival vin, three rows record and pass.
    let chain = spendable_chain();
    let block = candidate_on(&chain, vec![listed_on(&chain, point_at(60))]);
    for verdict in [
        check_alone_on::<G7>(&chain, &block),
        check_alone_on::<G9>(&chain, &block),
        check_alone_on::<G10>(&chain, &block),
    ] {
        verdict.expect("no archival vins: nothing to collide");
    }
}

#[test]
fn cen_g2_refuses_in_form_before_the_identity_is_derived() {
    // Through the stage: the refusal is the stage's verdict, and it is
    // G2's — B1/B2/B7 pass this header, and the coinbase rows pass its
    // coinbase, so nothing earlier in `judge_form!` claims it.
    let mut reordered = three_bodies();
    reordered.transactions.swap(0, 1);
    assert_refused(
        form_judges(reordered),
        CenRow::G2,
        Locus::Tx {
            slot: TxSlot::Listed(0),
        },
    );
}
