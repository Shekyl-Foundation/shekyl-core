// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.H fixtures (`CHAIN_RULES_SLICE_5.md` §5). Every implemented row
//! has a negative fixture asserting **the row at the slot judged** — the
//! pool's `TxSlot::Lone` directly through `tx_form`, and `TxSlot::Listed(n)`
//! through `validate` — and the scope mechanism is fixtured once here
//! rather than per row.

use super::*;
use crate::coverage::RuleCoverage;
use crate::harness::fixture::{candidate_on, coinbase, listed, serve_credit_only, G, TWO_G};
use crate::harness::{assert_refused, formed_on, judged, MockChain};
use crate::rule_set::RuleSet;
use crate::rules::TxKind;
use crate::trust::Trust;
use crate::validate::{tx_form, validate};
use crate::verdict::{Locus, TxSlot};
use shekyl_wire::{Ct, CtBase, Input, Transaction};

const KI: [u8; 32] = [0xC1; 32];

/// A refusal through `tx_form` at the pool's slot names the row and `Lone`.
fn refused_lone(tx: &Transaction, row: CenRow) {
    assert_refused(
        tx_form(tx, TxSlot::Lone, &RuleSet::GENESIS),
        row,
        Locus::Tx { slot: TxSlot::Lone },
    );
}

/// The same transaction listed first in a block is refused by `validate` on
/// the same row at `Listed(0)` — one function, two sites.
fn refused_listed(tx: &Transaction, row: CenRow) {
    let chain = MockChain::default();
    chain.with_view(|view| {
        let formed = formed_on(&chain, candidate_on(&chain, vec![tx.clone()]));
        assert_refused(
            judged(validate(
                formed,
                &view,
                &RuleSet::GENESIS,
                &Trust::UNANCHORED,
            )),
            row,
            Locus::Tx {
                slot: TxSlot::Listed(0),
            },
        );
    });
}

// ---- the class ----------------------------------------------------------

/// The kind is the slot's, not the bytes': a coinbase-shaped transaction in
/// a listed or lone slot is judged as a non-coinbase transaction (Q2 as
/// amended), and the miner slot is the coinbase whatever it carries. This is
/// the fixture for the principle on [`TxKind`]: the input does not select
/// the rules it is judged under.
#[test]
fn the_kind_is_derived_from_the_slot_not_the_bytes() {
    assert_eq!(TxKind::of(TxSlot::Miner), TxKind::Coinbase);
    assert_eq!(TxKind::of(TxSlot::Lone), TxKind::Listed);
    assert_eq!(TxKind::of(TxSlot::Listed(3)), TxKind::Listed);
    let coinbase_shaped = coinbase(1);
    assert!(coinbase_shaped.is_coinbase());
    // And judged as one: a lone sole-`gen` transaction is H5's refusal, not
    // a coinbase.
    let mut coverage = RuleCoverage::EMPTY;
    assert_refused(
        TxContext::derive(&coinbase_shaped, TxSlot::Lone, &mut coverage).map(|cx| cx.kind),
        CenRow::H5,
        Locus::Tx { slot: TxSlot::Lone },
    );
    let spend_tx = listed(KI);
    let cx = TxContext::derive(&spend_tx, TxSlot::Lone, &mut coverage).expect("a spend");
    assert_eq!(cx.kind, TxKind::Listed);
    assert_eq!(cx.locus(), Locus::Tx { slot: TxSlot::Lone });
}

/// A `NonCoinbase` row is recorded **vacuous** at the miner slot — in the
/// coverage, not run — and run everywhere else. The coinbase fixture has
/// one input, so H4 cannot tell the two apart by its verdict; the
/// difference shows on a coinbase with no inputs: refused as a listed
/// transaction, passed (vacuous) as the miner.
#[test]
fn a_non_coinbase_row_is_vacuous_at_the_miner_slot_and_run_elsewhere() {
    let mut no_inputs = coinbase(1);
    no_inputs.prefix.inputs.clear();
    // Vacuous at the miner slot: H4 does not run, and is recorded.
    let form = tx_form(&no_inputs, TxSlot::Miner, &RuleSet::GENESIS).expect("vacuous");
    assert!(form.contains(CenRow::H4));
    // Run at the pool's slot.
    refused_lone(&no_inputs, CenRow::H4);
}

/// Every listed slot records what it evaluated, and `validate` unions the
/// per-slot coverages: with H4 landed, a block of two well-formed listed
/// transactions carries H4 once.
#[test]
fn tx_form_coverage_is_unioned_per_slot_by_validate() {
    let chain = MockChain::default();
    chain.with_view(|view| {
        let formed = formed_on(
            &chain,
            candidate_on(&chain, vec![listed(KI), listed([0xC2; 32])]),
        );
        let valid = judged(validate(
            formed,
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .expect("two well-formed listed transactions connect");
        assert!(valid.coverage().contains(CenRow::H4));
    });
}

// ---- the limits: pinned to the C++ defines, held equal to the wire's ----

/// The integer a `#define NAME value` line in `cryptonote_config.h` carries.
/// Read from the header itself, not from a copy of the number, so a C++
/// edit that moves a limit fails here rather than diverging silently (the
/// slice-4 Q5 pin shape).
fn cxx_define(name: &str) -> u64 {
    let config_h = include_str!("../../../../src/cryptonote_config.h");
    let line = config_h
        .lines()
        .find(|l| {
            let mut words = l.split_whitespace();
            words.next() == Some("#define") && words.next() == Some(name)
        })
        .unwrap_or_else(|| panic!("cryptonote_config.h defines {name}"));
    line.split_whitespace()
        .nth(2)
        .expect("the define carries a value")
        .parse()
        .unwrap_or_else(|_| panic!("{name}'s value is an integer"))
}

/// The one define that is an alias: `CRYPTONOTE_MAX_BLOCK_HEIGHT_SENTINEL`
/// names `CRYPTONOTE_MAX_BLOCK_NUMBER`, so the sentinel pins to the latter
/// and this asserts the alias still holds.
#[test]
fn the_limits_are_the_cxx_defines() {
    assert_eq!(cxx_define("CRYPTONOTE_MAX_TX_SIZE"), MAX_TX_SIZE as u64);
    assert_eq!(
        cxx_define("CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE"),
        COINBASE_BLOB_RESERVED as u64
    );
    assert_eq!(
        cxx_define("CRYPTONOTE_MAX_BLOCK_NUMBER"),
        UNLOCK_TIME_SENTINEL
    );
    let config_h = include_str!("../../../../src/cryptonote_config.h");
    assert!(
        config_h.lines().any(|l| {
            let mut w = l.split_whitespace();
            w.next() == Some("#define")
                && w.next() == Some("CRYPTONOTE_MAX_BLOCK_HEIGHT_SENTINEL")
                && w.next() == Some("CRYPTONOTE_MAX_BLOCK_NUMBER")
        }),
        "the sentinel is still the alias of CRYPTONOTE_MAX_BLOCK_NUMBER"
    );
}

/// H3's limit is derived, never restated: the formula is
/// `get_transaction_weight_limit`'s, its operands are the generated
/// full-reward zone and the coinbase reserve, and the shipped value is
/// what the census pins.
#[test]
fn the_weight_limit_is_derived_from_the_zone_and_the_reserve() {
    assert_eq!(
        max_tx_weight(),
        (FULL_REWARD_ZONE / 2) as usize - COINBASE_BLOB_RESERVED
    );
    assert_eq!(max_tx_weight(), 149_400, "the shipped limit (census H3)");
}

/// The codec's DoS bounds and the consensus limits are the same numbers —
/// held equal by this test, not by a comment (Q5 as ruled). The rule's
/// source is the C++ define (above), never the codec.
#[test]
fn the_limits_equal_the_wire_crates_bounds() {
    assert_eq!(MAX_TX_SIZE, shekyl_wire::transaction::MAX_TX_SIZE);
    assert_eq!(
        UNLOCK_TIME_SENTINEL,
        shekyl_wire::transaction::UNLOCK_TIME_BLOCK_SENTINEL
    );
}

/// `listed(KI)` with its `extra` sized so the serialized transaction is
/// exactly `target` bytes long. The varint that prefixes `extra` grows with
/// its length, so the size is solved for rather than assumed.
fn listed_serialized_to(target: usize) -> Transaction {
    let mut tx = listed(KI);
    let base = tx.serialized_len();
    assert!(target > base, "the fixture already exceeds {target}");
    // First guess ignores the varint growth; then adjust by the difference.
    let mut extra_len = target - base;
    loop {
        tx.prefix.extra = vec![0xEE; extra_len];
        let len = tx.serialized_len();
        if len == target {
            return tx;
        }
        assert!(len > target, "monotone: growing extra never shrinks the tx");
        extra_len -= len - target;
    }
}

// ---- CEN-H1 -------------------------------------------------------------

/// Boundary: a transaction of exactly `MAX_TX_SIZE` bytes passes H1; one
/// byte more is refused on it. The inclusive edge is asserted on the rule
/// alone — through `tx_form` a megabyte transaction is refused by H3
/// (149 400) whatever H1 says, in the C++'s order too — and the refusal
/// side through `tx_form` at both sites names H1, which runs first.
#[test]
fn h1_the_size_limit_is_inclusive() {
    crate::harness::boundary_pair(
        listed_serialized_to(MAX_TX_SIZE),
        listed_serialized_to(MAX_TX_SIZE + 1),
        CenRow::H1,
        Locus::Tx { slot: TxSlot::Lone },
        |tx| {
            let mut coverage = RuleCoverage::EMPTY;
            let cx = TxContext::derive(&tx, TxSlot::Lone, &mut coverage)?;
            H1::check(&cx)
        },
    );
    refused_lone(&listed_serialized_to(MAX_TX_SIZE + 1), CenRow::H1);
    refused_listed(&listed_serialized_to(MAX_TX_SIZE + 1), CenRow::H1);
}

// ---- CEN-H3 -------------------------------------------------------------

/// Boundary: a transaction of exactly `max_tx_weight()` passes; one more
/// is refused on H3. With no prunable region weight equals size, so the
/// size fixture serves.
#[test]
fn h3_the_weight_limit_is_inclusive() {
    let at = listed_serialized_to(max_tx_weight());
    assert_eq!(at.weight(), max_tx_weight());
    crate::harness::boundary_pair(
        at,
        listed_serialized_to(max_tx_weight() + 1),
        CenRow::H3,
        Locus::Tx { slot: TxSlot::Lone },
        |tx| tx_form(&tx, TxSlot::Lone, &RuleSet::GENESIS),
    );
    refused_listed(&listed_serialized_to(max_tx_weight() + 1), CenRow::H3);
}

/// H1 and H3 are non-coinbase rows: an oversized coinbase is not theirs to
/// refuse (the block bounds it), and both are recorded vacuous at the
/// miner slot.
#[test]
fn h1_and_h3_are_vacuous_at_the_miner_slot() {
    let mut huge = coinbase(1);
    huge.prefix.extra = vec![0xEE; MAX_TX_SIZE + 1];
    let form = tx_form(&huge, TxSlot::Miner, &RuleSet::GENESIS).expect("vacuous");
    assert!(form.contains(CenRow::H1) && form.contains(CenRow::H3));
}

// ---- CEN-H16 ------------------------------------------------------------

/// Boundary: `unlock_time` one below the sentinel is a height and passes;
/// the sentinel itself is a timestamp and is refused on H16 — at the pool's
/// slot and listed. At the miner slot the row is vacuous: the C++ reaches
/// `check_tx_outputs` from the non-input path only, and the coinbase's
/// unlock time is F6's.
#[test]
fn h16_the_sentinel_is_the_first_refused_unlock_time() {
    let unlocking_at = |t: u64| {
        let mut tx = listed(KI);
        tx.prefix.unlock_time = t;
        tx
    };
    crate::harness::boundary_pair(
        unlocking_at(UNLOCK_TIME_SENTINEL - 1),
        unlocking_at(UNLOCK_TIME_SENTINEL),
        CenRow::H16,
        Locus::Tx { slot: TxSlot::Lone },
        |tx| tx_form(&tx, TxSlot::Lone, &RuleSet::GENESIS),
    );
    refused_listed(&unlocking_at(UNLOCK_TIME_SENTINEL), CenRow::H16);
    let mut miner = coinbase(1);
    miner.prefix.unlock_time = UNLOCK_TIME_SENTINEL;
    let form = tx_form(&miner, TxSlot::Miner, &RuleSet::GENESIS).expect("vacuous on the coinbase");
    assert!(form.contains(CenRow::H16));
}

// ---- CEN-H9 -------------------------------------------------------------

/// Two outputs whose amounts sum past `u64::MAX` are refused on H9 — as a
/// listed transaction at both sites, and at the miner slot (the C++ runs
/// `check_outs_overflow` on the coinbase; F7 judges the same sum under its
/// own row in `form`, so the miner-slot case is asserted on the rule alone).
#[test]
fn h9_output_amounts_that_overflow_are_refused_everywhere() {
    let overflowing = |mut tx: Transaction| {
        let second = tx.prefix.outputs[0].clone();
        tx.prefix.outputs.push(second);
        tx.prefix.outputs[0].amount = u64::MAX;
        tx.prefix.outputs[1].amount = 1;
        tx
    };
    // A listed emission, so H14 does not refuse the loud amounts first.
    let emission_tx = overflowing(with_inputs(vec![emission()]));
    refused_lone(&emission_tx, CenRow::H9);
    refused_listed(&emission_tx, CenRow::H9);
    let miner = overflowing(coinbase(1));
    let mut coverage = RuleCoverage::EMPTY;
    let cx = TxContext::derive(&miner, TxSlot::Miner, &mut coverage).expect("the coinbase");
    assert_refused(
        H9::check(&cx),
        CenRow::H9,
        Locus::Tx {
            slot: TxSlot::Miner,
        },
    );
}

// ---- CEN-H14 ------------------------------------------------------------

/// A non-zero output amount is refused on H14 for every non-coinbase shape
/// but the emission, whose loud vouts pass; the coinbase's amounts are
/// 4.F's (vacuous at the miner slot).
#[test]
fn h14_loud_amounts_are_refused_except_on_an_emission() {
    let loud = |mut tx: Transaction| {
        tx.prefix.outputs[0].amount = 5;
        tx
    };
    refused_lone(&loud(listed(KI)), CenRow::H14);
    refused_listed(&loud(listed(KI)), CenRow::H14);
    refused_lone(&loud(with_inputs(vec![bond_post(), spend(1)])), CenRow::H14);
    let emission_tx = loud(with_inputs(vec![emission()]));
    assert!(tx_form(&emission_tx, TxSlot::Lone, &RuleSet::GENESIS)
        .expect("a loud emission passes H14")
        .contains(CenRow::H14));
    let form = tx_form(&loud(coinbase(1)), TxSlot::Miner, &RuleSet::GENESIS).expect("vacuous");
    assert!(form.contains(CenRow::H14));
}

// ---- the classification, CEN-H5 and CEN-H6 -----------------------------

/// Archival input fixtures. The class reads the variant, never the
/// contents, so these carry the minimum the type requires.
fn serve_credit() -> Input {
    Input::ServeCredit {
        canonical_bytes: Vec::new(),
    }
}

fn emission() -> Input {
    Input::ArchivalRewardEmission {
        canonical_bytes: Vec::new(),
    }
}

fn bond_post() -> Input {
    use shekyl_wire::{BondPost, BondPostKind, Holdings};
    Input::BondPost(Box::new(BondPost {
        hybrid_public_key: Vec::new(),
        p_canonical_id: shekyl_types::PCanonicalId::from_bytes([0xB0; 32]),
        kind: BondPostKind::Other(2),
        holdings: Holdings::CompleteTree,
        bonded_total_atomic: 0,
        bond_credit: 0,
        bond_debit: 0,
    }))
}

fn spend(fill: u8) -> Input {
    Input::ToKey {
        amount: 0,
        key_offsets: Vec::new(),
        key_image: [fill; 32],
    }
}

/// `listed(KI)` with its inputs replaced.
fn with_inputs(inputs: Vec<Input>) -> Transaction {
    let mut tx = listed(KI);
    tx.prefix.inputs = inputs;
    tx
}

/// The class a lone transaction with `inputs` derives to, or the refusal.
fn class_of(inputs: Vec<Input>) -> Verdict<TxClass> {
    let mut coverage = RuleCoverage::EMPTY;
    TxContext::derive(&with_inputs(inputs), TxSlot::Lone, &mut coverage).map(|cx| cx.class)
}

/// The four non-coinbase shapes, each with its indices and counts, and the
/// empty vector (H4's, classified totally as a spend of nothing).
#[test]
fn the_classification_names_the_four_shapes_and_the_coinbase() {
    assert_eq!(
        class_of(vec![spend(1), spend(2)]),
        Ok(TxClass::Spend { spends: 2 })
    );
    assert_eq!(class_of(Vec::new()), Ok(TxClass::Spend { spends: 0 }));
    assert_eq!(
        class_of(vec![serve_credit(), serve_credit()]),
        Ok(TxClass::ServeCreditOnly { credits: 2 })
    );
    assert_eq!(
        class_of(vec![spend(1), bond_post(), spend(2)]),
        Ok(TxClass::BondPost { post: 1, spends: 2 })
    );
    assert_eq!(
        class_of(vec![emission()]),
        Ok(TxClass::Emission { at: 0, spends: 0 })
    );
    assert_eq!(
        class_of(vec![spend(1), emission()]),
        Ok(TxClass::Emission { at: 1, spends: 1 })
    );
    let mut coverage = RuleCoverage::EMPTY;
    let miner = coinbase(1);
    let cx = TxContext::derive(&miner, TxSlot::Miner, &mut coverage).expect("the coinbase");
    assert_eq!(cx.class, TxClass::Coinbase);
    assert!(coverage.contains(CenRow::H5) && coverage.contains(CenRow::H6));
}

/// CEN-H5, the `gen` half: a `gen` input anywhere but the coinbase position
/// is refused — alone, mixed, listed — and the coinbase position accepts
/// its own.
#[test]
fn h5_gen_is_refused_outside_the_coinbase_position() {
    assert_refused(
        class_of(vec![Input::Gen(1)]),
        CenRow::H5,
        Locus::Tx { slot: TxSlot::Lone },
    );
    assert_refused(
        class_of(vec![spend(1), Input::Gen(1)]),
        CenRow::H5,
        Locus::Tx { slot: TxSlot::Lone },
    );
    refused_lone(&with_inputs(vec![Input::Gen(1)]), CenRow::H5);
    // A coinbase-shaped transaction *listed in a block* is refused as H5 at
    // its listed slot: the fixture for the slot-derived kind.
    refused_listed(&coinbase(1), CenRow::H5);
    // A `gen` mixed into the miner slot is not a coinbase either; F1 refuses
    // it in `form`, and were it to reach here it is H5's, totally.
    let mut coverage = RuleCoverage::EMPTY;
    let mixed_miner = with_inputs(vec![Input::Gen(1), spend(1)]);
    assert_refused(
        TxContext::derive(&mixed_miner, TxSlot::Miner, &mut coverage).map(|cx| cx.class),
        CenRow::H5,
        Locus::Tx {
            slot: TxSlot::Miner,
        },
    );
}

/// CEN-H6: each of the C++'s four mixings, refused; and the permitted
/// co-residencies (spends beside a bond post, spends beside an emission)
/// pass.
#[test]
fn h6_the_archival_mixings_are_refused_and_the_permitted_ones_pass() {
    let lone = Locus::Tx { slot: TxSlot::Lone };
    // Serve credits mix with nothing.
    assert_refused(class_of(vec![serve_credit(), spend(1)]), CenRow::H6, lone);
    assert_refused(
        class_of(vec![serve_credit(), bond_post()]),
        CenRow::H6,
        lone,
    );
    assert_refused(class_of(vec![serve_credit(), emission()]), CenRow::H6, lone);
    // At most one bond post; at most one emission.
    assert_refused(class_of(vec![bond_post(), bond_post()]), CenRow::H6, lone);
    assert_refused(class_of(vec![emission(), emission()]), CenRow::H6, lone);
    // Emission and bond post never co-reside.
    assert_refused(class_of(vec![emission(), bond_post()]), CenRow::H6, lone);
    // Through both sites.
    refused_lone(&with_inputs(vec![serve_credit(), spend(1)]), CenRow::H6);
    refused_listed(&with_inputs(vec![serve_credit(), spend(1)]), CenRow::H6);
    // Permitted.
    assert!(class_of(vec![bond_post(), spend(1), spend(2)]).is_ok());
    assert!(class_of(vec![emission(), spend(1)]).is_ok());
}

// ---- CEN-H4 -------------------------------------------------------------

/// Refusal fixture: a non-coinbase transaction with no inputs, at both
/// sites.
#[test]
fn h4_a_listed_transaction_with_no_inputs_is_refused() {
    let mut tx = listed(KI);
    tx.prefix.inputs.clear();
    refused_lone(&tx, CenRow::H4);
    refused_listed(&tx, CenRow::H4);
}

/// The well-formed listed fixture passes every landed row at the pool's slot
/// and records them all.
#[test]
fn a_well_formed_listed_transaction_records_every_landed_row() {
    let form = tx_form(&listed(KI), TxSlot::Lone, &RuleSet::GENESIS).expect("passes");
    assert_eq!(
        form.iter().collect::<Vec<_>>(),
        [
            CenRow::H1,
            CenRow::H3,
            CenRow::H4,
            CenRow::H5,
            CenRow::H6,
            CenRow::H9,
            CenRow::H10,
            CenRow::H14,
            CenRow::H15,
            CenRow::H16,
            CenRow::H20
        ]
    );
}

// ---- CEN-H10 ------------------------------------------------------------

/// Two `ToKey` inputs with the same key image are refused on H10; two
/// distinct ones pass. (I5's ordering — slice 6 — would refuse the same
/// pair; this is the inherited belt on its own.)
#[test]
fn h10_a_repeated_key_image_within_one_transaction_is_refused() {
    let dup = with_inputs(vec![spend(0x33), spend(0x33)]);
    refused_lone(&dup, CenRow::H10);
    refused_listed(&dup, CenRow::H10);
    // Two pseudo-outs for two spends, so the layout/pseudo-out shapes are
    // not what refuses here.
    let mut distinct = with_inputs(vec![spend(0x44), spend(0x33)]);
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut distinct.ct
    {
        p.pseudo_outs.push(TWO_G);
    }
    assert!(tx_form(&distinct, TxSlot::Lone, &RuleSet::GENESIS)
        .expect("distinct key images pass")
        .contains(CenRow::H10));
}

// ---- CEN-H15 (the Null half) --------------------------------------------

/// A non-coinbase transaction with a `Null` CT is refused on H15 at both
/// sites — including on what would be a Fakechain node (Q9: unconditional,
/// where the C++ gates the check on `m_nettype != FAKECHAIN`). At the miner
/// slot `Null` is the coinbase's CT (F3) and the row is vacuous.
#[test]
fn h15_a_null_ct_outside_the_coinbase_is_refused() {
    let mut tx = listed(KI);
    tx.ct = Ct::Null(CtBase {
        enc_amounts: vec![[0x11; 9]],
        enc_labels: vec![[0x22; 9]],
        commitments: vec![TWO_G],
    });
    refused_lone(&tx, CenRow::H15);
    refused_listed(&tx, CenRow::H15);
    let form = tx_form(&coinbase(1), TxSlot::Miner, &RuleSet::GENESIS).expect("the coinbase");
    assert!(form.contains(CenRow::H15));
}

// ---- CEN-H19 (the layout half) ------------------------------------------

/// The layout predicate on its own: one proof with `|L| = |R|` rounds
/// where `2^(|L|−6)` is the smallest power of two at or above the output
/// count; no proof only for no outputs; never two proofs; rounds within
/// `6..=10`.
#[test]
fn h19_the_canonical_layout_is_one_proof_sized_to_the_outputs() {
    use crate::harness::fixture::bp_plus_layout_for;
    use shekyl_wire::Prunable;
    let with = |proofs: Vec<shekyl_wire::BpPlus>| Prunable {
        bulletproofs: proofs,
        tree_depth: 0,
        fcmp_proof: vec![0xF0],
        pseudo_outs: vec![TWO_G],
        serve_credit_pruned: Vec::new(),
    };
    // Exact fits and the padded ranges: 1 → 6 rounds; 2 → 7; 3, 4 → 8;
    // 5..=8 → 9; 9..=16 → 10.
    for (n_out, rounds) in [
        (1, 6),
        (2, 7),
        (3, 8),
        (4, 8),
        (5, 9),
        (8, 9),
        (9, 10),
        (16, 10),
    ] {
        let bp = bp_plus_layout_for(n_out);
        assert_eq!(bp.l.len(), rounds, "{n_out} outputs");
        assert!(H19Layout::canonical(Some(&with(vec![bp])), n_out));
    }
    // Too many rounds for the count (a 2-output proof for 1 output), too few
    // (a 1-output proof for 2), rounds out of range, two proofs, `|L| != |R|`.
    assert!(!H19Layout::canonical(
        Some(&with(vec![bp_plus_layout_for(2)])),
        1
    ));
    assert!(!H19Layout::canonical(
        Some(&with(vec![bp_plus_layout_for(1)])),
        2
    ));
    let mut eleven = bp_plus_layout_for(16);
    eleven.l.push([0; 32]);
    eleven.r.push([0; 32]);
    assert!(!H19Layout::canonical(Some(&with(vec![eleven])), 16));
    let mut five = bp_plus_layout_for(1);
    five.l.pop();
    five.r.pop();
    assert!(!H19Layout::canonical(Some(&with(vec![five])), 1));
    assert!(!H19Layout::canonical(
        Some(&with(vec![bp_plus_layout_for(1), bp_plus_layout_for(1)])),
        1
    ));
    let mut lopsided = bp_plus_layout_for(1);
    lopsided.r.push([0; 32]);
    assert!(!H19Layout::canonical(Some(&with(vec![lopsided])), 1));
    // No proof: canonical only for no outputs.
    assert!(H19Layout::canonical(None, 0));
    assert!(!H19Layout::canonical(None, 1));
    assert!(H19Layout::canonical(Some(&with(Vec::new())), 0));
}

/// Through `tx_form`: a spend whose proof is sized for two outputs but
/// carries one is refused under H19 — a refusal on a row the registry still
/// holds `pending` (its verification half is slice 6's), so the row is not
/// in any passing coverage.
#[test]
fn h19_a_non_canonical_layout_is_refused_and_the_row_is_not_yet_recorded() {
    use crate::harness::fixture::bp_plus_layout_for;
    let mut tx = listed(KI);
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut tx.ct
    {
        p.bulletproofs = vec![bp_plus_layout_for(2)];
    }
    refused_lone(&tx, CenRow::H19);
    refused_listed(&tx, CenRow::H19);
    assert!(!tx_form(&listed(KI), TxSlot::Lone, &RuleSet::GENESIS)
        .expect("the fixture")
        .contains(CenRow::H19));
}

// ---- CEN-H20 ------------------------------------------------------------

/// Each departure from the serve-credit-only shape is refused on H20: a fee,
/// a `pqc_auth`, an output (with its mask), spend material in the prunable
/// region, a `Null` CT (that one is H15's first — the class is derived from
/// the inputs, the CT type is H15's). The fixture shape passes and the row
/// is vacuous on a spend.
#[test]
fn h20_every_departure_from_the_serve_credit_shape_is_refused() {
    use shekyl_wire::{PqcAuth, Prunable};
    let base = || serve_credit_only([0x77; 32]);
    let mutate = |f: &dyn Fn(&mut Transaction)| {
        let mut tx = base();
        f(&mut tx);
        tx
    };
    let fee = mutate(&|tx| {
        if let Ct::Fcmp { fee, .. } = &mut tx.ct {
            *fee = 1;
        }
    });
    refused_lone(&fee, CenRow::H20);
    refused_listed(&fee, CenRow::H20);
    let auth = mutate(&|tx| {
        if let Ct::Fcmp { pqc_auths, .. } = &mut tx.ct {
            pqc_auths.push(PqcAuth {
                auth_version: 1,
                scheme_id: 1,
                flags: 0,
                hybrid_public_key: Vec::new(),
                hybrid_signature: Vec::new(),
            });
        }
    });
    refused_lone(&auth, CenRow::H20);
    let output = mutate(&|tx| {
        tx.prefix.outputs.push(shekyl_wire::Output {
            amount: 0,
            key: G,
            view_tag: 1,
        });
        if let Ct::Fcmp { base, .. } = &mut tx.ct {
            base.commitments.push(TWO_G);
            base.enc_amounts.push([0; 9]);
            base.enc_labels.push([0; 9]);
        }
    });
    refused_lone(&output, CenRow::H20);
    let spend_material = mutate(&|tx| {
        if let Ct::Fcmp { prunable, .. } = &mut tx.ct {
            *prunable = Some(Prunable {
                bulletproofs: Vec::new(),
                tree_depth: 0,
                fcmp_proof: vec![0xF0],
                pseudo_outs: Vec::new(),
                serve_credit_pruned: Vec::new(),
            });
        }
    });
    refused_lone(&spend_material, CenRow::H20);
    // A prunable region holding only pass records (RF-D1's shape) is not
    // spend material.
    let pass_records = mutate(&|tx| {
        if let Ct::Fcmp { prunable, .. } = &mut tx.ct {
            *prunable = Some(Prunable {
                bulletproofs: Vec::new(),
                tree_depth: 0,
                fcmp_proof: Vec::new(),
                pseudo_outs: Vec::new(),
                serve_credit_pruned: vec![vec![0x01, 0x02]],
            });
        }
    });
    assert!(tx_form(&pass_records, TxSlot::Lone, &RuleSet::GENESIS)
        .expect("pass records are not spend material")
        .contains(CenRow::H20));
    assert!(tx_form(&listed(KI), TxSlot::Lone, &RuleSet::GENESIS)
        .expect("a spend")
        .contains(CenRow::H20));
}
