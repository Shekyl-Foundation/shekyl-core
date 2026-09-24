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
use crate::harness::fixture::{candidate_on, coinbase, listed, point, serve_credit_only, G, TWO_G};
use crate::harness::{assert_refused, credited_to_this_falsifier, formed_on, judged, MockChain};
use crate::rule_set::RuleSet;
use crate::rules::TxKind;
use crate::trust::Trust;
use crate::validate::{tx_form, validate};
use crate::verdict::{Locus, TxSlot};
use shekyl_wire::{Ct, CtBase, Input, Transaction};

#[path = "tx_balance_tests.rs"]
mod tx_balance_tests;

/// The fixture spend's key image: a table point (CEN-H11 holds an image
/// to pointness) at an index the keys and masks do not use.
const KI: [u8; 32] = point(9);

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
            candidate_on(&chain, vec![listed(KI), listed(point(10))]),
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

/// The input side of H9 (`check_inputs_overflow`): two `ToKey` inputs whose
/// `amount`s sum past `u64::MAX` are refused at both sites, and only the
/// `ToKey` amounts count — a boundary pair at exactly `u64::MAX` passes the
/// rule, and an emission vin beside a `u64::MAX` spend adds nothing to the
/// sum. `ToKey.amount` carries no meaning under FCMP++, which is why the wire
/// admits any value in it and why the C++ still sums it (review of #839).
#[test]
fn h9_input_amounts_that_overflow_are_refused_everywhere() {
    let with_amounts = |amounts: &[u64]| {
        let mut tx = with_inputs(vec![spend(9), spend(10)]);
        for (input, amount) in tx.prefix.inputs.iter_mut().zip(amounts) {
            if let Input::ToKey { amount: a, .. } = input {
                *a = *amount;
            }
        }
        tx
    };
    let overflowing = with_amounts(&[u64::MAX, 1]);
    refused_lone(&overflowing, CenRow::H9);
    refused_listed(&overflowing, CenRow::H9);
    // The boundary and the exemption, on the rule alone: H9 is the only
    // subject here, and the fixture's second input has no auth or pseudo-out.
    let mut coverage = RuleCoverage::EMPTY;
    let at_max = with_amounts(&[u64::MAX, 0]);
    let cx = TxContext::derive(&at_max, TxSlot::Lone, &mut coverage).expect("a spend");
    H9::check(&cx).expect("u64::MAX exactly is not an overflow");
    let mut beside_an_emission = with_inputs(vec![spend(9), emission()]);
    if let Some(Input::ToKey { amount, .. }) = beside_an_emission.prefix.inputs.get_mut(0) {
        *amount = u64::MAX;
    }
    let cx = TxContext::derive(&beside_an_emission, TxSlot::Lone, &mut coverage)
        .expect("an emission with one fee spend");
    H9::check(&cx).expect("an archival vin adds nothing to the input sum");
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
    refused_lone(
        &loud(with_inputs(vec![bond_post(), spend(11)])),
        CenRow::H14,
    );
    // A loud emission passes H14 — asserted on the rule alone, since the
    // whole form also needs H22's balance. **Coupled to
    // `balanced_bond_post_and_emission_fixtures_pass`**, which is what
    // shows H14 is *wired* for an emission through `tx_form` (the loud case
    // differs only in amount visibility, not in dispatch); narrow or delete
    // that test and this one silently becomes a unit test on `H14::check`
    // with no evidence the rule runs.
    let emission_tx = loud(with_inputs(vec![emission()]));
    let mut coverage = RuleCoverage::EMPTY;
    let cx = TxContext::derive(&emission_tx, TxSlot::Lone, &mut coverage).expect("an emission");
    assert!(H14::check(&cx).is_ok(), "a loud emission passes H14");
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

/// A spend input whose key image is the `k`-th table point.
fn spend(k: usize) -> Input {
    Input::ToKey {
        amount: 0,
        key_offsets: Vec::new(),
        key_image: point(k),
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
        class_of(vec![spend(11), spend(12)]),
        Ok(TxClass::Spend { spends: 2 })
    );
    assert_eq!(class_of(Vec::new()), Ok(TxClass::Spend { spends: 0 }));
    assert_eq!(
        class_of(vec![serve_credit(), serve_credit()]),
        Ok(TxClass::ServeCreditOnly { credits: 2 })
    );
    assert_eq!(
        class_of(vec![spend(11), bond_post(), spend(12)]),
        Ok(TxClass::BondPost {
            spends: 2,
            credit: 0,
            debit: 0
        })
    );
    let mut credited = bond_post();
    if let Input::BondPost(bond) = &mut credited {
        bond.bond_credit = 7;
    }
    assert_eq!(
        class_of(vec![spend(11), credited]),
        Ok(TxClass::BondPost {
            spends: 1,
            credit: 7,
            debit: 0
        })
    );
    assert_eq!(
        class_of(vec![emission()]),
        Ok(TxClass::Emission { spends: 0 })
    );
    assert_eq!(
        class_of(vec![spend(11), emission()]),
        Ok(TxClass::Emission { spends: 1 })
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
        class_of(vec![spend(11), Input::Gen(1)]),
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
    let mixed_miner = with_inputs(vec![Input::Gen(1), spend(11)]);
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
    assert_refused(class_of(vec![serve_credit(), spend(11)]), CenRow::H6, lone);
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
    refused_lone(&with_inputs(vec![serve_credit(), spend(11)]), CenRow::H6);
    refused_listed(&with_inputs(vec![serve_credit(), spend(11)]), CenRow::H6);
    // Permitted.
    assert!(class_of(vec![bond_post(), spend(11), spend(12)]).is_ok());
    assert!(class_of(vec![emission(), spend(11)]).is_ok());
}

// ---- the rows that hold by construction (Q4, Q6, Q7) --------------------

/// CEN-H8's falsifier: the wire reads exactly one commitment per output —
/// `CtBase::read` takes the count from the prefix's `vout` and reads that
/// many, so a transaction whose committed base has a different number of
/// masks than outputs **cannot be parsed**: its serialization either leaves
/// bytes the reader misinterprets or runs short. (`check_commitment_masks`'s
/// arity gate, which H17 runs, holds the same for a hand-built value that
/// never went through the parser.) If the wire ever carried its own count
/// for the committed base, this would decode and H8 would need a rule.
#[test]
fn h8_the_wire_reads_one_commitment_per_output() {
    credited_to_this_falsifier(&[CenRow::H8], "h8_the_wire_reads_one_commitment_per_output");
    let mut two_masks = listed(KI);
    if let Ct::Fcmp { base, .. } = &mut two_masks.ct {
        base.commitments.push(TWO_G);
        base.enc_amounts.push([0; 9]);
        base.enc_labels.push([0; 9]);
    }
    assert_eq!(two_masks.prefix.outputs.len(), 2);
    assert!(
        Transaction::from_bytes(&two_masks.serialize()).is_err(),
        "three masks over two outputs must not round-trip"
    );
    let mut no_masks = listed(KI);
    if let Ct::Fcmp { base, .. } = &mut no_masks.ct {
        base.commitments.clear();
        base.enc_amounts.clear();
        base.enc_labels.clear();
    }
    assert!(
        Transaction::from_bytes(&no_masks.serialize()).is_err(),
        "no mask over two outputs must not round-trip"
    );
    assert!(Transaction::from_bytes(&listed(KI).serialize()).is_ok());
}

/// CEN-H24's falsifier (slice 5 Q7), **flipped at slice 6 commit 2**. The
/// residue check — a relative `key_offset` after the first must not be
/// `0` — has nothing to read on the empty offset list CEN-I6 admits, and
/// it fires on the list I6 forbids.
///
/// H24 is bucket 3: no registry row, no coverage. The census cell and this
/// test are what index it. Until I6 landed, `tx_form` accepted the offsets
/// fixture and this test held the gap open with an `expect`; the day a row
/// refused it, the assertion was to become that row's refusal. That day is
/// this commit: the fixture is refused on **I6**, at both sites, and H24's
/// residue arm has no input left to read on a transaction the validator
/// admits.
#[test]
fn h24_cannot_fire_on_an_input_i6_admits() {
    let residue_fires = |offsets: &[u64]| offsets.iter().skip(1).any(|&o| o == 0);
    assert!(
        !residue_fires(&[]),
        "CEN-H24 has nothing to read on empty offsets"
    );
    assert!(
        residue_fires(&[7, 0]),
        "CEN-H24 fires on a zero relative offset"
    );
    let mut with_offsets = listed(KI);
    if let Some(Input::ToKey { key_offsets, .. }) = with_offsets.prefix.inputs.get_mut(0) {
        *key_offsets = vec![7, 0];
    }
    refused_lone(&with_offsets, CenRow::I6);
    refused_listed(&with_offsets, CenRow::I6);
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
            CenRow::H7,
            CenRow::H9,
            CenRow::H10,
            CenRow::H11,
            CenRow::H14,
            CenRow::H15,
            CenRow::H16,
            CenRow::H17,
            CenRow::H18,
            CenRow::H20,
            CenRow::H21,
            CenRow::H22,
            CenRow::I1,
            CenRow::I4,
            CenRow::I5,
            CenRow::I6,
            CenRow::I8,
            CenRow::I9,
            CenRow::I14,
            CenRow::I16
        ]
    );
}

// ---- CEN-H10 ------------------------------------------------------------

/// Two `ToKey` inputs with the same key image are refused on H10; two
/// distinct ones pass. (I5's ordering — slice 6 — would refuse the same
/// pair; this is the inherited belt on its own.)
#[test]
fn h10_a_repeated_key_image_within_one_transaction_is_refused() {
    let dup = with_inputs(vec![spend(11), spend(11)]);
    refused_lone(&dup, CenRow::H10);
    refused_listed(&dup, CenRow::H10);
    // Two distinct images in the order I5 wants (descending), and two
    // pseudo-outs summing to the fixture's masks (`4·G + G = 2·G + 3·G`) —
    // so neither order, layout nor balance is what decides here.
    let (hi, lo) = if point(12) > point(11) {
        (12, 11)
    } else {
        (11, 12)
    };
    let mut distinct = with_inputs(vec![spend(hi), spend(lo)]);
    if let Ct::Fcmp {
        pqc_auths,
        prunable: Some(p),
        ..
    } = &mut distinct.ct
    {
        // One auth per input (I8).
        pqc_auths.push(crate::harness::fixture::pqc_auth_filler());
        p.pseudo_outs = vec![crate::harness::fixture::multiple_of_g(4), G];
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
        assert!(H19::canonical(Some(&with(vec![bp])), n_out));
    }
    // Too many rounds for the count (a 2-output proof for 1 output), too few
    // (a 1-output proof for 2), rounds out of range, two proofs, `|L| != |R|`.
    assert!(!H19::canonical(Some(&with(vec![bp_plus_layout_for(2)])), 1));
    assert!(!H19::canonical(Some(&with(vec![bp_plus_layout_for(1)])), 2));
    let mut eleven = bp_plus_layout_for(16);
    eleven.l.push([0; 32]);
    eleven.r.push([0; 32]);
    assert!(!H19::canonical(Some(&with(vec![eleven])), 16));
    let mut five = bp_plus_layout_for(1);
    five.l.pop();
    five.r.pop();
    assert!(!H19::canonical(Some(&with(vec![five])), 1));
    assert!(!H19::canonical(
        Some(&with(vec![bp_plus_layout_for(1), bp_plus_layout_for(1)])),
        1
    ));
    let mut lopsided = bp_plus_layout_for(1);
    lopsided.r.push([0; 32]);
    assert!(!H19::canonical(Some(&with(vec![lopsided])), 1));
    // No proof: canonical only for no outputs.
    assert!(H19::canonical(None, 0));
    assert!(!H19::canonical(None, 1));
    assert!(H19::canonical(Some(&with(Vec::new())), 0));
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
        // Three outputs' layout (padded 4) over the fixture's two: `4 < 2·2`
        // fails, so the layout is not canonical for the count.
        p.bulletproofs = vec![bp_plus_layout_for(3)];
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

// ---- census 4.I, the stateless rows (slice 6 commit 2) ------------------
//
// Each row's refusal at both sites (the pool's `Lone` slot through
// `tx_form`; a `Listed` slot through `validate`), the last admitted value
// beside the first refused where the row has an edge, and the vacuous
// record on the coinbase. The wire twin's self-arming arms in
// `tx_conformance_tests` hold the crate to seven of these rows on the
// twin's own trips; these are the rows' own fixtures.

/// A well-formed two-input spend: images descending (I5), one auth per
/// input (I8), two pseudo-outs summing to the masks (`4·G + G = 2·G +
/// 3·G`, H18), the fixture's two outputs (I1).
fn two_input_spend() -> Transaction {
    // The pinned table has sixteen points; images past it are computed.
    let (a, b) = (
        crate::harness::fixture::point_at(21),
        crate::harness::fixture::point_at(22),
    );
    let (hi, lo) = if a > b { (a, b) } else { (b, a) };
    let image = |key_image| Input::ToKey {
        amount: 0,
        key_offsets: Vec::new(),
        key_image,
    };
    let mut tx = with_inputs(vec![image(hi), image(lo)]);
    if let Ct::Fcmp {
        pqc_auths,
        prunable: Some(p),
        ..
    } = &mut tx.ct
    {
        pqc_auths.push(crate::harness::fixture::pqc_auth_filler());
        p.pseudo_outs = vec![crate::harness::fixture::multiple_of_g(4), G];
    }
    tx
}

/// The 4.I rows a coinbase records as vacuous: every one is `NonCoinbase`,
/// so the miner slot evaluates the premise and holds trivially.
#[test]
fn the_stateless_4i_rows_are_vacuous_on_the_coinbase() {
    let form = tx_form(&coinbase(3), TxSlot::Miner, &RuleSet::GENESIS).expect("a coinbase");
    for row in [
        CenRow::I1,
        CenRow::I4,
        CenRow::I5,
        CenRow::I6,
        CenRow::I8,
        CenRow::I9,
        CenRow::I14,
        CenRow::I16,
    ] {
        assert!(
            form.contains(row),
            "{row} recorded vacuous at the miner slot"
        );
    }
}

/// CEN-I1: two outputs are the last admitted count and one the first
/// refused, on a spend and on a bond post; a serve-credit response has
/// none and is exempt.
#[test]
fn i1_fewer_than_two_outputs_is_refused_except_on_a_serve_credit() {
    let one = crate::harness::fixture::spend(KI, 1);
    refused_lone(&one, CenRow::I1);
    refused_listed(&one, CenRow::I1);
    assert!(tx_form(&listed(KI), TxSlot::Lone, &RuleSet::GENESIS)
        .expect("two outputs")
        .contains(CenRow::I1));
    assert!(tx_form(
        &serve_credit_only([0x51; 32]),
        TxSlot::Lone,
        &RuleSet::GENESIS
    )
    .expect("a serve credit has no outputs and is exempt")
    .contains(CenRow::I1));
}

/// CEN-I4: eight inputs are admitted (the cap is `MAX_FCMP_INPUTS`, the
/// wire's mirror of `FCMP_MAX_INPUTS_PER_TX`), nine refused — at both
/// sites, and on what would be a Fakechain node: the C++ gates this on
/// `m_nettype != FAKECHAIN`; the rule does not read the nettype (rule 71).
#[test]
fn i4_the_ninth_input_is_refused_and_the_eighth_admitted() {
    let with_n = |n: usize| {
        // Images strictly descending, one auth each, and pseudo-outs that
        // still sum to the masks: `n − 1` of `G` and one of `5 − (n − 1)`
        // — kept positive by the counts used here.
        let mut images: Vec<[u8; 32]> = (30..30 + n as u64)
            .map(crate::harness::fixture::point_at)
            .collect();
        images.sort_unstable_by(|a, b| b.cmp(a));
        let mut tx = with_inputs(
            images
                .into_iter()
                .map(|key_image| Input::ToKey {
                    amount: 0,
                    key_offsets: Vec::new(),
                    key_image,
                })
                .collect(),
        );
        // Balance kept so H18 (which runs first) passes: `n` pseudo-outs of
        // `G` sum to `n·G`, and the two masks are set to `2·G + (n−2)·G`.
        // `n ≥ 8` here, so neither mask is `G` (H17's trivial mask).
        if let Ct::Fcmp {
            pqc_auths,
            base,
            prunable: Some(p),
            ..
        } = &mut tx.ct
        {
            *pqc_auths = vec![crate::harness::fixture::pqc_auth_filler(); n];
            p.pseudo_outs = vec![G; n];
            base.commitments = vec![
                TWO_G,
                crate::harness::fixture::multiple_of_g(u64::try_from(n).expect("small") - 2),
            ];
        }
        tx
    };
    let eight = with_n(shekyl_wire::transaction::MAX_FCMP_INPUTS);
    assert!(tx_form(&eight, TxSlot::Lone, &RuleSet::GENESIS)
        .expect("eight inputs are admitted")
        .contains(CenRow::I4));
    let nine = with_n(shekyl_wire::transaction::MAX_FCMP_INPUTS + 1);
    refused_lone(&nine, CenRow::I4);
    refused_listed(&nine, CenRow::I4);
}

/// CEN-I5: the images must strictly descend — an ascending pair is refused
/// at both sites, and an equal pair is refused (on H10 first, as the order
/// runs; on I5 when asked alone). Archival inputs between two spends are
/// skipped, not a reset.
#[test]
fn i5_ascending_or_equal_key_images_are_refused() {
    let mut ascending = two_input_spend();
    ascending.prefix.inputs.swap(0, 1);
    refused_lone(&ascending, CenRow::I5);
    refused_listed(&ascending, CenRow::I5);
    assert!(tx_form(&two_input_spend(), TxSlot::Lone, &RuleSet::GENESIS)
        .expect("descending passes")
        .contains(CenRow::I5));
    // Equal: H10 is first in `tx_form`; I5 alone refuses the same bytes.
    let equal = with_inputs(vec![spend(11), spend(11)]);
    refused_lone(&equal, CenRow::H10);
    let mut coverage = RuleCoverage::EMPTY;
    let cx = TxContext::derive(&equal, TxSlot::Lone, &mut coverage).expect("classifies");
    assert!(I5::check(&cx).is_err(), "I5 refuses a repeat on its own");
    // An archival input between two descending spends does not reset the
    // comparison: still admitted through I5 (the shape is H6's business).
    let mut interleaved = two_input_spend();
    interleaved.prefix.inputs.insert(1, emission());
    let mut coverage = RuleCoverage::EMPTY;
    let cx = TxContext::derive(&interleaved, TxSlot::Lone, &mut coverage).expect("classifies");
    assert!(I5::check(&cx).is_ok());
}

/// CEN-I6: any non-empty `key_offsets` is refused at both sites; the
/// offset list `[7, 0]` is CEN-H24's own trip, which can no longer be
/// reached on an admitted transaction (`h24_cannot_fire_on_an_input_i6_admits`).
#[test]
fn i6_key_offsets_are_refused() {
    let mut one_offset = listed(KI);
    if let Some(Input::ToKey { key_offsets, .. }) = one_offset.prefix.inputs.get_mut(0) {
        *key_offsets = vec![1];
    }
    refused_lone(&one_offset, CenRow::I6);
    refused_listed(&one_offset, CenRow::I6);
}

/// CEN-I8: a spend's auth count off the input count — one too few, one too
/// many — is refused at both sites. The bond post's and emission's counts
/// are H21's and H22's; the serve-credit's zero is H20's.
#[test]
fn i8_the_auth_count_must_equal_the_input_count_on_a_spend() {
    let mut fewer = two_input_spend();
    if let Ct::Fcmp { pqc_auths, .. } = &mut fewer.ct {
        pqc_auths.pop();
    }
    refused_lone(&fewer, CenRow::I8);
    refused_listed(&fewer, CenRow::I8);
    let mut more = listed(KI);
    if let Ct::Fcmp { pqc_auths, .. } = &mut more.ct {
        pqc_auths.push(crate::harness::fixture::pqc_auth_filler());
    }
    refused_lone(&more, CenRow::I8);
    refused_listed(&more, CenRow::I8);
}

/// CEN-I9: a spend's pseudo-out count off the input count is refused at
/// both sites — with the balance kept, so H18 is not what decides: two
/// inputs against one pseudo-out of `5·G` (the masks' sum).
#[test]
fn i9_the_pseudo_out_count_must_equal_the_input_count_on_a_spend() {
    let mut one_for_two = two_input_spend();
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut one_for_two.ct
    {
        p.pseudo_outs = vec![crate::harness::fixture::multiple_of_g(5)];
    }
    refused_lone(&one_for_two, CenRow::I9);
    refused_listed(&one_for_two, CenRow::I9);
}

/// CEN-I14: a spend whose FCMP++ proof is empty is refused at both sites;
/// so is the storage-pruned form (no prunable region at all — its BP+
/// layout is H19's refusal first, so I14 is asked alone there).
#[test]
fn i14_an_empty_proof_on_a_spend_is_refused() {
    let mut empty = listed(KI);
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut empty.ct
    {
        p.fcmp_proof.clear();
    }
    refused_lone(&empty, CenRow::I14);
    refused_listed(&empty, CenRow::I14);
    let mut pruned = listed(KI);
    if let Ct::Fcmp { prunable, .. } = &mut pruned.ct {
        *prunable = None;
    }
    let mut coverage = RuleCoverage::EMPTY;
    let cx = TxContext::derive(&pruned, TxSlot::Lone, &mut coverage).expect("classifies");
    assert!(I14::check(&cx).is_err(), "no prunable region is no proof");
}

/// CEN-I16: each structural departure is refused at both sites — the
/// version, the flags, an unknown scheme, a solo key blob one byte off
/// either way, a multisig blob below the header and above the cap — and
/// the solo shape and a minimal multisig shape are admitted.
#[test]
fn i16_every_structural_departure_of_a_pqc_auth_is_refused() {
    use shekyl_crypto_pq::multisig::HYBRID_SCHEME_ID_MULTISIG;
    use shekyl_wire::transaction::{PQC_HYBRID_SINGLE_KEY_LEN, PQC_MAX_PUBLIC_KEY_BLOB};
    let with_auth = |edit: &dyn Fn(&mut shekyl_wire::PqcAuth)| {
        let mut tx = listed(KI);
        if let Ct::Fcmp { pqc_auths, .. } = &mut tx.ct {
            edit(&mut pqc_auths[0]);
        }
        tx
    };
    for (what, tx) in [
        ("version 2", with_auth(&|a| a.auth_version = 2)),
        ("flags set", with_auth(&|a| a.flags = 1)),
        ("scheme 3", with_auth(&|a| a.scheme_id = 3)),
        (
            "solo key one short",
            with_auth(&|a| a.hybrid_public_key.truncate(PQC_HYBRID_SINGLE_KEY_LEN - 1)),
        ),
        (
            "solo key one long",
            with_auth(&|a| a.hybrid_public_key.push(0)),
        ),
        (
            "multisig key below the header",
            with_auth(&|a| {
                a.scheme_id = HYBRID_SCHEME_ID_MULTISIG;
                a.hybrid_public_key = vec![0; 2];
            }),
        ),
        (
            "multisig key above the cap",
            with_auth(&|a| {
                a.scheme_id = HYBRID_SCHEME_ID_MULTISIG;
                a.hybrid_public_key = vec![0; PQC_MAX_PUBLIC_KEY_BLOB + 1];
            }),
        ),
    ] {
        let lone = tx_form(&tx, TxSlot::Lone, &RuleSet::GENESIS);
        assert!(
            matches!(&lone, Err(refused) if refused.rule == CenRow::I16),
            "{what}: {lone:?}"
        );
        refused_listed(&tx, CenRow::I16);
    }
    assert!(tx_form(&listed(KI), TxSlot::Lone, &RuleSet::GENESIS)
        .expect("the solo shape")
        .contains(CenRow::I16));
    let minimal_multisig = with_auth(&|a| {
        a.scheme_id = HYBRID_SCHEME_ID_MULTISIG;
        a.hybrid_public_key = vec![0; 3];
    });
    assert!(tx_form(&minimal_multisig, TxSlot::Lone, &RuleSet::GENESIS)
        .expect("the multisig header alone is I16's floor; the parse is I17/I18's")
        .contains(CenRow::I16));
}
