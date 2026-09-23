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
use crate::harness::fixture::{candidate_on, coinbase, listed};
use crate::harness::{assert_refused, formed_on, judged, MockChain};
use crate::rule_set::RuleSet;
use crate::rules::TxKind;
use crate::trust::Trust;
use crate::validate::{tx_form, validate};
use crate::verdict::{Locus, TxSlot};
use shekyl_wire::Transaction;

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
/// amended), and the miner slot is the coinbase whatever it carries.
#[test]
fn the_kind_is_derived_from_the_slot_not_the_bytes() {
    assert_eq!(TxKind::of(TxSlot::Miner), TxKind::Coinbase);
    assert_eq!(TxKind::of(TxSlot::Lone), TxKind::Listed);
    assert_eq!(TxKind::of(TxSlot::Listed(3)), TxKind::Listed);
    let coinbase_shaped = coinbase(1);
    assert!(coinbase_shaped.is_coinbase());
    let cx = TxContext::new(&coinbase_shaped, TxSlot::Lone);
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
        |tx| H1::check(&TxContext::new(&tx, TxSlot::Lone)),
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
/// slot, listed, **and at the miner slot**, since the C++ runs
/// `check_tx_outputs` on the coinbase too.
#[test]
fn h16_the_sentinel_is_the_first_refused_unlock_time_everywhere() {
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
    assert_refused(
        tx_form(&miner, TxSlot::Miner, &RuleSet::GENESIS),
        CenRow::H16,
        Locus::Tx {
            slot: TxSlot::Miner,
        },
    );
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
        [CenRow::H1, CenRow::H3, CenRow::H4, CenRow::H16]
    );
}
