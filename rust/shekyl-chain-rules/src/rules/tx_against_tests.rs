// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fixtures for the view-bound 4.I rows landed so far — CEN-I7 through
//! `tx_against` at the pool's slot and through `validate` at a listed slot,
//! CEN-L1 through `validate` — the emission's reference context (CEN-J21,
//! the same reads under one row), and the two 4.I rows held by construction
//! (I2's falsifier lives here; I3's is `f2_the_wire_admits_one_transaction_version`).

use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::fault::{Corrupt, PerHeightRecord, ViewRead};
use crate::harness::fixture::{
    anchored_on, balanced_emission, candidate_on, coinbase, emission_vin, listed, listed_on, point,
    point_at, referencing, serve_credit_only, spend, spendable_chain, TWO_G,
};
use crate::harness::{
    assert_refused, credited_to_this_falsifier, defined, formed_on, judged, Faulted, FaultingView,
    MockChain, WithheldRead,
};
use crate::rule_set::RuleSet;
use crate::rules::tx::{refused_listed, refused_lone};
use crate::rules::tx_against::{
    judge_reference, judge_signatures, I11, I13, I17, I18, REFERENCE_BLOCK_MAX_AGE,
    REFERENCE_BLOCK_MIN_AGE,
};
use crate::rules::TxContext;
use crate::trust::Trust;
use crate::validate::{tx_against, validate};
use crate::verdict::{Locus, TxSlot};
use shekyl_types::{BlockHeight, KeyImage};
use shekyl_wire::transaction::CT_TYPE_FCMP;
use shekyl_wire::{Ct, CtBase, Input, Transaction};

const KI: [u8; 32] = point(9);

// ---- the reference window: pinned to the JSON authority ----------------

/// `REFERENCE_BLOCK_{MIN,MAX}_AGE` equal `config/consensus_constants.json`'s
/// `fcmp_reference_block_{min,max}_age`. The build script is what a
/// production build reads; this is the falsifier that the consts are still
/// that file — a later edit that replaces the generated value with a
/// literal fails here (slice 6 Q5). The header derives from the JSON too.
#[test]
fn reference_window_is_the_json_authoritys() {
    let json: serde_json::Value =
        serde_json::from_str(include_str!("../../../../config/consensus_constants.json"))
            .expect("consensus_constants.json parses");
    let age = |key: &str| {
        json[key]
            .as_u64()
            .unwrap_or_else(|| panic!("consensus_constants.json carries {key} as an integer"))
    };
    assert_eq!(
        REFERENCE_BLOCK_MIN_AGE.to_raw(),
        age("fcmp_reference_block_min_age")
    );
    assert_eq!(
        REFERENCE_BLOCK_MAX_AGE.to_raw(),
        age("fcmp_reference_block_max_age")
    );
    assert!(
        REFERENCE_BLOCK_MAX_AGE.to_raw() > REFERENCE_BLOCK_MIN_AGE.to_raw(),
        "the window is non-empty (cryptonote_config.h's static_assert)"
    );
}

// ---- CEN-I7 -------------------------------------------------------------

/// A spend of a key image the chain has recorded is refused on I7 at the
/// pool's slot; the same body with a fresh image passes and records the
/// row. Both through `tx_against`, the entry point the pool calls.
#[test]
fn i7_a_spent_key_image_is_refused_and_a_fresh_one_records() {
    let chain = spendable_chain().with_key_image(KeyImage::from_bytes(KI));
    chain.with_view(|view| {
        assert_refused(
            defined(tx_against(
                &listed_on(&chain, KI),
                TxSlot::Lone,
                &view,
                &RuleSet::GENESIS,
            )),
            CenRow::I7,
            Locus::Input {
                slot: TxSlot::Lone,
                input: 0,
            },
        );
        let fresh = defined(tx_against(
            &listed_on(&chain, point(10)),
            TxSlot::Lone,
            &view,
            &RuleSet::GENESIS,
        ))
        .expect("an unspent image passes");
        assert!(fresh.contains(CenRow::I7));
    });
}

/// The same refusal at a listed slot through `validate`: `validate` hands
/// `tx_against` the slot it is judging, so the refusal is written at
/// `Listed(n)` — the transaction's position, not the pool's — and nothing
/// re-homes it afterwards (`Locus::rehome` went with slice 6 commit 4).
#[test]
fn i7_at_a_listed_slot_the_refusal_names_the_slot() {
    let chain = spendable_chain().with_key_image(KeyImage::from_bytes(point(11)));
    chain.with_view(|view| {
        let block = candidate_on(
            &chain,
            vec![listed_on(&chain, point(10)), listed_on(&chain, point(11))],
        );
        let formed = formed_on(&chain, block);
        assert_refused(
            judged(validate(
                formed,
                &view,
                &RuleSet::GENESIS,
                &Trust::UNANCHORED,
            )),
            CenRow::I7,
            Locus::Input {
                slot: TxSlot::Listed(1),
                input: 0,
            },
        );
    });
}

/// Every `ToKey` input is looked up, whichever class carries it: a bond
/// post's funding spend of a recorded image is I7's refusal, as the C++'s
/// archival arms make it.
#[test]
fn i7_looks_up_an_archival_shapes_funding_spend_too() {
    let funding = point_at(23);
    let chain = spendable_chain().with_key_image(KeyImage::from_bytes(funding));
    // A two-input spend whose second input is the recorded image; the
    // class does not matter to the lookup, and a plain spend keeps the
    // fixture out of H21's balance arithmetic.
    let mut tx = listed_on(&chain, KI);
    tx.prefix.inputs.push(Input::ToKey {
        amount: 0,
        key_offsets: Vec::new(),
        key_image: funding,
    });
    // Descending images (I5) and one auth per input (I8) so `tx_form`
    // admits the shape and `tx_against` is what judges it.
    tx.prefix
        .inputs
        .sort_by_key(|input| core::cmp::Reverse(key_image_of(input)));
    if let Ct::Fcmp {
        pqc_auths,
        prunable: Some(p),
        ..
    } = &mut tx.ct
    {
        pqc_auths.push(pqc_auths[0].clone());
        // H18: two pseudo-outs summing to the masks (`2·G + 3·G`).
        p.pseudo_outs = vec![TWO_G, point(3)];
    }
    // The refusal names the input the recorded image sits at, wherever the
    // sort put it.
    let spent_at = tx
        .prefix
        .inputs
        .iter()
        .position(|input| key_image_of(input) == funding)
        .expect("the funding image is an input");
    chain.with_view(|view| {
        assert_refused(
            defined(tx_against(&tx, TxSlot::Lone, &view, &RuleSet::GENESIS)),
            CenRow::I7,
            Locus::Input {
                slot: TxSlot::Lone,
                input: spent_at,
            },
        );
    });
}

fn key_image_of(input: &Input) -> [u8; 32] {
    match input {
        Input::ToKey { key_image, .. } => *key_image,
        _ => unreachable!("the fixture's inputs are spends"),
    }
}

/// The coinbase has no key image to look up: I7 is vacuous at the miner
/// slot and recorded as evaluated.
#[test]
fn i7_is_vacuous_on_the_coinbase() {
    let chain = MockChain::default();
    chain.with_view(|view| {
        let formed = formed_on(&chain, candidate_on(&chain, Vec::new()));
        let valid = judged(validate(
            formed,
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .expect("a block of one coinbase");
        assert!(valid.coverage().contains(CenRow::I7));
        assert!(valid.coverage().contains(CenRow::L1));
    });
}

/// A view that cannot answer is a fault, never a verdict: `tx_against`
/// propagates it and derives nothing.
#[test]
fn i7_propagates_a_view_fault() {
    let view = FaultingView::default();
    assert_eq!(
        tx_against(&listed(KI), TxSlot::Lone, &view, &RuleSet::GENESIS)
            .expect_err("the view faulted"),
        ViewRead::View(Faulted)
    );
}

// ---- CEN-L1 -------------------------------------------------------------

/// Two listed transactions spending one key image — each admissible on its
/// own, since the chain has neither — are refused on L1 at the **second**
/// occurrence, naming the slot and the input. Without this row the block
/// would pass `validate` and meet the store's fatal SI-1 at connect.
#[test]
fn l1_a_key_image_twice_across_a_blocks_transactions_is_refused_at_the_second() {
    let chain = spendable_chain();
    chain.with_view(|view| {
        // Distinct transactions (different outputs) over the same image.
        let first = listed_on(&chain, KI);
        let mut second = anchored_on(&chain, spend(KI, 3));
        second.prefix.extra = crate::harness::fixture::pqc_extra(3);
        let block = candidate_on(&chain, vec![first, second]);
        let formed = formed_on(&chain, block);
        assert_refused(
            judged(validate(
                formed,
                &view,
                &RuleSet::GENESIS,
                &Trust::UNANCHORED,
            )),
            CenRow::L1,
            Locus::Input {
                slot: TxSlot::Listed(1),
                input: 0,
            },
        );
    });
}

/// L1 runs after every slot has passed: a block whose second transaction
/// fails a per-transaction row is refused on that row, not on L1, even
/// when the images collide — the C++'s `add_spent_key` is the last check
/// too.
#[test]
fn l1_runs_after_the_per_transaction_rows() {
    let chain = spendable_chain();
    chain.with_view(|view| {
        let first = listed_on(&chain, KI);
        let mut second = listed_on(&chain, KI);
        // The second transaction fails H15 (a `Null` CT off the coinbase).
        second.ct = Ct::Null(CtBase {
            enc_amounts: vec![[0x11; 9]; 2],
            enc_labels: vec![[0x22; 9]; 2],
            commitments: vec![TWO_G; 2],
        });
        let formed = formed_on(&chain, candidate_on(&chain, vec![first, second]));
        assert_refused(
            judged(validate(
                formed,
                &view,
                &RuleSet::GENESIS,
                &Trust::UNANCHORED,
            )),
            CenRow::H15,
            Locus::Tx {
                slot: TxSlot::Listed(1),
            },
        );
    });
}

/// A block of distinct spends passes and records L1.
#[test]
fn l1_distinct_images_pass_and_record() {
    let chain = spendable_chain();
    chain.with_view(|view| {
        let formed = formed_on(
            &chain,
            candidate_on(
                &chain,
                vec![listed_on(&chain, point(10)), listed_on(&chain, point(11))],
            ),
        );
        let valid = judged(validate(
            formed,
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .expect("distinct images");
        assert!(valid.coverage().contains(CenRow::L1));
    });
}

// ---- CEN-I10, I11, I12 -------------------------------------------------
//
// The mock earns three things here and no more. The window's boundary
// arithmetic (`I11::window`) is predicate logic on two heights. An
// unrecorded hash is absence — `height_of` returns `None`, which is what
// the read means, so CEN-I10's refusal of that hash is the mock's to say.
// A root missing where the same view just reported the block recorded is
// [`WithheldRead::RootAt`], charter job 3. The rows *operating* — a real
// spend's reference found and its anchor read — are witnessed by the
// driver: the ingest's mutation family (`UnknownReference`,
// `ReferenceTooRecent`) through the production pipeline against a real
// store, and every captured chain's real spends (`vectors_tests`). An
// anchored spend on `MockChain` is the fixture writing a hash the mock
// serves back, and is not a witness that those rows operate.

/// The young edge: a reference exactly `MIN_AGE` below the connecting
/// height is admitted; one block younger is refused.
#[test]
fn i11_admits_a_reference_exactly_min_age_old_and_refuses_one_younger() {
    let min = REFERENCE_BLOCK_MIN_AGE.to_raw();
    let connecting = BlockHeight::from_raw(REFERENCE_BLOCK_MAX_AGE.to_raw());
    let newest = BlockHeight::from_raw(connecting.to_raw() - min);
    assert_eq!(I11::window(connecting, newest), Ok(()));
    assert_eq!(
        I11::window(connecting, BlockHeight::from_raw(newest.to_raw() + 1)),
        Err(())
    );
}

/// The old edge: a reference exactly `MAX_AGE` below is admitted; one
/// block older is refused. At `connecting == MAX_AGE` the oldest admissible
/// is genesis and nothing is below it — the C++'s `chain_height > MAX_AGE`
/// guard, which `checked_sub_count` yielding `Some(0)` reproduces exactly.
#[test]
fn i11_admits_a_reference_exactly_max_age_old_and_refuses_one_older() {
    let max = REFERENCE_BLOCK_MAX_AGE.to_raw();
    assert_eq!(
        I11::window(BlockHeight::from_raw(max), BlockHeight::ZERO),
        Ok(()),
        "at connecting == MAX_AGE genesis is exactly MAX_AGE old"
    );
    assert_eq!(
        I11::window(BlockHeight::from_raw(max + 1), BlockHeight::from_raw(1)),
        Ok(())
    );
    assert_eq!(
        I11::window(BlockHeight::from_raw(max + 1), BlockHeight::ZERO),
        Err(()),
        "one past MAX_AGE"
    );
}

/// A chain too young to hold any admissible reference refuses every
/// height; the first connecting height that admits one is `MIN_AGE`,
/// referencing genesis — which is why `spendable_chain` is `MIN_AGE` blocks.
#[test]
fn i11_refuses_every_reference_on_a_chain_younger_than_min_age() {
    let min = REFERENCE_BLOCK_MIN_AGE.to_raw();
    for connecting in 0..min {
        assert_eq!(
            I11::window(BlockHeight::from_raw(connecting), BlockHeight::ZERO),
            Err(()),
            "connecting at {connecting}: no reference is MIN_AGE old"
        );
    }
    assert_eq!(
        I11::window(BlockHeight::from_raw(min), BlockHeight::ZERO),
        Ok(())
    );
    assert_eq!(
        spendable_chain().tip().map(|tip| tip.height.to_raw() + 1),
        Some(min),
        "the harness's spendable chain connects at MIN_AGE"
    );
}

/// A spend whose `referenceBlock` is the hash no chain holds is CEN-I10's
/// refusal at the transaction. Absence is what `height_of` means, so the
/// mock can say it. The pass — an anchored spend recording I10, I11 and
/// I12 — is the driver's (`mutation_tests`, `vectors_tests`) and the
/// fixture gate's (`fixture_sanity_tests`).
#[test]
fn i10_refuses_an_unrecorded_reference() {
    let chain = spendable_chain();
    chain.with_view(|view| {
        assert_refused(
            defined(tx_against(
                &listed(KI),
                TxSlot::Lone,
                &view,
                &RuleSet::GENESIS,
            )),
            CenRow::I10,
            Locus::Tx { slot: TxSlot::Lone },
        );
    });
}

/// The reference rows are the regular spend's: a serve-credit-only body has
/// no reference to look up, and the three are recorded vacuous, as the
/// coinbase's are (`validate_tests::tx_entry_points_record_the_landed_rows`).
///
/// Called as the sequence, not through `tx_against`: since E6 slice 8 row
/// 3 a serve credit over the mock is refused on CEN-J4 (`MockChain` holds
/// no bonds by policy), so the whole-stage call no longer reaches the
/// reference rows. The witness for a credit *through* `tx_against` is a
/// driven chain that posted the bond (`shekyl-chain-ingest`).
#[test]
fn i10_i11_i12_are_vacuous_on_a_serve_credit() {
    let chain = spendable_chain();
    let credit = serve_credit_only([0x5e; 32]);
    chain.with_view(|view| {
        let mut coverage = RuleCoverage::EMPTY;
        let cx = TxContext::derive(&credit, TxSlot::Lone, &mut coverage)
            .expect("a serve-credit-only body classifies");
        let context = defined(judge_reference(&cx, &view, &mut coverage))
            .expect("a serve credit has no reference to judge");
        assert_eq!(context, None, "no context: nothing verifies against one");
        for row in [CenRow::I10, CenRow::I11, CenRow::I12, CenRow::J21] {
            assert!(coverage.contains(row), "{row} recorded vacuous");
        }
    });
}

/// I12 reads the anchor at a height I10 just found recorded; a view that
/// answers `AboveTip` there has a hole below its tip. That is a store
/// invariant observed broken — `ViewRead::Corrupt(HoleBelowTip)`, the
/// class that halts the writer — never a verdict, and the reason
/// `tx_against`'s fault is a `ViewRead`. A driven chain cannot produce this
/// (SI-4 keeps every root below the tip recorded), which is what makes it
/// the mock's to witness.
#[test]
fn i12_a_missing_root_at_the_reference_height_is_corrupt_not_a_verdict() {
    let chain = spendable_chain();
    // The anchored spend references genesis (`newest_admissible_reference`
    // of the connecting height), so genesis's root is the one withheld.
    let tx = listed_on(&chain, KI);
    chain.with_view(|inner| {
        let view = inner.withholding(WithheldRead::RootAt(BlockHeight::ZERO));
        assert_eq!(
            tx_against(&tx, TxSlot::Lone, &view, &RuleSet::GENESIS),
            Err(ViewRead::Corrupt(Corrupt::HoleBelowTip {
                at: BlockHeight::ZERO,
                record: PerHeightRecord::CurveTreeRoot,
            }))
        );
    });
}

// ---- CEN-J21 (I13) ------------------------------------------------------
//
// The emission's reference context is the spend's reads under one row, so
// the mock's share is the same three things: the predicates (`I13::admits`
// over two depths; the window is I11's, pinned above), absence (an
// unrecorded hash, a reference the window refuses, a body with no
// declared depth), and the two holes below the tip (the root, the leaf
// count the depth is a function of). These chains plant no tree
// (`MockChain::push`, never `push_tree`), so every recorded height's depth
// is 0, no declared depth is admitted, and an anchored emission here is
// J21's refusal, not its pass. The pass is the driver's: an assembled
// claim's declared depth is the tree's at its reference
// (`scenario_emission_tests`), and the context it yields is what the
// emission's proof rows verify against.

/// `I13::admits`: `[1, depth]`, closed at both ends; nothing is admitted
/// against an empty tree.
#[test]
fn i13_admits_a_declared_depth_in_one_through_the_depth_at_the_reference() {
    assert!(!I13::admits(0, 5), "a zero depth names no tree");
    assert!(I13::admits(1, 5));
    assert!(I13::admits(5, 5), "the depth at the reference itself");
    assert!(!I13::admits(6, 5), "one layer more than the reference held");
    assert!(!I13::admits(1, 0), "the empty tree holds no proof");
    assert!(!I13::admits(u64::from(u8::MAX) + 1, u8::MAX), "beyond a u8");
}

/// A fee-bearing emission with a parseable vin, unanchored.
fn emission(key_image: [u8; 32]) -> Transaction {
    let Input::ArchivalRewardEmission { canonical_bytes } = emission_vin(0x13, &[1]) else {
        unreachable!("emission_vin builds an emission input");
    };
    balanced_emission(key_image, canonical_bytes, 5)
}

/// J21 refuses at the transaction: the reference no chain holds (I10's
/// read), and a reference the window refuses (I11's — the tip itself,
/// zero blocks old). The refusal row is J21 on an emission, where the
/// spend's would be I10 or I11.
#[test]
fn j21_refuses_an_unrecorded_reference_and_one_the_window_refuses() {
    let chain = spendable_chain();
    let tip = chain.tip().expect("a spendable chain has a tip").hash;
    chain.with_view(|view| {
        for tx in [emission(KI), referencing(emission(KI), tip)] {
            assert_refused(
                defined(tx_against(&tx, TxSlot::Lone, &view, &RuleSet::GENESIS)),
                CenRow::J21,
                Locus::Tx { slot: TxSlot::Lone },
            );
        }
    });
}

/// An anchored emission whose declared depth the tree at the reference
/// does not hold — here, any depth, against the mock's empty tree — is
/// J21's refusal; so is a body with no prunable region to declare one.
#[test]
fn j21_refuses_a_declared_depth_the_reference_does_not_hold() {
    let chain = spendable_chain();
    let anchored = anchored_on(&chain, emission(KI));
    let mut declared_one = anchored.clone();
    let mut pruned = anchored.clone();
    match (&mut declared_one.ct, &mut pruned.ct) {
        (
            Ct::Fcmp {
                prunable: Some(p), ..
            },
            Ct::Fcmp { prunable, .. },
        ) => {
            p.tree_depth = 1;
            *prunable = None;
        }
        _ => unreachable!("an emission is an Fcmp ct with a prunable region"),
    }
    chain.with_view(|view| {
        for tx in [anchored, declared_one, pruned] {
            let mut coverage = RuleCoverage::EMPTY;
            let cx = TxContext::derive(&tx, TxSlot::Lone, &mut coverage)
                .expect("an emission classifies");
            assert_refused(
                defined(judge_reference(&cx, &view, &mut coverage)),
                CenRow::J21,
                Locus::Tx { slot: TxSlot::Lone },
            );
            assert!(
                !coverage.contains(CenRow::J21),
                "a refused row is not recorded"
            );
        }
    });
}

/// J21's two per-height reads at a height I10 just found recorded: a view
/// that answers `AboveTip` for either has a hole below its tip — the
/// `Corrupt` class, over the record that was missing, never a verdict.
#[test]
fn j21_a_missing_root_or_leaf_count_at_the_reference_is_corrupt_not_a_verdict() {
    let chain = spendable_chain();
    // Anchored on genesis (`newest_admissible_reference` of the connecting
    // height), so genesis's rows are the ones withheld.
    let tx = anchored_on(&chain, emission(KI));
    for (withheld, record) in [
        (
            WithheldRead::RootAt(BlockHeight::ZERO),
            PerHeightRecord::CurveTreeRoot,
        ),
        (
            WithheldRead::LeafCountAt(BlockHeight::ZERO),
            PerHeightRecord::LeafCount,
        ),
    ] {
        chain.with_view(|inner| {
            let view = inner.withholding(withheld);
            assert_eq!(
                tx_against(&tx, TxSlot::Lone, &view, &RuleSet::GENESIS),
                Err(ViewRead::Corrupt(Corrupt::HoleBelowTip {
                    at: BlockHeight::ZERO,
                    record,
                }))
            );
        });
    }
}

// ---- CEN-I17 ------------------------------------------------------------

/// I17 is a definition adopted from the wire: what `tx_against` derives
/// for a spend is `Transaction::pqc_signing_payload_hashes`, one hash per
/// input, and the row is recorded at the derivation. The bytes themselves
/// are the wire KAT's subject (`pqc_signing_preimage_kat.rs`, eight
/// daemon-accepted shapes); this holds only that the validator reads that
/// derivation and no other.
#[test]
fn i17_derives_the_wires_signing_preimage_and_records_the_row() {
    let chain = spendable_chain();
    let tx = listed_on(&chain, KI);
    let mut coverage = RuleCoverage::EMPTY;
    let cx = TxContext::derive(&tx, TxSlot::Lone, &mut coverage).expect("a spend classifies");
    let hashes = I17::signed_hashes(&cx, &mut coverage);
    assert_eq!(hashes, tx.pqc_signing_payload_hashes());
    assert_eq!(
        hashes.len(),
        tx.prefix.inputs.len(),
        "one preimage per input"
    );
    assert!(coverage.contains(CenRow::I17));
    chain.with_view(|view| {
        let against = defined(tx_against(&tx, TxSlot::Lone, &view, &RuleSet::GENESIS))
            .expect("an anchored spend passes");
        assert!(against.contains(CenRow::I17), "recorded through tx_against");
    });
}

/// The serve-credit form has no signing preimage — not because it is
/// unsigned, but because CEN-H20 forbids it `pqc_auths` and its hybrid
/// countersignature is CEN-J10's, over the pass record. Two failure modes
/// are pinned here for I17 and, by the same shape, for I18 (commit 8):
///
/// 1. **It does not reach for J10's object.** The derivation is bound to
///    the class, not to the record: corrupting every byte of the pass record
///    changes nothing — still zero hashes, still admitted through the
///    signature sequence. A derivation that read the record would move.
/// 2. **Zero-yield is exactly the classes with no `pqc_auths` by
///    construction** — the serve credit and the coinbase — never an in-scope
///    class that happened to produce nothing: a spend yields one per input.
///
/// The row is recorded **vacuous, not absent**, as I10–I12 are on the same
/// body and as every out-of-scope row is (slice 5 Q2, `rules/mod.rs`): the
/// bitset says the row was evaluated at this slot, so a block of serve
/// credits can be complete and the pool cannot mis-declare a kind. What
/// distinguishes a vacuous record from a judgment is (2): the class, which
/// this test holds fixed.
#[test]
fn i17_reads_none_of_a_serve_credits_pass_record_and_yields_only_where_pqc_auths_are() {
    let chain = spendable_chain();
    let intact = serve_credit_only([0x5e; 32]);
    let mut corrupt = intact.clone();
    match &mut corrupt.prefix.inputs[0] {
        Input::ServeCredit { canonical_bytes } => {
            // Every payload byte flipped; the tag byte stays so the codec's
            // shape check admits the body and I17 alone is under test.
            for byte in &mut canonical_bytes[1..] {
                *byte ^= 0xFF;
            }
        }
        other => panic!("a serve-credit fixture carries a serve-credit input, not {other:?}"),
    }
    for (name, tx) in [("intact", &intact), ("corrupt record", &corrupt)] {
        let mut coverage = RuleCoverage::EMPTY;
        let cx = TxContext::derive(tx, TxSlot::Lone, &mut coverage)
            .expect("a serve-credit-only body classifies");
        assert!(
            matches!(cx.class, crate::rules::tx::TxClass::ServeCreditOnly { .. }),
            "{name}: the class the zero-yield follows from"
        );
        assert!(
            I17::signed_hashes(&cx, &mut coverage).is_empty(),
            "{name}: no pqc_auths, no preimage — the pass record is J10's, unread here"
        );
        assert!(
            coverage.contains(CenRow::I17),
            "{name}: recorded vacuous, not absent"
        );
        // The signature sequence, run as `tx_against` runs it, admits the
        // body regardless of the record. It is called directly: on a chain
        // with no record for the persona, `tx_against` refuses the intact
        // body on J4 before I17 is reached (slice 8 row 3), and that
        // refusal is the bond state's, not this row's.
        judge_signatures(&cx, &mut coverage).unwrap_or_else(|refused| {
            panic!("{name}: admitted regardless of the record; refused {refused:?}")
        });
    }
    // (2): the coinbase is the other body with no `pqc_auths`; a spend yields
    // one hash per input, so an empty yield can only be one of the two.
    let mut coverage = RuleCoverage::EMPTY;
    let cb = coinbase(1);
    let cx = TxContext::derive(&cb, TxSlot::Miner, &mut coverage).expect("a coinbase classifies");
    assert!(
        I17::signed_hashes(&cx, &mut coverage).is_empty(),
        "the coinbase yields nothing"
    );
    let spend = listed_on(&chain, KI);
    let cx = TxContext::derive(&spend, TxSlot::Lone, &mut coverage).expect("a spend classifies");
    assert_eq!(
        I17::signed_hashes(&cx, &mut coverage).len(),
        spend.prefix.inputs.len(),
        "a spend yields one per input — in scope, never vacuous"
    );
}

// ---- CEN-I18 ------------------------------------------------------------

/// The fixture substrate is signed (`fixture::signed`, at `anchored_at`):
/// an anchored spend's every slot verifies through the body the daemon
/// and K13 call, and `tx_against` records I18 beside I17.
#[test]
fn i18_an_anchored_spends_signatures_verify_and_the_row_is_recorded() {
    let chain = spendable_chain();
    let tx = listed_on(&chain, KI);
    let Ct::Fcmp { pqc_auths, .. } = &tx.ct else {
        panic!("a spend is Fcmp");
    };
    for (auth, hash) in pqc_auths.iter().zip(tx.pqc_signing_payload_hashes()) {
        shekyl_crypto_pq::signature::verify_pqc_auth(
            auth.scheme_id,
            &auth.hybrid_public_key,
            &auth.hybrid_signature,
            hash.as_bytes(),
        )
        .expect("the fixture's slot verifies through the shared body");
    }
    chain.with_view(|view| {
        let against = defined(tx_against(&tx, TxSlot::Lone, &view, &RuleSet::GENESIS))
            .expect("a signed, anchored spend passes");
        assert!(against.contains(CenRow::I18), "recorded through tx_against");
    });
}

/// One flipped byte in one input's signature refuses **that input** under
/// I18 — the E2 driver's `ForgedSignature` place — and the rows before it
/// (I7, the reference sequence, I17) have already passed: the refusal is
/// the signature's, not an earlier row's. The row itself stays unrecorded
/// on that refusal.
#[test]
fn i18_refuses_a_forged_signature_at_its_input() {
    let chain = spendable_chain();
    // Two inputs, so the refusal's input index is a discrimination and not
    // the only value it could take.
    let mut two = spend(KI, 2);
    two.prefix.inputs.push(Input::ToKey {
        amount: 0,
        key_offsets: Vec::new(),
        key_image: [0x2b; 32],
    });
    if let Ct::Fcmp { pqc_auths, .. } = &mut two.ct {
        pqc_auths.push(crate::harness::fixture::pqc_auth_filler());
    }
    let mut tx = anchored_on(&chain, two);
    let Ct::Fcmp { pqc_auths, .. } = &mut tx.ct else {
        panic!("a spend is Fcmp");
    };
    assert_eq!(pqc_auths.len(), 2, "both slots signed at anchoring");
    *pqc_auths[1]
        .hybrid_signature
        .last_mut()
        .expect("a signature") ^= 0x01;
    chain.with_view(|view| {
        assert_refused(
            defined(tx_against(&tx, TxSlot::Lone, &view, &RuleSet::GENESIS)),
            CenRow::I18,
            Locus::Input {
                slot: TxSlot::Lone,
                input: 1,
            },
        );
    });
    // Both refusal arms leave the row unrecorded. `tx_against` drops its
    // coverage with the verdict, so the contract is held on `I18::check`.
    let mut coverage = RuleCoverage::EMPTY;
    let cx =
        TxContext::derive(&tx, TxSlot::Lone, &mut coverage).expect("the forged spend classifies");
    let hashes = I17::signed_hashes(&cx, &mut coverage);
    assert!(I18::check(&cx, &hashes, &mut coverage).is_err());
    assert!(
        !coverage.contains(CenRow::I18),
        "a signature that does not verify does not record the row"
    );
    let mut coverage = RuleCoverage::EMPTY;
    let intact = listed_on(&chain, KI);
    let cx = TxContext::derive(&intact, TxSlot::Lone, &mut coverage).expect("a spend classifies");
    assert!(I18::check(&cx, &[], &mut coverage).is_err());
    assert!(
        !coverage.contains(CenRow::I18),
        "a hash list that is not one per auth does not record the row"
    );
}

/// A signature that is valid — for a different message. Touching the
/// prefix after signing (here `unlock_time`, a field no view-bound row
/// reads) changes the pruned segment every slot's message binds, so a
/// standing signature no longer verifies: refused at input 0, the first
/// slot judged. This is the binding I17 exists for, witnessed from the
/// verifying side.
#[test]
fn i18_refuses_a_signature_over_a_body_that_has_since_changed() {
    let chain = spendable_chain();
    let mut tx = listed_on(&chain, KI);
    tx.prefix.unlock_time += 1;
    chain.with_view(|view| {
        assert_refused(
            defined(tx_against(&tx, TxSlot::Lone, &view, &RuleSet::GENESIS)),
            CenRow::I18,
            Locus::Input {
                slot: TxSlot::Lone,
                input: 0,
            },
        );
    });
}

/// The boundary row 8 pinned before this row started: on the serve-credit
/// form I18 verifies nothing — corrupt the pass record's countersignature
/// legs and the verdict does not move — because the form's signature is
/// CEN-J10's, over the pass record, and I17 yields no message here. A
/// verifier that reached for J10's object would refuse a corrupt one; this
/// is the falsifier for "does not reach". Recorded vacuous, not absent
/// (slice 5 Q2), as the I17 test on the same body explains.
///
/// Called as the signature sequence, not through `tx_against`, for the
/// reason the I10–I12 test above gives: over the mock a credit is CEN-J4's
/// refusal first, and this test's subject is the row after it.
#[test]
fn i18_is_vacuous_on_a_serve_credit_and_does_not_reach_for_its_countersignature() {
    let mut corrupt = serve_credit_only([0x5e; 32]);
    match &mut corrupt.prefix.inputs[0] {
        Input::ServeCredit { canonical_bytes } => {
            for byte in &mut canonical_bytes[1..] {
                *byte ^= 0xFF;
            }
        }
        other => panic!("a serve-credit fixture carries a serve-credit input, not {other:?}"),
    }
    let mut coverage = RuleCoverage::EMPTY;
    let cx = TxContext::derive(&corrupt, TxSlot::Lone, &mut coverage)
        .expect("a serve-credit-only body classifies");
    judge_signatures(&cx, &mut coverage)
        .expect("J10's object is not this row's; the verdict does not move");
    assert!(
        coverage.contains(CenRow::I18),
        "recorded vacuous, not absent"
    );
}

// ---- CEN-I2, by construction ------------------------------------------

/// CEN-I2 — a non-coinbase transaction's CT is `FcmpPlusPlusPqc` — holds
/// by construction on the wire's type set plus H15: `Ct` has two variants,
/// the parser admits exactly two type bytes, and the `Null` variant off
/// the coinbase is H15's landed refusal. List-and-iterate (slice 5 Q6):
/// the row this falsifier is credited to is named, the type set is
/// walked, and H15's refusal is re-asserted here so the two halves of the
/// property fail in one place.
#[test]
fn i2_the_wire_admits_two_ct_types_and_h15_refuses_null_off_the_coinbase() {
    credited_to_this_falsifier(
        &[CenRow::I2],
        "i2_the_wire_admits_two_ct_types_and_h15_refuses_null_off_the_coinbase",
    );
    // The type byte leads the CT section, which is the tail of the
    // transaction: `varint(TX_VERSION) ‖ prefix ‖ Ct::write`.
    let tx = listed(KI);
    let mut ct = Vec::new();
    tx.ct.write(&mut ct).expect("Vec");
    let bytes = tx.serialize();
    let type_at = bytes.len() - ct.len();
    assert_eq!(bytes[type_at], CT_TYPE_FCMP);
    assert_eq!(&bytes[type_at..], ct.as_slice());
    assert!(Transaction::from_bytes(&bytes).is_ok());
    for other in [0x02u8, 0x03, 0x7F, 0xFF] {
        let mut mutated = bytes.clone();
        mutated[type_at] = other;
        assert!(
            Transaction::from_bytes(&mutated).is_err(),
            "ct type {other:#04x} must not decode"
        );
    }
    // The one other type the wire admits is `Null`, and off the coinbase it
    // is H15's refusal at both sites.
    let mut null = listed(KI);
    null.ct = Ct::Null(CtBase {
        enc_amounts: vec![[0x11; 9]; 2],
        enc_labels: vec![[0x22; 9]; 2],
        commitments: vec![TWO_G; 2],
    });
    refused_lone(&null, CenRow::H15);
    refused_listed(&null, CenRow::H15);
    // And on the coinbase `Null` is the shape (F3): the type set has no
    // third member for either slot to reach.
    let _ = coinbase(1);
}
