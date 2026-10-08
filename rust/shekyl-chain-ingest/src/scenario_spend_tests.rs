// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Real spends through the production stack: the acceptances, and the
//! refusals behind an accepted body, that `shekyl-chain-rules` cannot
//! witness (`CHAIN_RULES_SLICE_6.md` §5 row 6).
//!
//! A fixture spend is refused at CEN-I13 on any `MockChain` view — its
//! `referenceBlock` is a hash no chain holds — so the only block the rules
//! crate can see `validate` accept is coinbase-only, and nothing there can
//! stand *behind* a listed body that passed. Each test here is one of the
//! witnesses that crate's tests point at, by name: the rows a connected
//! spend records (`Mined::judged_by`), the listed body as the block
//! weight's addend (`Mined::weights`), CEN-L1 across two slots, and the
//! two per-slot refusals at `Listed(1)` — CEN-I18 on a moved body and
//! CEN-I7 on a respend — that only a passing `Listed(0)` makes reachable.
//! What moved from the rules crate is the witness, not the row.
//!
//! The chain is `body_pairing_tests::two_body_chain`'s: [`AT`] empty
//! blocks, then spends of block 0's and block 1's coinbases, the first two
//! that mature (a coinbase from block `k` spends at `k +
//! FIRST_SPEND_HEIGHT`). Default lane, like that file.

use shekyl_chain_rules::{CenRow, Locus, TxSlot};
use shekyl_harness_spender::Spender;
use shekyl_types::BlockWeight;
use shekyl_wire::Transaction;

use crate::archival_driver::refused_at;
use crate::scenario::{FreeHash, Mined, Scenario};
use crate::test_support::{h, Family, FIRST_SPEND_HEIGHT};

/// The height of the spending block: block 0's and block 1's coinbases
/// have both matured for it, and the respend test's third (block 2's) for
/// the block after.
const AT: u64 = FIRST_SPEND_HEIGHT + 1;

/// The rows a block of real spends is judged under beyond the coinbase-only
/// set (`scenario_tests::JUDGES_EVERY_BLOCK`): the listed form's H4, the
/// per-slot sequence `tx_against` runs on a spend (I7, I10–I12, I17, I18),
/// the chain-arm G1 before the slot loop and L1 after it. The rows I13 and
/// I15 join when the spend class's depth step and anchor turn on
/// (`CHAIN_RULES_SLICE_6.md` §5 row 6; the flip commit adds them here).
const JUDGES_A_SPENDING_BLOCK: [CenRow; 9] = [
    CenRow::H4,
    CenRow::G1,
    CenRow::I7,
    CenRow::I10,
    CenRow::I11,
    CenRow::I12,
    CenRow::I17,
    CenRow::I18,
    CenRow::L1,
];

/// Mine [`AT`] empty blocks and build the two spends the block at [`AT`]
/// lists — block 0's coinbase at `fee`, block 1's at the family fee.
async fn matured(name: &str) -> (Scenario<FreeHash>, Vec<Mined>, Transaction, Transaction) {
    let mut scenario = Scenario::open(name);
    let mined = scenario.mine(AT).await;
    let (a, b) = {
        let spender = Spender::over(&mined);
        let wallet = scenario.wallet();
        (
            spender.spend_coinbase(wallet, h(0), h(AT), Family::Main.fee()),
            spender.spend_coinbase(wallet, h(1), h(AT), Family::Main.fee()),
        )
    };
    (scenario, mined, a, b)
}

/// Where a refusal at the second listed slot's first input is written.
const SECOND_SLOT_FIRST_INPUT: Locus = Locus::Input {
    slot: TxSlot::Listed(1),
    input: 0,
};

/// Two real spends connect; the block records every per-slot row once
/// (the per-slot coverages are unioned by `validate`: H4 appears once for
/// two listed bodies), L1 and G1 with them; and the verdict's weight is
/// the coinbase's plus each listed body's — `blockchain.cpp:5445`'s
/// `coinbase_weight + Σ td.weight`, which the rules crate's clamp test
/// can show only with an empty sum.
#[tokio::test]
async fn two_spends_connect_and_the_per_slot_rows_record() {
    let (mut scenario, _mined, a, b) = matured("spend-two").await;
    let two = scenario
        .mine_listing(vec![a.clone(), b.clone()])
        .await
        .unwrap_or_else(|outcome| panic!("two real spends connect: {outcome}"));
    assert_eq!(two.height, h(AT));
    for row in JUDGES_A_SPENDING_BLOCK {
        assert!(
            two.judged_by.contains(&row),
            "{row} did not judge the spending block"
        );
    }
    let coinbase = &two.template.block.miner_transaction;
    let expected = coinbase.weight() + a.weight() + b.weight();
    assert_eq!(
        two.weights.weight,
        BlockWeight::from_raw(u64::try_from(expected).expect("fits")),
        "the block's weight is the coinbase's plus every listed body's"
    );
    scenario.close().await;
}

/// CEN-L1 across slots: a twin of the first spend at another fee is a
/// different body over the same key image, admissible alone, and refused
/// behind the first at `Listed(1)`, input 0 — the second occurrence, as
/// the row names it. The chain holds neither image yet, so I7 passes both
/// slots and L1, after the slot loop, is what refuses.
#[tokio::test]
async fn l1_refuses_a_twin_spend_listed_behind_the_first() {
    let (mut scenario, mined, a, _b) = matured("spend-twin-l1").await;
    let twin = Spender::over(&mined).spend_coinbase(
        scenario.wallet(),
        h(0),
        h(AT),
        Family::Main.fee() + 1,
    );
    assert_ne!(twin.hash(), a.hash(), "another fee is another body");
    refused_at(
        scenario.mine_listing(vec![a, twin]).await,
        CenRow::L1,
        SECOND_SLOT_FIRST_INPUT,
    );
    scenario.close().await;
}

/// A body moved after it was signed: the first spend's prefix touched
/// (`unlock_time`, a field no view-bound row reads) and listed behind the
/// untouched one. Its key image doubles the first's, so L1 would refuse it
/// too — but the slot loop runs first, and the first row in the spend's
/// `tx_against` sequence that binds the prefix refuses at `Listed(1)`: a
/// per-transaction row behind a passing body is seen before the
/// block-level row, the C++'s order (`add_spent_key` is the last check).
/// Today that row is I18, at input 0 — the signature no longer covers its
/// message. When CEN-I15 runs on the spend class (slice 6 row 6's flip,
/// this PR) the membership proof binds the prefix earlier in the sequence
/// and the refusal is I15's, at the transaction; the signature's own
/// binding stays witnessed on the signature sequence in the rules crate.
/// The mutation family's `ForgedSignature` flips the signature and leaves
/// the body.
#[tokio::test]
async fn a_moved_body_listed_behind_its_twin_is_refused_per_slot_before_l1_can() {
    let (mut scenario, _mined, a, _b) = matured("spend-moved-i18").await;
    let mut moved = a.clone();
    moved.prefix.unlock_time += 1;
    refused_at(
        scenario.mine_listing(vec![a, moved]).await,
        CenRow::I18,
        SECOND_SLOT_FIRST_INPUT,
    );
    scenario.close().await;
}

/// CEN-I7 behind a passing body: after the two spends connect, the block
/// after lists a fresh spend (block 2's coinbase) first and a respend of
/// block 0's — a new body over an image the chain now holds — second. The
/// refusal is written at `Listed(1)`, input 0: the transaction's position,
/// not the pool's, and nothing re-homes it. The rules crate's listed-slot
/// test can reach only `Listed(0)`, since a fixture ahead of its subject
/// would be refused at I13 first.
#[tokio::test]
async fn i7_refuses_a_respend_at_the_slot_behind_a_fresh_spend() {
    let (mut scenario, mut mined, a, b) = matured("spend-respend-i7").await;
    let two = scenario
        .mine_listing(vec![a, b])
        .await
        .unwrap_or_else(|outcome| panic!("two real spends connect: {outcome}"));
    mined.push(two);
    let after = AT + 1;
    let (fresh, respend) = {
        let spender = Spender::over(&mined);
        let wallet = scenario.wallet();
        (
            spender.spend_coinbase(wallet, h(2), h(after), Family::Main.fee()),
            spender.spend_coinbase(wallet, h(0), h(after), Family::Main.fee()),
        )
    };
    refused_at(
        scenario.mine_listing(vec![fresh, respend]).await,
        CenRow::I7,
        SECOND_SLOT_FIRST_INPUT,
    );
    scenario.close().await;
}
