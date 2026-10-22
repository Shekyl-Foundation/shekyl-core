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
//! two per-slot refusals at `Listed(1)` — CEN-I15 on a moved body and
//! CEN-I7 on a respend — that only a passing `Listed(0)` makes reachable.
//! What moved from the rules crate is the witness, not the row.
//!
//! The chain is `body_pairing_tests::two_body_chain`'s: [`AT`] empty
//! blocks, then spends of block 0's and block 1's coinbases, the first two
//! that mature (a coinbase from block `k` spends at `k +
//! FIRST_SPEND_HEIGHT`). Default lane, like that file.

use shekyl_block_template::Fill;
use shekyl_chain_rules::{CenRow, Locus, TxSlot};
use shekyl_economics::{EconomicParams, TxVolume};
use shekyl_harness_spender::Spender;
use shekyl_types::BlockWeight;
use shekyl_wire::transaction::COINBASE_RESERVE;
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
/// per-slot sequence `tx_against` runs on a spend (I7, I10–I13, I15, I17,
/// I18), the chain-arm G1 before the slot loop, and after it the block's
/// range-proof batch (H19's verification half) and L1. I13 and I15 are the
/// rows the flip of `CHAIN_RULES_SLICE_6.md` §5 row 6 turned on
/// (2026-10-08): a real spend's declared depth admitted at its reference,
/// and its membership proof verified there. H19 records once the batch over
/// both spends' proofs has decided.
const JUDGES_A_SPENDING_BLOCK: [CenRow; 12] = [
    CenRow::H4,
    CenRow::H19,
    CenRow::G1,
    CenRow::I7,
    CenRow::I10,
    CenRow::I11,
    CenRow::I12,
    CenRow::I13,
    CenRow::I15,
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
/// too — but the per-slot rows run first, and the first row in the
/// spend's sequence that binds the prefix refuses at `Listed(1)`: a
/// per-transaction row behind a passing body is seen before the
/// block-level row, the C++'s order (`add_spent_key` is the last check).
/// That row is CEN-I18, at input 0: since 2026-10-16 `form` runs the
/// signature sequence at every listed slot before the verify rows
/// (`CHAIN_RULES_CRATE.md` §4.6), and the signing preimage binds the
/// prefix (CEN-I17), so the signature no longer covers its message before
/// the membership proof — which binds the prefix hash too — is verified.
/// *Records-was:* from the flip (slice 6 row 6, 2026-10-08) to 2026-10-16
/// the row was CEN-I15 at the transaction, `validate` verifying the proof
/// ahead of the signatures; before the flip, I18 at input 0 as now. The
/// proof's own binding stays witnessed by the mutation family and the
/// rules crate; `ForgedSignature` flips the signature and leaves the body.
#[tokio::test]
async fn a_moved_body_listed_behind_its_twin_is_refused_per_slot_before_l1_can() {
    let (mut scenario, _mined, a, _b) = matured("spend-moved-i18").await;
    let mut moved = a.clone();
    moved.prefix.unlock_time += 1;
    refused_at(
        scenario.mine_listing(vec![a, moved]).await,
        CenRow::I18,
        Locus::Input {
            slot: TxSlot::Listed(1),
            input: 0,
        },
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

/// CEN-H19's verification half on the production stack (slice 6 Q9's
/// fixture): a driven block listing two wallet-built spends, the second's
/// range proof one bit off what its prover made, is refused on H19 at that
/// transaction; the same two spends unflipped connect, with H19 recorded —
/// the positive control. The flip is made before the wallet signs
/// (`Spender::spend_coinbase_breaking_range_proof`), so every other row
/// passes the body: flipped after, it is CEN-I18's refusal in the slot loop
/// and never reaches the batch.
#[tokio::test]
async fn h19_refuses_a_flipped_range_proof_and_the_unflipped_block_connects() {
    let (mut scenario, mined, a, b) = matured("spend-h19-flip").await;
    let flipped = Spender::over(&mined).spend_coinbase_breaking_range_proof(
        scenario.wallet(),
        h(1),
        h(AT),
        Family::Main.fee(),
    );
    refused_at(
        scenario.mine_listing(vec![a.clone(), flipped]).await,
        CenRow::H19,
        Locus::Tx {
            slot: TxSlot::Listed(1),
        },
    );
    let two = scenario
        .mine_listing(vec![a, b])
        .await
        .unwrap_or_else(|outcome| panic!("the unflipped spends connect: {outcome}"));
    assert!(
        two.judged_by.contains(&CenRow::H19),
        "the batch decided the unflipped block"
    );
    scenario.close().await;
}

/// The locus: one bad proof among good ones, in the middle of three listed
/// spends, and the refusal names that transaction — the batch fails, and
/// each proof re-verified alone under its own derived seed finds it.
#[tokio::test]
async fn h19_names_the_bad_proof_among_good_ones() {
    let mut scenario = Scenario::open("spend-h19-locus");
    let mined = scenario.mine(AT + 1).await;
    let at = AT + 1;
    let listed = {
        let spender = Spender::over(&mined);
        let wallet = scenario.wallet();
        let fee = Family::Main.fee();
        vec![
            spender.spend_coinbase(wallet, h(0), h(at), fee),
            spender.spend_coinbase_breaking_range_proof(wallet, h(1), h(at), fee),
            spender.spend_coinbase(wallet, h(2), h(at), fee),
        ]
    };
    refused_at(
        scenario.mine_listing(listed).await,
        CenRow::H19,
        Locus::Tx {
            slot: TxSlot::Listed(1),
        },
    );
    scenario.close().await;
}

/// Bodies at the fill's bound connect, and the validator admits the block.
///
/// The bound is the fill's at the production zone — the median an early
/// chain floors at — less the derived coinbase reserve. A filler spend
/// cannot witness it: CEN-I13 refuses one on any mock view, and the
/// validator prices from the static parameter set, so the zone cannot be
/// shrunk for the test. The spends are the harness miner's coinbases,
/// built across the cores the way the shard fill builds them, and the
/// block enters through the scenario's door.
#[tokio::test]
async fn bodies_at_the_fills_bound_are_admitted() {
    let params = EconomicParams::default();
    let zone = params.full_reward_zone;
    let coinbase = u64::try_from(COINBASE_RESERVE).expect("the reserve fits");
    let bound = Fill::empty(
        zone,
        coinbase,
        0,
        TxVolume::per_block(params.tx_volume_baseline),
        &params,
    )
    .expect("an empty block at the zone prices")
    .bodies_weight_bound();

    let mut scenario = Scenario::open("spend-bound");
    // One matured coinbase sizes the batch. It is not listed: the spends
    // that connect are built at the later height, against that height's
    // reference.
    let mut mined = scenario.mine(FIRST_SPEND_HEIGHT).await;
    let sample = Spender::over(&mined).spend_coinbase(
        scenario.wallet(),
        h(0),
        h(FIRST_SPEND_HEIGHT),
        Family::Main.fee(),
    );
    let one = u64::try_from(sample.weight()).expect("a spend's weight fits");
    assert!(one > 0 && one <= bound, "one spend fits under the bound");
    let count = usize::try_from(bound / one).expect("the count fits");

    // Coinbase `k` is spendable at `k + FIRST_SPEND_HEIGHT`. `count`
    // coinbases (0..count) are all mature when the next block is
    // `FIRST_SPEND_HEIGHT + count - 1`, and `mine` has already landed the
    // first `FIRST_SPEND_HEIGHT` blocks.
    if count > 1 {
        mined.extend(
            scenario
                .mine(u64::try_from(count - 1).expect("the count fits"))
                .await,
        );
    }
    let at = FIRST_SPEND_HEIGHT + u64::try_from(count - 1).expect("the count fits");
    assert_eq!(
        mined.len(),
        usize::try_from(at).expect("the height fits"),
        "the prefix reaches the spending height"
    );

    let spender = Spender::over(&mined);
    let wallet = scenario.wallet();
    let fee = Family::Main.fee();
    let listed: Vec<Transaction> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..count)
            .map(|i| {
                let height = u64::try_from(i).expect("the count fits");
                let spender = &spender;
                scope.spawn(move || spender.spend_coinbase(wallet, h(height), h(at), fee))
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("a spend builds"))
            .collect()
    });
    let mut listed = listed;
    let unit = u64::try_from(listed[0].weight()).expect("a spend's weight fits");
    assert!(
        listed.iter().all(|tx| tx.weight() == listed[0].weight()),
        "every spend in the batch has the same weight"
    );
    // The sample that sized the batch was built at an earlier height. A
    // wider varint here makes each spend a byte heavier, and the batch
    // drops the tail until one more of this weight would pass the bound.
    while listed.len() > 1 {
        let bodies: u64 = u64::try_from(listed.len()).expect("fits") * unit;
        if bodies <= bound {
            break;
        }
        listed.pop();
    }
    let count = listed.len();
    let bodies = u64::try_from(count).expect("fits") * unit;
    assert!(bodies <= bound, "the batch fits the fill's bound");
    assert!(
        bodies + unit > bound,
        "one more spend of this weight still fits the bound"
    );

    let block = scenario
        .mine_listing(listed)
        .await
        .unwrap_or_else(|outcome| panic!("spends at the fill's bound connect: {outcome}"));
    assert_eq!(
        block.template.transactions.len(),
        count,
        "the template kept every spend"
    );
    let coinbase_weight = block.template.block.miner_transaction.weight();
    assert!(
        coinbase_weight <= COINBASE_RESERVE,
        "the built coinbase is within the derived reserve"
    );
    let limit = block.weights.medians.limit().to_raw();
    assert_eq!(
        limit,
        zone.saturating_mul(2),
        "the early chain floors at the zone"
    );
    assert!(
        block.weights.weight.to_raw() <= limit,
        "the validator's weight is within twice the median"
    );
    let expected = u64::try_from(coinbase_weight).expect("fits") + bodies;
    assert_eq!(
        block.weights.weight,
        BlockWeight::from_raw(expected),
        "the admitted weight is the coinbase plus the spends"
    );
    assert!(
        block.judged_by.contains(&CenRow::F14),
        "the weight bound judged the block"
    );
    eprintln!(
        "bound admission: {count} spends of {unit} B, bodies {bodies} B, bound {bound} B, block {} B",
        block.weights.weight.to_raw()
    );
    scenario.close().await;
}
