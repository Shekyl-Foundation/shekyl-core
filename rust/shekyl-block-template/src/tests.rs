// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a block template must do, by design — each test names the census
//! row or spec clause it holds the template to, and the validator judges
//! wherever a row has landed. Nothing here transcribes
//! `create_block_template`; byte-parity with it is a different witness.

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use shekyl_chain_rules::harness::fixture::{point_at, recorded_with_work, root, spend};
use shekyl_chain_rules::harness::{expected_seed, judged, MockChain, MockSubstrate};
use shekyl_chain_rules::{
    form, validate, Candidate, CenRow, ChainView, FormAttempt, RuleSet, Trust,
};
use shekyl_crypto_pq::kem::{HybridX25519MlKem, KeyEncapsulation};
use shekyl_difficulty::{CumulativeDifficulty, GENESIS_DIFFICULTY};
use shekyl_economics::{
    compute_emission_split, compute_fee_burn, paid_block_reward, CirculatingSupply, EconomicParams,
    FrozenSegmentCount, TxVolume, FULL_REWARD_ZONE,
};
use shekyl_types::{AttestationRoot, BlockHash, BlockHeight, CurveTreeRoot, Timestamp};
use shekyl_units::AtomicUnits;
use shekyl_wire::transaction::{Ct, Input, Transaction};
use shekyl_wire::tx_extra::{self, check_tx_extra_shape, ExtraSubject, TxExtraField};

use crate::{
    build, template_timestamp, tx_pubkey, EmissionOperands, MinerKeys, Template, TemplateContext,
    TemplateError,
};

/// A miner: spend key `k·G` for a fixed `k`, hybrid KEM keys generated
/// once. Every template in a test pays the same miner, so determinism is
/// the template's and not the keys'.
fn miner() -> MinerKeys {
    let k = Scalar::from_bytes_mod_order([0x4d; 32]);
    let (pk, _sk) = HybridX25519MlKem
        .keypair_generate()
        .expect("hybrid KEM keypair generation");
    MinerKeys {
        spend_public: EdwardsPoint::mul_base(&k).compress().to_bytes(),
        x25519_pk: pk.x25519,
        ml_kem_ek: pk.ml_kem,
    }
}

/// The harness clock is `1_700_000_100`; the producer's clock sits just
/// under it, and the recorded blocks' timestamps run up to it, so C1 and C2
/// both have room to hold.
const NOW: Timestamp = Timestamp::from_raw(1_700_000_050);

/// A chain of `len` recorded blocks, work recorded at the genesis
/// difficulty, timestamps ascending 120 s apart and ending below [`NOW`].
fn chain_of(len: u64) -> MockChain {
    (0..len).fold(MockChain::default(), |chain, h| {
        chain.push(
            recorded_with_work(
                1_699_000_000 + h * 120,
                CumulativeDifficulty::from_raw(u128::from(h + 1) * GENESIS_DIFFICULTY),
            ),
            root(u8::try_from(h % 250).expect("fits") + 1),
        )
    })
}

/// What the tip tells a template: the connecting height, the tip's
/// identity, and the tree state at the connecting height (CEN-B5) — read
/// off the view the way a driver reads them off the store.
fn tip_facts(chain: &MockChain) -> (BlockHeight, BlockHash, CurveTreeRoot) {
    let tip = chain.tip();
    // `tip + 1`, `0` on an empty chain. `Tip::connecting_height` is the
    // rules crate's own operand and crate-private by ruling
    // (`CHAIN_RULES_SLICE_1.md` §2); a test computing the same figure is
    // not the second production consumer that ruling names.
    let connecting = tip.as_ref().map_or(BlockHeight::ZERO, |t| {
        BlockHeight::from_raw(t.height.to_raw() + 1)
    });
    let root = chain.with_view(|view| {
        let root = view.root_at(connecting);
        match shekyl_chain_rules::harness::infallible(root) {
            shekyl_chain_rules::AtHeight::Recorded(root) => root,
            shekyl_chain_rules::AtHeight::AboveTip => panic!("the mock records root_at(tip + 1)"),
        }
    });
    (connecting, tip.map_or(BlockHash::NULL, |t| t.hash), root)
}

/// The median the recorded chain has: the middle timestamp of its blocks,
/// `None` when empty. (The C2 window is wider than these chains; the
/// median of everything is what the rule computes below the window.)
fn median_of(chain: &MockChain) -> Option<Timestamp> {
    let tip = chain.tip()?;
    let mut stamps: Vec<u64> = chain.with_view(|view| {
        (0..=tip.height.to_raw())
            .map(|h| {
                match shekyl_chain_rules::harness::infallible(
                    view.block_at(BlockHeight::from_raw(h)),
                ) {
                    shekyl_chain_rules::AtHeight::Recorded(block) => block.header.timestamp,
                    shekyl_chain_rules::AtHeight::AboveTip => panic!("below the tip"),
                }
            })
            .collect()
    });
    stamps.sort_unstable();
    Some(Timestamp::from_raw(stamps[stamps.len() / 2]))
}

/// Emission operands for a chain whose recorded blocks generated nothing —
/// the fixture chain's record — at the genesis epoch.
fn genesis_era_emission() -> EmissionOperands {
    EmissionOperands {
        already_generated_coins: AtomicUnits::ZERO,
        total_burned: AtomicUnits::ZERO,
        median_weight: FULL_REWARD_ZONE,
        tx_volume: TxVolume::ZERO,
        frozen_segments: FrozenSegmentCount::ZERO,
        emission_split_epoch: BlockHeight::from_raw(1),
    }
}

/// The context a driver composes for `chain`'s next block, listing
/// `listed`. `params` and `miner` outlive it.
fn context<'a>(
    chain: &MockChain,
    params: &'a EconomicParams,
    miner: &'a MinerKeys,
    listed: &'a [Transaction],
) -> TemplateContext<'a> {
    let (height, previous, curve_tree_root) = tip_facts(chain);
    TemplateContext {
        height,
        previous,
        curve_tree_root,
        attestation_root: AttestationRoot::from_bytes([0x33; 32]),
        major_version: RuleSet::GENESIS.header_major_version(),
        minor_version: 0,
        now: NOW,
        median_timestamp: median_of(chain),
        unlock_window: RuleSet::GENESIS.mined_money_unlock_window(),
        emission: genesis_era_emission(),
        params,
        miner,
        tx_key_secret: [0x77; 32],
        extra_nonce: [0; tx_extra::COINBASE_NONCE_BYTES],
        listed,
    }
}

/// Both stages over `chain` under the genesis rule set, claiming the seed
/// the chain expects. Returns the rows that judged the candidate.
fn admitted(chain: &MockChain, template: Template) -> Vec<CenRow> {
    let candidate = Candidate::new(template.block, template.transactions);
    let formed = form(
        candidate,
        &RuleSet::GENESIS,
        &MockSubstrate::default(),
        expected_seed(chain),
        FormAttempt::FIRST,
    )
    .expect("the default substrate never faults")
    .unwrap_or_else(|refused| panic!("the template was refused by a stateless rule: {refused}"));
    chain.with_view(|view| {
        let valid = judged(validate(
            formed,
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .unwrap_or_else(|refused| panic!("the template was refused by a view rule: {refused}"));
        CenRow::ALL
            .iter()
            .copied()
            .filter(|row| valid.coverage().contains(*row))
            .collect()
    })
}

// ---------------------------------------------------------------------------
// The validator is the falsifier
// ---------------------------------------------------------------------------

/// The 4.F rows the validator has landed: every one of them judged the
/// template, and none refused it. Rows this list omits (F14, F16–F18) are
/// pending on CEN-G6 (slice 7) and are held by construction below until
/// they land; when they land they belong here.
const LANDED_MINER_ROWS: [CenRow; 8] = [
    CenRow::F1,
    CenRow::F3,
    CenRow::F4,
    CenRow::F5,
    CenRow::F6,
    CenRow::F7,
    CenRow::F9,
    CenRow::F10,
];

#[test]
fn the_genesis_template_is_admitted_and_judged_by_every_landed_miner_row() {
    let params = EconomicParams::default();
    let miner = miner();
    let chain = MockChain::default();
    let template = build(&context(&chain, &params, &miner, &[])).expect("builds");
    let judged_by = admitted(&chain, template);
    for row in LANDED_MINER_ROWS {
        assert!(
            judged_by.contains(&row),
            "{row} did not judge the genesis template"
        );
    }
}

#[test]
fn the_template_on_a_tip_is_admitted_and_judged_by_every_landed_miner_row() {
    let params = EconomicParams::default();
    let miner = miner();
    let chain = chain_of(3);
    let template = build(&context(&chain, &params, &miner, &[])).expect("builds");
    let judged_by = admitted(&chain, template);
    for row in LANDED_MINER_ROWS {
        assert!(judged_by.contains(&row), "{row} did not judge the template");
    }
    // The header rows the template satisfies from the tip's facts.
    for row in [CenRow::A2, CenRow::B1, CenRow::B5, CenRow::C1, CenRow::C2] {
        assert!(judged_by.contains(&row), "{row} did not judge the template");
    }
}

#[test]
fn a_template_listing_bodies_hashes_them_in_order() {
    let params = EconomicParams::default();
    let miner = miner();
    let chain = chain_of(2);
    let listed = [spend(point_at(11), 1), spend(point_at(12), 2)];
    let template = build(&context(&chain, &params, &miner, &listed)).expect("builds");
    assert_eq!(
        template.block.transaction_hashes,
        listed.iter().map(Transaction::hash).collect::<Vec<_>>(),
        "CEN-A3/A4: the header names the listed bodies, in order"
    );
    // A3 is pending and A4 held by the C++ (census); the validator admits
    // the block with its bodies, and the naming is asserted above.
    let _judged_by = admitted(&chain, template);
}

// ---------------------------------------------------------------------------
// The coinbase, by design
// ---------------------------------------------------------------------------

#[test]
fn the_coinbase_has_one_gen_input_at_the_connecting_height_and_one_output() {
    let params = EconomicParams::default();
    let miner = miner();
    let chain = chain_of(5);
    let template = build(&context(&chain, &params, &miner, &[])).expect("builds");
    let coinbase = &template.block.miner_transaction;
    assert_eq!(coinbase.prefix.inputs, vec![Input::Gen(5)], "CEN-F1/F5");
    assert_eq!(
        coinbase.prefix.outputs.len(),
        1,
        "CEN-F4: one output above genesis"
    );
    assert_eq!(
        coinbase.prefix.unlock_time,
        5 + RuleSet::GENESIS.mined_money_unlock_window().to_raw(),
        "CEN-F6"
    );
    assert!(matches!(coinbase.ct, Ct::Null(_)), "CEN-F3");
}

#[test]
fn the_coinbase_pays_exactly_the_miners_leg_of_the_split_plus_its_fee_share() {
    // CEN-F18 over F13/F14/F15/F16/F17/F20. The validator's row is pending
    // on G6 (slice 7); until it lands, this is the identity it will
    // falsify, computed here from the owners on the template's own
    // operands — including the weight the template reports it priced at.
    let params = EconomicParams::default();
    let miner = miner();
    let chain = chain_of(2);
    let listed = [spend(point_at(21), 1), spend(point_at(22), 1)];
    let cx = context(&chain, &params, &miner, &listed);
    let template = build(&cx).expect("builds");

    let fees: u64 = listed
        .iter()
        .map(|tx| match &tx.ct {
            Ct::Fcmp { fee, .. } => *fee,
            Ct::Null(_) => unreachable!("fixture spends carry a fee"),
        })
        .sum();
    let reward = paid_block_reward(
        cx.emission.median_weight,
        template.block_weight,
        cx.emission.already_generated_coins.to_raw(),
        cx.emission.tx_volume,
        &params,
    )
    .expect("priceable");
    let split = compute_emission_split(reward, cx.height.to_raw(), 1);
    let supply =
        CirculatingSupply::derive(AtomicUnits::ZERO, AtomicUnits::ZERO).expect("consistent");
    let burn = compute_fee_burn(
        fees,
        cx.emission.tx_volume,
        supply,
        FrozenSegmentCount::ZERO,
        &params,
    );

    let paid = template.block.miner_transaction.prefix.outputs[0].amount;
    assert_eq!(
        paid,
        split.miner_emission + burn.miner_fee_income,
        "CEN-F18"
    );
    assert_eq!(template.total_fees.to_raw(), fees);
    assert_eq!(
        template.block_reward.to_raw(),
        reward,
        "CEN-F13's generation figure"
    );
    assert_eq!(template.miner_emission.to_raw(), split.miner_emission);
    assert_eq!(template.miner_fee_income.to_raw(), burn.miner_fee_income);
}

#[test]
fn the_weight_the_reward_was_priced_at_is_the_weight_the_block_carries() {
    // CEN-F14's operand: the penalty is a function of the block's weight,
    // coinbase included, so the assembly must settle on a coinbase whose
    // own size is already in the weight it was priced at.
    let params = EconomicParams::default();
    let miner = miner();
    let chain = chain_of(2);
    let listed = [spend(point_at(31), 3)];
    let template = build(&context(&chain, &params, &miner, &listed)).expect("builds");
    let carried: usize = template.block.miner_transaction.weight()
        + template
            .transactions
            .iter()
            .map(Transaction::weight)
            .sum::<usize>();
    assert_eq!(u64::try_from(carried).expect("fits"), template.block_weight);
}

#[test]
fn the_extra_is_the_coinbase_grammar_and_names_the_tx_public_key() {
    let params = EconomicParams::default();
    let miner = miner();
    let chain = chain_of(1);
    let cx = context(&chain, &params, &miner, &[]);
    let template = build(&cx).expect("builds");
    let coinbase = &template.block.miner_transaction;
    let fields = tx_extra::parse(&coinbase.prefix.extra).expect("parses");
    check_tx_extra_shape(
        &fields,
        coinbase.prefix.outputs.len(),
        ExtraSubject::Coinbase,
    )
    .expect("CEN-I20: the coinbase grammar");
    assert!(
        fields.contains(&TxExtraField::PubKey(tx_pubkey(&cx.tx_key_secret))),
        "the 0x01 field is r·G for the context's r"
    );
    assert!(
        fields.contains(&TxExtraField::Nonce(cx.extra_nonce.to_vec())),
        "the 0x02 field is the context's nonce"
    );
}

#[test]
fn the_coinbase_round_trips_the_wire() {
    let params = EconomicParams::default();
    let miner = miner();
    let chain = chain_of(1);
    let template = build(&context(&chain, &params, &miner, &[])).expect("builds");
    let coinbase = &template.block.miner_transaction;
    coinbase
        .validate_context_free_pruned()
        .expect("context-free valid");
    let reparsed = Transaction::from_bytes(&coinbase.serialize()).expect("re-parses");
    assert_eq!(&reparsed, coinbase);
}

// ---------------------------------------------------------------------------
// Purity
// ---------------------------------------------------------------------------

#[test]
fn the_template_is_a_pure_function_of_its_context() {
    let params = EconomicParams::default();
    let miner = miner();
    let chain = chain_of(2);
    let listed = [spend(point_at(41), 1)];
    let cx = context(&chain, &params, &miner, &listed);
    let a = build(&cx).expect("builds");
    let b = build(&cx).expect("builds");
    assert_eq!(
        a.block.serialize(),
        b.block.serialize(),
        "same context, same bytes"
    );
    assert_eq!(a.block.hash(), b.block.hash());

    let mut other_key = cx.clone();
    other_key.tx_key_secret = [0x78; 32];
    let c = build(&other_key).expect("builds");
    assert_ne!(
        c.block.miner_transaction.prefix.outputs[0].key,
        a.block.miner_transaction.prefix.outputs[0].key,
        "a different tx secret pays a different one-time key"
    );
    assert_eq!(
        c.block.miner_transaction.prefix.outputs[0].amount,
        a.block.miner_transaction.prefix.outputs[0].amount,
        "and the same amount"
    );
}

// ---------------------------------------------------------------------------
// The header's timestamp
// ---------------------------------------------------------------------------

#[test]
fn the_timestamp_is_the_least_admissible_no_earlier_than_the_clock() {
    let now = Timestamp::from_raw(1_000);
    // No median (at and below the window): the clock.
    assert_eq!(template_timestamp(now, None), 1_000);
    // Median below the clock: the clock (C2 holds with room; C1 is the
    // clock's own).
    assert_eq!(
        template_timestamp(now, Some(Timestamp::from_raw(500))),
        1_000
    );
    // Median at or above the clock: strictly above the median (C2's
    // *strictly greater*), and the least such value.
    assert_eq!(
        template_timestamp(now, Some(Timestamp::from_raw(1_000))),
        1_001
    );
    assert_eq!(
        template_timestamp(now, Some(Timestamp::from_raw(5_000))),
        5_001
    );
    // A median at the ceiling has no admissible successor; the claim
    // saturates and the validator, not the template, refuses it.
    assert_eq!(
        template_timestamp(now, Some(Timestamp::from_raw(u64::MAX))),
        u64::MAX
    );
}

// ---------------------------------------------------------------------------
// Refusals by design — caller conditions, never consensus verdicts
// ---------------------------------------------------------------------------

/// A coinbase-shaped body: `Ct::Null`, no fee.
fn coinbase_shaped() -> Transaction {
    shekyl_chain_rules::harness::fixture::coinbase(0)
}

#[test]
fn a_body_without_a_fee_is_not_listable() {
    let params = EconomicParams::default();
    let miner = miner();
    let chain = chain_of(1);
    let listed = [spend(point_at(51), 1), coinbase_shaped()];
    let err = build(&context(&chain, &params, &miner, &listed)).expect_err("refused");
    assert!(
        matches!(err, TemplateError::ListedWithoutFee { index: 1 }),
        "{err}"
    );
}

#[test]
fn a_height_whose_unlock_overflows_yields_no_template() {
    // CEN-F6 cannot hold at such a height (the rule's own sum overflows
    // and refuses); the template says so instead of saturating into a
    // coinbase the validator would refuse.
    let params = EconomicParams::default();
    let miner = miner();
    let chain = chain_of(1);
    let mut cx = context(&chain, &params, &miner, &[]);
    cx.height = BlockHeight::from_raw(u64::MAX);
    let err = build(&cx).expect_err("refused");
    assert!(
        matches!(
            err,
            TemplateError::UnlockOverflow {
                height: u64::MAX,
                ..
            }
        ),
        "{err}"
    );
}

#[test]
fn an_inconsistent_supply_record_yields_no_template() {
    let params = EconomicParams::default();
    let miner = miner();
    let chain = chain_of(1);
    let mut cx = context(&chain, &params, &miner, &[]);
    cx.emission.total_burned = AtomicUnits::from_raw(1);
    let err = build(&cx).expect_err("refused");
    assert!(matches!(err, TemplateError::Supply(_)), "{err}");
}

#[test]
fn a_miner_key_the_kem_refuses_yields_no_template() {
    let params = EconomicParams::default();
    let mut miner = miner();
    miner.ml_kem_ek.truncate(7);
    let chain = chain_of(1);
    let err = build(&context(&chain, &params, &miner, &[])).expect_err("refused");
    assert!(matches!(err, TemplateError::Output(_)), "{err}");
}
