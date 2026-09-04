// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for `unstake_facade`, in a `#[path]` sibling so the
//! production source stays under the engine-decomposition ratchet's
//! `NEW_FILE_CAP` (the pattern `drain_orchestrator_tests.rs` follows).
//! Both files are scanned by the ratchet; this one is well under the cap
//! on its own.

use std::collections::BTreeMap;

use shekyl_engine_state::pending_post_block::{PendingUnbond, SealAdmission};
use shekyl_engine_state::pscan_cursor::PScanCursor;
use shekyl_engine_state::pscan_state::{
    BondPostRecord, MintLineageOutput, PFundingOutputRecord, RetiredPersonaRecord,
};
use shekyl_engine_state::{PendingBondPost, PendingPostState};
use shekyl_types::{BlockHeight, GlobalOutputIndex, SettlementEpoch};

use super::*;

fn persona(b: u8) -> PCanonicalId {
    PCanonicalId::from_bytes([b; 32])
}

fn bond_match(id: u8, kind: u8) -> BondPostRecord {
    BondPostRecord {
        height: BlockHeight::from_raw(1_000),
        p_canonical_id: persona(id),
        post_kind: kind,
    }
}

fn funding(slot: u32, gindex: u64, amount: u64) -> PFundingOutputRecord {
    PFundingOutputRecord {
        p_slot: PSlot::from_raw(slot),
        index_in_transaction: 0,
        gindex: GlobalOutputIndex::from_raw(gindex),
        output_key: [0; 32],
        commitment: [0; 32],
        ciphertext_x25519: [0; 32],
        ciphertext_ml_kem: Vec::new(),
        amount: AtomicUnits::from_raw(amount),
        height: BlockHeight::from_raw(2_000),
        epoch: SettlementEpoch::from_raw(1),
        lineage: MintLineageOutput::BondPostChange,
        spendable_height: BlockHeight::from_raw(2_010),
    }
}

fn pscan(
    matches: Vec<BondPostRecord>,
    pending_unbonds: BTreeMap<PCanonicalId, SettlementEpoch>,
    retired: Vec<RetiredPersonaRecord>,
    outputs: Vec<PFundingOutputRecord>,
) -> PScanState {
    PScanState::new(
        PScanCursor::at(BlockHeight::from_raw(5_000), [0x11; 32]),
        BTreeMap::new(),
        pending_unbonds,
        matches,
        outputs,
        retired,
        BTreeMap::new(),
    )
}

fn evidence(
    pscan_state: Option<PScanState>,
    pending: Option<PendingPostBlock>,
    slots: &[(u32, u8)],
) -> ExitEvidence {
    ExitEvidence {
        pscan: pscan_state,
        pending,
        id_by_slot: slots.iter().map(|&(s, id)| (s, persona(id))).collect(),
    }
}

fn exited(id: u8) -> BTreeMap<PCanonicalId, SettlementEpoch> {
    let mut m = BTreeMap::new();
    m.insert(persona(id), SettlementEpoch::from_raw(9));
    m
}

/// This bites against the resolution ladder falling through to a
/// different persona's irreversible post — the exact mis-selection the
/// two-verb split exists to prevent: with persona 1 exited (payouts
/// immature or not) and persona 2 still bonded, `unstake` must resolve
/// persona 2 ONLY as a deliberate post target, and `collect` must
/// resolve persona 1 ONLY — neither verb ever answers with the other's
/// persona. It does NOT cover the seam's own admission races.
#[test]
fn the_two_resolutions_never_trade_personas() {
    let state = pscan(
        vec![bond_match(1, 0), bond_match(2, 0)],
        exited(1),
        Vec::new(),
        vec![funding(1, 7, 500)],
    );
    let ev = evidence(Some(state), None, &[(1, 1), (2, 2)]);

    // `unstake` sees persona 2 (slot 2) — the only LIVE bond; persona 1
    // is pending-unbond and excluded from the live set.
    assert_eq!(
        resolve_unstake_target(&ev).expect("resolvable"),
        UnstakeTarget::Post(PSlot::from_raw(2)),
    );
    // `collect` sees persona 1 (slot 1) — the only observed exit.
    assert_eq!(
        resolve_collect_target(&ev).expect("resolvable"),
        CollectTarget::Sweep(PSlot::from_raw(1), persona(1)),
    );
}

/// This bites against "nothing staked" being reported over an exit in
/// progress (either a sealed unconfirmed exit or an observed one) — the
/// guidance states are distinct refusals, not silence. It does NOT
/// cover the RPC rendering of these arms.
#[test]
fn in_progress_states_are_named_before_nothing_staked() {
    // Observed exit, nothing else: ExitInProgress (collect's turf).
    let state = pscan(vec![bond_match(1, 0)], exited(1), Vec::new(), Vec::new());
    let ev = evidence(Some(state), None, &[(1, 1)]);
    assert_eq!(
        resolve_unstake_target(&ev).expect("resolvable"),
        UnstakeTarget::ExitInProgress
    );

    // Sealed-but-unconfirmed exit (dispatched, not yet observed): the
    // pending block's unbond seal is the evidence.
    let state = pscan(vec![bond_match(1, 0)], exited(1), Vec::new(), Vec::new());
    let mut block = PendingPostBlock::empty();
    let g = block.generation();
    assert_eq!(
        block.seal_unbond(
            PendingUnbond {
                persona: persona(1),
                tx_bytes: vec![0xEE; 4],
                funding_gindexes: Vec::new(),
                state: PendingPostState::Pending,
            },
            BlockHeight::from_raw(5_000),
            g,
        ),
        SealAdmission::Admit
    );
    let ev = evidence(Some(state), Some(block), &[(1, 1)]);
    assert_eq!(
        resolve_unstake_target(&ev).expect("resolvable"),
        UnstakeTarget::ExitInProgress
    );

    // In-flight bond post only: BondConfirming, not NothingStaked.
    let mut block = PendingPostBlock::empty();
    let g = block.generation();
    assert_eq!(
        block.seal_post(
            PendingBondPost {
                p_slot: PSlot::from_raw(0),
                persona: persona(9),
                tx_bytes: vec![0xAB; 4],
                bond_post_offset_blocks: 0,
                anchor_t0: BlockHeight::from_raw(1),
                funding_gindexes: Vec::new(),
                state: PendingPostState::Pending,
            },
            g,
        ),
        SealAdmission::Admit
    );
    let ev = evidence(
        Some(pscan(Vec::new(), BTreeMap::new(), Vec::new(), Vec::new())),
        Some(block),
        &[],
    );
    assert_eq!(
        resolve_unstake_target(&ev).expect("resolvable"),
        UnstakeTarget::BondConfirming
    );

    // Truly nothing.
    let ev = evidence(
        Some(pscan(Vec::new(), BTreeMap::new(), Vec::new(), Vec::new())),
        None,
        &[],
    );
    assert_eq!(
        resolve_unstake_target(&ev).expect("resolvable"),
        UnstakeTarget::NothingStaked
    );
}

/// This bites against an incomplete slot index reading as "nothing
/// staked" / "nothing to collect" — a bonded staker must never be told
/// they hold nothing over a missing index row (the staking-read
/// fail-closed posture, applied to resolution). It does NOT cover cache
/// (re)population.
#[test]
fn a_live_or_exited_persona_missing_from_the_index_fails_closed() {
    let state = pscan(
        vec![bond_match(1, 0)],
        Vec::new().into_iter().collect(),
        Vec::new(),
        Vec::new(),
    );
    let ev = evidence(Some(state), None, &[]);
    assert!(
        resolve_unstake_target(&ev).is_err(),
        "a live bond with no index row is an error, not NothingStaked"
    );

    let state = pscan(vec![bond_match(1, 0)], exited(1), Vec::new(), Vec::new());
    let ev = evidence(Some(state), None, &[]);
    assert!(
        resolve_collect_target(&ev).is_err(),
        "an observed exit with no index row is an error, not NoExit"
    );
}

/// This bites against multi-exit resolution skipping an emptied slot's
/// completion (`NothingLeft` must require EVERY exited slot empty) and
/// against slot-order drift (lowest exited slot with rows sweeps
/// first). It does NOT cover spendability (maturity is the pipeline's).
#[test]
fn collect_resolves_lowest_exited_slot_with_rows_and_completes_on_empty() {
    let mut both = exited(1);
    both.extend(exited(2));
    let state = pscan(
        Vec::new(),
        both.clone(),
        Vec::new(),
        vec![funding(2, 9, 400)], // slot 1 already swept; slot 2 holds rows
    );
    let ev = evidence(Some(state), None, &[(1, 1), (2, 2)]);
    assert_eq!(
        resolve_collect_target(&ev).expect("resolvable"),
        CollectTarget::Sweep(PSlot::from_raw(2), persona(2)),
    );

    let state = pscan(Vec::new(), both, Vec::new(), Vec::new());
    let ev = evidence(Some(state), None, &[(1, 1), (2, 2)]);
    assert_eq!(
        resolve_collect_target(&ev).expect("resolvable"),
        CollectTarget::NothingLeft
    );

    let ev = evidence(
        Some(pscan(Vec::new(), BTreeMap::new(), Vec::new(), Vec::new())),
        None,
        &[],
    );
    assert_eq!(
        resolve_collect_target(&ev).expect("resolvable"),
        CollectTarget::NoExit
    );
}

/// This bites against the seam's two pending refusals collapsing onto
/// one façade arm (review-1, Bugbot: `BondPostPending` mapped to
/// `ExitInProgress` sent a just-bonded wallet to `collect_unstaked`,
/// which answers `NoExit` — the GC-bridge window makes the seam arm
/// reachable past resolution). The two remedies point at different
/// verbs, so the arms must stay distinct. It does NOT cover the RPC
/// code mapping (error.rs's table test).
#[test]
fn the_two_pending_refusals_flatten_to_their_own_arms() {
    assert!(matches!(
        flatten_unstake_error(UnbondRequestError::UnbondPending),
        UnstakeError::ExitInProgress
    ));
    assert!(matches!(
        flatten_unstake_error(UnbondRequestError::BondPostPending),
        UnstakeError::BondConfirming
    ));
}

/// The façade's structural pins, `drain_facade`-tripwire style (comment
/// lines stripped; the test module excluded from the scan):
///
/// 1. **No slot steering and no active-persona resolution:** the
///    production section never takes a `p_slot:` parameter and never
///    calls `.active_persona()` — both verbs resolve engine-side from
///    the sealed evidence (the anti-shape on each side: a wire slot
///    would steer the exit; the active persona would strand rotated
///    personas).
/// 2. **Production witness mints:** the SP-R0 witness is
///    `arm1_watch_pruning_live` (never `for_test`), and the sweep
///    intent is built ONLY from `TerminalExitObserved::for_persona` on
///    the same evidence the resolution read.
/// 3. **The sweep rides the drain seam** (`submit_drain`) and the post
///    rides the exit seam (`submit_unbond`) — no other dispatch path.
#[test]
fn facade_cannot_steer_slot_or_mint_test_witnesses() {
    let (production, _tests) = include_str!("unstake_facade.rs")
        .split_once("\n#[cfg(test)]")
        .expect("unstake_facade.rs has a #[cfg(test)] section to exclude from the scan");
    let code: String = production
        .lines()
        .filter(|l| !l.trim_start().starts_with("//") && !l.trim_start().starts_with("//!"))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        !code.contains("p_slot:"),
        "the façade must not take or bind a wire slot parameter"
    );
    assert!(
        !code.contains(".active_persona()"),
        "neither verb may resolve the active persona — rotated-away \
         personas must stay exitable and collectable"
    );
    assert!(
        code.contains("SpentRecordsDurablyPruned::arm1_watch_pruning_live()")
            && !code.contains("SpentRecordsDurablyPruned::for_test()"),
        "production mints the live SP-R0 witness only"
    );
    assert!(
        code.contains("TerminalExitObserved::for_persona"),
        "the sweep intent is built only from the observed-exit witness mint"
    );
    assert!(
        code.contains("Engine::submit_unbond(") && code.contains("Engine::submit_drain("),
        "the two verbs ride exactly the two production seams"
    );
}

/// Lowest-slot-first is explicit (`sort_unstable_by_key`), not a BTreeMap
/// iteration accident: reverse insertion order still posts/collects the
/// lowest slot. Bitten red by dropping the sort.
#[test]
fn lowest_slot_is_independent_of_cache_insertion_order() {
    let state = pscan(
        vec![bond_match(1, 0), bond_match(2, 0)],
        BTreeMap::new(),
        Vec::new(),
        Vec::new(),
    );
    let ev = evidence(Some(state), None, &[(9, 2), (3, 1)]);
    assert_eq!(
        resolve_unstake_target(&ev).expect("resolvable"),
        UnstakeTarget::Post(PSlot::from_raw(3)),
        "lowest live slot posts first, regardless of cache insertion order"
    );

    let mut both = exited(2);
    both.extend(exited(1));
    let state = pscan(
        Vec::new(),
        both,
        Vec::new(),
        vec![funding(9, 1, 400), funding(3, 2, 400)],
    );
    let ev = evidence(Some(state), None, &[(9, 2), (3, 1)]);
    assert_eq!(
        resolve_collect_target(&ev).expect("resolvable"),
        CollectTarget::Sweep(PSlot::from_raw(3), persona(1)),
        "lowest exited slot with rows sweeps first"
    );
}

/// The dust rendering names the full fee-plus-payable-amount condition
/// (review-2 / Copilot): `fee + 1` is dust and larger than the fee, so
/// "smaller than the fee" is a lie. Bitten red by restoring that phrase.
#[test]
fn dust_remainder_names_the_split_floor_not_just_the_fee() {
    let msg = CollectUnstakedError::DustRemainder.to_string();
    assert!(
        msg.contains("payable amount"),
        "must name the two-output split floor: {msg}"
    );
    assert!(
        !msg.contains("smaller than the fee"),
        "fee+1 is dust and larger than the fee: {msg}"
    );
}
