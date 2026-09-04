// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for `unstake_facade`, in a `#[path]` sibling so the
//! production source stays under the engine-decomposition ratchet's
//! `NEW_FILE_CAP` (the pattern `drain_orchestrator_tests.rs` follows).
//! Both files are scanned by the ratchet; this one is well under the cap
//! on its own.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc as StdArc;

use shekyl_engine_file::SafetyOverrides;
use shekyl_engine_state::pending_post_block::{PendingUnbond, SealAdmission};
use shekyl_engine_state::pscan_cursor::PScanCursor;
use shekyl_engine_state::pscan_state::{
    BondPostRecord, MintLineageOutput, PFundingOutputRecord, RetiredPersonaRecord,
};
use shekyl_engine_state::{PendingBondPost, PendingPostState};
use shekyl_types::{BlockHeight, GlobalOutputIndex, SettlementEpoch};
use tokio::sync::RwLock as TokioRwLock;

use crate::engine::test_support::{dummy_daemon, fixed_seed};
use crate::engine::{Credentials, EngineCreateParams, SoloSigner};
use crate::StakeFacade;

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
        id_by_slot: slots
            .iter()
            .map(|&(s, id)| (PSlot::from_raw(s), persona(id)))
            .collect(),
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
        resolve_collect_target(&ev, &BTreeSet::new()).expect("resolvable"),
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
        resolve_collect_target(&ev, &BTreeSet::new()).is_err(),
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
        resolve_collect_target(&ev, &BTreeSet::new()).expect("resolvable"),
        CollectTarget::Sweep(PSlot::from_raw(2), persona(2)),
    );

    let state = pscan(Vec::new(), both, Vec::new(), Vec::new());
    let ev = evidence(Some(state), None, &[(1, 1), (2, 2)]);
    assert_eq!(
        resolve_collect_target(&ev, &BTreeSet::new()).expect("resolvable"),
        CollectTarget::NothingLeft
    );

    let ev = evidence(
        Some(pscan(Vec::new(), BTreeMap::new(), Vec::new(), Vec::new())),
        None,
        &[],
    );
    assert_eq!(
        resolve_collect_target(&ev, &BTreeSet::new()).expect("resolvable"),
        CollectTarget::NoExit
    );
}

/// This bites against the seam's two pending refusals collapsing onto
/// one façade arm (`BondPostPending` mapped to
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
        resolve_collect_target(&ev, &BTreeSet::new()).expect("resolvable"),
        CollectTarget::Sweep(PSlot::from_raw(3), persona(1)),
        "lowest exited slot with rows sweeps first"
    );
}

/// The dust rendering names the full fee-plus-payable-amount condition:
/// `fee + 1` is dust and larger than the fee, so
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

// --- The NotStaker / NothingStaked discrimination -------------------------
//
// `unstake`/`collect_unstaked` reject a wallet with no stake engine as
// `NotStaker` (-29513) BEFORE reading exit evidence, matching the seam's own
// `stake_handle().ok_or(NotStaker)`. Without the gate a non-staker's empty
// snapshot resolves to `NothingStaked`/`NoExit` and the seam's documented
// `NotStaker` arm is façade-unreachable — one state under two names. The pair
// below pins both directions: no actor -> NotStaker; actor present with
// nothing bonded -> the resolution's own verdict still lands, un-swallowed.

#[tokio::test(flavor = "multi_thread")]
async fn a_non_staker_reads_not_staker_never_nothing_staked() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base_path = tmp.path().join("wallet");
    let creds = Credentials::password_only(b"review-4 non-staker");
    let seed = fixed_seed(1);
    let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
    let engine = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
    assert!(
        !engine.has_stake_engine(),
        "fixture: a fresh wallet has no stake engine"
    );
    let arc = StdArc::new(TokioRwLock::new(engine));

    // The daemon address is never dialed — the gate returns before transport.
    let err = StakeFacade::unstake(arc.clone(), "http://127.0.0.1:1")
        .await
        .expect_err("a non-staker cannot unstake");
    assert!(
        matches!(err, UnstakeError::NotStaker),
        "no stake engine is NotStaker (-29513), not NothingStaked: {err:?}"
    );
    let cerr = StakeFacade::collect_unstaked(arc)
        .await
        .expect_err("a non-staker has nothing to collect");
    assert!(
        matches!(cerr, CollectUnstakedError::NotStaker),
        "no stake engine is NotStaker (-29513), not NoExitToCollect: {cerr:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_staker_with_nothing_bonded_is_not_collapsed_to_not_staker() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base_path = tmp.path().join("wallet");
    let creds = Credentials::password_only(b"review-4 idle staker");
    let seed = fixed_seed(2);
    let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
    let network = params.network;
    let engine = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
    // A durable bond record makes the reopen spawn the actor (Model D), so
    // `has_stake_engine()` is true; with no pscan/pending the resolution still
    // concludes NothingStaked/NoExit. The gate must NOT swallow that as
    // NotStaker — actor-present-and-idle and never-a-staker are two states.
    engine
        .persist_bond_record(PSlot::from_raw(3))
        .expect("persist bond record");
    engine.close(&creds).expect("close");
    let opened = Engine::<SoloSigner>::open_full(
        &base_path,
        &creds,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect("staker reopen")
    .into_wallet();
    assert!(
        opened.has_stake_engine(),
        "fixture: a reopened staker spawns the actor"
    );
    let arc = StdArc::new(TokioRwLock::new(opened));

    let err = StakeFacade::unstake(arc.clone(), "http://127.0.0.1:1")
        .await
        .expect_err("nothing is bonded to exit");
    assert!(
        matches!(err, UnstakeError::NothingStaked),
        "actor present, nothing bonded is NothingStaked, not NotStaker: {err:?}"
    );
    let cerr = StakeFacade::collect_unstaked(arc).await;
    assert!(
        matches!(cerr, Err(CollectUnstakedError::NoExitToCollect)),
        "actor present, no exited pool is NoExitToCollect, not NotStaker: {cerr:?}"
    );
}

// --- Resolution-ladder stranding: the candidate set, not the order --------
//
// The ladder still targets the lowest slot; eligibility is what narrowed. Unstake excludes a persona whose exit is already sealed (so a
// multi-bonded wallet advances instead of re-targeting the in-flight one, and
// a held seal on the lowest slot cannot strand the rest); collect skips a slot
// the caller has proven permanently unsweepable (so a stuck dust slot cannot
// strand a higher collectable pool).

/// A persona with a SEALED (dispatched, unconfirmed) exit is still in the
/// confirmed-bond set — the exit is not yet observed — but must not be an
/// unstake target: resolution excludes it so the next live bond can exit.
/// Red before the fix (it returned `Post(slot 1)`).
#[test]
fn a_sealed_exit_is_excluded_so_the_next_live_bond_can_exit() {
    // Personas 1 and 2 both hold live confirmed bonds; neither exit is
    // observed (pending_unbonds empty), but persona 1's exit is already sealed.
    let state = pscan(
        vec![bond_match(1, 0), bond_match(2, 0)],
        BTreeMap::new(),
        Vec::new(),
        Vec::new(),
    );
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
    let ev = evidence(Some(state), Some(block), &[(1, 1), (2, 2)]);
    assert_eq!(
        resolve_unstake_target(&ev).expect("resolvable"),
        UnstakeTarget::Post(PSlot::from_raw(2)),
        "the sealed-exit persona 1 is excluded; the next live bond (slot 2) is the target"
    );
}

/// Collect resolution honours a skip set: a slot the caller proved
/// permanently unsweepable falls through to the next exited pool, and when
/// every candidate is skipped resolution reports nothing left (the loop turns
/// that into the dust residual, not completion).
#[test]
fn collect_skips_a_slot_the_caller_proved_unsweepable() {
    let mut exited_both = exited(1);
    exited_both.insert(persona(2), SettlementEpoch::from_raw(9));
    let state = pscan(
        vec![bond_match(1, 0), bond_match(2, 0)],
        exited_both,
        Vec::new(),
        vec![funding(1, 7, 500), funding(2, 8, 500)],
    );
    let ev = evidence(Some(state), None, &[(1, 1), (2, 2)]);
    assert_eq!(
        resolve_collect_target(&ev, &BTreeSet::new()).expect("resolvable"),
        CollectTarget::Sweep(PSlot::from_raw(1), persona(1)),
        "no skip: the lowest exited slot with a pool"
    );
    let skip: BTreeSet<PSlot> = [PSlot::from_raw(1)].into_iter().collect();
    assert_eq!(
        resolve_collect_target(&ev, &skip).expect("resolvable"),
        CollectTarget::Sweep(PSlot::from_raw(2), persona(2)),
        "slot 1 skipped: advance to the next exited pool, never strand it"
    );
    let skip_all: BTreeSet<PSlot> = [PSlot::from_raw(1), PSlot::from_raw(2)]
        .into_iter()
        .collect();
    assert_eq!(
        resolve_collect_target(&ev, &skip_all).expect("resolvable"),
        CollectTarget::NothingLeft,
        "all candidates skipped: nothing resolvable (the loop reports the dust residual)"
    );
}

/// The maturing-rows gate is what keeps the dust skip from advancing past a
/// slot that is about to become collectable: a slot with any row not yet
/// spendable at the scanned frontier is maturing (wait), a slot whose rows are
/// all spendable is permanent-dust territory (skippable).
#[test]
fn a_slot_still_maturing_is_not_permanent_dust() {
    let mut maturing = funding(1, 9, 500);
    maturing.spendable_height = BlockHeight::from_raw(6_000); // > cursor 5_000
    let has_maturing = pscan(
        vec![bond_match(1, 0)],
        exited(1),
        Vec::new(),
        vec![funding(1, 7, 500), maturing],
    );
    assert!(
        slot_has_maturing_rows(&has_maturing, PSlot::from_raw(1)),
        "a row not yet spendable at the frontier is maturing — the dust is transient"
    );
    let all_mature = pscan(
        vec![bond_match(2, 0)],
        exited(2),
        Vec::new(),
        vec![funding(2, 8, 500)],
    );
    assert!(
        !slot_has_maturing_rows(&all_mature, PSlot::from_raw(2)),
        "all rows spendable at the frontier: no maturing value, dust here is permanent"
    );
}

/// The completion fact is TWO-part: `remainder` is per-slot, and
/// the lane-wide half is `other_exited_pools_remain` — with two exited
/// personas, sweeping the first to remainder 0 must NOT read as lane-wide
/// completion while the second still holds funds (including a dust-skipped
/// slot, whose pool is uncollected even if unsweepable today). Red before
/// the field existed: the CLI said "nothing further remains" over slot B's
/// funds.
#[test]
fn per_slot_zero_does_not_forge_lane_wide_completion() {
    let mut exited_both = exited(1);
    exited_both.insert(persona(2), SettlementEpoch::from_raw(9));
    // Both exited; both still hold rows.
    let ev = evidence(
        Some(pscan(
            vec![bond_match(1, 0), bond_match(2, 0)],
            exited_both.clone(),
            Vec::new(),
            vec![funding(1, 7, 500), funding(2, 8, 500)],
        )),
        None,
        &[(1, 1), (2, 2)],
    );
    assert!(
        other_exited_pools_remain(&ev, PSlot::from_raw(1)),
        "sweeping slot 1: slot 2's exited pool remains — the lane is not done"
    );
    assert!(
        other_exited_pools_remain(&ev, PSlot::from_raw(2)),
        "symmetric: sweeping slot 2 while slot 1 still holds rows"
    );

    // Slot 2's pool emptied: sweeping slot 1 IS lane-wide completion.
    let ev_one = evidence(
        Some(pscan(
            vec![bond_match(1, 0), bond_match(2, 0)],
            exited_both,
            Vec::new(),
            vec![funding(1, 7, 500)],
        )),
        None,
        &[(1, 1), (2, 2)],
    );
    assert!(
        !other_exited_pools_remain(&ev_one, PSlot::from_raw(1)),
        "no other exited pool holds rows: the lane completes with this slot"
    );

    // A LIVE (non-exited) persona's rows never count: persona 2 bonded but
    // not exited is `unstake`'s concern, not an uncollected pool.
    let ev_live = evidence(
        Some(pscan(
            vec![bond_match(1, 0), bond_match(2, 0)],
            exited(1),
            Vec::new(),
            vec![funding(1, 7, 500), funding(2, 8, 500)],
        )),
        None,
        &[(1, 1), (2, 2)],
    );
    assert!(
        !other_exited_pools_remain(&ev_live, PSlot::from_raw(1)),
        "a live persona's funding is not an uncollected exit pool"
    );
}
