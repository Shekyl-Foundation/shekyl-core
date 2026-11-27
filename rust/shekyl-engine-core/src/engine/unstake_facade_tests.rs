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
use shekyl_engine_state::pending_post_block::{PendingRelease, SealAdmission};
use shekyl_engine_state::pscan_cursor::PScanCursor;
use shekyl_engine_state::pscan_state::{
    BondPostRecord, MintLineageOutput, PFundingOutputRecord, RetiredPersonaRecord,
};
use shekyl_engine_state::{PendingBondPost, PendingPostState};
use shekyl_types::{BlockHeight, ChainCount, GlobalOutputIndex, SettlementEpoch};
use tokio::sync::RwLock as TokioRwLock;

use crate::engine::test_support::{dummy_daemon, fixed_seed};
use crate::engine::{Credentials, EngineCreateParams, SoloSigner};
use crate::StakeFacade;

use super::*;

fn persona(b: u8) -> PCanonicalId {
    PCanonicalId::from_bytes([b; 32])
}

/// The JoinMarket's wire byte, as the extractor records it. *Was* `0`, the
/// keyless JoinMarket's byte, retired 2026-10-12.
const JOIN: u8 = shekyl_wire::transaction::BOND_POST_KIND_JOINMARKET;

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
    pending_releases: BTreeMap<PCanonicalId, SettlementEpoch>,
    retired: Vec<RetiredPersonaRecord>,
    outputs: Vec<PFundingOutputRecord>,
) -> PScanState {
    PScanState::new(
        PScanCursor::at(
            BlockHeight::from_raw(5_000),
            [0x11; 32],
            shekyl_engine_state::pscan_cursor::ArchivalFold::genesis(),
        ),
        BTreeMap::new(),
        pending_releases,
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
        vec![bond_match(1, JOIN), bond_match(2, JOIN)],
        exited(1),
        Vec::new(),
        vec![funding(1, 7, 500)],
    );
    let ev = evidence(Some(state), None, &[(1, 1), (2, 2)]);

    // `unstake` sees persona 2 (slot 2) — the only LIVE bond; persona 1
    // is pending-release and excluded from the live set.
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
    let state = pscan(vec![bond_match(1, JOIN)], exited(1), Vec::new(), Vec::new());
    let ev = evidence(Some(state), None, &[(1, 1)]);
    assert_eq!(
        resolve_unstake_target(&ev).expect("resolvable"),
        UnstakeTarget::ExitInProgress
    );

    // Sealed-but-unconfirmed exit (dispatched, not yet observed): the
    // pending block's release seal is the evidence.
    let state = pscan(vec![bond_match(1, JOIN)], exited(1), Vec::new(), Vec::new());
    let mut block = PendingPostBlock::empty();
    let g = block.generation();
    assert_eq!(
        block.seal_release(
            PendingRelease {
                persona: persona(1),
                tx_bytes: vec![0xEE; 4],
                funding_gindexes: Vec::new(),
                state: PendingPostState::Pending,
                reference_height: shekyl_types::BlockHeight::from_raw(1_000_000),
                terminal: None,
            },
            ChainCount::from_raw(5_000),
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
                wait: None,
                p_slot: PSlot::from_raw(0),
                persona: persona(9),
                tx_bytes: vec![0xAB; 4],
                posture: shekyl_engine_state::PlannedPosture::SupportCompleteTree,
                due: ChainCount::from_raw(1),
                funded_through: shekyl_types::BlockHeight::from_raw(0),
                funding_gindexes: Vec::new(),
                state: PendingPostState::Pending,
                reference_height: shekyl_types::BlockHeight::from_raw(1_000_000),
                terminal: None,
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
        vec![bond_match(1, JOIN)],
        Vec::new().into_iter().collect(),
        Vec::new(),
        Vec::new(),
    );
    let ev = evidence(Some(state), None, &[]);
    assert!(
        resolve_unstake_target(&ev).is_err(),
        "a live bond with no index row is an error, not NothingStaked"
    );

    let state = pscan(vec![bond_match(1, JOIN)], exited(1), Vec::new(), Vec::new());
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

/// A failed peer check and a service at this computer stay that fault
/// through the exit, on the fee query and on the record fetch. Red edit:
/// map either to `DaemonUnreachable`, and unstake reports a retry.
#[test]
fn a_target_refusal_is_not_an_unreachable_daemon() {
    use shekyl_rpc_client::{DaemonFault, RpcError};

    let peer = flatten_unstake_error(ReleaseRequestError::Fetch(EmissionSourceError::Rpc(
        RpcError::PeerCheck("not a socket".into()),
    )));
    assert!(
        matches!(peer, UnstakeError::DaemonTarget(DaemonFault::PeerCheck)),
        "{peer:?}"
    );
    let view = "127.0.0.1:11030".parse().unwrap();
    let service = flatten_unstake_error(ReleaseRequestError::Fee(FeeEstimatorError::Daemon(
        DaemonFault::Service(Some(view)),
    )));
    assert!(
        matches!(
            service,
            UnstakeError::DaemonTarget(DaemonFault::Service(Some(got))) if got == view
        ),
        "{service:?}"
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
        flatten_unstake_error(ReleaseRequestError::ReleasePending),
        UnstakeError::ExitInProgress
    ));
    assert!(matches!(
        flatten_unstake_error(ReleaseRequestError::BondPostPending),
        UnstakeError::BondConfirming
    ));
}

/// A daemon's terminal verdict on the exit reaches the caller as the held
/// disposition, never as "released, retry at will": the seam keeps that
/// record (BD-Q3 Rule 2), so a retry would only meet the one-live-exit
/// lane. The pre-transport pairing refusal is the one released class.
#[test]
fn only_the_pairing_refusal_flattens_to_released() {
    use crate::engine::error::TerminalErrorKind;
    use crate::engine::transaction_submitter::{BroadcastSubmitError, SubmitterError};

    let terminal = BroadcastSubmitError::Submit(SubmitterError::RejectedTerminal {
        kind: TerminalErrorKind::DoubleSpend,
    });
    assert!(matches!(
        flatten_unstake_error(ReleaseRequestError::Submit(terminal)),
        UnstakeError::ExitFateUnknown { .. }
    ));
    let mismatch = BroadcastSubmitError::PersonaMismatch {
        bytes_persona: shekyl_types::PCanonicalId::from_bytes([1; 32]),
        submitter_persona: shekyl_types::PCanonicalId::from_bytes([2; 32]),
    };
    assert!(matches!(
        flatten_unstake_error(ReleaseRequestError::Submit(mismatch)),
        UnstakeError::ExitRefusedAndReleased { .. }
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
///    intent is built ONLY from `NoExitOwed::for_released` on
///    the same evidence the resolution read.
/// 3. **The sweep rides the drain seam** (`submit_drain`) and the post
///    rides the exit seam (`submit_release`) — no other dispatch path.
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
        code.contains("NoExitOwed::for_released"),
        "the sweep intent is built only from the observed-exit witness mint"
    );
    assert!(
        code.contains("Engine::submit_release(") && code.contains("Engine::submit_drain("),
        "the two verbs ride exactly the two production seams"
    );
}

/// Lowest-slot-first is explicit (`sort_unstable_by_key`), not a BTreeMap
/// iteration accident: reverse insertion order still posts/collects the
/// lowest slot. Bitten red by dropping the sort.
#[test]
fn lowest_slot_is_independent_of_cache_insertion_order() {
    let state = pscan(
        vec![bond_match(1, JOIN), bond_match(2, JOIN)],
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
    let err = StakeFacade::unstake(
        arc.clone(),
        &shekyl_rpc_transport::DaemonTarget::address("http://127.0.0.1:1"),
    )
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
    engine.close(&creds).await.expect("close");
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

    let err = StakeFacade::unstake(
        arc.clone(),
        &shekyl_rpc_transport::DaemonTarget::address("http://127.0.0.1:1"),
    )
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
    // observed (pending_releases empty), but persona 1's exit is already sealed.
    let state = pscan(
        vec![bond_match(1, JOIN), bond_match(2, JOIN)],
        BTreeMap::new(),
        Vec::new(),
        Vec::new(),
    );
    let mut block = PendingPostBlock::empty();
    let g = block.generation();
    assert_eq!(
        block.seal_release(
            PendingRelease {
                persona: persona(1),
                tx_bytes: vec![0xEE; 4],
                funding_gindexes: Vec::new(),
                state: PendingPostState::Pending,
                reference_height: shekyl_types::BlockHeight::from_raw(1_000_000),
                terminal: None,
            },
            ChainCount::from_raw(5_000),
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

/// An in-memory pending store: the block is the store. Its first save
/// reports the durability `first` names, every later one is confirmed: a
/// seal on a volume Windows cannot confirm, then its removal.
struct MemPending {
    block: std::sync::Mutex<Option<PendingPostBlock>>,
    first: std::sync::Mutex<Option<shekyl_engine_file::Durability>>,
}

impl MemPending {
    fn first_save(first: shekyl_engine_file::Durability) -> StdArc<Self> {
        StdArc::new(Self {
            block: std::sync::Mutex::new(None),
            first: std::sync::Mutex::new(Some(first)),
        })
    }
}

impl crate::engine::pscan::dispatch::PendingSealStore for StdArc<MemPending> {
    type Error = std::convert::Infallible;

    async fn load(&self) -> Result<Option<PendingPostBlock>, Self::Error> {
        Ok(self.block.lock().expect("mem pending").clone())
    }

    async fn save(
        &self,
        block: &PendingPostBlock,
    ) -> Result<shekyl_engine_file::Durability, Self::Error> {
        *self.block.lock().expect("mem pending") = Some(block.clone());
        Ok(self
            .first
            .lock()
            .expect("mem pending")
            .take()
            .unwrap_or(shekyl_engine_file::Durability::Confirmed))
    }

    fn save_cause(
        error: Self::Error,
    ) -> Result<crate::engine::error::PersistenceError, Self::Error> {
        match error {}
    }
}

/// Seal persona 1's exit through `store` as the seam does
/// (`seal_reporting`, its removal the unseal), and the save's durability.
async fn seal_exit(
    store: &crate::engine::pscan::dispatch::PendingPostStore<StdArc<MemPending>>,
) -> shekyl_engine_file::Durability {
    let (admission, durability) = store
        .seal_reporting(
            |block| {
                let g = block.generation();
                let admission = block.seal_release(
                    PendingRelease {
                        persona: persona(1),
                        tx_bytes: vec![0xEE; 4],
                        funding_gindexes: Vec::new(),
                        state: PendingPostState::Pending,
                        reference_height: BlockHeight::from_raw(1_000_000),
                        terminal: None,
                    },
                    ChainCount::from_raw(5_000),
                    g,
                );
                (admission == SealAdmission::Admit, admission)
            },
            |block| block.remove_release(&persona(1)).is_some(),
        )
        .await
        .expect("an in-memory seal");
    assert_eq!(admission, SealAdmission::Admit);
    durability
}

/// What `unstake` resolves for persona 1's live bond against `store`'s
/// block.
async fn retry_target(
    store: &crate::engine::pscan::dispatch::PendingPostStore<StdArc<MemPending>>,
) -> UnstakeTarget {
    let block = store.read(Clone::clone).await.expect("an in-memory read");
    let bonded = pscan(
        vec![bond_match(1, JOIN)],
        BTreeMap::new(),
        Vec::new(),
        Vec::new(),
    );
    resolve_unstake_target(&evidence(Some(bonded), Some(block), &[(1, 1)])).expect("resolvable")
}

/// An exit whose seal was saved but not confirmed on disk sent nothing
/// (Rick, 2026-11-19): it answers with the save's own cause, never
/// `-29522`'s "sent, seal held"; the seal is removed under the seal's own
/// guard, so no pending record is left and no other writer ever saw it;
/// and a retry resolves the same bond as its target again, never "an exit
/// is in progress". The test first asserts its own subject: a confirmed
/// seal closes the lane. Red edits: drop the `SealNotSaved` arm from
/// `flatten_unstake_error`, and the answer is `ExitFateUnknown`; drop the
/// unseal from `seal_reporting`, and the seal stays and the retry resolves
/// `ExitInProgress`.
#[tokio::test]
async fn an_unconfirmed_exit_seal_answers_its_save_code_and_reopens_the_lane() {
    use crate::engine::dispatch_durability::require_confirmed;
    use crate::engine::error::PersistenceError;
    use crate::engine::pending_post_gate::PendingPostGate;
    use crate::engine::pscan::dispatch::PendingPostStore;
    use crate::engine::transaction_submitter::BroadcastSubmitError;
    use shekyl_engine_file::{Durability, Unconfirmed};

    let confirmed = PendingPostStore::new(
        MemPending::first_save(Durability::Confirmed),
        PendingPostGate::new(),
    );
    assert!(matches!(seal_exit(&confirmed).await, Durability::Confirmed));
    assert_eq!(
        retry_target(&confirmed).await,
        UnstakeTarget::ExitInProgress,
        "the test's own subject: a sealed exit closes the lane"
    );

    let fat = || Unconfirmed::FileSystem("FAT32".to_owned());
    let unconfirmed = PendingPostStore::new(
        MemPending::first_save(Durability::Unconfirmed(fat())),
        PendingPostGate::new(),
    );
    let durability = seal_exit(&unconfirmed).await;
    // What the seam's `submit_bound` hands back for that durability.
    let refused = BroadcastSubmitError::SealNotSaved(
        require_confirmed(durability).expect_err("an unconfirmed seal is refused before any send"),
    );
    assert!(
        matches!(
            flatten_unstake_error(ReleaseRequestError::Submit(refused)),
            UnstakeError::SealNotSaved(PersistenceError::DurabilityUnconfirmed(
                Unconfirmed::FileSystem(ref name)
            )) if name == "FAT32"
        ),
        "the save's cause is the answer"
    );
    let left = unconfirmed
        .read(Clone::clone)
        .await
        .expect("an in-memory read");
    assert_eq!(
        left.sealed_records().count(),
        0,
        "no pending record is left"
    );
    assert_eq!(
        retry_target(&unconfirmed).await,
        UnstakeTarget::Post(PSlot::from_raw(1)),
        "a retry exits the same bond, never an exit in progress"
    );
}

/// A pending store whose every save fails with a read-only wallet file:
/// nothing is written.
struct ReadOnlyPending;

impl crate::engine::pscan::dispatch::PendingSealStore for StdArc<ReadOnlyPending> {
    type Error = shekyl_engine_file::WalletFileError;

    async fn load(&self) -> Result<Option<PendingPostBlock>, Self::Error> {
        Ok(None)
    }

    async fn save(
        &self,
        _block: &PendingPostBlock,
    ) -> Result<shekyl_engine_file::Durability, Self::Error> {
        Err(shekyl_engine_file::WalletFileError::ReadOnly {
            target: std::path::PathBuf::from("wallet.pending"),
        })
    }

    fn save_cause(
        error: Self::Error,
    ) -> Result<crate::engine::error::PersistenceError, Self::Error> {
        Ok(error.into())
    }
}

/// An exit whose seal's save fails outright answers the save's cause, as an
/// unconfirmed one does, never an internal fault (Rick, 2026-11-19): here a
/// read-only wallet file, which the contract answers as `SAVE_NOT_WRITABLE`
/// with its target. Nothing was written, so no pending record is left. Red
/// edit: fold a failed seal save into `SealError::Store`, and the release
/// path answers `Engine` (`-29107`).
#[tokio::test]
async fn a_failed_exit_seal_answers_its_save_cause() {
    use crate::engine::error::PersistenceError;
    use crate::engine::pending_post_gate::PendingPostGate;
    use crate::engine::pscan::dispatch::PendingPostStore;
    use crate::engine::pscan::pending_store::SealError;
    use crate::engine::transaction_submitter::BroadcastSubmitError;

    let store = PendingPostStore::new(StdArc::new(ReadOnlyPending), PendingPostGate::new());
    let failed = store
        .seal_reporting(
            |block| {
                let g = block.generation();
                let admission = block.seal_release(
                    PendingRelease {
                        persona: persona(1),
                        tx_bytes: vec![0xEE; 4],
                        funding_gindexes: Vec::new(),
                        state: PendingPostState::Pending,
                        reference_height: BlockHeight::from_raw(1_000_000),
                        terminal: None,
                    },
                    ChainCount::from_raw(5_000),
                    g,
                );
                (admission == SealAdmission::Admit, ())
            },
            |block| block.remove_release(&persona(1)).is_some(),
        )
        .await
        .expect_err("a read-only file refuses the seal");
    let SealError::NotSaved(cause) = failed else {
        panic!("a failed save is the save's cause, not a store fault: {failed:?}");
    };
    // What the release seam hands back for it.
    let answer = flatten_unstake_error(ReleaseRequestError::Submit(
        BroadcastSubmitError::SealNotSaved(cause),
    ));
    assert!(
        matches!(
            answer,
            UnstakeError::SealNotSaved(PersistenceError::WalletFile(
                shekyl_engine_file::WalletFileError::ReadOnly { .. }
            ))
        ),
        "{answer:?}"
    );
}

/// Every seal a broadcast follows (the bond post, the claim, the drain, the
/// exit) is taken through `seal_reporting`, which removes an unconfirmed
/// seal under its own guard (Rick, 2026-11-19), never through
/// `mutate_reporting`, which would leave it for the dispatch driver to
/// select. Comment lines are dropped, and each file's test module.
#[test]
fn every_broadcast_seal_is_taken_through_seal_reporting() {
    let seams = [
        ("bond_orchestrator.rs", include_str!("bond_orchestrator.rs")),
        ("claim_dispatch.rs", include_str!("claim_dispatch.rs")),
        ("drain_dispatch.rs", include_str!("drain_dispatch.rs")),
        ("release_dispatch.rs", include_str!("release_dispatch.rs")),
    ];
    for (name, text) in seams {
        let (production, _) = text
            .split_once("\n#[cfg(test)]\n")
            .unwrap_or_else(|| panic!("{name} carries its test-module marker"));
        let code: String = production
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            code.contains(".seal_reporting("),
            "{name} seals through seal_reporting"
        );
        assert!(
            !code.contains(".mutate_reporting("),
            "{name} takes no seal through mutate_reporting"
        );
    }
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
        vec![bond_match(1, JOIN), bond_match(2, JOIN)],
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
        vec![bond_match(1, JOIN)],
        exited(1),
        Vec::new(),
        vec![funding(1, 7, 500), maturing],
    );
    assert!(
        slot_has_maturing_rows(&has_maturing, PSlot::from_raw(1)),
        "a row not yet spendable at the frontier is maturing — the dust is transient"
    );
    let all_mature = pscan(
        vec![bond_match(2, JOIN)],
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
            vec![bond_match(1, JOIN), bond_match(2, JOIN)],
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
            vec![bond_match(1, JOIN), bond_match(2, JOIN)],
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
            vec![bond_match(1, JOIN), bond_match(2, JOIN)],
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

// ── WSS-Q14 class-C observation ─────────────────────────────────────────
//
// `submit_release` gates the exit on the sync witness before it reads the
// bond record as truth. The refusal's **public disposition** is observable
// here; the full-path bite (drive `submit_release` against a syncing
// transport and watch it decline) is owed and blocked — that method hangs
// off the seven-generic `Engine`, and this crate has no async `Engine`
// fixture to drive it with. Falsifier: when one exists, write it.
//
// What this does observe is not nothing, and it is the half that a caller
// actually sees: an exit refused for sync reasons must arrive at the public
// boundary as `Resyncing` (wait and retry), never as `NoBondRecord` (you
// have nothing staked) — the two send an operator to opposite places.

/// The sync refusal reaches the public boundary as the resyncing
/// disposition, carrying a detail that names the daemon.
///
/// This bites against the refusal being flattened onto a wrong-remedy arm;
/// it does **not** observe `submit_release` itself declining.
#[test]
fn a_sync_refusal_flattens_to_the_resyncing_disposition() {
    let flattened = super::flatten_unstake_error(ReleaseRequestError::DaemonSyncing);
    match flattened {
        UnstakeError::Resyncing { detail } => assert!(
            detail.contains("synchroniz"),
            "the detail must name the daemon's state so the remedy is legible: {detail}"
        ),
        other => panic!("a sync refusal must not present as a different remedy: {other:?}"),
    }
}

/// The signer's fault keeps its type from the assembly to every public
/// staking error, on each road a refusal takes. Red edit: drop the
/// `sign_fault` check from any one of the four mappings.
#[test]
fn a_signer_fault_keeps_its_type_through_every_staking_lane() {
    use crate::engine::bond_assembly::BondAssemblyError;
    use crate::engine::drain_assembly::DrainAssemblyError;
    use crate::engine::drain_facade::DrainToPrincipalError;
    use shekyl_tx_builder::{InternalSignFault, SignFault};

    let fault = SignFault::Internal(InternalSignFault::MembershipSelfCheck);
    let bond = || StakeEngineError::Assembly(BondAssemblyError::Signer(fault));
    let drain = || StakeEngineError::DrainAssembly(DrainAssemblyError::Signer(fault));

    assert!(matches!(
        DrainToPrincipalError::from(DrainRequestError::Drain(DrainOrchestrationError::Stake(
            drain()
        ))),
        DrainToPrincipalError::Signer(f) if f == fault
    ));
    let finalized = DrainAssemblyError::build("drain finalize", BondAssemblyError::Signer(fault));
    assert!(matches!(
        DrainToPrincipalError::from(DrainRequestError::Drain(DrainOrchestrationError::Stake(
            StakeEngineError::DrainAssembly(finalized)
        ))),
        DrainToPrincipalError::Signer(f) if f == fault
    ));
    assert!(matches!(
        DrainToPrincipalError::from(DrainRequestError::Stake(drain())),
        DrainToPrincipalError::Signer(f) if f == fault
    ));
    assert!(matches!(
        flatten_collect_error(DrainRequestError::Drain(DrainOrchestrationError::Stake(
            drain()
        ))),
        CollectUnstakedError::Signer(f) if f == fault
    ));
    assert!(matches!(
        flatten_collect_error(DrainRequestError::Stake(drain())),
        CollectUnstakedError::Signer(f) if f == fault
    ));
    assert!(matches!(
        flatten_unstake_error(ReleaseRequestError::Stake(bond())),
        UnstakeError::Signer(f) if f == fault
    ));
    assert!(matches!(
        crate::engine::bond_orchestrator::post_assembly_failure(bond()),
        crate::engine::bond_orchestrator::FirstStakeError::Signer(f) if f == fault
    ));
}

/// The assembly constructor keeps a signer fault and stringifies everything
/// else. Red edit: give `build` an `impl Display` parameter again.
#[test]
fn a_builder_error_cannot_be_stringified_at_the_assembly_boundary() {
    use crate::engine::bond_assembly::BondAssemblyError;
    use crate::engine::drain_assembly::DrainAssemblyError;
    use crate::engine::error::KeyEngineError;
    use shekyl_tx_builder::{SignFault, TxBuilderError};

    let refused = TxBuilderError::PqcLeafMismatch { index: 2 };
    assert!(matches!(
        BondAssemblyError::build("proving", refused),
        BondAssemblyError::Signer(SignFault::PqcLeafMismatch { input: 2 })
    ));

    let fault = SignFault::PqcLeafMismatch { input: 2 };
    assert!(matches!(
        DrainAssemblyError::build("drain wire assembly", KeyEngineError::Sign(fault)),
        DrainAssemblyError::Signer(f) if f == fault
    ));
    assert!(matches!(
        DrainAssemblyError::build("drain finalize", BondAssemblyError::Signer(fault)),
        DrainAssemblyError::Signer(f) if f == fault
    ));

    match BondAssemblyError::build("transaction key", "os randomness failed") {
        BondAssemblyError::Build { stage, detail } => {
            assert_eq!(stage, "transaction key");
            assert!(detail.contains("randomness"), "{detail}");
        }
        BondAssemblyError::Signer(_) => panic!("a pipeline detail is not a signer fault"),
        other => panic!("a pipeline detail stays a pipeline detail: {other}"),
    }
    match DrainAssemblyError::build(
        "drain wire assembly",
        KeyEngineError::Primitive {
            detail: "bulletproof",
        },
    ) {
        DrainAssemblyError::Build { detail, .. } => {
            assert!(detail.contains("bulletproof"), "{detail}");
        }
        other => panic!("a key-engine primitive failure is not a signer fault: {other:?}"),
    }
}
