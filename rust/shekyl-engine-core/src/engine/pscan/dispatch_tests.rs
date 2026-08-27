// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tests for the block-timed dispatch driver ([`super::dispatch`]).
//!
//! Extracted to a sibling rather than left inline: `dispatch.rs` reached its
//! `engine_decomposition_ratchet` ceiling when the reservation-settlement suite
//! landed, and the ratchet's remedy for a test-heavy file is the one the rest of
//! this crate already uses (`pscan/accrual_tests.rs`, `pscan/task_tests.rs`) —
//! move the suite out and EXCLUDE it, rather than raise a production ceiling to
//! make room for tests.

//! Driver gates from `ARCHIVAL_BOND_WI3_DISPATCH.md` §5: due-check
//! boundaries (gate 1), one-per-tick + deterministic ordering (gate 2),
//! seal-before-send (gate 3), byte-identical resubmit (gate 4),
//! confirmation retire + reservation release in one seal / state-agnostic
//! confirmation (gate 5), terminal rejection removal (gate 6), the
//! alarm-horizon resubmit bound (§3.4), and gate 5b — reservation
//! settlement for the claim/drain kinds.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use shekyl_types::{PSlot, TxHash};

use super::*;
use crate::engine::transaction_submitter::BroadcastKind;

/// One scripted submit verdict (the `BondBroadcast` return shape).
type Verdict = Result<SubmitSuccess, BroadcastSubmitError>;
/// The driver under test: in-memory seal store + scripted broadcast.
type TestDriver = DispatchDriver<std::sync::Arc<MemStore>, std::sync::Arc<ScriptedBroadcast>>;

// -- test doubles --------------------------------------------------------

/// In-memory [`PendingSealStore`] with a save kill-switch (for the
/// seal-failure half of gate 3).
#[derive(Default)]
struct MemStore {
    block: Mutex<Option<PendingPostBlock>>,
    fail_saves: AtomicBool,
    saves: Mutex<u64>,
}

#[derive(Debug, thiserror::Error)]
#[error("injected seal failure")]
struct InjectedSealFailure;

impl PendingSealStore for std::sync::Arc<MemStore> {
    type Error = InjectedSealFailure;

    async fn load(&self) -> Result<Option<PendingPostBlock>, Self::Error> {
        Ok(self.block.lock().expect("mem store").clone())
    }

    async fn save(&self, block: &PendingPostBlock) -> Result<(), Self::Error> {
        if self.fail_saves.load(Ordering::Relaxed) {
            return Err(InjectedSealFailure);
        }
        *self.saves.lock().expect("mem store") += 1;
        *self.block.lock().expect("mem store") = Some(block.clone());
        Ok(())
    }
}

/// Scripted [`BondBroadcast`]: pops the next verdict per call and records
/// every `(persona, bytes)` it was handed.
#[derive(Default)]
struct ScriptedBroadcast {
    script: Mutex<VecDeque<Verdict>>,
    sent: Mutex<Vec<(PCanonicalId, Vec<u8>)>>,
}

impl ScriptedBroadcast {
    fn scripted(outcomes: Vec<Verdict>) -> Self {
        Self {
            script: Mutex::new(outcomes.into()),
            sent: Mutex::new(Vec::new()),
        }
    }

    fn sent(&self) -> Vec<(PCanonicalId, Vec<u8>)> {
        self.sent.lock().expect("sent").clone()
    }
}

impl BondBroadcast for std::sync::Arc<ScriptedBroadcast> {
    async fn submit_bound(
        &self,
        bound: PBoundBytes,
    ) -> Result<SubmitSuccess, BroadcastSubmitError> {
        self.sent
            .lock()
            .expect("sent")
            .push((*bound.persona(), bound.bytes().to_vec()));
        self.script
            .lock()
            .expect("script")
            .pop_front()
            .unwrap_or(Ok(SubmitSuccess::Broadcast {
                hash: TxHash::from_bytes([0u8; 32]),
                kind: BroadcastKind::Accepted,
            }))
    }
}

fn persona(byte: u8) -> PCanonicalId {
    PCanonicalId::from_bytes([byte; 32])
}

fn post(persona_byte: u8, anchor: u64, offset: u64, gindexes: &[u64]) -> PendingBondPost {
    PendingBondPost {
        p_slot: PSlot::from_raw(u32::from(persona_byte)),
        persona: persona(persona_byte),
        tx_bytes: vec![persona_byte, 0xBE, 0xEF],
        bond_post_offset_blocks: offset,
        anchor_t0: BlockHeight::from_raw(anchor),
        funding_gindexes: gindexes
            .iter()
            .copied()
            .map(shekyl_types::GlobalOutputIndex::from_raw)
            .collect(),
        state: PendingPostState::Pending,
    }
}

fn test_config() -> DispatchConfig {
    DispatchConfig {
        alarm_horizon_blocks: 100,
        // No dispersal sleep in tests: the draw's decorrelation is a
        // WI-4-graded behavior, not a unit-testable invariant.
        dispersal_bound: Duration::ZERO,
    }
}

/// A fresh per-test pending-seal write lock (in production the `Engine`
/// owns one per wallet and shares it with the WI-2 assemble path).
fn test_lock() -> Arc<tokio::sync::Mutex<()>> {
    Arc::new(tokio::sync::Mutex::new(()))
}

fn driver_with_posts(
    posts: Vec<PendingBondPost>,
    outcomes: Vec<Verdict>,
) -> (
    TestDriver,
    std::sync::Arc<MemStore>,
    std::sync::Arc<ScriptedBroadcast>,
) {
    let store = std::sync::Arc::new(MemStore::default());
    *store.block.lock().expect("mem store") = Some(PendingPostBlock::new(posts));
    let broadcast = std::sync::Arc::new(ScriptedBroadcast::scripted(outcomes));
    let driver = DispatchDriver::new(store.clone(), broadcast.clone(), test_config(), test_lock());
    (driver, store, broadcast)
}

fn sealed_state(store: &MemStore, persona: &PCanonicalId) -> Option<PendingPostState> {
    store
        .block
        .lock()
        .expect("mem store")
        .as_ref()
        .and_then(|b| b.posts().iter().find(|p| &p.persona == persona))
        .map(|p| p.state)
}

// The helpers return the script's slot type on purpose (a `Verdict`, not a
// bare success): the scripted queue mixes Ok and Err entries.
#[allow(clippy::unnecessary_wraps)]
fn accepted() -> Verdict {
    Ok(SubmitSuccess::Broadcast {
        hash: TxHash::from_bytes([1u8; 32]),
        kind: BroadcastKind::Accepted,
    })
}

fn ambiguous() -> Verdict {
    Err(BroadcastSubmitError::Submit(SubmitterError::Ambiguous {
        kind: crate::engine::error::AmbiguousErrorKind::DaemonTimeout,
    }))
}

async fn tick(driver: &mut TestDriver, tip: u64) {
    driver
        .on_tick(
            BlockHeight::from_raw(tip),
            TickEvidence {
                confirmed_posts: &BTreeSet::new(),
                live_funding: &BTreeSet::new(),
            },
            &CancellationToken::new(),
        )
        .await
        .expect("tick");
}

// -- gate 1: due-check boundaries ----------------------------------------

/// `due = anchor_t0 + offset`, boundary-exact: nothing fires at
/// `due − 1`, the dispatch fires at `due`, and a late tick (`due + k`)
/// still fires (late is monotone noise, §3.6).
#[tokio::test]
async fn due_check_boundaries() {
    // anchor 100 + offset 10 ⇒ due at 110.
    let (mut driver, _store, broadcast) = driver_with_posts(
        vec![post(1, 100, 10, &[7])],
        (0..3).map(|_| accepted()).collect(),
    );

    tick(&mut driver, 109).await;
    assert!(broadcast.sent().is_empty(), "tip = due − 1 must not fire");

    tick(&mut driver, 110).await;
    assert_eq!(broadcast.sent().len(), 1, "tip = due fires");

    // A later overdue tick would resubmit only on unknown outcome; the
    // accepted verdict holds it — covered below. Late-first-dispatch:
    let (mut late_driver, _s, late_broadcast) =
        driver_with_posts(vec![post(2, 100, 10, &[8])], vec![accepted()]);
    tick(&mut late_driver, 500).await;
    assert_eq!(
        late_broadcast.sent().len(),
        1,
        "tip = due + k fires (lateness only adds delay, never a re-draw)"
    );
}

// -- gate 2: one-per-tick + deterministic ordering ------------------------

/// A catch-up backlog (every post overdue on one tick) dispatches exactly
/// one post per tick, lowest due block first; ties break by `anchor_t0`
/// then persona id.
#[tokio::test]
async fn one_per_tick_and_deterministic_ordering() {
    // due: A=130 (anchor 100), B=120 (anchor 90), C=120 (anchor 80),
    // D=120 (anchor 80, higher persona byte than C).
    let posts = vec![
        post(0xAA, 100, 30, &[1]),
        post(0xBB, 90, 30, &[2]),
        post(0xCC, 80, 40, &[3]),
        post(0xDD, 80, 40, &[4]),
    ];
    let (mut driver, _store, broadcast) =
        driver_with_posts(posts, (0..4).map(|_| accepted()).collect());

    // Every post overdue at once — the downtime catch-up shape (§3.2).
    for _ in 0..4 {
        tick(&mut driver, 1_000).await;
    }
    let sent: Vec<PCanonicalId> = broadcast.sent().iter().map(|(p, _)| *p).collect();
    assert_eq!(
        sent,
        vec![persona(0xCC), persona(0xDD), persona(0xBB), persona(0xAA)],
        "order: lowest due first (C/D/B at 120 before A at 130); the C/D tie breaks by \
         anchor_t0 (equal) then persona id (0xCC < 0xDD)"
    );

    // And strictly one per tick: 4 ticks, 4 sends.
    assert_eq!(broadcast.sent().len(), 4);
}

// -- gate 3: seal-before-send ---------------------------------------------

/// The sealed state already says `Dispatched` when the send fails: a
/// crash/failure after the seal resumes as "maybe sent", which is the
/// recoverable direction (§3.3 step 2).
#[tokio::test]
async fn seal_precedes_send_failed_send_leaves_dispatched() {
    let (mut driver, store, broadcast) =
        driver_with_posts(vec![post(1, 100, 0, &[7])], vec![ambiguous()]);

    tick(&mut driver, 100).await;

    assert_eq!(broadcast.sent().len(), 1, "the send was attempted");
    match sealed_state(&store, &persona(1)) {
        Some(PendingPostState::Dispatched { at, attempts }) => {
            assert_eq!(at.to_raw(), 100, "`at` records the due-check tip");
            assert_eq!(attempts, 1);
        }
        other => panic!("sealed state must be Dispatched after a failed send, got {other:?}"),
    }
}

/// The reverse half: when the SEAL fails, **no send happens** (§4 row 2 —
/// "error logged; no send happens; retried next tick").
#[tokio::test]
async fn failed_seal_sends_nothing() {
    let (mut driver, store, broadcast) =
        driver_with_posts(vec![post(1, 100, 0, &[7])], vec![accepted()]);
    store.fail_saves.store(true, Ordering::Relaxed);

    let result = driver
        .on_tick(
            BlockHeight::from_raw(100),
            TickEvidence {
                confirmed_posts: &BTreeSet::new(),
                live_funding: &BTreeSet::new(),
            },
            &CancellationToken::new(),
        )
        .await;

    assert!(result.is_err(), "the seal failure surfaces as a tick error");
    assert!(
        broadcast.sent().is_empty(),
        "nothing may reach a wire when the Dispatched transition did not seal"
    );

    // Recovery: the next tick (seal healthy again) dispatches normally.
    store.fail_saves.store(false, Ordering::Relaxed);
    tick(&mut driver, 101).await;
    assert_eq!(broadcast.sent().len(), 1, "retried next tick");
}

// -- gate 4 (driver half): byte-identical resubmit -------------------------

/// An unknown-outcome dispatch resubmits on the next tick with exactly
/// the sealed bytes (pin P-2 extended to the retry path), bumping the
/// attempt counter; `at` stays the first-dispatch tip.
#[tokio::test]
async fn resubmit_sends_identical_bytes_and_bumps_attempts() {
    let (mut driver, store, broadcast) = driver_with_posts(
        vec![post(1, 100, 0, &[7])],
        vec![ambiguous(), ambiguous(), accepted()],
    );

    tick(&mut driver, 100).await;
    tick(&mut driver, 101).await;
    tick(&mut driver, 102).await;

    let sent = broadcast.sent();
    assert_eq!(sent.len(), 3, "two unknown outcomes ⇒ two resubmits");
    assert_eq!(sent[0].1, sent[1].1, "attempt 2 sends the stored bytes");
    assert_eq!(sent[1].1, sent[2].1, "attempt 3 sends the stored bytes");

    match sealed_state(&store, &persona(1)) {
        Some(PendingPostState::Dispatched { at, attempts }) => {
            assert_eq!(attempts, 3);
            assert_eq!(
                at.to_raw(),
                100,
                "`at` records the FIRST due-check tip, never a resubmit's"
            );
        }
        other => panic!("expected Dispatched, got {other:?}"),
    }

    // The accepted verdict on attempt 3 holds further resubmits: the
    // record awaits pscan confirmation, resending adds nothing (F31).
    tick(&mut driver, 103).await;
    assert_eq!(
        broadcast.sent().len(),
        3,
        "a success-equivalent verdict stops the per-tick resubmit"
    );
}

/// A success-equivalent hold is session-scoped by design: a restarted
/// driver re-probes once with the same bytes (safe by P-2), then holds
/// again — the watchdog's probe discipline.
#[tokio::test]
async fn restart_reprobes_a_dispatched_post_once() {
    let (mut driver, store, broadcast) =
        driver_with_posts(vec![post(1, 100, 0, &[7])], vec![accepted()]);
    tick(&mut driver, 100).await;
    assert_eq!(broadcast.sent().len(), 1);

    // "Restart": a fresh driver over the same sealed store (held set empty).
    let broadcast2 = std::sync::Arc::new(ScriptedBroadcast::scripted(vec![accepted()]));
    let mut driver2 = DispatchDriver::new(
        store.clone(),
        broadcast2.clone(),
        test_config(),
        test_lock(),
    );
    tick(&mut driver2, 101).await;
    tick(&mut driver2, 102).await;

    let sent = broadcast2.sent();
    assert_eq!(sent.len(), 1, "one re-probe, then held again");
    assert_eq!(
        sent[0].1,
        vec![1, 0xBE, 0xEF],
        "the re-probe sends the sealed bytes"
    );
}

// -- gate 5: confirmation retire ------------------------------------------

/// A pscan confirmation removes the record — bytes and derived
/// reservation in one seal — and is state-agnostic: a `Pending` record
/// whose persona shows a confirmed post (the seal-before-send crash
/// case) retires identically.
#[tokio::test]
async fn confirmation_retires_bytes_and_reservation_in_one_seal() {
    let (mut driver, store, broadcast) = driver_with_posts(
        vec![post(1, 100, 0, &[7, 8]), post(2, 100, 500, &[9])],
        vec![accepted()],
    );
    tick(&mut driver, 100).await; // dispatch persona 1
    assert_eq!(broadcast.sent().len(), 1);

    // Confirmation for the Dispatched persona 1 AND the still-Pending
    // persona 2 (state-agnostic: prior instance sent and died pre-seal).
    let confirmed: BTreeSet<PCanonicalId> = [persona(1), persona(2)].into();
    driver
        .on_tick(
            BlockHeight::from_raw(101),
            TickEvidence {
                confirmed_posts: &confirmed,
                live_funding: &BTreeSet::new(),
            },
            &CancellationToken::new(),
        )
        .await
        .expect("tick");

    let block = store
        .block
        .lock()
        .expect("mem store")
        .clone()
        .expect("sealed");
    assert!(block.posts().is_empty(), "both records retired");
    assert!(
        block.reserved_gindexes().is_empty(),
        "the derived reservation released with the records — same seal, no second write"
    );
}

// -- gate 5b: reservation settlement (claims + drains) ---------------------

/// Seed a driver whose block also carries a live claim and a live drain,
/// each reserving one funding output.
fn driver_with_reservations() -> (TestDriver, std::sync::Arc<MemStore>) {
    use shekyl_engine_state::pending_post_block::{PendingDrain, PendingEmissionClaim};
    let mut block = PendingPostBlock::empty();
    assert!(block.push_claim(PendingEmissionClaim {
        persona: persona(1),
        tx_bytes: vec![0xCD; 8],
        fee_gindexes: vec![shekyl_types::GlobalOutputIndex::from_raw(11)],
        state: PendingPostState::Pending,
    }));
    assert!(block.push_drain(PendingDrain {
        persona: persona(2),
        tx_bytes: vec![0xEF; 8],
        funding_gindexes: vec![shekyl_types::GlobalOutputIndex::from_raw(22)],
        state: PendingPostState::Pending,
    }));
    let store = std::sync::Arc::new(MemStore::default());
    *store.block.lock().expect("mem store") = Some(block);
    let broadcast = std::sync::Arc::new(ScriptedBroadcast::scripted(vec![]));
    let driver = DispatchDriver::new(store.clone(), broadcast, test_config(), test_lock());
    (driver, store)
}

/// **The negative control, and it goes first.** A JoinMarket bond-post
/// confirmation must not retire a live claim or a live drain.
///
/// `confirmed_join_market_personas` reads like a general "these personas
/// confirmed" set and is filtered to `BOND_POST_KIND_JOINMARKET` by
/// construction. Handing it to the reservation-observed kinds would retire a
/// drain because that persona's *bond post* confirmed — a different
/// transaction, releasing the gate that stops a second drain racing the
/// first's inputs. Both records here name a persona in `confirmed_posts`, so
/// a driver that crossed the two evidence sources retires them and this test
/// goes red.
#[tokio::test]
async fn a_bond_post_confirmation_never_retires_a_claim_or_drain() {
    let (mut driver, store) = driver_with_reservations();

    // Both personas confirmed a bond post; both reservations are still live.
    let confirmed: BTreeSet<PCanonicalId> = [persona(1), persona(2)].into();
    let live: BTreeSet<shekyl_types::GlobalOutputIndex> = [11, 22]
        .map(shekyl_types::GlobalOutputIndex::from_raw)
        .into();
    driver
        .on_tick(
            BlockHeight::from_raw(100),
            TickEvidence {
                confirmed_posts: &confirmed,
                live_funding: &live,
            },
            &CancellationToken::new(),
        )
        .await
        .expect("tick");

    let block = store
        .block
        .lock()
        .expect("mem store")
        .clone()
        .expect("sealed");
    assert!(
        block.has_live_claim_for(&persona(1)),
        "a bond-post confirmation is not this claim's settlement"
    );
    assert!(
        block.has_live_drain_for(&persona(2)),
        "a bond-post confirmation is not this drain's settlement"
    );
}

/// The seal releases when the reservation settles — the defect this driver
/// closes, for both kinds.
///
/// Before it, a confirmed drain left `has_live_drain_for` true forever (the
/// persona's lane refused `-29511` across sessions) and a confirmed claim
/// left `has_live_claim_for` true forever — the worse of the two, because
/// claims are engine-automated: the persona simply stopped claiming, with no
/// user action to correlate the silence against.
#[tokio::test]
async fn a_settled_reservation_retires_the_claim_and_the_drain() {
    let (mut driver, store) = driver_with_reservations();

    // Neither reservation remains in the accrual's live funding set: both
    // transactions spent their inputs and confirmed.
    driver
        .on_tick(
            BlockHeight::from_raw(100),
            TickEvidence {
                confirmed_posts: &BTreeSet::new(),
                live_funding: &BTreeSet::new(),
            },
            &CancellationToken::new(),
        )
        .await
        .expect("tick");

    let block = store
        .block
        .lock()
        .expect("mem store")
        .clone()
        .expect("sealed");
    assert!(
        !block.has_live_claim_for(&persona(1)),
        "claim gate reopened"
    );
    assert!(
        !block.has_live_drain_for(&persona(2)),
        "drain lane reopened"
    );
    assert!(
        block.reserved_gindexes().is_empty(),
        "records and their reservations released in the same seal (R2-4)"
    );
}

/// A dispatched claim and drain that never settle both alarm — and the
/// **same persona gets both**.
///
/// That is the whole reason alarms are keyed by `(kind, persona)`. Keying on
/// persona alone would let the claim's alarm mark the persona as alarmed and
/// silence the drain's, turning alarm-once into alarm-never for the second
/// kind — on exactly the persona that has two things stuck at once, which is
/// the case an operator most needs to see. Collapsing the key makes this
/// test red.
#[tokio::test]
async fn a_stalled_claim_and_drain_on_one_persona_both_alarm() {
    use shekyl_engine_state::pending_post_block::{PendingDrain, PendingEmissionClaim};
    let p = persona(1);
    let mut block = PendingPostBlock::empty();
    assert!(block.push_claim(PendingEmissionClaim {
        persona: p,
        tx_bytes: vec![0xCD; 8],
        fee_gindexes: vec![shekyl_types::GlobalOutputIndex::from_raw(11)],
        state: PendingPostState::Pending,
    }));
    assert!(block.push_drain(PendingDrain {
        persona: p,
        tx_bytes: vec![0xEF; 8],
        funding_gindexes: vec![shekyl_types::GlobalOutputIndex::from_raw(22)],
        state: PendingPostState::Pending,
    }));
    let at = BlockHeight::from_raw(100);
    assert!(block.mark_claim_dispatched(&p, at).is_some());
    assert!(block.mark_drain_dispatched(&p, at).is_some());

    let store = std::sync::Arc::new(MemStore::default());
    *store.block.lock().expect("mem store") = Some(block);
    let mut driver = DispatchDriver::new(
        store.clone(),
        std::sync::Arc::new(ScriptedBroadcast::scripted(vec![])),
        test_config(),
        test_lock(),
    );

    // Well past the horizon, with both reservations still on chain.
    let live: BTreeSet<shekyl_types::GlobalOutputIndex> = [11, 22]
        .map(shekyl_types::GlobalOutputIndex::from_raw)
        .into();
    driver
        .on_tick(
            BlockHeight::from_raw(100 + test_config().alarm_horizon_blocks),
            TickEvidence {
                confirmed_posts: &BTreeSet::new(),
                live_funding: &live,
            },
            &CancellationToken::new(),
        )
        .await
        .expect("tick");

    assert!(
        driver
            .alarmed_reservations
            .contains(&(ReservationKind::Claim, p)),
        "the stalled claim must alarm"
    );
    assert!(
        driver
            .alarmed_reservations
            .contains(&(ReservationKind::Drain, p)),
        "the stalled drain must alarm too — one persona, two stuck records"
    );

    // Both records are HELD: the alarm names the stall, it does not resolve it.
    let block = store
        .block
        .lock()
        .expect("mem store")
        .clone()
        .expect("sealed");
    assert!(block.has_live_claim_for(&p) && block.has_live_drain_for(&p));
}

/// **Settling one kind must not un-alarm the other.**
///
/// The companion to `a_stalled_claim_and_drain_on_one_persona_both_alarm`, and
/// the half that test did NOT cover: it pinned the key's shape on the *insert*
/// side and said nothing about the clear. The first version of this driver
/// cleared both keys for any settled persona, so a persona whose claim settled
/// while its drain stayed stuck lost the drain's marker and re-alarmed it on
/// every subsequent sweep — alarm-once silently becoming alarm-always, on the
/// one record still in trouble.
///
/// Restoring the both-keys clear turns this red.
#[tokio::test]
async fn settling_a_claim_leaves_a_still_stuck_drains_alarm_marked() {
    use shekyl_engine_state::pending_post_block::{PendingDrain, PendingEmissionClaim};
    let p = persona(1);
    let mut block = PendingPostBlock::empty();
    assert!(block.push_claim(PendingEmissionClaim {
        persona: p,
        tx_bytes: vec![0xCD; 8],
        fee_gindexes: vec![shekyl_types::GlobalOutputIndex::from_raw(11)],
        state: PendingPostState::Pending,
    }));
    assert!(block.push_drain(PendingDrain {
        persona: p,
        tx_bytes: vec![0xEF; 8],
        funding_gindexes: vec![shekyl_types::GlobalOutputIndex::from_raw(22)],
        state: PendingPostState::Pending,
    }));
    let at = BlockHeight::from_raw(100);
    assert!(block.mark_claim_dispatched(&p, at).is_some());
    assert!(block.mark_drain_dispatched(&p, at).is_some());

    let store = std::sync::Arc::new(MemStore::default());
    *store.block.lock().expect("mem store") = Some(block);
    let mut driver = DispatchDriver::new(
        store.clone(),
        std::sync::Arc::new(ScriptedBroadcast::scripted(vec![])),
        test_config(),
        test_lock(),
    );
    let stalled_tip = BlockHeight::from_raw(100 + test_config().alarm_horizon_blocks);
    let both_live: BTreeSet<shekyl_types::GlobalOutputIndex> = [11, 22]
        .map(shekyl_types::GlobalOutputIndex::from_raw)
        .into();

    // Tick 1: both stall, both alarm.
    driver
        .on_tick(
            stalled_tip,
            TickEvidence {
                confirmed_posts: &BTreeSet::new(),
                live_funding: &both_live,
            },
            &CancellationToken::new(),
        )
        .await
        .expect("tick");
    assert!(driver
        .alarmed_reservations
        .contains(&(ReservationKind::Claim, p)));
    assert!(driver
        .alarmed_reservations
        .contains(&(ReservationKind::Drain, p)));

    // Tick 2: the CLAIM settles (gindex 11 gone); the drain is still stuck.
    let drain_only: BTreeSet<shekyl_types::GlobalOutputIndex> =
        [22].map(shekyl_types::GlobalOutputIndex::from_raw).into();
    driver
        .on_tick(
            stalled_tip,
            TickEvidence {
                confirmed_posts: &BTreeSet::new(),
                live_funding: &drain_only,
            },
            &CancellationToken::new(),
        )
        .await
        .expect("tick");

    let block = store
        .block
        .lock()
        .expect("mem store")
        .clone()
        .expect("sealed");
    assert!(!block.has_live_claim_for(&p), "the claim settled");
    assert!(block.has_live_drain_for(&p), "the drain is still stuck");

    assert!(
        !driver
            .alarmed_reservations
            .contains(&(ReservationKind::Claim, p)),
        "the settled claim's marker is cleared — it can alarm again if it ever \
         returns"
    );
    assert!(
        driver
            .alarmed_reservations
            .contains(&(ReservationKind::Drain, p)),
        "the still-stuck drain stays marked, so it does NOT re-alarm every tick"
    );
}

/// **The retire's premise, pinned at every writer that could falsify it.**
///
/// `remove_settled` reads "every gindex this record reserved has left the live
/// funding set" as proof that THIS record's transaction confirmed. That
/// inference holds only while a given gindex can be reserved by one record at a
/// time. If two records share an input, either one confirming spends it and
/// retires BOTH — reopening a gate whose transaction never landed, which is the
/// one outcome the seal exists to prevent.
///
/// Persona dedup does not give that: it refuses a second record *for the same
/// persona and kind*, and sees nothing about a cross-kind gindex collision. The pre-assembly `reserved_gindexes`
/// snapshot does not give it either — it is stale by the time the seal runs.
/// Only a re-check inside the same locked mutate does.
///
/// The drain seam had an overlap check but ran it BEFORE persona dedup; the
/// claim and bond-post seams had none. Review #572 replaced all three with one
/// shared decision, `PendingPostBlock::classify_seal`, reached only through the
/// `seal_post` / `seal_claim` / `seal_drain` trio that also performs the insert
/// — so the ordering and the overlap rule exist once and cannot drift, and a
/// seam cannot classify without sealing or seal without classifying.
///
/// This pin is deliberately only the structural half: it asserts every writer
/// routes through that trio. What the decision *does* — persona dedup
/// outranking overlap, cross-kind collisions classified as raced, one-live being
/// per kind — is covered behaviourally beside `classify_seal` itself, where a
/// wrong answer can be observed rather than merely a missing call. Splitting it
/// that way is what makes the pin honest: a grep can only ever prove the call
/// site exists, which is why the seal it names is the one that cannot be
/// performed wrongly.
#[test]
fn every_reservation_writer_rechecks_the_union_under_the_seal_lock() {
    // Production halves only — a doc-comment mention must not satisfy the pin.
    for (name, src, seal) in [
        (
            "drain_dispatch.rs",
            include_str!("../drain_dispatch.rs"),
            ".seal_drain(",
        ),
        (
            "claim_dispatch.rs",
            include_str!("../claim_dispatch.rs"),
            ".seal_claim(",
        ),
        (
            "bond_orchestrator.rs",
            include_str!("../bond_orchestrator.rs"),
            ".seal_post(",
        ),
    ] {
        let production = src
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .unwrap_or(src);
        let code: String = production
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            code.contains(seal),
            "{name} seals a reservation without routing through `{seal}` — \
             `remove_settled` then cannot tell which of two records sharing a \
             gindex actually confirmed, and the persona-vs-overlap ordering is \
             free to drift in this seam"
        );
        // The insert primitives bypass the classifier; only the trio may seal.
        for bare in [".push_post(", ".push_claim(", ".push_drain("] {
            assert!(
                !code.contains(bare),
                "{name} inserts a pending record with `{bare}`, which skips the \
                 shared seal decision"
            );
        }
        // The generation the seal compares is only sound if the pending block
        // was read BEFORE the pscan seal — otherwise stale funding pairs with a
        // current generation and the seal admits an already-spent input.
        // `load_seal_basis` owns that ordering; a seam that took the two reads
        // itself would be free to concurrently join them again, which is
        // exactly the regression review #572 round 6 found.
        assert!(
            code.contains("load_seal_basis("),
            "{name} builds its seal basis without `load_seal_basis`, so nothing \
             holds the pending read ahead of the pscan load"
        );
    }
}

// -- gate 6: terminal rejection --------------------------------------------

/// A terminal verify rejection removes the record (releasing bytes +
/// reservation, R2-4) and never resends.
#[tokio::test]
async fn terminal_rejection_removes_and_never_resends() {
    let terminal = Err(BroadcastSubmitError::Submit(
        SubmitterError::RejectedTerminal {
            kind: crate::engine::error::TerminalErrorKind::DoubleSpend,
        },
    ));
    let (mut driver, store, broadcast) =
        driver_with_posts(vec![post(1, 100, 0, &[7, 8])], vec![terminal]);

    tick(&mut driver, 100).await;
    assert_eq!(broadcast.sent().len(), 1);

    let block = store
        .block
        .lock()
        .expect("mem store")
        .clone()
        .expect("sealed");
    assert!(
        block.posts().is_empty(),
        "terminal reject prunes the signed bytes at rest (no resurrection on restart)"
    );
    assert!(block.reserved_gindexes().is_empty(), "reservation released");

    tick(&mut driver, 101).await;
    assert_eq!(broadcast.sent().len(), 1, "never resends after terminal");
}

// -- §3.4 resubmit bound: the alarm horizon ---------------------------------

/// A dispatched post unconfirmed past the alarm horizon stops
/// resubmitting and alarms once; the record and its reservation are held
/// (funds-safety over liveness).
#[tokio::test]
async fn alarm_horizon_stops_resubmits_and_holds_the_record() {
    let (mut driver, store, broadcast) = driver_with_posts(
        vec![post(1, 100, 0, &[7])],
        vec![ambiguous(), ambiguous(), ambiguous()],
    );

    tick(&mut driver, 100).await; // dispatch, at = 100
    tick(&mut driver, 150).await; // unknown outcome ⇒ resubmit
    assert_eq!(broadcast.sent().len(), 2);

    // horizon = 100 (test config): past-horizon at tip 200.
    tick(&mut driver, 200).await;
    tick(&mut driver, 201).await;
    assert_eq!(
        broadcast.sent().len(),
        2,
        "past the horizon, resubmits stop (the escalation is the alarm, not a faster loop)"
    );

    let block = store
        .block
        .lock()
        .expect("mem store")
        .clone()
        .expect("sealed");
    assert_eq!(block.posts().len(), 1, "the record is held, not removed");
    assert_eq!(
        block.reserved_gindexes(),
        [shekyl_types::GlobalOutputIndex::from_raw(7)].into(),
        "the funding reservation stays intact (funds-safety over liveness)"
    );
}

// -- selection unit coverage -------------------------------------------------

/// The pure selector: held and alarmed personas are excluded; `Pending`
/// posts are always candidates when due.
#[test]
fn selector_excludes_held_and_alarmed() {
    let posts = vec![post(1, 100, 0, &[1]), post(2, 100, 0, &[2])];
    let tip = BlockHeight::from_raw(100);

    let held: BTreeSet<PCanonicalId> = [persona(1)].into();
    let none = BTreeSet::new();
    // Pending posts ignore the held set (it only gates resubmits).
    let picked =
        select_dispatch_candidate(&posts, tip, 100, &held, &none).expect("a candidate exists");
    assert_eq!(picked.persona, persona(1), "Pending ignores held");

    let alarmed: BTreeSet<PCanonicalId> = [persona(1)].into();
    let picked =
        select_dispatch_candidate(&posts, tip, 100, &none, &alarmed).expect("a candidate exists");
    assert_eq!(picked.persona, persona(2), "alarmed personas are excluded");
}

/// GF-7 emission-completeness, driver edition (§3.7 / gate 8, the
/// stake-engine emission test's shape): every submit call site emits
/// exactly one `BondPostDispatched` — the first send and each
/// byte-identical resubmit (the timeline records every network
/// exposure, which is what WI-4's correlator grades) — with the opaque
/// slot ordinal and the due-check tip as the payload (no wall-clock,
/// no txid, no identity). Ticks that send nothing emit nothing.
#[cfg(feature = "gf7-hooks")]
#[tokio::test]
async fn gf7_emits_bond_post_dispatched_per_submit() {
    use std::sync::Arc;

    #[derive(Default)]
    struct Recorder(Arc<Mutex<Vec<TimelineEvent>>>);
    impl BroadcastTimelineObserver for Recorder {
        fn record(&mut self, event: TimelineEvent) {
            self.0.lock().expect("recorder").push(event);
        }
    }

    let events = Arc::new(Mutex::new(Vec::new()));
    // First send lands ambiguous ⇒ the next due tick resubmits.
    let (mut driver, _store, broadcast) =
        driver_with_posts(vec![post(5, 100, 0, &[7])], vec![ambiguous(), accepted()]);
    driver.set_observer(Box::new(Recorder(events.clone())));

    // Not yet due: no send, no emission (emission is the submit call
    // site, nothing else on the tick emits).
    tick(&mut driver, 99).await;
    assert!(
        events.lock().expect("recorder").is_empty(),
        "a no-send tick must not emit"
    );

    tick(&mut driver, 100).await; // first send (ambiguous outcome)
    tick(&mut driver, 150).await; // byte-identical resubmit (accepted)
    assert_eq!(broadcast.sent().len(), 2, "two network exposures");

    let recorded = events.lock().expect("recorder").clone();
    assert_eq!(
        recorded,
        vec![
            TimelineEvent::BondPostDispatched {
                persona: 5,
                at: 100
            },
            TimelineEvent::BondPostDispatched {
                persona: 5,
                at: 150
            },
        ],
        "one emission per submit — slot ordinal + the tick's tip, and nothing besides \
         the submit call site emits"
    );
}
