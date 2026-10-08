// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The serving task's lifecycle, driven against the operator alarm board.

use super::*;
use shekyl_curve_tree::{BlockHeight, LeafStore, ServingReader};
use shekyl_operator_alarm::{AlarmCondition, Arming, ConditionState, DisarmedReason};
use shekyl_p_host::PinReport as HostPinReport;
use shekyl_tor_control_wallet::service::OnionIdentity;

use crate::engine::refresh::RefreshSlot;

/// Longer than any wait in this suite.
///
/// The refresh cadence and the daemon-tip age share it, so the post-start
/// report is what a pass observes.
const BEYOND_THIS_SUITE: Duration = Duration::from_secs(60 * 60);

/// A pinner over a real (empty) store. An empty serve-set is a legitimate
/// production state — a released persona reports exactly this — so the
/// lifecycle can be driven end to end without fabricating segments.
struct EmptySetPinner {
    store: Arc<LeafStore>,
    fail: bool,
}

impl ServeSetPinner for EmptySetPinner {
    async fn pin_serve_set(&self) -> Result<HostPinReport, String> {
        if self.fail {
            return Err("pinner is down".into());
        }
        Ok(HostPinReport {
            set: shekyl_p_host::ReportedSet::ShardList {
                shard_ids: Vec::new(),
                outcomes: Vec::new(),
            },
            as_of_height: BlockHeight::from_raw(0),
            reader: ServingReader::new(Arc::clone(&self.store)),
        })
    }
}

fn pinner(fail: bool) -> EmptySetPinner {
    EmptySetPinner {
        store: Arc::new(LeafStore::open_ephemeral().expect("store")),
        fail,
    }
}

/// A pinner that answers the start pin and then never answers again — a
/// store actor that has wedged after the host came up.
struct WedgingPinner {
    inner: EmptySetPinner,
    answered_start: std::sync::atomic::AtomicBool,
}

impl ServeSetPinner for WedgingPinner {
    async fn pin_serve_set(&self) -> Result<HostPinReport, String> {
        if self
            .answered_start
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            std::future::pending().await
        } else {
            self.inner.pin_serve_set().await
        }
    }
}

/// A tor config whose binary cannot pass the hash gate. `start` returns as
/// soon as the supervisor is spawned (it does not await readiness), so this
/// drives a *successful* host start without a real tor.
fn churning_tor(dir: &tempfile::TempDir) -> WalletTorControlConfig {
    let bogus = dir.path().join("not-tor");
    std::fs::write(&bogus, b"not a tor binary").expect("write");
    WalletTorControlConfig {
        binary: shekyl_tor_control_wallet::service::TorBinarySource::At(bogus),
        data_dir: dir.path().join("data"),
        events: shekyl_tor_control_wallet::service::EventSink::unsubscribed(),
        policy: shekyl_tor_control_wallet::service::SupervisorPolicy::default(),
        disable_network: true,
        posture: shekyl_tor_control_wallet::service::ServingPosture::Client,
    }
}

fn serving_identity() -> PersonaServing {
    PersonaServing {
        identity: OnionIdentity::from_hs_id_seed(&[7u8; 32]),
        virtual_port: SERVING_VIRTUAL_PORT,
        max_streams: SERVING_MAX_STREAMS,
        key: std::sync::Arc::new(shekyl_p_host::RefusingKey),
        // Stamped, so these lifecycle cases exercise a persona whose
        // gate can answer. What the gate does with an unstamped cache is
        // `signer`'s and `daemon_tip`'s to assert, not this suite's.
        tip: {
            let tip = std::sync::Arc::new(shekyl_p_host::DaemonTipCache::new(BEYOND_THIS_SUITE));
            tip.stamp_synced(BlockHeight::from_raw(9_000));
            tip
        },
    }
}

/// No standoff and a cadence far longer than the test: the board must be
/// correct on the strength of the post-start report alone, never because a
/// refresh tick rescued it.
fn immediate() -> ServingConfig {
    ServingConfig {
        launch_window: Duration::ZERO,
        refresh_cadence: BEYOND_THIS_SUITE,
        staleness_bound: StalenessBound::blocks(10),
    }
}

/// A path that exists on the test machine's filesystem — the probe
/// must resolve rather than report `Unreadable` and muddy what the
/// lifecycle cases assert about the serve-set.
fn store_path() -> PathBuf {
    std::env::temp_dir()
}

fn claim() -> SlotGuard {
    RefreshSlot::new()
        .try_claim()
        .expect("fresh slot is claimable")
}

async fn settle_until(
    alarms: &OperatorAlarms,
    want: impl Fn(&shekyl_operator_alarm::AlarmBoard) -> bool,
) -> bool {
    for _ in 0..200 {
        if want(&alarms.board()) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

/// The board must not read "not serving" while the onion is live.
///
/// Without the post-start report the board keeps the standoff's
/// `NotServing` until the first refresh tick — up to a full cadence of an
/// operator being told the persona is down while it is published. The
/// cadence here is an hour, so only the immediate report can satisfy this.
#[tokio::test]
async fn the_board_stops_saying_not_serving_as_soon_as_the_host_is_up() {
    let dir = tempfile::tempdir().expect("tmp");
    let alarms = Arc::new(OperatorAlarms::new());
    let handle = spawn_serving_task(
        churning_tor(&dir),
        serving_identity(),
        pinner(false),
        Arc::clone(&alarms),
        immediate(),
        store_path(),
        claim(),
    );

    // `is_some_and`, not `!=`: the row does not exist until the spawned
    // task's first write, and `None != Some(..)` is *true* — so a `!=`
    // predicate is satisfied by the board being empty, before anything has
    // happened at all. That version passed with the post-start report
    // deleted, which is the definition of a test that proves nothing.
    let armed = settle_until(&alarms, |b| {
        b.condition(AlarmCondition::ServeSetIntegrity)
            .map(ConditionState::arming)
            .is_some_and(|a| a != Arming::Disarmed(DisarmedReason::NotServing))
    })
    .await;
    assert!(
        armed,
        "the serve-set row still reads as a stopped transport after the host \
         started; nothing would correct it for a whole refresh cadence",
    );
    handle.shutdown().await;
}

/// **The posture snapshot is the live serving truth, and absent before
/// anything is served.** The empty-set pinner reports the list arm, so a
/// started host publishes `Market`; before start and after shutdown the
/// answer is `None`, which the surfaces render "not serving".
///
/// The `None`-after-shutdown half is the one that earns its keep: a
/// snapshot left at its last value would have `staking_info` report a
/// posture for a host that has stopped — the same false-healthy reading
/// the alarm board refuses on every other condition.
#[tokio::test]
async fn the_posture_snapshot_tracks_the_host_and_clears_on_shutdown() {
    let dir = tempfile::tempdir().expect("tmp");
    let alarms = Arc::new(OperatorAlarms::new());
    let handle = spawn_serving_task(
        churning_tor(&dir),
        serving_identity(),
        pinner(false),
        Arc::clone(&alarms),
        immediate(),
        store_path(),
        claim(),
    );

    // Published once the host has actually pinned — never before, so the
    // standoff window cannot claim a posture it has not established.
    let mut published = None;
    for _ in 0..200 {
        if let Some(p) = handle.posture() {
            published = Some(p);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        published,
        Some(ServingPosture::Market),
        "an empty ShardSetCompact obligation is the market arm — not \
         the corpus, and not absent"
    );

    // `shutdown` consumes the handle, so the receiver is cloned first —
    // otherwise the clearing half of this test's name could only be
    // *asserted in a comment*, which is how a test ends up proving less
    // than it claims. The channel outlives the sender, so a clone still
    // reads the task's final write.
    let after_shutdown = handle.posture.clone();
    handle.shutdown().await;
    assert_eq!(
        *after_shutdown.borrow(),
        None,
        "teardown must clear the posture: a snapshot left at its last \
         value would have `staking_info` report a posture for a host \
         that has stopped"
    );
}

/// **Shutdown does not wait on a wedged refresh.** The refresh is an actor
/// round trip with no timeout; if it sat outside the cancel `select!`, a
/// store actor that stopped answering would hold `ServingHandle::shutdown`
/// open for as long as it stayed wedged — tor still published, the wallet
/// unable to close. The pinner here answers the start pin and then never
/// again, so the first refresh tick is pending inside the actor round trip
/// when shutdown is requested.
#[tokio::test]
async fn shutdown_completes_while_a_refresh_is_wedged_on_the_actor() {
    const CADENCE: Duration = Duration::from_millis(10);
    let dir = tempfile::tempdir().expect("tmp");
    let alarms = Arc::new(OperatorAlarms::new());
    let wedging = WedgingPinner {
        inner: pinner(false),
        answered_start: std::sync::atomic::AtomicBool::new(false),
    };
    let handle = spawn_serving_task(
        churning_tor(&dir),
        serving_identity(),
        wedging,
        Arc::clone(&alarms),
        ServingConfig {
            refresh_cadence: CADENCE,
            ..immediate()
        },
        store_path(),
        claim(),
    );

    // Started: the posture is published only after the start pin answered.
    let mut started = false;
    for _ in 0..200 {
        if handle.posture().is_some() {
            started = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        started,
        "the host never came up; the test cannot reach a refresh"
    );
    // Several cadences on: the refresh tick has fired and is parked in the
    // pinner that will not answer.
    tokio::time::sleep(CADENCE * 5).await;

    let after_shutdown = handle.posture.clone();
    tokio::time::timeout(Duration::from_secs(5), handle.shutdown())
        .await
        .expect("shutdown must not wait on a refresh the store actor will never answer");
    assert_eq!(
        *after_shutdown.borrow(),
        None,
        "teardown ran to the end: the posture is cleared after the host is gone"
    );
}

/// The disk probe reports against a real filesystem and reaches the
/// board: a started host arms `ServingDiskHeadroom` rather than leaving
/// it unobserved. The first reading is immediate — this uses the
/// hour-long `immediate()` cadence so a pass cannot be a refresh tick
/// rescuing a hitchhiked probe. The threshold arithmetic itself is
/// `shekyl-operator-alarm`'s (`disk::tests`); what only this layer can
/// prove is that the reading is taken at all and lands on the board.
#[tokio::test]
async fn a_started_host_observes_disk_headroom() {
    let dir = tempfile::tempdir().expect("tmp");
    let alarms = Arc::new(OperatorAlarms::new());
    let handle = spawn_serving_task(
        churning_tor(&dir),
        serving_identity(),
        pinner(false),
        Arc::clone(&alarms),
        immediate(),
        store_path(),
        claim(),
    );

    let observed = settle_until(&alarms, |b| {
        b.condition(AlarmCondition::ServingDiskHeadroom)
            .map(ConditionState::arming)
            .is_some_and(|a| a == Arming::Armed)
    })
    .await;
    assert!(
        observed,
        "the serving task never reported disk headroom; the condition \
         has no row, which renders as unwatched"
    );
    handle.shutdown().await;
    assert_eq!(
        alarms
            .board()
            .condition(AlarmCondition::ServingDiskHeadroom)
            .map(ConditionState::arming),
        Some(Arming::Disarmed(DisarmedReason::NotServing)),
        "teardown must disarm the volume check: a host that has \
         stopped is not a healthy disk"
    );
}

/// TJ-D's operator surface reaches the board: a started host arms
/// `ServeHealth` clean (nothing answered yet is nothing refused), and
/// teardown disarms it. The window — zero baseline, movement between
/// reads, a quiet tick clearing — is `TickWindow`'s, and its tests in
/// `shekyl-operator-alarm` drive that sequence through the same
/// `observe` → `apply` pair the health probe calls; the probe sampling
/// on its own tick while nothing else progresses is `serving::health`'s
/// test. The listener's loopback port is not exposed by `ServingHandle`
/// (nothing in production reads it), so a counted refusal cannot be
/// driven from this level without adding a test-only accessor; what only
/// this layer can prove is that the probe is spawned against the live
/// host and the row is kept, which is the `SH-2` falsifier in
/// `docs/FOLLOWUPS.md`. The counters moving on a real refusal is
/// `shekyl-p-host/tests/composition.rs`'s.
#[tokio::test]
async fn a_started_host_watches_its_serve_health() {
    let dir = tempfile::tempdir().expect("tmp");
    let alarms = Arc::new(OperatorAlarms::new());
    let handle = spawn_serving_task(
        churning_tor(&dir),
        serving_identity(),
        pinner(false),
        Arc::clone(&alarms),
        immediate(),
        store_path(),
        claim(),
    );

    let armed = settle_until(&alarms, |b| {
        b.condition(AlarmCondition::ServeHealth)
            .map(ConditionState::arming)
            .is_some_and(|a| a == Arming::Armed)
    })
    .await;
    assert!(
        armed,
        "a started host must arm serve health; an absent row renders as \
         a surface that was never wired"
    );
    assert!(
        alarms
            .board()
            .condition(AlarmCondition::ServeHealth)
            .and_then(ConditionState::live)
            .is_none(),
        "a host that has answered nothing has refused nothing"
    );
    handle.shutdown().await;
    assert_eq!(
        alarms
            .board()
            .condition(AlarmCondition::ServeHealth)
            .map(ConditionState::arming),
        Some(Arming::Disarmed(DisarmedReason::NotServing)),
        "teardown must disarm: a stopped host is not a healthy one"
    );
}

/// An unreadable path degrades to *disarmed*, and the serving task keeps
/// running. A broken disk probe must never take down a healthy server —
/// the diagnostic is subordinate to the obligation it reports on.
#[tokio::test]
async fn an_unreadable_disk_path_disarms_without_killing_the_task() {
    let dir = tempfile::tempdir().expect("tmp");
    let alarms = Arc::new(OperatorAlarms::new());
    let handle = spawn_serving_task(
        churning_tor(&dir),
        serving_identity(),
        pinner(false),
        Arc::clone(&alarms),
        immediate(),
        dir.path().join("no-such-directory"),
        claim(),
    );

    let disarmed = settle_until(&alarms, |b| {
        b.condition(AlarmCondition::ServingDiskHeadroom)
            .map(ConditionState::arming)
            .is_some_and(|a| a == Arming::Disarmed(DisarmedReason::DiskUnreadable))
    })
    .await;
    assert!(
        disarmed,
        "an unreadable path must read as unknown headroom, never as \
         healthy and never as an alarm"
    );
    // The serve-set side is still being reported, which is the proof the
    // task survived the failed probe rather than unwinding on it.
    assert!(
        alarms
            .board()
            .condition(AlarmCondition::ServeSetIntegrity)
            .is_some(),
        "the serving task must keep serving through a broken disk probe"
    );
    handle.shutdown().await;
}

/// The channel is reachable. Without this the whole of OA-1 is write-only
/// in production: alarms are raised onto a board nothing can subscribe to.
#[tokio::test]
async fn the_handle_exposes_the_board_it_reports_through() {
    let dir = tempfile::tempdir().expect("tmp");
    let alarms = Arc::new(OperatorAlarms::new());
    let handle = spawn_serving_task(
        churning_tor(&dir),
        serving_identity(),
        pinner(false),
        Arc::clone(&alarms),
        immediate(),
        store_path(),
        claim(),
    );

    // The embedder's only reference is the handle.
    let from_handle = handle.alarms();
    let seen = {
        let board = from_handle.subscribe();
        let b = board.borrow().clone();
        b.conditions().count()
    };
    assert!(
        seen > 0 || settle_until(&from_handle, |b| b.conditions().count() > 0).await,
        "the handle's board must be the one the task writes to",
    );
    handle.shutdown().await;
}

/// A start failure is reported *and* the handle still comes back, so the
/// embedder can render why rather than seeing a wallet that silently is
/// not serving.
#[tokio::test]
async fn a_failed_start_lands_on_the_board_reachable_from_the_handle() {
    let dir = tempfile::tempdir().expect("tmp");
    let alarms = Arc::new(OperatorAlarms::new());
    let handle = spawn_serving_task(
        churning_tor(&dir),
        serving_identity(),
        pinner(true),
        Arc::clone(&alarms),
        immediate(),
        store_path(),
        claim(),
    );

    let reported = settle_until(&handle.alarms(), |b| {
        b.condition(AlarmCondition::ServeSetIntegrity)
            .and_then(ConditionState::live)
            .is_some()
    })
    .await;
    assert!(reported, "a pinner that is down must reach the operator");
    assert_eq!(
        handle
            .alarms()
            .board()
            .condition(AlarmCondition::ServingDiskHeadroom)
            .map(ConditionState::arming),
        Some(Arming::Disarmed(DisarmedReason::NotServing)),
        "a host that never started still watches the volume row — \
         unwatched would look like the probe was never wired"
    );
    handle.shutdown().await;
}
