// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The persona body-store fill against a live daemon (`WSS-Q4`, `WSS-Q15`
//! to `WSS-Q18`; `docs/design/WALLET_SIDE_STORE.md` §6.5).
//!
//! A `#[path]` child of the regtest harness. Real daemon data only: every
//! shard here is closed by real wallet spends mined at difficulty 1, filled
//! from the daemon's own full-form read, and checked against the rows the
//! persona scan sealed. The one seam is the Q16 test's, and it is named
//! there: a real daemon whose reply is altered in transit.
//!
//! The draw on a filled shard is answered by the production endpoint over
//! the production provider reading the persona body store
//! (`StoreShardProvider`), countersigned by the persona's resident receipt
//! key and verified by the daemon's real fetch client against rows derived
//! from the chain here. The onion leg is the emission walk's; this suite
//! dials the endpoint over loopback.

#![cfg(test)]

use super::*;

use shekyl_archival_retention::{HoldingsDescriptor, HoldingsKind, ShardSet};
use shekyl_engine_state::pscan_state::PScanState;
use shekyl_p_loopback::{
    client_through, fetch_target, DiscardTxs, ExpectedShard, FetchError, PServeEndpoint,
    RequestHeader, Timeouts,
};
use shekyl_types::{shard_of, ArchivalLength};
use shekyl_wire::shard_frame::frame_rows_digest;
use shekyl_wire::{carries_archival_good, TxidParts};

use super::super::body_reconcile::{
    ReconcileState, ShardAlarm, ShardAlarmCause, ShardAlarms, ShardRefill,
};
use super::super::holdings_fill::{CompleteTreeFillError, FillFailure, MarketFillError};
use super::super::stake_engine::body_store_actor::StoredFrame;
use super::super::stake_engine::serving::receipt_key::ResidentReceiptKey;
use super::super::stake_engine::PSlot;
use super::shard::{close_shard, fill_closed_shard, price_closed_shard};

type Shared = Arc<RwLock<super::super::Engine<super::super::SoloSigner>>>;

const SLOT: u32 = 0;
/// One epoch holds both closes and the stake: shard 0 closes near block 405
/// and shard 1, after the supply its spends are mined from, near 1330. Both
/// land in epoch 0 and are final there, so each enters a support draw's
/// `final_count` at the open of epoch 1, its freeze epoch, and the node
/// discards their bodies at block `2 · SEB` (`WALLET_SIDE_STORE.md` §6.5.1,
/// §6.5.9). The walk asserts the closes land there.
const SEB: u64 = 1_500;
/// The shards' finality wait, and the P-scan's own test horizon.
const REORG_CAP: u64 = PSCAN_TEST_REORG_DEPTH;
const SCHEDULE: RegtestSchedule = RegtestSchedule {
    seb: SEB,
    reorg_cap: REORG_CAP,
};
/// Persona funding above `floor + bond fee`.
const FUNDING_CUSHION: u64 = 12_000_000_000;
/// A P-scan over some fifteen hundred blocks in a debug build, with room:
/// it bounds a hang, it does not time the scan.
const LONG_SCAN: Duration = Duration::from_secs(3600);

fn shard(n: u64) -> ShardId {
    ShardId::from_raw(n)
}

/// Spawn the daemon on `SCHEDULE` and arm this process's schedule latch to
/// it before any wallet-side epoch arithmetic (the walk's arming shape, and
/// its containment caveat: run this test alone in its process).
async fn armed_daemon(seed: &[u8; shekyl_crypto_pq::account::SEED_BYTES]) -> RegtestDaemon {
    let daemon = RegtestDaemon::start_for_seed_with_schedule(seed, Some(SCHEDULE)).await;
    SCHEDULE.set_in_process_env();
    let armed = shekyl_archival_retention::arm_settlement_epoch_override_for_regtest()
        .expect("the schedule levers must arm before any epoch arithmetic latches the schedule");
    assert_eq!(armed, SEB, "armed schedule must be the lever value");
    daemon
}

/// What `shard` holds, from the chain: every listed transaction from
/// genesis through `close_height` placed by the archival partition as the
/// rule is written (`SHT-Q1`, `SHT-Q2`) — the shard of the total before it,
/// for a transaction that carries archival good. Written out here, apart
/// from the fill's walk, so the draw below is checked against a second
/// reading of the chain.
async fn expected_shard(arc: &Shared, target: ShardId, close_height: u64) -> ExpectedShard {
    let client = arc.read().await.daemon().clone();
    let mut cum = ArchivalLength::ZERO;
    let mut first_before = None;
    let mut rows: Vec<TxidParts> = Vec::new();
    for number in 0..=close_height {
        let block = client
            .fetch_scannable_block(usize::try_from(number).expect("fits"))
            .await
            .expect("the chain's block");
        cum = cum
            .checked_add(block.block.miner_transaction.txid_parts().archival_len)
            .expect("fits");
        for tx in &block.transactions {
            let parts = tx.parts();
            if shard_of(cum) == target
                && carries_archival_good(parts.pqc_auth_hash, parts.prunable_hash)
            {
                first_before.get_or_insert(cum);
                rows.push(parts);
            }
            cum = cum.checked_add(parts.archival_len).expect("fits");
        }
    }
    ExpectedShard::new(target, first_before.expect("the shard has members"), rows)
        .expect("the chain's own rows")
}

/// The sealed P-scan state, as the fill reads it.
async fn sealed_state(arc: &Shared) -> PScanState {
    super::super::pscan::start::load_pscan_state_for_engine(arc.clone())
        .await
        .expect("load the sealed P-scan state")
        .expect("the staker has scanned")
}

/// Whether the persona body store holds `target` whole, with the rows the
/// persona scan sealed for it.
async fn holds_verified(arc: &Shared, target: ShardId) -> bool {
    let sealed = sealed_state(arc)
        .await
        .cursor()
        .archival()
        .close(target)
        .map(|close| close.rows);
    let stake = arc.read().await.stake_handle().expect("a staker");
    match stake.bodies.read_frame(target).await.expect("read") {
        StoredFrame::Frame(frame) => {
            frame_rows_digest(target, &frame).is_ok_and(|digest| Some(digest.rows) == sealed)
        }
        StoredFrame::NotHeld | StoredFrame::Unreadable => false,
    }
}

async fn holds(arc: &Shared, target: ShardId) -> bool {
    let stake = arc.read().await.stake_handle().expect("a staker");
    stake.bodies.holds(target).await.expect("held check")
}

/// Run the P-scan until its frontier reaches the finality horizon at the
/// daemon's tip, so what is final is known. The horizon is the scan's own
/// exclusive end, the block count less the cap (`pscan/task.rs`), which is
/// also the bound the fill checks the scan against.
async fn scan_to_the_horizon(daemon: &RegtestDaemon, arc: &Shared, pscan_seal: &std::path::Path) {
    let needed = daemon.height().await.saturating_sub(REORG_CAP);
    refresh(arc).await;
    pscan_until_within(
        arc,
        pscan_seal,
        "the finality horizon",
        |s| s.synced_height().to_raw() >= needed,
        LONG_SCAN,
    )
    .await;
}

/// One reconcile pass, as the body-store leg runs it.
async fn reconcile(
    daemon: &RegtestDaemon,
    arc: &Shared,
    state: &mut ReconcileState,
    alarms: &ShardAlarms,
) {
    let epoch = shekyl_archival_retention::settlement_epoch_at_height(daemon.height().await);
    super::super::Engine::reconcile_bodies(arc.clone(), &daemon.target(), epoch, state, alarms)
        .await
        .unwrap_or_else(|e| daemon.panic_with_log("reconcile the persona body store", e));
}

fn proving_timeouts() -> Timeouts {
    Timeouts {
        dial: Duration::from_secs(2),
        head: Duration::from_secs(10),
        body_stall: Duration::from_secs(20),
        body_total: Duration::from_secs(120),
    }
}

/// A draw on `target`, answered by the production endpoint over the
/// production provider reading this persona's body store and countersigned
/// by its resident receipt key; the daemon's fetch client verifies the
/// body against the chain's rows and the receipt against the persona's
/// receipt key. Then a draw on a shard the store does not hold, which is
/// the 404 and moves the not-held count.
///
/// Each request anchors where a requester does: [`PASS_ANCHOR_DEPTH_BLOCKS`]
/// below the tip, on that block's hash, with a fresh nonce. The depth is
/// the genesis reorg cap, not the regtest lever, and P's pre-sign gate
/// refuses every anchor (400) while its own height is below it, so the
/// chain is first mined past the depth.
///
/// [`PASS_ANCHOR_DEPTH_BLOCKS`]: shekyl_archival_retention::PASS_ANCHOR_DEPTH_BLOCKS
async fn draw_and_check(
    daemon: &RegtestDaemon,
    arc: &Shared,
    seed: &[u8; shekyl_crypto_pq::account::SEED_BYTES],
    target: ShardId,
    close_height: u64,
    unheld: ShardId,
) {
    use shekyl_crypto_pq::account::{normalize_seed, Network};
    use shekyl_crypto_pq::archival_p::derive_archival_p_keys;

    let expected = expected_shard(arc, target, close_height).await;
    let stake = arc.read().await.stake_handle().expect("a staker");
    let key: Arc<dyn shekyl_p_host::PassKey> =
        ResidentReceiptKey::new(&stake, PSlot::from_raw(SLOT));
    let depth = shekyl_archival_retention::PASS_ANCHOR_DEPTH_BLOCKS;
    let count = daemon.height().await;
    if count <= depth.to_raw() {
        daemon.generate_blocks(depth.to_raw() + 1 - count).await;
    }
    let top = shekyl_types::BlockHeight::from_raw(daemon.height().await - 1);
    let signer = shekyl_p_host::signer_at_synced_tip(key, top, Duration::from_secs(600));
    let provider = Arc::new(shekyl_p_serve::StoreShardProvider::new(Arc::new(
        stake.bodies.reads(),
    )));
    let endpoint = PServeEndpoint::bind(provider, signer)
        .await
        .expect("bind the serving endpoint");
    let client = client_through(endpoint.addr(), proving_timeouts()).await;
    let receipt_key = derive_archival_p_keys(&normalize_seed(seed), Network::Regtest, SLOT)
        .expect("derive persona keys")
        .receipt_sign_pk;
    let anchor = top
        .checked_sub_count(depth)
        .expect("the chain was mined past the anchor depth");
    let anchor_hash = arc
        .read()
        .await
        .daemon()
        .clone()
        .fetch_scannable_block(usize::try_from(anchor.to_raw()).expect("fits"))
        .await
        .expect("the anchor block")
        .block
        .hash();
    let header = || RequestHeader::fresh(anchor, anchor_hash).expect("entropy for the nonce");
    let served = client
        .fetch(
            &fetch_target(receipt_key.clone()),
            &header(),
            &expected,
            Arc::new(DiscardTxs),
        )
        .await
        .unwrap_or_else(|e| panic!("a draw on held shard {target:?} must answer 200: {e}"));
    assert_eq!(served.shard_id(), target);
    assert_eq!(endpoint.served_count(), 1);
    assert_eq!(endpoint.not_held_count(), 0);

    let refused = client
        .fetch(
            &fetch_target(receipt_key),
            &header(),
            &shekyl_p_loopback::fixture_expectation(unheld.to_raw()),
            Arc::new(DiscardTxs),
        )
        .await
        .expect_err("a shard the store does not hold is not served");
    assert!(matches!(refused, FetchError::Miss), "{refused}");
    assert_eq!(
        endpoint.not_held_count(),
        1,
        "the 404 moves the not-held count (WSS-Q17's backstop)"
    );
}

/// A `CompleteTree` bond, end to end on one chain (`WSS-Q15`, `WSS-Q17`):
///
/// 1. Shard 0 closes and is final. The bond's own fill (`first_stake`) puts
///    it in the body store before the post, and the post confirms.
/// 2. A draw on shard 0 answers 200 with a body that verifies against the
///    chain; a draw on a shard not held is the 404, and the count moves.
/// 3. Shard 1 closes after the bond and is final in its close epoch. The
///    next reconcile pass pulls it there, quietly, before its freeze epoch
///    opens: an already-joined tree is drawn on it from that open (§6.5.9).
///    A draw on it once the epoch has opened answers 200.
/// 4. A body that does not verify (shard 1's frame written as shard 0's)
///    raises `corrupt` and is refilled.
/// 5. The store file deleted and the wallet reopened: every owed shard
///    raises `missing` and is refilled inside the window.
/// 6. Past the boundary that discards the shards' bodies, a fill that fails
///    partway posts nothing, returns `Discarded`, and leaves no partial
///    shard; the refusal names the node's recovery fetch, the only way the
///    bodies come back (§6.5.4). The reconcile's alarm says the same.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow lane (run_live_daemon_gates.sh ARMED_SLOW): requires SHEKYLD_BIN; closes two shards with some four hundred real spends, stakes, and walks past the discard boundary"]
async fn e2e_complete_tree_bond_fills_serves_pulls_and_reconciles() {
    let seed = [0x5Au8; shekyl_crypto_pq::account::SEED_BYTES];
    let daemon = armed_daemon(&seed).await;
    let wallet = staker_wallet(daemon.rpc_port, &seed, PSlot::from_raw(SLOT)).await;
    let base = wallet.1.path().join("wallet");
    let pscan_seal = shekyl_engine_file::paths::pscan_state_path_from(&base);

    // (1) Shard 0: closed, final and scanned — and not filled here. The
    // bond's own fill must do it.
    let zero = close_shard(
        &daemon,
        &wallet.0,
        &wallet.2,
        &pscan_seal,
        shard(0),
        SCHEDULE,
    )
    .await;
    let fixture = stake_persona_to_confirmed_bond(
        &daemon,
        &seed,
        SLOT,
        FUNDING_CUSHION,
        FixtureStake::FirstStake,
        Some(wallet),
    )
    .await;
    let arc = fixture.arc.clone();
    assert!(
        holds_verified(&arc, shard(0)).await,
        "the CompleteTree bond's fill put shard 0 in the body store, whole"
    );

    // (2) A draw on it, and a 404.
    draw_and_check(&daemon, &arc, &seed, shard(0), zero.close_height, shard(7)).await;

    // (3) The next shard, pulled after finality and before its freeze epoch
    // opens.
    let alarms = ShardAlarms::default();
    let mut state = ReconcileState::default();
    reconcile(&daemon, &arc, &mut state, &alarms).await;
    assert_eq!(
        alarms.list(),
        [],
        "everything owed is held at the first pass"
    );
    let one = close_shard(
        &daemon,
        &arc,
        &fixture.principal,
        &pscan_seal,
        shard(1),
        SCHEDULE,
    )
    .await;
    assert!(
        zero.close_height < SEB && one.close_height < SEB,
        "both shards close in epoch 0 (at {} and {}), so epoch 1 is both freeze epochs: \
         SEB must exceed the closes",
        zero.close_height,
        one.close_height
    );
    assert!(
        !holds(&arc, shard(1)).await,
        "nothing has filled shard 1 yet"
    );
    reconcile(&daemon, &arc, &mut state, &alarms).await;
    assert!(
        holds_verified(&arc, shard(1)).await,
        "the pass pulled the newly final shard"
    );
    assert_eq!(alarms.list(), [], "a routine pull is not an alarm");
    let tip = daemon.height().await - 1;
    assert!(
        tip < SEB,
        "the pull ran in shard 1's close epoch, before the freeze epoch's open at {SEB} \
         where a support draw first counts it (tip {tip})"
    );
    // Into the freeze epoch: the draw that open makes possible is answered.
    let count = daemon.height().await;
    if count <= SEB {
        daemon.generate_blocks(SEB + 1 - count).await;
    }
    draw_and_check(&daemon, &arc, &seed, shard(1), one.close_height, shard(7)).await;

    // (4) A body that does not verify.
    let stake = arc.read().await.stake_handle().expect("a staker");
    let StoredFrame::Frame(frame_one) = stake.bodies.read_frame(shard(1)).await.expect("read")
    else {
        panic!("shard 1 is held");
    };
    stake
        .bodies
        .put(shard(0), frame_one)
        .await
        .expect("write the wrong body");
    assert!(!holds_verified(&arc, shard(0)).await);
    let alarms = ShardAlarms::default();
    reconcile(&daemon, &arc, &mut ReconcileState::default(), &alarms).await;
    assert_eq!(
        alarms.list(),
        [ShardAlarm {
            shard: 0,
            alarm: ShardAlarmCause::Corrupt,
            refill: ShardRefill::Refilled,
        }]
    );
    assert!(
        holds_verified(&arc, shard(0)).await,
        "refilled from the node"
    );

    // (5) The store file deleted, the wallet reopened.
    drop(stake);
    let ConfirmedBondFixture {
        arc: held,
        _tmp,
        principal,
        ..
    } = fixture;
    drop(arc);
    let creds = super::super::lifecycle::Credentials::password_only(b"pr4-staker");
    Arc::try_unwrap(held)
        .unwrap_or_else(|_| panic!("the engine still has co-owners at close"))
        .into_inner()
        .close(&creds)
        .await
        .expect("close the staker");
    std::fs::remove_file(shekyl_engine_file::paths::p_store_path_from(&base))
        .expect("delete the persona body store");
    let rpc = HttpRpc::new(format!("http://127.0.0.1:{}", daemon.rpc_port))
        .await
        .expect("wallet rpc (reopen)");
    let arc: Shared = Arc::new(RwLock::new(
        super::super::Engine::<super::super::SoloSigner>::open_full(
            &base,
            &creds,
            shekyl_address::Network::Regtest,
            super::super::DaemonClient::verifying(rpc, regtest_expectation()),
            shekyl_engine_file::SafetyOverrides::none(),
        )
        .expect("reopen the staker")
        .into_wallet(),
    ));
    let alarms = ShardAlarms::default();
    reconcile(&daemon, &arc, &mut ReconcileState::default(), &alarms).await;
    let missing_refilled = |n| ShardAlarm {
        shard: n,
        alarm: ShardAlarmCause::Missing,
        refill: ShardRefill::Refilled,
    };
    assert_eq!(alarms.list(), [missing_refilled(0), missing_refilled(1)]);
    assert!(holds_verified(&arc, shard(0)).await && holds_verified(&arc, shard(1)).await);

    // (6) Past the boundary: the node has discarded both shards' bodies.
    let boundary = 2 * SEB;
    let count = daemon.height().await;
    if count <= boundary {
        daemon.generate_blocks(boundary + 1 - count).await;
    }
    scan_to_the_horizon(&daemon, &arc, &pscan_seal).await;
    let stake = arc.read().await.stake_handle().expect("a staker");
    stake.bodies.erase(vec![1]).await.expect("erase shard 1");
    let complete_tree = HoldingsDescriptor {
        kind: HoldingsKind::CompleteTree,
        shard_ids: ShardSet::empty(),
    };
    let err =
        super::super::Engine::fill_complete_tree(arc.clone(), &daemon.target(), complete_tree)
            .await
            .expect_err("a discarded shard cannot be filled");
    assert!(
        matches!(
            err,
            CompleteTreeFillError::Fill(FillFailure::Discarded { shard: s }) if s == shard(1)
        ),
        "{err}"
    );
    assert!(
        err.to_string().contains("recovery fetch"),
        "the refusal names the node's recovery fetch: {err}"
    );
    assert!(!holds(&arc, shard(1)).await, "no partial shard was written");
    assert!(
        holds_verified(&arc, shard(0)).await,
        "the held shard is untouched"
    );
    stake.bodies.erase(vec![0]).await.expect("erase shard 0");
    let alarms = ShardAlarms::default();
    reconcile(&daemon, &arc, &mut ReconcileState::default(), &alarms).await;
    let missing_discarded = |n| ShardAlarm {
        shard: n,
        alarm: ShardAlarmCause::Missing,
        refill: ShardRefill::Discarded,
    };
    assert_eq!(alarms.list(), [missing_discarded(0), missing_discarded(1)]);
    eprintln!(
        "complete-tree body fill: shards 0 and 1 (closed at {} and {}) filled, served, pulled, \
         repaired and refused past the boundary; principal {principal}",
        zero.close_height, one.close_height
    );
    drop(stake);
    drop(_tmp);
}

/// A market bond (`WSS-Q4`): a shard set naming a shard that is not final is
/// refused before anything is filled or posted; the final shard, filled
/// while the node holds it, posts at its first admissible join (§6.5.2) and
/// is served.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow lane (run_live_daemon_gates.sh ARMED_SLOW): requires SHEKYLD_BIN; closes a shard with some two hundred real spends and stakes a market bond onto it"]
async fn e2e_market_bond_refuses_a_shard_that_is_not_final_then_fills_posts_and_serves() {
    let seed = [0x5Bu8; shekyl_crypto_pq::account::SEED_BYTES];
    let daemon = armed_daemon(&seed).await;
    let wallet = staker_wallet(daemon.rpc_port, &seed, PSlot::from_raw(SLOT)).await;
    let pscan_seal =
        shekyl_engine_file::paths::pscan_state_path_from(&wallet.1.path().join("wallet"));
    let zero = close_shard(
        &daemon,
        &wallet.0,
        &wallet.2,
        &pscan_seal,
        shard(0),
        SCHEDULE,
    )
    .await;

    // Shard 1 is open. With the scan at the horizon, that is "not final",
    // not "not scanned yet".
    scan_to_the_horizon(&daemon, &wallet.0, &pscan_seal).await;
    let both = HoldingsDescriptor {
        kind: HoldingsKind::ShardSetCompact,
        shard_ids: ShardSet::new(vec![0, 1]).expect("two shards"),
    };
    let err = super::super::Engine::fill_market(wallet.0.clone(), &daemon.target(), both)
        .await
        .expect_err("an open shard is refused");
    assert!(
        matches!(err, MarketFillError::NotFinal { shard: s } if s == shard(1)),
        "{err}"
    );
    assert!(
        !holds(&wallet.0, shard(0)).await,
        "the refusal comes before any fill"
    );

    // The final shard, filled while the node holds it, then priced and
    // posted. Shard 0 closed in epoch 0, so its first pricing pass is the
    // last block of epoch 1 and its first admissible join is the discard
    // block, `2 · SEB` (§6.5.2): the fill has to finish before the post can
    // connect.
    fill_closed_shard(&daemon, &wallet.0, &zero).await;
    let filled_at = daemon.height().await - 1;
    assert!(
        filled_at < 2 * SEB,
        "filled before the discard block (tip {filled_at})"
    );
    let priced = price_closed_shard(&daemon, &zero, SCHEDULE).await;
    eprintln!(
        "shard 0 priced by epoch {} at {}",
        priced.priced_by_epoch, priced.pass_height
    );
    assert_eq!(
        (priced.priced_by_epoch, priced.pass_height + 1),
        (0, 2 * SEB),
        "an epoch-0 shard is priced by pass 0 and joins at the discard block"
    );
    let market = HoldingsDescriptor {
        kind: HoldingsKind::ShardSetCompact,
        shard_ids: ShardSet::new(vec![0]).expect("one shard"),
    };
    let fixture = stake_persona_to_confirmed_bond(
        &daemon,
        &seed,
        SLOT,
        FUNDING_CUSHION,
        FixtureStake::MarketBond(market),
        Some(wallet),
    )
    .await;
    assert!(holds_verified(&fixture.arc, shard(0)).await);
    draw_and_check(
        &daemon,
        &fixture.arc,
        &seed,
        shard(0),
        zero.close_height,
        shard(5),
    )
    .await;
}

/// The one seam (`WSS-Q16`), named: a real daemon whose block reply is
/// altered in transit. The archival step catches a reported running total
/// its block's own bound lengths do not add up to, at the block it was
/// altered at.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live lane: requires SHEKYLD_BIN"]
async fn e2e_a_running_total_altered_in_transit_fails_the_archival_step() {
    use super::super::block_fetch::default_fetch_scannable_block;
    use super::super::pscan::exhaustiveness::{verify_exhaustive, ExhaustivenessError};
    use shekyl_engine_state::pscan_cursor::ArchivalFold;

    const BLOCKS: u64 = 12;
    const ALTERED: u64 = 7;

    let seed = [0x5Cu8; shekyl_crypto_pq::account::SEED_BYTES];
    let daemon = RegtestDaemon::start_for_seed(&seed).await;
    daemon.generate_blocks(BLOCKS).await;
    let honest = HttpRpc::new(format!("http://127.0.0.1:{}", daemon.rpc_port))
        .await
        .expect("daemon rpc");
    let altered = AlterTotal {
        inner: honest.clone(),
        at: ALTERED,
    };

    async fn blocks<R: shekyl_rpc_client::Rpc>(rpc: &R) -> Vec<shekyl_scanner::ScannableBlock> {
        let mut out = Vec::new();
        for number in 0..BLOCKS {
            out.push(
                default_fetch_scannable_block(rpc, usize::try_from(number).expect("fits"))
                    .await
                    .expect("block"),
            );
        }
        out
    }

    let verified = verify_exhaustive(
        shekyl_types::BlockHeight::ZERO,
        shekyl_types::BlockHash::NULL,
        &ArchivalFold::genesis(),
        &blocks(&honest).await,
    )
    .expect("the daemon's own replies add up");
    assert_eq!(verified.fold().total(), ArchivalLength::ZERO);

    let err = verify_exhaustive(
        shekyl_types::BlockHeight::ZERO,
        shekyl_types::BlockHash::NULL,
        &ArchivalFold::genesis(),
        &blocks(&altered).await,
    )
    .expect_err("a total the bodies do not add up to is caught");
    assert_eq!(
        err,
        ExhaustivenessError::ArchivalStepMismatch {
            height: ALTERED,
            reported: ArchivalLength::from_raw(1),
            checked: ArchivalLength::ZERO,
        }
    );
}

/// The Q16 seam: forwards every call to the daemon and adds one byte to the
/// running archival total of the one block it names in a `block_show`
/// reply. Nothing else in the reply changes, so the block, its hash and its
/// bodies are the daemon's own.
#[derive(Clone)]
struct AlterTotal {
    inner: HttpRpc,
    at: u64,
}

impl shekyl_rpc_client::Rpc for AlterTotal {
    fn post(
        &self,
        route: &str,
        body: Vec<u8>,
    ) -> impl Send + std::future::Future<Output = Result<Vec<u8>, shekyl_rpc_client::RpcError>>
    {
        let inner = self.inner.clone();
        let route = route.to_owned();
        let at = self.at;
        async move {
            let asked: serde_json::Value =
                serde_json::from_slice(&body).expect("a JSON-RPC request");
            let reply = inner.post(&route, body).await?;
            if asked["method"] != "block_show" {
                return Ok(reply);
            }
            let mut answer: serde_json::Value =
                serde_json::from_slice(&reply).expect("a JSON-RPC reply");
            let result = &mut answer["result"];
            if result["header"]["height"].as_u64() == Some(at) {
                let total = result["archival_cumulative"]
                    .as_u64()
                    .expect("a main-chain block carries its total");
                result["archival_cumulative"] = serde_json::json!(total + 1);
            }
            Ok(serde_json::to_vec(&answer).expect("re-encode"))
        }
    }
}
