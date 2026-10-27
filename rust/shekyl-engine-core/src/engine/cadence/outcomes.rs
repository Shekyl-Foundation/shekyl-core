// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pending-outcomes leg: re-derives the pending-funds integrity alarm
//! on every fire from durable state: the `spent_elsewhere` outcomes, and the
//! stakes the end-date release holds because every reserved input is spent
//! with no confirmation seen (`WALLET_RPC_STAKING_OUTCOMES.md` WR-Q3).
//!
//! The outcome is written by the dispatch driver when a record reaches its
//! end date with part of its reservation spent by another transaction; a
//! stake with all of it spent is held instead, in the pending seal. Both are
//! the system of record; the board's alarm is `LatchedRederived`, so this leg
//! re-raises it after every restart until the outcome is acknowledged and no
//! held stake remains.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};

use shekyl_engine_file::WalletFile;
use shekyl_engine_state::pending_post_block::OutcomeKind;
use shekyl_engine_state::PendingPostBlock;
use shekyl_operator_alarm::{AlarmCondition, OperatorAlarms};

use crate::engine::signer::EngineSignerKind;
use crate::engine::staking_outcomes::held_spent_stakes;
use crate::engine::traits::{
    DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, RefreshEngine,
};
use crate::engine::Engine;

use super::{CadenceLeg, WeakEngine};

/// How many records in `block` carry a `spent_elsewhere` outcome.
pub(super) fn spent_elsewhere_count(block: &PendingPostBlock) -> u64 {
    let n = block
        .outcomes()
        .iter()
        .filter(|o| o.outcome == OutcomeKind::SpentElsewhere)
        .count();
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// One read of the two sealed staking files per chain advance, mapped onto the
/// board by `shekyl_operator_alarm::cadence::apply_pending_outcomes`.
///
/// A wallet with no pending seal (a non-staker) reports nothing: its board has
/// no row for this condition, which reads as "not watched" rather than "not
/// checking", the same as the claim leg's. A seal that will not open is
/// logged and reports nothing this fire; it is not read as "no outcomes".
pub(super) struct PendingOutcomeLeg<S, D, L, E, R, P>
where
    S: EngineSignerKind,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
{
    pub(super) engine: WeakEngine<S, D, L, E, R, P, WalletFile>,
    pub(super) alarms: Arc<OperatorAlarms>,
    /// The counts last logged this start, so the error is written once per
    /// start and again only when they change (WR-Q3, WR-Q5).
    pub(super) logged: Arc<std::sync::Mutex<IntegrityCounts>>,
}

/// One reading of the durable integrity faults: `spent_elsewhere` outcomes
/// and held stakes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct IntegrityCounts {
    pub(super) spent_elsewhere: u64,
    pub(super) held_stakes: u64,
}

/// Whether this reading should be logged: it differs from the last logged
/// one and shows a fault. Records the reading either way, so a fault that
/// clears and returns is logged again.
pub(super) fn should_log(last: &mut IntegrityCounts, now: IntegrityCounts) -> bool {
    let changed = *last != now;
    *last = now;
    changed && now != IntegrityCounts::default()
}

/// The error a person reads in the wallet log (WR-Q3). It names no persona,
/// slot or record (WR-Q5): the counts and the remedy only.
fn log_integrity(now: IntegrityCounts) {
    tracing::error!(
        spent_elsewhere = now.spent_elsewhere,
        held_stakes = now.held_stakes,
        "staking funds this wallet set aside were spent by another transaction. \
         Nothing outside this wallet can spend them, so this is a wallet defect or a \
         compromised key. staking_info shows each case: a spent_elsewhere outcome, \
         or a stake held because every input it set aside is spent. Operator \
         action: check this wallet's logs and keys"
    );
}

impl<S, D, L, E, R, P> CadenceLeg for PendingOutcomeLeg<S, D, L, E, R, P>
where
    S: EngineSignerKind,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
    Engine<S, D, L, E, R, P, WalletFile>: Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        "pending-outcomes"
    }

    fn park_condition(&self) -> Option<AlarmCondition> {
        Some(AlarmCondition::PendingFundsIntegrity)
    }

    fn fire(&mut self, _tip: u64) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let weak = Weak::clone(&self.engine);
        let alarms = Arc::clone(&self.alarms);
        let logged = Arc::clone(&self.logged);
        Box::pin(async move {
            let Some(engine) = weak.upgrade() else {
                return;
            };
            // The daemon tip the cadence loop passed is not this clock.
            // staking_info judges the end date on the wallet ledger, and
            // the alarm has to name the same stakes that read reports held.
            let guard = engine.read().await;
            let ledger_tip = guard.ledger.synced_height();
            let read = guard.sealed_staking_records();
            match read {
                Ok((pscan, Some(block))) => {
                    let now = IntegrityCounts {
                        spent_elsewhere: spent_elsewhere_count(&block),
                        held_stakes: u64::try_from(
                            held_spent_stakes(&block, pscan.as_ref(), ledger_tip).len(),
                        )
                        .unwrap_or(u64::MAX),
                    };
                    shekyl_operator_alarm::cadence::apply_pending_outcomes(
                        &alarms,
                        now.spent_elsewhere,
                        now.held_stakes,
                    );
                    let log = should_log(
                        &mut logged
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner),
                        now,
                    );
                    if log {
                        log_integrity(now);
                    }
                }
                Ok((_, None)) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "pending-outcomes leg: the pending seal did not open");
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use shekyl_operator_alarm::OperatorAlarm;
    use tokio::sync::RwLock;

    use super::*;

    /// The leg's error is written once per start and again only when the
    /// counts change, and a fault that clears and returns is written again; a
    /// quiet reading writes nothing.
    #[test]
    fn the_integrity_error_is_written_once_per_start_and_on_change() {
        let fault = |spent_elsewhere, held_stakes| IntegrityCounts {
            spent_elsewhere,
            held_stakes,
        };
        let mut last = IntegrityCounts::default();
        assert!(!should_log(&mut last, fault(0, 0)), "quiet writes nothing");
        assert!(
            should_log(&mut last, fault(1, 0)),
            "the first reading of a fault"
        );
        assert!(
            !should_log(&mut last, fault(1, 0)),
            "not again on the next tick"
        );
        assert!(should_log(&mut last, fault(1, 1)), "a change is written");
        assert!(
            !should_log(&mut last, fault(0, 0)),
            "clearing writes nothing"
        );
        assert!(
            should_log(&mut last, fault(1, 1)),
            "a returning fault is written"
        );
    }

    /// The pending-outcomes leg (WR-Q3): a sealed `spent_elsewhere` outcome
    /// raises the pending-funds integrity alarm, a fresh board after a restart
    /// re-derives it from the same seal, and once the outcome is acknowledged a
    /// fresh board reads armed and quiet.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_pending_outcomes_leg_re_derives_the_integrity_alarm_from_the_seal() {
        use shekyl_engine_state::pending_post_block::{
            PendingDrain, PendingPostState, RecordKind, SealAdmission,
        };
        use shekyl_types::{BlockCount, BlockHeight, ChainCount, GlobalOutputIndex, PCanonicalId};

        fn live(alarms: &OperatorAlarms) -> Option<OperatorAlarm> {
            alarms
                .board()
                .condition(AlarmCondition::PendingFundsIntegrity)
                .and_then(shekyl_operator_alarm::ConditionState::live)
                .map(shekyl_operator_alarm::RaisedAlarm::alarm)
        }

        let (_tmp, engine) = crate::engine::test_support::staker_engine(3, 11);
        let arc = Arc::new(RwLock::new(engine));
        let leg_on = |alarms: &Arc<OperatorAlarms>| PendingOutcomeLeg {
            engine: Arc::downgrade(&arc),
            alarms: Arc::clone(alarms),
            logged: Arc::default(),
        };

        let before = Arc::new(OperatorAlarms::new());
        leg_on(&before).fire(1).await;
        assert_eq!(live(&before), None, "nothing to report before any outcome");

        // A drain reserving two inputs reaches its end date (reference 94 + 100)
        // with one of them spent by something else.
        let who = PCanonicalId::from_bytes([0x09; 32]);
        let gate = arc.read().await.pending_gate.clone();
        let store =
            crate::engine::pscan::start::pending_post_store_for_engine(Arc::clone(&arc), gate);
        let released = store
            .mutate(move |block| {
                let g = block.generation();
                let drain = PendingDrain {
                    persona: who,
                    tx_bytes: vec![0x09],
                    funding_gindexes: vec![
                        GlobalOutputIndex::from_raw(1),
                        GlobalOutputIndex::from_raw(2),
                    ],
                    state: PendingPostState::Pending,
                    reference_height: BlockHeight::from_raw(94),
                    terminal: None,
                };
                assert_eq!(
                    block.seal_drain(drain, ChainCount::from_raw(100), g),
                    SealAdmission::Admit
                );
                let out = block.release_ended(
                    BlockHeight::from_raw(194),
                    &[GlobalOutputIndex::from_raw(2)].into(),
                    BlockCount::from_raw(100),
                    BlockHeight::from_raw(194),
                );
                (true, out.released.len())
            })
            .await
            .expect("seal the outcome");
        assert_eq!(released, 1);

        let board = Arc::new(OperatorAlarms::new());
        leg_on(&board).fire(2).await;
        assert_eq!(
            live(&board),
            Some(OperatorAlarm::ReservationSpentElsewhere {
                records: 1,
                held_stakes: 0
            })
        );

        let restarted = Arc::new(OperatorAlarms::new());
        leg_on(&restarted).fire(3).await;
        assert_eq!(
            live(&restarted),
            Some(OperatorAlarm::ReservationSpentElsewhere {
                records: 1,
                held_stakes: 0
            }),
            "a fresh board re-derives the alarm from the durable outcome"
        );

        // A new drain sealed for the same persona does not clear it: a
        // `spent_elsewhere` outcome clears only on acknowledgement.
        store
            .mutate(move |block| {
                let g = block.generation();
                let next = PendingDrain {
                    persona: who,
                    tx_bytes: vec![0x0B],
                    funding_gindexes: vec![GlobalOutputIndex::from_raw(3)],
                    state: PendingPostState::Pending,
                    reference_height: BlockHeight::from_raw(200),
                    terminal: None,
                };
                let admitted =
                    block.seal_drain(next, ChainCount::from_raw(206), g) == SealAdmission::Admit;
                (admitted, admitted)
            })
            .await
            .map(|admitted| assert!(admitted))
            .expect("seal a new drain");
        let resealed = Arc::new(OperatorAlarms::new());
        leg_on(&resealed).fire(3).await;
        assert_eq!(
            live(&resealed),
            Some(OperatorAlarm::ReservationSpentElsewhere {
                records: 1,
                held_stakes: 0
            }),
            "a new seal of the kind leaves the outcome and its alarm"
        );

        store
            .mutate(move |block| {
                let acked =
                    block.acknowledge_outcomes(RecordKind::Drain, BlockHeight::from_raw(194));
                (acked > 0, acked)
            })
            .await
            .expect("acknowledge");
        let after = Arc::new(OperatorAlarms::new());
        leg_on(&after).fire(4).await;
        let row = after
            .board()
            .condition(AlarmCondition::PendingFundsIntegrity)
            .expect("a staker's seal still arms the row");
        assert!(row.live().is_none(), "acknowledged: armed and quiet");

        // A stake reaches its end date (reference 94 + 100) with its one input
        // spent and no match: held, and the alarm is re-derived from the two
        // seals. Once the scan seals its match, the stake is the dispatch tick's
        // to retire and the alarm is quiet.
        let staker = PCanonicalId::from_bytes([0x0A; 32]);
        store
            .mutate(move |block| {
                let g = block.generation();
                let post = shekyl_engine_state::PendingBondPost {
                    p_slot: shekyl_types::PSlot::from_raw(3),
                    persona: staker,
                    tx_bytes: vec![0x0A],
                    bond_post_offset_blocks: BlockCount::from_raw(0),
                    anchor_t0: ChainCount::from_raw(100),
                    funding_gindexes: vec![GlobalOutputIndex::from_raw(5)],
                    state: PendingPostState::Pending,
                    reference_height: BlockHeight::from_raw(94),
                    terminal: None,
                };
                let admitted = block.seal_post(post, g) == SealAdmission::Admit;
                (admitted, admitted)
            })
            .await
            .map(|admitted| assert!(admitted))
            .expect("seal the stake");
        let seal_scan = |matches: Vec<shekyl_engine_state::pscan_state::BondPostRecord>| {
            let state = shekyl_engine_state::pscan_state::PScanState::new(
                shekyl_engine_state::pscan_cursor::PScanCursor::at(
                    BlockHeight::from_raw(195),
                    [0; 32],
                ),
                Default::default(),
                Default::default(),
                matches,
                Vec::new(),
                Vec::new(),
                Default::default(),
            );
            let bytes = state.to_postcard_bytes().expect("encode pscan state");
            let arc = Arc::clone(&arc);
            async move {
                let g = arc.read().await;
                g.persistence()
                    .save_pscan_state(g.state_wrap_key().as_bytes(), &bytes)
                    .expect("seal the scan");
            }
        };
        // The alarm's end-date clock is the wallet ledger. A fresh
        // staker engine is still at genesis, and this stake's end date is 194.
        arc.read()
            .await
            .ledger
            .write()
            .ledger
            .ledger
            .tip
            .synced_height = BlockHeight::from_raw(194);
        seal_scan(Vec::new()).await;
        let held = Arc::new(OperatorAlarms::new());
        leg_on(&held).fire(5).await;
        assert_eq!(
            live(&held),
            Some(OperatorAlarm::ReservationSpentElsewhere {
                records: 0,
                held_stakes: 1
            }),
            "a held stake raises the alarm from durable state"
        );

        seal_scan(vec![shekyl_engine_state::pscan_state::BondPostRecord {
            height: BlockHeight::from_raw(150),
            p_canonical_id: staker,
            post_kind: shekyl_wire::transaction::BOND_POST_KIND_JOINMARKET,
        }])
        .await;
        let matched = Arc::new(OperatorAlarms::new());
        leg_on(&matched).fire(6).await;
        assert_eq!(live(&matched), None, "a matched stake is not held");
    }
}
