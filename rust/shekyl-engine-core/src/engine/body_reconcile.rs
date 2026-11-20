// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The persona body-store reconcile and its alarm (`WSS-Q17`;
//! `docs/design/WALLET_SIDE_STORE.md` §6.5.9, §6.7.1).
//!
//! The reconcile compares what the persona's **connected** bond owes with
//! what its body store holds, and checks every held body against the rows
//! digest the persona scan sealed for it. A shard owed and not held, or held
//! with a body that does not verify, raises a [`ShardAlarm`] and is refilled
//! from the wallet's own node, the same fill the post went through. A refill
//! the node can no longer answer — the shard is past its horizon, and the
//! read answers `archived` — leaves the alarm saying so, because the bodies
//! come back only through the node's recovery fetch (§6.5.4, the `WSS-Q9`
//! handoff), which is not built.
//!
//! **What is owed** is the connected record's holdings, read the way the
//! serving pinner reads them (`fetch_vouched_claim_source`): a market bond's
//! named shards, or, for `CompleteTree`, every final shard by the scan's fold
//! (`FillContext::final_shards`). Not the wallet's memory of what it
//! posted.
//!
//! **Pull first, then reconcile.** A shard that became owed since this
//! session's last pass — a `CompleteTree` bond's newly final shard — is the
//! routine pull, filled quietly. The leg runs on every chain advance, so the
//! pull follows finality by one advance: for a shard final before its
//! freeze epoch opens, that is in its close epoch, before the open at which
//! a support draw first counts it (§6.5.9). Only after that does
//! the reconcile look for loss, so routine operation never shows as an
//! alarm. At the first pass of a session nothing counts as newly owed: an
//! owed shard missing at open is missing.
//!
//! **No persisted alarm state** (the `tx_alarm` shape): [`ShardAlarms`] is
//! re-derived from the store and the chain by each session's passes. An entry
//! stays for the session once raised, carrying its refill's outcome, so a
//! loss that was repaired is still visible until the next open.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use shekyl_archival_retention::HoldingsKind;
use shekyl_engine_file::WalletFile;
use shekyl_rpc_transport::DaemonTarget;
use shekyl_types::{PSlot, ShardId};
use shekyl_wire::shard_frame::frame_rows_digest;
use tokio::sync::RwLock;

use super::emission_source::fetch_vouched_claim_source;
use super::holdings_fill::FillFailure;
use super::signer::EngineSignerKind;
use super::stake_engine::body_store_actor::StoredFrame;
use super::traits::{DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, RefreshEngine};
use super::Engine;

/// What the reconcile found wrong with a shard the bond owes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardAlarmCause {
    /// The store does not hold it.
    Missing,
    /// The store holds it, and its body does not verify: a chunk failed
    /// authentication, the chunks do not add up to the length the store
    /// recorded, or the frame's rows digest is not the one the persona scan
    /// sealed.
    Corrupt,
}

/// What became of the refill an alarm started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardRefill {
    /// Not finished yet.
    Pending,
    /// The shard was refilled from the node and is held, verified.
    Refilled,
    /// The node has discarded the shard's bodies at its horizon, and the
    /// recovery fetch that would bring them back is not built, so the shard
    /// cannot be refilled.
    Discarded,
    /// The refill failed for another reason (the node unreachable, a reply
    /// that did not verify, the store); the next pass retries.
    Failed,
}

/// One shard the bond owes that needs the operator's attention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardAlarm {
    /// The shard.
    pub shard: u64,
    /// What was wrong.
    pub alarm: ShardAlarmCause,
    /// What the refill did about it.
    pub refill: ShardRefill,
}

/// This session's shard alarms, shared by the reconcile that writes them and
/// the read that shows them. Re-derived each session; never persisted.
#[derive(Debug, Clone, Default)]
pub struct ShardAlarms(Arc<std::sync::Mutex<BTreeMap<u64, ShardAlarm>>>);

impl ShardAlarms {
    /// The alarms, ascending by shard.
    #[must_use]
    pub fn list(&self) -> Vec<ShardAlarm> {
        self.0
            .lock()
            .expect("shard alarms lock")
            .values()
            .copied()
            .collect()
    }

    fn raise(&self, shard: ShardId, alarm: ShardAlarmCause) {
        let shard = shard.to_raw();
        self.0.lock().expect("shard alarms lock").insert(
            shard,
            ShardAlarm {
                shard,
                alarm,
                refill: ShardRefill::Pending,
            },
        );
    }

    fn settle(&self, shard: ShardId, refill: ShardRefill) {
        if let Some(entry) = self
            .0
            .lock()
            .expect("shard alarms lock")
            .get_mut(&shard.to_raw())
        {
            entry.refill = refill;
        }
    }

    /// Drop the alarms for shards the bond no longer owes (a released bond).
    fn retain_owed(&self, owed: &BTreeSet<ShardId>) {
        self.0
            .lock()
            .expect("shard alarms lock")
            .retain(|shard, _| owed.contains(&ShardId::from_raw(*shard)));
    }
}

/// What one session's reconcile remembers between passes: the shards owed
/// at the last pass (to tell the routine pull from a loss) and the epoch it
/// last checked bodies in.
#[derive(Debug, Default)]
pub(crate) struct ReconcileState {
    owed: Option<BTreeSet<ShardId>>,
    swept_in_epoch: Option<u64>,
}

/// Why a pass could not run. Nothing was concluded about the store: the
/// alarms are left as the last pass found them.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ReconcileError {
    /// The fill's prerequisites could not be read (the node, the scan state).
    #[error("{0}")]
    Context(#[from] FillFailure),
    /// The persona's identity or its connected record could not be read.
    #[error("{0}")]
    Record(String),
    /// The body store could not be read.
    #[error("{0}")]
    Store(String),
}

#[allow(private_bounds)] // same Engine-trait privacy posture as assemble_bond_post
impl<S, D, L, E, R, P> Engine<S, D, L, E, R, P, WalletFile>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
    Self: Send + Sync,
{
    /// One pass: pull what became owed, then — at a session's first pass,
    /// at the first pass of each settlement epoch, and after a pull that
    /// filled — check every owed shard and refill what is lost.
    ///
    /// # Errors
    ///
    /// [`ReconcileError`]; the alarms are untouched by a pass that could not
    /// run.
    pub(crate) async fn reconcile_bodies(
        self_arc: Arc<RwLock<Self>>,
        daemon: &DaemonTarget,
        epoch: u64,
        state: &mut ReconcileState,
        alarms: &ShardAlarms,
    ) -> Result<(), ReconcileError> {
        let (stake, bonded) = {
            let g = self_arc.read().await;
            (g.stake_handle(), g.ledger.bonded_slots())
        };
        let Some(stake) = stake else {
            return Ok(());
        };
        if bonded.is_empty() {
            // No bonded persona owes anything.
            alarms.retain_owed(&BTreeSet::new());
            state.owed = Some(BTreeSet::new());
            return Ok(());
        }

        let ctx = Self::fill_context(self_arc, daemon).await?;
        // What every bonded persona's connected record owes, whether or not
        // the persona is active this session: an open is idle until a
        // request activates one, and the obligation is the record's.
        let mut owed = BTreeSet::new();
        for slot in bonded {
            let p_id = stake
                .persona_canonical_id(PSlot::from_raw(slot))
                .await
                .map_err(|e| ReconcileError::Record(e.to_string()))?;
            let vouched = fetch_vouched_claim_source(ctx.rpc(), &p_id.to_bytes())
                .await
                .map_err(|e| ReconcileError::Record(e.to_string()))?;
            match vouched.source().bond.as_ref() {
                None => {}
                Some(bond) => match bond.holdings.kind {
                    HoldingsKind::CompleteTree => owed.extend(ctx.final_shards()),
                    HoldingsKind::ShardSetCompact => owed.extend(
                        bond.holdings
                            .shard_ids
                            .as_slice()
                            .iter()
                            .copied()
                            .map(ShardId::from_raw),
                    ),
                },
            }
        }

        // Pull first: what became owed since the last pass is routine.
        let mut pulled = BTreeSet::new();
        if let Some(previous) = &state.owed {
            for &shard in owed.difference(previous) {
                let held = ctx
                    .bodies
                    .holds(shard)
                    .await
                    .map_err(ReconcileError::Store)?;
                if held {
                    continue;
                }
                match ctx.fill_one(shard).await {
                    Ok(()) => {
                        pulled.insert(shard);
                    }
                    // Not pulled in its window: from here it is a loss.
                    Err(e) => {
                        alarms.raise(shard, ShardAlarmCause::Missing);
                        alarms.settle(shard, refill_outcome(&e));
                    }
                }
            }
        }

        let first = state.owed.is_none();
        let new_epoch = state.swept_in_epoch != Some(epoch);
        if first || new_epoch || !pulled.is_empty() {
            for &shard in owed.difference(&pulled) {
                let cause = match ctx
                    .bodies
                    .read_frame(shard)
                    .await
                    .map_err(ReconcileError::Store)?
                {
                    StoredFrame::NotHeld => Some(ShardAlarmCause::Missing),
                    StoredFrame::Unreadable => Some(ShardAlarmCause::Corrupt),
                    StoredFrame::Frame(frame) => {
                        let sealed = ctx.fold.close(shard).map(|close| close.rows);
                        let verifies = frame_rows_digest(shard, &frame)
                            .is_ok_and(|digest| Some(digest.rows) == sealed);
                        (!verifies).then_some(ShardAlarmCause::Corrupt)
                    }
                };
                let Some(cause) = cause else {
                    continue;
                };
                alarms.raise(shard, cause);
                let refill = match ctx.fill_one(shard).await {
                    Ok(()) => ShardRefill::Refilled,
                    Err(e) => refill_outcome(&e),
                };
                alarms.settle(shard, refill);
            }
            state.swept_in_epoch = Some(epoch);
        }

        alarms.retain_owed(&owed);
        state.owed = Some(owed);
        Ok(())
    }
}

/// A refill's failure as the alarm shows it.
///
/// Logged by kind only, never with the shard or the failure's own text,
/// which names it: a shard id in the plaintext log, matched against the
/// chain's public bond history, identifies the persona (`WSS-20`). The
/// shard is on the alarm read, which only the wallet's own client sees.
fn refill_outcome(e: &FillFailure) -> ShardRefill {
    let (refill, kind) = match e {
        FillFailure::Discarded { .. } => (ShardRefill::Discarded, "the node discarded it"),
        FillFailure::LocalNodeRequired { .. } => (ShardRefill::Failed, "the node is not local"),
        FillFailure::DaemonSyncing => (ShardRefill::Failed, "the node is synchronizing"),
        FillFailure::DaemonUnreachable { .. } => (ShardRefill::Failed, "the node is unreachable"),
        FillFailure::ScanStateUnreadable { .. } => {
            (ShardRefill::Failed, "the scan state is unreadable")
        }
        FillFailure::DaemonMismatch { .. } => {
            (ShardRefill::Failed, "the node's reply does not verify")
        }
        FillFailure::StoreFailed { .. } => (ShardRefill::Failed, "the store could not write"),
    };
    tracing::warn!(
        cause = kind,
        "persona body store: an owed shard is lost and its refill did not complete; see \
         shard_alarm. The next pass retries"
    );
    refill
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shard(n: u64) -> ShardId {
        ShardId::from_raw(n)
    }

    #[test]
    fn a_raised_alarm_carries_its_refill_and_stays_for_the_session() {
        let alarms = ShardAlarms::default();
        alarms.raise(shard(4), ShardAlarmCause::Missing);
        assert_eq!(
            alarms.list(),
            [ShardAlarm {
                shard: 4,
                alarm: ShardAlarmCause::Missing,
                refill: ShardRefill::Pending,
            }],
            "the alarm is visible before its refill finishes"
        );
        alarms.settle(shard(4), ShardRefill::Refilled);
        assert_eq!(
            alarms.list()[0].refill,
            ShardRefill::Refilled,
            "a repaired loss stays on the read for the session"
        );
    }

    #[test]
    fn a_shard_the_bond_no_longer_owes_leaves_the_read() {
        let alarms = ShardAlarms::default();
        alarms.raise(shard(1), ShardAlarmCause::Corrupt);
        alarms.raise(shard(2), ShardAlarmCause::Missing);
        alarms.retain_owed(&[shard(2)].into_iter().collect());
        assert_eq!(
            alarms.list().iter().map(|a| a.shard).collect::<Vec<_>>(),
            [2]
        );
    }

    #[test]
    fn settling_a_shard_with_no_alarm_raises_none() {
        let alarms = ShardAlarms::default();
        alarms.settle(shard(9), ShardRefill::Failed);
        assert!(alarms.list().is_empty());
    }

    #[test]
    fn only_a_discarded_shard_reads_as_discarded() {
        assert_eq!(
            refill_outcome(&FillFailure::Discarded { shard: shard(3) }),
            ShardRefill::Discarded
        );
        assert_eq!(
            refill_outcome(&FillFailure::DaemonUnreachable {
                detail: String::new()
            }),
            ShardRefill::Failed
        );
    }
}
