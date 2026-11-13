// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The held sends that need the user's decision, and the user's resend
//! (A19; `DAEMON_SUBMIT_VERDICT.md` §5.3 rung 2, "a human decides").
//!
//! The watchdog's alarm used to reach only the diagnostic sink — a log
//! line. A human cannot decide on what they cannot see, so the alarm is a
//! read here ([`Engine::held_sends`]) and the decision an action
//! ([`Engine::resend_held_send`]; [`Engine::abandon_tx_persisted`] is the
//! other choice).
//!
//! # Nothing here is persisted
//!
//! The read is derived each time from the saved journal and the session:
//! a held send dispatched before this session needs a decision by that
//! fact alone ([`WatchdogAlarmReason::DispatchedBeforeThisSession`]), so
//! the alarm is re-derived every time the wallet opens (the
//! `AlarmLifetime::LatchedRederived` shape), with no alarm state on disk.
//! A send this session dispatched appears once the watchdog has latched an
//! alarm for it.

use shekyl_types::{BlockHeight, TxHash};

use super::diagnostics::WatchdogAlarmReason;
use super::dispatch_durability::EngineLedgerCommit;
use super::error::{AmbiguousErrorKind, RetryableRejectCause, TerminalErrorKind};
use super::pending::SubmitOutcome;
use super::submit_lifecycle::{apply_resend_verdict, WatchdogHost};
use super::traits::{
    DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, PersistenceEngine, RefreshEngine,
};
use super::transaction_submitter::{outcome_to_result, SubmitSuccess, SubmitterError};
use super::{Engine, EngineSignerKind};

/// One held send that needs the user's decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldSend {
    /// The send's canonical transaction id.
    pub tx_hash: TxHash,
    /// Why it needs a decision.
    pub alarm: WatchdogAlarmReason,
    /// The wallet's synced height when the send left.
    pub sent_height: BlockHeight,
}

/// Why a resend did not reach a verdict that keeps the send.
#[derive(Debug, thiserror::Error)]
pub enum ResendError {
    /// No held send has this id: it confirmed, was released, or was never
    /// this wallet's.
    #[error("no held send with this id")]
    NotHeld,
    /// The held send's record holds no bytes to resend
    /// ([`WatchdogAlarmReason::HeldBytesMissing`]).
    #[error("the held send has no saved bytes to resend")]
    BytesMissing,
    /// The daemon refused the bytes terminally. Under single-egress that
    /// proves they are in neither pool nor chain, so the send's input
    /// locks were released (§2.6 release path 2) — `released` says
    /// whether that release was saved.
    #[error("the daemon refused the resend: {kind:?}")]
    RejectedTerminal {
        /// The daemon's cause.
        kind: TerminalErrorKind,
        /// Whether the release of the send's inputs was saved.
        released: bool,
    },
    /// The daemon refused the bytes for a cause a fresh reference would
    /// cure: the bytes cannot be offered again as they are. The send stays
    /// held; rebuilding is the user's decision (§7.1).
    #[error("the daemon refused the resend: {cause:?}")]
    RejectedRetryable {
        /// The daemon's cause.
        cause: RetryableRejectCause,
    },
    /// The daemon gave no verdict. The send stays held; resending again
    /// is the status query.
    #[error("the daemon gave no verdict on the resend: {kind:?}")]
    Ambiguous {
        /// What the transport saw.
        kind: AmbiguousErrorKind,
    },
}

#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: DaemonEngine,
        L: LedgerEngine,
        E: EconomicsEngine,
        R: RefreshEngine,
        P: PendingTxEngine + WatchdogHost,
        F: PersistenceEngine,
    > Engine<S, D, L, E, R, P, F>
{
    /// The held sends that need the user's decision, oldest dispatch
    /// first: every held send dispatched before this session, and every
    /// one the watchdog has alarmed on in it.
    pub fn held_sends(&self) -> Vec<HeldSend> {
        let host: &dyn WatchdogHost = &self.pending;
        let mut sends: Vec<HeldSend> = host
            .held_submits()
            .into_iter()
            .filter_map(|held| {
                let tx_hash = held.tx_hash;
                let alarm = if host.held_bytes_for(&tx_hash).is_none() {
                    WatchdogAlarmReason::HeldBytesMissing
                } else if !host.dispatched_this_session(&tx_hash) {
                    WatchdogAlarmReason::DispatchedBeforeThisSession
                } else {
                    host.alarm_for(&tx_hash)?
                };
                Some(HeldSend {
                    tx_hash,
                    alarm,
                    sent_height: host.sent_height(&tx_hash)?,
                })
            })
            .collect();
        sends.sort_by_key(|send| (send.sent_height, send.tx_hash.to_bytes()));
        sends
    }

    /// Resend the held send `tx_hash`'s saved bytes, by the user's
    /// decision, and return the daemon's verdict.
    ///
    /// The bytes are exactly those that left at dispatch, so the resend is
    /// privacy-neutral (same txid; the daemon dedups) and doubles as the
    /// status query (§2.5). It goes to the wallet's own daemon. From here
    /// this session owns the send: the watchdog's automatic rung 1 applies
    /// to it again, and its alarm clears. The verdict is applied the way
    /// the watchdog applies its probe's
    /// ([`apply_resend_verdict`]): a terminal refusal releases the inputs.
    ///
    /// # Errors
    ///
    /// [`ResendError`]: not held, no saved bytes, a refusal, or no verdict.
    pub async fn resend_held_send(&self, tx_hash: TxHash) -> Result<SubmitOutcome, ResendError> {
        let host: &dyn WatchdogHost = &self.pending;
        let held = host
            .held_submits()
            .into_iter()
            .find(|held| held.tx_hash == tx_hash)
            .ok_or(ResendError::NotHeld)?;
        let bytes = host
            .held_bytes_for(&tx_hash)
            .ok_or(ResendError::BytesMissing)?;
        host.adopt_into_session(tx_hash);

        let outcome = self
            .daemon
            .submit_transaction(bytes)
            .await
            .map_err(|error| {
                let error: super::error::IoError = error.into();
                tracing::warn!(%error, "resend: the daemon gave no verdict");
                ResendError::Ambiguous {
                    kind: AmbiguousErrorKind::DaemonUnavailable,
                }
            })?;
        let commit = EngineLedgerCommit::new(&self.persistence, self.state_wrap_key());
        let released = apply_resend_verdict(host, &commit, &held, outcome.clone());
        match outcome_to_result(outcome) {
            Ok(SubmitSuccess::Broadcast { kind, .. }) => Ok(kind.into_outcome(tx_hash)),
            Ok(SubmitSuccess::AlreadyInChain { height, .. }) => Ok(SubmitOutcome::AlreadyInChain {
                hash: tx_hash,
                height,
            }),
            Err(SubmitterError::RejectedTerminal { kind }) => {
                Err(ResendError::RejectedTerminal { kind, released })
            }
            Err(SubmitterError::RejectedRetryable { cause }) => {
                Err(ResendError::RejectedRetryable { cause })
            }
            Err(SubmitterError::Ambiguous { kind }) => Err(ResendError::Ambiguous { kind }),
        }
    }
}
