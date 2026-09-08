// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The cadence-driver producers for the [operator alarm channel](crate) —
//! `ENGINE_CADENCE_DRIVER.md` §2 (chain-progress watchdog) and §4 (claim-leg
//! failure surfacing).
//!
//! Same split as [`disk`](crate::disk) / [`serve_set`](crate::serve_set) /
//! [`tor_posture`](crate::tor_posture): the *measurement* (tip polling, epoch
//! accounting, watchdog horizon) belongs to the engine's cadence driver; the
//! *mapping* from a reading onto the board lives here, where it is a total
//! function anyone can call in a test.
//!
//! # Why chain progress is a condition and not a log line
//!
//! The driver's tick base is chain progress: legs fire only when the observed
//! tip advances. A tick base that goes silent when the chain does is the
//! design (firing against a stale view is the eclipse hazard §2 names), which
//! makes the silence itself the thing that must be observable — a stalled
//! driver and a healthy wallet with nothing to do are indistinguishable
//! without a row that says which one is happening. That is this channel's
//! founding distinction (armed-and-quiet vs disarmed vs alarmed), so the
//! watchdog reports here rather than to `tracing`.

use crate::{AlarmCondition, DisarmedReason, OperatorAlarm, OperatorAlarms};

/// One chain-progress reading from the driver's wall-clock watchdog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainProgressObservation {
    /// The observed tip advanced (or the driver just started and took its
    /// first reading). The watchdog is healthy.
    Advancing,
    /// No tip advance for longer than the watchdog horizon. Carries the last
    /// height observed and how stale it is, so the operator can tell a
    /// daemon that is down from one that is eclipsed at a plausible height.
    Stalled {
        /// The last tip height the driver observed.
        last_height: u64,
        /// Seconds since that observation.
        stalled_for_secs: u64,
    },
}

/// Map one chain-progress reading onto the board.
pub fn apply_chain_progress(alarms: &OperatorAlarms, observation: ChainProgressObservation) {
    alarms.arm(AlarmCondition::ChainProgress);
    match observation {
        ChainProgressObservation::Advancing => {
            alarms.clear(AlarmCondition::ChainProgress);
        }
        ChainProgressObservation::Stalled {
            last_height,
            stalled_for_secs,
        } => {
            // Re-raising with a fresher `stalled_for_secs` updates the open
            // incident in place (same fault, payload aside) — one stall is
            // one incident however many ticks observe it.
            alarms.raise(OperatorAlarm::ChainProgressStalled {
                last_height,
                stalled_for_secs,
            });
        }
    }
}

/// One claim-leg reading, produced once per fired tick on staker wallets.
///
/// Non-staker wallets produce **no** claim observations: their board has no
/// `EpochClaim` / `ClaimForfeiture` rows at all, which reads as "not watched"
/// rather than "not checking" — the honest rendering for a wallet with no
/// claim obligation to watch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimObservation {
    /// Nothing outstanding: every settled epoch is claimed, value-deferred by
    /// policy, or empty. Deferral is a decision, not a fault, so a wallet
    /// holding ten underwater epochs reads healthy here.
    Current,
    /// Settled epochs are outstanding past the policy's expectation — a
    /// sealed claim not confirming, or pre-seal failures across consecutive
    /// ticks.
    Behind {
        /// The oldest outstanding epoch.
        oldest_epoch: u64,
        /// Total outstanding settled epochs.
        outstanding_epochs: u64,
    },
}

/// Map one claim-leg reading onto the board.
pub fn apply_claim(alarms: &OperatorAlarms, observation: ClaimObservation) {
    alarms.arm(AlarmCondition::EpochClaim);
    match observation {
        ClaimObservation::Current => alarms.clear(AlarmCondition::EpochClaim),
        ClaimObservation::Behind {
            oldest_epoch,
            outstanding_epochs,
        } => alarms.raise(OperatorAlarm::EpochUnclaimed {
            oldest_epoch,
            outstanding_epochs,
        }),
    }
}

/// Record a forfeit: held epochs reached the claim-window floor still
/// underwater and were let expire (`ENGINE_CADENCE_DRIVER.md` §4
/// evaluate-and-forfeit).
///
/// `forfeited_atomic_total` is the session's running total, not the
/// increment: re-raising the same fault updates the incident in place, so the
/// standing alarm always shows the full amount lost this session. The
/// producer never clears this condition — the record stands until close.
/// (A record that survives restart is durable-ledger work, tracked in
/// `docs/FOLLOWUPS.md`.)
pub fn record_forfeit(alarms: &OperatorAlarms, epoch: u64, forfeited_atomic_total: u64) {
    alarms.arm(AlarmCondition::ClaimForfeiture);
    alarms.raise(OperatorAlarm::ClaimForfeited {
        epoch,
        forfeited_atomic: forfeited_atomic_total,
    });
}

/// Park a cadence leg's condition after the leg panicked: disarmed, never
/// healthy-looking, for the rest of the session (§3 leg isolation).
pub fn park_condition(alarms: &OperatorAlarms, condition: AlarmCondition) {
    alarms.disarm(condition, DisarmedReason::DriverLegParked);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Arming;

    fn state(alarms: &OperatorAlarms, condition: AlarmCondition) -> crate::ConditionState {
        alarms
            .board()
            .condition(condition)
            .expect("the condition has a row once observed")
    }

    /// A stall raises, an advance clears, and the incident is continuous
    /// across re-observations of the same stall.
    #[test]
    fn stall_is_one_incident_and_advance_clears_it() {
        let alarms = OperatorAlarms::new();

        apply_chain_progress(&alarms, ChainProgressObservation::Advancing);
        let healthy = state(&alarms, AlarmCondition::ChainProgress);
        assert_eq!(healthy.arming(), Arming::Armed);
        assert!(healthy.live().is_none());

        apply_chain_progress(
            &alarms,
            ChainProgressObservation::Stalled {
                last_height: 100,
                stalled_for_secs: 1_800,
            },
        );
        let first = state(&alarms, AlarmCondition::ChainProgress)
            .live()
            .expect("stall raises");

        // The next tick observes the same stall, staler.
        apply_chain_progress(
            &alarms,
            ChainProgressObservation::Stalled {
                last_height: 100,
                stalled_for_secs: 3_600,
            },
        );
        let second = state(&alarms, AlarmCondition::ChainProgress)
            .live()
            .expect("still stalled");
        assert_eq!(
            first.incident(),
            second.incident(),
            "one stall is one incident however many ticks observe it"
        );
        assert_eq!(
            second.alarm(),
            OperatorAlarm::ChainProgressStalled {
                last_height: 100,
                stalled_for_secs: 3_600,
            },
            "the payload freshens in place"
        );

        apply_chain_progress(&alarms, ChainProgressObservation::Advancing);
        assert!(
            state(&alarms, AlarmCondition::ChainProgress)
                .live()
                .is_none(),
            "an advance ends the episode outright"
        );
    }

    /// Behind raises; current clears; value-deferral never reaches the board.
    #[test]
    fn claim_backlog_raises_and_confirmation_clears() {
        let alarms = OperatorAlarms::new();

        apply_claim(
            &alarms,
            ClaimObservation::Behind {
                oldest_epoch: 41,
                outstanding_epochs: 3,
            },
        );
        assert_eq!(
            state(&alarms, AlarmCondition::EpochClaim)
                .live()
                .map(crate::RaisedAlarm::alarm),
            Some(OperatorAlarm::EpochUnclaimed {
                oldest_epoch: 41,
                outstanding_epochs: 3,
            })
        );

        apply_claim(&alarms, ClaimObservation::Current);
        assert!(state(&alarms, AlarmCondition::EpochClaim).live().is_none());
    }

    /// A forfeit stands on its own condition: a later claim backlog does not
    /// overwrite the record of lost value, and the running total freshens in
    /// place under one incident.
    #[test]
    fn forfeit_outlives_later_claim_readings() {
        let alarms = OperatorAlarms::new();

        record_forfeit(&alarms, 17, 250);
        let first = state(&alarms, AlarmCondition::ClaimForfeiture)
            .live()
            .expect("forfeit raises");

        apply_claim(
            &alarms,
            ClaimObservation::Behind {
                oldest_epoch: 43,
                outstanding_epochs: 1,
            },
        );
        apply_claim(&alarms, ClaimObservation::Current);
        assert!(
            state(&alarms, AlarmCondition::ClaimForfeiture)
                .live()
                .is_some(),
            "claim-leg readings do not touch the forfeit record"
        );

        record_forfeit(&alarms, 43, 400);
        let second = state(&alarms, AlarmCondition::ClaimForfeiture)
            .live()
            .expect("still standing");
        assert_eq!(first.incident(), second.incident());
        assert_eq!(
            second.alarm(),
            OperatorAlarm::ClaimForfeited {
                epoch: 43,
                forfeited_atomic: 400,
            },
            "the session total freshens in place"
        );
    }

    /// A parked leg reads as "not checking", never as healthy.
    #[test]
    fn parking_disarms_rather_than_clearing() {
        let alarms = OperatorAlarms::new();
        apply_claim(
            &alarms,
            ClaimObservation::Behind {
                oldest_epoch: 5,
                outstanding_epochs: 1,
            },
        );
        park_condition(&alarms, AlarmCondition::EpochClaim);
        let parked = state(&alarms, AlarmCondition::EpochClaim);
        assert_eq!(
            parked.arming(),
            Arming::Disarmed(DisarmedReason::DriverLegParked)
        );
        assert!(
            parked.live().is_some(),
            "disarming stops the watch; it does not declare the fault fixed"
        );
    }
}
