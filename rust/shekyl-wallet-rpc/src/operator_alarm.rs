// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `operator_alarm` and `operator_alarm_acknowledge` (OA-1): the wallet's
//! operator alarm board on the wire.
//!
//! The board is the engine's, one for the open span
//! ([`Engine::operator_alarms`](shekyl_engine_core::Engine::operator_alarms)):
//! every condition the wallet watches for the operator, armed or not, and the
//! faults whose condition cleared while their damage stands. This module reads
//! it and projects it; nothing here observes a condition or decides one.
//!
//! # Who may read it
//!
//! Whoever holds the wallet RPC's credential: the owner-only socket, or the
//! basic-auth login on a TCP listener. The wallet RPC has no finer grant, and
//! a caller holding that credential can already move the wallet's funds and
//! read `staking_info` and `shard_alarm`. The board names no onion address, no
//! service id and no shard, and its only clock readings are durations, so it
//! tells that caller nothing beyond whether the persona's checks are running
//! and what they found.
//!
//! # Reading it does not tell anyone when it changed
//!
//! The crate doc of `shekyl-operator-alarm` names emission cadence as a
//! covert channel. A reader must not open a new one, so:
//! - The read is pull-only. There is no subscription, long poll or "changed
//!   since" form, so a reply's timing is the caller's, never the board's.
//! - Every reply has the same shape: every condition's row, in one fixed
//!   order, whatever has changed. Only the values differ.
//! - A read changes nothing. It takes a snapshot under the engine's read
//!   lock and does not reach a producer, the daemon or Tor, so reading more
//!   often puts no traffic anywhere a network observer could see.

use serde_json::Value;
use shekyl_engine_core::{
    AlarmBoard, AlarmCondition, Arming, DegradedCause, DisarmedReason, IncidentId, OperatorAlarm,
    RaisedAlarm,
};
use shekyl_rpc_types::Nullable;

use crate::error::WalletRpcError;
use crate::params::{parse_required_object, require_empty_object};
use crate::tenant::{require_open_engine, TenantState};
use crate::types::{
    AlarmConditionView, AlarmIncidentView, AlarmOutstandingView, AlarmRowView, AlarmView,
    ArmingView, DisarmedReasonView, OperatorAlarmAcknowledgeParams, OperatorAlarmAcknowledgeResult,
    OperatorAlarmResult, TransportCauseView,
};

/// `operator_alarm`: the board as it stands.
pub(crate) async fn operator_alarm(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    require_empty_object(params, "operator_alarm")?;
    let shared = require_open_engine(tenants).await?;
    let board = shared.read().await.operator_alarms().board();
    serde_json::to_value(operator_alarm_result(&board))
        .map_err(|e| WalletRpcError::InternalError(format!("serialize operator_alarm: {e}")))
}

/// `operator_alarm_acknowledge`: clear the outstanding fault the operator
/// was shown. A live fault is not in the queue, so this cannot silence one
/// that is still happening.
pub(crate) async fn operator_alarm_acknowledge(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: OperatorAlarmAcknowledgeParams =
        parse_required_object(params, "operator_alarm_acknowledge")?;
    let shared = require_open_engine(tenants).await?;
    let acknowledged = shared
        .read()
        .await
        .operator_alarms()
        .acknowledge(IncidentId::from_raw(p.incident));
    serde_json::to_value(OperatorAlarmAcknowledgeResult { acknowledged }).map_err(|e| {
        WalletRpcError::InternalError(format!("serialize operator_alarm_acknowledge: {e}"))
    })
}

/// Project the board to `operator_alarm`'s result: every condition's row in
/// the board's order, then the acknowledgment queue, oldest first.
pub fn operator_alarm_result(board: &AlarmBoard) -> OperatorAlarmResult {
    OperatorAlarmResult {
        conditions: board
            .conditions()
            .map(|(condition, state)| AlarmRowView {
                condition: condition_view(condition),
                arming: arming_view(state.arming()),
                fault: Nullable::from(state.live().map(incident_view)),
            })
            .collect(),
        unacknowledged: board
            .unacknowledged()
            .iter()
            .map(|raised| AlarmOutstandingView {
                incident: raised.incident().get(),
                condition: condition_view(raised.condition()),
                alarm: alarm_view(raised.alarm()),
            })
            .collect(),
    }
}

fn incident_view(raised: RaisedAlarm) -> AlarmIncidentView {
    AlarmIncidentView {
        incident: raised.incident().get(),
        alarm: alarm_view(raised.alarm()),
    }
}

/// Exhaustive, as every projection here is: a new condition, reason, alarm or
/// cause does not compile until it has its wire keyword.
fn condition_view(condition: AlarmCondition) -> AlarmConditionView {
    match condition {
        AlarmCondition::TransportLiveness => AlarmConditionView::TransportLiveness,
        AlarmCondition::OnionReachability => AlarmConditionView::OnionReachability,
        AlarmCondition::VanguardIntegrity => AlarmConditionView::VanguardIntegrity,
        AlarmCondition::ServeSetIntegrity => AlarmConditionView::ServeSetIntegrity,
        AlarmCondition::ServingDiskHeadroom => AlarmConditionView::ServeDiskHeadroom,
        AlarmCondition::ServeHealth => AlarmConditionView::ServeHealth,
        AlarmCondition::ChainProgress => AlarmConditionView::ChainProgress,
        AlarmCondition::EpochClaim => AlarmConditionView::EpochClaim,
        AlarmCondition::ClaimForfeiture => AlarmConditionView::ClaimForfeiture,
        AlarmCondition::PendingFundsIntegrity => AlarmConditionView::PendingFundsIntegrity,
    }
}

fn arming_view(arming: Arming) -> ArmingView {
    match arming {
        Arming::Armed => ArmingView::Armed(()),
        Arming::Disarmed(reason) => ArmingView::Disarmed(match reason {
            DisarmedReason::TransportNotReady => DisarmedReasonView::TransportUnready,
            DisarmedReason::TransportStopped => DisarmedReasonView::TransportStopped,
            DisarmedReason::CatchingUp => DisarmedReasonView::CatchingUp,
            DisarmedReason::DiskUnreadable => DisarmedReasonView::DiskUnreadable,
            DisarmedReason::NotServing => DisarmedReasonView::HostDown,
            DisarmedReason::DriverLegParked => DisarmedReasonView::DriverLegParked,
            DisarmedReason::Unreported => DisarmedReasonView::Unreported,
            DisarmedReason::CheckStopped => DisarmedReasonView::CheckStopped,
        }),
    }
}

fn cause_view(cause: DegradedCause) -> TransportCauseView {
    match cause {
        DegradedCause::BinaryRejected => TransportCauseView::InstallDefect(()),
        DegradedCause::ControlChannelFailed => TransportCauseView::ControlChannelFailed(()),
        DegradedCause::NoSocksListener => TransportCauseView::SocksMissing(()),
        DegradedCause::BootstrapTimeout => TransportCauseView::LaunchFailed(()),
        DegradedCause::Exited => TransportCauseView::Exited(()),
        DegradedCause::Internal => TransportCauseView::Internal(()),
        DegradedCause::OnionPublishFailed => TransportCauseView::OnionRefused(()),
        DegradedCause::VanguardsFailed => TransportCauseView::GuardsRefused(()),
    }
}

fn alarm_view(alarm: OperatorAlarm) -> AlarmView {
    match alarm {
        OperatorAlarm::TransportDegraded { cause } => AlarmView::TransportDegraded {
            cause: Nullable::from(cause.map(cause_view)),
        },
        OperatorAlarm::VanguardStateRedrawn => AlarmView::VanguardStateRedrawn(()),
        OperatorAlarm::VanguardStateUnpersisted => AlarmView::VanguardStateUnpersisted(()),
        OperatorAlarm::VanguardRepairSkipped { decoded, announced } => {
            AlarmView::VanguardViewIncomplete {
                decoded: decoded as u64,
                announced: announced as u64,
            }
        }
        OperatorAlarm::ServeSetStale { lag } => AlarmView::ServeSetStale { block_count: lag },
        OperatorAlarm::ServeSetRefreshFailing { consecutive } => {
            AlarmView::ServeSetRefreshFailing {
                count: u64::from(consecutive),
            }
        }
        OperatorAlarm::ServeSetPinsDropped { dropped, claimed } => AlarmView::ServeSetPinsDropped {
            dropped_count: u64::from(dropped),
            member_count: u64::from(claimed),
        },
        OperatorAlarm::ServeSetPostureLost { frozen_count } => {
            AlarmView::ServeSetPostureLost { frozen_count }
        }
        OperatorAlarm::ServingDiskLow {
            free_bytes,
            threshold_bytes,
        } => AlarmView::ServeDiskLow {
            free: free_bytes,
            free_min: threshold_bytes,
        },
        OperatorAlarm::ServeSetRolledBack { minted_at_tip, tip } => AlarmView::ServeSetRolledBack {
            minted_height: minted_at_tip,
            height: tip,
        },
        OperatorAlarm::ServeSetBytesPruned { members } => AlarmView::ServeSetBytesPruned {
            member_count: u64::from(members),
        },
        OperatorAlarm::ChainProgressStalled {
            last_height,
            stalled_for_secs,
        } => AlarmView::ChainProgressStalled {
            height: last_height,
            age: stalled_for_secs,
        },
        OperatorAlarm::EpochUnclaimed {
            oldest_epoch,
            outstanding_epochs,
        } => AlarmView::EpochUnclaimed {
            epoch: oldest_epoch,
            epoch_count: outstanding_epochs,
        },
        OperatorAlarm::ClaimForfeited {
            epoch,
            forfeited_atomic,
        } => AlarmView::ClaimForfeited {
            epoch,
            amount: forfeited_atomic,
        },
        OperatorAlarm::ReservationSpentElsewhere {
            records,
            held_stakes,
        } => AlarmView::ReservationSpentElsewhere {
            record_count: records,
            held_count: held_stakes,
        },
        OperatorAlarm::ServeSigningRefused { pre_flight, late } => {
            AlarmView::ServeSigningRefused { pre_flight, late }
        }
        OperatorAlarm::ServeLookupsFailing { failures } => {
            AlarmView::ServeLookupFailing { count: failures }
        }
        OperatorAlarm::ServeListenerFailing { accept_errors } => AlarmView::ServeListenerFailing {
            count: accept_errors,
        },
    }
}

#[cfg(test)]
#[path = "operator_alarm_tests.rs"]
mod tests;
