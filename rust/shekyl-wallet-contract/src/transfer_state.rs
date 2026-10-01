// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The contract's transfer state, and the one map from the send journal's
//! lifecycle onto it.

use serde::{Deserialize, Serialize};
use shekyl_engine_state::SendState;

/// Transfer confirmation state (OpenAPI `Transfer.state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransferState {
    /// Network-exposed spend awaiting confirmation (or still unsettled).
    Pending,
    /// Confirmed on chain, unspent (receive) or observed spent-on-chain (send).
    Confirmed,
    /// Spent (receive-side output consumed).
    Spent,
    /// Received but unspendable (INCOMING only; `PL-D3`,
    /// `FCMP_SPEND_LINKABILITY.md` §6.2): the sender's transaction
    /// published a `tx_extra` `0x07` leaf entry that does not open to this
    /// wallet's derivation for the output, so the chain leaf can never be
    /// proven by this wallet. The money is on chain and the row names the
    /// sender's transaction (`tx_hash`); it is excluded from every
    /// spendable balance (rule 82: a failure mode is first-class, not a
    /// log line). `unspendable_reason` says which half failed.
    Unspendable,
    /// Terminal failure: daemon refused the dispatch; the tx never mined
    /// (OUTGOING journal `TerminalRejected` only — rule 82 failed-send history).
    Failed,
    /// The network no longer holds the send: the watchdog's
    /// confirmed-absent horizon released the input locks, so the funds
    /// are spendable again and the send can be re-made (OUTGOING journal
    /// `PresumedDead` only).
    ///
    /// Distinct from [`Self::Pending`] because the wallet has stopped
    /// waiting — reporting PENDING would contradict the balance the
    /// same wallet reports — and distinct from [`Self::Failed`] because
    /// nothing proved the send was refused: a late confirmation still
    /// flips this row to CONFIRMED (rule 82).
    Dropped,
    /// The user abandoned the send (`abandon_tx`; OUTGOING journal
    /// `Abandoned` only).
    ///
    /// Distinct from [`Self::Dropped`] because the release came from
    /// user intent, not confirmed-absent evidence — the carried input
    /// locks may still be held until the watchdog resolves — and, as
    /// with DROPPED, a late confirmation still flips this row to
    /// CONFIRMED loudly rather than staying wrong (rule 82 / P3-4).
    Abandoned,
}

impl TransferState {
    /// OpenAPI / JSON-RPC wire string (`SCREAMING_SNAKE_CASE`). Single
    /// owner of that vocabulary so error data and `get_transfers` never
    /// diverge.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Confirmed => "CONFIRMED",
            Self::Spent => "SPENT",
            Self::Unspendable => "UNSPENDABLE",
            Self::Failed => "FAILED",
            Self::Dropped => "DROPPED",
            Self::Abandoned => "ABANDONED",
        }
    }
}

impl std::fmt::Display for TransferState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Map journal lifecycle onto the OpenAPI `TransferState` enum.
///
/// Every arm is a distinct user-facing situation; none collapses into
/// another, because each collapse is a different lie (rule 82):
///
/// - `Dispatched` → `PENDING` (in flight; the wallet is still waiting).
/// - `Confirmed` → `CONFIRMED` (refresh observed the spend on chain).
/// - `TerminalRejected` → `FAILED` (daemon refused; never mined — never
///   collapse into `CONFIRMED`).
/// - `PresumedDead` → `DROPPED` (the confirmed-absent watchdog released
///   the input locks — never collapse into `PENDING`, which would say
///   the wallet is still waiting while the same wallet reports those
///   funds spendable again).
/// - `Abandoned` → `ABANDONED` (user-authored give-up, P3-4 — never
///   collapse into `DROPPED`, whose release claim is evidence-backed;
///   an abandoned send's input locks may still be held).
///
/// This is the **single owner** of the journal → wire state map: the error
/// mapping and the RPC server's history filters call here rather than
/// re-listing the arms.
#[must_use]
pub fn outgoing_transfer_state_of(state: SendState) -> TransferState {
    match state {
        SendState::Dispatched => TransferState::Pending,
        SendState::Confirmed { .. } => TransferState::Confirmed,
        SendState::TerminalRejected => TransferState::Failed,
        SendState::PresumedDead => TransferState::Dropped,
        SendState::Abandoned => TransferState::Abandoned,
    }
}
