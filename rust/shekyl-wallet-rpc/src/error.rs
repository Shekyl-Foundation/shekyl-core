// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `WalletRpcError` and the stable JSON-RPC error-code table from
//! `docs/api/wallet_rpc.yaml` (`WalletRpcErrorCode`).

use serde_json::{json, Value};
use shekyl_engine_core::engine::error::{
    FeeEstimatorError, RetryableRejectCause, TerminalErrorKind,
};
use shekyl_engine_core::engine::SubmitError;
use shekyl_engine_core::{
    ChangePasswordError, DrainToPrincipalError, IoError, OpenError, PScanStartError,
    PendingTxError, PersistenceError, RefreshError, SendError, ServingStartError, SetTxNoteError,
    StakeInError,
};
use shekyl_engine_file::WalletFileError;
use shekyl_engine_state::{SetNoteError, TxNoteTooLong};
use shekyl_rpc_client::{RejectCause, SubmitVerdict};
use thiserror::Error;

/// The Foundation CompleteTree terms, stated to the operator on the path
/// that would take them on (`COMPLETETREE_ACTIVATION.md` §5, approved
/// verbatim — **a defect in this text is a finding for the round record,
/// never an edit here**).
///
/// # One text, two surfaces, and a gate that keeps them one
///
/// This constant is the body of [`WalletRpcError::StakeFoundationUnacknowledged`]
/// (`-29506`) and what the CLI prints before it will accept the typed
/// phrase. Both read *this*; neither keeps a copy. The contract carries the
/// same words in `docs/api/wallet_rpc.yaml`, and
/// `foundation_warning_matches_the_published_contract` compares the two
/// whitespace-normalized — so a wording change that lands in only one of
/// them fails the suite instead of leaving a client implementer reading
/// terms the server no longer states.
///
/// It is deliberately not a `format!` with substituted numbers: every
/// figure it could have interpolated (a bond floor, a disk estimate) would
/// be a second thing to keep true, and the terms that matter here are
/// structural — never earns, grows forever, slash side live — not
/// numeric.
pub const FOUNDATION_POSTURE_WARNING: &str = "\
Foundation CompleteTree posture — read before confirming.
This bond declares your node a whole-corpus archival backstop. It is not a staking product:
1. It never earns. CompleteTree holdings are excluded from the reward market by holdings shape, permanently. This is not a phase or a promotion path.
2. The obligation grows forever. You commit to storing and serving every frozen shard the chain ever produces. Disk consumption is unbounded and monotone. Your drive space is your commitment.
3. The penalty side is fully live. You are challenged like any archiver, over the entire frozen corpus. Missed service inside the tolerance window is absorbed; crossing it slashes your collateral, clears your holdings, and demotes this record to an ordinary market position. Reinstatement from there is as a market participant. Returning to CompleteTree posture requires a fresh foundation bond under a new persona.
4. Capital is locked at zero yield. The bond floor is nominal, but it is collateral against the largest possible obligation.
5. Durability credit is genesis-gated. Unless your identity is in the genesis foundation enumeration, this node also receives no durability_count credit — it is a pure donation to the network. Donations are welcome and genuinely valuable; they are simply not compensated.
To proceed, confirm that you are choosing a non-earning, unbounded-storage service posture.
CLI: type exactly: `serve without reward` — RPC: set `acknowledge_non_earning_unbounded: true`.";

/// Allocated application / protocol error codes (spec enum).
///
/// Emitting a code outside this set is a conformance failure. RESERVED-range
/// codes land in the sub-PR that implements their method (rule 21).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum WalletRpcErrorCode {
    /// JSON-RPC parse error.
    ParseError = -32700,
    /// JSON-RPC invalid request.
    InvalidRequest = -32600,
    /// JSON-RPC method not found (also covers RESERVED / not-yet-implemented).
    MethodNotFound = -32601,
    /// JSON-RPC invalid params.
    InvalidParams = -32602,
    /// JSON-RPC internal error.
    InternalError = -32603,
    /// A wallet is already open; close first.
    WalletAlreadyOpen = -29000,
    /// No wallet is open.
    WalletNotOpen = -29001,
    /// Create refused: wallet file already exists.
    WalletFileExists = -29002,
    /// Open failed: no such wallet file.
    WalletFileNotFound = -29003,
    /// Open / change_password: MAC / password failure.
    InvalidPassword = -29004,
    /// Operation requires a capability the open wallet lacks.
    CapabilityForbids = -29005,
    /// The open wallet's session has ended (its key actor stopped and the
    /// key material is wiped); close and reopen the wallet, then retry.
    WalletSessionEnded = -29006,
    /// Build: address parse / network check failed.
    InvalidRecipient = -29100,
    /// Build: spendable balance too low.
    InsufficientFunds = -29101,
    /// Build: daemon fee query failed.
    FeeEstimationFailed = -29102,
    /// Submit: unknown / expired reservation handle.
    ReservationNotFound = -29103,
    /// Submit: reorg raced the reservation.
    SnapshotInvalidated = -29104,
    /// Submit: `seen_gen` ≠ `content_gen` (CT-5d).
    ContentGenMismatch = -29105,
    /// Submit: definite daemon rejection.
    SubmitRejected = -29106,
    /// Submit: transport-level ambiguity.
    SubmitAmbiguous = -29107,
    /// `abandon_tx`: the send's state forbids abandoning (`CONFIRMED`
    /// is on chain; `FAILED` was never relayed). A state conflict, not
    /// a bad request — refresh the view and re-decide.
    AbandonStateForbids = -29108,
    /// Build / fee quote: the daemon's fee snapshot failed
    /// well-formedness (non-monotonic tier band, or a tier above the
    /// absolute per-weight cap). The daemon *answered*; the wallet
    /// refused what it said — distinct from `-29102`'s "the fee query
    /// itself failed" (rule 82).
    DaemonFeeUnreasonable = -29109,
    /// Refresh: single-flight violation.
    RefreshInProgress = -29200,
    /// Refresh / rescan / proofs: daemon RPC failed.
    ///
    /// For `rescan_blockchain` only the **preflight** refusal uses this code
    /// (wallet untouched). A scan that fails *after* the reset is durable
    /// emits [`Self::RescanIncomplete`] instead — same daemon class of
    /// failure, opposite durability claim.
    DaemonUnreachable = -29201,
    /// Rescan: refused — transactions in flight whose spend record a chain
    /// replay cannot rebuild. A resolvable state conflict, not a bad request.
    RescanBlocked = -29202,
    /// Rescan: the reset persisted, then the producer failed before the
    /// ledger was rebuilt. History is empty until a rescan finishes; retry.
    RescanIncomplete = -29203,
    /// `check_*`: proof string failed decode / framing / size caps.
    ProofMalformed = -29300,
    /// `get_tx_proof` OUTBOUND: no retained per-tx secret for the txid.
    ProofTxSecretUnavailable = -29301,
    /// `get_tx_proof` INBOUND / `get_reserve_proof`: nothing to prove.
    ProofNoProvableOutputs = -29302,
    /// Proofs: a txid named by the request is unknown to the daemon.
    ProofTxNotFound = -29303,
    /// Proofs: a reserve-proof locator names a tx the daemon holds only
    /// in its pool — unconfirmed money cannot back a reserve claim.
    ProofTxUnconfirmed = -29304,
    /// `get_transfer_by_id`: no match.
    UnknownTransferId = -29400,
    /// Stake: funding not ready (W1-clean refusal — fund the persona /
    /// let the scan catch up, then retry).
    StakeNotReady = -29500,
    /// Stake: a signed bond post is already awaiting dispatch.
    StakeInFlight = -29501,
    /// Stake: the wallet already holds a confirmed bond (idempotency).
    AlreadyStaked = -29502,
    /// Stake: the wallet's persona record moved during the credentialed
    /// reopen; nothing was written — re-invoke `stake`.
    StakeRecordMoved = -29503,
    /// Stake: this session's scan recovered a staked slot; staking becomes
    /// operational at the next wallet open — close and reopen, then retry.
    StakeRecoveredPendingReopen = -29504,
    /// Stake: market staking has no shard to bond over — shard assignment
    /// is an unbuilt round (`COMPLETETREE_ACTIVATION.md` §10 item 1).
    StakeNoShardsAvailable = -29505,
    /// Stake: the foundation posture was requested without the
    /// acknowledgment; the refusal message is the warning itself (D-4).
    StakeFoundationUnacknowledged = -29506,
    /// Stake: the persona's spendable funding is fragmented across more
    /// outputs than one bond post's vin headroom carries (the consensus
    /// vin cap minus the post's own bond input). W1-clean; funding is
    /// intact — neither "fund and retry" nor an internal fault.
    StakeFundingFragmented = -29512,
    /// Drain: this wallet runs no stake engine — it is not an archival
    /// staker, and the drain path does not exist here (WI-RPC-5;
    /// `stake_in`'s equivalent refusal is `-29500`).
    DrainNotStaker = -29507,
    /// Drain: the wallet is a staker but no persona is currently active.
    /// The façade resolves the LIVE active persona from actor state — there
    /// is no `p_slot` parameter to point elsewhere.
    DrainNoActivePersona = -29508,
    /// Drain: a live-persona drain would spend the pool below
    /// `EXIT_FEE_RESERVE_ATOMIC` (DS-4). Lower the payment or retire first.
    DrainReserveBreached = -29509,
    /// Drain: no submittable curve-tree reference can be anchored yet —
    /// transient; sync and retry. (The *read* method reports syncing as a
    /// result discriminant, not this code; this fires on an attempted send.)
    DrainUnanchorable = -29510,
    /// Drain: the one-live-drain-per-persona seal (a pending drain exists,
    /// or a concurrent post raced this drain's inputs — retry).
    DrainInFlight = -29511,
    /// Unstake/collect: this wallet runs no stake engine — the exit lane
    /// does not exist here (the drain's `-29507` sibling; shared by both
    /// exit verbs, which are one lane).
    UnstakeNotStaker = -29513,
    /// Unstake: no persona holds a live confirmed bond and nothing is
    /// mid-exit — there is nothing to unstake.
    UnstakeNothingStaked = -29514,
    /// Unstake: the only bond activity is a confirming bond post — wait
    /// for it to confirm, then unstake.
    UnstakeBondConfirming = -29515,
    /// Unstake: an exit is already in progress (dispatched or awaiting
    /// collection) — wait, then `collect_unstaked`.
    UnstakeExitInProgress = -29516,
    /// Unstake: consensus's readiness predicates refuse the exit for now
    /// (cooldown / slash watermark / interval log); `data.detail` carries
    /// the operands that say when the refusal lifts.
    UnstakeNotReady = -29517,
    /// Unstake: the daemon holds no bond record for the resolved persona —
    /// wallet and chain disagree; resync and retry.
    UnstakeNoBondRecord = -29518,
    /// Unstake: the exit's floor fee cannot be funded from the persona pool
    /// yet — wait for outputs to mature or land.
    UnstakeNotFundable = -29519,
    /// Unstake: a transient condition (reference view syncing, or a
    /// concurrent operation raced the exit's inputs); nothing was sent —
    /// retry. `data.cause` distinguishes `"syncing"` / `"raced"`.
    UnstakeRetryTransient = -29520,
    /// Unstake: the daemon refused the exit with a definite first-send
    /// verdict and the sealed record was RELEASED — nothing propagated;
    /// address the named refusal and retry at will.
    UnstakeRefusedReleased = -29521,
    /// Unstake: the exit's network fate is unknown (or retryable-refused);
    /// its sealed record is HELD funds-safe and the one-live-exit lane
    /// stays shut until it settles or the recovery slice disposes of it.
    /// Do NOT retry blindly; the stall alarm names the record.
    UnstakeFateUnknown = -29522,
    /// Collect: no confirmed exit awaits collection — unstake first, or
    /// wait for the exit to confirm and be observed.
    CollectNoExit = -29523,
    /// Collect: the released collateral is not spendable yet — wait for
    /// maturity and retry.
    CollectNotSpendableYet = -29524,
    /// Collect: the remaining residue cannot fund the fee plus a payable
    /// amount (the 2-atomic-unit two-output split floor) — the named dust
    /// residual; it stays in the persona's pool.
    CollectDustRemainder = -29525,
    /// Collect: a sweep pass is already in flight for this persona (or a
    /// concurrent operation raced this pass's inputs — `data.cause`).
    CollectPassInFlight = -29526,
    /// Collect: no submittable curve-tree reference can be anchored yet —
    /// transient; sync and retry.
    CollectSyncing = -29527,
    /// Unstake: the exit's record fetch rides the wallet's OWN node on
    /// loopback only (the local transport posture; remote posture for the
    /// exit lands with posture selection, DQ-T2.3) — this server's daemon
    /// address is not loopback. Operator-actionable configuration, never an
    /// internal fault.
    UnstakeLocalNodeRequired = -29528,
    /// Collect: a daemon query needed to prepare the sweep failed (the
    /// dispatch-tip clock read) before anything was sealed — the daemon is
    /// unreachable, not the wallet out of sync (`-29527`) nor an internal
    /// fault (`-32603`). Check the daemon and retry.
    CollectDaemonUnreachable = -29529,
    /// `verify_message`: well-formed, intact, and **not** a valid signature
    /// by the claimed address over this message on this network. An answer,
    /// not a fault (SM-R-6).
    MessageSigVerifyFailed = -29800,
    /// `verify_message`: the armored string's checksum does not match — the
    /// paste was corrupted in transit. Distinct from
    /// [`Self::MessageSigVerifyFailed`] by ruling (rule 82): "your copy is
    /// damaged" and "not from that address" are different sentences.
    MessageSigCorrupted = -29801,
    /// `verify_message`: the scheme byte names a signature scheme this
    /// build does not implement (SM-R-5's append-only forward-compat
    /// field) — "this wallet is too old to check it", not "malformed".
    MessageSigUnsupportedScheme = -29802,
    /// Server: wallet-dir tenancy unavailable.
    TenantUnavailable = -29900,
}

impl WalletRpcErrorCode {
    /// Stable numeric code for the JSON-RPC `error.code` field.
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

/// Unified RPC-boundary error. Domain errors from `shekyl-engine-core`
/// convert into this enum at the lifecycle / send boundary.
#[derive(Debug, Error)]
pub enum WalletRpcError {
    /// JSON body could not be parsed.
    #[error("parse error")]
    ParseError,
    /// Request failed JSON-RPC 2.0 structural checks.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// Method name is unknown, RESERVED, or not yet implemented.
    #[error("method not found: {0}")]
    MethodNotFound(String),
    /// Params failed schema / type checks.
    #[error("invalid params: {0}")]
    InvalidParams(String),
    /// Unexpected internal failure.
    #[error("internal error: {0}")]
    InternalError(String),
    /// HTTP basic auth failed or was missing when required.
    #[error("unauthorized")]
    Unauthorized,
    /// A wallet is already open on this tenant.
    #[error("wallet already open")]
    WalletAlreadyOpen,
    /// No wallet is open on this tenant.
    #[error("wallet not open")]
    WalletNotOpen,
    /// Create refused: keys file already exists.
    #[error("wallet file exists")]
    WalletFileExists,
    /// Open failed: keys file not found.
    #[error("wallet file not found")]
    WalletFileNotFound,
    /// Open / change_password: wrong password (or corrupt envelope).
    #[error("invalid password")]
    InvalidPassword,
    /// Operation requires a capability the open wallet lacks.
    #[error("capability forbids this operation")]
    CapabilityForbids {
        /// OpenAPI capability mode string (`FULL` / `VIEW_ONLY` / …).
        capability: String,
    },
    /// The open wallet's session has ended: its key actor stopped and the
    /// key blob is already zeroized, so **no retry inside this session can
    /// succeed**. Terminal-with-remedy, its own code rather than `-32603`
    /// because the user action differs from every other internal failure —
    /// close and reopen the wallet, then retry (rule 82; the same ruling
    /// that gives the stake path's pending-reopen state `-29504`).
    /// Currently emitted by `sign_message`; any future method that needs
    /// the live key actor maps its stopped-actor failure here too.
    #[error("wallet session ended — close and reopen the wallet, then retry")]
    WalletSessionEnded,
    /// Daemon RPC unreachable / failed.
    #[error("daemon unreachable")]
    DaemonUnreachable,
    /// Refresh already in flight (single-flight).
    #[error("refresh already running")]
    RefreshInProgress,
    /// Rescan refused: outstanding pending-tx reservations (consumer-held
    /// or in-flight) hold in-memory output locks into transfer rows the
    /// reset would destroy. Transient and client-resolvable — submit or
    /// discard the reservations, then retry. Unconfirmed *submitted* txs
    /// no longer refuse (send-journal re-derivation; PR-SJ-1).
    #[error(
        "cannot rescan while pending-tx reservations are held: {detail}; \
         submit or discard pending reservations, then retry"
    )]
    RescanBlocked {
        /// Server-side counts (`error.data.detail`) — no amounts, no txids.
        detail: String,
    },
    /// Rescan reset is durable but the subsequent scan failed. History is
    /// empty until a rescan finishes; the wallet is re-runnable.
    #[error(
        "rescan reset completed but the scan failed; history is empty until a \
         rescan finishes — retry once the problem is resolved"
    )]
    RescanIncomplete,
    /// Build: address parse / network check failed.
    #[error("invalid recipient")]
    InvalidRecipient,
    /// Build: spendable balance too low.
    #[error("insufficient funds")]
    InsufficientFunds,
    /// Build: daemon fee query failed.
    #[error("fee estimation failed")]
    FeeEstimationFailed,
    /// Build / quote (`-29109`): the daemon's fee snapshot was refused
    /// as ill-formed (non-monotonic or over the absolute cap). `data`
    /// carries the numeric facts; the message stays category-only.
    #[error("daemon fee estimate refused by the wallet's sanity ceiling ({reason})")]
    DaemonFeeUnreasonable {
        /// Which interim check refused (engine-supplied static string).
        reason: &'static str,
        /// Offending per-weight rate (atomic units).
        rate: u64,
        /// The violated bound (atomic units per weight).
        bound: u64,
    },
    /// Submit: unknown / expired reservation handle.
    #[error("reservation not found")]
    ReservationNotFound,
    /// Submit: reorg raced the reservation.
    #[error("snapshot invalidated")]
    SnapshotInvalidated,
    /// Submit: `seen_gen` ≠ `content_gen` (CT-5d).
    #[error("content generation mismatch")]
    ContentGenMismatch {
        /// Current content generation the client must re-confirm.
        content_gen: u64,
    },
    /// Submit: definite daemon rejection.
    #[error("submit rejected")]
    SubmitRejected {
        /// OpenAPI `error.data`: serde-tagged [`SubmitVerdict`] projection.
        data: Value,
    },
    /// Submit: transport-level ambiguity.
    #[error("submit ambiguous")]
    SubmitAmbiguous,
    /// `abandon_tx`: the send's current state forbids abandoning.
    /// `state` is the projected [`TransferState`](crate::types::TransferState) so the client hears
    /// the same vocabulary `get_transfers` speaks.
    #[error("cannot abandon: the send is {state}")]
    AbandonStateForbids {
        /// Projected [`TransferState`](crate::types::TransferState) of the refusing row.
        state: crate::types::TransferState,
    },
    /// `check_*`: proof string failed Bech32m decode, carried the wrong
    /// HRP, its wire framing did not parse, or it exceeds the section's
    /// size caps. The client message is deliberately stable and
    /// detail-free — the framing detail can echo client-controlled bytes
    /// (the HRP) and is logged server-side at the mapping site instead.
    #[error("proof string malformed")]
    ProofMalformed,
    /// `get_tx_proof` OUTBOUND: this wallet holds no retained per-tx
    /// secret for the txid (it did not send the tx, or another copy did).
    #[error("no retained tx secret for this transaction")]
    ProofTxSecretUnavailable,
    /// `get_tx_proof` INBOUND with no owned outputs in the tx, or
    /// `get_reserve_proof` with zero eligible outputs / unspent total
    /// below the requested amount.
    #[error("no provable outputs")]
    ProofNoProvableOutputs,
    /// Proofs: a txid named by the request (or embedded in a reserve
    /// proof's locators) is unknown to the daemon.
    #[error("transaction not found")]
    ProofTxNotFound,
    /// Proofs: a reserve-proof locator names an unconfirmed (pooled) tx.
    #[error("transaction is unconfirmed")]
    ProofTxUnconfirmed,
    /// `get_transfer_by_id`: no match.
    #[error("unknown transfer id")]
    UnknownTransferId,
    /// Stake: funding not ready — a W1-clean refusal (nothing durable was
    /// written): fund the persona and/or wait for the wallet's persona scan
    /// to catch up, then call `stake` again.
    #[error("stake not ready: fund the wallet's staking balance and retry once synced")]
    StakeNotReady {
        /// Server-side detail (`error.data.detail`) — operational cause, no
        /// secrets or amounts.
        detail: String,
    },
    /// Stake: a signed bond post is already sealed and awaiting its
    /// scheduled broadcast; no action needed.
    #[error("stake already in flight: the bond will broadcast at its scheduled time")]
    StakeInFlight,
    /// Stake: the persona's spendable funding is fragmented across more
    /// outputs than one bond post can carry (W1-clean; the funding is
    /// intact). Carries the public headroom constant, never the wallet's
    /// record count.
    #[error(
        "stake refused: persona funding is fragmented across more than {max} spendable          outputs — more than one bond post can carry; avoid splitting persona funding          across more than {max} stake_in transfers"
    )]
    StakeFundingFragmented {
        /// The per-transaction funding-input headroom (public constant).
        max: usize,
    },
    /// Stake: the wallet already staked (a confirmed bond exists).
    #[error("already staking")]
    AlreadyStaked,
    /// Stake: the wallet's own persona record advanced between the request
    /// and the credentialed reopen, so the slot chosen before it is stale.
    ///
    /// Two SP-R0 open-time reconcile outcomes reach this code:
    /// - **arm #3 (phantom GC)** collected the slot the request had picked,
    ///   while other bonded slots survive;
    /// - **arm #2 (retired burn)** advanced the monotone cursor past the
    ///   pre-read value.
    ///
    /// **Arm #4 adoption does NOT reach this code**, and the distinction is
    /// load-bearing: adoption re-arms `staking_enabled` and puts a slot with a
    /// matching bond post into `bonded_slots`, so `first_stake`'s
    /// already-staked scan fires first and the answer is
    /// [`Self::AlreadyStaked`] (`-29502`) — which is the correct one, since the
    /// wallet just proved it holds a confirmed bond. Do not "fix" that
    /// precedence.
    ///
    /// A **domain** refusal, not a fault: nothing durable was written and a
    /// plain re-invoke picks up the reconciled record. Deliberately carries
    /// no slot index — persona numbering is wallet-internal (rule 81) and
    /// the operator's remedy does not depend on it.
    #[error("staking record changed while opening; nothing was written — call stake again")]
    StakeRecordMoved,

    /// `stake` (`-29504`): the wallet's scan recovered a previously-staked
    /// slot **this session** (the from-seed bond watch), and a recovered
    /// slot becomes operational only when the wallet is next opened — the
    /// keys it needs are derived at open, never mid-session. A **domain**
    /// refusal with a self-contained remedy (rule 82): close and reopen the
    /// wallet, then retry; no protocol knowledge required (rule 81).
    #[error(
        "staking was recovered during this session's scan; close and reopen \
         the wallet to finish recovery, then retry"
    )]
    StakeRecoveredPendingReopen,

    /// `stake` (`-29505`): market staking bonds over an **assigned** shard
    /// subset, and the assignment mechanism is its own unbuilt round — so
    /// there is nothing for a market bond to cover yet. A domain refusal
    /// with a named remedy, kept off `-29500` because "fund and retry" is
    /// the wrong instruction for a wallet whose funding is fine (rule 82).
    /// Nothing durable was written.
    #[error(
        "market staking assigns a shard automatically, and shard assignment \
         is not available yet; nothing was written"
    )]
    StakeNoShardsAvailable,

    /// `stake` (`-29506`): posture `foundation_complete_tree` was requested
    /// without `acknowledge_non_earning_unbounded`.
    ///
    /// **The message is the warning** ([`FOUNDATION_POSTURE_WARNING`]), not
    /// a pointer to it. That is D-4's whole mechanism: the terms of an
    /// unbounded, non-earning, slash-exposed obligation reach the operator
    /// on the path that would have taken it on, and a third-party wrapper
    /// that wants to skip them has to echo an acknowledgment it was handed
    /// rather than simply omit a field. Nothing was written.
    #[error("{}", FOUNDATION_POSTURE_WARNING)]
    StakeFoundationUnacknowledged,

    /// `drain` (`-29507`): this wallet runs no stake engine — the drain
    /// path does not exist here. Permanent for this wallet, not transient
    /// (rule 82: "you are not a staker" is a different sentence from
    /// "fund and retry", which is why `stake_in`'s no-persona refusal
    /// stays on `-29500` while this one gets its own code).
    #[error("this wallet is not a staker: there is no staking balance to drain")]
    DrainNotStaker,
    /// `drain` (`-29508`): the wallet is a staker but no persona is
    /// currently active — nothing for a drain to act on. The Engine façade
    /// resolved the live active persona from actor state (no slot
    /// parameter exists to point elsewhere) and found none.
    #[error("no active staking persona to drain")]
    DrainNoActivePersona,
    /// `drain` (`-29509`): the payment would spend a **live** persona's
    /// pool below the exit-fee reserve (DS-4). Sweep-to-zero is only for a
    /// retired persona, which this method cannot select — lower the
    /// payment. Deliberately amount-free: the reserve constant and the
    /// shortfall stay off the wire.
    #[error(
        "drain refused: the requested amount would leave the staking pool \
         below its exit-fee reserve — lower the amount"
    )]
    DrainReserveBreached,
    /// `drain` (`-29510`): no submittable reference can be anchored yet —
    /// the wallet's staking-side view is still syncing. Transient; retry
    /// after a refresh. (The `get_drain_balance` *read* reports this as
    /// its `syncing` result arm, never as this error.)
    #[error("drain unavailable while the wallet syncs — retry after a refresh")]
    DrainUnanchorable {
        /// Server-side transient cause (`error.data.detail`) — scalar-free.
        detail: String,
    },
    /// `drain` (`-29511`): a pending drain already exists for this persona
    /// (one live drain per persona). The message deliberately promises no
    /// release trigger: releasing the seal is the drain lifecycle driver's
    /// job, and until that driver lands (FOLLOWUPS "Drain dispatch
    /// driver") the refusal persists across sessions — "wait for it to
    /// confirm" would prescribe an event that cannot yet help. Automation
    /// branches on `data.cause` (`"pending"` here vs `"raced"`), never by
    /// parsing this prose.
    #[error(
        "a drain is already in flight for this staking pool; a new drain \
         cannot start until the earlier drain's record is retired"
    )]
    DrainInFlight,
    /// `drain` (`-29511`, retry remedy): this drain's inputs stopped being
    /// current between snapshot and seal — either another live record (a bond
    /// post or an emission claim, of **any** persona) now reserves one, or a
    /// reservation was released mid-assembly. Nothing was sealed either way.
    /// Same code as [`Self::DrainInFlight`] (the
    /// one-live-drain seal is the shared cause class); the message carries
    /// the different remedy — plain retry — and `data.cause` (`"raced"`)
    /// carries it structurally, so a client that hardcodes one behavior
    /// per numeric code is not forced to spin against the seal or abandon
    /// a retryable race.
    #[error(
        "a concurrent staking operation changed this drain's inputs; \
         nothing was sent — retry"
    )]
    DrainInputRaced,

    /// `unstake`/`collect_unstaked` (`-29513`): no stake engine runs here.
    #[error("this wallet is not a staker: no stake engine is running")]
    UnstakeNotStaker,
    /// `unstake` (`-29514`): nothing is staked.
    #[error("nothing is staked: no persona holds a live bond")]
    UnstakeNothingStaked,
    /// `unstake` (`-29515`): the bond post is still confirming.
    #[error(
        "your stake is still confirming: a bond post is in flight — wait for \
         it to confirm, then unstake"
    )]
    UnstakeBondConfirming,
    /// `unstake` (`-29516`): an exit is already in progress.
    #[error(
        "an exit is already in progress — wait for it to confirm, then \
         collect the released collateral with collect_unstaked"
    )]
    UnstakeExitInProgress,
    /// `unstake` (`-29517`): consensus readiness refuses for now;
    /// `data.detail` carries the predicate's own operands (when it lifts).
    #[error("the exit is not ready yet — see data.detail for when it lifts")]
    UnstakeNotReady {
        /// The readiness predicate's own rendering.
        detail: String,
    },
    /// `unstake` (`-29518`): the daemon holds no bond record.
    #[error(
        "the daemon holds no bond record for this persona — the wallet and \
         chain disagree; resync and retry"
    )]
    UnstakeNoBondRecord,
    /// `unstake` (`-29519`): the exit fee cannot be funded from the pool yet.
    #[error("the exit cannot be funded from the persona pool yet — see data.detail")]
    UnstakeNotFundable {
        /// The assembly's own reason.
        detail: String,
    },
    /// `unstake` (`-29520`): transient — retry. `data.cause` says which.
    #[error("a transient condition refused the exit; nothing was sent — retry")]
    UnstakeRetryTransient {
        /// `"syncing"` or `"raced"`.
        cause: &'static str,
        /// The refusing stage's own rendering.
        detail: String,
    },
    /// `unstake` (`-29521`): definite refusal, seal released — retry at will
    /// after addressing `data.detail`.
    #[error("the daemon refused the exit and nothing was sent — see data.detail, then retry")]
    UnstakeRefusedReleased {
        /// The daemon's verdict rendering.
        detail: String,
    },
    /// `unstake` (`-29522`): fate unknown; sealed record held funds-safe.
    #[error(
        "the exit's network fate is unknown; its record is held funds-safe \
         and the exit lane stays shut until it settles — do not retry blindly"
    )]
    UnstakeFateUnknown {
        /// The transport/verdict rendering.
        detail: String,
    },
    /// `collect_unstaked` (`-29523`): nothing awaits collection.
    #[error(
        "no confirmed exit awaits collection — unstake first, or wait for \
         the exit to confirm and the wallet to observe it"
    )]
    CollectNoExit,
    /// `collect_unstaked` (`-29524`): not spendable yet — wait for maturity.
    #[error("the released collateral is not spendable yet — wait for maturity and retry")]
    CollectNotSpendableYet,
    /// `collect_unstaked` (`-29525`): the dust residual, named (scalar-free).
    #[error(
        "the remaining residue is too small to move (it cannot fund the fee \
         plus a payable amount); it stays in the persona's pool"
    )]
    CollectDustRemainder,
    /// `collect_unstaked` (`-29526`): one live pass per persona (or the
    /// pass's inputs raced — `data.cause`, the `-29511` precedent).
    #[error("a sweep pass is already in flight for this persona; wait for it to settle")]
    CollectPassInFlight,
    /// `collect_unstaked` (`-29526`, retry remedy): inputs raced — retry.
    #[error(
        "a concurrent staking operation changed this pass's inputs; nothing \
         was sent — retry"
    )]
    CollectInputRaced,
    /// `collect_unstaked` (`-29527`): reference view syncing — retry later.
    #[error("no submittable reference can be anchored yet — sync and retry")]
    CollectSyncing {
        /// The anchoring helper's own (scalar-free) reason.
        detail: String,
    },
    /// `collect_unstaked` (`-29529`): a daemon query needed to prepare the
    /// sweep failed before sealing — the daemon is unreachable; check it and
    /// retry.
    #[error("the daemon could not be reached to prepare the sweep — check the daemon and retry")]
    CollectDaemonUnreachable {
        /// Which daemon query failed, and the transport's own reason.
        detail: String,
    },
    /// `unstake` (`-29528`): the exit lane needs the wallet's own loopback
    /// node; this server points at a non-loopback daemon.
    #[error(
        "unstake needs this wallet's own node: the exit's record fetch runs \
         over loopback only — point the wallet server's daemon address at a \
         local node (remote-daemon support for the exit arrives with \
         transport-posture selection)"
    )]
    UnstakeLocalNodeRequired {
        /// The transport constructor's own refusal.
        detail: String,
    },

    /// `verify_message` (`-29800`): the signature is well-formed and intact
    /// but does not verify for that address, message, and network. This is
    /// the method's honest negative *answer* (SM-R-6), carried as its own
    /// code so automated clients can branch on it without string-matching.
    #[error("signature does not verify for this address and message")]
    MessageSigVerifyFailed,
    /// `verify_message` (`-29801`): checksum mismatch — the pasted string
    /// was damaged in transit. The remedy is "re-copy the signature", which
    /// is why it must never be conflated with
    /// [`Self::MessageSigVerifyFailed`] (rule 82).
    #[error("signature string corrupted — re-copy it and try again")]
    MessageSigCorrupted,
    /// `verify_message` (`-29802`): the scheme byte is not one this build
    /// implements. `data.scheme` carries the byte (public wire data) so a
    /// client can report which scheme its wallet is missing.
    #[error("unsupported signature scheme — this wallet is too old to check it")]
    MessageSigUnsupportedScheme {
        /// The unrecognized scheme byte from the decoded canonical header.
        scheme: u8,
    },
}

impl WalletRpcError {
    /// Map to the allocated JSON-RPC error code.
    pub fn code(&self) -> WalletRpcErrorCode {
        match self {
            Self::ParseError => WalletRpcErrorCode::ParseError,
            Self::InvalidRequest(_) | Self::Unauthorized => WalletRpcErrorCode::InvalidRequest,
            Self::MethodNotFound(_) => WalletRpcErrorCode::MethodNotFound,
            Self::InvalidParams(_) => WalletRpcErrorCode::InvalidParams,
            Self::InternalError(_) => WalletRpcErrorCode::InternalError,
            Self::WalletAlreadyOpen => WalletRpcErrorCode::WalletAlreadyOpen,
            Self::WalletNotOpen => WalletRpcErrorCode::WalletNotOpen,
            Self::WalletFileExists => WalletRpcErrorCode::WalletFileExists,
            Self::WalletFileNotFound => WalletRpcErrorCode::WalletFileNotFound,
            Self::InvalidPassword => WalletRpcErrorCode::InvalidPassword,
            Self::CapabilityForbids { .. } => WalletRpcErrorCode::CapabilityForbids,
            Self::WalletSessionEnded => WalletRpcErrorCode::WalletSessionEnded,
            Self::DaemonUnreachable => WalletRpcErrorCode::DaemonUnreachable,
            Self::RefreshInProgress => WalletRpcErrorCode::RefreshInProgress,
            Self::RescanBlocked { .. } => WalletRpcErrorCode::RescanBlocked,
            Self::RescanIncomplete => WalletRpcErrorCode::RescanIncomplete,
            Self::InvalidRecipient => WalletRpcErrorCode::InvalidRecipient,
            Self::InsufficientFunds => WalletRpcErrorCode::InsufficientFunds,
            Self::FeeEstimationFailed => WalletRpcErrorCode::FeeEstimationFailed,
            Self::DaemonFeeUnreasonable { .. } => WalletRpcErrorCode::DaemonFeeUnreasonable,
            Self::ReservationNotFound => WalletRpcErrorCode::ReservationNotFound,
            Self::SnapshotInvalidated => WalletRpcErrorCode::SnapshotInvalidated,
            Self::ContentGenMismatch { .. } => WalletRpcErrorCode::ContentGenMismatch,
            Self::SubmitRejected { .. } => WalletRpcErrorCode::SubmitRejected,
            Self::SubmitAmbiguous => WalletRpcErrorCode::SubmitAmbiguous,
            Self::AbandonStateForbids { .. } => WalletRpcErrorCode::AbandonStateForbids,
            Self::ProofMalformed => WalletRpcErrorCode::ProofMalformed,
            Self::ProofTxSecretUnavailable => WalletRpcErrorCode::ProofTxSecretUnavailable,
            Self::ProofNoProvableOutputs => WalletRpcErrorCode::ProofNoProvableOutputs,
            Self::ProofTxNotFound => WalletRpcErrorCode::ProofTxNotFound,
            Self::ProofTxUnconfirmed => WalletRpcErrorCode::ProofTxUnconfirmed,
            Self::UnknownTransferId => WalletRpcErrorCode::UnknownTransferId,
            Self::StakeNotReady { .. } => WalletRpcErrorCode::StakeNotReady,
            Self::StakeInFlight => WalletRpcErrorCode::StakeInFlight,
            Self::StakeFundingFragmented { .. } => WalletRpcErrorCode::StakeFundingFragmented,
            Self::AlreadyStaked => WalletRpcErrorCode::AlreadyStaked,
            Self::StakeRecordMoved => WalletRpcErrorCode::StakeRecordMoved,
            Self::StakeRecoveredPendingReopen => WalletRpcErrorCode::StakeRecoveredPendingReopen,
            Self::StakeNoShardsAvailable => WalletRpcErrorCode::StakeNoShardsAvailable,
            Self::StakeFoundationUnacknowledged => {
                WalletRpcErrorCode::StakeFoundationUnacknowledged
            }
            Self::DrainNotStaker => WalletRpcErrorCode::DrainNotStaker,
            Self::DrainNoActivePersona => WalletRpcErrorCode::DrainNoActivePersona,
            Self::DrainReserveBreached => WalletRpcErrorCode::DrainReserveBreached,
            Self::DrainUnanchorable { .. } => WalletRpcErrorCode::DrainUnanchorable,
            Self::DrainInFlight | Self::DrainInputRaced => WalletRpcErrorCode::DrainInFlight,
            Self::UnstakeNotStaker => WalletRpcErrorCode::UnstakeNotStaker,
            Self::UnstakeNothingStaked => WalletRpcErrorCode::UnstakeNothingStaked,
            Self::UnstakeBondConfirming => WalletRpcErrorCode::UnstakeBondConfirming,
            Self::UnstakeExitInProgress => WalletRpcErrorCode::UnstakeExitInProgress,
            Self::UnstakeNotReady { .. } => WalletRpcErrorCode::UnstakeNotReady,
            Self::UnstakeNoBondRecord => WalletRpcErrorCode::UnstakeNoBondRecord,
            Self::UnstakeNotFundable { .. } => WalletRpcErrorCode::UnstakeNotFundable,
            Self::UnstakeRetryTransient { .. } => WalletRpcErrorCode::UnstakeRetryTransient,
            Self::UnstakeRefusedReleased { .. } => WalletRpcErrorCode::UnstakeRefusedReleased,
            Self::UnstakeFateUnknown { .. } => WalletRpcErrorCode::UnstakeFateUnknown,
            Self::CollectNoExit => WalletRpcErrorCode::CollectNoExit,
            Self::CollectNotSpendableYet => WalletRpcErrorCode::CollectNotSpendableYet,
            Self::CollectDustRemainder => WalletRpcErrorCode::CollectDustRemainder,
            Self::CollectPassInFlight | Self::CollectInputRaced => {
                WalletRpcErrorCode::CollectPassInFlight
            }
            Self::CollectSyncing { .. } => WalletRpcErrorCode::CollectSyncing,
            Self::CollectDaemonUnreachable { .. } => WalletRpcErrorCode::CollectDaemonUnreachable,
            Self::UnstakeLocalNodeRequired { .. } => WalletRpcErrorCode::UnstakeLocalNodeRequired,
            Self::MessageSigVerifyFailed => WalletRpcErrorCode::MessageSigVerifyFailed,
            Self::MessageSigCorrupted => WalletRpcErrorCode::MessageSigCorrupted,
            Self::MessageSigUnsupportedScheme { .. } => {
                WalletRpcErrorCode::MessageSigUnsupportedScheme
            }
        }
    }

    /// Human-readable message. Never carries secrets, counterparty
    /// addresses, or amounts (spec: error text is the most-logged surface).
    pub fn message(&self) -> String {
        self.to_string()
    }

    /// Optional structured `error.data` object.
    pub fn data(&self) -> Option<Value> {
        match self {
            Self::CapabilityForbids { capability } => Some(json!({ "capability": capability })),
            Self::AbandonStateForbids { state } => Some(json!({ "state": state.as_str() })),
            Self::ContentGenMismatch { content_gen } => Some(json!({ "content_gen": content_gen })),
            Self::SubmitRejected { data } => Some(data.clone()),
            Self::StakeNotReady { detail }
            | Self::RescanBlocked { detail }
            | Self::DrainUnanchorable { detail }
            | Self::UnstakeNotReady { detail }
            | Self::UnstakeNotFundable { detail }
            | Self::UnstakeRefusedReleased { detail }
            | Self::UnstakeFateUnknown { detail }
            | Self::CollectSyncing { detail }
            | Self::CollectDaemonUnreachable { detail }
            | Self::UnstakeLocalNodeRequired { detail } => Some(json!({ "detail": detail })),
            // The `-29511` pair shares one code with two remedies; the
            // structured discriminant is what lets automation branch
            // wait-vs-retry without parsing prose (the -29500 `data.detail`
            // precedent, F-2).
            Self::DrainInFlight | Self::CollectPassInFlight => Some(json!({ "cause": "pending" })),
            Self::DrainInputRaced | Self::CollectInputRaced => Some(json!({ "cause": "raced" })),
            Self::UnstakeRetryTransient { cause, detail } => {
                Some(json!({ "cause": cause, "detail": detail }))
            }
            Self::MessageSigUnsupportedScheme { scheme } => Some(json!({ "scheme": scheme })),
            Self::DaemonFeeUnreasonable {
                reason,
                rate,
                bound,
            } => Some(json!({ "reason": reason, "rate": rate, "bound": bound })),
            _ => None,
        }
    }

    fn submit_rejected(cause: RejectCause) -> Self {
        let verdict = SubmitVerdict::Rejected { cause };
        let data = serde_json::to_value(verdict)
            .unwrap_or_else(|_| json!({ "verdict": "rejected", "cause": "unrecognized" }));
        Self::SubmitRejected { data }
    }

    /// Map a producer failure that arrives **after** `start_rescan` returned
    /// a handle — i.e. after the reset is durable.
    ///
    /// The durability claim is the load-bearing axis, not the failure class:
    /// `-29201` means "wallet untouched" (preflight only); every join-path
    /// failure means history is empty until a rescan finishes, so they all
    /// emit [`WalletRpcErrorCode::RescanIncomplete`]. Mapping only Io /
    /// Cancelled / Malformed / CurveTree and leaving ConcurrentMutation /
    /// InternalInvariantViolation to `-32603` was the same bug class as
    /// reusing `-29201` — clients that branch on the durability code would
    /// miss an incomplete rescan. Exhaustive match (no catch-all): a new
    /// [`RefreshError`] variant fails to compile here until its durability
    /// claim is named.
    pub(crate) fn from_rescan_scan_failure(err: RefreshError) -> Self {
        match &err {
            // Start-only refusals — unreachable on the join path. Preserve
            // their codes if they appear rather than inventing a third story.
            RefreshError::AlreadyRunning
            | RefreshError::RescanBlocked { .. }
            | RefreshError::RescanPersist(_) => err.into(),

            // Every producer failure after a durable reset: one wire code so
            // durability-branching clients cannot miss a subclass. Detail
            // stays server-side (`message()` contract / rule 30).
            RefreshError::Io(io) => {
                tracing::warn!(detail = %io, "rescan scan failed after durable reset");
                Self::RescanIncomplete
            }
            RefreshError::Cancelled
            | RefreshError::MalformedScanResult { .. }
            | RefreshError::CurveTreeIngest { .. }
            | RefreshError::ConcurrentMutation { .. }
            | RefreshError::InternalInvariantViolation { .. } => {
                tracing::warn!(?err, "rescan scan failed after durable reset");
                Self::RescanIncomplete
            }
        }
    }
}

impl From<OpenError> for WalletRpcError {
    fn from(err: OpenError) -> Self {
        match err {
            OpenError::IncorrectPassword => Self::InvalidPassword,
            OpenError::CapabilityMismatch { found }
            | OpenError::CapabilityNotYetImplemented { capability: found } => {
                Self::CapabilityForbids {
                    capability: crate::types::capability_mode_str(found).to_owned(),
                }
            }
            OpenError::OutstandingPendingTx { count } => {
                Self::InternalError(format!("outstanding pending transaction(s): {count}"))
            }
            OpenError::NetworkMismatch { wallet, expected } => Self::InternalError(format!(
                "network mismatch: wallet={wallet}, expected={expected}"
            )),
            OpenError::Io(IoError::WalletFile { detail }) => classify_wallet_file_detail(&detail),
            OpenError::Io(IoError::Daemon { .. }) => Self::DaemonUnreachable,
            OpenError::Io(other) => internal_detail("wallet I/O error", other),
            OpenError::Key(e) => internal_detail("wallet key error", e),
            OpenError::Persistence(e) => internal_detail("wallet persistence error", e),
        }
    }
}

impl From<ChangePasswordError> for WalletRpcError {
    fn from(err: ChangePasswordError) -> Self {
        match err {
            ChangePasswordError::RotateFailed(PersistenceError::WalletFile(
                WalletFileError::Envelope(_),
            )) => Self::InvalidPassword,
            ChangePasswordError::RotateFailed(e) => internal_detail("password rotation failed", e),
            ChangePasswordError::RotatedButPrefsFlushFailed(e) => {
                internal_detail("password rotated but preferences flush failed", e)
            }
        }
    }
}

impl From<RefreshError> for WalletRpcError {
    fn from(err: RefreshError) -> Self {
        match err {
            RefreshError::AlreadyRunning => Self::RefreshInProgress,
            // A state conflict, not a malformed request: `rescan_blockchain`
            // takes an empty params object, so the params were by definition
            // correct. `-32602` here would tell an automated client its
            // request shape is permanently wrong when the truth is "retry
            // once the in-flight transactions settle".
            RefreshError::RescanBlocked { reservations } => Self::RescanBlocked {
                detail: format!("{reservations} reservation(s)"),
            },
            // Past the point of no return for the in-memory ledger; durable
            // save may have failed. Category-only message — `detail` can
            // carry a local filesystem path (rule 30 / `message()` contract).
            RefreshError::RescanPersist(detail) => {
                internal_detail("rescan reset persistence failed", detail)
            }
            RefreshError::Io(IoError::Daemon { .. } | IoError::Scanner { .. }) => {
                Self::DaemonUnreachable
            }
            RefreshError::Io(other) => internal_detail("refresh I/O error", other),
            RefreshError::ConcurrentMutation { wallet, result } => internal_detail(
                "refresh concurrent mutation",
                format!("wallet={wallet}, result={result}"),
            ),
            RefreshError::MalformedScanResult { reason } => {
                internal_detail("malformed scan result", reason)
            }
            RefreshError::Cancelled => Self::InternalError("refresh cancelled".into()),
            RefreshError::InternalInvariantViolation { context } => {
                internal_detail("refresh invariant", context)
            }
            RefreshError::CurveTreeIngest { context, .. } => {
                internal_detail("curve-tree ingest", context)
            }
        }
    }
}

impl From<PScanStartError> for WalletRpcError {
    fn from(err: PScanStartError) -> Self {
        match err {
            // The auto-start (`start_pscan_if_staker`) guards on the stake engine
            // before spawning, and a fresh open holds a fresh single-flight slot,
            // so neither of these is reachable on the lifecycle path. Map them
            // defensively rather than panicking if a future caller hits them.
            PScanStartError::NoStakeEngine => {
                Self::InternalError("p-scan start: no stake engine".into())
            }
            // A mid-session bond-watch recovery: a domain state with a
            // user-doable remedy (reopen), never an internal fault.
            PScanStartError::RecoveredPendingReopen => Self::StakeRecoveredPendingReopen,
            PScanStartError::AlreadyRunning => {
                Self::InternalError("p-scan start: task already running".into())
            }
            // The reachable one: a corrupt / version-mismatched `.wallet.pscan`
            // (or `.wallet.pending`) seal. Fail the staker's open closed — a
            // staker whose firewall scan cannot start must not open into a state
            // where it silently is not scanning (privacy is not a degraded mode).
            //
            // The client message is deliberately stable and detail-free: the
            // boxed cause can carry a local filesystem path or internal schema
            // detail, and this string is returned over JSON-RPC. The detailed
            // cause is logged server-side at the reachable call site
            // (`lifecycle::wrap_and_start_pscan`), not handed to the client.
            PScanStartError::LoadFailed(_source) => {
                Self::InternalError("p-scan sealed state failed to load".into())
            }
        }
    }
}

impl From<ServingStartError> for WalletRpcError {
    fn from(err: ServingStartError) -> Self {
        match err {
            ServingStartError::NoStakeEngine => {
                Self::InternalError("serving start: no stake engine".into())
            }
            ServingStartError::RecoveredPendingReopen => Self::StakeRecoveredPendingReopen,
            // Reachable on the open path. The source can name a local
            // filesystem path (the derived `<P>.wallet.tor` directory);
            // that stays in the server log, not on the JSON-RPC wire.
            ServingStartError::TorConfig(_source) => {
                Self::InternalError("serving start: tor data directory is unusable".into())
            }
            ServingStartError::Identity(_source) => {
                Self::InternalError("serving start: persona identity unavailable".into())
            }
            // Reachable: a remote daemon is refused so the serve-set is
            // never derived over the principal's shared connection. The
            // source can name the refused URL; the client gets the
            // remedy, not the URL.
            ServingStartError::DaemonNotLoopback(_source) => {
                Self::InternalError("serving currently requires your own node on loopback".into())
            }
            ServingStartError::AlreadyRunning => {
                Self::InternalError("serving start: task already running".into())
            }
        }
    }
}

impl From<FeeEstimatorError> for WalletRpcError {
    fn from(err: FeeEstimatorError) -> Self {
        match err {
            FeeEstimatorError::DaemonFeeUnreasonable(v) => Self::DaemonFeeUnreasonable {
                reason: v.reason(),
                rate: v.rate(),
                bound: v.bound(),
            },
            // The caller's Custom rate is out of band: a request error,
            // -32602 — never blamed on the daemon (rule 82).
            FeeEstimatorError::CustomFeeOutOfRange(band) => {
                Self::InvalidParams(format!("custom fee rate out of range: {band}"))
            }
            _ => Self::FeeEstimationFailed,
        }
    }
}

impl From<SendError> for WalletRpcError {
    fn from(err: SendError) -> Self {
        match err {
            SendError::InvalidRecipient { .. } => Self::InvalidRecipient,
            SendError::Fee(e) => e.into(),
            SendError::InsufficientFunds { .. } => Self::InsufficientFunds,
            SendError::Io(IoError::Daemon { .. }) => Self::FeeEstimationFailed,
            SendError::Io(other) => Self::InternalError(other.to_string()),
            SendError::Tx(e) => Self::InternalError(e.to_string()),
            SendError::CannotSign { reason } => {
                Self::InternalError(format!("cannot sign: {reason}"))
            }
            SendError::SpendUnavailableRebuilding { .. } => Self::InternalError(
                "spending temporarily unavailable while membership data rebuilds".into(),
            ),
            SendError::CurveTreeUnavailable { detail } => {
                Self::InternalError(format!("curve-tree unavailable: {detail}"))
            }
            SendError::OutputNotYetSpendable { .. } => {
                Self::InternalError("output not yet spendable at the reference block".into())
            }
            SendError::WalletTooYoungToSpend { .. } => {
                Self::InternalError("wallet too young to spend".into())
            }
            SendError::SubmitLoopBreakerTripped { .. } => {
                Self::InternalError("submit loop-breaker tripped".into())
            }
        }
    }
}

impl From<StakeInError> for WalletRpcError {
    /// `stake_in` mints no new codes (WI-RPC-5 F-2 pin): the no-persona
    /// refusals reuse `-29500` (`STAKE_NOT_READY` — the remedy really is
    /// "get a funded persona, then retry"), the transfer-build failures
    /// reuse the `-291xx` send codes via the [`SendError`] mapping, and
    /// everything else is an internal fault with server-side detail.
    fn from(err: StakeInError) -> Self {
        match err {
            // The engine arm's own Display IS the wire `data.detail` (one
            // body — a hardcoded copy here drifted the moment the engine
            // rewords; the HTTP suite pins the current spelling).
            e @ (StakeInError::NotStaking | StakeInError::NoActivePersona) => Self::StakeNotReady {
                detail: e.to_string(),
            },
            // The -291xx family: recipient (unreachable here — the address
            // is engine-derived), funds, fee, and their internal residue.
            StakeInError::Send(e) => e.into(),
            StakeInError::StakeEngine(detail) => internal_detail("stake engine", detail),
            StakeInError::Address(e) => internal_detail("staking address encoding", e),
            StakeInError::RngSourceFailed(e) => {
                internal_detail("entropy source unavailable for the cover draw", e)
            }
            // The Display carries the offending amounts; category-only on
            // the wire, full detail server-side (`message()` contract).
            e @ StakeInError::CoverOverflow { .. } => {
                internal_detail("stake_in cover arithmetic overflow", e)
            }
        }
    }
}

impl From<DrainToPrincipalError> for WalletRpcError {
    /// The `drain` code table (WI-RPC-5 F-2): `-29507..-29511` for the five
    /// named drain refusals; the fee arms reuse the send path's
    /// `-29102`/`-29109` remedy split; a planner refusal of the payment
    /// itself is `-29101` (the "lower the amount / wait for accrual" remedy
    /// is exactly insufficient-funds'); a post-seal transport failure is
    /// `-29107` (the sealed record's fate is the drain driver's — the
    /// client must not re-fire blindly, which is the ambiguous contract).
    fn from(err: DrainToPrincipalError) -> Self {
        match err {
            DrainToPrincipalError::NotStaker => Self::DrainNotStaker,
            DrainToPrincipalError::NoActivePersona => Self::DrainNoActivePersona,
            DrainToPrincipalError::ReserveBreached => Self::DrainReserveBreached,
            DrainToPrincipalError::Unanchorable { detail } => Self::DrainUnanchorable { detail },
            DrainToPrincipalError::InFlight => Self::DrainInFlight,
            DrainToPrincipalError::InputRaced => Self::DrainInputRaced,
            // A zero payment is a malformed request (`-32602`), never
            // `-29101` — "lower the payment" is unsatisfiable at zero
            // (rule 82). The `drain` handler already refuses zero at its
            // params boundary, so through RPC this arm is defense in depth
            // for the façade's own pre-check and the planner's zero arm.
            DrainToPrincipalError::EmptyRequest => {
                Self::InvalidParams("the drain amount must be greater than zero".into())
            }
            DrainToPrincipalError::Refused { detail } => {
                // Scalar-free planner reason (exceeds spendable, uncoverable,
                // or needs more inputs than one drain can spend — zero has
                // its own EmptyRequest arm above); logged server-side,
                // category code on the wire.
                tracing::info!(detail = %detail, "drain payment refused by the planner");
                Self::InsufficientFunds
            }
            DrainToPrincipalError::FeeEstimate { detail } => {
                tracing::warn!(detail = %detail, "drain fee estimate failed");
                Self::FeeEstimationFailed
            }
            DrainToPrincipalError::FeeUnreasonable {
                reason,
                rate,
                bound,
            } => Self::DaemonFeeUnreasonable {
                reason,
                rate,
                bound,
            },
            DrainToPrincipalError::State { context, detail } => internal_detail(context, detail),
            DrainToPrincipalError::Submit { detail } => {
                tracing::warn!(detail = %detail, "drain dispatch failed at the choke point");
                Self::SubmitAmbiguous
            }
        }
    }
}

impl From<shekyl_engine_core::UnstakeError> for WalletRpcError {
    /// The `unstake` code table (PR-C): `-29513..-29522`, every arm named —
    /// no engine refusal falls through to `-32603` (the round-5 lesson from
    /// `-29512`). The two dispatch dispositions stay distinct because they
    /// demand opposite client behavior: `-29521` (seal released — retry at
    /// will) vs `-29522` (seal held — do not re-fire).
    fn from(err: shekyl_engine_core::UnstakeError) -> Self {
        use shekyl_engine_core::UnstakeError as E;
        match err {
            E::NotStaker => Self::UnstakeNotStaker,
            E::NothingStaked => Self::UnstakeNothingStaked,
            E::BondConfirming => Self::UnstakeBondConfirming,
            E::ExitInProgress => Self::UnstakeExitInProgress,
            E::NotReady { detail } => Self::UnstakeNotReady { detail },
            E::NoBondRecord => Self::UnstakeNoBondRecord,
            E::ExitNotFundable { detail } => Self::UnstakeNotFundable { detail },
            E::Resyncing { detail } => Self::UnstakeRetryTransient {
                cause: "syncing",
                detail,
            },
            E::InputRaced => Self::UnstakeRetryTransient {
                cause: "raced",
                detail: "a concurrent operation raced the exit's inputs".into(),
            },
            // A pre-seal daemon outage is transient like the two above, on the
            // same generic retry code with its own cause; NOT -32603.
            E::DaemonUnreachable { detail } => Self::UnstakeRetryTransient {
                cause: "daemon",
                detail,
            },
            E::FeeEstimate { detail } => {
                tracing::warn!(detail = %detail, "unstake fee estimate failed");
                Self::FeeEstimationFailed
            }
            E::FeeUnreasonable {
                reason,
                rate,
                bound,
            } => Self::DaemonFeeUnreasonable {
                reason,
                rate,
                bound,
            },
            E::ExitRefusedAndReleased { detail } => Self::UnstakeRefusedReleased { detail },
            E::ExitFateUnknown { detail } => {
                tracing::warn!(detail = %detail, "unstake dispatch fate unknown; seal held");
                Self::UnstakeFateUnknown { detail }
            }
            // NOT -32603: a non-loopback daemon address
            // is operator-fixable configuration — every other verb works over
            // a remote daemon, so "internal error" on exactly this one is the
            // hard-to-diagnose shape rule 82 forbids. Named code + remedy.
            E::Transport { detail } => Self::UnstakeLocalNodeRequired { detail },
            E::Engine { context, detail } => internal_detail(context, detail),
        }
    }
}

impl From<shekyl_engine_core::CollectUnstakedError> for WalletRpcError {
    /// The `collect_unstaked` code table (PR-C): `-29513` + `-29523..-29527` +
    /// `-29529` (a pre-seal daemon outage);
    /// the fee arms reuse the send path's `-29102`/`-29109` split and a
    /// post-seal transport failure is `-29107` (the drain precedent — the
    /// sealed pass's fate is the driver's; the client must not re-fire
    /// blindly).
    fn from(err: shekyl_engine_core::CollectUnstakedError) -> Self {
        use shekyl_engine_core::CollectUnstakedError as E;
        match err {
            E::NotStaker => Self::UnstakeNotStaker,
            E::NoExitToCollect => Self::CollectNoExit,
            E::NothingSpendableYet => Self::CollectNotSpendableYet,
            E::DustRemainder => Self::CollectDustRemainder,
            E::PassInFlight => Self::CollectPassInFlight,
            E::InputRaced => Self::CollectInputRaced,
            E::Unanchorable { detail } => Self::CollectSyncing { detail },
            // A pre-seal daemon outage is retryable, but its remedy ("check the
            // daemon") is not `CollectSyncing`'s ("wait for sync"), so it gets
            // its own code rather than borrowing one with the wrong text
            // NOT -32603.
            E::DaemonUnreachable { detail } => Self::CollectDaemonUnreachable { detail },
            E::FeeEstimate { detail } => {
                tracing::warn!(detail = %detail, "collect_unstaked fee estimate failed");
                Self::FeeEstimationFailed
            }
            E::FeeUnreasonable {
                reason,
                rate,
                bound,
            } => Self::DaemonFeeUnreasonable {
                reason,
                rate,
                bound,
            },
            E::Submit { detail } => {
                tracing::warn!(detail = %detail, "collect_unstaked dispatch failed at the choke point");
                Self::SubmitAmbiguous
            }
            E::Engine { context, detail } => internal_detail(context, detail),
        }
    }
}

impl From<SubmitError> for WalletRpcError {
    fn from(err: SubmitError) -> Self {
        match err {
            SubmitError::ReservationNotFound { .. } => Self::ReservationNotFound,
            SubmitError::SnapshotInvalidated { .. } => Self::SnapshotInvalidated,
            SubmitError::ContentChanged { content_gen, .. } => {
                Self::ContentGenMismatch { content_gen }
            }
            SubmitError::DaemonRejectedTerminal { kind } => {
                Self::submit_rejected(terminal_to_reject_cause(kind))
            }
            SubmitError::DaemonRejectedRetryable { cause, .. } => {
                Self::submit_rejected(retryable_to_reject_cause(cause))
            }
            SubmitError::DaemonAmbiguous { .. } => Self::SubmitAmbiguous,
            SubmitError::SubmitAlreadyPending { .. } => {
                Self::InternalError("submit already pending for this reservation".into())
            }
            SubmitError::ReanchorUnavailable { .. } => {
                Self::InternalError("re-anchor unavailable; retry later".into())
            }
            SubmitError::ReselectionRequired { .. } => {
                Self::InternalError("reselection required; discard and rebuild".into())
            }
            other => Self::InternalError(other.to_string()),
        }
    }
}

/// Map Engine terminal reject kinds onto the wire [`RejectCause`] vocabulary.
fn terminal_to_reject_cause(kind: TerminalErrorKind) -> RejectCause {
    match kind {
        TerminalErrorKind::DoubleSpend => RejectCause::DoubleSpendConflict,
        TerminalErrorKind::FeeTooLow => RejectCause::FeeTooLow,
        TerminalErrorKind::Malformed => RejectCause::Malformed,
        // `TerminalErrorKind` is `#[non_exhaustive]`; `Unrecognized` and any
        // unknown future kinds take the fail-safe Unrecognized disposition
        // (DAEMON_SUBMIT_VERDICT §2.5).
        _ => RejectCause::Unrecognized,
    }
}

/// Map Engine retryable reject causes onto the wire [`RejectCause`] vocabulary.
fn retryable_to_reject_cause(cause: RetryableRejectCause) -> RejectCause {
    match cause {
        RetryableRejectCause::StaleRoot => RejectCause::StaleRoot,
        RetryableRejectCause::ReferenceTooRecent => RejectCause::ReferenceTooRecent,
        RetryableRejectCause::ReferenceNotFound => RejectCause::ReferenceNotFound,
        _ => RejectCause::Unrecognized,
    }
}

impl From<shekyl_engine_core::AbandonTxError> for WalletRpcError {
    fn from(err: shekyl_engine_core::AbandonTxError) -> Self {
        use shekyl_engine_core::AbandonTxError as E;
        match err {
            // Same answer shape as `get_transfer_by_id` for an id the
            // wallet does not know (rule 82: "no send record" is the
            // truth, not an internal error).
            E::NotFound => Self::UnknownTransferId,
            E::StateForbids { state } => Self::AbandonStateForbids {
                // Single owner of the journal → wire map (`project`).
                state: crate::project::outgoing_transfer_state_of(state),
            },
            // Fail-closed rollback already ran; category-only message
            // (the detail can carry a filesystem path).
            E::Persistence(e) => internal_detail("abandon persistence failed", e),
        }
    }
}

impl From<TxNoteTooLong> for WalletRpcError {
    /// The one place an over-length note becomes a wire error, so the
    /// boundary's pre-lock fast-fail and the engine's write-path refusal
    /// cannot answer the same request differently.
    ///
    /// Counts only — [`TxNoteTooLong`]'s `Display` never carries the note
    /// body (rules 35/36).
    fn from(err: TxNoteTooLong) -> Self {
        Self::InvalidParams(err.to_string())
    }
}

impl From<SetNoteError> for WalletRpcError {
    fn from(err: SetNoteError) -> Self {
        match err {
            // A note targets a transaction of this wallet; a txid it has no
            // part in is a bad request, not an internal error. Message names
            // no txid (never an existence oracle) and no note body.
            SetNoteError::UnknownTransaction => Self::InvalidParams(err.to_string()),
            SetNoteError::NoteTooLong(e) => e.into(),
        }
    }
}

impl From<SetTxNoteError> for WalletRpcError {
    fn from(err: SetTxNoteError) -> Self {
        match err {
            SetTxNoteError::Note(e) => e.into(),
            // Fail-closed rollback already ran; category-only message
            // (the detail can carry a filesystem path).
            SetTxNoteError::Persistence(e) => internal_detail("wallet persistence error", e),
        }
    }
}

impl From<PendingTxError> for WalletRpcError {
    fn from(err: PendingTxError) -> Self {
        match err {
            PendingTxError::ReservationNotFound { .. } | PendingTxError::UnknownHandle => {
                Self::ReservationNotFound
            }
            PendingTxError::ChainStateChanged { .. } | PendingTxError::TooOld { .. } => {
                Self::SnapshotInvalidated
            }
            PendingTxError::DiscardBlockedPendingDaemonAck { .. }
            | PendingTxError::Io(IoError::Daemon { .. }) => Self::SubmitAmbiguous,
            PendingTxError::SubmitAlreadyPending { .. } => {
                Self::InternalError("submit already pending for this reservation".into())
            }
            PendingTxError::Io(other) => Self::InternalError(other.to_string()),
            other => Self::InternalError(other.to_string()),
        }
    }
}

/// Map an internal error to a category-only RPC message, logging the raw cause
/// server-side. `message()` is the most-logged surface and, in remote mode,
/// crosses to the client, so it must never carry a local filesystem path or
/// internal schema (rule 30; the `message()` contract). The full detail is
/// preserved in the server's own logs for diagnosis — mirroring the
/// `PScanStartError::LoadFailed` discipline above.
fn internal_detail(category: &'static str, detail: impl std::fmt::Display) -> WalletRpcError {
    tracing::warn!(category, detail = %detail, "wallet-rpc internal error");
    WalletRpcError::InternalError(category.to_owned())
}

fn classify_wallet_file_detail(detail: &str) -> WalletRpcError {
    let lower = detail.to_ascii_lowercase();
    if lower.contains("already exists") || lower.contains("refusing to overwrite") {
        WalletRpcError::WalletFileExists
    } else if lower.contains("not found") || lower.contains("no such file") {
        WalletRpcError::WalletFileNotFound
    } else if lower.contains("password") || lower.contains("corrupt") {
        WalletRpcError::InvalidPassword
    } else {
        WalletRpcError::InternalError(detail.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_incorrect_password() {
        let err: WalletRpcError = OpenError::IncorrectPassword.into();
        assert_eq!(err.code(), WalletRpcErrorCode::InvalidPassword);
    }

    #[test]
    fn maps_keys_already_exists_detail() {
        let err = classify_wallet_file_detail(
            "refusing to overwrite existing keys file at /tmp/x.wallet.keys",
        );
        assert_eq!(err.code(), WalletRpcErrorCode::WalletFileExists);
    }

    #[test]
    fn maps_refresh_already_running() {
        let err: WalletRpcError = RefreshError::AlreadyRunning.into();
        assert_eq!(err.code(), WalletRpcErrorCode::RefreshInProgress);
    }

    #[test]
    fn maps_refresh_daemon_io() {
        let err: WalletRpcError = RefreshError::Io(IoError::Daemon {
            detail: "connection refused".into(),
        })
        .into();
        assert_eq!(err.code(), WalletRpcErrorCode::DaemonUnreachable);
    }

    /// Join-path failures after a durable reset must not reuse `-29201`:
    /// that code's rescan contract is "wallet untouched" (preflight only).
    #[test]
    fn post_reset_daemon_io_is_rescan_incomplete_not_unreachable() {
        let err = WalletRpcError::from_rescan_scan_failure(RefreshError::Io(IoError::Daemon {
            detail: "/tmp/wallet.keys connection refused".into(),
        }));
        assert_eq!(err.code(), WalletRpcErrorCode::RescanIncomplete);
        assert!(
            !err.message().contains("/tmp"),
            "post-reset scan failure must not echo local paths: {}",
            err.message()
        );
    }

    /// Durability is the axis, not the failure subclass: ConcurrentMutation
    /// and InternalInvariantViolation after a durable reset are still
    /// `-29203`, never the catch-all `-32603`.
    #[test]
    fn post_reset_producer_failures_are_all_rescan_incomplete() {
        let cases = [
            RefreshError::Cancelled,
            RefreshError::MalformedScanResult {
                reason: "test malformed",
            },
            RefreshError::ConcurrentMutation {
                wallet: 1,
                result: 2,
            },
            RefreshError::InternalInvariantViolation {
                context: "test invariant",
            },
            RefreshError::CurveTreeIngest {
                context: "test ingest",
                recoverable_by_respawn: false,
            },
            RefreshError::Io(IoError::Scanner {
                detail: "scan budget exhausted".into(),
            }),
        ];
        for err in cases {
            let mapped = WalletRpcError::from_rescan_scan_failure(err);
            assert_eq!(
                mapped.code(),
                WalletRpcErrorCode::RescanIncomplete,
                "expected -29203 for {mapped:?}"
            );
        }
    }

    #[test]
    fn rescan_persist_is_category_only() {
        let err: WalletRpcError =
            RefreshError::RescanPersist("/home/user/.shekyl/wallet.keys: ENOSPC".into()).into();
        assert_eq!(err.code(), WalletRpcErrorCode::InternalError);
        assert_eq!(
            err.message(),
            "internal error: rescan reset persistence failed"
        );
        assert!(
            !err.message().contains("/home"),
            "persist failure must not leak filesystem paths"
        );
    }

    /// `abandon_tx` mapping (PR-SJ-3): unknown txid answers with the
    /// same shape `get_transfer_by_id` uses; a state refusal carries
    /// `-29108` with the refusing state in `get_transfers` vocabulary
    /// (via `outgoing_transfer_state_of`, not a parallel string table);
    /// a persistence failure is category-only (rolled back engine-side).
    #[test]
    fn abandon_errors_map_to_their_own_shapes() {
        use shekyl_engine_core::AbandonTxError;
        use shekyl_engine_state::SendState;

        use crate::types::TransferState;

        let err: WalletRpcError = AbandonTxError::NotFound.into();
        assert_eq!(err.code(), WalletRpcErrorCode::UnknownTransferId);

        let err: WalletRpcError = AbandonTxError::StateForbids {
            state: SendState::Confirmed { height: 42 },
        }
        .into();
        assert_eq!(err.code(), WalletRpcErrorCode::AbandonStateForbids);
        assert_eq!(err.code().as_i32(), -29108);
        assert_eq!(err.data().expect("data")["state"], "CONFIRMED");
        assert!(
            matches!(
                err,
                WalletRpcError::AbandonStateForbids {
                    state: TransferState::Confirmed
                }
            ),
            "refusal carries the typed TransferState, not a parallel string"
        );
        assert!(
            !err.message().contains("42"),
            "the refusal names the state, not chain detail: {}",
            err.message()
        );

        let err: WalletRpcError = AbandonTxError::StateForbids {
            state: SendState::TerminalRejected,
        }
        .into();
        assert_eq!(err.data().expect("data")["state"], "FAILED");
        assert_eq!(
            err.message(),
            "cannot abandon: the send is FAILED",
            "Display uses TransferState::as_str"
        );
    }

    /// **The published contract and the served text are one text.**
    ///
    /// D-4's mechanism is that the refusal body *is* the warning, and a
    /// client implementer reads the contract rather than this crate — so a
    /// wording change in one place and not the other would leave wrappers
    /// rendering terms the server no longer states. The comparison is
    /// whitespace-normalized because YAML block scalars carry indentation
    /// the wire text does not; every other character must match, which is
    /// what makes this a wording gate rather than a formatting one.
    #[test]
    fn foundation_warning_matches_the_published_contract() {
        let contract = include_str!("../../../docs/api/wallet_rpc.yaml");
        let squash = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");

        let served = squash(FOUNDATION_POSTURE_WARNING);
        assert!(
            squash(contract).contains(&served),
            "the -29506 body has drifted from docs/api/wallet_rpc.yaml; the \
             contract is the spec (RR-4, spec-first) — update it, or fix the \
             constant to match it"
        );

        // A negative control: the gate must be able to FAIL. If the
        // normalizer collapsed everything to a substring of the document,
        // the assertion above would pass over any text at all.
        assert!(
            !squash(contract).contains(&squash(
                "Foundation CompleteTree posture — it earns competitive yield."
            )),
            "the comparison must reject text the contract does not contain"
        );
    }

    /// The refusal body is the warning itself, not a pointer to it — the
    /// one property D-4 rests on, asserted through the public `message()`
    /// projection a client actually receives.
    #[test]
    fn unacknowledged_foundation_refusal_carries_the_terms() {
        let err = WalletRpcError::StakeFoundationUnacknowledged;
        assert_eq!(
            err.code(),
            WalletRpcErrorCode::StakeFoundationUnacknowledged
        );
        assert_eq!(err.code() as i32, -29506);

        let message = err.message();
        assert_eq!(message, FOUNDATION_POSTURE_WARNING);
        // The load-bearing clauses, named individually: a future edit that
        // trims the message to a summary keeps the equality above (it
        // would move with the constant) but loses these.
        assert!(message.contains("It never earns"));
        assert!(message.contains("grows forever"));
        assert!(message.contains("penalty side is fully live"));
        assert!(message.contains("serve without reward"));
    }

    #[test]
    fn submit_rejected_data_is_wire_submit_verdict() {
        use shekyl_engine_core::engine::error::TerminalErrorKind;
        use shekyl_engine_core::engine::SubmitError;

        let err: WalletRpcError = SubmitError::DaemonRejectedTerminal {
            kind: TerminalErrorKind::FeeTooLow,
        }
        .into();
        assert_eq!(err.code(), WalletRpcErrorCode::SubmitRejected);
        let data = err.data().expect("data");
        assert_eq!(data["verdict"], "rejected");
        assert_eq!(data["cause"], "fee_too_low");
    }

    /// The WI-RPC-5 F-2 pin, mechanically: the five drain refusals carry
    /// `-29507..-29511` exactly, and the two `-29511` arms (in-flight seal
    /// vs. input race) share the code while keeping distinct remedies in
    /// their messages. Bites against a re-numbering or an accidental reuse
    /// of the live `-29500..-29506` stake codes; it does NOT exercise the
    /// engine paths that produce these errors (the façade suite does).
    #[test]
    fn drain_refusals_carry_the_pinned_code_table() {
        let table: [(WalletRpcError, i32); 6] = [
            (WalletRpcError::DrainNotStaker, -29507),
            (WalletRpcError::DrainNoActivePersona, -29508),
            (WalletRpcError::DrainReserveBreached, -29509),
            (
                WalletRpcError::DrainUnanchorable {
                    detail: "curve-tree ingest behind the anchor age".into(),
                },
                -29510,
            ),
            (WalletRpcError::DrainInFlight, -29511),
            (WalletRpcError::DrainInputRaced, -29511),
        ];
        for (err, code) in table {
            assert_eq!(err.code().as_i32(), code, "{err:?}");
        }

        // The shared-code pair keeps distinct remedies — structurally, in
        // `data.cause` (automation must never have to parse the prose), and
        // in the prose itself. The in-flight message must NOT promise a
        // confirmation-triggered release: the drain lifecycle driver that
        // would deliver one is not wired yet (FOLLOWUPS), so "wait for it
        // to confirm" prescribed an event that cannot help.
        assert_eq!(
            WalletRpcError::DrainInFlight.data().expect("data")["cause"],
            "pending"
        );
        assert_eq!(
            WalletRpcError::DrainInputRaced.data().expect("data")["cause"],
            "raced"
        );
        assert!(WalletRpcError::DrainInFlight
            .message()
            .contains("already in flight"));
        assert!(
            !WalletRpcError::DrainInFlight.message().contains("confirm"),
            "the in-flight message must not promise confirmation-release \
             while the drain driver is unwired"
        );
        assert!(WalletRpcError::DrainInputRaced.message().contains("retry"));

        // The transient arm carries its cause in data, like -29500 does.
        let err = WalletRpcError::DrainUnanchorable {
            detail: "tree behind tip".into(),
        };
        assert_eq!(err.data().expect("data")["detail"], "tree behind tip");
    }

    /// The engine→wire map itself (`From<DrainToPrincipalError>`), arm by
    /// arm — the code-table test above constructs wire variants directly and
    /// cannot catch a swapped From-arm (e.g. `Refused` and `Submit` trading
    /// codes), which every prior test would have survived.
    #[test]
    fn drain_engine_errors_map_onto_the_pinned_codes() {
        use shekyl_engine_core::DrainToPrincipalError as E;

        let table: [(E, i32); 10] = [
            (E::NotStaker, -29507),
            (E::NoActivePersona, -29508),
            (E::ReserveBreached, -29509),
            (
                E::Unanchorable {
                    detail: "tree behind tip".into(),
                },
                -29510,
            ),
            (E::InFlight, -29511),
            (E::InputRaced, -29511),
            (E::EmptyRequest, -32602),
            (
                E::Refused {
                    detail: "exceeds spendable".into(),
                },
                -29101,
            ),
            (
                E::FeeEstimate {
                    detail: "connection refused".into(),
                },
                -29102,
            ),
            (
                E::Submit {
                    detail: "transport closed mid-dispatch".into(),
                },
                -29107,
            ),
        ];
        for (engine_err, code) in table {
            let wire: WalletRpcError = engine_err.into();
            assert_eq!(wire.code().as_i32(), code, "{wire:?}");
        }

        // The refused-answer fee arm keeps the -29109 shape WITH its
        // structured scalars (the send path's contract).
        let wire: WalletRpcError = E::FeeUnreasonable {
            reason: "economy above absolute cap",
            rate: 9_999,
            bound: 4_242,
        }
        .into();
        assert_eq!(wire.code().as_i32(), -29109);
        let data = wire.data().expect("fee data");
        assert_eq!(data["rate"], 9_999);
        assert_eq!(data["bound"], 4_242);

        // State stays the category-only internal arm.
        let wire: WalletRpcError = E::State {
            context: "pscan state load",
            detail: "seal version refused".into(),
        }
        .into();
        assert_eq!(wire.code().as_i32(), -32603);
    }

    /// The fragmented-funding stake refusal mints `-29512` and renders the
    /// public headroom constant, never the wallet's record count (which the
    /// arm does not even carry) — the classification whose absence routed
    /// this condition to `-32603` "internal error" (review #601 r5).
    #[test]
    fn stake_funding_fragmented_is_29512_and_count_free() {
        let err = WalletRpcError::StakeFundingFragmented { max: 7 };
        assert_eq!(err.code().as_i32(), -29512);
        assert!(err.to_string().contains('7'), "the headroom renders");
        assert!(
            err.to_string().contains("fragmented"),
            "names the condition"
        );
    }

    /// This bites against any `unstake` refusal falling through to `-32603`
    /// (the classification gap `-29512` was minted to close, #601 r5): every
    /// user-recoverable façade arm maps to its own `-295xx` code, and the two
    /// dispatch dispositions get DIFFERENT codes because they demand opposite
    /// client behavior (released ⇒ retry at will; held ⇒ do not re-fire).
    /// It does NOT cover the engine's own arm selection.
    #[test]
    fn every_unstake_refusal_has_a_named_code_and_dispositions_differ() {
        use shekyl_engine_core::UnstakeError as E;
        let cases: Vec<(WalletRpcError, i32)> = vec![
            (E::NotStaker.into(), -29513),
            (E::NothingStaked.into(), -29514),
            (E::BondConfirming.into(), -29515),
            (E::ExitInProgress.into(), -29516),
            (
                E::NotReady {
                    detail: "cooldown".into(),
                }
                .into(),
                -29517,
            ),
            (E::NoBondRecord.into(), -29518),
            (
                E::ExitNotFundable {
                    detail: "immature".into(),
                }
                .into(),
                -29519,
            ),
            (
                E::Resyncing {
                    detail: "lagging".into(),
                }
                .into(),
                -29520,
            ),
            (E::InputRaced.into(), -29520),
            (
                E::DaemonUnreachable {
                    detail: "connection refused".into(),
                }
                .into(),
                -29520,
            ),
            (
                E::ExitRefusedAndReleased {
                    detail: "refused".into(),
                }
                .into(),
                -29521,
            ),
            (
                E::ExitFateUnknown {
                    detail: "timeout".into(),
                }
                .into(),
                -29522,
            ),
        ];
        for (err, code) in &cases {
            assert_eq!(err.code().as_i32(), *code, "{err}");
            assert_ne!(err.code().as_i32(), -32603, "no fall-through: {err}");
        }
        let fee_query: WalletRpcError = E::FeeEstimate {
            detail: "daemon down".into(),
        }
        .into();
        assert_eq!(
            fee_query.code().as_i32(),
            -29102,
            "a failed fee QUERY keeps the shared retry-the-daemon code"
        );
        let fee_refused: WalletRpcError = E::FeeUnreasonable {
            reason: "per-weight rate above ceiling",
            rate: 9,
            bound: 3,
        }
        .into();
        assert_eq!(
            fee_refused.code().as_i32(),
            -29109,
            "a refused fee ANSWER keeps the shared sanity-ceiling code"
        );
        let transport: WalletRpcError = E::Transport {
            detail: "not loopback".into(),
        }
        .into();
        assert_eq!(
            transport.code().as_i32(),
            -29528,
            "a non-loopback daemon is operator config, never -32603"
        );
        // The shared-transient pair splits on data.cause, the -29511 shape.
        let syncing: WalletRpcError = E::Resyncing {
            detail: "lagging".into(),
        }
        .into();
        assert_eq!(syncing.data().expect("data")["cause"], "syncing");
        let raced: WalletRpcError = E::InputRaced.into();
        assert_eq!(raced.data().expect("data")["cause"], "raced");
        // A pre-seal daemon outage joins the same generic retry code on its
        // own cause — retryable, never -32603.
        let daemon: WalletRpcError = E::DaemonUnreachable {
            detail: "connection refused".into(),
        }
        .into();
        assert_eq!(daemon.data().expect("data")["cause"], "daemon");
    }

    /// The `collect_unstaked` table: named codes for the exit-collection
    /// states, the drain's shared fee/ambiguous codes for the shared
    /// machinery, and a scalar-free dust rendering (the sweep IS the
    /// P→principal value-out leg, so its refusals carry no amounts).
    #[test]
    fn collect_unstaked_codes_and_scalar_free_dust() {
        use shekyl_engine_core::CollectUnstakedError as E;
        let cases: Vec<(WalletRpcError, i32)> = vec![
            (E::NotStaker.into(), -29513),
            (E::NoExitToCollect.into(), -29523),
            (E::NothingSpendableYet.into(), -29524),
            (E::DustRemainder.into(), -29525),
            (E::PassInFlight.into(), -29526),
            (E::InputRaced.into(), -29526),
            (
                E::Unanchorable {
                    detail: "tree behind tip".into(),
                }
                .into(),
                -29527,
            ),
            (
                E::DaemonUnreachable {
                    detail: "connection refused".into(),
                }
                .into(),
                -29529,
            ),
            (
                E::FeeEstimate {
                    detail: "daemon down".into(),
                }
                .into(),
                -29102,
            ),
            (
                E::Submit {
                    detail: "transport".into(),
                }
                .into(),
                -29107,
            ),
        ];
        for (err, code) in &cases {
            assert_eq!(err.code().as_i32(), *code, "{err}");
            assert_ne!(err.code().as_i32(), -32603, "no fall-through: {err}");
        }
        // A pre-seal daemon outage is its own retryable code, not the
        // sync-remedy `-29527` nor an opaque internal fault.
        let unreachable: WalletRpcError = E::DaemonUnreachable {
            detail: "connection refused".into(),
        }
        .into();
        assert_eq!(
            unreachable.data().expect("data")["detail"],
            "connection refused"
        );
        let dust: WalletRpcError = E::DustRemainder.into();
        assert!(
            !dust.to_string().chars().any(|c| c.is_ascii_digit()),
            "the dust rendering is scalar-free: {dust}"
        );
        let pending: WalletRpcError = E::PassInFlight.into();
        assert_eq!(pending.data().expect("data")["cause"], "pending");
        let raced: WalletRpcError = E::InputRaced.into();
        assert_eq!(raced.data().expect("data")["cause"], "raced");
    }

    /// `stake_in` mints no new codes: the no-persona arms are `-29500`
    /// (with distinguishing `data.detail`), the transfer-build arms are the
    /// `-291xx` family, and internal arms are category-only `-32603`.
    #[test]
    fn stake_in_reuses_send_and_stake_not_ready_codes() {
        let err: WalletRpcError = StakeInError::NotStaking.into();
        assert_eq!(err.code().as_i32(), -29500);

        let err: WalletRpcError = StakeInError::NoActivePersona.into();
        assert_eq!(err.code().as_i32(), -29500);
        assert_eq!(
            err.data().expect("data")["detail"],
            "no active persona to fund"
        );

        let err: WalletRpcError = StakeInError::Send(SendError::InsufficientFunds {
            needed: 10,
            available: 5,
        })
        .into();
        assert_eq!(err.code(), WalletRpcErrorCode::InsufficientFunds);

        // Internal arm: category-only on the wire, no amounts.
        let err: WalletRpcError = StakeInError::CoverOverflow { stake: 7, cover: 3 }.into();
        assert_eq!(err.code(), WalletRpcErrorCode::InternalError);
        assert!(
            !err.message().contains('7') && !err.message().contains('3'),
            "amounts must not reach the wire: {}",
            err.message()
        );
    }

    /// The drain façade's fee arms preserve the send path's remedy split:
    /// a refused *answer* is `-29109` with the numeric facts in `data`; a
    /// failed *query* is `-29102` with nothing to carry.
    #[test]
    fn drain_fee_arms_preserve_the_29109_vs_29102_split() {
        let err: WalletRpcError = DrainToPrincipalError::FeeUnreasonable {
            reason: "tier above absolute cap",
            rate: 1_000_000,
            bound: 500_000,
        }
        .into();
        assert_eq!(err.code().as_i32(), -29109);
        let data = err.data().expect("data");
        assert_eq!(data["rate"], 1_000_000);
        assert_eq!(data["bound"], 500_000);

        let err: WalletRpcError = DrainToPrincipalError::FeeEstimate {
            detail: "connection refused".into(),
        }
        .into();
        assert_eq!(err.code().as_i32(), -29102);
    }
}
