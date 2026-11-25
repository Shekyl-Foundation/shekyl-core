// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `WalletRpcError` and the stable JSON-RPC error-code table from
//! `docs/api/wallet_rpc.yaml` (`WalletRpcErrorCode`).

use serde_json::{json, Value};
use shekyl_engine_core::engine::error::{
    FeeEstimatorError, FinalityBreach, FinalityStop, RetryableRejectCause, TerminalErrorKind,
};
use shekyl_engine_core::engine::{ResendError, SubmitError};
use shekyl_engine_core::{
    CurveTreeIngestFault, DrainToPrincipalError, IoError, KeyError, OpenError, PScanStartError,
    PendingTxError, PersistenceError, RefreshError, SendError, ServingStartError, SetTxNoteError,
    SignFault, StakeInError, StoreOpenFault, MAX_OUTPUTS,
};
use shekyl_engine_file::{PayloadError, WalletEnvelopeError, WalletFileError};
use shekyl_engine_state::WalletLedgerError;
use shekyl_engine_state::{SetNoteError, TxNoteTooLong};
use shekyl_rpc_client::{DaemonFault, HashHex, IdentityMismatch, Network};
use thiserror::Error;

pub use crate::shard_view::ShardViewNotOfferedCause;

/// A definite daemon rejection as the wallet RPC contract names it: the
/// `-29106` data's `cause` and `-29114`'s (`docs/api/wallet_rpc.yaml`).
///
/// The wallet contract's own vocabulary. The daemon's wire spells its
/// causes as one-key states since `CORE_RPC_VERSION` 4.0 (IG-Q76); this
/// contract keeps the words its callers read until it is renamed in its
/// own right.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectCause {
    /// The bytes do not parse, or break a structural or static rule.
    Malformed,
    /// Below the fee floor.
    FeeTooLow,
    /// Another transaction consumes one of this one's inputs.
    DoubleSpendConflict,
    /// The FCMP++ reference block's root is no longer the chain's.
    StaleRoot,
    /// The reference block is younger than the minimum age.
    ReferenceTooRecent,
    /// The daemon does not know the reference block.
    ReferenceNotFound,
    /// A consensus row refused the transaction; the row rides beside it.
    ConsensusRule,
    /// A cause this build does not know: the fail-safe disposition.
    Unrecognized,
}

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

/// Declare the code table once: the enum, [`WalletRpcErrorCode::ALL`] and
/// [`WalletRpcErrorCode::name`] come from the same list, so the set a test
/// compares with the contract is the set the server can emit, under the
/// names the contract spells.
macro_rules! wallet_rpc_error_codes {
    ($($(#[$doc:meta])* $name:ident = $value:literal => $wire:literal,)*) => {
        /// Allocated application / protocol error codes (spec enum).
        ///
        /// Emitting a code outside this set is a conformance failure. RESERVED-range
        /// codes land in the sub-PR that implements their method (rule 21).
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(i32)]
        pub enum WalletRpcErrorCode {
            $($(#[$doc])* $name = $value,)*
        }

        impl WalletRpcErrorCode {
            /// Every allocated code, in declaration order: exactly the
            /// contract's `WalletRpcErrorCode` enum
            /// (`docs/api/wallet_rpc.yaml`), both directions, by test.
            pub const ALL: &'static [Self] = &[$(Self::$name,)*];

            /// The contract's name for this code (the comment beside it in
            /// `wallet_rpc.yaml`'s enum), for a surface that reports a code by
            /// name rather than number.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self {
                    $(Self::$name => $wire,)*
                }
            }
        }
    };
}

wallet_rpc_error_codes! {
    /// JSON-RPC parse error.
    ParseError = -32700 => "PARSE_ERROR",
    /// JSON-RPC invalid request.
    InvalidRequest = -32600 => "INVALID_REQUEST",
    /// JSON-RPC method not found (also covers RESERVED / not-yet-implemented).
    MethodNotFound = -32601 => "METHOD_NOT_FOUND",
    /// JSON-RPC invalid params.
    InvalidParams = -32602 => "INVALID_PARAMS",
    /// JSON-RPC internal error.
    InternalError = -32603 => "INTERNAL_ERROR",
    /// A wallet is already open; close first.
    WalletAlreadyOpen = -29000 => "WALLET_ALREADY_OPEN",
    /// No wallet is open.
    WalletNotOpen = -29001 => "WALLET_NOT_OPEN",
    /// Create refused: wallet file already exists.
    WalletFileExists = -29002 => "WALLET_FILE_EXISTS",
    /// Open failed: no such wallet file.
    WalletFileNotFound = -29003 => "WALLET_FILE_NOT_FOUND",
    /// Open / change_password: MAC / password failure.
    InvalidPassword = -29004 => "INVALID_PASSWORD",
    // -29005 CAPABILITY_FORBIDS is RETIRED (never reuse): FULL is the
    // only capability (rule 23), so no operation can be refused on
    // capability grounds. The number stays recorded in wallet_rpc.yaml
    // so it is never reallocated with a new meaning.
    /// The open wallet's session has ended (its key actor stopped and the
    /// key material is wiped); close and reopen the wallet, then retry.
    WalletSessionEnded = -29006 => "WALLET_SESSION_ENDED",
    /// Open: the wallet file belongs to a different network than this
    /// server runs (`data`: `wallet`, `expected`).
    WalletNetworkMismatch = -29007 => "WALLET_NETWORK_MISMATCH",
    /// Open / create: another process holds the wallet's lock — it is
    /// open elsewhere.
    WalletLockedElsewhere = -29008 => "WALLET_LOCKED_ELSEWHERE",
    /// Create: the wallet directory does not exist.
    WalletDirMissing = -29009 => "WALLET_DIR_MISSING",
    /// Wallet files: the filesystem refused access.
    WalletFileAccessDenied = -29010 => "WALLET_FILE_ACCESS_DENIED",
    /// Wallet files: the contents are damaged or not a wallet's.
    WalletFileCorrupt = -29011 => "WALLET_FILE_CORRUPT",
    /// Wallet files: written by a version or in a shape this build cannot
    /// read.
    WalletFileVersionUnsupported = -29012 => "WALLET_FILE_VERSION_UNSUPPORTED",
    /// Wallet files: a read or write failed underneath (disk, filesystem).
    WalletFileIoFailed = -29013 => "WALLET_FILE_IO_FAILED",
    /// Close: transactions are in flight (`data`: `count`); submit or
    /// discard them first.
    WalletCloseBlocked = -29014 => "WALLET_CLOSE_BLOCKED",
    /// The wallet's curve-tree membership data is unavailable for this
    /// session; close and reopen the wallet.
    CurveTreeUnavailable = -29015 => "CURVE_TREE_UNAVAILABLE",
    /// Open: the wallet's curve-tree store (`.curvetree`) is damaged or from
    /// a version this build cannot read. It is rebuilt from the chain once
    /// deleted; `data.cause` says which.
    CurveTreeStoreUnusable = -29016 => "CURVE_TREE_STORE_UNUSABLE",
    /// Open: this computer's random-number source failed the wallet's
    /// check, so the wallet did not open. Only a `conformance` build runs
    /// the check.
    RandomSourceCheckFailed = -29017 => "RANDOM_SOURCE_CHECK_FAILED",
    /// Build: address parse / network check failed.
    InvalidRecipient = -29100 => "INVALID_RECIPIENT",
    /// Build: spendable balance too low.
    InsufficientFunds = -29101 => "INSUFFICIENT_FUNDS",
    /// Build: daemon fee query failed.
    FeeEstimationFailed = -29102 => "FEE_ESTIMATION_FAILED",
    /// Submit: unknown / expired reservation handle.
    ReservationNotFound = -29103 => "RESERVATION_NOT_FOUND",
    /// Submit: reorg raced the reservation.
    SnapshotInvalidated = -29104 => "SNAPSHOT_INVALIDATED",
    /// Submit: `seen_gen` ≠ `content_gen` (CT-5d).
    ContentGenMismatch = -29105 => "CONTENT_GEN_MISMATCH",
    /// Submit: definite daemon rejection.
    SubmitRejected = -29106 => "SUBMIT_REJECTED",
    /// Submit: transport-level ambiguity.
    SubmitAmbiguous = -29107 => "SUBMIT_AMBIGUOUS",
    /// `abandon_tx`: the send's state forbids abandoning (`CONFIRMED`
    /// is on chain; `FAILED` was never relayed). A state conflict, not
    /// a bad request — refresh the view and re-decide.
    AbandonStateForbids = -29108 => "ABANDON_STATE_FORBIDS",
    /// Build / fee quote: the daemon's fee snapshot failed
    /// well-formedness (non-monotonic tier band, or a tier above the
    /// absolute per-weight cap). The daemon *answered*; the wallet
    /// refused what it said — distinct from `-29102`'s "the fee query
    /// itself failed" (rule 82).
    DaemonFeeUnreasonable = -29109 => "DAEMON_FEE_UNREASONABLE",
    /// Build: the wallet has not synced any blocks yet.
    WalletNotSynced = -29110 => "WALLET_NOT_SYNCED",
    /// Build: funds exist but wait on the membership-data rebuild.
    SpendUnavailableRebuilding = -29111 => "SPEND_UNAVAILABLE_REBUILDING",
    /// Build: an output is too fresh for the reference block
    /// (`data`: `wait_blocks`).
    OutputNotYetSpendable = -29112 => "OUTPUT_NOT_YET_SPENDABLE",
    /// Build: the chain is too short to anchor a reference block
    /// (`data`: `synced_height`, `ref_anchor_age`).
    ChainTooShortToSpend = -29113 => "CHAIN_TOO_SHORT_TO_SPEND",
    /// Build: the rebuild-loop breaker is tripped (`data`: `kind`); the
    /// operator acknowledges it before builds resume.
    SubmitLoopBreakerTripped = -29114 => "SUBMIT_LOOP_BREAKER_TRIPPED",
    /// Submit: a submit for this reservation is already in progress.
    SubmitAlreadyPending = -29115 => "SUBMIT_ALREADY_PENDING",
    /// Submit: the proof needs re-anchoring and cannot be right now;
    /// the reservation is kept — retry.
    ReanchorUnavailable = -29116 => "REANCHOR_UNAVAILABLE",
    /// Submit: the proof cannot be re-anchored content-preservingly;
    /// discard and rebuild.
    ReselectionRequired = -29117 => "RESELECTION_REQUIRED",
    /// Build: the daemon's fee answer could not be read.
    DaemonFeeResponseInvalid = -29118 => "DAEMON_FEE_RESPONSE_INVALID",
    /// Build: the wallet's own signer hit an internal fault; `data.fault`
    /// names which.
    SignerFailed = -29119 => "SIGNER_FAILED",
    /// Submit: the send's record could not be saved because the wallet's
    /// folder, file or drive is not writable (`data`: `target`), so nothing
    /// was sent; the reservation is kept (A19). The save's other causes
    /// have their own codes, `-29128` to `-29134` (Rick, 2026-11-18 and
    /// 2026-11-19).
    SaveNotWritable = -29120 => "SAVE_NOT_WRITABLE",
    /// `tx_resend`: no held send has this id.
    TxNotHeld = -29121 => "TX_NOT_HELD",
    /// `tx_resend`: the held send has no saved bytes to resend.
    TxBytesMissing = -29122 => "TX_BYTES_MISSING",
    /// Build: the spend needs more inputs than one transaction may carry.
    TooManyInputs = -29123 => "TOO_MANY_INPUTS",
    /// Build: the request has more recipients than one transaction may
    /// carry with its change.
    TooManyOutputs = -29124 => "TOO_MANY_OUTPUTS",
    /// Build: an input's tree path does not hold the output it spends.
    InputNotInTree = -29125 => "INPUT_NOT_IN_TREE",
    /// Build: an input was received but can never be spent.
    InputUnspendable = -29126 => "INPUT_UNSPENDABLE",
    // -29127 OUTPUTS_PARKED is RETIRED (never reuse): the wallet has no
    // user-set hold on outputs (V3_WALLET_DECISION_LOG.md, 2026-11-15).
    // The number stays recorded in wallet_rpc.yaml so it is never
    // reallocated with a new meaning.
    /// Submit: the send was saved on a volume whose file system Windows
    /// cannot confirm survives a power cut, so nothing was sent; the
    /// reservation is kept (`data`: `file_system`).
    SaveDurabilityUnconfirmed = -29128 => "SAVE_DURABILITY_UNCONFIRMED",
    /// Submit: the disk holding the wallet is full, so the send was not
    /// saved and nothing was sent; the reservation is kept.
    SaveDiskFull = -29129 => "SAVE_DISK_FULL",
    /// Submit: another program held the wallet's file open past the save's
    /// wait (a scanner), so nothing was sent; the reservation is kept.
    SaveFileHeld = -29130 => "SAVE_FILE_HELD",
    /// Submit: the disk reported an error at a step of saving the send, so
    /// nothing was sent; the reservation is kept (`data`: `step`, `error`).
    SaveIoFailed = -29131 => "SAVE_IO_FAILED",
    /// Submit: the wallet's local NTFS drive refused the rename Windows
    /// confirms, so nothing was sent; the reservation is kept. Windows
    /// builds observed to give it: none observed.
    SaveRenameUnconfirmed = -29132 => "SAVE_RENAME_UNCONFIRMED",
    /// Submit: the wallet could not prepare the send's record to save (a
    /// fault in the wallet, not the disk), so nothing was sent; the
    /// reservation is kept.
    SaveInternalFault = -29133 => "SAVE_INTERNAL_FAULT",
    /// Submit: the wallet is on a network drive, where no save is confirmed
    /// to survive a power cut, so nothing was sent; the reservation is kept
    /// (Rick, 2026-11-19).
    SaveOnNetworkDrive = -29134 => "SAVE_ON_NETWORK_DRIVE",
    /// Refresh: single-flight violation.
    RefreshInProgress = -29200 => "REFRESH_IN_PROGRESS",
    /// Refresh / rescan / proofs / build: the daemon did not answer.
    ///
    /// For `rescan_blockchain` only the **preflight** refusal uses this code
    /// (wallet untouched). A scan that fails *after* the reset is durable
    /// emits [`Self::RescanIncomplete`] instead — same daemon class of
    /// failure, opposite durability claim.
    DaemonUnreachable = -29201 => "DAEMON_UNREACHABLE",
    /// Rescan: refused — transactions in flight whose spend record a chain
    /// replay cannot rebuild. A resolvable state conflict, not a bad request.
    RescanBlocked = -29202 => "RESCAN_BLOCKED",
    /// Rescan: the reset persisted, then the producer failed before the
    /// ledger was rebuilt. History is empty until a rescan finishes; retry.
    RescanIncomplete = -29203 => "RESCAN_INCOMPLETE",
    /// Refresh: cancelled before it completed (the wallet is closing).
    RefreshCancelled = -29204 => "REFRESH_CANCELLED",
    /// The daemon speaks another RPC version than this wallet: update the
    /// older side (`VC-4` wire axis).
    DaemonVersionMismatch = -29205 => "DAEMON_VERSION_MISMATCH",
    /// The daemon was built from other consensus rules than this wallet
    /// (`VC-4` rules axis).
    DaemonRulesMismatch = -29206 => "DAEMON_RULES_MISMATCH",
    /// The daemon runs another network than this wallet (`VC-4` network
    /// axis). Distinct from `-29007`, which is the wallet *file's* network.
    DaemonNetworkMismatch = -29207 => "DAEMON_NETWORK_MISMATCH",
    /// The daemon follows another chain than this wallet's: its genesis
    /// block differs (`VC-4` genesis axis).
    DaemonChainMismatch = -29208 => "DAEMON_CHAIN_MISMATCH",
    /// The daemon answered with something that breaks the RPC contract.
    DaemonProtocolViolation = -29209 => "DAEMON_PROTOCOL_VIOLATION",
    /// Refresh: the chain kept reorganizing past the rewind budget; nothing
    /// was merged.
    ChainUnstable = -29210 => "CHAIN_UNSTABLE",
    /// Refresh: a rollback would pass the finality window, so the
    /// curve-tree store has to be removed and rebuilt. Terminal for this
    /// store. Distinct from [`Self::RescanIncomplete`]: a rescan leaves
    /// the tree untouched, and this code says so even when the rescan
    /// already cleared history.
    ResyncRequired = -29211 => "RESYNC_REQUIRED",
    /// The daemon refused a call as outside this wallet's grant: the
    /// connection holds no grant the operation needs.
    DaemonGrantRefused = -29212 => "DAEMON_GRANT_REFUSED",
    /// Something other than this account's node answers at "this
    /// computer"'s rendezvous (`RPC_CHANNEL.md` RT-15): a security failure.
    /// The wallet did not connect, and does not retry or try another leg.
    DaemonPeerCheckFailed = -29213 => "DAEMON_PEER_CHECK_FAILED",
    /// "This computer"'s node runs as a service, which a wallet reaches
    /// only over the channel (RT-W12); until then it names the service's
    /// view listener as `daemon-address`. Nothing was dialled.
    DaemonIsAService = -29214 => "DAEMON_IS_A_SERVICE",
    /// `check_*`: proof string failed decode / framing / size caps.
    ProofMalformed = -29300 => "PROOF_MALFORMED",
    /// `get_tx_proof` OUTBOUND: no retained per-tx secret for the txid.
    ProofTxSecretUnavailable = -29301 => "PROOF_TX_SECRET_UNAVAILABLE",
    /// `get_tx_proof` INBOUND / `get_reserve_proof`: nothing to prove.
    ProofNoProvableOutputs = -29302 => "PROOF_NO_PROVABLE_OUTPUTS",
    /// Proofs: a txid named by the request is unknown to the daemon.
    ProofTxNotFound = -29303 => "PROOF_TX_NOT_FOUND",
    /// Proofs: a reserve-proof locator names a tx the daemon holds only
    /// in its pool — unconfirmed money cannot back a reserve claim.
    ProofTxUnconfirmed = -29304 => "PROOF_TX_UNCONFIRMED",
    /// Proof **verification** was asked of a daemon that is not
    /// synchronized: the chain facts a proof is checked against would not
    /// be the chain's, and "not found" / a short confirmation count from a
    /// daemon mid-sync is indistinguishable from a forged proof. Retryable
    /// once the daemon catches up.
    ProofDaemonSyncing = -29305 => "PROOF_DAEMON_SYNCING",
    /// `get_transfer_by_id`: no match.
    UnknownTransferId = -29400 => "UNKNOWN_TRANSFER_ID",
    /// Stake: funding not ready (W1-clean refusal — fund the persona /
    /// let the scan catch up, then retry).
    StakeNotReady = -29500 => "STAKE_NOT_READY",
    /// Stake: a signed bond post is already awaiting dispatch.
    StakeInFlight = -29501 => "STAKE_IN_FLIGHT",
    /// Stake: the wallet already holds a confirmed bond (idempotency).
    AlreadyStaked = -29502 => "ALREADY_STAKED",
    /// Stake: the wallet's persona record moved during the credentialed
    /// reopen; nothing was written — re-invoke `stake`.
    StakeRecordMoved = -29503 => "STAKE_RECORD_MOVED",
    /// Stake: this session's scan recovered a staked slot; staking becomes
    /// operational at the next wallet open — close and reopen, then retry.
    StakeRecoveredPendingReopen = -29504 => "STAKE_RECOVERED_PENDING_REOPEN",
    /// Stake: market staking has no shard to bond over — shard assignment
    /// is an unbuilt round (`COMPLETETREE_ACTIVATION.md` §10 item 1).
    StakeNoShardsAvailable = -29505 => "STAKE_NO_SHARDS_AVAILABLE",
    /// Stake: the foundation posture was requested without the
    /// acknowledgment; the refusal message is the warning itself (D-4).
    StakeFoundationUnacknowledged = -29506 => "STAKE_FOUNDATION_UNACKNOWLEDGED",
    /// Stake: the persona's spendable funding is fragmented across more
    /// outputs than one bond post's vin headroom carries (the consensus
    /// vin cap minus the post's own bond input). W1-clean; funding is
    /// intact — neither "fund and retry" nor an internal fault.
    StakeFundingFragmented = -29512 => "STAKE_FUNDING_FRAGMENTED",
    /// Drain: this wallet runs no stake engine — it is not an archival
    /// staker, and the drain path does not exist here (WI-RPC-5;
    /// `stake_in`'s equivalent refusal is `-29500`).
    DrainNotStaker = -29507 => "DRAIN_NOT_STAKER",
    /// Drain: the wallet is a staker but no persona is currently active.
    /// The façade resolves the LIVE active persona from actor state — there
    /// is no `p_slot` parameter to point elsewhere.
    DrainNoActivePersona = -29508 => "DRAIN_NO_ACTIVE_PERSONA",
    /// Drain: a live-persona drain would spend the pool below
    /// `EXIT_FEE_RESERVE_ATOMIC` (DS-4). Lower the payment or retire first.
    DrainReserveBreached = -29509 => "DRAIN_RESERVE_BREACHED",
    /// Drain: no submittable curve-tree reference can be anchored yet —
    /// transient; sync and retry. (The *read* method reports syncing as a
    /// result discriminant, not this code; this fires on an attempted send.)
    DrainUnanchorable = -29510 => "DRAIN_UNANCHORABLE",
    /// Drain: the one-live-drain-per-persona seal (a pending drain exists,
    /// or a concurrent post raced this drain's inputs — retry).
    DrainInFlight = -29511 => "DRAIN_IN_FLIGHT",
    /// Unstake/collect: this wallet runs no stake engine — the exit lane
    /// does not exist here (the drain's `-29507` sibling; shared by both
    /// exit verbs, which are one lane).
    UnstakeNotStaker = -29513 => "UNSTAKE_NOT_STAKER",
    /// Unstake: no persona holds a live confirmed bond and nothing is
    /// mid-exit — there is nothing to unstake.
    UnstakeNothingStaked = -29514 => "UNSTAKE_NOTHING_STAKED",
    /// Unstake: the only bond activity is a confirming bond post — wait
    /// for it to confirm, then unstake.
    UnstakeBondConfirming = -29515 => "UNSTAKE_BOND_CONFIRMING",
    /// Unstake: an exit is already in progress (dispatched or awaiting
    /// collection) — wait, then `collect_unstaked`.
    UnstakeExitInProgress = -29516 => "UNSTAKE_EXIT_IN_PROGRESS",
    /// Unstake: consensus's readiness predicates refuse the exit for now
    /// (cooldown / slash watermark / interval log); `data.detail` carries
    /// the operands that say when the refusal lifts.
    UnstakeNotReady = -29517 => "UNSTAKE_NOT_READY",
    /// Unstake: the daemon holds no bond record for the resolved persona —
    /// wallet and chain disagree; resync and retry.
    UnstakeNoBondRecord = -29518 => "UNSTAKE_NO_BOND_RECORD",
    /// Unstake: the exit's floor fee cannot be funded from the persona pool
    /// yet — wait for outputs to mature or land.
    UnstakeNotFundable = -29519 => "UNSTAKE_NOT_FUNDABLE",
    /// Unstake: a transient condition (reference view syncing, or a
    /// concurrent operation raced the exit's inputs); nothing was sent —
    /// retry. `data.cause` distinguishes `"syncing"` / `"raced"`.
    UnstakeRetryTransient = -29520 => "UNSTAKE_RETRY_TRANSIENT",
    /// Unstake: the daemon refused the exit with a definite first-send
    /// verdict and the sealed record was RELEASED — nothing propagated;
    /// address the named refusal and retry at will.
    UnstakeRefusedReleased = -29521 => "UNSTAKE_REFUSED_RELEASED",
    /// Unstake: the exit's network fate is unknown (or retryable-refused);
    /// its sealed record is HELD funds-safe and the one-live-exit lane
    /// stays shut until it settles or the recovery slice disposes of it.
    /// Do NOT retry blindly; the stall alarm names the record.
    UnstakeFateUnknown = -29522 => "UNSTAKE_FATE_UNKNOWN",
    /// Collect: no confirmed exit awaits collection — unstake first, or
    /// wait for the exit to confirm and be observed.
    CollectNoExit = -29523 => "COLLECT_NO_EXIT",
    /// Collect: the released collateral is not spendable yet — wait for
    /// maturity and retry.
    CollectNotSpendableYet = -29524 => "COLLECT_NOT_SPENDABLE_YET",
    /// Collect: the remaining residue cannot fund the fee plus a payable
    /// amount (the 2-atomic-unit two-output split floor) — the named dust
    /// residual; it stays in the persona's pool.
    CollectDustRemainder = -29525 => "COLLECT_DUST_REMAINDER",
    /// Collect: a sweep pass is already in flight for this persona (or a
    /// concurrent operation raced this pass's inputs — `data.cause`).
    CollectPassInFlight = -29526 => "COLLECT_PASS_IN_FLIGHT",
    /// Collect: no submittable curve-tree reference can be anchored yet —
    /// transient; sync and retry.
    CollectSyncing = -29527 => "COLLECT_SYNCING",
    /// Unstake: the exit's record fetch rides the wallet's OWN node on
    /// loopback only (the local transport posture; remote posture for the
    /// exit lands with posture selection, DQ-T2.3) — this server's daemon
    /// address is not loopback. Operator-actionable configuration, never an
    /// internal fault.
    UnstakeLocalNodeRequired = -29528 => "UNSTAKE_LOCAL_NODE_REQUIRED",
    /// Collect: a daemon query needed to prepare the sweep failed (the
    /// dispatch-tip clock read) before anything was sealed — the daemon is
    /// unreachable, not the wallet out of sync (`-29527`) nor an internal
    /// fault (`-32603`). Check the daemon and retry.
    CollectDaemonUnreachable = -29529 => "COLLECT_DAEMON_UNREACHABLE",
    /// Open (staker): the sealed staking-scan state could not be loaded;
    /// the wallet refuses to open without its scan.
    StakeStateUnreadable = -29530 => "STAKE_STATE_UNREADABLE",
    /// Open (staker): the wallet's Tor configuration is unusable, so the
    /// serving host cannot start.
    ServingTorUnusable = -29531 => "SERVING_TOR_UNUSABLE",
    /// Open (staker): the persona's serving identity is unavailable.
    ServingIdentityUnavailable = -29532 => "SERVING_IDENTITY_UNAVAILABLE",
    /// Open (staker): serving needs the wallet's own node on loopback.
    ServingLocalNodeRequired = -29533 => "SERVING_LOCAL_NODE_REQUIRED",
    /// `get_shard_view`: the shard is still open — the chain has not filled
    /// it, so it has no view yet (the daemon's `-24`). Wait for it to close.
    ShardStillOpen = -29534 => "SHARD_STILL_OPEN",
    /// `get_shard_view`: the shard is closed and the daemon's fetch reached
    /// no holder that served it (the daemon's `-22`). Transient; retry.
    ShardUnavailable = -29535 => "SHARD_UNAVAILABLE",
    /// `get_shard_view`: the daemon this wallet uses does not serve shard
    /// views — the call is outside the wallet's grant there
    /// (`OutsideTheGrant`), or it runs with Tor off (`shard.tor-off`).
    /// `data.cause` says which; the remedy is another daemon, not a retry.
    ShardViewNotOffered = -29536 => "SHARD_VIEW_NOT_OFFERED",
    /// `get_shard_view`: the daemon is already fetching a shard for a
    /// bounded caller and opens one such fetch at a time (`bound.shard`).
    /// Transient; retry shortly.
    ShardViewBusy = -29537 => "SHARD_VIEW_BUSY",
    /// Stake: the persona scan has not yet verified the chain up to the
    /// finality horizon, so the shards a `CompleteTree` bond owes are not
    /// known yet (`WSS-Q15`). Nothing was written; retry once the scan has
    /// caught up.
    StakeScanBehind = -29538 => "STAKE_SCAN_BEHIND",
    /// Stake: the wallet's node has discarded the bodies of a shard the bond
    /// owes. They come back only through the node's recovery fetch (the
    /// `WSS-Q9` handoff), which is not built, so the bond cannot be posted
    /// until it is (`WSS-Q15`). Nothing was written.
    StakeShardDiscarded = -29539 => "STAKE_SHARD_DISCARDED",
    /// Stake: the node's reply for a shard the bond owes does not match the
    /// chain the persona scan verified. Nothing was written; the node needs
    /// attention.
    StakeDaemonMismatch = -29540 => "STAKE_DAEMON_MISMATCH",
    /// Stake: the persona body store is filled from the wallet's own node on
    /// loopback, and this server's daemon address is not loopback.
    StakeLocalNodeRequired = -29541 => "STAKE_LOCAL_NODE_REQUIRED",
    /// Stake: the persona body store could not write a shard the bond owes.
    /// Nothing was posted; check the disk.
    StakeBodyStoreFailed = -29542 => "STAKE_BODY_STORE_FAILED",
    /// Stake: the node reports that it is still synchronizing, so finality
    /// cannot be judged yet. Retry once it has caught up.
    StakeDaemonSyncing = -29543 => "STAKE_DAEMON_SYNCING",
    /// Stake: the node could not be read while filling the persona body
    /// store. Nothing was posted; check the node and retry.
    StakeDaemonUnreachable = -29544 => "STAKE_DAEMON_UNREACHABLE",
    /// `verify_message`: well-formed, intact, and **not** a valid signature
    /// by the claimed address over this message on this network. An answer,
    /// not a fault (SM-R-6).
    MessageSigVerifyFailed = -29800 => "MSG_SIG_VERIFY_FAILED",
    /// `verify_message`: the armored string's checksum does not match — the
    /// paste was corrupted in transit. Distinct from
    /// [`Self::MessageSigVerifyFailed`] by ruling (rule 82): "your copy is
    /// damaged" and "not from that address" are different sentences.
    MessageSigCorrupted = -29801 => "MSG_SIG_CORRUPTED",
    /// `verify_message`: the scheme byte names a signature scheme this
    /// build does not implement (SM-R-5's append-only forward-compat
    /// field) — "this wallet is too old to check it", not "malformed".
    MessageSigUnsupportedScheme = -29802 => "MSG_SIG_UNSUPPORTED_SCHEME",
    /// Server: wallet-dir tenancy unavailable.
    TenantUnavailable = -29900 => "TENANT_UNAVAILABLE",
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
    /// Method name is REJECTED in the contract
    /// ([`crate::rejected::REJECTED_METHODS`]): answered `-32601` like any
    /// name the server does not serve, with the reason it is refused.
    #[error("{method} is not offered: {reason}")]
    MethodRejected {
        /// The name the caller sent.
        method: String,
        /// Why the contract refuses it.
        reason: &'static str,
    },
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
    /// `-29007`: the wallet file was made for another network. Network names
    /// are public, so both ride `data`.
    #[error("this wallet belongs to {wallet}, but this server runs {expected}")]
    WalletNetworkMismatch {
        /// The network the wallet file declares.
        wallet: String,
        /// The network this server runs.
        expected: String,
    },
    /// `-29008`: another process holds the wallet's lock.
    #[error("the wallet is open in another process — close it there first")]
    WalletLockedElsewhere,
    /// `-29009`: create was pointed at a directory that does not exist.
    #[error("the wallet directory does not exist — create it, then retry")]
    WalletDirMissing,
    /// `-29010`: the filesystem refused access to a wallet file.
    #[error("access to the wallet's files was denied — check their permissions")]
    WalletFileAccessDenied,
    /// `-29011`: a wallet file is damaged, or is not a wallet's.
    #[error("the wallet's files are damaged or are not a Shekyl wallet — restore from your seed")]
    WalletFileCorrupt,
    /// `-29012`: a wallet file was written by a version, or in a shape, this
    /// build cannot read.
    #[error(
        "the wallet's files were written by a version this build cannot read — open them \
         with the build that wrote them, or restore the wallet from your seed; your send \
         history, proofs for earlier sends, notes and payment requests are not restored"
    )]
    WalletFileVersionUnsupported,
    /// `-29013`: a read or write of the wallet's files failed underneath —
    /// disk full, filesystem error. The cause stays in the server log.
    #[error("reading or writing the wallet's files failed — check the disk, then retry")]
    WalletFileIoFailed,
    /// `-29014`: close refused while transactions are in flight.
    #[error("{count} transaction(s) are in flight — submit or discard them, then close")]
    WalletCloseBlocked {
        /// Pending transactions still held.
        count: usize,
    },
    /// `-29015`: the curve-tree membership data is unavailable for this
    /// session — its actor stopped, or its store would not rebuild.
    #[error("the wallet's membership data is unavailable — close and reopen the wallet")]
    CurveTreeUnavailable,
    /// `-29016`: the curve-tree store cannot be used. It holds no keys and
    /// no balance — the wallet rebuilds it from the chain — so the remedy is
    /// to delete it, never to restore the wallet.
    #[error("{}", curve_tree_store_message(*cause))]
    CurveTreeStoreUnusable {
        /// Why the store cannot be used.
        cause: CurveTreeStoreCause,
    },
    /// `-29017`: this computer's random-number source failed the check the
    /// wallet runs before it stakes (the `conformance` build's self-cert,
    /// S6). The wallet did not open: staking on numbers that fail it could
    /// link the wallet's stakes. The grade stays in the server log. The
    /// check's false-alarm rate is about one in a million, so one retry is
    /// the first remedy; a second failure means this computer.
    #[error(
        "this computer's random-number source failed the wallet's safety check, so the \
         wallet did not open — try once more; if it fails again, open the wallet on \
         another computer"
    )]
    RandomSourceCheckFailed,
    /// `-29201`: the daemon did not answer.
    #[error(
        "the daemon did not answer — check that it is running and its address is right, then retry"
    )]
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
    /// `-29204`: the refresh was cancelled before it completed.
    #[error("the refresh was cancelled before it completed — retry once the wallet is open")]
    RefreshCancelled,
    /// `-29205`: the daemon speaks another RPC version. `daemon_version` is
    /// `None` when its reply could not be read at all.
    #[error("{}", daemon_version_message(*wallet_version, *daemon_version))]
    DaemonVersionMismatch {
        /// This wallet's packed RPC version.
        wallet_version: u32,
        /// The daemon's packed RPC version, when its reply could be read.
        daemon_version: Option<u32>,
    },
    /// `-29206`: the daemon was built from other consensus rules. The two
    /// digests are public build facts, so they ride `data`.
    #[error(
        "the daemon was built with different consensus rules from this wallet — \
         connect to a daemon from the same release"
    )]
    DaemonRulesMismatch {
        /// This wallet's consensus-constants digest.
        wallet_digest: HashHex,
        /// The daemon's consensus-constants digest.
        daemon_digest: HashHex,
    },
    /// `-29207`: the daemon runs another network. Network names are public,
    /// so both ride `data`.
    #[error(
        "the daemon you connected to runs {daemon}, but this wallet is for {wallet} — \
         connect to a {wallet} daemon"
    )]
    DaemonNetworkMismatch {
        /// The network this wallet is for.
        wallet: Network,
        /// The network the daemon runs.
        daemon: Network,
    },
    /// `-29208`: the daemon's chain starts at another genesis block.
    #[error(
        "the daemon you connected to follows a different {network} chain from this \
         wallet's (their first blocks differ) — connect to a daemon on this wallet's chain"
    )]
    DaemonChainMismatch {
        /// The network whose genesis was compared.
        network: Network,
        /// The genesis block this wallet expects.
        wallet_genesis: HashHex,
        /// The daemon's genesis block.
        daemon_genesis: HashHex,
    },
    /// `-29209`: the daemon answered with something that breaks the RPC
    /// contract. What it sent stays in the server log.
    #[error(
        "the daemon's reply did not follow the RPC contract — it may be faulty or an \
         incompatible build; try another daemon"
    )]
    DaemonProtocolViolation,
    /// `-29212`: the daemon refused the call as outside this connection's
    /// grant. The same call on the same connection repeats the refusal.
    #[error(
        "the daemon refused the call as outside this wallet's grant — connect with a key \
         that holds it, or to your own node"
    )]
    DaemonGrantRefused,
    /// `-29213`: something other than this account's node answers at "this
    /// computer"'s rendezvous. A security failure: never retried.
    #[error(
        "something other than your Shekyl node is answering at its local address on this \
         computer — the wallet did not connect. Check what is running as your node"
    )]
    DaemonPeerCheckFailed,
    /// `-29214`: "this computer"'s node runs as a service. `view` is its
    /// view listener when it has one: the `daemon-address` to set.
    #[error("{}", shekyl_rpc_client::service_refusal(*view))]
    DaemonIsAService {
        /// The service's view listener, as its rendezvous record names it.
        view: Option<std::net::SocketAddr>,
    },
    /// `-29210`: the chain kept reorganizing during refresh.
    #[error(
        "the chain kept reorganizing during refresh and nothing was merged — retry once it settles"
    )]
    ChainUnstable,
    /// `-29211`: the finality window refused a rollback. The walk reads the
    /// ledger's hash record before ingest, and the tree file is a separate
    /// store, so the remedy clears both: delete `.curvetree`, then rescan.
    /// `history_cleared` is the rescan path, where the ledger is already
    /// empty and the file is the part still left.
    #[error("{}", resync_required_message(*depth, *finality_depth, *breach, *history_cleared))]
    ResyncRequired {
        /// Blocks the rollback would drop, or how far the hash record reached.
        depth: u64,
        /// `W`, in blocks.
        finality_depth: u64,
        /// Whether the depth was measured or the hash record ended first.
        breach: FinalityBreach,
        /// The refusing call was a rescan whose reset had already cleared history.
        history_cleared: bool,
    },
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
    /// `-29110`: the wallet has not synced a block yet.
    #[error("the wallet has not synced any blocks yet — refresh, then retry")]
    WalletNotSynced,
    /// `-29111`: the funds exist but wait on the membership-data rebuild.
    /// Amounts stay off the wire.
    #[error(
        "spending is temporarily unavailable while the wallet rebuilds its membership \
         data — retry when the rebuild finishes"
    )]
    SpendUnavailableRebuilding,
    /// `-29112`: an output is too fresh for the reference block.
    #[error("funds are not spendable yet — they become spendable in about {wait_blocks} block(s)")]
    OutputNotYetSpendable {
        /// Blocks the tip must advance first.
        wait_blocks: u64,
    },
    /// `-29113`: the chain is too short to anchor a reference block.
    #[error("the chain is too short to spend from yet — wait for more blocks")]
    ChainTooShortToSpend {
        /// The wallet's synced height.
        synced_height: u64,
        /// The minimum synced height a reference block needs.
        ref_anchor_age: u64,
    },
    /// `-29114`: the rebuild-loop breaker is tripped; builds stop until the
    /// operator acknowledges it (`acknowledge_submit_loop_breaker`).
    #[error(
        "sends are paused: the daemon refused the same kind of transaction twice — \
         investigate (data.cause), then call acknowledge_submit_loop_breaker"
    )]
    SubmitLoopBreakerTripped {
        /// The rejection the breaker tripped on, in the `-29106` vocabulary.
        cause: RejectCause,
    },
    /// `-29115`: a submit for this reservation is already running.
    #[error("a submit for this transaction is already in progress — wait for its result")]
    SubmitAlreadyPending,
    /// `-29116`: re-anchoring cannot complete right now; the reservation is
    /// kept.
    #[error("the transaction could not be refreshed for submission right now — retry")]
    ReanchorUnavailable,
    /// `-29117`: the proof cannot be re-anchored content-preservingly.
    #[error("the transaction can no longer be submitted as built — discard it and build again")]
    ReselectionRequired,
    /// `-29118`: the daemon answered the fee query with something the wallet
    /// could not read. Distinct from `-29102` (no answer) and `-29109` (an
    /// answer refused as unreasonable).
    #[error("the daemon's fee answer could not be read")]
    DaemonFeeResponseInvalid,
    /// `-29119`: the wallet's own signer hit an internal fault, named by
    /// one keyword: a builder invariant ([`InternalSignFault`](shekyl_engine_core::InternalSignFault)) or the
    /// wallet state signing reads. A bug, never the request's doing.
    #[error("the wallet's signer hit an internal fault ({fault}) — report it; the wallet log has the detail")]
    SignerFailed {
        /// The fault, one keyword from a closed set.
        fault: &'static str,
    },
    /// `-29123`: the amount needs more inputs than one transaction spends.
    #[error(
        "this send needs {count} inputs and one transaction spends at most {limit} — send less, \
         or first send part of your balance to yourself to merge small amounts"
    )]
    TooManyInputs {
        /// The inputs the build needed.
        count: usize,
        /// The most this transaction's shape can spend: at most
        /// the consensus cap, fewer in a deep tree.
        limit: usize,
    },
    /// `-29124`: more recipients than one transaction carries.
    #[error(
        "this send has {count} outputs with its change and one transaction carries at most \
         {limit} — split the recipients across two sends"
    )]
    TooManyOutputs {
        /// The outputs the request needs, change included.
        count: usize,
        /// [`MAX_OUTPUTS`].
        limit: usize,
    },
    /// `-29125`: an input's assembled tree path does not hold it — the
    /// wallet's copy of the membership data disagrees with the output.
    #[error(
        "the wallet's membership data does not hold an output this send spends — refresh the \
         wallet and build again"
    )]
    InputNotInTree {
        /// The input's position in the transaction.
        input: usize,
    },
    /// `-29126`: an input was received but its leaf does not open to this
    /// wallet's keys, so it can never be spent.
    #[error(
        "an output this send would spend was received but can never be spent by this wallet \
         (its sender published a leaf this wallet cannot open) — report it"
    )]
    InputUnspendable {
        /// The input's position in the transaction.
        input: usize,
    },
    /// `-29120`: the record of a send or a staking transaction (its signed
    /// bytes, and a send's tx secret) could not be saved because `target`
    /// is not writable for this account, so the wallet sent nothing (A19).
    /// A send's reservation is kept: fix the cause and submit it again, or
    /// discard it; a staking seal was removed, so the call is retried. Each
    /// other cause of an unsaved record is its own code, `-29128` to
    /// `-29134` (Rick, 2026-11-18 and 2026-11-19).
    #[error(
        "{} was not saved, so it was not sent — {} and {}",
        of.subject(),
        target.advice(),
        of.retry()
    )]
    SaveNotWritable {
        /// What could not be written: the folder, the file or the drive.
        target: SaveTarget,
        /// What the save was of.
        of: SaveOf,
    },
    /// `-29128`: the record was saved on a volume whose file system Windows
    /// cannot confirm keeps a save through a power cut (anything but NTFS:
    /// FAT32, exFAT, ReFS), so the wallet sent nothing (Rick, 2026-11-18).
    #[error(
        "{} was not sent — the wallet is on a {file_system} volume, where Windows cannot \
         confirm that a save survives a power cut; move the wallet to an NTFS volume and {}",
        of.subject(),
        of.retry()
    )]
    SaveDurabilityUnconfirmed {
        /// The volume's file system, as Windows names it.
        file_system: String,
        /// What the save was of.
        of: SaveOf,
    },
    /// `-29129`: the disk holding the wallet is full (or this account's
    /// quota on it is), so the record was not saved and the wallet sent
    /// nothing.
    #[error(
        "{} was not saved, so it was not sent — the disk holding the wallet is full; free \
         disk space and {}",
        of.subject(),
        of.retry()
    )]
    SaveDiskFull {
        /// What the save was of.
        of: SaveOf,
    },
    /// `-29130`: another program held the wallet's file (or the save's
    /// staged copy of it) open past the save's wait, so the record was not
    /// saved and the wallet sent nothing. A read-only file is `-29120` with
    /// `target: file`: the save reads the attribute to tell the two apart
    /// (Rick, 2026-11-19). The wording follows the daemon's
    /// `config.replace.held-open`.
    #[error(
        "{} was not saved, so it was not sent — another program, most likely an antivirus \
         scanner or a search indexer, held the wallet's file open; exclude the wallet's \
         folder from scanning and {}",
        of.subject(),
        of.retry()
    )]
    SaveFileHeld {
        /// What the save was of.
        of: SaveOf,
    },
    /// `-29131`: the disk reported an error at `step` of saving or
    /// confirming the record, so the wallet sent nothing. `error` is the
    /// system's words for it, never a path.
    #[error(
        "{} was not sent — the disk holding the wallet reported an error while {} \
         ({error}); check the disk and {}",
        of.subject(),
        step.words(),
        of.retry()
    )]
    SaveIoFailed {
        /// The step the disk failed.
        step: SaveStep,
        /// The system's description of the error, without a path.
        error: String,
        /// What the save was of.
        of: SaveOf,
    },
    /// `-29132`: the wallet is on a local NTFS drive that refused the
    /// rename Windows confirms survives a power cut, and the classic rename
    /// saved it, so the wallet sent nothing. Windows builds observed to give
    /// it: none observed (Rick, 2026-11-19).
    #[error(
        "{} was not sent — the wallet's NTFS drive refused the kind of save Windows can \
         confirm survives a power cut; move the wallet to another local NTFS drive and {}",
        of.subject(),
        of.retry()
    )]
    SaveRenameUnconfirmed {
        /// What the save was of.
        of: SaveOf,
    },
    /// `-29133`: the wallet could not prepare the record to save (its state
    /// failed a check, or could not be encoded or sealed): a fault in the
    /// wallet, not the disk, so the wallet sent nothing. The wallet's log
    /// has the detail.
    #[error(
        "{} was not sent — the wallet could not prepare its record to save (a fault in the \
         wallet, not the disk); {}",
        of.subject(),
        of.fault_remedy()
    )]
    SaveInternalFault {
        /// What the save was of.
        of: SaveOf,
    },
    /// `-29134`: the wallet is on a network drive, where no save is
    /// confirmed to survive a power cut whatever file system the drive
    /// reports (a Samba share reports NTFS), so the wallet sent nothing
    /// (Rick, 2026-11-19).
    #[error(
        "{} was not sent — the wallet is on a network drive, where no save is confirmed to \
         survive a power cut; move the wallet to a local drive and {}",
        of.subject(),
        of.retry()
    )]
    SaveOnNetworkDrive {
        /// What the save was of.
        of: SaveOf,
    },
    /// `-29121`: `tx_resend` named a transaction that is not a held send:
    /// it confirmed, was released, or was never this wallet's.
    #[error("no held send with this id — tx_alarm lists the held sends")]
    TxNotHeld,
    /// `-29122`: the held send's record holds no bytes to resend.
    #[error(
        "this held send has no saved bytes to resend — abandon it, or wait for refresh to \
         settle it"
    )]
    TxBytesMissing,
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
        /// OpenAPI `error.data`: the `rejected` verdict with its [`RejectCause`]
        /// (and `row` when a chain row refused it).
        data: Value,
    },
    /// Submit: transport-level ambiguity.
    #[error("submit ambiguous")]
    SubmitAmbiguous,
    /// `abandon_tx`: the send's current state forbids abandoning.
    /// `state` is the projected [`TransferState`](crate::TransferState) so the client hears
    /// the same vocabulary `get_transfers` speaks.
    #[error("cannot abandon: the send is {state}")]
    AbandonStateForbids {
        /// Projected [`TransferState`](crate::TransferState) of the refusing row.
        state: crate::TransferState,
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
    /// Proofs: verification was asked of a daemon that is not synchronized.
    #[error("daemon is syncing; retry proof verification once it has caught up")]
    ProofDaemonSyncing,
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
        "stake refused: persona funding is fragmented across more than {max} spendable \
         outputs — more than one bond post can carry; avoid splitting persona funding \
         across more than {max} stake_in transfers"
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

    /// `stake` (`-29506`): posture `support_complete_tree` was requested
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
    /// `unstake` (`-29521`): refused before anything was sent, seal released
    /// — retry at will after addressing `data.detail`.
    #[error("the exit was refused before anything was sent — see data.detail, then retry")]
    UnstakeRefusedReleased {
        /// The daemon's verdict rendering.
        detail: String,
    },
    /// `unstake` (`-29522`): the exit was sent; its record is held
    /// funds-safe until it lands or its end date passes (WR-Q3).
    #[error(
        "the exit was sent and its record is held funds-safe; do not retry. \
         Check staking_info: by the height it names, this exit will either \
         have completed or been withdrawn with its funds returned"
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
    /// `-29530`: a staker's sealed scan state would not load, and a staker
    /// does not open without its scan (privacy is not a degraded mode).
    #[error(
        "the wallet's staking scan state could not be loaded, so it will not open \
         without it — see the server log"
    )]
    StakeStateUnreadable,
    /// `-29530`, the form with a remedy: the staker's scan state file was
    /// written by another wallet version, older or newer, and this one
    /// refuses it rather than migrate it (rule 15; `FN_DSA_HYBRID.md` `FND-18` for the move off
    /// [`PSCAN_STATE_VERSION_KEYLESS_JOIN`](shekyl_engine_state::pscan_state::PSCAN_STATE_VERSION_KEYLESS_JOIN)).
    /// Shares the code with [`StakeStateUnreadable`](Self::StakeStateUnreadable)
    /// — both are "the scan state would not load, so the wallet will not
    /// open" — and `data` carries the file name and both versions so a client
    /// can tell the two apart without parsing prose (the `-29511` precedent).
    /// `file` is the name only. The directory stays on
    /// [`PScanStartError::StateFileVersionUnsupported`],
    /// which is what the server log prints. The remedy is the only one that
    /// exists today — nothing rewrites the file, `rescan_blockchain` needs an
    /// open wallet, and the wallet opens once the file is out of the way,
    /// after which the staking scan rebuilds it from the chain.
    #[error(
        "the wallet will not open: its staking scan file {file} was written by another \
         version of this wallet (file format {found}; this version reads format {expected}). \
         Move that one file out of the wallet's folder and open the wallet again; the staking \
         scan rebuilds it from the chain. Leave every other wallet file where it is"
    )]
    StakeStateVersionUnsupported {
        /// The scan state file's name (`<wallet>.wallet.pscan`).
        file: String,
        /// The format version the file carries.
        found: u32,
        /// The format version this wallet reads.
        expected: u32,
    },
    /// `-29531`: the wallet's Tor configuration is unusable.
    #[error("the wallet's Tor configuration is unusable, so serving cannot start")]
    ServingTorUnusable,
    /// `-29532`: the persona's serving identity is unavailable.
    #[error("the persona's serving identity is unavailable, so serving cannot start")]
    ServingIdentityUnavailable,
    /// `-29533`: serving needs the wallet's own node on loopback.
    #[error(
        "serving needs this wallet's own node: point the wallet server's daemon \
         address at a local node"
    )]
    ServingLocalNodeRequired,

    /// `get_shard_view` (`-29534`): the shard is still open. Its picture
    /// would change every block, so no view exists until it closes
    /// (`SHARD_VIEW_FETCH.md` `SV-D5`). `data.detail` is the daemon's own
    /// sentence, which names how far the open shard is from closing.
    #[error("this shard is still open — it has no view until the chain closes it")]
    ShardStillOpen {
        /// The daemon's message (secret-free by contract).
        detail: String,
    },
    /// `get_shard_view` (`-29535`): the shard is closed and the daemon's
    /// fetch reached no holder that served it. Transient: the holder set
    /// and the network change; retry later.
    #[error("the shard could not be retrieved from any holder — try again later")]
    ShardUnavailable {
        /// The daemon's message, which carries the attempt count.
        detail: String,
    },
    /// `get_shard_view` (`-29536`): the daemon this wallet is pointed at
    /// does not serve shard views. Two causes, one remedy (another
    /// daemon): the call is outside the wallet's grant there, or it runs
    /// with Tor off and has no client to fetch through (IG-Q90).
    #[error("this daemon does not serve shard views — point the wallet at a node that does")]
    ShardViewNotOffered {
        /// Why: `restricted` or `tor_off`.
        cause: ShardViewNotOfferedCause,
        /// The daemon's message.
        detail: String,
    },
    /// `get_shard_view` (`-29537`): the daemon is already fetching a shard
    /// for a bounded caller and opens one such fetch at a time
    /// (`RPC_CHANNEL.md` §6.3, IG-Q90). A view it already holds would have
    /// answered. Transient: retry shortly.
    #[error("the daemon is fetching another shard view — try again shortly")]
    ShardViewBusy {
        /// The daemon's message.
        detail: String,
    },

    /// `stake` (`-29538`): the persona scan has verified the chain to
    /// `scanned` and must reach `needed`, the finality horizon at the
    /// node's tip, before the shards a `CompleteTree` bond owes are known
    /// (`WALLET_SIDE_STORE.md` `WSS-Q15`). The scan runs on its own; nothing
    /// was written.
    #[error(
        "the staking scan has checked the chain up to block {scanned} and needs to reach block \
         {needed} before this bond's shards are known; nothing was written — try again once it \
         has caught up"
    )]
    StakeScanBehind {
        /// The scan's frontier: the first height it has not verified.
        scanned: u64,
        /// The frontier the fill needs.
        needed: u64,
    },
    /// `stake` (`-29539`): the node has already discarded the bodies of
    /// `shard`, which this bond owes: its full-form read answers `archived`
    /// (`SB-Q2`). The bodies come back only through the node's recovery
    /// fetch (`WALLET_SIDE_STORE.md` §6.5.4, the `WSS-Q9` handoff), which is
    /// not built, so the persona body store cannot be filled with it and the
    /// bond cannot be posted. This is also what a `CompleteTree` server
    /// joining after the first epochs meets. Nothing was written.
    #[error(
        "your node has already discarded shard {shard}, which this bond must hold; its bodies \
         come back only through the node's recovery fetch, which does not exist yet, so this \
         bond cannot be posted until it does. Nothing was written"
    )]
    StakeShardDiscarded {
        /// The discarded shard.
        shard: u64,
    },
    /// `stake` (`-29540`): the node's reply for `shard` does not match the
    /// chain the persona scan verified (a block off that chain, totals or
    /// bodies that do not add up). Bonding against it would be slashed, so
    /// nothing was written.
    #[error(
        "your node's reply for shard {shard} does not match the chain this wallet verified, so \
         nothing was written — check the node: {detail}"
    )]
    StakeDaemonMismatch {
        /// The shard being filled.
        shard: u64,
        /// What disagreed.
        detail: String,
    },
    /// `stake` (`-29541`): the persona body store is filled from the
    /// wallet's own node over loopback; this server's daemon address is not
    /// loopback.
    #[error(
        "staking needs this wallet's own node: the shards a bond holds are read from it over \
         loopback — point the wallet server's daemon address at a local node"
    )]
    StakeLocalNodeRequired {
        /// The transport constructor's own refusal.
        detail: String,
    },
    /// `stake` (`-29542`): the persona body store could not write `shard`.
    #[error("the staking body store could not write shard {shard}, so nothing was posted — check the disk: {detail}")]
    StakeBodyStoreFailed {
        /// The shard being written.
        shard: u64,
        /// The store's reason.
        detail: String,
    },
    /// `stake` (`-29543`): the node is still synchronizing, so which shards
    /// are final cannot be judged yet.
    #[error(
        "your node is still synchronizing; nothing was written — try again once it has caught up"
    )]
    StakeDaemonSyncing,
    /// `stake` (`-29544`): the node could not be read while filling the
    /// persona body store.
    #[error("your node could not be read while filling the staking body store, so nothing was posted — check the node and retry")]
    StakeDaemonUnreachable {
        /// The transport's reason.
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
            Self::MethodNotFound(_) | Self::MethodRejected { .. } => {
                WalletRpcErrorCode::MethodNotFound
            }
            Self::InvalidParams(_) => WalletRpcErrorCode::InvalidParams,
            Self::InternalError(_) => WalletRpcErrorCode::InternalError,
            Self::WalletAlreadyOpen => WalletRpcErrorCode::WalletAlreadyOpen,
            Self::WalletNotOpen => WalletRpcErrorCode::WalletNotOpen,
            Self::WalletFileExists => WalletRpcErrorCode::WalletFileExists,
            Self::WalletFileNotFound => WalletRpcErrorCode::WalletFileNotFound,
            Self::InvalidPassword => WalletRpcErrorCode::InvalidPassword,
            Self::WalletSessionEnded => WalletRpcErrorCode::WalletSessionEnded,
            Self::WalletNetworkMismatch { .. } => WalletRpcErrorCode::WalletNetworkMismatch,
            Self::WalletLockedElsewhere => WalletRpcErrorCode::WalletLockedElsewhere,
            Self::WalletDirMissing => WalletRpcErrorCode::WalletDirMissing,
            Self::WalletFileAccessDenied => WalletRpcErrorCode::WalletFileAccessDenied,
            Self::WalletFileCorrupt => WalletRpcErrorCode::WalletFileCorrupt,
            Self::WalletFileVersionUnsupported => WalletRpcErrorCode::WalletFileVersionUnsupported,
            Self::WalletFileIoFailed => WalletRpcErrorCode::WalletFileIoFailed,
            Self::WalletCloseBlocked { .. } => WalletRpcErrorCode::WalletCloseBlocked,
            Self::CurveTreeUnavailable => WalletRpcErrorCode::CurveTreeUnavailable,
            Self::CurveTreeStoreUnusable { .. } => WalletRpcErrorCode::CurveTreeStoreUnusable,
            Self::RandomSourceCheckFailed => WalletRpcErrorCode::RandomSourceCheckFailed,
            Self::DaemonUnreachable => WalletRpcErrorCode::DaemonUnreachable,
            Self::RefreshInProgress => WalletRpcErrorCode::RefreshInProgress,
            Self::RescanBlocked { .. } => WalletRpcErrorCode::RescanBlocked,
            Self::RescanIncomplete => WalletRpcErrorCode::RescanIncomplete,
            Self::RefreshCancelled => WalletRpcErrorCode::RefreshCancelled,
            Self::DaemonVersionMismatch { .. } => WalletRpcErrorCode::DaemonVersionMismatch,
            Self::DaemonRulesMismatch { .. } => WalletRpcErrorCode::DaemonRulesMismatch,
            Self::DaemonNetworkMismatch { .. } => WalletRpcErrorCode::DaemonNetworkMismatch,
            Self::DaemonChainMismatch { .. } => WalletRpcErrorCode::DaemonChainMismatch,
            Self::DaemonProtocolViolation => WalletRpcErrorCode::DaemonProtocolViolation,
            Self::DaemonGrantRefused => WalletRpcErrorCode::DaemonGrantRefused,
            Self::DaemonPeerCheckFailed => WalletRpcErrorCode::DaemonPeerCheckFailed,
            Self::DaemonIsAService { .. } => WalletRpcErrorCode::DaemonIsAService,
            Self::ChainUnstable => WalletRpcErrorCode::ChainUnstable,
            Self::ResyncRequired { .. } => WalletRpcErrorCode::ResyncRequired,
            Self::InvalidRecipient => WalletRpcErrorCode::InvalidRecipient,
            Self::InsufficientFunds => WalletRpcErrorCode::InsufficientFunds,
            Self::FeeEstimationFailed => WalletRpcErrorCode::FeeEstimationFailed,
            Self::DaemonFeeUnreasonable { .. } => WalletRpcErrorCode::DaemonFeeUnreasonable,
            Self::WalletNotSynced => WalletRpcErrorCode::WalletNotSynced,
            Self::SpendUnavailableRebuilding => WalletRpcErrorCode::SpendUnavailableRebuilding,
            Self::OutputNotYetSpendable { .. } => WalletRpcErrorCode::OutputNotYetSpendable,
            Self::ChainTooShortToSpend { .. } => WalletRpcErrorCode::ChainTooShortToSpend,
            Self::SubmitLoopBreakerTripped { .. } => WalletRpcErrorCode::SubmitLoopBreakerTripped,
            Self::SubmitAlreadyPending => WalletRpcErrorCode::SubmitAlreadyPending,
            Self::ReanchorUnavailable => WalletRpcErrorCode::ReanchorUnavailable,
            Self::ReselectionRequired => WalletRpcErrorCode::ReselectionRequired,
            Self::DaemonFeeResponseInvalid => WalletRpcErrorCode::DaemonFeeResponseInvalid,
            Self::SignerFailed { .. } => WalletRpcErrorCode::SignerFailed,
            Self::TooManyInputs { .. } => WalletRpcErrorCode::TooManyInputs,
            Self::TooManyOutputs { .. } => WalletRpcErrorCode::TooManyOutputs,
            Self::InputNotInTree { .. } => WalletRpcErrorCode::InputNotInTree,
            Self::InputUnspendable { .. } => WalletRpcErrorCode::InputUnspendable,
            Self::SaveNotWritable { .. } => WalletRpcErrorCode::SaveNotWritable,
            Self::SaveDurabilityUnconfirmed { .. } => WalletRpcErrorCode::SaveDurabilityUnconfirmed,
            Self::SaveDiskFull { .. } => WalletRpcErrorCode::SaveDiskFull,
            Self::SaveFileHeld { .. } => WalletRpcErrorCode::SaveFileHeld,
            Self::SaveIoFailed { .. } => WalletRpcErrorCode::SaveIoFailed,
            Self::SaveRenameUnconfirmed { .. } => WalletRpcErrorCode::SaveRenameUnconfirmed,
            Self::SaveInternalFault { .. } => WalletRpcErrorCode::SaveInternalFault,
            Self::SaveOnNetworkDrive { .. } => WalletRpcErrorCode::SaveOnNetworkDrive,
            Self::TxNotHeld => WalletRpcErrorCode::TxNotHeld,
            Self::TxBytesMissing => WalletRpcErrorCode::TxBytesMissing,
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
            Self::ProofDaemonSyncing => WalletRpcErrorCode::ProofDaemonSyncing,
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
            Self::StakeStateUnreadable | Self::StakeStateVersionUnsupported { .. } => {
                WalletRpcErrorCode::StakeStateUnreadable
            }
            Self::ServingTorUnusable => WalletRpcErrorCode::ServingTorUnusable,
            Self::ServingIdentityUnavailable => WalletRpcErrorCode::ServingIdentityUnavailable,
            Self::ServingLocalNodeRequired => WalletRpcErrorCode::ServingLocalNodeRequired,
            Self::ShardStillOpen { .. } => WalletRpcErrorCode::ShardStillOpen,
            Self::ShardUnavailable { .. } => WalletRpcErrorCode::ShardUnavailable,
            Self::ShardViewNotOffered { .. } => WalletRpcErrorCode::ShardViewNotOffered,
            Self::ShardViewBusy { .. } => WalletRpcErrorCode::ShardViewBusy,
            Self::StakeScanBehind { .. } => WalletRpcErrorCode::StakeScanBehind,
            Self::StakeShardDiscarded { .. } => WalletRpcErrorCode::StakeShardDiscarded,
            Self::StakeDaemonMismatch { .. } => WalletRpcErrorCode::StakeDaemonMismatch,
            Self::StakeLocalNodeRequired { .. } => WalletRpcErrorCode::StakeLocalNodeRequired,
            Self::StakeBodyStoreFailed { .. } => WalletRpcErrorCode::StakeBodyStoreFailed,
            Self::StakeDaemonSyncing => WalletRpcErrorCode::StakeDaemonSyncing,
            Self::StakeDaemonUnreachable { .. } => WalletRpcErrorCode::StakeDaemonUnreachable,
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
            | Self::UnstakeLocalNodeRequired { detail }
            | Self::ShardStillOpen { detail }
            | Self::ShardUnavailable { detail }
            | Self::ShardViewBusy { detail }
            | Self::StakeLocalNodeRequired { detail }
            | Self::StakeDaemonUnreachable { detail } => Some(json!({ "detail": detail })),
            Self::StakeScanBehind { scanned, needed } => {
                Some(json!({ "scanned": scanned, "needed": needed }))
            }
            Self::StakeShardDiscarded { shard } => Some(json!({ "shard": shard })),
            Self::StakeDaemonMismatch { shard, detail }
            | Self::StakeBodyStoreFailed { shard, detail } => {
                Some(json!({ "shard": shard, "detail": detail }))
            }
            Self::ShardViewNotOffered { cause, detail } => {
                Some(json!({ "cause": cause.as_str(), "detail": detail }))
            }
            // The `-29530` pair: the version form carries what the client
            // needs to show the remedy; the unreadable form carries nothing
            // (its cause is in the server log), so `data` is absent there.
            Self::StakeStateVersionUnsupported {
                file,
                found,
                expected,
            } => Some(json!({ "file": file, "found": found, "expected": expected })),
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
            Self::WalletNetworkMismatch { wallet, expected } => {
                Some(json!({ "wallet": wallet, "expected": expected }))
            }
            Self::WalletCloseBlocked { count } => Some(json!({ "count": count })),
            Self::CurveTreeStoreUnusable { cause } => Some(json!({ "cause": cause.as_str() })),
            Self::DaemonVersionMismatch {
                wallet_version,
                daemon_version,
            } => Some(json!({
                "wallet_version": IdentityMismatch::version_display(*wallet_version),
                "daemon_version": daemon_version.map(IdentityMismatch::version_display),
                "update": daemon_version.map(|theirs| OlderSide::of(*wallet_version, theirs).as_str()),
            })),
            Self::DaemonRulesMismatch {
                wallet_digest,
                daemon_digest,
            } => Some(json!({
                "wallet_digest": wallet_digest.to_string(),
                "daemon_digest": daemon_digest.to_string(),
            })),
            Self::DaemonNetworkMismatch { wallet, daemon } => {
                Some(json!({ "wallet": wallet, "daemon": daemon }))
            }
            Self::DaemonChainMismatch {
                network,
                wallet_genesis,
                daemon_genesis,
            } => Some(json!({
                "network": network,
                "wallet_genesis": wallet_genesis.to_string(),
                "daemon_genesis": daemon_genesis.to_string(),
            })),
            Self::OutputNotYetSpendable { wait_blocks } => {
                Some(json!({ "wait_blocks": wait_blocks }))
            }
            Self::SignerFailed { fault } => Some(json!({ "fault": fault })),
            Self::SaveDurabilityUnconfirmed { file_system, .. } => {
                Some(json!({ "file_system": file_system }))
            }
            Self::SaveNotWritable { target, .. } => Some(json!({ "target": target.as_str() })),
            Self::SaveIoFailed { step, error, .. } => {
                Some(json!({ "step": step.as_str(), "error": error }))
            }
            Self::TooManyInputs { count, limit } | Self::TooManyOutputs { count, limit } => {
                Some(json!({ "count": count, "limit": limit }))
            }
            Self::InputNotInTree { input } | Self::InputUnspendable { input } => {
                Some(json!({ "input": input }))
            }
            Self::ChainTooShortToSpend {
                synced_height,
                ref_anchor_age,
            } => Some(json!({
                "synced_height": synced_height,
                "ref_anchor_age": ref_anchor_age,
            })),
            Self::SubmitLoopBreakerTripped { cause } => Some(json!({ "cause": cause })),
            Self::DaemonIsAService { view } => {
                Some(json!({ "view": view.map(|view| view.to_string()) }))
            }
            Self::DaemonFeeUnreasonable {
                reason,
                rate,
                bound,
            } => Some(json!({ "reason": reason, "rate": rate, "bound": bound })),
            Self::ResyncRequired {
                depth,
                finality_depth,
                breach,
                history_cleared,
            } => Some(json!({
                "depth": depth,
                "finality_depth": finality_depth,
                "breach": breach.as_str(),
                "history_cleared": history_cleared,
            })),
            _ => None,
        }
    }

    fn submit_rejected(cause: RejectCause, row: Option<String>) -> Self {
        let mut data = json!({ "verdict": "rejected", "cause": cause });
        if let Some(row) = row {
            data["row"] = json!(row);
        }
        Self::SubmitRejected { data }
    }

    /// Map a producer failure that arrives **after** `start_rescan` returned
    /// a handle — i.e. after the reset is durable.
    ///
    /// The durability claim is the load-bearing axis, not the failure class:
    /// `-29201` means "wallet untouched" (preflight only). A join-path
    /// failure means history is empty until a rescan finishes, so those
    /// failures emit [`WalletRpcErrorCode::RescanIncomplete`]. A rollback
    /// past finality is the exception: finishing the rescan cannot repair
    /// the curve tree, so it emits [`WalletRpcErrorCode::ResyncRequired`]
    /// with `history_cleared`. Mapping only Io /
    /// Cancelled / Malformed / CurveTree and leaving ConcurrentMutation /
    /// InternalInvariantViolation to `-32603` was the same bug class as
    /// reusing `-29201` — clients that branch on the durability code would
    /// miss an incomplete rescan. Exhaustive match (no catch-all): a new
    /// [`RefreshError`] variant fails to compile here until its durability
    /// claim is named.
    ///
    /// For a server or embedder that reports a rescan's join-path result.
    pub fn from_rescan_scan_failure(err: RefreshError) -> Self {
        match &err {
            // Start-only refusals — unreachable on the join path. Preserve
            // their codes if they appear rather than inventing a third story.
            RefreshError::AlreadyRunning
            | RefreshError::RescanBlocked { .. }
            | RefreshError::RescanPersist(_) => err.into(),

            // The other producer failures after a durable reset share one wire
            // code so durability-branching clients cannot miss a subclass.
            // A past-finality rollback is the arm below (`-29211`), not this
            // one. Detail stays server-side (`message()` contract / rule 30).
            RefreshError::Io(io) => {
                tracing::warn!(detail = %io, "rescan scan failed after durable reset");
                Self::RescanIncomplete
            }
            // A past-finality rollback is not repaired by finishing the
            // rescan: the reset emptied history and left the curve tree
            // where it was. Same code as a refresh, and the message says
            // the history is already gone so a client does not retry the
            // rescan expecting the tree to move.
            RefreshError::ReorgDeeperThanFinality { stop } => {
                tracing::warn!(?stop, "rescan hit a rollback past finality");
                resync_required(*stop, true)
            }
            RefreshError::Cancelled
            | RefreshError::ReorgStorm
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
    /// Every arm named: an open failure reaches `-32603` only when it is a
    /// bug (a key-derivation primitive failing), never as a guess.
    fn from(err: OpenError) -> Self {
        match err {
            OpenError::IncorrectPassword => Self::InvalidPassword,
            OpenError::OutstandingPendingTx { count } => Self::WalletCloseBlocked { count },
            OpenError::NetworkMismatch { wallet, expected } => Self::WalletNetworkMismatch {
                wallet: wallet.to_string(),
                expected: expected.to_string(),
            },
            OpenError::Io(io) => from_io_error(io),
            OpenError::Key(e) => from_key_error(&e),
            OpenError::Persistence(e) => e.into(),
            // The grade was logged where the check ran. The wire carries the
            // remedy only.
            OpenError::StakeRngSelfCertFailed => Self::RandomSourceCheckFailed,
        }
    }
}

impl From<RefreshError> for WalletRpcError {
    fn from(err: RefreshError) -> Self {
        match err {
            RefreshError::AlreadyRunning => Self::RefreshInProgress,
            // A concurrent refresh merged first; the remedy is the
            // single-flight one — retry.
            RefreshError::ConcurrentMutation { wallet, result } => {
                tracing::info!(%wallet, %result, "refresh lost a concurrent merge");
                Self::RefreshInProgress
            }
            // A state conflict, not a malformed request: `rescan_blockchain`
            // takes an empty params object, so the params were by definition
            // correct. `-32602` here would tell an automated client its
            // request shape is permanently wrong when the truth is "retry
            // once the in-flight transactions settle".
            RefreshError::RescanBlocked { reservations } => Self::RescanBlocked {
                detail: format!("{reservations} reservation(s)"),
            },
            // The reset's durable save failed: a storage failure. The detail
            // can carry a local filesystem path, so it stays in the log.
            RefreshError::RescanPersist(detail) => {
                tracing::warn!(detail = %detail, "rescan reset persistence failed");
                Self::WalletFileIoFailed
            }
            RefreshError::Io(io) => from_io_error(io),
            RefreshError::Cancelled => Self::RefreshCancelled,
            RefreshError::ReorgStorm => Self::ChainUnstable,
            RefreshError::CurveTreeIngest { fault } => from_curve_tree_ingest_fault(fault),
            // Producer bugs (decision log, 2026-04-26), not states a client
            // can remedy.
            RefreshError::MalformedScanResult { reason } => {
                internal_detail("malformed scan result", reason)
            }
            RefreshError::InternalInvariantViolation { context } => {
                internal_detail("refresh invariant", context)
            }
            // The remedy is the whole point of the error, so it does not go
            // through `internal_detail` (that keeps its detail server-side).
            RefreshError::ReorgDeeperThanFinality { stop } => resync_required(stop, false),
        }
    }
}

impl From<PScanStartError> for WalletRpcError {
    fn from(err: PScanStartError) -> Self {
        match err {
            // The auto-start (`start_pscan_if_staker`) guards on the stake
            // engine before spawning, and a fresh open holds a fresh
            // single-flight slot, so neither is reachable on the lifecycle
            // path: reaching one is a bug.
            PScanStartError::NoStakeEngine => internal_detail("p-scan start", "no stake engine"),
            PScanStartError::AlreadyRunning => {
                internal_detail("p-scan start", "task already running")
            }
            // A mid-session bond-watch recovery: a domain state with a
            // user-doable remedy (reopen), never an internal fault.
            PScanStartError::RecoveredPendingReopen => Self::StakeRecoveredPendingReopen,
            // A corrupt seal, a pending-post version mismatch, or a nested
            // cursor version. The boxed cause can carry a local path; it is
            // logged at the reachable call site (`lifecycle::wrap_and_start_tasks`),
            // not handed to the client.
            PScanStartError::LoadFailed(_source) => Self::StakeStateUnreadable,
            // The outer schema word. The engine error carries the path, which
            // the log already printed. The client gets the file's name when
            // that name is Unicode; otherwise the detail-free form, never a
            // replacement character or a directory.
            PScanStartError::StateFileVersionUnsupported {
                path,
                found,
                expected,
            } => match staking_scan_file_name(&path) {
                Some(file) => Self::StakeStateVersionUnsupported {
                    file,
                    found,
                    expected,
                },
                None => Self::StakeStateUnreadable,
            },
        }
    }
}

/// The scan-state file's name, for the client. `None` when the path has no
/// final component, that component is empty, or it is not Unicode.
fn staking_scan_file_name(path: &std::path::Path) -> Option<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

impl From<ServingStartError> for WalletRpcError {
    fn from(err: ServingStartError) -> Self {
        match err {
            ServingStartError::NoStakeEngine => internal_detail("serving start", "no stake engine"),
            ServingStartError::AlreadyRunning => {
                internal_detail("serving start", "task already running")
            }
            ServingStartError::RecoveredPendingReopen => Self::StakeRecoveredPendingReopen,
            // Each source can name a local path (the derived tor directory) or
            // the refused URL; those stay in the server log.
            ServingStartError::TorConfig(source) => {
                tracing::warn!(error = %source, "serving start: tor configuration unusable");
                Self::ServingTorUnusable
            }
            ServingStartError::Identity(source) => {
                tracing::warn!(error = %source, "serving start: persona identity unavailable");
                Self::ServingIdentityUnavailable
            }
            ServingStartError::DaemonNotLoopback(source) => {
                tracing::warn!(error = %source, "serving start: daemon is not loopback");
                Self::ServingLocalNodeRequired
            }
        }
    }
}

impl From<FeeEstimatorError> for WalletRpcError {
    fn from(err: FeeEstimatorError) -> Self {
        match err {
            // The fee query's own "no answer" code (`-29102`); every other
            // daemon fault names its cause.
            FeeEstimatorError::Daemon(DaemonFault::Unreachable) => Self::FeeEstimationFailed,
            FeeEstimatorError::Daemon(fault) => from_daemon_fault(fault, "fee query"),
            FeeEstimatorError::DaemonResponseInvalid { reason } => {
                tracing::warn!(reason = %reason, "daemon fee response invalid");
                Self::DaemonFeeResponseInvalid
            }
            FeeEstimatorError::DaemonFeeUnreasonable(v) => Self::DaemonFeeUnreasonable {
                reason: v.reason(),
                rate: v.rate(),
                bound: v.bound(),
            },
            // `FeeEstimatorError` is `#[non_exhaustive]` (Phase 0a, semver for
            // consumers outside the workspace), so this arm is forced. Inside
            // one workspace build it is unreachable: every variant is named
            // above. A new variant lands here until it is named.
            other => internal_detail("fee estimator variant unmapped at the RPC boundary", other),
        }
    }
}

impl From<SendError> for WalletRpcError {
    /// Every arm named (no fall-through): each build refusal carries the
    /// remedy it names, and `-32603` is left to proof / signature
    /// construction failing and broken build preconditions — bugs.
    fn from(err: SendError) -> Self {
        match err {
            SendError::InvalidRecipient { .. } => Self::InvalidRecipient,
            SendError::Fee(e) => e.into(),
            SendError::InsufficientFunds { .. } => Self::InsufficientFunds,
            SendError::Io(io) => from_io_error(io),
            SendError::Sign(fault) => fault.into(),
            SendError::NotSynced => Self::WalletNotSynced,
            // No spend-key material in scope: the session's signer is gone,
            // which is what `-29006` names — reopen the wallet.
            SendError::SignerUnavailable => Self::WalletSessionEnded,
            SendError::SignerFailed { fault } => Self::SignerFailed {
                fault: fault.keyword(),
            },
            SendError::BuildInvariant { reason } => internal_detail("build invariant", reason),
            SendError::SpendUnavailableRebuilding { .. } => Self::SpendUnavailableRebuilding,
            SendError::CurveTreeUnavailable { detail } => {
                tracing::warn!(detail = %detail, "curve-tree actor unavailable at build");
                Self::CurveTreeUnavailable
            }
            SendError::OutputNotYetSpendable { wait_blocks, .. } => Self::OutputNotYetSpendable {
                wait_blocks: wait_blocks.to_raw(),
            },
            SendError::WalletTooYoungToSpend {
                synced_height,
                ref_anchor_age,
            } => Self::ChainTooShortToSpend {
                synced_height: synced_height.to_raw(),
                ref_anchor_age: ref_anchor_age.to_raw(),
            },
            SendError::SubmitLoopBreakerTripped { kind } => Self::SubmitLoopBreakerTripped {
                cause: terminal_to_reject_cause(kind),
            },
        }
    }
}

/// The signing pass's fault to its code: the four the user acts on each
/// get their own, with the limit or the input named; every internal
/// invariant is `-29119`, named by its keyword (A16). The one mapping for
/// every path that signs: a transfer, a stake, a drain, an unstake and a
/// collect.
impl From<SignFault> for WalletRpcError {
    fn from(fault: SignFault) -> Self {
        match fault {
            SignFault::TooManyInputs { count, limit } => Self::TooManyInputs { count, limit },
            SignFault::TooManyOutputs { count } => Self::TooManyOutputs {
                count,
                limit: MAX_OUTPUTS,
            },
            SignFault::SpentOutputNotInLeafChunk { input } => Self::InputNotInTree { input },
            SignFault::PqcLeafMismatch { input } => Self::InputUnspendable { input },
            SignFault::Internal(internal) => Self::SignerFailed {
                fault: internal.keyword(),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// The daemon: each fault, named where it was raised, to its own code.
// ---------------------------------------------------------------------------

/// A daemon failure by its [`DaemonFault`]. `detail` is the failure's own
/// rendering and can carry text the daemon sent, so it goes to the log
/// only. The "no answer" arm is `-29201`; a caller whose contract names a
/// narrower "no answer" code (the fee query's `-29102`) matches that arm
/// before delegating here.
pub(crate) fn from_daemon_fault(fault: DaemonFault, detail: &str) -> WalletRpcError {
    match fault {
        DaemonFault::Unreachable => {
            tracing::info!(detail, "daemon did not answer");
            WalletRpcError::DaemonUnreachable
        }
        DaemonFault::Identity(mismatch) => {
            tracing::warn!(axis = %mismatch.axis(), detail, "daemon refused on identity");
            from_identity_mismatch(mismatch)
        }
        DaemonFault::Protocol => {
            tracing::warn!(detail, "daemon reply broke the RPC contract");
            WalletRpcError::DaemonProtocolViolation
        }
        DaemonFault::FeeResponse => {
            tracing::warn!(detail, "daemon fee response unusable");
            WalletRpcError::DaemonFeeResponseInvalid
        }
        DaemonFault::Internal => internal_detail("daemon request", detail),
        DaemonFault::NotPermitted => {
            tracing::warn!(detail, "daemon refused the call as outside the grant");
            WalletRpcError::DaemonGrantRefused
        }
        DaemonFault::PeerCheck => {
            tracing::error!(
                detail,
                "the peer at this computer's rendezvous failed the check"
            );
            WalletRpcError::DaemonPeerCheckFailed
        }
        DaemonFault::Service(view) => {
            tracing::warn!(detail, "this computer's node is a service; nothing dialled");
            WalletRpcError::DaemonIsAService { view }
        }
    }
}

/// A curve-tree ingest failure that survived the engine's one rebuild, by
/// its remedy. Reopening helps only where the session's tree is what
/// failed; a fault a reopen reproduces never answers "close and reopen".
fn from_curve_tree_ingest_fault(fault: CurveTreeIngestFault) -> WalletRpcError {
    tracing::warn!(%fault, "curve-tree ingest failed");
    match fault {
        // The actor, or the store under it, would not come back for this
        // session. A reopen reopens the store, which names its own fault.
        CurveTreeIngestFault::ActorUnavailable
        | CurveTreeIngestFault::ClientPoisoned
        | CurveTreeIngestFault::RebuildFailed => WalletRpcError::CurveTreeUnavailable,
        // The daemon's data broke the contract: leaves its own header does not
        // commit to, or a block that does not decode.
        CurveTreeIngestFault::RootMismatch | CurveTreeIngestFault::BackfillBlockUndecodable => {
            WalletRpcError::DaemonProtocolViolation
        }
        // Contract and arithmetic faults a resume reproduces: bugs.
        CurveTreeIngestFault::ClientRejected
        | CurveTreeIngestFault::TipHeightOverflow
        | CurveTreeIngestFault::BackfillHeightOverflow => {
            internal_detail("curve-tree ingest", fault)
        }
    }
}

/// A daemon RPC failure a caller holds untyped by [`IoError`] (the proof
/// path keeps the upstream error). For any surface that holds a bare
/// [`RpcError`](shekyl_rpc_client::RpcError).
pub fn from_daemon_rpc_error(err: &shekyl_rpc_client::RpcError) -> WalletRpcError {
    from_daemon_fault(err.fault(), &err.to_string())
}

/// One code per identity axis, because each has its own remedy.
fn from_identity_mismatch(mismatch: IdentityMismatch) -> WalletRpcError {
    match mismatch {
        IdentityMismatch::Wire { ours, theirs } => WalletRpcError::DaemonVersionMismatch {
            wallet_version: ours,
            daemon_version: Some(theirs),
        },
        IdentityMismatch::WireUnreadable { ours } => WalletRpcError::DaemonVersionMismatch {
            wallet_version: ours,
            daemon_version: None,
        },
        IdentityMismatch::Rules { ours, theirs } => WalletRpcError::DaemonRulesMismatch {
            wallet_digest: ours,
            daemon_digest: theirs,
        },
        IdentityMismatch::Network { ours, theirs } => WalletRpcError::DaemonNetworkMismatch {
            wallet: ours,
            daemon: theirs,
        },
        IdentityMismatch::Genesis {
            ours,
            theirs,
            network,
        } => WalletRpcError::DaemonChainMismatch {
            network,
            wallet_genesis: ours,
            daemon_genesis: theirs,
        },
    }
}

/// Which side of an RPC version mismatch to update: the older one.
#[derive(Clone, Copy)]
enum OlderSide {
    Daemon,
    Wallet,
}

impl OlderSide {
    /// The two versions differ, or there would be no mismatch.
    const fn of(wallet_version: u32, daemon_version: u32) -> Self {
        if daemon_version < wallet_version {
            Self::Daemon
        } else {
            Self::Wallet
        }
    }

    /// The `data.update` value.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::Wallet => "wallet",
        }
    }
}

/// `-29211`: the measured stop, plus whether this call already cleared history.
fn resync_required(stop: FinalityStop, history_cleared: bool) -> WalletRpcError {
    WalletRpcError::ResyncRequired {
        depth: stop.depth.to_raw(),
        finality_depth: stop.finality_depth.to_raw(),
        breach: stop.breach,
        history_cleared,
    }
}

fn resync_required_message(
    depth: u64,
    finality_depth: u64,
    breach: FinalityBreach,
    history_cleared: bool,
) -> String {
    let cause = match breach {
        FinalityBreach::Measured => format!(
            "a rollback of {depth} blocks is outside the {finality_depth}-block window this \
             wallet treats as final ({breach})"
        ),
        // `depth` here is how far the record reached. It can be smaller than
        // the window, so it is not "a rollback outside the window".
        FinalityBreach::RecordEnded => format!(
            "the hash record ended after {depth} mismatches, before a common ancestor inside \
             the {finality_depth}-block window was confirmed ({breach})"
        ),
    };
    let remedy = if history_cleared {
        "Wallet history is already empty from this rescan. Close the wallet, delete its \
         .curvetree file, and open it again. The next refresh rebuilds the tree from genesis. \
         Running rescan_blockchain again while that file is still there leaves the same tree \
         in place"
    } else {
        "Close the wallet, delete its .curvetree file, open it again, and run \
         rescan_blockchain — in that order. The rescan rebuilds scan history from genesis, \
         and it rebuilds the tree only once that file is gone"
    };
    format!("{cause}. {remedy}")
}

/// `-29205`'s message: the remedy is to update whichever side is older, or,
/// when the daemon's reply could not be read, to run matching releases.
fn daemon_version_message(wallet_version: u32, daemon_version: Option<u32>) -> String {
    let ours = IdentityMismatch::version_display(wallet_version);
    match daemon_version {
        Some(theirs) => {
            let (newer_or_older, update) = match OlderSide::of(wallet_version, theirs) {
                OlderSide::Daemon => ("older", "the daemon"),
                OlderSide::Wallet => ("newer", "this wallet"),
            };
            format!(
                "the daemon runs a {newer_or_older} RPC version ({}) than this wallet ({ours}) — \
                 update {update}",
                IdentityMismatch::version_display(theirs),
            )
        }
        None => format!(
            "the daemon's version reply could not be read, so it is not the RPC version this \
             wallet ({ours}) was built for — run matching releases"
        ),
    }
}

// ---------------------------------------------------------------------------
// The wallet's storage: typed causes to named codes. Every path, the file
// store's and the curve-tree store's, stays in the server log.
// ---------------------------------------------------------------------------

/// An [`IoError`] by its typed cause. Every arm carries what it means for
/// the remedy, classified where it was raised, so the same failure answers
/// the same code whichever operation met it.
fn from_io_error(io: IoError) -> WalletRpcError {
    match io {
        IoError::WalletFile(e) => from_wallet_file_error(&e),
        IoError::CurveTreeStore { fault, detail } => from_store_open_fault(fault, &detail),
        IoError::PStore { detail } => internal_detail("p-store", detail),
        IoError::Daemon { fault, detail } => from_daemon_fault(fault, &detail),
        // Only this wallet's own view material reaches here as a scanner
        // failure (a daemon's malformed block is a `Daemon` protocol fault):
        // a bug, not a state a client can remedy.
        IoError::Scanner { detail } => internal_detail("scanner", detail),
    }
}

/// A wallet-file failure, variant by variant. The upstream `Display`s name
/// paths (`… at {path}`), so no message is taken from them; the detail is
/// logged here.
fn from_wallet_file_error(err: &WalletFileError) -> WalletRpcError {
    use WalletFileError as F;
    let code = match err {
        F::Envelope(e) => return from_envelope_error(e, err),
        F::Payload(PayloadError::UnsupportedVersion { .. }) => {
            WalletRpcError::WalletFileVersionUnsupported
        }
        // A file that parsed and cannot be this wallet's state: a damaged
        // frame, a network byte this build does not know, a postcard body
        // that does not decode, or records that contradict each other. A
        // group ledger that holds one output twice is that last case, the
        // same class as a solo ledger that breaks an invariant.
        F::Payload(
            PayloadError::TooShort { .. }
            | PayloadError::BadMagic
            | PayloadError::UnknownPayloadKind(_)
            | PayloadError::NonZeroReserved
            | PayloadError::BodyLenMismatch { .. }
            | PayloadError::BodyLenTooLarge { .. },
        )
        | F::UnexpectedPayloadKind { .. }
        | F::UnknownNetwork(_)
        | F::Ledger(
            WalletLedgerError::Postcard(_)
            | WalletLedgerError::InvariantFailed { .. }
            | WalletLedgerError::GroupInvariantFailed { .. },
        ) => WalletRpcError::WalletFileCorrupt,
        F::Ledger(
            WalletLedgerError::UnsupportedFormatVersion { .. }
            | WalletLedgerError::UnsupportedGroupFormatVersion { .. }
            | WalletLedgerError::UnsupportedBlockVersion { .. },
        )
        | F::UnknownCapability(_)
        | F::GroupWalletKeysFile
        | F::NotAGroupWalletKeysFile => WalletRpcError::WalletFileVersionUnsupported,
        F::Io(e) => from_io_kind(e.kind()),
        F::KeysFileAlreadyExists { .. } | F::SaveAsTargetExists { .. } => {
            WalletRpcError::WalletFileExists
        }
        F::DirectoryMissing { .. } => WalletRpcError::WalletDirMissing,
        F::AlreadyLocked { .. } => WalletRpcError::WalletLockedElsewhere,
        // The step's error by its kind, as an untyped one is; a read-only
        // file is this account's access refused.
        F::SaveStep { source, .. } => from_io_kind(source.kind()),
        F::ReadOnly { .. } => WalletRpcError::WalletFileAccessDenied,
        F::HeldOpen(_) => WalletRpcError::WalletFileIoFailed,
        F::NetworkMismatch { expected, found } => WalletRpcError::WalletNetworkMismatch {
            wallet: found.to_string(),
            expected: expected.to_string(),
        },
        // `save_as` is not a JSON-RPC method, and a write-once violation is a
        // bug by the variant's own contract.
        F::SaveAsCrossFilesystem { .. } | F::KeysFileWriteOnceViolation { .. } => {
            return internal_detail("wallet file", err);
        }
    };
    tracing::warn!(error = %err, code = code.code().as_i32(), "wallet file refused");
    code
}

fn from_envelope_error(e: &WalletEnvelopeError, whole: &WalletFileError) -> WalletRpcError {
    use WalletEnvelopeError as E;
    let code = match e {
        E::InvalidPasswordOrCorrupt => WalletRpcError::InvalidPassword,
        E::TooShort
        | E::BadMagic
        | E::KdfParamsOutOfRange { .. }
        | E::CapContentLenMismatch { .. }
        | E::StateSeedBlockMismatch => WalletRpcError::WalletFileCorrupt,
        E::FormatVersionTooNew { .. }
        | E::FormatVersionRetired { .. }
        | E::UnsupportedKdfAlgo(_)
        | E::UnsupportedWrapCount(_)
        | E::UnknownCapabilityMode(_) => WalletRpcError::WalletFileVersionUnsupported,
        E::Internal(_) => return internal_detail("wallet envelope", whole),
    };
    tracing::warn!(error = %whole, code = code.code().as_i32(), "wallet envelope refused");
    code
}

/// A filesystem failure by kind. `NotFound` is the file-level answer: a
/// missing *directory* on create is named before any write
/// ([`WalletFileError::DirectoryMissing`]).
fn from_io_kind(kind: std::io::ErrorKind) -> WalletRpcError {
    match kind {
        std::io::ErrorKind::NotFound => WalletRpcError::WalletFileNotFound,
        std::io::ErrorKind::PermissionDenied => WalletRpcError::WalletFileAccessDenied,
        // `io::ErrorKind` is foreign and `#[non_exhaustive]`: every other kind
        // is the filesystem failing underneath (disk full, I/O error, …).
        _ => WalletRpcError::WalletFileIoFailed,
    }
}

impl From<PersistenceError> for WalletRpcError {
    fn from(err: PersistenceError) -> Self {
        match err {
            PersistenceError::WalletFile(e) => from_wallet_file_error(&e),
            // A dispatch whose rename landed but whose durability was not
            // confirmed. Nothing was sent. The submit path reports this as
            // `DispatchNotSaved`; this arm is the same answer, by cause, if
            // the error reaches the boundary on its own.
            err @ PersistenceError::DurabilityUnconfirmed(_) => {
                from_unsaved_send(&err, SaveOf::Send)
            }
        }
    }
}

/// What a send's save could not write: `-29120`'s `data.target`, a closed
/// set, each with its own advice (Rick, 2026-11-19).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveTarget {
    /// The wallet's folder: this account may not create or replace a file
    /// in it.
    Folder,
    /// The wallet's file: its read-only attribute is set (Windows).
    File,
    /// The drive holding the wallet: read-only, or write-protected.
    Volume,
}

impl SaveTarget {
    /// The keyword `data.target` carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Folder => "folder",
            Self::File => "file",
            Self::Volume => "volume",
        }
    }

    /// The cause and the remedy, for the message; the retry follows.
    const fn advice(self) -> &'static str {
        match self {
            Self::Folder => {
                "the wallet's folder is not writable; make it writable for this account"
            }
            Self::File => "the wallet's file is read-only; clear its read-only attribute",
            Self::Volume => {
                "the drive holding the wallet is read-only; make it writable, or move the wallet \
                 to a writable drive,"
            }
        }
    }
}

/// The step of a send's save the disk failed: `-29131`'s `data.step`, a
/// closed set (Rick, 2026-11-19).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveStep {
    /// Writing the record's staged file: removing a leftover, creating,
    /// writing and syncing it.
    Write,
    /// Renaming the staged file over the wallet's file.
    Rename,
    /// Syncing the wallet's folder, before the rename or after it (Unix).
    FolderSync,
    /// Flushing the wallet's file after the rename (Windows).
    Flush,
    /// Asking the wallet's drive what it is: its device and its file system
    /// (Windows).
    VolumeQuery,
}

impl SaveStep {
    /// The keyword `data.step` carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Write => "write",
            Self::Rename => "rename",
            Self::FolderSync => "folder-sync",
            Self::Flush => "flush",
            Self::VolumeQuery => "volume-query",
        }
    }

    /// The step, as the message names it.
    const fn words(self) -> &'static str {
        match self {
            Self::Write => "writing the record",
            Self::Rename => "putting the record in place of the wallet's file",
            Self::FolderSync => "syncing the wallet's folder",
            Self::Flush => "flushing the wallet's file to the disk",
            Self::VolumeQuery => "asking the wallet's drive what it is",
        }
    }
}

/// What an unsaved record was of: the subject and the remedy's last words
/// differ, the code and its `data` do not (Rick, 2026-11-19: a staking
/// seal answers through the send's mapping, by cause).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveOf {
    /// A send (`submit_pending_tx`, `tx_resend`): its reservation is kept,
    /// so it is submitted again or discarded.
    Send,
    /// A staking transaction (`stake`, `unstake`, `drain`,
    /// `collect_unstaked`): its seal was removed and its lane reopened, so
    /// the call is retried.
    Staking,
}

impl SaveOf {
    /// What was not sent, as the message names it.
    const fn subject(self) -> &'static str {
        match self {
            Self::Send => "the send",
            Self::Staking => "the staking transaction",
        }
    }

    /// The remedy's last words, once the cause is fixed.
    const fn retry(self) -> &'static str {
        match self {
            Self::Send => "submit again, or discard the send",
            Self::Staking => "try again",
        }
    }

    /// The remedy for a fault in the wallet.
    const fn fault_remedy(self) -> &'static str {
        match self {
            Self::Send => "report it, and discard the send",
            Self::Staking => "report it",
        }
    }
}

impl From<shekyl_engine_file::Step> for SaveStep {
    fn from(step: shekyl_engine_file::Step) -> Self {
        use shekyl_engine_file::Step as S;
        match step {
            S::Write => Self::Write,
            S::FolderSync => Self::FolderSync,
            S::Rename => Self::Rename,
        }
    }
}

/// A record that was not saved, or not confirmed on disk, so nothing was
/// sent (A19): a send's, whose reservation is kept, or a staking seal's,
/// which was removed so its lane reopens ([`SaveOf`]). Every cause is its own
/// code and advice (Rick, 2026-11-18 and 2026-11-19): a folder, file or
/// drive this account cannot write (`-29120`, `data.target`), a full disk
/// (`-29129`), another program holding the file (`-29130`), the disk's
/// error at a step (`-29131`, `data.step`), a network drive (`-29134`), a
/// volume Windows does not confirm (`-29128`), a local NTFS drive that
/// refused the confirmed rename (`-29132`), and a fault in the wallet
/// before the disk was touched (`-29133`). The whole error, paths and all,
/// goes to the wallet's log only.
pub fn from_unsaved_send(err: &PersistenceError, of: SaveOf) -> WalletRpcError {
    use shekyl_engine_file::Unconfirmed as U;
    use WalletFileError as F;
    tracing::error!(error = %err, ?of, "the record could not be saved; nothing was sent");
    match err {
        PersistenceError::WalletFile(file) => match file {
            F::SaveStep { step, source, .. } => from_save_io((*step).into(), source, of),
            F::ReadOnly { .. } => WalletRpcError::SaveNotWritable {
                target: SaveTarget::File,
                of,
            },
            F::HeldOpen(_) => WalletRpcError::SaveFileHeld { of },
            // Before any file is touched the ledger's own check, its
            // encoding, the frame or the seal failed; a target with no
            // parent directory is the caller's; and a state save never
            // names the rest, so each would be a fault too.
            F::Io(_)
            | F::Ledger(_)
            | F::Payload(_)
            | F::Envelope(_)
            | F::UnexpectedPayloadKind { .. }
            | F::KeysFileAlreadyExists { .. }
            | F::KeysFileWriteOnceViolation { .. }
            | F::DirectoryMissing { .. }
            | F::AlreadyLocked { .. }
            | F::UnknownNetwork(_)
            | F::NetworkMismatch { .. }
            | F::UnknownCapability(_)
            | F::GroupWalletKeysFile
            | F::NotAGroupWalletKeysFile
            | F::SaveAsCrossFilesystem { .. }
            | F::SaveAsTargetExists { .. } => WalletRpcError::SaveInternalFault { of },
        },
        PersistenceError::DurabilityUnconfirmed(why) => match why {
            U::Remote(_) => WalletRpcError::SaveOnNetworkDrive { of },
            U::FileSystem(name) => WalletRpcError::SaveDurabilityUnconfirmed {
                file_system: name.clone(),
                of,
            },
            U::ClassicRename => WalletRpcError::SaveRenameUnconfirmed { of },
            U::DirectoryNotSynced(error) => from_save_io(SaveStep::FolderSync, error, of),
            U::Flush(error) => from_save_io(SaveStep::Flush, error, of),
            U::VolumeUnread(error) => from_save_io(SaveStep::VolumeQuery, error, of),
            // A wallet save stages a fresh file through its creating handle
            // every time and never resumes one a previous process left, so
            // it never reports this; if it did, that would be a fault.
            U::Reopened => WalletRpcError::SaveInternalFault { of },
        },
    }
}

/// The disk's error at `step` of a save of `of`, by what the user does
/// about it: a denial is the folder (the staged file is created and renamed
/// in it; a read-only file is its own variant upstream), a read-only or
/// write-protected drive the volume, a full disk or quota the space, and
/// anything else the step, named.
fn from_save_io(step: SaveStep, error: &std::io::Error, of: SaveOf) -> WalletRpcError {
    use std::io::ErrorKind as K;
    match error.kind() {
        K::PermissionDenied => WalletRpcError::SaveNotWritable {
            target: SaveTarget::Folder,
            of,
        },
        K::ReadOnlyFilesystem => WalletRpcError::SaveNotWritable {
            target: SaveTarget::Volume,
            of,
        },
        K::StorageFull | K::QuotaExceeded => WalletRpcError::SaveDiskFull { of },
        // `io::ErrorKind` is foreign and `#[non_exhaustive]`: every other
        // kind is the disk failing the step, named in `step` and `error`.
        _ => WalletRpcError::SaveIoFailed {
            step,
            error: system_words(error),
            of,
        },
    }
}

/// The system's words for `error`, never a path: an OS error's own text
/// (`Input/output error (os error 5)`), and for an error this process made
/// up, which may name a path, only its kind.
fn system_words(error: &std::io::Error) -> String {
    match error.raw_os_error() {
        Some(code) => std::io::Error::from_raw_os_error(code).to_string(),
        None => error.kind().to_string(),
    }
}

fn from_key_error(err: &KeyError) -> WalletRpcError {
    match err {
        // The keys file declares public material its seed does not derive:
        // damaged or tampered.
        KeyError::PublicBytesMismatch => {
            tracing::warn!("keys file public material does not match its seed");
            WalletRpcError::WalletFileCorrupt
        }
        KeyError::Primitive { detail } => internal_detail("key derivation primitive", detail),
    }
}

/// Why the curve-tree store cannot be used (`-29016`'s `data.cause`). The
/// remedy is the same for both — delete the store and reopen — so they share
/// a code; the message says which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurveTreeStoreCause {
    /// The store's contents contradict themselves.
    Corrupt,
    /// The store was written by a version this build cannot read.
    Unsupported,
}

impl CurveTreeStoreCause {
    /// The `data.cause` value.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Corrupt => "corrupt",
            Self::Unsupported => "unsupported",
        }
    }
}

/// `-29016`'s message. A wallet that holds its keys and balance elsewhere must
/// not be told to restore from its seed for a cache it can rebuild.
fn curve_tree_store_message(cause: CurveTreeStoreCause) -> String {
    let what = match cause {
        CurveTreeStoreCause::Corrupt => "is damaged",
        CurveTreeStoreCause::Unsupported => "was written by a version this build cannot read",
    };
    format!(
        "the wallet's membership data (the .curvetree file beside it) {what} — delete that \
         file and open the wallet again. It is rebuilt from the chain; your keys and balance \
         are not in it, and sending waits until the rebuild finishes"
    )
}

fn from_store_open_fault(fault: StoreOpenFault, detail: &str) -> WalletRpcError {
    tracing::warn!(?fault, detail = %detail, "curve-tree store would not open");
    match fault {
        StoreOpenFault::LockedElsewhere => WalletRpcError::WalletLockedElsewhere,
        StoreOpenFault::Corrupt => WalletRpcError::CurveTreeStoreUnusable {
            cause: CurveTreeStoreCause::Corrupt,
        },
        StoreOpenFault::Unsupported => WalletRpcError::CurveTreeStoreUnusable {
            cause: CurveTreeStoreCause::Unsupported,
        },
        StoreOpenFault::Io => WalletRpcError::WalletFileIoFailed,
        StoreOpenFault::Internal => WalletRpcError::InternalError("curve-tree store open".into()),
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
            DrainToPrincipalError::FeeEstimate(e) => e.into(),
            DrainToPrincipalError::FeeUnreasonable {
                reason,
                rate,
                bound,
            } => Self::DaemonFeeUnreasonable {
                reason,
                rate,
                bound,
            },
            DrainToPrincipalError::Signer(fault) => fault.into(),
            DrainToPrincipalError::State { context, detail } => internal_detail(context, detail),
            DrainToPrincipalError::Submit { detail } => {
                tracing::warn!(detail = %detail, "drain dispatch failed at the choke point");
                Self::SubmitAmbiguous
            }
            // The seal's save was not confirmed: nothing was sent and the
            // seal was removed. The save's cause answers (Rick, 2026-11-19).
            DrainToPrincipalError::SealNotSaved(error) => {
                from_unsaved_send(&error, SaveOf::Staking)
            }
        }
    }
}

impl From<shekyl_engine_core::UnstakeError> for WalletRpcError {
    /// The `unstake` code table (PR-C): `-29513..-29522`, every arm named —
    /// no engine refusal falls through to `-32603` (the round-5 lesson from
    /// `-29512`). The two dispatch dispositions stay distinct because they
    /// demand opposite client behavior: `-29521` (refused before sending,
    /// seal released — retry at will) vs `-29522` (sent, seal held until it
    /// lands or its end date passes — do not re-fire).
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
            // Not that retry. A failed peer check and a service at this
            // computer are the daemon-target codes, the same ones every
            // other wallet verb uses.
            E::DaemonTarget(fault) => from_daemon_fault(fault, "unstake"),
            E::FeeEstimate(e) => e.into(),
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
            // The seal's save was not confirmed: nothing was sent and the
            // seal was removed, so the lane is open. The save's cause
            // answers, never -29522 (Rick, 2026-11-19).
            E::SealNotSaved(error) => from_unsaved_send(&error, SaveOf::Staking),
            E::ExitFateUnknown { detail } => {
                tracing::warn!(detail = %detail, "unstake dispatch fate unknown; seal held");
                Self::UnstakeFateUnknown { detail }
            }
            // NOT -32603: a non-loopback daemon address
            // is operator-fixable configuration — every other verb works over
            // a remote daemon, so "internal error" on exactly this one is the
            // hard-to-diagnose shape rule 82 forbids. Named code + remedy.
            E::Transport { detail } => Self::UnstakeLocalNodeRequired { detail },
            E::Signer(fault) => fault.into(),
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
            E::FeeEstimate(e) => e.into(),
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
            // The seal's save was not confirmed: nothing was sent and the
            // seal was removed. The save's cause answers (Rick, 2026-11-19).
            E::SealNotSaved(error) => from_unsaved_send(&error, SaveOf::Staking),
            E::Signer(fault) => fault.into(),
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
            SubmitError::DaemonRejectedTerminal { kind } => Self::submit_rejected(
                terminal_to_reject_cause(kind),
                match kind {
                    TerminalErrorKind::ConsensusRule { row } => Some(row.as_str().to_owned()),
                    _ => None,
                },
            ),
            SubmitError::DaemonRejectedRetryable { cause, .. } => {
                Self::submit_rejected(retryable_to_reject_cause(cause), None)
            }
            SubmitError::DaemonAmbiguous { .. } => Self::SubmitAmbiguous,
            SubmitError::SubmitAlreadyPending { .. } => Self::SubmitAlreadyPending,
            SubmitError::ReanchorUnavailable { .. } => Self::ReanchorUnavailable,
            SubmitError::ReselectionRequired { .. } => Self::ReselectionRequired,
            SubmitError::DispatchNotSaved { source, .. } => {
                from_unsaved_send(&source, SaveOf::Send)
            }
            // `SubmitError` is `#[non_exhaustive]` (Phase 0a); every variant is
            // named above, so inside one workspace build this is unreachable.
            other => internal_detail("submit variant unmapped at the RPC boundary", other),
        }
    }
}

impl From<ResendError> for WalletRpcError {
    /// A resend's refusals speak the submit's vocabulary: a daemon refusal
    /// is `-29106` with the same `data` (`verdict`, `cause`, and `row` for
    /// a consensus refusal), and no verdict is `-29107`.
    fn from(err: ResendError) -> Self {
        match err {
            ResendError::NotHeld => Self::TxNotHeld,
            ResendError::BytesMissing => Self::TxBytesMissing,
            ResendError::RejectedTerminal { kind, .. } => Self::submit_rejected(
                terminal_to_reject_cause(kind),
                match kind {
                    TerminalErrorKind::ConsensusRule { row } => Some(row.as_str().to_owned()),
                    _ => None,
                },
            ),
            ResendError::RejectedRetryable { cause } => {
                Self::submit_rejected(retryable_to_reject_cause(cause), None)
            }
            ResendError::Ambiguous { .. } => Self::SubmitAmbiguous,
        }
    }
}

/// Map Engine terminal reject kinds onto the contract's [`RejectCause`].
fn terminal_to_reject_cause(kind: TerminalErrorKind) -> RejectCause {
    match kind {
        TerminalErrorKind::DoubleSpend => RejectCause::DoubleSpendConflict,
        TerminalErrorKind::FeeTooLow => RejectCause::FeeTooLow,
        TerminalErrorKind::Malformed => RejectCause::Malformed,
        TerminalErrorKind::ConsensusRule { .. } => RejectCause::ConsensusRule,
        // `TerminalErrorKind` is `#[non_exhaustive]`; `Unrecognized` and any
        // unknown future kinds take the fail-safe Unrecognized disposition
        // (DAEMON_SUBMIT_VERDICT §2.5).
        _ => RejectCause::Unrecognized,
    }
}

/// Map Engine retryable reject causes onto the contract's [`RejectCause`].
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
                state: crate::outgoing_transfer_state_of(state),
            },
            // Fail-closed rollback already ran; what is left is the storage
            // failure, named by its cause (paths stay in the log).
            E::Persistence(e) => e.into(),
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
            // Fail-closed rollback already ran; what is left is the storage
            // failure, named by its cause (paths stay in the log).
            SetTxNoteError::Persistence(e) => e.into(),
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
            // A daemon failure at submit is ambiguous whatever its fault: the
            // bytes may have gone out. An identity refusal cannot first
            // appear here — the build's fee query ran the handshake on the
            // same client, which caches its verdict.
            PendingTxError::DiscardBlockedPendingDaemonAck { .. }
            | PendingTxError::Io(IoError::Daemon { .. }) => Self::SubmitAmbiguous,
            PendingTxError::SubmitAlreadyPending { .. } => Self::SubmitAlreadyPending,
            PendingTxError::Io(io) => from_io_error(io),
            // `PendingTxError` is `#[non_exhaustive]` (Phase 0a); every variant
            // is named above, so inside one workspace build this is unreachable.
            other => internal_detail("pending-tx variant unmapped at the RPC boundary", other),
        }
    }
}

/// Map an internal error to a category-only RPC message, logging the raw cause
/// server-side. `message()` is the most-logged surface and, in remote mode,
/// crosses to the client, so it must never carry a local filesystem path or
/// internal schema (rule 30; the `message()` contract). The full detail is
/// preserved in the server's own logs for diagnosis.
///
/// Reserved for what is a bug or an unrecoverable internal state: anything a
/// user or operator can act on has its own code.
fn internal_detail(category: &'static str, detail: impl std::fmt::Display) -> WalletRpcError {
    tracing::warn!(category, detail = %detail, "wallet-rpc internal error");
    WalletRpcError::InternalError(category.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_engine_core::MAX_INPUTS;

    #[test]
    fn maps_incorrect_password() {
        let err: WalletRpcError = OpenError::IncorrectPassword.into();
        assert_eq!(err.code(), WalletRpcErrorCode::InvalidPassword);
    }

    #[test]
    fn maps_keys_already_exists_by_type() {
        let err: WalletRpcError = OpenError::Io(IoError::WalletFile(
            WalletFileError::KeysFileAlreadyExists {
                path: "/tmp/x.wallet.keys".into(),
            },
        ))
        .into();
        assert_eq!(err.code(), WalletRpcErrorCode::WalletFileExists);
        assert!(!err.message().contains("/tmp"), "{}", err.message());
    }

    #[test]
    fn maps_refresh_already_running() {
        let err: WalletRpcError = RefreshError::AlreadyRunning.into();
        assert_eq!(err.code(), WalletRpcErrorCode::RefreshInProgress);
    }

    #[test]
    fn maps_refresh_daemon_io() {
        let err: WalletRpcError = RefreshError::Io(IoError::Daemon {
            fault: DaemonFault::Unreachable,
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
            fault: DaemonFault::Unreachable,
            detail: "/tmp/wallet.keys connection refused".into(),
        }));
        assert_eq!(err.code(), WalletRpcErrorCode::RescanIncomplete);
        assert!(
            !err.message().contains("/tmp"),
            "post-reset scan failure must not echo local paths: {}",
            err.message()
        );
    }

    fn finality_stop(depth: u64, breach: FinalityBreach) -> FinalityStop {
        FinalityStop {
            depth: shekyl_types::BlockCount::from_raw(depth),
            // The fixture's window. The policy's real `W` is pinned in the
            // engine; this test checks that the number it is handed is the
            // number the caller reads.
            finality_depth: shekyl_types::BlockCount::from_raw(730),
            breach,
        }
    }

    /// `CT-6` C7 / rule 82. The remedy has to reach the caller, which is the
    /// half that was missing: `internal_detail` logs its detail and returns
    /// only the category, so a refusal routed through it would have told the
    /// user "curve-tree ingest" and put the remedy in a server log.
    #[test]
    fn a_reorg_past_finality_tells_the_caller_to_resync() {
        let err = WalletRpcError::from(RefreshError::ReorgDeeperThanFinality {
            stop: finality_stop(1_000, FinalityBreach::Measured),
        });
        assert_eq!(err.code(), WalletRpcErrorCode::ResyncRequired);
        assert_eq!(WalletRpcErrorCode::ResyncRequired as i32, -29211);

        let message = err.to_string();
        assert!(
            message.contains(".curvetree") && message.contains("rescan_blockchain"),
            "the remedy clears the file and the scan history: {message}"
        );
        assert!(
            message.contains("in that order"),
            "the file has to be gone before the rescan: {message}"
        );
        assert!(
            message.contains("1000") && message.contains("730"),
            "the cause must travel with the remedy: {message}"
        );
        assert!(
            !message.contains("already empty"),
            "an ordinary refresh has not cleared history: {message}"
        );
        let data = err.data().expect("structured depth");
        assert_eq!(data["depth"], 1_000);
        assert_eq!(data["finality_depth"], 730);
        assert_eq!(data["breach"], "measured");
        assert_eq!(data["history_cleared"], false);
    }

    /// A scan file from a newer wallet is refused with the same remedy as
    /// a stale one, and the message does not call it older: it names both
    /// formats and says another version wrote it. Red edit: the earlier
    /// wording, "written by an earlier version", which is false here.
    #[test]
    fn a_scan_file_from_a_newer_wallet_is_not_called_older() {
        use shekyl_engine_state::pscan_state::PSCAN_STATE_VERSION;

        let err = WalletRpcError::from(PScanStartError::StateFileVersionUnsupported {
            path: std::path::PathBuf::from("/home/alice/wallets/primary.wallet.pscan"),
            found: PSCAN_STATE_VERSION + 1,
            expected: PSCAN_STATE_VERSION,
        });
        let message = err.to_string();
        assert!(!message.contains("earlier"), "{message}");
        assert!(message.contains("another version"), "{message}");
        assert!(
            message.contains(&format!("file format {}", PSCAN_STATE_VERSION + 1)),
            "{message}"
        );
        assert!(message.contains("Move that one file"), "{message}");
    }

    /// Rules 80–82 on the `-29530` refusal. A staker whose `.wallet.pscan`
    /// was written under an earlier `PSCAN_STATE_VERSION` cannot open the
    /// wallet, `rescan_blockchain` needs an open wallet, and nothing rewrites
    /// the file — so the refusal has to name the file, both versions and
    /// the one remedy that exists. The engine error keeps the directory for
    /// the server log; this mapping is the only user sentence. A path with
    /// no Unicode file name falls back to the detail-free form rather than
    /// inventing a name. This bites against a mapping that drops the engine's
    /// typed refusal back into `StakeStateUnreadable` for a normal path, and
    /// against one that forwards the directory. It does NOT cover the engine
    /// producing that refusal from a real seal (`lifecycle_tests::
    /// a_stale_pscan_seal_refuses_the_staker_start_naming_the_file_and_versions`).
    #[test]
    fn a_stale_staking_scan_file_is_named_with_both_versions_and_the_remedy() {
        use shekyl_engine_state::pscan_state::{
            PSCAN_STATE_VERSION, PSCAN_STATE_VERSION_KEYLESS_JOIN,
        };

        // Sibling of the documented `/home/alice/wallets/primary.wallet` base.
        // `alice` names nobody; a personal home is not a fixture this repo can publish.
        let path = std::path::PathBuf::from("/home/alice/wallets/primary.wallet.pscan");
        let engine_err = PScanStartError::StateFileVersionUnsupported {
            path: path.clone(),
            found: PSCAN_STATE_VERSION_KEYLESS_JOIN,
            expected: PSCAN_STATE_VERSION,
        };
        let logged = engine_err.to_string();
        let rendered = path.display().to_string();
        assert!(
            logged.contains(&rendered),
            "the log line carries the seal path: {logged}"
        );
        assert!(
            !logged.contains("Move that"),
            "the remedy is the client sentence, not the log line: {logged}"
        );

        let err = WalletRpcError::from(engine_err);
        assert_eq!(err.code(), WalletRpcErrorCode::StakeStateUnreadable);
        assert_eq!(WalletRpcErrorCode::StakeStateUnreadable as i32, -29530);

        let message = err.to_string();
        assert!(
            message.contains("primary.wallet.pscan"),
            "the refusal names the file the user has to find: {message}"
        );
        assert!(
            message.contains(&format!("format {PSCAN_STATE_VERSION_KEYLESS_JOIN}"))
                && message.contains(&format!("format {PSCAN_STATE_VERSION}")),
            "the refusal names the version found and the version expected: {message}"
        );
        assert!(
            message.contains("Move that one file out of the wallet's folder")
                && message.contains("open the wallet again"),
            "the refusal says what to do: {message}"
        );
        let directory = path
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .expect("the fixture path has a directory")
            .display()
            .to_string();
        assert!(
            !message.contains(&directory),
            "the directory stays in the server log: {message}"
        );

        let data = err
            .data()
            .expect("the version form carries structured data");
        assert_eq!(data["file"], "primary.wallet.pscan");
        assert_eq!(data["found"], PSCAN_STATE_VERSION_KEYLESS_JOIN);
        assert_eq!(data["expected"], PSCAN_STATE_VERSION);

        let unnamed = WalletRpcError::from(PScanStartError::StateFileVersionUnsupported {
            path: std::path::PathBuf::from(".."),
            found: PSCAN_STATE_VERSION_KEYLESS_JOIN,
            expected: PSCAN_STATE_VERSION,
        });
        assert!(
            matches!(unnamed, WalletRpcError::StakeStateUnreadable),
            "a path with no file name is the detail-free form"
        );
        assert!(unnamed.data().is_none());

        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let mut bytes = b"/tmp/".to_vec();
            bytes.extend_from_slice(&[0xff, 0xfe]);
            bytes.extend_from_slice(b".wallet.pscan");
            let non_unicode = WalletRpcError::from(PScanStartError::StateFileVersionUnsupported {
                path: std::path::PathBuf::from(std::ffi::OsString::from_vec(bytes)),
                found: PSCAN_STATE_VERSION_KEYLESS_JOIN,
                expected: PSCAN_STATE_VERSION,
            });
            assert!(
                matches!(non_unicode, WalletRpcError::StakeStateUnreadable),
                "a non-Unicode file name is not shown to the client"
            );
            assert!(non_unicode.data().is_none());
        }

        // Control: the cause-unknown form keeps the detail-free message and
        // no data, so the two are told apart by `data`, not by prose.
        let unreadable = WalletRpcError::from(PScanStartError::LoadFailed(Box::new(
            std::io::Error::other("sealed state did not open"),
        )));
        assert_eq!(unreadable.code(), WalletRpcErrorCode::StakeStateUnreadable);
        assert!(unreadable.data().is_none());
        assert!(unreadable.to_string().contains("see the server log"));
    }

    /// The same refusal during a rescan still names the tree. History is
    /// already empty, and retrying the rescan leaves the tree in place, so
    /// the durability fact is a clause of this code rather than a different
    /// one. The depth here is only what the record reached.
    #[test]
    fn during_a_rescan_the_tree_still_has_to_be_removed() {
        let err = WalletRpcError::from_rescan_scan_failure(RefreshError::ReorgDeeperThanFinality {
            stop: finality_stop(40, FinalityBreach::RecordEnded),
        });
        assert_eq!(err.code(), WalletRpcErrorCode::ResyncRequired);
        let message = err.to_string();
        assert!(message.contains(".curvetree"), "{message}");
        assert!(message.contains("already empty"), "{message}");
        assert!(
            message.contains("while that file is still there"),
            "{message}"
        );
        assert!(
            message.contains("40") && message.contains("730"),
            "{message}"
        );
        assert!(message.contains("hash record ended"), "{message}");
        assert!(
            !message.contains("outside"),
            "a short record is not a measured rollback: {message}"
        );
        let data = err.data().expect("structured depth");
        assert_eq!(data["breach"], "record_ended");
        assert_eq!(data["history_cleared"], true);
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
                wallet: shekyl_types::BlockHeight::from_raw(1),
                result: shekyl_types::BlockHeight::from_raw(2),
            },
            RefreshError::InternalInvariantViolation {
                context: "test invariant",
            },
            RefreshError::CurveTreeIngest {
                fault: CurveTreeIngestFault::ClientRejected,
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
    fn rescan_persist_is_a_storage_failure_without_the_path() {
        let err: WalletRpcError =
            RefreshError::RescanPersist("/home/user/.shekyl/wallet.keys: ENOSPC".into()).into();
        assert_eq!(err.code(), WalletRpcErrorCode::WalletFileIoFailed);
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

        use crate::TransferState;

        let err: WalletRpcError = AbandonTxError::NotFound.into();
        assert_eq!(err.code(), WalletRpcErrorCode::UnknownTransferId);

        let err: WalletRpcError = AbandonTxError::StateForbids {
            state: SendState::Confirmed {
                height: shekyl_types::BlockHeight::from_raw(42),
            },
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
    fn submit_rejected_data_is_the_contracts_verdict() {
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
        assert!(
            data.get("row").is_none(),
            "no row for a cause that has none"
        );

        let row = shekyl_engine_core::engine::error::CenRowName::parse("CEN-J15").expect("fits");
        let err: WalletRpcError = SubmitError::DaemonRejectedTerminal {
            kind: TerminalErrorKind::ConsensusRule { row },
        }
        .into();
        let data = err.data().expect("data");
        assert_eq!(data["cause"], "consensus_rule");
        assert_eq!(
            data["row"], "CEN-J15",
            "the row rides to the wallet's caller"
        );
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
                E::FeeEstimate(FeeEstimatorError::Daemon(DaemonFault::Unreachable)),
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
        let fee_query: WalletRpcError =
            E::FeeEstimate(FeeEstimatorError::Daemon(DaemonFault::Unreachable)).into();
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
                E::FeeEstimate(FeeEstimatorError::Daemon(DaemonFault::Unreachable)).into(),
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

        let err: WalletRpcError =
            DrainToPrincipalError::FeeEstimate(FeeEstimatorError::Daemon(DaemonFault::Unreachable))
                .into();
        assert_eq!(err.code().as_i32(), -29102);
    }

    // ---------------------------------------------------------------------
    // Specific causes, specific codes (the catch-all audit)
    // ---------------------------------------------------------------------

    const LOCAL_PATH: &str = "/home/user/.shekyl/wallets/w";

    fn file_err(e: WalletFileError) -> WalletRpcError {
        OpenError::Io(IoError::WalletFile(e)).into()
    }

    /// Every wallet-file variant lands on its named code, and no message
    /// carries a path — even when the upstream `Display` does.
    #[test]
    fn every_wallet_file_failure_has_its_own_code_and_no_path() {
        use std::io::{Error as IoErr, ErrorKind};
        use std::path::PathBuf;
        let path = || PathBuf::from(LOCAL_PATH);
        let cases: Vec<(WalletFileError, WalletRpcErrorCode)> = vec![
            (
                WalletFileError::DirectoryMissing { dir: path() },
                WalletRpcErrorCode::WalletDirMissing,
            ),
            (
                WalletFileError::AlreadyLocked { path: path() },
                WalletRpcErrorCode::WalletLockedElsewhere,
            ),
            (
                WalletFileError::KeysFileAlreadyExists { path: path() },
                WalletRpcErrorCode::WalletFileExists,
            ),
            (
                WalletFileError::Io(IoErr::from(ErrorKind::NotFound)),
                WalletRpcErrorCode::WalletFileNotFound,
            ),
            (
                WalletFileError::Io(IoErr::from(ErrorKind::PermissionDenied)),
                WalletRpcErrorCode::WalletFileAccessDenied,
            ),
            (
                WalletFileError::Io(IoErr::other("disk full")),
                WalletRpcErrorCode::WalletFileIoFailed,
            ),
            (
                WalletFileError::SaveStep {
                    step: shekyl_engine_file::Step::Rename,
                    target: path(),
                    source: IoErr::other("EXDEV"),
                },
                WalletRpcErrorCode::WalletFileIoFailed,
            ),
            (
                // A step's denial is the access code, as an untyped one is.
                WalletFileError::SaveStep {
                    step: shekyl_engine_file::Step::Write,
                    target: path(),
                    source: IoErr::from(ErrorKind::PermissionDenied),
                },
                WalletRpcErrorCode::WalletFileAccessDenied,
            ),
            (
                WalletFileError::ReadOnly { target: path() },
                WalletRpcErrorCode::WalletFileAccessDenied,
            ),
            (
                // Outside a send, a file another program held past the
                // replace's wait stays the file-I/O code; its `Display`
                // names both paths, which must stay in the log.
                WalletFileError::HeldOpen(shekyl_engine_file::HeldOpen {
                    held: path(),
                    live: path(),
                }),
                WalletRpcErrorCode::WalletFileIoFailed,
            ),
            (
                WalletFileError::Envelope(WalletEnvelopeError::InvalidPasswordOrCorrupt),
                WalletRpcErrorCode::InvalidPassword,
            ),
            (
                WalletFileError::Envelope(WalletEnvelopeError::BadMagic),
                WalletRpcErrorCode::WalletFileCorrupt,
            ),
            (
                WalletFileError::Envelope(WalletEnvelopeError::FormatVersionTooNew {
                    got: 9,
                    max: 1,
                }),
                WalletRpcErrorCode::WalletFileVersionUnsupported,
            ),
            (
                WalletFileError::Envelope(WalletEnvelopeError::FormatVersionRetired {
                    got: 1,
                    current: 2,
                }),
                WalletRpcErrorCode::WalletFileVersionUnsupported,
            ),
            (
                WalletFileError::Payload(PayloadError::BadMagic),
                WalletRpcErrorCode::WalletFileCorrupt,
            ),
            (
                WalletFileError::Payload(PayloadError::UnsupportedVersion { file: 9, binary: 1 }),
                WalletRpcErrorCode::WalletFileVersionUnsupported,
            ),
            (
                WalletFileError::Ledger(WalletLedgerError::UnsupportedFormatVersion {
                    file: 9,
                    binary: 1,
                }),
                WalletRpcErrorCode::WalletFileVersionUnsupported,
            ),
            (
                WalletFileError::Ledger(WalletLedgerError::GroupInvariantFailed {
                    invariant: "group-outputs-unique",
                    detail: "two group outputs share an output key".into(),
                }),
                WalletRpcErrorCode::WalletFileCorrupt,
            ),
            (
                WalletFileError::NetworkMismatch {
                    expected: shekyl_engine_file::Network::Testnet,
                    found: shekyl_engine_file::Network::Mainnet,
                },
                WalletRpcErrorCode::WalletNetworkMismatch,
            ),
            (
                WalletFileError::KeysFileWriteOnceViolation { path: path() },
                WalletRpcErrorCode::InternalError,
            ),
        ];
        for (cause, expected) in cases {
            let shown = format!("{cause}");
            let err = file_err(cause);
            assert_eq!(err.code(), expected, "{shown}");
            assert!(
                !err.message().contains("/home"),
                "{expected:?} leaked a path: {}",
                err.message()
            );
        }
    }

    /// A wallet file whose ledger block an earlier build wrote (version 14,
    /// before the user freeze was removed) is refused `-29012`, and the
    /// message names the remedy, restoring the wallet from its seed, and
    /// what that restore does not bring back (rule 82).
    #[test]
    fn an_earlier_ledger_version_is_refused_with_the_remedy() {
        let err = file_err(WalletFileError::Ledger(
            WalletLedgerError::UnsupportedBlockVersion {
                block: "ledger",
                file: 14,
                binary: 15,
            },
        ));
        assert_eq!(err.code(), WalletRpcErrorCode::WalletFileVersionUnsupported);
        let message = err.message();
        assert!(
            message.contains("restore the wallet from your seed"),
            "{message}"
        );
        assert!(
            message.contains(
                "your send history, proofs for earlier sends, notes and payment requests are \
                 not restored"
            ),
            "{message}"
        );
    }

    /// The network mismatch names both networks (public), in `data` too.
    #[test]
    fn a_network_mismatch_names_both_networks() {
        let err: WalletRpcError = OpenError::NetworkMismatch {
            wallet: shekyl_engine_file::Network::Mainnet,
            expected: shekyl_engine_file::Network::Testnet,
        }
        .into();
        assert_eq!(err.code().as_i32(), -29007);
        let data = err.data().expect("data");
        assert_ne!(data["wallet"], data["expected"]);
    }

    /// The stake random-number check's refusal is `-29017`, with the remedy
    /// and no grade on the wire. The variant is a unit, so this build can
    /// construct it and the conversion is the real `From` arm.
    #[test]
    fn a_failed_random_source_check_names_its_remedy() {
        let err: WalletRpcError = OpenError::StakeRngSelfCertFailed.into();
        assert_eq!(err.code(), WalletRpcErrorCode::RandomSourceCheckFailed);
        assert_eq!(err.code().as_i32(), -29017);
        assert_eq!(err.data(), None);
        let message = err.message();
        assert!(!message.contains("chi-square"), "{message}");
        for remedy in ["did not open", "try once more", "another computer"] {
            assert!(message.contains(remedy), "{remedy}: {message}");
        }
    }

    #[test]
    fn a_blocked_close_counts_what_is_in_flight() {
        let err: WalletRpcError = OpenError::OutstandingPendingTx { count: 2 }.into();
        assert_eq!(err.code().as_i32(), -29014);
        assert_eq!(err.data().expect("data")["count"], 2);
    }

    /// The curve-tree store's classified fault reaches its code; the store's
    /// own diagnosis (which can name a path) stays off the wire.
    #[test]
    fn a_store_open_fault_names_its_remedy() {
        let unusable = |cause| Some(json!({ "cause": cause }));
        for (fault, expected, data) in [
            (
                StoreOpenFault::LockedElsewhere,
                WalletRpcErrorCode::WalletLockedElsewhere,
                None,
            ),
            (
                StoreOpenFault::Corrupt,
                WalletRpcErrorCode::CurveTreeStoreUnusable,
                unusable("corrupt"),
            ),
            (
                StoreOpenFault::Unsupported,
                WalletRpcErrorCode::CurveTreeStoreUnusable,
                unusable("unsupported"),
            ),
            (
                StoreOpenFault::Io,
                WalletRpcErrorCode::WalletFileIoFailed,
                None,
            ),
            (
                StoreOpenFault::Internal,
                WalletRpcErrorCode::InternalError,
                None,
            ),
        ] {
            let err: WalletRpcError = OpenError::Io(IoError::CurveTreeStore {
                fault,
                detail: LOCAL_PATH.into(),
            })
            .into();
            assert_eq!(err.code(), expected, "{fault:?}");
            assert_eq!(err.data(), data, "{fault:?}");
            let message = err.message();
            assert!(!message.contains("/home"), "{message}");
            // The store is a rebuildable cache: its remedy is to delete it,
            // never to restore the wallet from its seed.
            assert!(!message.contains("seed"), "{message}");
        }
    }

    /// Each build refusal a user or operator can act on has its own code;
    /// `-32603` is left to construction failing and broken preconditions.
    #[test]
    fn every_build_refusal_names_its_remedy() {
        use shekyl_types::{BlockCount, BlockHeight};
        let cases: Vec<(SendError, WalletRpcErrorCode)> = vec![
            (SendError::NotSynced, WalletRpcErrorCode::WalletNotSynced),
            (
                SendError::SignerUnavailable,
                WalletRpcErrorCode::WalletSessionEnded,
            ),
            (
                SendError::SignerFailed {
                    fault: shekyl_engine_core::SignerFault::HandleMismatch,
                },
                WalletRpcErrorCode::SignerFailed,
            ),
            (
                SendError::Sign(SignFault::TooManyInputs {
                    count: MAX_INPUTS + 1,
                    limit: MAX_INPUTS,
                }),
                WalletRpcErrorCode::TooManyInputs,
            ),
            (
                SendError::Sign(SignFault::TooManyOutputs { count: 17 }),
                WalletRpcErrorCode::TooManyOutputs,
            ),
            (
                SendError::Sign(SignFault::SpentOutputNotInLeafChunk { input: 1 }),
                WalletRpcErrorCode::InputNotInTree,
            ),
            (
                SendError::Sign(SignFault::PqcLeafMismatch { input: 0 }),
                WalletRpcErrorCode::InputUnspendable,
            ),
            (
                SendError::Sign(SignFault::Internal(
                    shekyl_engine_core::InternalSignFault::BalanceSelfCheck,
                )),
                WalletRpcErrorCode::SignerFailed,
            ),
            (
                SendError::SpendUnavailableRebuilding {
                    needed: 9,
                    spendable_now: 1,
                    pending_rebuild: 8,
                },
                WalletRpcErrorCode::SpendUnavailableRebuilding,
            ),
            (
                SendError::CurveTreeUnavailable {
                    detail: "actor stopped".into(),
                },
                WalletRpcErrorCode::CurveTreeUnavailable,
            ),
            (
                SendError::OutputNotYetSpendable {
                    eligible_height: BlockHeight::from_raw(110),
                    reference_block_height: BlockHeight::from_raw(100),
                    wait_blocks: BlockCount::from_raw(10),
                },
                WalletRpcErrorCode::OutputNotYetSpendable,
            ),
            (
                SendError::WalletTooYoungToSpend {
                    synced_height: BlockHeight::from_raw(3),
                    ref_anchor_age: BlockCount::from_raw(10),
                },
                WalletRpcErrorCode::ChainTooShortToSpend,
            ),
            (
                SendError::SubmitLoopBreakerTripped {
                    kind: TerminalErrorKind::FeeTooLow,
                },
                WalletRpcErrorCode::SubmitLoopBreakerTripped,
            ),
            (
                SendError::Io(IoError::Daemon {
                    fault: DaemonFault::Unreachable,
                    detail: "connection refused".into(),
                }),
                WalletRpcErrorCode::DaemonUnreachable,
            ),
            (
                SendError::BuildInvariant {
                    reason: "lock poisoned",
                },
                WalletRpcErrorCode::InternalError,
            ),
        ];
        for (cause, expected) in cases {
            let shown = format!("{cause}");
            let err: WalletRpcError = cause.into();
            assert_eq!(err.code(), expected, "{shown}");
        }
        // Amounts stay off the wire even when the engine's Display has them.
        let rebuilding: WalletRpcError = SendError::SpendUnavailableRebuilding {
            needed: 123_456,
            spendable_now: 1,
            pending_rebuild: 8,
        }
        .into();
        assert!(
            !rebuilding.message().contains("123456"),
            "{}",
            rebuilding.message()
        );
        let wait: WalletRpcError = SendError::OutputNotYetSpendable {
            eligible_height: BlockHeight::from_raw(110),
            reference_block_height: BlockHeight::from_raw(100),
            wait_blocks: BlockCount::from_raw(10),
        }
        .into();
        assert_eq!(wait.data().expect("data")["wait_blocks"], 10);
    }

    /// The submit and pending-tx refusals that used to share `-32603`.
    #[test]
    fn submit_refusals_have_their_own_codes() {
        use shekyl_engine_core::ReservationId;
        let rid = ReservationId::from_raw(7);
        let cases: Vec<(WalletRpcError, WalletRpcErrorCode)> = vec![
            (
                SubmitError::SubmitAlreadyPending {
                    reservation_id: rid,
                }
                .into(),
                WalletRpcErrorCode::SubmitAlreadyPending,
            ),
            (
                SubmitError::ReanchorUnavailable {
                    reservation_id: rid,
                }
                .into(),
                WalletRpcErrorCode::ReanchorUnavailable,
            ),
            (
                SubmitError::ReselectionRequired {
                    reservation_id: rid,
                }
                .into(),
                WalletRpcErrorCode::ReselectionRequired,
            ),
            (
                PendingTxError::SubmitAlreadyPending {
                    reservation_id: rid,
                }
                .into(),
                WalletRpcErrorCode::SubmitAlreadyPending,
            ),
            (
                FeeEstimatorError::DaemonResponseInvalid { reason: "not json" }.into(),
                WalletRpcErrorCode::DaemonFeeResponseInvalid,
            ),
            (
                RefreshError::Cancelled.into(),
                WalletRpcErrorCode::RefreshCancelled,
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(err.code(), expected, "{err:?}");
        }
    }

    /// A submit refused because the send's save was not confirmed.
    fn unsaved(source: PersistenceError) -> WalletRpcError {
        SubmitError::DispatchNotSaved {
            reservation_id: shekyl_engine_core::ReservationId::from_raw(7),
            source,
        }
        .into()
    }

    /// A send saved on a FAT32 or exFAT volume is refused `-29128`, naming
    /// the file system in `data` and the message, and the fix, an NTFS
    /// volume (Rick, 2026-11-18). The same refusal reaching the boundary on
    /// its own answers the same. Red edit: map the unconfirmed save to
    /// `-29120` again, and the code, the data and the advice all differ.
    #[test]
    fn a_save_on_a_volume_windows_cannot_confirm_names_it_and_ntfs() {
        use shekyl_engine_file::Unconfirmed;
        for file_system in ["FAT32", "exFAT"] {
            let refusal = || {
                PersistenceError::DurabilityUnconfirmed(Unconfirmed::FileSystem(
                    file_system.to_owned(),
                ))
            };
            for err in [unsaved(refusal()), WalletRpcError::from(refusal())] {
                assert_eq!(
                    err.code(),
                    WalletRpcErrorCode::SaveDurabilityUnconfirmed,
                    "{err:?}"
                );
                assert_eq!(err.code().as_i32(), -29128);
                assert_eq!(err.data(), Some(json!({ "file_system": file_system })));
                let message = err.message();
                assert!(
                    message.contains(&format!("{file_system} volume"))
                        && message.contains("move the wallet to an NTFS volume")
                        && message.contains("not sent"),
                    "{message}"
                );
            }
        }
    }

    /// A staking seal whose save was not confirmed answers with the save's
    /// own code, by cause, from every staking call that seals (Rick,
    /// 2026-11-19): never `-29522` or `-29107`, whose "sent, held" and
    /// "may have propagated" are false when nothing was sent. The words are
    /// a staking transaction's: the seal was removed, so the remedy ends in
    /// a retry, never "discard the send". Red edit: map `SealNotSaved` to
    /// the old arms, or pass `SaveOf::Send`, and the code or the words
    /// differ.
    #[test]
    fn an_unconfirmed_staking_seal_answers_its_save_code() {
        use shekyl_engine_core::{CollectUnstakedError, DrainToPrincipalError, UnstakeError};
        use shekyl_engine_file::Unconfirmed;
        let unconfirmed =
            || PersistenceError::DurabilityUnconfirmed(Unconfirmed::FileSystem("FAT32".to_owned()));
        let answers = [
            WalletRpcError::from(UnstakeError::SealNotSaved(unconfirmed())),
            WalletRpcError::from(DrainToPrincipalError::SealNotSaved(unconfirmed())),
            WalletRpcError::from(CollectUnstakedError::SealNotSaved(unconfirmed())),
        ];
        for err in answers {
            assert_eq!(err.code().as_i32(), -29128, "{err:?}");
            assert_eq!(err.data(), Some(json!({ "file_system": "FAT32" })));
            let message = err.message();
            assert!(
                message.starts_with("the staking transaction was not sent")
                    && message.ends_with("move the wallet to an NTFS volume and try again")
                    && !message.contains("discard"),
                "{message}"
            );
        }
        let network = WalletRpcError::from(UnstakeError::SealNotSaved(
            PersistenceError::DurabilityUnconfirmed(Unconfirmed::Remote("NTFS".to_owned())),
        ));
        assert_eq!(network.code().as_i32(), -29134, "{network:?}");
        // A seal whose save failed outright answers by cause too, never as
        // an internal fault: here a read-only wallet file.
        let read_only = WalletRpcError::from(UnstakeError::SealNotSaved(
            PersistenceError::WalletFile(shekyl_engine_file::WalletFileError::ReadOnly {
                target: std::path::PathBuf::from("wallet.pending"),
            }),
        ));
        assert_eq!(read_only.code().as_i32(), -29120, "{read_only:?}");
        assert_eq!(read_only.data(), Some(json!({ "target": "file" })));
        assert!(
            read_only
                .message()
                .starts_with("the staking transaction was not saved")
                && !read_only.message().contains("wallet.pending"),
            "{}",
            read_only.message()
        );
    }

    /// Every cause of an unsaved send has its own code, `data` and advice,
    /// and none of them leaks a path (Rick, 2026-11-18: the audit of
    /// `-29120`; 2026-11-19: its target, the step, the network drive). A
    /// cause is what the user does differently: make the folder writable,
    /// clear the file's read-only attribute, make the drive writable, free
    /// disk space, exclude the folder from scanning, check the disk, move
    /// the wallet, or report a fault.
    #[test]
    fn every_cause_of_an_unsaved_send_has_its_own_code_and_advice() {
        use shekyl_engine_file::{HeldOpen, Step, Unconfirmed};
        use std::io::{Error as IoErr, ErrorKind};
        use std::path::PathBuf;
        use WalletRpcErrorCode as C;
        let path = || PathBuf::from(LOCAL_PATH);
        let file = PersistenceError::WalletFile;
        let unconfirmed = PersistenceError::DurabilityUnconfirmed;
        let at = |step, source| {
            file(WalletFileError::SaveStep {
                step,
                target: path(),
                source,
            })
        };
        // A generic disk error and a "not a directory's place" error, each
        // in the OS's own text, which names no path. The raw numbers are the
        // platform's: Linux's `EIO` (5) is Windows' `ERROR_ACCESS_DENIED`,
        // which the mapping rightly reads as not writable, so Windows uses
        // `ERROR_IO_DEVICE` (1117), its generic I/O device error (measured
        // on the Windows host at 42f306f11f).
        #[cfg(windows)]
        const GENERIC_IO_ERROR: i32 = 1117;
        #[cfg(not(windows))]
        const GENERIC_IO_ERROR: i32 = 5;
        // `EISDIR` on Unix, `ERROR_NOT_READY` on Windows: either is a disk
        // error the mapping sends to SAVE_IO_FAILED.
        const OTHER_IO_ERROR: i32 = 21;
        let eio = || IoErr::from_raw_os_error(GENERIC_IO_ERROR);
        let eio_words = IoErr::from_raw_os_error(GENERIC_IO_ERROR).to_string();
        let eisdir_words = IoErr::from_raw_os_error(OTHER_IO_ERROR).to_string();
        let failed = |step: &str, words: &str| Some(json!({ "step": step, "error": words }));
        let cases: Vec<(PersistenceError, C, Option<Value>, &str)> = vec![
            (
                at(Step::Write, IoErr::from(ErrorKind::PermissionDenied)),
                C::SaveNotWritable,
                Some(json!({ "target": "folder" })),
                "the wallet's folder is not writable; make it writable",
            ),
            (
                file(WalletFileError::ReadOnly { target: path() }),
                C::SaveNotWritable,
                Some(json!({ "target": "file" })),
                "the wallet's file is read-only; clear its read-only attribute",
            ),
            (
                at(Step::Rename, IoErr::from(ErrorKind::ReadOnlyFilesystem)),
                C::SaveNotWritable,
                Some(json!({ "target": "volume" })),
                "the drive holding the wallet is read-only; make it writable",
            ),
            (
                at(Step::Write, IoErr::from(ErrorKind::StorageFull)),
                C::SaveDiskFull,
                None,
                "free disk space",
            ),
            (
                at(Step::Write, IoErr::from(ErrorKind::QuotaExceeded)),
                C::SaveDiskFull,
                None,
                "free disk space",
            ),
            (
                file(WalletFileError::HeldOpen(HeldOpen {
                    held: path(),
                    live: path(),
                })),
                C::SaveFileHeld,
                None,
                "exclude the wallet's folder from scanning",
            ),
            (
                at(Step::Write, eio()),
                C::SaveIoFailed,
                failed("write", &eio_words),
                "while writing the record",
            ),
            (
                at(Step::FolderSync, eio()),
                C::SaveIoFailed,
                failed("folder-sync", &eio_words),
                "while syncing the wallet's folder",
            ),
            (
                // The rename refused, the regtest gate's blocked state path.
                at(Step::Rename, IoErr::from_raw_os_error(OTHER_IO_ERROR)),
                C::SaveIoFailed,
                failed("rename", &eisdir_words),
                "while putting the record in place of the wallet's file",
            ),
            (
                // An error this process made up may carry a path; only its
                // kind is shown.
                at(
                    Step::Write,
                    IoErr::new(ErrorKind::InvalidData, format!("{LOCAL_PATH} is odd")),
                ),
                C::SaveIoFailed,
                failed("write", &ErrorKind::InvalidData.to_string()),
                "check the disk",
            ),
            (
                unconfirmed(Unconfirmed::DirectoryNotSynced(eio())),
                C::SaveIoFailed,
                failed("folder-sync", &eio_words),
                "while syncing the wallet's folder",
            ),
            (
                unconfirmed(Unconfirmed::Flush(eio())),
                C::SaveIoFailed,
                failed("flush", &eio_words),
                "while flushing the wallet's file to the disk",
            ),
            (
                unconfirmed(Unconfirmed::VolumeUnread(eio())),
                C::SaveIoFailed,
                failed("volume-query", &eio_words),
                "while asking the wallet's drive what it is",
            ),
            (
                // A Samba share reports NTFS: the network drive decides.
                unconfirmed(Unconfirmed::Remote("NTFS".to_owned())),
                C::SaveOnNetworkDrive,
                None,
                "move the wallet to a local drive",
            ),
            (
                unconfirmed(Unconfirmed::FileSystem("ReFS".to_owned())),
                C::SaveDurabilityUnconfirmed,
                Some(json!({ "file_system": "ReFS" })),
                "move the wallet to an NTFS volume",
            ),
            (
                unconfirmed(Unconfirmed::ClassicRename),
                C::SaveRenameUnconfirmed,
                None,
                "move the wallet to another local NTFS drive",
            ),
            (
                unconfirmed(Unconfirmed::Reopened),
                C::SaveInternalFault,
                None,
                "report it",
            ),
            (
                // A target with no parent directory is the caller's fault,
                // not the disk's.
                file(WalletFileError::Io(IoErr::new(
                    ErrorKind::InvalidInput,
                    format!("target {LOCAL_PATH} has no parent directory"),
                ))),
                C::SaveInternalFault,
                None,
                "report it",
            ),
            (
                file(WalletFileError::Ledger(
                    WalletLedgerError::InvariantFailed {
                        invariant: "I-1",
                        detail: "tip below a transfer".into(),
                    },
                )),
                C::SaveInternalFault,
                None,
                "report it",
            ),
            (
                file(WalletFileError::KeysFileWriteOnceViolation { path: path() }),
                C::SaveInternalFault,
                None,
                "report it",
            ),
        ];
        for (cause, code, data, advice) in cases {
            let shown = format!("{cause}");
            let err = unsaved(cause);
            assert_eq!(err.code(), code, "{shown}");
            assert_eq!(err.data(), data, "{shown}");
            let message = err.message();
            assert!(
                message.contains("not sent") && message.contains(advice),
                "{shown}: {message}"
            );
            assert!(
                !message.contains("/home"),
                "{shown} leaked a path: {message}"
            );
        }
    }

    /// The code table here and the contract's `WalletRpcErrorCode` enum are
    /// one set, both directions: a code the server can emit that the contract
    /// does not list is a conformance failure, and a contract code with no
    /// variant is a promise nothing keeps.
    /// Text a daemon controls, with a path in it: none of it may reach a
    /// message.
    const DAEMON_TEXT: &str = "reply from /home/user/.shekyl: missing field `nettype`";

    fn wire(ours: u32, theirs: u32) -> DaemonFault {
        DaemonFault::Identity(IdentityMismatch::Wire { ours, theirs })
    }

    /// Every daemon fault, the code it answers, and the `data` it carries.
    fn every_daemon_fault() -> Vec<(DaemonFault, WalletRpcErrorCode, Option<Value>)> {
        use WalletRpcErrorCode as C;
        let digest = |b| HashHex::from_bytes([b; 32]);
        vec![
            (DaemonFault::Unreachable, C::DaemonUnreachable, None),
            (
                wire(0x0003_001d, 0x0003_001c),
                C::DaemonVersionMismatch,
                Some(json!({
                    "wallet_version": "3.29", "daemon_version": "3.28", "update": "daemon",
                })),
            ),
            (
                wire(0x0003_001d, 0x0003_001e),
                C::DaemonVersionMismatch,
                Some(json!({
                    "wallet_version": "3.29", "daemon_version": "3.30", "update": "wallet",
                })),
            ),
            (
                DaemonFault::Identity(IdentityMismatch::WireUnreadable { ours: 0x0003_001d }),
                C::DaemonVersionMismatch,
                Some(json!({
                    "wallet_version": "3.29", "daemon_version": null, "update": null,
                })),
            ),
            (
                DaemonFault::Identity(IdentityMismatch::Rules {
                    ours: digest(1),
                    theirs: digest(2),
                }),
                C::DaemonRulesMismatch,
                Some(json!({
                    "wallet_digest": digest(1).to_string(),
                    "daemon_digest": digest(2).to_string(),
                })),
            ),
            (
                DaemonFault::Identity(IdentityMismatch::Network {
                    ours: Network::Mainnet,
                    theirs: Network::Testnet,
                }),
                C::DaemonNetworkMismatch,
                Some(json!({ "wallet": "mainnet", "daemon": "testnet" })),
            ),
            (
                DaemonFault::Identity(IdentityMismatch::Genesis {
                    ours: digest(3),
                    theirs: digest(4),
                    network: Network::Testnet,
                }),
                C::DaemonChainMismatch,
                Some(json!({
                    "network": "testnet",
                    "wallet_genesis": digest(3).to_string(),
                    "daemon_genesis": digest(4).to_string(),
                })),
            ),
            (DaemonFault::Protocol, C::DaemonProtocolViolation, None),
            (DaemonFault::FeeResponse, C::DaemonFeeResponseInvalid, None),
            (DaemonFault::Internal, C::InternalError, None),
            (DaemonFault::NotPermitted, C::DaemonGrantRefused, None),
            (DaemonFault::PeerCheck, C::DaemonPeerCheckFailed, None),
            (
                DaemonFault::Service(Some("127.0.0.1:11030".parse().unwrap())),
                C::DaemonIsAService,
                Some(json!({ "view": "127.0.0.1:11030" })),
            ),
            (
                DaemonFault::Service(None),
                C::DaemonIsAService,
                Some(json!({ "view": null })),
            ),
        ]
    }

    /// A service at "this computer" says what to set (Rick, 2026-11-17):
    /// the view listener as the `daemon-address`, or, with none, that the
    /// node serves no wallet leg and `rpc-view-listen`. A failed peer check
    /// is reported as the security failure it is.
    #[test]
    fn a_service_here_names_the_setting_and_a_peer_check_is_a_security_failure() {
        let view = from_daemon_fault(
            DaemonFault::Service(Some("127.0.0.1:11030".parse().unwrap())),
            DAEMON_TEXT,
        );
        assert_eq!(
            view.message(),
            "The node on this computer runs as a service. Until wallets reach a service over \
             the channel, set daemon-address = 127.0.0.1:11030"
        );
        let none = from_daemon_fault(DaemonFault::Service(None), DAEMON_TEXT).message();
        assert!(none.contains("serves no wallet leg"), "{none}");
        assert!(none.contains("rpc-view-listen"), "{none}");
        let peer = from_daemon_fault(DaemonFault::PeerCheck, DAEMON_TEXT).message();
        assert!(peer.contains("did not connect"), "{peer}");

        // The exit reports the same codes, not a retry. Red edit: map
        // `UnstakeError::DaemonTarget` to `UnstakeRetryTransient`.
        use shekyl_engine_core::UnstakeError;
        let exit_peer: WalletRpcError = UnstakeError::DaemonTarget(DaemonFault::PeerCheck).into();
        assert_eq!(exit_peer.code(), WalletRpcErrorCode::DaemonPeerCheckFailed);
        let exit_service: WalletRpcError = UnstakeError::DaemonTarget(DaemonFault::Service(Some(
            "127.0.0.1:11030".parse().unwrap(),
        )))
        .into();
        assert_eq!(exit_service.code(), WalletRpcErrorCode::DaemonIsAService);
        assert_ne!(
            exit_service.code(),
            WalletRpcErrorCode::UnstakeRetryTransient
        );
    }

    /// A daemon fault answers the same code whichever operation met it, and
    /// none of the daemon's text reaches the message.
    #[test]
    fn every_daemon_fault_names_its_remedy_on_every_path() {
        let io = |fault| IoError::Daemon {
            fault,
            detail: DAEMON_TEXT.to_owned(),
        };
        for (fault, code, data) in every_daemon_fault() {
            let paths: [(&str, WalletRpcError); 4] = [
                ("open", OpenError::Io(io(fault)).into()),
                ("refresh", RefreshError::Io(io(fault)).into()),
                ("build", SendError::Io(io(fault)).into()),
                ("storage", from_io_error(io(fault))),
            ];
            for (path, err) in paths {
                assert_eq!(err.code(), code, "{path}: {fault:?}");
                assert_eq!(err.data(), data, "{path}: {fault:?}");
                let message = err.message();
                assert!(
                    !message.contains("/home/user") && !message.contains("missing field"),
                    "{path}: the daemon's text stays in the log: {message}"
                );
            }
        }
    }

    /// The identity messages name the remedy, not only the disagreement.
    #[test]
    fn a_version_mismatch_says_which_side_to_update() {
        let older: WalletRpcError = from_daemon_fault(wire(0x0003_001d, 0x0003_001c), DAEMON_TEXT);
        assert!(older.message().contains("update the daemon"), "{older}");
        let newer: WalletRpcError = from_daemon_fault(wire(0x0003_001d, 0x0003_001e), DAEMON_TEXT);
        assert!(newer.message().contains("update this wallet"), "{newer}");
        let network = from_daemon_fault(
            DaemonFault::Identity(IdentityMismatch::Network {
                ours: Network::Stagenet,
                theirs: Network::Mainnet,
            }),
            DAEMON_TEXT,
        );
        assert!(
            network
                .message()
                .contains("runs mainnet, but this wallet is for stagenet"),
            "{network}"
        );
    }

    /// The fee query keeps its own "no answer" code (`-29102`); every other
    /// daemon fault behind it names its cause, on the send path and on each
    /// staking lane that quotes a fee.
    #[test]
    fn a_failed_fee_query_names_its_cause() {
        use shekyl_engine_core::{
            CollectUnstakedError, DrainToPrincipalError, FirstStakeError, UnstakeError,
        };
        let wrong_network = DaemonFault::Identity(IdentityMismatch::Network {
            ours: Network::Mainnet,
            theirs: Network::Testnet,
        });
        for (fault, code) in [
            (
                DaemonFault::Unreachable,
                WalletRpcErrorCode::FeeEstimationFailed,
            ),
            (wrong_network, WalletRpcErrorCode::DaemonNetworkMismatch),
            (
                DaemonFault::Protocol,
                WalletRpcErrorCode::DaemonProtocolViolation,
            ),
            (
                DaemonFault::FeeResponse,
                WalletRpcErrorCode::DaemonFeeResponseInvalid,
            ),
        ] {
            let fee = FeeEstimatorError::Daemon(fault);
            let lanes: [(&str, WalletRpcError); 4] = [
                ("send", SendError::Fee(fee).into()),
                ("drain", DrainToPrincipalError::FeeEstimate(fee).into()),
                ("unstake", UnstakeError::FeeEstimate(fee).into()),
                ("collect", CollectUnstakedError::FeeEstimate(fee).into()),
            ];
            for (lane, err) in lanes {
                assert_eq!(err.code(), code, "{lane}: {fault:?}");
            }
            // First-stake maps inside its handler; its payload is the same
            // typed error the lanes above carry.
            assert!(matches!(
                FirstStakeError::FeeEstimate(fee),
                FirstStakeError::FeeEstimate(FeeEstimatorError::Daemon(f)) if f == fault
            ));
        }
    }

    /// A signer fault answers the same on every path that signs: an internal
    /// one is `-29119` with its keyword, and one the user can act on keeps
    /// its own code. Red edit: map a lane's `Signer` arm to an internal error.
    #[test]
    fn a_signer_fault_answers_the_same_on_every_signing_path() {
        use shekyl_engine_core::{
            CollectUnstakedError, DrainToPrincipalError, InternalSignFault, UnstakeError,
        };
        let internal = SignFault::Internal(InternalSignFault::MembershipSelfCheck);
        for (fault, code) in [
            (internal, WalletRpcErrorCode::SignerFailed),
            (
                SignFault::PqcLeafMismatch { input: 1 },
                WalletRpcErrorCode::InputUnspendable,
            ),
        ] {
            let lanes: [(&str, WalletRpcError); 4] = [
                ("send", SendError::Sign(fault).into()),
                ("drain", DrainToPrincipalError::Signer(fault).into()),
                ("unstake", UnstakeError::Signer(fault).into()),
                ("collect", CollectUnstakedError::Signer(fault).into()),
            ];
            for (lane, err) in lanes {
                assert_eq!(err.code(), code, "{lane}: {fault:?}");
                if fault == internal {
                    assert!(
                        matches!(
                            err,
                            WalletRpcError::SignerFailed {
                                fault: "membership-self-check"
                            }
                        ),
                        "{lane}: {err:?}"
                    );
                }
            }
        }
    }

    /// A curve-tree ingest failure answers "close and reopen" only where a
    /// reopen can help; a daemon's bad data and a bug each keep their own.
    #[test]
    fn a_curve_tree_ingest_failure_names_its_remedy() {
        use CurveTreeIngestFault as F;
        use WalletRpcErrorCode as C;
        for (fault, code) in [
            (F::ActorUnavailable, C::CurveTreeUnavailable),
            (F::ClientPoisoned, C::CurveTreeUnavailable),
            (F::RebuildFailed, C::CurveTreeUnavailable),
            (F::RootMismatch, C::DaemonProtocolViolation),
            (F::BackfillBlockUndecodable, C::DaemonProtocolViolation),
            (F::ClientRejected, C::InternalError),
            (F::TipHeightOverflow, C::InternalError),
            (F::BackfillHeightOverflow, C::InternalError),
        ] {
            let err: WalletRpcError = RefreshError::CurveTreeIngest { fault }.into();
            assert_eq!(err.code(), code, "{fault:?}");
        }
    }

    /// A chain that kept reorganizing is its own remedy — wait for it to
    /// settle — and after a durable rescan reset it is still "incomplete".
    #[test]
    fn a_reorg_storm_is_not_an_outage() {
        let err: WalletRpcError = RefreshError::ReorgStorm.into();
        assert_eq!(err.code(), WalletRpcErrorCode::ChainUnstable);
        let err = WalletRpcError::from_rescan_scan_failure(RefreshError::ReorgStorm);
        assert_eq!(err.code(), WalletRpcErrorCode::RescanIncomplete);
    }

    #[test]
    fn the_code_table_is_the_contracts() {
        let contract = include_str!("../../../docs/api/wallet_rpc.yaml");
        let schema = contract
            .find("\n    WalletRpcErrorCode:\n")
            .expect("the contract declares WalletRpcErrorCode");
        let after = &contract[schema..];
        let list = after.find("enum:").expect("an enum list") + "enum:".len();
        // Each entry is `- <code>   # <NAME>[ — prose]`: the name is the
        // comment's first word.
        let mut listed = std::collections::BTreeSet::new();
        for line in after[list..].lines().skip(1) {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            let Some(rest) = t.strip_prefix("- ") else {
                break;
            };
            let (number, comment) = rest.split_once('#').expect("a named entry");
            let name = comment.split_whitespace().next().expect("a name");
            listed.insert((
                number.trim().parse::<i32>().expect("a numeric code"),
                name.to_owned(),
            ));
        }
        assert!(listed.len() > 50, "the parse found the list: {listed:?}");
        let emitted: std::collections::BTreeSet<(i32, String)> = WalletRpcErrorCode::ALL
            .iter()
            .map(|c| (c.as_i32(), c.name().to_owned()))
            .collect();
        let unlisted: Vec<_> = emitted.difference(&listed).collect();
        let unbacked: Vec<_> = listed.difference(&emitted).collect();
        assert!(
            unlisted.is_empty() && unbacked.is_empty(),
            "emitted but not in the contract: {unlisted:?}; in the contract with no variant: {unbacked:?}"
        );
    }

    /// `-29119`'s `data.fault` is one keyword of a closed set: the builder's
    /// invariants and the wallet-side faults. The contract and the input
    /// grammar list that set; both lists are the two enums' keywords. Bites
    /// when a fault is added, renamed or removed in the code without the
    /// docs, or the docs name a keyword nothing emits.
    #[test]
    fn the_signer_fault_keywords_are_the_documented_set() {
        use std::collections::BTreeSet;
        let emitted: BTreeSet<&str> = shekyl_engine_core::InternalSignFault::ALL
            .iter()
            .map(|f| f.keyword())
            .chain(
                shekyl_engine_core::SignerFault::ALL
                    .iter()
                    .map(|f| f.keyword()),
            )
            .collect();
        assert_eq!(
            emitted.len(),
            shekyl_engine_core::InternalSignFault::ALL.len()
                + shekyl_engine_core::SignerFault::ALL.len(),
            "no keyword names two faults"
        );

        fn between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
            let from = text.find(start).expect(start) + start.len();
            let len = text[from..].find(end).expect(end);
            &text[from..from + len]
        }

        let contract = include_str!("../../../docs/api/wallet_rpc.yaml");
        // The entry wraps across the YAML's description column: one space
        // between words, so a phrase reads whole.
        let entry = between(contract, "-29119 SIGNER_FAILED", "-29120 SAVE_NOT_WRITABLE")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let builder = between(&entry, "a builder invariant — ", " — or the wallet");
        let wallet = between(&entry, "signing reads — ", ").");
        let listed: BTreeSet<&str> = builder
            .split(',')
            .chain(wallet.split(','))
            .map(str::trim)
            .collect();
        assert_eq!(listed, emitted, "wallet_rpc.yaml's -29119 keywords");

        let grammar = include_str!("../../../docs/design/INPUT_GRAMMAR.md");
        let sentence = between(
            grammar,
            "`-29119 SIGNER_FAILED` gains `data.fault`, one keyword of a closed set:",
            "(the wallet state signing reads",
        );
        let listed: BTreeSet<&str> = sentence.split('`').skip(1).step_by(2).collect();
        assert_eq!(listed, emitted, "INPUT_GRAMMAR.md's -29119 keywords");
    }
}
