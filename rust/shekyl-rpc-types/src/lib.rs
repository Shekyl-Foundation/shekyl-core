// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Wallet↔daemon RPC **wire-contract types** — the single Rust definition of
//! the transaction-submit contract, consumed by `shekyl-daemon-rpc` (server)
//! and `shekyl-rpc-client` (wallet).
//!
//! The contract is specified in `docs/design/DAEMON_SUBMIT_VERDICT.md` §2 and
//! is **draft until the §8 parity matrix clears** (the ⚠-rows named by that
//! document's freeze rule); the types here are the §2.1 text made
//! compilable, with the skew rules (§2.3) pinned by `tests/skew.rs`.
//!
//! ## Contract shape
//!
//! - Endpoint: `POST /submit_transaction`, request [`SubmitTransactionRequest`]
//!   (`{ "tx_blob": "<hex>" }`), response **is** the serde-tagged
//!   [`SubmitVerdict`] (HTTP 200 for every verdict including `Rejected`;
//!   transport/availability failures use transport-level status codes and
//!   surface client-side as the `Err` arm, never as a verdict).
//! - A verdict is truth at commit-check time — the wallet acts on it
//!   (lock-lifecycle transitions only; ledger `spent` finality stays
//!   refresh-authoritative).
//! - Wire minimalism (§2.2): no `relayed`/`diffused`/`height` payloads, no
//!   `detail` field. Every deleted field was either trusted-daemon metadata
//!   the wallet must not consume or a snapshot observable trustlessly via
//!   refresh.
//!
//! ## Version-skew rules (§2.3, test-pinned)
//!
//! Wallet and daemon are released together but not deployed atomically:
//!
//! - Unknown `cause` string → deserializes to [`RejectCause::Unrecognized`]
//!   (`#[serde(other)]`) — fail-safe: released + one-shot rebuild, never
//!   retryable-in-place, never ambiguous.
//! - Unknown `verdict` tag → deserialization **error** → the client's `Err`
//!   arm (transport-equivalent ambiguity, TTL-resubmit). A verdict the
//!   client cannot name is not a verdict it can act on.
//! - Unknown *fields* within known variants are tolerated (no
//!   `deny_unknown_fields`), so additive daemon-side evolution does not
//!   break older wallets.
//!
//! ## Schema-evolution rule (§2.3, F38 — binding on authors)
//!
//! New **rejection** semantics MUST land as additive [`RejectCause`]
//! variants (older wallets degrade to `Unrecognized` → release, the
//! fail-safe direction). New **top-level [`SubmitVerdict`] tags** are
//! reserved for genuinely new *non-rejection* dispositions and are a
//! **breaking change** requiring a coordinated wire-version bump plus
//! skew-test extension — a rejection-shaped top-level tag would route every
//! older wallet into `Err` → TTL-resubmit → the same unknown tag, a
//! designed-in loop on every such release.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Request body for `POST /submit_transaction` (§2.4).
///
/// The transaction blob is hex-encoded raw tx bytes. There are no other
/// fields by design: the legacy `do_not_relay` and `do_sanity_checks` knobs
/// are deleted (§2.4 — a submitted tx is an offered tx; engine rules are
/// always on), and unknown fields sent by a newer client are ignored by an
/// older daemon per the §2.3 skew rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitTransactionRequest {
    /// Hex-encoded transaction blob (the exact bytes the wallet built).
    pub tx_blob: String,
}

/// The daemon's atomic verdict on one submitted transaction
/// (`docs/design/DAEMON_SUBMIT_VERDICT.md` §2.1).
///
/// Computed by the Rust admission engine with every mutable premise
/// re-checked under one lock scope (§3.1 Phase D), so the variants are
/// mutually consistent facts, not racy snapshots. The client-side type is
/// `Result<SubmitVerdict, RpcError>`: a verdict is definite; only the `Err`
/// arm (transport drop after send — Two Generals) is ambiguous.
///
/// Authoring constraint (F38): new rejection semantics go under
/// [`RejectCause`]; new top-level tags here are a breaking change. See the
/// crate docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum SubmitVerdict {
    /// Admitted to this daemon's pool at commit-check time; relay is
    /// daemon-owned from here (design doc §5.2). `Accepted ⇒ in pool at
    /// commit-check time` — a later eviction is observable via refresh, which
    /// is why the wallet keys liveness on chain confirmation, not verdicts.
    Accepted,
    /// Identity match: these exact bytes (same txid) are in the pool.
    /// Resolves prior transport ambiguity for this txid.
    AlreadyInPool,
    /// Identity match: this txid is in the main chain. Confirmation observed
    /// by verdict; refresh remains the settlement authority (reorgs happen).
    AlreadyInChain,
    /// Not in pool, not in chain, and not admitted — `cause` says why. Under
    /// single-egress this carries the proof that the bytes were not relayed
    /// by this daemon (design doc §7.1), so lock release is safe.
    Rejected {
        /// Why the transaction was refused.
        cause: RejectCause,
    },
}

/// Why a transaction was rejected (`docs/design/DAEMON_SUBMIT_VERDICT.md`
/// §2.1), with the per-cause wallet dispositions specified in §2.5.
///
/// Additive variants are the *only* schema-evolution vector for rejection
/// semantics (F38): older wallets deserialize unknown causes to
/// [`RejectCause::Unrecognized`] and take the fail-safe release path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectCause {
    /// Parse, structural, semantic, or policy-static failure — including
    /// coinbase-submit, zero-fee, tx-extra cap, nonzero unlock time,
    /// key-image domain/order violations. Deterministically permanent for
    /// these bytes.
    Malformed,
    /// Fee below the floor: at Phase C against the snapshot params, at the
    /// Phase-D re-gate against fresh params (the floor is per-block dynamic,
    /// design doc §3.1 / F34), or admitted-then-evicted under pool pressure
    /// at the post-prune membership check. All mean the same thing to the
    /// wallet: not in the pool, fee is why.
    FeeTooLow,
    /// A *different* transaction (pool or chain) consumes at least one of
    /// this tx's inputs — a key image, or an archival claim slot (a bond
    /// record already posted for this P; a serve-credit already claimed for
    /// this (P, shard, epoch); design doc §8.7.1). Emitted from Phase D
    /// re-check (or Phase C over chain-state facts) — never from the Phase B
    /// snapshot alone — so it genuinely means a competing consumption.
    DoubleSpendConflict,
    /// The FCMP++ reference block is no longer canonical (reorged away), or
    /// the curve-tree root at the reference height no longer matches, or the
    /// tree depth moved out of range. Rebuild the proof against a fresh
    /// root; input selection is still sound.
    StaleRoot,
    /// Reference block is canonical but younger than the FCMP++ reference
    /// minimum age. Timed backoff, then resubmit-same-bytes.
    ReferenceTooRecent,
    /// Reference block hash unknown to this daemon (typically: daemon not
    /// yet synced to it). Sync-gated retry (§2.5).
    ReferenceNotFound,
    /// Forward-compat catch-all: a cause this client build does not know.
    /// Deserialize-side only — a daemon never authors it. Disposition per
    /// §2.5: release + one-shot rebuild (the F28 loop-breaker applies).
    #[serde(other)]
    Unrecognized,
}
