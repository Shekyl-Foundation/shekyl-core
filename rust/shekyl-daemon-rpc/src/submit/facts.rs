// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The [`SubmitStateShim`] seam and its fact types
//! (`docs/design/DAEMON_SUBMIT_VERDICT.md` §3.2 / §4).
//!
//! The shim is the **named reversion boundary** (rule 21): production
//! implements it over the C++ FFI shims (§4.1–§4.3); the race suite
//! implements it as a deterministic mock (§10 item 2); the eventual Rust
//! mempool implements it natively. Facts are plain data — the shim fetches,
//! the engine decides. Zero verdict logic lives behind this trait.

use shekyl_types::{BlockHash, BlockHeight, TxHash};

use crate::submit::certificate::VerificationCertificate;

/// Per-key-image conflict descriptor from the snapshot / re-check
/// (§4.1: `none | own_txid | other`).
///
/// `OwnTx` means the pool's spender of this key image *is* the submitted
/// txid (an identity fact, paired with `in_pool`); `Other` means a
/// different transaction consumes the input — the only arm that can ever
/// classify as `DoubleSpendConflict`, and only from Phase-D fresh facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyImageConflict {
    /// No pool- or chain-level spender for this key image.
    Free,
    /// The spender is the submitted transaction itself (identity, not conflict).
    OwnTx,
    /// A different transaction consumes this key image.
    Other,
}

/// Facts about the submitted reference block, present iff the daemon knows
/// the block **by hash** (§3.1 item 4: the reference is pinned by hash; a
/// block hash commits to its prefix chain, so hash-canonicality within the
/// age window ⇒ root-canonicality).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferenceFacts {
    /// Height of the reference block on the main chain.
    pub height: BlockHeight,
    /// Curve-tree root at that height.
    pub root: [u8; 32],
    /// Current curve-tree depth in the consensus/LMDB convention
    /// (`curve_trees_tree_depth` = layer count − 1) — the row-K10 upper
    /// bound for the wire `tree_depth`. The verifier reconstructs its
    /// layer count as `wire tree_depth + 1`, exactly as the C++ caller
    /// does (`blockchain.cpp:4119`).
    pub tree_depth: u8,
}

/// The Phase-B POD fact snapshot (§3.1 Phase B / §4.1), taken under one
/// short pool→blockchain lock scope. Also the shape of Phase-D **fresh
/// facts** when the commit races.
///
/// `reference: None` means the reference-block hash is unknown to this
/// daemon (not found on the main chain) — at Phase C that is
/// `ReferenceNotFound`; at a Phase-D re-check on a reference that *was*
/// found at B it is a reorg, classified `StaleRoot`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitFacts {
    /// The submitted txid is pool-resident (at the `legacy` relay category).
    pub in_pool: bool,
    /// The submitted txid is in the main chain.
    pub in_chain: bool,
    /// Conflict descriptor per submitted key image, in submission order.
    pub key_image_conflicts: Vec<KeyImageConflict>,
    /// Reference-block facts, iff the hash is known to the daemon.
    pub reference: Option<ReferenceFacts>,
    /// Dynamic per-byte fee floor parameter (moves every block — F34).
    pub fee_per_byte: u64,
    /// Fee quantization mask (`get_fee_quantization_mask`, always ≥ 1).
    pub fee_quantization_mask: u64,
    /// Transaction weight limit (compile-time constant on Shekyl:
    /// `min_block_weight / 2 − COINBASE_BLOB_RESERVED_SIZE` = 149 400; §3.1).
    pub weight_limit: u64,
    /// Chain height as a block **count** (`m_db->height()`), the consensus
    /// basis for the ref-age window arithmetic.
    pub chain_height: BlockHeight,
}

/// Meta fields the commit shim needs for the existing `add_tx` insert tail
/// (§4.2): everything else in `txpool_tx_meta_t` is derived C++-side from
/// the blob and the certificate facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxMeta {
    /// Consensus transaction weight (serialized size + Bp+ clawback).
    pub weight: u64,
    /// Transaction fee (`Ct::Fcmp` fee field).
    pub fee: u64,
}

/// Outcome of the Phase-D check-and-commit (§3.2 / §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitOutcome {
    /// Every re-checked premise held; the tx is in the pool (attested via
    /// the certificate) and survived the post-insert `prune()` membership
    /// check (F23). `Accepted ⇒ in pool at commit-check time`.
    Committed,
    /// A mutable premise moved between the Phase-B snapshot and the commit
    /// lock. Carries the fresh facts; **Rust classifies**, most-terminal-
    /// first (§3.1) — the shim never chooses a verdict.
    Raced(SubmitFacts),
    /// The insert tail succeeded but the tail's `prune()` evicted the tx
    /// under pool pressure (F23 / defect 0.7) — classified
    /// `Rejected{FeeTooLow}` (pool-pressure variant).
    PrunedOnInsert,
    /// Internal inconsistency (§3.4: release-mode txid divergence between
    /// the engine hash and C++ `get_transaction_hash` over the same blob,
    /// or a marshalling fault). Never a verdict: surfaced as a loud
    /// transport-level error so a daemon defect is not converted into a
    /// wallet rebuild.
    InternalFault,
}

/// The engine's seam to pool/blockchain state (§3.2). See the module docs
/// for the reversion shape.
pub trait SubmitStateShim {
    /// Phase B: one short pool→blockchain lock scope, reads only (§4.1).
    fn snapshot_facts(
        &self,
        txid: &TxHash,
        key_images: &[[u8; 32]],
        reference_block: &BlockHash,
    ) -> SubmitFacts;

    /// Phase D: one short pool→blockchain lock scope — release-mode txid
    /// check first, then the §3.1 re-check list (identity, key images,
    /// hash-anchored reference + age window, root compare, `check_fee`
    /// re-gate against fresh params), then the existing `add_tx` insert
    /// tail with certificate-gated `fcmp_verified` attestation (§3.5) and
    /// the post-prune membership check (§4.2).
    fn commit(
        &self,
        blob: &[u8],
        txid: &TxHash,
        meta: &TxMeta,
        cert: &VerificationCertificate,
        expected: &SubmitFacts,
    ) -> CommitOutcome;

    /// Post-commit relay nudge into the existing
    /// `relay_transactions(local)` dispatch (§4.3). Fire and forget: the
    /// nudge is latency; the Dandelion++ embargo + periodic loop are the
    /// guarantee (§5.2).
    fn relay(&self, txid: &TxHash);
}

// Forwarding impl: one shim instance shared across transport workers (and
// across the engine + a test's assertion handle) is the normal ownership
// shape; without this, every out-of-crate implementor hits the orphan rule
// wrapping its mock in `Arc`.
impl<T: SubmitStateShim + ?Sized> SubmitStateShim for std::sync::Arc<T> {
    fn snapshot_facts(
        &self,
        txid: &TxHash,
        key_images: &[[u8; 32]],
        reference_block: &BlockHash,
    ) -> SubmitFacts {
        (**self).snapshot_facts(txid, key_images, reference_block)
    }

    fn commit(
        &self,
        blob: &[u8],
        txid: &TxHash,
        meta: &TxMeta,
        cert: &VerificationCertificate,
        expected: &SubmitFacts,
    ) -> CommitOutcome {
        (**self).commit(blob, txid, meta, cert, expected)
    }

    fn relay(&self, txid: &TxHash) {
        (**self).relay(txid)
    }
}
