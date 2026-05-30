// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Extended transfer details with Shekyl staking and PQC fields.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use curve25519_dalek::{EdwardsPoint, Scalar};

use shekyl_crypto_pq::{handle::OutputHandle, kem::HybridCiphertext, key_image::KeyImage};
use shekyl_oxide::primitives::Commitment;

use crate::{
    payment_id::PaymentId,
    serde_helpers::{commitment_bytes, edwards_point_bytes, scalar_bytes},
    subaddress::SubaddressIndex,
};

/// Outputs must mature this many blocks before the daemon inserts them into
/// the curve tree. Mirrors `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE` (C++).
pub const SPENDABLE_AGE: u64 = 10;

/// A precomputed FCMP++ curve-tree path for an output.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct FcmpPrecomputedPath {
    /// The reference block hash used when computing this path.
    pub reference_block: [u8; 32],
    /// The curve-tree depth at precompute time.
    pub tree_depth: u32,
    /// The block height when this path was precomputed.
    pub precompute_height: u64,
    /// The serialized path blob from the daemon.
    pub path_blob: Vec<u8>,
}

/// Extended transfer details combining base output data with Shekyl-specific fields.
///
/// This is the Shekyl-native transfer record, extended from the monero-oxide output
/// shape with PQC and staking metadata. Per-output spend secrets (HKDF-derived
/// `ho`, `y`, `z`, `k_amount`, `combined_shared_secret`) are deliberately
/// **not** persisted on this struct: they are re-derived inside the engine from
/// `(view_secret, source_ciphertext)` at signing time per
/// `STAGE_1_PR_3_KEY_ENGINE.md` §7.10–§7.12. The orchestrator-side
/// `TransferDetails` carries only the public on-chain residue
/// (`source_ciphertext`) plus the wallet-private opaque identifier
/// (`output_handle`) needed to look the output up. See
/// `docs/design/STAGE_1_PR_3_M3D_PREFLIGHT.md` §3.3 for the
/// "secrets confined to engine" property delivered at M3d.
///
/// ### Deliberately NOT `Clone`
///
/// The original (pre-M3d) ban was motivated by `Zeroizing<[u8; N]>` secret
/// fields whose duplication would have bypassed the explicit
/// drop-time-zeroization discipline. M3d removed those fields, so the
/// memory-safety framing no longer applies — `OutputHandle` is `Copy`
/// (a 16-byte transparent newtype over `[u8; OUTPUT_HANDLE_LEN]`) and
/// `TransferDetails`' remaining fields are ordinary plain data.
///
/// The ban is retained post-M3d for **two distinct, still-load-bearing
/// reasons**:
///
/// 1. **Privacy-correlation discipline on `OutputHandle`.** The handle is
///    cryptographically non-secret (cSHAKE256 with a secret keying input
///    is a PRF), but per its `Privacy-correlation note` it is
///    wallet-state-correlating — only a holder of the wallet's
///    `view_secret` can reproduce a handle, and possession of two handles
///    that share a wallet origin links them. Forcing every duplication
///    through a serialize/deserialize ceremony keeps each handle's flow
///    visible at the call site and prevents accidental proliferation of
///    correlation-sensitive identifiers through bare `.clone()` calls.
/// 2. **Snapshotting-explicit discipline.** Engine bookkeeping that
///    legitimately needs two views of a `TransferDetails` (e.g. a
///    pre-/post-snapshot for a signing round) should make that intent
///    visible in the code rather than hide it behind an implicit clone.
///    Forcing `Serialize` into a buffer and `Deserialize` back keeps
///    every snapshot's lifetime and intent explicit at the call site.
///
/// If a caller legitimately needs two copies, they must `Serialize` into
/// a buffer and `Deserialize` back; the process is explicit about the
/// boundary.
#[derive(Serialize, Deserialize)]
pub struct TransferDetails {
    // ── Base output data (from scanner) ──
    pub tx_hash: [u8; 32],
    pub internal_output_index: u64,
    pub global_output_index: u64,
    pub block_height: u64,
    #[serde(with = "edwards_point_bytes")]
    pub key: EdwardsPoint,
    #[serde(with = "scalar_bytes")]
    pub key_offset: Scalar,
    #[serde(with = "commitment_bytes")]
    pub commitment: Commitment,
    pub subaddress: Option<SubaddressIndex>,
    pub payment_id: Option<PaymentId>,

    // ── Spend tracking ──
    pub spent: bool,
    pub spent_height: Option<u64>,
    /// Per-output key image. Wrapped in [`KeyImage`] for type-system
    /// protection at the engine boundary; `KeyImage` is
    /// `#[serde(transparent)]` over `[u8; 32]` so the on-disk wire
    /// format is unchanged from `Option<[u8; 32]>`.
    pub key_image: Option<KeyImage>,

    // ── Staking fields ──
    pub staked: bool,
    pub stake_tier: u8,
    pub stake_lock_until: u64,
    /// Local claim watermark: the `to_height` of the last successful claim.
    pub last_claimed_height: u64,

    // ── M3b deterministic-handle pathway (per `STAGE_1_PR_3_M3B_PREFLIGHT.md`) ──
    //
    // These two fields replaced the five per-output secret fields
    // (`combined_shared_secret`, `ho`, `y`, `z`, `k_amount`) at M3d. The
    // engine re-derives the secrets from `(view_secret, source_ciphertext)`
    // at signing time; the orchestrator-resident `TransferDetails` carries
    // only the inputs to that re-derivation plus the handle that names the
    // output.
    /// On-chain hybrid X25519 + ML-KEM-768 ciphertext from the source
    /// transaction.
    ///
    /// **Non-secret** (broadcast in the transaction's `tx_extra`). The
    /// engine's deterministic-handle pathway
    /// (`shekyl_engine_core::engine::local_keys::LocalKeys::derive_source_secrets_bundle`)
    /// consumes this field to re-derive `combined_ss` and the per-output
    /// secrets at signing time. Post-M3d, the orchestrator-side
    /// `TransferDetails` schema no longer carries those derived secrets;
    /// `source_ciphertext` is the single load-bearing input.
    ///
    /// `Option` for transitional shape: pre-M3b-scanned outputs lack
    /// this field and are re-populated by the engine post-pass at
    /// `engine::merge::populate_engine_handle_fields` after the
    /// scanned block is merged into the ledger. In a v4 store
    /// (`LEDGER_BLOCK_VERSION >= 4`, post-M3d) the engine post-pass
    /// runs unconditionally, so every persisted transfer carries
    /// `Some(...)`; the `Option` wrapping is retained because
    /// `from_wallet_output` constructs the record before the engine
    /// post-pass populates the field.
    #[serde(default)]
    pub source_ciphertext: Option<HybridCiphertext>,

    /// Deterministic 16-byte output handle
    /// (`shekyl_crypto_pq::handle::derive_output_handle(view_secret,
    /// tx_hash, output_index)`).
    ///
    /// **Non-secret** in the cryptographic sense (cSHAKE256 with a
    /// secret keying input is a PRF and discloses no view-secret
    /// material), but **wallet-private derivable** — only a holder of
    /// the wallet's `view_secret` can reproduce a handle. See
    /// `OutputHandle`'s "Non-secret status" and "Privacy-correlation
    /// note" docs; the handle is wallet-state-correlating and is not
    /// surfaced through public boundaries (logs, RPC, public errors).
    /// Persisted as a memo of the cSHAKE256 derivation so the
    /// orchestrator can use the handle as a stable opaque identifier
    /// in cross-engine bookkeeping (`HashMap<OutputHandle, _>`)
    /// without re-deriving from the view secret on every lookup.
    ///
    /// `Option` for transitional shape, same as `source_ciphertext`
    /// above.
    #[serde(default)]
    pub output_handle: Option<OutputHandle>,

    /// Block height at which the output becomes spendable (inserted into curve tree).
    /// `block_height + SPENDABLE_AGE`. The daemon has no tree path for immature
    /// outputs, so spending before this height would fail at FCMP++ proof generation.
    pub eligible_height: u64,

    // ── Engine management ──
    pub frozen: bool,
    pub fcmp_precomputed_path: Option<FcmpPrecomputedPath>,
}

impl TransferDetails {
    /// Whether this output is available for regular spending.
    ///
    /// Staked outputs are NEVER directly spendable -- they must go through
    /// the unstake transaction path once matured. Outputs below `eligible_height`
    /// are immature (no curve-tree path yet) and cannot be spent.
    pub fn is_spendable(&self, current_height: u64) -> bool {
        !self.spent && !self.frozen && !self.staked && current_height >= self.eligible_height
    }

    /// Whether this staked output can be unstaked (lock period expired, not yet spent).
    pub fn is_unstakeable(&self, current_height: u64) -> bool {
        self.staked && !self.spent && !self.frozen && self.stake_lock_until <= current_height
    }

    /// Whether this staked output has unclaimed reward backlog.
    pub fn has_claimable_rewards(&self, current_height: u64) -> bool {
        if !self.staked || self.spent {
            return false;
        }
        let accrual_cap = std::cmp::min(current_height, self.stake_lock_until);
        let watermark = if self.last_claimed_height > 0 {
            self.last_claimed_height
        } else {
            self.block_height
        };
        watermark < accrual_cap
    }

    /// The amount (in atomic units) held in this output.
    pub fn amount(&self) -> u64 {
        self.commitment.amount
    }

    /// Whether this is a staked output still within its lock period.
    pub fn is_locked_stake(&self, current_height: u64) -> bool {
        self.staked && self.stake_lock_until > current_height
    }

    /// Whether this is a staked output whose lock period has expired.
    pub fn is_matured_stake(&self, current_height: u64) -> bool {
        self.staked && self.stake_lock_until <= current_height
    }
}

// ---------------------------------------------------------------------------
// `postcard-schema` support — delegated to a mirror struct whose Rust field
// types match the *wire* layout produced by the `#[serde(with = "...")]`
// helpers in `serde_helpers`. `postcard_schema`'s derive only respects
// `#[serde(rename)]`; it does NOT see `#[serde(with)]`, so a naive derive on
// `TransferDetails` would emit a schema that calls `<EdwardsPoint as Schema>`
// — a type that deliberately has no `Schema` impl (curve crates are
// no-std-first and do not depend on postcard-schema). The mirror approach
// produces a schema that is *wire-accurate* (every curve/scalar/commitment
// field appears as a length-prefixed byte sequence, matching what
// `serde_bytes::Bytes::new(&[u8; N])` produces on the wire) and keeps
// `TransferDetails` itself free of schema-compatibility concerns.
//
// The mirror is private, never instantiated: only its associated `SCHEMA`
// constant is read (once, by the snapshot-assertion test). Fields are
// `Vec<u8>` rather than `serde_bytes::ByteBuf` because `Vec<u8>` has an
// upstream `Schema` impl and is wire-identical to `serde_bytes::Bytes` in
// postcard (both emit `varint(len) || bytes`).

#[derive(postcard_schema::Schema)]
#[allow(dead_code)]
struct TransferDetailsSchema {
    tx_hash: [u8; 32],
    internal_output_index: u64,
    global_output_index: u64,
    block_height: u64,
    // EdwardsPoint via `edwards_point_bytes` — compressed-Y 32 bytes.
    key: Vec<u8>,
    // Scalar via `scalar_bytes` — canonical LE 32 bytes.
    key_offset: Vec<u8>,
    // Commitment via `commitment_bytes` — 32-byte mask || 8-byte LE amount.
    commitment: Vec<u8>,
    subaddress: Option<crate::subaddress::SubaddressIndex>,
    payment_id: Option<crate::payment_id::PaymentId>,
    spent: bool,
    spent_height: Option<u64>,
    key_image: Option<[u8; 32]>,
    staked: bool,
    stake_tier: u8,
    stake_lock_until: u64,
    last_claimed_height: u64,
    // Non-secret on-chain payloads; reference the workspace types
    // directly (their `postcard_schema::Schema` derives lock the wire
    // shape from the source side per
    // `STAGE_1_PR_3_M3B_PREFLIGHT.md` §2 D3 disposition α).
    source_ciphertext: Option<HybridCiphertext>,
    output_handle: Option<OutputHandle>,
    eligible_height: u64,
    frozen: bool,
    fcmp_precomputed_path: Option<FcmpPrecomputedPath>,
}

impl postcard_schema::Schema for TransferDetails {
    // Delegate to the wire-accurate mirror but rename the top-level type
    // back to `TransferDetails` so the snapshot reads naturally.
    const SCHEMA: &'static postcard_schema::schema::NamedType =
        &postcard_schema::schema::NamedType {
            name: "TransferDetails",
            ty: <TransferDetailsSchema as postcard_schema::Schema>::SCHEMA.ty,
        };
}

impl Zeroize for TransferDetails {
    fn zeroize(&mut self) {
        self.tx_hash.zeroize();
        self.internal_output_index.zeroize();
        self.global_output_index.zeroize();
        self.block_height.zeroize();
        self.key.zeroize();
        self.key_offset.zeroize();
        self.commitment.zeroize();
        self.spent.zeroize();
        self.spent_height.zeroize();
        self.key_image.zeroize();
        self.staked.zeroize();
        self.stake_tier.zeroize();
        self.stake_lock_until.zeroize();
        self.last_claimed_height.zeroize();
        // `source_ciphertext` and `output_handle` are non-secret — see
        // the field docs above. `HybridCiphertext` is on-chain public
        // data; `OutputHandle` is wallet-private-derivable from any
        // view secret and is correlation-sensitive only at the
        // boundary (logs / RPC) per its "Privacy-correlation note".
        // Neither is wiped here; doing so would require giving them
        // `Zeroize` impls we deliberately omit at the source. Per-output
        // spend secrets formerly held on this struct (M3a–M3c era's
        // `combined_shared_secret`, `ho`, `y`, `z`, `k_amount`) were
        // removed in M3d; the engine re-derives them from
        // `(view_secret, source_ciphertext)` and wipes them inside
        // its own boundary.
        self.eligible_height.zeroize();
        self.frozen.zeroize();
        if let Some(ref mut path) = self.fcmp_precomputed_path {
            path.reference_block.zeroize();
            path.path_blob.zeroize();
        }
    }
}

impl Drop for TransferDetails {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for TransferDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransferDetails")
            .field("tx_hash", &hex::encode(self.tx_hash))
            .field("internal_output_index", &self.internal_output_index)
            .field("global_output_index", &self.global_output_index)
            .field("block_height", &self.block_height)
            .field("amount", &self.amount())
            .field("spent", &self.spent)
            .field("staked", &self.staked)
            .field("eligible_height", &self.eligible_height)
            .field("frozen", &self.frozen)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

    fn sample() -> TransferDetails {
        TransferDetails {
            tx_hash: [0xAB; 32],
            internal_output_index: 3,
            global_output_index: 1234,
            block_height: 100,
            key: ED25519_BASEPOINT_POINT,
            key_offset: Scalar::ONE,
            commitment: Commitment::new(Scalar::ONE, 1_000_000),
            subaddress: Some(SubaddressIndex::new(1)),
            payment_id: None,
            spent: false,
            spent_height: None,
            key_image: None,
            staked: false,
            stake_tier: 0,
            stake_lock_until: 0,
            last_claimed_height: 0,
            source_ciphertext: None,
            output_handle: None,
            eligible_height: 110,
            frozen: false,
            fcmp_precomputed_path: None,
        }
    }

    #[test]
    fn json_roundtrip_minimal() {
        let td = sample();
        let s = serde_json::to_string(&td).unwrap();
        let back: TransferDetails = serde_json::from_str(&s).unwrap();
        assert_eq!(td.tx_hash, back.tx_hash);
        assert_eq!(td.key.compress(), back.key.compress());
        assert_eq!(td.key_offset, back.key_offset);
        assert_eq!(td.commitment.amount, back.commitment.amount);
        assert_eq!(td.commitment.mask, back.commitment.mask);
    }

    #[test]
    fn postcard_roundtrip_with_handle_fields() {
        // Post-M3d (per `STAGE_1_PR_3_M3D_PREFLIGHT.md` §3.3), the
        // `TransferDetails` schema no longer carries the five legacy
        // secret-bearing fields (`combined_shared_secret`, `ho`, `y`,
        // `z`, `k_amount`); the engine re-derives the secrets from
        // `(view_secret, source_ciphertext)` at signing time. The
        // load-bearing Option-valued fields that this round-trip needs
        // to pin are the M3b deterministic-handle pathway memos
        // (`source_ciphertext`, `output_handle`) plus the long-standing
        // `key_image` / spend-state shape — same coverage shape as the
        // pre-M3d `postcard_roundtrip_with_secrets` test, retargeted at
        // the surviving Option-valued fields.
        let mut td = sample();
        td.source_ciphertext = Some(HybridCiphertext {
            x25519: [0xA5; 32],
            ml_kem: vec![0xC3; 1088],
        });
        td.output_handle = Some(shekyl_crypto_pq::handle::derive_output_handle(
            &[0x77; 32],
            &td.tx_hash,
            td.internal_output_index,
        ));
        td.key_image = Some(KeyImage::from_canonical_bytes([7u8; 32]));
        td.spent = true;
        td.spent_height = Some(200);

        let bytes = postcard::to_allocvec(&td).unwrap();
        let back: TransferDetails = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(
            td.source_ciphertext.as_ref().map(|c| &c.x25519),
            back.source_ciphertext.as_ref().map(|c| &c.x25519)
        );
        assert_eq!(
            td.source_ciphertext.as_ref().map(|c| c.ml_kem.as_slice()),
            back.source_ciphertext.as_ref().map(|c| c.ml_kem.as_slice())
        );
        assert_eq!(td.output_handle, back.output_handle);
        assert_eq!(td.key_image, back.key_image);
        assert_eq!(td.spent, back.spent);
        assert_eq!(td.spent_height, back.spent_height);
    }
}
