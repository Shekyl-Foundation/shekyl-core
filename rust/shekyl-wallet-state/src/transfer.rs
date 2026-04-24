// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Extended transfer details with Shekyl staking and PQC fields.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use curve25519_dalek::{EdwardsPoint, Scalar};

use shekyl_oxide::primitives::Commitment;

use crate::{
    payment_id::PaymentId,
    serde_helpers::{
        commitment_bytes, edwards_point_bytes, opt_zeroizing_bytes_32, opt_zeroizing_bytes_64,
        scalar_bytes,
    },
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
/// shape with PQC and staking metadata. All HKDF-derived secrets are stored
/// explicitly (not re-derived on demand) to avoid label-drift bugs between
/// scan-time and sign-time.
///
/// ### Deliberately NOT `Clone`
///
/// Cloning a `TransferDetails` would duplicate its `Zeroizing<[u8; N]>` secrets into
/// a second heap allocation that the compiler has no way to track. If a caller
/// legitimately needs two copies (e.g. a snapshot for a signing round), they must
/// `Serialize` into a `Zeroizing<Vec<u8>>` plaintext buffer and `Deserialize` back —
/// the process is explicit about the secret-handling boundary.
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
    pub key_image: Option<[u8; 32]>,

    // ── Staking fields ──
    pub staked: bool,
    pub stake_tier: u8,
    pub stake_lock_until: u64,
    /// Local claim watermark: the `to_height` of the last successful claim.
    pub last_claimed_height: u64,

    // ── PQC / KEM-derived secrets (populated at scan time) ──
    /// 64-byte combined shared secret from KEM decapsulation (X25519 || ML-KEM).
    #[serde(with = "opt_zeroizing_bytes_64", default)]
    pub combined_shared_secret: Option<Zeroizing<[u8; 64]>>,
    /// HKDF-derived scalar: `x = ho + b` gives the discrete log of O w.r.t. G.
    #[serde(with = "opt_zeroizing_bytes_32", default)]
    pub ho: Option<Zeroizing<[u8; 32]>>,
    /// HKDF-derived T-component scalar for FCMP++ SAL.
    #[serde(with = "opt_zeroizing_bytes_32", default)]
    pub y: Option<Zeroizing<[u8; 32]>>,
    /// HKDF-derived Pedersen commitment mask: `C = z*G + amount*H`.
    #[serde(with = "opt_zeroizing_bytes_32", default)]
    pub z: Option<Zeroizing<[u8; 32]>>,
    /// HKDF-derived amount encryption key.
    #[serde(with = "opt_zeroizing_bytes_32", default)]
    pub k_amount: Option<Zeroizing<[u8; 32]>>,

    /// Block height at which the output becomes spendable (inserted into curve tree).
    /// `block_height + SPENDABLE_AGE`. The daemon has no tree path for immature
    /// outputs, so spending before this height would fail at FCMP++ proof generation.
    pub eligible_height: u64,

    // ── Wallet management ──
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
    // Each of the five secret fields is `Option<Zeroizing<[u8; N]>>`
    // serialized as `Option<bytes>` via the `opt_zeroizing_bytes_*`
    // helpers. The `Zeroizing` wrapper is a zero-cost in-memory decoration;
    // it does NOT change the wire format, so it does not appear in the
    // schema.
    combined_shared_secret: Option<Vec<u8>>,
    ho: Option<Vec<u8>>,
    y: Option<Vec<u8>>,
    z: Option<Vec<u8>>,
    k_amount: Option<Vec<u8>>,
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
        self.combined_shared_secret.zeroize();
        self.ho.zeroize();
        self.y.zeroize();
        self.z.zeroize();
        self.k_amount.zeroize();
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
            subaddress: SubaddressIndex::new(0, 1),
            payment_id: None,
            spent: false,
            spent_height: None,
            key_image: None,
            staked: false,
            stake_tier: 0,
            stake_lock_until: 0,
            last_claimed_height: 0,
            combined_shared_secret: None,
            ho: None,
            y: None,
            z: None,
            k_amount: None,
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
    fn postcard_roundtrip_with_secrets() {
        let mut td = sample();
        td.ho = Some(Zeroizing::new([1u8; 32]));
        td.y = Some(Zeroizing::new([2u8; 32]));
        td.z = Some(Zeroizing::new([3u8; 32]));
        td.k_amount = Some(Zeroizing::new([4u8; 32]));
        td.combined_shared_secret = Some(Zeroizing::new([5u8; 64]));
        td.key_image = Some([7u8; 32]);
        td.spent = true;
        td.spent_height = Some(200);

        let bytes = postcard::to_allocvec(&td).unwrap();
        let back: TransferDetails = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(td.ho.as_deref(), back.ho.as_deref());
        assert_eq!(td.y.as_deref(), back.y.as_deref());
        assert_eq!(td.z.as_deref(), back.z.as_deref());
        assert_eq!(td.k_amount.as_deref(), back.k_amount.as_deref());
        assert_eq!(
            td.combined_shared_secret.as_deref(),
            back.combined_shared_secret.as_deref()
        );
        assert_eq!(td.key_image, back.key_image);
        assert_eq!(td.spent, back.spent);
        assert_eq!(td.spent_height, back.spent_height);
    }
}
