// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Extended transfer details with Shekyl staking and PQC fields.

use zeroize::{Zeroize, Zeroizing};

use curve25519_dalek::{Scalar, EdwardsPoint};

use shekyl_oxide::primitives::Commitment;

use crate::{SubaddressIndex, extra::PaymentId, output::WalletOutput};

/// Outputs must mature this many blocks before the daemon inserts them into
/// the curve tree. Mirrors `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE` (C++).
pub const SPENDABLE_AGE: u64 = 10;

/// A precomputed FCMP++ curve-tree path for an output.
#[derive(Clone, Debug)]
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
/// This is the Rust equivalent of C++ `wallet2::transfer_details`, extended
/// with PQC and staking metadata. All HKDF-derived secrets are stored
/// explicitly (not re-derived on demand) to avoid label-drift bugs between
/// scan-time and sign-time.
pub struct TransferDetails {
    // ── Base output data (from scanner) ──
    pub tx_hash: [u8; 32],
    pub internal_output_index: u64,
    pub global_output_index: u64,
    pub block_height: u64,
    pub key: EdwardsPoint,
    pub key_offset: Scalar,
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
    pub combined_shared_secret: Option<Zeroizing<[u8; 64]>>,
    /// HKDF-derived scalar: `x = ho + b` gives the discrete log of O w.r.t. G.
    pub ho: Option<Zeroizing<[u8; 32]>>,
    /// HKDF-derived T-component scalar for FCMP++ SAL.
    pub y: Option<Zeroizing<[u8; 32]>>,
    /// HKDF-derived Pedersen commitment mask: `C = z*G + amount*H`.
    pub z: Option<Zeroizing<[u8; 32]>>,
    /// HKDF-derived amount encryption key.
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
    /// Create a TransferDetails from a scanned WalletOutput at a given block height.
    ///
    /// Automatically populates staking fields if the output carries `StakingMeta`.
    /// `stake_lock_until` is computed as `block_height + tier_lock_blocks`.
    /// PQC fields (ho, y, z, k_amount, combined_shared_secret) are left `None`
    /// and must be populated by the caller after KEM recovery.
    pub fn from_wallet_output(output: &WalletOutput, block_height: u64) -> Self {
        let (staked, stake_tier, stake_lock_until) = match output.staking() {
            Some(meta) => {
                let lock_blocks = shekyl_staking::tiers::tier_by_id(meta.lock_tier)
                    .map(|t| t.lock_blocks)
                    .unwrap_or(0);
                (true, meta.lock_tier, block_height + lock_blocks)
            }
            None => (false, 0, 0),
        };
        TransferDetails {
            tx_hash: output.transaction(),
            internal_output_index: output.index_in_transaction(),
            global_output_index: output.index_on_blockchain(),
            block_height,
            key: output.key(),
            key_offset: output.key_offset(),
            commitment: output.commitment().clone(),
            subaddress: output.subaddress(),
            payment_id: output.payment_id(),
            spent: false,
            spent_height: None,
            key_image: None,
            staked,
            stake_tier,
            stake_lock_until,
            last_claimed_height: 0,
            combined_shared_secret: None,
            ho: None,
            y: None,
            z: None,
            k_amount: None,
            eligible_height: block_height + SPENDABLE_AGE,
            frozen: false,
            fcmp_precomputed_path: None,
        }
    }

    /// Whether this output is available for regular spending.
    ///
    /// Staked outputs are NEVER directly spendable -- they must go through
    /// the unstake transaction path once matured. Outputs below `eligible_height`
    /// are immature (no curve-tree path yet) and cannot be spent.
    pub fn is_spendable(&self, current_height: u64) -> bool {
        !self.spent
            && !self.frozen
            && !self.staked
            && current_height >= self.eligible_height
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
