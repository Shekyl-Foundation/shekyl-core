// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Extended transfer details with Shekyl staking and PQC fields.

use zeroize::{Zeroize, Zeroizing};

use curve25519_dalek::{Scalar, EdwardsPoint};

use shekyl_oxide::primitives::Commitment;

use crate::{SubaddressIndex, extra::PaymentId, output::WalletOutput};

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
/// with PQC and staking metadata.
#[derive(Clone, Debug)]
pub struct TransferDetails {
    // Base output data (from scanner)
    pub tx_hash: [u8; 32],
    pub internal_output_index: u64,
    pub global_output_index: u64,
    pub block_height: u64,
    pub key: EdwardsPoint,
    pub key_offset: Scalar,
    pub commitment: Commitment,
    pub subaddress: Option<SubaddressIndex>,
    pub payment_id: Option<PaymentId>,

    // Spend tracking
    pub spent: bool,
    pub spent_height: Option<u64>,
    pub key_image: Option<[u8; 32]>,

    // Staking fields
    pub staked: bool,
    pub stake_tier: u8,
    pub stake_lock_until: u64,

    // PQC fields
    /// 64-byte combined shared secret from KEM decapsulation (X25519 || ML-KEM).
    pub combined_shared_secret: Option<Zeroizing<Vec<u8>>>,

    // Wallet management
    pub frozen: bool,
    pub fcmp_precomputed_path: Option<FcmpPrecomputedPath>,
}

impl TransferDetails {
    /// Create a TransferDetails from a scanned WalletOutput at a given block height.
    pub fn from_wallet_output(output: &WalletOutput, block_height: u64) -> Self {
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
            staked: false,
            stake_tier: 0,
            stake_lock_until: 0,
            combined_shared_secret: None,
            frozen: false,
            fcmp_precomputed_path: None,
        }
    }

    /// Whether this output is available to spend (not spent, not frozen, not locked).
    pub fn is_spendable(&self, current_height: u64) -> bool {
        !self.spent
            && !self.frozen
            && !(self.staked && self.stake_lock_until > current_height)
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
        self.key_offset.zeroize();
        self.spent.zeroize();
        self.spent_height.zeroize();
        self.key_image.zeroize();
        self.staked.zeroize();
        self.stake_tier.zeroize();
        self.stake_lock_until.zeroize();
        self.combined_shared_secret.zeroize();
        self.frozen.zeroize();
    }
}
