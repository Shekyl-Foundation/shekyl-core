// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bond-construction failure modes.

use thiserror::Error;

/// Errors raised while constructing a JoinMarket archival bond post.
#[derive(Debug, Error)]
pub enum BondBuildError {
    /// `bond_floor(holdings)` was zero — structurally invalid holdings (empty
    /// shard set or count overflow). A bond cannot be posted for nothing.
    #[error("bond_floor(holdings) is zero; holdings are structurally invalid")]
    BondFloorZero,

    /// The P identity hybrid public key could not be serialized to its
    /// canonical wire bytes.
    #[error("failed to encode P identity hybrid public key: {0}")]
    IdentityEncode(shekyl_crypto_pq::CryptoError),

    /// Hybrid signing over the bond-post preimage failed.
    #[error("hybrid signature over bond-post preimage failed: {0}")]
    Sign(shekyl_crypto_pq::CryptoError),

    /// The credit-path amounts did not satisfy
    /// `sum(funding) == sum(outputs) + fee + floor`.
    #[error(
        "credit witness amounts do not balance: \
         sum(funding)={funding} != sum(outputs)={outputs} + fee={fee} + floor={floor}"
    )]
    CreditImbalance {
        /// Total committed value across funding inputs.
        funding: u64,
        /// Total value across constructed outputs.
        outputs: u64,
        /// Transaction fee.
        fee: u64,
        /// `bond_floor(holdings)` (== `bond_credit`).
        floor: u64,
    },

    /// A funding or output amount, or their sum, overflowed `u64`.
    #[error("credit witness amount arithmetic overflowed u64")]
    AmountOverflow,
}
