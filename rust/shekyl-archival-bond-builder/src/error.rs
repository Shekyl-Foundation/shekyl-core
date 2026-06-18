// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bond-construction failure modes.

use shekyl_archival_retention::BondPostKind;
use thiserror::Error;

/// Errors raised while constructing a JoinMarket archival bond post.
#[derive(Debug, Error)]
pub enum BondBuildError {
    /// `bond_floor(holdings)` was zero — structurally invalid holdings (empty
    /// shard set or count overflow). A bond cannot be posted for nothing.
    #[error("bond_floor(holdings) is zero; holdings are structurally invalid")]
    BondFloorZero,

    /// `verify_credit_funding` was applied to a vin that is not a JoinMarket
    /// credit-path post. The credit funding equation
    /// `funding == outputs + fee + bond_credit` is only sound when there is no
    /// input-side bond term, so a non-JoinMarket kind or a non-zero
    /// `bond_debit` is rejected rather than silently accepted at the amount
    /// level.
    #[error(
        "vin is not a JoinMarket credit-path post \
         (post_kind={post_kind:?}, bond_debit={bond_debit})"
    )]
    NotCreditPath {
        /// The offending vin's post kind.
        post_kind: BondPostKind,
        /// The offending vin's `bond_debit` (must be zero on a credit path).
        bond_debit: u64,
    },

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
