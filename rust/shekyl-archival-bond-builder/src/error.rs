// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bond-construction failure modes.

use thiserror::Error;

/// Errors raised while constructing an archival bond-post vin (JoinMarket
/// credit or Unbond debit).
#[derive(Debug, Error)]
pub enum BondBuildError {
    /// `bond_floor(holdings)` was zero — structurally invalid holdings (empty
    /// shard set or count overflow). A bond cannot be posted for nothing.
    #[error("bond_floor(holdings) is zero; holdings are structurally invalid")]
    BondFloorZero,

    /// The debit-path amounts did not satisfy
    /// `sum(funding) + bond_debit == sum(outputs) + fee`.
    ///
    /// The mirror of [`Self::CreditImbalance`], and the sides are not
    /// interchangeable: a credit is a **sink** (`BondTerm::Credit` places it on
    /// the output side) while a debit is a **source** (`BondTerm::Debit` places
    /// it on the input side). Putting the released collateral on the wrong side
    /// balances arithmetically for a *different* transaction than the one being
    /// built, which is why the two rules are separate functions rather than one
    /// signed term.
    #[error(
        "debit witness amounts do not balance: \
         sum(funding)={funding} + debit={debit} != sum(outputs)={outputs} + fee={fee}"
    )]
    DebitImbalance {
        /// Total committed value across funding inputs.
        funding: u64,
        /// The released collateral entering the transaction.
        debit: u64,
        /// Total value across constructed outputs.
        outputs: u64,
        /// Transaction fee.
        fee: u64,
    },

    /// A full `Unbond` was requested against a record with nothing bonded.
    ///
    /// Refused **here**, at assembly, rather than assembled and rejected by the
    /// daemon (`BondPostError::NothingToUnbond`). On this path the difference
    /// matters: an exit that fails at the wallet fails loudly to the person who
    /// asked for it, while one that fails at the chain fails opaquely after a
    /// broadcast.
    #[error("nothing to unbond: the record's bonded total is zero")]
    NothingToUnbond,

    /// The P identity hybrid public key could not be serialized to its
    /// canonical wire bytes.
    #[error("failed to encode P identity hybrid public key: {0}")]
    IdentityEncode(shekyl_crypto_pq::CryptoError),

    /// The GF-1 bond-debit authorizer public key (`bond_spend_pk`) could not
    /// be serialized to its canonical wire bytes.
    #[error("failed to encode bond_spend_pk (GF-1 debit authorizer): {0}")]
    BondSpendEncode(shekyl_crypto_pq::CryptoError),

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
    #[error("bond-post witness amount arithmetic overflowed u64")]
    AmountOverflow,
}
