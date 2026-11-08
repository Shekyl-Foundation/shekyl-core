// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The checks a coinbase output makes before it pays an address.
//!
//! Account derivation stays in [`account`](crate::account). This is the
//! mining address's one validator: the daemon's `mine-address` row and the
//! miner both call it, and both reach it through `account`.

use crate::montgomery;

/// Why a coinbase cannot pay an address's keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecipientRefused {
    /// The spend key does not decode to a curve point.
    #[error("the address's spend key is not a valid curve point")]
    SpendKeyNotAPoint,
    /// The view key is not a point the X25519 half of the KEM target can
    /// be derived from.
    #[error("the address's view key is not a valid curve point")]
    ViewKeyNotAPoint,
    /// The ML-KEM-768 encapsulation key is not well-formed.
    #[error("the address's ML-KEM-768 key is not a well-formed encapsulation key")]
    KemKeyMalformed,
}

/// The X25519 half of a coinbase output's KEM target, after the checks the
/// C++ address decode makes: the spend key is a curve point, the view key
/// maps to X25519, and the ML-KEM-768 key is well-formed
/// ([`crate::kem::check_ml_kem_768_ek`]). The mining address's one
/// validator: the daemon's `mine-address` row and the miner both call it.
///
/// # Errors
///
/// [`RecipientRefused`], the first check that fails, in that order.
pub fn coinbase_recipient(
    spend_pk: &[u8; 32],
    view_pk: &[u8; 32],
    ml_kem_ek: &[u8],
) -> Result<[u8; 32], RecipientRefused> {
    if curve25519_dalek::edwards::CompressedEdwardsY(*spend_pk)
        .decompress()
        .is_none()
    {
        return Err(RecipientRefused::SpendKeyNotAPoint);
    }
    let x25519 = montgomery::ed25519_pk_to_x25519_pk(view_pk)
        .map_err(|_| RecipientRefused::ViewKeyNotAPoint)?;
    crate::kem::check_ml_kem_768_ek(ml_kem_ek).map_err(|_| RecipientRefused::KemKeyMalformed)?;
    Ok(x25519)
}
