// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The coinbase's `0x0C` draw commitment, drawn where the coinbase extra
//! is written (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §4.2;
//! `ARCHIVAL_SETTLEMENT_WRITER.md` §16.8 decision 4).
//!
//! The daemon's template builder calls `shekyl_coinbase_extra` for the
//! coinbase's extra and passes nothing about the commitment: this module
//! draws it inside that call. A witness key and a seed are drawn, committed
//! to, and dropped before the function returns, so nothing can open the
//! commitment and the block it rides in issues no draw.
//!
//! **The producer's secrets stay on this side of the boundary.** The
//! producer that keeps the pair for `W₂` blocks, reads the drawn shards and
//! files the reveal is Rust: it replaces the body of
//! [`commit_and_discard`] with a draw that also hands the pair to a Rust
//! store. The C interface does not change for it, and no secret, and no
//! commitment, becomes a C++ value (rule 36).
//!
//! The template is priced in passes, and each pass builds a coinbase, so
//! each pass draws. The last pass's coinbase is the block's. The field is
//! a fixed 32 bytes, so the passes agree on weight whatever they drew.
//! Which pass's secrets a producer keeps is that producer's question.

use rand::rngs::OsRng;
use rand::RngCore;
use shekyl_archival_retention::draw_commit;
use shekyl_crypto_pq::fn_dsa_hybrid::HybridEd25519FnDsa;
use shekyl_crypto_pq::CryptoError;
use shekyl_types::archival::DrawCommitment;
use zeroize::Zeroizing;

/// Commit to a fresh witness key and a fresh seed, independent of each
/// other and of everything else, and keep neither.
///
/// The seed is wiped when this returns (`Zeroizing`); the secret key wipes
/// itself on drop.
///
/// # Errors
///
/// If the OS random source or key generation fails. There is no fallback
/// commitment.
pub(crate) fn commit_and_discard() -> Result<DrawCommitment, CryptoError> {
    let (witness_pk, _witness_sk) = HybridEd25519FnDsa::generate_keypair()?;
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(seed.as_mut())
        .map_err(|e| CryptoError::KeyGenerationFailed(format!("OS RNG: {e}")))?;
    Ok(DrawCommitment::from_bytes(draw_commit(
        &witness_pk.to_canonical_bytes(),
        &seed,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two coinbases never share a commitment: each commits to its own
    /// key and seed (the specification's §4.2, "neither is derived from
    /// anything two blocks share").
    #[test]
    fn two_draws_commit_to_different_secrets() {
        let a = commit_and_discard().expect("first");
        let b = commit_and_discard().expect("second");
        assert_ne!(a, b);
    }
}
