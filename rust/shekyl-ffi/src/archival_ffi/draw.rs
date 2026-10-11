// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The block template's `0x0C` draw commitment
//! (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §4.2; `ARCHIVAL_SETTLEMENT_WRITER.md`
//! §16.8 decision 4).
//!
//! The daemon's template builder needs 32 bytes for the coinbase and must
//! hold neither secret behind them (rule 36). This is the smallest writer
//! that satisfies the grammar: it draws a witness key and a seed, commits
//! to them, and drops both before it returns. Nothing can open the
//! commitment afterwards, so the block it rides in issues no draw.
//!
//! The producer that keeps the pair for `W₂` blocks, reads the drawn
//! shards and files carriers replaces the body of [`commit_and_discard`],
//! not its caller: the C++ still receives 32 bytes.

use rand::rngs::OsRng;
use rand::RngCore;
use shekyl_archival_retention::draw_commit;
use shekyl_crypto_pq::fn_dsa_hybrid::HybridEd25519FnDsa;
use shekyl_crypto_pq::CryptoError;
use shekyl_types::archival::{DrawCommitment, DRAW_COMMITMENT_LEN};
use zeroize::Zeroizing;

/// The commitment was written.
pub const SHEKYL_ARCHIVAL_DRAW_COMMITMENT_OK: u8 = 0;
/// `out` was null.
pub const SHEKYL_ARCHIVAL_DRAW_COMMITMENT_ERR_NULL_PTR: u8 = 1;
/// The OS random source or key generation failed. Nothing was written: a
/// template without a commitment is not a template.
pub const SHEKYL_ARCHIVAL_DRAW_COMMITMENT_ERR_ENTROPY: u8 = 2;

/// Commit to a fresh witness key and a fresh seed, independent of each
/// other and of everything else, and keep neither.
///
/// The seed is wiped when this returns (`Zeroizing`); the secret key wipes
/// itself on drop.
fn commit_and_discard() -> Result<DrawCommitment, CryptoError> {
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

/// Write a block template's draw commitment into `out`.
///
/// One call per template: the daemon passes the same 32 bytes to every
/// pricing pass of that template's coinbase.
///
/// # Safety
/// `out` is writable for [`DRAW_COMMITMENT_LEN`] bytes, or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_draw_commitment(out: *mut u8) -> u8 {
    if out.is_null() {
        return SHEKYL_ARCHIVAL_DRAW_COMMITMENT_ERR_NULL_PTR;
    }
    let Ok(commitment) = commit_and_discard() else {
        return SHEKYL_ARCHIVAL_DRAW_COMMITMENT_ERR_ENTROPY;
    };
    // SAFETY: `out` is non-null and writable for the commitment's width by
    // the caller's contract; the source is a local array.
    unsafe {
        std::ptr::copy_nonoverlapping(commitment.as_bytes().as_ptr(), out, DRAW_COMMITMENT_LEN);
    }
    SHEKYL_ARCHIVAL_DRAW_COMMITMENT_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two templates never share a commitment: each commits to its own
    /// key and seed (the specification's §4.2, "neither is derived from
    /// anything two blocks share").
    #[test]
    fn two_templates_commit_to_different_secrets() {
        let a = commit_and_discard().expect("first");
        let b = commit_and_discard().expect("second");
        assert_ne!(a, b);
    }

    #[test]
    fn the_export_writes_thirty_two_bytes_and_refuses_a_null_pointer() {
        let mut out = [0u8; DRAW_COMMITMENT_LEN];
        // SAFETY: `out` is a 32-byte local.
        let rc = unsafe { shekyl_archival_draw_commitment(out.as_mut_ptr()) };
        assert_eq!(rc, SHEKYL_ARCHIVAL_DRAW_COMMITMENT_OK);
        let mut again = [0u8; DRAW_COMMITMENT_LEN];
        // SAFETY: as above.
        let rc = unsafe { shekyl_archival_draw_commitment(again.as_mut_ptr()) };
        assert_eq!(rc, SHEKYL_ARCHIVAL_DRAW_COMMITMENT_OK);
        assert_ne!(out, again);
        // SAFETY: null is the refused case.
        let rc = unsafe { shekyl_archival_draw_commitment(std::ptr::null_mut()) };
        assert_eq!(rc, SHEKYL_ARCHIVAL_DRAW_COMMITMENT_ERR_NULL_PTR);
    }
}
