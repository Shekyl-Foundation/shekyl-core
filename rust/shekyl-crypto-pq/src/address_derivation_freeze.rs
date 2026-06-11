// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! ADDRESS_DERIVATION_V1 corpus freeze tripwire.
//!
//! The pinned SHA-256 digest covers the exact on-disk bytes of
//! `docs/test_vectors/ADDRESS_DERIVATION_V1/manifest.json` followed by
//! `vectors.json` (no separator). Any deliberate corpus rotation must
//! update both files and this constant via the KAT regenerator.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::CryptoError;

const MANIFEST_JSON: &str =
    include_str!("../../../docs/test_vectors/ADDRESS_DERIVATION_V1/manifest.json");
const VECTORS_JSON: &str =
    include_str!("../../../docs/test_vectors/ADDRESS_DERIVATION_V1/vectors.json");

/// SHA-256 over the concatenated on-disk corpus files (`manifest.json` then
/// `vectors.json`). Rotated only by a deliberate derivation-version bump.
pub const ADDRESS_DERIVATION_MANIFEST_HASH: [u8; 32] = [
    0x24, 0xce, 0xad, 0xc4, 0x84, 0x1e, 0x24, 0xc1, 0xe0, 0x8a, 0x8a, 0x9a, 0xd0, 0x2f, 0x17,
    0x42, 0xb9, 0x3b, 0xe8, 0x05, 0xc6, 0xb4, 0x86, 0xfa, 0xa1, 0x8a, 0x21, 0xd0, 0xf6, 0xcb,
    0xe5, 0x8f,
];

/// Recompute the corpus digest from the embedded file bytes.
#[must_use]
pub fn compute_address_derivation_manifest_hash() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MANIFEST_JSON.as_bytes());
    hasher.update(VECTORS_JSON.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Verify the embedded corpus matches the compile-time pin.
pub fn address_derivation_manifest_self_check() -> Result<(), CryptoError> {
    let got = compute_address_derivation_manifest_hash();
    if got.ct_eq(&ADDRESS_DERIVATION_MANIFEST_HASH).into() {
        Ok(())
    } else {
        Err(CryptoError::InvalidInput(
            "ADDRESS_DERIVATION_V1 corpus hash mismatch (manifest/vectors drift)".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_hash_matches_embedded_corpus() {
        address_derivation_manifest_self_check().expect("corpus must match pin");
    }
}
