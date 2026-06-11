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
//!
//! Byte stability across checkouts is guaranteed by the repository-level
//! `.gitattributes` pin (`docs/test_vectors/** -text`), which disables EOL
//! conversion so `include_str!` sees the committed bytes on every platform.

use sha2::{Digest, Sha256};

use crate::CryptoError;

const MANIFEST_JSON: &str =
    include_str!("../../../docs/test_vectors/ADDRESS_DERIVATION_V1/manifest.json");
const VECTORS_JSON: &str =
    include_str!("../../../docs/test_vectors/ADDRESS_DERIVATION_V1/vectors.json");

/// SHA-256 over the concatenated on-disk corpus files (`manifest.json` then
/// `vectors.json`). Rotated only by a deliberate derivation-version bump.
pub const ADDRESS_DERIVATION_MANIFEST_HASH: [u8; 32] = [
    0xd4, 0x18, 0x1e, 0xa1, 0xf0, 0xc6, 0xd6, 0xe5, 0x11, 0x49, 0xd9, 0x41, 0xc4, 0xe5, 0x5c, 0x21,
    0x67, 0xfc, 0x8d, 0xc8, 0x7a, 0x77, 0xa5, 0xf3, 0x95, 0xe0, 0x1f, 0xe3, 0x4e, 0xca, 0x75, 0x23,
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
///
/// Both values are public compile-time constants (the corpus is a published
/// KAT fixture), so a plain comparison is correct; constant-time comparison
/// would signal a secret where none exists.
pub fn address_derivation_manifest_self_check() -> Result<(), CryptoError> {
    let got = compute_address_derivation_manifest_hash();
    if got == ADDRESS_DERIVATION_MANIFEST_HASH {
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
