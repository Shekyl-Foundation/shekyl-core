// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! ARCHIVAL_P_DERIVE_V1 corpus freeze tripwire.
//!
//! The pinned SHA-256 digest covers the exact on-disk bytes of
//! `docs/test_vectors/ARCHIVAL_P_DERIVE_V1/manifest.json` followed by
//! `vectors.json` (no separator). Any deliberate corpus rotation must
//! update both files and this constant via the KAT regenerator.
//!
//! Byte stability across checkouts is guaranteed by the repository-level
//! `.gitattributes` pin (`docs/test_vectors/** -text`), which disables EOL
//! conversion so `include_str!` sees the committed bytes on every platform.
//! This is the third cross-arch-deterministic primitive (after
//! `reward_arithmetic` and the standoff draw); the digest is the platform-drift
//! tripwire that the `aarch64` qemu lane exercises.

use sha2::{Digest, Sha256};

use crate::CryptoError;

const MANIFEST_JSON: &str =
    include_str!("../../../docs/test_vectors/ARCHIVAL_P_DERIVE_V1/manifest.json");
const VECTORS_JSON: &str =
    include_str!("../../../docs/test_vectors/ARCHIVAL_P_DERIVE_V1/vectors.json");

/// SHA-256 over the concatenated on-disk corpus files (`manifest.json` then
/// `vectors.json`). Rotated only by a **deliberate corpus change** routed through
/// the KAT regenerator — either a derivation-version bump (`…-v2`) or an
/// in-version `ARCHIVAL_P_DERIVE_V1` amendment that adds a frozen label (e.g.
/// SPIKE-F-4's GF-9 `hs_id` label, `ARCHIVAL_FIREWALL_GATE6.md` §10.13). Never
/// incidentally: an unexplained change here is corpus drift, which is the
/// tripwire.
pub const ARCHIVAL_P_DERIVE_MANIFEST_HASH: [u8; 32] = [
    0x95, 0xb3, 0x80, 0xb4, 0x2a, 0xbb, 0x30, 0x8f, 0xfa, 0x70, 0x50, 0x69, 0x93, 0x9a, 0xb5, 0x04,
    0xd7, 0xa6, 0xff, 0x67, 0xd9, 0x36, 0x9a, 0x7f, 0xba, 0x76, 0xc7, 0x75, 0x67, 0xc0, 0x53, 0xcb,
];

/// Recompute the corpus digest from the embedded file bytes.
#[must_use]
pub fn compute_archival_p_derive_manifest_hash() -> [u8; 32] {
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
pub fn archival_p_derive_manifest_self_check() -> Result<(), CryptoError> {
    let got = compute_archival_p_derive_manifest_hash();
    if got == ARCHIVAL_P_DERIVE_MANIFEST_HASH {
        Ok(())
    } else {
        // Surface both digests in hex. This guard's primary failure mode is
        // platform-drift on the aarch64 qemu lane, where the committed corpus
        // bytes must read bit-identically; printing got/pinned makes that
        // failure self-diagnosing in CI without rebuilding vectors by hand.
        Err(CryptoError::InvalidInput(format!(
            "ARCHIVAL_P_DERIVE_V1 corpus hash mismatch (manifest/vectors drift): \
             got {}, pinned {}",
            hex32(&got),
            hex32(&ARCHIVAL_P_DERIVE_MANIFEST_HASH),
        )))
    }
}

/// Lowercase-hex a 32-byte digest for diagnostics. Cold path (mismatch only),
/// so the per-byte allocation is irrelevant; avoids a `hex` runtime dependency
/// for what is otherwise a dev-only crate need.
fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_hash_matches_embedded_corpus() {
        archival_p_derive_manifest_self_check().expect("corpus must match pin");
    }
}
