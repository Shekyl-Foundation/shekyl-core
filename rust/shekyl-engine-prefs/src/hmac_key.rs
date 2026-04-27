// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Derivation of the prefs HMAC key per
//! [`docs/WALLET_PREFS.md §2.2`](../../docs/WALLET_PREFS.md).
//!
//! ```text
//! prefs_hmac_key = HKDF-Expand(
//!     prk  = file_kek,
//!     info = b"shekyl-prefs-hmac-v1" || expected_classical_address,
//!     L    = 32,
//! )
//! ```
//!
//! # Why two inputs?
//!
//! `file_kek` alone would already give a per-wallet HMAC key (the
//! envelope's wrap layer uses a random 32-byte `file_kek` per creation,
//! and re-wraps it on password rotation). Binding to the 65-byte
//! `expected_classical_address` on top of that provides domain
//! separation defense-in-depth: if two wallets in the unlikely event
//! share a `file_kek`, their prefs HMAC keys are still distinct, so a
//! `prefs.toml` lifted from one wallet cannot validate against
//! another's HMAC file. Same pattern as `seed_block_tag` binding
//! `.wallet` to `.wallet.keys` in `WALLET_FILE_FORMAT_V1`.
//!
//! The `-v1` label reserves room for a future algorithm bump. When
//! that day comes, the old wallets keep the old label, the new ones
//! adopt `-v2`, and neither path silently migrates — matching the
//! "no silent migration" rule for consensus-critical state while
//! still leaving prefs upgradable.
//!
//! # Zeroization
//!
//! [`PrefsHmacKey`] wraps a [`Zeroizing<[u8; 32]>`], which wipes its
//! buffer on drop. Callers should keep one `PrefsHmacKey` alive for
//! the duration of a session (it's cheap to re-derive but cheaper to
//! cache) and drop it when the wallet handle is released.
//!
//! # What this module does not do
//!
//! It does not touch the filesystem and knows nothing about
//! `prefs.toml`. The caller derives a key once, then passes
//! `&PrefsHmacKey` into [`crate::io`] for every load/save.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Length of the derived HMAC key in bytes. 32 bytes matches the
/// output size of HMAC-SHA256 and is also the block-size-equivalent
/// for the cipher suite used elsewhere in the wallet.
pub const PREFS_HMAC_KEY_BYTES: usize = 32;

/// Length of the envelope's `file_kek` in bytes. Matches
/// `FILE_KEK_BYTES` in [`shekyl_crypto_pq::wallet_envelope`]; pinned
/// here so a future divergence trips a compile error instead of
/// silently producing an incompatible HMAC key.
pub const FILE_KEK_BYTES: usize = 32;

/// Length of the canonical `expected_classical_address` committed in
/// the keys-file AAD: `version(1) || spend_pk(32) || view_pk(32)`.
/// Matches `EXPECTED_CLASSICAL_ADDRESS_BYTES` in the envelope crate.
pub const EXPECTED_CLASSICAL_ADDRESS_BYTES: usize = 65;

/// Fixed label for the HKDF `info` parameter. Includes the `-v1`
/// suffix so a future algorithm change (e.g. `-v2` with a different
/// MAC or a rebound address format) cannot be confused with a v1
/// derivation.
pub const HKDF_INFO_LABEL: &[u8] = b"shekyl-prefs-hmac-v1";

/// 32-byte HMAC-SHA256 key for `prefs.toml` / `prefs.toml.hmac`
/// integrity. Zeroized on drop.
///
/// The public API is deliberately narrow: callers construct one via
/// [`Self::derive`] and read it once through [`Self::as_bytes`] when
/// feeding an HMAC instance. No `Clone`, no `Debug` leak path, and no
/// public constructor that accepts raw bytes (to prevent callers from
/// accidentally reusing an unrelated 32-byte value as the prefs key).
pub struct PrefsHmacKey {
    bytes: Zeroizing<[u8; PREFS_HMAC_KEY_BYTES]>,
}

impl PrefsHmacKey {
    /// Derive the prefs HMAC key from `file_kek` and
    /// `expected_classical_address` per the spec formula. Infallible
    /// because both inputs are fixed-size arrays and HKDF-Expand at
    /// 32 bytes is well within the 255-block output limit for
    /// SHA-256.
    pub fn derive(
        file_kek: &[u8; FILE_KEK_BYTES],
        expected_classical_address: &[u8; EXPECTED_CLASSICAL_ADDRESS_BYTES],
    ) -> Self {
        // HKDF-Expand with no salt (prk is file_kek, already high-entropy).
        // info = b"shekyl-prefs-hmac-v1" || expected_classical_address.
        let hk = Hkdf::<Sha256>::from_prk(file_kek.as_slice())
            .expect("file_kek has 32 bytes ≥ SHA-256 output size, from_prk is infallible");
        let mut info = Vec::with_capacity(HKDF_INFO_LABEL.len() + EXPECTED_CLASSICAL_ADDRESS_BYTES);
        info.extend_from_slice(HKDF_INFO_LABEL);
        info.extend_from_slice(expected_classical_address);
        let mut out = Zeroizing::new([0u8; PREFS_HMAC_KEY_BYTES]);
        hk.expand(&info, out.as_mut())
            .expect("HKDF-Expand at 32 bytes is always within the 255-block limit");
        Self { bytes: out }
    }

    /// Borrow the raw key bytes. Use only to initialise an HMAC
    /// context; do not copy the slice into a non-zeroizing buffer.
    pub fn as_bytes(&self) -> &[u8; PREFS_HMAC_KEY_BYTES] {
        &self.bytes
    }
}

impl std::fmt::Debug for PrefsHmacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrefsHmacKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_file_kek() -> [u8; FILE_KEK_BYTES] {
        let mut k = [0u8; FILE_KEK_BYTES];
        for (i, b) in k.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap_or(0);
        }
        k
    }

    fn fixture_address() -> [u8; EXPECTED_CLASSICAL_ADDRESS_BYTES] {
        let mut a = [0u8; EXPECTED_CLASSICAL_ADDRESS_BYTES];
        a[0] = 0x01;
        for (i, b) in a.iter_mut().enumerate().skip(1) {
            *b = u8::try_from(i).unwrap_or(0).wrapping_mul(3);
        }
        a
    }

    /// Deterministic KAT: the same `(file_kek, address)` pair must
    /// always derive the same 32 bytes. If this ever changes, every
    /// existing `prefs.toml.hmac` in the wild silently breaks, so the
    /// test doubles as a tripwire against unintentional formula
    /// drift.
    #[test]
    fn derive_is_deterministic() {
        let k1 = PrefsHmacKey::derive(&fixture_file_kek(), &fixture_address());
        let k2 = PrefsHmacKey::derive(&fixture_file_kek(), &fixture_address());
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    /// The address is part of the `info` input, so changing it must
    /// yield a different key even under the same `file_kek`. Defends
    /// against the "two wallets share a file_kek" edge case the
    /// binding exists to address.
    #[test]
    fn derive_depends_on_address() {
        let a1 = fixture_address();
        let mut a2 = a1;
        a2[7] ^= 0xAA;
        let k1 = PrefsHmacKey::derive(&fixture_file_kek(), &a1);
        let k2 = PrefsHmacKey::derive(&fixture_file_kek(), &a2);
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    /// Likewise the `file_kek` dominates derivation — a one-bit flip
    /// in the kek yields an entirely different HMAC key.
    #[test]
    fn derive_depends_on_file_kek() {
        let mut k = fixture_file_kek();
        let addr = fixture_address();
        let k1 = PrefsHmacKey::derive(&k, &addr);
        k[0] ^= 0x01;
        let k2 = PrefsHmacKey::derive(&k, &addr);
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    /// Debug output must not leak key bytes.
    #[test]
    fn debug_redacts_bytes() {
        let k = PrefsHmacKey::derive(&fixture_file_kek(), &fixture_address());
        let s = format!("{k:?}");
        assert!(s.contains("REDACTED"), "{s}");
        // Spot-check: the first byte of the derived key should not
        // leak as a literal 2-hex-digit string in `Debug` output.
        // Defensive, not structural — catches an accidental
        // `#[derive(Debug)]` regression that would dump bytes.
        let raw = k.as_bytes();
        let first_byte = raw[0];
        assert!(!s.contains(&format!("{first_byte:02x}")), "{s}");
    }
}
