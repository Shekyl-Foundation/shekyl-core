// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Per-output key image — public on-chain double-spend identifier.
//!
//! `KeyImage` is the 32-byte canonical encoding of `I = x · H_p(O)`,
//! where `x` is the per-output spend secret derivative and `H_p(O)`
//! is the deterministic hash-to-point of the output's one-time
//! public key. Under a well-formed spend, the key image is the
//! consensus-visible primitive that prevents double-spending: a
//! second transaction reusing the same output produces the same
//! `I`, and the consensus layer rejects it.
//!
//! # Type-placement disposition
//!
//! Per [`.cursor/rules/18-type-placement.mdc`], `KeyImage` is
//! **transform-shaped** — defined by the function
//! `I = x · H_p(O)` whose computation lives in this crate's
//! [`output`] module. Per the rule, the type lives with its
//! defining function rather than with any state-shaped owner that
//! happens to store key images.
//!
//! # Privacy-correlation discipline (mirrors [`crate::handle::OutputHandle`])
//!
//! Pre-spend, a wallet's set of unspent key images is privacy-
//! relevant: an observer who learns "this set of `KeyImage`s
//! belongs to wallet X" can correlate later on-chain spends to
//! wallet X by direct byte comparison. Post-spend, the key image
//! is public on-chain and not secret. The defensive discipline:
//!
//! - **No `Display`** until a use case emerges. Default `Display`
//!   on a wallet-bound identifier invites correlation through log
//!   output and stringly-typed boundaries.
//! - **Manual truncated `Debug`** prints the first two bytes only.
//!   `format!("{key_image:?}")` in error messages, panic
//!   backtraces, or trace logs reveals 16 bits of differentiation
//!   (sufficient to disambiguate two specific values during
//!   debugging) without exposing the full 256-bit identifier.
//! - **`Zeroize` (without `ZeroizeOnDrop`).** A `KeyImage` is
//!   publicly derivable from on-chain data and the spend secret —
//!   it is **not itself a wipe-on-drop concern**. But containers
//!   that hold a `KeyImage` alongside genuinely-secret material
//!   (`shekyl_engine_state::TransferDetails`,
//!   `shekyl_scanner::RecoveredWalletOutput`) wipe every field on
//!   `Drop` for uniform-write-pattern hygiene; providing
//!   `Zeroize` (without `ZeroizeOnDrop`, which would conflict with
//!   `Copy`) lets those containers `.zeroize()` the inner bytes
//!   without a special-case raw-bytes accessor at the wipe site.
//!   The `Copy + Zeroize` pairing matches the pattern used by
//!   [`crate::keys::SpendPublicKey`] / [`crate::keys::ViewPublicKey`].
//!
//! # Wire format
//!
//! `Serialize` / `Deserialize` are provided with
//! `#[serde(transparent)]` so the wire format is byte-identical to
//! `[u8; 32]`. This preserves `TransferDetails`' on-disk and
//! postcard-schema layouts when its `key_image` field migrates from
//! `Option<[u8; 32]>` to `Option<KeyImage>`.
//!
//! [`.cursor/rules/18-type-placement.mdc`]: ../../../../../.cursor/rules/18-type-placement.mdc

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Per-output key image `I = x · H_p(O)`.
///
/// 32-byte canonical compressed Ed25519 point encoding. Constructed
/// at the engine boundary via [`Self::from_canonical_bytes`] from
/// the raw bytes returned by this crate's
/// [`scan_output_recover`](crate::output::scan_output_recover) /
/// `compute_key_image` derivations; consumed at the trait surface
/// of `KeyEngine::try_claim_output` via [`OutputClaim`] in
/// `shekyl-engine-core`.
///
/// Bytes are accessible via [`Self::as_bytes`] for cryptographic
/// input plumbing and on-chain serialization. The newtype's
/// purpose is type-system discipline: at every site that consumes
/// or produces a key image, the type surfaces "this is a per-
/// output double-spend identifier" rather than "this is an
/// arbitrary 32-byte array."
///
/// [`OutputClaim`]: shekyl_engine_core::engine::traits::key::OutputClaim
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Zeroize, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyImage([u8; 32]);

impl KeyImage {
    /// Wrap canonical 32-byte key-image encoding.
    ///
    /// **Boundary constructor.** Caller's responsibility to ensure
    /// the bytes are the canonical compressed Ed25519 encoding of
    /// `I = x · H_p(O)` produced by this crate's key-image
    /// derivation. The newtype does not re-validate the encoding —
    /// invalid bytes here produce a `KeyImage` that fails downstream
    /// verification, which is the correct failure surface (consensus
    /// rejects malformed key images at block validation).
    ///
    /// Public constructor (rather than `pub(crate)`) because the
    /// engine boundary lives outside this crate: the
    /// `KeyEngine::try_claim_output` implementor in
    /// `shekyl-engine-core` constructs `KeyImage` from the raw
    /// bytes returned by [`scan_output_recover`](crate::output::scan_output_recover)
    /// at the trait-surface boundary.
    pub fn from_canonical_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the canonical 32-byte encoding for cryptographic
    /// input plumbing and on-chain serialization.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for KeyImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyImage({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_from_canonical_bytes() {
        let bytes = [0xab; 32];
        let ki = KeyImage::from_canonical_bytes(bytes);
        assert_eq!(ki.as_bytes(), &bytes);
    }

    #[test]
    fn debug_is_truncated() {
        let bytes = [0u8; 32];
        let ki = KeyImage::from_canonical_bytes(bytes);
        let s = format!("{ki:?}");
        // First two bytes shown, rest abbreviated; the remaining 30
        // bytes must not appear in the rendered Debug output.
        assert_eq!(s, "KeyImage(0000..)");
    }

    #[test]
    fn equal_bytes_compare_equal() {
        let a = KeyImage::from_canonical_bytes([1u8; 32]);
        let b = KeyImage::from_canonical_bytes([1u8; 32]);
        let c = KeyImage::from_canonical_bytes([2u8; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
