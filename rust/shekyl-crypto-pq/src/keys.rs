// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Typed wrappers around the wallet's secret-bearing key material.
//!
//! Per `.cursor/rules/18-type-placement.mdc`, secret-bearing 32-byte
//! values get type-system protection against accidental misuse. Each
//! wrapper:
//!
//! - Encapsulates the raw bytes (private field; no `Copy`).
//! - Implements `Zeroize + ZeroizeOnDrop` so wipe-on-drop is structural,
//!   not per-call-site discipline (see `.cursor/rules/35-secure-memory.mdc`).
//! - Exposes an `as_canonical_bytes()` accessor (`-> &[u8; N]`) —
//!   the single auditable boundary at which the typed value is converted
//!   into raw bytes for cryptographic input. Cryptographic functions in
//!   this crate take `&[u8; N]` primitives, not the typed values, so the
//!   crate stays consumable by callers that have raw bytes (FFI, wallet
//!   envelope deserialization) without forcing them through the typed
//!   wrapper.
//!
//! Houses the `AllKeysBlob` secret- and public-key wrappers:
//!
//! - [`ViewSecret`] — view-secret scalar (gates view-only access).
//! - [`SpendSecret`] — spend-secret scalar (gates spend authority).
//! - [`MlKem768DecapKey`] — ML-KEM-768 decap (secret) key.
//! - [`SpendPublicKey`] — Ed25519 spend public key (account identity).
//! - [`ViewPublicKey`] — Ed25519 view public key (account identity).
//!
//! Secret wrappers (`ViewSecret`, `SpendSecret`, `MlKem768DecapKey`)
//! carry `Zeroize + ZeroizeOnDrop` and forbid `Copy`. Public-key
//! wrappers (`SpendPublicKey`, `ViewPublicKey`) carry `Copy + Eq + Hash`
//! for use as identity-bearing values in registries (e.g. the subaddress
//! registry's `HashMap<SpendPublicKey, SubaddressIndex>` in
//! `shekyl-engine-core`'s `LocalKeys`); they implement `Zeroize` (so
//! the surrounding `AllKeysBlob`'s derived `ZeroizeOnDrop` calls
//! `.zeroize()` on them as part of the uniform field-wipe pattern raw
//! `[u8; 32]` fields had) but not `ZeroizeOnDrop` (which would conflict
//! with `Copy`).
//!
//! All five wrappers are `#[repr(transparent)]` so the bit-for-bit
//! FFI layout invariant between [`crate::account::AllKeysBlob`] and
//! `shekyl_ffi::ShekylAllKeysBlob` is preserved (asserted by the
//! latter's `size_of::<...>()` test).

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::kem::ML_KEM_768_DK_LEN;

/// The wallet's view-secret scalar, 32 canonical little-endian bytes.
///
/// This is the secret that gates view-only access to the wallet:
/// scanning the chain for owned outputs, decapsulating their hybrid
/// shared secrets, and deriving per-output spend material. Holding
/// `ViewSecret` is sufficient to detect outputs and read amounts;
/// spending also requires `SpendSecret` (forthcoming typed wrapper).
///
/// # Hygiene properties
///
/// - **No `Copy`.** Compiler-emitted copies would defeat
///   wipe-on-drop discipline; `Clone` is opt-in by callers.
/// - **`Zeroize + ZeroizeOnDrop`.** The inner bytes are wiped when
///   the wrapper drops. Holding a `ViewSecret` and dropping it
///   leaves no readable secret residue in the dropped allocation.
/// - **No `Debug`.** Default `Debug` would format the bytes; a
///   manual impl would still encode the secret. Callers needing
///   to inspect bytes for debugging must explicitly route through
///   `as_canonical_bytes()` and accept responsibility for what they
///   do with the result.
///
/// # Canonical-bytes contract
///
/// `as_canonical_bytes()` returns the 32-byte little-endian
/// scalar representation. Cryptographic functions
/// (e.g., [`crate::handle::derive_output_handle`]) take
/// `&[u8; 32]` and rely on this representation being stable across
/// every call site. Changing the encoding here invalidates every
/// previously-derived value keyed on `view_secret`. See
/// `.cursor/rules/18-type-placement.mdc` for the discipline.
///
/// # FFI layout invariant
///
/// `#[repr(transparent)]` guarantees `ViewSecret` has identical
/// memory layout to its inner `[u8; 32]`. This preserves the
/// bit-for-bit compatibility invariant between
/// [`crate::account::AllKeysBlob`] and `shekyl_ffi::ShekylAllKeysBlob`
/// asserted at the latter's `size_of::<...>()` test.
#[repr(transparent)]
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ViewSecret([u8; 32]);

impl ViewSecret {
    /// Construct from raw bytes.
    ///
    /// `pub(crate)` because the only legitimate construction sites are
    /// inside this crate (key derivation in `account.rs`, wallet-file
    /// open paths in `wallet_envelope.rs`). External callers receive
    /// `AllKeysBlob` references and read via `as_canonical_bytes`; they
    /// do not synthesize new `ViewSecret` values.
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the canonical 32-byte representation for cryptographic
    /// input. See type-level "Canonical-bytes contract" doc-comment.
    pub fn as_canonical_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The wallet's spend-secret scalar, 32 canonical little-endian bytes.
///
/// This is the secret that gates spend authority: producing the
/// per-output spend material `x · H_p(O)` (and therefore the key
/// image `I`), and signing transaction inputs at the FCMP++
/// witness-assembly layer. Holding `ViewSecret` alone is insufficient
/// to spend; `SpendSecret` is required.
///
/// # Hygiene properties
///
/// Mirrors [`ViewSecret`]:
///
/// - **No `Copy`.** Compiler-emitted copies would defeat
///   wipe-on-drop discipline; `Clone` is opt-in by callers.
/// - **`Zeroize + ZeroizeOnDrop`.** Inner bytes wipe at drop time.
/// - **No `Debug`.** Manual or derived `Debug` on a 32-byte secret
///   would format the bytes; callers needing to inspect bytes for
///   debugging must explicitly route through `as_canonical_bytes()`
///   and accept responsibility for what they do with the result.
///
/// # Canonical-bytes contract
///
/// `as_canonical_bytes()` returns the 32-byte little-endian scalar
/// representation. Cryptographic functions (e.g.
/// [`crate::output::compute_output_key_image`]) take `&[u8; 32]` and
/// rely on this representation being stable across every call site.
/// See `.cursor/rules/18-type-placement.mdc`.
///
/// # FFI layout invariant
///
/// `#[repr(transparent)]` guarantees `SpendSecret` has identical
/// memory layout to its inner `[u8; 32]`. This preserves the
/// bit-for-bit compatibility invariant between
/// [`crate::account::AllKeysBlob`] and `shekyl_ffi::ShekylAllKeysBlob`
/// asserted at the latter's `size_of::<...>()` test.
#[repr(transparent)]
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SpendSecret([u8; 32]);

impl SpendSecret {
    /// Construct from raw bytes.
    ///
    /// `pub(crate)` because the only legitimate construction sites
    /// are inside this crate (key derivation in `account.rs`,
    /// wallet-file open paths in `wallet_envelope.rs`).
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the canonical 32-byte representation for cryptographic
    /// input. See type-level "Canonical-bytes contract" doc-comment.
    pub fn as_canonical_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The wallet's ML-KEM-768 decapsulation (secret) key, 2400 bytes
/// in the FIPS 203 canonical encoding.
///
/// This is the post-quantum half of the wallet's hybrid view-side
/// secret material: `(view_sk, ml_kem_dk)` together gate ECDH+KEM
/// decapsulation of every output's hybrid shared secret. Holding
/// `ViewSecret` alone is insufficient for view-only access on the
/// PQC-augmented chain; `MlKem768DecapKey` is required.
///
/// # Hygiene properties
///
/// Mirrors [`ViewSecret`] / [`SpendSecret`]:
///
/// - **No `Copy`.** Compiler-emitted copies of a 2400-byte secret
///   would defeat wipe-on-drop discipline; `Clone` is opt-in by
///   callers.
/// - **`Zeroize + ZeroizeOnDrop`.** Inner bytes wipe at drop time.
/// - **No `Debug`.** Manual or derived `Debug` on a 2400-byte
///   secret would format the bytes; callers needing to inspect
///   bytes for debugging must explicitly route through
///   `as_canonical_bytes()` and accept responsibility for what
///   they do with the result.
///
/// # Canonical-bytes contract
///
/// `as_canonical_bytes()` returns the 2400-byte FIPS 203
/// decapsulation-key encoding. Cryptographic functions
/// (e.g. [`crate::output::scan_output_recover`]) take
/// `&[u8]` and rely on this representation being stable across
/// every call site. See `.cursor/rules/18-type-placement.mdc`
/// for the discipline.
///
/// # FFI layout invariant
///
/// `#[repr(transparent)]` guarantees `MlKem768DecapKey` has
/// identical memory layout to its inner `[u8; ML_KEM_768_DK_LEN]`.
/// This preserves the bit-for-bit compatibility invariant between
/// [`crate::account::AllKeysBlob`] and `shekyl_ffi::ShekylAllKeysBlob`
/// asserted at the latter's `size_of::<...>()` test.
#[repr(transparent)]
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKem768DecapKey([u8; ML_KEM_768_DK_LEN]);

impl MlKem768DecapKey {
    /// Construct from raw bytes.
    ///
    /// `pub(crate)` because the only legitimate construction sites
    /// are inside this crate (key derivation in `account.rs`,
    /// wallet-file open paths in `wallet_envelope.rs`).
    pub(crate) fn from_bytes(bytes: [u8; ML_KEM_768_DK_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the canonical 2400-byte FIPS 203 representation for
    /// cryptographic input. See type-level "Canonical-bytes
    /// contract" doc-comment.
    pub fn as_canonical_bytes(&self) -> &[u8; ML_KEM_768_DK_LEN] {
        &self.0
    }
}

/// The wallet's Ed25519 spend public key, 32-byte canonical
/// compressed encoding.
///
/// Half of the wallet's public account identity (paired with
/// [`ViewPublicKey`] in the classical address). Public material —
/// no wipe-on-drop discipline applies, but a [`Zeroize`] impl is
/// provided so the surrounding [`crate::account::AllKeysBlob`]
/// derives `ZeroizeOnDrop`, which calls `.zeroize()` on every field
/// (including this one) at drop time as part of its uniform field-wipe
/// pattern.
///
/// # Hygiene properties
///
/// - **`Copy`.** Public-key values flow through registries
///   (e.g. `LocalKeys`'s `HashMap<SpendPublicKey, SubaddressIndex>`)
///   and through cryptographic plumbing; `Copy` matches their
///   value-type role.
/// - **`Eq + Hash + Ord`.** Required by the subaddress registry
///   and any other identity-bearing key map.
/// - **Manual truncated `Debug`** prints the first two bytes only.
///   Default `Debug` on an account-bound identifier invites
///   correlation through log output and panic backtraces; the
///   truncated form gives 16 bits of differentiation (sufficient
///   to disambiguate during debugging) without exposing the full
///   identifier even in unsanitised log streams.
/// - **`Zeroize` (without `ZeroizeOnDrop`).** `ZeroizeOnDrop`
///   would imply `Drop`, which is incompatible with `Copy`;
///   the surrounding `AllKeysBlob` derives `ZeroizeOnDrop`,
///   which calls `.zeroize()` on this field at drop time as
///   part of its uniform field-wipe pattern.
///
/// # FFI layout invariant
///
/// `#[repr(transparent)]` guarantees identical memory layout to
/// the inner `[u8; 32]`, preserving the bit-for-bit invariant
/// against `shekyl_ffi::ShekylAllKeysBlob`.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Zeroize)]
pub struct SpendPublicKey([u8; 32]);

impl SpendPublicKey {
    /// Wrap canonical 32-byte spend-public-key encoding.
    ///
    /// **Boundary constructor.** Caller's responsibility to ensure
    /// the bytes are the canonical compressed Ed25519 encoding of a
    /// spend public key. The newtype does not re-validate the
    /// encoding — invalid bytes here produce a `SpendPublicKey` that
    /// fails downstream decompression, which is the correct failure
    /// surface.
    ///
    /// Public constructor (rather than `pub(crate)`) because the
    /// engine boundary lives outside this crate: subaddress
    /// derivation in `shekyl-engine-core::engine::local_keys` wraps
    /// the bytes returned by [`crate::subaddress::subaddress_keys`]
    /// at the trait-surface boundary, mirroring the
    /// [`crate::key_image::KeyImage::from_canonical_bytes`] pattern.
    pub fn from_canonical_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the canonical 32-byte representation for cryptographic
    /// input plumbing and on-chain serialization.
    pub fn as_canonical_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SpendPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SpendPublicKey({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}

/// The wallet's Ed25519 view public key, 32-byte canonical
/// compressed encoding.
///
/// Half of the wallet's public account identity (paired with
/// [`SpendPublicKey`] in the classical address). Birationally maps
/// to the X25519 KEM public-key half via
/// [`crate::montgomery::ed25519_pk_to_x25519_pk`]. Public material;
/// see [`SpendPublicKey`]'s "Hygiene properties" — `ViewPublicKey`
/// follows the identical discipline (Copy + Eq + Hash + Ord +
/// truncated Debug + Zeroize without ZeroizeOnDrop).
///
/// # Distinct type from `SpendPublicKey`
///
/// Both wrappers are 32-byte compressed Ed25519 points; the type
/// system distinguishes them so misframings ("passed view_pk where
/// spend_pk was expected") become compile errors rather than
/// silent address-rederivation bugs.
///
/// # FFI layout invariant
///
/// `#[repr(transparent)]` preserves the bit-for-bit invariant
/// against `shekyl_ffi::ShekylAllKeysBlob`.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Zeroize)]
pub struct ViewPublicKey([u8; 32]);

impl ViewPublicKey {
    /// Wrap canonical 32-byte view-public-key encoding. Public
    /// constructor for the same reasons as
    /// [`SpendPublicKey::from_canonical_bytes`].
    pub fn from_canonical_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the canonical 32-byte representation.
    pub fn as_canonical_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ViewPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ViewPublicKey({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_canonical_bytes() {
        let bytes = [0x42u8; 32];
        let secret = ViewSecret::from_bytes(bytes);
        assert_eq!(secret.as_canonical_bytes(), &bytes);
    }

    #[test]
    fn clone_produces_equal_canonical_bytes() {
        let secret = ViewSecret::from_bytes([0x37u8; 32]);
        let cloned = secret.clone();
        assert_eq!(secret.as_canonical_bytes(), cloned.as_canonical_bytes(),);
    }

    #[test]
    fn spend_secret_round_trip_canonical_bytes() {
        let bytes = [0x99u8; 32];
        let secret = SpendSecret::from_bytes(bytes);
        assert_eq!(secret.as_canonical_bytes(), &bytes);
    }

    #[test]
    fn ml_kem_768_decap_key_round_trip_canonical_bytes() {
        let bytes = [0x55u8; ML_KEM_768_DK_LEN];
        let dk = MlKem768DecapKey::from_bytes(bytes);
        assert_eq!(dk.as_canonical_bytes(), &bytes);
    }

    #[test]
    fn ml_kem_768_decap_key_clone_produces_equal_canonical_bytes() {
        let dk = MlKem768DecapKey::from_bytes([0xa3u8; ML_KEM_768_DK_LEN]);
        let cloned = dk.clone();
        assert_eq!(dk.as_canonical_bytes(), cloned.as_canonical_bytes());
    }

    #[test]
    fn spend_public_key_round_trip_and_eq_hash() {
        use std::collections::HashMap;
        let bytes = [0x01u8; 32];
        let pk_a = SpendPublicKey::from_canonical_bytes(bytes);
        let pk_b = SpendPublicKey::from_canonical_bytes(bytes);
        let pk_c = SpendPublicKey::from_canonical_bytes([0x02u8; 32]);
        assert_eq!(pk_a, pk_b);
        assert_ne!(pk_a, pk_c);
        let mut map = HashMap::new();
        map.insert(pk_a, "primary");
        assert_eq!(map.get(&pk_b), Some(&"primary"));
    }

    #[test]
    fn spend_public_key_debug_is_truncated() {
        let pk = SpendPublicKey::from_canonical_bytes([0u8; 32]);
        assert_eq!(format!("{pk:?}"), "SpendPublicKey(0000..)");
    }

    #[test]
    fn view_public_key_round_trip_and_truncated_debug() {
        let bytes = [0xfeu8; 32];
        let pk = ViewPublicKey::from_canonical_bytes(bytes);
        assert_eq!(pk.as_canonical_bytes(), &bytes);
        assert_eq!(format!("{pk:?}"), "ViewPublicKey(fefe..)");
    }

    #[test]
    fn distinct_types_for_spend_and_view_public_keys() {
        // Compile-time type discipline: `SpendPublicKey` and
        // `ViewPublicKey` must NOT be coercible. This test simply
        // documents the invariant; if the types were merged, a
        // compile error here would surface the regression.
        fn _take_spend(_: SpendPublicKey) {}
        fn _take_view(_: ViewPublicKey) {}
        let s = SpendPublicKey::from_canonical_bytes([0u8; 32]);
        let v = ViewPublicKey::from_canonical_bytes([0u8; 32]);
        _take_spend(s);
        _take_view(v);
        // _take_spend(v); // would not compile; intentionally commented.
    }
}
