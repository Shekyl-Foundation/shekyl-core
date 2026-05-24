// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! 32-byte [`Seedhash`] newtype — the typed key used to derive a
//! cache (via [`crate::PreparedCache::derive`]) and (in Phase 2F
//! commit 2) to index `CacheStore` slots.
//!
//! # Why a newtype, not a type alias
//!
//! Per the Phase 2F plan-doc (`docs/design/RANDOMX_V2_PHASE2F_PLAN.md`)
//! §1.1 Round 2 + §3.1 Round 2 disposition: the verifier crate's
//! threat model treats *which 32-byte input is a seedhash* as a
//! load-bearing distinction. Output hashes (the 32-byte result of
//! [`crate::compute_hash`]), generic content hashes (in unrelated
//! caller code), and seedhashes are all `[u8; 32]` at the byte
//! level; without a newtype the type system cannot prevent a
//! caller from passing an output hash where a seedhash is
//! expected (or vice versa). The newtype turns those failures
//! into compile-time errors at the call site, rather than
//! silently-accepted runtime calls that produce wrong hashes the
//! network rejects.
//!
//! The newtype is also the foundation for any future type-system
//! enforcement of seedhash provenance (e.g., a hypothetical
//! `ValidatedSeedhash(Seedhash)` wrapper around block-header-
//! validated seedhashes vs. user-input seedhashes); a type alias
//! forecloses that direction.
//!
//! # Representation
//!
//! Internally a fixed `[u8; 32]` array; the field is private and
//! accessor-mediated rather than field-mediated. Pre-genesis the
//! representation can change (per
//! `15-deletion-and-debt.mdc`'s pre-V3-launch discount) without
//! churning every call site. Post-genesis,
//! [`Seedhash::from_bytes`] / [`Seedhash::as_bytes`] preserve the
//! byte-level interop contract.
//!
//! # Display
//!
//! [`core::fmt::Display`] renders as lowercase hex (matches
//! `hex::encode` and the cryptographic-output convention).
//! Verifier-crate code itself does not log seedhashes; the
//! `Display` impl exists for downstream consumers (FFI shim,
//! daemon-side logging, test diagnostics). See the Phase 2F
//! plan-doc §1.1 Round 2 post-closure pin #1 for the framing-
//! correction audit trail.

use core::fmt;

/// 32-byte seedhash — the typed key for cache derivation (via
/// [`crate::PreparedCache::derive`]) and (in Phase 2F commit 2)
/// `CacheStore` slot indexing.
///
/// Distinct from generic `[u8; 32]` values (output hashes, content
/// hashes, etc.) at the type level. See the module rustdoc for the
/// full rationale.
///
/// # Construction
///
/// The sole constructor is [`Seedhash::from_bytes`]. The internal
/// representation is private; consumers go through
/// [`Seedhash::as_bytes`] for read-only byte access.
///
/// # Derives
///
/// `Copy + Clone + Debug + Eq + Hash + PartialEq` per Phase 2F
/// §1.1 Round 2: `Hash + Eq` are required for
/// `HashMap<Seedhash, _>` keying in the (Phase 2F commit 2)
/// `CacheStore` in-flight derivation map; `Copy` is inherited
/// from `[u8; 32]` and is cheap (32 bytes); `Debug` aids test
/// diagnostics. No `Default` (no canonical zero seedhash); no
/// `Display` derive — the [`core::fmt::Display`] impl is hand-
/// written for the lowercase-hex format.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Seedhash([u8; 32]);

impl Seedhash {
    /// Construct a [`Seedhash`] from raw bytes.
    ///
    /// Takes ownership of the byte array; the caller can construct
    /// a `Seedhash` from a stack literal, a byte array obtained
    /// from a block-header read, or a byte array converted from
    /// the FFI shim's `*const uint8_t [32]`. No validation is
    /// performed — *any* 32-byte value is a syntactically-valid
    /// seedhash for the verifier crate. Validation against
    /// block-header constraints (e.g., "this seedhash matches the
    /// epoch derivable from this block height") is the daemon-
    /// side caller's responsibility.
    pub fn from_bytes(bytes: [u8; 32]) -> Seedhash {
        Seedhash(bytes)
    }

    /// Borrow the underlying 32-byte representation.
    ///
    /// Returns a reference to the internal `[u8; 32]` for byte-
    /// level access (e.g., feeding to a hasher, copying into an
    /// FFI buffer). Per the module rustdoc, the representation is
    /// pre-genesis-mutable; consumers that depend on the byte-
    /// level shape should treat this accessor as the contract
    /// rather than relying on internal field access.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Seedhash {
    /// Render as 64 lowercase hex characters (no `0x` prefix, no
    /// separators).
    ///
    /// Matches `hex::encode([u8; 32])` and the broader
    /// cryptographic-output convention. Does *not* match
    /// `Debug`'s output (which uses Rust's default array
    /// formatting); use `Display` for log lines and
    /// human-readable diagnostics, `Debug` for assertion-failure
    /// messages and `dbg!` output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: `from_bytes(b).as_bytes() == &b` for a known
    /// pattern. Catches a hypothetical future representation
    /// change that breaks the byte-level identity contract.
    #[test]
    fn from_bytes_as_bytes_round_trip() {
        let bytes: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let s = Seedhash::from_bytes(bytes);
        assert_eq!(s.as_bytes(), &bytes);
    }

    /// `Eq` + `PartialEq`: two `Seedhash` values constructed from
    /// the same bytes compare equal; two from different bytes
    /// compare not-equal. Catches a hypothetical breakage of the
    /// `HashMap<Seedhash, _>` key contract used by the (Phase 2F
    /// commit 2) `CacheStore` in-flight derivation map.
    #[test]
    fn eq_compares_bytes_not_identity() {
        let a = Seedhash::from_bytes([0x42; 32]);
        let b = Seedhash::from_bytes([0x42; 32]);
        let c = Seedhash::from_bytes([0x43; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    /// `Hash`: equal seedhashes hash to equal `u64`s. Belt-and-
    /// suspenders for the `HashMap` key contract — `Eq + Hash`
    /// must be consistent.
    #[test]
    fn hash_consistent_with_eq() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a = Seedhash::from_bytes([0x42; 32]);
        let b = Seedhash::from_bytes([0x42; 32]);

        let mut ha = DefaultHasher::new();
        a.hash(&mut ha);

        let mut hb = DefaultHasher::new();
        b.hash(&mut hb);

        assert_eq!(ha.finish(), hb.finish());
    }

    /// `Display` renders as 64 lowercase hex characters, no
    /// prefix, no separators. Pins the format the FFI shim and
    /// downstream tooling consume.
    #[test]
    fn display_lowercase_hex_no_prefix() {
        let s = Seedhash::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ]);
        let rendered = format!("{s}");
        assert_eq!(
            rendered,
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        );
        assert_eq!(rendered.len(), 64);
    }

    /// `Display` of an all-`0xff` seedhash renders as 64 `f`
    /// characters. Catches sign-extension or `as i8` -> `as u8`
    /// drift in a hypothetical future representation change.
    #[test]
    fn display_all_ones_renders_64_f() {
        let s = Seedhash::from_bytes([0xff; 32]);
        assert_eq!(format!("{s}"), "f".repeat(64));
    }

    /// `Copy` semantics: a `Seedhash` value can be passed to two
    /// functions without a clone. Compile-time check; the test
    /// only fails to build if `Copy` is dropped.
    #[test]
    fn copy_allows_two_consumers() {
        fn consume(_s: Seedhash) {}
        let s = Seedhash::from_bytes([0x00; 32]);
        consume(s);
        consume(s);
    }
}
