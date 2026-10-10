// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Single owner of the workspace's OS-entropy failure policy.
//!
//! Every randomness draw in the signing stack falls into one of two
//! classes, and the correct response to a failing OS RNG differs between
//! them. This module exists so that the choice is made once, here, rather
//! than re-derived (and inevitably diverged) at each call site — the
//! reserve-proof DLEQ carried a bare-RNG nonce for months while the
//! sibling Schnorr signature eleven lines away was hedged, precisely
//! because each site owned its own draw.
//!
//! **Hedged constructions — fail-safe.** A hedged nonce
//! (`k = H(domain ‖ secret ‖ statement ‖ fresh)`) already commits the
//! secret and the full signed statement into the hash, so fresh entropy
//! only adds unpredictability against an adversary who *does* hold the
//! secret's hash inputs — it is never the sole defense. On RNG failure
//! the construction degrades to its deterministic RFC-6979-style form:
//! never a repeated nonce across distinct statements, never a panic that
//! aborts the supervisor owning the caller. [`hedged_fresh32`] is that
//! policy for a caller that wants 32 bytes: fresh bytes, or all-zeros on
//! failure, never a panic. `HedgedOsRng` is the same policy as an
//! `RngCore`, for a signer that hedges internally and draws with
//! infallible `fill_bytes`. Both are sound only inside such a
//! construction — a caller that uses the output as a nonce or a key
//! directly reintroduces the bare-RNG defect this module retires.
//!
//! **Key material — fail-loud.** Master seeds, transaction keys, and
//! session seeds have no deterministic fallback that is safe to emit: a
//! predictable key is a compromised key. `key_material32` is that draw
//! inside this crate: 32 fresh bytes, or an error, never zeros and never
//! a panic. It is crate-private, so the public surface of this module
//! stays the one function whose failure mode is the opposite of a key
//! draw. Callers outside this crate still draw `OsRng` and handle the
//! error at the site; `stake_engine`'s `try_fill_bytes` preflight is
//! that shape for a supervisor that must survive the outage. Do not feed
//! key material through [`hedged_fresh32`].

use rand::rngs::OsRng;
use rand::RngCore as _;

/// 32 fresh bytes from the OS CSPRNG, or all-zeros if the OS RNG fails.
///
/// For hedged nonce constructions **only** — see the module docs for why
/// zero-on-failure is safe there and nowhere else.
#[must_use]
pub fn hedged_fresh32() -> [u8; 32] {
    let mut fresh = [0u8; 32];
    if OsRng.try_fill_bytes(&mut fresh).is_err() {
        fresh = [0u8; 32];
    }
    fresh
}

/// The OS CSPRNG as a [`rand::RngCore`], with [`hedged_fresh32`]'s policy:
/// fresh bytes, or zeros if the OS RNG fails, never a panic.
///
/// For a signer that **hedges internally** and takes its randomness as an
/// RNG it calls infallibly. FN-DSA's is the case this exists for: its
/// `sign` draws a seed with `fill_bytes` and immediately replaces it with
/// `SHAKE256(H(signing key) ‖ μ ‖ seed)`, so the seed is one input among
/// three and a zero seed degrades to a deterministic signature over the
/// same key and message rather than to a repeated nonce. Handing that
/// signer the bare `OsRng` would instead panic, inside whatever task was
/// signing, the moment the OS RNG failed.
///
/// **Not for key generation**, and not for any consumer that uses the
/// bytes as a secret directly — see the module docs. A deterministic
/// FN-DSA signature is only as safe as its floating-point arithmetic is
/// reproducible: two different signatures over one hashed point leak the
/// key, and a zero seed makes the hashed point a function of the key and
/// message alone. That is why the signing vectors are pinned on both
/// supported architectures (`tests/kat_fn_dsa_hybrid_v1.rs`).
///
/// Crate-private for that reason: it is a `CryptoRng` that can return
/// zeros, and the type system would accept it wherever a key generator
/// takes one. No caller outside this crate can name it.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct HedgedOsRng;

impl rand::RngCore for HedgedOsRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if OsRng.try_fill_bytes(dest).is_err() {
            dest.fill(0);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// A hedged signer's randomness source: the fallback is sound only inside
/// the construction, which is the caller's to establish.
impl rand::CryptoRng for HedgedOsRng {}

/// 32 bytes of key material from the OS CSPRNG, or an error.
///
/// The fail-loud half of this module's policy. A caller that must survive
/// an entropy outage gets an `Err` to propagate, and never a predictable
/// key. Crate-private: the public entropy function is [`hedged_fresh32`],
/// and its zero-on-failure policy is unsafe for a key.
pub(crate) fn key_material32() -> Result<zeroize::Zeroizing<[u8; 32]>, rand::Error> {
    let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
    OsRng.try_fill_bytes(bytes.as_mut())?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The healthy path returns distinct non-zero draws — the property that
    /// would silently vanish if a refactor wired the fallback arm
    /// unconditionally. Collision of two honest 32-byte CSPRNG draws is
    /// ~2^-256; not worth an inject-`RngCore` seam that would exist only to
    /// de-probabilize this assertion.
    #[test]
    fn healthy_draws_are_distinct() {
        let a = hedged_fresh32();
        let b = hedged_fresh32();
        assert_ne!(a, b, "consecutive draws must differ under a working RNG");
        assert_ne!(a, [0u8; 32], "a working RNG must not return the fallback");
    }

    /// The adapter draws real entropy when the OS provides it: the same
    /// property as above, through the `RngCore` face a signer calls.
    #[test]
    fn the_adapter_draws_distinct_bytes() {
        use rand::RngCore as _;
        let (mut a, mut b) = ([0u8; 40], [0u8; 40]);
        HedgedOsRng.fill_bytes(&mut a);
        HedgedOsRng.fill_bytes(&mut b);
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 40]);
    }

    #[test]
    fn key_material_draws_are_distinct() {
        let a = key_material32().expect("a working OS RNG");
        let b = key_material32().expect("a working OS RNG");
        assert_ne!(*a, *b);
    }
}
