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
//! aborts the supervisor owning the caller. [`hedged_fresh32`] encodes
//! that policy: fresh bytes, or all-zeros on failure, never a panic.
//! It is **only** sound inside such a construction — a caller that uses
//! the output as a nonce directly reintroduces the bare-RNG defect this
//! module retires.
//!
//! **Key material — fail-loud.** Master seeds, transaction keys, and
//! session seeds have no deterministic fallback that is safe to emit: a
//! predictable key is a compromised key. Those call sites draw from
//! `OsRng` directly (panicking or erroring on entropy failure) and are
//! deliberately *not* routed through this module — a fail-safe helper
//! there would convert an outage into silent key reuse. See
//! `stake_engine`'s `try_fill_bytes` preflight for the fail-loud-without-
//! panic variant where a supervisor needs to survive.

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

#[cfg(test)]
mod tests {
    use super::*;

    /// The healthy path returns distinct draws — the property that would
    /// silently vanish if a refactor wired the fallback arm unconditionally.
    #[test]
    fn healthy_draws_are_distinct() {
        let a = hedged_fresh32();
        let b = hedged_fresh32();
        assert_ne!(a, b, "consecutive draws must differ under a working RNG");
        assert_ne!(a, [0u8; 32], "a working RNG must not return the fallback");
    }
}
