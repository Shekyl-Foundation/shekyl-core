// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! D2 — the persona's v3 onion key: **derived, `p_slot`-bound, and never stored.**
//!
//! # This module is a thin composition over production code
//!
//! The persona's onion keypair is `shekyl-crypto-pq`'s
//! [`derive_p_onion_keypair`] (the GF-9 HS-identity label, frozen under
//! `ARCHIVAL_P_DERIVE_V2`; the RFC 8032 expansion and the public key are
//! computed there). The rend-spec-v3 §6 `.onion` address and tor's
//! `ED25519-V3` key blob are
//! [`shekyl_tor_control_client::onion_identity::OnionIdentity`]'s.
//!
//! What remains here is the spike-only composition: wire the production
//! derivation to the production encoding under a fixed derivation context, so
//! the retained hop-latency apparatus (rule 15) still exercises the full
//! `(master_seed, p_slot) → .onion` pipeline end-to-end against a real tor.
//! The live cross-check that ties this encoding to tor's own answer is
//! [`crate::harness::Apparatus::bring_up_with_pow`]'s inline
//! `published != service_id` fail-stop, driven by the `tests/live_apparatus.rs`
//! integration test on the `SHEKYL_TEST_TOR_BINARY` lane. The custody
//! discipline is unchanged: nothing is written to disk; the key is
//! reproduced on demand and handed to tor via `ADD_ONION`.

use shekyl_crypto_pq::account::Network;
use shekyl_crypto_pq::archival_p::derive_p_onion_keypair;
use shekyl_tor_control_client::onion_identity::OnionIdentity;
use shekyl_types::PSlot;

/// Derive persona `p_slot`'s onion identity from a wallet master seed under an
/// explicit derivation context — the spike's `(master_seed, net, p_slot)
/// → OnionIdentity` composition.
///
/// The keypair is the **production** GF-9 onion keypair
/// ([`derive_p_onion_keypair`], frozen under `ARCHIVAL_P_DERIVE_V2`; its seed
/// never leaves `shekyl-crypto-pq`); the identity is the **production**
/// [`OnionIdentity::from_keypair`]. `net` selects the derivation context
/// exactly as the production path does.
///
/// In production the wallet performs this composition and hands the resulting
/// `OnionIdentity` (never a seed) across the serving boundary; the spike keeps
/// it here so the retained apparatus can drive the whole pipeline.
#[must_use]
pub fn derive_onion_identity(
    master_seed_64: &[u8; 64],
    net: Network,
    p_slot: PSlot,
) -> OnionIdentity {
    OnionIdentity::from_keypair(derive_p_onion_keypair(master_seed_64, net, p_slot.to_raw()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 64] = [0x5au8; 64];

    /// Derive under one fixed context so these unit tests exercise the
    /// composition without repeating the network at every call. The context
    /// choice is irrelevant to what they assert (the expansion's and the
    /// public key's pins, the seed's cross-arch vectors included, live in
    /// `shekyl-crypto-pq`: `onion.rs` and `kat_archival_p_derive_v2`).
    fn identity(seed: &[u8; 64], slot: u32) -> OnionIdentity {
        derive_onion_identity(seed, Network::Mainnet, PSlot::from_raw(slot))
    }

    #[test]
    fn derivation_is_deterministic_and_slot_bound() {
        // Stable across calls (the "persist without storing" property: a
        // restart reproduces the same .onion) and distinct per slot (the
        // persona binding).
        let a = identity(&SEED, 0);
        let a2 = identity(&SEED, 0);
        let b = identity(&SEED, 1);
        assert_eq!(a.service_id(), a2.service_id());
        assert_ne!(a.service_id(), b.service_id());
    }

    #[test]
    fn derivation_is_seed_bound() {
        // A different wallet must not land on the same persona address.
        let other = [0x5bu8; 64];
        assert_ne!(
            identity(&SEED, 3).service_id(),
            identity(&other, 3).service_id()
        );
    }

    #[test]
    fn slots_do_not_collide_across_a_sweep() {
        // Catches a composition that ignored `p_slot` or folded it in a way
        // that collapses (e.g. truncating to u8). Not an injectivity proof,
        // but it fails loudly for the shapes that actually go wrong.
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for slot in 0..512u32 {
            let id = identity(&SEED, slot);
            assert!(
                seen.insert(id.service_id().as_str().to_owned()),
                "slot {slot} collided"
            );
        }
    }
}
