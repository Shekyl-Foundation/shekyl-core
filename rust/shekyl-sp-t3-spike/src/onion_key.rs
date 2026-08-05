// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! D2 — the persona's v3 onion key: **derived, `p_slot`-bound, and never stored.**
//!
//! # The ruling this implements, and what "persist" turned out to mean
//!
//! The maintainer ruling for this spike was *persist per-persona key (GF-9
//! rotation)* — the `.onion` must be stable across restarts and bound to the
//! persona slot, so rotation semantics belong to the persona rather than to the
//! session. `ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md` §6 pins the same thing from the
//! design side: *"the HS key is `p_slot`-bound + seed-derived (GF-9), so the
//! `.onion` rotates with the persona."*
//!
//! Seed-derivation satisfies "persist" **without a secret at rest**: the key is
//! reproducible on demand from `(master_seed_64, p_slot)`, handed to tor via
//! `ADD_ONION` each session, and zeroized after. Nothing is written to disk. That
//! is strictly better than persisting it — a bonded archival persona's onion key
//! at rest would be a standing compromise of the persona's network identity, and
//! its file would itself be a persona-existence artifact on the wallet host.
//!
//! # The encoding question, answered empirically rather than assumed
//!
//! tor's `ADD_ONION ED25519-V3:` `KeyBlob` is the **expanded** secret key, not a
//! seed — the control-spec defines it as *"Base64 encoding of the concatenation
//! of the 32-byte ed25519 secret scalar in little-endian and the 32-byte ed25519
//! PRF secret."* The charter flagged this as a possible halt (*"v3 expects an
//! expanded ed25519 secret, not a seed … halt rather than inventing a
//! conversion"*).
//!
//! **The halt does not fire, and no conversion is invented.** Seed → expanded is
//! RFC 8032 §5.1.5 itself: `SHA-512(seed)`, clamp the low 32 bytes. That is the
//! same function `ed25519_dalek::SigningKey` applies internally and the same one
//! tor applies to its own generated seeds; it is the *definition* of an ed25519
//! key's expansion, not a bridge between two formats.
//!
//! This was then **verified against the pinned binary rather than trusted**: the
//! spike derives a key, computes the v3 address itself
//! ([`OnionIdentity::service_id`]), hands the expanded blob to a real tor, and
//! asserts tor's returned `ServiceID` is byte-identical. It is
//! (`onion_key_matches_tors_service_id`, and the same check ran against Tor
//! Expert Bundle 15.0.17 during the pre-flight).
//!
//! ## The trap that check exists to catch
//!
//! `curve25519_dalek::Scalar::from_bytes_mod_order(clamp_integer(b))` **reduces
//! mod ℓ**, and a clamped integer is ≥ 2²⁵⁴ > ℓ — so `scalar.to_bytes()` is *not*
//! the clamped bytes tor wants. Deriving the blob's first half from a dalek
//! `Scalar` would produce a key that still yields a valid service id, just a
//! **different one** from the key tor was handed, and the service would be
//! unreachable at the address the persona advertises. So the clamp is applied to
//! raw bytes here (`expand_seed`) and never round-tripped through a `Scalar`.
//!
//! # SPIKE-F-4: the seed derivation now lives where it belongs; this is encoding
//!
//! This module originally carried a *second*, spike-local cSHAKE256 derivation
//! from the master seed, deliberately labelled `-spike-` so its keys could never
//! be silently inherited by production. That was a stopgap: the master-seed →
//! persona-key map is owned by `shekyl_crypto_pq::archival_p`, *"the **single
//! source of truth** for how a Shekyl archival staking persona (`P`) derives its
//! keys"*, HKDF-SHA-512 under versioned `ARCHIVAL_P_*_INFO` labels, frozen and
//! KAT-pinned under `ARCHIVAL_P_DERIVE_V1`.
//!
//! SPIKE-F-4 executed the gate-6 §10.13 carry: the GF-9 HS-identity seed is now
//! [`derive_p_hs_id_seed`] (label `ARCHIVAL_P_HS_ID_INFO`, `L=32`), an
//! `ARCHIVAL_P_DERIVE_V1` amendment with regenerated cross-arch KAT vectors that
//! pin both the seed **and** the derived ed25519 public key. The spike-local
//! duplicate is deleted, and [`derive_onion_identity`] now *consumes* the
//! production seed.
//!
//! What remains here is the **v3-onion encoding**: RFC 8032 seed expansion to
//! tor's `ED25519-V3` blob (`expand_seed`) and the rend-spec-v3 §6 `.onion`
//! address construction (`service_id_from_pubkey`). That is transport surface,
//! not key derivation — in production it belongs in `shekyl-tor` alongside the
//! rest of the control-port machinery, not in `crypto-pq`. It stays in this
//! disposable spike because no non-spike consumer needs it yet (the serving path
//! is 2d-2 SP-T3 proper), and the retained apparatus (rule 15, for the owed Tor
//! hop-latency measurement) exercises it end-to-end against a real tor.

use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha512};
use sha3::Sha3_256;
use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat};
use shekyl_crypto_pq::archival_p::derive_p_hs_id_seed;
use shekyl_tor::control::onion::{OnionKey, ServiceId, ONION_KEY_BYTES};
use shekyl_types::PSlot;
use zeroize::Zeroizing;

/// Version byte of a v3 onion address (rend-spec-v3 §6).
const ONION_ADDRESS_VERSION: u8 = 0x03;

/// Domain-separation prefix for the v3 address checksum (rend-spec-v3 §6).
const ONION_CHECKSUM_PREFIX: &[u8] = b".onion checksum";

/// A persona's onion identity: the secret key to hand tor, and the public
/// service id that key implies.
///
/// The secret half is moved out with [`Self::into_onion_key`] so it reaches
/// `ADD_ONION` and nothing else; the public half is a plain [`ServiceId`] the
/// client leg dials.
pub struct OnionIdentity {
    key: OnionKey,
    service_id: ServiceId,
}

impl OnionIdentity {
    /// The `.onion` service id this key publishes at.
    #[must_use]
    pub fn service_id(&self) -> &ServiceId {
        &self.service_id
    }

    /// Take the secret key, for the one `ADD_ONION` call site.
    #[must_use]
    pub fn into_onion_key(self) -> OnionKey {
        self.key
    }
}

// The derived key is inside `OnionKey`, whose own `Debug` redacts; deriving
// `Debug` here would still be safe, but it is written out so the redaction is
// visible at this level too rather than depending on a member's behaviour.
impl std::fmt::Debug for OnionIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnionIdentity")
            .field("key", &"<redacted>")
            .field("service_id", &"<redacted>")
            .finish()
    }
}

/// Derive persona `p_slot`'s onion identity from a wallet master seed under an
/// explicit derivation context.
///
/// The 32-byte seed is the **production** GF-9 HS-identity seed
/// ([`derive_p_hs_id_seed`], label `ARCHIVAL_P_HS_ID_INFO`, frozen under
/// `ARCHIVAL_P_DERIVE_V1`), which this function expands per RFC 8032 to tor's
/// `ED25519-V3` blob. `net`/`fmt` select the derivation context exactly as the
/// production path does — the caller chooses, nothing is hidden — so any given
/// `(seed, net, fmt, p_slot)` reproduces the KAT's `hs_id_pubkey` vector. (The
/// apparatus pins one context; see `Apparatus::bring_up_with_pow`.)
///
/// Every intermediate is `Zeroizing`; the only value that outlives the call is
/// the [`OnionKey`], which wipes on drop.
#[must_use]
pub fn derive_onion_identity(
    master_seed_64: &[u8; 64],
    net: DerivationNetwork,
    fmt: SeedFormat,
    p_slot: PSlot,
) -> OnionIdentity {
    let seed = derive_p_hs_id_seed(master_seed_64, net, fmt, p_slot.to_raw());

    let expanded = expand_seed(&seed);
    let verifying = verifying_key_from_seed(&seed);
    let service_id = service_id_from_pubkey(verifying.as_bytes());

    OnionIdentity {
        // Move the expanded bytes in; `Zeroizing`'s drop wipes the source copy.
        key: OnionKey::from_expanded_bytes(*expanded),
        service_id,
    }
}

/// RFC 8032 §5.1.5 expansion: `SHA-512(seed)`, with the low 32 bytes clamped.
///
/// This is tor's `ED25519-V3` `KeyBlob` payload (before base64). The clamp is
/// applied to **raw bytes**, never via a `curve25519_dalek::Scalar` — see the
/// module doc's trap note: a `Scalar` round-trip reduces mod ℓ and silently
/// yields a different key.
fn expand_seed(seed: &[u8; 32]) -> Zeroizing<[u8; ONION_KEY_BYTES]> {
    let mut out = Zeroizing::new([0u8; ONION_KEY_BYTES]);
    // Copy straight out of the digest into the `Zeroizing` destination. The
    // digest's own `GenericArray` is not `Zeroize`-able, so it is consumed
    // immediately rather than bound to a named local that would outlive the copy
    // (rule 35's hand-off discipline: minimise the window where secret bytes sit
    // outside a wiping wrapper).
    out.copy_from_slice(&Sha512::digest(seed));
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
    out
}

/// The ed25519 public key for `seed`.
///
/// Goes through `SigningKey`, which performs the identical RFC 8032 expansion
/// internally — so the public key here and the secret key tor receives are two
/// views of one key, and the service id computed below is the address tor will
/// report.
fn verifying_key_from_seed(seed: &[u8; 32]) -> VerifyingKey {
    // `SigningKey` is `ZeroizeOnDrop` in its own right (the `zeroize` feature is
    // enabled in Cargo.toml), so it wipes when this scope ends without needing a
    // `Zeroizing` wrapper -- which it could not take anyway, as `Zeroizing`
    // requires `DefaultIsZeroes`.
    let signing = ed25519_dalek::SigningKey::from_bytes(seed);
    signing.verifying_key()
}

/// The v3 `.onion` service id for an ed25519 public key (rend-spec-v3 §6):
/// `base32(pubkey ‖ SHA3-256(".onion checksum" ‖ pubkey ‖ version)[..2] ‖ version)`.
///
/// Computed here, independently of tor, precisely so the live test can assert
/// tor's answer matches — which is what turns "the encoding should work" into
/// evidence that it does.
fn service_id_from_pubkey(pubkey: &[u8; 32]) -> ServiceId {
    let mut hasher = Sha3_256::new();
    sha3::Digest::update(&mut hasher, ONION_CHECKSUM_PREFIX);
    sha3::Digest::update(&mut hasher, pubkey);
    sha3::Digest::update(&mut hasher, [ONION_ADDRESS_VERSION]);
    let checksum = hasher.finalize();

    let mut raw = [0u8; 35];
    raw[..32].copy_from_slice(pubkey);
    raw[32..34].copy_from_slice(&checksum[..2]);
    raw[34] = ONION_ADDRESS_VERSION;

    ServiceId::parse(&base32_lower(&raw)).expect("a 35-byte v3 address encodes to 56 base32 chars")
}

/// RFC 4648 base32, lowercase, unpadded.
///
/// Hand-rolled for the same reason as the base64 in `shekyl_tor::control::onion`:
/// one fixed-width call site, the alphabet is the load-bearing property, and it
/// is pinned by RFC 4648 vectors below. 35 bytes is a whole number of 5-byte
/// groups (7 × 5), so no padding case arises for the real input — the general
/// path is written and tested anyway rather than assuming the caller.
fn base32_lower(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 64] = [0x5au8; 64];

    /// Derive under one fixed context so these unit tests exercise the encoding
    /// and slot/seed binding without repeating `(net, fmt)` at every call. The
    /// context choice is irrelevant to what they assert.
    fn identity(seed: &[u8; 64], slot: u32) -> OnionIdentity {
        derive_onion_identity(
            seed,
            DerivationNetwork::Mainnet,
            SeedFormat::Bip39,
            PSlot::from_raw(slot),
        )
    }

    #[test]
    fn base32_matches_rfc4648_vectors() {
        // RFC 4648 §10, lowercased and unpadded — the address alphabet. A drift
        // here yields a syntactically valid but *wrong* .onion, which would fail
        // only as an unreachable service, so it is pinned to exact bytes.
        assert_eq!(base32_lower(b""), "");
        assert_eq!(base32_lower(b"f"), "my");
        assert_eq!(base32_lower(b"fo"), "mzxq");
        assert_eq!(base32_lower(b"foo"), "mzxw6");
        assert_eq!(base32_lower(b"foob"), "mzxw6yq");
        assert_eq!(base32_lower(b"fooba"), "mzxw6ytb");
        assert_eq!(base32_lower(b"foobar"), "mzxw6ytboi");
    }

    #[test]
    fn expansion_clamps_and_is_not_a_reduced_scalar() {
        // The module doc's trap, as an assertion. The clamped low half must carry
        // the ed25519 clamp bits *unreduced*: bit 254 set, bits 0-2 and 255 clear.
        // A `Scalar::to_bytes()` round-trip would reduce mod l and clear bit 254,
        // producing a different (still valid) key and an unreachable address.
        let seed = [0x11u8; 32];
        let expanded = expand_seed(&seed);
        assert_eq!(expanded[0] & 0b0000_0111, 0, "low three bits cleared");
        assert_eq!(expanded[31] & 0b1000_0000, 0, "bit 255 cleared");
        assert_eq!(expanded[31] & 0b0100_0000, 0x40, "bit 254 set");
        // The high half is the untouched PRF secret (SHA-512's tail).
        let raw = Sha512::digest(seed);
        assert_eq!(&expanded[32..], &raw[32..]);
    }

    #[test]
    fn derivation_is_deterministic_and_slot_bound() {
        // Stable across calls (the "persist without storing" property: a restart
        // reproduces the same .onion) and distinct per slot (the persona binding).
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
        // Catches a derivation that ignored `p_slot` or folded it in a way that
        // collapses (e.g. truncating to u8). Not an injectivity proof — collision
        // resistance is the real property — but it fails loudly for the shapes
        // that actually go wrong.
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

    // Domain separation between the public on-chain `P_canonical_id` and the
    // serving onion key is now a *production* invariant (both labels live in
    // `shekyl-crypto-pq` / `shekyl-archival-retention`), so it is asserted where
    // both are visible and the crate is not disposable:
    // `shekyl-archival-retention`'s `kat_p_canonical_id_cross_check` test
    // (`hs_id_seed_is_domain_separated_from_p_canonical_id`). It does not belong
    // in a spike that may be deleted.

    #[test]
    fn service_id_is_a_wellformed_v3_address() {
        let id = identity(&SEED, 7);
        let s = id.service_id().as_str();
        assert_eq!(s.len(), 56);
        assert!(s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)));
        // The version byte lands in the final base32 group: a v3 address always
        // ends in 'd' (0x03 in the low bits of the last quantum).
        assert!(s.ends_with('d'), "v3 addresses end in 'd': {s}");
    }

    #[test]
    fn identity_debug_redacts() {
        let id = identity(&SEED, 2);
        let rendered = format!("{id:?}");
        assert!(!rendered.contains(id.service_id().as_str()));
        assert!(rendered.contains("<redacted>"));
    }
}
