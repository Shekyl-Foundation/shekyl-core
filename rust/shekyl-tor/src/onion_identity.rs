// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The persona's v3 onion identity: expand a **derived** 32-byte HS-identity
//! seed into tor's `ED25519-V3` key blob, and compute the `.onion` address
//! that key implies.
//!
//! Relocated from the SP-T3 spike's `onion_key.rs` (its own SPIKE-F-4 note:
//! *"That is transport surface, not key derivation — in production it belongs
//! in `shekyl-tor`"*). What lives here is **encoding only**: RFC 8032 §5.1.5
//! seed expansion (`SHA-512` + clamp) and the rend-spec-v3 §6 address
//! construction. The seed itself comes from
//! `shekyl_crypto_pq::archival_p::derive_p_hs_id_seed` — the GF-9 serving
//! label, network-scoped and `p_slot`-bound, frozen under
//! `ARCHIVAL_P_DERIVE_V1` — and that derivation stays in `shekyl-crypto-pq`
//! on the **wallet** side of the custody boundary.
//!
//! # The custody boundary is the API (`ARCHIVAL_CHALLENGE_MECHANISM.md` §7.2(iii))
//!
//! Two concentric constraints:
//!
//! 1. **No master seed in this crate.** Expansion takes only the already-
//!    derived 32-byte HS-identity seed ([`OnionIdentity::from_hs_id_seed`]);
//!    nothing here accepts a wallet master seed.
//! 2. **Serving config takes an [`OnionIdentity`], never a seed.** The seed
//!    is consumed at expansion time and dies with the call; the value that
//!    crosses into the supervisor is this identity (expanded key + address).
//!    See [`crate::onion_service::OnionServiceSpec`].
//!
//! Holding `master_seed` — or holding the derived seed and inviting the
//! convenient "just pass the seed" wiring — is one edit away from also
//! holding `bond_spend_pk`'s authority. The type boundary makes that edit
//! unrepresentable on the serving path.
//!
//! # The `Scalar` trap (verified against a real tor, kept from the spike)
//!
//! `curve25519_dalek::Scalar::from_bytes_mod_order(clamp_integer(b))`
//! **reduces mod ℓ**, and a clamped integer is ≥ 2²⁵⁴ > ℓ — so a `Scalar`
//! round-trip yields a *different* (still valid) key and an unreachable
//! address. The clamp here is applied to raw bytes and never round-tripped
//! through a `Scalar`. The SP-T3 spike's live apparatus asserts a real tor
//! reports byte-identical `ServiceID` for this expansion (the
//! `published != service_id` fail-stop in its `bring_up_with_pow`, on the
//! `SHEKYL_TEST_TOR_BINARY` lane).

use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha512};
use sha3::Sha3_256;
use zeroize::Zeroizing;

use crate::control::onion::{OnionKey, ServiceId, ONION_KEY_BYTES};

/// Version byte of a v3 onion address (rend-spec-v3 §6).
const ONION_ADDRESS_VERSION: u8 = 0x03;

/// Domain-separation prefix for the v3 address checksum (rend-spec-v3 §6).
const ONION_CHECKSUM_PREFIX: &[u8] = b".onion checksum";

/// A persona's onion identity: the **expanded** serving key plus the public
/// service id it implies — derived **once** in the wallet context and handed
/// to the serving supervisor as the least-privilege credential.
///
/// # Why this, and not a seed, is the boundary type
///
/// The custody ruling (§7.2(iii)) is a property of *which secret crosses
/// into the serving role*, not of the derivation tree: the wallet's flat
/// HKDF siblings are independent, but they all derive from `master_seed`,
/// so a serving process holding `master_seed` — or holding the derived
/// `hs_id_seed` and thereby inviting the convenient "just pass the seed"
/// wiring — is one edit away from also holding `bond_spend_pk`'s authority.
/// So the expansion runs here, on the wallet side ([`Self::from_hs_id_seed`]
/// consumes the derived seed and it dies at the end of that call), and the
/// value that reaches the supervisor is this identity: the expanded onion
/// key (which authorizes exactly one thing — publishing this onion) and its
/// address. `OnionServiceSpec::new` takes an `OnionIdentity`, never a seed,
/// so `master_seed` cannot enter the serving config by construction.
///
/// # Why it holds expanded bytes rather than an [`OnionKey`]
///
/// [`OnionKey`] is deliberately one-shot (non-`Clone`, consumed by
/// `AddOnion`), but a supervised onion must be **re-published on every
/// incarnation** (`Detach` is unrepresentable, so the onion dies with its
/// control connection). This identity therefore holds the expanded bytes and
/// mints a fresh one-shot [`OnionKey`] per incarnation
/// ([`Self::mint_onion_key`]) — the `OnionKey` posture is unchanged, and the
/// re-mintable secret lives behind the same `Zeroizing`/redacting-`Debug`
/// discipline.
///
/// # Not `Clone`
///
/// Same secret posture as [`OnionKey`]: holding these expanded bytes *is*
/// the persona on the network. Accidental copies are not free; the type is
/// moved into [`crate::onion_service::OnionServiceSpec`] and remints keys by
/// reference. Shared ownership, if ever needed, must be an explicit
/// `Arc<OnionIdentity>` at the call site.
pub struct OnionIdentity {
    expanded: Zeroizing<[u8; ONION_KEY_BYTES]>,
    service_id: ServiceId,
}

impl OnionIdentity {
    /// Expand a **derived** 32-byte HS-identity seed (GF-9,
    /// `derive_p_hs_id_seed`) into the identity tor publishes.
    ///
    /// The seed is consumed for the expansion and does not outlive this
    /// call; the returned identity carries only the expanded key and the
    /// address. This is the one place a seed touches the onion path — see
    /// the type doc's custody note.
    #[must_use]
    pub fn from_hs_id_seed(seed: &[u8; 32]) -> Self {
        let expanded = expand_seed(seed);
        let verifying = verifying_key_from_seed(seed);
        let service_id = service_id_from_pubkey(verifying.as_bytes());
        Self {
            expanded,
            service_id,
        }
    }

    /// The `.onion` service id this key publishes at — authoritative because
    /// it was computed from the key during derivation, so the supervisor can
    /// advertise it and fail-stop any incarnation tor publishes differently
    /// without recomputing anything.
    #[must_use]
    pub fn service_id(&self) -> &ServiceId {
        &self.service_id
    }

    /// Mint a fresh one-shot [`OnionKey`] for one `ADD_ONION` — usable
    /// repeatedly across incarnations without weakening `OnionKey`'s
    /// one-shot posture (each minted key is still consumed by exactly one
    /// `AddOnion`).
    #[must_use]
    pub fn mint_onion_key(&self) -> OnionKey {
        OnionKey::from_expanded_bytes(*self.expanded)
    }
}

// Both fields are secret-or-secret-adjacent (the expanded key, and the
// service id which is the persona's public network identity); render only
// the type name so neither reaches a log or panic message.
impl std::fmt::Debug for OnionIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OnionIdentity(<redacted>)")
    }
}

/// RFC 8032 §5.1.5 expansion: `SHA-512(seed)`, with the low 32 bytes
/// clamped.
///
/// This is tor's `ED25519-V3` `KeyBlob` payload (before base64). The clamp
/// is applied to **raw bytes**, never via a `curve25519_dalek::Scalar` —
/// see the module doc's trap note.
fn expand_seed(seed: &[u8; 32]) -> Zeroizing<[u8; ONION_KEY_BYTES]> {
    let mut out = Zeroizing::new([0u8; ONION_KEY_BYTES]);
    // Copy straight out of the digest into the `Zeroizing` destination. The
    // digest's own `GenericArray` is not `Zeroize`-able, so it is consumed
    // immediately rather than bound to a named local that would outlive the
    // copy (rule 35's hand-off discipline).
    out.copy_from_slice(&Sha512::digest(seed));
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
    out
}

/// The ed25519 public key for `seed`.
///
/// Goes through `SigningKey`, which performs the identical RFC 8032
/// expansion internally — so the public key here and the secret key tor
/// receives are two views of one key, and the service id computed below is
/// the address tor will report.
fn verifying_key_from_seed(seed: &[u8; 32]) -> VerifyingKey {
    // `SigningKey` is `ZeroizeOnDrop` in its own right (the `zeroize`
    // feature is enabled in Cargo.toml), so it wipes when this scope ends.
    let signing = ed25519_dalek::SigningKey::from_bytes(seed);
    signing.verifying_key()
}

/// The v3 `.onion` service id for an ed25519 public key (rend-spec-v3 §6):
/// `base32(pubkey ‖ SHA3-256(".onion checksum" ‖ pubkey ‖ version)[..2] ‖ version)`.
///
/// Computed independently of tor, precisely so the publish path can
/// fail-stop when tor's reported `ServiceID` differs from the address the
/// persona advertises.
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
/// Hand-rolled for the same reason as the base64 in `control::onion`: one
/// fixed-width call site, the alphabet is the load-bearing property, and it
/// is pinned by RFC 4648 vectors below. 35 bytes is a whole number of
/// 5-byte groups (7 × 5), so no padding case arises for the real input —
/// the general path is written and tested anyway rather than assuming the
/// caller.
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

    #[test]
    fn base32_matches_rfc4648_vectors() {
        // RFC 4648 §10, lowercased and unpadded — the address alphabet. A
        // drift here yields a syntactically valid but *wrong* .onion, which
        // would fail only as an unreachable service, so it is pinned to
        // exact bytes.
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
        // The module doc's trap, as an assertion. The clamped low half must
        // carry the ed25519 clamp bits *unreduced*: bit 254 set, bits 0-2
        // and 255 clear. A `Scalar::to_bytes()` round-trip would reduce
        // mod l and clear bit 254, producing a different (still valid) key
        // and an unreachable address.
        let seed = [0x11u8; 32];
        let expanded = expand_seed(&seed);
        assert_eq!(expanded[0] & 0b0000_0111, 0, "low three bits cleared");
        assert_eq!(expanded[31] & 0b1000_0000, 0, "bit 255 cleared");
        assert_eq!(expanded[31] & 0b0100_0000, 0x40, "bit 254 set");
        // The high half is the untouched PRF secret (SHA-512's tail).
        let raw = Sha512::digest(seed);
        assert_eq!(&expanded[32..], &raw[32..]);
    }

    /// Golden KAT: a fixed derived seed pins the exact `.onion` string, so
    /// any drift in expansion, checksum, or alphabet fails byte-exactly
    /// here instead of surfacing as an unreachable service in the field.
    /// (The seed→pubkey half of this pipeline is additionally pinned
    /// cross-arch by `kat_archival_p_derive_v1`'s `hs_id_pubkey` vectors in
    /// `shekyl-crypto-pq`; the live tor cross-check is the SP-T3 spike's
    /// `bring_up_with_pow` published-vs-derived fail-stop.)
    #[test]
    fn service_id_golden_kat() {
        let identity = OnionIdentity::from_hs_id_seed(&[0x42u8; 32]);
        assert_eq!(
            identity.service_id().as_str(),
            "efjprum3peosirjsilqv6lvlns3476t3njpngaexsyhangeb3mjo7sad",
            "the v3 address for the fixed seed"
        );
    }

    #[test]
    fn identity_is_deterministic_and_seed_bound() {
        let a = OnionIdentity::from_hs_id_seed(&[0x5au8; 32]);
        let a2 = OnionIdentity::from_hs_id_seed(&[0x5au8; 32]);
        let b = OnionIdentity::from_hs_id_seed(&[0x5bu8; 32]);
        assert_eq!(a.service_id(), a2.service_id());
        assert_ne!(a.service_id(), b.service_id());
    }

    #[test]
    fn service_id_is_a_wellformed_v3_address() {
        let id = OnionIdentity::from_hs_id_seed(&[0x77u8; 32]);
        let s = id.service_id().as_str();
        assert_eq!(s.len(), 56);
        assert!(s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)));
        // The version byte lands in the final base32 group: a v3 address
        // always ends in 'd' (0x03 in the low bits of the last quantum).
        assert!(s.ends_with('d'), "v3 addresses end in 'd': {s}");
    }

    #[test]
    fn identity_debug_redacts() {
        let id = OnionIdentity::from_hs_id_seed(&[0x33u8; 32]);
        let rendered = format!("{id:?}");
        assert!(!rendered.contains(id.service_id().as_str()));
        assert!(rendered.contains("<redacted>"));
    }
}
