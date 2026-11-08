// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! v3 onion identity: an onion keypair as Tor takes it, the `ED25519-V3` key
//! blob from its expanded secret and the `.onion` address from its public
//! key. The caller supplies the keypair; this crate does not know whether it
//! is a persona's durable onion or the daemon's ephemeral one.
//!
//! The keypair is `shekyl_crypto_pq::onion::OnionKeypair`. The RFC 8032
//! expansion and the public key are secret-byte operations and live there
//! (rule 36): a persona's comes from
//! `shekyl_crypto_pq::archival_p::derive_p_onion_keypair` (the GF-9 serving
//! label, network-scoped and `p_slot`-bound, frozen under
//! `ARCHIVAL_P_DERIVE_V2`), the daemon's from `OnionKeypair::ephemeral`. This
//! crate hashes, clamps and multiplies nothing secret: it encodes the address
//! from the public key (rend-spec-v3 §6) and hands the expanded secret to Tor.
//!
//! # The custody boundary is the API (`ARCHIVAL_CHALLENGE_MECHANISM.md` §7.2(iii))
//!
//! The serving path holds only the keypair, which is what it hands Tor. No
//! seed exists outside `shekyl-crypto-pq`, and nothing here accepts a wallet
//! master seed. Serving config takes an [`OnionIdentity`]; see
//! `shekyl-tor-control-wallet`'s `onion_service::OnionServiceSpec`
//! (wallet-owned). A serving process holding `master_seed` would be one edit
//! away from also holding `bond_spend_pk`'s authority, and the type boundary
//! makes that edit unrepresentable on the serving path.

/// The keypair an [`OnionIdentity`] is built from, re-exported so a caller
/// of this crate names it without a second dependency edge.
pub use shekyl_crypto_pq::onion::OnionKeypair;
use shekyl_crypto_pq::onion::ONION_EXPANDED_SECRET_BYTES;

use crate::control::onion::{OnionKey, ServiceId, ONION_KEY_BYTES};

// Tor's key blob is the expanded secret, byte for byte.
const _: () = assert!(ONION_KEY_BYTES == ONION_EXPANDED_SECRET_BYTES);

/// An onion identity: the keypair plus the public service id it implies,
/// built once and handed to the serving supervisor as the least-privilege
/// credential.
///
/// # Why this is the boundary type
///
/// The custody ruling (§7.2(iii)) is a property of *which secret crosses
/// into the serving role*. What reaches the supervisor is this identity: the
/// expanded onion key (which authorizes exactly one thing — publishing this
/// onion) and its address. `OnionServiceSpec::new` takes an `OnionIdentity`,
/// so no seed can enter the serving config by construction.
///
/// # Why it holds the keypair rather than an [`OnionKey`]
///
/// [`OnionKey`] is deliberately one-shot (non-`Clone`, consumed by
/// `AddOnion`), but a supervised onion must be **re-published on every
/// incarnation** (`Detach` is unrepresentable, so the onion dies with its
/// control connection). This identity therefore holds the keypair and mints
/// a fresh one-shot [`OnionKey`] per incarnation ([`Self::mint_onion_key`]).
///
/// # Not `Clone`
///
/// Same secret posture as [`OnionKey`]: holding the expanded secret *is* the
/// persona on the network. The type is moved into the serving spec and
/// remints keys by reference. Shared ownership, if ever needed, must be an
/// explicit `Arc<OnionIdentity>` at the call site.
pub struct OnionIdentity {
    keypair: OnionKeypair,
    service_id: ServiceId,
}

impl OnionIdentity {
    /// The identity for `keypair`: its address, computed here from the
    /// public key, and the keypair itself, kept for minting.
    #[must_use]
    pub fn from_keypair(keypair: OnionKeypair) -> Self {
        let service_id = service_id_from_pubkey(&keypair.public_key());
        Self {
            keypair,
            service_id,
        }
    }

    /// Raw 32-byte ed25519 public key (the JoinMarket serving endpoint).
    /// The secret half stays behind [`Self::mint_onion_key`].
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.keypair.public_key()
    }

    /// The `.onion` service id this key publishes at — authoritative because
    /// it was computed from the key when the identity was built, so the
    /// supervisor can advertise it and fail-stop any incarnation tor
    /// publishes differently without recomputing anything.
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
        OnionKey::from_expanded_bytes(*self.keypair.expanded_secret())
    }
}

// The keypair is secret and the service id is the persona's public network
// identity; render only the type name so neither reaches a log or panic
// message.
impl std::fmt::Debug for OnionIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OnionIdentity(<redacted>)")
    }
}

/// The v3 `.onion` service id for an ed25519 public key.
///
/// Computed independently of tor, precisely so the publish path can
/// fail-stop when tor's reported `ServiceID` differs from the address the
/// persona advertises. The transform is `shekyl-onion-v3` — the same
/// function the daemon fetch client uses to dial the bond-record
/// endpoint — so the address a persona publishes and the address a
/// daemon derives cannot drift.
fn service_id_from_pubkey(pubkey: &[u8; 32]) -> ServiceId {
    ServiceId::parse(&shekyl_onion_v3::v3_service_id(pubkey))
        .expect("a 35-byte v3 address encodes to 56 base32 chars")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> OnionIdentity {
        OnionIdentity::from_keypair(OnionKeypair::ephemeral().expect("OS CSPRNG"))
    }

    // The expansion, the public key and the fixed-seed address are pinned in
    // `shekyl-crypto-pq` (`onion.rs`, and `kat_archival_p_derive_v2`'s
    // `hs_id_pubkey` vectors), where they are computed.

    #[test]
    fn public_key_is_the_service_ids_preimage() {
        // The wire carries the key (EU-D3); the address is a display form a
        // reader reconstructs. If these ever disagree, the endpoint a bond
        // advertises is not the address tor serves.
        let keypair = OnionKeypair::ephemeral().expect("OS CSPRNG");
        let public_key = keypair.public_key();
        let id = OnionIdentity::from_keypair(keypair);
        assert_eq!(id.public_key(), public_key);
        assert_eq!(service_id_from_pubkey(&id.public_key()), *id.service_id());
    }

    #[test]
    fn the_identity_is_the_keypairs() {
        let keypair = OnionKeypair::ephemeral().expect("OS CSPRNG");
        let same = keypair.duplicate();
        let a = OnionIdentity::from_keypair(keypair);
        let b = OnionIdentity::from_keypair(same);
        assert_eq!(a.service_id(), b.service_id());
        assert_ne!(a.service_id(), identity().service_id());
    }

    #[test]
    fn service_id_is_a_wellformed_v3_address() {
        let id = identity();
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
        let id = identity();
        let rendered = format!("{id:?}");
        assert!(!rendered.contains(id.service_id().as_str()));
        assert!(rendered.contains("<redacted>"));
    }
}
