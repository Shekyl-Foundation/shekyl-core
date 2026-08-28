// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Relay network identity — the Rust mirror of `epee::net_utils::zone`.
//!
//! Discriminants match `contrib/epee/include/net/enums.h` exactly because the
//! value crosses the FFI as a `u8`. There is **no persisted zone field** on the
//! txpool entry (§89.2): the embargo draw is told the zone at
//! `set_relayed` time, not reminded of it later.

/// The network a relay zone runs on.
///
/// # FFI contract
///
/// Callers pass `static_cast<uint8_t>(zone)`. Anything outside `0..=3` must
/// resolve to [`Self::Invalid`], which [`crate::params::DandelionParams::adopted_for`]
/// provisions as the **longest** embargo — a corrupt or miscast byte costs
/// recovery latency, never the shortest (clearnet) wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RelayZone {
    /// `zone::invalid` — out-of-domain FFI byte, or "origin unknown".
    Invalid = 0,
    /// `zone::public_` — clearnet.
    Public = 1,
    /// `zone::i2p`.
    I2p = 2,
    /// `zone::tor`.
    Tor = 3,
}

impl RelayZone {
    /// Every zone, in discriminant order.
    ///
    /// Exists so callers can COUNT zones by predicate instead of hand-copying
    /// the answer — `params::carrier::CEILING_ZONES` is the first, and a
    /// hand-maintained "there are 2 encrypted zones" is exactly the duplicate
    /// that goes stale when a third is added.
    ///
    /// Completeness is enforced, not assumed: see [`Self::position`].
    pub const ALL: [Self; 4] = [Self::Invalid, Self::Public, Self::I2p, Self::Tor];

    /// Index of this zone within [`Self::ALL`].
    ///
    /// **This is the exhaustiveness tripwire and that is its whole job.** The
    /// match has no wildcard arm, so adding a `RelayZone` variant fails to
    /// compile HERE — and the `const` block below then re-checks that
    /// [`Self::ALL`] actually lists every variant, in order. Without both
    /// halves, `ALL` could silently omit a new zone and every count derived
    /// from it would be quietly wrong.
    #[must_use]
    pub const fn position(self) -> usize {
        match self {
            Self::Invalid => 0,
            Self::Public => 1,
            Self::I2p => 2,
            Self::Tor => 3,
        }
    }

    /// Whether this zone's links are encrypted.
    ///
    /// **This is what decides noise eligibility**, and it is deliberately not
    /// the same question as anonymity. Anonymity is about who can be
    /// *identified*; encryption is about what a wire observer can *read*.
    /// Noise conceals packet sizing, and sizing is the only thing left to read
    /// once the link is encrypted — on a cleartext link the observer reads the
    /// contents outright, so padding the sizes conceals nothing and the
    /// bandwidth is spent for no privacy.
    ///
    /// The two predicates coincide for the current zone set only because
    /// ordinary internet traffic is not encrypted. Encrypting it would make
    /// [`Self::Public`] eligible for noise **without** making it anonymous,
    /// and this is the one place that would change.
    ///
    /// [`Self::Invalid`] answers **false**, and the asymmetry with
    /// [`Self::from_ffi_u8`] is deliberate rather than an oversight. A corrupt
    /// byte draws the *anonymity* parameters there because the longer embargo
    /// is the safe direction when the zone is unknown. Here the safe direction
    /// is the opposite one: an unknown link is not presumed encrypted, so it
    /// earns no noise. Both choose the answer that cannot silently weaken a
    /// protection — which is why they point opposite ways.
    ///
    /// **The hop that matters is the overlay leaving the machine.** A loopback
    /// SOCKS into a local Tor/i2p daemon (`--tx-proxy tor,127.0.0.1:9050`) is
    /// the standard first hop and is not a wire observer: Tor/i2p encrypts
    /// what leaves. Do not re-key this predicate on the SOCKS endpoint's
    /// address — that collapses overlay secrecy into first-hop locality, which
    /// is a connect-path concern and a different axis.
    ///
    /// Callers that need secrecy as a *value* (a zone constructor argument,
    /// a stored axis) go through [`LinkSecrecy::of`], which is the only way
    /// to mint one. This predicate stays the defining function.
    #[must_use]
    pub const fn is_encrypted(self) -> bool {
        matches!(self, Self::I2p | Self::Tor)
    }

    /// Decode a zone arriving across the FFI as a whole byte.
    ///
    /// Out of `0..=3` → [`Self::Invalid`]. **Do not mask** (`raw & 0b11`):
    /// `5 & 0b11 == 1` would decode a corrupt byte to [`Self::Public`] and
    /// draw the shortest embargo silently.
    #[must_use]
    pub const fn from_ffi_u8(raw: u8) -> Self {
        match raw {
            1 => Self::Public,
            2 => Self::I2p,
            3 => Self::Tor,
            _ => Self::Invalid,
        }
    }

    /// The discriminant as a byte — array index into the per-zone embargo
    /// table and the value C++ casts from `epee::net_utils::zone`.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Whether this zone is clearnet.
    ///
    /// Deliberately **not** the negation of an "anonymity network" helper:
    /// [`Self::Invalid`] is neither, and the embargo must not treat an unknown
    /// origin as clearnet (shorter embargo = privacy-losing direction).
    #[must_use]
    pub const fn is_clearnet(self) -> bool {
        matches!(self, Self::Public)
    }
}

/// Whether a zone's links are encrypted — the **network secrecy** axis.
///
/// Transform-shaped (rule 18): defined by [`RelayZone::is_encrypted`], so it
/// lives next to that function rather than at the consumer. Constructed only
/// from a [`RelayZone`] via [`LinkSecrecy::of`]. There is no `Encrypted` or
/// `Cleartext` variant a caller can mint beside the wrong reach — that is
/// the collapse this type exists to make unrepresentable.
///
/// Kept as its own type rather than a `bool` because adjacent same-typed
/// arguments transpose silently, and because *reach* (who receives a fluff)
/// and *secrecy* (what a wire observer can read) are independent axes that
/// this subsystem keeps collapsing into one word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkSecrecy {
    encrypted: bool,
}

impl LinkSecrecy {
    /// The secrecy of `zone`'s links. **The only constructor.**
    #[must_use]
    pub const fn of(zone: RelayZone) -> Self {
        Self {
            encrypted: zone.is_encrypted(),
        }
    }

    /// True when a wire observer cannot read contents — the noise-eligibility
    /// predicate. Equal to [`RelayZone::is_encrypted`] on the zone this was
    /// constructed from.
    #[must_use]
    pub const fn is_encrypted(self) -> bool {
        self.encrypted
    }
}

const _: () = {
    // `ALL` lists every variant exactly once and in discriminant order. The
    // `position` match above breaks first on a new variant; this catches the
    // other half — an `ALL` that was not updated to match it.
    let mut i = 0;
    while i < RelayZone::ALL.len() {
        assert!(
            RelayZone::ALL[i].position() == i,
            "RelayZone::ALL is incomplete or out of discriminant order"
        );
        i += 1;
    }
};

#[cfg(test)]
mod tests {
    use super::{LinkSecrecy, RelayZone};
    use crate::params::DandelionParams;

    #[test]
    fn ffi_bytes_round_trip_the_domain() {
        for zone in [
            RelayZone::Invalid,
            RelayZone::Public,
            RelayZone::I2p,
            RelayZone::Tor,
        ] {
            assert_eq!(RelayZone::from_ffi_u8(zone.as_u8()), zone);
            assert!(zone.as_u8() <= 3);
        }
    }

    #[test]
    fn an_out_of_domain_ffi_byte_never_decodes_to_clearnet() {
        // Masking would send 5 → Public. That is the whole hazard this
        // decoder exists to prevent.
        assert_eq!(5_u8 & 0b11, 1, "the mask hazard: 5 becomes Public");
        assert_eq!(RelayZone::from_ffi_u8(5), RelayZone::Invalid);

        let clearnet_hop = DandelionParams::adopted_for(RelayZone::Public).time_between_hop_ms;
        for raw in 4_u8..=255 {
            let zone = RelayZone::from_ffi_u8(raw);
            assert_eq!(zone, RelayZone::Invalid, "raw {raw} escaped the domain");
            assert!(
                DandelionParams::adopted_for(zone).time_between_hop_ms > clearnet_hop,
                "raw {raw} decoded to something provisioned no better than clearnet"
            );
        }
        for raw in 0_u8..=3 {
            assert_eq!(RelayZone::from_ffi_u8(raw).as_u8(), raw);
        }
    }

    #[test]
    fn invalid_is_not_clearnet() {
        assert!(!RelayZone::Invalid.is_clearnet());
        assert!(RelayZone::Public.is_clearnet());
        assert!(!RelayZone::I2p.is_clearnet());
        assert!(!RelayZone::Tor.is_clearnet());
    }

    #[test]
    fn invalid_is_not_encrypted_and_tor_i2p_are() {
        // The fail-safe opposite of `from_ffi_u8`: unknown zone → longest
        // embargo (safe for anonymity parameters) but NOT presumed encrypted
        // (an unknown link earns no noise). Both pick the answer that cannot
        // silently weaken a protection.
        assert!(!RelayZone::Invalid.is_encrypted());
        assert!(!RelayZone::Public.is_encrypted());
        assert!(RelayZone::I2p.is_encrypted());
        assert!(RelayZone::Tor.is_encrypted());
    }

    #[test]
    fn link_secrecy_is_a_function_of_the_zone_and_nothing_else() {
        assert!(!LinkSecrecy::of(RelayZone::Invalid).is_encrypted());
        assert!(!LinkSecrecy::of(RelayZone::Public).is_encrypted());
        assert!(LinkSecrecy::of(RelayZone::I2p).is_encrypted());
        assert!(LinkSecrecy::of(RelayZone::Tor).is_encrypted());
        assert_eq!(
            LinkSecrecy::of(RelayZone::Tor),
            LinkSecrecy::of(RelayZone::I2p),
            "both encrypted networks are the same secrecy value — identity is not this axis"
        );
        assert_ne!(
            LinkSecrecy::of(RelayZone::Tor),
            LinkSecrecy::of(RelayZone::Public)
        );
    }
}
