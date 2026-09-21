// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Per-host **inbound** admission — PWD-I7 of `docs/design/SHEKYL_P2P_PROTOCOL.md`.
//!
//! How many connections one remote *host* may hold **into** this node, and
//! which zones that question is even askable on. C++ owns the connection
//! list and walks it; the verdict is here.
//!
//! # Not the outbound cap
//!
//! PWD-I1's same-host cap (`nodetool::outbound_connection_takes_host`) is
//! `!connection_is_income` by construction, and its comment records why:
//! capping inbound there would let any peer suppress this node's dials to a
//! host simply by connecting to us. This module is the *other* direction —
//! inherited Monero-lineage behaviour with an inherited default — and the
//! two must not be conflated. They are separate rules with separate reasons.
//!
//! # Nettype-uniform by construction (rule 71)
//!
//! Nothing here takes a nettype. The admission decision is a function of
//! `(zone, count, cap)` and nothing else, so mainnet, testnet and stagenet
//! cannot diverge without someone adding a parameter that does not exist.
//! Rule 71 forbids adding one on the consensus-adjacent surface; keeping
//! nettype out of the *signature* is what makes that structural rather than
//! a convention a reviewer has to police.
//!
//! # The number is not ruled here
//!
//! [`HostInboundCap::DEFAULT`] preserves the inherited value exactly. Moving
//! it is a ruling reserved to the maintainer (PWD-I7's owed-back question 1),
//! and this module's job is to give that ruling one place to land instead of
//! two C++ literals.

/// The zone an inbound connection arrived on — the `epee::net_utils::zone`
/// discriminant, as the C ABI byte.
///
/// Pinned on the C++ side by the `static_assert`s at `src/p2p/net_node.inl`
/// (`invalid` 0, `public_` 1, `i2p` 2, `tor` 3), the same pins the zone-route
/// family already relies on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum InboundZone {
    /// The zone could not be determined.
    ///
    /// **Not host-capped**, which preserves the inherited behaviour exactly:
    /// the C++ test was `!= public_`, so an undeterminable zone already fell
    /// through to "no cap". It is also the right default — a cap keyed on a
    /// host identity we could not establish would be keyed on nothing.
    #[default]
    Invalid = 0,

    /// Clearnet. **The only host-capped zone.**
    Public = 1,

    /// I2P. Exempt — see [`InboundZone::is_host_capped`].
    I2p = 2,

    /// Tor. Exempt — see [`InboundZone::is_host_capped`].
    Tor = 3,
}

impl InboundZone {
    /// Total: any byte outside the named set is [`InboundZone::Invalid`],
    /// which is not host-capped. A future zone this binary predates is
    /// therefore exempt rather than capped on a host identity it cannot
    /// interpret.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::Public,
            2 => Self::I2p,
            3 => Self::Tor,
            _ => Self::Invalid,
        }
    }

    /// Is a per-host inbound cap meaningful on this zone at all?
    ///
    /// **True for the public zone only, and the exemption is a necessity
    /// rather than a leniency.** An anonymity zone's inbound peers do not
    /// carry distinguishable host identities: the tor zone calls
    /// `set_default_remote(net::tor_address::unknown())`, so *every* inbound
    /// onion peer presents as the same address, and `tor_address::is_same_host`
    /// is a `strcmp` of those host strings. Applying a cap of 1 there would
    /// not bound one host — it would bound the entire tor inbound population
    /// at one connection.
    ///
    /// A future reader meeting the C++ early-return will read it as a gap.
    /// It is not; it is the only correct behaviour given what an anonymity
    /// zone's addresses mean.
    #[must_use]
    pub const fn is_host_capped(self) -> bool {
        matches!(self, Self::Public)
    }

    /// The C ABI byte.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        self as u8
    }
}

/// How many inbound connections one remote host may hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostInboundCap(u32);

impl HostInboundCap {
    /// The inherited default, **unchanged**: one inbound connection per host.
    ///
    /// This is the value that made two daemons behind one NAT unable to both
    /// reach the same peer (PWD-I7's observation). It is preserved here
    /// deliberately — the forward cut moves *ownership*, not the number.
    pub const DEFAULT: Self = Self(1);

    /// The operator's `--max-connections-per-ip`.
    #[must_use]
    pub const fn from_configured(cap: u32) -> Self {
        Self(cap)
    }

    /// The configured value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// May a **further** inbound connection from a host that already holds
    /// `existing_same_host_inbound` of them be admitted?
    ///
    /// **The candidate is not counted in `existing_same_host_inbound`.** The
    /// caller asks before its connection list is updated — the C++ call site
    /// carries that note twice, and it is load-bearing: counting the
    /// candidate would refuse the *first* connection from every host at the
    /// default cap of 1.
    ///
    /// A cap of 0 admits nothing, which is what `--max-connections-per-ip 0`
    /// has always meant.
    #[must_use]
    pub const fn admits(self, existing_same_host_inbound: u32) -> bool {
        existing_same_host_inbound < self.0
    }

    /// Resolve the operator's `--max-connections-per-ip` as it arrives from a
    /// command line: a **signed** value where anything negative is the
    /// *sentinel* meaning "unset, use the default".
    ///
    /// The signedness is load-bearing and is why this is not a `u32` in the
    /// first place: **`0` is a legal choice** meaning *refuse every inbound
    /// connection*, so it cannot double as "unset".
    ///
    /// Values above `u32::MAX` **saturate** rather than wrap. A wrap would
    /// turn a large cap into a small one — silently, and in the refusing
    /// direction — which is the failure mode this whole row exists about.
    /// Not `const`, and deliberately cast-free: `u32::try_from(..).unwrap_or`
    /// *is* the saturation rule, where an `as` cast would need two clippy
    /// suppressions to say the same thing less clearly. A suppression here
    /// would be silencing the check exactly where it is right.
    #[must_use]
    pub fn resolve(configured: i64) -> Self {
        if configured < 0 {
            Self::DEFAULT
        } else {
            Self(u32::try_from(configured).unwrap_or(u32::MAX))
        }
    }
}

impl Default for HostInboundCap {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The observation, as a test: daemon A holds the slot, daemon B is
    /// refused, and raising the cap to 2 admits it.
    ///
    /// Red edit: `<` → `<=` in [`HostInboundCap::admits`].
    #[test]
    fn a_second_inbound_from_one_host_is_refused_at_one_and_admitted_at_two() {
        let default = HostInboundCap::DEFAULT;
        assert!(default.admits(0), "the first connection from a host");
        assert!(
            !default.admits(1),
            "a host already holding one inbound connection took the only slot: \
             this is the NAT failure PWD-I7 records"
        );

        let two = HostInboundCap::from_configured(2);
        assert!(two.admits(0));
        assert!(two.admits(1), "raising the cap admits the second daemon");
        assert!(!two.admits(2), "and still bounds the third");
    }

    /// The sentinel's three arms, including the one that is a trap: `0` is a
    /// real choice and must not be swallowed as "unset".
    ///
    /// Red edit: `configured < 0` -> `configured <= 0` in [`HostInboundCap::resolve`].
    #[test]
    fn resolve_treats_negative_as_unset_and_zero_as_a_choice() {
        assert_eq!(HostInboundCap::resolve(-1), HostInboundCap::DEFAULT);
        assert_eq!(HostInboundCap::resolve(i64::MIN), HostInboundCap::DEFAULT);
        assert_eq!(
            HostInboundCap::resolve(0).get(),
            0,
            "--max-connections-per-ip 0 means refuse every inbound connection; \
             swallowing it as unset hands the operator the default instead"
        );
        assert_eq!(HostInboundCap::resolve(2).get(), 2);
    }

    /// Above `u32::MAX` saturates. A wrap would turn a large cap into a small
    /// one in the refusing direction.
    ///
    /// Red edit: `configured as u32` without the upper guard.
    #[test]
    fn resolve_saturates_rather_than_wrapping() {
        assert_eq!(HostInboundCap::resolve(i64::from(u32::MAX)).get(), u32::MAX);
        assert_eq!(
            HostInboundCap::resolve(i64::from(u32::MAX) + 1).get(),
            u32::MAX
        );
        assert_eq!(HostInboundCap::resolve(i64::MAX).get(), u32::MAX);
    }

    /// Control: a cap of 0 refuses everything, so `admits` is not a predicate
    /// that merely says yes.
    ///
    /// Red edit: make `admits` return `true` unconditionally.
    #[test]
    fn a_zero_cap_admits_nothing() {
        let none = HostInboundCap::from_configured(0);
        assert!(!none.admits(0));
        assert!(!none.admits(1));
    }

    /// The default is the inherited value and has not moved. The number is
    /// the maintainer's to rule (PWD-I7 owed-back Q1); this pins that the
    /// forward cut did not quietly change it.
    ///
    /// Red edit: any change to [`HostInboundCap::DEFAULT`].
    #[test]
    fn the_default_cap_is_the_inherited_one() {
        assert_eq!(HostInboundCap::DEFAULT.get(), 1);
        assert_eq!(HostInboundCap::default(), HostInboundCap::DEFAULT);
    }

    /// The zone exemption, over the whole byte domain rather than a restated
    /// discriminant list.
    ///
    /// Red edit: add `| Self::Tor` to [`InboundZone::is_host_capped`].
    #[test]
    fn the_public_zone_is_host_capped_and_no_other_byte_is() {
        for byte in 0..=u8::MAX {
            let zone = InboundZone::from_byte(byte);
            assert_eq!(
                zone.is_host_capped(),
                byte == 1,
                "byte {byte} resolved to {zone:?}"
            );
        }
    }

    /// An anonymity zone must never be host-capped: its inbound peers all
    /// present as one address, so a cap of 1 would bound the whole population.
    ///
    /// Red edit: as above.
    #[test]
    fn an_anonymity_zone_is_never_host_capped() {
        assert!(!InboundZone::Tor.is_host_capped());
        assert!(!InboundZone::I2p.is_host_capped());
    }

    /// Unknown bytes round-trip to `Invalid` and stay exempt — the inherited
    /// `!= public_` test behaved this way and a future zone must not be
    /// capped on a host identity this binary cannot interpret.
    ///
    /// Red edit: make `from_byte`'s fallback `Self::Public`.
    #[test]
    fn an_unrecognised_zone_byte_is_invalid_and_exempt() {
        assert_eq!(InboundZone::from_byte(4), InboundZone::Invalid);
        assert_eq!(InboundZone::from_byte(200), InboundZone::Invalid);
        assert!(!InboundZone::from_byte(4).is_host_capped());
    }

    /// The named discriminants are the C ABI and are pinned by
    /// `static_assert` on the C++ side; pin them here too so the two cannot
    /// drift silently.
    ///
    /// Red edit: renumber any variant.
    #[test]
    fn the_zone_discriminants_are_the_c_abi() {
        assert_eq!(InboundZone::Invalid.to_byte(), 0);
        assert_eq!(InboundZone::Public.to_byte(), 1);
        assert_eq!(InboundZone::I2p.to_byte(), 2);
        assert_eq!(InboundZone::Tor.to_byte(), 3);
    }

    /// Rule 71, structurally: the admission decision is a function of
    /// `(zone, existing, cap)` and nothing else. There is no nettype input,
    /// so the same inputs give the same verdict on every network.
    ///
    /// This test cannot be made red by editing a nettype branch, because
    /// there is nowhere to put one — that is the point. It goes red if
    /// `admits` stops being a pure function of its arguments.
    #[test]
    fn admission_is_a_pure_function_of_zone_count_and_cap() {
        for cap in 0..4u32 {
            for existing in 0..4u32 {
                let a = HostInboundCap::from_configured(cap).admits(existing);
                let b = HostInboundCap::from_configured(cap).admits(existing);
                assert_eq!(a, b, "cap={cap} existing={existing}");
                assert_eq!(a, existing < cap, "cap={cap} existing={existing}");
            }
        }
    }
}
