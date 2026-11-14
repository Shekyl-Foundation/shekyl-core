// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon RPC's grants (`docs/design/RPC_CHANNEL.md` §6.1).
//!
//! A grant is a set of facts or actions a connection may ask for. A
//! connection holds a [`GrantSet`]; an operator names a [`Preset`] or a list
//! of grants when enrolling a key. Two classes are not grants, host-only data
//! and the armed test levers, and live in the method table's policy column,
//! not here.
//!
//! The grant set is also a wire value: the channel's message 3 and message 4
//! payloads carry one (`RPC_CHANNEL.md` §6.2, RT-O31). Which bit is which
//! grant is [`Grant::bit`], a constant pinned by a known answer in this
//! crate's tests, so editing the design document never changes the wire. A
//! set read from the wire with a bit outside the known grants is refused,
//! never ignored ([`GrantSet::from_bits`]).
//!
//! `option show` names a row's grant with the same type (IG-9, RT-O24): one
//! vocabulary for the RPC and the option table.

#![no_std]
#![deny(unsafe_code)]

/// One grant (`RPC_CHANNEL.md` §6.1's table, in its order).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Grant {
    /// Chain reads.
    Chain,
    /// The relayed pool.
    Pool,
    /// Whether this node is usable now.
    Health,
    /// Facts about this node, each a fingerprint. Holding it holds
    /// [`Grant::Health`] (ruled 2026-10-24: a level of `health`).
    Status,
    /// The peer graph.
    Peers,
    /// Submitting a transaction.
    Submit,
    /// An external miner's loop.
    MiningWork,
    /// This node's own miner.
    MiningControl,
    /// Bans.
    Bans,
    /// Control of the node.
    Node,
    /// The node's configuration.
    Config,
    /// Enrolling and revoking keys (RT-O9.1).
    Enrol,
}

impl Grant {
    /// Every grant, in the table's order.
    pub const ALL: [Self; 12] = [
        Self::Chain,
        Self::Pool,
        Self::Health,
        Self::Status,
        Self::Peers,
        Self::Submit,
        Self::MiningWork,
        Self::MiningControl,
        Self::Bans,
        Self::Node,
        Self::Config,
        Self::Enrol,
    ];

    /// This grant's bit in a [`GrantSet`] on the wire. Fixed: a change is a
    /// wire change, and the known-answer test fails.
    #[must_use]
    pub const fn bit(self) -> u16 {
        match self {
            Self::Chain => 1 << 0,
            Self::Pool => 1 << 1,
            Self::Health => 1 << 2,
            Self::Status => 1 << 3,
            Self::Peers => 1 << 4,
            Self::Submit => 1 << 5,
            Self::MiningWork => 1 << 6,
            Self::MiningControl => 1 << 7,
            Self::Bans => 1 << 8,
            Self::Node => 1 << 9,
            Self::Config => 1 << 10,
            Self::Enrol => 1 << 11,
        }
    }

    /// The grant's name as an operator writes it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Chain => "chain",
            Self::Pool => "pool",
            Self::Health => "health",
            Self::Status => "status",
            Self::Peers => "peers",
            Self::Submit => "submit",
            Self::MiningWork => "mining-work",
            Self::MiningControl => "mining-control",
            Self::Bans => "bans",
            Self::Node => "node",
            Self::Config => "config",
            Self::Enrol => "enrol",
        }
    }

    /// The grant an operator's name names.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|grant| grant.name() == name)
    }

    /// Whether an option row may name this grant (RT-O24). A row is
    /// disclosed under health, status, peers, or config, and under nothing
    /// else: chain, pool, and the action grants are not option rows.
    #[must_use]
    pub const fn discloses_option_row(self) -> bool {
        matches!(
            self,
            Self::Health | Self::Status | Self::Peers | Self::Config
        )
    }
}

/// A set of grants: what a connection holds, a ceiling, or a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct GrantSet(u16);

/// A wire value with a bit outside the known grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownGrantBits(pub u16);

impl GrantSet {
    /// No grant.
    pub const EMPTY: Self = Self(0);

    /// Every grant: the `admin` preset.
    pub const ALL: Self = {
        let mut bits = 0;
        let mut i = 0;
        while i < Grant::ALL.len() {
            bits |= Grant::ALL[i].bit();
            i += 1;
        }
        Self(bits)
    };

    /// The set of exactly these grants.
    #[must_use]
    pub const fn of(grants: &[Grant]) -> Self {
        let mut bits = 0;
        let mut i = 0;
        while i < grants.len() {
            bits |= grants[i].bit();
            i += 1;
        }
        Self(bits)
    }

    /// Whether the set names `grant` itself.
    #[must_use]
    pub const fn names(self, grant: Grant) -> bool {
        self.0 & grant.bit() != 0
    }

    /// Whether a connection holding this set holds `grant`. Holding
    /// [`Grant::Status`] holds [`Grant::Health`]; otherwise a grant is held
    /// when it is named.
    #[must_use]
    pub const fn holds(self, grant: Grant) -> bool {
        match grant {
            Grant::Health => self.names(Grant::Health) || self.names(Grant::Status),
            _ => self.names(grant),
        }
    }

    /// Both sets' grants.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// A request clamped to a ceiling.
    ///
    /// A grant is in the result when both sets hold it and at least one
    /// names it. Holding is [`Self::holds`], so a `health` request under a
    /// `status` ceiling is `health`. A grant neither side names is not
    /// stored: `status` holds `health`, and `status` clamped to itself
    /// stays `status`.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        let mut bits = 0;
        let mut i = 0;
        while i < Grant::ALL.len() {
            let grant = Grant::ALL[i];
            if (self.names(grant) || other.names(grant)) && self.holds(grant) && other.holds(grant)
            {
                bits |= grant.bit();
            }
            i += 1;
        }
        Self(bits)
    }

    /// Whether every grant this set names is held by `other`.
    ///
    /// `health` is within `status`; `status` is not within `health`.
    #[must_use]
    pub const fn within(self, other: Self) -> bool {
        let mut i = 0;
        while i < Grant::ALL.len() {
            let grant = Grant::ALL[i];
            if self.names(grant) && !other.holds(grant) {
                return false;
            }
            i += 1;
        }
        true
    }

    /// The set's wire bits.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// A set read from the wire. A bit outside the known grants is refused,
    /// never ignored (RT-O31).
    ///
    /// # Errors
    ///
    /// [`UnknownGrantBits`] when `bits` names a bit no grant has.
    pub const fn from_bits(bits: u16) -> Result<Self, UnknownGrantBits> {
        let unknown = bits & !Self::ALL.0;
        if unknown == 0 {
            Ok(Self(bits))
        } else {
            Err(UnknownGrantBits(unknown))
        }
    }

    /// The channel's message-3 or message-4 payload carrying this set
    /// (RT-O31): byte 0 the version, [`PAYLOAD_VERSION`]; bytes 1 and 2 the
    /// bits, little-endian; bytes 3 to 15 zero.
    #[must_use]
    pub const fn to_payload(self) -> [u8; PAYLOAD_LEN] {
        let bits = self.0.to_le_bytes();
        let mut payload = [0u8; PAYLOAD_LEN];
        payload[0] = PAYLOAD_VERSION;
        payload[1] = bits[0];
        payload[2] = bits[1];
        payload
    }

    /// The set a message-3 or message-4 payload carries. Anything but
    /// [`PAYLOAD_LEN`] bytes of [`PAYLOAD_VERSION`] with zero reserved bytes
    /// and known bits is refused, never ignored (RT-O31).
    ///
    /// # Errors
    ///
    /// [`PayloadRefused`], naming what was wrong.
    pub const fn from_payload(payload: &[u8]) -> Result<Self, PayloadRefused> {
        if payload.len() != PAYLOAD_LEN {
            return Err(PayloadRefused::Length);
        }
        if payload[0] != PAYLOAD_VERSION {
            return Err(PayloadRefused::Version(payload[0]));
        }
        let mut at = 3;
        while at < PAYLOAD_LEN {
            if payload[at] != 0 {
                return Err(PayloadRefused::Reserved);
            }
            at += 1;
        }
        match Self::from_bits(u16::from_le_bytes([payload[1], payload[2]])) {
            Ok(set) => Ok(set),
            Err(UnknownGrantBits(bits)) => Err(PayloadRefused::UnknownGrants(bits)),
        }
    }

    /// The grants this set names, in the table's order.
    pub fn iter(self) -> impl Iterator<Item = Grant> {
        Grant::ALL
            .into_iter()
            .filter(move |grant| self.names(*grant))
    }
}

/// The length of the channel's message-3 and message-4 payloads: one
/// length for every grant set, so each message is one size on the wire
/// (RT-O31).
pub const PAYLOAD_LEN: usize = 16;

/// The payload's version, its first byte.
pub const PAYLOAD_VERSION: u8 = 1;

/// Why a message-3 or message-4 payload was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadRefused {
    /// Not [`PAYLOAD_LEN`] bytes.
    Length,
    /// A version this build does not read.
    Version(u8),
    /// A reserved byte is not zero.
    Reserved,
    /// Bits no grant has.
    UnknownGrants(u16),
}

/// What an operator names at enrolment (`RPC_CHANNEL.md` §6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preset {
    /// `chain` + `pool` + `health`.
    View,
    /// `view` + `submit` + `status`.
    Wallet,
    /// `view` + `mining-work`.
    Miner,
    /// Every grant, `enrol` included.
    Admin,
}

impl Preset {
    /// The preset's grants.
    #[must_use]
    pub const fn grants(self) -> GrantSet {
        const VIEW: GrantSet = GrantSet::of(&[Grant::Chain, Grant::Pool, Grant::Health]);
        match self {
            Self::View => VIEW,
            Self::Wallet => VIEW.union(GrantSet::of(&[Grant::Submit, Grant::Status])),
            Self::Miner => VIEW.union(GrantSet::of(&[Grant::MiningWork])),
            Self::Admin => GrantSet::ALL,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire bits, pinned (rule 30). Changing one is a wire change: this
    /// test is written from the table, not from `bit()`.
    #[test]
    fn the_wire_bits_are_pinned() {
        let pinned: [(Grant, u16); 12] = [
            (Grant::Chain, 0x0001),
            (Grant::Pool, 0x0002),
            (Grant::Health, 0x0004),
            (Grant::Status, 0x0008),
            (Grant::Peers, 0x0010),
            (Grant::Submit, 0x0020),
            (Grant::MiningWork, 0x0040),
            (Grant::MiningControl, 0x0080),
            (Grant::Bans, 0x0100),
            (Grant::Node, 0x0200),
            (Grant::Config, 0x0400),
            (Grant::Enrol, 0x0800),
        ];
        for (grant, bit) in pinned {
            assert_eq!(grant.bit(), bit, "{grant:?}");
        }
        assert_eq!(GrantSet::ALL.bits(), 0x0FFF);
    }

    #[test]
    fn every_grant_has_its_own_bit_and_name() {
        for (i, a) in Grant::ALL.iter().enumerate() {
            assert_eq!(a.bit().count_ones(), 1, "{a:?}");
            assert_eq!(Grant::from_name(a.name()), Some(*a));
            for b in &Grant::ALL[i + 1..] {
                assert_ne!(a.bit(), b.bit());
                assert_ne!(a.name(), b.name());
            }
        }
        assert_eq!(Grant::from_name("everything"), None);
    }

    #[test]
    fn status_holds_health_and_nothing_else_implies() {
        let status = GrantSet::of(&[Grant::Status]);
        assert!(status.holds(Grant::Health));
        assert!(!status.names(Grant::Health));
        let health = GrantSet::of(&[Grant::Health]);
        assert!(!health.holds(Grant::Status));
        for grant in Grant::ALL {
            if grant != Grant::Health && grant != Grant::Status {
                assert!(!status.holds(grant), "{grant:?}");
            }
        }
    }

    #[test]
    fn the_payload_is_pinned_and_round_trips() {
        // RT-O31: version 1, the view preset's bits little-endian, zeros.
        let view = Preset::View.grants().to_payload();
        assert_eq!(view, [1, 0x07, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let admin = GrantSet::ALL.to_payload();
        assert_eq!(&admin[..3], &[1, 0xFF, 0x0F]);
        for set in [GrantSet::EMPTY, Preset::Wallet.grants(), GrantSet::ALL] {
            assert_eq!(GrantSet::from_payload(&set.to_payload()), Ok(set));
        }
    }

    /// Each way a payload can be wrong is refused. Red edit: skip the
    /// reserved-byte loop, and the payload with byte 15 set is read.
    #[test]
    fn a_payload_that_is_not_the_format_is_refused() {
        let good = GrantSet::ALL.to_payload();
        assert_eq!(
            GrantSet::from_payload(&good[..15]),
            Err(PayloadRefused::Length)
        );
        let mut version = good;
        version[0] = 2;
        assert_eq!(
            GrantSet::from_payload(&version),
            Err(PayloadRefused::Version(2))
        );
        let mut reserved = good;
        reserved[15] = 1;
        assert_eq!(
            GrantSet::from_payload(&reserved),
            Err(PayloadRefused::Reserved)
        );
        let mut unknown = good;
        unknown[2] = 0x1F;
        assert_eq!(
            GrantSet::from_payload(&unknown),
            Err(PayloadRefused::UnknownGrants(0x1000))
        );
    }

    #[test]
    fn unknown_wire_bits_are_refused() {
        assert_eq!(GrantSet::from_bits(0x0FFF), Ok(GrantSet::ALL));
        assert_eq!(GrantSet::from_bits(0), Ok(GrantSet::EMPTY));
        assert_eq!(GrantSet::from_bits(0x1000), Err(UnknownGrantBits(0x1000)));
        assert_eq!(GrantSet::from_bits(0x8005), Err(UnknownGrantBits(0x8000)));
    }

    #[test]
    fn the_presets_are_the_tables() {
        use Grant::*;
        assert_eq!(Preset::View.grants(), GrantSet::of(&[Chain, Pool, Health]));
        assert_eq!(
            Preset::Wallet.grants(),
            GrantSet::of(&[Chain, Pool, Health, Submit, Status])
        );
        assert_eq!(
            Preset::Miner.grants(),
            GrantSet::of(&[Chain, Pool, Health, MiningWork])
        );
        assert_eq!(Preset::Admin.grants(), GrantSet::ALL);
        // `peers` and `config` are in no preset but `admin`.
        for preset in [Preset::View, Preset::Wallet, Preset::Miner] {
            assert!(!preset.grants().names(Peers), "{preset:?}");
            assert!(!preset.grants().names(Config), "{preset:?}");
            assert!(!preset.grants().names(Enrol), "{preset:?}");
        }
    }

    #[test]
    fn a_request_is_clamped_to_its_ceiling() {
        use Grant::*;
        let request = GrantSet::of(&[Chain, Submit, Peers]);
        let ceiling = Preset::Wallet.grants();
        let effective = request.intersection(ceiling);
        assert_eq!(effective, GrantSet::of(&[Chain, Submit]));
        assert!(effective.within(ceiling));
        assert!(!request.within(ceiling));
    }

    /// Clamping follows [`GrantSet::holds`] and does not store a grant
    /// neither side names. Both operand orders, because the operation is
    /// commutative.
    #[test]
    fn clamping_honors_status_holding_health() {
        let health = GrantSet::of(&[Grant::Health]);
        let status = GrantSet::of(&[Grant::Status]);
        assert_eq!(health.intersection(status), health);
        assert_eq!(status.intersection(health), health);
        assert_eq!(status.intersection(status), status);
        assert!(!status.intersection(status).names(Grant::Health));
        assert_eq!(health.intersection(health), health);
        assert!(health.within(status));
        assert!(!status.within(health));
        assert!(status.within(status));
        assert_eq!(status.union(status), status);
        assert!(health.union(status).names(Grant::Health));
        assert!(health.union(status).names(Grant::Status));
    }

    /// The four grants an option row may name, written out. The other eight
    /// are actions or chain facts, not a disclosure of a row.
    #[test]
    fn an_option_row_is_disclosed_by_four_grants() {
        let disclosing = [Grant::Health, Grant::Status, Grant::Peers, Grant::Config];
        for grant in Grant::ALL {
            assert_eq!(
                grant.discloses_option_row(),
                disclosing.contains(&grant),
                "{grant:?}"
            );
        }
    }
}
