// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Once-at-origin zone routing (Q12-D5a, `Q12_D6A_PEER_DISCOVERY_RUN.md`
//! §§12, 18) — the decision family that chooses where `send_txs` places a
//! transaction.
//!
//! # Moved from C++ (rule 20), and what stayed behind
//!
//! These functions were `constexpr` helpers in
//! `src/cryptonote_protocol/enums.h`. They are pure transforms —
//! `(relay method, arrival zone) → decision` — which is the clearest case for
//! Rust ownership, and their governing parameter was *already* Rust-owned
//! (`MIXED_ELIGIBILITY_PCT_HUNDREDTHS` in `shekyl-relay-privacy`), so the
//! split put a decision and its parameter under different owners.
//!
//! C++ keeps exactly one thing: the `zone_route` **token class** — private
//! constructor, single friend — because the compile-time guarantee it provides
//! ("`send_txs` cannot be called without a decision only `once_at_origin_route`
//! can construct") has to live where `send_txs` lives. Its body now forwards
//! here; the semantics have one owner.
//!
//! # The invariant this family carries (§30.5, §18.3)
//!
//! Originated traffic that chose the anonymity zone **fail-closes**: if the
//! zone is unusable the node sends *nothing*, and never falls back to
//! clearnet — re-broadcasting a user's own transaction from their own IP is
//! the first-spy case this arc exists to prevent. In §18.3's terms, the one
//! path that puts originated traffic on clearnet is the roll saying clearnet
//! *by design* ([`originated_zone_from_anonymity_roll`] with
//! `take_anonymity = false`), never a fallback an adversary can force.

use core::fmt;

// Compile-time pin of every discriminant to the shared byte contract. The C++
// side pins ITS enums to the same literals (`enums.h` static_asserts), so a
// renumbering on either side is a compile error on that side — neither side
// can observe the other at compile time, and without these pins a Rust
// renumbering whose `from_byte` moved with it would slide through both
// builds. The runtime witness that the two compile-time pins describe the
// same wire is the unchanged `levin.cpp` gtest table, which crosses the real
// FFI with real C++ enum values.
const _: () = {
    assert!(RelayMethod::None as u8 == 0);
    assert!(RelayMethod::Local as u8 == 1);
    assert!(RelayMethod::Stem as u8 == 2);
    assert!(RelayMethod::Fluff as u8 == 3);
    assert!(RelayMethod::Block as u8 == 4);
    assert!(NetZone::Invalid as u8 == 0);
    assert!(NetZone::Public as u8 == 1);
    assert!(NetZone::I2p as u8 == 2);
    assert!(NetZone::Tor as u8 == 3);
    assert!(ZoneRouteDecision::KeepArrival as u8 == 0);
    assert!(ZoneRouteDecision::AnonymityFailClosed as u8 == 1);
    assert!(ZoneRouteDecision::PublicClearnet as u8 == 2);
    assert!(ZoneRouteDecision::BroadcastAllZones as u8 == 3);
};

/// How a transaction was received, mirrored from C++ `cryptonote::relay_method`
/// **by value and test, not by include**: the C++ side `static_assert`s each
/// variant's byte against this contract at the FFI seam, so a renumbering on
/// either side is a compile error there rather than a silent remap here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RelayMethod {
    /// Received via RPC with `do_not_relay` set.
    None = 0,
    /// Received via RPC; trying to send over i2p/tor. The class that routes
    /// the txpool backstop to fail-closed rather than `public_req`.
    Local = 1,
    /// Received/sent using Dandelion++ stem.
    Stem = 2,
    /// Received/sent using Dandelion++ fluff — the deliberate exit (§59.1).
    Fluff = 3,
    /// Received in a block.
    Block = 4,
}

impl RelayMethod {
    /// Byte-contract decode. `None` on an unknown byte — the FFI layer maps
    /// that to the fail-closed arm rather than guessing a semantics.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::None),
            1 => Some(Self::Local),
            2 => Some(Self::Stem),
            3 => Some(Self::Fluff),
            4 => Some(Self::Block),
            _ => None,
        }
    }
}

/// The network zone a transaction arrived on (or, for originated traffic, the
/// zone the origination roll chose). Mirrors `epee::net_utils::zone` by value
/// and `static_assert`, same contract discipline as [`RelayMethod`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NetZone {
    /// No zone — for originated traffic this is the roll saying "take
    /// anonymity", resolved by the caller's own zone map, fail-closed.
    Invalid = 0,
    /// The clear internet.
    Public = 1,
    /// I2P.
    I2p = 2,
    /// Tor.
    Tor = 3,
}

impl NetZone {
    /// Byte-contract decode; `None` on an unknown byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Invalid),
            1 => Some(Self::Public),
            2 => Some(Self::I2p),
            3 => Some(Self::Tor),
            _ => None,
        }
    }

    /// A real anonymity network — not clearnet, not absent.
    #[must_use]
    pub const fn is_anonymity(self) -> bool {
        matches!(self, Self::I2p | Self::Tor)
    }
}

/// Where `send_txs` places the transaction. The C++ `zone_route` token wraps
/// exactly this value; its byte contract is `static_assert`ed at the seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ZoneRouteDecision {
    /// Still-stemming on a real anonymity origin: stay there (R-1 coherence,
    /// §89.2). No re-roll — re-rolling per hop was the one-way absorption
    /// Q12-D5a deleted.
    KeepArrival = 0,
    /// Originated traffic chose anonymity (or the pool re-relays `Local`):
    /// take the zone, **send nothing if it is unusable** (§30.5). Never
    /// clearnet.
    AnonymityFailClosed = 1,
    /// Clearnet inherit, or the roll choosing clearnet by design.
    ///
    /// **No longer the fluff exit** — see [`Self::BroadcastAllZones`] (§91).
    PublicClearnet = 2,
    /// **Design A (§91): a fluff goes to EVERY configured zone.**
    ///
    /// Transport is a parameter, not a topology: clearnet, Tor and i2p are
    /// link classes in one propagation graph, so a fluff floods all of them.
    ///
    /// Before §91 a fluff took [`Self::PublicClearnet`], which is
    /// `send(*m_network_zones.begin())` — the clearnet zone, **singular**. That
    /// made the anonymity zone a depth-one injection point into clearnet: a
    /// Tor-only node saw only anonymity-originated traffic, so it could not
    /// maintain a mempool, disarm embargoes against the real flood, or mine on
    /// a current template. **Tor-only was not a working posture — by routing,
    /// not by ruling** (§91.1).
    BroadcastAllZones = 3,
}

impl fmt::Display for ZoneRouteDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::KeepArrival => "keep_arrival",
            Self::AnonymityFailClosed => "anonymity_fail_closed",
            Self::PublicClearnet => "public_clearnet",
            Self::BroadcastAllZones => "broadcast_all_zones",
        })
    }
}

/// Pre-fluff relay methods (stem / local). Fluff is the deliberate exit from
/// the anonymity zone: once a transaction fluffs it must leave, or coherence
/// would strand it in the anonymity subgraph (§59.1).
#[must_use]
pub const fn is_pre_fluff_relay(method: RelayMethod) -> bool {
    matches!(method, RelayMethod::Stem | RelayMethod::Local)
}

/// Originated traffic on an anonymity zone keeps its `Local` txpool record,
/// whatever the transport did with it.
///
/// §30.5 forbids the backstop falling out to the public zone. `Local` is the
/// class that prevents it: the pool re-relay routes `Local` to the private
/// request at [`NetZone::Invalid`], which [`once_at_origin_route`] maps to
/// [`ZoneRouteDecision::AnonymityFailClosed`]. This matters because the
/// txpool's method upgrade is monotone — one record of `Stem` or `Fluff`
/// moves the entry out of `Local` permanently, and the next pool re-relay
/// puts the user's own transaction on the clear internet.
///
/// Relayed traffic is excluded deliberately: it records `Stem` so the
/// per-zone embargo is drawn (§89.2), and clearnet was always that traffic's
/// home. Clearnet origins are excluded too — their home *is* clearnet.
#[must_use]
pub const fn originated_stays_in_zone(tx_relay: RelayMethod, nzone: NetZone) -> bool {
    matches!(tx_relay, RelayMethod::Local) && nzone.is_anonymity()
}

/// R-1 coherence: keep a still-stemming transaction on its arrival anonymity
/// zone (no re-roll).
///
/// True only when the method is pre-fluff **and** the arrival zone is a real
/// anonymity network. Clearnet never coheres to itself via this path; absent
/// origin never coheres; fluff never coheres (liveness exit). The caller
/// still checks that the zone is present in the local zone map before
/// sending.
#[must_use]
pub const fn r1_coherence_keeps_origin(tx_relay: RelayMethod, origin: NetZone) -> bool {
    is_pre_fluff_relay(tx_relay) && origin.is_anonymity()
}

/// The Q12-D5a once-at-origin routing decision — the single constructor of
/// the C++ `zone_route` token's value.
///
/// What edit reds the table (`zone_route` tests here, and the unchanged
/// `levin.cpp` gtest as the migration oracle): returning
/// [`ZoneRouteDecision::PublicClearnet`] from the coherence arm. What edit
/// fails to compile in C++: constructing a `zone_route` anywhere except its
/// forwarding `once_at_origin_route`, or calling `send_txs` without one.
#[must_use]
pub const fn once_at_origin_route(tx_relay: RelayMethod, origin: NetZone) -> ZoneRouteDecision {
    // §91 Design A: a fluff floods every link class, whatever it arrived on.
    // Checked FIRST because fluff can never cohere (`is_pre_fluff_relay` is
    // `Stem | Local`), so the coherence arm below would never claim it — but
    // stating the fluff rule first is what makes the ordering an assertion
    // rather than a coincidence of the arms beneath it.
    if matches!(tx_relay, RelayMethod::Fluff) {
        return ZoneRouteDecision::BroadcastAllZones;
    }
    if r1_coherence_keeps_origin(tx_relay, origin) {
        ZoneRouteDecision::KeepArrival
    } else if matches!(origin, NetZone::Invalid) && is_pre_fluff_relay(tx_relay) {
        ZoneRouteDecision::AnonymityFailClosed
    } else {
        ZoneRouteDecision::PublicClearnet
    }
}

/// Map the origination roll onto the zone argument `send_txs` reads.
///
/// `true` (take anonymity) → [`NetZone::Invalid`], which
/// [`once_at_origin_route`] treats as fail-closed. `false` (clearnet **by
/// design**) → [`NetZone::Public`].
///
/// These two must stay distinguishable from "chose anon, zone unusable": that
/// path never produces a `Public` origin argument — it sends nothing. Pool
/// re-relays of `Local` keep passing `Invalid` and do **not** re-roll; they
/// share the fail-closed arm, which is why the roll lives at first
/// origination rather than on every nil-source call into `send_txs`.
#[must_use]
pub const fn originated_zone_from_anonymity_roll(take_anonymity: bool) -> NetZone {
    if take_anonymity {
        NetZone::Invalid
    } else {
        NetZone::Public
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const METHODS: [RelayMethod; 5] = [
        RelayMethod::None,
        RelayMethod::Local,
        RelayMethod::Stem,
        RelayMethod::Fluff,
        RelayMethod::Block,
    ];
    const ZONES: [NetZone; 4] = [
        NetZone::Invalid,
        NetZone::Public,
        NetZone::I2p,
        NetZone::Tor,
    ];

    /// The full 5 × 4 truth table, written as data rather than re-derived, so
    /// a change to any arm reds a named row. This SUPERSETS the C++
    /// `levin.cpp` tables, which stay in place unchanged as the migration
    /// oracle.
    #[test]
    fn once_at_origin_route_full_table() {
        use RelayMethod as M;
        use ZoneRouteDecision as D;

        for &method in &METHODS {
            for &zone in &ZONES {
                let expect = match (method, zone) {
                    // Coherence: still-stemming on a real anonymity origin.
                    (M::Stem | M::Local, NetZone::I2p | NetZone::Tor) => D::KeepArrival,
                    // Originated chose anon (or pool re-relay of Local):
                    // fail closed, never clearnet (§30.5).
                    (M::Stem | M::Local, NetZone::Invalid) => D::AnonymityFailClosed,
                    // §91 Design A: a fluff floods every configured zone.
                    (M::Fluff, _) => D::BroadcastAllZones,
                    // Everything else exits public: clearnet inherit and the
                    // non-relay classes.
                    _ => D::PublicClearnet,
                };
                assert_eq!(
                    once_at_origin_route(method, zone),
                    expect,
                    "({method:?}, {zone:?})"
                );
            }
        }
    }

    /// §30.5 / §18.3, armed exhaustively: no pre-fluff method with an absent
    /// origin ever routes to clearnet. This is the fail-closed-never-fallback
    /// invariant — the one behavior the achieved count is permitted to leave
    /// in place at degree 0 (§18.3's named exception), and the reversal
    /// §89.8.5 warns a future reader against.
    #[test]
    fn fail_closed_is_never_a_clearnet_fallback() {
        for &method in &METHODS {
            if is_pre_fluff_relay(method) {
                assert_eq!(
                    once_at_origin_route(method, NetZone::Invalid),
                    ZoneRouteDecision::AnonymityFailClosed,
                    "{method:?} at Invalid must send NOTHING, not fall back"
                );
            }
        }
    }

    /// Fluff is the exit on every origin — coherence would strand it (§59.1).
    #[test]
    fn fluff_never_coheres() {
        for &zone in &ZONES {
            assert!(!r1_coherence_keeps_origin(RelayMethod::Fluff, zone));
            // Coherence is still refused — that is the invariant. What §91
            // changed is where a fluff goes once refused: every zone, not
            // clearnet alone.
            assert_eq!(
                once_at_origin_route(RelayMethod::Fluff, zone),
                ZoneRouteDecision::BroadcastAllZones
            );
        }
    }

    /// The C++ `r1_coherence` witness table, ported line for line.
    #[test]
    fn r1_coherence_table() {
        for &m in &[RelayMethod::Stem, RelayMethod::Local] {
            assert!(!r1_coherence_keeps_origin(m, NetZone::Public));
            assert!(!r1_coherence_keeps_origin(m, NetZone::Invalid));
            assert!(r1_coherence_keeps_origin(m, NetZone::I2p));
            assert!(r1_coherence_keeps_origin(m, NetZone::Tor));
            assert!(is_pre_fluff_relay(m));
        }
        assert!(!r1_coherence_keeps_origin(RelayMethod::None, NetZone::Tor));
        assert!(!r1_coherence_keeps_origin(RelayMethod::Block, NetZone::Tor));
        assert!(!is_pre_fluff_relay(RelayMethod::Fluff));
    }

    /// `originated_stays_in_zone` is `Local`-only and anonymity-only — the
    /// §89.8 fix, exhaustively.
    #[test]
    fn originated_stays_in_zone_is_local_and_anonymity_only() {
        for &method in &METHODS {
            for &zone in &ZONES {
                let expect = method == RelayMethod::Local && zone.is_anonymity();
                assert_eq!(
                    originated_stays_in_zone(method, zone),
                    expect,
                    "({method:?}, {zone:?})"
                );
            }
        }
    }

    /// The roll mapping, and the distinguishability it must preserve: `true`
    /// never yields `Public` (that would erase the design/fallback
    /// distinction §89.8.5 warns about).
    #[test]
    fn roll_mapping_preserves_the_design_fallback_distinction() {
        assert_eq!(originated_zone_from_anonymity_roll(true), NetZone::Invalid);
        assert_eq!(originated_zone_from_anonymity_roll(false), NetZone::Public);
    }

    /// Byte contracts are total on the defined range and reject outside it.
    #[test]
    fn byte_contracts() {
        for &m in &METHODS {
            assert_eq!(RelayMethod::from_byte(m as u8), Some(m));
        }
        for &z in &ZONES {
            assert_eq!(NetZone::from_byte(z as u8), Some(z));
        }
        assert_eq!(RelayMethod::from_byte(5), None);
        assert_eq!(NetZone::from_byte(4), None);
    }

    /// §91: a fluff floods every zone, from every zone. Asserted as its own
    /// row because the whole Design A ruling reduces to this one mapping, and
    /// a reversion to `PublicClearnet` re-creates the depth-one injection that
    /// made Tor-only unworkable (§91.1).
    #[test]
    fn a_fluff_broadcasts_from_every_zone() {
        for &zone in &ZONES {
            assert_eq!(
                once_at_origin_route(RelayMethod::Fluff, zone),
                ZoneRouteDecision::BroadcastAllZones,
                "fluff arriving on {zone:?} must flood every zone (§91)"
            );
        }
    }
}
