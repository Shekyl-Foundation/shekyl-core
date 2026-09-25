// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The relay vocabulary two crates need — DRS-E1 S-POOL (`DRS_E1_SPOOL.md`
//! §3.4, `SPL-Q6` RULED 2026-09-24).
//!
//! [`RelayMethod`] and [`NetZone`] were born in `shekyl-relay::zone_route`
//! as the FFI seam's words: an arrival class handed in, a routing plan
//! handed out, each byte-pinned to the C++ enum it mirrors
//! (`cryptonote::relay_method`, `epee::net_utils::zone`). The daemon's pool
//! store needs the same words and cannot take `shekyl-relay` — a relay
//! scheduler with an async driver — as a dependency, so they live here and
//! `shekyl-relay` re-exports them (rule 18: a word two crates need lives
//! below both; `SCU-Q2`, `SAR-Q2`).
//!
//! # What these enums are, and are not
//!
//! They are the **seam's** vocabulary. The pool *record* does not persist a
//! `RelayMethod`: `DAEMON_RELAY_PRIVACY.md` §92.4 unbundled `Local` into
//! provenance (permanent), re-broadcast responsibility (disarmed by
//! observation) and a class, and the record carries those as three fields
//! with three lifetimes (`shekyl-chain-store::pool`, `SPL-Q9`); the seam
//! derives the byte from them where C++ still speaks it (SPL-18).
//!
//! # `None` survives because the enum is shared
//!
//! `relay_method::none` is unreachable in Shekyl — it means "received via
//! RPC with `do_not_relay` set", and there is no such RPC
//! (`src/blockchain_db/blockchain_db.h:123`). The variant stays because the
//! byte contract is pinned at the FFI seam and a mechanical cleanup that
//! deleted it would shift every discriminant under that pin. It guards
//! nothing (`SPL-Q6` as ruled: refusing it at a codec was a guard on the
//! wrong value); what guards the relay state is the decoder below having
//! **no default arm** — SPL-14.
//!
//! # SPL-14 — no relay state is reachable by fall-through
//!
//! The C++ decoder sums four bits and returns `fluff` — *broadcasted*, the
//! leaking direction — for `default: // error case`
//! (`blockchain_db.cpp:132–165`); its own header records that a zeroed
//! record decodes to `fluff` (`blockchain_db.h:126–130`). [`RelayMethod::from_byte`]
//! is exhaustive over the five pinned bytes and returns `None` for
//! anything else; [`Fluff`](RelayMethod::Fluff) is reached only by byte `3`.
//! The precedent in the same subsystem is `shekyl-relay-privacy`'s stem
//! map, which removed a sentinel the C++ used in three roles.

/// How a transaction was received, mirrored from C++ `cryptonote::relay_method`
/// **by value and test, not by include**: the C++ side `static_assert`s each
/// variant's byte against this contract at the FFI seam, so a renumbering on
/// either side is a compile error there rather than a silent remap here.
/// `shekyl-relay::zone_route` carries the Rust-side `const` pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RelayMethod {
    /// Received via RPC with `do_not_relay` set. **Unreachable in Shekyl**
    /// (no such RPC); kept because the byte contract is shared. Matches no
    /// relay category but `All`.
    None = 0,
    /// Originated by this node; trying to send over i2p/tor. The class that
    /// routes the txpool backstop to fail-closed rather than `public_req`.
    /// At the seam only — the record spells it
    /// `RelayState::Originated { phase: Held, .. }` (§92.4).
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
    /// that to the fail-closed arm rather than guessing a semantics, and a
    /// codec refuses the row. Exhaustive over the five pinned bytes; there
    /// is no arm that reaches [`Fluff`](Self::Fluff) but its own (SPL-14).
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

    /// The pinned byte.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    /// The C++ `matches_category` table (`blockchain_db.cpp:51–96`),
    /// transcribed exhaustively on both operands — no `default`, so a new
    /// member of either enum is a compile error here, as `-Werror=switch`
    /// makes it there.
    ///
    /// `Broadcasted` is "the network already knows": `Block` or `Fluff`,
    /// nothing earlier — the leaking direction, so `None`, `Local` and `Stem`
    /// are named in the `false` arm rather than left to a fallback.
    /// `Relayable` is every method but `None`. `All` is every method.
    #[must_use]
    pub const fn matches(self, category: RelayCategory) -> bool {
        match category {
            RelayCategory::All => true,
            RelayCategory::Relayable => !matches!(self, Self::None),
            RelayCategory::Broadcasted => match self {
                Self::None | Self::Local | Self::Stem => false,
                Self::Block | Self::Fluff => true,
            },
        }
    }
}

/// The pool's visibility classes — C++ `relay_category`
/// (`src/blockchain_db/blockchain_db.h:114–141`). A **classifier's
/// operand**, applied by the pool to a [`RelayMethod`]; the store never
/// applies it (`DRS_E1_SPOOL.md` §3.3).
///
/// Three members. `relay_category::legacy` (`broadcasted` + `none`) was
/// deleted from the C++ on 2026-08-24 as having no referent in a
/// pre-genesis coin (`DAEMON_RELAY_PRIVACY.md` §93.4) and is **not** minted
/// here. Never serialized, never crosses the FFI, so no byte pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelayCategory {
    /// Public: received via a block or fluff. What a peer may learn we hold.
    Broadcasted,
    /// Every method but `None`.
    Relayable,
    /// Everything in the pool.
    All,
}

/// The network zone a transaction arrived on (or, for originated traffic, the
/// zone the origination roll chose). Mirrors `epee::net_utils::zone` by value
/// and `static_assert`, same contract discipline as [`RelayMethod`].
///
/// `Invalid == 0` is load-bearing on the C++ side: a pool record written
/// before the zone field existed carries zero there and decodes to "origin
/// unknown" with no migration (`blockchain_db.cpp`, `set_origin_zone`'s
/// `static_assert`). The Rust pool record has no such history, but the pin
/// is the seam's and stays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum NetZone {
    /// No zone — for originated traffic this is the roll saying "take
    /// anonymity", resolved by the caller's own zone map, fail-closed; for
    /// an arrival, "origin unknown".
    Invalid = 0,
    /// The clear internet.
    Public = 1,
    /// I2P.
    I2p = 2,
    /// Tor.
    Tor = 3,
}

impl NetZone {
    /// Byte-contract decode; `None` on an unknown byte. Exhaustive: a fifth
    /// zone is a new arm here, never a masked alias of an existing one.
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

    /// The pinned byte.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    /// A real anonymity network — not clearnet, not absent.
    #[must_use]
    pub const fn is_anonymity(self) -> bool {
        matches!(self, Self::I2p | Self::Tor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every byte outside the five pinned discriminants is refused, and no
    /// byte reaches `Fluff` but `3` (SPL-14).
    #[test]
    fn relay_method_decoder_has_no_fall_through() {
        let mut fluff_bytes = 0;
        for b in 0..=u8::MAX {
            match RelayMethod::from_byte(b) {
                Some(m) => {
                    assert!(b <= 4, "byte {b} decoded to {m:?}");
                    assert_eq!(m.to_byte(), b);
                    if m == RelayMethod::Fluff {
                        fluff_bytes += 1;
                        assert_eq!(b, 3);
                    }
                }
                None => assert!(b > 4, "pinned byte {b} refused"),
            }
        }
        assert_eq!(fluff_bytes, 1);
        // In particular the C++ "all-clear ⇒ fluff" state does not exist:
        // byte 0 is `None`, and `None` is not broadcasted.
        assert_eq!(RelayMethod::from_byte(0), Some(RelayMethod::None));
        assert!(!RelayMethod::None.matches(RelayCategory::Broadcasted));
    }

    #[test]
    fn net_zone_decoder_is_exhaustive() {
        for b in 0..=u8::MAX {
            match NetZone::from_byte(b) {
                Some(z) => assert_eq!(z.to_byte(), b),
                None => assert!(b > 3),
            }
        }
        assert!(NetZone::Tor.is_anonymity());
        assert!(NetZone::I2p.is_anonymity());
        assert!(!NetZone::Public.is_anonymity());
        assert!(!NetZone::Invalid.is_anonymity());
    }

    /// The C++ `matches_category` table, row for row
    /// (`blockchain_db.cpp:51–96`; pinned there by
    /// `tests/unit_tests/relay_category.cpp`).
    #[test]
    fn matches_is_the_cxx_table() {
        use RelayCategory::{All, Broadcasted, Relayable};
        use RelayMethod::{Block, Fluff, Local, None, Stem};
        let table = [
            (None, false, false, true),
            (Local, false, true, true),
            (Stem, false, true, true),
            (Fluff, true, true, true),
            (Block, true, true, true),
        ];
        for (m, broadcasted, relayable, all) in table {
            assert_eq!(m.matches(Broadcasted), broadcasted, "{m:?} broadcasted");
            assert_eq!(m.matches(Relayable), relayable, "{m:?} relayable");
            assert_eq!(m.matches(All), all, "{m:?} all");
        }
    }
}
