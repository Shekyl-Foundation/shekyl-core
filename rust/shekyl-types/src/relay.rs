// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The relay seam's words — DRS-E1 S-POOL (`DRS_E1_SPOOL.md` §3.4,
//! `SPL-Q6` RULED 2026-09-24).
//!
//! [`RelayMethod`] and [`NetZone`] are the FFI seam's words. The pool does
//! not read either (DX-F6, 2026-10-16): its record carries one relay fact,
//! whether the transaction is public yet, and the relay owns the rest.
//! Their Rust reader is `shekyl-relay`, whose `graph` module pins
//! [`RelayMethod`]'s bytes; [`NetZone`]'s pins sit on this type. They live
//! at this path because the C++ side of the byte contract names it
//! (`src/cryptonote_protocol/enums.h:64–80`), and they leave with the C++
//! relay at the DRS-X flip.
//!
//! # What these enums are, and are not
//!
//! They are the **seam's** vocabulary, and nothing persists them. There is
//! no Rust `relay_category`: a pool that knows only "public yet" has no
//! category to apply to a [`RelayMethod`].
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
/// `shekyl-relay::graph` carries the Rust-side `const` pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RelayMethod {
    /// Received via RPC with `do_not_relay` set. **Unreachable in Shekyl**
    /// (no such RPC); kept because the byte contract is shared.
    None = 0,
    /// Originated by this node; trying to send over Tor. The class that
    /// routes the txpool backstop to fail-closed rather than `public_req`.
    /// At the seam only; no pool record carries a method (DX-F6).
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
}

/// The network class the zone-parameterized embargo still names. Not a
/// connector id, and not a route: the one relay does not read this byte.
/// The C++ `netzone_*` constants pin the same bytes.
///
/// `Invalid == 0` is the seam pin with `cryptonote::netzone_invalid`.
/// The pool record does not store an arrival zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum NetZone {
    /// Unknown byte. The origination roll that used this value is retired.
    /// The zone-parameterized embargo still draws its long window here.
    Invalid = 0,
    /// The clear internet.
    Public = 1,
    /// Tor. Discriminant 2 is unused so this value stays 3.
    Tor = 3,
}

const _: () = {
    assert!(NetZone::Invalid as u8 == 0);
    assert!(NetZone::Public as u8 == 1);
    assert!(NetZone::Tor as u8 == 3);
};

impl NetZone {
    /// Byte-contract decode; `None` on an unknown byte. Exhaustive: a fifth
    /// zone is a new arm here, never a masked alias of an existing one.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Invalid),
            1 => Some(Self::Public),
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
        matches!(self, Self::Tor)
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
    }

    #[test]
    fn net_zone_decoder_is_exhaustive() {
        for b in 0..=u8::MAX {
            match NetZone::from_byte(b) {
                Some(z) => assert_eq!(z.to_byte(), b),
                None => assert!(b == 2 || b > 3, "pinned byte {b} refused"),
            }
        }
        assert!(NetZone::Tor.is_anonymity());
        assert!(!NetZone::Public.is_anonymity());
        assert!(!NetZone::Invalid.is_anonymity());
    }
}
