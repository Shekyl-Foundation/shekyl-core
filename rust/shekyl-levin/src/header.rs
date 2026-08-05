// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The 33-byte Levin bucket header (`bucket_head2` in the C++ oracle) and
//! its flag word. Byte layout per `docs/LEVIN_PROTOCOL.md` §Header; all
//! multi-byte fields are little-endian.

use crate::Error;

/// The 8-byte protocol signature ("Bender's nightmare"). On the wire the
/// little-endian bytes read `01 21 01 01 01 01 01 01`.
pub const LEVIN_SIGNATURE: u64 = 0x0101_0101_0101_2101;

/// Serialized header size in bytes.
pub const HEADER_SIZE: usize = 33;

/// The only protocol version Shekyl speaks (`LEVIN_PROTOCOL_VER_1`).
pub const PROTOCOL_VERSION_1: u32 = 1;

/// Packet-size limit before the p2p handshake completes (256 KiB).
pub const INITIAL_MAX_PACKET_SIZE: u64 = 256 * 1024;

/// Packet-size limit after the handshake (100 MB, base 10 — the C++
/// `LEVIN_DEFAULT_MAX_PACKET_SIZE`).
pub const DEFAULT_MAX_PACKET_SIZE: u64 = 100_000_000;

/// The header's 32-bit flag word. Unknown bits are preserved verbatim so a
/// decode/encode round-trip is byte-identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags(u32);

impl Flags {
    /// `Q` — the message is a request (also set on notifications).
    pub const REQUEST: Flags = Flags(0x0000_0001);
    /// `S` — the message is a response.
    pub const RESPONSE: Flags = Flags(0x0000_0002);
    /// `B` — first fragment of a fragmented message.
    pub const BEGIN: Flags = Flags(0x0000_0004);
    /// `E` — last fragment of a fragmented message. `B|E` marks a dummy.
    pub const END: Flags = Flags(0x0000_0008);
    /// Payload is a zstd frame (Shekyl extension to the inherited protocol).
    pub const COMPRESSED: Flags = Flags(0x0000_0010);

    /// Construct from a raw wire value, preserving unknown bits.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Flags {
        Flags(bits)
    }

    /// The raw wire value.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// True if every bit of `other` is set in `self`.
    #[must_use]
    pub const fn contains(self, other: Flags) -> bool {
        (self.0 & other.0) == other.0
    }

    /// True if any bit of `other` is set in `self`.
    #[must_use]
    pub const fn intersects(self, other: Flags) -> bool {
        (self.0 & other.0) != 0
    }

    /// Union of two flag sets.
    #[must_use]
    pub const fn union(self, other: Flags) -> Flags {
        Flags(self.0 | other.0)
    }

    /// `self` with every bit of `other` cleared.
    #[must_use]
    pub const fn difference(self, other: Flags) -> Flags {
        Flags(self.0 & !other.0)
    }
}

/// A parsed Levin bucket header.
///
/// The signature is verified on decode and written on encode; it is not
/// stored. Every other field is kept in its wire form so that
/// `BucketHead::read(b).write() == *b` for **any** 33 bytes carrying a valid
/// signature: unknown [`Flags`] bits are preserved verbatim, and
/// `expect_response` keeps the raw `uint8_t` the C++ reads as truthy rather
/// than being narrowed to a `bool` (which would re-encode a sender's `0x02`
/// as `0x01`). Use [`BucketHead::expects_response`] for the truthiness test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketHead {
    /// Payload length in bytes (`m_cb`); excludes the header itself.
    pub payload_len: u64,
    /// Whether the peer must answer this command
    /// (`m_have_to_return_data`), as the raw wire byte: any non-zero value
    /// means "yes". Emitters write `0` or `1` via [`BucketHead::make`].
    pub expect_response: u8,
    /// Command identifier (e.g. 1001 handshake, 2002 new-transactions).
    pub command: u32,
    /// Response return code; `0` on requests and notifications.
    pub return_code: i32,
    /// Q/S/B/E/COMPRESSED flag word.
    pub flags: Flags,
    /// Protocol version; always [`PROTOCOL_VERSION_1`] from conforming peers.
    pub protocol_version: u32,
}

impl BucketHead {
    /// Build a header the way the C++ `make_header` does: version 1,
    /// return code 0.
    #[must_use]
    pub fn make(command: u32, payload_len: u64, flags: Flags, expect_response: bool) -> BucketHead {
        BucketHead {
            payload_len,
            expect_response: u8::from(expect_response),
            command,
            return_code: 0,
            flags,
            protocol_version: PROTOCOL_VERSION_1,
        }
    }

    /// Whether the peer must answer this command. Mirrors the C++ reading
    /// `m_have_to_return_data` as a truthy `uint8_t`.
    #[must_use]
    pub const fn expects_response(&self) -> bool {
        self.expect_response != 0
    }

    /// Serialize to the 33-byte wire form.
    #[must_use]
    pub fn write(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[0..8].copy_from_slice(&LEVIN_SIGNATURE.to_le_bytes());
        out[8..16].copy_from_slice(&self.payload_len.to_le_bytes());
        out[16] = self.expect_response;
        out[17..21].copy_from_slice(&self.command.to_le_bytes());
        out[21..25].copy_from_slice(&self.return_code.to_le_bytes());
        out[25..29].copy_from_slice(&self.flags.bits().to_le_bytes());
        out[29..33].copy_from_slice(&self.protocol_version.to_le_bytes());
        out
    }

    /// Parse the 33-byte wire form, verifying the signature.
    ///
    /// # Errors
    ///
    /// [`Error::BadSignature`] if the first 8 bytes are not
    /// [`LEVIN_SIGNATURE`] — connection-fatal in the C++ oracle.
    pub fn read(bytes: &[u8; HEADER_SIZE]) -> Result<BucketHead, Error> {
        if !signature_matches(bytes) {
            return Err(Error::BadSignature);
        }
        // Slice→array conversions cannot fail on a fixed-size input; unwraps
        // here are on statically-sized subslices.
        let le_u64 = |range: core::ops::Range<usize>| {
            u64::from_le_bytes(bytes[range].try_into().expect("static 8-byte slice"))
        };
        let le_u32 = |range: core::ops::Range<usize>| {
            u32::from_le_bytes(bytes[range].try_into().expect("static 4-byte slice"))
        };
        Ok(BucketHead {
            payload_len: le_u64(8..16),
            expect_response: bytes[16],
            command: le_u32(17..21),
            return_code: i32::from_le_bytes(bytes[21..25].try_into().expect("static 4-byte slice")),
            flags: Flags::from_bits(le_u32(25..29)),
            protocol_version: le_u32(29..33),
        })
    }
}

/// Check the signature prefix of a (possibly partial) buffer. Requires at
/// least 8 bytes; the reader uses this for the C++ early-reject (`handle_recv`
/// closes the connection on a signature mismatch before the full header has
/// arrived).
#[must_use]
pub(crate) fn signature_matches(bytes: &[u8]) -> bool {
    bytes.len() >= 8 && bytes[0..8] == LEVIN_SIGNATURE.to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_wire_bytes_match_protocol_doc() {
        // docs/LEVIN_PROTOCOL.md header diagram: 0x01 0x21 0x01 0x01 ...
        assert_eq!(
            LEVIN_SIGNATURE.to_le_bytes(),
            [0x01, 0x21, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]
        );
    }

    #[test]
    fn header_roundtrip() {
        let head = BucketHead {
            payload_len: 0xDEAD_BEEF,
            expect_response: 1,
            command: 1001,
            return_code: -7,
            flags: Flags::REQUEST.union(Flags::COMPRESSED),
            protocol_version: PROTOCOL_VERSION_1,
        };
        let bytes = head.write();
        assert_eq!(BucketHead::read(&bytes).unwrap(), head);
    }

    /// Decode/encode must be byte-exact for *any* signed header, not just the
    /// ones our own builders emit — a relay or differential harness that
    /// re-emits a peer's bucket must reproduce its bytes.
    #[test]
    fn decode_encode_is_byte_exact_for_unusual_wire_values() {
        let mut bytes = BucketHead::make(2002, 7, Flags::REQUEST, false).write();
        // A sender whose `expect_response` is truthy but not 1, and flag bits
        // outside the five this crate names.
        bytes[16] = 0x02;
        bytes[25..29].copy_from_slice(&0x8000_0021u32.to_le_bytes());

        let head = BucketHead::read(&bytes).unwrap();
        assert!(head.expects_response(), "0x02 is truthy");
        assert_eq!(
            head.write(),
            bytes,
            "re-encoding must not normalize wire bytes"
        );
    }

    #[test]
    fn bad_signature_rejected() {
        let mut bytes = BucketHead::make(0, 0, Flags::default(), false).write();
        bytes[0] = 0xFF;
        assert_eq!(BucketHead::read(&bytes), Err(Error::BadSignature));
    }
}
