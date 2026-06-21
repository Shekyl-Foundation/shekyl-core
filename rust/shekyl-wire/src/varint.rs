// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Canonical LEB128 varint — Shekyl's `V(x)` (GENESIS_TX_WIRE_FORMAT.md §6 Q10).
//!
//! 7 data bits per byte, MSB = continuation, little-endian. The encoding is
//! **canonical**: a non-leading `0x00` byte (a redundant trailing zero) is
//! rejected, and an encoding wider than the target type is rejected. This
//! matches the consensus encoding (the C++ oracle / vendored `shekyl-oxide`
//! `io::{read,write}_varint`) byte-for-byte; the live-blob round-trip KAT is the
//! proof, and the rejection rules are §12 negative-corpus cases.

use std::io::{self, Read, Write};

use crate::bytes::read_byte;

const CONTINUATION: u8 = 0b1000_0000;
const PAYLOAD: u8 = !CONTINUATION;

/// A fixed-width unsigned integer encodable as a canonical varint.
///
/// Conversions are centralised here (rather than `as` casts at call sites) so the
/// workspace's deny-by-default cast lints stay satisfied.
pub trait VarInt: Copy {
    /// Widen to the `u64` working type.
    fn to_u64(self) -> u64;
    /// Narrow back, returning `None` if the decoded value does not fit.
    fn from_u64(value: u64) -> Option<Self>;
}

macro_rules! impl_varint_from {
    ($t:ty) => {
        impl VarInt for $t {
            fn to_u64(self) -> u64 {
                u64::from(self)
            }
            fn from_u64(value: u64) -> Option<Self> {
                <$t>::try_from(value).ok()
            }
        }
    };
}
impl_varint_from!(u8);
impl_varint_from!(u32);

impl VarInt for u64 {
    fn to_u64(self) -> u64 {
        self
    }
    fn from_u64(value: u64) -> Option<Self> {
        Some(value)
    }
}

// `to_u64` widens `usize` to `u64`. Guard the assumption at compile time so a
// hypothetical platform with `usize` wider than 64 bits fails to build rather than
// silently truncating a consensus-critical length (mirrors the shekyl-oxide varint
// guard); `<=` keeps the common 16/32/64-bit targets valid.
const _: () = assert!(usize::BITS <= u64::BITS);

impl VarInt for usize {
    fn to_u64(self) -> u64 {
        // Widening (guarded above by `usize::BITS <= u64::BITS`): no truncation.
        self as u64
    }
    fn from_u64(value: u64) -> Option<Self> {
        usize::try_from(value).ok()
    }
}

/// Write `value` as a canonical varint.
pub fn write_varint<U: VarInt, W: Write>(value: U, w: &mut W) -> io::Result<()> {
    let mut value = value.to_u64();
    loop {
        let mut byte =
            u8::try_from(value & u64::from(PAYLOAD)).expect("7-bit masked value is a byte");
        value >>= 7;
        if value != 0 {
            byte |= CONTINUATION;
        }
        w.write_all(&[byte])?;
        if value == 0 {
            break;
        }
    }
    Ok(())
}

/// Read a canonical varint, rejecting non-canonical encodings and values that
/// overflow `U`.
///
/// The 7-bit groups accumulate into a `u64` working value, then [`VarInt::from_u64`]
/// narrows (and rejects) per target type. The per-group guard cannot underflow or
/// panic on hostile input: `shift >= u64::BITS` is checked first and `||`
/// short-circuits, so the shift below is only evaluated for an in-range `shift`, and
/// the round-trip-through-shift comparison rejects any group whose high bits would
/// fall off the `u64`.
pub fn read_varint<U: VarInt, R: Read>(r: &mut R) -> io::Result<U> {
    let mut res: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        let byte = read_byte(r)?;
        // A non-leading terminator of `0x00` is a redundant trailing zero.
        if shift != 0 && byte == 0 {
            return Err(io::Error::other(
                "non-canonical varint (redundant trailing zero)",
            ));
        }
        let payload = u64::from(byte & PAYLOAD);
        if shift >= u64::BITS || (payload << shift) >> shift != payload {
            return Err(io::Error::other("varint overflow (exceeds u64 width)"));
        }
        res |= payload << shift;
        shift += 7;
        if byte & CONTINUATION != CONTINUATION {
            break;
        }
    }
    U::from_u64(res).ok_or_else(|| io::Error::other("varint overflow for target type"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip_u64(value: u64) {
        let mut buf = Vec::new();
        write_varint(value, &mut buf).unwrap();
        let decoded: u64 = read_varint(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, value, "round-trip mismatch for {value}");
    }

    #[test]
    fn round_trips_representative_values() {
        for v in [
            0u64,
            1,
            127,
            128,
            255,
            256,
            16_383,
            16_384,
            u64::from(u32::MAX),
            u64::MAX,
        ] {
            round_trip_u64(v);
        }
    }

    #[test]
    fn single_byte_zero_is_canonical() {
        let mut buf = Vec::new();
        write_varint(0u64, &mut buf).unwrap();
        assert_eq!(buf, vec![0x00]);
    }

    #[test]
    fn rejects_redundant_trailing_zero() {
        // 0x80 = continuation with payload 0, then 0x00 terminator: non-canonical.
        let err = read_varint::<u64, _>(&mut [0x80u8, 0x00].as_slice()).unwrap_err();
        assert!(err.to_string().contains("non-canonical"), "{err}");
    }

    #[test]
    fn two_byte_value_decodes() {
        // 0x80,0x01 => 0 | (1 << 7) = 128; fits u8 (== 128).
        let v: u8 = read_varint(&mut [0x80u8, 0x01].as_slice()).unwrap();
        assert_eq!(v, 128);
    }

    #[test]
    fn rejects_overflow_for_narrow_type() {
        // 0x80,0x02 => 0 | (2 << 7) = 256, which does not fit a u8.
        let err = read_varint::<u8, _>(&mut [0x80u8, 0x02].as_slice()).unwrap_err();
        assert!(err.to_string().contains("overflow"), "{err}");
    }

    #[test]
    fn rejects_overlong_varint_without_panic() {
        // 11 continuation bytes is more 7-bit groups than fit in a u64. The shift
        // guard must return an error, never underflow/panic on this hostile input.
        let err = read_varint::<u64, _>(&mut [0x80u8; 11].as_slice()).unwrap_err();
        assert!(err.to_string().contains("overflow"), "{err}");
    }
}
