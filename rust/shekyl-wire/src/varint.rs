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
    /// Bit width of the target type — the bound for the overflow-reject check.
    const BITS: u32;
    /// Widen to the `u64` working type.
    fn to_u64(self) -> u64;
    /// Narrow back, returning `None` if the decoded value does not fit.
    fn from_u64(value: u64) -> Option<Self>;
}

macro_rules! impl_varint_from {
    ($t:ty) => {
        impl VarInt for $t {
            const BITS: u32 = <$t>::BITS;
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
    const BITS: u32 = u64::BITS;
    fn to_u64(self) -> u64 {
        self
    }
    fn from_u64(value: u64) -> Option<Self> {
        Some(value)
    }
}

impl VarInt for usize {
    const BITS: u32 = usize::BITS;
    fn to_u64(self) -> u64 {
        // Widening on every supported platform (`u64 >= usize`): no truncation.
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
pub fn read_varint<U: VarInt, R: Read>(r: &mut R) -> io::Result<U> {
    let mut bits: u32 = 0;
    let mut res: u64 = 0;
    loop {
        let byte = read_byte(r)?;
        // A non-leading terminator of `0x00` is a redundant trailing zero.
        if bits != 0 && byte == 0 {
            return Err(io::Error::other(
                "non-canonical varint (redundant trailing zero)",
            ));
        }
        // Overflow: only checkable once we are within 7 bits of the type width,
        // where `U::BITS - bits <= 7`, so the shift below stays in range.
        if (bits + 7) >= U::BITS && byte >= (1u8 << (U::BITS - bits)) {
            return Err(io::Error::other("varint overflow for target type"));
        }
        res += u64::from(byte & PAYLOAD) << bits;
        bits += 7;
        if byte & CONTINUATION != CONTINUATION {
            break;
        }
    }
    U::from_u64(res).ok_or_else(|| io::Error::other("varint does not fit target type"))
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
}
