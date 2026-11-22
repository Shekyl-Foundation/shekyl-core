// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use crate::error::Error;

/// Maximum value `pack_varint` will encode (C++ `!(val >> 31 >> 31)` on
/// 64-bit `size_t`: 2^62 − 1).
pub(crate) const VARINT_MAX: u64 = 4_611_686_018_427_387_903;

/// The largest value each varint width carries: the low two bits of the
/// first byte name the width, so a width of `n` bytes holds `8n - 2` bits.
const ONE_BYTE_MAX: u64 = 63;
const TWO_BYTE_MAX: u64 = 16_383;
const FOUR_BYTE_MAX: u64 = 1_073_741_823;

/// How many bytes [`write_varint`] writes for `val`: 1, 2, 4 or 8.
///
/// For a caller that sizes an encoding without building it (a byte budget
/// over a list of strings). A value above the varint's range is answered
/// with the widest form; the encoder refuses it.
#[must_use]
pub const fn varint_len(val: u64) -> u64 {
    if val <= ONE_BYTE_MAX {
        1
    } else if val <= TWO_BYTE_MAX {
        2
    } else if val <= FOUR_BYTE_MAX {
        4
    } else {
        8
    }
}

pub(crate) fn write_varint(out: &mut Vec<u8>, val: u64) -> Result<(), Error> {
    if val <= ONE_BYTE_MAX {
        let packed = u8::try_from(val << 2).expect("val <= 63");
        out.push(packed);
    } else if val <= TWO_BYTE_MAX {
        let packed = u16::try_from((val << 2) | 1).expect("val <= 16383");
        out.extend_from_slice(&packed.to_le_bytes());
    } else if val <= FOUR_BYTE_MAX {
        let packed = u32::try_from((val << 2) | 2).expect("val <= 2^30-1");
        out.extend_from_slice(&packed.to_le_bytes());
    } else if val <= VARINT_MAX {
        out.extend_from_slice(&((val << 2) | 3).to_le_bytes());
    } else {
        return Err(Error::VarintTooLarge);
    }
    Ok(())
}

pub(crate) fn read_varint(input: &mut &[u8]) -> Result<u64, Error> {
    let first = *input.first().ok_or(Error::Truncated)?;
    match first & 0x03 {
        0 => {
            let v = take_arr::<1>(input)?;
            Ok(u64::from(v[0]) >> 2)
        }
        1 => {
            let v = take_arr::<2>(input)?;
            Ok(u64::from(u16::from_le_bytes(v)) >> 2)
        }
        2 => {
            let v = take_arr::<4>(input)?;
            Ok(u64::from(u32::from_le_bytes(v)) >> 2)
        }
        3 => {
            let v = take_arr::<8>(input)?;
            Ok(u64::from_le_bytes(v) >> 2)
        }
        _ => unreachable!("mask is 2 bits"),
    }
}

fn take_arr<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], Error> {
    if input.len() < N {
        return Err(Error::Truncated);
    }
    let (head, rest) = input.split_at(N);
    *input = rest;
    let mut out = [0u8; N];
    out.copy_from_slice(head);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_examples() {
        let cases: &[(u64, &[u8])] = &[
            (0, &[0x00]),
            (7, &[0x1c]),
            (101, &[0x95, 0x01]),
            (17_000, &[0xa2, 0x09, 0x01, 0x00]),
            (
                7_942_319_744,
                &[0x03, 0xba, 0x98, 0x65, 0x07, 0x00, 0x00, 0x00],
            ),
        ];
        for &(val, expected) in cases {
            let mut buf = Vec::new();
            write_varint(&mut buf, val).expect("in range");
            assert_eq!(buf, expected, "encode {val}");
            let mut rest = expected;
            assert_eq!(read_varint(&mut rest).expect("decode"), val);
            assert!(rest.is_empty());
        }
    }

    /// `varint_len` is the encoder's own width at every band edge.
    ///
    /// Red edit: answer any band in `varint_len` with another band's
    /// width, or compare with `<` in place of `<=`, and that band's edge
    /// fails.
    #[test]
    fn the_counted_width_is_the_written_width() {
        for val in [
            0,
            1,
            ONE_BYTE_MAX,
            ONE_BYTE_MAX + 1,
            TWO_BYTE_MAX,
            TWO_BYTE_MAX + 1,
            1_000_000,
            FOUR_BYTE_MAX,
            FOUR_BYTE_MAX + 1,
            VARINT_MAX,
        ] {
            let mut buf = Vec::new();
            write_varint(&mut buf, val).expect("in range");
            assert_eq!(
                u64::try_from(buf.len()).expect("a few bytes"),
                varint_len(val),
                "width of {val}"
            );
        }
    }
}
