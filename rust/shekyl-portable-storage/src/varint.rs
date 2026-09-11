// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use crate::error::Error;

/// Maximum value `pack_varint` will encode (C++ `!(val >> 31 >> 31)` on
/// 64-bit `size_t`: 2^62 − 1).
pub(crate) const VARINT_MAX: u64 = 4_611_686_018_427_387_903;

pub(crate) fn write_varint(out: &mut Vec<u8>, val: u64) -> Result<(), Error> {
    if val <= 63 {
        let packed = u8::try_from(val << 2).expect("val <= 63");
        out.push(packed);
    } else if val <= 16_383 {
        let packed = u16::try_from((val << 2) | 1).expect("val <= 16383");
        out.extend_from_slice(&packed.to_le_bytes());
    } else if val <= 1_073_741_823 {
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
}
