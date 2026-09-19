// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Canonical codecs for the scalar leaves every stored value is built from.
//!
//! Integers are **little-endian**, matching `shekyl-chain-store`'s
//! `digest_v0` preimages and redb's own `u64` / `u8`
//! [`Value`](redb::Value) encoding, so a typed column and a canonically
//! encoded `&[u8]` cell fold identically. The test at the bottom pins that
//! agreement byte for byte.
//!
//! They live here rather than in either store because the types are
//! foreign to both: once [`Canonical`] is foreign to a store crate, the
//! orphan rule leaves only the trait's crate (crate docs, CTS-13).

use crate::{exact, Canonical, CodecError};

impl Canonical for u8 {
    const NAME: &'static str = "u8";
    const FIXED_WIDTH: Option<usize> = Some(1);

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(*self);
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        exact::<1>(Self::NAME, bytes).map(|[b]| b)
    }
}

impl Canonical for u64 {
    const NAME: &'static str = "u64";
    const FIXED_WIDTH: Option<usize> = Some(8);

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_le_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        exact::<8>(Self::NAME, bytes).map(Self::from_le_bytes)
    }
}

#[cfg(test)]
mod tests {
    use redb::Value;

    use super::*;

    fn roundtrip<T: Canonical + PartialEq + core::fmt::Debug>(v: &T) {
        let enc = v.encode();
        assert_eq!(Some(enc.len()), T::FIXED_WIDTH, "{}", T::NAME);
        assert_eq!(&T::decode(&enc).expect("own encoding decodes"), v);
    }

    #[test]
    fn scalars_round_trip_at_their_declared_width() {
        for v in [0_u8, 1, 0x7f, 0xff] {
            roundtrip(&v);
        }
        for v in [0_u64, 1, 0x0102_0304_0506_0708, u64::MAX] {
            roundtrip(&v);
        }
    }

    #[test]
    fn integers_are_little_endian() {
        assert_eq!(0x0102_0304_0506_0708_u64.encode(), [8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(u64::decode(&[1, 0, 0, 0, 0, 0, 0, 0]), Ok(1));
    }

    #[test]
    fn a_wrong_width_is_refused_not_padded_or_truncated() {
        assert!(matches!(
            u64::decode(&[1, 0, 0, 0, 0, 0, 0]),
            Err(CodecError::Length {
                codec: "u64",
                expected: 8,
                actual: 7
            })
        ));
        assert!(matches!(
            u64::decode(&[0; 9]),
            Err(CodecError::Length {
                codec: "u64",
                expected: 8,
                actual: 9
            })
        ));
        assert!(matches!(u8::decode(&[]), Err(CodecError::Length { .. })));
    }

    #[test]
    fn canonical_scalars_agree_with_redb_typed_columns() {
        // A `TableDefinition<u64, u64>` column and a `&[u8]` cell holding
        // the canonical u64 must be the same bytes, or the digest would fold
        // the same logical value two ways depending on which column it came
        // from. redb encodes integers little-endian; so do we. Pinned here
        // so a redb bump that changed its integer layout would be caught.
        for v in [0_u64, 1, 0xdead_beef, u64::MAX] {
            assert_eq!(v.encode(), <u64 as Value>::as_bytes(&v).as_ref());
        }
        for v in [0_u8, 7, 0xff] {
            assert_eq!(v.encode(), <u8 as Value>::as_bytes(&v).as_ref());
        }
    }
}
