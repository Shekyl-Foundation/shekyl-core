// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one scalar codec this store owns: [`Hash32`], the storage hash
//! `lmdb_order` carries LMDB's ordering on.
//!
//! The integer scalars (`u8`, `u64`) are foreign types and live in
//! `shekyl-store-codec` with the trait (`codec` module docs). They are
//! little-endian there, matching [`digest_v0`](crate::digest_v0)'s
//! preimages and redb's own encoding; the test at the bottom pins that a
//! `Hash32` cell is its 32 bytes verbatim, which is the agreement this
//! crate has to hold.

use crate::lmdb_order::Hash32;

use super::{exact, Canonical, CodecError};

impl Canonical for Hash32 {
    const NAME: &'static str = "hash32";
    const FIXED_WIDTH: Option<usize> = Some(32);

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        exact::<32>(Self::NAME, bytes).map(Self::from_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash32_round_trips_at_its_declared_width() {
        let h = Hash32::from_bytes([0xab; 32]);
        let enc = h.encode();
        assert_eq!(Some(enc.len()), Hash32::FIXED_WIDTH);
        assert_eq!(Hash32::decode(&enc).expect("own encoding decodes"), h);
    }

    #[test]
    fn a_wrong_width_is_refused_not_padded_or_truncated() {
        assert!(matches!(
            Hash32::decode(&[0; 31]),
            Err(CodecError::Length {
                codec: "hash32",
                expected: 32,
                actual: 31
            })
        ));
        assert!(matches!(
            Hash32::decode(&[0; 33]),
            Err(CodecError::Length { .. })
        ));
    }

    #[test]
    fn hash32_is_the_stored_form_verbatim() {
        // `Hash32` is a layout type with no redb impl of its own
        // (§11.1(f)); its codec is the stored form verbatim, so a cell and
        // the digest's preimage are the same 32 bytes.
        let h = Hash32::from_bytes(core::array::from_fn(|i| {
            u8::try_from(i).expect("32 indices fit a byte")
        }));
        assert_eq!(h.encode(), h.to_bytes());
    }
}
