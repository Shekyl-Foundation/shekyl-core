// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Canonical codecs for the domain vocabulary — the `shekyl-types` and
//! `shekyl-units` newtypes a store persists but does not own.
//!
//! They live here for the same reason the scalars do: once [`Canonical`]
//! is foreign to a store crate, an impl for a foreign type can live only
//! where the trait lives, and the vocabulary crates are `no_std` and must
//! not depend on `redb` (crate docs, CTS-13 / CTS-Q6). Hosting them once
//! is also what keeps the two stores from minting a newtype apiece for the
//! same value.
//!
//! Each doc line names the daemon table the codec was written for — that
//! is its provenance, not its scope; a second store reading the same
//! vocabulary reads the same bytes, which is the point of the crate.
//! Bytes are what the `u64` and `hash32` codecs already wrote: only the
//! value's *name* is new.

use shekyl_types::{BlockHeight, CurveTreeRoot, PqcAuthHash, PrunableHash, TreeLeaf, TreePosition};
use shekyl_units::AtomicUnits;

use crate::{exact, Canonical, CodecError};

/// `curve_tree_roots[h + 1]` — a Selene field element, not a raw hash.
///
/// Codec `NAME` stays `"curve_root"` so the committed snapshot identity
/// does not move; the wrapper type `CurveRoot` is deleted (RTN-2).
impl Canonical for CurveTreeRoot {
    const NAME: &'static str = "curve_root";
    const FIXED_WIDTH: Option<usize> = Some(32);

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        exact::<32>(Self::NAME, bytes).map(Self::from_bytes)
    }
}

/// `block_heights[hash]` — the height a block hash sits at. The
/// `shekyl-types` newtype, stored as its raw LE `u64`.
impl Canonical for BlockHeight {
    const NAME: &'static str = "block_height";
    const FIXED_WIDTH: Option<usize> = Some(8);

    fn encode_into(&self, out: &mut Vec<u8>) {
        self.to_raw().encode_into(out);
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        u64::decode(bytes)
            .map(Self::from_raw)
            .map_err(|e| e.in_codec(Self::NAME))
    }
}

/// `txs_prunable_hash[tx_id]` — the digest of a transaction's prunable
/// region, the txid's fourth component (S-CHAIN-W SCW-10). The
/// `shekyl-types` identity type, stored as its 32 bytes; the daemon
/// store's `Hash32` (`lmdb_order`) appears only where an LMDB *ordering*
/// is carried, which a value is not.
impl Canonical for PrunableHash {
    const NAME: &'static str = "prunable_hash";
    const FIXED_WIDTH: Option<usize> = Some(32);

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        exact::<32>(Self::NAME, bytes).map(Self::from_bytes)
    }
}

/// `txs_pqc_auth_hash[tx_id]` — the digest of a transaction's `pqc_auths`
/// segment as the txid commits it, `keccak256(varint(count) ‖ auths)`; the
/// txid's **third** component (`PDM-Q-F26`, DRS §7.7). Present ⇔ the txid is
/// 4-part; never deleted by a prune. The `shekyl-types` identity type, 32
/// bytes.
impl Canonical for PqcAuthHash {
    const NAME: &'static str = "pqc_auth_hash";
    const FIXED_WIDTH: Option<usize> = Some(32);

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        exact::<32>(Self::NAME, bytes).map(Self::from_bytes)
    }
}

/// `block_burn[height]` — atomic units burned by the block, per
/// `blockchain.cpp:6148`; written only when non-zero (the daemon store's
/// `store/connect.rs` phase 8). The `shekyl-units` newtype (RTN-2 put it
/// on `ConnectFacts`), stored as its raw LE `u64` — the bytes the `u64`
/// codec wrote before the value had a name.
impl Canonical for AtomicUnits {
    const NAME: &'static str = "atomic_units";
    const FIXED_WIDTH: Option<usize> = Some(8);

    fn encode_into(&self, out: &mut Vec<u8>) {
        self.to_raw().encode_into(out);
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        u64::decode(bytes)
            .map(Self::from_raw)
            .map_err(|e| e.in_codec(Self::NAME))
    }
}

/// `curve_tree_leaves[position]`'s **key**, as a value where a position is
/// stored (DRS-E1 S-CURVE, `SCU-Q2`): the curve tree's dense drain-order
/// position, the `shekyl-types` newtype, stored as its raw LE `u64`. Both
/// stores key leaves by it; each wraps it in its own redb key type, and
/// this is the codec they share.
impl Canonical for TreePosition {
    const NAME: &'static str = "tree_position";
    const FIXED_WIDTH: Option<usize> = Some(8);

    fn encode_into(&self, out: &mut Vec<u8>) {
        self.to_raw().encode_into(out);
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        u64::decode(bytes)
            .map(Self::from_raw)
            .map_err(|e| e.in_codec(Self::NAME))
    }
}

/// `curve_tree_leaves[position]` — one stored leaf: the four Selene
/// scalars `{O.x, I.x, C.x, CM.x}` as 128 bytes, the layout the C++
/// `CT_LEAF_SIZE` row has and the wallet-side `leaves` table holds. The
/// `shekyl-types` name for those bytes (S-CURVE, `SCU-Q2`).
impl Canonical for TreeLeaf {
    const NAME: &'static str = "tree_leaf";
    const FIXED_WIDTH: Option<usize> = Some(TreeLeaf::LEN);

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        exact::<{ TreeLeaf::LEN }>(Self::NAME, bytes).map(Self::from_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T: Canonical + PartialEq + core::fmt::Debug + Copy>(v: T) {
        let enc = v.encode();
        assert_eq!(Some(enc.len()), T::FIXED_WIDTH, "{}", T::NAME);
        assert_eq!(T::decode(&enc).expect("own encoding decodes"), v);
        // One byte short and one byte long are both refused: a stored cell
        // is exactly one encoding or it is a `CodecError` (crate docs).
        let width = T::FIXED_WIDTH.expect("every vocabulary codec is fixed-width");
        assert!(matches!(
            T::decode(&enc[..width - 1]),
            Err(CodecError::Length { .. })
        ));
        let mut long = enc.clone();
        long.push(0);
        assert!(matches!(T::decode(&long), Err(CodecError::Length { .. })));
    }

    #[test]
    fn vocabulary_codecs_round_trip_at_their_declared_widths() {
        roundtrip(CurveTreeRoot::from_bytes([0x5e; 32]));
        roundtrip(BlockHeight::from_raw(0x0102_0304_0506_0708));
        roundtrip(PrunableHash::from_bytes([0xab; 32]));
        roundtrip(PqcAuthHash::from_bytes([0xcd; 32]));
        roundtrip(AtomicUnits::from_raw(u64::MAX));
    }

    #[test]
    fn the_scalar_backed_codecs_are_the_raw_le_word() {
        assert_eq!(
            BlockHeight::from_raw(1).encode(),
            [1, 0, 0, 0, 0, 0, 0, 0],
            "a height is its raw LE u64, not a re-encoding"
        );
        assert_eq!(AtomicUnits::from_raw(1).encode(), [1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(BlockHeight::from_raw(7).encode(), 7_u64.encode());
    }

    #[test]
    fn the_32_byte_codecs_are_the_bytes_verbatim_and_named_apart() {
        assert_eq!(
            CurveTreeRoot::from_bytes([0x5e; 32]).encode(),
            vec![0x5e; 32]
        );
        assert_eq!(
            PrunableHash::from_bytes([0x11; 32]).encode(),
            vec![0x11; 32]
        );
        assert_eq!(PqcAuthHash::from_bytes([0x22; 32]).encode(), vec![0x22; 32]);
        // Same width, three meanings: the `NAME`s are what keep their
        // tables' value `TypeName`s apart (`shape` module docs).
        let names = [
            CurveTreeRoot::NAME,
            PrunableHash::NAME,
            PqcAuthHash::NAME,
            BlockHeight::NAME,
            AtomicUnits::NAME,
        ];
        let unique: std::collections::BTreeSet<&str> = names.iter().copied().collect();
        assert_eq!(unique.len(), names.len(), "codec NAMEs must be unique");
    }

    #[test]
    fn a_wrapping_codec_refuses_under_its_own_name_not_the_scalars() {
        assert!(matches!(
            BlockHeight::decode(&[0; 7]),
            Err(CodecError::Length {
                codec: "block_height",
                expected: 8,
                actual: 7
            })
        ));
        assert!(matches!(
            AtomicUnits::decode(&[0; 9]),
            Err(CodecError::Length {
                codec: "atomic_units",
                ..
            })
        ));
    }
}
