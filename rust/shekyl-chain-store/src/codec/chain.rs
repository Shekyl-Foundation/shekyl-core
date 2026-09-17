// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Canonical codecs for the connect write set's table values (S-CHAIN-W
//! commit 2; `DRS_E1_SCHAIN_W.md` §3.7, §4).
//!
//! Every layout here is the LMDB struct the C++ store writes
//! (`LMDB_SCHEMA.md`, `db_lmdb.cpp`), **minus the field that became the redb
//! key** under the zerokval collapse (`schema` module docs): `block_info`
//! drops `bi_height`, `tx_indices` drops the tx hash, `output_txs` drops
//! `output_id`. Carrying the key inside the value as well would let the two
//! disagree; the row's digest element is `key ‖ value`, assembled at fold
//! time. `output_amounts`' member keeps its `amount_index` prefix because
//! that prefix *is* the multimap's member order (`U64PrefixBytes`) — SCW-8:
//! LMDB's keying is ported verbatim while R8b-2 is open.
//!
//! Integers are little-endian `u64` (`primitives`), hashes are the raw 32
//! bytes. Fixed-width codecs refuse any other length; the one variable-width
//! codec ([`TxOutputIndices`]) refuses a length that is not a whole number of
//! entries. All of it is strict both ways (`codec` module docs).

use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{
    BlockHash, BlockHeight, BlockWeight, CommitmentBytes, CurveTreeRoot, LongTermWeight,
    OneTimePubkey, OutputIndexInTx, Timelock, Timestamp, TxHash,
};
use shekyl_units::AtomicUnits;

use super::{exact, Canonical, CodecError};
use crate::ids::{AmountIndex, OutputStorageId, TxStorageId};

/// Decode a stored `unlock_time` word.
///
/// The reverse of [`Timelock::to_unlock_raw`] is **not** in `shekyl-types`
/// (the owning wire format owns the lift). Store cells treat `0` as
/// [`Timelock::None`] and every other value as a block-height lock — the
/// only encoding Shekyl writes.
#[must_use]
pub(crate) fn stored_timelock(raw: u64) -> Timelock {
    if raw == 0 {
        Timelock::None
    } else {
        Timelock::Block(BlockHeight::from_raw(raw))
    }
}

/// `curve_tree_roots[h + 1]` — a Selene field element, not a [`Hash32`].
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

/// `block_info[height]` — LMDB `mdb_block_info_4` minus `bi_height`, 88 bytes.
///
/// Every field but `hash` and `rct_outputs` is a consensus-visible value the
/// store records and never derives (C2-R8 Q4; `ConnectFacts`). `rct_outputs`
/// is a storage count the store does maintain — **this block's** RCT output
/// count, not a running total: LMDB's `bi_cum_rct` is set to `num_rct_outs`
/// (`db_lmdb.cpp:1006`) and the `major_version >= 4` arm that would add the
/// parent's value is the dead Monero-v4 dispatch CEN-L15 rules "delete, do
/// not port" (live major is 1). The field name follows what the bytes hold;
/// a port that accumulated would diverge from LMDB at height 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockInfo {
    /// `bi_timestamp`.
    pub timestamp: Timestamp,
    /// `bi_coins` — coins generated through this block.
    pub coins_generated: AtomicUnits,
    /// `bi_weight`.
    pub weight: BlockWeight,
    /// `bi_diff_lo ‖ bi_diff_hi` as one integer.
    pub cumulative_difficulty: CumulativeDifficulty,
    /// `bi_hash` — the block's identity (CEN-B6).
    pub hash: BlockHash,
    /// `bi_cum_rct` — **this block's** RCT output count (per-block at this
    /// pin, CEN-L15; the LMDB field name is a misnomer).
    pub rct_outputs: u64,
    /// `bi_long_term_block_weight`.
    pub long_term_weight: LongTermWeight,
}

impl Canonical for BlockInfo {
    const NAME: &'static str = "block_info";
    const FIXED_WIDTH: Option<usize> = Some(88);

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.timestamp.to_raw().to_le_bytes());
        out.extend_from_slice(&self.coins_generated.to_raw().to_le_bytes());
        out.extend_from_slice(&self.weight.to_raw().to_le_bytes());
        // `bi_diff_lo` then `bi_diff_hi`: a little-endian u128.
        out.extend_from_slice(&self.cumulative_difficulty.to_raw().to_le_bytes());
        out.extend_from_slice(self.hash.as_bytes());
        out.extend_from_slice(&self.rct_outputs.to_le_bytes());
        out.extend_from_slice(&self.long_term_weight.to_raw().to_le_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let b = exact::<88>(Self::NAME, bytes)?;
        Ok(Self {
            timestamp: Timestamp::from_raw(le_u64(&b[0..8])),
            coins_generated: AtomicUnits::from_raw(le_u64(&b[8..16])),
            weight: BlockWeight::from_raw(le_u64(&b[16..24])),
            cumulative_difficulty: CumulativeDifficulty::from_raw(u128::from_le_bytes(
                b[24..40].try_into().expect("16-byte slice"),
            )),
            hash: BlockHash::from_bytes(b[40..72].try_into().expect("32-byte slice")),
            rct_outputs: le_u64(&b[72..80]),
            long_term_weight: LongTermWeight::from_raw(le_u64(&b[80..88])),
        })
    }
}

/// `tx_indices[tx_hash]` — LMDB `txindex` minus the hash (`tx_data_t`), 24 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxIndex {
    /// The storage id: the transaction's position in the `txs_*` tables.
    pub tx_id: TxStorageId,
    /// The transaction's `unlock_time`, as its prefix carries it.
    pub unlock_time: Timelock,
    /// `block_id` — the height of the block that recorded it.
    pub height: BlockHeight,
}

impl Canonical for TxIndex {
    const NAME: &'static str = "tx_index";
    const FIXED_WIDTH: Option<usize> = Some(24);

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.tx_id.to_raw().to_le_bytes());
        out.extend_from_slice(&self.unlock_time.to_unlock_raw().to_le_bytes());
        out.extend_from_slice(&self.height.to_raw().to_le_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let b = exact::<24>(Self::NAME, bytes)?;
        Ok(Self {
            tx_id: TxStorageId::from_raw(le_u64(&b[0..8])),
            unlock_time: stored_timelock(le_u64(&b[8..16])),
            height: BlockHeight::from_raw(le_u64(&b[16..24])),
        })
    }
}

/// `output_txs[output_id]` — LMDB `outtx` minus `output_id`, 40 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutTx {
    /// The transaction that created the output.
    pub tx_hash: TxHash,
    /// The output's position in that transaction's `vout`.
    pub local_index: OutputIndexInTx,
}

impl Canonical for OutTx {
    const NAME: &'static str = "out_tx";
    const FIXED_WIDTH: Option<usize> = Some(40);

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.tx_hash.as_bytes());
        out.extend_from_slice(&self.local_index.to_raw().to_le_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let b = exact::<40>(Self::NAME, bytes)?;
        Ok(Self {
            tx_hash: TxHash::from_bytes(b[0..32].try_into().expect("32-byte slice")),
            local_index: OutputIndexInTx::from_raw(le_u64(&b[32..40])),
        })
    }
}

/// `output_amounts[amount] ∋ member` — LMDB `outkey`, 96 bytes, **verbatim**.
///
/// The member keeps `amount_index` as its first 8 bytes because that is the
/// member order (`U64PrefixBytes` compares the little-endian prefix first),
/// and LMDB keys every confidential output under `amount = 0` with a dense
/// per-amount `amount_index` (SCW-8; the R8b-2 question is whether that
/// index is *exposed*, not how it is stored).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutKey {
    /// Position among this amount's outputs — the member's sort prefix.
    pub amount_index: AmountIndex,
    /// The global output id (`output_txs` key).
    pub output_id: OutputStorageId,
    /// The output's one-time public key.
    pub pubkey: OneTimePubkey,
    /// The output's `unlock_time`.
    pub unlock_time: Timelock,
    /// The height of the block that created it.
    pub height: BlockHeight,
    /// The amount commitment.
    pub commitment: CommitmentBytes,
}

impl OutKey {
    /// The `amount_index` an encoded member carries — its `U64PrefixBytes`
    /// sort prefix, read without decoding the rest. `None` for bytes too
    /// short to carry one (a member this codec never wrote).
    #[must_use]
    pub fn amount_index_of(encoded: &[u8]) -> Option<AmountIndex> {
        encoded
            .first_chunk::<8>()
            .map(|prefix| AmountIndex::from_raw(u64::from_le_bytes(*prefix)))
    }
}

impl Canonical for OutKey {
    const NAME: &'static str = "out_key";
    const FIXED_WIDTH: Option<usize> = Some(96);

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.amount_index.to_raw().to_le_bytes());
        out.extend_from_slice(&self.output_id.to_raw().to_le_bytes());
        out.extend_from_slice(self.pubkey.as_bytes());
        out.extend_from_slice(&self.unlock_time.to_unlock_raw().to_le_bytes());
        out.extend_from_slice(&self.height.to_raw().to_le_bytes());
        out.extend_from_slice(self.commitment.as_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let b = exact::<96>(Self::NAME, bytes)?;
        Ok(Self {
            amount_index: AmountIndex::from_raw(le_u64(&b[0..8])),
            output_id: OutputStorageId::from_raw(le_u64(&b[8..16])),
            pubkey: OneTimePubkey::from_bytes(b[16..48].try_into().expect("32-byte slice")),
            unlock_time: stored_timelock(le_u64(&b[48..56])),
            height: BlockHeight::from_raw(le_u64(&b[56..64])),
            commitment: CommitmentBytes::from_bytes(b[64..96].try_into().expect("32-byte slice")),
        })
    }
}

/// `tx_outputs[tx_id]` — the dense `uint64_t[]` of per-output amount
/// indices, one per `vout` entry, in `vout` order. Variable width: exactly
/// `8 · n` bytes for `n` outputs; `n = 0` is the empty encoding.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TxOutputIndices(pub Vec<AmountIndex>);

impl Canonical for TxOutputIndices {
    const NAME: &'static str = "tx_output_indices";
    const FIXED_WIDTH: Option<usize> = None;

    fn encode_into(&self, out: &mut Vec<u8>) {
        for index in &self.0 {
            out.extend_from_slice(&index.to_raw().to_le_bytes());
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if !bytes.len().is_multiple_of(8) {
            return Err(CodecError::Invalid {
                codec: Self::NAME,
                reason: "length is not a whole number of u64 entries",
            });
        }
        Ok(Self(
            bytes
                .chunks_exact(8)
                .map(|chunk| AmountIndex::from_raw(le_u64(chunk)))
                .collect(),
        ))
    }
}

/// Read a little-endian `u64` from an 8-byte slice the caller has already
/// bounded (every call site is inside an `exact::<N>` or `chunks_exact(8)`).
fn le_u64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().expect("8-byte slice"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lmdb_order::Hash32;

    fn h(byte: u8) -> BlockHash {
        BlockHash::from_bytes([byte; 32])
    }

    #[test]
    fn block_info_layout_is_the_lmdb_struct_minus_height() {
        let info = BlockInfo {
            timestamp: Timestamp::from_raw(1),
            coins_generated: AtomicUnits::from_raw(2),
            weight: BlockWeight::from_raw(3),
            cumulative_difficulty: CumulativeDifficulty::from_raw((5u128 << 64) | 4), // lo = 4, hi = 5
            hash: h(0xab),
            rct_outputs: 6,
            long_term_weight: LongTermWeight::from_raw(7),
        };
        let bytes = info.encode();
        assert_eq!(bytes.len(), 88);
        // LMDB offsets shifted left by the 8 dropped height bytes.
        assert_eq!(&bytes[0..8], &1u64.to_le_bytes());
        assert_eq!(&bytes[16..24], &3u64.to_le_bytes());
        assert_eq!(&bytes[24..32], &4u64.to_le_bytes(), "bi_diff_lo");
        assert_eq!(&bytes[32..40], &5u64.to_le_bytes(), "bi_diff_hi");
        assert_eq!(&bytes[40..72], &[0xab; 32]);
        assert_eq!(&bytes[72..80], &6u64.to_le_bytes());
        assert_eq!(&bytes[80..88], &7u64.to_le_bytes());
        assert_eq!(BlockInfo::decode(&bytes), Ok(info));
        assert!(matches!(
            BlockInfo::decode(&bytes[..87]),
            Err(CodecError::Length {
                codec: "block_info",
                expected: 88,
                actual: 87
            })
        ));
    }

    #[test]
    fn tx_index_and_out_tx_round_trip_at_their_lmdb_widths() {
        let ti = TxIndex {
            tx_id: TxStorageId::from_raw(9),
            unlock_time: stored_timelock(10),
            height: BlockHeight::from_raw(11),
        };
        let bytes = ti.encode();
        assert_eq!(bytes.len(), 24);
        assert_eq!(TxIndex::decode(&bytes), Ok(ti));

        let ot = OutTx {
            tx_hash: TxHash::from_bytes([0x33; 32]),
            local_index: OutputIndexInTx::from_raw(2),
        };
        let bytes = ot.encode();
        assert_eq!(bytes.len(), 40);
        assert_eq!(&bytes[0..32], &[0x33; 32]);
        assert_eq!(OutTx::decode(&bytes), Ok(ot));
        assert!(OutTx::decode(&bytes[..39]).is_err());
    }

    #[test]
    fn out_key_is_the_96_byte_outkey_with_amount_index_first() {
        let ok = OutKey {
            amount_index: AmountIndex::from_raw(0x0102_0304_0506_0708),
            output_id: OutputStorageId::from_raw(1),
            pubkey: OneTimePubkey::from_bytes([0x11; 32]),
            unlock_time: stored_timelock(2),
            height: BlockHeight::from_raw(3),
            commitment: CommitmentBytes::from_bytes([0x22; 32]),
        };
        let bytes = ok.encode();
        assert_eq!(bytes.len(), 96);
        // The U64PrefixBytes member order reads these first 8 bytes LE.
        assert_eq!(&bytes[0..8], &[8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(&bytes[16..48], &[0x11; 32]);
        assert_eq!(&bytes[64..96], &[0x22; 32]);
        assert_eq!(OutKey::decode(&bytes), Ok(ok));
    }

    #[test]
    fn tx_output_indices_are_dense_u64s_and_refuse_a_partial_entry() {
        let v = TxOutputIndices(vec![
            AmountIndex::from_raw(0),
            AmountIndex::from_raw(7),
            AmountIndex::from_raw(u64::MAX),
        ]);
        let bytes = v.encode();
        assert_eq!(bytes.len(), 24);
        assert_eq!(TxOutputIndices::decode(&bytes), Ok(v));
        assert_eq!(TxOutputIndices::decode(&[]), Ok(TxOutputIndices::default()));
        assert_eq!(
            TxOutputIndices::decode(&bytes[..23]),
            Err(CodecError::Invalid {
                codec: "tx_output_indices",
                reason: "length is not a whole number of u64 entries",
            })
        );
    }

    #[test]
    fn curve_root_is_32_bytes_and_not_a_hash32() {
        let root = CurveTreeRoot::from_bytes([0x5e; 32]);
        assert_eq!(root.encode(), vec![0x5e; 32]);
        assert_eq!(CurveTreeRoot::decode(&[0x5e; 32]), Ok(root));
        assert!(CurveTreeRoot::decode(&[0x5e; 31]).is_err());
        assert_eq!(CurveTreeRoot::NAME, "curve_root");
        assert_ne!(CurveTreeRoot::NAME, Hash32::NAME);
    }
}
