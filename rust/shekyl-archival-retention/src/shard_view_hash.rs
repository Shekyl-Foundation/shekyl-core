// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The **view hash** of a `W`-byte archival shard — `SV-D1`
//! ([`docs/design/SHARD_VIEW_FETCH.md`](../../../docs/design/SHARD_VIEW_FETCH.md)).
//!
//! The visualization's seed is a digest **over the shard's archival bytes**:
//! for every in-domain transaction in `[b_k, b_{k+1})`, in storage order,
//! its txid, its prunable region and its `pqc_auths`, each component
//! length-framed. The input is the bytes, never their retained digests:
//! folding `txs_prunable_hash` / `txs_pqc_auth_hash` would make the value
//! computable from skeleton rows, and the ruling exists to make it *not* be
//! — a node that discarded the body cannot answer a view, and the fetch is
//! the point (`SV-D2`).
//!
//! ```text
//! view_hash(k) = cSHAKE256(
//!     "shekyl/archival-shard-view-hash-v1",
//!     shard_id_le[8]
//!   ‖ for each tx in [b_k, b_{k+1}):
//!         txid[32] ‖ prunable_len_le[8] ‖ prunable ‖ pqc_auths_len_le[8] ‖ pqc_auths
//! )[..32]
//! ```
//!
//! Distinct from the challenge path's verification: a challenge checks each
//! transaction against its two retained digests (`PDM-Q6`); this fold is per
//! shard, never a skeleton row, never consensus, and never supplied by the
//! serving persona — a value `P` sent would be a claim about the body, and
//! the picture is a function of the body.
//!
//! The hasher is a streaming fold so the fetch client folds it in the same
//! pass that verifies, one transaction resident (`SV-D8`); a local holder
//! folds it over its own store. Feeding the same transactions in the same
//! order from any source gives the one value, and [`shard_view_hash`] is
//! this hasher run once, so the two cannot differ.

use sha3::digest::core_api::CoreWrapper;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{CShake256, CShake256Core};
use shekyl_types::{ShardId, ShardViewHash, TxHash};

/// cSHAKE256 customization for the shard view hash (rule 30: one label, one
/// function, versioned). Registered in `CRYPTO_DOMAIN_REGISTRY.tsv`
/// (mechanism 1).
pub const SHARD_VIEW_HASH_CUSTOMIZATION: &[u8] = b"shekyl/archival-shard-view-hash-v1";

/// One in-domain transaction's archival components, as the fold consumes
/// them: the identity that fixes order, and the two byte regions that *are*
/// the archival good (`SHT-Q2`). Borrowed, so a streaming verifier hands
/// over the transaction it just checked without copying it.
#[derive(Clone, Copy, Debug)]
pub struct ArchivalTx<'a> {
    /// The transaction's id (binds order and identity into the fold).
    pub txid: &'a TxHash,
    /// The prunable region's bytes, exactly as serialized.
    pub prunable: &'a [u8],
    /// The `pqc_auths` bytes, exactly as serialized; empty for a body
    /// without them.
    pub pqc_auths: &'a [u8],
}

/// [`shard_view_hash`] computed incrementally, one transaction at a time.
pub struct ShardViewHasher(CShake256);

impl ShardViewHasher {
    /// Start the fold for `shard_id`.
    #[must_use]
    pub fn begin(shard_id: ShardId) -> Self {
        let mut hasher: CShake256 =
            CoreWrapper::from_core(CShake256Core::new(SHARD_VIEW_HASH_CUSTOMIZATION));
        hasher.update(&shard_id.to_raw().to_le_bytes());
        Self(hasher)
    }

    /// Fold the next transaction in storage order.
    pub fn fold_tx(&mut self, tx: ArchivalTx<'_>) {
        self.0.update(tx.txid.as_bytes());
        self.0.update(&len_le(tx.prunable));
        self.0.update(tx.prunable);
        self.0.update(&len_le(tx.pqc_auths));
        self.0.update(tx.pqc_auths);
    }

    /// The shard's view hash.
    #[must_use]
    pub fn finish(self) -> ShardViewHash {
        let mut out = [0u8; 32];
        self.0.finalize_xof().read(&mut out);
        ShardViewHash::from_bytes(out)
    }
}

/// The view hash of `shard_id` over `txs`, which must be the shard's
/// in-domain transactions in storage order.
#[must_use]
pub fn shard_view_hash<'a>(
    shard_id: ShardId,
    txs: impl IntoIterator<Item = ArchivalTx<'a>>,
) -> ShardViewHash {
    let mut hasher = ShardViewHasher::begin(shard_id);
    for tx in txs {
        hasher.fold_tx(tx);
    }
    hasher.finish()
}

/// `u64` little-endian length prefix. A region longer than `u64::MAX` bytes
/// does not exist; the cast is the framing's width, not a truncation.
fn len_le(bytes: &[u8]) -> [u8; 8] {
    (bytes.len() as u64).to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::cshake256_32;

    fn tx(seed: u8, prunable_len: usize, pqc_len: usize) -> (TxHash, Vec<u8>, Vec<u8>) {
        let txid = TxHash::from_bytes([seed; 32]);
        let prunable: Vec<u8> = (0u8..).take(prunable_len).map(|i| i ^ seed).collect();
        let pqc: Vec<u8> = (0u8..)
            .take(pqc_len)
            .map(|i| i.wrapping_mul(seed))
            .collect();
        (txid, prunable, pqc)
    }

    fn view(txid: &TxHash, prunable: &[u8], pqc: &[u8]) -> ArchivalTx<'static> {
        // Leak for the test's lifetime: the borrow is what the production
        // caller hands over from its own stream buffer.
        ArchivalTx {
            txid: Box::leak(Box::new(*txid)),
            prunable: Box::leak(prunable.to_vec().into_boxed_slice()),
            pqc_auths: Box::leak(pqc.to_vec().into_boxed_slice()),
        }
    }

    /// The fold is the one-shot preimage under the registered label: the
    /// hasher cannot drift from the documented formula.
    #[test]
    fn fold_equals_the_documented_one_shot_preimage() {
        let (a_id, a_p, a_q) = tx(0x11, 40, 16);
        let (b_id, b_p, b_q) = tx(0x22, 7, 0);
        let shard = ShardId::from_raw(9);

        let mut preimage = Vec::new();
        preimage.extend_from_slice(&9u64.to_le_bytes());
        for (id, p, q) in [(&a_id, &a_p, &a_q), (&b_id, &b_p, &b_q)] {
            preimage.extend_from_slice(id.as_bytes());
            preimage.extend_from_slice(&(p.len() as u64).to_le_bytes());
            preimage.extend_from_slice(p);
            preimage.extend_from_slice(&(q.len() as u64).to_le_bytes());
            preimage.extend_from_slice(q);
        }
        let expected = cshake256_32(SHARD_VIEW_HASH_CUSTOMIZATION, &preimage);

        let folded = shard_view_hash(shard, [view(&a_id, &a_p, &a_q), view(&b_id, &b_p, &b_q)]);
        assert_eq!(folded.to_bytes(), expected);
    }

    /// Order is part of the value: the same two transactions swapped are a
    /// different shard.
    #[test]
    fn order_is_bound() {
        let (a_id, a_p, a_q) = tx(0x11, 40, 16);
        let (b_id, b_p, b_q) = tx(0x22, 7, 3);
        let shard = ShardId::from_raw(1);
        let ab = shard_view_hash(shard, [view(&a_id, &a_p, &a_q), view(&b_id, &b_p, &b_q)]);
        let ba = shard_view_hash(shard, [view(&b_id, &b_p, &b_q), view(&a_id, &a_p, &a_q)]);
        assert_ne!(ab, ba);
    }

    /// Length framing keeps the concatenation injective: moving one byte
    /// from the prunable region to `pqc_auths` is a different input.
    #[test]
    fn components_are_length_framed() {
        let txid = TxHash::from_bytes([0x33; 32]);
        let bytes: Vec<u8> = (1u8..=20).collect();
        let shard = ShardId::from_raw(4);
        let split_a = shard_view_hash(shard, [view(&txid, &bytes[..12], &bytes[12..])]);
        let split_b = shard_view_hash(shard, [view(&txid, &bytes[..13], &bytes[13..])]);
        assert_ne!(split_a, split_b);
    }

    /// The shard id and every archival byte are covered; an empty shard is
    /// still a value (the partition never produces one, but the function is
    /// total).
    #[test]
    fn shard_id_and_every_byte_are_covered() {
        let (id, p, q) = tx(0x44, 64, 8);
        let base = shard_view_hash(ShardId::from_raw(2), [view(&id, &p, &q)]);
        assert_ne!(
            base,
            shard_view_hash(ShardId::from_raw(3), [view(&id, &p, &q)])
        );
        for i in [0, p.len() / 2, p.len() - 1] {
            let mut other = p.clone();
            other[i] ^= 0x80;
            assert_ne!(
                base,
                shard_view_hash(ShardId::from_raw(2), [view(&id, &other, &q)])
            );
        }
        let mut other_q = q.clone();
        other_q[0] ^= 1;
        assert_ne!(
            base,
            shard_view_hash(ShardId::from_raw(2), [view(&id, &p, &other_q)])
        );
        let _empty = shard_view_hash(ShardId::ZERO, []);
    }

    /// Known answer, pinned so Python (`shekyl-dev/visualization`,
    /// `shard_visual/view_hash.py`) and Rust share one value; the pin was
    /// cross-checked against pycryptodome's independent cSHAKE256 before it
    /// was written down. Two transactions, shard 7. Regenerate only with a
    /// `-v2` label (`SV-D1` reopening).
    #[test]
    fn known_answer_v1() {
        let a = TxHash::from_bytes([0x01; 32]);
        let b = TxHash::from_bytes([0x02; 32]);
        let a_p: Vec<u8> = (0u8..32).collect();
        let a_q: Vec<u8> = vec![0xAA; 8];
        let b_p: Vec<u8> = (0u8..16).rev().collect();
        let got = shard_view_hash(
            ShardId::from_raw(7),
            [view(&a, &a_p, &a_q), view(&b, &b_p, &[])],
        );
        assert_eq!(
            got.to_string(),
            "82cd08db7efc6b0d72e4855c936c3a8a688924e2938eec4522d9fbaaf318f33d",
            "known answer moved: the fold or the label changed"
        );
    }
}
