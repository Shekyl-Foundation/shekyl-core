// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`DrawableEpoch`]: an epoch's drawable set `D` and each pair's receipt
//! key, as one value.
//!
//! The spec calls this the `h_open(E)` snapshot. The type is not named
//! that: `shekyl-chain-rules`' emission gather is already `EpochSnapshot`
//! (`archival/close.rs`), and a second type of that name in the same
//! judgement would be the wrong one at the cutover.
//!
//! Design: [`ARCHIVAL_SERVE_CREDIT_SPEC.md`](../../../docs/design/ARCHIVAL_SERVE_CREDIT_SPEC.md)
//! §9.1, §9.6 (`SCS-P19`). The draw selects an index into `D`; the bundle
//! rule verifies that pair's receipt under that pair's receipt key. If the
//! two read different heights, a pair in `D` can lack a key, and one such
//! pair refuses a whole bundle. So they read one value: [`DrawableEpoch`]
//! has no height parameter and no second source for either answer.
//!
//! # A pair without a key cannot be built
//!
//! [`DrawableEpoch::new`] is the only constructor. It fails on a pair
//! whose persona has no receipt key and on a key that does not parse, so
//! "a pair in `D` lacks a key" is not a state the verifier meets.
//!
//! # The digest
//!
//! [`DrawableEpoch::digest`] is the 32 bytes the store keeps for `E`
//! (`archival_drawable_digest`): written when `h_open(E)` connects and
//! compared, when `E` settles, with the digest of a value rebuilt from the
//! bond journals (spec §9.5 check 2). It covers the pairs in canonical
//! order and each persona's receipt key, so a drift in either is a
//! different digest (`SO-D12` ruling B, 2026-10-17). One function on the
//! type, so the writer and the check cannot hash different encodings.
//!
//! # Who builds it
//!
//! `shekyl-chain-rules`' drawable-epoch builder, from the post-state at
//! `h_open(E)` and by the walk back from a later tip (`SO-D12` increment
//! 2). The bundle verifier reads it through its view from the cutover
//! (§9.6, §11).

use std::borrow::Borrow;

use shekyl_crypto_pq::fn_dsa_hybrid::FnDsaHybridPublicKey;
use shekyl_types::archival::{DrawableDigest, ReceiptSignPk, RECEIPT_SIGN_PK_LEN};
use shekyl_types::{PCanonicalId, SettlementEpoch, ShardId};

use crate::drawable_pair::DrawablePair;
use crate::hash::cshake256_32;

/// cSHAKE256 customization for [`DrawableEpoch::digest`] (rule 30: one
/// label, one function, versioned).
pub const DRAWABLE_EPOCH_DIGEST_CUSTOMIZATION: &[u8] = b"shekyl/archival-drawable-epoch-v1";

/// Why a [`DrawableEpoch`] could not be built. Each is a defect of the
/// state the caller read, never a verdict on a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DrawableEpochError {
    /// A pair's persona has no receipt key among those supplied.
    #[error("persona {persona:?} holds shard {shard} and has no receipt key")]
    MissingReceiptKey {
        /// The persona.
        persona: PCanonicalId,
        /// One shard it holds.
        shard: ShardId,
    },
    /// A persona's receipt key is not a canonical Ed25519 + FN-DSA-1024
    /// public key.
    #[error("persona {persona:?}'s receipt key does not parse")]
    ReceiptKeyMalformed {
        /// The persona.
        persona: PCanonicalId,
    },
    /// Two receipt keys were supplied for one persona.
    #[error("persona {persona:?} was given two receipt keys")]
    DuplicateReceiptKey {
        /// The persona.
        persona: PCanonicalId,
    },
    /// One pair was supplied twice.
    #[error("persona {persona:?} holds shard {shard} twice")]
    DuplicatePair {
        /// The persona.
        persona: PCanonicalId,
        /// The shard.
        shard: ShardId,
    },
}

/// The `h_open(E)` state the draw and the bundle rule both read: the
/// drawable pairs in canonical order, and each pair's receipt key.
///
/// Canonical order is persona canonical-id bytes, then the shard
/// numerically (§4.1) — [`DrawablePair`]'s `Ord`. `index(P, s)` is a
/// pair's position in it and is constant through the epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrawableEpoch {
    epoch: SettlementEpoch,
    /// Canonical order, no pair twice.
    pairs: Vec<DrawablePair>,
    /// One parsed key per persona that holds a pair, ascending by persona
    /// id. A key is stored once and returned per pair.
    receipt_keys: Vec<(PCanonicalId, FnDsaHybridPublicKey)>,
}

impl DrawableEpoch {
    /// The drawable epoch of `epoch` with these receipt keys and these pairs.
    ///
    /// `receipt_keys` is one entry per persona: its id and its bond
    /// record's receipt key at `h_open(E)`. `pairs` is `D` in any order.
    /// The two are separate arguments so that a key is supplied, parsed and
    /// stored once per persona however many shards it holds; a persona that
    /// holds no pair contributes nothing and its key is not kept.
    ///
    /// A [`ReceiptSignPk`] is a key's length and nothing more (CEN-J28
    /// judged the content before the record was written), so the key of a
    /// persona that holds a pair is parsed here.
    ///
    /// # Errors
    ///
    /// - [`DrawableEpochError::DuplicateReceiptKey`]: a persona appears
    ///   twice in `receipt_keys`.
    /// - [`DrawableEpochError::DuplicatePair`]: a pair appears twice.
    /// - [`DrawableEpochError::MissingReceiptKey`]: a pair's persona is
    ///   not in `receipt_keys`.
    /// - [`DrawableEpochError::ReceiptKeyMalformed`]: the key of a persona
    ///   that holds a pair does not parse.
    pub fn new<K: Borrow<ReceiptSignPk>>(
        epoch: SettlementEpoch,
        receipt_keys: impl IntoIterator<Item = (PCanonicalId, K)>,
        pairs: impl IntoIterator<Item = DrawablePair>,
    ) -> Result<Self, DrawableEpochError> {
        let mut pairs: Vec<DrawablePair> = pairs.into_iter().collect();
        pairs.sort_unstable();
        if let Some(twice) = pairs.windows(2).find(|w| w[0] == w[1]) {
            return Err(DrawableEpochError::DuplicatePair {
                persona: twice[0].persona,
                shard: twice[0].shard,
            });
        }

        let mut offered: Vec<(PCanonicalId, K)> = receipt_keys.into_iter().collect();
        offered.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        if let Some(twice) = offered.windows(2).find(|w| w[0].0 == w[1].0) {
            return Err(DrawableEpochError::DuplicateReceiptKey {
                persona: twice[0].0,
            });
        }

        // `pairs` is sorted by persona first, so its personas are met in
        // ascending order and `parsed` is built sorted.
        let mut parsed: Vec<(PCanonicalId, FnDsaHybridPublicKey)> = Vec::new();
        for pair in &pairs {
            if parsed
                .last()
                .is_some_and(|(persona, _)| *persona == pair.persona)
            {
                continue;
            }
            let persona = pair.persona;
            let Ok(at) = offered.binary_search_by(|(offered, _)| offered.cmp(&persona)) else {
                return Err(DrawableEpochError::MissingReceiptKey {
                    persona,
                    shard: pair.shard,
                });
            };
            let key = FnDsaHybridPublicKey::from_receipt_sign_pk(offered[at].1.borrow())
                .map_err(|_| DrawableEpochError::ReceiptKeyMalformed { persona })?;
            parsed.push((persona, key));
        }

        Ok(Self {
            epoch,
            pairs,
            receipt_keys: parsed,
        })
    }

    /// The epoch this is the `h_open(E)` state of.
    #[must_use]
    pub const fn epoch(&self) -> SettlementEpoch {
        self.epoch
    }

    /// `D`: the number of drawable pairs.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.pairs.len() as u64
    }

    /// Whether the epoch has no drawable pair. A block of such an epoch
    /// has no draws.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// The pair at `index` in canonical order (§4.1).
    #[must_use]
    pub fn pair(&self, index: u64) -> Option<DrawablePair> {
        self.pairs.get(usize::try_from(index).ok()?).copied()
    }

    /// The receipt key of the pair at `index`. `Some` exactly where
    /// [`Self::pair`] is: the constructor refuses a pair without one.
    #[must_use]
    pub fn receipt_key(&self, index: u64) -> Option<&FnDsaHybridPublicKey> {
        let pair = self.pairs.get(usize::try_from(index).ok()?)?;
        let at = self
            .receipt_keys
            .binary_search_by(|(persona, _)| persona.cmp(&pair.persona))
            .ok()?;
        Some(&self.receipt_keys[at].1)
    }

    /// The digest the store keeps for this epoch's drawable set (spec §9.5
    /// check 2; `SO-D12` ruling B):
    ///
    /// ```text
    /// cSHAKE256_32("shekyl/archival-drawable-epoch-v1",
    ///       E_le8
    ///     ‖ n_pairs_le8
    ///     ‖ for each pair, canonical order:     p_canonical_id[32] ‖ shard_id_le8
    ///     ‖ n_personas_le8
    ///     ‖ for each persona, ascending by id:  p_canonical_id[32] ‖ receipt_sign_pk[1837]
    /// )
    /// ```
    ///
    /// Every field is fixed-width and each list is preceded by its count,
    /// so no two values share an encoding. The personas are those that
    /// hold a pair, which are the keys this value keeps; a key is hashed
    /// once per persona, as its canonical encoding. The pair list fixes
    /// every `index(P, s)`, and the persona list fixes the key each
    /// index's receipt is verified under. A plain hash over the whole
    /// value, computed once: `D` is never extended a draw at a time, as
    /// the issued-draw index is.
    #[must_use]
    pub fn digest(&self) -> DrawableDigest {
        // The epoch and the two counts are each one little-endian `u64`.
        const WORD: usize = size_of::<u64>();
        const PAIR_LEN: usize = size_of::<PCanonicalId>() + WORD;
        const PERSONA_LEN: usize = size_of::<PCanonicalId>() + RECEIPT_SIGN_PK_LEN;
        let mut input = Vec::with_capacity(
            3 * WORD + self.pairs.len() * PAIR_LEN + self.receipt_keys.len() * PERSONA_LEN,
        );
        input.extend_from_slice(&self.epoch.to_raw().to_le_bytes());
        input.extend_from_slice(&self.len().to_le_bytes());
        for pair in &self.pairs {
            input.extend_from_slice(pair.persona.as_bytes());
            input.extend_from_slice(&pair.shard.to_raw().to_le_bytes());
        }
        input.extend_from_slice(&(self.receipt_keys.len() as u64).to_le_bytes());
        for (persona, key) in &self.receipt_keys {
            input.extend_from_slice(persona.as_bytes());
            input.extend_from_slice(key.to_receipt_sign_pk().as_bytes());
        }
        DrawableDigest::from_bytes(cshake256_32(DRAWABLE_EPOCH_DIGEST_CUSTOMIZATION, &input))
    }
}

#[cfg(test)]
#[path = "drawable_epoch_tests.rs"]
mod drawable_epoch_tests;
