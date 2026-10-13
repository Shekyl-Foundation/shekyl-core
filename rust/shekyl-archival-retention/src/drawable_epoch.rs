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
//! # Disposition: STAGED
//!
//! This is the type, its constructor and its tests. The value is built
//! from the bond journals as of `h_open(E)` by `SO-D12`'s increment 2, and
//! read by the bundle verifier in `shekyl-chain-rules` through its view
//! ([`ARCHIVAL_SERVE_CREDIT_SPEC.md`](../../../docs/design/ARCHIVAL_SERVE_CREDIT_SPEC.md)
//! §9.6, §11). Until then its only callers are tests.

use shekyl_crypto_pq::fn_dsa_hybrid::FnDsaHybridPublicKey;
use shekyl_types::{PCanonicalId, SettlementEpoch};

use crate::drawable_pair::DrawablePair;

/// Why a [`DrawableEpoch`] could not be built. Each is a defect of the
/// state the caller read, never a verdict on a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DrawableEpochError {
    /// A pair's persona has no receipt key among those supplied.
    #[error("persona {persona:?} holds shard {shard_id} and has no receipt key")]
    MissingReceiptKey {
        /// The persona.
        persona: PCanonicalId,
        /// One shard it holds.
        shard_id: u64,
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
    #[error("persona {persona:?} holds shard {shard_id} twice")]
    DuplicatePair {
        /// The persona.
        persona: PCanonicalId,
        /// The shard.
        shard_id: u64,
    },
}

/// The `h_open(E)` state the draw and the bundle rule both read: the
/// drawable pairs in canonical order, and each pair's receipt key.
///
/// Canonical order is persona canonical-id bytes, then `shard_id`
/// numerically (§4.1) — [`DrawablePair`]'s `Ord`. `index(P, s)` is a
/// pair's position in it and is constant through the epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrawableEpoch {
    epoch: SettlementEpoch,
    /// Canonical order, no pair twice.
    pairs: Vec<DrawablePair>,
    /// One parsed key per persona that holds a pair, ascending by persona
    /// id. A key is stored once and returned per pair.
    receipt_keys: Vec<([u8; 32], FnDsaHybridPublicKey)>,
}

impl DrawableEpoch {
    /// The drawable epoch of `epoch` with these receipt keys and these pairs.
    ///
    /// `receipt_keys` is one entry per persona: its canonical id and its
    /// receipt key's canonical bytes, as its bond record carries them at
    /// `h_open(E)`. `pairs` is `D` in any order. The two are separate
    /// arguments so that a key is supplied, parsed and stored once per
    /// persona however many shards it holds; a persona that holds no pair
    /// contributes nothing and its key is not kept.
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
    pub fn new<K: AsRef<[u8]>>(
        epoch: SettlementEpoch,
        receipt_keys: impl IntoIterator<Item = ([u8; 32], K)>,
        pairs: impl IntoIterator<Item = DrawablePair>,
    ) -> Result<Self, DrawableEpochError> {
        let mut pairs: Vec<DrawablePair> = pairs.into_iter().collect();
        pairs.sort_unstable();
        if let Some(twice) = pairs.windows(2).find(|w| w[0] == w[1]) {
            return Err(DrawableEpochError::DuplicatePair {
                persona: PCanonicalId::from_bytes(twice[0].p_id),
                shard_id: twice[0].shard_id,
            });
        }

        let mut offered: Vec<([u8; 32], K)> = receipt_keys.into_iter().collect();
        offered.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        if let Some(twice) = offered.windows(2).find(|w| w[0].0 == w[1].0) {
            return Err(DrawableEpochError::DuplicateReceiptKey {
                persona: PCanonicalId::from_bytes(twice[0].0),
            });
        }

        // `pairs` is sorted by persona first, so its personas are met in
        // ascending order and `parsed` is built sorted.
        let mut parsed: Vec<([u8; 32], FnDsaHybridPublicKey)> = Vec::new();
        for pair in &pairs {
            if parsed.last().is_some_and(|(p_id, _)| *p_id == pair.p_id) {
                continue;
            }
            let persona = PCanonicalId::from_bytes(pair.p_id);
            let Ok(at) = offered.binary_search_by(|(p_id, _)| p_id.cmp(&pair.p_id)) else {
                return Err(DrawableEpochError::MissingReceiptKey {
                    persona,
                    shard_id: pair.shard_id,
                });
            };
            let key = FnDsaHybridPublicKey::from_canonical_bytes(offered[at].1.as_ref())
                .map_err(|_| DrawableEpochError::ReceiptKeyMalformed { persona })?;
            parsed.push((pair.p_id, key));
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
            .binary_search_by(|(p_id, _)| p_id.cmp(&pair.p_id))
            .ok()?;
        Some(&self.receipt_keys[at].1)
    }
}

#[cfg(test)]
#[path = "drawable_epoch_tests.rs"]
mod drawable_epoch_tests;
