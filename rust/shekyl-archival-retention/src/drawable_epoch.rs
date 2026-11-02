// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`DrawableEpoch`]: an epoch's drawable set `D` and each pair's receipt
//! key, its support members with theirs, and the archive width, as one
//! value.
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
//! [`DrawableEpoch::new`] builds a set that has pairs. It fails on a pair
//! whose persona has no receipt key and on a key that does not parse, so
//! "a pair in `D` lacks a key" is not a state the verifier meets.
//! [`DrawableEpoch::empty`] is the set with no pairs: an open with no
//! bonds writes its digest, and that constructor cannot fail.
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
//! # The support stream reads the same value
//!
//! A complete tree is drawn on its own stream, not from `D`
//! (`ARCHIVAL_SUPPORT_DRAW.md`). The schedule seats the trees that were
//! members at `h_open(E)` and selects each draw's shard from the archive
//! width at that block, and the bundle rule verifies a support bit under
//! the member's receipt key. Those are the same kind of fact as `D`: state
//! at `h_open(E)` that the bundle rule reads and admission never rebuilds.
//! So they are filed with it, under its digest (`SO-D12` S1, ruled
//! 2026-11-01). [`DrawableEpoch::with_support`] adds the members;
//! [`DrawableEpoch::new`] takes the width.
//!
//! The width is the count of shards closed and final at `h_open(E)`, the
//! prefix `0..width`. Every pair's shard is inside it, and a set with
//! members has a width above zero: a complete tree of an empty archive
//! holds nothing a draw could select, as a compact holding of a shard not
//! yet closed is no pair. Both are checked here, so neither is a state the
//! verifier meets.
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
pub const DRAWABLE_EPOCH_DIGEST_CUSTOMIZATION: &[u8] = b"shekyl/archival-drawable-epoch-v2";

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
    /// A pair's shard is not below the archive width.
    #[error("persona {persona:?} holds shard {shard}, outside an archive of {width}")]
    PairOutsideArchive {
        /// The persona.
        persona: PCanonicalId,
        /// The shard.
        shard: ShardId,
        /// The archive width.
        width: u64,
    },
    /// A support member was supplied twice.
    #[error("support member {persona:?} was given twice")]
    DuplicateSupportMember {
        /// The persona.
        persona: PCanonicalId,
    },
    /// A support member's receipt key does not parse.
    #[error("support member {persona:?}'s receipt key does not parse")]
    SupportKeyMalformed {
        /// The persona.
        persona: PCanonicalId,
    },
    /// A support member also holds a drawable pair. A record is a
    /// complete tree or a compact set, never both.
    #[error("support member {persona:?} also holds a drawable pair")]
    SupportMemberHoldsPair {
        /// The persona.
        persona: PCanonicalId,
    },
    /// Support members were given for an archive with no shard.
    #[error("support members given for an empty archive")]
    SupportOnEmptyArchive,
}

/// The `h_open(E)` state the draw and the bundle rule both read: the
/// drawable pairs in canonical order with each pair's receipt key, the
/// support members in persona order with theirs, and the archive width.
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
    /// The shards closed and final at `h_open(E)`: the prefix `0..width`.
    archive_width: u64,
    /// The complete trees that were members at `h_open(E)`, ascending by
    /// persona id, each with its parsed receipt key. Empty when the width
    /// is zero.
    support: Vec<(PCanonicalId, FnDsaHybridPublicKey)>,
}

impl DrawableEpoch {
    /// The drawable epoch of `epoch` over an archive of `archive_width`
    /// shards, with these receipt keys and these pairs, and no support
    /// member ([`Self::with_support`] adds them).
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
    /// - [`DrawableEpochError::PairOutsideArchive`]: a pair's shard is not
    ///   below `archive_width`.
    pub fn new<K: Borrow<ReceiptSignPk>>(
        epoch: SettlementEpoch,
        archive_width: u64,
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
        if let Some(outside) = pairs.iter().find(|p| p.shard.to_raw() >= archive_width) {
            return Err(DrawableEpochError::PairOutsideArchive {
                persona: outside.persona,
                shard: outside.shard,
                width: archive_width,
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
            archive_width,
            support: Vec::new(),
        })
    }

    /// This epoch with these support members: the complete trees that
    /// were members at `h_open(E)`, each with its bond record's receipt key,
    /// in any order. Replaces any members already set.
    ///
    /// A member's key is parsed here, as a pair holder's is in
    /// [`Self::new`]: the bundle rule verifies a support bit under it.
    ///
    /// # Errors
    ///
    /// - [`DrawableEpochError::SupportOnEmptyArchive`]: members were given
    ///   and the archive width is zero.
    /// - [`DrawableEpochError::DuplicateSupportMember`]: a persona appears
    ///   twice.
    /// - [`DrawableEpochError::SupportMemberHoldsPair`]: a member holds a
    ///   pair of `D`.
    /// - [`DrawableEpochError::SupportKeyMalformed`]: a member's key does
    ///   not parse.
    pub fn with_support<K: Borrow<ReceiptSignPk>>(
        mut self,
        members: impl IntoIterator<Item = (PCanonicalId, K)>,
    ) -> Result<Self, DrawableEpochError> {
        let mut offered: Vec<(PCanonicalId, K)> = members.into_iter().collect();
        if offered.is_empty() {
            self.support = Vec::new();
            return Ok(self);
        }
        if self.archive_width == 0 {
            return Err(DrawableEpochError::SupportOnEmptyArchive);
        }
        offered.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        if let Some(twice) = offered.windows(2).find(|w| w[0].0 == w[1].0) {
            return Err(DrawableEpochError::DuplicateSupportMember {
                persona: twice[0].0,
            });
        }
        let mut support = Vec::with_capacity(offered.len());
        for (persona, key) in offered {
            if self
                .receipt_keys
                .binary_search_by(|(holder, _)| holder.cmp(&persona))
                .is_ok()
            {
                return Err(DrawableEpochError::SupportMemberHoldsPair { persona });
            }
            let key = FnDsaHybridPublicKey::from_receipt_sign_pk(key.borrow())
                .map_err(|_| DrawableEpochError::SupportKeyMalformed { persona })?;
            support.push((persona, key));
        }
        self.support = support;
        Ok(self)
    }

    /// An epoch with no drawable pair, no support member, and an empty
    /// archive.
    ///
    /// The same value as [`Self::new`] at width zero with no keys and no
    /// pairs: the open of a chain that has no bonds and has closed no
    /// shard. There is no pair that could lack a key, so this constructor
    /// does not fail.
    #[must_use]
    pub const fn empty(epoch: SettlementEpoch) -> Self {
        Self {
            epoch,
            pairs: Vec::new(),
            receipt_keys: Vec::new(),
            archive_width: 0,
            support: Vec::new(),
        }
    }

    /// The archive width at `h_open(E)`: the support draw selects its shard
    /// from `0..width`.
    #[must_use]
    pub const fn archive_width(&self) -> u64 {
        self.archive_width
    }

    /// The support members, ascending by persona id, each with its receipt
    /// key.
    #[must_use]
    pub fn support_members(&self) -> &[(PCanonicalId, FnDsaHybridPublicKey)] {
        &self.support
    }

    /// The receipt key of support member `persona`, or `None` when it is
    /// not a member.
    #[must_use]
    pub fn support_key(&self, persona: &PCanonicalId) -> Option<&FnDsaHybridPublicKey> {
        let at = self
            .support
            .binary_search_by(|(member, _)| member.cmp(persona))
            .ok()?;
        Some(&self.support[at].1)
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
    /// check 2; `SO-D12` ruling B, widened by S1 of 2026-11-01):
    ///
    /// ```text
    /// cSHAKE256_32("shekyl/archival-drawable-epoch-v2",
    ///       E_le8
    ///     ‖ n_pairs_le8
    ///     ‖ for each pair, canonical order:     p_canonical_id[32] ‖ shard_id_le8
    ///     ‖ n_personas_le8
    ///     ‖ for each persona, ascending by id:  p_canonical_id[32] ‖ receipt_sign_pk[1837]
    ///     ‖ archive_width_le8
    ///     ‖ n_members_le8
    ///     ‖ for each member, ascending by id:   p_canonical_id[32] ‖ receipt_sign_pk[1837]
    /// )
    /// ```
    ///
    /// Every field is fixed-width and each list is preceded by its count,
    /// so no two values share an encoding. The personas are those that
    /// hold a pair, which are the keys this value keeps; a key is hashed
    /// once per persona, as its canonical encoding. The pair list fixes
    /// every `index(P, s)`, and the persona list fixes the key each
    /// index's receipt is verified under. The width fixes the set a
    /// support draw selects from, and the member list fixes who is seated
    /// and the key each support bit is verified under. A member holds no
    /// pair, so it is in the member list and not the persona list. A plain
    /// hash over the whole value, computed once: `D` is never extended a
    /// draw at a time, as the issued-draw index is.
    #[must_use]
    pub fn digest(&self) -> DrawableDigest {
        // The epoch, the width and the three counts are each one
        // little-endian `u64`.
        const WORD: usize = size_of::<u64>();
        const PAIR_LEN: usize = size_of::<PCanonicalId>() + WORD;
        const PERSONA_LEN: usize = size_of::<PCanonicalId>() + RECEIPT_SIGN_PK_LEN;
        let mut input = Vec::with_capacity(
            5 * WORD
                + self.pairs.len() * PAIR_LEN
                + (self.receipt_keys.len() + self.support.len()) * PERSONA_LEN,
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
        input.extend_from_slice(&self.archive_width.to_le_bytes());
        input.extend_from_slice(&(self.support.len() as u64).to_le_bytes());
        for (persona, key) in &self.support {
            input.extend_from_slice(persona.as_bytes());
            input.extend_from_slice(key.to_receipt_sign_pk().as_bytes());
        }
        DrawableDigest::from_bytes(cshake256_32(DRAWABLE_EPOCH_DIGEST_CUSTOMIZATION, &input))
    }
}

#[cfg(test)]
#[path = "drawable_epoch_tests.rs"]
mod drawable_epoch_tests;
