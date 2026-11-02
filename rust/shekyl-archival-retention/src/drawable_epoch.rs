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
//! 2026-11-01), as one [`SupportRoster`].
//!
//! # No shards, no support stream
//!
//! The width is the count of shards closed and final at `h_open(E)`, the
//! prefix `0..width`. Every pair's shard is inside it. No support draw is
//! made while the archive has no closed shard (Rick, 2026-11-02: "you can't
//! draw from an empty pool"), and that is a fact of the type, not a check:
//! a [`SupportRoster`]'s width is a [`NonZeroU64`], and the snapshot holds
//! `Option<SupportRoster>`, present only when the archive has a shard. A
//! roster with members at width zero is not a value, so the seats, the
//! view's width answer and [`crate::select_support_shard`] never meet one.
//! The economy has the same shape without a guard: with no shards `D` is
//! empty and the count rule draws zero.
//!
//! # Who builds it
//!
//! `shekyl-chain-rules`' drawable-epoch builder, from the post-state at
//! `h_open(E)` and by the walk back from a later tip (`SO-D12` increment
//! 2). The bundle verifier reads it through its view from the cutover
//! (§9.6, §11).

use std::borrow::Borrow;
use std::num::NonZeroU64;

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
        /// The archive width: zero when the snapshot has no roster, the
        /// archive having no closed shard.
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
}

/// The support stream's half of an epoch snapshot: the archive width at
/// `h_open(E)` and the complete trees that were members then, each with its
/// parsed receipt key, ascending by persona id (`SO-D12` S1).
///
/// The width is a [`NonZeroU64`]: a roster exists only over an archive with
/// a closed shard. An epoch whose archive has none has no roster at all, so
/// "members at width zero" cannot be written down:
///
/// ```compile_fail,E0308
/// use shekyl_archival_retention::SupportRoster;
/// use shekyl_types::{archival::ReceiptSignPk, PCanonicalId};
///
/// let members: Vec<(PCanonicalId, ReceiptSignPk)> = Vec::new();
/// // A width of zero is not a `NonZeroU64`.
/// let _ = SupportRoster::new(0u64, members);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupportRoster {
    width: NonZeroU64,
    members: Vec<(PCanonicalId, FnDsaHybridPublicKey)>,
}

impl SupportRoster {
    /// The roster over an archive of `width` shards with these members:
    /// each complete tree that was a member at `h_open(E)` with its bond
    /// record's receipt key, in any order.
    ///
    /// A member's key is parsed here, as a pair holder's is in
    /// [`DrawableEpoch::new`]: the bundle rule verifies a support bit under
    /// it.
    ///
    /// # Errors
    ///
    /// - [`DrawableEpochError::DuplicateSupportMember`]: a persona appears
    ///   twice.
    /// - [`DrawableEpochError::SupportKeyMalformed`]: a member's key does
    ///   not parse.
    pub fn new<K: Borrow<ReceiptSignPk>>(
        width: NonZeroU64,
        members: impl IntoIterator<Item = (PCanonicalId, K)>,
    ) -> Result<Self, DrawableEpochError> {
        let mut offered: Vec<(PCanonicalId, K)> = members.into_iter().collect();
        offered.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        if let Some(twice) = offered.windows(2).find(|w| w[0].0 == w[1].0) {
            return Err(DrawableEpochError::DuplicateSupportMember {
                persona: twice[0].0,
            });
        }
        let mut members = Vec::with_capacity(offered.len());
        for (persona, key) in offered {
            let key = FnDsaHybridPublicKey::from_receipt_sign_pk(key.borrow())
                .map_err(|_| DrawableEpochError::SupportKeyMalformed { persona })?;
            members.push((persona, key));
        }
        Ok(Self { width, members })
    }

    /// A roster over an archive of `width` shards with no member: an
    /// archive with a closed shard and no complete tree.
    #[must_use]
    pub const fn empty(width: NonZeroU64) -> Self {
        Self {
            width,
            members: Vec::new(),
        }
    }

    /// The archive width at `h_open(E)`: a support draw selects its shard
    /// from `0..width`.
    #[must_use]
    pub const fn width(&self) -> NonZeroU64 {
        self.width
    }

    /// The members, ascending by persona id, each with its receipt key.
    #[must_use]
    pub fn members(&self) -> &[(PCanonicalId, FnDsaHybridPublicKey)] {
        &self.members
    }

    /// The receipt key of member `persona`, or `None` when it is not one.
    #[must_use]
    pub fn key(&self, persona: &PCanonicalId) -> Option<&FnDsaHybridPublicKey> {
        let at = self
            .members
            .binary_search_by(|(member, _)| member.cmp(persona))
            .ok()?;
        Some(&self.members[at].1)
    }
}

/// The `h_open(E)` state the draw and the bundle rule both read: the
/// drawable pairs in canonical order with each pair's receipt key, and the
/// support roster when the archive has a closed shard.
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
    /// The archive width and the support members. `None` exactly when no
    /// shard was closed and final at `h_open(E)`.
    roster: Option<SupportRoster>,
}

impl DrawableEpoch {
    /// The drawable epoch of `epoch` with this support roster (`None` when
    /// the archive has no closed shard), these receipt keys and these
    /// pairs.
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
    ///   below the roster's width, or there is a pair and no roster.
    /// - [`DrawableEpochError::SupportMemberHoldsPair`]: a support member
    ///   holds a pair of `D`. A record is a complete tree or a compact set,
    ///   never both.
    pub fn new<K: Borrow<ReceiptSignPk>>(
        epoch: SettlementEpoch,
        roster: Option<SupportRoster>,
        receipt_keys: impl IntoIterator<Item = (PCanonicalId, K)>,
        pairs: impl IntoIterator<Item = DrawablePair>,
    ) -> Result<Self, DrawableEpochError> {
        let archive_width = roster.as_ref().map_or(0, |roster| roster.width.get());
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

        if let Some((persona, _)) = roster
            .iter()
            .flat_map(SupportRoster::members)
            .find(|(m, _)| parsed.binary_search_by(|(holder, _)| holder.cmp(m)).is_ok())
        {
            return Err(DrawableEpochError::SupportMemberHoldsPair { persona: *persona });
        }

        Ok(Self {
            epoch,
            pairs,
            receipt_keys: parsed,
            roster,
        })
    }

    /// An epoch with no drawable pair and no support roster.
    ///
    /// The same value as [`Self::new`] with no roster, no keys and no
    /// pairs: the open of a chain that has no bonds and has closed no
    /// shard. There is no pair that could lack a key, so this constructor
    /// does not fail.
    #[must_use]
    pub const fn empty(epoch: SettlementEpoch) -> Self {
        Self {
            epoch,
            pairs: Vec::new(),
            receipt_keys: Vec::new(),
            roster: None,
        }
    }

    /// The support roster: the archive width and the members. `None` when
    /// the archive had no closed shard at `h_open(E)`, and then this epoch
    /// has no support stream.
    #[must_use]
    pub const fn support_roster(&self) -> Option<&SupportRoster> {
        self.roster.as_ref()
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
    ///     ‖ roster_tag[1]                       0x00: no roster; 0x01: a roster, then
    ///     ‖ archive_width_le8                   (the roster's width, never zero)
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
    /// index's receipt is verified under. The roster tag tells "no roster"
    /// (an archive with no closed shard) from "a roster with no members"
    /// (a closed shard and no complete tree); the width fixes the set a
    /// support draw selects from, and the member list fixes who is seated
    /// and the key each support bit is verified under. A member holds no
    /// pair, so it is in the member list and not the persona list. A plain
    /// hash over the whole value, computed once: `D` is never extended a
    /// draw at a time, as the issued-draw index is.
    #[must_use]
    pub fn digest(&self) -> DrawableDigest {
        // The epoch, the width and the three counts are each one
        // little-endian `u64`; the roster tag is one byte.
        const WORD: usize = size_of::<u64>();
        const PAIR_LEN: usize = size_of::<PCanonicalId>() + WORD;
        const PERSONA_LEN: usize = size_of::<PCanonicalId>() + RECEIPT_SIGN_PK_LEN;
        const ROSTER_ABSENT: u8 = 0x00;
        const ROSTER_PRESENT: u8 = 0x01;
        let members = self.roster.as_ref().map_or(0, |r| r.members.len());
        let mut input = Vec::with_capacity(
            5 * WORD
                + 1
                + self.pairs.len() * PAIR_LEN
                + (self.receipt_keys.len() + members) * PERSONA_LEN,
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
        match &self.roster {
            None => input.push(ROSTER_ABSENT),
            Some(roster) => {
                input.push(ROSTER_PRESENT);
                input.extend_from_slice(&roster.width.get().to_le_bytes());
                input.extend_from_slice(&(roster.members.len() as u64).to_le_bytes());
                for (persona, key) in &roster.members {
                    input.extend_from_slice(persona.as_bytes());
                    input.extend_from_slice(key.to_receipt_sign_pk().as_bytes());
                }
            }
        }
        DrawableDigest::from_bytes(cshake256_32(DRAWABLE_EPOCH_DIGEST_CUSTOMIZATION, &input))
    }
}

#[cfg(test)]
#[path = "drawable_epoch_tests.rs"]
mod drawable_epoch_tests;
