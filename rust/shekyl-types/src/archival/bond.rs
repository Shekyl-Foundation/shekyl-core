// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The persisted bond record and the close-row scalars read beside it
//! (DRS-E1 S-ARCH `SAR-Q3`, DRS-E4 `ARW-Q8`). Shapes only: the `Canonical`
//! codec stays in `shekyl-store-codec`.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use shekyl_units::AtomicUnits;

use crate::{BlockHeight, PCanonicalId, SettlementEpoch, ShardId};

use super::{
    BadInterval, HoldingsDescriptor, HoldingsKind, ShardSet, ShardSetError, MAX_HOLDINGS_SHARDS,
};

// ---------------------------------------------------------------------------
// The persisted bond record (DRS-E1 S-ARCH `SAR-Q3`; moved here by DRS-E4
// `ARW-Q8`) — shapes only. The `Canonical` codec is `shekyl-store-codec`'s.
// ---------------------------------------------------------------------------

/// Canonical length of a persona's receipt key: the Ed25519 + FN-DSA-1024
/// hybrid public key in its canonical encoding (four-byte header, two
/// length-prefixed halves; `FN_DSA_HYBRID.md` §1). Twin of
/// `shekyl_crypto_pq::fn_dsa_hybrid::FnDsaHybridPublicKey::CANONICAL_LEN`,
/// restated because this crate holds words and depends on no cryptography;
/// `shekyl-wire`'s `archival_arms_roundtrip` test, which sees both, holds
/// the two equal.
pub const RECEIPT_SIGN_PK_LEN: usize = 1837;

/// A persona's receipt key as the chain carries it: exactly
/// [`RECEIPT_SIGN_PK_LEN`] bytes, the canonical encoding of an Ed25519 +
/// FN-DSA-1024 hybrid public key (`FN_DSA_HYBRID.md` §8).
///
/// The JoinMarket bond post commits it and the bond record keeps it, so the
/// wire, the validator and both stores name the same bytes: the type lives
/// here (rule 18, a type both stores need), and the computation over it —
/// parsing it as a key, verifying under it — stays in `shekyl-crypto-pq`.
///
/// **The length is the type's; that the bytes are a key is not.** A value
/// of this type is 1,837 bytes and nothing more is claimed. CEN-J28 is what
/// judges a posted one a key, before it reaches a record.
///
/// The bytes are boxed: the key is larger than everything else in a bond
/// post together, and inline it would make every enum and struct that
/// carries one that much larger to move.
#[derive(Clone, PartialEq, Eq)]
pub struct ReceiptSignPk(Box<[u8; RECEIPT_SIGN_PK_LEN]>);

impl ReceiptSignPk {
    /// Wrap exactly [`RECEIPT_SIGN_PK_LEN`] bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; RECEIPT_SIGN_PK_LEN]) -> Self {
        Self(Box::new(bytes))
    }

    /// The canonical bytes.
    ///
    /// There is no mutable counterpart: a chain-carried key is not edited
    /// in place. A fixture that needs a string one edit away from a key
    /// copies these bytes, edits the copy and wraps it with
    /// [`Self::from_bytes`].
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; RECEIPT_SIGN_PK_LEN] {
        &self.0
    }
}

impl From<[u8; RECEIPT_SIGN_PK_LEN]> for ReceiptSignPk {
    fn from(bytes: [u8; RECEIPT_SIGN_PK_LEN]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl fmt::Debug for ReceiptSignPk {
    /// Eight bytes of each half: the first eight of the Ed25519 key, which
    /// follows the encoding's 8-byte header, and the last eight of the
    /// string, which are the FN-DSA key's. The header is the same in every
    /// valid key, so a prefix would print every key alike; these tell two
    /// keys apart in a failed assertion, whichever half differs, without
    /// printing 1,837 bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const HEADER: usize = 8;
        const SHOWN: usize = 8;
        f.write_str("ReceiptSignPk(")?;
        for byte in &self.0[HEADER..HEADER + SHOWN] {
            write!(f, "{byte:02x}")?;
        }
        f.write_str("…")?;
        for byte in &self.0[RECEIPT_SIGN_PK_LEN - SHOWN..] {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

/// Upper bound on the byte length of each of the bond record's two
/// length-prefixed key fields (`hybrid_pubkey`, `bond_spend_pk`) — the C++
/// codec's `kMaxPubkeyLen`. A **codec** cap, not the canonical length: every
/// record is created by JoinMarket connect, whose vin serializer enforces the
/// exact hybrid-key length; a store bounds what an untrusted decode will
/// allocate for.
pub const MAX_BOND_KEY_BYTES: usize = 2048;

/// One held shard and the settlement epoch stored as its add epoch.
///
/// On the production join path since the immutable-bond ruling (2026-09-20)
/// that epoch is the bond's join epoch: a shard joins at `JoinMarket` or
/// never. The type does not enforce the equality. Slash-log reconstruction,
/// the held-at-height bound, and per-shard `E_add + 1` serve-credit counting
/// (P2B-7 Pin 5) still read the stored field. Collapsing the column into the
/// bond's join epoch is enumerated, not ruled, at
/// `PRINCIPAL_STAKE_LIFECYCLE.md` §5.3.2 row 7 — a collapse-to-record-field
/// candidate, not a deletion.
///
/// *Records-was:* a `HoldingsUpdate` add carried its own `E_add`, and the
/// field powered the drop-eligibility gate. That kind is REJECTED 2026-09-20.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldShard {
    /// Which shard.
    pub shard: ShardId,
    /// The settlement epoch the shard was acquired in.
    pub add_epoch: SettlementEpoch,
}

/// A bond's compact holdings: one [`HeldShard`] per shard.
///
/// The list is private. [`Holdings::shard_set`] is the constructor, and it
/// is the only one: a duplicate or an over-cap list cannot be spelled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldShards {
    pairs: Vec<HeldShard>,
}

impl HeldShards {
    /// The pairs, in insertion order.
    #[must_use]
    pub fn as_slice(&self) -> &[HeldShard] {
        &self.pairs
    }
}

impl core::ops::Deref for HeldShards {
    type Target = [HeldShard];

    fn deref(&self) -> &[HeldShard] {
        &self.pairs
    }
}

/// A bond's holdings as persisted (gate-4 §3.4.1).
///
/// The C++ kept a kind byte plus `held_shard_ids` and `shard_add_epochs`,
/// "index-parallel", coupled by one count in the codec and by call-site
/// discipline in memory, with a FATAL on desync. Here a compact holding is a
/// list of [`HeldShard`] pairs and a complete tree carries nothing: the two
/// lengths cannot disagree because there is one list (**SI-14**). The
/// compact list is a [`HeldShards`], so the duplicate and cap checks in
/// [`Holdings::shard_set`] are the only way to build one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Holdings {
    /// An explicit, bounded, duplicate-free list — insertion order
    /// preserved, as the wire's [`ShardSet`] is.
    ShardSet(HeldShards),
    /// Every shard; a foundation record. Like every record since the
    /// immutable-bond ruling (2026-09-20), its holdings cannot change.
    CompleteTree,
}

/// Why a shard list is not a valid [`Holdings::ShardSet`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HoldingsError {
    /// More than [`MAX_HOLDINGS_SHARDS`] entries.
    CountExceeded {
        /// The length offered.
        got: usize,
    },
    /// A shard appears twice.
    Duplicate {
        /// The repeated shard.
        shard: ShardId,
    },
}

impl fmt::Display for HoldingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CountExceeded { got } => {
                write!(f, "held-shard count {got} exceeds {MAX_HOLDINGS_SHARDS}")
            }
            Self::Duplicate { shard } => {
                write!(f, "shard {} is held twice", shard.to_raw())
            }
        }
    }
}

impl core::error::Error for HoldingsError {}

impl From<ShardSetError> for HoldingsError {
    fn from(err: ShardSetError) -> Self {
        match err {
            ShardSetError::CountExceeded { got } => Self::CountExceeded { got },
            ShardSetError::Duplicate { shard_id } => Self::Duplicate {
                shard: ShardId::from_raw(shard_id),
            },
        }
    }
}

impl Holdings {
    /// A compact holding from its pairs, refusing an over-cap or
    /// duplicate-bearing list. Uniqueness and the cap are [`ShardSet::new`]'s,
    /// the wire form's check, applied to the shard ids of these pairs.
    ///
    /// # Errors
    ///
    /// [`HoldingsError`] naming the bound or the first duplicate.
    pub fn shard_set(held: Vec<HeldShard>) -> Result<Self, HoldingsError> {
        let ids = held.iter().map(|h| h.shard.to_raw()).collect::<Vec<_>>();
        ShardSet::new(ids)?;
        Ok(Self::ShardSet(HeldShards { pairs: held }))
    }

    /// The kind byte the wire and the C++ record both use.
    #[must_use]
    pub const fn kind(&self) -> HoldingsKind {
        match self {
            Self::ShardSet(_) => HoldingsKind::ShardSetCompact,
            Self::CompleteTree => HoldingsKind::CompleteTree,
        }
    }

    /// Whether `shard` is held **at tip** (the record's current state). The
    /// as-of-height question — "was it held at `h`?" — is a fold over this
    /// and the slash log, the retention crate's (`holds_shard_at`, E4).
    #[must_use]
    pub fn holds(&self, shard: ShardId) -> bool {
        match self {
            Self::CompleteTree => true,
            Self::ShardSet(held) => held.iter().any(|h| h.shard == shard),
        }
    }

    /// The stored add epoch of `shard` if the shard is held. `None` for a
    /// complete tree, which has no per-shard epochs. On the production join
    /// path since 2026-09-20 this equals the bond's join epoch; the type
    /// does not enforce it (`PRINCIPAL_STAKE_LIFECYCLE.md` §5.3.2 row 7).
    #[must_use]
    pub fn add_epoch(&self, shard: ShardId) -> Option<SettlementEpoch> {
        match self {
            Self::CompleteTree => None,
            Self::ShardSet(held) => held.iter().find(|h| h.shard == shard).map(|h| h.add_epoch),
        }
    }

    /// The wire-shaped view the retention crate's folds take: the kind and
    /// the id list (empty for a complete tree). Insertion order preserved.
    ///
    /// Infallible: [`HeldShards`] is built only by [`Self::shard_set`], which
    /// has already run [`ShardSet::new`] on these ids.
    #[must_use]
    pub fn descriptor(&self) -> HoldingsDescriptor {
        match self {
            Self::CompleteTree => HoldingsDescriptor {
                kind: HoldingsKind::CompleteTree,
                shard_ids: ShardSet::empty(),
            },
            Self::ShardSet(held) => {
                let ids = held.iter().map(|h| h.shard.to_raw()).collect::<Vec<_>>();
                HoldingsDescriptor {
                    kind: HoldingsKind::ShardSetCompact,
                    shard_ids: ShardSet::new(ids)
                        .expect("HeldShards is built only after ShardSet::new"),
                }
            }
        }
    }
}

/// Height of the emission that first paid a persona.
///
/// The C++ record stored "not yet paid" as height `0`, and documented that
/// `0` cannot be a real payment: no emission pays before the first
/// settlement epoch closes, which is after genesis. Absence on the record
/// is [`Option::None`]. This type is the `Some` arm, so a paid height of
/// zero cannot be constructed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FirstPayingHeight(BlockHeight);

impl FirstPayingHeight {
    /// A paying height. `None` when `height` is [`BlockHeight::ZERO`] — that
    /// word is the record's absence, not a payment.
    #[must_use]
    pub const fn new(height: BlockHeight) -> Option<Self> {
        if height.to_raw() == BlockHeight::ZERO.to_raw() {
            None
        } else {
            Some(Self(height))
        }
    }

    /// The height.
    #[must_use]
    pub const fn height(self) -> BlockHeight {
        self.0
    }

    /// The height as a raw chain ordinal.
    #[must_use]
    pub const fn to_raw(self) -> u64 {
        self.0.to_raw()
    }
}

/// `archival_bond[p]` — one persona's bond record, the typed form of the
/// C++ `ArchivalBondValue` v7: every field that record carried,
/// re-specified (`SAR-Q3`: same semantics, not byte-compatible; the codec's
/// layout is documented on its `Canonical` impl in `shekyl-store-codec`).
///
/// What the re-specification buys:
///
/// - [`Holdings`] is one sum type. A held shard and its add-epoch are one
///   [`HeldShard`]; the parallel-vector desync the C++ made FATAL is
///   unrepresentable (**SI-14**).
/// - `first_paying_emission_height` is an [`Option<FirstPayingHeight>`]:
///   the C++ spelled "not yet paid" as height `0`; the type refuses it.
///
/// What it does not buy, deliberately: the interval log keeps
/// [`BadInterval`]'s two entry kinds in one vector (SAR-10 — the fold's
/// input, the retention crate's to re-shape), and the claimed-epoch set is
/// held as the strictly-increasing list the C++ validated, not re-derived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondRecord {
    /// The hybrid identity key `P` bonded with; `p_canonical_id` derives from
    /// it (`shekyl-archival-retention::id`).
    pub hybrid_pubkey: Vec<u8>,
    /// GF-1 debit authorizer, committed once at JoinMarket connect and
    /// immutable for the record's life; every later `bond_debit` verifies
    /// against this copy, never the identity key.
    pub bond_spend_pk: Vec<u8>,
    /// The persona's receipt key (`FN_DSA_HYBRID.md` §8): the key every
    /// receipt this persona signs is verified under. Every record has one —
    /// a JoinMarket has one wire form and it commits the key. Set once, at
    /// JoinMarket connect, from the post the identity key signed, and never
    /// changed: Reinstate and Release do not touch it, and no post kind
    /// exists that could (bond records are immutable in this respect, as in
    /// `bond_spend_pk` and the endpoint). That it is a key is CEN-J28's,
    /// judged before connect. Stored fixed-width, with no length prefix.
    pub receipt_sign_pk: ReceiptSignPk,
    /// The 32-byte serving endpoint, written once at JoinMarket connect. Any
    /// 32 bytes — zero is a value the vin carried, not an absence.
    pub endpoint: [u8; 32],
    /// The settlement epoch the bond joined in.
    pub join_settlement_epoch: SettlementEpoch,
    /// Per-`P` bonded balance (gate-4 §4.1); equals `bond_floor(holdings)`
    /// post-connect.
    pub bonded_total: AtomicUnits,
    /// What the bond holds (SI-14).
    pub holdings: Holdings,
    /// The standing log: bad-standing intervals and clean-close markers, in
    /// write order, at most [`super::MAX_BOND_BAD_INTERVALS`] (genesis-frozen).
    pub bad_intervals: Vec<BadInterval>,
    /// Settlement epochs already claimed by an emission vin, strictly
    /// increasing, at most [`super::MAX_CLAIMED_EPOCH_ENTRIES`] and spanning at most
    /// [`super::MAX_CLAIM_AGE_W_EPOCHS`] (`last − first ≤ W`). The windowed
    /// `check_and_set` that maintains it is consensus and lives in
    /// `shekyl-archival-retention::claimed_epochs`; this is the at-rest
    /// shape.
    pub claimed_settlement_epochs: Vec<SettlementEpoch>,
    /// Height of the first emission that paid this `P`; set once, immutable.
    /// `None` until then. Height zero is not a value of this field.
    pub first_paying_emission_height: Option<FirstPayingHeight>,
}

impl BondRecord {
    /// Whether the record is a foundation complete-tree bond.
    #[must_use]
    pub const fn is_complete_tree(&self) -> bool {
        matches!(self.holdings, Holdings::CompleteTree)
    }
}

/// `archival_r_market[(shard, epoch)]` — the market's co-holder count for a
/// shard at an epoch's close (`ARCHIVAL_CONSENSUS_STATE.md` §3.3). A
/// **written** `RMarket(0)` is a closed epoch with no co-holders; an absent
/// row is an epoch that never closed — the read returns `Option` and does not
/// invent `0` (SAR-8), and the writer writes the zero (DRS-E4 `ARW-Q4`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RMarket(u64);

impl RMarket {
    /// Wrap a raw count.
    #[must_use]
    pub const fn from_raw(n: u64) -> Self {
        Self(n)
    }

    /// The count.
    #[must_use]
    pub const fn to_raw(self) -> u64 {
        self.0
    }
}

/// `archival_sigma_work[epoch]` — the finalized `Σwork(E)` in milli-units,
/// frozen at epoch close and never recomputed by a verifier (the stored
/// denominator; `ARCHIVAL_CONSENSUS_STATE.md` §3.4). `0` is a closed epoch
/// that did no work or was M1-gated; absent is an epoch that never closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SigmaWorkMilli(u64);

impl SigmaWorkMilli {
    /// Wrap a raw milli-work value.
    #[must_use]
    pub const fn from_raw(n: u64) -> Self {
        Self(n)
    }

    /// The milli-work value.
    #[must_use]
    pub const fn to_raw(self) -> u64 {
        self.0
    }
}

/// `archival_complete_trees[E]` — the personas `E`'s slash pass excluded
/// from `E`'s market **as complete trees** (`ARCHIVAL_SETTLEMENT_WRITER.md`
/// `SO-D12h`, ruled 2026-10-17): among the bonds the gather credited at `E`,
/// those whose record held a complete tree as the pass left it.
///
/// The fact is frozen at the pass because the record does not keep it. A
/// complete tree that is slashed or released afterwards holds a compact
/// set, and a claim's re-gather that read the record would put it in the
/// market the pass kept it out of. So both readers of the gather — the
/// pass, and the claim's re-gather (CEN-J23) — take every bond's
/// complete-tree flag from this set and neither reads the record's.
///
/// Persona ids, strictly increasing: one order, no duplicate, so two sets
/// with one membership have one encoding. The empty set is a value (an
/// epoch whose credited bonds were all compact, or that credited none),
/// written like any other (`ARW-Q4`); an epoch with no row was not settled.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CompleteTreeSet(Vec<PCanonicalId>);

/// [`CompleteTreeSet::new`]'s refusal: the ids are not strictly increasing.
/// `index` is the first id not above the one before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompleteTreeSetError {
    /// Position of the first out-of-order or repeated id.
    pub index: usize,
}

impl fmt::Display for CompleteTreeSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "complete-tree persona {} is not above the one before it",
            self.index
        )
    }
}

impl CompleteTreeSet {
    /// The set of `ids`, which must be strictly increasing.
    ///
    /// # Errors
    ///
    /// [`CompleteTreeSetError`] at the first id that is not above its
    /// predecessor.
    pub fn new(ids: Vec<PCanonicalId>) -> Result<Self, CompleteTreeSetError> {
        if let Some(index) = ids
            .windows(2)
            .position(|pair| pair[0] >= pair[1])
            .map(|before| before + 1)
        {
            return Err(CompleteTreeSetError { index });
        }
        Ok(Self(ids))
    }

    /// Whether `persona` is in the set: the frozen complete-tree flag.
    #[must_use]
    pub fn contains(&self, persona: &PCanonicalId) -> bool {
        self.0.binary_search(persona).is_ok()
    }

    /// The ids, ascending.
    #[must_use]
    pub fn as_slice(&self) -> &[PCanonicalId] {
        &self.0
    }
}

impl FromIterator<PCanonicalId> for CompleteTreeSet {
    /// Sorts and deduplicates, so any order of any ids makes a set.
    fn from_iter<I: IntoIterator<Item = PCanonicalId>>(iter: I) -> Self {
        let mut ids: Vec<PCanonicalId> = iter.into_iter().collect();
        ids.sort_unstable();
        ids.dedup();
        Self(ids)
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::vec;

    use super::{CompleteTreeSet, CompleteTreeSetError, ReceiptSignPk, RECEIPT_SIGN_PK_LEN};
    use crate::PCanonicalId;

    fn persona(byte: u8) -> PCanonicalId {
        PCanonicalId::from_bytes([byte; 32])
    }

    /// The constructor holds the order the codec and `contains` rely on.
    /// Red edit: drop the check — the repeated and the reversed inputs then
    /// construct, and `contains` misses an id a binary search walks past.
    #[test]
    fn a_complete_tree_set_is_strictly_increasing() {
        let set = CompleteTreeSet::new(vec![persona(1), persona(3)]).expect("ascending");
        assert!(set.contains(&persona(3)));
        assert!(!set.contains(&persona(2)));
        assert_eq!(
            CompleteTreeSet::new(vec![persona(1), persona(1)]),
            Err(CompleteTreeSetError { index: 1 })
        );
        assert_eq!(
            CompleteTreeSet::new(vec![persona(1), persona(4), persona(2)]),
            Err(CompleteTreeSetError { index: 2 })
        );
        let empty = CompleteTreeSet::new(vec![]).expect("the empty set is a value");
        assert_eq!(empty, CompleteTreeSet::default());
        assert!(!empty.contains(&persona(0)));
        let collected: CompleteTreeSet = [persona(3), persona(1), persona(3)].into_iter().collect();
        assert_eq!(collected.as_slice(), &[persona(1), persona(3)]);
    }

    /// Two keys that differ in either half print differently, and two that
    /// share only the encoding's header do not print alike. Red edit: print
    /// the first eight bytes — every valid key then prints the same.
    #[test]
    fn debug_tells_two_keys_apart_by_either_half() {
        let header = [0x01, 0x03, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00];
        let key = |ed: u8, fn_dsa_tail: u8| {
            let mut bytes = [0u8; RECEIPT_SIGN_PK_LEN];
            bytes[..8].copy_from_slice(&header);
            bytes[8] = ed;
            bytes[RECEIPT_SIGN_PK_LEN - 1] = fn_dsa_tail;
            format!("{:?}", ReceiptSignPk::from_bytes(bytes))
        };
        assert_ne!(key(1, 0), key(2, 0), "the Ed25519 halves differ");
        assert_ne!(key(0, 1), key(0, 2), "the FN-DSA halves differ");
        assert_eq!(
            key(0xAB, 0xCD),
            "ReceiptSignPk(ab00000000000000…00000000000000cd)"
        );
    }
}
