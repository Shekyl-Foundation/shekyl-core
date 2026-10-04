// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The persisted bond record and the close-row scalars read beside it
//! (DRS-E1 S-ARCH `SAR-Q3`, DRS-E4 `ARW-Q8`). Shapes only: the `Canonical`
//! codec stays in `shekyl-store-codec`.

use alloc::vec::Vec;
use core::fmt;

use shekyl_units::AtomicUnits;

use crate::{BlockHeight, SettlementEpoch, ShardId};

use super::{
    BadInterval, HoldingsDescriptor, HoldingsKind, ShardSet, ShardSetError, MAX_HOLDINGS_SHARDS,
};

// ---------------------------------------------------------------------------
// The persisted bond record (DRS-E1 S-ARCH `SAR-Q3`; moved here by DRS-E4
// `ARW-Q8`) — shapes only. The `Canonical` codec is `shekyl-store-codec`'s.
// ---------------------------------------------------------------------------

/// Upper bound on the bond record's two key fields' byte length — the C++
/// codec's `kMaxPubkeyLen`. A **codec** cap, not the canonical length: every
/// record is created by JoinMarket connect, whose vin serializer enforces the
/// exact hybrid-key length; a store bounds what an untrusted decode will
/// allocate for.
pub const MAX_BOND_KEY_BYTES: usize = 2048;

/// One held shard with the settlement epoch it was acquired in. Since the
/// immutable-bond ruling (2026-09-20, `PRINCIPAL_STAKE_LIFECYCLE.md` §5.3)
/// a shard joins a bond at `JoinMarket` or never, so every shard's
/// `add_epoch` equals its bond's join epoch; the field, its v6 column and
/// the `held_at_height` bound that reads it are the add-epoch substrate
/// enumerated at §5.3.2 row 7. *(As written: "a `HoldingsUpdate` add carries
/// its `E_add`; the add-epoch powers the drop-eligibility gate (gate-4 §4.4)".
/// That kind is REJECTED and the gate has no subject.)* Per-shard
/// `E_add + 1` serve-credit counting (P2B-7 Pin 5) still reads it.
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

    /// The add-epoch of `shard`, if held. `None` for a complete tree, which
    /// has no per-shard epochs. For a compact record this is the bond's
    /// join epoch (immutable-bond ruling, 2026-09-20).
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
