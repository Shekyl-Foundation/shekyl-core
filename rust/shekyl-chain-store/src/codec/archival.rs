// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The archival tables' stored shapes — DRS-E1 S-ARCH
//! (`DRS_E1_SARCH.md` §3.4, §4; `SAR-Q3` RULED 2026-09-23).
//!
//! Six tables the C++ left as raw bytes gain types here (the seventh row of
//! the read set is a `properties` cell, `codec::property`); E4's writers will
//! write what these describe and may not choose a second shape for the same
//! byte. The vocabulary two crates share — [`PCanonicalId`], [`ShardId`],
//! [`SettlementEpoch`], [`BadInterval`], [`ShardSet`], [`HoldingsKind`] —
//! lives in `shekyl-types` (`SAR-Q2`); what is here is the daemon store's
//! own: the persisted **bond record** and the three close-row scalars.
//!
//! # The bond record is re-specified, not ported (`SAR-Q3`)
//!
//! `ArchivalBondValue` v7 (`src/blockchain_db/shekyl_types.h`) is a 350-line
//! hand codec with a `holdings_kind` byte and two index-parallel vectors
//! whose equal length the encoder throws on and the decoder assumes. The
//! ruling: **same semantics, not byte-compatible** — the field set and the
//! genesis-frozen caps are the C++'s; the encoding is this codec's own, and
//! nothing hashes or relays the stored record (the wire record is
//! `bond_wire.rs`'s, a different object). What the re-specification buys:
//!
//! - [`Holdings`] is one sum type. A held shard and its add-epoch are one
//!   [`HeldShard`]; the parallel-vector desync the C++ made FATAL at
//!   `db_lmdb.cpp:4943` is unrepresentable (**SI-14**).
//! - `first_paying_emission_height` is an [`Option<FirstPayingHeight>`].
//!   The C++ spelled "not yet paid" as height `0` and documented why `0`
//!   could not be a real value (`shekyl_types.h`, the field's comment).
//!   [`FirstPayingHeight`] refuses that sentinel, so a paid record at
//!   genesis cannot be stored.
//! - Every count is bounded **before** it sizes an allocation, by the cap
//!   the consensus constant names ([`MAX_HOLDINGS_SHARDS`],
//!   [`MAX_BOND_BAD_INTERVALS`], [`MAX_CLAIMED_EPOCH_ENTRIES`]) and by the
//!   bytes that remain.
//!
//! What it does not buy, deliberately: the interval log keeps
//! [`BadInterval`]'s two entry kinds in one vector (SAR-10 — the fold's
//! input, the retention crate's to re-shape), and the claimed-epoch set is
//! held as the strictly-increasing list the C++ validated, not re-derived.
//!
//! # Layout
//!
//! All integers little-endian; counts and lengths `u32`.
//!
//! ```text
//! hybrid_pubkey        u32 len ‖ bytes            len ≤ MAX_BOND_KEY_BYTES
//! bond_spend_pk        u32 len ‖ bytes            len ≤ MAX_BOND_KEY_BYTES
//! endpoint             [u8; 32]
//! join_settlement_epoch u64
//! bonded_total         u64                         atomic units
//! holdings             u8 kind
//!                      kind 0: u32 n ‖ (u64 shard ‖ u64 add_epoch) × n   n ≤ MAX_HOLDINGS_SHARDS
//!                      kind 1: nothing
//! bad_intervals        u32 n ‖ (u64 start ‖ u64 end_exclusive) × n      n ≤ MAX_BOND_BAD_INTERVALS
//! claimed_epochs       u32 n ‖ u64 × n, strictly increasing,             n ≤ MAX_CLAIMED_EPOCH_ENTRIES,
//!                      last − first ≤ MAX_CLAIM_AGE_W_EPOCHS
//! first_paying_height  u8 present ‖ (u64 height if present)
//! ```
//!
//! # The v7 cross-check (ruled on PR #840)
//!
//! A round trip of this codec against itself proves it self-consistent, not
//! that it is the same record. `docs/test_vectors/ARCHIVAL_BOND_RECORD_V7.json`
//! holds real `ArchivalBondValue` v7 blobs with the fields the **C++
//! decoder** read from them; `archival_tests.rs` builds a [`BondRecord`]
//! from each field set and asserts nothing is lost. Captured now because E4
//! deletes the only oracle.

use shekyl_store_codec::{BlobKind, Canonical, CodecError};
use shekyl_types::archival::{
    BadInterval, HoldingsDescriptor, HoldingsKind, ShardSet, ShardSetError,
    MAX_ATTESTATION_WITNESS_BYTES, MAX_BOND_BAD_INTERVALS, MAX_CLAIMED_EPOCH_ENTRIES,
    MAX_CLAIM_AGE_W_EPOCHS, MAX_HOLDINGS_SHARDS,
};
use shekyl_types::{BlockHeight, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;

use super::reader::{put_bytes, put_count, Reader};

/// Upper bound on the two key fields' byte length — the C++ codec's
/// `kMaxPubkeyLen`. A **codec** cap, not the canonical length: every record
/// is created by JoinMarket connect, whose vin serializer enforces the exact
/// hybrid-key length (`HYBRID_PUBKEY_CANONICAL_BYTES`); the store bounds
/// what an untrusted decode will allocate for.
pub const MAX_BOND_KEY_BYTES: usize = 2048;

// ---------------------------------------------------------------------------
// Holdings
// ---------------------------------------------------------------------------

/// One held shard with the settlement epoch it was acquired in — join-time
/// shards carry `E_join`; a `HoldingsUpdate` add carries its `E_add`. The
/// add-epoch powers the drop-eligibility gate (gate-4 §4.4) and per-shard
/// `E_add + 1` serve-credit counting (P2B-7 Pin 5).
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
    /// Every shard; a foundation record. Cannot `HoldingsUpdate`.
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

impl core::fmt::Display for HoldingsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

impl std::error::Error for HoldingsError {}

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
    /// has no per-shard epochs (it cannot `HoldingsUpdate`).
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

// ---------------------------------------------------------------------------
// The record
// ---------------------------------------------------------------------------

/// `archival_bond[p]` — one persona's bond record, the store's typed form of
/// `ArchivalBondValue` v7 (module docs). Every field the C++ record carried,
/// re-specified.
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
    /// write order, at most [`MAX_BOND_BAD_INTERVALS`] (genesis-frozen).
    pub bad_intervals: Vec<BadInterval>,
    /// Settlement epochs already claimed by an emission vin, strictly
    /// increasing, at most [`MAX_CLAIMED_EPOCH_ENTRIES`] and spanning at most
    /// [`MAX_CLAIM_AGE_W_EPOCHS`] (`last − first ≤ W`). The windowed
    /// `check_and_set` that maintains it is consensus and lives in
    /// `shekyl-archival-retention::claimed_epochs`; the store holds the
    /// at-rest shape.
    pub claimed_settlement_epochs: Vec<SettlementEpoch>,
    /// Height of the first emission that paid this `P`; set once, immutable.
    /// `None` until then. Height zero is not a value of this field.
    pub first_paying_emission_height: Option<FirstPayingHeight>,
}

impl BondRecord {
    const HOLDINGS_COMPACT: u8 = HoldingsKind::ShardSetCompact as u8;
    const HOLDINGS_COMPLETE: u8 = HoldingsKind::CompleteTree as u8;

    /// Whether the record is a foundation complete-tree bond.
    #[must_use]
    pub const fn is_complete_tree(&self) -> bool {
        matches!(self.holdings, Holdings::CompleteTree)
    }
}

impl Canonical for BondRecord {
    const NAME: &'static str = "bond_record";
    const FIXED_WIDTH: Option<usize> = None;

    fn encode_into(&self, out: &mut Vec<u8>) {
        put_bytes(out, &self.hybrid_pubkey);
        put_bytes(out, &self.bond_spend_pk);
        out.extend_from_slice(&self.endpoint);
        out.extend_from_slice(&self.join_settlement_epoch.to_raw().to_le_bytes());
        out.extend_from_slice(&self.bonded_total.to_raw().to_le_bytes());
        match &self.holdings {
            Holdings::CompleteTree => out.push(Self::HOLDINGS_COMPLETE),
            Holdings::ShardSet(held) => {
                out.push(Self::HOLDINGS_COMPACT);
                put_count(out, held.len());
                for h in held.iter() {
                    out.extend_from_slice(&h.shard.to_raw().to_le_bytes());
                    out.extend_from_slice(&h.add_epoch.to_raw().to_le_bytes());
                }
            }
        }
        put_count(out, self.bad_intervals.len());
        for iv in &self.bad_intervals {
            out.extend_from_slice(&iv.start_epoch.to_le_bytes());
            out.extend_from_slice(&iv.end_exclusive.to_le_bytes());
        }
        put_count(out, self.claimed_settlement_epochs.len());
        for e in &self.claimed_settlement_epochs {
            out.extend_from_slice(&e.to_raw().to_le_bytes());
        }
        match self.first_paying_emission_height {
            None => out.push(0),
            Some(h) => {
                out.push(1);
                out.extend_from_slice(&h.to_raw().to_le_bytes());
            }
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(Self::NAME, bytes);
        let hybrid_pubkey = r
            .bytes_bounded(
                MAX_BOND_KEY_BYTES,
                "hybrid_pubkey exceeds MAX_BOND_KEY_BYTES",
            )?
            .to_vec();
        let bond_spend_pk = r
            .bytes_bounded(
                MAX_BOND_KEY_BYTES,
                "bond_spend_pk exceeds MAX_BOND_KEY_BYTES",
            )?
            .to_vec();
        let endpoint = r.array::<32>("buffer ends inside the endpoint")?;
        let join_settlement_epoch = SettlementEpoch::from_raw(r.u64()?);
        let bonded_total = AtomicUnits::from_raw(r.u64()?);
        let holdings = match r.u8()? {
            Self::HOLDINGS_COMPLETE => Holdings::CompleteTree,
            Self::HOLDINGS_COMPACT => {
                let n = r.count_bounded(
                    16,
                    MAX_HOLDINGS_SHARDS,
                    "held-shard count exceeds MAX_HOLDINGS_SHARDS",
                )?;
                let mut held = Vec::with_capacity(n);
                for _ in 0..n {
                    held.push(HeldShard {
                        shard: ShardId::from_raw(r.u64()?),
                        add_epoch: SettlementEpoch::from_raw(r.u64()?),
                    });
                }
                Holdings::shard_set(held).map_err(|e| {
                    r.invalid(match e {
                        HoldingsError::CountExceeded { .. } => "unreachable: count was bounded",
                        HoldingsError::Duplicate { .. } => "a shard is held twice",
                    })
                })?
            }
            _ => return Err(r.invalid("holdings kind byte names neither shape")),
        };
        let n = r.count_bounded(
            16,
            MAX_BOND_BAD_INTERVALS,
            "bad-interval count exceeds MAX_BOND_BAD_INTERVALS",
        )?;
        let mut bad_intervals = Vec::with_capacity(n);
        for _ in 0..n {
            bad_intervals.push(BadInterval {
                start_epoch: r.u64()?,
                end_exclusive: r.u64()?,
            });
        }
        let n = r.count_bounded(
            8,
            MAX_CLAIMED_EPOCH_ENTRIES,
            "claimed-epoch count exceeds MAX_CLAIMED_EPOCH_ENTRIES",
        )?;
        let mut claimed_settlement_epochs = Vec::with_capacity(n);
        for _ in 0..n {
            let e = SettlementEpoch::from_raw(r.u64()?);
            if let Some(prev) = claimed_settlement_epochs.last() {
                if e <= *prev {
                    return Err(r.invalid("claimed epochs are not strictly increasing"));
                }
            }
            claimed_settlement_epochs.push(e);
        }
        // The at-rest span rule the C++ record enforces (`claimed_epochs_well_formed`):
        // an emission claims at most `W` epochs back, so the set spans at most `W`.
        if let (Some(first), Some(last)) = (
            claimed_settlement_epochs.first(),
            claimed_settlement_epochs.last(),
        ) {
            if last.to_raw() - first.to_raw() > MAX_CLAIM_AGE_W_EPOCHS {
                return Err(r.invalid("claimed epochs span more than the claim window W"));
            }
        }
        let first_paying_emission_height = match r.u8()? {
            0 => None,
            1 => {
                let height =
                    FirstPayingHeight::new(BlockHeight::from_raw(r.u64()?)).ok_or_else(|| {
                        r.invalid("first paying height 0 is the unset sentinel, not a payment")
                    })?;
                Some(height)
            }
            _ => return Err(r.invalid("first-paying-height presence byte is neither 0 nor 1")),
        };
        if !r.is_empty() {
            return Err(r.invalid("trailing bytes after the record"));
        }
        Ok(Self {
            hybrid_pubkey,
            bond_spend_pk,
            endpoint,
            join_settlement_epoch,
            bonded_total,
            holdings,
            bad_intervals,
            claimed_settlement_epochs,
            first_paying_emission_height,
        })
    }
}

// ---------------------------------------------------------------------------
// Close-row scalars
// ---------------------------------------------------------------------------

/// `archival_r_market[(shard, epoch)]` — the market's co-holder count for a
/// shard at an epoch's close (`ARCHIVAL_CONSENSUS_STATE.md` §3.3). A
/// **written** `RMarket(0)` is a closed epoch with no co-holders; an absent
/// row is an epoch that never closed — the read returns `Option` and does not
/// invent `0` (SAR-8).
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

impl Canonical for RMarket {
    const NAME: &'static str = "r_market";
    const FIXED_WIDTH: Option<usize> = Some(8);

    fn encode_into(&self, out: &mut Vec<u8>) {
        self.0.encode_into(out);
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        u64::decode(bytes)
            .map(Self)
            .map_err(|e| e.in_codec(Self::NAME))
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

impl Canonical for SigmaWorkMilli {
    const NAME: &'static str = "sigma_work_milli";
    const FIXED_WIDTH: Option<usize> = Some(8);

    fn encode_into(&self, out: &mut Vec<u8>) {
        self.0.encode_into(out);
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        u64::decode(bytes)
            .map(Self)
            .map_err(|e| e.in_codec(Self::NAME))
    }
}

/// `archival_attestation_witness[height]` — a block's attestation witness
/// as stored: bytes the store does not parse (`shekyl-archival-retention::
/// attestation_wire` owns the parse). A [`BlobKind`], not a codec: the
/// consumer checks well-formedness, and an empty witness is **no row**, not
/// an empty row (the writer stores nothing for an empty attestation set).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestationWitnessBytes;

impl BlobKind for AttestationWitnessBytes {
    const NAME: &'static str = "attestation_witness";

    fn well_formed(bytes: &[u8]) -> Result<(), &'static str> {
        if bytes.is_empty() {
            return Err("an empty witness is no row, never an empty row");
        }
        if bytes.len() > MAX_ATTESTATION_WITNESS_BYTES {
            return Err("attestation witness exceeds MAX_ATTESTATION_WITNESS_BYTES");
        }
        Ok(())
    }
}
