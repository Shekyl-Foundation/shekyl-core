// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The archival bond's **shared vocabulary** — the words the daemon store
//! persists and the retention crate folds over (DRS-E1 S-ARCH,
//! `DRS_E1_SARCH.md` §3.4, `SAR-Q2` RULED 2026-09-23).
//!
//! These three shapes were minted in `shekyl-archival-retention`
//! (`bond_wire.rs`, `consensus_state.rs`, `bond_connect.rs`) when that crate
//! was the only Rust reader of a bond. The daemon store now holds the
//! record they describe and cannot take the retention crate's graph
//! (`shekyl-fcmp`, `shekyl-crypto-pq`, …), so they move down here under the
//! crate's placement rule (*What lives here when two stores need it*, crate
//! docs): **the type both crates need lives in `shekyl-types`; the
//! computation lives in the owning crate.** Every fold — `good_through`,
//! `holds_shard_at`, the release cooldown, the shard-set diffs — stays in
//! `shekyl-archival-retention`, which re-exports these at their old paths so
//! its callers do not move. `SAR-Q2` is the fourth instance of the argument
//! ([`KeyImage`](crate::KeyImage), [`CurveTreeRoot`](crate::CurveTreeRoot),
//! [`TreePosition`](crate::TreePosition) / [`TreeLeaf`](crate::TreeLeaf)
//! before it).
//!
//! The persona, shard and epoch words were already here:
//! [`PCanonicalId`](crate::PCanonicalId), [`ShardId`](crate::ShardId),
//! [`SettlementEpoch`](crate::SettlementEpoch). Minting a `PersonaId` twin
//! for the store would have been the CTS-3 error this module exists to
//! avoid.
//!
//! # Shapes and the caps that bound them
//!
//! - [`ShardSet`] — a bounded, duplicate-free, **order-preserving** list of
//!   held shard ids; [`MAX_HOLDINGS_SHARDS`] is its cap. The elements stay
//!   `u64`: every wire struct, FFI marshal and fold in the archival stack
//!   spells a shard id that way at its edge and converts to
//!   [`ShardId`](crate::ShardId) where it reasons; re-typing the element is
//!   that stack's own change, not the move's.
//! - [`HoldingsKind`] / [`HoldingsDescriptor`] — which of the two holdings
//!   shapes a bond declares (gate-4 §3.4.1).
//! - [`BadInterval`] — one entry of a bond's standing log, carrying the
//!   `u64::MAX` open end and the zero-length clean-close marker exactly as
//!   the wire and the fold do (module docs on the type). Its cap is
//!   [`MAX_BOND_BAD_INTERVALS`], **genesis-frozen**.
//! - [`MAX_CLAIMED_EPOCH_ENTRIES`] — the at-rest cap on a bond's
//!   claimed-epoch set, the `W + 6` pin from `REWARD_EMISSION_LEG.md` §6.3.
//!   The retention crate derives the same number from the consensus
//!   constants file and const-asserts equality with this pin, so the
//!   derivation and the frozen value cannot drift apart silently.
//! - [`MAX_ATTESTATION_WITNESS_BYTES`] — the exact maximum of a canonical
//!   attestation witness. The retention crate derives the same product from
//!   the witness layout and const-asserts equality; the wire twin
//!   `PQC_HYBRID_SINGLE_SIG_LEN` const-asserts the signature factor.
//!
//! The persisted record these words compose into — [`BondRecord`], with
//! [`Holdings`], [`HeldShard`], [`FirstPayingHeight`] and the two close-row
//! scalars [`RMarket`] and [`SigmaWorkMilli`] — **lives here since
//! 2026-09-29** (DRS-E4 `ARW-Q8`). It was the daemon store's own
//! (`shekyl-chain-store::codec::archival`) while the store was its only
//! reader, because its amount field is `AtomicUnits` and this crate did not
//! take `shekyl-units`; E6 slice 8 reads the record through `ChainView`,
//! which is the second reader `SAR-Q2`'s reopening clause named, so the edge
//! is taken (`shekyl-units` is `no_std` + `alloc` as this crate is) and the
//! record moves. Its `Canonical` codec is `shekyl-store-codec`'s, where the
//! orphan rule puts an impl of a store trait for a vocabulary type; the
//! daemon store re-exports the types so its paths did not move.

use alloc::vec::Vec;
use core::fmt;

use shekyl_units::AtomicUnits;

use crate::{BlockHeight, PCanonicalId, SettlementEpoch, ShardId};

// ---------------------------------------------------------------------------
// Caps — consensus constants a codec must bound an untrusted decode by
// ---------------------------------------------------------------------------

/// Upper bound on the shard ids one bond's `ShardSetCompact` holdings may
/// list (gate-4 §3.4.1; the C++ codec's `kMaxHoldings`). A decode past it is
/// refused before any allocation is sized from the count.
pub const MAX_HOLDINGS_SHARDS: usize = ARCHIVAL_MAX_HOLDINGS_SHARDS;

scalar_u64! {
    /// An **archival length**: the bytes of archival good a transaction carries —
    /// its prunable region plus its `pqc_auths` segment, exactly the bytes a body
    /// store holds and discards — or the sum of those over a run of transactions
    /// (`SHT-Q2`, RULED 2026-09-29). Stored as a skeleton row, never
    /// declared or signed. A coinbase's is zero.
    ///
    /// **The txid binding is pending.** A full body's length is fixed by its
    /// bytes, which the txid already binds through the prunable hash; a
    /// pruned form carries that hash but not the bytes, so its length is
    /// bound by nothing until the txid gains the length term the ruling
    /// names. That term is held on the ruling for how a pruned form supplies
    /// the length (`ARCHIVAL_SHARD_T_DERIVATION.md` §8.6, the FOLLOWUPS
    /// "Build SHT-Q2" row).
    ///
    /// A distinct type because the partition it drives used to be a
    /// transaction count, and a `u64` would let a count, a storage id and a
    /// length stand in for one another without a word of complaint.
    ArchivalLength
}

impl ArchivalLength {
    /// `self + other`, or `None` on overflow — the fold's only arithmetic.
    #[must_use]
    pub const fn checked_add(self, other: Self) -> Option<Self> {
        match self.0.checked_add(other.0) {
            Some(sum) => Some(Self(sum)),
            None => None,
        }
    }
}

/// `W`: the archival length of a shard (`SHT-Q2`, RULED 2026-09-29;
/// `ARCHIVAL_SHARD_T_DERIVATION.md` §8.6, §9). Shard `k` holds the
/// transactions whose cumulative archival length **before** them lies in
/// `[k·W, (k+1)·W)` — [`shard_of`]. Global multiples: no boundary table,
/// and membership depends on nothing but the cumulative length, which every
/// node derives from the rows it keeps.
///
/// **PROVISIONAL numeric**, `3,000,000` bytes: the §9 selection rule's
/// output (the smallest `W` whose overshoot — one transaction's largest
/// archival length over `W` — is at most 5 %), re-pinned before genesis by
/// the overshoot tolerance and the multi-size W₂ and `U1b` measurements.
/// Sourced from `config/consensus_constants.json`
/// (`archival_shard_length_bytes`, via this crate's `build.rs`); this is its
/// one home. The static relation "one transaction's largest archival length
/// is below `W`", which is what keeps every shard non-empty, is
/// const-asserted in `shekyl-chain-rules` (`rules/tx.rs`, beside CEN-H3's
/// `max_tx_weight`), where both constants are visible.
pub const SHARD_LENGTH: ArchivalLength = ArchivalLength::from_raw(ARCHIVAL_SHARD_LENGTH_BYTES);

/// The shard a transaction belongs to, from the cumulative archival length
/// of every transaction before it: `⌊cum_before / W⌋`. The partition's one
/// boundary function; nothing else places a boundary.
#[must_use]
pub const fn shard_of(cum_before: ArchivalLength) -> crate::ShardId {
    crate::ShardId::from_raw(cum_before.to_raw() / SHARD_LENGTH.to_raw())
}

/// Where shard `k` starts: the cumulative archival length `k·W`, or `None`
/// when it overflows. A transaction is in shard `k` or later iff its
/// cumulative-before is at least this.
#[must_use]
pub const fn shard_start(k: crate::ShardId) -> Option<ArchivalLength> {
    match k.to_raw().checked_mul(SHARD_LENGTH.to_raw()) {
        Some(start) => Some(ArchivalLength::from_raw(start)),
        None => None,
    }
}

/// Where the shard holding offset `at` starts: `⌊at / W⌋·W`, which is
/// `shard_start(shard_of(at))` without the overflow — it is at most `at`.
/// The opening a fold that has reached `at` has certainly crossed.
#[must_use]
pub const fn shard_floor(at: ArchivalLength) -> ArchivalLength {
    ArchivalLength::from_raw(at.to_raw() - at.to_raw() % SHARD_LENGTH.to_raw())
}

include!(concat!(
    env!("OUT_DIR"),
    "/consensus_constants_generated.rs"
));

const _: () = assert!(
    SHARD_LENGTH.to_raw() > 0,
    "a shard has a positive archival length"
);

// The cap bounds a `Vec` length, so `build.rs` emits it as `usize` rather than
// `u64` like its neighbour: there is no cast to lint, and a value exceeding
// `usize` on a 32-bit target fails to compile at the generated literal instead
// of wrapping into a SMALLER bound — which would make a wire decoder refuse
// holdings the store accepts.
const _: () = assert!(
    MAX_HOLDINGS_SHARDS > 0,
    "a compact holdings set holds at least one shard"
);

/// Storage ids issued through `height` inclusive.
///
/// `listed` is `cumulative_tx_count` at that height: non-coinbase
/// transactions only. Each block records one miner transaction before its
/// listed transactions (CEN-F), so the ids through `height` are `listed`
/// plus the `height + 1` blocks in `0..=height`. `None` when the sum
/// overflows. `first_tx_id(h)` for `h ≥ 1` is this function at `h − 1`.
#[must_use]
pub const fn storage_ids_through(listed: u64, height: u64) -> Option<u64> {
    let Some(blocks) = height.checked_add(1) else {
        return None;
    };
    listed.checked_add(blocks)
}

/// Upper bound on a bond record's standing-log entries. **Genesis-frozen
/// consensus constant, not a codec tunable:** Release verify rejects a
/// record at this cap (`IntervalLogFull`, the connect's clean interval-close
/// could not append), so transaction validity depends on the value. The C++
/// twin `ArchivalBondValue::kMaxBadIntervals` (`shekyl_types.h`) is pinned
/// against it by `static_assert`; a change is a hard fork and moves both.
pub const MAX_BOND_BAD_INTERVALS: usize = 256;

/// Upper bound on a bond record's at-rest claimed-epoch set: the claim
/// window `W = 26` plus 6 epochs of reorg slack (`REWARD_EMISSION_LEG.md`
/// §6.3 pins 32). Unreachable through the windowed `check_and_set` (a pruned
/// set holds at most `W` entries); it bounds what an untrusted decode
/// accepts. `shekyl-archival-retention::claimed_epochs` derives
/// `MAX_CLAIM_AGE_W + 6` from the consensus constants file and
/// const-asserts it equals this pin.
pub const MAX_CLAIMED_EPOCH_ENTRIES: usize = 32;

/// The claim window `W` in settlement epochs (`config/consensus_constants.json`
/// `max_claim_age_w`, 26): an emission may claim an epoch at most `W` epochs
/// behind the current settled one, so a bond record's at-rest claimed set
/// spans at most `W` — `last − first ≤ W` — and the C++ record refuses a
/// wider one at encode and decode. The store's decode holds the same bound.
/// `shekyl-archival-retention` derives `MAX_CLAIM_AGE_W` from the constants
/// file and const-asserts it equals this pin; [`MAX_CLAIMED_EPOCH_ENTRIES`]
/// is `W + 6`.
pub const MAX_CLAIM_AGE_W_EPOCHS: u64 = 26;

/// Records in one block's attestation witness. Genesis-frozen.
/// `shekyl-archival-retention::MAX_ATTESTATION_RECORDS` const-asserts equality.
pub const MAX_ATTESTATION_RECORDS: usize = 256;

/// `count` prefix of a canonical attestation witness, in bytes.
pub const ATTESTATION_WITNESS_COUNT_LEN: usize = 8;

/// Nonce on one witness entry.
pub const ATTESTATION_WITNESS_NONCE_LEN: usize = 32;

/// Anchor height on one witness entry.
pub const ATTESTATION_WITNESS_ANCHOR_LEN: usize = 8;

/// One hybrid signature on a witness entry. Twin of
/// `HybridSignature::CANONICAL_LEN` and `PQC_HYBRID_SINGLE_SIG_LEN`; both
/// const-assert equality, so this factor cannot drift from the signature.
pub const ATTESTATION_WITNESS_SIGNATURE_LEN: usize = 3385;

/// Exact maximum of a canonical attestation witness:
/// count prefix, then [`MAX_ATTESTATION_RECORDS`] entries of
/// nonce ‖ anchor height ‖ signature.
///
/// The retention crate derives the same product from
/// `HybridSignature::CANONICAL_LEN` and const-asserts equality. The daemon
/// store refuses a longer blob before it copies one. A hand-picked slack
/// figure above the product would be free padding on every block.
pub const MAX_ATTESTATION_WITNESS_BYTES: usize = ATTESTATION_WITNESS_COUNT_LEN
    + MAX_ATTESTATION_RECORDS
        * (ATTESTATION_WITNESS_NONCE_LEN
            + ATTESTATION_WITNESS_ANCHOR_LEN
            + ATTESTATION_WITNESS_SIGNATURE_LEN);

// ---------------------------------------------------------------------------
// ShardSet
// ---------------------------------------------------------------------------

/// A bounded, duplicate-free list of held shard ids — the validated form of
/// a `ShardSetCompact` holdings' shard list (gate-4 §3.4.1).
///
/// Parse-don't-validate: the two structural invariants that were previously
/// carried by convention — each verify re-guarding, and `bond_floor`
/// signalling an invalid set with an in-band `0` (the same value the
/// legitimate empty exit shape returns) — are enforced once, at construction,
/// so an invalid set is unrepresentable past any decoder:
///
/// - **bounded**: `len <= MAX_HOLDINGS_SHARDS` (the codec cap);
/// - **duplicate-free**: a shard id appears at most once ("a set on the
///   wire" — previously rejected only inside per-kind diffs and silently
///   tolerated by `JoinMarket`, which let `[7, 7]` bond `2·FLOOR` for one
///   shard).
///
/// **Insertion order is preserved** (ratified 2026-07-15): the §3.4.1
/// encoding writes the ids in slice order, so a valid `ShardSet` encodes
/// byte-identically to the pre-newtype `Vec` — this change tightens
/// *validity* (dupe-carrying byte strings now reject at decode) without
/// re-encoding any accepted tx. So `[7, 42]` and `[42, 7]` remain distinct
/// valid encodings of the same set; benign, since holdings feed the
/// signature preimage (only the signer produces either, and only one
/// connects).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ShardSet(Vec<u64>);

/// Why a list of shard ids is not a [`ShardSet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardSetError {
    /// `len > MAX_HOLDINGS_SHARDS`.
    CountExceeded {
        /// The length that was offered.
        got: usize,
    },
    /// A shard id appears more than once.
    Duplicate {
        /// The repeated id.
        shard_id: u64,
    },
}

impl fmt::Display for ShardSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CountExceeded { got } => {
                write!(
                    f,
                    "shard count {got} exceeds the bound ({MAX_HOLDINGS_SHARDS})"
                )
            }
            Self::Duplicate { shard_id } => {
                write!(f, "shard id {shard_id} appears more than once")
            }
        }
    }
}

impl core::error::Error for ShardSetError {}

impl ShardSet {
    /// The one fallible constructor — every decoder / FFI marshal / builder
    /// routes through it. Enforces the bound and duplicate-freeness;
    /// preserves insertion order.
    ///
    /// # Errors
    ///
    /// [`ShardSetError::CountExceeded`] past [`MAX_HOLDINGS_SHARDS`];
    /// [`ShardSetError::Duplicate`] naming the first repeated id.
    pub fn new(ids: Vec<u64>) -> Result<Self, ShardSetError> {
        if ids.len() > MAX_HOLDINGS_SHARDS {
            return Err(ShardSetError::CountExceeded { got: ids.len() });
        }
        // Duplicate check on a sorted scratch copy — do NOT perturb the
        // caller's insertion order (that is the wire form). Bounded above,
        // so the sort is at most MAX_HOLDINGS_SHARDS elements.
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        if let Some(pair) = sorted.windows(2).find(|w| w[0] == w[1]) {
            return Err(ShardSetError::Duplicate { shard_id: pair[0] });
        }
        Ok(Self(ids))
    }

    /// The empty set (`CompleteTree` carries none; the `Release` exit shape).
    /// The empty set is trivially bounded and duplicate-free.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Borrow the ids as a slice (also available through `Deref`).
    #[must_use]
    pub fn as_slice(&self) -> &[u64] {
        &self.0
    }

    /// Consume into the raw id vec — the `shekyl-wire` handoff (an
    /// independent oracle that owns its own bound/dupe checks).
    #[must_use]
    pub fn into_vec(self) -> Vec<u64> {
        self.0
    }
}

impl core::ops::Deref for ShardSet {
    type Target = [u64];
    fn deref(&self) -> &[u64] {
        &self.0
    }
}

impl TryFrom<Vec<u64>> for ShardSet {
    type Error = ShardSetError;
    fn try_from(ids: Vec<u64>) -> Result<Self, ShardSetError> {
        Self::new(ids)
    }
}

// Order-sensitive comparison against raw id lists — matches the wire form,
// for call sites and tests that assert a set equals expected ids.
impl PartialEq<[u64]> for ShardSet {
    fn eq(&self, other: &[u64]) -> bool {
        self.0 == other
    }
}

impl<const N: usize> PartialEq<[u64; N]> for ShardSet {
    fn eq(&self, other: &[u64; N]) -> bool {
        self.0.as_slice() == other.as_slice()
    }
}

impl PartialEq<Vec<u64>> for ShardSet {
    fn eq(&self, other: &Vec<u64>) -> bool {
        &self.0 == other
    }
}

// ---------------------------------------------------------------------------
// Holdings
// ---------------------------------------------------------------------------

/// Which holdings shape a bond declares (gate-4 §3.4.1). The discriminant
/// values are the wire's and the C++ record's (`kHoldingsShardSetCompact`,
/// `kHoldingsCompleteTree`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HoldingsKind {
    /// An explicit, bounded shard list.
    ShardSetCompact = 0,
    /// Every shard — a foundation record; carries no list.
    CompleteTree = 1,
}

/// A byte that names neither holdings kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HoldingsKindError(pub u8);

impl fmt::Display for HoldingsKindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid holdings kind {}", self.0)
    }
}

impl core::error::Error for HoldingsKindError {}

impl HoldingsKind {
    /// Decode the kind byte.
    ///
    /// # Errors
    ///
    /// [`HoldingsKindError`] carrying the byte for anything but `0` or `1`.
    pub const fn from_u8(v: u8) -> Result<Self, HoldingsKindError> {
        match v {
            0 => Ok(Self::ShardSetCompact),
            1 => Ok(Self::CompleteTree),
            other => Err(HoldingsKindError(other)),
        }
    }

    /// The kind byte.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

/// A bond's declared holdings: the kind and, for `ShardSetCompact`, the
/// validated shard list (empty for `CompleteTree` — the wire forbids a list
/// there, and the retention crate's decoder enforces it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HoldingsDescriptor {
    /// Which shape.
    pub kind: HoldingsKind,
    /// The held shards; empty for a complete tree.
    pub shard_ids: ShardSet,
}

// ---------------------------------------------------------------------------
// BadInterval
// ---------------------------------------------------------------------------

/// One entry of a bond's standing log: a half-open settlement-epoch range
/// `[start_epoch, end_exclusive)`.
///
/// Carries **two entry kinds** — do not assume every entry is a slash. A
/// bad-standing interval has `start < end` (a slash opens it with
/// `end_exclusive = u64::MAX`; `Reinstate` closes it in place), while the
/// `Release` **clean interval-close** is **zero-length** (`start == end`) — a
/// pure exit marker recording the release settlement epoch. Its empty range
/// excludes no epoch from `good_through` by construction, and every
/// codec/marshal path deliberately carries `start == end`; never add a
/// "valid interval is non-empty" assertion on this type. (The C++ header
/// and the retention crate each carried this warning; it is stated once
/// here now. `DRS_E1_SARCH.md` SAR-10 records the typed-entry form as a
/// forward-action for the fold's owner, not this move's.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadInterval {
    /// First epoch of the range.
    pub start_epoch: u64,
    /// One past the last epoch; `u64::MAX` for open-ended bad standing.
    pub end_exclusive: u64,
}

impl BadInterval {
    /// The open end the wire spells as `u64::MAX`.
    pub const OPEN_END: u64 = u64::MAX;

    /// Whether this is the zero-length clean-close marker.
    #[must_use]
    pub const fn is_clean_close(&self) -> bool {
        self.start_epoch == self.end_exclusive
    }

    /// Whether the bad standing is still open.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.end_exclusive == Self::OPEN_END
    }
}

/// Blocks per settlement epoch — the one number the epoch geometry is a
/// function of (`floor(height / SEB)` and its inverses).
///
/// Three readers, one word (moved here at DRS-E4 `ARW-15`; the fifth
/// instance of the module's placement argument): the daemon store **pins**
/// it in its header at create and refuses a session under another value
/// (S-CHAIN-W SCW-2); the rule set **carries** it — the genesis constant on
/// every issued set, the regtest lever's value on a Fakechain set — so the
/// validator derives epochs, closes and slash deadlines from the rules in
/// force and never from a process's environment (rule 71: nettype selects
/// data, never control flow); and `shekyl-archival-retention` **computes**
/// with it (`SettlementSchedule`, the one home of the geometry). The store
/// compares its pin to the in-force set's at every connect, which is what
/// makes the two readers one schedule and not two.
///
/// `0` is not a schedule: the C++ used it as "unpinned", and a file the
/// store writes is never unpinned, so the type cannot spell it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SettlementEpochBlocks(core::num::NonZeroU64);

impl SettlementEpochBlocks {
    /// `blocks` per epoch; `None` for zero, which names no schedule.
    #[must_use]
    pub const fn new(blocks: u64) -> Option<Self> {
        match core::num::NonZeroU64::new(blocks) {
            Some(n) => Some(Self(n)),
            None => None,
        }
    }

    /// The schedule, in blocks.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl core::fmt::Display for SettlementEpochBlocks {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} blocks/epoch", self.0)
    }
}

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
    /// write order, at most [`MAX_BOND_BAD_INTERVALS`] (genesis-frozen).
    pub bad_intervals: Vec<BadInterval>,
    /// Settlement epochs already claimed by an emission vin, strictly
    /// increasing, at most [`MAX_CLAIMED_EPOCH_ENTRIES`] and spanning at most
    /// [`MAX_CLAIM_AGE_W_EPOCHS`] (`last − first ≤ W`). The windowed
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

// ---------------------------------------------------------------------------
// The serve-credit reads' answers (DRS-E1 S-ARCH A3–A5; on `ChainView`
// since DRS-E4 commit 2, which is why they are here and not in the store)
// ---------------------------------------------------------------------------

/// How many pass bits a `(persona, shard, epoch)` recorded — `PC-D5`'s
/// enumeration over the pair-epoch prefix. `u32` in the C++ (`PC-D5`'s
/// bound); the newtype keeps it from being added to an epoch. Admission
/// collapsed it to `> 0` while the beacon issued one challenge (CEN-J3's
/// dedup); the settlement writer and the assignment cutover's count bound
/// consume the number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PassCount(u32);

impl PassCount {
    /// No pass bits.
    pub const ZERO: Self = Self(0);

    /// A count the reader tallied.
    #[must_use]
    pub const fn from_raw(n: u32) -> Self {
        Self(n)
    }

    /// The count.
    #[must_use]
    pub const fn to_raw(self) -> u32 {
        self.0
    }

    /// Whether any pass was recorded — the admission arm's question.
    #[must_use]
    pub const fn any(self) -> bool {
        self.0 > 0
    }
}

/// A served shard and the latest settlement epoch it earned a pass bit in
/// — one row of the served-shards read (S-ARCH A4), the release cooldown's
/// anchor (CEN-J16) and the drop arm's grace-tail operand (CEN-J17).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServedShard {
    /// Which shard.
    pub shard: ShardId,
    /// The latest epoch with a pass bit for it.
    pub last_served: SettlementEpoch,
}

// ---------------------------------------------------------------------------
// The slash log — consensus history, not a journal (DRS-E4 `ARW-Q2`)
// ---------------------------------------------------------------------------

/// What one slash took from a record's holdings — the pre-image the
/// as-of-height fold needs and nothing the undo log already holds.
///
/// `holds_shard_at(h)` asks *did `P` hold `s` at `h`*; for a shard the
/// record does not hold at tip, the answer is *yes* iff a logged slash
/// strictly above `h` removed it — either this exact shard was erased from
/// a compact set that had held it since `add_epoch`, or the record was a
/// complete tree that a slash demoted to empty (`db_lmdb.cpp`,
/// `archival_slash_removed_holding_after`). The two arms are the two
/// variants; the C++'s `holdings_pre_kind` byte plus a zero-when-unused
/// `slashed_shard_add_epoch` become one sum, so an add-epoch on a
/// complete-tree demotion cannot be spelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlashedHolding {
    /// A compact set held the challenged shard since `add_epoch`; the slash
    /// erased that one shard.
    Shard {
        /// The settlement epoch the erased shard had been acquired in.
        add_epoch: SettlementEpoch,
    },
    /// A complete-tree record; the slash demoted it to an empty compact set.
    CompleteTree,
}

/// `archival_slash_log[(height, seq)]` — one slash the scheduler applied,
/// as history.
///
/// This is the **one archival journal that is a fact**: the record after a
/// slash says what is held now, not when a shard left, and the as-of-height
/// question reaches back past the reorg window the undo log covers
/// (`DRS_E4_ARCHIVAL_WRITER.md` §3.3). What is here is exactly what that
/// read consumes — who, which shard, which epoch's failure, and what the
/// slash took. The C++ row also carried the slashed amount and an
/// epoch-marker row kind; neither has a reader once pop is the undo log's
/// (the amount's pre-image is the record's; the marker's job is the
/// `archival_last_slash_epoch` cell's own pre-image), so neither is here.
/// The amount reopens with a named reader (rule 21).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlashLogEntry {
    /// The slashed persona.
    pub persona: PCanonicalId,
    /// The shard whose challenge failed.
    pub shard: ShardId,
    /// The settlement epoch whose failure this slash settles.
    pub epoch: SettlementEpoch,
    /// What the slash took from the record's holdings.
    pub holding: SlashedHolding,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn shard_set_enforces_bound_and_uniqueness_and_keeps_order() {
        assert_eq!(ShardSet::new(vec![42, 7]).unwrap(), [42u64, 7]);
        assert_eq!(
            ShardSet::new(vec![7, 7]),
            Err(ShardSetError::Duplicate { shard_id: 7 })
        );
        let too_many: Vec<u64> = (0..=MAX_HOLDINGS_SHARDS as u64).collect();
        assert_eq!(
            ShardSet::new(too_many),
            Err(ShardSetError::CountExceeded {
                got: MAX_HOLDINGS_SHARDS + 1
            })
        );
        assert!(ShardSet::empty().is_empty());
    }

    /// `SHT-Q2`'s boundary function: a transaction whose cumulative-before is
    /// exactly `k·W` opens shard `k`; one byte less is still shard `k − 1`.
    #[test]
    fn a_transaction_starting_exactly_at_k_w_opens_shard_k() {
        let w = SHARD_LENGTH.to_raw();
        assert_eq!(shard_of(ArchivalLength::ZERO), crate::ShardId::ZERO);
        for k in [1u64, 2, 7, 1_000] {
            let start = shard_start(crate::ShardId::from_raw(k)).expect("fits");
            assert_eq!(start.to_raw(), k * w);
            assert_eq!(shard_of(start).to_raw(), k, "k·W opens shard {k}");
            assert_eq!(
                shard_of(ArchivalLength::from_raw(start.to_raw() - 1)).to_raw(),
                k - 1,
                "one byte before k·W is still shard {}",
                k - 1
            );
        }
        assert_eq!(
            shard_start(crate::ShardId::from_raw(u64::MAX)),
            None,
            "k·W overflows"
        );
        for at in [0, 1, w - 1, w, w + 1, 7 * w - 1, 7 * w, u64::MAX] {
            let at = ArchivalLength::from_raw(at);
            let floor = shard_floor(at);
            assert!(floor <= at, "the floor never passes its offset");
            assert_eq!(shard_of(floor), shard_of(at), "one shard");
            assert_eq!(Some(floor), shard_start(shard_of(at)), "k·W");
        }
        assert_eq!(
            ArchivalLength::from_raw(u64::MAX).checked_add(ArchivalLength::from_raw(1)),
            None
        );
    }

    #[test]
    fn storage_ids_count_one_coinbase_per_block() {
        // Height 0, no listed transactions: the genesis coinbase is id 0,
        // and one id has been issued.
        assert_eq!(storage_ids_through(0, 0), Some(1));
        // The prune fixture: through height 199, one listed spend and 200
        // coinbases — 201 ids issued, so the first id at height 200 is 201.
        assert_eq!(storage_ids_through(1, 199), Some(201));
        assert_eq!(storage_ids_through(u64::MAX, 0), None);
    }

    #[test]
    fn holdings_kind_round_trips_its_byte_and_refuses_others() {
        assert_eq!(HoldingsKind::from_u8(0), Ok(HoldingsKind::ShardSetCompact));
        assert_eq!(HoldingsKind::from_u8(1), Ok(HoldingsKind::CompleteTree));
        assert_eq!(HoldingsKind::from_u8(2), Err(HoldingsKindError(2)));
        assert_eq!(HoldingsKind::CompleteTree.to_u8(), 1);
    }

    #[test]
    fn a_zero_length_interval_is_the_clean_close_marker_not_a_defect() {
        let close = BadInterval {
            start_epoch: 9,
            end_exclusive: 9,
        };
        assert!(close.is_clean_close());
        assert!(!close.is_open());
        let open = BadInterval {
            start_epoch: 3,
            end_exclusive: BadInterval::OPEN_END,
        };
        assert!(open.is_open());
        assert!(!open.is_clean_close());
    }
}
