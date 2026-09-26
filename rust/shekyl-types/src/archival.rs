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
//! The persisted record these words compose into — `BondRecord` — is the
//! daemon store's own (`shekyl-chain-store::codec::archival`), as
//! `CurveTreeState` is: its amount field is `AtomicUnits`, which this crate
//! does not see (`shekyl-units` is a sibling foundation crate, not a
//! dependency), and no second store persists it. Should E6 slice 8 need the
//! record on `ChainView`, the record moves here and that edge is decided
//! then (`DRS_E1_SARCH.md` decision log, 2026-09-23).

use alloc::vec::Vec;
use core::fmt;

// ---------------------------------------------------------------------------
// Caps — consensus constants a codec must bound an untrusted decode by
// ---------------------------------------------------------------------------

/// Upper bound on the shard ids one bond's `ShardSetCompact` holdings may
/// list (gate-4 §3.4.1; the C++ codec's `kMaxHoldings`). A decode past it is
/// refused before any allocation is sized from the count.
pub const MAX_HOLDINGS_SHARDS: usize = 4096;

/// `T` — transactions per archival shard: shard `k` is the storage ids
/// `[k·T, (k+1)·T)`, `k = ⌊tx_id / T⌋` (`PDM-Q6` item 5, RULED
/// 2026-09-23; `DRS_E1_SPRUNE.md` §2). The one consensus constant of the
/// partition: no boundary table, no length rows, no byte lengths.
///
/// A storage id is not `cumulative_tx_count`. That field counts listed
/// transactions. [`storage_ids_through`] adds one coinbase per block;
/// `first_tx_id(h)` for `h ≥ 1` is that total at height `h − 1`, and
/// `first_tx_id(0)` is `0`. Every node derives the same shard set from
/// that total and `T`.
///
/// **PROVISIONAL numeric** (Round-2 gate with `n`, `D_max`, `w_launch`):
/// chosen so a typical shard at ~16.7 KB/tx lands near 3.33 MB. Sourced
/// from `config/consensus_constants.json` (`archival_shard_tx_count`, via
/// this crate's `build.rs`) like the gate's other numerics, and exposed
/// here, the shard vocabulary's home, so the store's discard (`⌊id / T⌋`)
/// and the archiver's holdings name one `T`. A second home for `T` — a
/// literal in a shipped crate, or a shard boundary derived from anything
/// but `cumulative_tx_count` and this — is the FOLLOWUPS row's falsifier.
pub const SHARD_TX_COUNT: u64 = ARCHIVAL_SHARD_TX_COUNT;

include!(concat!(
    env!("OUT_DIR"),
    "/consensus_constants_generated.rs"
));

const _: () = assert!(SHARD_TX_COUNT > 0, "a shard holds at least one transaction");

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
