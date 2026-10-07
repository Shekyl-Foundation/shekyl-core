// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The narrow, read-only view a rule reads the recorded chain through.
//!
//! [`ChainView`] is the whole of what a rule may know about the chain beyond
//! the candidate in its hand. The store implements it over its
//! `WriteBatch<'_, 'id>` (S-CHAIN-W); the test harness implements it over a
//! `BTreeMap`. A rule is generic over it and is therefore testable with no
//! database (`CONSENSUS_C2_R8_STORE_PLACEMENT.md` §9.1). Methods grow with
//! the increment that consumes them, each justified by a named census row
//! (round-1 ruling Q3): narrowness is what keeps rules mockable and the mock
//! smaller than the store.
//!
//! # Three answers, three positions
//!
//! Every method returns `Result<_, Self::Fault>`. The `Err` is the view's
//! **substrate** failing — a redb read error in the store's projection,
//! [`Infallible`](core::convert::Infallible) in the mock — and is not a
//! verdict: `validate` hands it back *outside* its `Result<ChainValid,
//! InvalidBlock>`, and the caller halts. Inside a rule, `?` therefore
//! propagates a fault and only a fault; a refusal is written out at the site
//! that judged, naming its row. The fault type is opaque here by genericity
//! — no bound, so nothing in this crate can inspect, match, or convert it —
//! which is the conversion ban (G2) held by the type system and not by the
//! gate alone.
//!
//! # Absence is a case, not a `None`
//!
//! By-height reads return [`AtHeight`], not `Option`. Heights at or below the
//! tip are dense — the store's invariant — so the only absence a view can
//! report is *above the tip*, and a rule that reads the parent, the preceding
//! timestamps, or the membership anchor must say, at that arm, what it does
//! about it. `AtHeight` has nothing to fall through: an absent block is a
//! refusal the rule writes, never a pass it arrives at by `?` or
//! `unwrap_or_default`.

use shekyl_difficulty::CumulativeDifficulty;
use shekyl_fcmp::tree::layer_count_for_leaves;
use shekyl_types::archival::{
    BondRecord, PassCount, RMarket, ServedShard, SigmaWorkMilli, SlashLogEntry,
};
use shekyl_types::{
    ArchivalLength, BlockCount, BlockHash, BlockHeight, BlockWeight, CurveTreeRoot,
    GlobalOutputIndex, KeyImage, LongTermWeight, PCanonicalId, SettlementEpoch, ShardId, TxHash,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::BlockHeader;

use crate::tree_growth::TreeFrontier;

/// The two weights the store records for one block (`block_info.weight`,
/// `block_info.long_term_weight`) — what CEN-G6's two rolling medians are
/// over. A projection of the row, not the row: the window read that
/// returns these decodes each `block_info` once and hands back only the
/// columns the medians consume, which is why it is a read of its own
/// rather than a loop over [`ChainView::block_at`] (E6 slice 7 Q2, ruled
/// (b) on the Pi 4 floor — 36.6 ms against 598 ms for the 100 000-row
/// window).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordedWeights {
    /// The block's wire weight (`Transaction::weight` summed, CEN-F14's
    /// operand) — CEN-G6b's short-term median is over these.
    pub weight: BlockWeight,
    /// The block's long-term weight, the clamp of `weight` to
    /// `[LTEM/1.7, LTEM·1.7]` at its own connect (CEN-G6b) — CEN-G6's
    /// long-term median is over these.
    pub long_term_weight: LongTermWeight,
}

/// A by-height lookup against the recorded chain.
///
/// Matched exhaustively. Deliberately **not** convertible to `Option`, and
/// without `map` / `unwrap_or_*` / `?` — the shapes by which an absence
/// becomes a silent pass in a diff that reads entirely reasonably:
///
/// ```compile_fail
/// # use shekyl_chain_rules::AtHeight;
/// let at: AtHeight<u8> = AtHeight::Recorded(1);
/// let _: Option<u8> = at.into(); // no such conversion
/// ```
///
/// ```compile_fail
/// # use shekyl_chain_rules::AtHeight;
/// fn read(at: AtHeight<u8>) -> Option<u8> { Some(at?) } // nothing for `?` to take
/// ```
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtHeight<T> {
    /// The chain recorded `T` at that height.
    Recorded(T),
    /// No block has been recorded at that height: it is above the tip.
    /// Heights at or below the tip are dense (the store's invariant, not a
    /// view fact), so this is the only absence a view can report.
    AboveTip,
}

/// The last recorded block: its height and identity.
///
/// `ChainView::tip()` returns `Option<Tip>` — `None` is the empty chain, and
/// the candidate is genesis. **`Option`, not a bespoke absence enum** (slice
/// 1, Q1, ruled 2026-09-16): a custom absence type earns its keep when its
/// absence case carries semantics the caller must act on — `AtHeight::
/// AboveTip` does (walk back; the state is not there) — and an empty chain
/// is one behaviour with no valid-looking alternative, so `None` cannot be
/// read as data. What `Option` does rule out is the C++ shape:
/// `top_block_hash` hands back **two** sentinels on an empty chain,
/// `null_hash` and `*block_height = UINT64_MAX`, neither distinguishable
/// from a recorded value (`db_lmdb.cpp:3185–3191`). The store's own read
/// (`RecordedTip { tip: Tip, connect }`, S-CHAIN-R) composes this struct.
///
/// Fields justified per ruling Q3: `hash` — CEN-A2 (`previous` must be the
/// tip's hash); `height` — the connecting height height-indexed rules
/// read (B5 here via [`Tip::connecting_height`]; 4.C and CEN-F5 later).
/// B1 does not read this: the rule set in force is an input the caller
/// chose with `rules_at(height)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tip {
    /// The tip's height.
    pub height: BlockHeight,
    /// The tip's identity (CEN-B6).
    pub hash: BlockHash,
}

impl Tip {
    /// The height a candidate connecting onto `tip` will have: `0` for an
    /// empty chain, `tip.height + 1` otherwise. Derived from the view and
    /// never from the candidate (CEN-F5: `txin_gen.height` is producer-
    /// chosen; the height operand is caller-derived), so every rule that is
    /// stated at "this block's height" reads it from one place.
    ///
    /// `u64::MAX` is unreachable — a dense chain of 2^64 blocks — so the
    /// saturation can never be observed; it is written rather than
    /// `unwrap`ped so no rule carries a panic path.
    ///
    /// Crate-private (`CHAIN_RULES_SLICE_1.md` §2): the connecting height is
    /// a rule's operand, and the store derives its own from `block_info`'s
    /// last key at `connect` (SI-2). A second consumer would be a reason to
    /// reopen, documented with its call site (rule 21), not a `pub` in
    /// advance.
    #[must_use]
    pub(crate) fn connecting_height(tip: Option<&Self>) -> BlockHeight {
        tip.map_or(BlockHeight::ZERO, |t| {
            BlockHeight::from_raw(t.height.to_raw().saturating_add(1))
        })
    }
}

/// A block the chain has recorded, as a rule reads it.
///
/// Every field is here because a named row reads it (round-1 ruling Q3):
/// `hash` — CEN-A2 (`prev_id` is the tip's hash), CEN-A4 (the parent is a
/// known block), CEN-D3 (the seed block's identity); `header` — CEN-C2,
/// CEN-C3 (the timestamps of the eleven preceding blocks), CEN-D4 (the
/// LWMA-1 window's timestamps); `cumulative_difficulty` — CEN-D4 (the
/// window's work); `coins_generated` — CEN-F13 (the parent's accumulator
/// is the subsidy curve's operand); `cumulative_tx_count` — CEN-F20 (two
/// prefix sums make the volume window). Weight arrives with 4.G; fields
/// grow with rows, never ahead of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedBlock {
    /// The block's identity, derived once when it was recorded (CEN-B6).
    pub hash: BlockHash,
    /// The header as recorded.
    pub header: BlockHeader,
    /// Work through this block: the parent's plus this block's target
    /// (`block_info.cumulative_difficulty`). Strictly increasing along the
    /// chain (SI-10); a rule that sees a decrease *or an equal pair*
    /// reports
    /// [`Corrupt::CumulativeDifficultyNotMonotone`](crate::Corrupt::CumulativeDifficultyNotMonotone).
    pub cumulative_difficulty: CumulativeDifficulty,
    /// Gross emission through this block (`block_info.coins_generated`):
    /// the parent's plus this block's paid reward. CEN-F13's operand — the
    /// subsidy curve reads the **parent's** value for a candidate at
    /// `parent + 1`. Gross, not net of burn: the curve is a function of
    /// what was issued (FL-R16c's net operand is the *burn ratio's*, a
    /// different quantity).
    pub coins_generated: AtomicUnits,
    /// Transactions listed in blocks `0..=this`, a prefix sum
    /// (`block_info.cumulative_tx_count`, S-CHAIN-W). CEN-F20's operand:
    /// `Σ tx_hashes.len()` over the prior `min(h, W)` blocks is the
    /// difference of two of these.
    pub cumulative_tx_count: u64,
    /// Archival length of every transaction in blocks `0..=this`, a prefix
    /// sum (`block_info.cumulative_archival_len`, `SHT-Q2`; SI-24 ties it
    /// to the per-transaction rows). The shard partition's operand: shard
    /// `k` holds the transactions whose fold-before lies in `[k·W, (k+1)·W)`
    /// (`shekyl_types::shard_of`), so the shards the chain through this
    /// block has closed are `0..shard_of(this)` — CEN-F17's `n`
    /// ([`closed_shards_before`](crate::closed_shards_before)) and the
    /// close's age operand ([`shard_close_height`](crate::shard_close_height))
    /// read it here.
    pub cumulative_archival_len: ArchivalLength,
}

/// What one recorded output contributes to its curve-tree leaf — the three
/// points `construct_leaf` takes (`O`, `C`, and the `0x07` entry's
/// commitment `CM`, `PL-D3`) and the chain-wide index the leaf's position
/// map records (DRS-E3 §3.2, §3.3). The points are carried as the recorded
/// bytes: decompressing them is the derivation's, and a byte string that is
/// not a point is `Corrupt`, never a leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeafSource {
    /// The output's chain-wide dense index — what `output_to_leaf` is keyed
    /// by. Never a tree position (`SOK-10`).
    pub output: GlobalOutputIndex,
    /// The one-time output key `O`, compressed Ed25519.
    pub key: [u8; 32],
    /// The amount commitment `C`, compressed Ed25519.
    pub commitment: [u8; 32],
    /// The `0x07` entry's leaf-commitment point `CM`, compressed Ed25519.
    pub pqc_leaf_commitment: [u8; 32],
}

/// A recorded block's outputs, split by the maturity each half drains at:
/// the coinbase's at `height + mined_money_unlock_window`, the listed
/// transactions' at `height + tx_spendable_age` (DRS-E3 §3.2; CTW-10 — the
/// pending set is a function of the block index, not a table). Each half
/// is in output order, which is global-index order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockOutputs {
    /// The miner transaction's outputs.
    pub coinbase: Vec<LeafSource>,
    /// The listed transactions' outputs, transaction order then output order.
    pub listed: Vec<LeafSource>,
}

/// The narrow, read-only view a rule consumes.
///
/// `'id` is the transaction brand (`WriteBatch<'_, 'id>`). `validate` mints
/// `ChainValid<'id, V>` so the verdict is branded with **both** the batch
/// lifetime and the view *type*. An unbranded `impl<'id> ChainView<'id> for
/// Evil` can still pick up a batch's `'id`, but `connect` will demand
/// `ChainValid<'id, StoreView<'_, 'id>>` and `Evil` will not unify. The trait
/// has no `'id`-carrying method — well-behaved implementors (the store
/// projection, the crate's test mock) put `'id` in their type; G4 is
/// closed at the token, not by sealing the trait (the store crate must
/// implement it, and this crate cannot name the store).
///
/// Implementors answer about the **recorded** chain only. A pool decorator
/// (DRS-E5) that also knows the pool's own key images implements this trait
/// over an inner view; this crate never names it.
pub trait ChainView<'id> {
    /// What the view's substrate can fail with. Opaque to every rule (no
    /// bound): the store's engine error for its projection,
    /// [`Infallible`](core::convert::Infallible) for the mock. A fault is
    /// not a verdict — see the module docs.
    type Fault;

    /// Whether `key_image` has been spent on the recorded chain.
    ///
    /// CEN-I7 (chain-wide key-image uniqueness); the chain half of CEN-L1.
    fn has_key_image(&self, key_image: &KeyImage) -> Result<bool, Self::Fault>;

    /// The block recorded at `height`.
    ///
    /// CEN-A2, CEN-A4 (the parent, by hash); CEN-C2, CEN-C3 (the preceding
    /// timestamps).
    fn block_at(&self, height: BlockHeight) -> Result<AtHeight<RecordedBlock>, Self::Fault>;

    /// The height the block `hash` is recorded at, or `None` if the chain
    /// does not contain it. By hash, so `Option` and not [`AtHeight`]:
    /// absence has one meaning here — the block is not on this chain —
    /// where a height-keyed read distinguishes "above the tip" from a hole.
    ///
    /// CEN-I10 (the spend's `referenceBlock` is a main-chain block; its
    /// height is CEN-I11's and CEN-I12's operand). The store has carried
    /// this read since S-CHAIN-R (`ReadSnapshot::height_of`); slice 6
    /// commit 5 put it on the contract.
    fn height_of(&self, hash: &BlockHash) -> Result<Option<BlockHeight>, Self::Fault>;

    /// The curve-tree state **at** chain height `height` — the root after
    /// the block at `height − 1` connected and **before** the block at
    /// `height` drained its own leaves. It is the membership anchor a spend
    /// that references `height` is verified against, and the root the header
    /// at `height` must carry (CEN-B5).
    ///
    /// Not the root *after* the block at `height`: that is the anchor for a
    /// reference to `height + 1`. The daemon keys this state at `height`
    /// (`store_curve_tree_root_at_height(prev_height + 1, …)` from the
    /// parent's connect), so an implementation reads its per-height table at
    /// `height`, never `height + 1` (S-CHAIN-W SCW-19).
    ///
    /// CEN-I12.
    fn root_at(&self, height: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Self::Fault>;

    /// The last recorded block, or `None` for an empty chain (genesis
    /// admission). See [`Tip`] for why `Option`.
    ///
    /// CEN-A2 (`hash`); B5 and later 4.C / CEN-F5 (`height`, via
    /// [`Tip::connecting_height`]).
    fn tip(&self) -> Result<Option<Tip>, Self::Fault>;

    /// The curve tree as the next grow needs it: its leaf count and every
    /// layer's last chunk hash (DRS-E3 §3.1; CTW-8 — the only chunks a grow
    /// can change). [`TreeFrontier::EMPTY`] for a tree nothing has grown.
    ///
    /// Read by the growth derivation in `validate`, which is not a rule
    /// (it refuses nothing) but the operand F17, I12, I13 and I15 read.
    fn tree_frontier(&self) -> Result<TreeFrontier, Self::Fault>;

    /// The leaf count **at** chain height `height` — after the block at
    /// `height − 1` drained, before the block at `height` drains — keyed
    /// exactly as [`root_at`](Self::root_at) is (SCW-19). `0` at height
    /// `0`. The primitive [`depth_at`](Self::depth_at) derives from
    /// (`CTW-Q4`: depth is a function of this count and is never stored
    /// per height) and CEN-F17's operand.
    fn leaf_count_at(&self, height: BlockHeight) -> Result<AtHeight<u64>, Self::Fault>;

    /// The recorded block at `height`'s outputs, as leaf sources, split by
    /// the maturity each half drains at (DRS-E3 §3.2). The drain at
    /// connecting height `h` reads two of these: `h − mined_money_unlock_window`
    /// (its coinbase half) and `h − tx_spendable_age` (its listed half).
    ///
    /// Not a rule's read: the growth derivation's.
    fn outputs_at(&self, height: BlockHeight) -> Result<AtHeight<BlockOutputs>, Self::Fault>;

    /// The tree's depth **at** `height` — layers above the leaf layer
    /// (`fcmp_layers = depth + 1`) — derived from
    /// [`leaf_count_at`](Self::leaf_count_at) by the library's layer
    /// arithmetic, so a per-height depth is never stored beside the count
    /// it is a function of (`CTW-Q4`). `0` for an empty tree.
    ///
    /// CEN-I13's operand (E6 slice 6 Q8: the depth the spend's proof was
    /// built over, at `ref_height`, never the current depth).
    fn depth_at(&self, height: BlockHeight) -> Result<AtHeight<u8>, Self::Fault> {
        Ok(match self.leaf_count_at(height)? {
            AtHeight::Recorded(0) => AtHeight::Recorded(0),
            AtHeight::Recorded(count) => AtHeight::Recorded(layer_count_for_leaves(count) - 1),
            AtHeight::AboveTip => AtHeight::AboveTip,
        })
    }

    /// The recorded weights of the up-to-`at_most` blocks **strictly
    /// below** `end`, in height order — heights `[end − k, end)` with
    /// `k = min(at_most, end)`. `end` is the height the caller is judging
    /// *for* (a candidate's connecting height): the window holds what was
    /// recorded before it, never the candidate itself. `end` above
    /// `tip + 1` is [`AtHeight::AboveTip`] — the caller asked about blocks
    /// the chain does not have; a hole inside the window is the view's
    /// fault (SI-7: `block_info` is dense to the tip), never a shorter
    /// vector.
    ///
    /// CEN-G6 / G6b: the long-term median over the last `min(100 000, h)`
    /// long-term weights and the short-term median over the last 100
    /// weights — one read for the long window, the short window its
    /// suffix. The C++'s `get_long_term_block_weight_median(start, n)` and
    /// `get_last_n_blocks_weights(n)`, as one bulk read (E6 slice 7 Q2).
    fn weights_window(
        &self,
        end: BlockHeight,
        at_most: BlockCount,
    ) -> Result<AtHeight<Vec<RecordedWeights>>, Self::Fault>;

    /// Whether a transaction with identity `hash` is recorded on the chain
    /// — in any block, the miner transaction included (the store records
    /// it under its identity like a listed one; the C++'s `tx_exists`).
    /// By hash, so `bool` and not [`AtHeight`]: absence has one meaning.
    ///
    /// CEN-G1 (no listed transaction may already exist in the chain). The
    /// store has carried this membership since S-CHAIN-W (`tx_indices`);
    /// slice 7 lifts it onto the view.
    fn has_transaction(&self, hash: &TxHash) -> Result<bool, Self::Fault>;

    /// Atomic units destroyed by the whole chain **as this view holds it**
    /// — the `total_burned` fold at parent state (the store's R9 register;
    /// `0` for a chain that has never burned). A chain-state read, not a
    /// per-height one: the view *is* parent state (F19's brand), so there
    /// is no height to key it by and no `AtHeight`.
    ///
    /// CEN-F17's operand, with the parent's `coins_generated`: the
    /// circulating supply the burn ratio reads is `coins_generated −
    /// total_burned` (FL-R16c), and `total_burned > coins_generated` is a
    /// store invariant broken — [`Corrupt::BurnExceedsEmission`], never a
    /// clamp. The C++'s `m_db->get_total_burned()` at `blockchain.cpp:5819`,
    /// read once and shared with the accrual (G11). E6 slice 7 wave B.
    ///
    /// [`Corrupt::BurnExceedsEmission`]: crate::Corrupt::BurnExceedsEmission
    fn total_burned(&self) -> Result<AtomicUnits, Self::Fault>;

    // -----------------------------------------------------------------------
    // The archival reads (DRS-E4 §2.3; DRS-E1 S-ARCH A1–A9, A11–A13)
    //
    // Recorded archival *state*, for the 4.J rows E6 slice 8 lands and the
    // E4 fold that derives a bond post's transition: a record is state, the
    // class the view exists to carry (G13 — no recorded body crosses it).
    // Each is a by-key read, so `Option` / empty and not `AtHeight`:
    // absence has one meaning per read, spelled on the read. All are
    // parent-state reads (F19's brand) — there is no height to key them by.
    //
    // A view whose archival answers are one policy implements all of them
    // with [`archival_reads!`](crate::archival_reads): `empty` (no bonds),
    // `fault` (every read fails), or `delegate` (forward to an inner view).
    // The real store projection answers from its rows and does not use the
    // macro. Adding a method here without adding it there leaves those
    // impls short of the trait, so the omission fails at compile time.
    // -----------------------------------------------------------------------

    /// **A1.** `persona`'s bond record as recorded, or `None` for a persona
    /// with no bond. CEN-J4's read (the named persona must have a record),
    /// the operand of every 4.J arm that reads the record (J5, J6, J13–J18)
    /// and of the as-of-height holdings fold
    /// (`shekyl-archival-retention::holds_shard_at`).
    fn bond_record(&self, persona: &PCanonicalId) -> Result<Option<BondRecord>, Self::Fault>;

    /// **A2.** Every slash logged against `persona` at a height **strictly
    /// above** `height`, in log order; empty when none. The history half of
    /// the as-of-height holdings question — `holds_shard_at` folds these
    /// over the record to say whether a shard was held *as of* `height`
    /// (CEN-J8's operand at the fire height; CEN-L16). Scoped to the persona
    /// by the read, so the fold need not re-check it.
    fn slash_log_after(
        &self,
        persona: &PCanonicalId,
        height: BlockHeight,
    ) -> Result<Vec<SlashLogEntry>, Self::Fault>;

    /// **A3.** The latest settlement epoch `persona` earned a pass bit in
    /// for `shard`, or `None` for a pair that never served — the release
    /// cooldown's anchor and its vacuous arm (CEN-J16).
    fn last_served_epoch(
        &self,
        persona: &PCanonicalId,
        shard: ShardId,
    ) -> Result<Option<SettlementEpoch>, Self::Fault>;

    /// **A4.** Every shard `persona` ever earned a pass bit for, each with
    /// its latest epoch; empty for a persona that never served. The
    /// last-served marshal in its complete-tree form (such a record stores
    /// no shard list, so the served set is the only list there is) —
    /// CEN-J16's cooldown over every shard. (It was also CEN-J17's
    /// drop-arm grace tail until that row retired with `HoldingsUpdate`,
    /// `ARW-14`; slice 8 Q1.)
    fn served_shards(&self, persona: &PCanonicalId) -> Result<Vec<ServedShard>, Self::Fault>;

    /// **A5.** Pass bits recorded for `(persona, shard, epoch)`;
    /// [`PassCount::ZERO`] when none. CEN-J3's pair-epoch dedup reads
    /// [`PassCount::any`]; the settlement writer reads the count.
    fn pass_count(
        &self,
        persona: &PCanonicalId,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<PassCount, Self::Fault>;

    /// **A6.** The market's co-holder count for `shard` at `epoch`'s close,
    /// or `None` for an epoch that never closed for it. A written
    /// `RMarket(0)` is a closed epoch with no co-holders (SAR-8): the view
    /// keeps the two apart; what a rule does with `None` is that rule's to
    /// say (`SAR-Q6`). CEN-J15's admission operand, CEN-J25's work
    /// arithmetic.
    fn r_market(
        &self,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<Option<RMarket>, Self::Fault>;

    /// **A7.** The frozen `Σwork(E)` for `epoch`, in milli-units, or `None`
    /// for an epoch that never closed (SAR-8). The stored denominator a
    /// verifier never recomputes — CEN-J25's.
    fn sigma_work(&self, epoch: SettlementEpoch) -> Result<Option<SigmaWorkMilli>, Self::Fault>;

    /// **A8.** The frozen `budget(E)` for `epoch`, or `None` for an epoch
    /// that never closed. CEN-J23: every claimed epoch must have one.
    fn budget(&self, epoch: SettlementEpoch) -> Result<Option<AtomicUnits>, Self::Fault>;

    /// **A9.** The slash watermark — the latest settlement epoch whose
    /// slashes have been applied — or `None` when no epoch has settled yet
    /// (the C++'s `u64::MAX` sentinel, gone by the type). CEN-J16's
    /// "settlement current through the anchor".
    fn last_settled_slash_epoch(&self) -> Result<Option<SettlementEpoch>, Self::Fault>;

    // -----------------------------------------------------------------------
    // The transition's reads (DRS-E4 commit 4; `DRS_E4_ARCHIVAL_WRITER.md`
    // §3.2 phase 9). A1–A9 answer a rule's question about one persona or
    // one epoch; the slash scan and the close ask over *every* record, and
    // the accrual reads the open epoch's running sum. Parent-state reads
    // like the rest.
    // -----------------------------------------------------------------------

    /// **A11.** Every bond record, in persona-key order, each with its
    /// persona; empty for a chain with no bonds. The slash scan's and the
    /// close's universe (`db_lmdb.cpp:5301`'s record cursor and `:7600`'s
    /// gather both walk `archival_bond` whole). Key order is the order the
    /// scan applies slashes in, so the slash log's per-height sequence is a
    /// function of the view and not of any iteration the store chose.
    fn bond_records(&self) -> Result<Vec<(PCanonicalId, BondRecord)>, Self::Fault>;

    /// **A12.** Whether the slash for `(persona, shard, epoch)` has been
    /// applied — the scan's dedup, read before anything else about the
    /// triple (`archival_challenge_failed_at_height`'s first probe,
    /// `db_lmdb.cpp:5471`). A set membership, so `bool` and never `Option`.
    fn slash_applied(
        &self,
        persona: &PCanonicalId,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<bool, Self::Fault>;

    /// **A13.** The staker inflow accrued so far in `epoch` while it is
    /// **open** (`archival_budget_accruing[E]`, SI-23), or `None` when no
    /// block has accrued into it yet — the first block of an epoch, or a
    /// closed epoch whose row the close deleted. The accrual adds this
    /// block's inflow to it; the close freezes it as `budget(E)` (A8).
    fn budget_accruing(&self, epoch: SettlementEpoch) -> Result<Option<AtomicUnits>, Self::Fault>;
}

/// Implement every archival [`ChainView`] read (A1–A9, A11–A13) as one policy.
///
/// Three policies, one method list. A new archival read is added here, once;
/// every view that expands the macro then implements it. A view that answers
/// from real rows (the store's `BatchView`) writes its own methods and
/// does not expand this.
///
/// * `archival_reads!(empty)` — no bonds: `None`, empty, `PassCount::ZERO`,
///   `false`. The `Ok` is any `Self::Fault`, including [`Infallible`](core::convert::Infallible).
/// * `archival_reads!(empty, r_market from <path>, close from <path>)` —
///   `empty`, except that `r_market` answers from the first `self.<path>`,
///   a `BTreeMap<(ShardId, SettlementEpoch), RMarket>` of planted prices,
///   and `sigma_work` / `budget` answer from the second, a
///   `BTreeMap<SettlementEpoch, (SigmaWorkMilli, AtomicUnits)>` of planted
///   closes. The archival reads a no-bonds view may plant: CEN-J15's
///   accept needs a priced shard, CEN-J25's refusal a closed epoch, and no
///   driven chain in the tree closes either (`rules/tx_bond.rs`, J15's
///   witness note; `rules/tx_emission_against.rs`). A price and a frozen
///   close are settled values the close wrote, not records, so planting
///   them tests no construction.
/// * `archival_reads!(fault <expr>)` — every read returns `Err(<expr>)`.
///   The expression is pasted into each method, so it is a unit constructor
///   or another value that is cheap to repeat.
/// * `archival_reads!(delegate <field>)` — each read is `self.<field>.the_method(...)`.
///   `<field>` names the inner view; the expansion writes `self` inside each method.
///
/// Paths are absolute so the expansion compiles in this crate and in a
/// downstream test view (`shekyl-chain-ingest`'s grown tree) without matching
/// imports.
#[macro_export]
macro_rules! archival_reads {
    (empty) => {
        $crate::archival_reads!(@methods {empty});
    };
    (empty, r_market from $($price:ident).+, close from $($close:ident).+) => {
        $crate::archival_reads!(@methods {planted $($price).+ ; $($close).+});
    };
    (fault $err:expr) => {
        $crate::archival_reads!(@methods {fault $err});
    };
    (delegate $inner:ident) => {
        $crate::archival_reads!(@methods {delegate $inner});
    };
    (@methods $policy:tt) => {
        // One signature list. `@emit` writes the whole method, receiver and
        // body together: a nested macro may not name `self`.
        $crate::archival_reads!(@emit $policy; bond_record;
            (persona: &shekyl_types::PCanonicalId);
            (::core::option::Option<shekyl_types::archival::BondRecord>);
            (persona);
            (::core::option::Option::None));
        $crate::archival_reads!(@emit $policy; slash_log_after;
            (persona: &shekyl_types::PCanonicalId, height: shekyl_types::BlockHeight);
            (::std::vec::Vec<shekyl_types::archival::SlashLogEntry>);
            (persona, height);
            (::std::vec::Vec::new()));
        $crate::archival_reads!(@emit $policy; last_served_epoch;
            (persona: &shekyl_types::PCanonicalId, shard: shekyl_types::ShardId);
            (::core::option::Option<shekyl_types::SettlementEpoch>);
            (persona, shard);
            (::core::option::Option::None));
        $crate::archival_reads!(@emit $policy; served_shards;
            (persona: &shekyl_types::PCanonicalId);
            (::std::vec::Vec<shekyl_types::archival::ServedShard>);
            (persona);
            (::std::vec::Vec::new()));
        $crate::archival_reads!(@emit $policy; pass_count;
            (
                persona: &shekyl_types::PCanonicalId,
                shard: shekyl_types::ShardId,
                epoch: shekyl_types::SettlementEpoch
            );
            (shekyl_types::archival::PassCount);
            (persona, shard, epoch);
            (shekyl_types::archival::PassCount::ZERO));
        $crate::archival_reads!(@emit $policy; r_market;
            (shard: shekyl_types::ShardId, epoch: shekyl_types::SettlementEpoch);
            (::core::option::Option<shekyl_types::archival::RMarket>);
            (shard, epoch);
            (::core::option::Option::None));
        $crate::archival_reads!(@emit $policy; sigma_work;
            (epoch: shekyl_types::SettlementEpoch);
            (::core::option::Option<shekyl_types::archival::SigmaWorkMilli>);
            (epoch);
            (::core::option::Option::None));
        $crate::archival_reads!(@emit $policy; budget;
            (epoch: shekyl_types::SettlementEpoch);
            (::core::option::Option<shekyl_units::AtomicUnits>);
            (epoch);
            (::core::option::Option::None));
        $crate::archival_reads!(@emit $policy; last_settled_slash_epoch;
            ();
            (::core::option::Option<shekyl_types::SettlementEpoch>);
            ();
            (::core::option::Option::None));
        $crate::archival_reads!(@emit $policy; bond_records;
            ();
            (::std::vec::Vec<(shekyl_types::PCanonicalId, shekyl_types::archival::BondRecord)>);
            ();
            (::std::vec::Vec::new()));
        $crate::archival_reads!(@emit $policy; slash_applied;
            (
                persona: &shekyl_types::PCanonicalId,
                shard: shekyl_types::ShardId,
                epoch: shekyl_types::SettlementEpoch
            );
            (bool);
            (persona, shard, epoch);
            (false));
        $crate::archival_reads!(@emit $policy; budget_accruing;
            (epoch: shekyl_types::SettlementEpoch);
            (::core::option::Option<shekyl_units::AtomicUnits>);
            (epoch);
            (::core::option::Option::None));
    };
    (@emit {empty}; $name:ident; ($($params:tt)*); ($ok:ty); ($($arg:expr),*); ($empty:expr)) => {
        fn $name(&self, $($params)*) -> ::core::result::Result<$ok, Self::Fault> {
            $crate::archival_reads!(@touch $($arg),*);
            ::core::result::Result::Ok($empty)
        }
    };
    // The planted reads: matched before the generic `planted` arm below,
    // so only `r_market`, `sigma_work` and `budget` read their maps and
    // every other read is `empty`'s.
    (@emit {planted $($price:ident).+ ; $($close:ident).+}; r_market; ($($params:tt)*); ($ok:ty); ($($arg:expr),*); ($empty:expr)) => {
        fn r_market(&self, $($params)*) -> ::core::result::Result<$ok, Self::Fault> {
            ::core::result::Result::Ok(self.$($price).+.get(&($($arg),*)).copied())
        }
    };
    (@emit {planted $($price:ident).+ ; $($close:ident).+}; sigma_work; ($($params:tt)*); ($ok:ty); ($($arg:expr),*); ($empty:expr)) => {
        fn sigma_work(&self, $($params)*) -> ::core::result::Result<$ok, Self::Fault> {
            ::core::result::Result::Ok(self.$($close).+.get(&($($arg),*)).map(|close| close.0))
        }
    };
    (@emit {planted $($price:ident).+ ; $($close:ident).+}; budget; ($($params:tt)*); ($ok:ty); ($($arg:expr),*); ($empty:expr)) => {
        fn budget(&self, $($params)*) -> ::core::result::Result<$ok, Self::Fault> {
            ::core::result::Result::Ok(self.$($close).+.get(&($($arg),*)).map(|close| close.1))
        }
    };
    (@emit {planted $($price:ident).+ ; $($close:ident).+}; $name:ident; ($($params:tt)*); ($ok:ty); ($($arg:expr),*); ($empty:expr)) => {
        fn $name(&self, $($params)*) -> ::core::result::Result<$ok, Self::Fault> {
            $crate::archival_reads!(@touch $($arg),*);
            ::core::result::Result::Ok($empty)
        }
    };
    (@emit {fault $err:expr}; $name:ident; ($($params:tt)*); ($ok:ty); ($($arg:expr),*); ($empty:expr)) => {
        fn $name(&self, $($params)*) -> ::core::result::Result<$ok, Self::Fault> {
            $crate::archival_reads!(@touch $($arg),*);
            ::core::result::Result::Err($err)
        }
    };
    (@emit {delegate $inner:ident}; $name:ident; ($($params:tt)*); ($ok:ty); ($($arg:expr),*); ($empty:expr)) => {
        fn $name(&self, $($params)*) -> ::core::result::Result<$ok, Self::Fault> {
            self.$inner.$name($($arg),*)
        }
    };
    (@touch) => {};
    (@touch $($arg:expr),+) => {
        let _ = ($($arg,)*);
    };
}
