// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The faults [`validate`](crate::validate) can return that are **not the
//! view's**: a stateless-stage premise that no longer holds against the
//! committing view ([`Stale`]), and view data no conforming store can hold
//! ([`Corrupt`]). Neither is a verdict (`CHAIN_RULES_SLICE_2.md` §8.1 Q8).
//!
//! # Why a fourth kind
//!
//! `form` judges a block with no view: it computes the longhash under a
//! **seed the caller claims** is the block id at the seed height, and under
//! a rule set the caller claims is in force. `validate` then checks both
//! claims against the transaction that will apply the block. A claim that
//! fails is not a refusal of the block — the block is **unproven, not
//! disproven** — and it is not a validator hole or a store capability
//! limit. It means the world moved between the stages (a reorg at least
//! `SEEDHASH_EPOCH_LAG` deep, or a rule-set boundary), and the remedy is to
//! run `form` again. So it has its own type and its own position, beside
//! the view's fault and never inside `InvalidBlock`.
//!
//! # The conversion ban extends here
//!
//! No `From`/`Into` between [`Stale`] (or [`Fault`]) and `InvalidBlock`, a
//! separate arm at every consumer, and `check_store_error_conversion_ban.py`
//! covers the token. A retry arm is *more* tempting to collapse than a store
//! error, not less — "couldn't prove it" reads like "rejected it" at a
//! glance — which is exactly why the gate names it.
//!
//! # The retry is bounded, and the bound has a terminal name
//!
//! Seed mismatch means redo `form`. Under sustained reorg pressure an
//! adversary can make that loop, and an unbounded redo on an
//! attacker-influenced trigger is a DoS primitive. So the count lives in
//! the type: `form` takes a [`FormAttempt`], a `Stale` carries the
//! [`Retry`] the driver is allowed — [`Retry::Again`] with the next attempt,
//! or [`Retry::Exhausted`] with nothing to pass back in. The driver cannot
//! call `form` a fourth time because it has no `FormAttempt` to call it
//! with; the terminal outcome is a named state, not a counter someone
//! forgot to check.

use core::fmt;

use shekyl_fcmp::LeafInput;
use shekyl_types::{
    BlockHash, BlockHeight, GlobalOutputIndex, PCanonicalId, SettlementEpoch, ShardId,
};
use shekyl_units::AtomicUnits;

use crate::rule_set::RuleSet;
use crate::tree_growth::FrontierFault;

/// What `validate` can fail with: the view's own fault, or one of the two
/// kinds this crate defines. Matched arm by arm — `?` on the caller's side
/// propagates the whole enum, never a part of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault<V> {
    /// The view's substrate could not answer. Opaque; the store's own
    /// error for its projection.
    View(V),
    /// A stateless-stage premise no longer holds against the committing
    /// view. Remedy: redo `form`, as the payload allows.
    Stale(Stale),
    /// The view answered with data no conforming store can hold (a store
    /// invariant observed broken from the validator's side). Remedy: the
    /// writer halt — this is an `InvariantViolated` the store did not see
    /// itself, and `connect` treats it as one.
    Corrupt(Corrupt),
}

/// A premise `form` was given that the committing view refutes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stale {
    /// The seed `form` computed the longhash under is not the block id at
    /// the seed height on the chain this block is connecting onto (CEN-D3).
    /// The seed height is at least `SEEDHASH_EPOCH_LAG` blocks below the
    /// connecting height, so this fires only on a reorg that deep between
    /// the two stages.
    Seed {
        /// What the caller claimed.
        claimed: BlockHash,
        /// What the view holds at the seed height.
        expected: BlockHash,
        /// Whether `form` may be run again.
        retry: Retry,
    },
    /// The rule set `form` judged under is not the one in force at the
    /// connecting height. Compared by **value** — a Fakechain `Fixed`
    /// target reuses [`RuleSetId::GENESIS`](crate::RuleSetId::GENESIS), so
    /// the id alone cannot tell `GENESIS` from `fakechain(n)`, or two
    /// different `n`.
    ///
    /// **This arm is what sized [`Fault`]** (112 bytes at slice 5 with
    /// `RuleSet` at 48): it carries two rule sets by value, so every byte
    /// `RuleSet` gains was charged twice here. That is the first cost slice
    /// 2 Q10 has presented — making the rule set runtime-parameterised made
    /// `RuleSetId` stop being a key, and anything that round-trips a rule
    /// set must carry the value. Not a reason to reverse Q10 (the
    /// fixed-difficulty lever being impossible on public nets *by type* is
    /// worth more than a struct's width). It mattered when `reorg_cap`
    /// joined the set (PR #861: `RuleSet` 56, `Fault` past clippy's 128;
    /// `tx_spendable_age` took it to 64 at DRS-E3 commit 2, absorbed) and
    /// the fix is the one written here in advance — **the payload is
    /// boxed**, which keeps the by-value comparison the Fakechain caveat
    /// requires — not shrinking `RuleSet`, and not keeping limits off it
    /// that a schedule step could vary (slice 5 Q5, corrected). `Fault` and
    /// `Stale` are `Clone`, not `Copy`, for this box.
    RuleSet {
        /// What `form` was given.
        formed_under: Box<RuleSet>,
        /// What `validate` was given.
        in_force: Box<RuleSet>,
        /// Whether `form` may be run again.
        retry: Retry,
    },
}

/// Which per-height record a [`Corrupt::HoleBelowTip`] failed to find.
///
/// The fault class is one — a view whose tip and rows disagree (SI-7) —
/// and the record is data, because the store maps it onto the cell that
/// was read. A root hole reported as the block row would halt the writer
/// against the wrong table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PerHeightRecord {
    /// [`crate::ChainView::block_at`]. The store's `block_info` cell.
    Block,
    /// [`crate::ChainView::root_at`]. The store's `curve_tree_roots` cell.
    CurveTreeRoot,
    /// [`crate::ChainView::leaf_count_at`]. The store's
    /// `curve_tree_leaf_counts` cell (DRS-E3).
    LeafCount,
    /// [`crate::ChainView::outputs_at`]. The store's block body and output
    /// rows at a height below the tip (DRS-E3: the drain's two source
    /// blocks).
    Outputs,
}

impl fmt::Display for PerHeightRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Block => "block",
            Self::CurveTreeRoot => "curve-tree root",
            Self::LeafCount => "curve-tree leaf count",
            Self::Outputs => "block outputs",
        })
    }
}

/// View data that violates a store invariant, observed by a rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Corrupt {
    /// Recorded cumulative work did not **strictly increase** between two
    /// adjacent heights — a decrease *or an equal pair*; every target is at
    /// least one, so both are impossible on a conforming store (SI-10;
    /// overflow of the same fold is SI-8).
    CumulativeDifficultyNotMonotone {
        /// The height whose cumulative difficulty is not above its parent's.
        at: BlockHeight,
    },
    /// The parent's cumulative difficulty plus this block's target does not
    /// fit the type.
    ///
    /// (A `ZeroTarget` arm lived here until 2026-09-20. Zero at the mint is
    /// **not** a corrupt view — LWMA-1 has no output floor and a conforming
    /// slow chain derives it — so it is CEN-D6's *refusal*, a verdict, and
    /// no longer a fault: `rules::difficulty` module docs, DRS-E2 RD-F17.)
    CumulativeDifficultyOverflow,
    /// The recorded `cumulative_tx_count` **decreased** between two heights
    /// the volume window spans (CEN-F20). A prefix sum the store folds
    /// under SI-8 cannot go backwards (SI-13, the read-side form) on a conforming store; read as a
    /// window it would price a dormant chain, so it is a fault, not a
    /// smaller number.
    TxCountNotMonotone {
        /// The upper height of the pair whose prefix sum is below the lower's.
        at: BlockHeight,
    },
    /// The archival fold does not place the close of shard `shard` at or
    /// below the height asked (`shard_close_height`). A shard
    /// [`closed_shards_before`](crate::closed_shards_before) counted closed
    /// has its end `(shard + 1) · W` at most the parent's
    /// `cumulative_archival_len`, and a non-decreasing fold (SI-13) crosses
    /// that end at one height. The search refuses when the height it lands
    /// on is still short of the end: the shard is open through the parent,
    /// the end does not fit `u64`, or the fold fell below the end and stayed
    /// down. SI-13, enforced when the store connects each block, is what
    /// makes the fold non-decreasing.
    ShardCloseUnplaced {
        /// The shard whose close was asked.
        shard: ShardId,
        /// The height the search landed on, or the parent when the shard's
        /// end does not fit.
        at: BlockHeight,
    },
    /// The recorded `total_burned` exceeds the parent's `coins_generated`
    /// (CEN-F17's two operands). Burn destroys issued coins, so the fold
    /// is bounded by the accumulator on every conforming store; a view
    /// where it is not has a fold that ran ahead of the emission it
    /// destroys from. FL-R16c ruled this a store-invariant violation and
    /// never a zero: `shekyl_economics::CirculatingSupply::derive` refuses
    /// it, and the validator halts rather than pricing a burn ratio over a
    /// supply the chain does not have (E6 slice 7 wave B).
    BurnExceedsEmission {
        /// The parent's gross emission.
        coins_generated: AtomicUnits,
        /// The chain's destroyed fold, larger than it.
        total_burned: AtomicUnits,
    },
    /// A per-height read answered `AboveTip` for a height a rule reads as
    /// **below** the connecting height: the parent, a window member, the
    /// seed height, block 0, a spend's reference height. `record` says
    /// which read. A conforming store reports a hole below its tip as
    /// its own fault (SI-7) before a rule can see one; a view that answers
    /// `AboveTip` there is a view whose tip and rows disagree.
    ///
    /// Until 2026-09-24 four sites carried this as `unreachable!`, each
    /// arguing from SI-7 that the arm had no producer. That is a store
    /// invariant defending a validator panic: if the argument is wrong
    /// anywhere, a crafted chain state kills the node instead of halting
    /// the writer. The class that halts — this one — already existed for
    /// SI-10 and SI-13; a rule that observes SI-7 broken uses it too. The
    /// validator's job is to refuse or halt, never to die.
    HoleBelowTip {
        /// The height that should have been recorded.
        at: BlockHeight,
        /// Which record was missing. The store maps this onto the cell.
        record: PerHeightRecord,
    },
    /// A recorded output's points do not decompress — `construct_leaf`
    /// refused them (DRS-E3 §3.2). Every admitted output's key, commitment
    /// and `0x07` point were gated as canonical prime-order points at
    /// admission (CEN-L11's argument, made a halt rather than a panic), so
    /// a recorded one that is not is bytes no conforming store holds.
    /// [`LeafInput`] names which point, so the store halts on the cell that
    /// holds it: `O` and `C` live in `output_amounts`, `CM` in the pruned
    /// transaction's `0x07` field.
    LeafNotConstructible {
        /// The output whose leaf could not be made.
        output: GlobalOutputIndex,
        /// Which point did not decompress.
        input: LeafInput,
    },
    /// The frontier the view served could not be grown ([`FrontierFault`]).
    /// An empty batch is not this arm: [`crate::GrowFault::NoLeaves`] is the
    /// caller's, and the drain does not ask `grow` to append nothing.
    TreeUnservable {
        /// What the served frontier refused.
        fault: FrontierFault,
    },
    /// A recorded bond record holds values the retention folds rule out
    /// ([`RecordInvariant`] says which). Every record the store holds was
    /// written from a delta the validator derived through those same folds,
    /// so a record they refuse is bytes no conforming store holds — the
    /// C++ writer's `FATAL: … invariant broken` arms, as a halt on the cell
    /// rather than a process abort (DRS-E4 §3.1; CEN-L9). Not the fold
    /// errors that name the *post* — a debit that is not the record's
    /// total, a Reinstate whose holdings moved — those are CEN-L7's
    /// refusals of the block, and the record is fine.
    BondRecordInvariant {
        /// The persona whose record is inconsistent.
        persona: PCanonicalId,
        /// Which invariant the fold found broken.
        which: RecordInvariant,
    },
    /// A recorded bond's `hybrid_pubkey` is not a canonical hybrid public
    /// key. The at-rest record keeps the key as bytes (`BondRecord` lives
    /// in `shekyl-types`, below the crypto crate that owns the grammar),
    /// and a bond is admitted only with bytes that grammar accepts. Bytes
    /// that no longer parse are store contents admission cannot have
    /// written — the same class as [`Self::LeafNotConstructible`], a halt
    /// on `archival_bond`, not a fold [`RecordInvariant`].
    ///
    /// Absence of a record is CEN-B4's refusal of the block. The FFI
    /// distinguishes a malformed key from an absent bond because there the
    /// bytes are the caller's input. Here they are the view's.
    BondHybridKeyMalformed {
        /// The persona whose record holds the key.
        persona: PCanonicalId,
    },
    /// The open epoch's accruing budget plus this block's accrual does not
    /// fit the type (CEN-L8's third clause; SI-8 on
    /// `archival_budget_accruing`). The accrual is bounded by the emission
    /// (every block's is a share of a paid reward that fits `u64`), so a
    /// running total that wraps is a fold that ran ahead of the chain, the
    /// class `CumulativeDifficultyOverflow` names — observed by the
    /// validator because the validator computes the post-image (ARW-Q1).
    AccrualOverflow {
        /// The open epoch whose total overflowed.
        epoch: SettlementEpoch,
    },
    /// Settlement of `epoch` found the recorded state it folds unfit to
    /// fold (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §9.5; SI-25). Never a refusal
    /// of the block: the block at the slash height is not invalid, this
    /// node cannot settle it.
    SettlementIntegrity {
        /// The epoch being settled.
        epoch: SettlementEpoch,
        /// Which check failed.
        check: SettlementCheck,
    },
}

/// Which of settlement's integrity checks failed —
/// [`Corrupt::SettlementIntegrity`]'s discriminant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettlementCheck {
    /// The epoch's issued-draw rows do not fold to the epoch's running
    /// digest (§9.5 check 1): a row was lost, gained or changed after the
    /// draw was indexed, or the digest was.
    IssuedIndexDigest,
    /// The fold counted more passes for a pair than draws it selected
    /// (§9.5 check 3, in the form the row type holds: `passes ≤ counted`,
    /// with `counted` three, or none below three issued — which implies
    /// `passes ≤ issued`). The fold selects at most three and only then
    /// counts, so this is a defect of the fold and not a state a store can
    /// hold. It halts, and is never clamped and never skipped: a pair with
    /// no row reads as unobserved.
    PassesExceedCounted {
        /// The persona of the pair.
        persona: PCanonicalId,
        /// The shard of the pair.
        shard: ShardId,
    },
}

/// Which of a bond record's invariants a retention fold found broken —
/// [`Corrupt::BondRecordInvariant`]'s discriminant. Each arm is a C++ writer
/// `FATAL` that names the *record*, not the post (`db_lmdb.cpp`
/// `apply_archival_unbond` / `apply_archival_reinstate` /
/// `process_archival_slash_apply_one`); the store maps the class onto the
/// `archival_bond` cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordInvariant {
    /// `bonded_total` is not the floor its holdings imply
    /// (`ReleaseConnectError::RecordFloorInvariantBroken`,
    /// `ReinstateConnectError::RecordFloorInvariantBroken`).
    FloorBroken,
    /// More than one open bad interval — the P2B-9 Pin 5 coalescing
    /// invariant (`ReinstateConnectError::MultipleOpenIntervals`).
    MultipleOpenIntervals,
    /// The open interval starts at or after the Reinstate that closes it
    /// (`ReinstateConnectError::IntervalOrdering`).
    IntervalOrdering,
    /// Interval or counter arithmetic left the type's range on a fold
    /// (`ReinstateConnectError::CounterRange`).
    CounterRange,
    /// The interval log is at its cap when a slash must append an open
    /// interval. Reinstate verify keeps two entries of headroom below the
    /// cap and a slash appends only when no interval is open, so a valid
    /// chain never reaches this — the C++'s *"a log above the cap cannot
    /// exist on disk"*.
    IntervalLogFull,
    /// A slash lands on a shard the compact record does not hold. The scan
    /// slashes what the record holds, from the record — the two cannot
    /// disagree unless the record changed under the scan.
    ShardNotHeld,
    /// `bonded_total` is below the bond floor a slash burns. The floor
    /// invariant (`FloorBroken`) makes every held shard's floor part of the
    /// total; a total below one floor while a shard is held is the same
    /// invariant, observed at the subtraction.
    BondedUnderflow,
}

impl fmt::Display for RecordInvariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::FloorBroken => "bonded_total is not the floor its holdings imply",
            Self::MultipleOpenIntervals => "more than one open bad interval",
            Self::IntervalOrdering => "the open bad interval does not precede the close",
            Self::CounterRange => "interval arithmetic out of range",
            Self::IntervalLogFull => "the bad-interval log is at its cap",
            Self::ShardNotHeld => "a slashed shard is not held",
            Self::BondedUnderflow => "bonded_total is below the bond floor",
        })
    }
}

/// What a **parent-side view read** can raise: the view's own fault, or a
/// store invariant the read observed broken ([`Corrupt`]). Narrower than
/// [`Fault`] — a read has no stale premise to raise — so a caller that is
/// a *definition* rather than a `Fault`-returning stage (F20's window,
/// C3's) matches two arms, not three, and never an arm that cannot occur.
/// Converts into [`Fault`] by `?` where a stage is the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewRead<VF> {
    /// The view faulted.
    View(VF),
    /// The view answered, and the answer breaks an invariant.
    Corrupt(Corrupt),
}

impl<VF> From<ViewRead<VF>> for Fault<VF> {
    fn from(read: ViewRead<VF>) -> Self {
        match read {
            ViewRead::View(fault) => Self::View(fault),
            ViewRead::Corrupt(corrupt) => Self::Corrupt(corrupt),
        }
    }
}

impl<VF> From<VF> for ViewRead<VF> {
    /// A view method's error, lifted into the parent-side read position.
    ///
    /// A block rule returns [`ViewRead`], so `?` on a view method (whose
    /// error is `V::Fault`) becomes [`ViewRead::View`]. This does not lift
    /// a view fault into [`Fault`]: that remains [`Fault::View`] or the
    /// [`From<ViewRead>`] above, and a definition that still returns
    /// `V::Fault` cannot become a halt by `?`.
    fn from(fault: VF) -> Self {
        Self::View(fault)
    }
}

/// The bound on redoing `form` after a [`Stale`] fault.
///
/// A mismatch needs a reorg at least `SEEDHASH_EPOCH_LAG` (64) blocks deep
/// between the two stages; two such reorgs during one block's admission is
/// not an organic condition (rule 75: the rationale for the value). After
/// the last attempt the block is dropped as unproven and the driver does
/// nothing further with it — a fresh relay starts a fresh
/// [`FormAttempt::FIRST`]. The peer that relayed it is not penalised: the
/// block may well be valid.
pub const MAX_FORM_ATTEMPTS: u8 = 3;

/// Which attempt at `form` this is, `1..=MAX_FORM_ATTEMPTS`. The only
/// constructor is [`FIRST`](Self::FIRST); later attempts come from a
/// [`Stale`]'s [`Retry::Again`] and nowhere else.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FormAttempt(u8);

impl FormAttempt {
    /// The first attempt — what a driver starts with.
    pub const FIRST: Self = Self(1);

    /// Which attempt this is, for the driver's log line.
    #[must_use]
    pub const fn number(self) -> u8 {
        self.0
    }

    /// The attempt after this one, for a fixture that wants to start
    /// mid-sequence without a `Stale` to hand it one.
    #[cfg(test)]
    pub(crate) fn next_for_tests(self) -> Self {
        match self.next() {
            Retry::Again(next) => next,
            Retry::Exhausted => panic!("no attempt after the last"),
        }
    }

    /// The final attempt, for the fixture that checks it is terminal.
    #[cfg(test)]
    pub(crate) const fn last_for_tests() -> Self {
        Self(MAX_FORM_ATTEMPTS)
    }

    /// The attempt after this one, or the terminal state.
    pub(crate) const fn next(self) -> Retry {
        if self.0 < MAX_FORM_ATTEMPTS {
            Retry::Again(Self(self.0 + 1))
        } else {
            Retry::Exhausted
        }
    }
}

/// What a driver may do after a [`Stale`] fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Retry {
    /// Run `form` again with this attempt.
    Again(FormAttempt),
    /// The bound is spent. The block is dropped as unproven; there is no
    /// `FormAttempt` to run `form` with, so the terminal state is enforced
    /// by the type, not by the driver remembering to stop.
    Exhausted,
}

impl fmt::Display for Stale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Seed {
                claimed,
                expected,
                retry,
            } => write!(
                f,
                "stale seed: formed under {claimed:?}, the chain holds {expected:?} ({retry})"
            ),
            Self::RuleSet {
                formed_under,
                in_force,
                retry,
            } => write!(
                f,
                "stale rule set: formed under {formed_under:?}, {in_force:?} is in force ({retry})"
            ),
        }
    }
}

impl fmt::Display for Retry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Again(attempt) => write!(f, "retry as attempt {}", attempt.number()),
            Self::Exhausted => f.write_str("retries exhausted; block dropped as unproven"),
        }
    }
}

impl fmt::Display for Corrupt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CumulativeDifficultyNotMonotone { at } => write!(
                f,
                "cumulative difficulty does not increase at height {at:?} (SI-10)"
            ),
            Self::CumulativeDifficultyOverflow => {
                f.write_str("cumulative difficulty overflows past the parent")
            }
            Self::TxCountNotMonotone { at } => write!(
                f,
                "cumulative transaction count decreases at height {at:?} (SI-13)"
            ),
            Self::ShardCloseUnplaced { shard, at } => write!(
                f,
                "the archival fold does not place the close of shard {shard:?} at height {at:?} (SI-13)"
            ),
            Self::BurnExceedsEmission {
                coins_generated,
                total_burned,
            } => write!(
                f,
                "total_burned {total_burned:?} exceeds coins_generated {coins_generated:?} (FL-R16c: the burned fold is bounded by the emission)"
            ),
            Self::HoleBelowTip { at, record } => write!(
                f,
                "no {record} recorded at height {at:?}, below the connecting height (SI-7)"
            ),
            Self::LeafNotConstructible { output, input } => write!(
                f,
                "recorded output {output:?} has a {input} that does not decompress; its leaf cannot be constructed"
            ),
            Self::TreeUnservable { fault } => write!(f, "curve tree cannot be grown: {fault}"),
            Self::BondRecordInvariant { persona, which } => {
                write!(f, "bond record of {persona} is inconsistent: {which} (SI-7)")
            }
            Self::BondHybridKeyMalformed { persona } => write!(
                f,
                "bond record of {persona} holds a hybrid key that is not canonical (SI-7)"
            ),
            Self::AccrualOverflow { epoch } => {
                write!(f, "budget accruing for epoch {epoch} overflows (SI-8)")
            }
            Self::SettlementIntegrity { epoch, check } => match check {
                SettlementCheck::IssuedIndexDigest => write!(
                    f,
                    "the issued draws recorded for epoch {epoch} do not fold to its digest (SI-25)"
                ),
                SettlementCheck::PassesExceedCounted { persona, shard } => write!(
                    f,
                    "settling ({persona}, {shard}) for epoch {epoch} counted more passes than \
                     draws selected (SI-25)"
                ),
            },
        }
    }
}

impl<V: fmt::Display> fmt::Display for Fault<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::View(fault) => write!(f, "view fault: {fault}"),
            Self::Stale(stale) => stale.fmt(f),
            Self::Corrupt(corrupt) => write!(f, "corrupt view: {corrupt}"),
        }
    }
}

impl<V: fmt::Debug + fmt::Display> std::error::Error for Fault<V> {}

#[cfg(test)]
#[path = "fault_tests.rs"]
mod fault_tests;
