// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The consensus rules as an explicit input: which rule set a verdict was
//! checked under, and which rule set is in force at a height.
//!
//! [`RuleSetId`] is **its own space** (`CHAIN_RULES_CRATE.md` §4.2, round-1
//! ruling Q5). It coincides with `BlockHeader.major_version` today because
//! the shipped hardfork table has one entry — the same inertness that hid
//! the `on_block_popped` defect — and the coincidence is a fact about the
//! table, not a definition. So there is no `From<u8>`, no `PartialEq<u8>`,
//! and no reading of the header version anywhere here: the header version
//! a rule set *admits* is one of its parameters ([`RuleSet::header_major_version`],
//! landed with CEN-B1 in slice 1), never its identity.
//!
//! [`RuleSchedule`] is where R4's state-dependent activation has its seat.
//! `rules_at(height)` is a function, seeded as the identity (every network,
//! every height → [`RuleSet::GENESIS`]), so a second rule set arrives as a
//! schedule step and no caller changes. Nettype selects **data** (rule 71):
//! three schedule values, one `rules_at`, no `match network` anywhere a rule
//! runs.
//!
//! [`AdmissionPolicy`] is relay/pool policy — a separate input with a
//! separate id, never merged into [`RuleSet`] (ruling §8). Its consumer is
//! DRS-E5; it is staged here because `DAEMON_REDB_STORE.md` §7.5.1 lists it
//! with the crate.

use core::fmt;

use shekyl_address::Network;
pub use shekyl_archival_retention::{SettlementEpochBlocks, SettlementSchedule};
use shekyl_types::{BlockCount, BlockHeight};

use crate::census::{CenRow, RowStatus};
use crate::reorg::D_MAX;
use crate::rules::difficulty::Target;

/// Identifies the consensus rule set a `ChainValid` was checked under.
///
/// Persisted beside the verdict at S-CHAIN-W and compared to
/// [`RuleSchedule::rules_at`] on `connect`; a mismatch is refused there as
/// `StoreCannot` — the block was judged under rules not in force at its
/// height, which is not a verdict about the block.
///
/// Not the header's `major_version`, and not comparable to one — the 1:1 is
/// a fact about today's table, and equality would erase the distinction
/// [`RuleSchedule::rules_at`] exists to preserve:
///
/// ```compile_fail
/// # use shekyl_chain_rules::RuleSetId;
/// assert!(RuleSetId::GENESIS == 1u8); // no `PartialEq<u8>`
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RuleSetId(u8);

impl RuleSetId {
    /// The rule set in force from genesis.
    pub const GENESIS: Self = Self(1);

    /// Wrap a raw id. An *edge* constructor for the store's decode of a
    /// persisted id; the value it names may not be issued — resolve it with
    /// [`RuleSet::for_id`] before trusting it.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self(raw)
    }

    /// The raw id, for the store's encode.
    #[must_use]
    pub const fn to_raw(self) -> u8 {
        self.0
    }
}

/// The consensus rules as an explicit input to `validate`.
///
/// A rule set is a named, **issued** value: [`RuleSet::for_id`] resolves an
/// id to one, and the public-network path — `RuleSchedule::for_network` →
/// `rules_at` → `for_id` — can build no other. Parameters populate as
/// rules land. The first is `enforced` — the census rows this rule set
/// holds a block to, which is also the denominator a verdict's coverage is
/// measured complete against. The second is `header_major_version` — the
/// `BlockHeader.major_version` this rule set admits (CEN-B1), landed with
/// slice 1. It is not CEN-B2's operand: the header's minor version is
/// reserved at one value under every rule set. The third is `difficulty` — how
/// CEN-D4 derives the target — landed with slice 2 and the reason one
/// non-issued constructor exists ([`RuleSet::fakechain`]). The fourth —
/// `mined_money_unlock_window` (CEN-F6) — landed with slice 4
/// (`CHAIN_RULES_SLICE_4.md` Q5): the C++ `#define`
/// `CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW`, stated here because F6 reads it.
/// The fifth — `reorg_cap` (CEN-E2's `D_max`, `PDM-Q11`) — is the deepest
/// reorganisation a node following this rule set is built to accept:
/// consensus data, so it lives here and not in any store's configuration
/// (PR #861 review: the store's undo retention is *constrained by* the
/// in-force set's cap, never the other way round). `GENESIS` carries
/// [`D_MAX`]; a Fakechain set names its own through [`RuleSet::fakechain`],
/// the same witness `Fixed` uses, so a shortened regtest schedule runs a
/// rule set whose cap fits inside its epoch rather than a store field the
/// validator would have to defer to. The sixth — `tx_spendable_age` — is
/// the miner window's sibling (DRS-E3 `CTW-Q5`): how many blocks after its
/// height a *listed* transaction's outputs stay out of the curve tree, the
/// C++ `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE`. Both decide when an output
/// becomes usable — the pair is the drain calendar the tree grows by
/// (`DRS_E3_CURVE_WRITER.md` §3.2, §3.6) — so they live together and move
/// together; the reason is coherence with F6, not schedule variance.
/// The seventh — `settlement_schedule` (DRS-E4 `ARW-15`) — is
/// the epoch geometry the archival rows (CEN-L1…L9) are judged against:
/// which epoch a height sits in, where a challenge opens and closes, when
/// an epoch's claims settle. It is the reorg cap's other half — SPR-9's
/// `SEB > D_max` is an invariant *between two fields of this struct*, held
/// by [`FakechainSchedule`] — and it joined the set for the cap's reason:
/// the validator reads its parameters off the rule set in force, never
/// off the process's environment. Before it did, the daemon armed the
/// `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` lever into a process latch and the
/// validator read the latch; a replay of a capture made under the lever,
/// in a process that had not armed it, refused the first claim under L7
/// (`DRS_E4_ARCHIVAL_WRITER.md` §5 ARW-15). CEN-F21's split epoch is
/// `shekyl_economics::EMISSION_SPLIT_EPOCH`, not a field.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RuleSet {
    id: RuleSetId,
    enforced: &'static [CenRow],
    header_major_version: u8,
    difficulty: DifficultyRule,
    mined_money_unlock_window: BlockCount,
    reorg_cap: BlockCount,
    tx_spendable_age: BlockCount,
    settlement_schedule: SettlementSchedule,
}

/// The two schedule parameters a Fakechain rule set may name — blocks per
/// settlement epoch and the reorg cap — **as a validated pair**: the cap
/// strictly inside the epoch (`0 < cap < SEB`, SPR-9 / `reorg.rs`'s
/// `SEB > D_max`), refused at construction rather than discovered when the
/// undo floor crosses the body horizon.
///
/// Why a pair and not two levers: the invariant is between them, so a
/// constructor that took them separately would have to be fallible on the
/// second, or leave the check to a store that does not own either number.
/// [`RuleSet::fakechain`] takes one of these and stays infallible;
/// [`Self::PRODUCTION`] is the genesis pair, and `fakechain(None,
/// PRODUCTION)` is `GENESIS` by value. The daemon's
/// `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` / `SHEKYL_ARCHIVAL_REORG_DEPTH_BLOCKS`
/// levers and the replay tool's flags both resolve to one of these before
/// a rule set exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FakechainSchedule {
    settlement: SettlementSchedule,
    reorg_cap: BlockCount,
}

/// A [`FakechainSchedule`] whose reorg cap is not strictly inside its epoch
/// (`0 < cap < SEB` fails). The store's `RetentionNotInsideEpoch` is the
/// same inequality on the session's retention; this is it on the rule
/// set's own parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReorgCapNotInsideEpoch {
    /// Blocks per epoch the pair named.
    pub settlement_epoch: SettlementEpochBlocks,
    /// The cap it named.
    pub reorg_cap: BlockCount,
}

impl fmt::Display for ReorgCapNotInsideEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "reorg cap {} is not strictly inside the settlement epoch ({}): 0 < cap < SEB is required",
            self.reorg_cap.to_raw(),
            self.settlement_epoch
        )
    }
}

impl std::error::Error for ReorgCapNotInsideEpoch {}

impl FakechainSchedule {
    /// The genesis pair: `SETTLEMENT_EPOCH_BLOCKS` per epoch, `D_MAX` cap
    /// — the invariant on it is `reorg.rs`'s compile-time assertion.
    pub const PRODUCTION: Self = Self {
        settlement: SettlementSchedule::GENESIS,
        reorg_cap: D_MAX,
    };

    /// The pair `(settlement_epoch, reorg_cap)`, if `0 < reorg_cap < SEB`.
    ///
    /// # Errors
    ///
    /// [`ReorgCapNotInsideEpoch`] otherwise.
    pub const fn new(
        settlement_epoch: SettlementEpochBlocks,
        reorg_cap: BlockCount,
    ) -> Result<Self, ReorgCapNotInsideEpoch> {
        let cap = reorg_cap.to_raw();
        if cap == 0 || cap >= settlement_epoch.get() {
            return Err(ReorgCapNotInsideEpoch {
                settlement_epoch,
                reorg_cap,
            });
        }
        Ok(Self {
            settlement: SettlementSchedule::new(settlement_epoch),
            reorg_cap,
        })
    }

    /// The epoch geometry.
    #[must_use]
    pub const fn settlement(self) -> SettlementSchedule {
        self.settlement
    }

    /// The reorg cap.
    #[must_use]
    pub const fn reorg_cap(self) -> BlockCount {
        self.reorg_cap
    }

    /// Whether this is [`PRODUCTION`](Self::PRODUCTION) — the pair no lever
    /// was pulled to reach, so a public network may carry it (`const`,
    /// where `==` cannot yet be).
    #[must_use]
    pub const fn is_production(self) -> bool {
        self.settlement.blocks().get() == Self::PRODUCTION.settlement.blocks().get()
            && self.reorg_cap.to_raw() == Self::PRODUCTION.reorg_cap.to_raw()
    }
}

// The genesis pair satisfies its own invariant — the same fact `reorg.rs`
// asserts, restated on the type that carries it.
const _: () = assert!(
    FakechainSchedule::PRODUCTION.reorg_cap.to_raw()
        < FakechainSchedule::PRODUCTION.settlement.blocks().get()
);

/// How a rule set derives the next-block target (CEN-D4 reads this).
///
/// Every issued rule set is [`Lwma1`](Self::Lwma1). [`Fixed`](Self::Fixed)
/// is the `--fixed-difficulty` regtest lever as **data on a Fakechain rule
/// set** (CEN-D7; `CHAIN_RULES_SLICE_2.md` §4.5, arm (d)): the DAA is not
/// bypassed by a flag the validator consults, the rule set in force simply
/// says what the target is. No override path exists on any nettype other
/// than Fakechain, enforced by the type system rather than by a runtime
/// check — the API the public nettypes select cannot express `Fixed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DifficultyRule {
    /// LWMA-1 over the recorded window; the genesis constant below `N`.
    Lwma1,
    /// A fixed target at every height above genesis (height `0` is `1`, as
    /// `blockchain.cpp:975` has it).
    ///
    /// **`RuleSetId` no longer uniquely determines the rule set once this
    /// variant exists.** A Fakechain set carries `RuleSetId::GENESIS` with a
    /// parameter no issued set has, so two Fakechain nodes at the same id
    /// may hold different rule sets. Tolerable — Fakechain is
    /// single-operator and cross-node identity does not matter there — but
    /// `RuleSetId` equality is **not** a proxy for rule-set equality, and
    /// code that compares ids to decide whether two nodes run the same rules
    /// is wrong on Fakechain by exactly this variant.
    Fixed(Target),
}

impl RuleSet {
    /// The genesis rule set: every consensus row of the census; admits
    /// header version `1` (the C++ `CURRENT_BLOCK_MAJOR_VERSION`;
    /// `rule_set_tests` pins the two equal); LWMA-1 difficulty.
    pub const GENESIS: Self = Self {
        id: RuleSetId::GENESIS,
        enforced: CenRow::ALL,
        header_major_version: 1,
        difficulty: DifficultyRule::Lwma1,
        mined_money_unlock_window: BlockCount::from_raw(60),
        reorg_cap: D_MAX,
        tx_spendable_age: BlockCount::from_raw(10),
        settlement_schedule: SettlementSchedule::GENESIS,
    };

    /// Every rule set a schedule may name, in id order. A schedule step that
    /// names an id absent from here does not compile (`well_formed`).
    const ISSUED: &'static [Self] = &[Self::GENESIS];

    /// The genesis rules as a **Fakechain** set: the target fixed when
    /// `shekyld --regtest --fixed-difficulty=<n>` names one (CEN-D7, arm
    /// (d)), and the settlement schedule the regtest runs —
    /// [`FakechainSchedule::PRODUCTION`] for a regtest on the genesis
    /// schedule, a shortened epoch with a cap inside it for a regtest under
    /// the `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` / `SHEKYL_ARCHIVAL_REORG_DEPTH_BLOCKS`
    /// levers (the pair's constructor refuses `cap ≥ SEB`; the store
    /// refuses a retention below the cap, and a pinned epoch other than
    /// the set's, at open and at every connect).
    ///
    /// The one constructor of a non-issued rule set, and deliberately not
    /// reachable from [`RuleSchedule::for_network`]: `shekyl_address::Network`
    /// has no Fakechain variant (slice 2 §4.5 F10), so the daemon's
    /// `--regtest` is what binds this call to fakechain today; when the
    /// variant exists this takes it as a witness. `fixed` is non-zero by
    /// its type, so the target it fixes is a [`Target`] by construction
    /// (CEN-D6); `schedule` is a valid pair by its type, so the invariant
    /// between the two fields it sets holds by construction.
    /// `fakechain(None, FakechainSchedule::PRODUCTION)` **is** `GENESIS`
    /// by value.
    #[must_use]
    pub const fn fakechain(
        fixed: Option<core::num::NonZeroU128>,
        schedule: FakechainSchedule,
    ) -> Self {
        let difficulty = match fixed {
            Some(fixed) => DifficultyRule::Fixed(Target::fixed(fixed)),
            None => DifficultyRule::Lwma1,
        };
        Self {
            difficulty,
            reorg_cap: schedule.reorg_cap,
            settlement_schedule: schedule.settlement,
            ..Self::GENESIS
        }
    }

    /// How this rule set derives the next-block target.
    #[must_use]
    pub const fn difficulty(&self) -> DifficultyRule {
        self.difficulty
    }

    /// The settlement-epoch geometry the archival rows are judged against
    /// (CEN-L1…L9): which epoch a height sits in, where a challenge opens,
    /// closes and is slash-final, which epoch a height closes. The
    /// validator reads epoch arithmetic here and nowhere else — never the
    /// process-latched `SettlementSchedule::effective()`, which is the
    /// daemon's and the FFI's entry point (rule 71: the schedule in force is
    /// data on the set in force). The store pins the same number in its
    /// header and refuses a session whose in-force set names another.
    #[must_use]
    pub const fn settlement_schedule(&self) -> SettlementSchedule {
        self.settlement_schedule
    }

    /// The deepest reorganisation a node under this rule set is built to
    /// accept (`D_max`, CEN-E2 / `PDM-Q11`). The store's undo retention is
    /// at least this (S-CHAIN-W SCW-7), so a legal reorg never meets
    /// `PopBelowFloor`; CEN-E2's `is_alternative_block_allowed` reads this,
    /// never `D_MAX` directly, so a Fakechain set and its store agree.
    #[must_use]
    pub const fn reorg_cap(&self) -> BlockCount {
        self.reorg_cap
    }

    /// The rule set `id` names; `None` for an id no schedule has issued.
    #[must_use]
    pub fn for_id(id: RuleSetId) -> Option<Self> {
        Self::ISSUED
            .iter()
            .copied()
            .find(|rule_set| rule_set.id == id)
    }

    /// This rule set's id.
    #[must_use]
    pub const fn id(&self) -> RuleSetId {
        self.id
    }

    /// The consensus rows this rule set holds a block to **and the
    /// per-block stages can evaluate**, in census order. Excluded: rows
    /// held by the C++ ingest driver ([`RowStatus::HeldByCxx`]), which are
    /// not the validator's; and rows this crate enforces at another site
    /// ([`RowStatus::EnforcedAt`] — CEN-E5 at writer open) or holds by
    /// construction ([`RowStatus::ByConstruction`] — CEN-F2, F8, F19), which
    /// no per-block coverage could contain. So `Coverage::is_complete_for`
    /// measures `enforced − held − at-open − by-construction` — the census
    /// denominator itself never moves for any of them (the gate prints the
    /// subtractions beside it).
    pub fn enforced(&self) -> impl Iterator<Item = CenRow> + '_ {
        self.enforced.iter().copied().filter(|row| {
            !matches!(
                row.status(),
                RowStatus::HeldByCxx | RowStatus::EnforcedAt | RowStatus::ByConstruction
            )
        })
    }

    /// A rule set that admits `header_major_version`, for the version-rule
    /// fixtures only: `ISSUED` holds one set today, and B1 under a later set
    /// has no other way to be exercised. Never
    /// issued, never named by a schedule, not constructible outside tests.
    #[cfg(test)]
    pub(crate) const fn admitting_for_tests(header_major_version: u8) -> Self {
        Self {
            id: RuleSetId::from_raw(u8::MAX),
            enforced: CenRow::ALL,
            header_major_version,
            ..Self::GENESIS
        }
    }

    /// How many blocks after its height a coinbase's outputs stay locked
    /// (CEN-F6: `unlock_time == height + window`). `60` on every issued
    /// rule set — the C++ `CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW`, a
    /// `#define` in `cryptonote_config.h` rather than a `config/` key (the
    /// census notes the asymmetry); `rule_set_tests` pins the two equal.
    #[must_use]
    pub const fn mined_money_unlock_window(&self) -> BlockCount {
        self.mined_money_unlock_window
    }

    /// How many blocks after its height a **listed** transaction's outputs
    /// stay out of the curve tree — the maturity the drain uses for every
    /// non-coinbase output (DRS-E3 §3.2: block `h`'s listed outputs drain
    /// at `h + tx_spendable_age`; its coinbase at
    /// `h + mined_money_unlock_window`). `10` on every issued rule set —
    /// the C++ `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE`; `rule_set_tests` pins
    /// the two equal, and pins both maturities to the wallet side's
    /// `shekyl_consensus::{DEFAULT_LOCK_WINDOW, COINBASE_LOCK_WINDOW}` —
    /// the eligibility arithmetic that assumes the daemon inserts at exactly
    /// these heights (`shekyl_engine_state::transfer::SPENDABLE_AGE`).
    #[must_use]
    pub const fn tx_spendable_age(&self) -> BlockCount {
        self.tx_spendable_age
    }

    /// The `BlockHeader.major_version` this rule set admits (CEN-B1).
    ///
    /// A **parameter**, not the identity: it equals
    /// `RuleSetId::GENESIS.to_raw()` today because one rule set is issued,
    /// and nothing here reads one as the other (`CHAIN_RULES_CRATE.md` §4.2,
    /// ruling Q5). The header's other version byte is not a parameter: it
    /// is `shekyl_wire::block::HEADER_MINOR_VERSION` under every rule set
    /// (CEN-B2).
    #[must_use]
    pub const fn header_major_version(&self) -> u8 {
        self.header_major_version
    }
}

impl fmt::Debug for RuleSet {
    // The row list is 153 names long; a failing assertion wants the count.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleSet")
            .field("id", &self.id)
            .field(
                "enforced",
                &format_args!(
                    "{} of {} rows (per-block; held, at-open and by-construction rows excluded)",
                    self.enforced().count(),
                    CenRow::ALL.len()
                ),
            )
            .field("header_major_version", &self.header_major_version)
            .field("difficulty", &self.difficulty)
            .field("mined_money_unlock_window", &self.mined_money_unlock_window)
            .field("reorg_cap", &self.reorg_cap)
            .field("tx_spendable_age", &self.tx_spendable_age)
            .field("settlement_schedule", &self.settlement_schedule)
            .finish()
    }
}

/// Height → rule set, per network.
///
/// A schedule always names the rule set in force at [`BlockHeight::ZERO`];
/// later activations are `steps`, strictly ascending by height, each in
/// force from its height until the next. Both properties hold by
/// construction: `genesis` is not optional, there is no public constructor,
/// and every schedule this module defines is `const`-asserted
/// `well_formed` — a step at `ZERO` (shadowing `genesis`), a step out of
/// order, or a step naming an unissued rule set is a compile error, not a
/// height at which `rules_at` has no answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleSchedule {
    /// In force from `BlockHeight::ZERO` until the first step.
    genesis: RuleSetId,
    /// Later activations, `(from, rules)`: `rules` is in force at every
    /// height `>= from` until the next step's `from`.
    steps: &'static [(BlockHeight, RuleSetId)],
}

impl RuleSchedule {
    /// The identity schedule: the genesis rules at every height. What the
    /// shipped one-entry hardfork table means.
    const IDENTITY: Self = Self {
        genesis: RuleSetId::GENESIS,
        steps: &[],
    };

    /// Mainnet's schedule.
    const MAINNET: Self = Self::IDENTITY;
    /// Testnet's schedule.
    const TESTNET: Self = Self::IDENTITY;
    /// Stagenet's schedule.
    const STAGENET: Self = Self::IDENTITY;

    /// The schedule for `network`. Three values, one lookup: nettype selects
    /// data, never control flow (rule 71).
    #[must_use]
    pub const fn for_network(network: Network) -> Self {
        match network {
            Network::Mainnet => Self::MAINNET,
            Network::Testnet => Self::TESTNET,
            Network::Stagenet => Self::STAGENET,
        }
    }

    /// The rule set in force at `height`: the last step at or below it, or
    /// `genesis` when there is none.
    #[must_use]
    pub fn rules_at(&self, height: BlockHeight) -> RuleSetId {
        self.steps
            .iter()
            .take_while(|(from, _)| *from <= height)
            .last()
            .map_or(self.genesis, |(_, rules)| *rules)
    }
}

/// Whether `id` names a rule set in [`RuleSet::ISSUED`]. `const` so a
/// schedule can be checked at compile time.
const fn issued(id: RuleSetId) -> bool {
    let mut i = 0;
    while i < RuleSet::ISSUED.len() {
        if RuleSet::ISSUED[i].id.to_raw() == id.to_raw() {
            return true;
        }
        i += 1;
    }
    false
}

/// The schedule invariant: `genesis` and every step's rule set are issued;
/// steps are strictly ascending by height and none is at `ZERO`, where it
/// would shadow `genesis` and make that field a lie.
const fn well_formed(schedule: &RuleSchedule) -> bool {
    if !issued(schedule.genesis) {
        return false;
    }
    let mut i = 0;
    while i < schedule.steps.len() {
        let (from, rules) = schedule.steps[i];
        if from.is_zero() || !issued(rules) {
            return false;
        }
        if i > 0 && from.to_raw() <= schedule.steps[i - 1].0.to_raw() {
            return false;
        }
        i += 1;
    }
    true
}

// Every schedule `for_network` can return is well formed, at compile time.
const _: () = {
    assert!(well_formed(&RuleSchedule::MAINNET));
    assert!(well_formed(&RuleSchedule::TESTNET));
    assert!(well_formed(&RuleSchedule::STAGENET));
};

/// Identifies a relay/pool admission policy.
///
/// Its own space. There is no conversion to or from [`RuleSetId`] in either
/// direction, ever — a policy id arriving where a rule-set id is expected is
/// proximity promotion, and the type refuses it:
///
/// ```compile_fail
/// # use shekyl_chain_rules::{AdmissionPolicyId, RuleSetId};
/// let _: RuleSetId = AdmissionPolicyId::GENESIS.into();
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AdmissionPolicyId(u8);

impl AdmissionPolicyId {
    /// The admission policy in force from genesis.
    pub const GENESIS: Self = Self(1);
}

/// Relay/pool admission policy — the policy-flagged census rows
/// ([`crate::PolicyRow`]) as an input, separate from [`RuleSet`] by type so
/// a consensus verdict cannot depend on it.
///
/// Consumer: DRS-E5 (`PoolView`, `PolicyCoverage`). Its parameters populate
/// there; increment 1 stages the identity only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionPolicy {
    id: AdmissionPolicyId,
}

impl AdmissionPolicy {
    /// The genesis admission policy.
    pub const GENESIS: Self = Self {
        id: AdmissionPolicyId::GENESIS,
    };

    /// This policy's id.
    #[must_use]
    pub const fn id(&self) -> AdmissionPolicyId {
        self.id
    }
}

// Declared here rather than in `lib.rs` because the schedule tests build
// multi-step fixtures against the private fields.
#[cfg(test)]
#[path = "rule_set_tests.rs"]
mod rule_set_tests;
