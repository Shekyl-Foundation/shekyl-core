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
use shekyl_types::BlockHeight;

use crate::census::CenRow;

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
/// id to one, and there is no way to build one that was not issued.
/// Parameters populate as rules land. The first is `enforced` — the census
/// rows this rule set holds a block to, which is also the denominator a
/// verdict's coverage is measured complete against. The second is
/// `header_major_version` — the `BlockHeader.major_version` this rule set
/// admits (CEN-B1; the vote floor of CEN-B2), landed with slice 1.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RuleSet {
    id: RuleSetId,
    enforced: &'static [CenRow],
    header_major_version: u8,
}

impl RuleSet {
    /// The genesis rule set: every consensus row of the census; admits
    /// header version `1` (`hardforks.cpp:35–50`, the one-entry table).
    pub const GENESIS: Self = Self {
        id: RuleSetId::GENESIS,
        enforced: CenRow::ALL,
        header_major_version: 1,
    };

    /// Every rule set a schedule may name, in id order. A schedule step that
    /// names an id absent from here does not compile (`well_formed`).
    const ISSUED: &'static [Self] = &[Self::GENESIS];

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

    /// The consensus rows this rule set enforces, in census order.
    pub fn enforced(&self) -> impl Iterator<Item = CenRow> + '_ {
        self.enforced.iter().copied()
    }

    /// The `BlockHeader.major_version` this rule set admits (CEN-B1), and
    /// the floor a header's version vote must reach (CEN-B2).
    ///
    /// A **parameter**, not the identity: it equals
    /// `RuleSetId::GENESIS.to_raw()` today because the shipped hardfork table
    /// has one entry, and nothing here reads one as the other
    /// (`CHAIN_RULES_CRATE.md` §4.2, ruling Q5).
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
                &format_args!("{} of {} rows", self.enforced.len(), CenRow::ALL.len()),
            )
            .field("header_major_version", &self.header_major_version)
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
