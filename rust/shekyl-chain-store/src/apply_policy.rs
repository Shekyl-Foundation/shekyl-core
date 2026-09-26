// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Which archival apply paths a store run actually exercised (DRS-E1).
//!
//! # Why this is on the critical path and not a test convenience
//!
//! §7.1.1: *"a backend can omit all apply/revert hooks and still pass
//! core digests."* That sentence is the document's. **The three-control
//! taxonomy below is this lane's analysis, not §7.1.1's text** — the
//! document names archival digest coverage or a replacement KAT, and the
//! word "sufficiency" does not appear in it. Of the three controls this
//! lane proposed against that hazard, only sufficiency (family X stubbed
//! ⇒ diff **red**) has **redb's apply** as its subject. A green is uninterpretable without knowing the apply
//! paths ran, so the policy is recorded on every artifact and a green
//! published before the stamp exists is the artifact the stamp exists
//! to prevent.
//!
//! # A runtime value, deliberately not a cargo feature
//!
//! A `#[cfg(feature = …)]` switch compiles the store **differently**
//! under test. One compilation and one dispatch path means the red comes
//! from the shipping code declining to write. Constructing a stubbed
//! policy is as explicit as [`redb::Durability::None`]; the guard is the
//! **stamp**.
//!
//! # Session intent, not file history
//!
//! A policy is what **one run** does. What a *file* has been written under
//! is [`Provenance`](crate::provenance::Provenance): the store persists the
//! union of every committed batch's stubbed set and widens it at commit.
//! The stamp and the parity verdict live there, because a file that ever
//! took a stubbed commit is not parity evidence no matter how the session
//! reading it was configured. Increment 1's `ApplyPolicy::Unknown` — the
//! fail-closed stand-in for a reopen that could not know its history — is
//! gone: the history is in the file.
//!
//! The family list is **one** macro invocation. [`ArchivalFamily::ALL`]
//! and [`ArchivalFamily::table`] cannot drift from each other;
//! `check_lmdb_schema_coverage.py` pins the table names against the
//! X-macro.

use crate::family_set::FamilySet;

/// One archival family — an `archival_*` table in `SHEKYL_LMDB_TABLES`.
///
/// Generated with [`ArchivalFamily::ALL`] from the same rows; adding a
/// family is one line in the macro.
macro_rules! archival_families {
    (
        $(
            $(#[$meta:meta])*
            $variant:ident => $table:literal
        ),+ $(,)?
    ) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum ArchivalFamily {
            $(
                $(#[$meta])*
                $variant,
            )+
        }

        impl ArchivalFamily {
            /// Every family, in the macro's order (X-macro order).
            pub const ALL: [Self; { 0 $(+ { let _ = stringify!($variant); 1 })+ }] = [
                $(Self::$variant,)+
            ];

            /// The LMDB table name this family owns.
            #[must_use]
            pub const fn table(self) -> &'static str {
                match self {
                    $(Self::$variant => $table,)+
                }
            }

            /// Inverse of [`table`](Self::table). `None` for a name that
            /// is not an archival family (chain tables, probe tables).
            #[must_use]
            pub fn from_table(name: &str) -> Option<Self> {
                match name {
                    $($table => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

archival_families! {
    /// `archival_serve_credit`
    ServeCredit => "archival_serve_credit",
    /// `archival_settlement` — apply is unforceable (no production caller)
    /// and its revert is vacuous over an unwritten table. Named exclusion.
    Settlement => "archival_settlement",
    /// `archival_attestation_witness`
    AttestationWitness => "archival_attestation_witness",
    /// `archival_alt_attestation_witness`
    AltAttestationWitness => "archival_alt_attestation_witness",
    /// `archival_bond`
    Bond => "archival_bond",
    /// `archival_shard_segment`
    ShardSegment => "archival_shard_segment",
    /// `archival_slash_applied`
    SlashApplied => "archival_slash_applied",
    /// `archival_slash_log`
    SlashLog => "archival_slash_log",
    /// `archival_emission_claim_log`
    EmissionClaimLog => "archival_emission_claim_log",
    /// `archival_bond_unbond_log`
    BondUnbondLog => "archival_bond_unbond_log",
    /// `archival_bond_holdings_update_log`
    BondHoldingsUpdateLog => "archival_bond_holdings_update_log",
    /// `archival_bond_reinstate_log`
    BondReinstateLog => "archival_bond_reinstate_log",
    /// `archival_r_market`
    RMarket => "archival_r_market",
    /// `archival_sigma_work`
    SigmaWork => "archival_sigma_work",
    /// `archival_epoch_close_log`
    EpochCloseLog => "archival_epoch_close_log",
    /// `archival_budget_accrual`
    BudgetAccrual => "archival_budget_accrual",
    /// `archival_budget`
    Budget => "archival_budget",
}

/// Which archival applies a store run is permitted to perform.
///
/// A session value: bound at [`ChainStore`](crate::store::ChainStore)
/// construction so a run cannot change its own provenance halfway
/// through, and folded into the file's
/// [`Provenance`](crate::provenance::Provenance) when a batch commits.
/// Anything but [`Full`](Self::Full) is a deliberately weakened run whose
/// output exists to prove the comparator **can** fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ApplyPolicy {
    /// Every archival apply runs.
    #[default]
    Full,
    /// The named families' applies are skipped, so the comparator must go
    /// red. Construct with [`Self::stubbed`]; an empty set is refused.
    StubbedFamilies(FamilySet),
}

/// [`ApplyPolicy::stubbed`] was given an empty list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmptyApplyStub;

impl ApplyPolicy {
    /// Stub the named families. Refuses an empty list: that would be
    /// [`Full`](Self::Full) wearing a non-parity stamp.
    ///
    /// # Errors
    ///
    /// [`EmptyApplyStub`] if `families` is empty.
    pub const fn stubbed(families: &[ArchivalFamily]) -> Result<Self, EmptyApplyStub> {
        let policy = Self::StubbedFamilies(FamilySet::of(families));
        match policy.reject_empty_stub() {
            Ok(()) => Ok(policy),
            Err(e) => Err(e),
        }
    }

    /// `Err` iff this is a stub of no families.
    pub const fn reject_empty_stub(self) -> Result<(), EmptyApplyStub> {
        match self {
            Self::StubbedFamilies(set) if set.is_empty() => Err(EmptyApplyStub),
            Self::Full | Self::StubbedFamilies(_) => Ok(()),
        }
    }

    /// The families this policy skips. Empty for [`Full`](Self::Full).
    #[must_use]
    pub const fn stubbed_set(self) -> FamilySet {
        match self {
            Self::Full => FamilySet::EMPTY,
            Self::StubbedFamilies(set) => set,
        }
    }

    /// Whether `family`'s apply runs under this policy.
    ///
    /// Consumed by [`WriteBatch::open_insert_table`](crate::store::WriteBatch::open_insert_table)
    /// and [`WriteBatch::open_upsert_table`](crate::store::WriteBatch::open_upsert_table).
    #[must_use]
    pub const fn applies(self, family: ArchivalFamily) -> bool {
        !self.stubbed_set().contains(family)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_full_and_full_skips_nothing() {
        assert_eq!(ApplyPolicy::default(), ApplyPolicy::Full);
        assert!(ApplyPolicy::Full.stubbed_set().is_empty());
        for f in ArchivalFamily::ALL {
            assert!(ApplyPolicy::Full.applies(f), "{f:?}");
        }
    }

    #[test]
    fn an_empty_stub_is_refused() {
        assert_eq!(ApplyPolicy::stubbed(&[]), Err(EmptyApplyStub));
        assert!(ApplyPolicy::StubbedFamilies(FamilySet::EMPTY)
            .reject_empty_stub()
            .is_err());
        assert!(ApplyPolicy::Full.reject_empty_stub().is_ok());
    }

    #[test]
    fn stubbing_one_family_leaves_the_others_running() {
        let p = ApplyPolicy::stubbed(&[ArchivalFamily::Bond]).expect("non-empty");
        assert!(!p.applies(ArchivalFamily::Bond));
        assert_eq!(p.stubbed_set(), FamilySet::of(&[ArchivalFamily::Bond]));
        for f in ArchivalFamily::ALL {
            if f != ArchivalFamily::Bond {
                assert!(p.applies(f), "{f:?} should still apply");
            }
        }
    }

    #[test]
    fn a_policy_can_be_built_in_a_const() {
        const P: ApplyPolicy = match ApplyPolicy::stubbed(&[ArchivalFamily::SlashLog]) {
            Ok(p) => p,
            Err(EmptyApplyStub) => panic!("non-empty"),
        };
        assert!(!P.applies(ArchivalFamily::SlashLog));
    }

    #[test]
    fn table_and_from_table_are_inverses_over_all() {
        let names: Vec<&str> = ArchivalFamily::ALL.iter().map(|f| f.table()).collect();
        let unique: std::collections::HashSet<_> = names.iter().copied().collect();
        assert_eq!(names.len(), unique.len(), "duplicate table name");
        assert!(
            names.iter().all(|n| n.starts_with("archival_")),
            "{names:?}"
        );
        for family in ArchivalFamily::ALL {
            assert_eq!(ArchivalFamily::from_table(family.table()), Some(family));
        }
        assert_eq!(ArchivalFamily::from_table("blocks"), None);
        assert_eq!(ArchivalFamily::from_table("archival_r2_market"), None);
    }
}
