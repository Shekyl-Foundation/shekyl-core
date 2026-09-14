// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Which archival apply paths a store run actually exercised (DRS-E1,
//! §7.1.1 sufficiency).
//!
//! # Why this is on the critical path and not a test convenience
//!
//! §7.1.1: *"a backend can omit all apply/revert hooks and still pass
//! core digests."* Of the three controls proposed against that, only
//! sufficiency (family X stubbed ⇒ diff **red**) has **redb's apply** as
//! its subject. A green is uninterpretable without knowing the apply
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
//! The family list is **one** macro invocation. [`ArchivalFamily::ALL`]
//! and [`ArchivalFamily::table`] cannot drift from each other;
//! `check_lmdb_schema_coverage.py` pins the table names against the
//! X-macro.

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
    /// `archival_bond_rebond_log`
    BondRebondLog => "archival_bond_rebond_log",
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
/// [`Full`](Self::Full) is the only policy under which a comparator result
/// is parity evidence. Anything else is a deliberately weakened run whose
/// output exists to prove the comparator **can** fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ApplyPolicy {
    /// Every archival apply runs. The only policy a parity claim may cite.
    #[default]
    Full,
    /// The named families' applies are skipped, so the comparator must go
    /// red. Construct with [`Self::stubbed`]; an empty list is refused.
    StubbedFamilies(&'static [ArchivalFamily]),
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
    pub const fn stubbed(families: &'static [ArchivalFamily]) -> Result<Self, EmptyApplyStub> {
        let policy = Self::StubbedFamilies(families);
        match policy.reject_empty_stub() {
            Ok(()) => Ok(policy),
            Err(e) => Err(e),
        }
    }

    /// `Err` iff this is a stub of no families.
    pub const fn reject_empty_stub(self) -> Result<(), EmptyApplyStub> {
        match self {
            Self::StubbedFamilies([]) => Err(EmptyApplyStub),
            Self::Full | Self::StubbedFamilies(_) => Ok(()),
        }
    }

    /// Whether a comparator result under this policy may be cited as parity
    /// evidence, or archived under §8.1.
    #[must_use]
    pub const fn is_parity_evidence(self) -> bool {
        matches!(self, Self::Full)
    }

    /// Whether `family`'s apply runs under this policy.
    ///
    /// Consumed by [`WriteBatch::open_table`](crate::store::WriteBatch::open_table).
    #[must_use]
    pub fn applies(self, family: ArchivalFamily) -> bool {
        match self {
            Self::Full => true,
            Self::StubbedFamilies(list) => !list.contains(&family),
        }
    }

    /// A short tag for stamping artifacts.
    #[must_use]
    pub fn artifact_stamp(self) -> String {
        match self {
            Self::Full => "apply-policy=full".to_owned(),
            Self::StubbedFamilies(list) => {
                let mut names: Vec<&str> = list.iter().map(|f| f.table()).collect();
                names.sort_unstable();
                names.dedup();
                format!(
                    "apply-policy=STUBBED[{}] NOT-PARITY-EVIDENCE",
                    names.join(",")
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_full_and_only_full_is_parity_evidence() {
        assert_eq!(ApplyPolicy::default(), ApplyPolicy::Full);
        assert!(ApplyPolicy::Full.is_parity_evidence());
        let stubbed = ApplyPolicy::stubbed(&[ArchivalFamily::Bond]).expect("non-empty");
        assert!(!stubbed.is_parity_evidence());
    }

    #[test]
    fn an_empty_stub_is_refused() {
        assert_eq!(ApplyPolicy::stubbed(&[]), Err(EmptyApplyStub));
        assert!(ApplyPolicy::StubbedFamilies(&[])
            .reject_empty_stub()
            .is_err());
    }

    #[test]
    fn a_stubbed_stamp_says_so_in_the_artifact() {
        let s = ApplyPolicy::stubbed(&[ArchivalFamily::SlashLog])
            .expect("non-empty")
            .artifact_stamp();
        assert!(s.contains("NOT-PARITY-EVIDENCE"), "{s}");
        assert!(s.contains("archival_slash_log"), "{s}");
        assert!(!ApplyPolicy::Full.artifact_stamp().contains("NOT-PARITY"));
    }

    #[test]
    fn stubbing_one_family_leaves_the_others_running() {
        let p = ApplyPolicy::stubbed(&[ArchivalFamily::Bond]).expect("non-empty");
        assert!(!p.applies(ArchivalFamily::Bond));
        for f in ArchivalFamily::ALL {
            if f != ArchivalFamily::Bond {
                assert!(p.applies(f), "{f:?} should still apply");
            }
        }
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

    #[test]
    fn a_duplicate_in_the_stub_list_stamps_once() {
        let s = ApplyPolicy::stubbed(&[ArchivalFamily::Bond, ArchivalFamily::Bond])
            .expect("non-empty")
            .artifact_stamp();
        assert_eq!(s.matches("archival_bond").count(), 1, "{s}");
    }
}
