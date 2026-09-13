// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Which archival apply paths a store run actually exercised (DRS-E1,
//! §7.1.1 sufficiency).
//!
//! # Why this is on the critical path and not a test convenience
//!
//! §7.1.1 states the hazard it exists to prevent: *"a backend can omit all
//! apply/revert hooks and still pass core digests."* Three controls get
//! proposed against that, and only one of them has **redb's apply** as its
//! subject:
//!
//! | Control | Subject | Reaches the hazard |
//! |---|---|---|
//! | Coverage assertion | the corpus, against LMDB | no — no redb in it |
//! | Necessity (corpus minus family X ⇒ diff still green) | the corpus, against the diff | no — backend held at `Full` |
//! | **Sufficiency** (family X's apply stubbed ⇒ diff **red**) | **redb's apply** | **yes** |
//!
//! Neither of the first two **varies redb**, so neither can detect redb
//! omitting a hook whichever colour it goes. They are preconditions, not
//! weaker versions: a corpus that never reaches a family makes every later
//! statement about that family vacuous.
//!
//! The consequence is the reason this module lands early. **No archival
//! family's parity can be claimed from a diff alone** — a green is
//! uninterpretable without knowing the apply paths ran. So the policy is
//! recorded on every artifact the comparator emits, and a green published
//! before the stamp exists is precisely the artifact that gets cited as
//! parity later. That artifact has to be impossible to produce, not
//! discouraged.
//!
//! # A runtime value, deliberately not a cargo feature
//!
//! A `#[cfg(feature = …)]` switch compiles the store **differently** under
//! test, so a red obtained that way is evidence about a differently-compiled
//! store. One compilation and one dispatch path means the red comes from the
//! shipping code declining to write. `#[cfg(test)]` fails for a second
//! reason: the forcing corpus runs outside this crate and cannot see
//! test-only internals.
//!
//! Constructing a stubbed policy is as explicit as constructing
//! [`redb::Durability::None`], which is likewise always available. The guard
//! that matters is not concealment but the **stamp**.

/// One archival family — an `archival_*` table in `SHEKYL_LMDB_TABLES`.
///
/// Seventeen, matching the X-macro exactly; `check_lmdb_schema_coverage.py`
/// pins the name set so a table added to the C++ without a variant here
/// fails rather than silently falling outside every policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ArchivalFamily {
    /// `archival_serve_credit`
    ServeCredit,
    /// `archival_settlement` — apply is unforceable (no production caller)
    /// and its revert is vacuous over an unwritten table. Named exclusion.
    Settlement,
    /// `archival_attestation_witness`
    AttestationWitness,
    /// `archival_alt_attestation_witness`
    AltAttestationWitness,
    /// `archival_bond`
    Bond,
    /// `archival_shard_segment`
    ShardSegment,
    /// `archival_slash_applied`
    SlashApplied,
    /// `archival_slash_log`
    SlashLog,
    /// `archival_emission_claim_log`
    EmissionClaimLog,
    /// `archival_bond_unbond_log`
    BondUnbondLog,
    /// `archival_bond_holdings_update_log`
    BondHoldingsUpdateLog,
    /// `archival_bond_rebond_log`
    BondRebondLog,
    /// `archival_r_market`
    RMarket,
    /// `archival_sigma_work`
    SigmaWork,
    /// `archival_epoch_close_log`
    EpochCloseLog,
    /// `archival_budget_accrual`
    BudgetAccrual,
    /// `archival_budget`
    Budget,
}

impl ArchivalFamily {
    /// Every family, in X-macro order.
    pub const ALL: [Self; 17] = [
        Self::ServeCredit,
        Self::Settlement,
        Self::AttestationWitness,
        Self::AltAttestationWitness,
        Self::Bond,
        Self::ShardSegment,
        Self::SlashApplied,
        Self::SlashLog,
        Self::EmissionClaimLog,
        Self::BondUnbondLog,
        Self::BondHoldingsUpdateLog,
        Self::BondRebondLog,
        Self::RMarket,
        Self::SigmaWork,
        Self::EpochCloseLog,
        Self::BudgetAccrual,
        Self::Budget,
    ];

    /// The LMDB table name this family owns.
    #[must_use]
    pub const fn table(self) -> &'static str {
        match self {
            Self::ServeCredit => "archival_serve_credit",
            Self::Settlement => "archival_settlement",
            Self::AttestationWitness => "archival_attestation_witness",
            Self::AltAttestationWitness => "archival_alt_attestation_witness",
            Self::Bond => "archival_bond",
            Self::ShardSegment => "archival_shard_segment",
            Self::SlashApplied => "archival_slash_applied",
            Self::SlashLog => "archival_slash_log",
            Self::EmissionClaimLog => "archival_emission_claim_log",
            Self::BondUnbondLog => "archival_bond_unbond_log",
            Self::BondHoldingsUpdateLog => "archival_bond_holdings_update_log",
            Self::BondRebondLog => "archival_bond_rebond_log",
            Self::RMarket => "archival_r_market",
            Self::SigmaWork => "archival_sigma_work",
            Self::EpochCloseLog => "archival_epoch_close_log",
            Self::BudgetAccrual => "archival_budget_accrual",
            Self::Budget => "archival_budget",
        }
    }
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
    /// red. Used by §7.1.1's sufficiency control and by nothing else.
    StubbedFamilies(&'static [ArchivalFamily]),
}

impl ApplyPolicy {
    /// Whether a comparator result under this policy may be cited as parity
    /// evidence, or archived under §8.1.
    ///
    /// This is the whole point of the type: not that a stubbed run is hard
    /// to produce, but that its output cannot be mistaken for the other
    /// kind.
    #[must_use]
    pub const fn is_parity_evidence(self) -> bool {
        matches!(self, Self::Full)
    }

    /// Whether `family`'s apply runs under this policy.
    ///
    /// **No dispatch site consumes this yet, and that is deliberate:**
    /// §7.1.1 bars implementing archival apply in this crate until the
    /// extraction bar is discharged. The type and the stamp land first so
    /// that the first archival green is already conditional — a green
    /// published before the stamp exists is the artifact the stamp was
    /// designed to prevent, arriving one release too late.
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
        assert!(!ApplyPolicy::StubbedFamilies(&[ArchivalFamily::Bond]).is_parity_evidence());
    }

    #[test]
    fn a_stubbed_stamp_says_so_in_the_artifact() {
        // The guard is not concealment -- constructing a stubbed policy is
        // as easy as Durability::None -- it is that the OUTPUT cannot be
        // mistaken for a parity run.
        let s = ApplyPolicy::StubbedFamilies(&[ArchivalFamily::SlashLog]).artifact_stamp();
        assert!(s.contains("NOT-PARITY-EVIDENCE"), "{s}");
        assert!(s.contains("archival_slash_log"), "{s}");
        assert!(!ApplyPolicy::Full.artifact_stamp().contains("NOT-PARITY"));
    }

    #[test]
    fn stubbing_one_family_leaves_the_others_running() {
        let p = ApplyPolicy::StubbedFamilies(&[ArchivalFamily::Bond]);
        assert!(!p.applies(ArchivalFamily::Bond));
        for f in ArchivalFamily::ALL {
            if f != ArchivalFamily::Bond {
                assert!(p.applies(f), "{f:?} should still apply");
            }
        }
    }

    #[test]
    fn every_family_has_a_distinct_archival_table_name() {
        let names: Vec<&str> = ArchivalFamily::ALL.iter().map(|f| f.table()).collect();
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(
            names.len(),
            unique.len(),
            "duplicate table name across families"
        );
        assert_eq!(ArchivalFamily::ALL.len(), 17);
        assert!(
            names.iter().all(|n| n.starts_with("archival_")),
            "{names:?}"
        );
    }
}
