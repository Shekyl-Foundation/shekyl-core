// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a store's rows were written under (DRS-E1 increment 2).
//!
//! # Session intent versus file history
//!
//! [`ApplyPolicy`] is what **this run**
//! intends: which archival applies it will skip. It says nothing about the
//! rows already in the file. Increment 1 conflated the two and had to
//! invent `ApplyPolicy::Unknown` for every reopen — fail-closed, but it
//! meant a file's own history was unknowable from the file, so no reopen
//! could ever be parity evidence.
//!
//! [`Provenance`] is the file's answer: the union of every stubbed set any
//! **committed** batch was begun under, persisted in the `apply_policy`
//! cell and widened in the same transaction as the rows it describes. A
//! store created under [`ApplyPolicy::Full`] starts [`Provenance::FULL`];
//! one created under a stub is sealed with that stub already recorded,
//! since it has been written under it from its first byte. A stubbed
//! session's commit taints it; nothing untaints it short of a rebuild.
//! Reopen therefore reads the record instead of guessing, and `Unknown`
//! has no reason to exist.
//!
//! # What it vouches for
//!
//! Only [`FULL`](Provenance::FULL) is parity evidence. That is the §7.1.1
//! hazard closed at the file: a green produced over a file that ever took
//! a stubbed commit carries the stamp, so it cannot be mistaken for
//! parity no matter which session produced it.

use crate::apply_policy::ApplyPolicy;
use crate::family_set::FamilySet;

/// The archival families some committed batch over this file skipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Provenance {
    stubbed: FamilySet,
}

impl Provenance {
    /// No committed batch ever skipped an apply. The only provenance a
    /// parity claim may cite.
    pub const FULL: Self = Self {
        stubbed: FamilySet::EMPTY,
    };

    /// A provenance whose skipped set is exactly `stubbed`.
    #[must_use]
    pub const fn of(stubbed: FamilySet) -> Self {
        Self { stubbed }
    }

    /// The families some committed batch skipped.
    #[must_use]
    pub const fn stubbed(self) -> FamilySet {
        self.stubbed
    }

    /// Whether a comparator result over this file may be cited as parity
    /// evidence, or archived under §8.1.
    #[must_use]
    pub const fn is_parity_evidence(self) -> bool {
        self.stubbed.is_empty()
    }

    /// This provenance after a batch begun under `policy` commits.
    ///
    /// Monotone: the result contains `self`. A `Full` session leaves it
    /// unchanged; a stubbed one adds its set.
    #[must_use]
    pub const fn widened_by(self, policy: ApplyPolicy) -> Self {
        Self {
            stubbed: self.stubbed.union(policy.stubbed_set()),
        }
    }

    /// A short tag for stamping artifacts.
    ///
    /// `apply-policy=full`, or `apply-policy=STUBBED[<tables>]
    /// NOT-PARITY-EVIDENCE` with the skipped tables in macro order. The
    /// key spelling is kept from increment 1 so existing artifact readers
    /// find it.
    #[must_use]
    pub fn artifact_stamp(self) -> String {
        if self.is_parity_evidence() {
            "apply-policy=full".to_owned()
        } else {
            format!("apply-policy=STUBBED[{}] NOT-PARITY-EVIDENCE", self.stubbed)
        }
    }
}

impl core::fmt::Display for Provenance {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.artifact_stamp())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply_policy::ArchivalFamily;

    #[test]
    fn a_fresh_file_is_full_and_only_full_is_evidence() {
        assert_eq!(Provenance::default(), Provenance::FULL);
        assert!(Provenance::FULL.is_parity_evidence());
        assert_eq!(Provenance::FULL.artifact_stamp(), "apply-policy=full");
        let tainted = Provenance::of(FamilySet::of(&[ArchivalFamily::Bond]));
        assert!(!tainted.is_parity_evidence());
    }

    #[test]
    fn widening_is_monotone_and_full_sessions_change_nothing() {
        let bond = ApplyPolicy::stubbed(&[ArchivalFamily::Bond]).expect("non-empty");
        let slash = ApplyPolicy::stubbed(&[ArchivalFamily::SlashLog]).expect("non-empty");
        let p = Provenance::FULL.widened_by(bond);
        assert_eq!(p.stubbed(), FamilySet::of(&[ArchivalFamily::Bond]));
        let p = p.widened_by(ApplyPolicy::Full);
        assert_eq!(
            p.stubbed(),
            FamilySet::of(&[ArchivalFamily::Bond]),
            "Full never narrows"
        );
        let p = p.widened_by(slash).widened_by(bond);
        assert_eq!(
            p.stubbed(),
            FamilySet::of(&[ArchivalFamily::Bond, ArchivalFamily::SlashLog])
        );
        assert!(!p.is_parity_evidence());
    }

    #[test]
    fn a_stubbed_stamp_names_the_tables_once_in_macro_order() {
        let s = Provenance::of(FamilySet::of(&[
            ArchivalFamily::SlashLog,
            ArchivalFamily::Bond,
            ArchivalFamily::Bond,
        ]))
        .artifact_stamp();
        assert_eq!(
            s,
            "apply-policy=STUBBED[archival_bond,archival_slash_log] NOT-PARITY-EVIDENCE"
        );
        assert_eq!(s.matches("archival_bond").count(), 1);
    }
}
