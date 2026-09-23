// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;

#[test]
fn empty_evaluated_nothing_and_is_never_complete() {
    let empty = RuleCoverage::EMPTY;
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert_eq!(empty.iter().count(), 0);
    assert!(CenRow::ALL.iter().all(|row| !empty.contains(*row)));
    // Not complete even for GENESIS, whose enforced set is the whole census;
    // the scaffold verdict is never parity evidence.
    assert!(!empty.is_complete_for(&RuleSet::GENESIS));
    assert_eq!(format!("{empty:?}"), "Coverage{}");
}

#[test]
fn insert_records_exactly_the_row_and_iter_yields_census_order() {
    let mut coverage = RuleCoverage::EMPTY;
    // Rows from three different words of the bitset, inserted out of order.
    let picked = [CenRow::ALL[130], CenRow::A1, CenRow::ALL[70]];
    for row in picked {
        coverage.insert(row);
    }
    assert_eq!(coverage.len(), 3);
    assert!(!coverage.is_empty());
    for row in picked {
        assert!(coverage.contains(row));
    }
    let others = CenRow::ALL.iter().filter(|row| !picked.contains(row));
    for row in others {
        assert!(!coverage.contains(*row), "{row} leaked in");
    }
    // Iteration order is census order, not insertion order.
    let mut expected = picked.to_vec();
    expected.sort();
    assert_eq!(coverage.iter().collect::<Vec<_>>(), expected);
}

#[test]
fn insert_is_idempotent() {
    let mut coverage = RuleCoverage::EMPTY;
    coverage.insert(CenRow::B5);
    coverage.insert(CenRow::B5);
    assert_eq!(coverage.len(), 1);
}

#[test]
fn union_folds_the_other_side_in() {
    let mut left = RuleCoverage::EMPTY;
    left.insert(CenRow::A1);
    left.insert(CenRow::I1);
    let mut right = RuleCoverage::EMPTY;
    right.insert(CenRow::I1);
    right.insert(CenRow::M8);
    left.union(&right);
    assert_eq!(
        left.iter().collect::<Vec<_>>(),
        [CenRow::A1, CenRow::I1, CenRow::M8]
    );
    // `right` is unchanged.
    assert_eq!(right.iter().collect::<Vec<_>>(), [CenRow::I1, CenRow::M8]);
}

#[test]
fn contains_all_is_the_mint_predicate() {
    let empty = RuleCoverage::EMPTY;
    assert!(empty.contains_all([]));
    assert!(!empty.contains_all([CenRow::A1]));
    let mut one = RuleCoverage::EMPTY;
    one.insert(CenRow::A1);
    assert!(one.contains_all([CenRow::A1]));
    assert!(!one.contains_all([CenRow::A1, CenRow::A2]));
}

#[test]
fn covers_landed_requires_exactly_the_implemented_rows() {
    // Was `covers_landed_is_vacuous_while_every_row_is_pending` in the
    // scaffold (DRS-D12). Slice 1 flipped rows, so empty coverage no longer
    // covers what has landed — a `validate` that forgot a landed rule would
    // reach the mint with this false, and the mint panics (G9's runtime
    // half). Coverage of exactly the implemented rows suffices; pending rows
    // are not required.
    assert!(!RuleCoverage::EMPTY.covers_landed(&RuleSet::GENESIS));
    let mut landed = RuleCoverage::EMPTY;
    for row in CenRow::ALL
        .iter()
        .copied()
        .filter(|row| row.status() == crate::census::RowStatus::Implemented)
    {
        landed.insert(row);
    }
    assert!(!landed.is_empty(), "slice 1 flipped at least one row");
    assert!(landed.covers_landed(&RuleSet::GENESIS));
    assert!(!landed.is_complete_for(&RuleSet::GENESIS));
    // One implemented row missing is enough to refuse the mint.
    let mut short = landed;
    short.words = [0; 4];
    for row in landed.iter().skip(1) {
        short.insert(row);
    }
    assert!(!short.covers_landed(&RuleSet::GENESIS));
}

#[test]
fn complete_means_every_validator_enforced_row_and_nothing_less() {
    use crate::census::RowStatus;
    let held = CenRow::ALL
        .iter()
        .filter(|row| row.status() == RowStatus::HeldByCxx)
        .count();
    let at_open = CenRow::ALL
        .iter()
        .filter(|row| row.status() == RowStatus::EnforcedAt)
        .count();
    let by_construction = CenRow::ALL
        .iter()
        .filter(|row| row.status() == RowStatus::ByConstruction)
        .count();
    let mut coverage = RuleCoverage::EMPTY;
    for row in RuleSet::GENESIS.enforced() {
        coverage.insert(row);
    }
    assert!(coverage.is_complete_for(&RuleSet::GENESIS));
    // Complete is `enforced − held − at-open − by-construction`: the rows
    // the C++ ingest driver holds (A1, A4 after slice 1) are not the
    // validator's to evaluate; the rows this crate enforces at another site
    // (E5 at writer open, slice 3) and the rows that hold by construction
    // (F2, F8, F19, slice 4) can never be in a per-block coverage. The
    // census denominator itself moves for none of them.
    assert_eq!(
        coverage.len(),
        CenRow::ALL.len() - held - at_open - by_construction
    );
    assert_eq!(held, 2, "slice 1 holds exactly A1 and A4");
    assert_eq!(at_open, 1, "slice 3 enforces exactly E5 at open");
    assert_eq!(
        by_construction, 4,
        "slice 4: F2, F8, F19, F21 hold by construction"
    );
    for row in [
        CenRow::A1,
        CenRow::A4,
        CenRow::E5,
        CenRow::F2,
        CenRow::F8,
        CenRow::F19,
        CenRow::F21,
    ] {
        assert!(!coverage.contains(row));
        assert!(!RuleSet::GENESIS.enforced().any(|r| r == row));
    }
    // Recording a held row anyway does not make coverage more complete and
    // does not make it less — it is outside the denominator.
    coverage.insert(CenRow::A1);
    assert!(coverage.is_complete_for(&RuleSet::GENESIS));

    // Drop one validator-enforced row: no longer complete.
    let mut short = RuleCoverage::EMPTY;
    for row in RuleSet::GENESIS.enforced().skip(1) {
        short.insert(row);
    }
    assert_eq!(
        short.len(),
        CenRow::ALL.len() - held - at_open - by_construction - 1
    );
    assert!(!short.is_complete_for(&RuleSet::GENESIS));
}

#[test]
fn debug_prints_the_register_form() {
    let mut coverage = RuleCoverage::EMPTY;
    coverage.insert(CenRow::D1b);
    coverage.insert(CenRow::A1);
    assert_eq!(format!("{coverage:?}"), "Coverage{CEN-A1, CEN-D1b}");

    let mut policy = PolicyCoverage::EMPTY;
    policy.insert(PolicyRow::M1);
    assert_eq!(format!("{policy:?}"), "Coverage{CEN-M1}");
}

#[test]
fn every_row_of_both_registries_has_a_distinct_slot() {
    // The bitset relies on `index()` being injective within a registry.
    let mut all = RuleCoverage::EMPTY;
    for (n, row) in CenRow::ALL.iter().enumerate() {
        assert_eq!(all.len(), n);
        all.insert(*row);
    }
    assert_eq!(all.len(), CenRow::ALL.len());

    let mut all = PolicyCoverage::EMPTY;
    for (n, row) in PolicyRow::ALL.iter().enumerate() {
        assert_eq!(all.len(), n);
        all.insert(*row);
    }
    assert_eq!(all.len(), PolicyRow::ALL.len());
}
