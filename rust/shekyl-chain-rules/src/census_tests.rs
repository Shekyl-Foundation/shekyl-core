// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Registry tests — what the enums themselves guarantee. The bijection with
//! the census is the Python gate's (`check_chain_rules_coverage.py`) and is
//! deliberately **not** re-tested here: a second census parser would be a
//! second source of truth for the denominator.

use std::collections::BTreeSet;

use crate::census::{CenRow, Flag, PolicyRow, Row, RowStatus};
use crate::rules::header::{B1, B2, B5, B6, B7};
use crate::rules::topology::A2;
use crate::rules::Rule;

/// Every generic property a registry must hold, checked once per `R`.
fn registry_invariants<R: Row>() {
    assert!(
        !R::ALL.is_empty(),
        "{:?}: a registry with no rows is a gate subject, not a registry",
        R::FLAG
    );

    for (position, row) in R::ALL.iter().enumerate() {
        // `index()` is the position in `ALL` — the property the coverage
        // bitset relies on. Bites a hand-edited discriminant or a reordered
        // `ALL` that no longer matches the declaration order.
        assert_eq!(
            usize::from(row.index()),
            position,
            "{row}: index/position drift"
        );

        // The register form: `CEN-` + the variant name, and `Display` is it.
        let s = row.as_str();
        assert!(s.starts_with("CEN-"), "{s}: register form lost its prefix");
        assert_eq!(s, row.to_string());
        assert_eq!(
            format!("{row:?}"),
            &s[4..],
            "{s}: Debug should be the bare variant"
        );
    }

    // Distinct rows, distinct register strings.
    let strings: BTreeSet<&str> = R::ALL.iter().map(|r| r.as_str()).collect();
    assert_eq!(
        strings.len(),
        R::ALL.len(),
        "{:?}: duplicate register string",
        R::FLAG
    );
}

#[test]
fn cen_row_registry_invariants() {
    registry_invariants::<CenRow>();
    assert_eq!(CenRow::FLAG, Flag::Consensus);
    assert_eq!(<CenRow as Row>::FLAG, Flag::Consensus);
}

#[test]
fn policy_row_registry_invariants() {
    registry_invariants::<PolicyRow>();
    assert_eq!(PolicyRow::FLAG, Flag::Policy);
    assert_eq!(<PolicyRow as Row>::FLAG, Flag::Policy);
}

#[test]
fn the_two_registries_are_disjoint() {
    // A row filed in both enums would be counted toward both denominators —
    // the proximity promotion the sibling-enum ruling exists to prevent. The
    // gate holds this against the census; this holds it against the enums.
    let consensus: BTreeSet<&str> = CenRow::ALL.iter().map(|r| r.as_str()).collect();
    let policy: BTreeSet<&str> = PolicyRow::ALL.iter().map(|r| r.as_str()).collect();
    let both: Vec<&&str> = consensus.intersection(&policy).collect();
    assert!(both.is_empty(), "rows in both registries: {both:?}");
}

#[test]
fn the_implemented_rows_are_exactly_the_landed_slices() {
    // Rewritten from `increment_one_registers_no_rule` as that test said it
    // would be: every flip to `implemented(...)` is a visible, reviewed
    // change here rather than a quiet numerator move. Slice 1: the six
    // predicate rows of 4.A/4.B (`CHAIN_RULES_SLICE_1.md` §3). Slice 2: 4.C
    // (`CHAIN_RULES_SLICE_2.md` §2, commit 4), then 4.D by its commits.
    // Slice 3: E1 (E5 is at-open, not here). Slice 4: the 4.F predicates
    // and definitions (`CHAIN_RULES_SLICE_4.md` Q1 (a)); F2/F8/F19/F21 hold
    // by construction and are not `Implemented` either.
    let implemented: Vec<CenRow> = CenRow::ALL
        .iter()
        .copied()
        .filter(|r| r.status() == RowStatus::Implemented)
        .collect();
    assert_eq!(
        implemented,
        [
            CenRow::A2,
            CenRow::B1,
            CenRow::B2,
            CenRow::B5,
            CenRow::B6,
            CenRow::B7,
            CenRow::C1,
            CenRow::C2,
            CenRow::C3,
            CenRow::D1,
            CenRow::D1b,
            CenRow::D2,
            CenRow::D3,
            CenRow::D4,
            CenRow::D6,
            CenRow::D7,
            CenRow::E1,
            CenRow::F1,
            CenRow::F3,
            CenRow::F4,
            CenRow::F5,
            CenRow::F6,
            CenRow::F7,
            CenRow::F9,
            CenRow::F10,
            CenRow::F11,
            CenRow::F13,
            // Slice 7 commit 5: the reward chain (`CHAIN_RULES_SLICE_7.md`
            // §5 row 5) — F14, F14b, F16 here, G12 below.
            CenRow::F14,
            CenRow::F14b,
            CenRow::F15,
            CenRow::F16,
            // Slice 7 commit 9 (wave B): F17 the fee split, F18 the exact
            // payout — with G11/G13 below.
            CenRow::F17,
            CenRow::F18,
            CenRow::F20,
            // Slice 7 commit 7: G1 before the slot loop
            // (`CHAIN_RULES_SLICE_7.md` §5 row 7); G7/G9/G10 below, after it.
            CenRow::G1,
            // Slice 7 commit 6: the body's pairing, a `FormRule`
            // (`CHAIN_RULES_SLICE_7.md` §5 row 6).
            CenRow::G2,
            // Slice 7 commit 4: the two block-weight definitions
            // (`CHAIN_RULES_SLICE_7.md` §5 row 4).
            CenRow::G6,
            CenRow::G6b,
            CenRow::G7,
            CenRow::G9,
            CenRow::G10,
            CenRow::G11,
            CenRow::G12,
            CenRow::G13,
            CenRow::H1,
            CenRow::H3,
            CenRow::H4,
            CenRow::H5,
            CenRow::H6,
            CenRow::H7,
            CenRow::H9,
            CenRow::H10,
            CenRow::H11,
            CenRow::H14,
            CenRow::H15,
            CenRow::H16,
            CenRow::H17,
            CenRow::H18,
            CenRow::H20,
            CenRow::H21,
            CenRow::H22,
            // Slice 6 commit 2: the stateless 4.I rows (`CHAIN_RULES_SLICE_6.md`
            // §5 row 2). The view-bound and verification rows follow.
            CenRow::I1,
            CenRow::I4,
            CenRow::I5,
            CenRow::I6,
            CenRow::I7,
            CenRow::I8,
            CenRow::I9,
            CenRow::I10,
            CenRow::I11,
            CenRow::I12,
            CenRow::I14,
            CenRow::I16,
            CenRow::I17,
            CenRow::I18,
            CenRow::I19,
            CenRow::I20,
            // `SHT-9`'s conformance correction (2026-10-03): the serve
            // credit's pass records against its vins.
            CenRow::J2,
            // Slice 8 row 3: the bond-state rows on a serve-credit vin.
            CenRow::J4,
            CenRow::J5,
            CenRow::J6,
            // Slice 8 row 4: the bond post's key and hint, its JoinMarket
            // coupling, and the key its kind selects.
            CenRow::J11,
            CenRow::J12,
            CenRow::J13,
            // Slice 8 row 5: the post against its record — a join's floor and
            // claim slot, a Release's exit, a Reinstate's open interval.
            CenRow::J14,
            // Slice 8 row 6: a compact join's held shards closed, final,
            // priced and viable at the parent.
            CenRow::J15,
            CenRow::J16,
            CenRow::J18,
            // Slice 8 row 8: the emission statics — the vin's parse, the
            // slot's key, the signable hash and the reward commit set.
            CenRow::J19,
            CenRow::J20,
            // Slice 8 row 9: the emission's reference context (I10–I13's
            // reads, judged as one row in `judge_reference`), the frozen
            // closes gathered per claimed epoch and the verify over them
            // (`judge_emission_claim`).
            CenRow::J21,
            CenRow::J22,
            CenRow::J23,
            CenRow::J24,
            CenRow::J25,
            CenRow::L1,
            // DRS-E4 commit 4: the archival transition on the verdict
            // (`DRS_E4_ARCHIVAL_WRITER.md` §6 row 4); L8 and L9 below.
            CenRow::L7,
        ]
    );
    let by_construction: Vec<CenRow> = CenRow::ALL
        .iter()
        .copied()
        .filter(|r| r.status() == RowStatus::ByConstruction)
        .collect();
    assert_eq!(
        by_construction,
        [
            CenRow::F2,
            CenRow::F8,
            CenRow::F19,
            CenRow::F21,
            CenRow::G3,
            CenRow::G4,
            CenRow::G5,
            CenRow::H2,
            CenRow::H8,
            CenRow::H12,
            CenRow::H13,
            CenRow::H23,
            CenRow::I2,
            CenRow::I3,
            CenRow::L8,
            CenRow::L9,
        ],
        "slice 4 Q4: the wire's version and output tag, the view brand, the epoch parameter; \
         slice 5 Q6: the same version (H2, H13) and tag (H12) for listed transactions, one \
         commitment per output (H8), and a parsed transaction as `tx_form`'s input (H23); \
         slice 6 Q3: the CT type set plus H15 (I2) and the same version a fourth time (I3); \
         slice 7 row 8: every listed body through `tx_form` and `tx_against` with no pool \
         door and no skip (G3, G4), and the full form the only body a block rule sees (G5); \
         DRS-E4 commit 4: the accrual fold (L8) and the slash fold (L9) return the C++'s \
         aborts as `Corrupt` by type"
    );
    assert!(PolicyRow::ALL
        .iter()
        .all(|r| r.status() == RowStatus::Pending));
    // SCW-18's compile-time pin is the check; this is the runtime echo so a
    // swapped `implemented(B2)` under the B1 entry cannot hide behind a
    // matching status list.
    assert_eq!(<A2 as Rule>::ROW, CenRow::A2);
    assert_eq!(<B1 as Rule>::ROW, CenRow::B1);
    assert_eq!(<B2 as Rule>::ROW, CenRow::B2);
    assert_eq!(<B5 as Rule>::ROW, CenRow::B5);
    assert_eq!(<B6 as Rule>::ROW, CenRow::B6);
    assert_eq!(<B7 as Rule>::ROW, CenRow::B7);
}

#[test]
fn suffixed_census_ids_keep_their_suffix() {
    // The six census ids with a letter suffix must survive the `CEN-` strip
    // and the variant naming unchanged — `CEN-D1b` is a different row from
    // `CEN-D1`, and the gate maps by exact string.
    assert_eq!(CenRow::D1b.as_str(), "CEN-D1b");
    assert_eq!(CenRow::F14b.as_str(), "CEN-F14b");
    assert_eq!(CenRow::G6b.as_str(), "CEN-G6b");
    assert_eq!(CenRow::K1a.as_str(), "CEN-K1a");
    assert_eq!(CenRow::K1b.as_str(), "CEN-K1b");
    assert_eq!(CenRow::K5b.as_str(), "CEN-K5b");
    assert_ne!(CenRow::D1b, CenRow::D1);
}

#[test]
fn registries_are_the_expected_size_at_this_increment() {
    // The denominators the design quotes (CHAIN_RULES_CRATE.md §6.3), verified
    // against the census by the gate. Pinned here so a registry edit that
    // changes the count is visible in Rust as well as in the gate's output;
    // when the census moves, both move together in the same PR. 153 → 152
    // on 2026-09-21: CEN-F12 (the dead decomposed-denomination gate) went
    // to bucket 3 and was deleted with its C++ in the same PR (E6 slice 4
    // Q2 (a)). 152 → 153 on 2026-09-23: CEN-I20 (the coinbase extra
    // grammar, TXE-Q6′) minted with its implementation in shekyl-wire —
    // pending here, like I19, until the 4.I slice (slice 6) wires
    // `check_tx_extra_shape` — I19 + I20 in one function; slice 4 (4.F)
    // landed 2026-09-22 without either, as CHAIN_RULES_SLICE_4.md S21 records.
    // 153 → 154 on 2026-09-23: CEN-L16 (the store-evaluated holds-shard
    // predicate, an R8-class placement row minted by S-ARCH's pre-flight,
    // DRS_E1_SARCH.md SAR-2 / SAR-7) — pending here until E4 moves the fold
    // to shekyl-archival-retention and slice 8 judges through it.
    // 154 → 153 on 2026-10-04: CEN-J17 (the `HoldingsUpdate` add / drop
    // arms, a post kind REJECTED 2026-09-20 and deleted by E4's ARW-14) went
    // to bucket 3 (E6 slice 8 Q1 (a)) — a row whose subject is gone does
    // not inflate the denominator.
    assert_eq!(CenRow::ALL.len(), 153);
    assert_eq!(PolicyRow::ALL.len(), 9);
}

#[test]
fn g9_pin_form_accepts_a_generic_rule() {
    // The pin is `use path as _`, not `let _ = path`. A generic 4.I rule
    // (`fn<'id, V: ChainView<'id>>(...)`) must compile under that form;
    // `let _ = generic;` is E0283 (Copilot #753).
    #[allow(dead_code, reason = "existence pin: use generic as _")]
    fn generic<'id, V: crate::view::ChainView<'id>>(_: &V) {}
    #[allow(unused_imports)]
    use generic as _;
}

#[test]
fn rows_are_ordered_by_census_position() {
    // `Ord` derives from the discriminant, so sorting rows sorts them into
    // census order — the order `Coverage::iter` and the gate's `--describe`
    // both emit.
    let mut shuffled = vec![CenRow::M8, CenRow::A1, CenRow::I7, CenRow::D1b];
    shuffled.sort();
    assert_eq!(shuffled, [CenRow::A1, CenRow::D1b, CenRow::I7, CenRow::M8]);
}
