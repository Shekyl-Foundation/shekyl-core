// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The census registry: every **enforced** row of
//! `docs/design/CONSENSUS_RULE_CENSUS.md` §4 as a typed identity, partitioned
//! **by type** into the two census flags.
//!
//! [`CenRow`] enumerates the consensus-flagged rows, [`PolicyRow`] the
//! policy-flagged ones. They are sibling enums rather than one enum with a
//! flag field (`CHAIN_RULES_CRATE.md` §4.1, round-1 ruling Q4): a flag field
//! is a check someone can forget, while two enums make "a policy row counted
//! toward consensus coverage" — proximity promotion arriving through the
//! instrument — unrepresentable. Both implement the sealed [`Row`] trait so
//! coverage and the test harness are written once.
//!
//! # The registry is checked, not trusted
//!
//! `scripts/ci/check_chain_rules_coverage.py` reads the two `census_rows!`
//! invocations below and asserts a bijection with the census: every enforced
//! row (bucket ≠ 3) of a flag has exactly one entry in that flag's enum, in
//! census order; no entry lacks a row; no bucket-3 row appears. It prints
//! `implemented / enforced` and `ratified / enforced` per flag — two lines,
//! two denominators, never a merged figure. An entry marked
//! `implemented(path)` is additionally pinned by the compiler: the macro
//! emits `use path as _;`, so a rule function that moves or is deleted while
//! its entry still claims it is a compile error, not a stale claim (G9).
//! `use` names the item without instantiating it — `let _ = path` is E0283
//! on the generic `fn<'id, V: ChainView<'id>>(...)` every 4.I rule is.
//!
//! # Entries flip as slices land
//!
//! The scaffold landed every entry `pending` (DRS-D12). Each porting slice
//! flips its rows to `implemented(<rule type>)` — slice 1 began with 4.B's
//! version rows — and the gate's printed numerator moves with them. An
//! `implemented` entry names a **type** implementing `rules::Rule`; the
//! macro pins both that it exists (G9) and that its `ROW` is this entry
//! (SCW-18).

use core::fmt;
use core::hash::Hash;

/// Which census denominator a row belongs to.
///
/// The census's `C`/`P` flag. Partitions first (ruling §9.4): the two flags
/// have separate registries, separate coverage sets, and separate
/// `implemented / enforced` figures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Flag {
    /// A consensus rule — every correctly implementing node reproduces it.
    Consensus,
    /// A relay/pool admission policy — applied by `AdmissionPolicy`, never
    /// merged into `RuleSet` (ruling §8).
    Policy,
}

/// How a row is held: not yet, by a rule type `validate` runs, by a rule
/// type this crate enforces at another site, or by the C++ ingest driver
/// until cutover.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RowStatus {
    /// No rule yet; the row is counted in the denominator only.
    Pending,
    /// A rule type is registered and compile-pinned (G9 + SCW-18), and
    /// `form` / `validate` run it per block.
    Implemented,
    /// A rule type is registered and compile-pinned, and **this crate**
    /// enforces it at a site other than the per-block stages, so no
    /// per-block coverage could ever contain it (`CHAIN_RULES_SLICE_3.md`
    /// Q4). The first is CEN-E5, run once by the writer at open
    /// (`ReleaseAnchors::conflict_with`); CEN-A1 and CEN-A4 take this
    /// status at cutover, when their C++ holder leaves and the Rust ingest
    /// driver decides acceptance topology.
    ///
    /// The registry entry carries the citation — `enforced_at(path, "test")`
    /// — and that is the only copy. The path is compile-pinned; the gate
    /// asserts the named `#[test]` is defined in this crate (rule 47). A
    /// string stored on the value would be a second copy nothing reads, free
    /// to drift from the entry. Same shape as [`HeldByCxx`](Self::HeldByCxx).
    ///
    /// Excluded from [`RuleSet::enforced`](crate::RuleSet::enforced) for the
    /// same reason a hold is (per-block completeness is measured over what
    /// `validate` evaluates) and, unlike a hold, **counted as Rust-enforced**
    /// by the gate: `held_by_cxx` would be false here — the enforcement is
    /// not the C++'s.
    EnforcedAt,
    /// Acceptance topology the C++ ingest driver decides — where a block
    /// *goes* (`ALREADY_EXISTS`, `ORPHANED`), not whether it is valid — and
    /// so not a predicate `validate` can evaluate (`CHAIN_RULES_SLICE_1.md`
    /// §4, Q2). The registry entry cites the C++ **test that proves the
    /// holder refuses** (`held_by_cxx("<file>", "<test>")`); the gate asserts
    /// the file exists and contains the test, never merely that a token
    /// appears (PWD-B10). A **deferral with a known expiry**: the cited file
    /// leaves the tree at cutover, the gate goes red, and the row is
    /// re-classified then — held rows cannot outlive the C++ silently.
    /// Excluded from [`RuleSet::enforced`](crate::RuleSet::enforced), so
    /// completeness is measured over what the validator can hold; the gate
    /// prints the subtraction beside the fixed denominator.
    HeldByCxx,
}

mod sealed {
    pub trait Sealed {}
}

/// A census row identity — implemented only by [`CenRow`] and [`PolicyRow`].
///
/// Sealed: the set of registries is the two the census flags define, and
/// generic code over `R: Row` (`Coverage<R>`, the harness) may rely on that.
/// `index()` is the row's position in [`Row::ALL`] and its `#[repr(u8)]`
/// discriminant — the same number, so a coverage bitset needs no table.
pub trait Row:
    sealed::Sealed + Copy + Eq + Ord + Hash + fmt::Debug + fmt::Display + 'static
{
    /// The flag every row of this registry carries.
    const FLAG: Flag;
    /// Every row of the registry, in census order.
    const ALL: &'static [Self];
    /// The register form, e.g. `"CEN-A1"`.
    fn as_str(self) -> &'static str;
    /// Whether a rule function is registered for the row.
    fn status(self) -> RowStatus;
    /// Position in [`Row::ALL`]; equals the discriminant.
    fn index(self) -> u8;
}

/// `RowStatus` from an entry's status token. A status other than `pending`,
/// `implemented(path)`, `enforced_at(path, "test")` or
/// `held_by_cxx("file", "test")` is a macro error at the entry.
macro_rules! census_status {
    (pending) => {
        $crate::census::RowStatus::Pending
    };
    (implemented($path:path)) => {
        $crate::census::RowStatus::Implemented
    };
    (enforced_at($path:path, $test:literal)) => {
        $crate::census::RowStatus::EnforcedAt
    };
    (held_by_cxx($file:literal, $test:literal)) => {
        $crate::census::RowStatus::HeldByCxx
    };
}

/// The two pins on an `implemented(path)` entry.
///
/// **G9 — the path exists.** `use $path as _` names the item without
/// instantiating it, so a rule that moved or was deleted while its entry
/// still claims it is a compile error.
///
/// **SCW-18 — the path is *this row's* rule.** Existence alone accepts
/// `implemented(rules::header::B2)` under the `B1` entry. The entry names a
/// **type** implementing [`crate::rules::Rule`], and the `const` assertion
/// below refuses one whose `ROW` is not the entry's own variant — row
/// binding is structural, not nominal (`rules/mod.rs`). `Bound<$name>` is
/// the registry-generic face of `Rule`, so the one macro serves both enums.
macro_rules! census_pin {
    (pending, $name:ident, $var:ident) => {};
    // Nothing the compiler can pin: the holder is a C++ test. The gate
    // asserts the cited file exists and contains the test (rule 47).
    (held_by_cxx($file:literal, $test:literal), $name:ident, $var:ident) => {};
    // The same two pins as `implemented`: the site exists and is bound to
    // this row. The test is the gate's to assert (a `#[test]` in this crate).
    (enforced_at($path:path, $test:literal), $name:ident, $var:ident) => {
        census_pin!(implemented($path), $name, $var);
    };
    (implemented($path:path), $name:ident, $var:ident) => {
        #[allow(unused_imports)]
        use $path as _;
        const _: () = assert!(
            matches!(<$path as $crate::rules::Bound<$name>>::ROW, $name::$var),
            concat!(
                "shekyl-chain-rules: the type registered under ",
                stringify!($var),
                " is bound to a different census row (SCW-18)"
            )
        );
    };
}

/// Defines one census registry enum: `pub enum Name: Flag { Var status, … }`.
///
/// Per entry, `status` is `pending`, `implemented(rust::path::to::RuleType)`,
/// `enforced_at(rust::path::to::RuleType, "test_fn_in_this_crate")` or
/// `held_by_cxx("tests/…​.cpp", "gen_test_name")`.
/// Entries must be listed in census §4 order restricted to the flag; the gate
/// asserts this so `index()` is census-derived. The variant name is the census
/// id without its `CEN-` prefix (`CEN-D1b` → `D1b`).
macro_rules! census_rows {
    (
        $(#[$doc:meta])*
        pub enum $name:ident : $flag:ident {
            $(
                $(#[$vdoc:meta])*
                $var:ident $status:ident $( ( $($arg:tt)* ) )?,
            )+
        }
    ) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
        #[repr(u8)]
        pub enum $name {
            $(
                $(#[$vdoc])*
                $var,
            )+
        }

        impl $name {
            /// The flag every row of this registry carries.
            pub const FLAG: Flag = Flag::$flag;

            /// Every row of the registry, in census order.
            pub const ALL: &'static [Self] = &[$(Self::$var),+];

            /// The register form, e.g. `"CEN-A1"`.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$var => concat!("CEN-", stringify!($var)),)+
                }
            }

            /// Whether a rule function is registered for the row.
            #[must_use]
            pub const fn status(self) -> RowStatus {
                match self {
                    $(Self::$var => census_status!($status $( ( $($arg)* ) )?),)+
                }
            }

            /// Position in [`Self::ALL`]; equals the `#[repr(u8)]` discriminant.
            #[must_use]
            pub const fn index(self) -> u8 {
                self as u8
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl sealed::Sealed for $name {}

        impl Row for $name {
            const FLAG: Flag = Self::FLAG;
            const ALL: &'static [Self] = Self::ALL;
            fn as_str(self) -> &'static str { Self::as_str(self) }
            fn status(self) -> RowStatus { Self::status(self) }
            fn index(self) -> u8 { Self::index(self) }
        }

        // G9 + SCW-18: every `implemented(path)` names a type that exists
        // and whose `ROW` is this entry's variant (`census_pin!`). Two
        // registries both expand here; `as _` does not collide.
        $( census_pin!($status $( ( $($arg)* ) )?, $name, $var); )+
    };
}

#[cfg(test)]
#[path = "census_tests.rs"]
mod census_tests;

census_rows! {
    /// The consensus-flagged enforced census rows — the `C` denominator.
    ///
    /// One variant per `CONSENSUS_RULE_CENSUS.md` §4 row with flag `C` and
    /// bucket ≠ 3, in census order. Sections follow the census subsystems;
    /// the gate holds the bijection.
    pub enum CenRow: Consensus {
        // 4.A Acceptance topology (`CHAIN_RULES_SLICE_1.md` §3–§4)
        // A1/A4: where a block goes, not whether it is valid. The C++ ingest
        // driver holds these rows until cutover; each entry cites the core
        // test that observes the outcome byte.
        A1 held_by_cxx("tests/core_tests/block_validation.cpp", "gen_block_already_known_is_already_exists"),
        A2 implemented(crate::rules::topology::A2),
        // A3: subsumed by B4's empty-witness arm — never its own rule; the
        // row closes when B4 lands (Q3).
        A3 pending,
        A4 held_by_cxx("tests/core_tests/block_validation.cpp", "gen_block_invalid_prev_id"),
        // A5: subsumed by the 4.G weight rule (slice 7); the pre-parse fast
        // path is the driver's DoS choice, not a row.
        A5 pending,
        // A6/A7: wire invariants (R8 arm B, holder `shekyl_wire::Block::
        // from_bytes`); re-homed to the wire-side invariant register when
        // the wire-format port mints it. A7's *value* is arm C (F2).
        A6 pending,
        A7 pending,
        // 4.B Block header: version, attestation, curve-tree root
        B1 implemented(crate::rules::header::B1),
        B2 implemented(crate::rules::header::B2),
        B3 pending,
        B4 pending,
        B5 implemented(crate::rules::header::B5),
        B6 implemented(crate::rules::header::B6),
        B7 implemented(crate::rules::header::B7),
        // 4.C Timestamps (slice 2): C1/C2 predicates, C3 the window definition
        // recorded at `C3::window`.
        C1 implemented(crate::rules::timestamps::C1),
        C2 implemented(crate::rules::timestamps::C2),
        C3 implemented(crate::rules::timestamps::C3),
        // 4.D PoW and difficulty (slice 2). D2 the longhash definition in
        // `form`; D3 the seed verification, D1b the comparison definition
        // and D1 the predicate in `validate` (`rules/pow.rs`).
        D1 implemented(crate::rules::pow::D1),
        D1b implemented(crate::rules::pow::D1b),
        D2 implemented(crate::rules::pow::D2),
        D3 implemented(crate::rules::pow::D3),
        // D4 the target definition, recorded at `D4::target`; D6 held by the
        // `Target` type (`NonZeroU128`), recorded at every production path
        // (`D6::record` / `D6::mint`) so Fakechain `Fixed` and genesis-block
        // `1` cover the row as well as LWMA-1 (slice 2 Q4). D5 is **subsumed
        // by D4 over an alt view**: the same LWMA-1
        // reads its window through `ChainView::block_at`, and the alt
        // stitching is what an alt view's `block_at` does — it stays
        // `pending` until slice 9 lands that view and a fixture drives D4
        // over it (slice 2 Q7; the A5 → 4.G shape).
        D4 implemented(crate::rules::difficulty::D4),
        D5 pending,
        D6 implemented(crate::rules::difficulty::D6),
        // D7 as data on a Fakechain rule set (`DifficultyRule::Fixed`), the
        // override arm D4 consults on every block (slice 2 Q10, arm (d)).
        D7 implemented(crate::rules::difficulty::D7),
        // 4.E Checkpoints and fast-sync trust — the anchor model's rows
        // (`CHAIN_RULES_SLICE_3.md` §0; `PDM-Q5`).
        E1 implemented(crate::rules::anchors::E1),
        // E2 has no Rust site: the store admits no alternative block and the
        // main chain satisfies the anchor floor by construction. Subsumed
        // behind the alt `ChainView` (slice 9) AND `D_max`'s numeric
        // (`PDM-Q11`, provisional) — the D5 shape with two blockers; the
        // longer wait governs (slice 3 §2).
        E2 pending,
        // E5 is enforced once, by the writer at open — not per block
        // (slice 3 Q4 (a)); the test named is the refusal fixture.
        E5 enforced_at(crate::rules::anchors::E5, "a_recorded_block_that_is_not_the_anchor_is_the_conflict"),
        // 4.F Miner transaction (structure and emission)
        F1 pending,
        F2 pending,
        F3 pending,
        F4 pending,
        F5 pending,
        F6 pending,
        F7 pending,
        F8 pending,
        F9 pending,
        F10 pending,
        F11 pending,
        F13 pending,
        F14 pending,
        F14b pending,
        F15 pending,
        F16 pending,
        F17 pending,
        F18 pending,
        F19 pending,
        F20 pending,
        F21 pending,
        // 4.G Block body (per-tx and block-level, main-chain connect)
        G1 pending,
        G2 pending,
        G3 pending,
        G4 pending,
        G5 pending,
        G6 pending,
        G6b pending,
        G7 pending,
        G9 pending,
        G10 pending,
        G11 pending,
        G12 pending,
        G13 pending,
        // 4.H Transaction: non-input consensus, semantics, outputs
        H1 pending,
        H2 pending,
        H3 pending,
        H4 pending,
        H5 pending,
        H6 pending,
        H7 pending,
        H8 pending,
        H9 pending,
        H10 pending,
        H11 pending,
        H12 pending,
        H13 pending,
        H14 pending,
        H15 pending,
        H16 pending,
        H17 pending,
        H18 pending,
        H19 pending,
        H20 pending,
        H21 pending,
        H22 pending,
        H23 pending,
        // 4.I Transaction inputs — the FCMP++ spend path
        I1 pending,
        I2 pending,
        I3 pending,
        I4 pending,
        I5 pending,
        I6 pending,
        I7 pending,
        I8 pending,
        I9 pending,
        I10 pending,
        I11 pending,
        I12 pending,
        I13 pending,
        I14 pending,
        I15 pending,
        I16 pending,
        I17 pending,
        I18 pending,
        I19 pending,
        // 4.J Archival transaction families (all verdicts Rust-side; C++ marshals)
        J1 pending,
        J2 pending,
        J3 pending,
        J4 pending,
        J5 pending,
        J6 pending,
        J7 pending,
        J8 pending,
        J9 pending,
        J10 pending,
        J11 pending,
        J12 pending,
        J13 pending,
        J14 pending,
        J15 pending,
        J16 pending,
        J17 pending,
        J18 pending,
        J19 pending,
        J20 pending,
        J21 pending,
        J22 pending,
        J23 pending,
        J24 pending,
        J25 pending,
        J26 pending,
        // 4.K Reorg / alternative chains
        K1a pending,
        K1b pending,
        K2 pending,
        K3 pending,
        K4 pending,
        K5 pending,
        K5b pending,
        K6 pending,
        K7 pending,
        K8 pending,
        K9 pending,
        K10 pending,
        // 4.L Storage layer (constraints that reject chain data at write time)
        L1 pending,
        L7 pending,
        L8 pending,
        L9 pending,
        L10 pending,
        L11 pending,
        L12 pending,
        L14 pending,
        // 4.M Mempool admission (the `kept_by_block` axis) — consensus-flagged rows
        M2 pending,
        M8 pending,
    }
}

census_rows! {
    /// The policy-flagged enforced census rows — the `P` denominator.
    ///
    /// One variant per `CONSENSUS_RULE_CENSUS.md` §4 row with flag `P` and
    /// bucket ≠ 3, in census order. Applied by `AdmissionPolicy` (DRS-E5);
    /// a `PolicyRow` cannot enter a `RuleCoverage` — the type forbids it.
    pub enum PolicyRow: Policy {
        // 4.M Mempool admission (the `kept_by_block` axis) — policy-flagged rows
        M1 pending,
        M3 pending,
        M4 pending,
        M5 pending,
        M6 pending,
        M7 pending,
        M9 pending,
        M10 pending,
        M11 pending,
    }
}
