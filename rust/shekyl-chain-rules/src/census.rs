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

/// Whether a rule function exists for a row in this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RowStatus {
    /// No rule yet; the row is counted in the denominator only.
    Pending,
    /// A rule function is registered and compile-pinned.
    Implemented,
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

/// `RowStatus` from an entry's status token. A status other than `pending`
/// or `implemented(path)` is a macro error at the entry.
macro_rules! census_status {
    (pending) => {
        $crate::census::RowStatus::Pending
    };
    (implemented($path:path)) => {
        $crate::census::RowStatus::Implemented
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
/// Per entry, `status` is `pending` or `implemented(rust::path::to::rule)`.
/// Entries must be listed in census §4 order restricted to the flag; the gate
/// asserts this so `index()` is census-derived. The variant name is the census
/// id without its `CEN-` prefix (`CEN-D1b` → `D1b`).
macro_rules! census_rows {
    (
        $(#[$doc:meta])*
        pub enum $name:ident : $flag:ident {
            $(
                $(#[$vdoc:meta])*
                $var:ident $status:tt $(($path:path))?,
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
                    $(Self::$var => census_status!($status $(($path))?),)+
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
        $( census_pin!($status $(($path))?, $name, $var); )+
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
        // 4.A Acceptance topology
        A1 pending,
        A2 implemented(crate::rules::topology::A2),
        A3 pending,
        A4 pending,
        A5 pending,
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
        // 4.C Timestamps
        C1 pending,
        C2 pending,
        C3 pending,
        // 4.D PoW and difficulty
        D1 pending,
        D1b pending,
        D2 pending,
        D3 pending,
        D4 pending,
        D5 pending,
        D6 pending,
        D7 pending,
        // 4.E Checkpoints and fast-sync trust
        E1 pending,
        E2 pending,
        E5 pending,
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
        F12 pending,
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
