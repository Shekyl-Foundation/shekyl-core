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
/// type this crate enforces at another site, by construction, or by a Rust
/// crate below the validator.
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
    /// (`ReleaseAnchors::conflict_with`).
    ///
    /// The registry entry carries the citation — `enforced_at(path, "test")`
    /// — and that is the only copy. The path is compile-pinned; the gate
    /// asserts the named `#[test]` is defined in this crate (rule 47). A
    /// string stored on the value would be a second copy nothing reads, free
    /// to drift from the entry. Same shape as
    /// [`HeldByStore`](Self::HeldByStore), whose test is in the holder.
    ///
    /// Excluded from [`RuleSet::enforced`](crate::RuleSet::enforced), since
    /// per-block completeness is measured over what `validate` evaluates,
    /// and **counted as enforced** by the gate: the enforcement is this
    /// crate's, at another site.
    EnforcedAt,
    /// The row holds **by construction**: no runtime site evaluates it
    /// because the type system (or the wire's parser) makes the violation
    /// unrepresentable, and a per-block check would be a fixture that
    /// cannot fire (`CHAIN_RULES_SLICE_4.md` Q4, ruled (a)). Three
    /// instances at mint: CEN-F19 (`validate` runs inside the write
    /// transaction over a view branded `'id` that *is* parent state, so
    /// the read-point drift the C++ asserts against has no expression),
    /// CEN-F2 (`shekyl_wire::Transaction::read` admits one version) and
    /// CEN-F8 (`Output::read` admits one output tag). The `PDM-Q3`
    /// instrument is the same class.
    ///
    /// The registry entry carries `by_construction(property, "falsifier")`:
    /// `property` is the Rust path whose existence is compile-pinned (the
    /// type or item that holds the property — not a rule type, so no
    /// `ROW` assertion applies), and `falsifier` names the test in this
    /// crate that would fail if the property lapsed — a `#[test]` that
    /// exercises the parser, `doctest:<item>` for a `compile_fail`
    /// doctest on `<item>`, or `trybuild:<test>` for the `#[test]` under
    /// `tests/` that compares `compile_fail` programs against stderr
    /// snapshots (F19's since 2026-10-10: its doctests had been green on
    /// a stub that no longer implemented `ChainView`, not at `connect`).
    /// The gate asserts the falsifier is defined (rule 47: a property
    /// with no way to fail is a claim).
    ///
    /// Excluded from [`RuleSet::enforced`](crate::RuleSet::enforced), as
    /// [`EnforcedAt`](Self::EnforcedAt) is, and counted as Rust-enforced by
    /// the gate; unlike `EnforcedAt` there is no site that *runs*.
    ByConstruction,
    /// A row **a Rust crate below the validator** enforces — the store,
    /// whose alt-chain indexing is where the row's operand lives
    /// (`DRS_E5_POOL_ALT_PRUNE.md` `E5-18`, decided 2026-10-11). The
    /// validator cannot evaluate it: the rules crate imports no store
    /// (DRS-D12 (i), `check_chain_rules_no_store.sh`), so the dependency
    /// direction is store → rules and the refusal is minted on the store's
    /// side of it. Four at mint: CEN-K1a and CEN-K2 (`AltChain::build`
    /// links an alt entry to a recorded row or refuses it), CEN-K3
    /// (`insert_alt_block` refuses a held hash) and CEN-K8 (`HeaderRecord`
    /// carries no `coins_generated` for an alt entry to disturb). The same
    /// status holds the rows the **switch** enforces — CEN-K5, K5b, K6 and
    /// K7, held by `shekyl-chain-ingest`, the store's single writer, whose
    /// switch sequences promotion, the fork choice's match and the demoted
    /// rows (DRS-E5 a5) — and the two acceptance-topology rows its
    /// **router** holds, CEN-A1 and CEN-A4 (DRS-X PR 2): like the store, a
    /// crate the validator does not import, which is what the status names.
    ///
    /// The registry entry cites the crate and the test that proves the
    /// holder refuses — `held_by_store("<crate>", "<test>")` — and the gate
    /// asserts a `#[test] fn <test>` is **defined** in that crate's `src/`
    /// or `tests/`, never merely that the token appears (the same shape as
    /// [`EnforcedAt`](Self::EnforcedAt), whose test is in this crate).
    /// Nothing the compiler can pin from here: the holder is outside this
    /// crate by construction.
    ///
    /// Not `by_construction`: that status is a claim about a **type** in
    /// this crate with a falsifier in this crate, and a runtime test in
    /// another crate is neither. Not `enforced_at`: that site is this
    /// crate's. Excluded from [`RuleSet::enforced`](crate::RuleSet::enforced)
    /// as both are (per-block completeness is what `validate` evaluates),
    /// and **counted as enforced** by the gate, printed as its own figure.
    HeldByStore,
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
/// `implemented(path)`, `enforced_at(path, "test")`,
/// `by_construction(path, "falsifier")` or `held_by_store("crate", "test")`
/// is a macro error at the entry.
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
    (by_construction($path:path, $falsifier:literal)) => {
        $crate::census::RowStatus::ByConstruction
    };
    (held_by_store($krate:literal, $test:literal)) => {
        $crate::census::RowStatus::HeldByStore
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
    // Nothing the compiler can pin: the holder is a crate this one
    // does not import (DRS-D12 (i)). The gate asserts the named `#[test]`
    // is defined in that crate (rule 47).
    (held_by_store($krate:literal, $test:literal), $name:ident, $var:ident) => {};
    // The same two pins as `implemented`: the site exists and is bound to
    // this row. The test is the gate's to assert (a `#[test]` in this crate).
    (enforced_at($path:path, $test:literal), $name:ident, $var:ident) => {
        census_pin!(implemented($path), $name, $var);
    };
    // One pin: the property's home exists (G9). It is not a rule type, so
    // there is no `ROW` to assert; the falsifier is the gate's to assert.
    (by_construction($path:path, $falsifier:literal), $name:ident, $var:ident) => {
        #[allow(unused_imports)]
        use $path as _;
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
/// `enforced_at(rust::path::to::RuleType, "test_fn_in_this_crate")`,
/// `by_construction(rust::path::to::Property, "falsifier_test")` or
/// `held_by_store("shekyl-chain-store", "test_fn_in_that_crate")`.
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
        // A1/A4: where a block goes, not whether it is valid. The ingest
        // service's router holds them (DRS-X PR 2, `router.rs`): a held
        // block is `AlreadyHeld`, and a block whose parent neither table
        // holds is `Unlinked` and not stored. The router is in
        // `shekyl-chain-ingest`, a crate this one does not import, which is
        // what `held_by_store` names; `enforced_at` would be a site here.
        A1 held_by_store("shekyl-chain-ingest", "an_arrival_this_node_holds_is_already_held"),
        A2 implemented(crate::rules::topology::A2),
        // A3: subsumed by B4's empty-witness arm — never its own rule
        // (slice 1 Q3). The validator has no witness-less entry to guard:
        // `Candidate::attestation_witness` is the one door, and B4 judges
        // `None` as the empty preimage against the header root, so a
        // non-empty root with nothing supplied refuses as B4 (slice 8
        // row 10). The second guard the C++ needed is unrepresentable.
        A3 by_construction(crate::block::Candidate, "cen_b4_non_empty_root_with_nothing_supplied_is_refused"),
        A4 held_by_store("shekyl-chain-ingest", "an_arrival_whose_parent_is_unheld_is_unlinked_and_not_stored"),
        // A6/A7: wire invariants (R8 arm B), held by `Block::from_bytes`:
        // no `Block` exists that the parser refused, so no rule sees one.
        // The path is the type — `use` cannot name an associated function.
        // A7's *value* is arm C: the wire refuses above `READ_LEN_CAP`
        // (10^6), tighter than the census's 2^28, and the two bounds are
        // one field's two undocumented values (FOLLOWUPS, CEN-A7's row).
        A6 by_construction(shekyl_wire::Block, "a6_a_block_blob_the_wire_cannot_parse_is_refused"),
        A7 by_construction(shekyl_wire::Block, "a7_a_transaction_hash_count_above_the_bound_is_refused_before_any_hash_is_read"),
        // 4.B Block header: version, attestation, curve-tree root
        B1 implemented(crate::rules::header::B1),
        B2 implemented(crate::rules::header::B2),
        // B3: the store's rule-set belt (`connect` phases 1 and 7) — a
        // verdict judged under a set other than the one in force refuses
        // at connect, compared by value; the id is recorded per height.
        // The rules crate imports no store, so the holder is the store's
        // (E5-18, as K1a/K2/K3/K8).
        B3 held_by_store("shekyl-chain-store", "a_fakechain_verdict_is_refused_under_genesis_in_force"),
        B4 implemented(crate::rules::attestation::B4),
        B5 implemented(crate::rules::header::B5),
        B6 implemented(crate::rules::header::B6),
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
        // `1` cover the row as well as LWMA-1 (slice 2 Q4). D5 is D4's
        // algorithm over the stitched view — `D5::target` wraps `D4::target`
        // and records the row at the one site that feeds D4 an alt view,
        // `alt_against` (DRS-E5 slice 9); not per block, so `enforced_at`.
        D4 implemented(crate::rules::difficulty::D4),
        D5 enforced_at(crate::rules::alt::D5, "the_alt_target_follows_the_window_it_is_fed"),
        D6 implemented(crate::rules::difficulty::D6),
        // D7 as data on a Fakechain rule set (`DifficultyRule::Fixed`), the
        // override arm D4 consults on every block (slice 2 Q10, arm (d)).
        D7 implemented(crate::rules::difficulty::D7),
        // 4.E Checkpoints and fast-sync trust — the anchor model's rows
        // (`CHAIN_RULES_SLICE_3.md` §0; `PDM-Q5`).
        E1 implemented(crate::rules::anchors::E1),
        // E2 the anchor floor and the rolling reorg cap, judged over the fork
        // an alternative would cause (`E2::check`, `alt_against`, DRS-E5
        // slice 9). The main chain satisfies both by construction, so the
        // row is the alt tier's alone — `enforced_at`, not per block.
        E2 enforced_at(crate::rules::alt::E2, "an_alternative_rooted_below_the_anchor_is_refused_and_one_at_or_above_it_is_not"),
        // E5 is enforced once, by the writer at open — not per block
        // (slice 3 Q4 (a)); the test named is the refusal fixture.
        E5 enforced_at(crate::rules::anchors::E5, "a_recorded_block_that_is_not_the_anchor_is_the_conflict"),
        // 4.F Miner transaction (structure and emission)
        F1 implemented(crate::rules::miner::F1),
        F2 by_construction(shekyl_wire::transaction::TX_VERSION, "f2_the_wire_admits_one_transaction_version"),
        F3 implemented(crate::rules::miner::F3),
        F4 implemented(crate::rules::miner::F4),
        F5 implemented(crate::rules::miner::F5),
        F6 implemented(crate::rules::miner::F6),
        F7 implemented(crate::rules::miner::F7),
        F8 by_construction(shekyl_wire::Output, "f8_the_wire_admits_one_output_tag"),
        F9 implemented(crate::rules::miner::F9),
        F10 implemented(crate::rules::miner::F10),
        F11 implemented(crate::rules::miner::F11),
        F13 implemented(crate::rules::miner::F13),
        F14 implemented(crate::rules::reward::F14),
        F14b implemented(crate::rules::reward::F14b),
        F15 implemented(crate::rules::miner::F15),
        F16 implemented(crate::rules::reward::F16),
        F17 implemented(crate::rules::reward::F17),
        F18 implemented(crate::rules::reward::F18),
        F19 by_construction(crate::view::ChainView, "trybuild:a_verdict_connects_under_the_view_it_was_judged_against_and_no_other"),
        F20 implemented(crate::rules::miner::F20),
        F21 by_construction(shekyl_economics::EMISSION_SPLIT_EPOCH, "the_staker_share_starts_at_block_one"),
        // 4.G Block body (per-tx and block-level, main-chain connect)
        G1 implemented(crate::rules::body::G1),
        G2 implemented(crate::rules::body::G2),
        /// `validate` runs `tx_form` on **every** listed body, whatever door
        /// the ingest brought it through; there is no pool path into
        /// `validate` and no "already verified" set, so a body failing an H
        /// row refuses the block (slice 7 §5 row 8). Falsified through
        /// `validate` on a listed body with no inputs.
        G3 by_construction(crate::validate::validate, "h4_a_listed_transaction_with_no_inputs_is_refused"),
        /// `tx_against` on every slot, unconditionally. The C++'s hash-gated
        /// skip of the FCMP re-verify for admission-verified bytes (CEN-M8)
        /// is a *cost* behaviour — a proof re-verified over identical bytes
        /// has the same verdict — not a rule; **do not build a cache to
        /// match it** (slice 7 §3.2). Falsified through `validate` on a
        /// listed spend of a spent image.
        G4 by_construction(crate::validate::validate, "i7_at_a_listed_slot_the_refusal_names_the_slot"),
        /// A pruned body has no weight; the C++ refuses the block. In Rust the
        /// storage-pruned form cannot reach a block rule: `Transaction` is
        /// the full form, and a body missing its prunable region is refused
        /// by `tx_form` at both sites — on **H18**, the balance whose
        /// pseudo-outs went with the region (slice 7 §3.3, measured).
        G5 by_construction(shekyl_wire::Transaction, "g5_the_storage_pruned_spend_is_refused_before_any_block_rule_sees_it"),
        G6 implemented(crate::rules::block_weight::G6),
        G6b implemented(crate::rules::block_weight::G6b),
        G7 implemented(crate::rules::body::G7),
        G9 implemented(crate::rules::body::G9),
        G10 implemented(crate::rules::body::G10),
        G11 implemented(crate::rules::reward::G11),
        G12 implemented(crate::rules::reward::G12),
        G13 implemented(crate::rules::reward::G13),
        // 4.H Transaction: non-input consensus, semantics, outputs
        H1 implemented(crate::rules::tx::H1),
        H2 by_construction(shekyl_wire::transaction::TX_VERSION, "f2_the_wire_admits_one_transaction_version"),
        H3 implemented(crate::rules::tx::H3),
        H4 implemented(crate::rules::tx::H4),
        H5 implemented(crate::rules::tx::H5),
        H6 implemented(crate::rules::tx::H6),
        H7 implemented(crate::rules::tx::H7),
        H8 by_construction(shekyl_wire::CtBase, "h8_the_wire_reads_one_commitment_per_output"),
        H9 implemented(crate::rules::tx::H9),
        H10 implemented(crate::rules::tx::H10),
        H11 implemented(crate::rules::tx::H11),
        H12 by_construction(shekyl_wire::Output, "f8_the_wire_admits_one_output_tag"),
        H13 by_construction(shekyl_wire::transaction::TX_VERSION, "f2_the_wire_admits_one_transaction_version"),
        H14 implemented(crate::rules::tx::H14),
        H15 implemented(crate::rules::tx::H15),
        H16 implemented(crate::rules::tx::H16),
        H17 implemented(crate::rules::tx::H17),
        H18 implemented(crate::rules::tx::H18),
        H19 implemented(crate::rules::tx::H19),
        H20 implemented(crate::rules::tx::H20),
        H21 implemented(crate::rules::tx::H21),
        H22 implemented(crate::rules::tx::H22),
        H23 by_construction(shekyl_wire::Transaction, "doctest:tx_form"),
        // 4.I Transaction inputs — the FCMP++ spend path. The stateless
        // rows landed in `tx_form` at slice 6 commit 2 (`rules/tx_inputs.rs`);
        // the view-bound and verification rows follow in `tx_against`.
        I1 implemented(crate::rules::tx_inputs::I1),
        // I2: a non-coinbase CT is `FcmpPlusPlusPqc`. The wire's `Ct` has two
        // variants and the `Null` half is H15's landed refusal off the
        // coinbase; nothing else is representable (slice 6 Q3, list-and-
        // iterate: the falsifier names I2 and walks the type set).
        I2 by_construction(shekyl_wire::Ct, "i2_the_wire_admits_two_ct_types_and_h15_refuses_null_off_the_coinbase"),
        // I3: version exactly 3 — the fourth row on `TX_VERSION`'s falsifier
        // (F2, H2, H13 before it; slice 6 Q3).
        I3 by_construction(shekyl_wire::transaction::TX_VERSION, "f2_the_wire_admits_one_transaction_version"),
        I4 implemented(crate::rules::tx_inputs::I4),
        I5 implemented(crate::rules::tx_inputs::I5),
        I6 implemented(crate::rules::tx_inputs::I6),
        I7 implemented(crate::rules::tx_against::I7),
        I8 implemented(crate::rules::tx_inputs::I8),
        I9 implemented(crate::rules::tx_inputs::I9),
        // I10–I12 (slice 6 commit 5) are the regular-spend reference rows,
        // run by `tx_against` in the D4 arrangement: I10 yields `ref_height`,
        // I11 measures it, I12 is the definition of the anchor read at it.
        I10 implemented(crate::rules::tx_against::I10),
        I11 implemented(crate::rules::tx_against::I11),
        I12 implemented(crate::rules::tx_against::I12),
        // I13 (slice 6 row 6, the flip of 2026-10-08): the depth step of the
        // spend's reference sequence, run by `tx_against::judge_reference`
        // under this row; the same step runs on the emission under J21
        // (slice 8 row 9). Pending from slice 6 commit 5 until the
        // filler-fixture migration ruled 2026-10-07 made the spends real.
        I13 implemented(crate::rules::tx_against::I13),
        I14 implemented(crate::rules::tx_inputs::I14),
        // I15 (slice 6 row 6, the same flip): the FCMP++ verify over every
        // `ToKey` input of a spend, after the reference sequence yields its
        // context; the same body runs on the emission's fee inputs as J26.
        I15 implemented(crate::rules::tx_against::I15),
        I16 implemented(crate::rules::tx_inputs::I16),
        // I17 (slice 6 commit 7): the signing preimage, adopted from the wire's
        // one derivation (Q7 (c)) and recorded where `tx_against` derives it.
        I17 implemented(crate::rules::tx_against::I17),
        I18 implemented(crate::rules::tx_against::I18),
        I19 implemented(crate::rules::tx_extra::I19),
        I20 implemented(crate::rules::tx_extra::I20),
        // 4.J Archival transaction families (all verdicts Rust-side; C++ marshals)
        J1 pending,
        J2 implemented(crate::rules::tx_inputs::J2),
        J3 pending,
        J4 implemented(crate::rules::tx_bond::J4),
        J5 implemented(crate::rules::tx_bond::J5),
        J6 implemented(crate::rules::tx_bond::J6),
        J7 pending,
        J8 pending,
        J9 pending,
        J10 pending,
        J11 implemented(crate::rules::tx_inputs::J11),
        J12 implemented(crate::rules::tx_inputs::J12),
        // J28 (FN-DSA increment 3, minted 2026-10-12 with its
        // implementation): a JoinMarket's `receipt_sign_pk` parses as a
        // canonical `FnDsaHybridPublicKey`. Filed with the bond post's
        // key-shape rows (after J12), not by number — J27's precedent.
        J28 implemented(crate::rules::tx_inputs::J28),
        J13 implemented(crate::rules::tx_bond::J13),
        J14 implemented(crate::rules::tx_bond::J14),
        J15 implemented(crate::rules::tx_bond::J15),
        J16 implemented(crate::rules::tx_bond::J16),
        // J17 is bucket 3 (REJECTED, immutable-bond 2026-09-20; slice 8 Q1
        // (a) 2026-10-04). The census keeps the id marked REJECTED; this
        // registry does not. CEN-F12 is the precedent.
        J18 implemented(crate::rules::tx_bond::J18),
        // J27 (slice 6 row 6, minted 2026-10-08): the bond post's funding
        // half — the reference sequence as I10–I13 and the FCMP++ verify
        // over the funding spends as I15, one row, the bond-post arm of
        // `judge_reference`. Filed with the bond-post family in census
        // order (after J18), not by number.
        J27 implemented(crate::rules::tx_against::J27),
        J19 implemented(crate::rules::tx_emission::J19),
        J20 implemented(crate::rules::tx_emission::J20),
        // J21 (slice 8 row 9): the emission's reference context, judged
        // as one row over I10–I13's reads in `judge_reference`.
        J21 implemented(crate::rules::tx_against::J21),
        J22 implemented(crate::rules::tx_emission::J22),
        // J23, J25 and J26 (slice 8 row 9): the frozen closes gathered per
        // claimed epoch, the retention verify over them, then I15's body
        // over the fee inputs, in `judge_emission_claim`.
        J23 implemented(crate::rules::tx_emission_against::J23),
        J24 implemented(crate::rules::tx_emission::J24),
        J25 implemented(crate::rules::tx_emission_against::J25),
        J26 implemented(crate::rules::tx_emission_against::J26),
        // J29–J37 (minted 2026-10-12, STAGED): the serve-credit bundle's
        // admission checks, a block-level section (`ARCHIVAL_SERVE_CREDIT_SPEC.md`
        // §9.1). The pure verifier that names them as refusals is built
        // (`crate::archival::check_section`, `crate::archival::verify_bundle`)
        // and nothing on the connect path calls it, so no rule type is
        // bound and each row is `pending`: in the denominator, in no
        // coverage. `SO-D12`'s cutover increment binds them. J28 is filed
        // with the bond-post key-shape rows above, where increment 3
        // minted it. J17 stays unregistered (bucket 3).
        J29 pending,
        J30 pending,
        J31 pending,
        J32 pending,
        J33 pending,
        J34 pending,
        J35 pending,
        J36 pending,
        J37 pending,
        // 4.K Reorg / alternative chains (DRS-E5 slice 9, the alt tier).
        // The store holds what its structures make true — the chain's root
        // and linkage (K1a, K2), a held hash refused at insert (K3), no
        // supply word on an alt row (K8) — and the rules crate imports no
        // store (DRS-D12 (i)), so each is `held_by_store` with the test in
        // `shekyl-chain-store` that proves it (E5-18). The alt tier's own
        // rows are `enforced_at` its sites: the height-0 claim (K1b), the
        // tier as the set and order of its steps (K4). K5–K7 are the
        // switch's — the single writer's sequencing of the store, in
        // `shekyl-chain-ingest` (DRS-E5 a5; `DRS_E5_POOL_ALT_PRUNE.md`
        // §2.3), `held_by_store` with the switch test that proves each. K9
        // is the pool's (PR-b). CEN-K10 is deleted (bucket 3, 2026-10-17):
        // reorg retention parked an alternative chain's bodies in the pool,
        // and the store holds them now.
        K1a held_by_store("shekyl-chain-store", "a_chain_through_two_alt_entries_reaches_a_recorded_row"),
        K1b enforced_at(crate::rules::alt::K1b, "a_height_zero_claim_is_refused_before_anything_is_read"),
        K2 held_by_store("shekyl-chain-store", "the_orphan_is_unlinked_at_the_first_unheld_hash"),
        K3 held_by_store("shekyl-chain-store", "insert_of_a_held_hash_and_remove_of_an_absent_one_are_refusals"),
        K4 enforced_at(crate::rules::alt::K4, "the_cheap_tier_evaluates_the_header_ladder_and_the_alt_arms_and_nothing_else"),
        K5 held_by_store("shekyl-chain-ingest", "a_promoted_block_that_fails_validate_rolls_back_and_removes_its_suffix"),
        K5b held_by_store("shekyl-chain-ingest", "a_tampered_witness_on_an_alt_row_fails_promotion_k5b"),
        K6 held_by_store("shekyl-chain-ingest", "a_heavier_branch_switches_and_equals_the_branch_connected_directly"),
        K7 held_by_store("shekyl-chain-ingest", "a_checkpoint_forced_switch_discards_the_demoted_chain"),
        K8 held_by_store("shekyl-chain-store", "an_alt_row_has_no_supply_word"),
        // K9: an alternative block's bodies (DRS-E5 PR-b b4; the review of
        // #1102, B1) — held by the store beside its row and promoted from
        // it, then offered to the pool door for relay. Witnessed by the
        // switch over the production stack.
        K9 held_by_store("shekyl-chain-ingest", "an_alternatives_bodies_are_the_stores_and_its_promotion_needs_no_pool"),
        // 4.L Storage layer (constraints that reject chain data at write time)
        // L1 is the validator's (C2-R8 Q6): the intra-block half of key-image
        // uniqueness, run in `validate` after every slot; SI-1 is the store's
        // belt beneath it, never the rule.
        L1 implemented(crate::rules::tx_against::L1),
        // L7–L9 are the C++ archival connect hooks, which the verdict runs
        // as the archival transition (DRS-E4 commit 4, `ARW-Q1`): the
        // store holds no archival arithmetic. L7 is the rule — a post,
        // credit or claim the folds cannot apply refuses the block at its
        // input. L8 and L9 are the folds themselves: the close is a
        // derivation the delta carries, and what the C++ aborted on
        // (accrual overflow; a slash the record cannot take) is a
        // `Corrupt` the fold returns by type — no per-block predicate, so
        // no rule type; the falsifiers exercise the folds directly.
        L7 implemented(crate::archival::L7),
        L8 by_construction(crate::archival::accrue, "l8_an_accrual_that_overflows_is_a_corrupt_view"),
        L9 by_construction(crate::archival::apply_slash, "l9_slashing_a_shard_the_record_does_not_hold_is_a_corrupt_view"),
        L10 pending,
        // L11/L12: growth has no rule type (E3 Round 1, `drain.rs`'s module
        // docs). The rows still bind, because B5 judges the next header's
        // root against the root `tree_after` derives from the chain below:
        // a drain that dropped an accepted output (L11), or matured one at
        // any height but h+60 (coinbase) / h+10 (listed) (L12), is another
        // root, and B5 refuses it. The derivation is the holder.
        L11 by_construction(crate::drain::tree_after, "l11_an_accepted_output_left_out_of_the_tree_is_a_different_root"),
        L12 by_construction(crate::drain::tree_after, "l12_a_coinbase_leaf_joins_at_sixty_and_a_listed_leaf_at_ten_and_neither_earlier"),
        // L14: the mechanism is ruled and built (every keyed write is a
        // declared verb). The three sites that outlive SO-D12 are named
        // against their write (DX-Q9, the census row): bond records insert
        // at the join and replace after it (SI-19, SI-20), the accrual row
        // is an intended upsert held to one row (SI-23), and curve-root
        // heights insert (SI-4). Pending until SO-D12's merged increment
        // deletes the other two, the pass bits and the witness rows
        // (`ARCHIVAL_SETTLEMENT_WRITER.md` §16.3).
        L14 pending,
        // L16: the as-of-height holdings fold is `holds_shard_at` (DRS-E4
        // commit 2), evaluated by this crate's `ChainView` walk over A1's
        // record and A2's slash-log rows; the store reads rows and folds
        // nothing. The falsifier holds the verdict's logged slash to what
        // the fold reads back.
        L16 by_construction(shekyl_archival_retention::holds_shard_at, "l16_the_slash_the_verdict_logs_is_what_the_held_at_height_fold_reads"),
        // 4.M Mempool admission — consensus-flagged rows. M2: the pool door
        // runs the full NIC set because it *is* the validator's per-slot
        // judgement at `Lone` (DRS-E5 PR-b b2); held by `shekyl-mempool`,
        // witnessed where the real spends live — the door and a block of
        // one agree, row for row.
        M2 held_by_store("shekyl-chain-ingest", "the_door_and_a_block_of_one_agree_on_every_spend"),
        // M8: the pool's verification cache — the `(reference, height,
        // root)` triple the proof verified against, held in memory and
        // consulted at a reconcile (b4); an open trusts no anchor from the
        // file. `form` never consults it (`E5-Q8`).
        M8 held_by_store("shekyl-chain-ingest", "a_reconcile_on_the_same_anchor_skips_the_proof_and_an_open_verifies_it"),
    }
}

census_rows! {
    /// The policy-flagged enforced census rows — the `P` denominator.
    ///
    /// One variant per `CONSENSUS_RULE_CENSUS.md` §4 row with flag `P` and
    /// bucket ≠ 3, in census order. Applied by `AdmissionPolicy` (DRS-E5);
    /// a `PolicyRow` cannot enter a `RuleCoverage` — the type forbids it.
    pub enum PolicyRow: Policy {
        // 4.M Mempool admission — policy-flagged rows. M3, M4 and M5 are
        // `policy_form`'s (the third call of the pool door, DRS-E5 PR-b b1).
        // CEN-M11 is deleted (bucket 3): redundant with M3, which refuses a
        // zero-fee transaction at the one door.
        // M1, M6 and M7 are the pool's own (`shekyl-mempool`, b2): a
        // duplicate is not judged; the chain's spent images (M6) and the
        // pool's (M7) are one I7 read through the decorator. Witnessed over
        // real spends in `shekyl-chain-ingest`.
        M1 held_by_store("shekyl-chain-ingest", "the_pool_holds_one_spender_per_image_refuses_duplicates_and_the_floor"),
        M3 implemented(crate::policy::M3),
        M4 implemented(crate::policy::M4),
        M5 implemented(crate::policy::M5),
        M6 held_by_store("shekyl-chain-ingest", "the_door_and_a_block_of_one_agree_on_every_spend"),
        M7 held_by_store("shekyl-chain-ingest", "the_pool_holds_one_spender_per_image_refuses_duplicates_and_the_floor"),
        // M9: the submit engine's seam over the Rust pool
        // (`shekyl_daemon_rpc::RustPoolShim`), prepared, not routed; its
        // commit is the pool door. Witnessed by the engine end to end.
        M9 held_by_store("shekyl-chain-ingest", "the_engine_submits_through_the_rust_pool_and_its_door"),
        // M10: the pool's eviction (b4) — the weight limit the chain
        // derives, the cheapest per weight first, the template's refusals;
        // no timer (an entry leaves when its reference leaves CEN-I11's
        // window, at the reconcile).
        M10 held_by_store("shekyl-mempool", "the_cheapest_leave_first_under_weight_pressure"),
    }
}
