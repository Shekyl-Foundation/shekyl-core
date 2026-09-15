// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The rule-42 codec gate for the chain store.
//!
//! One committed fixture snapshot per [`Canonical`] impl under
//! `rust/shekyl-chain-store/schemas/<NAME>.snap`: the codec's name and
//! width, then representative values with their canonical encodings in
//! hex. The per-codec tests re-encode the fixtures and compare against the
//! committed text, then decode the encoding back and compare against the
//! value, so both directions are pinned to the bytes reviewers approved.
//!
//! # Why a fixture KAT and not a type schema
//!
//! The wallet's gate (`shekyl-engine-state/src/schema_snapshot.rs`)
//! snapshots a derived `postcard` schema, because there the *derive* is
//! the encoding. Here the encodings are written by hand and the digest
//! folds them (`DAEMON_REDB_STORE.md` §11.1(b)), so what must not move is
//! the **bytes**, and the snapshot is of bytes.
//!
//! # The table catalogue is a snapshot too
//!
//! §11.1(b) owes a version bump for a table added, removed or re-keyed,
//! not only for a codec whose bytes moved — and none of those touch a
//! codec fixture. So `schemas/tables.snap` pins [`schema::catalogue`]: one
//! row per definition with its name, shape and the key/value `TypeName`s
//! redb checks at `open_table`. A layout change of that kind moves this
//! text and enters the same paired-bump gate as the codec bytes.
//!
//! # One version, so the pairing is a glob
//!
//! Every codec in this crate pairs with the same constant —
//! [`SCHEMA_VERSION`] — because the store has one layout version
//! (§11.1(a)). `.github/workflows/schema-snapshot.yml` therefore enforces
//! *any change under `schemas/` ⟹ the value `SCHEMA_VERSION` is declared
//! with increased in the same PR*, with no per-codec registry to keep in
//! sync. What this module still has to guard is that the snapshot **set**
//! is the impl set plus the catalogue ([`every_canonical_impl_has_a_snapshot`])
//! and that the workflow is actually wired to this crate — runs this whole
//! module, and parses the declaration in the grammar it is written in
//! ([`workflow_gates_this_crate`]). A gate whose subject is absent is not a
//! gate (rule 47).
//!
//! # Regenerating
//!
//! ```text
//! UPDATE_SNAPSHOTS=1 cargo test -p shekyl-chain-store codec::snapshot_tests
//! ```
//!
//! then bump [`SCHEMA_VERSION`] in `src/codec/schema_version.rs` and re-run
//! **without** the variable. [`codec_snapshot_assertions_are_armed`] fails
//! while it is set, so a regeneration run can never pass as an assertion
//! run.

// Whole-file test module: the parent already gates it with
// `#[cfg(test)] mod snapshot_tests;`, and this inner marker is how the
// file declares the same thing to `build.yml`'s debug-macro lint, whose
// scan keys on the first `#[cfg(test)]` / `#![cfg(test)]` in the file. The
// regeneration driver's `eprintln!` is test-only output and must not read
// as production.
#![cfg(test)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::apply_policy::ArchivalFamily;
use crate::family_set::FamilySet;
use crate::lmdb_order::Hash32;
use crate::schema::{self, TableShape};

use super::{Canonical, SchemaVersion, SCHEMA_VERSION};

/// The stem of the table-catalogue snapshot under `schemas/`. Not a codec
/// name; [`every_canonical_impl_has_a_snapshot`] holds the two namespaces
/// apart.
const TABLE_CATALOGUE_SNAP: &str = "tables";

/// The `cargo test` filter that selects exactly this module — what the
/// workflow's assert job runs. Pinned here so [`workflow_gates_this_crate`]
/// can hold the workflow to it and hold it to `module_path!()`.
const TEST_FILTER: &str = "codec::snapshot_tests";

const SNAPSHOT_HEADER: &str =
    "# shekyl-chain-store canonical codec snapshot (rule 42). Do not edit by hand:\n\
     #   UPDATE_SNAPSHOTS=1 cargo test -p shekyl-chain-store codec::snapshot_tests\n\
     # and bump SCHEMA_VERSION in src/codec/schema_version.rs in the same PR.\n";

/// A codec's representative values.
trait Fixtures: Canonical + PartialEq + core::fmt::Debug {
    fn fixtures() -> Vec<(&'static str, Self)>;
}

impl Fixtures for u8 {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![("zero", 0), ("one", 1), ("high_bit", 0x80), ("max", 0xff)]
    }
}

impl Fixtures for u64 {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            ("zero", 0),
            ("one", 1),
            // Every byte distinct, so the snapshot is a byte-order witness:
            // a big-endian regression reads `0807060504030201` here.
            ("byte_order", 0x0102_0304_0506_0708),
            ("max", u64::MAX),
        ]
    }
}

impl Fixtures for Hash32 {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            ("zero", Hash32::from_bytes([0; 32])),
            (
                "ascending",
                Hash32::from_bytes(core::array::from_fn(|i| {
                    u8::try_from(i).expect("32 indices fit a byte")
                })),
            ),
            ("max", Hash32::from_bytes([0xff; 32])),
        ]
    }
}

impl Fixtures for SchemaVersion {
    fn fixtures() -> Vec<(&'static str, Self)> {
        // Literals, not `SCHEMA_VERSION`: the snapshot pins the *codec*,
        // and must not move just because the version it pairs with did.
        vec![
            ("zero", SchemaVersion::new(0)),
            ("one", SchemaVersion::new(1)),
            ("byte_order", SchemaVersion::new(0x0102_0304_0506_0708)),
        ]
    }
}

impl Fixtures for FamilySet {
    fn fixtures() -> Vec<(&'static str, Self)> {
        let mut fixtures = vec![("empty", FamilySet::EMPTY)];
        // One-hot per family, labelled by the table it owns, in X-macro
        // order: the snapshot IS the family→bit assignment. A persisted
        // provenance mask is only readable while that assignment holds,
        // and the `all` mask cannot see two families swap places, so every
        // bit needs its own row.
        fixtures.extend(
            ArchivalFamily::ALL
                .iter()
                .map(|&family| (family.table(), FamilySet::of(&[family]))),
        );
        fixtures.extend([
            // Composition: two one-hots OR together, duplicates collapse.
            (
                "bond_and_slash_log",
                FamilySet::of(&[ArchivalFamily::Bond, ArchivalFamily::SlashLog]),
            ),
            // Pins the family COUNT too: adding a family widens this mask.
            ("all", FamilySet::ALL),
        ]);
        fixtures
    }
}

/// The type name as written after `impl Canonical for`, for the source scan.
fn type_name<T>() -> &'static str {
    core::any::type_name::<T>()
        .rsplit("::")
        .next()
        .expect("type_name is non-empty")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Render the snapshot text, having first held every fixture to the width
/// the codec declares. `fixed_width = n` in the header is a claim the
/// fixtures below it must witness: a codec declaring `Some(n)` while
/// emitting another length would otherwise round-trip, snapshot, and
/// still break the fixed-width storage contract (`DAEMON_REDB_STORE.md`
/// §11.1(b)). Checked in regeneration runs too — it is a property of the
/// codec, not of the committed text.
fn render<T: Fixtures>() -> String {
    let fixtures = T::fixtures();
    let mut labels = BTreeSet::new();
    for (label, value) in &fixtures {
        assert!(
            labels.insert(*label),
            "{}: duplicate fixture label `{label}`",
            T::NAME
        );
        let encoded = value.encode();
        if let Some(width) = T::FIXED_WIDTH {
            assert_eq!(
                encoded.len(),
                width,
                "{}: fixture `{label}` encodes to {} bytes but the codec declares \
                 FIXED_WIDTH = Some({width})",
                T::NAME,
                encoded.len(),
            );
        }
    }

    let mut out = String::from(SNAPSHOT_HEADER);
    out.push_str(&format!("codec = {}\n", T::NAME));
    match T::FIXED_WIDTH {
        Some(n) => out.push_str(&format!("fixed_width = {n}\n")),
        None => out.push_str("fixed_width = variable\n"),
    }
    out.push_str("[fixtures]\n");
    for (label, value) in &fixtures {
        out.push_str(&format!("{label} = {}\n", hex(&value.encode())));
    }
    out
}

/// Render the table catalogue: one row per definition, sorted by name
/// (redb addresses tables by name; declaration order is not layout), as
/// `name = shape<key, value>` in the `TypeName`s redb records on disk.
fn render_table_catalogue() -> String {
    let catalogue = schema::catalogue();
    assert!(!catalogue.is_empty(), "schema::catalogue() is empty");
    let mut rows = BTreeMap::new();
    for spec in &catalogue {
        let shape = match spec.shape {
            TableShape::Map => "map",
            TableShape::Multimap => "multimap",
        };
        let row = format!("{shape}<{}, {}>", spec.key.name(), spec.value.name());
        assert!(
            rows.insert(spec.name.as_str(), row).is_none(),
            "duplicate table name `{}` in schema::catalogue()",
            spec.name
        );
    }
    let mut out = String::from(SNAPSHOT_HEADER);
    out.push_str(&format!("tables = {}\n[tables]\n", rows.len()));
    for (name, row) in rows {
        out.push_str(&format!("{name} = {row}\n"));
    }
    out
}

fn schemas_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas")
}

fn snapshot_path(stem: &str) -> PathBuf {
    schemas_dir().join(format!("{stem}.snap"))
}

/// What the driver did with a rendered snapshot.
enum Snapshot {
    /// `UPDATE_SNAPSHOTS` is set: the file was (re)written, nothing asserted.
    Written,
    /// The file exists and equals the rendering.
    Matched,
}

/// Assert-or-update driver, the same shape as the wallet's. `what` names
/// the subject in the failure text; `consequence` says what a mismatch
/// means for the store.
fn check_or_update(stem: &str, rendered: &str, what: &str, consequence: &str) -> Snapshot {
    let path = snapshot_path(stem);

    if env::var_os("UPDATE_SNAPSHOTS").is_some() {
        fs::create_dir_all(schemas_dir()).expect("create schemas dir");
        fs::write(&path, rendered)
            .unwrap_or_else(|e| panic!("cannot write snapshot {}: {e}", path.display()));
        eprintln!("UPDATE_SNAPSHOTS=1: wrote {}", path.display());
        return Snapshot::Written;
    }

    let committed = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing snapshot {}: {e}\n\
             hint: `UPDATE_SNAPSHOTS=1 cargo test -p shekyl-chain-store codec::snapshot_tests` \
             to bootstrap, then bump SCHEMA_VERSION.",
            path.display()
        )
    });
    assert!(
        rendered == committed,
        "snapshot mismatch for {what}\n\
         --- committed ({}) vs. +++ current ---\n{}\n\
         {consequence} That is a layout change (DAEMON_REDB_STORE.md §11.1(b)) and\n\
         a rebuild for every existing store. If intentional:\n\
         \n\
           1. bump SCHEMA_VERSION in src/codec/schema_version.rs in the same commit;\n\
           2. regenerate: UPDATE_SNAPSHOTS=1 cargo test -p shekyl-chain-store codec::snapshot_tests\n\
           3. review the diff above.\n",
        path.display(),
        unified_diff(&committed, rendered),
    );
    Snapshot::Matched
}

fn check_or_update_snapshot<T: Fixtures>() {
    let rendered = render::<T>();
    if let Snapshot::Written = check_or_update(
        T::NAME,
        &rendered,
        &format!("codec `{}`", T::NAME),
        "The canonical encoding of a stored value has changed — digest-visible.",
    ) {
        return;
    }

    // The committed bytes decode back to the values that produced them.
    for (label, value) in T::fixtures() {
        let decoded = T::decode(&value.encode())
            .unwrap_or_else(|e| panic!("{}: fixture `{label}` does not decode: {e}", T::NAME));
        assert_eq!(decoded, value, "{}: fixture `{label}` round-trip", T::NAME);
    }
}

/// The table catalogue snapshot (`schemas/tables.snap`).
#[test]
fn table_catalogue_snapshot() {
    let rendered = render_table_catalogue();
    let _ = check_or_update(
        TABLE_CATALOGUE_SNAP,
        &rendered,
        "the table catalogue (schema.rs)",
        "A table was added, removed, renamed or re-typed.",
    );
}

/// Source scan: every `TableDefinition::new(` / `MultimapTableDefinition::new(`
/// in `schema.rs` is in [`schema::catalogue`]. The `tables!` macro
/// catalogues everything declared through it; this catches a definition
/// declared beside it, which the snapshot above could not see.
#[test]
fn every_table_definition_is_catalogued() {
    let text = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/schema.rs"))
        .expect("read schema.rs");
    let declared: BTreeSet<String> = text
        .lines()
        .filter_map(|line| {
            let (_, rest) = line.split_once("TableDefinition::new(\"")?;
            rest.split_once('"').map(|(name, _)| name.to_owned())
        })
        .collect();
    assert!(
        !declared.is_empty(),
        "schema.rs: no table definitions parsed"
    );
    let catalogued: BTreeSet<String> = schema::catalogue().into_iter().map(|s| s.name).collect();
    assert_eq!(
        declared, catalogued,
        "every table definition in schema.rs must be declared inside `tables!` so it is catalogued"
    );
}

fn unified_diff(a: &str, b: &str) -> String {
    let a: Vec<&str> = a.lines().collect();
    let b: Vec<&str> = b.lines().collect();
    let mut out = String::new();
    for i in 0..a.len().max(b.len()) {
        match (a.get(i), b.get(i)) {
            (Some(x), Some(y)) if x == y => out.push_str(&format!("  {x}\n")),
            (Some(x), Some(y)) => {
                out.push_str(&format!("- {x}\n"));
                out.push_str(&format!("+ {y}\n"));
            }
            (Some(x), None) => out.push_str(&format!("- {x}\n")),
            (None, Some(y)) => out.push_str(&format!("+ {y}\n")),
            (None, None) => unreachable!("i < max(len)"),
        }
    }
    out
}

/// Every codec with a snapshot, in one place. [`every_canonical_impl_has_a_snapshot`]
/// holds this list equal to the `impl Canonical for` set in the source tree.
macro_rules! snapshotted_codecs {
    ($($ty:ty => $test:ident),* $(,)?) => {
        $(
            #[test]
            fn $test() {
                check_or_update_snapshot::<$ty>();
            }
        )*

        fn snapshotted() -> Vec<(&'static str, &'static str)> {
            vec![$((type_name::<$ty>(), <$ty as Canonical>::NAME)),*]
        }
    };
}

snapshotted_codecs! {
    u8 => codec_snapshot_u8,
    u64 => codec_snapshot_u64,
    Hash32 => codec_snapshot_hash32,
    SchemaVersion => codec_snapshot_schema_version,
    FamilySet => codec_snapshot_family_set,
}

/// The gate asserts its own arming state (rule 47). `UPDATE_SNAPSHOTS`
/// disarms every comparison above into a write; a run with it set must
/// fail somewhere, or a regeneration run is indistinguishable from a
/// green one.
#[test]
fn codec_snapshot_assertions_are_armed() {
    assert!(
        env::var_os("UPDATE_SNAPSHOTS").is_none(),
        "UPDATE_SNAPSHOTS is set: every codec snapshot test in this module \
         OVERWROTE its `.snap` instead of comparing. Snapshots were regenerated; \
         re-run WITHOUT the variable to assert them."
    );
}

/// Source scan: the set of `impl Canonical for <T>` in `src/` equals the
/// set registered in [`snapshotted_codecs!`], and the committed `.snap`
/// files are exactly that set's names plus the table catalogue. A codec
/// cannot be added without a fixture, and a deleted codec cannot leave an
/// orphan snapshot behind.
#[test]
fn every_canonical_impl_has_a_snapshot() {
    if env::var_os("UPDATE_SNAPSHOTS").is_some() {
        return;
    }
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut impls = BTreeSet::new();
    scan_impls(&src, &mut impls);
    let registered: BTreeSet<&str> = snapshotted().into_iter().map(|(ty, _)| ty).collect();
    assert_eq!(
        impls.iter().map(String::as_str).collect::<BTreeSet<_>>(),
        registered,
        "every `impl Canonical for T` under src/ must appear in `snapshotted_codecs!` \
         (and vice versa) so it has a committed fixture snapshot"
    );

    let mut names: BTreeSet<&str> = snapshotted().into_iter().map(|(_, name)| name).collect();
    assert_eq!(
        names.len(),
        registered.len(),
        "Canonical::NAME must be unique per codec"
    );
    assert!(
        names.insert(TABLE_CATALOGUE_SNAP),
        "a codec is NAMEd `{TABLE_CATALOGUE_SNAP}`, which is the table catalogue's snapshot stem"
    );
    let snaps: BTreeSet<String> = fs::read_dir(schemas_dir())
        .expect("read schemas dir")
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            (path.extension()? == "snap").then(|| path.file_stem()?.to_str().map(String::from))?
        })
        .collect();
    assert_eq!(
        snaps.iter().map(String::as_str).collect::<BTreeSet<_>>(),
        names,
        "rust/shekyl-chain-store/schemas/*.snap must be exactly the registered codecs' NAMEs \
         plus `{TABLE_CATALOGUE_SNAP}.snap`"
    );
}

fn scan_impls(dir: &Path, out: &mut BTreeSet<String>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            scan_impls(&path, out);
            continue;
        }
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("read source");
        for line in text.lines() {
            let Some(rest) = line.trim_start().strip_prefix("impl") else {
                continue;
            };
            assert!(
                !rest.starts_with('<') || !rest.contains("Canonical for"),
                "{}: a generic `impl<..> Canonical for` needs an explicit snapshot policy",
                path.display()
            );
            let Some(rest) = rest.strip_prefix(" Canonical for ") else {
                continue;
            };
            let ty: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            assert!(
                !ty.is_empty(),
                "{}: unparsable impl line {line:?}",
                path.display()
            );
            assert!(
                out.insert(ty.clone()),
                "duplicate `impl Canonical for {ty}`"
            );
        }
    }
}

/// The grammar the workflow parses `SCHEMA_VERSION` out of: the declaration
/// at column 0, the value a decimal literal inside `SchemaVersion::new(…)`.
/// The workflow's `sed` carries the same regex; both are pinned below.
const DECL_PREFIX: &str = "pub const SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(";
const WORKFLOW_VERSION_REGEX: &str = r"SchemaVersion::new\(([0-9_]+)\)";

/// The workflow gates this crate: its trigger paths include the crate, its
/// assert job runs **this module** (the filter it uses selects
/// `module_path!()`, so the meta-tests run with the assertions), and its
/// paired-bump job names this crate's snapshot directory and version
/// constant and parses that constant in the grammar it is declared in.
/// Without this, the gate could be silently unwired — or narrowed to the
/// per-codec tests — by a workflow edit and every test here would still
/// pass.
#[test]
fn workflow_gates_this_crate() {
    let workflow =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/schema-snapshot.yml");
    let yaml = fs::read_to_string(&workflow)
        .unwrap_or_else(|e| panic!("read {}: {e}", workflow.display()));
    let run_line = format!("cargo test -p shekyl-chain-store {TEST_FILTER}");
    for needle in [
        "- \"rust/shekyl-chain-store/**\"",
        run_line.as_str(),
        "rust/shekyl-chain-store/schemas/",
        "rust/shekyl-chain-store/src/codec/schema_version.rs",
        "SCHEMA_VERSION",
        WORKFLOW_VERSION_REGEX,
    ] {
        assert!(
            yaml.contains(needle),
            "{} does not contain {needle:?}; the codec gate is not wired",
            workflow.display()
        );
    }
    // The filter the workflow runs is a substring of every test path in
    // this module and of nothing narrower: it selects the meta-tests too.
    assert!(
        module_path!().ends_with(TEST_FILTER),
        "TEST_FILTER {TEST_FILTER:?} does not select this module ({})",
        module_path!()
    );

    // The constant the workflow parses is declared in the grammar it parses:
    // the same extraction here yields the compiled value.
    let decl = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/codec/schema_version.rs"),
    )
    .expect("read schema_version.rs");
    let declared: Vec<u64> = decl
        .lines()
        .filter_map(|l| l.strip_prefix(DECL_PREFIX))
        .map(|rest| {
            let digits: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '_')
                .filter(|c| *c != '_')
                .collect();
            digits.parse().unwrap_or_else(|e| {
                panic!("SCHEMA_VERSION literal {digits:?} is not a decimal u64: {e}")
            })
        })
        .collect();
    assert_eq!(
        declared,
        vec![SCHEMA_VERSION.get()],
        "src/codec/schema_version.rs must declare SCHEMA_VERSION exactly once, at column 0, \
         as `{DECL_PREFIX}<decimal>);` — the workflow's paired-bump job parses the value \
         from that line at the PR's base and head and requires it to increase"
    );

    // A constant's doc is part of the edit (rule 91): the History list on
    // the declaration must name the current version.
    let entry = format!("/// - `{}` —", SCHEMA_VERSION.get());
    assert!(
        decl.contains(&entry),
        "src/codec/schema_version.rs: the History list has no entry {entry:?} for the \
         current SCHEMA_VERSION; record what changed when you bump"
    );
}
