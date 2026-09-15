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
//! # One version, so the pairing is a glob
//!
//! Every codec in this crate pairs with the same constant —
//! [`SCHEMA_VERSION`] — because the store has one layout version
//! (§11.1(a)). `.github/workflows/schema-snapshot.yml` therefore enforces
//! *any change under `schemas/` ⟹ the `SCHEMA_VERSION` declaration line
//! moved in the same PR*, with no per-codec registry to keep in sync. What
//! this module still has to guard is that the snapshot **set** is the impl
//! set ([`every_canonical_impl_has_a_snapshot`]) and that the workflow is
//! actually wired to this crate ([`workflow_gates_this_crate`]) — a gate
//! whose subject is absent is not a gate (rule 47).
//!
//! # Regenerating
//!
//! ```text
//! UPDATE_SNAPSHOTS=1 cargo test -p shekyl-chain-store codec_snapshot
//! ```
//!
//! then bump [`SCHEMA_VERSION`] in `src/codec/schema_version.rs` and re-run
//! **without** the variable. [`snapshot_assertions_are_armed`] fails while
//! it is set, so a regeneration run can never pass as an assertion run.

// Whole-file test module: the parent already gates it with
// `#[cfg(test)] mod snapshot_tests;`, and this inner marker is how the
// file declares the same thing to `build.yml`'s debug-macro lint, whose
// scan keys on the first `#[cfg(test)]` / `#![cfg(test)]` in the file. The
// regeneration driver's `eprintln!` is test-only output and must not read
// as production.
#![cfg(test)]

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::apply_policy::ArchivalFamily;
use crate::family_set::FamilySet;
use crate::lmdb_order::Hash32;

use super::{Canonical, SchemaVersion, SCHEMA_VERSION};

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
        vec![
            ("empty", FamilySet::EMPTY),
            ("first_family", FamilySet::of(&[ArchivalFamily::ALL[0]])),
            (
                "bond_and_slash_log",
                FamilySet::of(&[ArchivalFamily::Bond, ArchivalFamily::SlashLog]),
            ),
            // Pins the family COUNT too: adding a family widens this mask.
            ("all", FamilySet::ALL),
        ]
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

fn render<T: Fixtures>() -> String {
    let mut out = String::new();
    out.push_str(
        "# shekyl-chain-store canonical codec snapshot (rule 42). Do not edit by hand:\n\
         #   UPDATE_SNAPSHOTS=1 cargo test -p shekyl-chain-store codec_snapshot\n\
         # and bump SCHEMA_VERSION in src/codec/schema_version.rs in the same PR.\n",
    );
    out.push_str(&format!("codec = {}\n", T::NAME));
    match T::FIXED_WIDTH {
        Some(n) => out.push_str(&format!("fixed_width = {n}\n")),
        None => out.push_str("fixed_width = variable\n"),
    }
    out.push_str("[fixtures]\n");
    for (label, value) in T::fixtures() {
        out.push_str(&format!("{label} = {}\n", hex(&value.encode())));
    }
    out
}

fn schemas_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas")
}

fn snapshot_path<T: Canonical>() -> PathBuf {
    schemas_dir().join(format!("{}.snap", T::NAME))
}

/// Assert-or-update driver, the same shape as the wallet's.
fn check_or_update_snapshot<T: Fixtures>() {
    let rendered = render::<T>();
    let path = snapshot_path::<T>();

    if env::var_os("UPDATE_SNAPSHOTS").is_some() {
        fs::create_dir_all(schemas_dir()).expect("create schemas dir");
        fs::write(&path, &rendered)
            .unwrap_or_else(|e| panic!("cannot write snapshot {}: {e}", path.display()));
        eprintln!("UPDATE_SNAPSHOTS=1: wrote {}", path.display());
        return;
    }

    let committed = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing snapshot {}: {e}\n\
             hint: `UPDATE_SNAPSHOTS=1 cargo test -p shekyl-chain-store codec_snapshot` \
             to bootstrap, then bump SCHEMA_VERSION.",
            path.display()
        )
    });
    assert!(
        rendered == committed,
        "codec snapshot mismatch for `{}`\n\
         --- committed ({}) vs. +++ current ---\n{}\n\
         The canonical encoding of a stored value has changed. That is a layout\n\
         change (DAEMON_REDB_STORE.md §11.1(b)), digest-visible, and a rebuild for\n\
         every existing store. If intentional:\n\
         \n\
           1. bump SCHEMA_VERSION in src/codec/schema_version.rs in the same commit;\n\
           2. regenerate: UPDATE_SNAPSHOTS=1 cargo test -p shekyl-chain-store codec_snapshot\n\
           3. review the diff above.\n",
        T::NAME,
        path.display(),
        unified_diff(&committed, &rendered),
    );

    // The committed bytes decode back to the values that produced them.
    for (label, value) in T::fixtures() {
        let decoded = T::decode(&value.encode())
            .unwrap_or_else(|e| panic!("{}: fixture `{label}` does not decode: {e}", T::NAME));
        assert_eq!(decoded, value, "{}: fixture `{label}` round-trip", T::NAME);
    }
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
/// files are exactly that set's names. A codec cannot be added without a
/// fixture, and a deleted codec cannot leave an orphan snapshot behind.
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

    let names: BTreeSet<&str> = snapshotted().into_iter().map(|(_, name)| name).collect();
    assert_eq!(
        names.len(),
        registered.len(),
        "Canonical::NAME must be unique per codec"
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
        "rust/shekyl-chain-store/schemas/*.snap must be exactly the registered codecs' NAMEs"
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

/// The workflow gates this crate: its trigger paths include the crate, its
/// assert job runs these tests, and its paired-bump job names this crate's
/// snapshot directory and version constant. Without this, the gate could
/// be silently unwired by a workflow edit and every test here would still
/// pass.
#[test]
fn workflow_gates_this_crate() {
    let workflow =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/schema-snapshot.yml");
    let yaml = fs::read_to_string(&workflow)
        .unwrap_or_else(|e| panic!("read {}: {e}", workflow.display()));
    for needle in [
        "- \"rust/shekyl-chain-store/**\"",
        "cargo test -p shekyl-chain-store codec_snapshot",
        "rust/shekyl-chain-store/schemas/",
        "rust/shekyl-chain-store/src/codec/schema_version.rs",
        "SCHEMA_VERSION",
    ] {
        assert!(
            yaml.contains(needle),
            "{} does not contain {needle:?}; the codec gate is not wired",
            workflow.display()
        );
    }
    // The constant the workflow greps for is declared in the shape it greps.
    let decl = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/codec/schema_version.rs"),
    )
    .expect("read schema_version.rs");
    assert!(
        decl.lines()
            .any(|l| l.starts_with("pub const SCHEMA_VERSION:")),
        "SCHEMA_VERSION must be declared as `pub const SCHEMA_VERSION: ...` at column 0 \
         so the workflow's `^[-+]pub const SCHEMA_VERSION\\s*:` diff grep can see a bump"
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
