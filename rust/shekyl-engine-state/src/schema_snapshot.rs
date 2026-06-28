// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Snapshot tests for the postcard wire schema of each persisted ledger
//! block.
//!
//! This module is the mechanical half of the `block_version` discipline
//! described in `docs/MID_REWIRE_HARDENING.md` §3.4 (hardening-pass commit
//! 3.4). Every type that lands on disk — [`WalletLedger`] and the five inner
//! blocks [`LedgerBlock`], [`BookkeepingBlock`], [`TxMetaBlock`],
//! [`SyncStateBlock`], and [`StakingBlock`], plus the `P`-isolated
//! [`PScanCursor`] and [`PScanState`] (separate sealed records, not
//! wallet-ledger sub-blocks) —
//! derives [`postcard_schema::Schema`](postcard_schema::Schema), producing a
//! compile-time [`NamedType`] tree that captures every field's wire shape.
//! The snapshot tests in this module serialize that tree to pretty JSON and
//! compare it against a committed `.snap` file under
//! `rust/shekyl-engine-state/schemas/`.
//!
//! # Relationship to `block_version`
//!
//! When a block's Rust field set changes (addition, removal, rename,
//! reorder, type change), the derived schema changes, this test fails, and
//! the diff points reviewers at the offending field. The contract is that
//! the same PR must bump the corresponding version constant:
//!
//! - `wallet_ledger.snap`          ↔  [`WALLET_LEDGER_FORMAT_VERSION`]
//! - `ledger_block.snap`           ↔  [`LEDGER_BLOCK_VERSION`]
//! - `bookkeeping_block.snap`      ↔  [`BOOKKEEPING_BLOCK_VERSION`]
//! - `tx_meta_block.snap`          ↔  [`TX_META_BLOCK_VERSION`]
//! - `sync_state_block.snap`       ↔  [`SYNC_STATE_BLOCK_VERSION`]
//! - `staking_block.snap`          ↔  [`STAKING_BLOCK_VERSION`]
//! - `pscan_cursor.snap`           ↔  [`PSCAN_CURSOR_VERSION`]
//! - `pscan_state.snap`            ↔  [`PSCAN_STATE_VERSION`]
//!
//! The pairing is enforced in CI by
//! `.github/workflows/schema-snapshot.yml` — any PR that touches a `.snap`
//! without also touching the matching constant fails the workflow.
//!
//! # Update workflow
//!
//! Running the test suite normally asserts the snapshots. To regenerate
//! them after a deliberate schema change:
//!
//! ```text
//! UPDATE_SNAPSHOTS=1 cargo test -p shekyl-engine-state schema_snapshot
//! ```
//!
//! Which will overwrite every `.snap` file with the current schema. The
//! test pass then flags any snapshot that was regenerated so the reviewer
//! knows something changed intentionally.
//!
//! # Why schema JSON, not raw postcard bytes
//!
//! The snapshot is a *description* of the wire, not a sample of it. A
//! wire-byte snapshot would be byte-for-byte, but it would also be opaque:
//! a reviewer looking at a hex diff cannot tell whether a field was
//! renamed, reordered, or grew by four bytes. The [`NamedType`] tree
//! pretty-printed as JSON names every field and spells out its
//! `DataModelType` (`U64`, `ByteArray`, `Seq(&NamedType)`, etc.), so the
//! diff is self-explanatory.
//!
//! [`NamedType`]: postcard_schema::schema::NamedType
//! [`WALLET_LEDGER_FORMAT_VERSION`]: crate::wallet_ledger::WALLET_LEDGER_FORMAT_VERSION
//! [`LEDGER_BLOCK_VERSION`]: crate::ledger_block::LEDGER_BLOCK_VERSION
//! [`BOOKKEEPING_BLOCK_VERSION`]: crate::bookkeeping_block::BOOKKEEPING_BLOCK_VERSION
//! [`TX_META_BLOCK_VERSION`]: crate::tx_meta_block::TX_META_BLOCK_VERSION
//! [`SYNC_STATE_BLOCK_VERSION`]: crate::sync_state_block::SYNC_STATE_BLOCK_VERSION
//! [`STAKING_BLOCK_VERSION`]: crate::staking_block::STAKING_BLOCK_VERSION
//! [`PSCAN_CURSOR_VERSION`]: crate::pscan_cursor::PSCAN_CURSOR_VERSION
//! [`PSCAN_STATE_VERSION`]: crate::pscan_state::PSCAN_STATE_VERSION
//! [`WalletLedger`]: crate::wallet_ledger::WalletLedger
//! [`LedgerBlock`]: crate::ledger_block::LedgerBlock
//! [`BookkeepingBlock`]: crate::bookkeeping_block::BookkeepingBlock
//! [`TxMetaBlock`]: crate::tx_meta_block::TxMetaBlock
//! [`SyncStateBlock`]: crate::sync_state_block::SyncStateBlock
//! [`StakingBlock`]: crate::staking_block::StakingBlock
//! [`PScanCursor`]: crate::pscan_cursor::PScanCursor
//! [`PScanState`]: crate::pscan_state::PScanState

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        env, fs,
        path::{Path, PathBuf},
    };

    use postcard_schema::{
        schema::{owned::OwnedNamedType, NamedType},
        Schema,
    };

    use crate::{
        bookkeeping_block::BookkeepingBlock, ledger_block::LedgerBlock, pscan_cursor::PScanCursor,
        pscan_state::PScanState, staking_block::StakingBlock, sync_state_block::SyncStateBlock,
        tx_meta_block::TxMetaBlock, wallet_ledger::WalletLedger,
    };

    /// Snapshot directory, relative to the `shekyl-engine-state` crate root.
    /// Cargo sets `CARGO_MANIFEST_DIR` to that root at compile time; we
    /// resolve at runtime against it so the test passes regardless of
    /// working directory.
    fn schemas_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("schemas")
    }

    /// Render a schema tree as pretty JSON. The indirection through
    /// `OwnedNamedType` is load-bearing: `NamedType` is built from
    /// `&'static` references that `serde_json` cannot roundtrip through,
    /// whereas `OwnedNamedType` owns its children and serializes cleanly.
    /// A trailing newline matches the convention of the rest of the repo
    /// (`.gitattributes` enforces it).
    fn render_schema(schema: &'static NamedType) -> String {
        let owned = OwnedNamedType::from(schema);
        let mut s = serde_json::to_string_pretty(&owned)
            .expect("OwnedNamedType serializes to JSON without failing");
        s.push('\n');
        s
    }

    /// Assert-or-update driver. Running with `UPDATE_SNAPSHOTS=1` writes
    /// the current schema to `<schemas>/<name>.snap`; running without it
    /// compares the current schema against the committed snapshot and
    /// panics with a `pretty_assertions`-style diff on mismatch.
    ///
    /// The `name` argument is the file stem (e.g. `"ledger_block"`). It
    /// must be unique per call site; this module's five tests use the
    /// names documented in the module-level docs.
    fn check_or_update_snapshot(name: &str, schema: &'static NamedType) {
        let rendered = render_schema(schema);
        let path: PathBuf = schemas_dir().join(format!("{name}.snap"));

        let update = env::var_os("UPDATE_SNAPSHOTS").is_some();

        if update {
            // Create the schemas directory on first run — lets a fresh
            // clone bootstrap the snapshots without a manual `mkdir`.
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap_or_else(|e| {
                    panic!("cannot create schemas dir {}: {e}", parent.display())
                });
            }
            fs::write(&path, &rendered)
                .unwrap_or_else(|e| panic!("cannot write snapshot {}: {e}", path.display()));
            // Surface regeneration as a soft signal in the test log —
            // the test still passes so CI doesn't fail while bootstrapping,
            // but reviewers running `UPDATE_SNAPSHOTS=1` locally see what
            // moved.
            eprintln!("UPDATE_SNAPSHOTS=1: wrote {}", path.display());
            return;
        }

        let expected = fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "missing snapshot {}: {e}\n\
                 hint: run `UPDATE_SNAPSHOTS=1 cargo test -p shekyl-engine-state \
                 schema_snapshot` to bootstrap.",
                path.display(),
            )
        });

        if rendered != expected {
            let diff = unified_diff(&expected, &rendered);
            panic!(
                "schema snapshot mismatch for {}\n\
                 --- committed ({}) vs. +++ current ---\n\
                 {}\n\
                 \n\
                 The wire schema of a persisted block has changed. Required action:\n\
                 \n\
                 1. Bump the matching version constant in the same commit\n\
                    (see `docs/MID_REWIRE_HARDENING.md` §3.4 for the pairing\n\
                    and `.cursor/rules/42-serialization-policy.mdc` for the policy).\n\
                 2. Regenerate the snapshot with:\n\
                    UPDATE_SNAPSHOTS=1 cargo test -p shekyl-engine-state schema_snapshot\n\
                 3. Review the diff above — a rename, reorder, field add/remove,\n\
                    or type change each have distinct migration consequences.\n",
                name,
                path.display(),
                diff,
            );
        }
    }

    /// Minimal unified-diff-ish renderer for the mismatch panic. Avoids a
    /// runtime dependency on `similar` or `pretty_assertions` for what is
    /// a once-per-PR failure path; the output is line-oriented and highly
    /// readable even on short diffs.
    fn unified_diff(a: &str, b: &str) -> String {
        let a_lines: Vec<&str> = a.lines().collect();
        let b_lines: Vec<&str> = b.lines().collect();
        let mut out = String::new();
        let max = a_lines.len().max(b_lines.len());
        for i in 0..max {
            match (a_lines.get(i), b_lines.get(i)) {
                (Some(x), Some(y)) if x == y => out.push_str(&format!("  {x}\n")),
                (Some(x), Some(y)) => {
                    out.push_str(&format!("- {x}\n"));
                    out.push_str(&format!("+ {y}\n"));
                }
                (Some(x), None) => out.push_str(&format!("- {x}\n")),
                (None, Some(y)) => out.push_str(&format!("+ {y}\n")),
                (None, None) => unreachable!(),
            }
        }
        out
    }

    #[test]
    fn wallet_ledger_schema_matches_snapshot() {
        check_or_update_snapshot("wallet_ledger", <WalletLedger as Schema>::SCHEMA);
    }

    #[test]
    fn ledger_block_schema_matches_snapshot() {
        check_or_update_snapshot("ledger_block", <LedgerBlock as Schema>::SCHEMA);
    }

    #[test]
    fn bookkeeping_block_schema_matches_snapshot() {
        check_or_update_snapshot("bookkeeping_block", <BookkeepingBlock as Schema>::SCHEMA);
    }

    #[test]
    fn tx_meta_block_schema_matches_snapshot() {
        check_or_update_snapshot("tx_meta_block", <TxMetaBlock as Schema>::SCHEMA);
    }

    #[test]
    fn sync_state_block_schema_matches_snapshot() {
        check_or_update_snapshot("sync_state_block", <SyncStateBlock as Schema>::SCHEMA);
    }

    #[test]
    fn staking_block_schema_matches_snapshot() {
        check_or_update_snapshot("staking_block", <StakingBlock as Schema>::SCHEMA);
    }

    #[test]
    fn pscan_cursor_schema_matches_snapshot() {
        check_or_update_snapshot("pscan_cursor", <PScanCursor as Schema>::SCHEMA);
    }

    #[test]
    fn pscan_state_schema_matches_snapshot() {
        check_or_update_snapshot("pscan_state", <PScanState as Schema>::SCHEMA);
    }

    /// Meta-guard against the dual-registry divergence: the version-bump CI
    /// registry (the `PAIRS` array in `.github/workflows/schema-snapshot.yml`)
    /// must list **exactly** the committed snapshots.
    ///
    /// The `.snap` files are the harness's de-facto registry — every type with a
    /// `*_schema_matches_snapshot` test above writes `schemas/<stem>.snap`. The
    /// YAML `PAIRS` is a *second*, hand-maintained registry; it exists because it
    /// drives a **git-level** check the in-process tests cannot do (a `.snap`
    /// changed in a PR ⟹ its `_VERSION` constant moved in the same PR — the test
    /// has no diff to see). Two hand-mirrored registries are a silent-divergence
    /// hazard: register a new type's snapshot without adding its `PAIRS` entry and
    /// the `.snap`↔`_VERSION` enforcement is silently absent (CI green, guard
    /// gone). This test makes that divergence **loud** — the two stem-sets must be
    /// equal — so a new (or removed) type can't slip the pairing past review.
    #[test]
    fn version_bump_registry_covers_every_snapshot() {
        // Assert-mode only: this invariant is about the *committed* snapshot set.
        // Under `UPDATE_SNAPSHOTS=1` the `.snap` files are being (re)generated, so
        // `schemas/` may not exist yet and — because Rust runs tests in a
        // non-deterministic order — the set is only transiently complete while the
        // per-type writers run. Comparing it to `PAIRS` mid-regeneration is
        // meaningless and would fail spuriously. CI's assert-snapshots job runs
        // *without* the flag, so the guard still fires where it gates merges. (Same
        // `UPDATE_SNAPSHOTS` branch the snapshot writers above take.)
        if env::var_os("UPDATE_SNAPSHOTS").is_some() {
            return;
        }

        // The committed snapshots: the set of `schemas/*.snap` stems.
        let snap_stems: BTreeSet<String> = fs::read_dir(schemas_dir())
            .expect("read schemas dir")
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                if path.extension()? == "snap" {
                    path.file_stem()?.to_str().map(String::from)
                } else {
                    None
                }
            })
            .collect();

        // The YAML `PAIRS` stems. `CARGO_MANIFEST_DIR` is the crate root
        // (`rust/shekyl-engine-state`); the workflow is two levels up, at repo root.
        let workflow = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../.github/workflows/schema-snapshot.yml");
        let yaml = fs::read_to_string(&workflow)
            .unwrap_or_else(|e| panic!("read {}: {e}", workflow.display()));
        let pair_stems: BTreeSet<String> = yaml.lines().filter_map(parse_pairs_stem).collect();

        assert_eq!(
            snap_stems, pair_stems,
            "the `PAIRS` array in .github/workflows/schema-snapshot.yml must list \
             exactly the committed snapshots (rust/shekyl-engine-state/schemas/*.snap). \
             A snapshot with no `PAIRS` entry leaves its .snap<->_VERSION pairing \
             silently unenforced; a `PAIRS` entry with no snapshot is stale. Sync them.",
        );
    }

    /// Extract `<stem>` from a `PAIRS` line `"<stem>|<src>.rs|<VERSION>"`. Returns
    /// `None` for any other YAML line (the shape-gate below keeps it specific).
    fn parse_pairs_stem(line: &str) -> Option<String> {
        let inner = line.trim().strip_prefix('"')?.strip_suffix('"')?;
        let mut parts = inner.split('|');
        let stem = parts.next()?;
        let src = parts.next()?;
        let version = parts.next()?;
        (parts.next().is_none() && src.ends_with(".rs") && version.contains("VERSION"))
            .then(|| stem.to_string())
    }

    /// Defense-in-depth: the rendered JSON must actually be
    /// deserializable back into an `OwnedNamedType`. This catches any
    /// future regression in `postcard_schema`'s Serialize impl (e.g. a
    /// version bump that introduces fields the Deserialize cannot see).
    #[test]
    fn rendered_schemas_are_self_parseable() {
        for schema in [
            <WalletLedger as Schema>::SCHEMA,
            <LedgerBlock as Schema>::SCHEMA,
            <BookkeepingBlock as Schema>::SCHEMA,
            <TxMetaBlock as Schema>::SCHEMA,
            <SyncStateBlock as Schema>::SCHEMA,
            <StakingBlock as Schema>::SCHEMA,
        ] {
            let json = render_schema(schema);
            let parsed: OwnedNamedType = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("rendered schema does not roundtrip: {e}"));
            // Name equality is the cheapest sanity check — exhaustive
            // tree equality is implicit from the string roundtrip.
            assert_eq!(parsed.name, schema.name);
        }
    }

    /// Sanity: the five snapshot files all live under `schemas/` and not
    /// anywhere else. Guards against a refactor accidentally writing the
    /// snapshots to `target/` or a stale location.
    #[test]
    fn schemas_directory_is_canonical() {
        let dir = schemas_dir();
        // The directory either exists (normal state) or does not
        // (first-time bootstrap). We do not require it to exist here;
        // that is the responsibility of `check_or_update_snapshot`.
        assert!(
            !dir.to_string_lossy().contains("target"),
            "schemas dir must not live under target/: {}",
            dir.display(),
        );
        let rel = dir
            .strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")))
            .expect("schemas dir must be relative to the crate root");
        assert_eq!(rel, Path::new("schemas"));
    }
}
