// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Snapshot tests for the postcard wire schema of each persisted ledger
//! block.
//!
//! This module is the mechanical half of the `block_version` discipline
//! described in `docs/MID_REWIRE_HARDENING.md` §3.4 (hardening-pass commit
//! 3.4). Every block type that lands on disk — [`WalletLedger`] and the
//! four inner blocks [`LedgerBlock`], [`BookkeepingBlock`], [`TxMetaBlock`],
//! and [`SyncStateBlock`] — derives
//! [`postcard_schema::Schema`](postcard_schema::Schema), producing a
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
//! [`WalletLedger`]: crate::wallet_ledger::WalletLedger
//! [`LedgerBlock`]: crate::ledger_block::LedgerBlock
//! [`BookkeepingBlock`]: crate::bookkeeping_block::BookkeepingBlock
//! [`TxMetaBlock`]: crate::tx_meta_block::TxMetaBlock
//! [`SyncStateBlock`]: crate::sync_state_block::SyncStateBlock

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        path::{Path, PathBuf},
    };

    use postcard_schema::{
        schema::{owned::OwnedNamedType, NamedType},
        Schema,
    };

    use crate::{
        bookkeeping_block::BookkeepingBlock, ledger_block::LedgerBlock,
        sync_state_block::SyncStateBlock, tx_meta_block::TxMetaBlock, wallet_ledger::WalletLedger,
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
