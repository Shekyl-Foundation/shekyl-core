// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The bundle rows' census registration, and the falsifier that the
//! verifier is still staged.
//!
//! Sibling of `bundle_tests` and `bundle_section_tests`. Every test names
//! the edit that turns it red.

use std::path::{Path, PathBuf};

use shekyl_archival_retention::{BundleRef, PassBitmap};
use shekyl_types::BlockHeight;

use super::*;

/// One reference of `count` draws, for a charge that only needs a count.
fn reference_of(count: u32) -> BundleRef {
    BundleRef::new(
        shekyl_archival_retention::BundleKept {
            h: BlockHeight::from_raw(100),
            seed: [0x5E; 32],
            passes: PassBitmap::from_passes(count, []).expect("no passes"),
            support: PassBitmap::none(),
        },
        [0xAB; 32],
    )
}

/// Every refusal names its census row, and a record's refusal its draw.
/// Red edit: move an arm to another row in `BundleInvalid::row`.
#[test]
fn every_refusal_names_its_census_row() {
    use BundleInvalid as B;
    assert_eq!(
        SectionRefused::OutOfOrder { position: 1 }.row(),
        CenRow::J29
    );
    assert_eq!(SectionRefused::Root.row(), CenRow::J29);
    assert_eq!(SectionRefused::Malformed { position: 0 }.row(), CenRow::J29);
    assert_eq!(
        SectionRefused::OverBudget {
            charge: SectionCharge::of(std::slice::from_ref(&reference_of(3))),
            budget: shekyl_archival_retention::SectionBudget::from_draws(2)
        }
        .row(),
        CenRow::J30
    );
    assert_eq!(
        SectionRefused::TooManyReferences { found: usize::MAX }.row(),
        CenRow::J29
    );
    assert_eq!(
        SectionRefused::OutsideWindow { position: 0 }.row(),
        CenRow::J31
    );
    let rows: [(B, CenRow, Option<u32>); 10] = [
        (B::OutsideWindow, CenRow::J31, None),
        (B::AlreadyRevealed, CenRow::J31, None),
        (B::BodyMalformed, CenRow::J32, None),
        (B::Count, CenRow::J32, None),
        (B::RecordCount, CenRow::J32, None),
        (B::Commitment, CenRow::J33, None),
        (B::WitnessSignature, CenRow::J34, None),
        (B::Attempt { draw: 7 }, CenRow::J35, Some(7)),
        (B::Anchor { draw: 8 }, CenRow::J36, Some(8)),
        (B::Receipt { draw: 9 }, CenRow::J37, Some(9)),
    ];
    for (refusal, row, draw) in rows {
        assert_eq!(refusal.row(), row, "{refusal:?}");
        assert_eq!(refusal.draw(), draw, "{refusal:?}");
        assert!(
            refusal.to_string().starts_with(row.as_str()),
            "{refusal}: the message leads with the row"
        );
    }
}

/// The rows are registered `pending`: in the denominator and bound to no
/// rule type, so no verdict's coverage holds them. Red edit: flip one to
/// `implemented(...)` without wiring it — and this test is then the
/// cutover's to delete, with the next one.
#[test]
fn the_bundle_rows_are_pending_until_the_cutover() {
    use crate::census::RowStatus;
    for row in [
        CenRow::J29,
        CenRow::J30,
        CenRow::J31,
        CenRow::J32,
        CenRow::J33,
        CenRow::J34,
        CenRow::J35,
        CenRow::J36,
        CenRow::J37,
    ] {
        assert_eq!(row.status(), RowStatus::Pending, "{row}");
    }
}

/// **The falsifier of this module's STAGED disposition** (rule 23): no
/// source of this crate on the connect path names the bundle verifier.
///
/// The walk is every `src/**/*.rs` of the crate, so a file added to the
/// connect path tomorrow — a segment beside `header_ladder.rs`, a rule —
/// is judged by default; a list of files would judge yesterday's. What is
/// exempt, and why:
///
/// - `*_tests.rs`: `cfg(test)`, and the bundle's own tests name the
///   subject.
/// - `harness.rs` and `harness/`: the fixture that implements
///   `BundleView` for these tests — `cfg(test)` or the `harness` feature,
///   never on the production surface.
/// - `archival/bundle.rs`, `archival/bundle_records.rs` and
///   `archival/bundle_section.rs`: the module under test. The section
///   file is exempt only while it still holds the section checker, and
///   the record file only while it still holds the shared pass check;
///   the test asserts both, so deleting a file or emptying it is red.
/// - `census.rs`: the registry's comment on the nine `pending` rows names
///   the functions as the rows' refusals. It is held to a narrower check
///   instead: no `implemented`, `enforced_at` or `by_construction` entry
///   names the bundle module, which is what wiring would look like there.
///
/// Two files export the surface and are judged with that one `pub use`
/// removed: `archival/mod.rs` and `lib.rs`. The rest of each — including
/// `transition` — must not name it.
///
/// The subject is asserted, not counted: each file the connect path runs
/// through today is required by name, with the identifier it is read for,
/// so the walk cannot shrink or move without this test saying so.
///
/// Bites against the verifier being wired into a block path without the
/// module's banner, the census rows' status and the specification's §2
/// moving with it. Does not cover a caller outside this crate: the store
/// and the ingest driver are other crates, and `SO-D12`'s cutover is where
/// they change. The bundle queue (increment 4c) is such a caller, live in
/// the ingest connector; it judges against the tip and is not the connect
/// path, so it does not move this test. The cutover deletes this test in
/// the change that wires the rule.
#[test]
fn nothing_on_the_connect_path_calls_the_bundle_verifier() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let files = connect_path_sources(&src);
    let names: &[&str] = &[
        "verify_bundle",
        "check_section",
        "open_body",
        "open_reference",
        "BundleView",
        "judge_bundles",
        "draw_targets",
    ];

    // Rule 47: the connect path's files, by name, each with the identifier
    // it is read for. A move or a rename is a red test, not a shorter walk.
    let required: &[(&str, &str)] = &[
        ("validate.rs", "pub fn validate"),
        ("block.rs", "pub struct Candidate"),
        ("alt.rs", "pub fn alt_against"),
        ("header_ladder.rs", "fn judge_header_ladder"),
        ("drain.rs", "fn drain"),
        ("archival/mod.rs", "fn transition"),
        ("rules/mod.rs", "trait BlockRule"),
    ];
    for (name, identifier) in required {
        let path = src.join(name);
        assert!(
            files.contains(&path),
            "{name} is not in the walk; the connect path moved, repoint this test: {files:?}"
        );
        let text = std::fs::read_to_string(&path).expect(name);
        assert!(
            text.contains(identifier),
            "{name} no longer holds `{identifier}`; repoint this test"
        );
    }

    // Exempt from the walk, and held to still being the section checker.
    // A file that no longer holds these names is not the module under test,
    // and an exemption that outlives the checker would hide a call site.
    let section = src.join("archival").join("bundle_section.rs");
    let section_text = std::fs::read_to_string(&section).expect("archival/bundle_section.rs");
    assert!(
        section_text.contains("pub fn check_section<"),
        "archival/bundle_section.rs no longer holds the section checker"
    );
    assert!(
        section_text.contains("fn inside_window"),
        "archival/bundle_section.rs no longer holds the window the verifier shares"
    );
    let records = src.join("archival").join("bundle_records.rs");
    let records_text = std::fs::read_to_string(&records).expect("archival/bundle_records.rs");
    assert!(
        records_text.contains("fn judge_passes"),
        "archival/bundle_records.rs no longer holds the shared pass check"
    );

    let exporting = [src.join("archival").join("mod.rs"), src.join("lib.rs")];
    for file in &files {
        let text = std::fs::read_to_string(file).expect("a readable source file");
        let judged = if exporting.contains(file) {
            without_staged_export(&text, names)
        } else {
            text
        };
        for name in names {
            assert!(
                !judged.contains(name),
                "{} names `{name}`: the bundle rule is no longer staged. Move the module \
                 banner, the census rows and this test in the same change.",
                file.display()
            );
        }
    }

    // The registry, exempt from the scan and held to what wiring would be.
    let census = std::fs::read_to_string(src.join("census.rs")).expect("census.rs");
    let binds = |line: &&str| {
        ["implemented(", "enforced_at(", "by_construction("]
            .iter()
            .any(|entry| line.contains(entry))
    };
    assert!(
        census.contains("rules::bundle_admission::J29"),
        "the staged rule types are named on the pending rows"
    );
    for line in census.lines().filter(binds) {
        assert!(
            !line.contains("bundle"),
            "a census entry binds the bundle module; the rows are no longer staged: {line}"
        );
    }
}

/// Every non-test Rust source the connect path can run through:
/// `src/**/*.rs` less the exemptions the test's doc names.
fn connect_path_sources(src: &Path) -> Vec<PathBuf> {
    let exempt_files = [
        src.join("harness.rs"),
        src.join("census.rs"),
        src.join("archival").join("bundle.rs"),
        src.join("archival").join("bundle_records.rs"),
        src.join("archival").join("bundle_section.rs"),
    ];
    let exempt_dir = src.join("harness");
    let mut files = Vec::new();
    rust_sources(src, &mut files);
    assert!(!files.is_empty(), "{} has no Rust sources", src.display());
    files.retain(|path| {
        !is_test_source(path) && !exempt_files.contains(path) && !path.starts_with(&exempt_dir)
    });
    files.sort();
    files
}

/// Every `.rs` under `dir`, recursively.
fn rust_sources(dir: &Path, into: &mut Vec<PathBuf>) {
    for entry in
        std::fs::read_dir(dir).unwrap_or_else(|_| panic!("{} is a directory", dir.display()))
    {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            rust_sources(&path, into);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            into.push(path);
        }
    }
}

fn is_test_source(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with("_tests.rs"))
}

/// `source` with the one `pub use` that exports the staged surface
/// removed. The export is found by the names it carries, not by its path,
/// so `archival/mod.rs`'s `pub use bundle::{..}` and `lib.rs`'s
/// `pub use archival::{..}` are one case. Exactly one such `pub use` is
/// required: none means the export moved, two means the second is a call
/// site to judge.
fn without_staged_export(source: &str, names: &[&str]) -> String {
    let mut spans = Vec::new();
    let mut from = 0;
    while let Some(at) = source[from..].find("pub use ") {
        let start = from + at;
        let end = start + source[start..].find(';').expect("a `pub use` ends in `;`") + 1;
        if names.iter().all(|name| source[start..end].contains(name)) {
            spans.push((start, end));
        }
        from = end;
    }
    assert_eq!(
        spans.len(),
        1,
        "one `pub use` exports the staged surface: none means it moved, two means the second \
         is a call site to judge"
    );
    let (start, end) = spans[0];
    format!("{}{}", &source[..start], &source[end..])
}

/// Each staged type's row is the verifier's name for that refusal.
/// Constructing the types is what keeps them live while unbound.
#[test]
fn the_staged_rule_types_name_the_verifier_rows() {
    use crate::census::CenRow;
    use crate::rules::bundle_admission::{J29, J30, J31, J32, J33, J34, J35, J36, J37};
    use crate::rules::Rule;
    use shekyl_archival_retention::SectionBudget;

    let _ = (J29, J30, J31, J32, J33, J34, J35, J36, J37);
    let charge = SectionCharge::of(&[]);
    let budget = SectionBudget::from_draws(0);
    let section = [
        (SectionRefused::Malformed { position: 0 }.row(), J29::ROW),
        (SectionRefused::OutOfOrder { position: 1 }.row(), J29::ROW),
        (
            SectionRefused::TooManyReferences { found: usize::MAX }.row(),
            J29::ROW,
        ),
        (SectionRefused::Root.row(), J29::ROW),
        (
            SectionRefused::OverBudget { charge, budget }.row(),
            J30::ROW,
        ),
        (
            SectionRefused::OutsideWindow { position: 0 }.row(),
            J31::ROW,
        ),
    ];
    for (named, row) in section {
        assert_eq!(named, row);
    }
    let bundles = [
        (BundleInvalid::OutsideWindow.row(), J31::ROW),
        (BundleInvalid::AlreadyRevealed.row(), J31::ROW),
        (BundleInvalid::BodyMalformed.row(), J32::ROW),
        (BundleInvalid::Count.row(), J32::ROW),
        (BundleInvalid::RecordCount.row(), J32::ROW),
        (BundleInvalid::Commitment.row(), J33::ROW),
        (BundleInvalid::WitnessSignature.row(), J34::ROW),
        (BundleInvalid::Attempt { draw: 0 }.row(), J35::ROW),
        (BundleInvalid::Anchor { draw: 0 }.row(), J36::ROW),
        (BundleInvalid::Receipt { draw: 0 }.row(), J37::ROW),
    ];
    for (named, row) in bundles {
        assert_eq!(named, row);
    }
    assert_eq!(J29::ROW, CenRow::J29);
    assert_eq!(J37::ROW, CenRow::J37);
}
