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
            budget: 2
        }
        .row(),
        CenRow::J30
    );
    let rows: [(B, CenRow, Option<u32>); 11] = [
        (B::OutsideWindow, CenRow::J31, None),
        (B::AlreadyRevealed, CenRow::J31, None),
        (B::UnknownBlock, CenRow::J31, None),
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
/// file on the connect path names the bundle verifier.
///
/// The connect path is `validate`, the block types, the alternative tier,
/// every rule, and the archival transition `validate` calls
/// (`archival::transition` and the modules beside it). `archival/mod.rs`
/// re-exports this surface; that re-export is removed before the scan, and
/// the rest of the file — including `transition` — must not name it.
///
/// Bites against the verifier being wired into a block path without the
/// module's banner, the census rows' status and the specification's §2
/// moving with it. Does not cover a caller outside this crate: the store
/// and the ingest driver are other crates, and `SO-D12`'s cutover is where
/// they change. The cutover deletes this test in the change that wires
/// the rule.
#[test]
fn nothing_on_the_connect_path_calls_the_bundle_verifier() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = vec![
        src.join("validate.rs"),
        src.join("block.rs"),
        src.join("alt.rs"),
    ];
    // `alt.rs` is the alternative tier (DRS-E5): the other entry a block
    // is judged through, and where the section check will be called.
    files.extend(rule_sources(&src.join("rules")));
    files.extend(archival_sources(&src.join("archival")));

    let names: &[&str] = &[
        "verify_bundle",
        "check_section",
        "open_body",
        "open_reference",
        "BundleView",
    ];
    let transition = src.join("archival").join("mod.rs");
    assert!(
        files.iter().any(|path| path == &transition),
        "the archival transition is not in the walk: {files:?}"
    );
    let transition_src = std::fs::read_to_string(&transition).expect("archival/mod.rs");
    let (body, reexport) = without_bundle_reexport(&transition_src);
    assert!(
        body.contains("fn transition"),
        "archival/mod.rs no longer holds `transition`; repoint this test"
    );
    for name in names {
        assert!(
            reexport.contains(name),
            "the staged re-export no longer names `{name}`"
        );
    }
    let validate = std::fs::read_to_string(src.join("validate.rs")).expect("validate.rs");
    assert!(
        validate.contains("pub fn validate"),
        "validate.rs is not where `validate` lives any more; repoint this test"
    );
    assert!(files.len() > 15, "the rules tree was not found: {files:?}");

    for file in files {
        let text = std::fs::read_to_string(&file).expect("a readable source file");
        let judged = if file == transition {
            body.as_str()
        } else {
            &text
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
}

/// Rust sources of a directory, tests excluded. The directory is the
/// subject: an empty one is a missing tree, not an empty connect path.
fn rule_sources(dir: &Path) -> Vec<PathBuf> {
    sources_in(dir)
        .into_iter()
        .filter(|path| !is_test_source(path))
        .collect()
}

/// The archival connect path. The verifier module defines the names, and
/// its tests name them as the subject, so both stay out of the walk.
fn archival_sources(dir: &Path) -> Vec<PathBuf> {
    sources_in(dir)
        .into_iter()
        .filter(|path| {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name != "bundle.rs" && !is_test_source(path)
        })
        .collect()
}

fn sources_in(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|_| panic!("{} is a directory", dir.display()))
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .collect();
    assert!(!files.is_empty(), "{} has no Rust sources", dir.display());
    files.sort();
    files
}

fn is_test_source(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with("_tests.rs"))
}

/// The staged surface's re-export, and the file with that item removed.
/// A call inside `transition` survives the removal; the export does not.
fn without_bundle_reexport(source: &str) -> (String, String) {
    let marker = "pub use bundle::";
    let start = source
        .find(marker)
        .expect("archival/mod.rs re-exports the staged bundle surface");
    assert_eq!(
        source.matches(marker).count(),
        1,
        "one re-export is the staged surface; a second is a call site to judge"
    );
    let close = source[start..]
        .find("};")
        .expect("the bundle re-export closes");
    let end = start + close + 2;
    let reexport = source[start..end].to_string();
    let mut body = String::new();
    body.push_str(&source[..start]);
    body.push_str(&source[end..]);
    (body, reexport)
}
