// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SA-R-7 pattern gate: the FFI boundary's raw-read and raw-reserve
//! ratchet (`SIGNATURE_ALIGNMENT.md` §2.3, the ratification's filed
//! residual — this test is the mechanical trigger that turns the
//! cap-before-reserve rule from remembered into enforced).
//!
//! Two patterns are counted per source file, over comment-stripped code:
//!
//! - **the `from_raw_parts` token** — deliberately the bare token, not
//!   the `slice::`-qualified path, so an imported `use
//!   std::slice::from_raw_parts;` call cannot slip past the count; it
//!   also matches `_mut` and `Vec::from_raw_parts`, each of which
//!   hand-owns a UB precondition of its own (byte bound / layout
//!   match). Every raw call re-owns those preconditions individually;
//!   the guarded seam is [`legacy_util::slice_from_ptr`]. (A textual
//!   gate bounds drift, not adversaries — `use ... as alias` can evade
//!   any needle; a reviewer evades a ratchet only on purpose.)
//! - **`Vec::with_capacity(`**: a raw reserve. The guarded seam is
//!   [`legacy_util::bounded_capacity`] (backing bound); counts that are
//!   cheap-per-element additionally need a protocol ceiling (the
//!   `MAX_TREE_DEPTH` lesson — a *backed* count can still amplify).
//!
//! The baselines below fail in BOTH directions, exactly like the engine
//! decomposition ratchet:
//!
//! - **regression** — a file exceeds its pin: a net-new raw site landed.
//!
//! **Honest scope (stated, not papered over):** the pins are per-file
//! NET counts, so a same-file swap — one raw site removed, a different
//! one added — passes the gate. Catching that would need normalized
//! call-site identities, i.e. a brittle pseudo-parser whose churn
//! punishes every legitimate refactor; the engine decomposition
//! ratchet accepts the identical property for line counts. The swap
//! case is a **review duty**: a diff that touches a raw site in a
//! pinned file is reviewed against rule 40's seam obligations even
//! when the pin stays green. What the gate DOES guarantee
//! mechanically: the per-file raw count is monotone non-increasing.
//!   Route it through the seam helpers, or — for a reviewed, deliberate
//!   raw site (typed slices, sub-pointer arithmetic, a local guarded
//!   helper with its own error type like `flat_commitment_keys`) — bump
//!   the pin in the same commit with a rationale comment.
//! - **slack** — a file drops below its pin: a win was made; tighten the
//!   pin here so it can never grow back.
//!
//! `legacy_util.rs` is exempt by name: it is the seam's home (the
//! definitional `from_raw_parts` inside `slice_from_ptr`, the
//! `with_capacity` inside `bounded_capacity`, and the free path), and it
//! is the one file where these patterns are the point.

use std::collections::BTreeMap;
use std::path::Path;

/// (src-relative path, `from_raw_parts`-token count, `Vec::with_capacity(` count)
///
/// Baseline 2026-08-14 (SA-R-7 close). Honest inventory, not an
/// endorsement: raw `from_raw_parts` sites each hand-own the byte-bound
/// precondition, and the pins exist so their number can only shrink.
const BASELINE: &[(&str, usize, usize)] = &[
    ("account_ffi.rs", 7, 0),
    ("archival_admission_ffi.rs", 3, 0),
    ("archival_ffi/attestation.rs", 6, 2),
    ("archival_ffi/bond.rs", 2, 0),
    ("archival_ffi/ct_balance.rs", 1, 0),
    ("archival_ffi/emission.rs", 9, 3),
    ("archival_ffi/epoch_close.rs", 6, 3),
    ("archival_ffi/schedule.rs", 4, 0),
    ("archival_ffi/serve_credit.rs", 3, 1),
    ("archival_ffi/tests.rs", 0, 3),
    ("ct_balance_ffi.rs", 5, 0),
    ("difficulty_ffi.rs", 2, 0),
    ("engine_file_ffi.rs", 2, 1),
    ("legacy_core.rs", 4, 0),
    ("legacy_curve_tree.rs", 4, 0),
    ("legacy_fcmp.rs", 1, 6),
    ("legacy_frost.rs", 2, 3),
    ("legacy_proofs.rs", 4, 0),
    ("legacy_tests.rs", 3, 0),
    ("legacy_tx.rs", 1, 2),
    ("levin_ffi.rs", 4, 0),
    ("pow_randomx_ffi.rs", 1, 0),
    ("relay_zone_ffi/mod.rs", 5, 1),
    ("relay_zone_ffi/tests.rs", 4, 0),
];

fn scan(dir: &Path, src_root: &Path, counts: &mut BTreeMap<String, (usize, usize)>) {
    for entry in std::fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            scan(&path, src_root, counts);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let rel = path
            .strip_prefix(src_root)
            .expect("under src")
            .to_string_lossy()
            .replace('\\', "/");
        if rel == "legacy_util.rs" {
            continue; // the seam's home — see the module docs
        }
        let text = std::fs::read_to_string(&path).expect("read source file");
        let mut frp = 0;
        let mut wc = 0;
        for line in text.lines() {
            let code = line.split("//").next().unwrap_or("");
            frp += code.matches("from_raw_parts").count();
            wc += code.matches("Vec::with_capacity(").count();
        }
        if frp > 0 || wc > 0 {
            counts.insert(rel, (frp, wc));
        }
    }
}

#[test]
fn raw_boundary_reads_and_reserves_only_ratchet_down() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut counts = BTreeMap::new();
    scan(&src, &src, &mut counts);

    let pins: BTreeMap<&str, (usize, usize)> = BASELINE
        .iter()
        .map(|&(f, frp, wc)| (f, (frp, wc)))
        .collect();

    let mut failures = Vec::new();
    for (file, &(frp, wc)) in &counts {
        match pins.get(file.as_str()) {
            None => failures.push(format!(
                "{file}: {frp} raw from_raw_parts / {wc} raw Vec::with_capacity in an \
                 unpinned file — route through legacy_util::slice_from_ptr / bounded_capacity, \
                 or add a reviewed baseline row with a rationale"
            )),
            Some(&(pf, pw)) => {
                if frp > pf || wc > pw {
                    failures.push(format!(
                        "{file}: raw counts grew (from_raw_parts {pf} -> {frp}, with_capacity \
                         {pw} -> {wc}) — a net-new raw site landed; route it through the seam \
                         helpers or bump the pin in the same commit with a rationale"
                    ));
                } else if frp < pf || wc < pw {
                    failures.push(format!(
                        "{file}: raw counts dropped (from_raw_parts {pf} -> {frp}, with_capacity \
                         {pw} -> {wc}) — a win was made; tighten this file's baseline row so it \
                         cannot grow back"
                    ));
                }
            }
        }
    }
    for (file, &(pf, pw)) in &pins {
        if !counts.contains_key(*file) {
            failures.push(format!(
                "{file}: pinned ({pf}/{pw}) but now has zero raw sites (or was removed) — \
                 delete its baseline row to lock the win in"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "FFI boundary ratchet (SA-R-7):\n{}",
        failures.join("\n")
    );
}
