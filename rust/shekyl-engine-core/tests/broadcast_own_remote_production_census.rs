// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! PWD-A1's falsifier, run by CI instead of by hand
//! (`docs/design/P2P_2_DISPATCH_BRIEF.md` §2.4).
//!
//! The archival-submission claim is falsifiable by construction: *production
//! submission runs through the ① `Local` posture, and no production caller
//! selects the per-`P` ② `OwnRemote` arm — name such a call site and PWD-A1 is
//! refuted.* Until now that was a grep a human had to remember to run. This is
//! the same question, asked every `cargo test`.
//!
//! ## The shape: pin the allowed set, never assert zero
//!
//! Two production occurrences of the ② arm exist on a clean tree and are
//! **correct**, both inside `impl BroadcastSubmitter`:
//!
//! - `transaction_submitter.rs`'s `BroadcastPosture::OwnRemote { base_url } =>`
//!   — the audited *handling* arm of the `for_posture` choke point;
//! - `BroadcastSubmitter::local`'s own `Self::for_posture(` call — the
//!   pre-bound ① constructor.
//!
//! A gate asserting *zero* would therefore be red on an unmutated tree, and the
//! obvious repair — excluding `transaction_submitter.rs` from the sweep —
//! reopens exactly the hole the gate closes, since a future direct construction
//! in **that** file is the one most likely to slip through. So the census pins
//! the allowed occurrences per file and fails on any addition *anywhere*,
//! including there.
//!
//! That single instrument carries both directions:
//!
//! - **Subject assertion** (`47-gate-subject-assertion.mdc`): every needle must
//!   match *somewhere* in production. If the handling arm is renamed away, the
//!   census goes red rather than reporting the clean "nothing selects ②" that a
//!   vanished subject would otherwise forge.
//! - **Inverse**: nothing outside the pinned set constructs the posture, calls
//!   `for_posture` directly, or reaches `select_broadcast`.
//!
//! ## Why a count-pin and not a scope-pin
//!
//! A scope-pin (allow the occurrences only *within* `impl BroadcastSubmitter`)
//! is more precise and would distinguish a handling arm from a construction.
//! It also requires a brace-matching parser inside a gate, and would go red or —
//! worse — silently wrong on any refactor that moves the impl block. A count is
//! cruder and harder to fool: it cannot be satisfied by relocating code, and its
//! failure mode is a false red that a reader resolves by looking at one diff.
//!
//! ## What this does NOT cover
//!
//! - **It is a source-text check, not a reachability proof.** It reads
//!   characters, never the call graph. A site that reaches the ② arm through a
//!   trait object, a generic parameter, or a binding it does not name by hand is
//!   invisible to it. "No production caller selects `OwnRemote`" remains a claim
//!   about *text*; the census keeps that text from drifting without review.
//! - **It says nothing about the ① arm's loopback premise.** That
//!   `BroadcastSubmitter::local` really is the operator's own box, and that a
//!   loopback observer is conceded (`ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md` §3.1
//!   part 3), are design claims argued elsewhere and untouched here.
//! - **It cannot tell a construction from a pattern.** See the count-pin note.
//! - **Its crate scope is a premise, not an accident** — see
//!   [`crate_private_types_bound_the_sweep`]. `BroadcastPosture` and
//!   `for_posture` are `pub(crate)`, so `shekyl-engine-core/src` is the whole
//!   population. Widen either to `pub` and the sweep is no longer complete; that
//!   assertion is what says so out loud.
//!
//! ## When the 2c config-source slice lands
//!
//! This census is the thing that will go red. That is its job: the 2c slice is
//! precisely what gives an operator's explicit ② choice a production caller, and
//! PWD-A1 must be re-derived — not re-pinned reflexively — in the same PR.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The tests-module marker the engine's source gates split on.
const TESTS_MARKER: &str = "\n#[cfg(test)]\nmod tests {";

/// The needles, in the order the pin table's columns carry them.
///
/// Plain literals are safe in this file: the sweep reads
/// `shekyl-engine-core/src`, and this test lives in `tests/`, so the needles
/// cannot self-match the way they could in an in-module gate.
///
/// `OwnRemote` (bare) is the evasion-resistant needle — an alias import
/// (`use BroadcastPosture::OwnRemote as X`) still has to write the identifier
/// once. The qualified form is the precise one, and keeps the failure message
/// specific to the broadcast posture rather than the fetch posture that shares
/// the variant name.
const NEEDLES: [&str; 4] = [
    "OwnRemote",
    "BroadcastPosture::OwnRemote",
    "for_posture(",
    "select_broadcast(",
];

/// Every production occurrence of a [`NEEDLES`] entry in the crate, by file.
///
/// | file | bare | qualified | `for_posture(` | `select_broadcast(` | what they are |
/// | --- | --- | --- | --- | --- | --- |
/// | `engine/posture.rs` | 2 | 0 | 0 | 1 | the two `OwnRemote` **variant declarations** (fetch `Posture` and `BroadcastPosture`; neither is path-qualified, hence 0 in the qualified column) and the `select_broadcast` **definition** |
/// | `engine/transaction_submitter.rs` | 1 | 1 | 2 | 0 | the `for_posture` ② **handling arm** (one occurrence, counted in both `OwnRemote` columns), plus `for_posture`'s own **definition** and the `Self::for_posture(` call inside `local()` |
///
/// A row for any other file means a production site named the ② arm: re-run
/// PWD-A1's falsifier before touching this table.
const PINNED: &[(&str, [usize; 4])] = &[
    ("engine/posture.rs", [2, 0, 0, 1]),
    ("engine/transaction_submitter.rs", [1, 1, 2, 0]),
];

/// The files whose production halves must exist for the census to mean
/// anything: the type's home, the choke point, and the four production
/// submission sites.
const ANCHORS: &[&str] = &[
    "engine/posture.rs",
    "engine/transaction_submitter.rs",
    "engine/claim_dispatch.rs",
    "engine/drain_dispatch.rs",
    "engine/release_dispatch.rs",
    "engine/pscan/start.rs",
];

/// The four production seams that dispatch a broadcast. Each must still ride
/// the hardwired ① construction — otherwise "no production caller selects ②"
/// could hold because the submission sites went away, which is a different
/// world, not a safer one.
const SUBMISSION_SITES: &[&str] = &[
    "engine/claim_dispatch.rs",
    "engine/drain_dispatch.rs",
    "engine/release_dispatch.rs",
    "engine/pscan/start.rs",
];

/// The hardwired ① construction every submission site routes through.
const LOCAL_CHOKE: &str = "BroadcastSubmitter::local(";

fn src_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Every `.rs` file under `src`, mapped to its **production** code: the text
/// ahead of the tests-module marker, with comment-only lines dropped.
///
/// Two deliberate asymmetries, both erring toward a false red:
///
/// - a file with no tests module is read whole (over-inclusion — a test-only
///   file that acquired a needle would trip the census, which is the review
///   signal we want, not a miss);
/// - comment-*only* lines are dropped rather than truncating each line at
///   `//`, so a `//` inside a string literal can never delete live code from
///   the text being judged.
fn production_sources() -> BTreeMap<String, String> {
    let root = src_root();
    let mut out = BTreeMap::new();
    collect(&root, &root, &mut out);
    out
}

fn collect(dir: &Path, root: &Path, out: &mut BTreeMap<String, String>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            collect(&path, root, out);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .expect("under src")
            .to_string_lossy()
            .replace('\\', "/");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let production = text
            .split(TESTS_MARKER)
            .next()
            .expect("split always yields a first piece")
            .to_owned();
        let code: String = production
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        out.insert(rel, code);
    }
}

/// The sweep's scope is sound only because the ② arm is crate-private: a
/// `pub(crate)` type cannot be constructed from `benches/`, `tests/`, or
/// another crate, so `shekyl-engine-core/src` is the entire population of
/// possible callers.
///
/// This bites against a widening of either item to `pub`; it does NOT cover
/// re-exports of a value already built inside the crate.
#[test]
fn crate_private_types_bound_the_sweep() {
    let sources = production_sources();
    let posture = sources
        .get("engine/posture.rs")
        .expect("engine/posture.rs is in the sweep");
    assert!(
        posture.contains("pub(crate) enum BroadcastPosture"),
        "BroadcastPosture is no longer crate-private — a src-only sweep no longer \
         covers every caller, so this census under-reports. Widen the sweep or \
         re-derive PWD-A1's scope."
    );
    let submitter = sources
        .get("engine/transaction_submitter.rs")
        .expect("engine/transaction_submitter.rs is in the sweep");
    assert!(
        submitter.contains("pub(crate) fn for_posture("),
        "for_posture is no longer crate-private (or was renamed) — the census's \
         population premise broke."
    );
}

/// The census itself: the ② arm appears in production exactly where PWD-A1 says
/// it does, and nowhere else.
///
/// This bites against a net-new production site naming `OwnRemote`, calling
/// `for_posture` outside the choke point, or reaching `select_broadcast`; it
/// does NOT prove unreachability (see the module docs) and says nothing about
/// the ① arm's loopback premise.
#[test]
fn no_production_site_outside_the_choke_point_selects_the_own_remote_arm() {
    let sources = production_sources();

    // Subject, part 1: the sweep read the tree it claims to have read. An empty
    // or relocated `src` would otherwise produce a flawless empty census.
    for anchor in ANCHORS {
        assert!(
            sources.contains_key(*anchor),
            "{anchor} was not found by the sweep — the census read a tree that does \
             not contain PWD-A1's subject, and its silence means nothing"
        );
    }

    let mut counted: BTreeMap<String, [usize; NEEDLES.len()]> = BTreeMap::new();
    let mut totals = [0usize; NEEDLES.len()];
    for (rel, code) in &sources {
        let mut row = [0usize; NEEDLES.len()];
        for (slot, needle) in NEEDLES.iter().enumerate() {
            row[slot] = code.matches(needle).count();
            totals[slot] += row[slot];
        }
        if row.iter().any(|&n| n > 0) {
            counted.insert(rel.clone(), row);
        }
    }

    // Subject, part 2: every needle must match live production code. A needle
    // that matches nothing is not evidence of a clean tree — it is evidence the
    // thing it names moved, and a green here would be the exact silent no-op
    // this gate exists to remove.
    for (slot, needle) in NEEDLES.iter().enumerate() {
        assert!(
            totals[slot] > 0,
            "needle `{needle}` matches no production code anywhere in the crate. \
             The ② broadcast arm was renamed or removed; re-derive PWD-A1 rather \
             than reading this census's silence as a pass."
        );
    }

    // Subject, part 3: the submission sites are still submitting, on the ① arm.
    for site in SUBMISSION_SITES {
        let code = sources.get(*site).expect("anchor checked above");
        assert!(
            code.contains(LOCAL_CHOKE),
            "{site} no longer constructs through {LOCAL_CHOKE} — PWD-A1's \
             'production submission runs through Local' half is unpinned here, and \
             the ② census below would hold vacuously"
        );
    }

    // The census proper.
    let pins: BTreeMap<&str, [usize; NEEDLES.len()]> = PINNED.iter().copied().collect();
    let mut failures = Vec::new();
    for (file, row) in &counted {
        match pins.get(file.as_str()) {
            None => failures.push(format!(
                "{file}: names the ② broadcast arm in production \
                 ({}) but carries no pin — a production site now selects or routes \
                 `OwnRemote`. This is PWD-A1's stated falsifier: re-derive the claim \
                 in `P2P_2_DISPATCH_BRIEF.md` §2.4 before adding a row here.{}",
                describe(row),
                bare_only_caveat(row, &[0; NEEDLES.len()])
            )),
            Some(pinned) if pinned != row => failures.push(format!(
                "{file}: pinned {} but found {} — the choke point's shape moved. If \
                 the 2c config-source slice landed, re-run PWD-A1's falsifier and \
                 update §2.4; do not re-pin reflexively.{}",
                describe(pinned),
                describe(row),
                bare_only_caveat(row, pinned)
            )),
            Some(_) => {}
        }
    }
    let seen: BTreeSet<&str> = counted.keys().map(String::as_str).collect();
    for (file, pinned) in &pins {
        if !seen.contains(file) {
            failures.push(format!(
                "{file}: pinned {} but now has zero production occurrences (or was \
                 removed) — the census's subject moved out from under it; find where \
                 the ② arm lives now rather than deleting the row.",
                describe(pinned)
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "PWD-A1 ② broadcast-arm census (`P2P_2_DISPATCH_BRIEF.md` §2.4):\n{}",
        failures.join("\n")
    );
}

/// The bare `OwnRemote` needle is shared with the **fetch** `Posture` enum,
/// which carries an `OwnRemote` variant of its own and whose scan-loop wiring
/// slice (`posture.rs` module docs) has yet to land. When a row moves on that
/// column *alone*, this census genuinely cannot tell PWD-A1's falsifier from
/// that unrelated slice — so it says which reading it cannot rule out instead
/// of asserting the broadcast one at a maintainer who is working on the other.
///
/// The bare needle stays despite the conflation: it is what makes an alias
/// import (`use BroadcastPosture::OwnRemote as X`) unable to slip the census,
/// since the `use` line must still write the identifier.
fn bare_only_caveat(
    row: &[usize; NEEDLES.len()],
    baseline: &[usize; NEEDLES.len()],
) -> &'static str {
    let bare_moved = row[0] != baseline[0];
    let rest_unchanged = row[1..] == baseline[1..];
    if bare_moved && rest_unchanged {
        " Only the bare `OwnRemote` identifier moved: if this is the fetch \
         `Posture::OwnRemote` (the scan-loop wiring slice), re-pin with that \
         rationale; if it is the broadcast arm reached through an alias import, \
         this IS the falsifier."
    } else {
        ""
    }
}

fn describe(row: &[usize; NEEDLES.len()]) -> String {
    NEEDLES
        .iter()
        .zip(row.iter())
        .map(|(needle, n)| format!("{needle}={n}"))
        .collect::<Vec<_>>()
        .join(" ")
}
