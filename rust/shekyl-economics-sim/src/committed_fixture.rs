// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The committed outputs the sim's drift tripwires compare against, and
//! their regeneration.
//!
//! A committed narration or record is self-pinned (rule 50): the sim
//! produced it and it was frozen, so it catches an unintended change and
//! proves nothing about the day it was pinned. Moving one is a decision,
//! not a command: [`regenerate`] refuses unless the invocation cites the
//! [`DECISION_LOG`] entry that says what moved and why, as
//! `SHEKYL_PINNED_REGEN_DECISION="YYYY-MM-DD <rationale>"`.

use shekyl_crypto_pq::test_support::regen_decision_in_log_or_refuse;

/// The record the sim's committed outputs move under: the rebase
/// document's dated sections.
pub(crate) const DECISION_LOG: &str = "docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md";

/// Panics, naming the first differing line, when `current` is not the text
/// committed at `path`. `report` names the output in the message.
pub(crate) fn assert_matches(report: &str, path: &str, current: &str) {
    let committed = std::fs::read_to_string(path).expect("read the committed output");
    if committed == current {
        return;
    }
    let first = committed
        .lines()
        .zip(current.lines())
        .position(|(a, b)| a != b)
        .map_or_else(
            || committed.lines().count().min(current.lines().count()) + 1,
            |i| i + 1,
        );
    panic!(
        "{report} drifted from {path}; first differing line {first} ({} committed lines, {} \
         current). If the change is intended, cite the {DECISION_LOG} entry that records it \
         and regenerate; otherwise the sim drifted from its record.",
        committed.lines().count(),
        current.lines().count(),
    );
}

/// A committed output: where it lives, and how the sim builds it.
pub(crate) struct Output {
    pub(crate) path: &'static str,
    pub(crate) build: fn() -> String,
}

/// Write each of `outputs`, `what` naming them, once the invocation cites
/// the decision that moves them. The citation is checked before anything is
/// built: a refused regeneration costs nothing.
pub(crate) fn regenerate(what: &str, outputs: &[Output]) {
    let decision = regen_decision_in_log_or_refuse(what, DECISION_LOG);
    eprintln!("regenerating {what} under decision: {decision}");
    for output in outputs {
        std::fs::write(output.path, (output.build)()).expect("write the committed output");
        eprintln!("wrote {}", output.path);
    }
}
