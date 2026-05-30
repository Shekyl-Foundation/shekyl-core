// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Harness invocation banner (§5.1.18, §4.6 M4).
//!
//! Per `docs/design/RANDOMX_V2_PHASE2G_PLAN.md` §5.1.18 + §4.6 M4
//! Round-3 substrate-completeness amendment, the harness emits a
//! disposition-source banner to stderr **before any test output
//! begins**. The banner makes the authority claim explicit:
//! reviewers reading CI logs see the plan-doc citation, the
//! attack-class coverage claim, the leg-3-backstop framing, the
//! fork-pin SHA, and the modification-discipline pointer before
//! they see the per-mode test results.
//!
//! ## Why the banner exists (§4.5 / §4.6 active-threat-surface)
//!
//! The harness's contract is implicit: a reviewer reading CI logs
//! assumes the harness is running against the plan-doc-anchored
//! corpus, canonical outputs, and assertions. §4.5 T-A7 ("trust
//! laundering: the CI green check is treated as the audit
//! signal"), T-A8 ("harness tamper: the harness itself is the
//! attack vector"), and T-A11 ("rubber-stamp: reviewer attention
//! shortfall") all turn on the implicit-contract gap. M4 closes
//! the gap by surfacing the contract at every invocation; the
//! banner is the §4.6 M4 mitigation.
//!
//! ## What the banner contains (per §5.1.18 template + T17)
//!
//! T17 (per §6.7.5) asserts the stderr banner contains:
//!
//! 1. The disposition-source citation (plan-doc + Round 3 +
//!    substrate-completeness amendment).
//! 2. The §4.5 T-A coverage claim (T-A1 through T-A11).
//! 3. The §4.6 mitigation patterns claim (M1 through M4).
//! 4. The §2.5 + §4.3 leg-3-backstop framing.
//! 5. The fork-pin SHA from §1.7.
//! 6. The modification-discipline pointer (§5.7 + §8.3).
//! 7. The active mode (`correctness` / `worst-case` / `latency` /
//!    `concurrent`).
//!
//! Banner format follows the §4.6 M4 template literally; T17's
//! substring assertions in `#[cfg(test)]` below pin the exact
//! plan-doc-anchored strings each item supplies.

use std::io::{self, Write};

use crate::failure_output::FORK_PIN_SHA;

/// Emit the §5.1.18 + §4.6 M4 banner to `writer` (typically
/// `io::stderr()`). The banner is plain-text (not JSON; the
/// structured-output channel is reserved for the §5.1.14 failure
/// schema per R1-D11) and is emitted before any per-mode output
/// begins. The `mode` argument is the active mode-tag per
/// [`crate::Mode::as_str`] (`correctness` / `worst-case` /
/// `latency` / `concurrent`).
///
/// # Errors
///
/// Returns `io::Error` if writing to `writer` fails. The caller
/// is `main.rs`'s dispatch path, which uses `io::stderr()`;
/// `eprintln!`-style emission to a closed stderr would propagate
/// the underlying I/O error rather than silently dropping the
/// banner. The error is surfaced (not absorbed) so a future
/// regression that breaks the stderr channel is loud per the
/// §00-mission.mdc "deletion or migration" stance against
/// graceful-degradation defaults.
pub fn emit_banner<W: Write>(writer: &mut W, mode: &str) -> io::Result<()> {
    writeln!(writer, "Shekyl RandomX v2 Differential Harness")?;
    writeln!(
        writer,
        "Disposition source: RANDOMX_V2_PHASE2G_PLAN.md Round 3 close + substrate-completeness amendment"
    )?;
    writeln!(
        writer,
        "Active-threat-surface coverage: §4.5 T-A1 through T-A11; mitigation patterns §4.6 M1–M4"
    )?;
    writeln!(
        writer,
        "Leg-3 backstop framing: this harness is the catch-of-last-resort per §2.5 + §4.3;"
    )?;
    writeln!(
        writer,
        "  spec-faithfulness requires audit-against-actual-code (legs 1 + 2)"
    )?;
    writeln!(
        writer,
        "Modifications to harness behavior require a corresponding plan-doc amendment per §5.7 + §8.3."
    )?;
    writeln!(writer, "Mode: {mode}")?;
    writeln!(writer, "Fork-pin: {FORK_PIN_SHA}")?;
    Ok(())
}

/// Convenience wrapper that emits the banner to `io::stderr()`.
/// Used by `main.rs`'s dispatch path; failures are absorbed
/// (logged to stderr with the `error: invocation_banner emit
/// failed:` prefix) rather than aborting the harness — a banner
/// emission failure must not block the divergence-detection
/// pipeline that the banner exists to attest to. Returns `true`
/// when the banner was emitted, `false` on absorbed I/O error.
pub fn emit_banner_to_stderr(mode: &str) -> bool {
    let mut stderr = io::stderr();
    match emit_banner(&mut stderr, mode) {
        Ok(()) => true,
        Err(err) => {
            // Best-effort second attempt — if stderr is broken,
            // even `eprintln!` may fail, in which case the
            // diagnostic loss is itself the failure signal.
            eprintln!("error: invocation_banner emit failed: {err}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T17 (`invocation_banner_emission`) per §6.7.5: harness
    /// invoked with any mode; the banner must contain the
    /// required disposition-source citation, the §4.5 T-A
    /// coverage claim (T-A1 through T-A11), the §4.6 mitigation
    /// patterns claim, the §2.5 + §4.3 leg-3-backstop framing,
    /// the fork-pin SHA (§1.7), and the modification-discipline
    /// pointer (§5.7 + §8.3). The assertion is a substring
    /// check on each required string; we run the test against
    /// each mode-tag so a future mode addition that bypasses
    /// the banner is caught.
    #[test]
    fn t17_invocation_banner_emission() {
        for mode in ["correctness", "worst-case", "latency", "concurrent"] {
            let mut buf: Vec<u8> = Vec::new();
            emit_banner(&mut buf, mode).expect("emit_banner succeeds");
            let banner = String::from_utf8(buf).expect("banner is UTF-8");

            // (1) Disposition-source citation.
            assert!(
                banner.contains(
                    "RANDOMX_V2_PHASE2G_PLAN.md Round 3 close + substrate-completeness amendment"
                ),
                "mode={mode}: disposition-source missing from banner: {banner}"
            );
            // (2) §4.5 T-A coverage claim.
            assert!(
                banner.contains("§4.5 T-A1 through T-A11"),
                "mode={mode}: T-A coverage missing from banner: {banner}"
            );
            // (3) §4.6 mitigation patterns claim.
            assert!(
                banner.contains("§4.6 M1–M4"),
                "mode={mode}: M1–M4 claim missing from banner: {banner}"
            );
            // (4) §2.5 + §4.3 leg-3-backstop framing.
            assert!(
                banner.contains("§2.5 + §4.3"),
                "mode={mode}: leg-3 backstop framing missing from banner: {banner}"
            );
            assert!(
                banner.contains("catch-of-last-resort"),
                "mode={mode}: catch-of-last-resort missing from banner: {banner}"
            );
            // (5) Fork-pin SHA.
            assert!(
                banner.contains(FORK_PIN_SHA),
                "mode={mode}: fork-pin SHA missing from banner: {banner}"
            );
            // (6) Modification-discipline pointer.
            assert!(
                banner.contains("§5.7 + §8.3"),
                "mode={mode}: modification-discipline pointer missing from banner: {banner}"
            );
            // (7) Active mode.
            assert!(
                banner.contains(&format!("Mode: {mode}")),
                "mode={mode}: active-mode line missing from banner: {banner}"
            );
        }
    }

    /// The banner emits a fixed-shape multi-line block — 8
    /// lines per the §4.6 M4 template (header + 7 content
    /// lines). Catches a future regression that drops or
    /// duplicates a line silently.
    #[test]
    fn banner_line_count_matches_template() {
        let mut buf: Vec<u8> = Vec::new();
        emit_banner(&mut buf, "correctness").expect("emit");
        let banner = String::from_utf8(buf).expect("utf8");
        // 8 `writeln!` calls produce 8 newlines; splitting by
        // `\n` yields 9 elements (the trailing empty after the
        // final newline). The substantive line count is 8.
        let lines: Vec<&str> = banner.lines().collect();
        assert_eq!(
            lines.len(),
            8,
            "banner line count drift; expected 8, got {}: {banner}",
            lines.len()
        );
    }

    /// The header line is exactly the §4.6 M4 template's
    /// header — "Shekyl RandomX v2 Differential Harness". A
    /// future rename of the harness crate must update this
    /// constant intentionally (and update the plan-doc's M4
    /// template to match).
    #[test]
    fn banner_header_is_fixed() {
        let mut buf: Vec<u8> = Vec::new();
        emit_banner(&mut buf, "correctness").expect("emit");
        let banner = String::from_utf8(buf).expect("utf8");
        let first_line = banner.lines().next().expect("at least one line");
        assert_eq!(first_line, "Shekyl RandomX v2 Differential Harness");
    }
}
