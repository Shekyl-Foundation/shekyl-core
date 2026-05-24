// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Cargo-test wrapper for the RandomX crate-invariant grep gate.
//!
//! Per Phase 2F §6.2 (`docs/design/RANDOMX_V2_PHASE2F_PLAN.md`):
//! invokes `scripts/ci/check_randomx_crate_invariants.sh` via
//! [`std::process::Command`]; asserts exit status zero. Lets
//! `cargo test -p shekyl-pow-randomx` run the same gate locally
//! without depending on CI infrastructure (the gate also runs as
//! a `build.yml` step sibling to the FPU step).
//!
//! The cargo-test layer also functions as a *positive* check: a
//! test below intentionally introduces commented-out docstring
//! examples of each pattern A/B/C, ensuring the test would fail
//! if the script's logic regressed (the comments themselves are
//! lines beginning with `//` and so are not matched by any of the
//! three column-0 / leading-whitespace-anchored regexes; if a
//! future patch unanchored a pattern, the comments would start
//! matching and the assertions below would expose the regression).

use std::path::PathBuf;
use std::process::Command;

/// Locate the workspace-root-relative script. The test binary is
/// built into `<workspace>/rust/target/{debug,release}/deps/...`
/// and runs with the working directory set to the crate root
/// (`<workspace>/rust/shekyl-pow-randomx/`); the script lives at
/// `<workspace>/scripts/ci/check_randomx_crate_invariants.sh`.
/// We resolve via `CARGO_MANIFEST_DIR` to walk up two levels (out
/// of the crate, out of `rust/`) to the workspace root.
fn script_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("..")
        .join("..")
        .join("scripts")
        .join("ci")
        .join("check_randomx_crate_invariants.sh")
}

/// Locate the workspace root (used as the script's CWD; the
/// script's `CRATE_SRC="rust/shekyl-pow-randomx/src"` constant is
/// resolved relative to wherever the script is invoked).
fn workspace_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir).join("..").join("..")
}

#[test]
fn t_ci_1_pattern_a_returns_zero_hits() {
    // Pattern A (runtime-mutable lazy state imports) — together
    // with patterns B and C, the script returns clean if and only
    // if all three patterns return zero hits. The test asserts
    // the script's overall exit status; sub-pattern attribution
    // lives in the script's stderr output.
    let script = script_path();
    assert!(
        script.exists(),
        "{} not found (CARGO_MANIFEST_DIR walk failed?)",
        script.display()
    );
    let status = Command::new(&script)
        .current_dir(workspace_root())
        .status()
        .expect("failed to invoke crate-invariants script");
    assert!(
        status.success(),
        "scripts/ci/check_randomx_crate_invariants.sh failed; \
         see stderr for the matched lines",
    );
}

#[test]
fn t_ci_2_pattern_b_returns_zero_hits() {
    // Same script; same assertion. The Phase 2F §6.2 test plan
    // splits T-CI-1/T-CI-2/T-CI-3 conceptually per pattern, but
    // the script's contract is "clean iff all three patterns are
    // clean," so each test invokes the same script. The split
    // into three tests preserves the §6.2 row-per-pattern table
    // shape and gives `cargo test` a per-pattern test name when
    // grep'ing test output.
    let script = script_path();
    let status = Command::new(&script)
        .current_dir(workspace_root())
        .status()
        .expect("failed to invoke crate-invariants script");
    assert!(status.success());
}

#[test]
fn t_ci_3_pattern_c_returns_zero_hits() {
    // See T-CI-1's note on per-pattern naming.
    let script = script_path();
    let status = Command::new(&script)
        .current_dir(workspace_root())
        .status()
        .expect("failed to invoke crate-invariants script");
    assert!(status.success());
}

// Documentation-only "would-match" examples for the three
// patterns. These are inside Rust line comments (`//`), so none of
// the three regexes can match them — patterns A and B are anchored
// at column 0 with no leading-whitespace allowance, and pattern C's
// leading-whitespace allowance still requires the attribute or
// `extern "C" fn` token at the leading non-whitespace position
// (which `//` precludes).
//
// If a future patch were to unanchor one of the patterns (e.g.,
// drop the `^` from pattern A), the unanchored regex would start
// matching the citations below, the script would report the hit,
// and the t_ci_*_returns_zero_hits tests would fail. The failure
// is the regression-detection mechanism; it does not require a
// dedicated negative test.
//
// Pattern A would-match example (kept as comment):
//   use std::sync::OnceLock;
//   use once_cell::sync::Lazy;
//
// Pattern B would-match example (kept as comment):
//   static GLOBAL_STATE: AtomicUsize = AtomicUsize::new(0);
//   pub static GLOBAL_TABLE: [u8; 16] = [0; 16];
//
// Pattern C would-match example (kept as comment):
//   #[no_mangle]
//   extern "C" fn shekyl_randomx_compute_hash() { todo!() }
//   #[unsafe(export_name = "shekyl_randomx_thunk")]

/// Substrate sanity check: the script file itself exists and is
/// executable. If a checkout has lost the executable bit (e.g.,
/// archived without permissions), the t_ci_*_returns_zero_hits
/// tests will fail with a confusing message; this test fails
/// earlier with a clearer one.
#[test]
fn script_file_is_executable() {
    use std::os::unix::fs::PermissionsExt;
    let script = script_path();
    assert!(script.exists(), "{} not found", script.display());
    let metadata = std::fs::metadata(&script).expect("metadata read failed");
    let mode = metadata.permissions().mode();
    assert!(
        mode & 0o111 != 0,
        "script is not executable: mode = {mode:o}",
    );
}
