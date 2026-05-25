// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Phase 2g Rust/C differential test harness binary entry point.
//!
//! Per `docs/design/RANDOMX_V2_PHASE2G_PLAN.md` §5.1.1 + §5.1.3, this
//! is the single binary surface for the differential harness; it
//! dispatches `--mode={correctness,worst-case,latency,concurrent}` to
//! the four mode modules (§§5.1.10–5.1.13). Argument parsing is
//! hand-rolled with `std::env::args()` because the §5.1.15 dep list
//! intentionally excludes `clap` — the harness's CLI surface is small,
//! flag-style, and stable per §5.7's drift-prevention discipline.
//!
//! ## Commit-by-commit scope (per §8.1)
//!
//! - **C4:** argparse + `--mode=*` dispatch shell (this skeleton's
//!   original scope).
//! - **C5a–C5b:** corpus modules (§§5.1.5–5.1.6) + canonical outputs
//!   (§5.1.17) + Round 7 amendments (no code surface).
//! - **C6:** `c_oracle` (§5.1.8) + `rust_subject` (§5.1.9) +
//!   `cache_precondition` (§5.1.7); `--debug-cache-divergence`
//!   flag + `--seedhash=<hex>` argument are wired in this commit
//!   (T4 diagnostic precondition path), but the mode-module
//!   consumer landing at C7 / C9 is what exercises them at run
//!   time. Until then, the C4 → C5 bisection boundary invariant
//!   (§8.2) requires that `--mode=*` returns a clear "corpus
//!   modules not yet wired" error rather than silently producing
//!   empty output; the [`Command::Mode`] arm in [`main`] enforces
//!   this.
//! - **C7–C9:** failure output schema (§5.1.14), invocation banner
//!   (§5.1.18), and the mode implementations (§§5.1.10, 5.1.12,
//!   5.1.13; §5.1.11 / `--mode=worst-case` deferred per §3.19
//!   R7-D4).
//!
//! ## §5.1.18 invocation banner placeholder
//!
//! Per §5.1.18 + §4.6 M4, the harness must emit a disposition-source
//! banner on stderr before any test output. The banner module lands
//! at C9 alongside the failure-output module (per §8.1's C9
//! "failure-output JSON schema + invocation banner" boundary). At C4,
//! no banner is emitted because no test output is produced; the
//! discipline gap closes when C9 wires both the banner and the
//! `--mode=*` real dispatch in the same commit.

use std::env;
use std::process::ExitCode;

/// Modes enumerated by §5.1.1 (CLI surface) + §5.7 (drift-prevention).
///
/// The variant set is closed: any addition is a §5.7 contract reshape
/// that requires a plan-doc round per §3.15 forward-template + §5.7
/// "Round 2 may reshape this contract" discipline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// `correctness` — per-PR byte-equality across `(seedhash, data)`
    /// pairs over the random + adversarial corpora (§5.1.10).
    Correctness,
    /// `worst-case` — adversarial-corpus per-hash latency
    /// measurement; release-gate cadence (§5.1.11).
    WorstCase,
    /// `latency` — interleaved Rust/C per-hash latency benchmark;
    /// nightly cadence; replaces the deleted Phase 2c
    /// `tests/perf/per_hash_latency.rs` per R1-D7 (§5.1.12).
    Latency,
    /// `concurrent` — multi-worker concurrent correctness with RSS
    /// bound assertion; per-PR cadence (§5.1.13).
    Concurrent,
}

impl Mode {
    /// Parse the `--mode=<value>` argument value. Per §3.15.4 +
    /// §5.1.1, the value set is closed and case-sensitive.
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "correctness" => Ok(Self::Correctness),
            "worst-case" => Ok(Self::WorstCase),
            "latency" => Ok(Self::Latency),
            "concurrent" => Ok(Self::Concurrent),
            other => Err(format!(
                "unknown mode '{other}'; valid modes: correctness, worst-case, latency, concurrent"
            )),
        }
    }

    /// Stable display name; used by the C4-skeleton diagnostic.
    fn as_str(self) -> &'static str {
        match self {
            Self::Correctness => "correctness",
            Self::WorstCase => "worst-case",
            Self::Latency => "latency",
            Self::Concurrent => "concurrent",
        }
    }
}

/// Parsed `--mode=<value>` invocation, including the C6-wired
/// `--debug-cache-divergence` + `--seedhash=<hex>` flags.
///
/// Per §5.1.7 + T4, the `--debug-cache-divergence` flag is valid on
/// `correctness` mode only and requires a `--seedhash=<hex>`
/// argument naming the failing seedhash to re-derive locally. The
/// flag is parsed in this commit (C6) so the argparse surface is
/// stable for the C7 mode_correctness wiring; the actual byte-diff
/// invocation lives in [`crate::cache_precondition::byte_diff`] and
/// is called from the C7 mode module.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ModeInvocation {
    mode: Mode,
    /// Set when `--debug-cache-divergence` is present. The
    /// accompanying `--seedhash=<hex>` value is required and
    /// validated at parse time so a malformed hex string fails
    /// before any mode-module work begins.
    debug_cache_divergence_seedhash: Option<[u8; 32]>,
}

/// Top-level parsed command. The C4 skeleton recognized only
/// `--help` and `--mode=<value>`; the C6 commit adds
/// `--debug-cache-divergence` + `--seedhash=<hex>` for T4's
/// diagnostic precondition path.
#[derive(Debug)]
enum Command {
    Help,
    Mode(ModeInvocation),
}

/// Parse a 64-character lowercase-hex string (without separators or
/// `0x` prefix) into a 32-byte array. Returns `Err(String)` with a
/// human-readable diagnostic on length or character violations.
///
/// Used by `--seedhash=<hex>`'s argument validation per §5.1.7 +
/// T4. Pinned to lowercase-only per [`Seedhash`]'s `Display` impl
/// in the verifier crate (`seedhash.rs:75-77`), so reviewers who
/// copy a failing seedhash from CI output into the local
/// `--seedhash=` invocation get a 1:1 byte match.
fn parse_seedhash_hex(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err(format!(
            "--seedhash: expected 64 hex characters, got {} characters",
            value.len()
        ));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in value.as_bytes().chunks(2).enumerate() {
        let hex_byte = std::str::from_utf8(chunk)
            .map_err(|_| format!("--seedhash: byte {i}: invalid UTF-8 in hex pair"))?;
        out[i] = u8::from_str_radix(hex_byte, 16)
            .map_err(|e| format!("--seedhash: byte {i}: invalid hex pair '{hex_byte}': {e}"))?;
    }
    Ok(out)
}

/// Hand-rolled argv parser. Returns a clean diagnostic for any
/// unknown / malformed argument so reviewers reading CI logs see the
/// specific argument that broke the invocation.
fn parse_args(args: &[String]) -> Result<Command, String> {
    if args.is_empty() {
        return Err("no arguments; pass --help for usage".to_owned());
    }
    let mut mode: Option<Mode> = None;
    let mut debug_cache_divergence = false;
    let mut seedhash_hex: Option<[u8; 32]> = None;
    for arg in args {
        if arg == "--help" || arg == "-h" {
            return Ok(Command::Help);
        }
        if let Some(value) = arg.strip_prefix("--mode=") {
            if mode.is_some() {
                return Err("--mode specified more than once".to_owned());
            }
            mode = Some(Mode::parse(value)?);
            continue;
        }
        if arg == "--debug-cache-divergence" {
            if debug_cache_divergence {
                return Err("--debug-cache-divergence specified more than once".to_owned());
            }
            debug_cache_divergence = true;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--seedhash=") {
            if seedhash_hex.is_some() {
                return Err("--seedhash specified more than once".to_owned());
            }
            seedhash_hex = Some(parse_seedhash_hex(value)?);
            continue;
        }
        return Err(format!("unknown argument '{arg}'; pass --help for usage"));
    }
    let mode = mode.ok_or_else(|| "no --mode specified; pass --help for usage".to_owned())?;
    let debug_cache_divergence_seedhash = match (debug_cache_divergence, seedhash_hex) {
        (false, None) => None,
        (true, Some(s)) => {
            if mode != Mode::Correctness {
                return Err(format!(
                    "--debug-cache-divergence is valid only with --mode=correctness; \
                     got --mode={}",
                    mode.as_str()
                ));
            }
            Some(s)
        }
        (true, None) => {
            return Err("--debug-cache-divergence requires --seedhash=<64-char-hex>".to_owned())
        }
        (false, Some(_)) => {
            return Err("--seedhash=<hex> is valid only with --debug-cache-divergence".to_owned())
        }
    };
    Ok(Command::Mode(ModeInvocation {
        mode,
        debug_cache_divergence_seedhash,
    }))
}

/// `--help` output. The text references the plan-doc anchor so a
/// reviewer reading the CLI surface can find the authoritative spec
/// without spelunking the source tree.
fn print_help() {
    println!(
        "shekyl-randomx-differential — Phase 2g Rust/C differential test harness\n\
         \n\
         Compares the shekyl-pow-randomx Rust verifier against the\n\
         external/randomx-v2 C reference implementation.\n\
         \n\
         USAGE:\n  \
             shekyl-randomx-differential --mode=<MODE> [FLAGS]\n\
         \n\
         MODES:\n  \
             correctness   Per-PR byte-equality across random + adversarial corpora\n  \
             worst-case    Release-gate adversarial latency measurement\n  \
             latency       Nightly per-hash latency benchmark\n  \
             concurrent    Per-PR multi-worker concurrent correctness + RSS bound\n\
         \n\
         FLAGS:\n  \
             --help, -h                          Print this message and exit\n  \
             --debug-cache-divergence            Post-failure cache byte-diff (T4 §5.1.7)\n  \
             --seedhash=<64-char-lowercase-hex>  Seedhash for --debug-cache-divergence\n\
         \n\
         --debug-cache-divergence requires --seedhash=<hex> and is valid\n\
         only with --mode=correctness (per §5.1.7 + T4).\n\
         \n\
         See docs/design/RANDOMX_V2_PHASE2G_PLAN.md §3 + §5.1 for the\n\
         authoritative CLI surface and mode semantics. Additional flags\n\
         (--random-corpus-seedhashes, --random-corpus-data-per-seedhash, …)\n\
         land alongside their module surfaces in subsequent commits\n\
         (C5–C9 per §8.1).\n"
    );
}

fn main() -> ExitCode {
    let argv: Vec<String> = env::args().collect();
    match parse_args(&argv[1..]) {
        Ok(Command::Help) => {
            print_help();
            ExitCode::SUCCESS
        }
        Ok(Command::Mode(invocation)) => {
            // C6 bisection boundary invariant (§8.2): C5 + C6 have
            // landed the corpus, C oracle, Rust subject, and
            // cache-precondition modules; the mode-module dispatch
            // (mode_correctness / mode_latency / mode_concurrent
            // per §§5.1.10, 5.1.12, 5.1.13) lands at C7 + C8 + C9.
            // Until then, surface a clean, attributable error
            // rather than silently exiting zero. The
            // `--debug-cache-divergence` flag is parsed for
            // forward-compatibility per §8.1 C6's "flag wired per
            // T4" acceptance criterion, but the byte-diff path
            // lives in mode_correctness at C7.
            eprintln!(
                "error: shekyl-randomx-differential is at the C6 \
                 boundary (per RANDOMX_V2_PHASE2G_PLAN.md §8.1); \
                 mode '{}' dispatch requires the mode modules \
                 (§§5.1.10, 5.1.12, 5.1.13), which land at C7–C9. \
                 Re-run after the corresponding commits land on this \
                 branch.",
                invocation.mode.as_str()
            );
            if invocation.debug_cache_divergence_seedhash.is_some() {
                eprintln!(
                    "note: --debug-cache-divergence --seedhash=<hex> was parsed \
                     successfully; the diagnostic precondition path lands at C7 \
                     alongside mode_correctness (per §8.1 C7 row)."
                );
            }
            ExitCode::FAILURE
        }
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn parse_help_long() {
        let a = args(&["--help"]);
        assert!(matches!(parse_args(&a), Ok(Command::Help)));
    }

    #[test]
    fn parse_help_short() {
        let a = args(&["-h"]);
        assert!(matches!(parse_args(&a), Ok(Command::Help)));
    }

    #[test]
    fn parse_help_precedes_other_args() {
        let a = args(&["--help", "--mode=correctness"]);
        assert!(matches!(parse_args(&a), Ok(Command::Help)));
    }

    /// Helper: pull the `ModeInvocation` out of a parsed command, or
    /// panic with a description of what we actually got. Keeps test
    /// bodies short while still naming the unexpected value at
    /// failure time.
    fn expect_mode(cmd: Result<Command, String>) -> ModeInvocation {
        match cmd {
            Ok(Command::Mode(m)) => m,
            Ok(Command::Help) => panic!("expected Mode(_), got Help"),
            Err(e) => panic!("expected Mode(_), got Err({e})"),
        }
    }

    #[test]
    fn parse_each_mode() {
        for (s, want) in [
            ("correctness", Mode::Correctness),
            ("worst-case", Mode::WorstCase),
            ("latency", Mode::Latency),
            ("concurrent", Mode::Concurrent),
        ] {
            let a = args(&[&format!("--mode={s}")]);
            let parsed = expect_mode(parse_args(&a));
            assert_eq!(parsed.mode, want, "mode {s}");
            assert_eq!(
                parsed.debug_cache_divergence_seedhash, None,
                "mode {s}: --debug-cache-divergence default unset"
            );
        }
    }

    /// `--debug-cache-divergence` + `--seedhash=<hex>` on
    /// `--mode=correctness` parses to a `ModeInvocation` with the
    /// 32-byte seedhash captured. Pins T4's positive parse path.
    #[test]
    fn parse_debug_cache_divergence_with_seedhash() {
        let seedhash_hex = "11".repeat(32); // 64-char hex
        let a = args(&[
            "--mode=correctness",
            "--debug-cache-divergence",
            &format!("--seedhash={seedhash_hex}"),
        ]);
        let parsed = expect_mode(parse_args(&a));
        assert_eq!(parsed.mode, Mode::Correctness);
        assert_eq!(parsed.debug_cache_divergence_seedhash, Some([0x11; 32]));
    }

    /// `--debug-cache-divergence` without `--seedhash=` errors with
    /// an actionable message. Pins T4's missing-pair detection.
    #[test]
    fn parse_debug_cache_divergence_without_seedhash_errors() {
        let a = args(&["--mode=correctness", "--debug-cache-divergence"]);
        let err = parse_args(&a).expect_err("expected Err for missing seedhash");
        assert!(err.contains("--seedhash="), "got: {err}");
    }

    /// `--seedhash=<hex>` without `--debug-cache-divergence` errors.
    /// Pins T4's reverse-direction detection (the flag's
    /// argument cannot be supplied without the flag).
    #[test]
    fn parse_seedhash_without_debug_flag_errors() {
        let seedhash_hex = "22".repeat(32);
        let a = args(&["--mode=correctness", &format!("--seedhash={seedhash_hex}")]);
        let err = parse_args(&a).expect_err("expected Err for orphan seedhash");
        assert!(err.contains("--debug-cache-divergence"), "got: {err}");
    }

    /// `--debug-cache-divergence` on a non-correctness mode errors;
    /// the precondition's diagnostic path is only meaningful when
    /// the precondition itself runs (which only `correctness` does
    /// per §5.1.10).
    #[test]
    fn parse_debug_cache_divergence_on_non_correctness_mode_errors() {
        let seedhash_hex = "33".repeat(32);
        for non_correct in ["worst-case", "latency", "concurrent"] {
            let a = args(&[
                &format!("--mode={non_correct}"),
                "--debug-cache-divergence",
                &format!("--seedhash={seedhash_hex}"),
            ]);
            let err = parse_args(&a).expect_err(&format!("expected Err for --mode={non_correct}"));
            assert!(
                err.contains("--mode=correctness"),
                "for --mode={non_correct}: got {err}"
            );
        }
    }

    /// Seedhash with the wrong length errors.
    #[test]
    fn parse_seedhash_wrong_length_errors() {
        let a = args(&[
            "--mode=correctness",
            "--debug-cache-divergence",
            "--seedhash=deadbeef", // 8 chars, not 64
        ]);
        let err = parse_args(&a).expect_err("expected Err for short seedhash");
        assert!(err.contains("64 hex characters"), "got: {err}");
    }

    /// Seedhash with invalid hex character errors.
    #[test]
    fn parse_seedhash_invalid_hex_errors() {
        // 64 chars but with a 'z' to fail hex parsing.
        let seedhash_hex = format!("{}{}", "11".repeat(31), "1z");
        let a = args(&[
            "--mode=correctness",
            "--debug-cache-divergence",
            &format!("--seedhash={seedhash_hex}"),
        ]);
        let err = parse_args(&a).expect_err("expected Err for bad hex");
        assert!(err.contains("invalid hex"), "got: {err}");
    }

    /// `--debug-cache-divergence` specified twice errors.
    #[test]
    fn parse_debug_cache_divergence_twice_errors() {
        let seedhash_hex = "44".repeat(32);
        let a = args(&[
            "--mode=correctness",
            "--debug-cache-divergence",
            "--debug-cache-divergence",
            &format!("--seedhash={seedhash_hex}"),
        ]);
        let err = parse_args(&a).expect_err("expected Err for duplicate flag");
        assert!(
            err.contains("--debug-cache-divergence specified more than once"),
            "got: {err}"
        );
    }

    /// `--seedhash=<hex>` specified twice errors.
    #[test]
    fn parse_seedhash_twice_errors() {
        let a = args(&[
            "--mode=correctness",
            "--debug-cache-divergence",
            "--seedhash=55552222555522225555222255552222555522225555222255552222ffff0000",
            "--seedhash=ffff2222555522225555222255552222555522225555222255552222ffff0000",
        ]);
        let err = parse_args(&a).expect_err("expected Err for duplicate seedhash");
        assert!(
            err.contains("--seedhash specified more than once"),
            "got: {err}"
        );
    }

    /// `parse_seedhash_hex` round-trips the standard `Seedhash::Display`
    /// emission format (lowercase hex, no separator).
    #[test]
    fn parse_seedhash_hex_round_trips_lowercase() {
        let bytes: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let hex_str: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let parsed = parse_seedhash_hex(&hex_str).expect("valid hex");
        assert_eq!(parsed, bytes);
    }

    #[test]
    fn parse_empty_argv_errors() {
        let a = args(&[]);
        assert!(parse_args(&a).is_err());
    }

    #[test]
    fn parse_unknown_arg_errors() {
        let a = args(&["--wat"]);
        assert!(parse_args(&a).is_err());
    }

    #[test]
    fn parse_unknown_mode_errors() {
        let a = args(&["--mode=stress"]);
        let err = parse_args(&a).expect_err("expected Err for unknown mode");
        assert!(err.contains("unknown mode 'stress'"));
    }

    #[test]
    fn parse_mode_specified_twice_errors() {
        let a = args(&["--mode=correctness", "--mode=latency"]);
        assert!(parse_args(&a).is_err());
    }

    #[test]
    fn parse_no_mode_errors() {
        let a = args(&["--unknown-but-not-help=value"]);
        assert!(parse_args(&a).is_err());
    }

    #[test]
    fn mode_as_str_round_trips() {
        for m in [
            Mode::Correctness,
            Mode::WorstCase,
            Mode::Latency,
            Mode::Concurrent,
        ] {
            assert_eq!(Mode::parse(m.as_str()).unwrap(), m);
        }
    }
}
