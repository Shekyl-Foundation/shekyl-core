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
//! - **C7:** `mode_correctness` (§5.1.10) + `mode_latency`
//!   (§5.1.12) implementations; `--mode={correctness,latency}`
//!   dispatch wires through to the module entry points
//!   (§5.1.11 / `mode_worst_case` / `--mode=worst-case` deferred
//!   per §3.19 R7-D4 to the post-2g adversarial-corpus design
//!   round).
//! - **C8:** `mode_concurrent` (§5.1.13) implementation +
//!   `--mode=concurrent` dispatch wire-through + `--workers=<N>`
//!   flag wired (R1-D9 + §3.15.3 default = 5) + RSS-bound
//!   assertion (T7 + T8).
//! - **C9:** `failure_output` (§5.1.14) JSON schema +
//!   `invocation_banner` (§5.1.18) stderr emission + deletion of
//!   the `rust/shekyl-pow-randomx/tests/perf/per_hash_latency.rs`
//!   placeholder (per §8.1's C9 row).
//!
//! ## §5.1.18 invocation banner
//!
//! Per §5.1.18 + §4.6 M4, the harness emits a disposition-source
//! banner on stderr before any test output begins. The banner is
//! emitted in [`dispatch`] right after the help-branch returns,
//! before any mode-module entry point runs. T17 (per §6.7.5)
//! pins the banner content via [`invocation_banner`]'s
//! `#[cfg(test)]` unit tests; emission failures are absorbed
//! (logged to stderr) rather than aborting the harness — a
//! broken stderr channel must not block the divergence-detection
//! pipeline the banner exists to attest to.

use std::env;
use std::process::ExitCode;

use shekyl_randomx_differential::{
    invocation_banner, mode_concurrent, mode_correctness, mode_latency,
};

/// R4-D6 default for `--random-corpus-seedhashes` (nightly sizing
/// per §6.1 T1; per-PR CI passes `--random-corpus-seedhashes=16`).
const DEFAULT_RANDOM_CORPUS_SEEDHASHES: usize = 32;

/// R4-D6 default for `--random-corpus-data-per-seedhash` (nightly
/// sizing per §6.1 T1; per-PR CI passes
/// `--random-corpus-data-per-seedhash=8`).
const DEFAULT_RANDOM_CORPUS_DATA_PER_SEEDHASH: usize = 32;

/// R1-D7 / §3.15.3 default for `--samples` (latency mode iteration
/// count). Per the §3.15.3 CLI sketch's "[--samples=<u32>] # default:
/// 1024; valid on latency only" line.
const DEFAULT_LATENCY_SAMPLES: usize = 1024;

/// R1-D9 / §3.15.3 default for `--workers` (concurrent mode worker
/// count). Per the §3.15.3 CLI sketch's "[--workers=<u32>] # default:
/// 5; valid on concurrent only" line; the constant is also re-
/// exposed as [`mode_concurrent::DEFAULT_WORKER_COUNT`] for the
/// mode-module's internal references. Re-stating the literal here
/// keeps the CLI-default substrate at the binary boundary (a
/// reviewer reading `main.rs` sees the default without spelunking
/// the library).
const DEFAULT_CONCURRENT_WORKERS: usize = 5;

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
    /// `--random-corpus-seedhashes=<N>` override (R4-D6; valid on
    /// correctness only; default
    /// [`DEFAULT_RANDOM_CORPUS_SEEDHASHES`]).
    random_corpus_seedhashes: Option<usize>,
    /// `--random-corpus-data-per-seedhash=<M>` override (R4-D6;
    /// valid on correctness only; default
    /// [`DEFAULT_RANDOM_CORPUS_DATA_PER_SEEDHASH`]).
    random_corpus_data_per_seedhash: Option<usize>,
    /// `--samples=<N>` override (R1-D7; valid on latency only;
    /// default [`DEFAULT_LATENCY_SAMPLES`]).
    samples: Option<usize>,
    /// `--workers=<N>` override (R1-D9; valid on concurrent only;
    /// default [`DEFAULT_CONCURRENT_WORKERS`]).
    workers: Option<usize>,
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
    // Reject `[A-F]` explicitly. `u8::from_str_radix(_, 16)` accepts
    // both cases, but the lowercase pin (matching `Seedhash::Display`
    // in `seedhash.rs:75-77`) is load-bearing: CI emits failing
    // seedhashes lowercase, and a copy-paste-into-`--seedhash=`
    // workflow needs the parser to refuse mixed-case input rather
    // than silently accept it and produce a value that no longer
    // round-trips through Display. The discipline parallels the
    // `Seedhash::from_hex_string` pattern in the verifier crate.
    for (i, byte) in value.bytes().enumerate() {
        if byte.is_ascii_uppercase() {
            return Err(format!(
                "--seedhash: character {i}: uppercase hex rejected; use lowercase per Seedhash::Display"
            ));
        }
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

/// Parse a `--<flag>=<value>` integer argument, surfacing the flag
/// name in any error diagnostic so reviewers don't have to map
/// "invalid value 'foo'" back to "which flag was that for again?".
///
/// `0` is rejected explicitly because every flag wired here
/// (`--random-corpus-seedhashes`, `--random-corpus-data-per-seedhash`,
/// `--samples`) is meaningless at zero; the modes' invariants
/// require at least one iteration.
fn parse_positive_usize(flag: &str, value: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|e| format!("--{flag}: invalid integer '{value}': {e}"))?;
    if parsed == 0 {
        return Err(format!("--{flag}: must be >= 1; got 0"));
    }
    Ok(parsed)
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
    let mut random_corpus_seedhashes: Option<usize> = None;
    let mut random_corpus_data_per_seedhash: Option<usize> = None;
    let mut samples: Option<usize> = None;
    let mut workers: Option<usize> = None;
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
        if let Some(value) = arg.strip_prefix("--random-corpus-seedhashes=") {
            if random_corpus_seedhashes.is_some() {
                return Err("--random-corpus-seedhashes specified more than once".to_owned());
            }
            random_corpus_seedhashes =
                Some(parse_positive_usize("random-corpus-seedhashes", value)?);
            continue;
        }
        if let Some(value) = arg.strip_prefix("--random-corpus-data-per-seedhash=") {
            if random_corpus_data_per_seedhash.is_some() {
                return Err("--random-corpus-data-per-seedhash specified more than once".to_owned());
            }
            random_corpus_data_per_seedhash = Some(parse_positive_usize(
                "random-corpus-data-per-seedhash",
                value,
            )?);
            continue;
        }
        if let Some(value) = arg.strip_prefix("--samples=") {
            if samples.is_some() {
                return Err("--samples specified more than once".to_owned());
            }
            samples = Some(parse_positive_usize("samples", value)?);
            continue;
        }
        if let Some(value) = arg.strip_prefix("--workers=") {
            if workers.is_some() {
                return Err("--workers specified more than once".to_owned());
            }
            workers = Some(parse_positive_usize("workers", value)?);
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
    // §3.15.3 mode-scope-violation enforcement: corpus-sizing flags
    // are valid on correctness only; --samples is valid on latency
    // only. Reject at parse time with a clear "flag X is valid only
    // for --mode=Y" message rather than letting the mode-module
    // ignore it silently.
    if random_corpus_seedhashes.is_some() && mode != Mode::Correctness {
        return Err(format!(
            "--random-corpus-seedhashes is valid only with --mode=correctness; \
             got --mode={}",
            mode.as_str()
        ));
    }
    if random_corpus_data_per_seedhash.is_some() && mode != Mode::Correctness {
        return Err(format!(
            "--random-corpus-data-per-seedhash is valid only with --mode=correctness; \
             got --mode={}",
            mode.as_str()
        ));
    }
    if samples.is_some() && mode != Mode::Latency {
        return Err(format!(
            "--samples is valid only with --mode=latency; got --mode={}",
            mode.as_str()
        ));
    }
    if workers.is_some() && mode != Mode::Concurrent {
        return Err(format!(
            "--workers is valid only with --mode=concurrent; got --mode={}",
            mode.as_str()
        ));
    }
    Ok(Command::Mode(ModeInvocation {
        mode,
        debug_cache_divergence_seedhash,
        random_corpus_seedhashes,
        random_corpus_data_per_seedhash,
        samples,
        workers,
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
             --help, -h                                Print this message and exit\n  \
             --debug-cache-divergence                  Post-failure cache byte-diff (T4 §5.1.7)\n  \
             --seedhash=<64-char-lowercase-hex>        Seedhash for --debug-cache-divergence\n  \
             --random-corpus-seedhashes=<N>            Random corpus seedhash count (default 32; correctness only)\n  \
             --random-corpus-data-per-seedhash=<M>     Random corpus data-per-seedhash count (default 32; correctness only)\n  \
             --samples=<N>                             Latency mode sample count (default 1024; latency only)\n  \
             --workers=<N>                             Concurrent mode worker count (default 5; concurrent only)\n\
         \n\
         --debug-cache-divergence requires --seedhash=<hex> and is valid\n\
         only with --mode=correctness (per §5.1.7 + T4).\n\
         \n\
         Per-PR CI passes --random-corpus-seedhashes=16\n\
         --random-corpus-data-per-seedhash=8 (per §6.1 T1 sizing);\n\
         nightly + release-gate run defaults (32×32) per R4-D6.\n\
         \n\
         See docs/design/RANDOMX_V2_PHASE2G_PLAN.md §3 + §5.1 for the\n\
         authoritative CLI surface and mode semantics.\n"
    );
}

fn main() -> ExitCode {
    let argv: Vec<String> = env::args().collect();
    match parse_args(&argv[1..]) {
        Ok(Command::Help) => {
            print_help();
            ExitCode::SUCCESS
        }
        Ok(Command::Mode(invocation)) => dispatch(&invocation),
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

/// Dispatch a parsed `ModeInvocation` to the corresponding mode
/// module. Pulled out of `main` so the dispatch surface is unit-
/// testable structurally (the `ExitCode` return is opaque, but the
/// mode-module entry points are integration-testable in isolation).
///
/// Per §8.1's C7 → C9 sequencing:
///
/// - **C7**: `correctness` (§5.1.10) + `latency` (§5.1.12) wired.
/// - **C8**: `concurrent` (§5.1.13) wired with `--workers=<N>`.
/// - **C9**: `failure_output` JSON schema + invocation banner +
///   `mode_worst_case` per §3.19 R7-D4 deferral resolution (or
///   permanent deferral if the post-2g adversarial-corpus design
///   round confirms infeasibility).
///
/// Until then, `worst-case` surfaces a clean "deferred" error
/// with the R7-D4 anchor so the C7 → C9 transitional state is
/// reviewer-attributable per §8.2's bisection invariant.
fn dispatch(invocation: &ModeInvocation) -> ExitCode {
    // §5.1.18 + §4.6 M4: emit the disposition-source banner to
    // stderr before any mode-module entry point runs. Emission
    // failures are absorbed (logged with `error: invocation_banner
    // emit failed:`) per `emit_banner_to_stderr`'s contract;
    // the divergence-detection pipeline must not be blocked by
    // a broken stderr channel.
    invocation_banner::emit_banner_to_stderr(invocation.mode.as_str());

    match invocation.mode {
        Mode::Correctness => {
            let seedhashes = invocation
                .random_corpus_seedhashes
                .unwrap_or(DEFAULT_RANDOM_CORPUS_SEEDHASHES);
            let data_per_seedhash = invocation
                .random_corpus_data_per_seedhash
                .unwrap_or(DEFAULT_RANDOM_CORPUS_DATA_PER_SEEDHASH);
            match mode_correctness::run(
                seedhashes,
                data_per_seedhash,
                invocation.debug_cache_divergence_seedhash,
            ) {
                Ok(report) => {
                    println!("{report}");
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("error: {err}");
                    ExitCode::FAILURE
                }
            }
        }
        Mode::Latency => {
            let samples = invocation.samples.unwrap_or(DEFAULT_LATENCY_SAMPLES);
            match mode_latency::run(samples) {
                Ok(report) => {
                    println!("{report}");
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("error: {err}");
                    ExitCode::FAILURE
                }
            }
        }
        Mode::WorstCase => {
            // §3.19 R7-D4: --mode=worst-case is deferred to the
            // post-2g adversarial-corpus design round per the
            // statistical-infeasibility finding against R1-D5's
            // grinded-corpus methodology. Surface a clean,
            // attributable error so a reviewer reading CI output
            // can locate the disposition without spelunking.
            eprintln!(
                "error: --mode=worst-case is deferred per \
                 RANDOMX_V2_PHASE2G_PLAN.md §3.19 R7-D4 \
                 (adversarial-corpus methodology design round \
                 deferred to post-2g per V3.0 pre-genesis queue \
                 in docs/FOLLOWUPS.md); the mode dispatch is \
                 retained in the CLI surface for forward-\
                 compatibility but produces no output until the \
                 post-2g design round resolves R1-D5 + R1-D6."
            );
            ExitCode::FAILURE
        }
        Mode::Concurrent => {
            let workers = invocation.workers.unwrap_or(DEFAULT_CONCURRENT_WORKERS);
            match mode_concurrent::run(workers) {
                Ok(report) => {
                    println!("{report}");
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("error: {err}");
                    ExitCode::FAILURE
                }
            }
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
            assert_eq!(
                parsed.random_corpus_seedhashes, None,
                "mode {s}: --random-corpus-seedhashes default unset"
            );
            assert_eq!(
                parsed.random_corpus_data_per_seedhash, None,
                "mode {s}: --random-corpus-data-per-seedhash default unset"
            );
            assert_eq!(parsed.samples, None, "mode {s}: --samples default unset");
            assert_eq!(parsed.workers, None, "mode {s}: --workers default unset");
        }
    }

    /// `--workers=<N>` on `--mode=concurrent` parses cleanly. Pins
    /// R1-D9's `--workers` override path.
    #[test]
    fn parse_workers_on_concurrent() {
        let a = args(&["--mode=concurrent", "--workers=4"]);
        let parsed = expect_mode(parse_args(&a));
        assert_eq!(parsed.mode, Mode::Concurrent);
        assert_eq!(parsed.workers, Some(4));
    }

    /// `--workers=0` is rejected at parse time.
    #[test]
    fn parse_workers_zero_rejected() {
        let a = args(&["--mode=concurrent", "--workers=0"]);
        let err = parse_args(&a).expect_err("expected Err for --workers=0");
        assert!(err.contains("must be >= 1"), "got: {err}");
    }

    /// `--workers=<N>` specified twice errors.
    #[test]
    fn parse_workers_twice_errors() {
        let a = args(&["--mode=concurrent", "--workers=4", "--workers=5"]);
        let err = parse_args(&a).expect_err("expected Err for duplicate flag");
        assert!(
            err.contains("--workers specified more than once"),
            "got: {err}"
        );
    }

    /// `--workers=<N>` on a non-concurrent mode errors with the
    /// mode-scope-violation diagnostic.
    #[test]
    fn parse_workers_on_non_concurrent_errors() {
        for non_concurrent in ["correctness", "worst-case", "latency"] {
            let a = args(&[&format!("--mode={non_concurrent}"), "--workers=4"]);
            let err =
                parse_args(&a).expect_err(&format!("expected Err for --mode={non_concurrent}"));
            assert!(
                err.contains("--mode=concurrent"),
                "for --mode={non_concurrent}: got {err}"
            );
        }
    }

    /// Per-PR CI passes `--random-corpus-seedhashes=16` +
    /// `--random-corpus-data-per-seedhash=8`. Pins the §6.1 T1
    /// per-PR sizing parse path.
    #[test]
    fn parse_random_corpus_sizing_per_pr() {
        let a = args(&[
            "--mode=correctness",
            "--random-corpus-seedhashes=16",
            "--random-corpus-data-per-seedhash=8",
        ]);
        let parsed = expect_mode(parse_args(&a));
        assert_eq!(parsed.mode, Mode::Correctness);
        assert_eq!(parsed.random_corpus_seedhashes, Some(16));
        assert_eq!(parsed.random_corpus_data_per_seedhash, Some(8));
    }

    /// `--samples=2048` on `--mode=latency` parses cleanly. Pins
    /// R1-D7's `--samples` override path.
    #[test]
    fn parse_samples_on_latency() {
        let a = args(&["--mode=latency", "--samples=2048"]);
        let parsed = expect_mode(parse_args(&a));
        assert_eq!(parsed.mode, Mode::Latency);
        assert_eq!(parsed.samples, Some(2048));
    }

    /// `--random-corpus-seedhashes=0` is rejected at parse time
    /// (every flag's zero value is meaningless for the modes that
    /// consume them).
    #[test]
    fn parse_zero_value_flags_rejected() {
        for (flag, mode) in [
            ("--random-corpus-seedhashes=0", "correctness"),
            ("--random-corpus-data-per-seedhash=0", "correctness"),
            ("--samples=0", "latency"),
        ] {
            let a = args(&[&format!("--mode={mode}"), flag]);
            let err = parse_args(&a).expect_err(&format!("expected Err for {flag}"));
            assert!(err.contains("must be >= 1"), "for {flag}: got {err}");
        }
    }

    /// Corpus-sizing flags on a non-correctness mode error with
    /// the mode-scope-violation diagnostic.
    #[test]
    fn parse_corpus_flags_on_non_correctness_errors() {
        for non_correct in ["worst-case", "latency", "concurrent"] {
            let a = args(&[
                &format!("--mode={non_correct}"),
                "--random-corpus-seedhashes=16",
            ]);
            let err = parse_args(&a).expect_err(&format!("expected Err for --mode={non_correct}"));
            assert!(
                err.contains("--mode=correctness"),
                "for --mode={non_correct}: got {err}"
            );
        }
    }

    /// `--samples=<N>` on a non-latency mode errors with the
    /// mode-scope-violation diagnostic.
    #[test]
    fn parse_samples_on_non_latency_errors() {
        for non_latency in ["correctness", "worst-case", "concurrent"] {
            let a = args(&[&format!("--mode={non_latency}"), "--samples=1024"]);
            let err = parse_args(&a).expect_err(&format!("expected Err for --mode={non_latency}"));
            assert!(
                err.contains("--mode=latency"),
                "for --mode={non_latency}: got {err}"
            );
        }
    }

    /// `--random-corpus-seedhashes=<N>` specified twice errors.
    #[test]
    fn parse_random_corpus_seedhashes_twice_errors() {
        let a = args(&[
            "--mode=correctness",
            "--random-corpus-seedhashes=16",
            "--random-corpus-seedhashes=8",
        ]);
        let err = parse_args(&a).expect_err("expected Err for duplicate flag");
        assert!(
            err.contains("--random-corpus-seedhashes specified more than once"),
            "got: {err}"
        );
    }

    /// `--random-corpus-seedhashes=foo` errors with the
    /// "invalid integer" diagnostic.
    #[test]
    fn parse_random_corpus_seedhashes_non_integer_errors() {
        let a = args(&["--mode=correctness", "--random-corpus-seedhashes=foo"]);
        let err = parse_args(&a).expect_err("expected Err for non-integer");
        assert!(err.contains("invalid integer 'foo'"), "got: {err}");
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
    fn parse_seedhash_hex_rejects_uppercase() {
        // The lowercase pin is load-bearing per the function's doc-
        // comment cross-reference to `Seedhash::Display`; CI output
        // is lowercase by construction, and a mixed-case input that
        // silently parsed would produce a `Seedhash` that no longer
        // round-trips through `Display`. The test pairs with the
        // explicit rejection branch above.
        let upper = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899";
        let err = parse_seedhash_hex(upper).expect_err("uppercase must reject");
        assert!(
            err.contains("uppercase hex rejected"),
            "diagnostic should name uppercase rejection; got: {err}"
        );
        // Mixed case also rejects (the first uppercase char wins).
        let mixed = "aaBBccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        assert!(parse_seedhash_hex(mixed).is_err());
        // Lowercase still works (parallel positive case).
        let lower = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        assert!(parse_seedhash_hex(lower).is_ok());
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
