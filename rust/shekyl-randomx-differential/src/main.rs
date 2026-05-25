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
//! ## C4 skeleton scope
//!
//! At C4 (per §8.1), only the argparse + `--mode=*` dispatch shell is
//! in place. The corpus modules (§§5.1.5, 5.1.6), C oracle (§5.1.8),
//! Rust subject (§5.1.9), cache precondition (§5.1.7), failure output
//! schema (§5.1.14), invocation banner (§5.1.18), and the mode
//! implementations (§§5.1.10–5.1.13) all land at C5–C9. The C4 → C5
//! bisection boundary invariant (§8.2) requires that `--mode=*`
//! returns a clear "corpus modules not yet wired" error rather than
//! silently producing empty output; the [`Command::Mode`] arm in
//! [`main`] enforces this.
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

/// Top-level parsed command. The C4 skeleton recognizes only `--help`
/// and `--mode=<value>`; flag additions land alongside the corresponding
/// module surface (e.g., `--debug-cache-divergence` at C6 §5.1.7;
/// `--random-corpus-seedhashes=<N>` / `--random-corpus-data-per-seedhash=<M>`
/// at C5 §5.1.5).
#[derive(Debug)]
enum Command {
    Help,
    Mode(Mode),
}

/// Hand-rolled argv parser. Returns a clean diagnostic for any
/// unknown / malformed argument so reviewers reading CI logs see the
/// specific argument that broke the invocation.
fn parse_args(args: &[String]) -> Result<Command, String> {
    if args.is_empty() {
        return Err("no arguments; pass --help for usage".to_owned());
    }
    let mut mode: Option<Mode> = None;
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
        return Err(format!(
            "unknown argument '{arg}'; pass --help for usage"
        ));
    }
    mode.map(Command::Mode)
        .ok_or_else(|| "no --mode specified; pass --help for usage".to_owned())
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
             --help, -h    Print this message and exit\n\
         \n\
         See docs/design/RANDOMX_V2_PHASE2G_PLAN.md §3 + §5.1 for the\n\
         authoritative CLI surface and mode semantics. Additional flags\n\
         (--random-corpus-seedhashes, --random-corpus-data-per-seedhash,\n\
         --debug-cache-divergence, …) land alongside their module\n\
         surfaces in subsequent commits (C5–C9 per §8.1).\n"
    );
}

fn main() -> ExitCode {
    let argv: Vec<String> = env::args().collect();
    match parse_args(&argv[1..]) {
        Ok(Command::Help) => {
            print_help();
            ExitCode::SUCCESS
        }
        Ok(Command::Mode(mode)) => {
            // C4 → C5 bisection boundary invariant (§8.2): until C5
            // lands the corpus modules and C6 lands the C oracle +
            // Rust subject + cache precondition, no mode can produce
            // hash output. Surface a clean, attributable error rather
            // than silently exiting zero.
            eprintln!(
                "error: shekyl-randomx-differential is at the C4 \
                 skeleton (per RANDOMX_V2_PHASE2G_PLAN.md §8.1); \
                 mode '{}' dispatch requires the corpus modules \
                 (§5.1.5, §5.1.6) and the C oracle / Rust subject / \
                 cache-precondition modules (§5.1.7–§5.1.9), which \
                 land at C5–C6. Re-run after the corresponding \
                 commits land on this branch.",
                mode.as_str()
            );
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

    /// Helper: pull the `Mode` out of a parsed command, or panic with
    /// a description of what we actually got. Keeps test bodies short
    /// while still naming the unexpected value at failure time.
    fn expect_mode(cmd: Result<Command, String>) -> Mode {
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
            assert_eq!(expect_mode(parse_args(&a)), want, "mode {s}");
        }
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
        for m in [Mode::Correctness, Mode::WorstCase, Mode::Latency, Mode::Concurrent] {
            assert_eq!(Mode::parse(m.as_str()).unwrap(), m);
        }
    }
}
