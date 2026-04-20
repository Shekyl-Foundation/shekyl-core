// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Legacy easylogging++ `log-levels=` grammar translator.
//!
//! Input grammar (summarized from `contrib/epee/src/mlog.cpp`
//! `mlog_set_log` and `mlog_set_categories`):
//!
//! ```text
//! spec     := empty | numeric | numeric "," categories | categories
//! numeric  := 0 | 1 | 2 | 3 | 4
//! categories := category ("," category)*
//! category := ("+" | "-")? name ":" LEVEL
//!             | ("+" | "-")? name
//! name     := literal name | "*" | prefix "*" | "*" suffix  (* rejected *)
//! LEVEL    := FATAL | ERROR | WARNING | INFO | DEBUG | TRACE
//!             (case-insensitive on input; warnings fire for lowercase)
//! ```
//!
//! Output grammar: `tracing_subscriber::EnvFilter` directive syntax.
//! EnvFilter treats `foo=debug` as a prefix match at the `::` boundary,
//! which matches easylogging++'s `foo.bar:LEVEL` addressing once we
//! translate `.` → `::`.
//!
//! The preset translations for `--log-level 0..=4` are **hand-written** in
//! [`PRESETS`] below, verified against
//! `contrib/epee/src/mlog.cpp:get_default_categories`. Do not regenerate
//! them by round-tripping through this module; that would ratify whatever
//! the implementation happens to produce.

use tracing::Level;

use crate::filter::{level_directive, FilterError, TranslationReport};

/// Hand-translated EnvFilter directives for the five numeric presets.
///
/// Sourced from `contrib/epee/src/mlog.cpp:get_default_categories`
/// (LEVEL 0..=4) and verified manually. Each string MUST round-trip
/// through `EnvFilter::try_new` without error.
///
/// `LEVEL 3` in the C++ source is `*:TRACE,*.dump:DEBUG`. The `*.dump`
/// suffix-glob is rejected in the general translator path (see
/// [`FilterError::UnsupportedGlob`]). For the LEVEL 3 preset specifically,
/// Rust has no `.dump` targets today — the Chore #2 C++ integration
/// introduces them — so the preset reduces to `trace` for now. When
/// Chore #2 wires the C++ shim through `tracing`, this preset must be
/// revisited. A note lives in `docs/STRUCTURAL_TODO.md`.
const PRESETS: [&str; 5] = [
    // LEVEL 0 — mirrors mlog.cpp, order preserved for diff review.
    "warn,\
net=error,\
net::http=error,\
net::ssl=error,\
net::p2p=error,\
net::cn=error,\
daemon::rpc=error,\
global=info,\
verify=error,\
serialization=error,\
daemon::rpc::payment=error,\
stacktrace=info,\
logging=info,\
msgwriter=info",
    // LEVEL 1
    "info,\
global=info,\
stacktrace=info,\
logging=info,\
msgwriter=info,\
perf=debug",
    // LEVEL 2
    "debug",
    // LEVEL 3 (see comment above; *.dump:DEBUG dropped for Chore #1)
    "trace",
    // LEVEL 4
    "trace",
];

/// Retrieve the preset directive for a numeric level.
#[must_use]
pub(crate) fn preset_directive(level: u8) -> Option<&'static str> {
    PRESETS.get(level as usize).copied()
}

/// Main entry point; see [`crate::filter::directives_from_legacy_categories`].
pub(crate) fn translate(
    current_spec: Option<&str>,
    new_spec: &str,
    fallback_default: Level,
) -> Result<TranslationReport, FilterError> {
    let trimmed = new_spec.trim();

    // Empty-spec handling — the whole landmine discussion lives here.
    if trimmed.is_empty() {
        return Ok(if current_spec.is_some() {
            // RPC-runtime path: empty input means "don't change the
            // current filter." Return an empty directive; caller knows
            // this is a no-op.
            TranslationReport::default()
        } else {
            // Startup path: no prior filter, no input. Fall back to the
            // caller-provided binary default rather than letting the
            // subscriber run with an empty directive (which
            // `EnvFilter::try_new` accepts and silently means "disabled").
            TranslationReport {
                directive: level_directive(fallback_default),
                unknown: Vec::new(),
                warnings: Vec::new(),
            }
        });
    }

    // Try the numeric-only or numeric+categories path first, so that
    // negative numeric literals (`-1`, `-5`) reach
    // `NumericLevelOutOfRange` rather than being mis-read as
    // `-`-modifier specs. `split_numeric_head` returns `None` when the
    // head is not a valid integer, so `-foo` falls through to the
    // modifier path below.
    if let Some((numeric_part, rest)) = split_numeric_head(trimmed) {
        return translate_numeric(numeric_part, rest);
    }

    // Resolve `+` / `-` modifiers by textually merging against
    // `current_spec` before translation. The merged spec is then fed
    // back into the translator. Recursion depth is bounded to 1 because
    // `merge_modifier` always produces a non-modifier spec.
    if let Some(first) = trimmed.chars().next() {
        if first == '+' || first == '-' {
            let merged = merge_modifier(current_spec.unwrap_or(""), trimmed)?;
            return translate(current_spec, &merged, fallback_default);
        }
    }

    // Plain comma-separated category list.
    translate_categories(trimmed)
}

/// Apply an append (`+`) or remove (`-`) modifier to `current`.
///
/// The modifier grammar is simple: the input starts with `+` or `-`,
/// followed by a normal category-list spec. `+cat:LEVEL` appends; `-cat`
/// removes all entries whose name matches `cat` exactly.
fn merge_modifier(current: &str, input: &str) -> Result<String, FilterError> {
    // We split off the leading modifier character and parse the rest as a
    // normal category list. The result is textually spliced back into
    // `current`.
    let mut chars = input.chars();
    let modifier = chars.next().ok_or_else(|| FilterError::MalformedSpec {
        reason: "empty modifier spec".to_owned(),
    })?;
    let tail = chars.as_str().trim();
    if tail.is_empty() {
        return Err(FilterError::MalformedSpec {
            reason: format!("modifier {modifier:?} with no body"),
        });
    }

    match modifier {
        '+' => {
            // Append each comma-separated entry to `current`. We do not
            // deduplicate; last-wins ordering handles overlap naturally.
            let current_trimmed = current.trim();
            if current_trimmed.is_empty() {
                Ok(tail.to_owned())
            } else {
                Ok(format!("{current_trimmed},{tail}"))
            }
        }
        '-' => {
            // Remove any entry in `current` whose bare name (part before
            // `:`) matches any name in `tail`. `tail` may contain levels
            // (`-foo:DEBUG`); we key on the name only, matching mlog.cpp
            // behavior.
            let remove_names: Vec<&str> = tail
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|entry| entry.split(':').next().unwrap_or(entry).trim())
                .collect();

            let kept: Vec<&str> = current
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .filter(|entry| {
                    let name = entry.split(':').next().unwrap_or(entry).trim();
                    !remove_names.contains(&name)
                })
                .collect();

            Ok(kept.join(","))
        }
        other => Err(FilterError::MalformedSpec {
            reason: format!("unknown modifier {other:?}"),
        }),
    }
}

/// Try to peel a leading numeric-preset value from `spec`.
///
/// Returns `Some((n, rest_after_comma))` when successful.
fn split_numeric_head(spec: &str) -> Option<(i64, &str)> {
    let (head, rest) = match spec.find(',') {
        Some(ix) => (&spec[..ix], &spec[ix + 1..]),
        None => (spec, ""),
    };
    let parsed: i64 = head.trim().parse().ok()?;
    Some((parsed, rest))
}

fn translate_numeric(numeric: i64, rest: &str) -> Result<TranslationReport, FilterError> {
    if !(0..=4).contains(&numeric) {
        return Err(FilterError::NumericLevelOutOfRange { value: numeric });
    }
    // Range-checked above.
    let preset = u8::try_from(numeric)
        .ok()
        .and_then(preset_directive)
        .expect("range-checked 0..=4 above");

    let rest_trimmed = rest.trim();
    if rest_trimmed.is_empty() {
        return Ok(TranslationReport {
            directive: preset.to_owned(),
            unknown: Vec::new(),
            warnings: Vec::new(),
        });
    }

    // Translate the remainder and concat. Last-wins means appended
    // entries override preset entries for matching targets.
    let tail = translate_categories(rest_trimmed)?;
    let mut directive = preset.to_owned();
    if !tail.directive.is_empty() {
        directive.push(',');
        directive.push_str(&tail.directive);
    }
    Ok(TranslationReport {
        directive,
        unknown: tail.unknown,
        warnings: tail.warnings,
    })
}

fn translate_categories(spec: &str) -> Result<TranslationReport, FilterError> {
    let mut directive_parts: Vec<String> = Vec::new();
    let mut unknown: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    for raw_entry in spec.split(',') {
        let entry = raw_entry.trim();
        if entry.is_empty() {
            continue;
        }
        if let Some(glob_err) = detect_suffix_glob(entry) {
            return Err(glob_err);
        }
        translate_one_entry(entry, &mut directive_parts, &mut unknown, &mut warnings)?;
    }

    Ok(TranslationReport {
        directive: directive_parts.join(","),
        unknown,
        warnings,
    })
}

/// Detect the unsupported suffix-glob shape (`*y.z:LEVEL` /
/// `*.dump:LEVEL`) and return a [`FilterError::UnsupportedGlob`] if
/// found.
fn detect_suffix_glob(entry: &str) -> Option<FilterError> {
    // Peel the optional `:LEVEL` tail before inspecting the name shape.
    let name = entry.split(':').next().unwrap_or(entry).trim();

    if !name.starts_with('*') || name == "*" {
        return None;
    }
    // Bare `*:LEVEL` is fine; covered above.
    // Names like `*foo` or `*.foo` are suffix globs.

    // Special-case `*.something` as a likely typo for `something.*`
    // (prefix glob). The suggestion materializes a rewrite the user can
    // paste back without further thought.
    let suggested_rewrite = if let Some(after_star_dot) = name.strip_prefix("*.") {
        // Reconstruct with the level tail attached, if present.
        let level_tail = entry
            .split_once(':')
            .map_or(String::new(), |(_, level)| format!(":{level}"));
        Some(format!("{after_star_dot}.*{level_tail}"))
    } else {
        None
    };

    Some(FilterError::UnsupportedGlob {
        original: name.to_owned(),
        suggested_rewrite,
    })
}

fn translate_one_entry(
    entry: &str,
    directive_parts: &mut Vec<String>,
    unknown: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Result<(), FilterError> {
    // Entries are `name[:LEVEL]` — the bare `name` form has no direct
    // EnvFilter equivalent, so we treat it as MalformedSpec.
    let (name, level_token) = match entry.split_once(':') {
        Some((n, l)) => (n.trim(), Some(l.trim())),
        None => (entry, None),
    };
    let Some(level_token) = level_token else {
        return Err(FilterError::MalformedSpec {
            reason: format!("entry {entry:?} has no level; expected name:LEVEL"),
        });
    };

    let (level_lower, was_lowercase) = normalize_level_name(level_token)?;
    if was_lowercase {
        warnings.push(format!(
            "lowercase level {level_token:?} accepted; prefer uppercase"
        ));
    }

    // Recognized vs. reserved-for-legacy names: we don't reject unknown
    // names, but we report them through `unknown`. The target-known list
    // changes frequently enough that hardcoding it in this crate would
    // bit-rot; that discipline lives in `tests/presets.rs`.
    if !is_known_legacy_category(name) {
        unknown.push(name.to_owned());
    }

    directive_parts.push(match name {
        // `*:LEVEL` is the global default, written in EnvFilter as a
        // bare level with no target.
        "*" => level_lower.to_owned(),
        // `perf.*:LEVEL` becomes `perf=level`; the `::` prefix-match
        // semantics of EnvFilter handle the wildcard exactly.
        name if name.ends_with(".*") => {
            let prefix = name.trim_end_matches(".*");
            let prefix = prefix.replace('.', "::");
            format!("{prefix}={level_lower}")
        }
        // `glo*:LEVEL` (prefix glob without `.` anchor) — EnvFilter does
        // not support this form natively. We translate to the nearest
        // available thing (`glo={level}`) and warn: in the legacy C++
        // world `glo*` matched `global`, `globals`, etc; in tracing it
        // will match only the literal `glo` target and descendants under
        // the `::` boundary. Cleanup is on the user.
        name if name.ends_with('*') => {
            let prefix = name.trim_end_matches('*');
            warnings.push(format!(
                "prefix glob without `.` anchor: {entry:?} translated as \
                 `{prefix}={level_lower}`; the legacy behavior that matched \
                 any target starting with {prefix:?} is not expressible in \
                 EnvFilter"
            ));
            let target = prefix.replace('.', "::");
            format!("{target}={level_lower}")
        }
        name => {
            let target = name.replace('.', "::");
            format!("{target}={level_lower}")
        }
    });
    Ok(())
}

/// Map a level token (any case, six names) to the EnvFilter lowercase
/// spelling, and report whether the input was lowercase (for warnings).
///
/// FATAL maps to `error` since `tracing` has no FATAL level.
fn normalize_level_name(token: &str) -> Result<(&'static str, bool), FilterError> {
    let upper = token.to_ascii_uppercase();
    let (lowered, _) = match upper.as_str() {
        "FATAL" | "ERROR" => ("error", "ERROR"),
        "WARNING" | "WARN" => ("warn", "WARN"),
        "INFO" => ("info", "INFO"),
        "DEBUG" => ("debug", "DEBUG"),
        "TRACE" => ("trace", "TRACE"),
        _ => {
            return Err(FilterError::UnknownLevel {
                token: token.to_owned(),
            })
        }
    };
    let was_lowercase = token != upper;
    Ok((lowered, was_lowercase))
}

/// Conservative check: categories that are definitely legacy
/// easylogging++ names (derived from the corpus dump).
///
/// This list feeds only the `unknown` reporting channel; unrecognized
/// names are still accepted into the directive. The list is deliberately
/// conservative — false negatives (valid name missing from the list)
/// surface as a soft warning, not a hard error.
fn is_known_legacy_category(name: &str) -> bool {
    // Anything with a wildcard is handled by the special forms above.
    if name.contains('*') {
        return true;
    }
    // Hardcoded from the corpus of SHEKYL_DEFAULT_LOG_CATEGORY definitions
    // plus the preset-embedded names. See `tests/presets.rs` for the same
    // list in a test-visible form.
    const KNOWN: &[&str] = &[
        // Preset-embedded names
        "global",
        "net",
        "net.http",
        "net.ssl",
        "net.p2p",
        "net.cn",
        "daemon.rpc",
        "daemon.rpc.payment",
        "verify",
        "serialization",
        "stacktrace",
        "logging",
        "msgwriter",
        "perf",
        // Common SHEKYL_DEFAULT_LOG_CATEGORY values
        "blockchain",
        "blockchain.db",
        "blockchain.db.lmdb",
        "bcutil",
        "cn",
        "daemon",
        "debugtools.dnschecks",
        "debugtools.deserialize",
        "hardfork",
        "levin",
        "miner",
        "mnemonic",
        "p2p",
        "rpc",
        "tests.core",
        "txpool",
        "wallet",
        "wallet.mms",
        "wallet.ringdb",
        "wallet.simplewallet",
        "wallet.wallet2",
    ];
    KNOWN.contains(&name)
}

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT: Level = Level::WARN;

    fn ok(input: &str) -> TranslationReport {
        translate(None, input, DEFAULT).expect("expected Ok translation")
    }

    fn err(input: &str) -> FilterError {
        translate(None, input, DEFAULT).expect_err("expected Err translation")
    }

    #[test]
    fn empty_spec_at_startup_falls_back_to_default() {
        let report = translate(None, "", Level::INFO).unwrap();
        assert_eq!(report.directive, "info");
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn empty_spec_with_current_is_noop() {
        let report = translate(Some("warn,net=error"), "", Level::INFO).unwrap();
        assert_eq!(report.directive, "");
    }

    #[test]
    fn whitespace_only_treated_as_empty() {
        let report = translate(None, "   \t\n", Level::WARN).unwrap();
        assert_eq!(report.directive, "warn");
    }

    #[test]
    fn numeric_preset_level_0_matches_hand_written() {
        assert_eq!(ok("0").directive, PRESETS[0]);
    }

    #[test]
    fn numeric_preset_level_2_is_bare_debug() {
        assert_eq!(ok("2").directive, "debug");
    }

    #[test]
    fn numeric_out_of_range_positive() {
        assert!(matches!(
            err("5"),
            FilterError::NumericLevelOutOfRange { value: 5 }
        ));
    }

    #[test]
    fn numeric_out_of_range_negative() {
        assert!(matches!(
            err("-1"),
            FilterError::NumericLevelOutOfRange { value: -1 }
        ));
    }

    #[test]
    fn numeric_plus_categories_appends() {
        let report = ok("2,foo:ERROR");
        assert_eq!(report.directive, "debug,foo=error");
    }

    #[test]
    fn lowercase_level_warns_and_normalizes() {
        let report = ok("foo:debug");
        assert_eq!(report.directive, "foo=debug");
        assert_eq!(report.warnings.len(), 1);
        assert!(report.warnings[0].contains("lowercase"));
    }

    #[test]
    fn unknown_level_errors() {
        assert!(matches!(err("foo:SHOUT"), FilterError::UnknownLevel { .. }));
    }

    #[test]
    fn suffix_glob_bare_yields_no_rewrite() {
        let e = err("*y.z:TRACE");
        match e {
            FilterError::UnsupportedGlob {
                original,
                suggested_rewrite,
            } => {
                assert_eq!(original, "*y.z");
                assert!(suggested_rewrite.is_none());
            }
            _ => panic!("wrong error variant"),
        }
    }

    #[test]
    fn suffix_glob_dotstar_suggests_rewrite() {
        let e = err("*.dump:DEBUG");
        match e {
            FilterError::UnsupportedGlob {
                original,
                suggested_rewrite,
            } => {
                assert_eq!(original, "*.dump");
                assert_eq!(suggested_rewrite.as_deref(), Some("dump.*:DEBUG"));
            }
            _ => panic!("wrong error variant"),
        }
    }

    #[test]
    fn prefix_glob_translates_to_envfilter_prefix() {
        assert_eq!(ok("perf.*:DEBUG").directive, "perf=debug");
    }

    #[test]
    fn last_wins_preserved_across_glob_and_literal() {
        // From tests/unit_tests/logging.cpp: the glob appears after the
        // typo'd literal and wins despite lower specificity. In the
        // translated form the EnvFilter parser's own last-wins rule
        // carries the semantic through.
        let report = ok("gobal:FATAL,glo*:DEBUG");
        assert_eq!(report.directive, "gobal=error,glo=debug");
        // And we loudly warn that the `glo*` prefix-glob-without-dot
        // won't match Rust targets the way legacy C++ did.
        assert!(report
            .warnings
            .iter()
            .any(|w| w.contains("prefix glob without `.` anchor")));
    }

    #[test]
    fn last_wins_literal_override() {
        // Even simpler last-wins check: two literal directives with
        // overlapping target names. EnvFilter keeps both; the runtime
        // last-match wins.
        let report = ok("foo:WARNING,foo:DEBUG");
        assert_eq!(report.directive, "foo=warn,foo=debug");
    }

    #[test]
    fn star_level_becomes_bare_level() {
        assert_eq!(ok("*:WARNING").directive, "warn");
    }

    #[test]
    fn unknown_category_is_reported_but_not_rejected() {
        let report = ok("nonexistent_category:DEBUG");
        assert_eq!(report.directive, "nonexistent_category=debug");
        assert_eq!(report.unknown, vec!["nonexistent_category".to_owned()]);
    }

    #[test]
    fn append_modifier_against_current() {
        // `current_spec` is in the legacy easylogging++ grammar, not in
        // EnvFilter format. Chore #2's C++ shim keeps the last-applied
        // legacy spec string around and passes it verbatim.
        let report = translate(
            Some("*:WARNING,net:ERROR"),
            "+debugtools.dnschecks:INFO",
            DEFAULT,
        )
        .unwrap();
        assert_eq!(
            report.directive,
            "warn,net=error,debugtools::dnschecks=info"
        );
    }

    #[test]
    fn remove_modifier_against_current() {
        let report = translate(
            Some("*:WARNING,net:ERROR,foo:INFO"),
            "-foo",
            DEFAULT,
        )
        .unwrap();
        assert_eq!(report.directive, "warn,net=error");
    }

    #[test]
    fn append_modifier_with_no_current_is_plain_spec() {
        let report = translate(None, "+foo:INFO", DEFAULT).unwrap();
        assert_eq!(report.directive, "foo=info");
    }

    #[test]
    fn category_without_level_is_malformed() {
        assert!(matches!(err("foo"), FilterError::MalformedSpec { .. }));
    }
}
