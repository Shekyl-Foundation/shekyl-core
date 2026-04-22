// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Enforce that legacy easylogging++ self-instrumentation target names
//! (`logging`, `msgwriter`) are never introduced as Rust `tracing::*`
//! targets.
//!
//! These names appear in the preset strings because they name C++
//! self-instrumentation categories that the translator passes through
//! verbatim. In Rust, using `target: "logging"` or `target: "msgwriter"`
//! would collide with the translator's passthrough and silently override
//! preset-preserved filter behavior.
//!
//! A doc-comment in `src/filter.rs` reserves these names at the module
//! level. This test is the enforcement mechanism: CI fails if either
//! literal shows up in any `rust/**` source file outside this crate.
//! (The `shekyl-logging` crate itself is exempt because it owns the
//! reservation, discusses the reserved names in prose, and carries
//! fixture text that contains them verbatim. The exemption is a whole-
//! crate path-component check, not a per-file filter.)

use std::fs;
use std::path::{Path, PathBuf};

/// Reserved `tracing` target names (bare, unquoted). The matcher in
/// [`line_uses_reserved_target`] looks for `target <ws>? : <ws>?
/// "{name}"` so it catches formatting variants — `target:"logging"`,
/// `target : "logging"`, tabs, extra spaces, etc. — that rustfmt may
/// or may not normalize before CI runs. The previous implementation
/// matched exact substrings like `target: "logging"`, which a hand
/// edit could silently bypass.
const RESERVED: &[&str] = &["logging", "msgwriter"];

/// Return true if `line` contains a `target: "<reserved>"`-shaped
/// assignment for any name in `reserved`, tolerating arbitrary ASCII
/// whitespace around the colon and requiring that `target` is a
/// whole word (not a suffix of some longer identifier like
/// `my_target`).
fn line_uses_reserved_target(line: &str, reserved: &[&str]) -> bool {
    let bytes = line.as_bytes();
    for name in reserved {
        let needle = format!("\"{name}\"");
        let mut search_from = 0usize;
        while let Some(rel) = line[search_from..].find(&needle) {
            let quote_start = search_from + rel;
            // Walk left over whitespace, then expect `:`, then walk
            // left over whitespace, then expect the word `target`
            // preceded by a non-identifier byte (or start of line).
            let mut i = quote_start;
            while i > 0 && (bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') {
                i -= 1;
            }
            if i == 0 || bytes[i - 1] != b':' {
                search_from = quote_start + needle.len();
                continue;
            }
            i -= 1;
            while i > 0 && (bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') {
                i -= 1;
            }
            const TARGET: &[u8] = b"target";
            if i >= TARGET.len() && &bytes[i - TARGET.len()..i] == TARGET {
                let before = i - TARGET.len();
                let prev_is_ident = before > 0
                    && (bytes[before - 1].is_ascii_alphanumeric()
                        || bytes[before - 1] == b'_');
                if !prev_is_ident {
                    return true;
                }
            }
            search_from = quote_start + needle.len();
        }
    }
    false
}

fn rust_root() -> PathBuf {
    // Cargo sets CARGO_MANIFEST_DIR to this crate's root during tests.
    let manifest = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest)
        .parent()
        .expect("crate has a parent workspace dir")
        .to_path_buf()
}

fn visit(dir: &Path, offenders: &mut Vec<(PathBuf, usize, String)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_owned(),
            None => continue,
        };

        // Skip the generated Cargo target directory and the crate that
        // owns the reservation (this one).
        if file_name == "target" || file_name == ".git" {
            continue;
        }
        if path.is_dir() {
            visit(&path, offenders);
            continue;
        }
        if !file_name.ends_with(".rs") {
            continue;
        }
        // Skip the entire `shekyl-logging` crate's own sources and
        // tests: this crate owns the reservation and discusses the
        // reserved names in prose (doc-comments, fixture text, etc.).
        // The reservation binds callers; we're looking for them, not
        // ourselves. Match on `Path` components so the skip works on
        // Windows (where separators are `\`) and on Unix alike.
        if path
            .components()
            .any(|c| c.as_os_str() == "shekyl-logging")
        {
            continue;
        }
        let Ok(contents) = fs::read_to_string(&path) else {
            continue;
        };
        // Track `/* ... */` block-comment state across lines so prose
        // inside multi-line block comments doesn't produce false
        // positives. `//` / `///` / `//!` are all caught by the
        // `starts_with("//")` check since `//!` starts with `//`.
        let mut in_block_comment = false;
        for (lineno, line) in contents.lines().enumerate() {
            let stripped = line.trim_start();
            if in_block_comment {
                // A `*/` on this line closes the block; anything
                // before it is still prose, so skip the whole line
                // either way.
                if stripped.contains("*/") {
                    in_block_comment = false;
                }
                continue;
            }
            if stripped.starts_with("//") {
                continue;
            }
            if stripped.starts_with("/*") {
                // Single-line block comment (`/* ... */`) stays in
                // prose mode for this line; multi-line (`/* ...`)
                // flips the state until we see the close token.
                if !stripped.contains("*/") {
                    in_block_comment = true;
                }
                continue;
            }
            if line_uses_reserved_target(line, RESERVED) {
                offenders.push((path.clone(), lineno + 1, line.trim().to_owned()));
            }
        }
    }
}

#[test]
fn matcher_accepts_canonical_and_rejects_safe_variants() {
    // Rustfmt canonical + common hand-edit variants all flag.
    assert!(line_uses_reserved_target(
        "tracing::info!(target: \"logging\", \"hi\");",
        RESERVED
    ));
    assert!(line_uses_reserved_target(
        "tracing::info!(target:\"logging\", \"hi\");",
        RESERVED
    ));
    assert!(line_uses_reserved_target(
        "tracing::info!(target : \"logging\", \"hi\");",
        RESERVED
    ));
    assert!(line_uses_reserved_target(
        "tracing::info!(target:\t\"msgwriter\", \"hi\");",
        RESERVED
    ));

    // Identifier that merely ends in `target` must not trip the matcher.
    assert!(!line_uses_reserved_target(
        "let my_target: &str = \"logging\";",
        RESERVED
    ));

    // Other reserved names are not flagged.
    assert!(!line_uses_reserved_target(
        "tracing::info!(target: \"net.p2p\", \"hi\");",
        RESERVED
    ));
}

#[test]
fn reserved_tracing_targets_are_not_used_in_rust_sources() {
    let root = rust_root();
    let mut offenders = Vec::new();
    visit(&root, &mut offenders);

    if !offenders.is_empty() {
        let mut msg = String::from(
            "Reserved tracing targets used in Rust source:\n\
             (see shekyl-logging/src/filter.rs for why these are reserved)\n\n",
        );
        for (path, lineno, line) in &offenders {
            msg.push_str(&format!("{}:{}: {}\n", path.display(), lineno, line));
        }
        panic!("{msg}");
    }
}
