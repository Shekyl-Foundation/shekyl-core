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

use std::collections::BTreeSet;
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
                    && (bytes[before - 1].is_ascii_alphanumeric() || bytes[before - 1] == b'_');
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

fn visit(
    dir: &Path,
    offenders: &mut Vec<(PathBuf, usize, String)>,
    scanned: &mut BTreeSet<String>,
    root: &Path,
) {
    // `expect`, not a silent `else { return }`: an unreadable directory used
    // to drop its whole subtree from the corpus while the gate stayed green,
    // which is the one failure mode a search-for-offenders test cannot show
    // in its output.
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("the reserved-name walk must read {}: {e}", dir.display()));
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
            visit(&path, offenders, scanned, root);
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
        if path.components().any(|c| c.as_os_str() == "shekyl-logging") {
            continue;
        }
        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("the reserved-name walk must read {}: {e}", path.display()));
        // Record which workspace crate this file belongs to, so the corpus can
        // be cross-checked against the manifest below.
        // Every ancestor directory of the file, not just the first component:
        // workspace members nest (`shekyl-oxide/crypto/fcmps/ec-gadgets`), and
        // a first-component key would report those unreached forever.
        if let Ok(rel) = path.strip_prefix(root) {
            let mut prefix = PathBuf::new();
            for component in rel.parent().unwrap_or(Path::new("")).components() {
                prefix.push(component);
                scanned.insert(prefix.to_string_lossy().replace('\\', "/"));
            }
        }
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

    // Rule 47, and the premise this gate's own module doc asserts but its code
    // never established: "CI fails if either literal shows up in any `rust/**`
    // source file outside this crate." That claim rests entirely on the walk
    // reaching the workspace, and a search-for-offenders test reports the same
    // empty output whether the corpus was clean or was never read. A crate
    // moved one directory deeper would re-root `rust_root()` onto a fraction
    // of the tree, in silence. `shekyl-ffi/tests/ffi_boundary_ratchet.rs`
    // already carries this shape of cross-check; this is the same idea against
    // the manifest instead of a baseline table.
    let manifest = fs::read_to_string(root.join("Cargo.toml"))
        .expect("rust_root() must be the Rust workspace root (it has no Cargo.toml)");
    assert!(
        manifest.contains("[workspace]"),
        "rust_root() resolved to {}, which is not the workspace root — every \
         assertion below would pass over the wrong corpus",
        root.display()
    );
    let members: BTreeSet<String> = manifest
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('"') && l.ends_with("\","))
        .map(|l| l.trim_matches(|c| c == '"' || c == ',').to_owned())
        .filter(|m| !m.is_empty() && m != "shekyl-logging")
        .collect();
    assert!(
        !members.is_empty(),
        "no workspace members parsed out of {}/Cargo.toml — the corpus \
         cross-check below would be vacuous",
        root.display()
    );

    let mut offenders = Vec::new();
    let mut scanned = BTreeSet::new();
    visit(&root, &mut offenders, &mut scanned, &root);

    let unreached: Vec<&String> = members.difference(&scanned).collect();
    assert!(
        unreached.is_empty(),
        "the walk never reached {} of {} workspace members ({:?}) — it proved \
         nothing about them, so fix the walk before trusting this gate",
        unreached.len(),
        members.len(),
        unreached
    );

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
