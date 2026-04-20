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
//! literal shows up in any `rust/**` source file outside this file.

use std::fs;
use std::path::{Path, PathBuf};

const RESERVED: &[&str] = &["target: \"logging\"", "target: \"msgwriter\""];

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
        for (lineno, line) in contents.lines().enumerate() {
            // Ignore comment-only lines — offenders are actual macro
            // invocations, not prose that happens to mention the
            // needle.
            let stripped = line.trim_start();
            if stripped.starts_with("//") || stripped.starts_with("///") {
                continue;
            }
            for needle in RESERVED {
                if line.contains(needle) {
                    offenders.push((path.clone(), lineno + 1, line.trim().to_owned()));
                }
            }
        }
    }
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
