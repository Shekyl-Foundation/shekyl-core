// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What the workspace's code logs under, read from its source: the check
//! that holds the subsystem map, and each binary's `log-category` keys, to
//! the code (Rick, 2026-11-28).
//!
//! A crate logs under its own name when a `tracing` event names no target,
//! and under the string an event's `target:` names. [`targets`] reads both
//! from a crate's `src/`, leaving out code compiled for its tests alone.
//! [`subsystems_logged_by`] takes a binary's own crate and every workspace
//! crate it depends on, as `cargo tree` resolves them for every platform,
//! and maps each target to its [`Subsystem`].
//!
//! The source is read through the one lexer the `WSS-20` gate also reads
//! through (`lex`), so every spelling of a macro call that gate pins (a
//! path, an alias, `r#info!`, the `{}` and `[]` forms) is an event here too.
//! What the scan does not read, by construction: spans and
//! `#[instrument]`, which open no line (the workspace's binaries open
//! none); a wrapper macro defined in a crate, whose expansion logs under
//! that crate's name while its call sites name no event macro; and a
//! target that is not a string literal, which is refused rather than
//! guessed.
//!
//! Test support: built for a test of this crate, and for a crate that turns
//! on the `audit` feature in its dev-dependencies.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::subsystem::Subsystem;

mod lex;

use lex::{lex, macro_sites, tokens, Lexed, Token, TokenKind};

/// The `tracing` event macros. A span opens no line, so the spans are not
/// read.
const EVENTS: [&str; 6] = ["trace", "debug", "info", "warn", "error", "event"];

/// Whether the tokens at `i` open a `#[cfg(..)]` whose predicate holds only
/// under test: `cfg(test)` or `cfg(all(test, ..))`. `cfg(any(test, ..))` is
/// also compiled outside tests and is read. Returns the index of the token
/// after the attribute's `]`.
fn test_only_attribute(lexed: &Lexed, toks: &[Token], i: usize) -> Option<usize> {
    let ident = |k: usize, w: &str| toks.get(k).is_some_and(|t| t.is_ident(lexed, w));
    let punct = |k: usize, p: u8| toks.get(k).is_some_and(|t| t.is_punct(p));
    if !(punct(i, b'#') && punct(i + 1, b'[') && ident(i + 2, "cfg") && punct(i + 3, b'(')) {
        return None;
    }
    let test_only = ident(i + 4, "test") && punct(i + 5, b')')
        || ident(i + 4, "all") && punct(i + 5, b'(') && ident(i + 6, "test");
    if !test_only {
        return None;
    }
    closing(toks, i + 1).map(|k| k + 1)
}

/// The index of the token that closes the delimiter opened at `open`.
fn closing(toks: &[Token], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (k, tok) in toks.iter().enumerate().skip(open) {
        match tok.kind {
            TokenKind::Punct(b'(' | b'[' | b'{') => depth += 1,
            TokenKind::Punct(b')' | b']' | b'}') => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(k);
                }
            }
            _ => {}
        }
    }
    None
}

/// The index after the item starting at `i`: past its `;`, or past its
/// braced body. A `mod name;` names a module file the tests own.
fn item_end(lexed: &Lexed, toks: &[Token], mut i: usize, modules: &mut Vec<String>) -> usize {
    // Further attributes on the same item.
    while toks.get(i).is_some_and(|t| t.is_punct(b'#')) {
        match closing(toks, i + 1) {
            Some(k) => i = k + 1,
            None => return toks.len(),
        }
    }
    if let (Some(m), Some(name), Some(semi)) = (toks.get(i), toks.get(i + 1), toks.get(i + 2)) {
        if m.is_ident(lexed, "mod") && name.kind == TokenKind::Ident && semi.is_punct(b';') {
            modules.push(name.text(lexed).to_owned());
            return i + 3;
        }
    }
    while let Some(tok) = toks.get(i) {
        match tok.kind {
            TokenKind::Punct(b';') => return i + 1,
            TokenKind::Punct(b'{') => return closing(toks, i).map_or(toks.len(), |k| k + 1),
            TokenKind::Punct(b'(' | b'[') => i = closing(toks, i).map_or(toks.len(), |k| k + 1),
            _ => i += 1,
        }
    }
    i
}

/// What one file's code logs under, outside its test-only items: the
/// explicit targets, whether any event names none, how many events there
/// are, and the module files it declares test-only (`#[cfg(test)] mod x;`).
#[derive(Debug, Default, PartialEq, Eq)]
struct FileScan {
    explicit: BTreeSet<String>,
    implicit: bool,
    events: usize,
    test_modules: Vec<String>,
}

/// The string literal whose contents start at `start`: the byte span of its
/// contents.
fn string_at(lexed: &Lexed, start: usize) -> Option<(usize, usize)> {
    lexed
        .string_spans
        .iter()
        .find(|(s, _)| *s == start)
        .copied()
}

/// The string `const name: &str = "..."` of this file names, if it names
/// one. Two such constants of one name with different strings are refused:
/// which one an event reads depends on its module.
fn string_const(
    src: &str,
    lexed: &Lexed,
    toks: &[Token],
    name: &str,
) -> Result<Option<(usize, usize)>, String> {
    let mut found: Option<(usize, usize)> = None;
    for (i, tok) in toks.iter().enumerate() {
        if !(tok.is_ident(lexed, "const")
            && toks.get(i + 1).is_some_and(|t| t.is_ident(lexed, name))
            && toks.get(i + 2).is_some_and(|t| t.is_punct(b':'))
            && toks.get(i + 3).is_some_and(|t| t.is_punct(b'&')))
        {
            continue;
        }
        // `&str` or `&'static str`.
        let mut k = i + 4;
        if toks.get(k).is_some_and(|t| t.is_punct(b'\'')) {
            k += 2;
        }
        if !(toks.get(k).is_some_and(|t| t.is_ident(lexed, "str"))
            && toks.get(k + 1).is_some_and(|t| t.is_punct(b'='))
            && toks.get(k + 2).is_some_and(|t| t.is_punct(b'"')))
        {
            continue;
        }
        let Some(span) = toks.get(k + 2).and_then(|q| string_at(lexed, q.end)) else {
            continue;
        };
        match found {
            Some(earlier) if src[earlier.0..earlier.1] != src[span.0..span.1] => {
                return Err(format!("two string constants named `{name}` differ"));
            }
            _ => found = Some(span),
        }
    }
    Ok(found)
}

fn scan_file(src: &str) -> Result<FileScan, String> {
    let lexed = lex(src);
    let toks = tokens(&lexed);
    let mut scan = FileScan::default();
    // The byte ranges of items compiled for tests alone.
    let mut test_only: Vec<Range<usize>> = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        if let Some(after) = test_only_attribute(&lexed, &toks, i) {
            let end = item_end(&lexed, &toks, after, &mut scan.test_modules);
            let last = toks.get(end.saturating_sub(1)).map_or(src.len(), |t| t.end);
            test_only.push(toks[i].start..last);
            i = end;
        } else {
            i += 1;
        }
    }
    for site in macro_sites(&lexed) {
        if !EVENTS.contains(&site.name.as_str())
            || test_only.iter().any(|r| r.contains(&site.body.0))
        {
            continue;
        }
        scan.events += 1;
        let (start, end) = site.body;
        let body: Vec<&Token> = toks
            .iter()
            .filter(|t| t.start >= start && t.end <= end)
            .collect();
        let names_target = body.first().is_some_and(|t| t.is_ident(&lexed, "target"))
            && body.get(1).is_some_and(|t| t.is_punct(b':'))
            && !body.get(2).is_some_and(|t| t.is_punct(b':'));
        if !names_target {
            scan.implicit = true;
            continue;
        }
        // The target: a string literal, or a `const` of this file that is
        // one (`target: TARGET`, the named-constant spelling).
        let literal = match body.get(2) {
            Some(t) if t.is_punct(b'"') => string_at(&lexed, t.end),
            Some(t)
                if t.kind == TokenKind::Ident && body.get(3).is_some_and(|c| c.is_punct(b',')) =>
            {
                string_const(src, &lexed, &toks, t.text(&lexed))?
            }
            _ => None,
        };
        match literal {
            Some((s, e)) => {
                scan.explicit.insert(src[s..e].to_owned());
            }
            None => {
                return Err(format!(
                    "line {}: an event's target is neither a string literal nor a string \
                     `const` of this file, so it cannot be checked against the subsystems",
                    site.line
                ))
            }
        }
    }
    Ok(scan)
}

/// What a crate logs under.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Logged {
    /// The targets: the crate's own name when an event names none, and each
    /// explicit target.
    pub targets: BTreeSet<String>,
    /// How many events were read.
    pub events: usize,
}

/// The `.rs` files under `dir`, sorted.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut paths: Vec<PathBuf> = entries
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    paths.sort();
    for path in paths {
        if path.is_dir() {
            rust_files(&path, out)?;
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// The directory a file's child modules live in: its own directory for a
/// crate root or a `mod.rs`, `dir/name/` for `dir/name.rs`.
fn child_dir(file: &Path) -> PathBuf {
    let parent = file.parent().unwrap_or(Path::new("."));
    match file.file_stem().and_then(|s| s.to_str()) {
        Some("lib" | "main" | "mod") | None => parent.to_path_buf(),
        Some(stem) => parent.join(stem),
    }
}

/// What the crate in `package_dir`, named `crate_name`, logs under: every
/// event in its `src/`, outside items and module files compiled for its
/// tests alone.
///
/// # Errors
/// A file that cannot be read, or source the scan does not understand.
pub fn targets(package_dir: &Path, crate_name: &str) -> Result<Logged, String> {
    let mut files = Vec::new();
    rust_files(&package_dir.join("src"), &mut files)?;
    let mut scans = BTreeMap::new();
    for file in &files {
        let text = std::fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
        let scan = scan_file(&text).map_err(|e| format!("{}: {e}", file.display()))?;
        scans.insert(file.clone(), scan);
    }
    // A module declared test-only, and everything below it, is the tests'.
    let mut test_dirs = Vec::new();
    let mut test_files = BTreeSet::new();
    for (file, scan) in &scans {
        let dir = child_dir(file);
        for module in &scan.test_modules {
            test_files.insert(dir.join(format!("{module}.rs")));
            test_dirs.push(dir.join(module));
        }
    }
    let mut logged = Logged::default();
    for (file, scan) in scans {
        if test_files.contains(&file) || test_dirs.iter().any(|d| file.starts_with(d)) {
            continue;
        }
        logged.events += scan.events;
        if scan.implicit {
            logged.targets.insert(crate_name.to_owned());
        }
        logged.targets.extend(scan.explicit);
    }
    Ok(logged)
}

/// The workspace manifest, beside this crate.
fn workspace_manifest() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or(Path::new(".."))
        .join("Cargo.toml")
}

/// The workspace packages `cargo tree` prints for these arguments, by
/// name, with their directories.
fn tree(args: &[&str]) -> Result<BTreeMap<String, PathBuf>, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .arg("tree")
        .arg("--manifest-path")
        .arg(workspace_manifest())
        .args(args)
        .args(["--prefix", "none", "--locked"])
        .output()
        .map_err(|e| format!("cargo tree could not start: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo tree {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let text = String::from_utf8(output.stdout).map_err(|e| format!("cargo tree: {e}"))?;
    let mut out = BTreeMap::new();
    for line in text.lines() {
        // `name vX.Y.Z (/path/to/package)`, with ` (*)` on a repeat. A
        // registry package carries no path.
        let line = line.trim_end().trim_end_matches(" (*)");
        let Some(name) = line.split_whitespace().next() else {
            continue;
        };
        if let Some(path) = line
            .split_once(" (/")
            .and_then(|(_, rest)| rest.strip_suffix(')'))
        {
            out.insert(name.to_owned(), PathBuf::from(format!("/{path}")));
        }
    }
    Ok(out)
}

/// Every workspace member that logs, by package name, with what it logs
/// under.
///
/// # Errors
/// `cargo tree` failing, or a crate the scan cannot read.
pub fn workspace_logging() -> Result<BTreeMap<String, Logged>, String> {
    let members = tree(&["--workspace", "--depth", "0", "-e", "normal"])?;
    if members.is_empty() {
        return Err("cargo tree listed no workspace member".to_owned());
    }
    let mut out = BTreeMap::new();
    for (name, dir) in members {
        let logged = targets(&dir, &name.replace('-', "_"))?;
        if logged.events > 0 {
            out.insert(name, logged);
        }
    }
    Ok(out)
}

/// The subsystems a binary logs under: every target its own crate and the
/// workspace crates it depends on (normal edges, every platform) log under,
/// mapped to its subsystem.
///
/// # Errors
/// `cargo tree` failing, the binary not in its own tree, a crate the scan
/// cannot read, nothing logged at all, or a target no subsystem covers.
pub fn subsystems_logged_by(binary: &str) -> Result<BTreeSet<Subsystem>, String> {
    let closure = tree(&["-p", binary, "-e", "normal", "--target", "all"])?;
    if !closure.contains_key(binary) {
        return Err(format!("cargo tree for {binary} does not list {binary}"));
    }
    let mut out = BTreeSet::new();
    let mut events = 0;
    for (name, dir) in closure {
        let logged = targets(&dir, &name.replace('-', "_"))?;
        events += logged.events;
        for target in logged.targets {
            let subsystem = Subsystem::of_target(&target).ok_or_else(|| {
                format!("{name} logs under `{target}`, which no subsystem covers")
            })?;
            out.insert(subsystem);
        }
    }
    if events == 0 {
        return Err(format!("no event was read in {binary} or its dependencies"));
    }
    Ok(out)
}

/// Panics unless `keys` is exactly the set of subsystems `binary` logs
/// under, naming what is missing and what is extra. A binary's
/// `log-category` test calls this with its table's list.
///
/// # Panics
/// On any difference, or when the audit itself fails.
pub fn assert_keys_are_what_it_logs(binary: &str, keys: &[Subsystem]) {
    let logged = subsystems_logged_by(binary).unwrap_or_else(|e| panic!("{e}"));
    let named: BTreeSet<Subsystem> = keys.iter().copied().collect();
    assert_eq!(
        named.len(),
        keys.len(),
        "{binary}'s list names a subsystem twice"
    );
    let missing: Vec<&str> = logged.difference(&named).map(|s| s.name()).collect();
    let extra: Vec<&str> = named.difference(&logged).map(|s| s.name()).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "{binary}'s log-category keys differ from what it logs under: it logs under {missing:?} \
         and does not list them; it lists {extra:?} and logs nothing under them"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(text: &str) -> FileScan {
        scan_file(text).expect("scans")
    }

    #[test]
    fn an_event_without_a_target_logs_under_the_crate_and_one_with_a_target_under_it() {
        let s = scan(
            r#"fn f() {
                tracing::info!("one");
                warn!(target: "txpool", %e, "two");
                tracing::event!(target: "tor", Level::INFO, "three");
            }"#,
        );
        assert!(s.implicit);
        assert_eq!(s.events, 3);
        assert_eq!(
            s.explicit,
            ["tor".to_owned(), "txpool".to_owned()]
                .into_iter()
                .collect()
        );
    }

    #[test]
    fn comments_strings_and_lookalikes_are_not_events() {
        let s = scan(
            r##"// tracing::info!("in a comment");
            /* debug!(target: "x", "block /* nested */ comment") */
            fn f() {
                let s = "info!(\"in a string\")";
                let r = r#"warn!("in a raw string")"#;
                let c = '"';
                let l: &'static str = s;
                debug_assert!(true);
                macro_rules! info { () => {} }
            }"##,
        );
        assert_eq!(s.events, 0, "{s:?}");
        assert!(!s.implicit);
    }

    #[test]
    fn test_only_items_and_module_files_are_left_out() {
        let s = scan(
            r#"
            #[cfg(test)]
            mod tests { fn t() { tracing::info!(target: "test_only", "x"); } }
            #[cfg(all(test, unix))]
            fn u() { tracing::info!("y"); }
            #[cfg(test)]
            mod more;
            #[cfg(any(test, feature = "h"))]
            fn h() { tracing::info!(target: "kept", "z"); }
            "#,
        );
        assert_eq!(s.explicit, ["kept".to_owned()].into_iter().collect());
        assert!(!s.implicit);
        assert_eq!(s.test_modules, vec!["more".to_owned()]);
    }

    #[test]
    fn a_target_named_by_a_string_const_of_the_file_is_read() {
        let s = scan(
            r#"mod m {
                const TARGET: &str = "shekyl_clearnet::message_size";
                fn f() { tracing::info!(target: TARGET, bytes = 1, "x"); }
            }"#,
        );
        assert_eq!(
            s.explicit,
            ["shekyl_clearnet::message_size".to_owned()]
                .into_iter()
                .collect()
        );
        assert!(!s.implicit);
        assert!(scan_file(
            "const T: &str = \"a\"; mod n { const T: &'static str = \"b\"; } fn f() { info!(target: T, \"x\"); }"
        )
        .is_err());
    }

    #[test]
    fn a_computed_target_is_refused() {
        assert!(scan_file("fn f() { info!(target: TARGET, \"x\"); }").is_err());
    }

    /// The audit reads this crate's own tree: its subject exists.
    #[test]
    fn the_audit_reads_the_workspace() {
        let logging = workspace_logging().expect("audit");
        assert!(logging.len() > 10, "{:?}", logging.keys());
        assert!(logging.contains_key("shekyl-relay"), "{:?}", logging.keys());
    }
}
