// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `WSS-20` — no `P`-correlated identifier reaches a log.
//!
//! ## Why this gate exists
//!
//! `WALLET_SIDE_STORE.md` `WSS-18` establishes that the plaintext
//! `.wallet.curvetree` store is an at-rest route to the serving persona `P`
//! beside an encrypted `.wallet`. `WSS-19`'s audit of `P`'s *other* persisted
//! state found a second route with the same reach: a `tracing` line that put
//! released shard ids at `info` into `--log-file`, a plaintext file created
//! mode `0600` (`shekyl-logging/src/appender.rs`) that persists exactly as the
//! store does. Released shard ids matched against the chain's **public** bond
//! history identify `P`. The adversary is the one the encrypted wallet was
//! ruled against and the one `WSS-18`'s table prices as the position that
//! matters: an offline image, no password — forensics, VPS snapshots, shared
//! machines.
//!
//! So encrypting the store does not close the at-rest route on its own, and a
//! fix that closes one of several routes while being described as closing
//! "the" route is worse than none, because it retires the question. This gate
//! is the standing half of that fix: the call sites were corrected once, and
//! this keeps them corrected.
//!
//! Mission rule `00-mission` commitment **2 (privacy is the product)** is the
//! binding one. Privacy is not a setting, so the guarantee cannot rest on
//! every future author of a log line remembering it.
//!
//! ## What it bites against, and what it does NOT cover
//!
//! Per `50-testing`, the coverage boundary is stated rather than inferred.
//!
//! **Bites against**, in the paths `WSS-19` audited:
//!
//! 1. A `P`-correlated or wallet-correlating identifier appearing as a
//!    `tracing` **field name**, a **shorthand field** (`%x` / `?x` / `x`), or
//!    anywhere in a field's **value expression**, at any level, anywhere under
//!    `shekyl-engine-core/src/engine/stake_engine/`.
//! 2. The same identifier reaching the message through an **inline format
//!    capture** (`"… {shard_id} …"`), which the field scan alone cannot see
//!    because the scan deliberately blanks string literals.
//! 3. The same identifier arriving through a `tracing` surface that is not a
//!    level macro: `event!`, and the `*_span!` family whose fields print on
//!    every event inside the span. `#[tracing::instrument]` is refused
//!    outright in these paths — it records every un-skipped argument as a
//!    span field, so the identifier is named by a function signature the
//!    body scan never reads.
//! 4. `shekyl-p-host`, `shekyl-p-serve` and `shekyl-tor-control-client`
//!    **growing a logging surface at all** — a logging dependency or a
//!    `println!`/`eprintln!`/`dbg!`. These three crates have none today, so a
//!    denylist over their (zero) log sites would be vacuously green: the edit
//!    that makes a field scan red there needs a dependency *and* a site *and*
//!    a denylisted name. The check that can actually fail is structural, and
//!    it makes adding logging to the persona host a conscious gate edit —
//!    which is when review should happen (`47-gate-subject-assertion`).
//!
//! **Does NOT cover:**
//!
//! - A value whose binding name is innocuous, passed under an innocuous field
//!   name or positionally (`n = ?v` where `v` holds shard ids). Only naming
//!   discipline catches that; the durable answer is exposure policy on the
//!   **type**, as `shekyl-types`' `hash32!` `redact` / `no_display` arms
//!   already do for `PCanonicalId` and `KeyImage`. Shard ids are a bare `u64`
//!   across the p-host/curve-tree API and have no such policy.
//! - `Display`/`Debug` of error types that may embed an identifier.
//! - Every path outside the three crates above and `stake_engine/` — notably
//!   `engine/pscan/`, whose `persona = ?persona` sites are covered by the
//!   ratified `redact` arm (a two-byte `Debug` prefix) and are a separate
//!   question from this one.
//! - Whether the redacted forms that *are* ratified survive `WSS-20`'s
//!   adversary. That is a design-round question, not a call-site one.
//! - journald, log encryption, and the logging framework itself — out of
//!   scope for `WSS-20` by construction.
//!
//! ## Why a static scan and not a `tracing` capture layer
//!
//! A capture layer can only assert about events a test actually drives, and
//! three of the four audited paths have no `tracing` dependency at all —
//! there is nothing to attach to, and no way to assert "and it stays zero".
//! A source scan covers the absent case, which is most of the subject. It
//! also runs under the existing `cargo test --workspace` lane with no
//! workflow registration, so it cannot become an armed gate with no trigger.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Identifier stems that make a logged value `P`-correlated (matched against
/// the chain's public bond history) or wallet-correlating (matched against the
/// chain's outputs). A source identifier is flagged when it *contains* one of
/// these, so `shard_ids`, `released_shard`, `p_slot_id` and `gindex_raw` all
/// trip on their stem.
///
/// The wallet-correlating stems are here because `shekyl-types` already ranks
/// that class **stricter** than the persona class — `KeyImage` is minted
/// `redact, no_display` while `PCanonicalId` keeps a full-hex `Display`. An
/// identifier of the stricter class has no business in a sink the looser one
/// is being stripped from.
const FORBIDDEN_STEMS: &[&str] = &[
    // `P`-correlated: the serve set and the persona's own identity.
    "shard",
    "p_canonical",
    "persona",
    // The onion service id: the address `P` publishes. `hostname` is here
    // because `ServiceId`'s own doc calls `hostname()` "a forensic surface"
    // — its `Debug` is redacted, that accessor is not.
    "onion",
    "service_id",
    "hs_addr",
    "hostname",
    // Wallet-correlating: an output or a spend, matched against the chain.
    "gindex",
    "global_output",
    "key_image",
    "keyimage",
    "output_key",
];

/// Stems too short to match as a substring without catching innocents:
/// `step_id`, `stop_id` and `map_id` all *contain* `p_id`, and `map_slot`
/// contains `p_slot`. Matched as a prefix instead, so `p_id` / `p_ids` /
/// `p_slot_of` trip and `step_id` does not. A gate that goes red on an
/// innocent field invites someone to delete the stem, which is the failure
/// this split is avoiding.
const FORBIDDEN_PREFIX_STEMS: &[&str] = &["p_id", "p_slot"];

/// Crates on `P`'s serving path that carry **no logging surface at all**, and
/// must keep carrying none. See the module doc, item 3.
const P_PATH_CRATES_WITHOUT_LOGGING: &[&str] = &[
    "shekyl-p-host",
    "shekyl-p-serve",
    "shekyl-tor-control-client",
];

/// Crates whose presence in a `[dependencies]` table means the crate can log.
const LOGGING_CRATES: &[&str] = &[
    "tracing",
    "tracing-core",
    "tracing-subscriber",
    "tracing-attributes",
    "log",
    "env_logger",
    "slog",
    "shekyl-logging",
];

/// Macros that write a line a human can read off disk.
const PRINT_MACROS: &[&str] = &["println", "eprintln", "print", "eprint", "dbg"];

/// Every `tracing` macro that takes a field list, in both spellings the
/// workspace uses (`tracing::info!` and a bare `info!` behind a `use`).
///
/// The `*_span!` names are listed individually rather than relying on a
/// `span!` match: the whole-word check in [`log_sites`] rejects the `span!`
/// inside `info_span!` because `_` continues an identifier, so an unlisted
/// `info_span!` would be missed entirely. A span's fields print on every
/// event inside it under the `fmt` layer, so they reach the file exactly
/// as an event's own fields do. `event!`'s leading `Level::INFO` is just a
/// harmless first element to the field parser.
const LEVELS: &[&str] = &[
    "trace",
    "debug",
    "info",
    "warn",
    "error",
    "event",
    "span",
    "trace_span",
    "debug_span",
    "info_span",
    "warn_span",
    "error_span",
];

// ─────────────────────────────────────────────────────────────────────────
// Lexing: blank comments and string contents, keeping byte offsets stable.
// ─────────────────────────────────────────────────────────────────────────

/// A lexed view of a Rust source file.
struct Lexed {
    /// Same length as the input. Comment bodies and string-literal *contents*
    /// are replaced by spaces (newlines preserved), so offsets and line
    /// numbers still line up with the original.
    ///
    /// Blanking string contents is what lets the field scan run without
    /// tripping on prose: the corrected `WSS-20` line's own message still
    /// reads "these shards were absent from the bond record", and a sweep
    /// cannot otherwise tell that quotation from a reference.
    blanked: String,
    /// `(start, end)` byte spans of each string literal's **contents** in the
    /// original text, so inline format captures can be scanned separately.
    string_spans: Vec<(usize, usize)>,
}

fn lex(src: &str) -> Lexed {
    let b = src.as_bytes();
    let mut out: Vec<u8> = src.as_bytes().to_vec();
    let mut spans = Vec::new();
    let mut i = 0usize;

    // Blank `[from, to)` in `out`, preserving newlines so line numbers hold.
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for byte in &mut out[from..to] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    };

    while i < b.len() {
        match b[i] {
            b'/' if i + 1 < b.len() && b[i + 1] == b'/' => {
                let start = i;
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
                blank(&mut out, start, i);
            }
            b'/' if i + 1 < b.len() && b[i + 1] == b'*' => {
                let start = i;
                let mut depth = 1usize;
                i += 2;
                while i < b.len() && depth > 0 {
                    if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
                        depth += 1;
                        i += 2;
                    } else if b[i] == b'*' && i + 1 < b.len() && b[i + 1] == b'/' {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                blank(&mut out, start, i);
            }
            // Raw string: `r"…"`, `r#"…"#`, `br#"…"#`.
            b'r' | b'b' => {
                let mut j = i;
                if b[j] == b'b' {
                    j += 1;
                }
                if j < b.len() && b[j] == b'r' {
                    let mut hashes = 0usize;
                    let mut k = j + 1;
                    while k < b.len() && b[k] == b'#' {
                        hashes += 1;
                        k += 1;
                    }
                    if k < b.len() && b[k] == b'"' {
                        // Not preceded by an identifier byte (else it is a
                        // suffix of some longer name, e.g. `my_r`).
                        let prev_ident =
                            i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
                        if !prev_ident {
                            let content_start = k + 1;
                            let mut m = content_start;
                            let closer_hashes = hashes;
                            loop {
                                if m >= b.len() {
                                    break;
                                }
                                if b[m] == b'"' {
                                    let mut h = 0usize;
                                    while h < closer_hashes
                                        && m + 1 + h < b.len()
                                        && b[m + 1 + h] == b'#'
                                    {
                                        h += 1;
                                    }
                                    if h == closer_hashes {
                                        break;
                                    }
                                }
                                m += 1;
                            }
                            let content_end = m.min(b.len());
                            spans.push((content_start, content_end));
                            blank(&mut out, content_start, content_end);
                            i = (content_end + 1 + closer_hashes).min(b.len());
                            continue;
                        }
                    }
                }
                i += 1;
            }
            b'"' => {
                let content_start = i + 1;
                let mut m = content_start;
                while m < b.len() {
                    if b[m] == b'\\' {
                        m += 2;
                        continue;
                    }
                    if b[m] == b'"' {
                        break;
                    }
                    m += 1;
                }
                let content_end = m.min(b.len());
                spans.push((content_start, content_end));
                blank(&mut out, content_start, content_end);
                i = (content_end + 1).min(b.len());
            }
            // A char literal can hold a quote (`'"'`) and would otherwise
            // open a phantom string. A lifetime (`'a`) must not be eaten.
            b'\'' => {
                // Blank the interior too: a `'('` left in place would forge
                // paren depth for the body matcher below.
                if i + 1 < b.len() && b[i + 1] == b'\\' {
                    let mut m = i + 2;
                    while m < b.len() && b[m] != b'\'' {
                        m += 1;
                    }
                    blank(&mut out, i + 1, m.min(b.len()));
                    i = (m + 1).min(b.len());
                } else if i + 2 < b.len() && b[i + 2] == b'\'' {
                    blank(&mut out, i + 1, i + 2);
                    i += 3;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }

    Lexed {
        // Blanking only ever writes ASCII spaces over whole bytes of
        // comment/string bodies, so the result is still valid UTF-8 — but
        // a multi-byte char inside a blanked span is replaced byte-wise,
        // which is fine because every replacement byte is ASCII.
        blanked: String::from_utf8_lossy(&out).into_owned(),
        string_spans: spans,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Scanning: find log macro bodies, split their fields, flag identifiers.
// ─────────────────────────────────────────────────────────────────────────

/// Identifiers in `text` that contain a forbidden stem, lowercased.
fn flagged_idents(text: &str) -> Vec<String> {
    let mut hits = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let ident = text[start..i].to_ascii_lowercase();
            let forbidden = FORBIDDEN_STEMS.iter().any(|s| ident.contains(s))
                || FORBIDDEN_PREFIX_STEMS.iter().any(|s| ident.starts_with(s));
            if forbidden && !hits.contains(&ident) {
                hits.push(ident);
            }
        } else {
            i += 1;
        }
    }
    hits
}

/// Identifiers named by an inline format capture (`{ident}`, `{ident:?}`).
fn inline_capture_idents(literal: &str) -> Vec<String> {
    let mut out = Vec::new();
    let b = literal.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'{' {
            if i + 1 < b.len() && b[i + 1] == b'{' {
                i += 2;
                continue;
            }
            let start = i + 1;
            let mut j = start;
            while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                j += 1;
            }
            if j > start && !b[start].is_ascii_digit() {
                out.push(literal[start..j].to_owned());
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

/// One log macro invocation found in a source file.
struct LogSite {
    line: usize,
    /// Byte span of the macro's argument list contents (inside the parens).
    body: (usize, usize),
}

/// Find every `[path::]<level>!( … )` invocation in already-lexed source.
fn log_sites(lexed: &Lexed) -> Vec<LogSite> {
    let text = &lexed.blanked;
    let b = text.as_bytes();
    let mut sites = Vec::new();
    for level in LEVELS {
        let needle = format!("{level}!");
        let mut from = 0usize;
        while let Some(rel) = text[from..].find(&needle) {
            let at = from + rel;
            from = at + needle.len();
            // Whole word: the byte before the level name must not continue an
            // identifier (so `is_error!` and `my_warn!` do not match).
            if at > 0 && (b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_') {
                continue;
            }
            // `!` then optional whitespace then `(`.
            let mut k = at + needle.len();
            while k < b.len() && (b[k] == b' ' || b[k] == b'\t' || b[k] == b'\n') {
                k += 1;
            }
            if k >= b.len() || b[k] != b'(' {
                continue;
            }
            let open = k;
            let mut depth = 0i32;
            let mut m = open;
            while m < b.len() {
                match b[m] {
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                m += 1;
            }
            if depth != 0 {
                continue;
            }
            sites.push(LogSite {
                line: text[..at].matches('\n').count() + 1,
                body: (open + 1, m),
            });
        }
    }
    sites.sort_by_key(|s| s.body.0);
    sites
}

/// Split a macro body at top-level commas.
fn split_top_level(body: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let b = body.as_bytes();
    let (mut depth, mut start) = (0i32, 0usize);
    for (i, byte) in b.iter().enumerate() {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b',' if depth == 0 => {
                out.push(body[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    let tail = body[start..].trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    out.into_iter().filter(|s| !s.is_empty()).collect()
}

/// Every violation in one source file: `(line, offending identifier, how)`.
fn violations_in_source(src: &str) -> Vec<(usize, String, &'static str)> {
    let lexed = lex(src);
    let mut out = Vec::new();
    for site in log_sites(&lexed) {
        let (bstart, bend) = site.body;
        // Field names and value expressions: read from the blanked text, so
        // the message string contributes nothing.
        for element in split_top_level(&lexed.blanked[bstart..bend]) {
            for ident in flagged_idents(element) {
                out.push((site.line, ident, "tracing field name or value"));
            }
        }
        // Inline format captures: read from the original string contents.
        for &(s, e) in &lexed.string_spans {
            if s >= bstart && e <= bend {
                for captured in inline_capture_idents(&src[s..e]) {
                    for ident in flagged_idents(&captured) {
                        out.push((site.line, ident, "inline format capture"));
                    }
                }
            }
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────
// Corpus helpers
// ─────────────────────────────────────────────────────────────────────────

fn rust_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate has a parent workspace dir")
        .to_path_buf()
}

/// Every `.rs` file under `dir`, sorted. Panics on an unreadable directory:
/// a walk that silently drops a subtree reports the same clean output as a
/// clean corpus, which is the one failure a search-for-offenders test cannot
/// show in its own output.
fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("the WSS-20 walk must read {}: {e}", dir.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(rust_files(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// Logging crates named in a manifest's **non-dev, non-build** dependency
/// tables, including `[dependencies.x]` and `[target.'cfg(…)'.dependencies]`.
fn logging_deps(manifest: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut in_deps_table = false;
    for line in manifest.lines() {
        let t = line.trim();
        if let Some(header) = t.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            let header = header.trim();
            let is_dev_or_build =
                header.contains("dev-dependencies") || header.contains("build-dependencies");
            in_deps_table = !is_dev_or_build && header.ends_with("dependencies");
            // `[dependencies.tracing]` names the dependency in the header.
            if !is_dev_or_build {
                if let Some((_, dep)) = header.rsplit_once("dependencies.") {
                    let dep = dep.trim().trim_matches('"');
                    if LOGGING_CRATES.contains(&dep) {
                        found.insert(dep.to_owned());
                    }
                }
            }
            continue;
        }
        if !in_deps_table || t.is_empty() || t.starts_with('#') {
            continue;
        }
        let Some((key, _)) = t.split_once('=') else {
            continue;
        };
        // `tracing = { … }`, `tracing.workspace = true`, `"tracing" = …`.
        let key = key.trim().trim_matches('"');
        let name = key
            .split('.')
            .next()
            .unwrap_or(key)
            .trim()
            .trim_matches('"');
        if LOGGING_CRATES.contains(&name) {
            found.insert(name.to_owned());
        }
    }
    found
}

/// Print-macro invocations in already-lexed source: `(line, macro)`.
fn print_macro_sites(src: &str) -> Vec<(usize, &'static str)> {
    let lexed = lex(src);
    let text = &lexed.blanked;
    let b = text.as_bytes();
    let mut out = Vec::new();
    for mac in PRINT_MACROS {
        let needle = format!("{mac}!");
        let mut from = 0usize;
        while let Some(rel) = text[from..].find(&needle) {
            let at = from + rel;
            from = at + needle.len();
            if at > 0 && (b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_') {
                continue;
            }
            out.push((text[..at].matches('\n').count() + 1, *mac));
        }
    }
    out
}

/// `#[tracing::instrument]` sites in already-lexed source: `(line, text)`.
///
/// The attribute records **every** function argument into the span unless
/// `skip` / `skip_all` names it, and those fields print on every event
/// inside the span. It is a field list written as an attribute, so the body
/// scanner cannot see it — and the argument it would capture is named by the
/// function signature, not by the log site. Treated the way a logging
/// dependency is: absent, and a deliberate edit to introduce.
fn instrument_sites(src: &str) -> Vec<(usize, String)> {
    let lexed = lex(src);
    let text = &lexed.blanked;
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = text[from..].find("instrument") {
        let at = from + rel;
        from = at + "instrument".len();
        let b = text.as_bytes();
        if at > 0 && (b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_') {
            continue;
        }
        // Only the attribute form, not the word in a path or a binding.
        let before = text[..at].trim_end();
        if !(before.ends_with("#[") || before.ends_with("tracing::") || before.ends_with('(')) {
            continue;
        }
        let line = text[..at].matches('\n').count() + 1;
        // Report the whole source line, not the slice from the match: the
        // `#[tracing::` prefix is the part that identifies the attribute.
        let start = text[..at].rfind('\n').map_or(0, |n| n + 1);
        let end = text[at..].find('\n').map_or(text.len(), |n| at + n);
        out.push((line, text[start..end].trim().to_owned()));
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────
// Self-tests: the negative controls. `50-testing` — a check that has never
// been seen red is not a check.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn scanner_flags_the_wss20_defect_and_clears_its_fix() {
    // The defect exactly as it stood at `serve_set_source.rs:261-263`, message
    // prose included. The prose says "these shards were absent"; the gate must
    // key on the *field*, not the quotation.
    let defect = r#"
        tracing::info!(
            released = reply.released,
            shard_ids = ?releasable,
            epochs_absent = EPOCHS_BEFORE_PIN_RELEASE,
            "released serve-set pins: these shards were absent from the bond \
             record across two consecutive settlement-epoch opens"
        );
    "#;
    let hits = violations_in_source(defect);
    assert!(
        hits.iter().any(|(_, id, _)| id == "shard_ids"),
        "the scanner must flag `shard_ids = ?releasable`; it found {hits:?}"
    );

    // The landed fix: same message, counts instead of ids. Must be clean —
    // otherwise the gate is keying on the prose and is unfixable by design.
    let fixed = r#"
        tracing::info!(
            released = reply.released,
            releasable = releasable.len(),
            epochs_absent = EPOCHS_BEFORE_PIN_RELEASE,
            "released serve-set pins: these shards were absent from the bond \
             record across two consecutive settlement-epoch opens"
        );
    "#;
    assert!(
        violations_in_source(fixed).is_empty(),
        "the corrected form must be clean; the scanner reported {:?}",
        violations_in_source(fixed)
    );
}

#[test]
fn scanner_flags_a_value_expression_a_shorthand_and_an_inline_capture() {
    // The `actor.rs` defect: the identifier is in the *value*, not the name.
    let by_value = "tracing::error!(index = gindex.to_raw(), %reason, \"quarantined\");";
    assert!(
        violations_in_source(by_value)
            .iter()
            .any(|(_, id, _)| id == "gindex"),
        "a forbidden identifier in a field's value expression must be flagged"
    );

    // Shorthand field, bare-macro spelling, non-`info` level.
    let shorthand = "warn!(?onion_address, \"published\");";
    assert!(
        !violations_in_source(shorthand).is_empty(),
        "a shorthand field must be flagged"
    );

    // Inline format capture — invisible to the field scan by construction.
    let capture = "tracing::debug!(\"released {shard_id} at {height}\");";
    let hits = violations_in_source(capture);
    assert!(
        hits.iter()
            .any(|(_, id, how)| id == "shard_id" && *how == "inline format capture"),
        "an inline format capture must be flagged; found {hits:?}"
    );
}

#[test]
fn scanner_does_not_fire_on_safe_neighbours() {
    // Prose alone, in a message and in a comment, is not a reference.
    let prose = r#"
        // these shards were absent from the bond record; the persona is gone
        tracing::info!(released = reply.released, "these shards were absent; persona idle");
    "#;
    assert!(
        violations_in_source(prose).is_empty(),
        "prose in a message or a comment must not trip the gate: {:?}",
        violations_in_source(prose)
    );

    // A non-log macro with a forbidden name is not this gate's business.
    let not_a_log = "assert_eq!(shard_ids.len(), 2);";
    assert!(
        violations_in_source(not_a_log).is_empty(),
        "only log macros are in scope"
    );

    // An identifier that merely ends in a level name must not open a site.
    let near_miss = "let is_error = shard_ids.len() > 0;";
    assert!(
        violations_in_source(near_miss).is_empty(),
        "`is_error` is not a log macro"
    );
}

#[test]
fn scanner_flags_the_span_and_event_macros_and_the_instrument_attribute() {
    // `event!` carries fields in the same body shape, behind a level arg.
    let event = "tracing::event!(Level::INFO, shard_id = ?x, \"released\");";
    assert!(
        violations_in_source(event)
            .iter()
            .any(|(_, id, _)| id == "shard_id"),
        "`event!` must be in scope: it is a log line with a field list"
    );

    // A span's fields print on every event inside it. `info_span!` must be
    // matched by name — the whole-word check rejects the `span!` inside it.
    let span = "let _g = tracing::info_span!(\"serve\", onion_address = %addr).entered();";
    assert!(
        violations_in_source(span)
            .iter()
            .any(|(_, id, _)| id == "onion_address"),
        "`info_span!` must be in scope, not shadowed by the `span!` entry"
    );

    // The attribute form captures arguments the body scan never sees.
    let instrumented = "#[tracing::instrument]\nfn serve(shard_id: u64) {}\n";
    assert!(
        !instrument_sites(instrumented).is_empty(),
        "`#[tracing::instrument]` must be flagged: it records every \
         un-skipped argument as a span field"
    );
    // The bare word is not the attribute.
    assert!(
        instrument_sites("let instrument = 3; // instrument\n").is_empty(),
        "a binding named `instrument` is not the attribute"
    );
}

#[test]
fn prefix_stems_do_not_catch_innocent_neighbours() {
    // `step_id` contains `p_id`; `map_slot` contains `p_slot`. Neither is an
    // identifier this gate is about, and a gate that reds on them invites
    // someone to delete the stem.
    assert!(
        flagged_idents("step_id stop_id map_id map_slot group_id").is_empty(),
        "prefix stems must not fire on innocent identifiers: {:?}",
        flagged_idents("step_id stop_id map_id map_slot group_id")
    );
    // The real ones still trip.
    for ident in ["p_id", "p_ids", "p_slot", "p_slot_of"] {
        assert!(
            !flagged_idents(ident).is_empty(),
            "`{ident}` must still be flagged"
        );
    }
}

#[test]
fn manifest_matcher_separates_a_real_dep_from_a_dev_dep_and_a_comment() {
    let with_dep = "[dependencies]\ntracing = { version = \"0.1\" }\n";
    assert!(
        logging_deps(with_dep).contains("tracing"),
        "a plain `[dependencies]` entry must be found"
    );

    let table_form = "[dependencies.tracing]\nversion = \"0.1\"\n";
    assert!(
        logging_deps(table_form).contains("tracing"),
        "the `[dependencies.tracing]` table form must be found"
    );

    let target_form = "[target.'cfg(unix)'.dependencies]\nlog = \"0.4\"\n";
    assert!(
        logging_deps(target_form).contains("log"),
        "a target-specific dependency table must be found"
    );

    let workspace_form = "[dependencies]\ntracing.workspace = true\n";
    assert!(
        logging_deps(workspace_form).contains("tracing"),
        "the `dep.workspace = true` form must be found"
    );

    // Dev-dependencies never ship; a comment naming the crate is not a dep.
    let dev_only = "[dev-dependencies]\ntracing = \"0.1\"\n";
    assert!(
        logging_deps(dev_only).is_empty(),
        "a dev-dependency must not trip the gate"
    );
    let commented = "[dependencies]\n# tracing = \"0.1\"\ntokio = \"1\"\n";
    assert!(
        logging_deps(commented).is_empty(),
        "a commented-out dependency must not trip the gate"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// The gates
// ─────────────────────────────────────────────────────────────────────────

/// Sites in `stake_engine/` the scanner recognised at the time this gate was
/// written (`serve_set_source.rs`, `actor.rs`, `claim.rs` ×3, `serving/disk.rs`,
/// `serving/tor_config.rs`). A floor rather than an exact pin: the file is
/// live under concurrent work, and the property this protects is that the
/// parser still *sees* the corpus, not that the corpus is frozen. If the
/// parser regresses to finding nothing, the identifier assertion below would
/// pass over an empty set and prove nothing (`47-gate-subject-assertion`).
const STAKE_ENGINE_LOG_SITE_FLOOR: usize = 6;

#[test]
fn stake_engine_logs_name_no_p_correlated_identifier() {
    let root = rust_root();
    let dir = root.join("shekyl-engine-core/src/engine/stake_engine");
    assert!(
        dir.is_dir(),
        "{} is not a directory — the gate has no subject; the module moved, \
         so fix the path rather than letting this pass on an empty scan",
        dir.display()
    );

    let files = rust_files(&dir);
    assert!(
        !files.is_empty(),
        "no .rs files under {} — the gate has no subject",
        dir.display()
    );

    let mut sites = 0usize;
    let mut offenders: Vec<String> = Vec::new();
    for file in &files {
        let src = fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("the WSS-20 scan must read {}: {e}", file.display()));
        sites += log_sites(&lex(&src)).len();
        for (line, ident, how) in violations_in_source(&src) {
            offenders.push(format!(
                "{}:{line}: `{ident}` reaches a log line as a {how}",
                file.display()
            ));
        }
        for (line, text) in instrument_sites(&src) {
            offenders.push(format!(
                "{}:{line}: `{text}` records every un-skipped argument as a \
                 span field, which the body scan cannot see",
                file.display()
            ));
        }
    }

    assert!(
        sites >= STAKE_ENGINE_LOG_SITE_FLOOR,
        "the scanner found only {sites} log site(s) under {} (floor {}) — the \
         parser stopped recognising the corpus, so the identifier assertion \
         below would be vacuous. Fix the parser before trusting this gate.",
        dir.display(),
        STAKE_ENGINE_LOG_SITE_FLOOR
    );

    assert!(
        offenders.is_empty(),
        "WSS-20: a `P`-correlated identifier reaches a log line.\n\
         The sink is a plaintext file that outlives the process; these ids \
         matched against the chain's public bond history identify `P`. Log a \
         count, or a value the chain does not publish.\n\n{}\n",
        offenders.join("\n")
    );
}

#[test]
fn p_serving_crates_carry_no_logging_surface() {
    let root = rust_root();
    let mut failures: Vec<String> = Vec::new();

    for crate_name in P_PATH_CRATES_WITHOUT_LOGGING {
        let crate_dir = root.join(crate_name);
        let manifest_path = crate_dir.join("Cargo.toml");
        let manifest = fs::read_to_string(&manifest_path).unwrap_or_else(|e| {
            panic!(
                "{} is unreadable ({e}) — the gate's subject is absent. The \
                 crate was renamed or removed; retire or re-point this gate \
                 deliberately rather than leaving it green.",
                manifest_path.display()
            )
        });
        // Rule 47: assert the manifest really is this crate's, so the scan
        // below cannot pass over the wrong one.
        assert!(
            manifest.contains(&format!("name = \"{crate_name}\"")),
            "{} does not declare `name = \"{crate_name}\"` — the gate is \
             reading the wrong manifest",
            manifest_path.display()
        );

        for dep in logging_deps(&manifest) {
            failures.push(format!(
                "{}: declares `{dep}` as a dependency",
                manifest_path.display()
            ));
        }

        let src = crate_dir.join("src");
        assert!(
            src.is_dir(),
            "{} has no src/ — the source half of this gate has no subject",
            src.display()
        );
        let files = rust_files(&src);
        assert!(
            !files.is_empty(),
            "no .rs files under {} — the source half of this gate has no subject",
            src.display()
        );
        for file in &files {
            let text = fs::read_to_string(file)
                .unwrap_or_else(|e| panic!("the WSS-20 scan must read {}: {e}", file.display()));
            for (line, mac) in print_macro_sites(&text) {
                failures.push(format!("{}:{line}: uses `{mac}!`", file.display()));
            }
            for (line, ident, how) in violations_in_source(&text) {
                failures.push(format!(
                    "{}:{line}: `{ident}` reaches a log line as a {how}",
                    file.display()
                ));
            }
            for (line, attr) in instrument_sites(&text) {
                failures.push(format!("{}:{line}: `{attr}`", file.display()));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "WSS-20: a crate on `P`'s serving path grew a logging surface.\n\
         These three crates hold `P`'s identity, its serve set and its onion \
         address, and deliberately cannot write any of it to disk. Adding a \
         logging surface here is a decision that needs review — not a \
         dependency line. If it is the right decision, widen this gate to a \
         field scan for these crates in the same change.\n\n{}\n",
        failures.join("\n")
    );
}
