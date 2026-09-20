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
//! 4. `shekyl-p-host`, `shekyl-p-serve`, `shekyl-tor-control-client` and
//!    `shekyl-tor-control-wallet` **growing a logging surface at all** — a
//!    logging dependency or a `println!`/`eprintln!`/`dbg!`. These four
//!    crates have none today, so a denylist over their (zero) log sites
//!    would be vacuously green: the edit that makes a field scan red there
//!    needs a dependency *and* a site *and* a denylisted name. The check
//!    that can actually fail is structural, and it makes adding logging to
//!    the persona host a conscious gate edit — which is when review should
//!    happen (`47-gate-subject-assertion`).
//! 5. Every **spelling** of a macro call, because site detection reads a
//!    token stream rather than source text: whitespace or a comment between
//!    the path and its `!`, the `{}` and `[]` delimiter forms, the raw
//!    identifier `r#info!`, a leading-colon path, and a module-aliased path
//!    (`t::info!`) all resolve to the same site.
//! 6. An identifier spelled in **camel case**. The stems are snake case, but
//!    a type reaches a log through its constructor (`%PCanonicalId::from(b)`),
//!    and lowercasing alone turns `PCanonicalId` into `pcanonicalid`, which
//!    contains no stem — so the strictest names in the workspace were the
//!    likeliest to slip through. Identifiers are normalised to snake case
//!    before matching.
//! 7. Three ways to **rename the thing being matched on**, each refused
//!    rather than chased, because each leaves the call site spelling
//!    something this gate does not recognise:
//!    - `use tracing::info as note;` — a `use` rename, so `note!(…)` no
//!      longer spells a level;
//!    - `macro_rules! note { ($($a:tt)*) => { tracing::info!($($a)*) } }` —
//!      a forwarding wrapper, which names no identifier of its own *and*
//!      whose call sites name no level, defeating both halves at once;
//!    - `telemetry = { package = "tracing" }` — Cargo's own rename, which
//!      keeps the crate linked while the dependency key stops spelling it.
//!
//! **Does NOT cover** — the bypasses this scanner admits by construction,
//! each one named rather than left implied, because a source-text matcher
//! that does not say where it stops is read as saying it does not stop:
//!
//! - **An innocuous binding name.** A value passed under an innocuous field
//!   name or positionally (`n = ?v` where `v` holds shard ids). Only naming
//!   discipline catches that; the durable answer is exposure policy on the
//!   **type**, as `shekyl-types`' `hash32!` `redact` / `no_display` arms
//!   already do for `PCanonicalId` and `KeyImage`. Shard ids are a bare `u64`
//!   across the p-host/curve-tree API and have no such policy. Two shapes of
//!   the same hole: a **struct** logged whole whose `Debug` prints an id
//!   under an innocent field, and a `format!`/`write!` into an innocuous
//!   binding that is then logged.
//! - **`Display`/`Debug` of an error type** that embeds an identifier.
//!   `EmissionVerifyError` is the live example: three of its variants carry a
//!   `shard_id` in their `Display`, and `claim.rs` renders it with `%e`.
//!   Those two legs cannot reach those variants today, but the *type* admits
//!   it — a reachability argument, not a structural one, and reachability is
//!   exactly what a later edit changes.
//! - **A wrapper macro defined outside these paths.** One defined *in* path
//!   is refused outright (item 7) — scanning its definition for a forbidden
//!   identifier is **not** sufficient, because a forwarding wrapper's body
//!   names none. One defined elsewhere and invoked here expands past this
//!   scan entirely, and is the residue. There are no `macro_rules!`
//!   definitions in these five paths today, which is what keeps the gap
//!   narrow rather than closed.
//! - **`Span::record("shard_id", &value)`** — a field set through a method
//!   call with a string-literal name, which this scanner blanks along with
//!   every other literal. There are no `tracing` `Span::record` calls in
//!   these paths today (the `.record(` hits are a timeline observer and a
//!   backing store, neither a span).
//! - **The framework's own API** — `Event::dispatch`, a hand-written
//!   `Visit`. Out of reach for a source scan of call sites by construction.
//! - Every path outside the four crates above and `stake_engine/` — notably
//!   `engine/pscan/`, whose `persona = ?persona` sites are covered by the
//!   ratified `redact` arm (a two-byte `Debug` prefix) and are a separate
//!   question from this one.
//! - Whether the redacted forms that *are* ratified survive `WSS-20`'s
//!   adversary. That is a design-round question, not a call-site one.
//! - journald, log encryption, and the logging framework itself — out of
//!   scope for `WSS-20` by construction.
//!
//! What *is* caught and might read as absent: positional arguments
//! (`info!("{}", shard_id)`), dotted field names (`shard.id = ?x`) and a
//! value built by a call (`tracing::field::debug(&shard_ids)`) are all inside
//! the body span and are scanned as value expressions.
//!
//! ## Why a static scan and not a `tracing` capture layer
//!
//! A capture layer can only assert about events a test actually drives, and
//! four of the five audited paths have no `tracing` dependency at all —
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
/// must keep carrying none. See the module doc, item 4.
///
/// `shekyl-tor-control-wallet` is here because it *owns* the serving
/// identity rather than merely handling it: `shekyl-p-host/src/host.rs:15`
/// imports `OnionIdentity` and `ServiceId` from it, and it is the supervisor
/// that drives the control actor. Omitting it would leave the layer holding
/// `P`'s onion credential free to grow an unreviewed logging surface while
/// this gate stayed green — the gate being green because it was not looking.
const P_PATH_CRATES_WITHOUT_LOGGING: &[&str] = &[
    "shekyl-p-host",
    "shekyl-p-serve",
    "shekyl-tor-control-client",
    "shekyl-tor-control-wallet",
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

/// Every `tracing` macro that takes a field list. Matched on the macro's
/// final path segment, so `tracing::info!` and a bare `info!` behind a `use`
/// are the same entry and no spelling of the path needs listing.
///
/// The `*_span!` names are each listed in full because a macro's name is one
/// identifier token: `info_span` is not `span`, and an unlisted `info_span!`
/// would be missed entirely. A span's fields print on every event inside it
/// under the `fmt` layer, so they reach the file exactly as an event's own
/// fields do. `event!`'s leading `Level::INFO` is just a harmless first
/// element to the field parser.
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

/// `PCanonicalId` → `p_canonical_id`, `KeyImage` → `key_image`.
///
/// The stems are written in snake case, but a type name reaches a log line
/// in camel case — through a constructor (`%PCanonicalId::from_bytes(b)`) or
/// an associated function. Lowercasing alone turns `PCanonicalId` into
/// `pcanonicalid`, which contains **no** stem, so the strictest identifiers
/// in the workspace were the ones most likely to slip through. An underscore
/// goes before an upper-case letter that follows a lower-case letter or a
/// digit, and before the last upper-case letter of a run that starts a new
/// word — so `HTTPClient` becomes `http_client`, not `h_t_t_p_client`.
fn snake_case(ident: &str) -> String {
    let b = ident.as_bytes();
    let mut out = String::with_capacity(ident.len() + 4);
    for (i, &byte) in b.iter().enumerate() {
        if byte.is_ascii_uppercase() && i > 0 {
            let prev = b[i - 1];
            let starts_word = prev.is_ascii_lowercase() || prev.is_ascii_digit();
            let ends_acronym =
                prev.is_ascii_uppercase() && b.get(i + 1).is_some_and(u8::is_ascii_lowercase);
            if starts_word || ends_acronym {
                out.push('_');
            }
        }
        out.push(byte.to_ascii_lowercase() as char);
    }
    out
}

/// Identifiers in `text` that contain a forbidden stem, in snake case.
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
            let ident = snake_case(&text[start..i]);
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

// ─────────────────────────────────────────────────────────────────────────
// Tokenising: a token stream over the blanked text.
//
// Site detection is where every *spelling* bypass lives, so it reads tokens
// rather than raw text. Rust accepts whitespace — or a comment — between a
// macro's path and its `!` (`tracing::info ! (…)`), accepts `{}` and `[]` as
// macro delimiters (`info!{…}`), and accepts the raw-identifier spelling
// (`r#info!`). A needle like `"info!"` sees none of those. A token pair
// `Ident("info")` + `Punct('!')` sees all of them at once, because the
// whitespace between them never becomes a token in the first place.
//
// Only site *detection* moved to tokens. Field splitting and identifier
// flagging stay text-based: they read a body span this layer has already
// delimited correctly, which is the part that was ever in doubt.
// ─────────────────────────────────────────────────────────────────────────

/// What a token is. Identifiers carry text; everything else that matters to
/// site detection is a single punctuation byte.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TokenKind {
    Ident,
    Punct(u8),
}

/// A token of the blanked source, spanning the same bytes as the original.
#[derive(Clone, Copy, Debug)]
struct Token {
    kind: TokenKind,
    start: usize,
    end: usize,
}

impl Token {
    /// The identifier's text, with any `r#` sigil already dropped.
    fn text<'a>(&self, lexed: &'a Lexed) -> &'a str {
        &lexed.blanked[self.start..self.end]
    }

    fn is_punct(&self, byte: u8) -> bool {
        self.kind == TokenKind::Punct(byte)
    }

    fn is_ident(&self, lexed: &Lexed, name: &str) -> bool {
        self.kind == TokenKind::Ident && self.text(lexed) == name
    }
}

fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Tokenise already-lexed source. Comment bodies and string contents are
/// spaces by this point, so they yield no identifiers and — the reason the
/// two passes are ordered this way — cannot forge a delimiter.
fn tokens(lexed: &Lexed) -> Vec<Token> {
    let b = lexed.blanked.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        // `r#ident` is the same identifier as `ident`. Start past the sigil
        // so `r#info!` and `info!` produce the same token text. A raw string
        // (`r#"…"#`) is not this: its third byte is a quote, not an
        // identifier byte, so it falls through to punctuation.
        if b[i] == b'r' && i + 2 < b.len() && b[i + 1] == b'#' && is_ident_start(b[i + 2]) {
            i += 2;
        }
        if is_ident_start(b[i]) {
            let start = i;
            while i < b.len() && is_ident_continue(b[i]) {
                i += 1;
            }
            out.push(Token {
                kind: TokenKind::Ident,
                start,
                end: i,
            });
        } else if b[i].is_ascii_whitespace() {
            i += 1;
        } else {
            out.push(Token {
                kind: TokenKind::Punct(b[i]),
                start: i,
                end: i + 1,
            });
            i += 1;
        }
    }
    out
}

/// Line number (1-based) of a byte offset in the lexed text.
fn line_of(lexed: &Lexed, offset: usize) -> usize {
    lexed.blanked[..offset].matches('\n').count() + 1
}

/// The whole source line containing `offset`, trimmed — what a human needs
/// to recognise the site, rather than the slice the match started at.
fn source_line(lexed: &Lexed, offset: usize) -> String {
    let start = lexed.blanked[..offset].rfind('\n').map_or(0, |n| n + 1);
    let end = lexed.blanked[offset..]
        .find('\n')
        .map_or(lexed.blanked.len(), |n| offset + n);
    lexed.blanked[start..end].trim().to_owned()
}

/// One macro invocation: `[path::]name! <delimited body>`.
struct MacroSite {
    /// The **final** path segment, lowercased — `info`, `info_span`,
    /// `println`. Path-insensitive by construction, so `tracing::info!`,
    /// `::tracing::info!` and a module-aliased `t::info!` are one site.
    name: String,
    line: usize,
    /// Byte span of the body *inside* the delimiters.
    body: (usize, usize),
}

/// Every macro invocation in already-lexed source.
///
/// Matches `Ident` `!` `(`|`[`|`{`, which is the whole grammar of a macro
/// call's head. `a != b` cannot match: its third token is `=`, not an
/// opening delimiter. The matching closer is found over the token stream, so
/// a delimiter inside a blanked string or char literal cannot shift depth.
fn macro_sites(lexed: &Lexed) -> Vec<MacroSite> {
    let toks = tokens(lexed);
    let mut out = Vec::new();
    for (i, tok) in toks.iter().enumerate() {
        if tok.kind != TokenKind::Ident {
            continue;
        }
        if !toks.get(i + 1).is_some_and(|t| t.is_punct(b'!')) {
            continue;
        }
        let Some(open) = toks.get(i + 2) else {
            continue;
        };
        let TokenKind::Punct(opener) = open.kind else {
            continue;
        };
        let closer = match opener {
            b'(' => b')',
            b'[' => b']',
            b'{' => b'}',
            _ => continue,
        };
        let mut depth = 0i32;
        let mut body_end = None;
        for later in &toks[i + 2..] {
            if later.is_punct(opener) {
                depth += 1;
            } else if later.is_punct(closer) {
                depth -= 1;
                if depth == 0 {
                    body_end = Some(later.start);
                    break;
                }
            }
        }
        let Some(end) = body_end else {
            continue;
        };
        out.push(MacroSite {
            name: tok.text(lexed).to_ascii_lowercase(),
            line: line_of(lexed, tok.start),
            body: (open.end, end),
        });
    }
    out
}

/// Macro invocations that write a `tracing` line carrying a field list.
fn log_sites(lexed: &Lexed) -> Vec<MacroSite> {
    macro_sites(lexed)
        .into_iter()
        .filter(|site| LEVELS.contains(&site.name.as_str()))
        .collect()
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

/// A step of the walk that could not be completed, naming the path.
#[derive(Debug)]
struct WalkError {
    path: PathBuf,
    source: std::io::Error,
}

impl std::fmt::Display for WalkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the WSS-20 walk could not read {}: {}. The corpus is \
             incomplete, so a clean result would mean the scan did not look \
             rather than that there was nothing to find",
            self.path.display(),
            self.source
        )
    }
}

/// Every `.rs` file under `dir`, sorted.
///
/// **Every** fallible step surfaces, carrying the path that failed: the
/// directory read, each entry within it, and the metadata call that decides
/// whether an entry is a subtree to descend into. A walk that turns any of
/// those into a skip reports exactly what a clean corpus reports — absence
/// of signal read as evidence of absence, which is the failure
/// `47-gate-subject-assertion` names, arriving inside the gate itself.
///
/// `Path::is_dir` is deliberately **not** used: it answers `false` for any
/// path it cannot stat, so a dangling symlink, a permission-denied subtree
/// or a vanished entry all become "not a directory, not a `.rs` file" and
/// are dropped in silence. `fs::metadata` follows the link and reports the
/// failure instead, which is the difference between a scanner that found
/// nothing and one that could not look.
fn rust_files(dir: &Path) -> Result<Vec<PathBuf>, WalkError> {
    let mut out = Vec::new();
    let entries = fs::read_dir(dir).map_err(|source| WalkError {
        path: dir.to_path_buf(),
        source,
    })?;
    for entry in entries {
        // Iteration itself is fallible, per entry, independently of the
        // `read_dir` that opened the directory.
        let entry = entry.map_err(|source| WalkError {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let meta = fs::metadata(&path).map_err(|source| WalkError {
            path: path.clone(),
            source,
        })?;
        if meta.is_dir() {
            out.extend(rust_files(&path)?);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// The walk, with an unreadable corpus turned into a failed gate rather than
/// a quiet one. Every caller is a gate that must not proceed on a partial
/// corpus, so there is one shared way to stop.
fn rust_files_or_fail(dir: &Path) -> Vec<PathBuf> {
    rust_files(dir).unwrap_or_else(|e| panic!("{e}"))
}

/// The crate a `package = "…"` key renames to, if this line carries one.
fn package_rename(line: &str) -> Option<String> {
    let at = line.find("package")?;
    // A key, not the tail of another one (`default-package`).
    if at > 0 {
        let prev = line.as_bytes()[at - 1];
        if is_ident_continue(prev) || prev == b'-' {
            return None;
        }
    }
    let rest = line[at + "package".len()..].trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

/// Logging crates named in a manifest's **non-dev, non-build** dependency
/// tables, including `[dependencies.x]` and `[target.'cfg(…)'.dependencies]`.
///
/// A dependency can be renamed — `telemetry = { package = "tracing" }` — and
/// then the key stops spelling the crate while the crate is still linked and
/// still logs. That is the manifest's version of `use tracing::info as note`,
/// and it is read the same way: the `package` **value** names the real crate
/// whatever the key says. All three spellings are covered — the inline table
/// on one line, the `[dependencies.telemetry]` table form, and the inline
/// table spread across lines.
fn logging_deps(manifest: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut in_deps_table = false;
    // True while an inline table opened on an earlier line is still open, so
    // `telemetry = {` / `package = "tracing"` / `}` reads as one entry.
    let mut inline_table_open = false;

    for line in manifest.lines() {
        let t = line.trim();
        if let Some(header) = t.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            let header = header.trim();
            let is_dev_or_build =
                header.contains("dev-dependencies") || header.contains("build-dependencies");
            in_deps_table = !is_dev_or_build && header.ends_with("dependencies");
            inline_table_open = false;
            // `[dependencies.tracing]` names the dependency in the header;
            // `[dependencies.telemetry]` may still rename via `package`, so
            // the table's body stays in scope either way.
            if !is_dev_or_build {
                if let Some((_, dep)) = header.rsplit_once("dependencies.") {
                    let dep = dep.trim().trim_matches('"');
                    if is_logging_crate(dep) {
                        found.insert(dep.to_owned());
                    }
                    in_deps_table = true;
                }
            }
            continue;
        }
        if !in_deps_table || t.is_empty() || t.starts_with('#') {
            continue;
        }

        // A `package = "x"` anywhere in scope names the real crate.
        if let Some(renamed) = package_rename(t) {
            if is_logging_crate(&renamed) {
                found.insert(renamed);
            }
        }

        if inline_table_open {
            if t.contains('}') {
                inline_table_open = false;
            }
            continue;
        }

        let Some((key, value)) = t.split_once('=') else {
            continue;
        };
        if value.trim_start().starts_with('{') && !value.contains('}') {
            inline_table_open = true;
        }
        // `tracing = { … }`, `tracing.workspace = true`, `"tracing" = …`.
        let key = key.trim().trim_matches('"');
        let name = key
            .split('.')
            .next()
            .unwrap_or(key)
            .trim()
            .trim_matches('"');
        if is_logging_crate(name) {
            found.insert(name.to_owned());
        }
    }
    found
}

/// Print-macro invocations: `(line, macro name)`.
fn print_macro_sites(src: &str) -> Vec<(usize, String)> {
    macro_sites(&lex(src))
        .into_iter()
        .filter(|site| PRINT_MACROS.contains(&site.name.as_str()))
        .map(|site| (site.line, site.name))
        .collect()
}

/// Whether a `use`-path segment names a logging crate. Manifests spell these
/// with hyphens (`tracing-core`) and source spells them with underscores
/// (`tracing_core`); this compares in the manifest's spelling.
fn is_logging_crate(segment: &str) -> bool {
    LOGGING_CRATES.contains(&segment.replace('_', "-").as_str())
        || LOGGING_CRATES.contains(&segment)
}

/// `macro_rules!` definitions whose body invokes a logging macro:
/// `(line, the macro's name)`.
///
/// A **forwarding** wrapper defeats both halves of this scanner at once:
///
/// ```ignore
/// macro_rules! note { ($($a:tt)*) => { tracing::info!($($a)*) } }
/// note!(shard_ids = ?releasable);
/// ```
///
/// The definition names no forbidden identifier — `$($a:tt)*` is opaque — so
/// scanning it finds nothing; and the call site spells `note!`, not a level,
/// so site detection never opens it. Scanning definitions is therefore *not*
/// enough on its own, which is why the definition is refused outright: a
/// wrapper around a log macro in these paths is a decision, not a detail.
fn logging_wrapper_macros(src: &str) -> Vec<(usize, String)> {
    let lexed = lex(src);
    let toks = tokens(&lexed);
    let logs = log_sites(&lexed);
    let mut out = Vec::new();
    for (i, tok) in toks.iter().enumerate() {
        // `macro_rules` `!` `name` `{` — the name sits where a macro call
        // would put its delimiter, so `macro_sites` does not match this.
        if !tok.is_ident(&lexed, "macro_rules") {
            continue;
        }
        if !toks.get(i + 1).is_some_and(|t| t.is_punct(b'!')) {
            continue;
        }
        let Some(name) = toks.get(i + 2).filter(|t| t.kind == TokenKind::Ident) else {
            continue;
        };
        let Some(open) = toks.get(i + 3).filter(|t| t.is_punct(b'{')) else {
            continue;
        };
        let (mut depth, mut body_end) = (0i32, None);
        for later in &toks[i + 3..] {
            if later.is_punct(b'{') {
                depth += 1;
            } else if later.is_punct(b'}') {
                depth -= 1;
                if depth == 0 {
                    body_end = Some(later.start);
                    break;
                }
            }
        }
        let Some(end) = body_end else {
            continue;
        };
        let forwards = logs
            .iter()
            .any(|site| site.body.0 >= open.end && site.body.1 <= end);
        if forwards {
            out.push((line_of(&lexed, tok.start), name.text(&lexed).to_owned()));
        }
    }
    out
}

/// `use` items that rename something out of a logging crate:
/// `(line, the item's source line)`.
///
/// Site detection keys on a macro's final path segment, so
/// `use tracing::info as note;` followed by `note!(shard_id = 1)` would pass
/// a name-based scan — the invocation no longer spells a level. Rather than
/// chase an alias through the file (and still miss the multi-hop case), the
/// rename itself is refused in these paths: there is no reason to rename a
/// log macro here, and doing it should be a deliberate edit to this gate.
fn aliased_logging_imports(src: &str) -> Vec<(usize, String)> {
    let lexed = lex(src);
    let toks = tokens(&lexed);
    let mut out = Vec::new();
    for (i, tok) in toks.iter().enumerate() {
        if !tok.is_ident(&lexed, "use") {
            continue;
        }
        let (mut renamed, mut from_logging) = (false, false);
        for later in &toks[i + 1..] {
            if later.is_punct(b';') {
                break;
            }
            if later.kind != TokenKind::Ident {
                continue;
            }
            let text = later.text(&lexed);
            if text == "as" {
                renamed = true;
            } else if is_logging_crate(text) {
                from_logging = true;
            }
        }
        if renamed && from_logging {
            out.push((line_of(&lexed, tok.start), source_line(&lexed, tok.start)));
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
    let toks = tokens(&lexed);
    let mut out = Vec::new();
    for (i, tok) in toks.iter().enumerate() {
        if !tok.is_punct(b'#') {
            continue;
        }
        // `#[…]` (outer) and `#![…]` (inner) both introduce attributes.
        let mut j = i + 1;
        if toks.get(j).is_some_and(|t| t.is_punct(b'!')) {
            j += 1;
        }
        if !toks.get(j).is_some_and(|t| t.is_punct(b'[')) {
            continue;
        }
        // Any `instrument` identifier anywhere inside the attribute's
        // brackets counts. That covers `#[instrument]`,
        // `#[tracing::instrument(skip_all)]` and the indirect
        // `#[cfg_attr(feature = "x", tracing::instrument)]` alike, without
        // caring how the path is spelled or spaced.
        let (mut depth, mut closed, mut found) = (0i32, false, false);
        for later in &toks[j..] {
            if later.is_punct(b'[') {
                depth += 1;
            } else if later.is_punct(b']') {
                depth -= 1;
                if depth == 0 {
                    closed = true;
                    break;
                }
            } else if later.is_ident(&lexed, "instrument") {
                found = true;
            }
        }
        if closed && found {
            out.push((line_of(&lexed, tok.start), source_line(&lexed, tok.start)));
        }
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
fn scanner_sees_every_spelling_of_a_macro_call() {
    // The spellings a needle match misses. Each is valid Rust that reaches
    // the same `fmt` layer as the contiguous form, so each must be one site.
    let spellings = [
        // Whitespace between the path and the `!` (Copilot, `:422`).
        "tracing::info ! (shard_ids = ?releasable);",
        // A comment there, which lexing turns into whitespace.
        "tracing::info /* here */ ! (shard_ids = ?releasable);",
        // Brace and bracket delimiters are equally valid macro delimiters.
        "tracing::info!{shard_ids = ?releasable}",
        "tracing::info![shard_ids = ?releasable];",
        // The raw-identifier spelling of the same name.
        "tracing::r#info!(shard_ids = ?releasable);",
        // A leading-colon absolute path, and a module alias for the crate.
        "::tracing::info!(shard_ids = ?releasable);",
        "t::info!(shard_ids = ?releasable);",
        // Newline-separated path, `!` and delimiter.
        "tracing::info\n    !\n    (shard_ids = ?releasable);",
    ];
    for spelling in spellings {
        let hits = violations_in_source(spelling);
        assert!(
            hits.iter().any(|(_, id, _)| id == "shard_ids"),
            "`{spelling}` is a log site and must be scanned; found {hits:?}"
        );
    }

    // `!=` is not a macro call: the token after `!` is `=`, not a delimiter.
    assert!(
        violations_in_source("if info != shard_ids.len() { }").is_empty(),
        "a `!=` comparison must not open a macro site"
    );
    // A macro whose name merely ends in a level name is still not a level.
    assert!(
        violations_in_source("my_info!(shard_ids = ?x);").is_empty(),
        "`my_info!` is a different macro; the name must match as a whole"
    );
}

#[test]
fn scanner_refuses_an_aliased_logging_import() {
    // The alias bypass: the call site no longer spells a level, so a
    // name-based scan sees nothing. The rename is refused instead.
    let aliased = "use tracing::info as note;\nfn f() { note!(shard_id = 1); }\n";
    assert!(
        !aliased_logging_imports(aliased).is_empty(),
        "`use tracing::info as note;` must be refused: it renames the very \
         token this gate matches on"
    );
    // A rename that has nothing to do with logging is not this gate's
    // business — a gate that reds on those invites someone to delete it.
    for innocent in [
        "use rand_core::RngCore as _;",
        "use std::os::unix::fs::PermissionsExt as _;",
        "use std::collections::BTreeMap as Map;",
    ] {
        assert!(
            aliased_logging_imports(innocent).is_empty(),
            "`{innocent}` is not a logging rename"
        );
    }
    // Importing a logging macro *without* renaming it is fine: the call site
    // still spells the level, so the scan still sees it.
    assert!(
        aliased_logging_imports("use tracing::info;").is_empty(),
        "an un-renamed import keeps the call site's spelling and is in scope"
    );
}

#[test]
fn camel_case_type_names_normalise_onto_their_stems() {
    // Lowercasing alone turns `PCanonicalId` into `pcanonicalid`, which
    // contains no stem — so the workspace's *strictest* identifiers were the
    // likeliest to pass. Each of these is a real type from `shekyl-types`.
    for (camel, snake) in [
        ("PCanonicalId", "p_canonical_id"),
        ("KeyImage", "key_image"),
        ("ServiceId", "service_id"),
        ("GlobalOutputIndex", "global_output_index"),
        ("HTTPClient", "http_client"),
        ("StepId", "step_id"),
    ] {
        assert_eq!(snake_case(camel), snake, "`{camel}` must normalise");
    }

    // The constructor-expression form: the identifier is a *type*, and its
    // `Display` is full hex.
    let constructor = "tracing::info!(id = %PCanonicalId::from_bytes(bytes));";
    let hits = violations_in_source(constructor);
    assert!(
        hits.iter().any(|(_, id, _)| id == "p_canonical_id"),
        "a camel-case type in a value expression must be flagged; found {hits:?}"
    );

    // Normalisation must not manufacture a hit: `StepId` snake-cases to
    // `step_id`, which does not *start* with `p_id`.
    assert!(
        flagged_idents("StepId StopId MapSlot GroupId").is_empty(),
        "camel-case innocents must stay clean: {:?}",
        flagged_idents("StepId StopId MapSlot GroupId")
    );
}

#[test]
fn scanner_refuses_a_forwarding_wrapper_macro() {
    // The wrapper defeats both halves at once: `$($a:tt)*` names no
    // forbidden identifier, and `note!(…)` names no level. Scanning the
    // definition for an identifier — which is what this gate used to claim
    // covered the case — finds nothing at all.
    let forwarding = "macro_rules! note { ($($a:tt)*) => { tracing::info!($($a)*) }; }\n";
    assert!(
        violations_in_source(forwarding).is_empty(),
        "precondition: the wrapper body names no forbidden identifier, which \
         is exactly why scanning definitions is not sufficient"
    );
    let wrappers = logging_wrapper_macros(forwarding);
    assert!(
        wrappers.iter().any(|(_, name)| name == "note"),
        "a `macro_rules!` forwarding to a log macro must be refused; found \
         {wrappers:?}"
    );

    // A `macro_rules!` that does not log is not this gate's business.
    let innocent = "macro_rules! square { ($x:expr) => { $x * $x }; }\n";
    assert!(
        logging_wrapper_macros(innocent).is_empty(),
        "a non-logging macro definition must not trip the gate"
    );
}

#[test]
fn manifest_matcher_sees_through_a_cargo_rename() {
    // Cargo's own alias: the key stops spelling the crate, the crate stays
    // linked and still logs. Same class as `use tracing::info as note`.
    let inline = "[dependencies]\ntelemetry = { package = \"tracing\", version = \"0.1\" }\n";
    assert!(
        logging_deps(inline).contains("tracing"),
        "an inline `package = \"tracing\"` rename must be found: {:?}",
        logging_deps(inline)
    );

    let table = "[dependencies.telemetry]\npackage = \"tracing\"\nversion = \"0.1\"\n";
    assert!(
        logging_deps(table).contains("tracing"),
        "the `[dependencies.telemetry]` + `package` form must be found"
    );

    let multiline =
        "[dependencies]\ntelemetry = {\n    package = \"tracing\",\n    version = \"0.1\",\n}\n";
    assert!(
        logging_deps(multiline).contains("tracing"),
        "an inline table spread across lines must be found"
    );

    // A dev-dependency rename still never ships.
    let dev = "[dev-dependencies]\ntelemetry = { package = \"tracing\" }\n";
    assert!(
        logging_deps(dev).is_empty(),
        "a renamed dev-dependency must not trip the gate"
    );
    // A rename to something that is not a logging crate is not a finding.
    let unrelated = "[dependencies]\nrng = { package = \"rand_core\", version = \"0.6\" }\n";
    assert!(
        logging_deps(unrelated).is_empty(),
        "an unrelated rename must not trip the gate"
    );
}

#[test]
#[cfg(unix)]
fn walk_reports_an_entry_it_cannot_read_instead_of_skipping_it() {
    use std::os::unix::fs::symlink;

    // The F1 class: a walk step that fails must not read as "nothing here".
    // A dangling symlink is the deterministic form — `Path::is_dir` answers
    // `false` for it (it cannot stat the target) and the old walk therefore
    // dropped it in silence, reporting the same clean corpus as a clean one.
    let dir = std::env::temp_dir().join(format!("wss20-walk-{}", std::process::id()));
    fs::remove_dir_all(&dir).ok();
    fs::create_dir_all(&dir).expect("temp dir for the walk control");
    fs::write(dir.join("real.rs"), "// nothing\n").expect("a readable file");

    // Control: the walk is green and actually finds the subject.
    let found = rust_files(&dir).expect("a readable corpus must walk cleanly");
    assert_eq!(found.len(), 1, "the control must find the one real file");

    symlink("/nonexistent-wss20-target", dir.join("dangling")).expect("symlink");
    let err = rust_files(&dir).expect_err(
        "a dangling entry must fail the walk: a corpus the scanner cannot \
         resolve is not a corpus it found nothing in",
    );
    assert!(
        err.to_string().contains("dangling"),
        "the failure must name the path that could not be read: {err}"
    );

    fs::remove_dir_all(&dir).ok();
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

    let files = rust_files_or_fail(&dir);
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
        for (line, text) in aliased_logging_imports(&src) {
            offenders.push(format!(
                "{}:{line}: `{text}` renames a logging macro, so its call \
                 sites no longer spell a level this gate matches on",
                file.display()
            ));
        }
        for (line, name) in logging_wrapper_macros(&src) {
            offenders.push(format!(
                "{}:{line}: `macro_rules! {name}` forwards to a log macro, so \
                 `{name}!(…)` logs without naming a level this gate matches on",
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
        let files = rust_files_or_fail(&src);
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
            for (line, attr) in aliased_logging_imports(&text) {
                failures.push(format!(
                    "{}:{line}: `{attr}` renames a logging macro",
                    file.display()
                ));
            }
            for (line, name) in logging_wrapper_macros(&text) {
                failures.push(format!(
                    "{}:{line}: `macro_rules! {name}` forwards to a log macro",
                    file.display()
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "WSS-20: a crate on `P`'s serving path grew a logging surface.\n\
         These four crates hold `P`'s identity, its serve set and its onion \
         address, and deliberately cannot write any of it to disk. Adding a \
         logging surface here is a decision that needs review — not a \
         dependency line. If it is the right decision, widen this gate to a \
         field scan for these crates in the same change.\n\n{}\n",
        failures.join("\n")
    );
}
