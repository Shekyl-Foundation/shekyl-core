// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one lexer the workspace's log scans read Rust source through: the
//! `WSS-20` gate (`tests/p_correlated_ids_absent_from_logs.rs`, which
//! includes this file by path) and [`super`]'s audit of what each crate logs
//! under. It moved here from that gate unchanged, so the gate's self-tests
//! of every spelling of a macro call hold for both readers.

// ─────────────────────────────────────────────────────────────────────────
// Lexing: blank comments and string contents, keeping byte offsets stable.
// ─────────────────────────────────────────────────────────────────────────

/// A lexed view of a Rust source file.
pub(crate) struct Lexed {
    /// Same length as the input. Comment bodies and string-literal *contents*
    /// are replaced by spaces (newlines preserved), so offsets and line
    /// numbers still line up with the original.
    ///
    /// Blanking string contents is what lets the field scan run without
    /// tripping on prose: the corrected `WSS-20` line's own message still
    /// reads "these shards were absent from the bond record", and a sweep
    /// cannot otherwise tell that quotation from a reference.
    pub(crate) blanked: String,
    /// `(start, end)` byte spans of each string literal's **contents** in the
    /// original text, so inline format captures can be scanned separately.
    pub(crate) string_spans: Vec<(usize, usize)>,
}

pub(crate) fn lex(src: &str) -> Lexed {
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
pub(crate) enum TokenKind {
    Ident,
    Punct(u8),
}

/// A token of the blanked source, spanning the same bytes as the original.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Token {
    pub(crate) kind: TokenKind,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

impl Token {
    /// The identifier's text, with any `r#` sigil already dropped.
    pub(crate) fn text<'a>(&self, lexed: &'a Lexed) -> &'a str {
        &lexed.blanked[self.start..self.end]
    }

    pub(crate) fn is_punct(&self, byte: u8) -> bool {
        self.kind == TokenKind::Punct(byte)
    }

    pub(crate) fn is_ident(&self, lexed: &Lexed, name: &str) -> bool {
        self.kind == TokenKind::Ident && self.text(lexed) == name
    }
}

pub(crate) fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

pub(crate) fn is_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Tokenise already-lexed source. Comment bodies and string contents are
/// spaces by this point, so they yield no identifiers and — the reason the
/// two passes are ordered this way — cannot forge a delimiter.
pub(crate) fn tokens(lexed: &Lexed) -> Vec<Token> {
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
pub(crate) fn line_of(lexed: &Lexed, offset: usize) -> usize {
    lexed.blanked[..offset].matches('\n').count() + 1
}

/// One macro invocation: `[path::]name! <delimited body>`.
pub(crate) struct MacroSite {
    /// The **final** path segment, lowercased — `info`, `info_span`,
    /// `println`. Path-insensitive by construction, so `tracing::info!`,
    /// `::tracing::info!` and a module-aliased `t::info!` are one site.
    pub(crate) name: String,
    pub(crate) line: usize,
    /// Byte span of the body *inside* the delimiters.
    pub(crate) body: (usize, usize),
}

/// Every macro invocation in already-lexed source.
///
/// Matches `Ident` `!` `(`|`[`|`{`, which is the whole grammar of a macro
/// call's head. `a != b` cannot match: its third token is `=`, not an
/// opening delimiter. The matching closer is found over the token stream, so
/// a delimiter inside a blanked string or char literal cannot shift depth.
pub(crate) fn macro_sites(lexed: &Lexed) -> Vec<MacroSite> {
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
