// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The quoted-field lexer for one control-event line.
//!
//! A keyword is recognised only at the start of a token, before any quote is
//! opened. A keyword planted inside a quoted `SUMMARY` or `WARNING` stays part
//! of that value. [`super::events`] reads the tokens by name and by position.

/// One space-separated token of an event line.
#[derive(Debug, PartialEq, Eq)]
struct Token {
    /// `KEY` of a `KEY=VALUE` token, recognised only at the token's start and outside
    /// quotes. `None` for a positional token.
    key: Option<String>,
    /// The value, with a quoted string unquoted and its escapes decoded.
    value: String,
}

/// An event line's tokens, read by position or by keyword.
pub(super) struct Fields(Vec<Token>);

impl Fields {
    pub(super) fn of(line: &str) -> Self {
        Self(tokens(line))
    }

    /// The `index`th positional token, counting only tokens with no key.
    pub(super) fn positional(&self, index: usize) -> Option<&str> {
        self.0
            .iter()
            .filter(|t| t.key.is_none())
            .nth(index)
            .map(|t| t.value.as_str())
    }

    /// The value of the first `key=` token.
    pub(super) fn value(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|t| t.key.as_deref() == Some(key))
            .map(|t| t.value.as_str())
    }

    pub(super) fn has(&self, key: &str) -> bool {
        self.value(key).is_some()
    }

    pub(super) fn text(&self, key: &str) -> Option<String> {
        self.value(key).map(str::to_owned)
    }

    pub(super) fn number<T: std::str::FromStr>(&self, key: &str) -> Option<T> {
        self.value(key)?.parse().ok()
    }
}

/// Split an event line into tokens: on spaces outside double quotes. A token whose
/// leading characters are a keyword and `=` is a keyword token; the keyword test runs
/// before any quote is opened, so nothing inside a quoted value becomes a keyword.
fn tokens(line: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        while chars.next_if_eq(&' ').is_some() {}
        if chars.peek().is_none() {
            return tokens;
        }
        let mut raw = String::new();
        let mut quoted = false;
        while let Some(c) = chars.next() {
            match c {
                ' ' if !quoted => break,
                '"' => {
                    quoted = !quoted;
                    raw.push(c);
                }
                '\\' if quoted => {
                    raw.push(c);
                    if let Some(escaped) = chars.next() {
                        raw.push(escaped);
                    }
                }
                _ => raw.push(c),
            }
        }
        tokens.push(token(&raw));
    }
}

fn token(raw: &str) -> Token {
    let key_end = raw
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|&end| end > 0 && raw[end..].starts_with('='));
    match key_end {
        Some(end) => Token {
            key: Some(raw[..end].to_owned()),
            value: unquote(&raw[end + 1..]),
        },
        None => Token {
            key: None,
            value: unquote(raw),
        },
    }
}

/// Decode a control-spec `QuotedString`; a value with no surrounding quotes is
/// returned as it is. `\\`, `\"`, `\n`, `\r` and `\t` are decoded; any other escaped
/// character stands for itself.
fn unquote(raw: &str) -> String {
    let Some(inner) = raw.strip_prefix('"').and_then(|r| r.strip_suffix('"')) else {
        return raw.to_owned();
    };
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_quoted_string_is_decoded() {
        assert_eq!(unquote(r#""a\"b\\c\n""#), "a\"b\\c\n");
        assert_eq!(unquote("plain"), "plain");
        assert_eq!(
            tokens(r#"A="x y" B C="\"q r\"""#),
            [
                Token {
                    key: Some("A".to_owned()),
                    value: "x y".to_owned()
                },
                Token {
                    key: None,
                    value: "B".to_owned()
                },
                Token {
                    key: Some("C".to_owned()),
                    value: "\"q r\"".to_owned()
                },
            ]
        );
    }
}
