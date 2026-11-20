// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One strict reader for `docs/design/CRYPTO_DOMAIN_REGISTRY.tsv`.
//!
//! Included by `domain_registry` and `domain_binding` via `#[path]`. Those
//! stay separate test binaries. No tests live here — a `#[test]` in this
//! file would run in both.

/// One data row. Every row has exactly these ten columns; `key` and `notes`
/// may be empty. `line` is the 1-based line in the file.
///
/// Each binary reads a different subset of columns, so an unread field in
/// one of them is not a dead column.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub struct Row<'a> {
    pub line: usize,
    pub mech: &'a str,
    pub literal: &'a str,
    pub file: &'a str,
    pub konst: &'a str,
    pub status: &'a str,
    pub binding: &'a str,
    pub width: &'a str,
    pub role: &'a str,
    pub key: &'a str,
    pub notes: &'a str,
}

/// Well-formed mechanism ids: `1`..=`7` (live mechanisms) or `x` (excluded).
fn is_valid_mech(mech: &str) -> bool {
    matches!(mech, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "x")
}

fn is_valid_status(status: &str) -> bool {
    matches!(
        status,
        "shekyl-live" | "frozen-inherited" | "excluded" | "test-only" | "retired"
    )
}

/// Parse every data row. Blank lines and `#` comments are skipped. A data
/// row with any column count other than 10 is an error that names the line.
/// `mech`, `status`, and `key` are trimmed: distinctness and the status
/// closed list read them that way. The other columns are kept verbatim.
pub fn parse_rows(text: &str) -> Result<Vec<Row<'_>>, String> {
    let mut rows = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let line_no = lineno + 1;
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        // mech literal file const status binding width role key notes
        if f.len() != 10 {
            return Err(format!(
                "line {line_no}: expected exactly 10 columns (mech, literal, file, const, status, binding, width, role, key, notes), got {}",
                f.len()
            ));
        }
        let mech = f[0].trim();
        if !is_valid_mech(mech) {
            return Err(format!(
                "line {line_no}: bad mechanism id {mech:?} — expected 1..7 or x"
            ));
        }
        let literal = f[1];
        let file = f[2];
        if literal.is_empty() || file.is_empty() {
            return Err(format!(
                "line {line_no}: literal and file columns must be non-empty"
            ));
        }
        let status = f[4].trim();
        if !is_valid_status(status) {
            return Err(format!(
                "line {line_no}: bad status {status:?} — expected shekyl-live | \
                 frozen-inherited | excluded | test-only | retired"
            ));
        }
        // The excluded bucket and the excluded status must agree — a typo'd
        // mech id cannot smuggle a row out of (or into) distinctness scope.
        if (mech == "x") != (status == "excluded") {
            return Err(format!(
                "line {line_no}: mech {mech:?} / status {status:?} mismatch — \
                 mech x rows must be status excluded, and vice versa"
            ));
        }
        rows.push(Row {
            line: line_no,
            mech,
            literal,
            file,
            konst: f[3],
            status,
            binding: f[5],
            width: f[6],
            role: f[7],
            key: f[8].trim(),
            notes: f[9],
        });
    }
    Ok(rows)
}
