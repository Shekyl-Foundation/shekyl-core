// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SA-3b intra-mechanism domain distinctness.
//!
//! Reads the single-source registry (`docs/design/CRYPTO_DOMAIN_REGISTRY.tsv`)
//! and asserts that, **within each mechanism**, no two distinct signing/derivation
//! contexts share the same domain identity.
//!
//! Why per-mechanism, not a flat 80-way test: a domain-separation collision only
//! matters between two contexts that feed the *same* primitive. Every domain seam
//! in the tree feeds exactly one mechanism (cSHAKE customization, HKDF salt+info,
//! FROST transcript label, Blake2b DST, keccak/schnorr challenge DST, or the
//! SHA3-256 micro-bucket), so `b"shekyl-kem-v1"` (an HKDF salt) and a cSHAKE
//! customization that happened to share bytes could never collide — they are
//! never hashed by the same construction. A flat all-pairs distinctness assertion
//! would be a category error (and would spuriously flag the legitimate
//! cross-mechanism reuse of `b"nonce"`).
//!
//! The distinctness IDENTITY is the registry `key` column, defaulting to the
//! literal, **decoded to bytes** before comparison: registry spellings are
//! source-faithful (the CI gate greps them verbatim at the defining site), so
//! `b"A"` and `b"\x41"` — identical domains — may legitimately be spelled
//! differently, and comparing spellings would let a real same-mechanism
//! collision hide behind escape encoding. Mechanism 2 (HKDF) is keyed by
//! `salt|info`, because a derivation's
//! separation comes from the (salt, info) pair, not the info alone: the three
//! shared info labels (`shekyl-ed25519-spend/-view/-ml-kem-768`) appear as both a
//! const (composed `salt_for` salt) and an inline `SeedDerivation` (fixed
//! `shekyl-master-derive-v1` salt) — legitimately distinct derivations that a
//! bare-info test would wrongly report as a collision, and which SA-3b is NOT
//! permitted to "fix" (it mutates zero domain values).
//!
//! `test-only` rows are the segregation census: domains minted by test/bench
//! code. They are excluded from production distinctness (test-vs-test collisions
//! are legitimate) but must never equal a production identity in the same
//! mechanism — a test-minted artifact would otherwise verify against the
//! production context (cross-context replay of test artifacts).
//!
//! The per-mechanism census counts are pinned HERE and nowhere else: the TSV
//! section headers carry no counts, and the CBOM / SIGNATURE_ALIGNMENT copies
//! are dated snapshots that defer to this pin. A registry row silently vanishing
//! (which row-presence in the CI gate cannot see — it iterates the rows that
//! exist) fails the census pin instead.
//!
//! This test is the collision-catcher; the CI gate
//! (`scripts/ci/domain_registry_gate.sh`) is the drift-closer for *registered*
//! rows (row-presence + const binding + entry-point count-pins on mech 1/3 +
//! frozen-doc cross-check). Together they keep the registry honest against the
//! code without publishing any security constant. Completeness for mech 2/4/5/6
//! (new unregistered domains) is a review duty — see the gate header and CBOM §3.

use std::collections::{HashMap, HashSet};

const REGISTRY: &str = include_str!("../../../docs/design/CRYPTO_DOMAIN_REGISTRY.tsv");

/// Pinned census: (mech, shekyl-live rows, frozen-inherited rows). Update when
/// a row is deliberately added/removed — the failure message names the drift.
/// The CBOM table (docs/CRYPTOGRAPHIC_INVENTORY.md §3) is a dated snapshot of
/// these numbers.
const PRODUCTION_PINS: [(&str, usize, usize); 6] = [
    ("1", 25, 0), // SA-3c: +1 (snapshot-id moved mech 5→1 on cn_fast_hash/Keccak→cSHAKE)
    ("2", 44, 0),
    ("3", 1, 3),
    ("4", 9, 0),
    ("5", 6, 8), // SA-3c: -1 (snapshot-id left mechanism 5)
    ("6", 1, 0),
];
/// Pinned counts for the non-production sections.
const EXCLUDED_EXPECTED: usize = 8;
const TEST_ONLY_EXPECTED: usize = 6;

/// Well-formed mechanism ids: `1`..`6` (live mechanisms) or `x` (excluded).
fn is_valid_mech(mech: &str) -> bool {
    matches!(mech, "1" | "2" | "3" | "4" | "5" | "6" | "x")
}

fn is_valid_status(status: &str) -> bool {
    matches!(
        status,
        "shekyl-live" | "frozen-inherited" | "excluded" | "test-only"
    )
}

struct Row<'a> {
    mech: &'a str,
    literal: &'a str,
    file: &'a str,
    status: &'a str,
    key: &'a str,
}

impl Row<'_> {
    /// A row that participates in production distinctness (live or frozen).
    fn is_production(&self) -> bool {
        matches!(self.status, "shekyl-live" | "frozen-inherited")
    }
}

fn parse_rows(text: &str) -> Result<Vec<Row<'_>>, String> {
    let mut rows = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let line_no = lineno + 1;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        // mech  literal  file  const  status  key  notes
        let mech = f.first().copied().unwrap_or("").trim();
        if mech.is_empty() || mech.starts_with('#') {
            continue;
        }
        if !is_valid_mech(mech) {
            return Err(format!(
                "line {line_no}: bad mechanism id {mech:?} — expected 1..6 or x"
            ));
        }
        if f.len() < 5 {
            return Err(format!(
                "line {line_no}: expected at least 5 columns (mech, literal, file, const, status), got {}",
                f.len()
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
                 frozen-inherited | excluded | test-only"
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
        let key = f.get(5).copied().unwrap_or("").trim();
        rows.push(Row {
            mech,
            literal,
            file,
            status,
            key,
        });
    }
    Ok(rows)
}

/// Parse the registry or fail the calling test with the parser's diagnostic.
/// Single owner of the parse-and-validate step for every test below.
fn parsed_registry() -> Vec<Row<'static>> {
    parse_rows(REGISTRY).expect("registry must parse with valid mech ids, columns, and statuses")
}

/// Decode the Rust byte-string escapes a registry spelling may contain
/// (`\0`, `\t`, `\n`, `\r`, `\\`, `\'`, `\"`, `\xHH`) into the bytes the
/// mechanism actually hashes. Distinctness must compare BYTES, not spellings:
/// `b"A"` and `b"\x41"` are the same domain, and the registry deliberately
/// keeps SOURCE-FAITHFUL spellings (the CI gate greps the literal verbatim
/// at its defining site), so two rows could otherwise register identical
/// bytes under different escape encodings and pass. Unknown escapes are a
/// loud parse error, never passed through.
fn decode_escapes(s: &str) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        let Some(&esc) = b.get(i + 1) else {
            return Err(format!("{s:?}: dangling backslash"));
        };
        match esc {
            b'0' => out.push(0x00),
            b't' => out.push(b'\t'),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b'\\' => out.push(b'\\'),
            b'\'' => out.push(b'\''),
            b'"' => out.push(b'"'),
            b'x' => {
                let hex = s
                    .get(i + 2..i + 4)
                    .ok_or_else(|| format!("{s:?}: truncated \\x escape"))?;
                out.push(
                    u8::from_str_radix(hex, 16)
                        .map_err(|_| format!("{s:?}: bad \\x{hex} escape"))?,
                );
                i += 4;
                continue;
            }
            other => {
                return Err(format!(
                    "{s:?}: unsupported escape \\{} — extend decode_escapes deliberately",
                    other as char
                ));
            }
        }
        i += 2;
    }
    Ok(out)
}

/// The identity a row occupies within its mechanism's separation space,
/// decoded to bytes (escape-blind — see `decode_escapes`). For keyed rows
/// (mech-2 `salt|info` composites) the key is decoded the same way: its
/// fragments are literal spellings joined by separators.
fn identity(row: &Row<'_>) -> Vec<u8> {
    let spelling = if row.key.is_empty() {
        row.literal
    } else {
        row.key
    };
    decode_escapes(spelling).unwrap_or_else(|e| panic!("row {:?} ({}): {e}", row.literal, row.file))
}

/// The census pin: per-mechanism production row counts, plus the excluded and
/// test-only section sizes. This is the ONLY place counts live (the TSV headers
/// and prose docs defer here), and it is what makes a silently vanished row
/// loud — the CI gate iterates the rows that exist, so it cannot miss one.
#[test]
fn registry_census_matches_pins() {
    let rows = parsed_registry();

    let mut live: HashMap<&str, usize> = HashMap::new();
    let mut frozen: HashMap<&str, usize> = HashMap::new();
    let mut excluded = 0usize;
    let mut test_only = 0usize;
    for row in &rows {
        match row.status {
            "shekyl-live" => *live.entry(row.mech).or_default() += 1,
            "frozen-inherited" => *frozen.entry(row.mech).or_default() += 1,
            "excluded" => excluded += 1,
            "test-only" => test_only += 1,
            other => unreachable!("parse_rows validated status, got {other:?}"),
        }
    }

    for (mech, want_live, want_frozen) in PRODUCTION_PINS {
        assert_eq!(
            live.get(mech).copied().unwrap_or(0),
            want_live,
            "mechanism {mech}: shekyl-live row count drifted from the pin — \
             if the registry change is deliberate, update PRODUCTION_PINS and \
             the dated CBOM census (docs/CRYPTOGRAPHIC_INVENTORY.md §3)"
        );
        assert_eq!(
            frozen.get(mech).copied().unwrap_or(0),
            want_frozen,
            "mechanism {mech}: frozen-inherited row count drifted from the pin — \
             frozen DSTs are closed except by a genesis-parameter change \
             (docs/FROZEN_DOMAIN_SEPARATORS.md)"
        );
    }
    assert_eq!(
        excluded, EXCLUDED_EXPECTED,
        "excluded (mech x) row count drifted from the pin"
    );
    assert_eq!(
        test_only, TEST_ONLY_EXPECTED,
        "test-only row count drifted from the pin — register new test domains \
         (or update the pin when one is deleted)"
    );
}

#[test]
fn intra_mechanism_domains_are_distinct() {
    let rows = parsed_registry();

    // Group PRODUCTION identities by mechanism; excluded rows are not domains
    // and test-only rows are policed by the segregation test instead
    // (test-vs-test collisions are legitimate).
    let mut by_mech: HashMap<&str, Vec<(Vec<u8>, &str)>> = HashMap::new();
    for row in &rows {
        if !row.is_production() {
            continue;
        }
        by_mech
            .entry(row.mech)
            .or_default()
            .push((identity(row), row.file));
    }

    // Every one of the five mechanisms + the SHA3-256 micro-bucket must be present,
    // so a mechanism silently vanishing from the registry fails loudly.
    for expected in ["1", "2", "3", "4", "5", "6"] {
        assert!(
            by_mech.contains_key(expected),
            "mechanism {expected} missing from the registry entirely"
        );
    }

    let mut collisions = Vec::new();
    for (mech, entries) in &by_mech {
        let mut seen: HashMap<&[u8], &str> = HashMap::new();
        for (id, file) in entries {
            if let Some(prev_file) = seen.insert(id, file) {
                collisions.push(format!(
                    "mechanism {mech}: identity {:?} appears twice \
                     ({prev_file} and {file}) — a same-mechanism domain collision \
                     (compared as decoded BYTES, so differing escape spellings \
                     of the same bytes still collide)",
                    String::from_utf8_lossy(id)
                ));
            }
        }
    }

    assert!(
        collisions.is_empty(),
        "intra-mechanism domain collisions:\n{}",
        collisions.join("\n")
    );
}

/// Test-domain segregation (SA-3b scope item): a domain minted by test/bench
/// code must never equal a production identity in the same mechanism —
/// otherwise a test-minted signature or KAT vector verifies against the
/// production context (cross-context replay of test artifacts).
#[test]
fn test_domains_are_segregated_from_production() {
    let rows = parsed_registry();

    let production: HashSet<(&str, Vec<u8>)> = rows
        .iter()
        .filter(|r| r.is_production())
        .map(|r| (r.mech, identity(r)))
        .collect();

    let mut violations = Vec::new();
    for row in rows.iter().filter(|r| r.status == "test-only") {
        if production.contains(&(row.mech, identity(row))) {
            violations.push(format!(
                "mechanism {}: test-only domain {:?} ({}) equals a production \
                 identity (compared as decoded bytes) — test artifacts would \
                 verify in the production context",
                row.mech,
                String::from_utf8_lossy(&identity(row)),
                row.file
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "test-domain segregation violations:\n{}",
        violations.join("\n")
    );
}

/// Guards the mechanism-2 model itself: the three shared info labels MUST still
/// appear as two rows each (const site + inline SeedDerivation), distinct only by
/// salt. If a future edit collapses one, this fails — surfacing that the
/// salt-keyed distinctness model no longer matches the code, rather than letting
/// the main test pass on a silently-changed shape.
#[test]
fn shared_info_labels_stay_salt_separated() {
    let rows = parsed_registry();
    for shared in [
        "shekyl-ed25519-spend",
        "shekyl-ed25519-view",
        "shekyl-ml-kem-768",
    ] {
        let occurrences: Vec<&Row> = rows
            .iter()
            .filter(|r| r.mech == "2" && r.literal == shared)
            .collect();
        assert_eq!(
            occurrences.len(),
            2,
            "mech-2 info {shared:?}: expected exactly 2 salt-separated occurrences, found {}",
            occurrences.len()
        );
        // Their distinctness identities must differ (the salt qualifier is what
        // separates them).
        assert_ne!(
            identity(occurrences[0]),
            identity(occurrences[1]),
            "mech-2 info {shared:?}: the two occurrences share a distinctness key — \
             salt separation was lost"
        );
    }
}
