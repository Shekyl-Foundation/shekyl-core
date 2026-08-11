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
//! literal. Mechanism 2 (HKDF) is keyed by `salt|info`, because a derivation's
//! separation comes from the (salt, info) pair, not the info alone: the three
//! shared info labels (`shekyl-ed25519-spend/-view/-ml-kem-768`) appear as both a
//! const (composed `salt_for` salt) and an inline `SeedDerivation` (fixed
//! `shekyl-master-derive-v1` salt) — legitimately distinct derivations that a
//! bare-info test would wrongly report as a collision, and which SA-3b is NOT
//! permitted to "fix" (it mutates zero domain values).
//!
//! This test is the collision-catcher; the CI gate
//! (`scripts/ci/domain_registry_gate.sh`) is the drift-closer for *registered*
//! rows (row-presence + const binding + entry-point count-pins on mech 1/3).
//! Together they keep the registry honest against the code without publishing
//! any security constant. Completeness for mech 2/4/5/6 (new unregistered
//! domains) is a review duty — see the gate header and CBOM §3.

use std::collections::HashMap;

const REGISTRY: &str = include_str!("../../../docs/design/CRYPTO_DOMAIN_REGISTRY.tsv");

/// Well-formed mechanism ids: `1`..`6` (live mechanisms) or `x` (excluded).
fn is_valid_mech(mech: &str) -> bool {
    matches!(mech, "1" | "2" | "3" | "4" | "5" | "6" | "x")
}

struct Row<'a> {
    mech: &'a str,
    literal: &'a str,
    file: &'a str,
    key: &'a str,
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
        let key = f.get(5).copied().unwrap_or("").trim();
        rows.push(Row {
            mech,
            literal,
            file,
            key,
        });
    }
    Ok(rows)
}

/// The identity a row occupies within its mechanism's separation space.
fn identity<'a>(row: &Row<'a>) -> &'a str {
    if row.key.is_empty() {
        row.literal
    } else {
        row.key
    }
}

#[test]
fn registry_rows_are_well_formed() {
    let rows = parse_rows(REGISTRY).expect("registry must parse with valid mech ids and columns");
    assert!(
        rows.len() >= 90,
        "registry parsed only {} rows — expected the full ~100-row census; \
         parsing or the file is broken",
        rows.len()
    );
}

#[test]
fn intra_mechanism_domains_are_distinct() {
    let rows = parse_rows(REGISTRY).expect("registry must parse");

    // Non-vacuous guard: the registry parsed to a real census, not an empty file
    // or a mis-split that silently matched nothing, so the test cannot pass vacuously.
    assert!(
        rows.len() >= 90,
        "registry parsed only {} rows — expected the full ~100-row census; \
         parsing or the file is broken",
        rows.len()
    );

    // Group identities by mechanism; mechanism "x" (excluded, not a domain) is
    // out of scope for distinctness.
    let mut by_mech: HashMap<&str, Vec<(&str, &str)>> = HashMap::new();
    for row in &rows {
        if row.mech == "x" {
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
        let mut seen: HashMap<&str, &str> = HashMap::new();
        for (id, file) in entries {
            if let Some(prev_file) = seen.insert(id, file) {
                collisions.push(format!(
                    "mechanism {mech}: identity {id:?} appears twice \
                     ({prev_file} and {file}) — a same-mechanism domain collision"
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

/// Guards the mechanism-2 model itself: the three shared info labels MUST still
/// appear as two rows each (const site + inline SeedDerivation), distinct only by
/// salt. If a future edit collapses one, this fails — surfacing that the
/// salt-keyed distinctness model no longer matches the code, rather than letting
/// the main test pass on a silently-changed shape.
#[test]
fn shared_info_labels_stay_salt_separated() {
    let rows = parse_rows(REGISTRY).expect("registry must parse");
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
