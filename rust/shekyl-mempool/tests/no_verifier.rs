// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The probe: no proof or signature is verified in this crate (`E5-Q2`'s
//! condition; DRS-E5 PR-b). Two ways it could be, both closed here:
//!
//! - **By dependency.** A crate can call only what it depends on. This
//!   crate's normal dependencies are exactly the validator, the store and
//!   the three vocabulary crates — no verifier (`shekyl-bulletproofs`, the
//!   FCMP++ crates, `shekyl-crypto-pq`) — so every verification it causes
//!   is one the validator performs. A new edge fails here first.
//! - **Through the validator's side doors.** The validator exports things
//!   that verify besides the door's three calls — the H19 batch over a
//!   candidate (`ListedProofs`), the bundle verifier — so this crate's
//!   code is held to never naming one: every call it makes into the
//!   validator is one of the door's (`judge_slot_stateless`, `tx_against`,
//!   `policy_form`) or a read.

use std::collections::BTreeSet;

const MANIFEST: &str = include_str!("../Cargo.toml");

/// The keys of `[dependencies]`, in order.
fn normal_dependencies() -> BTreeSet<&'static str> {
    let mut deps = BTreeSet::new();
    let mut inside = false;
    for line in MANIFEST.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            inside = line == "[dependencies]";
            continue;
        }
        if inside && !line.is_empty() && !line.starts_with('#') {
            if let Some((key, _)) = line.split_once('=') {
                deps.insert(key.trim());
            }
        }
    }
    deps
}

#[test]
fn the_crate_depends_on_no_verifier() {
    let expected: BTreeSet<&str> = [
        "shekyl-chain-rules",
        "shekyl-chain-store",
        "shekyl-types",
        "shekyl-units",
        "shekyl-wire",
    ]
    .into_iter()
    .collect();
    assert_eq!(normal_dependencies(), expected);
}

/// Whether `code` names the identifier `word` — not as part of a longer one
/// (`policy_form` does not name `form`).
fn names(code: &str, word: &str) -> bool {
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    code.match_indices(word).any(|(at, _)| {
        let before = code[..at].chars().next_back();
        let after = code[at + word.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

/// Every production source file's code (comments stripped) names none of
/// the validator's verifying exports. The directory is read, not listed
/// here, so a module added later is held too; test files (`*_tests.rs`) are
/// not production and may build fixtures however they need.
#[test]
fn the_crate_calls_no_verifying_export_of_the_validator() {
    const FORBIDDEN: [&str; 7] = [
        "ListedProofs",
        "batch_outcome",
        "verify_bundle",
        "check_section",
        "verify_batch",
        "verify_transaction_pqc_auth",
        "form",
    ];
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut scanned = Vec::new();
    for entry in std::fs::read_dir(&src).expect("the crate's src/") {
        let path = entry.expect("an entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_owned();
        if !name.ends_with(".rs") || name.ends_with("_tests.rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("a source file");
        for (n, line) in source.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            for word in FORBIDDEN {
                assert!(
                    !names(code, word),
                    "{name}:{}: names `{word}` — a verification outside the door",
                    n + 1
                );
            }
        }
        scanned.push(name);
    }
    // The subject exists (rule 47): the door is among the files read.
    assert!(
        scanned.iter().any(|n| n == "door.rs"),
        "scanned {scanned:?}"
    );
    let door = std::fs::read_to_string(src.join("door.rs")).expect("door.rs");
    // The door's three calls are what it does name.
    for call in ["judge_slot_stateless(", "tx_against(", "policy_form("] {
        assert!(door.contains(call), "the door calls {call}");
    }
}
