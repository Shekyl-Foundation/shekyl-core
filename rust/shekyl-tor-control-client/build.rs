// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Compile the Tor disposition for the build target out of the pin file at
//! `config/tor_pins.json` (`TOR_BUNDLE_DISTRIBUTION.md` TB-4, TB-9).
//!
//! The pin file is the one record of what Shekyl ships: this script and the
//! packaging tool (`scripts/release/tor_bundle.py`) both read it, and neither
//! holds a copy. What is emitted is a single `TorDisposition` expression that
//! `src/binary.rs` `include!`s, so the pin stays compiled in and nothing reads
//! the file at runtime.
//!
//! **A build target with no row does not compile.** That is the point of the
//! panic below: "nobody has decided yet" is not a state a shipped binary can
//! be in. A new target is added by giving it a row — `pinned` with digests
//! from a signature-verified bundle, or `unavailable` with the reason.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

fn str_field<'a>(row: &'a Value, key: &str, context: &str) -> &'a str {
    row.get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{context}: missing or non-string field {key:?}"))
}

/// A 64-character lowercase hex digest, as a Rust byte-array literal.
fn digest_literal(hex: &str, context: &str) -> String {
    assert!(
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "{context}: a SHA-256 digest is 64 lowercase hex characters, got {hex:?}"
    );
    let mut out = String::from("[");
    for i in (0..64).step_by(2) {
        write!(out, "0x{}, ", &hex[i..i + 2]).expect("write to String");
    }
    out.push(']');
    out
}

/// A file name the gate will look for in tor's directory: one path component,
/// nothing that could name a different directory.
fn checked_file_name<'a>(name: &'a str, context: &str) -> &'a str {
    assert!(
        !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\', '\0']),
        "{context}: {name:?} is not a plain file name"
    );
    name
}

/// A version or target label. These compose the system directory
/// `/opt/shekyl/<bundle_version>-<bundle_target>/`, which the launcher then
/// names to the dynamic loader, so they are a closed alphabet: nothing that
/// could name another directory or split a loader path.
fn checked_label<'a>(row: &'a Value, key: &str, context: &str) -> &'a str {
    let label = str_field(row, key, context);
    assert!(
        !label.is_empty()
            && label != "."
            && label != ".."
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
        "{context}: {key} is letters, digits, '.', '_' and '-', got {label:?}"
    );
    label
}

fn pinned_expr(row: &Value, os: &str, context: &str) -> String {
    let executable = checked_file_name(str_field(row, "executable", context), context);
    // The tarball digest is the packaging side's gate, not the runtime's, but a
    // row that lacks one cannot be packaged, so it is refused here too.
    let _ = digest_literal(str_field(row, "tarball_sha256", context), context);

    let files = row
        .get("files")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{context}: a pinned target lists its files"));
    assert!(
        !files.is_empty(),
        "{context}: a pinned target lists its files"
    );

    // The same comparison the runtime gate uses (`TorPin::names_match`).
    // Windows folds case; every other platform keeps the bytes, so a Linux
    // row whose executable differs from its file only by case does not
    // compile — discovery would look for a name the directory does not have.
    let fold_case = os == "windows";
    let mut names: Vec<String> = Vec::new();
    let mut files_expr = String::new();
    for file in files {
        let name = checked_file_name(str_field(file, "name", context), context);
        let digest = digest_literal(str_field(file, "sha256", context), context);
        let identity = if fold_case {
            name.to_ascii_lowercase()
        } else {
            name.to_string()
        };
        assert!(
            !names.contains(&identity),
            "{context}: file {name:?} is listed twice"
        );
        names.push(identity);
        write!(
            files_expr,
            "PinnedFile {{ name: {name:?}, sha256: {digest} }}, "
        )
        .expect("write to String");
    }
    let executable_identity = if fold_case {
        executable.to_ascii_lowercase()
    } else {
        executable.to_string()
    };
    assert!(
        names.contains(&executable_identity),
        "{context}: the executable {executable:?} is not among the pinned files"
    );

    format!(
        "TorDisposition::Pinned(TorPin {{ bundle_version: {:?}, bundle_target: {:?}, \
         tor_version: {:?}, executable: {:?}, case_insensitive_names: {}, files: &[{}] }})",
        checked_label(row, "bundle_version", context),
        checked_label(row, "bundle_target", context),
        checked_label(row, "tor_version", context),
        executable,
        os == "windows",
        files_expr,
    )
}

fn main() {
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("missing CARGO_MANIFEST_DIR"));
    // This crate lives at rust/shekyl-tor-control-client; the pin file is two
    // levels up at config/.
    let pins_path = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("workspace root path expected")
        .join("config")
        .join("tor_pins.json");
    println!("cargo:rerun-if-changed={}", pins_path.display());

    let raw = fs::read_to_string(&pins_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", pins_path.display()));
    let doc: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", pins_path.display()));

    let os = env::var("CARGO_CFG_TARGET_OS").expect("missing CARGO_CFG_TARGET_OS");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("missing CARGO_CFG_TARGET_ARCH");

    let targets = doc
        .get("targets")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{}: no \"targets\" array", pins_path.display()));
    let mut rows = targets.iter().filter(|row| {
        row.get("os").and_then(Value::as_str) == Some(os.as_str())
            && row.get("arch").and_then(Value::as_str) == Some(arch.as_str())
    });
    let row = rows.next().unwrap_or_else(|| {
        panic!(
            "{} has no row for {os}/{arch}. Every build target has a Tor disposition: add a \
             \"pinned\" row (digests from a signature-verified Expert Bundle) or an \
             \"unavailable\" row with its reason.",
            pins_path.display()
        )
    });
    assert!(
        rows.next().is_none(),
        "{} has more than one row for {os}/{arch}",
        pins_path.display()
    );

    let context = format!("{} [{os}/{arch}]", pins_path.display());
    let disposition = match str_field(row, "disposition", &context) {
        "pinned" => {
            assert!(
                row.get("pending").is_none(),
                "{context}: a pinned row is not pending"
            );
            pinned_expr(row, &os, &context)
        }
        "unavailable" => {
            let reason = str_field(row, "reason", &context);
            assert!(!reason.trim().is_empty(), "{context}: an empty reason");
            // A row may carry `pending`: the identifier of the work that will
            // pin it. It compiles exactly as a ruled-unavailable row does,
            // because that is what this binary does about Tor today. The
            // difference is for `scripts/ci/check_tor_pin_targets.py`, which
            // counts pending rows so the startup refusal cannot land over one.
            if let Some(pending) = row.get("pending") {
                let ok = pending
                    .as_str()
                    .and_then(|p| p.rsplit_once('-'))
                    .is_some_and(|(family, number)| {
                        !family.is_empty()
                            && family.bytes().all(|b| b.is_ascii_uppercase())
                            && !number.is_empty()
                            && number.bytes().all(|b| b.is_ascii_digit())
                    });
                assert!(
                    ok,
                    "{context}: \"pending\" names a work item such as TB-11, got {pending}"
                );
            }
            format!("TorDisposition::Unavailable {{ reason: {reason:?} }}")
        }
        other => panic!("{context}: disposition is \"pinned\" or \"unavailable\", got {other:?}"),
    };
    let signing_key = str_field(&doc, "signing_key_fingerprint", &context);
    assert!(
        signing_key.len() == 40 && signing_key.bytes().all(|b| b.is_ascii_hexdigit()),
        "{context}: signing_key_fingerprint is a 40-character OpenPGP fingerprint"
    );

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("missing OUT_DIR"));
    fs::write(out_dir.join("tor_disposition.rs"), disposition)
        .expect("write the generated disposition");
    fs::write(
        out_dir.join("tor_signing_key_fpr.rs"),
        format!("{signing_key:?}"),
    )
    .expect("write the generated fingerprint");
}
