// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Emit `CONSENSUS_CONSTANTS_DIGEST` — the digest of the canonical form of
//! the integer constant authorities under `config/`
//! (`consensus_constants.json` and `economics_params.json`) — for
//! `src/consensus_digest.rs` (`docs/design/CLIENT_VERSION_CONSTANTS_VALIDATION.md`
//! §3.3, §3.4, §3.12; `VC-1`).
//!
//! Computed **once, here**, because every RPC party (`shekyl-daemon-rpc`,
//! `shekyl-engine-core`, `shekyl-rpc-client`) already depends on this crate
//! and the digest is a wire-contract fact that sits beside
//! `CORE_RPC_VERSION`. The consensus-constant and economics generators
//! elsewhere in the workspace read the same JSON for their own values and do
//! not compute this (`VC-D4`); neither does
//! `cmake/generate_consensus_constants.py`, because nothing in C++ consumes
//! it (`VC-D9`).
//!
//! The canonicalisation rules live in `build_support/consensus_canonical.rs`,
//! which this build script and the crate's tests both include — one
//! definition, two readers.

#[path = "build_support/consensus_canonical.rs"]
mod consensus_canonical;

use std::env;
use std::fs;
use std::path::PathBuf;

/// The reviewed digest of the canonical form of the files in
/// [`consensus_canonical::CANONICAL_FILES`]. A change to either file moves it
/// and fails this build with both values and the question to answer; see the
/// panic below.
///
/// **Re-pinned 2026-09-11 — key ADDED: `block_weight_short_term_surge_factor`
/// = 4 in `config/consensus_constants.json`.** The pin's question, answered
/// rather than silenced: *does a different value of this key make a different
/// chain?* **Yes, directly.** It is the ceiling the effective block-weight
/// median is clamped to, and the per-block weight limit is twice that median —
/// so a node holding `S = 50` accepts a block a node holding `S = 4` rejects as
/// over-weight. That is a split, not a preference, which is exactly why the key
/// belongs in this authority. The value implements the ratified `S = 4`
/// (`docs/completed/CONSENSUS_C2_R2_WEIGHT_FEES.md` Q3, signed 2026-09-06);
/// it replaces the hand-written `x50` that previously bypassed this authority
/// altogether — the key was ADDED here precisely so that it stops being a
/// constant this digest could not see.
const PINNED_DIGEST: &str = "1959257f4e5101a332e92a3d7f9cb8e7941860a9606edd2a9f9d11fee04189f8";

fn main() {
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("missing CARGO_MANIFEST_DIR"));
    // shekyl-rpc-types lives at rust/shekyl-rpc-types; the JSON authorities
    // are two levels up under config/.
    let repo_root = manifest_dir
        .parent()
        .expect("workspace/rust path expected")
        .parent()
        .expect("workspace root path expected")
        .to_path_buf();

    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir
            .join("build_support")
            .join("consensus_canonical.rs")
            .display()
    );
    println!("cargo:rerun-if-changed=build.rs");

    let mut contents = Vec::with_capacity(consensus_canonical::CANONICAL_FILES.len());
    for file in consensus_canonical::CANONICAL_FILES {
        let path = repo_root.join(file);
        println!("cargo:rerun-if-changed={}", path.display());
        let raw = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        contents.push(raw);
    }
    let pairs: Vec<(&str, &str)> = consensus_canonical::CANONICAL_FILES
        .iter()
        .copied()
        .zip(contents.iter().map(String::as_str))
        .collect();
    let canonical = consensus_canonical::canonical_form(&pairs).unwrap_or_else(|e| panic!("{e}"));
    let digest_bytes = consensus_canonical::digest_bytes(&canonical);
    let digest = consensus_canonical::hex_of(&digest_bytes);

    // The live-file pin (VC-D3, VC-D12). It lives here rather than as a
    // `const _: () = assert!(...)` beside the constant, because a const-eval
    // panic takes a literal message: it can say the digest moved but cannot
    // say what it moved *to*, and it makes the crate uncompilable, so the
    // test that would print the new value cannot run either. Observed in
    // review round 1 (VC-R5) — a developer who tripped it was told to re-pin
    // and given nothing to re-pin to. A build-script panic formats, so the
    // enforcement is the same and the re-pin is mechanical.
    if digest != PINNED_DIGEST {
        // The message branches on WHAT moved, because the single question
        // "does a different value make a different chain?" is answered "no"
        // by a pure rename — where no value moved at all — and the old
        // wording then steered the reader toward deleting a genesis-frozen
        // constant from its authority. Observed on this pin's first live
        // trip: `money_supply` -> `emission_curve_asymptote` (FL-R15),
        // value byte-identical. A message that only ever fires at a moment
        // of confusion has to be right in every case it fires
        // (`82-failure-mode-ux.mdc`).
        panic!(
            "the consensus-constant authorities changed: their canonical-form digest is now\n\
             \x20   {digest}\n\
             but this build pins\n\
             \x20   {PINNED_DIGEST}\n\
             \n\
             Re-pin `PINNED_DIGEST` in rust/shekyl-rpc-types/build.rs to the first value. Then\n\
             answer the question the pin exists to force, which depends on WHAT moved --\n\
             `git diff` {files:?} against the pinned tree and read off the case\n\
             (docs/design/CLIENT_VERSION_CONSTANTS_VALIDATION.md §3.7, §3.12):\n\
             \n\
             \x20 * A VALUE changed. Does the new value make a different chain? If yes, this is\n\
             \x20   a consensus change: re-pin, and expect every client built before it to\n\
             \x20   refuse every daemon built after it once VC-2..VC-4 land. If no, the\n\
             \x20   constant does not belong in these files -- move it out, do not silence\n\
             \x20   this.\n\
             \n\
             \x20 * Only a KEY changed -- a rename at an unchanged value. The digest moves BY\n\
             \x20   DESIGN (VC-D12): a key is part of the binding, because every generator\n\
             \x20   reads it by name. Re-pin and keep the constant. Do NOT conclude it does\n\
             \x20   not belong here; ask the chain question of the value the NEW name binds.\n\
             \x20   Post-genesis a rename in these files is a client-compatibility break and\n\
             \x20   rides a release boundary, not a cleanup PR (§3.12).\n\
             \n\
             \x20 * A key was ADDED or REMOVED. Same chain question, asked of that key: if a\n\
             \x20   different value of it would make a different chain it belongs here and you\n\
             \x20   re-pin; if not, it does not belong here.",
            files = consensus_canonical::CANONICAL_FILES
        );
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("missing OUT_DIR"));
    let out_file = out_dir.join("consensus_constants_digest.rs");

    // `{canonical:?}` renders the text as a valid Rust string literal.
    let output = format!(
        "// @generated by build.rs from config/consensus_constants.json and\n\
         // config/economics_params.json — do not edit.\n\
         //\n\
         // The canonical form (CLIENT_VERSION_CONSTANTS_VALIDATION.md §3.3, §3.12)\n\
         // and its SHA-256, computed once for every RPC party in the workspace.\n\
         pub const CONSENSUS_CONSTANTS_DIGEST: &str = \"{digest}\";\n\
         //\n\
         // The same 32 bytes, unrendered. VC-3/VC-4 compare `[u8; 32]`\n\
         // equality with no hex on the path; the string survives for the\n\
         // panic above and for operator output, which is the only place it\n\
         // is actually a string (VC-R16).\n\
         pub const CONSENSUS_CONSTANTS_DIGEST_BYTES: [u8; 32] = {digest_bytes:?};\n\
         pub const CONSENSUS_CONSTANTS_CANONICAL: &str = {canonical:?};\n"
    );

    fs::write(&out_file, output).expect("failed writing generated consensus constants digest");
}
