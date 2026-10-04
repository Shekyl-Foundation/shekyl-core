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
///
/// **Re-pinned 2026-09-13 — key ADDED: `archival_attestation_anchor_lag_blocks`
/// = 4 (PROVISIONAL) in `config/consensus_constants.json`.** The pin's
/// question: *does a different value of this key make a different chain?*
/// **Yes.** It is `L` in the SF-D8 pass-countersignature admission window
/// `[h − depth − L, h − depth]` (`ARCHIVAL_SHARD_FETCH.md` SF-D8): a node
/// holding `L = 4` admits a block carrying a pass anchored `h − depth − 4`
/// that a node holding `L = 3` rejects as `ANCHOR_OUT_OF_WINDOW`, and the
/// genesis threshold `depth + L` below which any pass record is refused moves
/// with it. A split, so the key belongs here; it is read by
/// `rust/shekyl-archival-retention/build.rs` (the single Rust authority — C++
/// sizes the window through `shekyl_archival_pass_anchor_window`, holding no
/// copy). The same change also re-commented `archival_reorg_depth_blocks`
/// (value unchanged at 720): `_comment_*` keys are outside the canonical
/// form, so that edit alone would not have moved this digest.
///
/// **Re-pinned 2026-09-21 (E6 slice 4 precursor, `CHAIN_RULES_SLICE_4.md`
/// §3.1 S8): a key was ADDED — `block_weight_full_reward_zone_bytes = 300000`
/// in `consensus_constants.json`.** The chain question, answered: a different
/// zone pays a different reward for the same block (the effective median is
/// soft-raised to it before the weight penalty; the block-weight limit is
/// twice it — CEN-F14b, G6b), so the key belongs here. The value is the one
/// every node already ran — it was the hand-written C++
/// `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5`, with no Rust home and
/// supplied to `shekyl-economics` as an argument on every call; the move
/// gives it one authority and two generated readers (`EconomicParams::
/// full_reward_zone`; the C++ macro is now defined from the generated
/// header). No behaviour changes; the digest moves because the binding grew.
///
/// **Re-pinned 2026-09-25 (S-PRUNE review, PR #861 item 6): a key was ADDED —
/// `archival_shard_tx_count = 200` (PROVISIONAL, `PDM-Q6` item 5) in
/// `consensus_constants.json`.** The chain question, answered: `T` is the
/// archival shard partition — shard `k` is the storage ids `[k·T, (k+1)·T)`
/// — so a node holding `T = 200` and one holding `T = 100` name different
/// shards for the same transactions: their retention prunes discard
/// different bodies at the same epoch boundary, their `h_scarce` differs, and
/// every archival holding (`ShardSetCompact` shard ids), pass and challenge
/// that names a shard means a different set of transactions. A split, so
/// the key belongs here. The value is the one already shipped as the
/// literal `shekyl_types::SHARD_TX_COUNT = 200`; the move gives it the same
/// sourcing as the other Round-2 gate numerics (`settlement_epoch_blocks`,
/// `archival_reorg_depth_blocks`, and at the time `challenge_resolution_blocks`,
/// removed 2026-09-30 below) — one
/// authority, read by `rust/shekyl-types/build.rs`. No behaviour changes;
/// the digest moves because the binding grew.
///
/// **Re-pinned 2026-09-27 (E6 slice 7 commit 4, `CHAIN_RULES_SLICE_7.md` Q6):
/// two keys were ADDED — `block_weight_long_term_window_blocks = 100000` and
/// `block_weight_short_term_window_blocks = 100` in
/// `consensus_constants.json`.** The chain question, answered for each: a
/// different window is a different median, a different block-weight limit
/// and a different set of valid blocks (CEN-G6/G6b), so both belong here.
/// The values are the ones every node already ran — the hand-written C++
/// `CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE` and
/// `CRYPTONOTE_REWARD_BLOCKS_WINDOW`, with no Rust home until the Rust
/// validator built the medians; the move gives each one authority and two
/// generated readers (`shekyl_economics::params`, the C++ macros). No
/// behaviour changes; the digest moves because the binding grew.
///
/// **Re-pinned 2026-09-27 (`SCC-4`, the shard-count cutover census): a key was
/// ADDED — `archival_max_holdings_shards = 4096` in
/// `consensus_constants.json`.** The chain question, answered: the cap is what a
/// codec refuses a holdings set *at*, so a node at 4096 and a node at 2048 admit
/// different bond posts for the same bytes — a different chain. It belongs here.
/// The second test (`DRS_E3_CURVE_WRITER.md` §3.9), answered: it is a **resource
/// cap**, which this file's own rule names as passing — the `CEN-I4` input-count
/// case, not a proof-system structural parameter — so a network could
/// legitimately name it differently.
///
/// Why it moved at all: the value had **six independent definitions** and nothing
/// tied them — `shekyl_types::MAX_HOLDINGS_SHARDS`, an **unguarded** crate-private
/// literal in `shekyl-wire` that is what enforces the wire bound, and four C++
/// `kMaxHoldings` (one authority on `ArchivalBondValue` plus three
/// `static_assert`-guarded revert mirrors). The C++ four could not drift from each
/// other, but neither Rust pair nor either language was tied to the other, so a
/// re-pin would have moved one side silently: a holdings set the store accepts
/// and the wire refuses. The move gives it one authority and two generated
/// readers (`rust/shekyl-types/build.rs`; the C++ macro, from which all four
/// `kMaxHoldings` are now defined). **No behaviour changes** — the value is the
/// 4096 every definition already carried; the digest moves because the binding
/// grew.
///
/// **Re-pinned 2026-09-28 (merge of `dev` into #889):** the two re-pins above
/// landed on separate branches the same day — Q6's two window keys on slice 7,
/// `SCC-4`'s cap on `dev` — and each pinned a digest over a file without the
/// other's keys. This value digests the merged file, all three keys present;
/// no value moved on either side.
///
/// **Re-pinned 2026-09-29 (the `SHT-Q2` build, `ARCHIVAL_SHARD_T_DERIVATION.md`
/// §8.6): a key was REPLACED — `archival_shard_tx_count = 200` by
/// `archival_shard_length_bytes = 3000000`.** Not a rename: the name, the unit
/// and the value all changed, because the partition did. Shards are cut by
/// archival length now — shard `k` holds the transactions whose cumulative
/// archival length before them lies in `[k·W, (k+1)·W)` — and nothing reads a
/// transaction count any more. The chain question, answered of the new value:
/// a node at `W = 3,000,000` and one at `2,000,000` place the same transactions
/// in different shards, so their retention prunes discard different bodies at
/// the same boundary and every holding, pass and challenge that names a shard
/// means different bytes — a split, so the key belongs here. The second test:
/// `W` is a partition parameter a network could legitimately name differently
/// (it is PROVISIONAL and re-pinned before genesis by measurement), not a
/// proof-system structural parameter. One authority, read by
/// `rust/shekyl-types/build.rs` (`shekyl_types::SHARD_LENGTH`).
///
/// **Re-pinned 2026-09-30 (DRS-E4 commit 5, `DRS_E4_ARCHIVAL_WRITER.md` §6
/// row 5 ruling): a key was REMOVED — `challenge_resolution_blocks = 10000`.**
/// The slash grace after a settlement epoch's last block is one settlement
/// epoch: `shekyl_archival_retention::SLASH_GRACE_EPOCHS = 1`, a multiple of
/// `settlement_epoch_blocks` rather than a block count of its own. The
/// record always meant it that way (Gate 6: *"a full settlement epoch"*; the
/// free-rider round: *"a full epoch of settling after close"*), and holding
/// it as a second 10 000 made a levered schedule malformed — a 100-block
/// epoch with a 10 000-block grace is a hundred-epoch grace, not a
/// scaled-down regime. The chain question, answered: the deadline is still
/// consensus (a node slashing at a different height is a different chain),
/// and it is still sourced here — through `settlement_epoch_blocks`, which
/// stays; the multiple is a ratified structural constant with no value of
/// its own to source, so no key replaces the removed one. No generator read
/// the key (no `build.rs`, no CMake); the Rust constant was hand-pinned. **No
/// production behaviour changes** — `1 · 10 000 = 10 000`; the digest moves
/// because the binding shrank.
///
/// **Re-pinned 2026-10-01 (`ARCHIVAL_SHARD_COUNT_CUTOVER.md` §F step 3): a
/// VALUE changed — `shekyl_escalation_knee_n` `100000 → 2250000`.** The knee
/// was the J-segment-era literal carried across the SHT-Q2 operand re-key
/// unchanged; it is now the Stage-2 sweep's middle candidate, re-derived in
/// closed shards of archival bytes (`shekyl-economics-sim` `KNEE_BAND`), not
/// converted. **No production behaviour changes:** the escalation ships flat
/// (`asymptote_share == staker_pool_share`), so `staker_pool_share_at` is
/// bit-identical at every `n` whatever the knee; the number is provisional
/// until the GF-7 ceremony picks it with the asymptote.
///
/// **Re-pinned 2026-10-04: a KEY changed and the chain changed with it.**
/// `emission_speed_factor_per_minute: 22` became
/// `emission_speed_factor_per_block: 22`. The value is byte-identical, but
/// the curve read it through Monero's per-minute conversion as 21 per block;
/// it now reads 22, the design's (`DESIGN_CONCEPTS.md` §3). Every block
/// reward above genesis changes, so this is a different chain, not a pure
/// rename (`shekyl_economics::emission_speed_factor`).
const PINNED_DIGEST: &str = "4bad8c3eafe2a03224238d2140e3a5ef3d72ce73c75837d6726d37112f15f54f";

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
             \x20   re-pin; if not, it does not belong here. For an ADDED key ask the second\n\
             \x20   test too (DRS_E3_CURVE_WRITER.md §3.9): could a schedule, a network or an\n\
             \x20   operator legitimately name it differently? A proof-system structural\n\
             \x20   parameter cannot -- it is a const-asserted constant in its crate, not a key.",
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
