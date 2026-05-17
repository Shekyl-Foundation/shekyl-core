---
name: LWMA-1 difficulty adjustment migration
overview: "Replace Shekyl's inherited CryptoNote cut-windowed-average DAA (src/cryptonote_basic/difficulty.cpp, DIFFICULTY_WINDOW=720, DIFFICULTY_LAG=15-with-warning, DIFFICULTY_CUT=60) with LWMA-1 (zawy12 canonical, N=90 for T=120s) implemented as a Rust crate shekyl-difficulty per 20-rust-vs-cpp-policy.mdc rule 2. Genesis-time landing per 16-architectural-inheritance.mdc pre-genesis discount and 60-no-monero-legacy.mdc no-version-dispatch rule. Sibling track to RANDOMX_V2_PLAN.md but independent: LWMA-1 and RandomX v2 are math-orthogonal (DAA operates on (timestamps, cum_difficulties); PoW changes the hash function), no wallet V3.2 gate applies, no Monero release-time audit dependency. FTL (BLOCK_FUTURE_TIME_LIMIT = N*T/20 = 540s) and MTP (BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW = 11) are co-tuned per zawy12 canonical requirements. Phase 0 produces two design docs (DAA_LWMA1.md + this plan). Implementation cascades through Phase 1 (crate scaffold + spec-vector tests), Phase 2 (canonical-reference cross-check harness), Phase 3 (FFI wire-up in shekyl-ffi), Phase 4 (C++ cutover and inherited-DAA deletion). Each phase is a separate PR per 06-branching.mdc."
todos:
  - id: phase0-design
    content: "Phase 0: Write docs/design/DAA_LWMA1.md AND docs/design/DAA_LWMA1_PLAN.md. Cover: (a) inherited CryptoNote DAA disposition (delete-not-gate) per 60-no-monero-legacy.mdc and 16-architectural-inheritance.mdc; (b) Rust-implementation decision per 20-rust-vs-cpp-policy.mdc rule 2 (cryptographic contract); (c) Shekyl-specific parameter selection (N=90, T=120s, GENESIS_DIFFICULTY=100 proposed, FTL=N*T/20=540s, MTP=11); (d) canonical zawy12 LWMA-1 algorithm spec with overflow guards; (e) FFI surface (1 function, i32 error code, u128 out-param); (f) test-vector strategy (synthetic unit + canonical-reference cross-check + simulated-history corpus); (g) C++ deletion surface (difficulty.{h,cpp}, DIFFICULTY_* constants, tests/difficulty/, FTL/MTP migration); (h) sketch disposition (pre-design rust/shekyl-difficulty/src/lwma1.rs is NOT canonical and was deleted during Phase 0; divergence catalogue retained in DAA_LWMA1.md §2.4 as the design record of why each shape is rejected); (i) alternatives considered (LWMA-2/3/4, ASERT, retuned-cut-windowed, SMA) with reversion clauses per 21-reversion-clause-discipline.mdc; (j) reviewer-discipline framing (no external algorithm-review gate; zawy12 canonical is audit-of-record). Pass 4-6 review rounds before any code lands."
    status: pending
  - id: phase1-crate-scaffold
    content: "Phase 1: Add rust/shekyl-difficulty crate to rust/Cargo.toml workspace members as a leaf crate (zero internal workspace deps per DAA_LWMA1.md §2.1). Create rust/shekyl-difficulty/Cargo.toml (Shekyl Foundation copyright; BSD-3-Clause; no_std-compatible if practical, #![deny(unsafe_code)] crate-level). Extend config/consensus_constants.json with daa_lwma1_{window_n=90, target_seconds=120, ftl_seconds=540, mtp_window=11, genesis_difficulty=100} per the JSON-authority pattern in DAA_LWMA1.md §4 and FOLLOWUPS.md. Extend cmake/generate_consensus_constants.py to emit the matching C++ symbols. Add rust/shekyl-difficulty/build.rs reading the JSON and emitting consensus_constants_generated.rs to OUT_DIR (preferred; or extend rust/shekyl-engine-core/build.rs as Option B). Create src/lib.rs re-exporting lwma1::lwma1_next, is_timestamp_below_ftl, is_above_mtp; src/consts.rs include!'ing the generated file and re-exporting N/T_SECONDS/FTL_SECONDS/MTP_WINDOW/GENESIS_DIFFICULTY plus the canonical-fixed BIAS_NUMERATOR=99/BIAS_DENOMINATOR=200/SOLVETIME_CLAMP_FACTOR=6/MIN_L_FLOOR=1/20 (NOT JSON-keyed per DAA_LWMA1.md §4); src/lwma1.rs (canonical implementation per DAA_LWMA1.md §5.3). Write unit tests against the §8.1 synthetic test corpus including the §5.3 step 8 overflow-boundary paired vectors. PR cannot merge if cargo test, cargo clippy --all-targets -- -D warnings, or cargo fmt --check fails per 45-rust-lint-checks.mdc."
    status: pending
  - id: phase2-cross-check-harness
    content: "Phase 2: Add tests/difficulty/lwma1_cross_check.cpp harness that builds the zawy12 LWMA1_() C++ reference (committed at docs/design/refs/zawy12_issue_3_lwma1.md per DAA_LWMA1.md §3) and asserts byte-equality between Rust output and C++ reference output across the §8.1 input corpus. CI runs the harness; failure fails CI. Also: commit docs/design/refs/zawy12_issue_3_lwma1.md as the pinned spec revision (hash-anchored against future GitHub edits)."
    status: pending
  - id: phase3-ffi-wire-up
    content: "Phase 3: Export shekyl_difficulty_lwma1_next from rust/shekyl-ffi/src/lib.rs per DAA_LWMA1.md §6.1 (i32 return; out_next_difficulty *mut u128; ERR_NULL_PTR / ERR_INVALID_COUNT / ERR_OVERFLOW / ERR_INTERNAL taxonomy). Add the declaration to src/shekyl/shekyl_ffi.h. Generate or hand-maintain the bindings per 25-rust-architecture.mdc. PR delivers the FFI surface; the daemon does NOT yet consume it (still on inherited next_difficulty)."
    status: pending
  - id: phase4-cpp-cutover
    content: "Phase 4: Rewire Blockchain::get_difficulty_for_next_block() (blockchain.cpp:~965), Blockchain::check_difficulty_checkpoints() (~1021), and Blockchain::get_next_difficulty_for_alternative_chain() (~1325) to call shekyl_difficulty_lwma1_next. DELETE src/cryptonote_basic/difficulty.{h,cpp}. Delete DIFFICULTY_TARGET_V1, DIFFICULTY_WINDOW, DIFFICULTY_LAG (the // !!! constant), DIFFICULTY_CUT, DIFFICULTY_BLOCKS_COUNT, DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN from src/cryptonote_config.h. DELETE DIFFICULTY_TARGET_V2 outright (do NOT rename); rewire consumers to SHEKYL_DAA_LWMA1_TARGET_SECONDS from the generated shekyl/consensus_constants_generated.h (extended in Phase 1). DELETE BLOCK_FUTURE_TIME_LIMIT and BLOCK_FUTURE_TIME_LIMIT_V2; rewire consumers to SHEKYL_DAA_LWMA1_FTL_SECONDS. DELETE BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW; rewire consumers to SHEKYL_DAA_LWMA1_MTP_WINDOW. Delete tests/difficulty/{difficulty.cpp, gen_wide_data.py, generate-data}. Add symbol-isolation CI invariant: nm shekyld must not contain T|U next_difficulty_64|next_difficulty|check_difficulty_checkpoints (per DAA_LWMA1.md §7.1). Add no-orphaned-magic-numbers CI invariant: git grep on the post-Phase-4 tree returns zero hits for BLOCK_FUTURE_TIME_LIMIT, BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW, DIFFICULTY_TARGET_V[12]. Update unit tests and docs."
    status: pending
  - id: phase5-docs
    content: "Phase 5: Update docs/USER_GUIDE.md, docs/SHEKYLD_PREREQUISITES.md, docs/DESIGN_CONCEPTS.md (or equivalents), docs/CHANGELOG.md per 91-documentation-after-plans.mdc. Close any DAA_LWMA1 follow-ups this plan introduces. Cross-reference the rule promotion 24-reviewer-discipline.mdc if it has landed by then."
    status: pending
isProject: false
---


# LWMA-1 difficulty adjustment migration

## Sequencing rationale

LWMA-1 is **independent** of the RandomX v2 PoW migration described
in [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md). The two are math-
orthogonal — RandomX v2 changes the PoW hash function; LWMA-1 changes
the difficulty-adjustment algorithm that operates on `(timestamp,
cumulative_difficulty)` tuples. Neither constrains the other. There is
no shared submodule, shared CMake toggle, shared external dependency,
or shared release-time gate.

LWMA-1 lands first because:

1. **No external-audit dependency.** The zawy12 canonical reference is
   a community-vetted, ~8-year-deployed specification; no Monero-funded
   audit equivalent applies. Phase 0 design + author-side review +
   the spec-vector + cross-check tests are the audit-of-record.
2. **Smaller scope.** One Rust crate (~300 lines), one FFI export,
   three C++ call-site rewires, one C++ file deletion. Versus
   RandomX v2's six rewired C++ files, submodule add, `cncrypto`
   PUBLIC-link drop, and full Phase 4 abstraction-removal sweep.
3. **De-risks the cutover pattern.** LWMA-1 exercises the same
   C++→Rust consensus-replacement pattern that the larger RandomX v2
   cutover relies on. Landing the smaller cutover first surfaces any
   FFI plumbing, build-system, or test-infrastructure issues at lower
   blast radius.
4. **No wallet V3.2 gate.** The wallet doesn't compute difficulty;
   the daemon does. LWMA-1 doesn't touch the wallet at all.

```mermaid
flowchart LR
  P0[Phase 0: Two design docs<br/>DAA_LWMA1.md<br/>DAA_LWMA1_PLAN.md] --> R0{Phase 0 review<br/>4-6 rounds<br/>landed on dev?}
  R0 -- no --> P0
  R0 -- yes --> P1
  P1[Phase 1: shekyl-difficulty crate<br/>scaffold + spec-vector tests] --> P2
  P2[Phase 2: Canonical-reference<br/>cross-check harness<br/>+ pinned spec revision commit] --> R1{spec-vector AND<br/>cross-check<br/>both pass?}
  R1 -- no --> P1
  R1 -- yes --> P3
  P3[Phase 3: shekyl_difficulty_lwma1_next<br/>FFI surface + header] --> P4
  P4[Phase 4: C++ cutover<br/>delete difficulty.{h,cpp}<br/>delete DIFFICULTY_* and BLOCK_FUTURE_TIME_LIMIT*<br/>consume LWMA-1 constants from generated header<br/>rewire 3 blockchain.cpp call sites] --> P5
  P5[Phase 5: Docs + CHANGELOG]
```

The two decision diamonds mirror the `RANDOMX_V2_PLAN.md` shape:
`R0` enforces the Phase 0 review-rounds gate before any code lands;
`R1` enforces the spec-correctness gate before the FFI surface and
the C++ cutover go in. A failure at `R1` loops back to Phase 1
(the implementation is wrong) rather than Phase 2 (the harness
itself is unlikely to be the source of divergence — the spec is the
source of truth per §2.3 of the design doc, and the harness is its
verbatim transcription).

There is no parallelism within the LWMA-1 track — each phase
sequentially depends on the previous. The whole sequence is small
enough that this is the simplest shape; multi-track plumbing would
add structural overhead for no gain.

## Permanent architectural decisions

These decisions are made now and locked. Any future proposal to
reverse them must start with a new design doc that addresses the
rationale in
[`DAA_LWMA1.md`](./DAA_LWMA1.md) §2 and §10.

### 1. LWMA-1 from genesis, no version dispatch

Per `60-no-monero-legacy.mdc`, genesis ships with LWMA-1 and nothing
else. No `HF_VERSION_LWMA1` gate, no fallback to inherited DAA, no
"v1 difficulty" path. Inherited code that handles pre-genesis DAA is
deleted, not gated.

### 2. Rust implementation in a separable `shekyl-difficulty` crate

Per `20-rust-vs-cpp-policy.mdc` rule 2 (Rust if any of: defines a
cryptographic contract that other code consumes). DAA is a
cryptographic-contract surface. The crate is a sibling of
`shekyl-pow-randomx`, not a child; DAA and PoW are independent
consensus surfaces and the crate-level separation reflects that.

### 3. Single function FFI surface

Per `RANDOMX_V2_RUST.md` §5's "one function FFI" precedent. The DAA
is structurally a single function; exposing constants or
intermediate computation steps adds attack surface without value.

### 4. FTL and MTP migrate with N

Per `DAA_LWMA1.md` §2.5, the canonical LWMA-1 specification couples
window size N to FTL and MTP. Phase 4 migrates all three together.
Splitting them across PRs leaves the chain in a non-canonical
intermediate state where LWMA-1's solvetime-clamp defense is
materially weakened by the wrong FTL.

### 5. Sketch is not the implementation

Per `DAA_LWMA1.md` §2.4, the pre-design Rust sketch that existed at
`rust/shekyl-difficulty/src/lwma1.rs` was **deleted** during Phase 0
in this PR's commit `91c6dc44c` per `15-deletion-and-debt.mdc`'s
default-delete rule. The divergence catalogue is preserved in
`DAA_LWMA1.md` §2.4 as the design record of why each non-canonical
shape is rejected, not as a description of any committed source.
Phase 1 starts from an empty crate directory and writes the
implementation fresh against the design doc.

## Phase 0 (this PR)

Two design documents:

### `docs/design/DAA_LWMA1.md`

1. **Why LWMA-1.** Inherited CryptoNote DAA disposition; three
   commitments from `00-mission.mdc`; alternatives considered (LWMA-
   2/3/4, ASERT, retuned cut-windowed, SMA) with reversion clauses
   per `21-reversion-clause-discipline.mdc`.
2. **Permanent decisions.** Rust crate, single algorithm path, spec
   source of truth, sketch-is-not-implementation, FTL/MTP co-tuning,
   single ratified GENESIS_DIFFICULTY constant.
3. **Spec source pin.** zawy12 Issue #3 with content hash pinned at
   `docs/design/refs/zawy12_issue_3_lwma1.md` (committed in Phase 2).
4. **Parameter selection table.** N=90, T=120, GENESIS_DIFFICULTY=100
   (proposed), FTL=540, MTP=11, bias 99/200.
5. **Algorithm specification.** Textual spec covering genesis short-
   circuit, out-of-sequence timestamp normalization, solvetime clamp,
   linear-weighted sum, minimum-L floor, average difficulty, formula
   with bias, overflow guard.
6. **FFI surface.** One function (`shekyl_difficulty_lwma1_next`)
   returning `i32` error code; `out_next_difficulty: *mut u128`.
7. **Isolation invariants.** Symbol-isolation against deleted-DAA
   symbols + no-C-ABI invariant matching RandomX v2 §7.2.
8. **Test-vector strategy.** Three tiers: synthetic unit, canonical-
   reference cross-check, simulated-history corpus.
9. **C++ deletion surface.** Explicit file and constant list.
10. **Reversion clause.** Named conditions for LWMA-2/3/4 or ASERT
    reopening.
11. **Wallet, RPC, node touchpoints.** None to wallet; rewire RPC
    indirectly via blockchain interface.
12. **Reviewer discipline.** Solo-architect review in the shape
    `24-reviewer-discipline.mdc` will land with — the rule does not
    yet exist at `.cursor/rules/`; its promotion is a V3.1 follow-up
    tracked by PR #45 (per `RANDOMX_V2_RUST.md` §17). No external
    algorithm-review gate. See `DAA_LWMA1.md` §12.
13. **Explicit non-goals.** No compatibility, no env-var overrides,
    no jump rules, no per-block output clamps.
14. **License and attribution.** BSD-3 Shekyl Foundation for Rust;
    canonical zawy12 MIT acknowledged in spec source pin.
15. **MSRV, Guix.** No new dependencies; clean reproducible-build
    delta.

### `docs/design/DAA_LWMA1_PLAN.md` (this file)

The phased plan with todos, sequencing rationale, and per-phase
gates.

**Phase 0 completion criterion:** both docs reviewed (4–6 rounds per
the same calibration as `RANDOMX_V2_PLAN.md`) and merged. Phase 1
cannot start until Phase 0 has merged.

## Phase 1 — `shekyl-difficulty` crate scaffold

Single PR adding the crate. Bounded scope; should be straightforward.
Six work items: workspace registration, crate manifest, crate
library, typed-constants module, algorithm module, synthetic unit
tests.

**Workspace registration.** Add `shekyl-difficulty` to
`rust/Cargo.toml`'s `[workspace.members]`.

**Crate manifest.** Create `rust/shekyl-difficulty/Cargo.toml`:

```toml
[package]
name = "shekyl-difficulty"
version = "0.1.0"
edition = "2024"
license = "BSD-3-Clause"
description = "Shekyl LWMA-1 difficulty-adjustment algorithm"
build = "build.rs"

[dependencies]
# No runtime workspace dependencies (leaf-crate property per
# DAA_LWMA1.md §2.1). The algorithm body is pure Rust, std-only,
# u128 arithmetic, no external math/util crates.
#
# Phase 1 reviewer note: workspace-level configuration is inherited
# normally and is NOT a violation of the leaf-crate property:
#   - [lints] section is inherited from rust/Cargo.toml workspace
#   - [profile.*] tuning is inherited from the workspace
#   - thiserror may be added if the Lwma1Error taxonomy benefits from
#     derive-based error types; thiserror is already a workspace dep
#     used by shekyl-crypto-pq and shekyl-fcmp, so no new supply-chain
#     surface is added. The decision is deferred to Phase 1 review.

[build-dependencies]
# serde_json is used by the existing shekyl-engine-core/build.rs to
# parse config/consensus_constants.json; same dep is reused here.
# This is a build-time dep only, not a runtime dep — does not break
# the leaf-crate property at runtime.
serde_json = "1"
```

**Crate library.** Create `rust/shekyl-difficulty/src/lib.rs`:

```rust
#![deny(unsafe_code)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::arithmetic_side_effects)]

pub mod consts;
pub mod lwma1;

pub use crate::lwma1::lwma1_next;
pub use crate::consts::{N, T_SECONDS, GENESIS_DIFFICULTY,
    FTL_SECONDS, MTP_WINDOW};
```

**Typed consensus constants — sourced from
`config/consensus_constants.json`.** Per `DAA_LWMA1.md` §4, the
numeric consensus constants live in the project's JSON authority
to prevent C++/Rust drift (per the
[`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) "Full migration of remaining
`SHEKYL_*` FFI constants to the JSON-authority pattern" entry, and
the [`docs/audit_trail/2026-05-ffi-constant-drift-audit.md`](../audit_trail/2026-05-ffi-constant-drift-audit.md)
audit that motivated it).

Three concrete work items in this PR:

1. **Extend `config/consensus_constants.json`** with the five
   LWMA-1 keys (final naming a Phase 1 review item):

   ```json
   {
     "daa_lwma1_window_n": 90,
     "daa_lwma1_target_seconds": 120,
     "daa_lwma1_ftl_seconds": 540,
     "daa_lwma1_mtp_window": 11,
     "daa_lwma1_genesis_difficulty": 100
   }
   ```

2. **Generate Rust constants.** Two options; pick one in Phase 1
   review:

   - **Option A (preferred):** add
     `rust/shekyl-difficulty/build.rs` mirroring the shape of
     `rust/shekyl-engine-core/build.rs`. Reads the JSON,
     emits `consensus_constants_generated.rs` to `OUT_DIR`,
     `src/consts.rs` `include!`s it. Keeps generation scoped to
     the consumer crate.
   - **Option B:** extend `rust/shekyl-engine-core/build.rs` to
     emit the LWMA-1 keys; `shekyl-difficulty` adds
     `shekyl-engine-core` as a workspace dep solely to consume the
     generated constants. **Cost:** breaks the leaf-crate property
     per `DAA_LWMA1.md` §2.1. Option A is preferred unless review
     surfaces a reason to centralize.

3. **Extend `cmake/generate_consensus_constants.py`** to emit the
   matching C++ symbols (`SHEKYL_DAA_LWMA1_WINDOW_N`, etc., as
   `constexpr` in `shekyl/consensus_constants_generated.h`).

The resulting `src/consts.rs` is short:

```rust
//! Typed consensus constants for LWMA-1.
//!
//! Numeric values are generated from config/consensus_constants.json
//! via build.rs; see DAA_LWMA1.md §4 and FOLLOWUPS.md (JSON-authority
//! pattern). The canonical-derivation constants below (BIAS_NUMERATOR,
//! BIAS_DENOMINATOR, SOLVETIME_CLAMP_FACTOR, MIN_L_FLOOR_*) are
//! deliberately NOT JSON-keyed: they are zawy12-canonical fixed
//! values per DAA_LWMA1.md §5.3 step 7, not Shekyl tunables.

include!(concat!(env!("OUT_DIR"), "/consensus_constants_generated.rs"));

// Re-export with the names DAA_LWMA1.md §4 uses (the JSON keys are
// scoped; the algorithm reads against canonical zawy12 names).
pub const N: u64 = DAA_LWMA1_WINDOW_N;
pub const T_SECONDS: u64 = DAA_LWMA1_TARGET_SECONDS;
pub const GENESIS_DIFFICULTY: u128 = DAA_LWMA1_GENESIS_DIFFICULTY as u128;
pub const FTL_SECONDS: u64 = DAA_LWMA1_FTL_SECONDS;
pub const MTP_WINDOW: u64 = DAA_LWMA1_MTP_WINDOW;

// Canonical zawy12 fixed values; NOT JSON-keyed.
pub(crate) const BIAS_NUMERATOR: u128 = 99;
pub(crate) const BIAS_DENOMINATOR: u128 = 200;
pub(crate) const SOLVETIME_CLAMP_FACTOR: u64 = 6;
pub(crate) const MIN_L_FLOOR_NUMERATOR: u128 = 1;
pub(crate) const MIN_L_FLOOR_DENOMINATOR: u128 = 20;

// Cross-language consistency sentinel (per FOLLOWUPS.md pattern).
const _STATIC_FTL_CHECK: () = assert!(FTL_SECONDS == N * T_SECONDS / 20);
const _STATIC_FTL_VALUE: () = assert!(FTL_SECONDS == 540);
```

**Algorithm.** Create `rust/shekyl-difficulty/src/lwma1.rs` from
the textual spec at [`DAA_LWMA1.md`](./DAA_LWMA1.md) §5.3. **Do not
transcribe** the on-disk sketch. Returns `Result<u128, Lwma1Error>`
for ergonomic Rust callers; the FFI shim in Phase 3 converts to the
`i32` error-code surface.

**Synthetic unit tests** per [`DAA_LWMA1.md`](./DAA_LWMA1.md) §8.1.

**Phase 1 merge gate.** `cargo test`, `cargo clippy --all-targets
-- -D warnings`, and `cargo fmt --check` must all pass per
`45-rust-lint-checks.mdc`. No `#[allow(...)]` of
`clippy::arithmetic_side_effects` or `clippy::indexing_slicing` is
permitted in the algorithm code; both require explicit `.checked_*`
/ `.get(...)` per `20-rust-vs-cpp-policy.mdc` rules 3 and 4.

**Phase 1 reversibility.** Removing the crate is mechanical (revert
the workspace member-addition and remove the directory). Phase 1 is
fully reversible without touching any C++ code.

## Phase 2 — Canonical-reference cross-check harness

Three work items: commit the pinned spec revision, build the
cross-check harness, integrate the harness into CI.

**Commit pinned spec revision.** Per
[`DAA_LWMA1.md`](./DAA_LWMA1.md) §3, capture the **raw issue body**
of [`zawy12/difficulty-algorithms#3`](https://github.com/zawy12/difficulty-algorithms/issues/3)
via the GitHub REST API at Phase 2 PR time:

```text
curl -sH "Accept: application/vnd.github.v3+json" \
  https://api.github.com/repos/zawy12/difficulty-algorithms/issues/3 \
  | jq -r .body > docs/design/refs/zawy12_issue_3_lwma1.md
```

Commit the file. Record its SHA-256 in `DAA_LWMA1.md` §3's pin
record. Pinning the raw `.body` (not GitHub's rendered HTML)
immunizes the audit trail against rendering-side changes that don't
affect spec meaning.

**Cross-check harness.** Add
`tests/difficulty/lwma1_cross_check.cpp` that builds the canonical
`LWMA1_()` C++ function (extracted from the pinned spec revision;
vendored as `tests/difficulty/zawy12_lwma1_reference.h`), iterates
the §8.1 input corpus, calls both the C++ reference and the Rust
implementation (via FFI declared in Phase 3, or via a tiny
test-only C++ wrapper around the `cargo build`-produced library),
and asserts byte-identical `u128` output. Failure aborts the test.

**CI integration.** Add the harness to `make tests` / `ctest` so
CI runs it as part of the default test build.

**Phase 2 merge gate.** The cross-check passes 100 % across the
§8.1 corpus before Phase 3 opens. If a divergence is found, the
spec wins by construction; the remediation is to fix the Rust
implementation. If the spec itself is ambiguous (the §8.1 corpus
exposes a case the canonical text doesn't cover), open an issue
against zawy12 Issue #3 and pause Phase 2 until the spec is
clarified.

**Phase 2 reversibility.** The harness is test-only; removal is
mechanical.

## Phase 3 — FFI wire-up in `shekyl-ffi`

Four work items: add the FFI export, declare the header, add
error-code constants, and verify panic safety.

**Add the FFI export** in `rust/shekyl-ffi/src/lib.rs`:

```rust
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shekyl_difficulty_lwma1_next(
    timestamps: *const u64,
    cum_difficulties: *const u128,
    count: usize,
    chain_height: u64,
    out_next_difficulty: *mut u128,
) -> i32 {
    // ... per DAA_LWMA1.md §6.1
}
```

The export sits inside the `shekyl-ffi` crate's single `unsafe`
surface per `25-rust-architecture.mdc`. The `shekyl-difficulty`
crate itself remains `#![deny(unsafe_code)]`.

**Header declaration** in `src/shekyl/shekyl_ffi.h`. Hand-maintained
to match the Rust signature; the FFI surface is the load-bearing
contract.

**Error-code constants** in `shekyl_ffi.h`:

```c
#define SHEKYL_DIFFICULTY_OK              0
#define SHEKYL_DIFFICULTY_ERR_NULL_PTR   -1
#define SHEKYL_DIFFICULTY_ERR_INVALID_COUNT -2
#define SHEKYL_DIFFICULTY_ERR_OVERFLOW   -3
#define SHEKYL_DIFFICULTY_ERR_INTERNAL   -4
```

**Panic safety.** The FFI shim wraps the Rust call in
`std::panic::catch_unwind` per the RandomX v2 plan's error taxonomy
framing ([`RANDOMX_V2_RUST.md`](./RANDOMX_V2_RUST.md) §17 /
[`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) Phase 2e); any
uncaught panic maps to `ERR_INTERNAL`.

**Phase 3 merge gate.** The FFI surface compiles and links cleanly
into the existing C++ build. The C++ side does NOT yet consume it;
the daemon still runs the inherited `next_difficulty`. Phase 3 is
purely additive; Phase 4 deletes the inherited path and rewires
consumers.

**Phase 3 reversibility.** Removing the export is mechanical
(delete the function and header declaration). Phase 3 is fully
reversible.

## Phase 4 — C++ cutover

Single PR rewires the three blockchain call sites, deletes the
inherited DAA implementation, deletes the `DIFFICULTY_*` constants,
and migrates FTL/MTP. Eleven work items, all in one PR (the cutover
is atomic by design: leaving the chain in a non-canonical
intermediate state — wrong FTL alongside the new DAA, or vice versa
— materially weakens LWMA-1's timestamp-attack defenses).

**Rewire** the three `next_difficulty` call sites in
`src/cryptonote_core/blockchain.cpp` (lines ~965, ~1021, ~1325) to
call `shekyl_difficulty_lwma1_next`. Each site already maintains
parallel `timestamps[]` and `difficulties[]` vectors; the rewire is
a function-call substitution plus an error-code check on the `i32`
return.

**Delete** [`src/cryptonote_basic/difficulty.cpp`](../../src/cryptonote_basic/difficulty.cpp)
and [`src/cryptonote_basic/difficulty.h`](../../src/cryptonote_basic/difficulty.h)
in full.

**Delete the `DIFFICULTY_*` constants** in `src/cryptonote_config.h`
per [`DAA_LWMA1.md`](./DAA_LWMA1.md) §9.2.

**Consume LWMA-1 numeric constants from the generated header.**
Per [`DAA_LWMA1.md`](./DAA_LWMA1.md) §4 and §6.2, the values for
`N`, `T_SECONDS`, `FTL_SECONDS`, `MTP_WINDOW`, and
`GENESIS_DIFFICULTY` come from the generated header
`shekyl/consensus_constants_generated.h` (emitted by
`cmake/generate_consensus_constants.py` from
`config/consensus_constants.json`, extended in Phase 1). C++ code
consumes those generated symbols (e.g.,
`SHEKYL_DAA_LWMA1_TARGET_SECONDS`) directly.

`DIFFICULTY_TARGET_V2` (currently `120`) is **deleted** outright,
not renamed. Every consumer of `DIFFICULTY_TARGET_V2` is rewired
to `SHEKYL_DAA_LWMA1_TARGET_SECONDS` from the generated header.
Renaming the hand-maintained `#define` would preserve the
drift-vulnerability bug class the JSON-authority pattern exists
to close.

**Migrate FTL.** Delete the hand-maintained
`BLOCK_FUTURE_TIME_LIMIT` and `BLOCK_FUTURE_TIME_LIMIT_V2`
`#define`s. Rewire consumers to `SHEKYL_DAA_LWMA1_FTL_SECONDS`
from the generated header.

**Migrate MTP.** Delete the hand-maintained
`BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW` `#define`. Rewire consumers to
`SHEKYL_DAA_LWMA1_MTP_WINDOW` from the generated header.

**No-orphaned-magic-numbers invariant.** After Phase 4, `git grep
-nE 'BLOCK_FUTURE_TIME_LIMIT|BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW|DIFFICULTY_TARGET_V[12]'`
in the C++ source tree returns zero hits except the deletion-
commit's own diff. CI can enforce this with a single grep step on
the post-Phase-4 tree.

**Delete tests/difficulty/.** `tests/difficulty/difficulty.cpp`,
`tests/difficulty/gen_wide_data.py`, and
`tests/difficulty/generate-data` are replaced by the Phase 1/2
Rust tests and Phase 2 cross-check harness.

**Symbol-isolation CI invariant.** Add a GitHub Actions step that
runs `nm shekyld | rg -q '^.* (T|U) (next_difficulty_64|next_difficulty|check_difficulty_checkpoints)\b'`
and fails on match. This shares the workflow file with the RandomX
v2 §7.1 invariant when both have landed; if RandomX v2's workflow
hasn't landed yet, this PR creates the workflow file and the
RandomX v2 PR adds to it.

**No-C-ABI invariant in `shekyl-difficulty`.** Same three-pattern
grep as RandomX v2's `shekyl-pow-randomx` invariant
([`RANDOMX_V2_RUST.md`](./RANDOMX_V2_RUST.md) §7.2):
`#\[(?:unsafe\(\s*)?no_mangle(?:\s*\))?\]`,
`\bextern\s+"C"\s+fn\b`, `#\[(?:unsafe\(\s*)?export_name\b`. Same
workflow file.

**Update unit tests.** Any test that consumed the inherited
`next_difficulty` is updated to consume the new FFI path (which it
will already have done if Phase 3's tests cover it).

**CHANGELOG.md and FOLLOWUPS.md** per
`91-documentation-after-plans.mdc`.

**Phase 4 merge gate.** The daemon builds and passes all consensus
tests against a test-vector corpus that includes the inherited
consensus-checkpoint test data (replayed against the LWMA-1
algorithm and expected to produce different difficulties because
the algorithm itself differs) and the §8.3 simulated-history
corpus (asserting Rust-vs-canonical-C++ output parity across
50,000+ blocks). If either test fails, the cutover is reverted to
Phase 3's end state (FFI surface exists but inherited DAA still
runs) until the failure is diagnosed.

**Phase 4 reversibility.** Reverting Phase 4 means: restore
`difficulty.{h,cpp}`, restore the `DIFFICULTY_*` constants,
un-rewire the three blockchain call sites, revert FTL/MTP
migration. Mechanical but multi-file. **The bar for reverting is
"Phase 4 broke consensus and we need to ship without LWMA-1"** — a
serious decision that triggers a new design doc revisiting
[`DAA_LWMA1.md`](./DAA_LWMA1.md) §1.4.

## Phase 5 — Docs

Update:

- [`docs/USER_GUIDE.md`](../USER_GUIDE.md) (or equivalent) — explain
  the difficulty adjustment for end-user-facing audiences. Probably
  one paragraph plus the parameter table from `DAA_LWMA1.md` §4.
- [`docs/SHEKYLD_PREREQUISITES.md`](../SHEKYLD_PREREQUISITES.md) —
  no new prerequisites (pure-Rust crate, no new C++ dependencies);
  confirm no doc churn needed.
- [`docs/DESIGN_CONCEPTS.md`](../DESIGN_CONCEPTS.md) or equivalent
  high-level design doc — DAA section updated to LWMA-1.
- [`docs/CHANGELOG.md`](../CHANGELOG.md) — record genesis-time DAA
  migration.
- [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) — close the FOLLOWUPS
  entry that triggered this work (the Cluster 2.5 / Mission Audit
  entry that named LWMA-1 as the target); cross-reference the
  `24-reviewer-discipline.mdc` rule-promotion entry only **if** that
  rule has landed at `.cursor/rules/` by Phase 5 time. If it has
  not, no cross-reference is added and §12 of `DAA_LWMA1.md`
  remains the canonical reviewer-discipline description.

## Risk and reversibility summary

| Risk | Mitigation | Reversibility |
| --- | --- | --- |
| Spec divergence Rust vs canonical C++ | §8.2 cross-check harness; spec is source of truth | Fix Rust; not revert |
| Wrong N, T, FTL, or MTP value | Phase 0 review ratification; values are typed `const` | Pre-genesis: change const + re-test. Post-genesis: hard fork. |
| LWMA-1 unsuitable for actual Shekyl hashrate profile | §10 reversion clause names criteria; §8.3 corpus stress-tests Shekyl-specific scenarios | Pre-genesis: new design doc per §10. Post-genesis: hard fork. |
| FTL/MTP migration leaves chain in non-canonical intermediate state | Phase 4 migrates all three together; never split across PRs | Phase 4 is atomic; partial-revert is not a supported state |
| Pre-design sketch in `rust/shekyl-difficulty/src/lwma1.rs` accidentally becomes the implementation | Sketch deleted in this PR (commit `91c6dc44c`) per `15-deletion-and-debt.mdc`; §2.4 divergence catalogue retained as design record only; Phase 1 starts from empty crate directory | N/A — sketch no longer exists on disk |

## Open questions for Phase 0 review

1. **GENESIS_DIFFICULTY = 100 (proposed).** Ratify or replace with a
   Shekyl-specific value derived from RandomX v2 single-CPU
   hashrate measurements at the v2 fork pin (`aaafe71`).
2. **N = 90 (zawy12 canonical for T=120).** Ratify or run a
   Shekyl-specific sensitivity analysis on the §8.3 simulated-
   history corpus to confirm 90 is optimal under Shekyl's expected
   bootstrap-regime hashrate volatility.
3. **Where the build.rs for the LWMA-1 consensus constants
   lives.** Option A (preferred per Phase 1 §"Typed consensus
   constants"): a new `rust/shekyl-difficulty/build.rs`. Option B:
   extend the existing `rust/shekyl-engine-core/build.rs`. Option
   A preserves `shekyl-difficulty`'s leaf-crate property (per
   `DAA_LWMA1.md` §2.1) at the cost of a second build.rs reading
   the same JSON; Option B centralizes but introduces a
   workspace-internal dep from `shekyl-difficulty` to
   `shekyl-engine-core`. Reviewer ratifies one.
4. **JSON key naming.** The proposed keys are
   `daa_lwma1_window_n`, `daa_lwma1_target_seconds`,
   `daa_lwma1_ftl_seconds`, `daa_lwma1_mtp_window`,
   `daa_lwma1_genesis_difficulty`. The existing
   `fcmp_reference_block_min_age` style uses
   `<subsystem>_<descriptor>`; the proposed style matches with the
   `daa_lwma1_` prefix. Reviewer ratifies or replaces.
5. **Phase 2 cross-check harness as Rust integration test vs. C++
   test target.** The current proposal places it in
   `tests/difficulty/` as a C++ target so it consumes the canonical
   C++ reference directly. A Rust integration test in
   `rust/shekyl-difficulty/tests/` that vendors the C++ reference
   via a `build.rs` is the alternative; the trade-off is whether
   the canonical C++ reference is easier to consume from C++ or
   from Rust.

## Cross-references

- [`DAA_LWMA1.md`](./DAA_LWMA1.md) — the companion design doc.
- [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) — sibling sequencing
  precedent; this plan's phased shape mirrors its structure.
- [`RANDOMX_V2_RUST.md`](./RANDOMX_V2_RUST.md) — §3 spec source of
  truth, §7 isolation invariants, §9 typed consensus constants,
  §17 FFI error taxonomy. These patterns are reused.
- [`zawy12/difficulty-algorithms#3`](https://github.com/zawy12/difficulty-algorithms/issues/3)
  — canonical LWMA-1 reference.
