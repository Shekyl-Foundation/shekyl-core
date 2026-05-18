---
name: LWMA-1 difficulty adjustment migration
overview: "Replace Shekyl's inherited CryptoNote cut-windowed-average DAA (src/cryptonote_basic/difficulty.cpp, DIFFICULTY_WINDOW=720, DIFFICULTY_LAG=15-with-warning, DIFFICULTY_CUT=60) with LWMA-1 (zawy12 canonical, N=90 for T=120s) implemented as a Rust crate shekyl-difficulty per 20-rust-vs-cpp-policy.mdc rule 2. Genesis-time landing per 16-architectural-inheritance.mdc pre-genesis discount and 60-no-monero-legacy.mdc no-version-dispatch rule. Sibling track to RANDOMX_V2_PLAN.md but independent: LWMA-1 and RandomX v2 are math-orthogonal (DAA operates on (timestamps, cum_difficulties); PoW changes the hash function), no wallet V3.2 gate applies, no Monero release-time audit dependency. FTL (CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT, tightened from 7200s to N*T/20 = 540s) and MTP (BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW, tightened from 60 back to 11) are co-tuned per zawy12 canonical requirements. Phase 0 produces two design docs (DAA_LWMA1.md + this plan). Implementation cascades through Phase 1 (crate scaffold + spec-vector tests), Phase 2 (canonical-reference cross-check harness), Phase 3 (FFI wire-up in shekyl-ffi), Phase 4 (C++ cutover and inherited-DAA deletion). Each phase is a separate PR per 06-branching.mdc."
todos:
  - id: phase0-design
    content: "Phase 0: Write docs/design/DAA_LWMA1.md AND docs/design/DAA_LWMA1_PLAN.md. Cover: (a) inherited CryptoNote DAA disposition (delete-not-gate) per 60-no-monero-legacy.mdc and 16-architectural-inheritance.mdc; (b) Rust-implementation decision per 20-rust-vs-cpp-policy.mdc rule 2 (cryptographic contract); (c) Shekyl-specific parameter selection (N=90, T=120s, GENESIS_DIFFICULTY=100 proposed, FTL=N*T/20=540s, MTP=11); (d) canonical zawy12 LWMA-1 algorithm spec with overflow guards; (e) FFI surface (1 function, i32 error code, u128 out-param); (f) test-vector strategy (synthetic unit + canonical-reference cross-check + simulated-history corpus); (g) C++ deletion surface (difficulty.{h,cpp}, DIFFICULTY_* constants, tests/difficulty/, FTL/MTP migration); (h) sketch disposition (pre-design rust/shekyl-difficulty/src/lwma1.rs is NOT canonical and was deleted during Phase 0; divergence catalogue retained in DAA_LWMA1.md §2.4 as the design record of why each shape is rejected); (i) alternatives considered (LWMA-2/3/4, ASERT, retuned-cut-windowed, SMA) with reversion clauses per 21-reversion-clause-discipline.mdc; (j) reviewer-discipline framing (no external algorithm-review gate; zawy12 canonical is audit-of-record). Pass 4-6 review rounds before any code lands."
    status: pending
  - id: phase1-crate-scaffold
    content: "Phase 1: Add rust/shekyl-difficulty crate to rust/Cargo.toml workspace members as a leaf crate (zero internal workspace deps per DAA_LWMA1.md §2.1). Create rust/shekyl-difficulty/Cargo.toml (Shekyl Foundation copyright; BSD-3-Clause; no_std-compatible if practical, #![deny(unsafe_code)] crate-level). Extend config/consensus_constants.json with algorithm-version-free keys daa_{window_n=90, target_seconds=120, ftl_seconds=540, mtp_window=11, genesis_difficulty=100} per the JSON-authority pattern in DAA_LWMA1.md §4 (the algorithm-version flavor lives in src/lwma1.rs, not in symbol names). Extend cmake/generate_consensus_constants.py to emit SHEKYL_DAA_* constexpr symbols. Add rust/shekyl-difficulty/build.rs reading the JSON and emitting consensus_constants_generated.rs to OUT_DIR (Round 3 closed Option A; extending shekyl-engine-core/build.rs is rejected as it breaks the leaf-crate property). Create src/lib.rs re-exporting lwma1::lwma1_next, is_timestamp_below_ftl, is_above_mtp; src/consts.rs include!'ing the generated file and re-exporting N/T_SECONDS/FTL_SECONDS/MTP_WINDOW/GENESIS_DIFFICULTY (Round 3 disposition: bias factor 99/200, solvetime clamp 6, min-L floor 1/20 appear as bare integer literals inside src/lwma1.rs, NOT as named consts in src/consts.rs; matches canonical zawy12 verbatim per DAA_LWMA1.md §4); src/lwma1.rs (canonical implementation per DAA_LWMA1.md §5.3). Write unit tests against the §8.1 synthetic test corpus including the §5.3 step 8 overflow-boundary paired vectors AND the new §8.1 solvetime[1] -T-offset regression vector. PR cannot merge if cargo test, cargo clippy --all-targets -- -D warnings, or cargo fmt --check fails per 45-rust-lint-checks.mdc."
    status: pending
  - id: phase2-cross-check-harness
    content: "Phase 2: Add tests/difficulty/lwma1_cross_check.cpp harness (C++ test target per Round 4 disposition; canonical reference is C++, consuming it directly is simpler than Rust-side vendoring) that builds the zawy12 LWMA1_() C++ reference (extracted to tests/difficulty/zawy12_lwma1_reference.h with explicit SPDX-License-Identifier: MIT header per Round 3 disposition; derived from the pinned-spec revision) and asserts byte-equality between Rust output and C++ reference output across the §8.1 input corpus. CI runs the harness; failure fails CI. Commit docs/design/refs/zawy12_issue_3_lwma1.md as the pinned spec revision (raw issue body via GitHub REST API, immune to rendering-side drift). Record three LWMA1_() disambiguation anchors in the same file or a sibling .lwma1-anchors.json: (a) byte-offset range [offset_start, offset_end) within the pinned .body containing the LWMA1_() function, (b) the literal first line of LWMA1_(), (c) the literal last line. The issue contains four LWMA reference functions; without these anchors, Phase 2 maintainers cannot disambiguate the LWMA1_() boundaries from LWMA2_/3_/4_ when the upstream author reorders content. Round 9 + Round 10 supplements: also commit docs/design/refs/zawy12_issue_3_lwma3.md (verbatim LWMA3_() extraction for reader convenience, per §5.3 step 2's partial LWMA-3 adoption), docs/design/refs/zawy12_issue_3_lwma1_with_lwma3_step2.md (Shekyl-composed hybrid reference used by the cross-check harness for out-of-sequence test vectors), and docs/design/refs/zawy12_issue_24_history.md (raw .body pin of zawy12 issue #24 supporting every 'item N' cross-reference downstream). Anchors file extends with lwma3_byte_offset_{start,end}/first_line/last_line per the same three-anchor discipline as LWMA1_."
    status: pending
  - id: phase3-ffi-wire-up
    content: "Phase 3: Export shekyl_difficulty_lwma1_next from rust/shekyl-ffi/src/lib.rs per DAA_LWMA1.md §6.1 (i32 return; cum_difficulties: *const ShekylU128; out_next_difficulty: *mut ShekylU128 where #[repr(C)] struct ShekylU128 { lo: u64, hi: u64 } — Round 5 pivoted from [u8; 16] to a field-named two-u64 struct per the FCMP++/KEM-derivation precedent; rationale: Rust u128 C ABI was target-dependent until rustc 1.77 and remains a footgun on uncommon targets; u64 has universally stable ABI on every Shekyl-supported target, debugger-friendly lo/hi field semantics carry the meaning, no improper_ctypes exposure; ERR_NULL_PTR / ERR_INVALID_COUNT / ERR_OVERFLOW / ERR_INTERNAL taxonomy). Add struct shekyl_u128 { uint64_t lo; uint64_t hi; } and the function declaration to src/shekyl/shekyl_ffi.h. Hand-maintain the bindings per 25-rust-architecture.mdc. PR delivers the FFI surface; the daemon does NOT yet consume it (still on inherited next_difficulty)."
    status: pending
  - id: phase4-cpp-cutover
    content: "Phase 4 (14 work items, deliberate atomic-cutover exception to 06-branching.mdc; rationale: FTL and MTP value changes cannot stage behind alias #defines without weakening consensus integrity in the intermediate state). Rewire Blockchain::get_difficulty_for_next_block() (blockchain.cpp:~965), Blockchain::check_difficulty_checkpoints() (~1021), Blockchain::get_next_difficulty_for_alternative_chain() (~1325) to shekyl_difficulty_lwma1_next. DELETE src/cryptonote_basic/difficulty.{h,cpp}. Delete the 7 inherited DIFFICULTY_* #defines (DIFFICULTY_TARGET_V1, DIFFICULTY_TARGET_V2, DIFFICULTY_WINDOW, DIFFICULTY_LAG with // !!! warning, DIFFICULTY_CUT, DIFFICULTY_BLOCKS_COUNT, DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN) from src/cryptonote_config.h. Rewire ~14 DIFFICULTY_TARGET_V2 consumers across 9 files (enumerated in DAA_LWMA1.md §9.7; preserves RPC contract per §9.8) to SHEKYL_DAA_TARGET_SECONDS from shekyl/consensus_constants_generated.h. Delete CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT; rewire 2 FTL consumers (enumerated in §9.5) to SHEKYL_DAA_FTL_SECONDS — consensus-rule value change 7200 → 540 takes effect here. Delete BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW; rewire 9 MTP consumers (enumerated in §9.6) to SHEKYL_DAA_MTP_WINDOW — consensus-rule value change 60 → 11 takes effect here. Delete tests/difficulty/{difficulty.cpp, gen_wide_data.py, generate-data}. Add symbol-isolation CI invariant: nm shekyld must not contain T|U next_difficulty_64|next_difficulty|check_difficulty_checkpoints (per DAA_LWMA1.md §7.1). Add no-C-ABI invariant on shekyl-difficulty per §7.2. Add no-orphaned-magic-numbers CI invariant: git grep on post-Phase-4 tree returns zero hits for CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT, BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW, DIFFICULTY_TARGET_V[12], DIFFICULTY_WINDOW, DIFFICULTY_LAG, DIFFICULTY_CUT, DIFFICULTY_BLOCKS_COUNT, DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN. Add RPC-contract regression test asserting daemon.get_info().block_target == 120 post-cutover. Audit and rewire wallet-side DIFFICULTY_TARGET_V2 consumers (wallet2.cpp:181/182/5975/11548, wallet_rpc_server.cpp:163). Update unit tests and docs."
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
  P4[Phase 4: C++ cutover<br/>delete difficulty.{h,cpp}<br/>delete DIFFICULTY_*, CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT,<br/>BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW<br/>rewire all consumers to SHEKYL_DAA_* from generated header<br/>FTL 7200→540, MTP 60→11 take effect] --> P5
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

**Phase 1 pre-flight — bias-factor empirical verification.** Per
[`DAA_LWMA1.md`](./DAA_LWMA1.md) §5.3 step 7's
stochastic-vs-deterministic clarification, the canonical zawy12
`LWMA1_()` C++ reference is run once before Phase 1
implementation begins, against the §8.1 "perfectly stable
hashrate" input vector with `avg_D = 1_000_000`, `N = 90`,
`T = 120`, and `solvetime[i] = T` for all `i ∈ 1..=N`. The
expected output is exactly `990_000` per the derivation in §5.3
step 7 and the §8.1 vector. The result is recorded in the Phase
1 PR description.

- If the canonical reference produces `990_000`: the design
  doc's §5.3 step 7 clarification and §8.1 expectation are both
  empirically confirmed; Phase 1 implementation proceeds against
  the unmodified spec.
- If the canonical reference produces `1_000_000`: the §8.1
  test vector's expected value is wrong (or the canonical
  reference has changed between the §3 pinned-revision and
  observation, which itself is a Phase 0 reversion-clause
  trigger per `DAA_LWMA1.md` §10). Phase 1 stops; the Phase 0
  doc is amended; Phase 0 re-reviews.
- Any other output: the canonical reference's behavior contradicts
  both the §5.3 derivation and the §8.1 expectation; treat as a
  reversion-clause trigger per §10 and surface the discrepancy
  on `dev` before further work.

This verification step is mechanical (one C++ run against the
canonical reference, one numeric comparison). It removes the
remaining ambiguity in §5.3 step 7's stochastic-vs-deterministic
framing as a function of empirical evidence rather than as a
function of derivation prose.

**Workspace registration.** Add `shekyl-difficulty` to
`rust/Cargo.toml`'s `[workspace.members]`.

**Crate manifest.** Create `rust/shekyl-difficulty/Cargo.toml`.
The manifest itself stays minimal — review-time commentary lives
in this design doc, not in long-lived TOML comments:

```toml
[package]
name = "shekyl-difficulty"
version = "0.1.0"
edition = "2024"
license = "BSD-3-Clause"
description = "Shekyl LWMA-1 difficulty-adjustment algorithm"
build = "build.rs"

[dependencies]
# Leaf crate: no runtime workspace deps. See DAA_LWMA1.md §2.1.

[build-dependencies]
serde_json = "1"
```

**Manifest review-checklist** (artifacts of Phase 1 review, **not**
content that lands in the manifest):

- The empty `[dependencies]` section is the leaf-crate property
  per `DAA_LWMA1.md` §2.1. Workspace-level configuration
  (`[lints]`, `[profile.*]`) is inherited from `rust/Cargo.toml`
  and does not violate the leaf-crate property.
- `[build-dependencies] serde_json = "1"` is a build-time-only
  dep used by `build.rs` to parse `config/consensus_constants.json`;
  it does not affect the runtime leaf-crate property.
- `thiserror` may be added under `[dependencies]` if the
  `Lwma1Error` taxonomy benefits from derive-based error types.
  `thiserror` is already a workspace dep used by
  `shekyl-crypto-pq` and `shekyl-fcmp`, so adding it here adds no
  new supply-chain surface. Phase 1 PR description records the
  decision; the manifest itself just lists the dep or doesn't.

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

1. **Extend `config/consensus_constants.json`** with the five DAA
   keys. Per `DAA_LWMA1.md` §4 ("Algorithm-version-free naming"),
   the keys are `daa_*`, not `daa_lwma1_*` — the algorithm-version
   flavor lives in the algorithm body (`src/lwma1.rs`), and the
   consensus constants are named for the role they play so a
   future §10 reversion (LWMA-2/3/4 or ASERT) doesn't require
   renaming every consumer:

   ```json
   {
     "daa_window_n": 90,
     "daa_target_seconds": 120,
     "daa_ftl_seconds": 540,
     "daa_mtp_window": 11,
     "daa_genesis_difficulty": 100
   }
   ```

2. **Generate Rust constants** via a new
   `rust/shekyl-difficulty/build.rs` (per `DAA_LWMA1.md` §4 and
   §2.1: the leaf-crate property requires generation be scoped to
   the consumer crate; extending `shekyl-engine-core/build.rs` was
   considered and rejected because it would introduce a workspace-
   internal dep purely to consume generated constants). The build
   script reads the JSON, emits
   `consensus_constants_generated.rs` to `OUT_DIR`,
   `src/consts.rs` `include!`s it.

3. **Extend `cmake/generate_consensus_constants.py`** to emit the
   matching C++ symbols as `constexpr` in
   `shekyl/consensus_constants_generated.h`:
   `SHEKYL_DAA_WINDOW_N`, `SHEKYL_DAA_TARGET_SECONDS`,
   `SHEKYL_DAA_FTL_SECONDS`, `SHEKYL_DAA_MTP_WINDOW`,
   `SHEKYL_DAA_GENESIS_DIFFICULTY`.

The resulting `src/consts.rs` is short:

```rust
//! Typed consensus constants for the DAA.
//!
//! Numeric values are generated from config/consensus_constants.json
//! via build.rs; see DAA_LWMA1.md §4 and FOLLOWUPS.md (JSON-authority
//! pattern). Names are algorithm-version-free per DAA_LWMA1.md §4 so
//! a future §10 reversion doesn't require renaming consumers.
//!
//! Canonical zawy12 fixed values (bias numerator 99, bias denominator
//! 200, solvetime clamp factor 6, min-L floor 1/20) are deliberately
//! NOT exposed here as named `const`. They appear as bare integer
//! literals inside `src/lwma1.rs` so the formula reads against the
//! canonical reference verbatim, per DAA_LWMA1.md §4. Naming them
//! would invite future "tunable" misreadings.

include!(concat!(env!("OUT_DIR"), "/consensus_constants_generated.rs"));

// Re-export under the canonical zawy12 names. The algorithm body
// reads against these.
pub const N: u64 = DAA_WINDOW_N;
pub const T_SECONDS: u64 = DAA_TARGET_SECONDS;
pub const GENESIS_DIFFICULTY: u128 = DAA_GENESIS_DIFFICULTY as u128;
pub const FTL_SECONDS: u64 = DAA_FTL_SECONDS;
pub const MTP_WINDOW: u64 = DAA_MTP_WINDOW;

// Cross-language consistency sentinels.
//
// If either of these `const _: () = assert!(...)` blocks fires at
// build time, the fix is NEVER to silence the assert. The JSON is
// the authority; if N, T_SECONDS, or FTL_SECONDS has changed in the
// JSON, the operator MUST update all three values together such that
// FTL_SECONDS == N * T_SECONDS / 20 still holds (the zawy12-canonical
// relationship) and re-derive the resulting FTL_SECONDS literal.
// The assert exists to catch arithmetic drift between the three
// values; silencing it converts an arithmetic-drift failure into an
// intent-drift failure with no surviving check.
const _STATIC_FTL_CHECK: () = assert!(FTL_SECONDS == N * T_SECONDS / 20);
const _STATIC_FTL_VALUE_V3_0: () = assert!(FTL_SECONDS == 540);
```

**Algorithm.** Create `rust/shekyl-difficulty/src/lwma1.rs` from
the textual spec at [`DAA_LWMA1.md`](./DAA_LWMA1.md) §5.3. **Do not
transcribe** the on-disk sketch. Returns `Result<u128, Lwma1Error>`
for ergonomic Rust callers; the FFI shim in Phase 3 converts to the
`i32` error-code surface.

**Round 9 partial-LWMA-3-adoption signed-arithmetic discipline.**
Per [`DAA_LWMA1.md`](./DAA_LWMA1.md) §5.3 steps 2–4 and §5.4
"Signed-arithmetic discipline," the Round 9 algorithm uses `i128`
internally for solvetime computation, symmetric clamping, and
weighted-sum accumulation; `u128` is restored at step 5's
minimum-L floor (which guarantees a positive value going into
step 7's unsigned division). The Phase 1 implementer must
preserve this signedness boundary precisely:

- Step 2's running-max formulation uses `prev_max: u64` and
  `solvetime[i]: i128`; the subtraction `timestamps[i] as i128 -
  prev_max as i128` is the canonical pattern (cast both operands
  before subtracting; avoid `as i128` after the subtraction).
- Step 3's symmetric clamp uses `solvetime.clamp(-6 * T as i128,
  6 * T as i128)`.
- Step 4's weighted sum accumulator is `let mut L: i128 = 0;`.
- Step 5's minimum-L floor re-types: `let L: u128 =
  L.max(N * N * T / 20) as u128;` (the `max` ensures
  positivity, the cast is infallible after the max).
- Step 7's division operates on `u128` throughout, unchanged
  from the Round 8 form.

The clippy lints
`clippy::arithmetic_side_effects` and `clippy::indexing_slicing`
apply to signed and unsigned arithmetic identically; the i128
intermediates use `.checked_mul`, `.checked_add`, `.checked_sub`
or explicit-cast-then-arithmetic patterns just like the u128 path.

**Synthetic unit tests** per [`DAA_LWMA1.md`](./DAA_LWMA1.md) §8.1.
The Round 9 vectors that exercise the partial-LWMA-3 adoption are
specifically called out in §8.1:

- "Out-of-sequence timestamp handling (running-max semantics,
  Round 9)" — exercises step 2's running-max and step 3's
  symmetric clamp with a single out-of-sequence pair; required.
- "Selfish-mine attack regression (zawy12 issue #24 item 14,
  September 2018 attack class)" — the regression test for the
  Round 9 algorithm change and the closing-condition gate for
  zawy12 issue #24 item 14; required.

These two vectors must produce byte-exact outputs that differ
from a hypothetical Round-8-kyuupichan implementation for the
same inputs; the divergence is the load-bearing property the
test catches. If a Round 9 Rust implementation produces the
Round 8 (kyuupichan) numerical output for these vectors, the
implementation has reverted to the Round 8 algorithm and Phase 1
gate fails.

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

**LWMA1_() disambiguation anchors.** The pinned issue body contains
**four** reference functions (`LWMA1_()`, `LWMA2_()`, `LWMA3_()`,
`LWMA4_()`); every `DAA_LWMA1.md` §5.3 citation that reads
"Issue #3, LWMA-1 reference, lines N–M" is otherwise ambiguous
between them. Phase 2 records three anchors alongside the pinned
body, in a sibling `docs/design/refs/zawy12_issue_3_lwma1.anchors.json`:

```json
{
  "lwma1_byte_offset_start": 0,
  "lwma1_byte_offset_end": 0,
  "lwma1_first_line": "",
  "lwma1_last_line": "",
  "pinned_body_sha256": "",
  "captured_at_utc": ""
}
```

The four fields are populated at Phase 2 PR time by inspecting the
pinned `.body` and recording (a) the byte-offset range
`[start, end)` that contains the entire `LWMA1_()` function
definition (signature line through closing brace), (b) the literal
first line of the function (verbatim, for grep-anchor recovery),
(c) the literal last line, and (d) the SHA-256 of the pinned
`.body` from which the anchors were derived. Together these pin
`LWMA1_()` against upstream reordering or insertions.

`DAA_LWMA1.md` §5.3's "lines N–M" citations resolve against the
LWMA1_() byte-offset range, not against the full `.body`.

**Round 9 supplementary reference files (committed alongside the
pin in the same Phase 2 PR).** Per
[`DAA_LWMA1.md`](./DAA_LWMA1.md) §3's Round-9 disposition, the
partial LWMA-3 adoption in §5.3 step 2/3 requires two additional
files under `docs/design/refs/`:

1. `zawy12_issue_3_lwma3.md` — convenience extraction of the
   `LWMA3_()` function from the pinned issue body. The extraction
   is verbatim against the LWMA-3 byte-offset anchor (see below);
   the file is *not* the canonical pin (file
   `zawy12_issue_3_lwma1.md` is) — it is a reader-convenience
   copy so audit-reviewers reading the cross-check derivation
   can see just the LWMA-3 source. If the two diverge, the
   canonical pin wins and this file is regenerated from it.
2. `zawy12_issue_3_lwma1_with_lwma3_step2.md` — the Shekyl-
   composed hybrid reference: LWMA-1's canonical body with step 2
   and step 3 substituted by LWMA-3's running-max + symmetric-
   clamp mechanism. This is a *derived* file (not a pin); it is
   the executable form of `DAA_LWMA1.md` §5.3's textual
   deviation. Phase 2's cross-check harness uses this file's
   body when computing expected outputs against out-of-sequence
   timestamp inputs (monotonic inputs use canonical `LWMA1_()`).

The same Phase 2 anchors file gains LWMA-3 byte-offset anchors
alongside the existing LWMA-1 anchors so that the LWMA3_()
extraction is grep-anchored against upstream reordering. The
anchors file structure extends to:

```json
{
  "lwma1_byte_offset_start": 0,
  "lwma1_byte_offset_end": 0,
  "lwma1_first_line": "",
  "lwma1_last_line": "",
  "lwma3_byte_offset_start": 0,
  "lwma3_byte_offset_end": 0,
  "lwma3_first_line": "",
  "lwma3_last_line": "",
  "pinned_body_sha256": "",
  "captured_at_utc": ""
}
```

**Round 10 supplementary reference file: zawy12 issue #24 pin.**
Per [`DAA_LWMA1.md`](./DAA_LWMA1.md) §3's Round-10 addition,
Phase 2 also commits
`docs/design/refs/zawy12_issue_24_history.md` — the raw `.body`
of [`zawy12/difficulty-algorithms#24`](https://github.com/zawy12/difficulty-algorithms/issues/24)
("LWMA's history"):

```text
curl -sH "Accept: application/vnd.github.v3+json" \
  https://api.github.com/repos/zawy12/difficulty-algorithms/issues/24 \
  | jq -r .body > docs/design/refs/zawy12_issue_24_history.md
```

Rationale: every "zawy12 issue #24 item N" cross-reference in
the design doc resolves against the numbered list inside this
pinned `.body`, not against the live GitHub-rendered issue.
Without the pin, an upstream-author edit that renumbers items
(e.g., inserting a new item between items 5 and 6) silently
invalidates every downstream "item N" citation. Per the
round-10 disposition, design-doc prose continues to cite by
date + description as the primary identifier; the item number
is a redundant cross-reference resolving against this pin.

Phase 2 records the issue-#24 pin SHA-256 and the
captured-at-UTC timestamp in `DAA_LWMA1.md` §3's pin record. No
byte-offset anchors are needed for the issue-#24 pin: the design
doc cites it by date + description, not by line range, so the
audit-trail anchor is the SHA-256 of the full `.body` rather
than per-section byte ranges.

**Cross-check harness.** Add
`tests/difficulty/lwma1_cross_check.cpp` that builds the canonical
`LWMA1_()` C++ function (extracted from the pinned spec revision;
vendored as `tests/difficulty/zawy12_lwma1_reference.h`), iterates
the §8.1 input corpus, calls both the C++ reference and the Rust
implementation (via FFI declared in Phase 3, or via a tiny
test-only C++ wrapper around the `cargo build`-produced library),
and asserts byte-identical `u128` output. Failure aborts the test.

**MIT attribution for the vendored reference.**
`tests/difficulty/zawy12_lwma1_reference.h` is a derived work of
the zawy12 canonical C++ source, which is published under
[MIT](https://github.com/zawy12/difficulty-algorithms/blob/master/LICENSE).
`DAA_LWMA1.md` §14 notes that the Rust algorithm body is an
independent transcription of the spec and so does not carry an
MIT-attribution obligation; the vendored C++ header **does**, and
its file header must include:

```cpp
// SPDX-License-Identifier: MIT
//
// Adapted verbatim from zawy12/difficulty-algorithms Issue #3
// (LWMA-1 canonical reference) at the revision pinned in
// docs/design/refs/zawy12_issue_3_lwma1.md.
//
// Original work copyright (c) zawy12 et al. and used here under
// the MIT License.
```

The harness wrapper (`lwma1_cross_check.cpp`) is Shekyl-authored
test glue and carries the standard Shekyl Foundation BSD-3-Clause
header.

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

**Add the FFI export** in `rust/shekyl-ffi/src/lib.rs`. The
difficulty type at the ABI boundary is `#[repr(C)] struct
ShekylU128 { lo: u64, hi: u64 }` per `DAA_LWMA1.md` §6.1 (Rust
`u128` C-ABI soundness was target-dependent until rustc 1.77 and
remains a footgun on uncommon targets; decomposing into two `u64`
fields — each with universally stable C ABI — eliminates the
exposure entirely; the field-named struct preserves explicit
`lo`/`hi` semantics, debugger-friendly and unambiguous at every
consumer call site):

```rust
#[repr(C)]
pub struct ShekylU128 {
    pub lo: u64,
    pub hi: u64,
}

impl From<u128> for ShekylU128 {
    fn from(v: u128) -> Self {
        Self { lo: v as u64, hi: (v >> 64) as u64 }
    }
}

impl From<ShekylU128> for u128 {
    fn from(v: ShekylU128) -> u128 {
        ((v.hi as u128) << 64) | (v.lo as u128)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn shekyl_difficulty_lwma1_next(
    timestamps: *const u64,
    cum_difficulties: *const ShekylU128,
    count: usize,
    chain_height: u64,
    out_next_difficulty: *mut ShekylU128,
) -> i32 {
    // Read cum_difficulties[i] via ptr::read followed by
    // ShekylU128::into() to recover u128; write out_next_difficulty
    // via ptr::write of ShekylU128::from(u128).
    // ... per DAA_LWMA1.md §6.1
}
```

The C-side declaration in `src/shekyl/shekyl_ffi.h`:

```c
struct shekyl_u128 {
    uint64_t lo;   // little-endian lower 64 bits
    uint64_t hi;   // little-endian upper 64 bits
};

int32_t shekyl_difficulty_lwma1_next(
    const uint64_t *timestamps,
    const struct shekyl_u128 *cum_difficulties,
    size_t count,
    uint64_t chain_height,
    struct shekyl_u128 *out_next_difficulty);
```

C++ callers with a native `uint128_t`-typed buffer **must
explicitly construct** `shekyl_u128` instances at the call site
(`{ .lo = (uint64_t)v, .hi = (uint64_t)(v >> 64) }`) and
decompose returned values symmetrically. The field-meaning is
the contract; reinterpret-casting `uint128_t` to `shekyl_u128`
relies on target-defined struct-layout ABI which Round 5
explicitly rejects.

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

Single PR. The cutover is **atomic by construction**: the FTL
value change (7200 s → 540 s) and the MTP value change (60 → 11)
are consensus-rule changes that cannot be staged behind alias
`#define`s, because an alias period would either (a) preserve the
old values across the rewire (changing behavior at the alias
deletion, not at the rewire — the worst possible bisection
surface) or (b) silently change behavior at the alias *definition*
(equivalent to atomic-cutover but split across two PRs for no
benefit). The only honest shape is one PR.

**Phase 4 invokes `07-consensus-atomic-cutovers.mdc`.** The
branch policy's 5-working-day / 10-commit guidance in
`06-branching.mdc` is a defense against unreviewable PRs
accumulating. Phase 4 invokes the named exception class
`07-consensus-atomic-cutovers.mdc`, which carves out a
small class of consensus-atomic cutovers from the splitting
guidance. The exception's four objectively-testable criteria
each apply here; the Phase 4 PR description repeats this
mapping verbatim so the invocation is auditable at PR-open
rather than by reference:

1. **Consensus-rule boundary (criterion 1).** Yes. The PR
   changes the FTL value (`7200 s → 540 s`), the MTP window
   (`60 → 11`), and the difficulty-computation algorithm
   itself. All three are consensus-rule values/behavior that
   correctly-implementing nodes must reproduce byte-identically
   on the same input; a validator running the old FTL or MTP
   would reach different acceptance conclusions on the same
   block header than one running the new values.
2. **Indivisible under flag decomposition (criterion 2).** Yes.
   Per the rule's criterion-2 framing, flag decomposition only
   counts as consensus-safe if both flag states are
   simultaneously valid (build-system flags, performance-tuning
   flags, instrumentation flags). For a consensus rule, both
   nodes must produce byte-identical output on the same input,
   so a flag that gated consensus behavior would have to
   dispatch identically regardless of state — which means it
   doesn't gate consensus behavior at all. The algorithm body,
   the FTL value, and the MTP window are all consensus-rule
   surfaces (criterion 1 above); there is therefore no
   simultaneously-valid flag decomposition for any of them, and
   none could exist without contradicting Shekyl's
   no-version-dispatch posture per `60-no-monero-legacy.mdc`.
   Criterion 2 is met structurally, not contingently.
3. **Surface enumerated in advance (criterion 3).** Yes.
   `DAA_LWMA1.md` §§9.4–9.7 enumerate every consensus-affecting
   symbol, file, and constant being changed, with line numbers
   and consumer counts derived from `git grep` at design-doc
   PR-open time. The Phase 4 PR description repeats the
   enumeration verbatim and links to the §§9.4–9.7 anchors.
4. **Disposition documented in PR (criterion 4).** Yes — the
   Phase 4 PR description cites `07-consensus-atomic-cutovers.mdc`
   by name; lists criteria 1–4 with one-sentence justifications
   per criterion (lifted from this section); includes a
   reviewer-map subsection partitioning the diff into
   *consensus-affecting* (the three `Blockchain` call sites
   from §9.4, the three FTL/MTP/algorithm `#define` deletions
   from §9.2, plus the generated-header pickup), *mechanical*
   (the 14 `DIFFICULTY_TARGET_V2` consumer rewires from §9.7,
   no logic change, only the source-of-value moves from
   `#define` to generated-header), and *deletion* (the
   `difficulty.{h,cpp}` pair); and includes a rollback
   procedure naming the specific files (the inverse of the
   reviewer-map's diff) and the order in which they would be
   reverted if consensus breaks post-merge.

Phase 4's scope is bounded by the criterion-3 enumeration: the
work-item ceiling is fixed at the 14 items below (no scope
creep within the PR; "while we're here" additions break the
exception per criterion 3 per `15-deletion-and-debt.mdc`).

**Reviewer-expectation note on diff size.** The "14 work items"
above are *categories of work*, not *file changes*: each
category covers between one and ~14 individual file edits.
Concretely, Phase 4's actual file-change count lands at
**roughly 45–55 file changes** across `src/` and `tests/`,
broken down as: 3 `next_difficulty` rewires (§9.4) + 2
`difficulty.{h,cpp}` deletions (§9.1) + 7 `DIFFICULTY_*` defines
removed from one file (`cryptonote_config.h`, §9.2) + 14
`DIFFICULTY_TARGET_V2` consumer rewires across 9 files (§9.7) +
1 FTL `#define` removed + 2 FTL consumer rewires across 2 files
(§9.5) + 1 MTP `#define` removed + 13 MTP consumer rewires
across 3 files (§9.6) + `tests/difficulty/` directory deletion
(§9.1) + 3 invariant-test additions (symbol-isolation,
no-C-ABI, no-orphaned-magic-numbers) + 1 RPC-contract test
(§9.8) + 5 wallet-side `T`-consumer rewires (§11 / §9.7) + 1
documentation update under `docs/`. A reviewer walking into the
Phase 4 PR sees a diff of ~50 files; the "14 work items"
framing is correct as a *categorization* but understates the
mechanical breadth of the rewire surface. The criterion-3
enumeration in `DAA_LWMA1.md` §§9.1–9.8 is the authoritative
file-by-file mapping; this paragraph is the
diff-size-expectation calibration for reviewers.

RandomX v2's Phase 3 sub-PR split (3a/3b/3c per
`RANDOMX_V2_PLAN.md`) does *not* invoke the same exception, and
`07-consensus-atomic-cutovers.mdc`'s history-of-application
section records RandomX v2 Phase 3 under "Cases that might
appear analogous but are not." The reason is structural: the
algorithm change itself (v1 → v2) does not ship in Phase 3 —
it ships in Phase 1's submodule swap. Phase 3 is implementation
routing: the FFI binding moves from the legacy path to the
monero-oxide-vendored path, and the algorithm body is
byte-identical on both sides of the 3a build flag. The 3a flag
is therefore a build-system / FFI-routing flag, not a consensus
flag, and criterion 1 is not met for Phase 3 at all. The
exception is structurally inapplicable rather than evaluated
and rejected; each sub-PR (3a/3b/3c) fits the standard
`06-branching.mdc` size limit independently. LWMA-1 Phase 4 is
the rule's first invocation, named in the rule's
history-of-application section at the time the rule itself
landed (PR #50). The eventual Phase 4 PR repeats the
four-criterion mapping above verbatim per
`07-consensus-atomic-cutovers.mdc` sub-clause 4.2.

Fourteen work items, all in this PR (numbered for the work-item
count audit; counts match `DAA_LWMA1.md` §§9.1–9.7):

1. **Rewire `next_difficulty` call sites** in
   `src/cryptonote_core/blockchain.cpp` (~965, ~1021, ~1325; per
   `DAA_LWMA1.md` §9.4) to call `shekyl_difficulty_lwma1_next`.
   Each site already maintains parallel `timestamps[]` and
   `difficulties[]` vectors; the rewire is a function-call
   substitution plus an error-code check on the `i32` return.
2. **Delete `src/cryptonote_basic/difficulty.cpp` and
   `difficulty.h` in full** (per `DAA_LWMA1.md` §9.1).
3. **Delete the inherited `DIFFICULTY_*` `#define`s** in
   `src/cryptonote_config.h` (seven constants: `DIFFICULTY_TARGET_V1`,
   `DIFFICULTY_TARGET_V2`, `DIFFICULTY_WINDOW`, `DIFFICULTY_LAG`,
   `DIFFICULTY_CUT`, `DIFFICULTY_BLOCKS_COUNT`,
   `DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN`; per `DAA_LWMA1.md` §9.2).
4. **Rewire `DIFFICULTY_TARGET_V2` consumers** across the ~14
   sites in 9 files enumerated by `DAA_LWMA1.md` §9.7 to
   `SHEKYL_DAA_TARGET_SECONDS` from
   `shekyl/consensus_constants_generated.h`. Value unchanged
   (still 120); only the source-of-truth moves. The
   `core_rpc_server.cpp:1452 res.block_target` site preserves the
   RPC contract per §9.8.
5. **Delete `CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT`** `#define` in
   `src/cryptonote_config.h:51` (per `DAA_LWMA1.md` §9.2). Rewire
   the two FTL consumers enumerated by `DAA_LWMA1.md` §9.5
   (`blockchain.cpp:4276`, `block_validation.cpp:137`) to
   `SHEKYL_DAA_FTL_SECONDS` from the generated header. **Value
   change 7200 → 540 takes effect at this work item.**
6. **Delete `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW`** `#define` in
   `src/cryptonote_config.h:56` (per `DAA_LWMA1.md` §9.2). Rewire
   the thirteen MTP consumers enumerated by `DAA_LWMA1.md` §9.6
   (eight in `blockchain.cpp`, five in `block_validation.{h,cpp}`)
   to `SHEKYL_DAA_MTP_WINDOW` from the generated header. **Value
   change 60 → 11 takes effect at this work item.**
7. **Delete the `tests/difficulty/` directory** (per
   `DAA_LWMA1.md` §9.1): `difficulty.cpp`, `gen_wide_data.py`,
   `generate-data`. Replaced by Phase 1 Rust unit tests and the
   Phase 2 cross-check harness.
8. **Symbol-isolation CI invariant.** Add a GitHub Actions step
   that runs
   `nm shekyld | rg -q '^.* (T|U) (next_difficulty_64|next_difficulty|check_difficulty_checkpoints)\b'`
   and fails on match. Shares the workflow file with the RandomX
   v2 §7.1 invariant when both have landed; if RandomX v2's
   workflow hasn't landed yet, this PR creates the workflow file
   and the RandomX v2 PR adds to it.
9. **No-C-ABI invariant in `shekyl-difficulty`.** Same
   three-pattern grep as RandomX v2's `shekyl-pow-randomx`
   invariant ([`RANDOMX_V2_RUST.md`](./RANDOMX_V2_RUST.md) §7.2):
   `#\[(?:unsafe\(\s*)?no_mangle(?:\s*\))?\]`,
   `\bextern\s+"C"\s+fn\b`,
   `#\[(?:unsafe\(\s*)?export_name\b`. Same workflow file.
10. **No-orphaned-magic-numbers CI invariant.** Add a workflow
    step that runs
    `git grep -nE 'CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT|BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW|DIFFICULTY_TARGET_V[12]|DIFFICULTY_WINDOW|DIFFICULTY_LAG|DIFFICULTY_CUT|DIFFICULTY_BLOCKS_COUNT|DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN' -- src/ tests/`
    and fails if any non-zero match remains on the post-Phase-4
    tree (modulo the deletion-commit's own diff visible only
    during PR review).
11. **RPC-contract regression test.** Add a test (or extend an
    existing one) that asserts `daemon.get_info().block_target ==
    120` after the cutover, exercising the §9.8 RPC-contract
    preservation property.
12. **Update inherited unit tests.** Any test that consumed
    `next_difficulty`, `DIFFICULTY_TARGET_V2`,
    `CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT`, or
    `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW` directly (rather than via
    the consensus path) is updated to the new symbol name. If
    a test asserted the *old* FTL or MTP value, the test is
    rewritten to assert the new value (the test was testing the
    inherited consensus rule; the rule changed).
13. **Wallet-side touchpoint audit.** Per `DAA_LWMA1.md` §11,
    `src/wallet/wallet2.cpp:181, 182, 5975, 11548` and
    `src/wallet/wallet_rpc_server.cpp:163` consume
    `DIFFICULTY_TARGET_V2`; rewire to `SHEKYL_DAA_TARGET_SECONDS`.
    Value unchanged; no wallet behavior change.
14. **CHANGELOG.md and FOLLOWUPS.md** per
    `91-documentation-after-plans.mdc`. CHANGELOG records the
    consensus-rule changes (FTL 7200 → 540, MTP 60 → 11) as
    consensus deltas, not as internal-refactor entries.

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
  entry that named LWMA-1 as the target).
- **`24-reviewer-discipline.mdc` cross-reference** is conditional
  on the rule's existence and mechanized so the Phase 5 reviewer
  can verify by grep, not by memory:

  ```bash
  if test -f .cursor/rules/24-reviewer-discipline.mdc; then
      # Update DAA_LWMA1.md §12 to cite the rule directly.
      # The §12 "the rule does not yet exist" framing is replaced
      # with a one-line cite plus the existing alignment language.
      echo "rule exists; update §12 to cite directly"
  else
      # Leave DAA_LWMA1.md §12's "rule does not yet exist" framing
      # intact. No cross-reference is added.
      echo "rule absent; §12 framing preserved"
  fi
  ```

  The Phase 5 PR description records which branch the script took
  and links to the resulting §12 state. This makes the conditional
  reviewer-checkable rather than reviewer-remembered.

## Risk and reversibility summary

| Risk | Mitigation | Reversibility |
| --- | --- | --- |
| Spec divergence Rust vs canonical C++ | §8.2 cross-check harness; spec is source of truth | Fix Rust; not revert |
| Wrong N, T, FTL, or MTP value | Phase 0 review ratification; values are typed `const` | Pre-genesis: change const + re-test. Post-genesis: hard fork. |
| LWMA-1 unsuitable for actual Shekyl hashrate profile | §10 reversion clause names criteria; §8.3 corpus stress-tests Shekyl-specific scenarios | Pre-genesis: new design doc per §10. Post-genesis: hard fork. |
| FTL/MTP migration leaves chain in non-canonical intermediate state | Phase 4 migrates all three together; never split across PRs | Phase 4 is atomic; partial-revert is not a supported state |
| Pre-design sketch in `rust/shekyl-difficulty/src/lwma1.rs` accidentally becomes the implementation | Sketch deleted in this PR (commit `91c6dc44c`) per `15-deletion-and-debt.mdc`; §2.4 divergence catalogue retained as design record only; Phase 1 starts from empty crate directory | N/A — sketch no longer exists on disk |

## Phase 0 dispositions (formerly open questions)

Round 4 closes the remaining Phase 0 questions. Carrying open
questions out of Phase 0 into Phase 1 is the design-rounds-in-
implementation-PR anti-pattern; if Phase 1 re-litigates ratified
values, Phase 0 hasn't done its job. The dispositions below have
defensible Phase-0-closeable answers and are now ratified.

- **`GENESIS_DIFFICULTY = 100` — ratified.** Source: zawy12
  canonical example value for new CPU-mineable chains. The
  "Shekyl-specific value derived from RandomX v2 single-CPU
  measurements at the v2 fork pin" alternative referenced a
  measurement that does not exist and cannot exist until
  RandomX v2 is implemented and a CPU-only hashrate sample is
  collected — ratifying-pending-measurement is functionally
  identical to "100 with a documented reversion trigger," which
  is what `DAA_LWMA1.md` §10's reversion clause already provides.
  First-week-of-testnet recalibration, if observed hashrate
  differs materially from canonical assumptions, lands as a
  sibling PR with its own design-doc justification, not as a
  Phase 0 unknown.
- **`N = 90` — ratified.** Source: zawy12 canonical recommendation
  for `T = 120 s` chains, anchored against ~8 years of deployment
  experience on CPU-mineable chains with comparable hashrate
  profiles. The "Shekyl-specific sensitivity analysis on
  bootstrap-regime hashrate volatility" alternative requires
  assumed-hashrate inputs we don't have either; the canonical
  value carries more deployment evidence than any pre-genesis
  Shekyl simulation could provide. `DAA_LWMA1.md` §10's reversion
  clause covers the case where post-genesis simulation reveals
  a materially better `N`.
- **Build.rs location — ratified as Option A** (a new
  `rust/shekyl-difficulty/build.rs`) per `DAA_LWMA1.md` §2.1's
  leaf-crate property and §4's source-of-truth pipeline. Option B
  (extending `shekyl-engine-core/build.rs`) is rejected because
  it introduces a workspace-internal dep purely to consume
  generated constants. If Phase 1 finds Option A creates real
  duplication pain, that's a Phase 1 review-item, not a Phase 0
  unknown. (Closed in Round 3; restated for completeness.)
- **JSON key / C++ symbol naming — ratified as
  algorithm-version-free**: `daa_window_n` /
  `daa_target_seconds` / `daa_ftl_seconds` / `daa_mtp_window` /
  `daa_genesis_difficulty`, with matching `SHEKYL_DAA_*`
  generated symbols. Per `DAA_LWMA1.md` §4 ("Algorithm-version-free
  naming"). The cost-of-rename analysis (algorithm-version-tagged
  names force a downstream rename across every consumer if §10's
  reversion clause fires) closes this in favor of the
  version-free shape. (Closed in Round 3; restated for
  completeness.)
- **Phase 2 cross-check harness language — ratified as C++ test
  target** (`tests/difficulty/lwma1_cross_check.cpp`). The
  canonical reference is C++; consuming it directly is simpler
  than vendoring it into Rust via `build.rs`. The "Rust
  integration test" alternative's only argument was "harness
  lives in the consumer crate's directory tree," which is a
  cosmetic preference, not a property the threat model needs.
  The C++ test-target approach also makes the cross-check
  available to C++ reviewers without a Rust toolchain at audit
  time.

## Round 9 dispositions (zawy12 issue #24 review)

Round 9 reviews [`DAA_LWMA1.md`](./DAA_LWMA1.md) against
[zawy12/difficulty-algorithms#24](https://github.com/zawy12/difficulty-algorithms/issues/24)
("LWMA's history"), the canonical author's cumulative log of
known LWMA issues, fixes, and security-relevant findings. The
review closes the design with explicit dispositions on five
issue items that surfaced during the review pass:

- **Item 3 (window size N=60 vs N=90).** zawy12 issue #24's 2018
  "N ≈ 60" recommendation referred to `T = 60 s` chains; the
  canonical recommendation scales inversely with `T`. For
  Shekyl's `T = 120 s`, `N = 90` gives the same ~90-minute
  window. Disposition: documentation polish only;
  [`DAA_LWMA1.md`](./DAA_LWMA1.md) §4's N parameter row now
  includes the T-scaling note. No algorithm or constant changes.
- **Item 7 (Jagerman MTP patch).** Verified present in Shekyl's
  inherited `Blockchain::create_block_template` at
  `blockchain.cpp:1650–1656` (the canonical `b.timestamp =
  time(NULL); if (!check_block_timestamp(b, median_ts))
  b.timestamp = median_ts;` pattern). The MTP window change from
  60 to 11 preserves the patch's effectiveness; no Phase 4 work
  required. Disposition recorded in
  [`DAA_LWMA1.md`](./DAA_LWMA1.md) §5.5 with code citation. A
  minor doc-vs-code drift at `blockchain.cpp:1540`'s cached-template
  path comment is recorded as a `FOLLOWUPS.md` item, not a
  Phase 4 atomic-cutover work item.
- **Item 9 (±7xT header timestamp limits vs FTL boundary).**
  zawy12 deprecated header-level `±7xT` limits in favor of
  FTL-based defenses once FTL was correctly tuned. Shekyl uses
  MTP + FTL + symmetric solvetime clamp + running-max
  normalization (§5.5) and does *not* implement a separate
  per-block-header `±7xT` rule. With `FTL = 540 s = 4.5*T`, the
  upper bound is tighter than `+7*T = 840 s`, and the lower-bound
  defense moves into the algorithm via §5.3 step 3's `-6*T`
  symmetric clamp. Disposition: documentation only;
  [`DAA_LWMA1.md`](./DAA_LWMA1.md) §5.5 records the non-adoption.
- **Item 14 (September 2018 selfish-mine via out-of-sequence
  timestamps).** Algorithm-level disposition: §5.3 steps 2 and
  3 adopt LWMA-3's running-max + signed-solvetime mechanism and
  symmetric `±6*T` clamp, replacing the kyuupichan-style
  forward-pass-with-1-floor used through Round 8. The remainder
  of the algorithm stays LWMA-1-canonical. Disposition recorded
  in [`DAA_LWMA1.md`](./DAA_LWMA1.md) §1.3 ("Partial LWMA-3
  adoption"), §3 ("Deviation from canonical LWMA-1,
  steps 2 and 3 only"), §5.3 steps 2/3/4 (algorithm rewrite),
  §5.4 ("Signed-arithmetic discipline"), and §8.1
  ("Selfish-mine attack regression"). Phase 1's test corpus
  gains one regression
  vector specifically exercising the September 2018 attack class.
  Phase 2's cross-check harness composes expectations from both
  canonical `LWMA1_()` and `LWMA3_()` references per §8.2.
- **Item 17 (May 2019 33% Sybil attack via peer-time-offset).**
  Closed by absence of substrate. The attack's precondition
  ("If your coin uses network time instead of node local time")
  is not met by Shekyl. Audit-trail evidence: `git grep -E
  'time_offset|TimeOffset|GetAdjustedTime|GetTimeOffset|MAX_PEER_DELTA|MAX_TIME_DELTA|MEDIAN_TIME|TIMESTAMPS_FOR_TIME_SYNC'
  src/` returns zero matches against any consensus-relevant
  surface as of `feat/daa-lwma1-phase0-design` HEAD.
  `Blockchain::check_block_timestamp(b)` compares
  `b.timestamp` against `time(NULL)` directly
  (`blockchain.cpp:4276`); `Blockchain::get_adjusted_time(height)`
  is blockchain-derived (median of recent block timestamps) and
  is consulted only by non-consensus paths (unlock-time leeway,
  RPC display). No `daa_peer_time_revert_threshold_seconds`
  constant is added because no peer-time-correction mechanism
  exists. Disposition recorded in [`DAA_LWMA1.md`](./DAA_LWMA1.md)
  §5.5's "Disposition on peer-time-derived clocks" paragraph,
  with a forward-looking constraint: if a future Shekyl version
  adds peer-time correction, the `FTL / 2` revert-threshold
  relationship per zawy12 issue #24 item 17 becomes load-bearing
  at that point.

Items #1, #2, #4, #5, #6, #10, #12, #15, and #16 were already
addressed prior to Round 9 review:

- **Item 1** (Thaer's negative-solvetime bug, kyuupichan fix):
  superseded by Round 9's partial-LWMA-3 adoption (item 14
  above), which replaces kyuupichan with running-max +
  symmetric clamp.
- **Item 2** (CryptoNote pre-LWMA sort, `DIFFICULTY_LAG`,
  `DIFFICULTY_CUT`): [`DAA_LWMA1.md`](./DAA_LWMA1.md) §9.2
  deletes all three.
- **Item 4** (FTL too high enables timestamp manipulation):
  FTL: 7200 → 540, [`DAA_LWMA1.md`](./DAA_LWMA1.md) §9.5.
- **Item 5** (IPBC signed/unsigned math bug): Rust's type system
  prevents the entire bug class; [`DAA_LWMA1.md`](./DAA_LWMA1.md)
  §5.4 properties explicitly note `u128` (and Round 9's `i128`)
  throughout.
- **Item 6** (vector-size off-by-one, N vs N+1):
  [`DAA_LWMA1.md`](./DAA_LWMA1.md) §5.6 and §6.1 both spell out
  `N+1 == 91` and the chain_height vs block-height distinction.
- **Item 10** (MTP = 11 vs 60): [`DAA_LWMA1.md`](./DAA_LWMA1.md)
  §9.6 documents the value change.
- **Items 12, 15, 16** (LWMA-2/3/4 deprecation):
  [`DAA_LWMA1.md`](./DAA_LWMA1.md) §1.3 considers each and
  rejects with reversion clauses. The Round 9 partial-LWMA-3
  adoption borrows only LWMA-3's step-2-and-3 timestamp-protection
  mechanism; LWMA-3 itself remains rejected per zawy12's January
  2019 deprecation.

## Cross-references

- [`DAA_LWMA1.md`](./DAA_LWMA1.md) — the companion design doc.
- [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) — sibling sequencing
  precedent; this plan's phased shape mirrors its structure.
- [`RANDOMX_V2_RUST.md`](./RANDOMX_V2_RUST.md) — §3 spec source of
  truth, §7 isolation invariants, §9 typed consensus constants,
  §17 FFI error taxonomy. These patterns are reused.
- [`zawy12/difficulty-algorithms#3`](https://github.com/zawy12/difficulty-algorithms/issues/3)
  — canonical LWMA-1 reference.
