# DAA LWMA-1 Phase 4 — pre-flight investigation

**Status.** Pre-implementation. The pre-flight commit lands on `dev`
before the Phase 4 implementation branch is cut.

**Base commit.** `dev` at `96555a829a4` (post-Phase-2 merge, PR #52
"feat/daa-lwma1-phase2"). Records the base SHA per
`07-consensus-atomic-cutovers.mdc` criterion 3's
grep-against-base-commit requirement; the Phase 4 PR description
repeats this SHA.

**Branch (forthcoming).** `feat/daa-lwma1-phase4`, cut off `dev` at
the SHA above once this pre-flight lands. Per `06-branching.mdc` rule
2 the branch is short-lived (target: ≤5 working days); per
`07-consensus-atomic-cutovers.mdc` criteria 1–4 the PR itself does not
split (single atomic cutover).

**Scope.** Re-anchors `DAA_LWMA1_PLAN.md` Phase 4's 14-item work
breakdown against the actual structural state on `dev` at
`96555a829a4`, surfaces drift between the plan's enumerated sites and
the current tree, audits the migration against
`16-architectural-inheritance.mdc` and `60-no-monero-legacy.mdc`,
sweeps `docs/FOLLOWUPS.md` for V3.0 items that should co-land, and
prepares the reviewer-map and criterion-mapping artifacts the Phase 4
PR description will reuse verbatim.

**Cross-references.**

- **Plan.** [`DAA_LWMA1_PLAN.md`](./DAA_LWMA1_PLAN.md) Phase 4
  (lines 829–1068) is the binding scope statement for the 14 work
  items.
- **Spec.** [`DAA_LWMA1.md`](./DAA_LWMA1.md) §§9.1–9.8 and §11 are
  the binding file-by-file enumeration.
- **Exception rule.**
  [`.cursor/rules/07-consensus-atomic-cutovers.mdc`](../../.cursor/rules/07-consensus-atomic-cutovers.mdc)
  defines the four-criterion test. LWMA-1 Phase 4 is the rule's
  first invocation per its "Approved invocations" section.
- **CI invariant pattern.**
  [`RANDOMX_V2_RUST.md`](./RANDOMX_V2_RUST.md) §7.1 (symbol
  isolation) and §7.2 (no-C-ABI in verifier crate) are the shape
  the Phase 4 invariants 8/9/10 (per plan) mirror. RandomX v2
  Phase 2f has not landed; Phase 4 creates the workflow file
  fresh (§15 of this doc).
- **Generated header.**
  [`config/consensus_constants.json`](../../config/consensus_constants.json)
  is the JSON authority; the C header
  `build/generated_include/shekyl/consensus_constants_generated.h`
  is the build-time emission consumed by the daemon. The
  `SHEKYL_DAA_*` symbols emitted there are verified in §10 below.

---

## §1 Audit invariants — re-verification on `dev` tip `96555a829a4`

The Phase 2 close-out left five property statements that Phase 4
re-verifies pre-implementation rather than assuming. Each is checked
mechanically against the current tree, not against memory of the
Phase 2 commit landing.

1. **`shekyl-difficulty` crate is in-workspace and exports
   `lwma1_next`.** Phase 1 landed
   `rust/shekyl-difficulty/src/lib.rs` with `pub fn lwma1_next(...)
   -> u128`; Phase 2's FFI shim at
   `rust/shekyl-ffi/src/difficulty_ffi.rs` wraps it as
   `shekyl_difficulty_lwma1_next` returning `i32`. **Verified.**

2. **C ABI surface exists.** The header
   `src/shekyl/shekyl_ffi.h` declares
   `shekyl_difficulty_lwma1_next` and `struct shekyl_u128`, and
   the macros `SHEKYL_DIFFICULTY_OK` / `SHEKYL_DIFFICULTY_ERR_*`.
   **Verified.**

3. **Cross-check harness is wired into `ctest`.**
   `tests/difficulty/lwma1_cross_check.cpp` is built via
   `tests/difficulty/CMakeLists.txt` (gated `if(NOT MSVC)` per the
   Phase 2 Copilot disposition for the `__int128` GCC/Clang
   extension). **Verified.**

4. **`SHEKYL_DAA_*` macros are emitted by the consensus-constants
   generator.** `build/generated_include/shekyl/consensus_constants_generated.h`
   contains `SHEKYL_DAA_WINDOW_N=90`, `SHEKYL_DAA_TARGET_SECONDS=120`,
   `SHEKYL_DAA_FTL_SECONDS=540`, `SHEKYL_DAA_MTP_WINDOW=11`,
   `SHEKYL_DAA_GENESIS_DIFFICULTY=100`. The header explicitly notes
   "Until Phase 4 lands, these macros are emitted but have no C++
   consumer." That note is fulfilled by this PR. **Verified.**

5. **Phase 2 cross-check passes at HEAD.** The §8.1 test corpus
   compares the Rust LWMA-1 (via FFI), zawy12 canonical C++, and
   the Shekyl hybrid C++ across the bring-up / running-average /
   running-max / symmetric-clamp axes, asserting documented
   equality / inequality relations. The Phase 2 PR (#52) merged
   green on `ctest`. **Verified by PR-merge state, not re-run here**
   — the Phase 4 implementation branch re-runs `ctest` at every
   commit per the standard discipline.

---

## §2 §9.1 file-deletion surface — current state and drift finding

`DAA_LWMA1.md` §9.1 enumerates four file-deletion targets:

| Target | Current state at `96555a829a4` | Disposition |
| --- | --- | --- |
| `src/cryptonote_basic/difficulty.cpp` | Present (9 121 bytes, mtime 2026-04-12) | Delete in full |
| `src/cryptonote_basic/difficulty.h` | Present (3 130 bytes) | Delete in full |
| `tests/difficulty/difficulty.cpp` | Present | Delete (inherited DAA tests) |
| `tests/difficulty/gen_wide_data.py` | Present | Delete (inherited test-vector generator) |
| `tests/difficulty/generate-data` | Present | Delete (inherited test-vector data) |

**Drift finding F1 — `tests/difficulty/` is no longer a
wholesale-delete target.** §9.1's text says "delete the
`tests/difficulty/` directory" (line 981 of `DAA_LWMA1_PLAN.md`,
work-item 7). That framing predates Phase 2, which landed three
new artifacts in the same directory:

- `tests/difficulty/lwma1_cross_check.cpp` (Phase 2 harness)
- `tests/difficulty/shekyl_lwma1_hybrid_reference.h` (vendored Shekyl
  hybrid LWMA-1)
- `tests/difficulty/zawy12_lwma1_reference.h` (vendored zawy12
  canonical LWMA-1)

Plus `tests/difficulty/CMakeLists.txt` carries both the
inherited-DAA `difficulty-tests` target and the Phase 2
`lwma1-cross-check` target. Phase 4 deletes only the inherited
files (`difficulty.cpp`, `data.txt`, `generate-data`,
`gen_wide_data.py`, `wide_difficulty.py`) and rewrites
`tests/difficulty/CMakeLists.txt` to drop the `difficulty-tests`
target while preserving `lwma1-cross-check`. The directory itself
stays; the harness stays. The Phase 4 PR's reviewer-map records
this as a **partial directory deletion**, not a wholesale one. §9.1
of the spec doc is amended in a Phase 4 commit (work-item 14 of
the plan, "documentation update") to past-tense the Phase 2 carve-out.

---

## §3 §9.2 `#define`-deletion surface — line-numbers verified, two drift findings

All nine `#define`s enumerated by §9.2 exist at the cited line numbers
in `src/cryptonote_config.h`. The plan-cited lines match exactly:

| Line | Symbol | Value | Disposition |
| --- | --- | --- | --- |
| 51 | `CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT` | `60*60*2` (7 200) | Delete; consumers → `SHEKYL_DAA_FTL_SECONDS` (540). **Consensus-rule change.** |
| 56 | `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW` | `60` | Delete; consumers → `SHEKYL_DAA_MTP_WINDOW` (11). **Consensus-rule change.** |
| 82 | `DIFFICULTY_TARGET_V2` | `120` | Delete; consumers → `SHEKYL_DAA_TARGET_SECONDS` (120, value-unchanged) |
| 83 | `DIFFICULTY_TARGET_V1` | `60` | Delete; no replacement (pre-genesis, dead under `60-no-monero-legacy.mdc`) |
| 84 | `DIFFICULTY_WINDOW` | `720` | Delete; LWMA-1 sources `N` from `SHEKYL_DAA_WINDOW_N` (90) |
| 85 | `DIFFICULTY_LAG` | `15 // !!!` | Delete; LWMA-1 has no lag |
| 86 | `DIFFICULTY_CUT` | `60` | Delete; LWMA-1 has no outlier-cut |
| 87 | `DIFFICULTY_BLOCKS_COUNT` | `DIFFICULTY_WINDOW + DIFFICULTY_LAG` | Delete |
| 95 | `DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN` | `DIFFICULTY_TARGET_V1` | Delete (test alias, dead) |

**Drift finding F2 — `CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V[12]`
depend on the to-be-deleted constants.** §9.2 does not enumerate these
two constants, but `src/cryptonote_config.h:90–91` reads:

```cpp
#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1   DIFFICULTY_TARGET_V1 * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2   DIFFICULTY_TARGET_V2 * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
```

Deleting `DIFFICULTY_TARGET_V1` / `_V2` without addressing these breaks
the build. Phase 4 disposition:

- **`_V1`**: delete entirely. Pre-genesis Monero behavior; dead under
  `60-no-monero-legacy.mdc`.
- **`_V2`**: either inline-rewire to `SHEKYL_DAA_TARGET_SECONDS *
  CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS` at consumer sites, or
  preserve the `#define` with the new RHS. Disposition decision is
  recorded by the Phase 4 PR per the consumer audit in §7 below.

This drift folds into work-item 3 of the Phase 4 plan ("delete the
inherited `DIFFICULTY_*` `#define`s") without expanding the PR scope —
both constants are mechanical downstream of the same deletion. The
followup item at `docs/FOLLOWUPS.md` line ~1019 ("Lens E finding
E.4-C-1 — pre-genesis Rule-60 residue cleanup for `cryptonote_config.h`
DIFFICULTY_* V1 parameters") explicitly notes "V1 parameters disappear
when the algorithm changes," so the drift is anticipated by the
FOLLOWUPS entry but not by the spec doc. The spec doc is amended in a
Phase 4 commit.

**Drift finding F3 — `tests/core_tests/block_validation.cpp` carries
four `next_difficulty(...DIFFICULTY_TARGET_V1)` test sites.** Lines 48,
178, 537, 552 each call `next_difficulty(timestamps,
cummulative_difficulties, DIFFICULTY_TARGET_V1)`. These tests exercise
the inherited algorithm at HF v1 — pre-genesis behavior that does not
exist under `60-no-monero-legacy.mdc`. When `next_difficulty` is
deleted (§9.1) and `DIFFICULTY_TARGET_V1` is deleted (§9.2), these
four sites stop compiling. Disposition: **delete the four test cases
outright**. The tests are inherited-algorithm-against-inherited-target;
both ends of the test no longer exist.

This is consistent with `60-no-monero-legacy.mdc`'s explicit guidance:
"Tests that exercise only Monero-era behavior are deleted or rewritten
against Shekyl's HF1+ rules." Phase 4 deletes (does not rewrite); the
LWMA-1 test surface is the `shekyl-difficulty` crate's Rust unit tests
plus the `lwma1-cross-check` harness, not these inherited C++ test
cases.

---

## §4 §9.4 `next_difficulty` call-site surface — verified exactly

The three blockchain.cpp sites enumerated by §9.4 match exactly at the
plan-cited line numbers:

| Site | Function | Plan line | Actual line | Status |
| --- | --- | --- | --- | --- |
| 1 | `Blockchain::get_difficulty_for_next_block()` | ~965 | 965 | Exact |
| 2 | `Blockchain::check_difficulty_checkpoints()` | ~1021 | 1021 | Exact |
| 3 | `Blockchain::get_next_difficulty_for_alternative_chain()` | ~1325 | 1325 | Exact |

All three rewire to `shekyl_difficulty_lwma1_next` via
`shekyl_ffi.h`. Each site already maintains parallel `timestamps[]`
and `cumulative_difficulties[]` vectors; the rewire is a
function-call substitution plus an `i32` error-code check.

Two reviewer notes:

- **The pre-rewire vectors are `std::vector<uint64_t>` for timestamps
  and `std::vector<difficulty_type>` for cumulative difficulties.**
  `difficulty_type` is `uint64_t` in the inherited code per
  `difficulty.h`. The FFI takes `ShekylU128` (two `u64`s) for the
  cumulative-difficulty inputs. The conversion at the call site is
  mechanical (`{static_cast<uint64_t>(d), 0}` for the lo/hi pair)
  but the conversion site discipline matters: a future
  `difficulty_type` widening to `uint128_t` (currently out of
  scope) would surface here.
- **Comment on line 890** of `blockchain.cpp` references
  `DIFFICULTY_BLOCKS_COUNT`. Comment-only; mechanical cleanup in
  the same commit that deletes the `#define`.

---

## §5 §9.5 FTL consumer surface — verified with cosmetic line drift

| Site | Plan line | Actual line | Drift | Disposition |
| --- | --- | --- | --- | --- |
| `src/cryptonote_core/blockchain.cpp` — `check_block_timestamp_main` | 4276 | 4275 | −1 | Rewire to `SHEKYL_DAA_FTL_SECONDS`. **This is the consensus-rule-change site (7200 → 540).** |
| `tests/core_tests/block_validation.cpp` — `gen_block_big_major_version` fixture | 137 | 137 | 0 | Rewire to `SHEKYL_DAA_FTL_SECONDS`; test fixture margin shrinks 7200+3600 → 540+3600 (still well past FTL) per §9.5's reviewer note |

Per §9.5's reviewer note, the test fixture's assertion must be keyed
to the FTL-violation error code specifically (e.g., `MERROR_VER` with
the `kFutureTimestampViolatesFutureTimeLimit` framing), not to a
generic "block rejected" outcome. The Phase 4 implementation branch
verifies this property at the rewire commit; if the fixture passes
for a generic-rejection reason, the fixture is rewritten so the
post-Phase-4 evidence value is preserved.

Line drift is cosmetic (±1 from intra-Phase-1/2 churn). Not material.

---

## §6 §9.6 MTP consumer surface — verified; thirteen sites confirmed

The §9.6 enumeration claims thirteen sites across three files. Each is
present at approximately the plan-cited line number:

| File | Plan lines | Actual lines | Drift |
| --- | --- | --- | --- |
| `src/cryptonote_core/blockchain.cpp` (8 sites) | 1981, 1985, 4223, 4230, 4240, 4259, 4285, 4293 | 1981, 1985, 4222, 4229, 4239, 4258, 4284, 4292 | 0, 0, −1×6 |
| `tests/core_tests/block_validation.h` (2 sites) | 92, 97 | 92, 97 | 0 |
| `tests/core_tests/block_validation.cpp` (3 sites) | 106, 120, 122 | 106, 120, 122 | 0 |

All thirteen sites rewire to `SHEKYL_DAA_MTP_WINDOW`. The value
change (60 → 11) is the consensus-rule change; it takes effect
simultaneously across all thirteen sites at the work-item-6 commit.

**Drift finding F4 — comment-only references in `blockchain.h` and
`blockchain.cpp`.** Lines 1564, 1597 of `blockchain.h` and lines
1976, 4266 of `blockchain.cpp` reference
`BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW` in doc comments. These are
not consumers (no compilation impact), but the comments become stale
when the symbol is renamed. Mechanical cleanup in the work-item-6
commit; one-line edits.

---

## §7 §9.7 `DIFFICULTY_TARGET_V2` consumer surface — undercount drift finding

`DAA_LWMA1.md` §9.7 claims **~14 consumers across 9 files**. The
post-Phase-2 grep finds **17 daemon-source consumers and additional
test consumers**. Reconciliation:

### Daemon-source consumers (17 total)

| File | Plan lines | Actual lines | Status |
| --- | --- | --- | --- |
| `src/cryptonote_basic/cryptonote_basic_impl.cpp` | 78, 79 | 78, 79 | Plan-enumerated; exact |
| `src/cryptonote_core/blockchain.cpp` | 1020, 1322, 5894 | 1020, 1322, **4239, 4243**, 5893 | **Plan undercounts by 2 (lines 4239, 4243)**; 5894→5893 cosmetic drift |
| `src/cryptonote_core/cryptonote_core.cpp` | 1817, 1829, 1838 | 1817, 1829, 1838 | Plan-enumerated; exact |
| `src/rpc/core_rpc_server.cpp` | 1452 | 1452 | Plan-enumerated; exact (RPC-contract surface, §9.8) |
| `src/daemon/rpc_command_executor.cpp` | 1319, 2039 | 1319, 2039 | Plan-enumerated; exact (display strings) |
| `src/cryptonote_protocol/cryptonote_protocol_handler.inl` | 524 | 524 | Plan-enumerated; exact (sync-progress display) |
| `src/wallet/wallet2.cpp` | 181, 182, 5975, 11548 | 181, 182, 5975, 11548 | Plan-enumerated; exact (per §11) |
| `src/wallet/wallet_rpc_server.cpp` | 163 | 163 | Plan-enumerated; exact (per §11) |
| `src/cryptonote_config.h` | (not enumerated) | 90, 91 | **Drift F2 above** — `CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V[12]` |

**Drift finding F5 — two undercount sites in `blockchain.cpp`.**

- **Line 4239:** the median-shift correction reads `median_ts +=
  (BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW + 1) * DIFFICULTY_TARGET_V2 / 2`,
  inside `check_block_timestamp` (the MTP-adjacent path §9.6 covers).
  The `DIFFICULTY_TARGET_V2` factor scales the median-shift
  correction. The site does both an MTP-window rewire (§9.6) and a
  target-seconds rewire (§9.7) at the same line. Phase 4 work-item 6
  covers MTP; the target-seconds rewire on the same line lands in
  work-item 4 (DIFFICULTY_TARGET_V2 consumer sweep).
- **Line 4243:** the timestamp-adjustment block reads
  `uint64_t adjusted_current_block_ts = timestamps.back() +
  DIFFICULTY_TARGET_V2`. Additional `DIFFICULTY_TARGET_V2` consumer.
  Rewires to `SHEKYL_DAA_TARGET_SECONDS` per work-item 4.

The undercount does not change the §9.7 disposition (rewire-not-delete,
value-unchanged); it changes the **count** the Phase 4 PR description
reports. The PR description records **17 daemon-source sites** rather
than the plan's stated ~14, with the additional sites named explicitly.

### Test consumers (additional drift)

The plan does not enumerate test consumers for `DIFFICULTY_TARGET_V2`.
Post-Phase-2 grep finds:

| File | Lines | Disposition |
| --- | --- | --- |
| `tests/core_tests/block_validation.cpp` | 627 | Rewire to `SHEKYL_DAA_TARGET_SECONDS` (value-unchanged) |
| `tests/core_tests/block_reward.cpp` | 256, 257 | Rewire to `SHEKYL_DAA_TARGET_SECONDS` (value-unchanged) |
| `tests/core_tests/chaingen.h` | 425 | **`current_difficulty_window` dispatches on `hf_ver`** — see §12 below |
| `tests/unit_tests/block_reward.cpp` | 63, 71 | Rewire to `SHEKYL_DAA_TARGET_SECONDS` (value-unchanged) |

The five test consumers rewire to `SHEKYL_DAA_TARGET_SECONDS` at
work-item 4 (mechanical, value-unchanged). The `chaingen.h:425` site is
discussed in §12 below — it's a `60-no-monero-legacy.mdc` cleanup
folded into work-item 4.

### Stall-detection path (cryptonote_core.cpp:1817/1829/1838)

§9.7's reviewer note on `cryptonote_core.cpp:1817–1838` flags that
the math is `T`-dependent (`expected_blocks_per_hour =
3600 / DIFFICULTY_TARGET_V2`) and that **no test exercises the
stall-detection path** per the Round 3 reconnaissance grep. The
plan asks Phase 4 to either (a) confirm coverage exists or (b) add
a minimal regression test. **Disposition for Phase 4:** option
(b) — add a deterministic stall-detection regression test under
`tests/core_tests/` (or `tests/unit_tests/`, per the test-style
fit of the surrounding harness) at work-item 11 (RPC-contract
regression test is the work-item home for "add a test that
exercises a previously-uncovered path during Phase 4"; the
stall-detection test is structurally adjacent). The PR description
records the test addition explicitly. **Reviewer note: this is
new test surface within Phase 4's scope, not "while we're here"
expansion** — it is a property the plan named as a Phase 4
disposition requirement in §9.7's reviewer note.

---

## §8 §9.8 RPC-contract preservation — verified

`src/rpc/core_rpc_server.cpp:1452` exists at the plan-cited line
with the plan-cited text:

```cpp
res.block_target = DIFFICULTY_TARGET_V2;
```

Rewires to `SHEKYL_DAA_TARGET_SECONDS` at work-item 4. **Value is
unchanged (120 before, 120 after).** The RPC wire-contract is
preserved.

The §9.8 regression test — wire-byte-identity comparison of
`get_info` response's `block_target` field pre/post Phase 4 — lands
as work-item 11. The test fixture captures the pre-rewire response
bytes once (at PR-open) and asserts byte-identity at every CI run.
This catches both numeric-value drift (caught by a value-only
assertion) and wire-encoding drift (caught only by byte-identity).
Both layers are required.

---

## §9 §11 wallet-side touchpoint surface — verified

All five wallet-side `DIFFICULTY_TARGET_V2` consumers enumerated by
§11 exist at the plan-cited line numbers:

| File | Plan lines | Actual lines | Status |
| --- | --- | --- | --- |
| `src/wallet/wallet2.cpp` | 181, 182, 5975, 11548 | 181, 182, 5975, 11548 | Exact |
| `src/wallet/wallet_rpc_server.cpp` | 163 | 163 | Exact |

All five rewire to `SHEKYL_DAA_TARGET_SECONDS` at work-item 13.
**Value is unchanged**; the wallet's `DEFAULT_UNLOCK_TIME` and
`RECENT_SPEND_WINDOW` defaults, plus the `seconds_per_block`
arithmetic in `wallet_rpc_server.cpp:163`, produce byte-identical
output pre- and post-rewire. No wallet-state migration needed; the
wallet V3.2 cutover (per `RANDOMX_V2_RUST.md` §14) does not gate
Phase 4 — only the constant's source-of-value changes, not its
numeric value.

---

## §10 `SHEKYL_DAA_*` macros — emission verified

`build/generated_include/shekyl/consensus_constants_generated.h` at
`96555a829a4` emits:

```c
#define SHEKYL_DAA_WINDOW_N           UINT64_C(90)
#define SHEKYL_DAA_TARGET_SECONDS     UINT64_C(120)
#define SHEKYL_DAA_FTL_SECONDS        UINT64_C(540)
#define SHEKYL_DAA_MTP_WINDOW         UINT64_C(11)
#define SHEKYL_DAA_GENESIS_DIFFICULTY UINT64_C(100)
```

Numeric values match `config/consensus_constants.json` and
`DAA_LWMA1.md` §4. The header's own comment block confirms the
Phase 4 wiring intent: "Until Phase 4 lands, these macros are
emitted but have no C++ consumer." That note is fulfilled by the
PR; Phase 4 work-item 14 (CHANGELOG / FOLLOWUPS / spec-doc updates)
amends the comment to past-tense the framing.

The macros' availability at the consumer sites depends on
`shekyl/consensus_constants_generated.h` being on the include path
for `cryptonote_core`, `cryptonote_basic`, `rpc`, `daemon`,
`cryptonote_protocol`, `wallet`, and the affected `tests/` targets.
Verified at build time by `cmake/generate_consensus_constants.py`'s
existing wiring (the FCMP / RCT-type symbols at lines 23–25 of the
generated header are already consumed by these targets via the same
include path).

---

## §11 Architectural-inheritance audit per `16-architectural-inheritance.mdc`

`16-architectural-inheritance.mdc` "Density expectations" section says:
"DAA is data-flow, not secret-touching; expected density: low."
Phase 4's audit confirms this.

For each Phase 4 touchpoint, the four-criterion check applies:

1. Does the touchpoint touch secrets (per `35-secure-memory.mdc`,
   `36-secret-locality.mdc`)?
2. Does it contradict a `30-cryptography.mdc` commitment?
3. Does it contradict `35-secure-memory.mdc`'s wipe-on-drop
   discipline?
4. Does it contradict `36-secret-locality.mdc`'s engine-confinement
   property?

Result for each Phase 4 surface:

- **`difficulty.{h,cpp}` deletion (§9.1).** Hash-comparison utility
  over public block-difficulty values. No secrets. **No finding.**
- **`next_difficulty` rewire (§9.4).** Orchestrates public
  difficulty values (timestamps + cumulative difficulties are public
  block-header content). No secrets. **No finding.**
- **FTL / MTP `#define` removal (§9.2, §9.5, §9.6).** Validates
  block timestamps (public) against system clock. No secrets. **No
  finding.**
- **`DIFFICULTY_TARGET_V2` consumer rewire (§9.7).** Block-time
  constant used in wallet unlock-time math, daemon CLI display
  strings, sync-progress UI, and Poisson-stall detection. None of
  these touch secrets; the wallet's unlock-time math operates on
  public block heights and counters. **No finding.**
- **RPC-contract preservation (§9.8).** Public RPC response field.
  **No finding.**

**Conclusion.** Zero architectural-inheritance findings under
`16-architectural-inheritance.mdc`. The migration is purely
data-flow (consensus values + algorithm), with no intersection
with the secret-locality, secret-memory, or cryptographic-
property surfaces. This matches the rule's density expectation
for DAA-class surfaces.

Per `16-architectural-inheritance.mdc`'s "Discovery cadence"
section, this is the expected outcome for PR 4+ pre-flights once
the discipline has been continuously applied — the audit
**confirms** rather than **discovers**. Phase 4 is the second
post-rule-landing PR to run a pre-flight inheritance audit (the
first being M3a–M3e on the Rust side); both produce the same
"no findings, migration is data-flow" shape for surfaces that
don't intersect the cryptographic substrate.

---

## §12 `60-no-monero-legacy.mdc` applications surfaced by Phase 4

`60-no-monero-legacy.mdc` is the rule that names "pre-genesis
Monero behavior is dead weight, delete don't preserve." Phase 4's
surface intersects three classes of Monero-era residue:

1. **`DIFFICULTY_TARGET_V1` and `_V1` lock-delta constants.**
   §3 above (drift finding F2) covers the `_V1` deletion; the
   FOLLOWUPS entry at line ~1019 ("Lens E finding E.4-C-1")
   anticipates this. Phase 4 closes E.4-C-1.

2. **`tests/core_tests/block_validation.cpp` lines 48, 178, 537,
   552 — `next_difficulty(..., DIFFICULTY_TARGET_V1)` test cases.**
   §3 above (drift finding F3) covers these. Pre-genesis Monero
   DAA test cases; deleted outright per
   `60-no-monero-legacy.mdc`'s test-deletion guidance.

3. **`tests/core_tests/chaingen.h:425` — `current_difficulty_window`
   dispatches on `hf_ver`.** The function reads:

   ```cpp
   inline uint64_t current_difficulty_window(const std::optional<uint8_t>& hf_ver=std::nullopt){
       return !hf_ver || *hf_ver <= 1 ? DIFFICULTY_TARGET_V1 : DIFFICULTY_TARGET_V2;
   }
   ```

   This is Monero-era hard-fork dispatch (HF v1 → V1 target;
   later → V2 target). Per `60-no-monero-legacy.mdc`: "When you
   encounter `if (version < N)` or `if (hf_version < N)` for any
   Monero-era hard fork, **delete the dead branch** rather than
   maintaining it." The disposition is: simplify the function to
   return `SHEKYL_DAA_TARGET_SECONDS` unconditionally, or
   inline-substitute at the function's call sites and delete the
   function entirely. The decision rests on the call-site count
   (a single-use helper inlines cleanly; multi-use justifies the
   simplified wrapper). The Phase 4 implementation branch grep-
   audits the call sites at the work-item-4 commit.

All three sit inside the Phase 4 surface as enumerated by
§§9.1–9.7; none expand scope beyond what work-items 3, 4, 7, and
12 already cover. They are recorded here as **already-anticipated
applications of `60-no-monero-legacy.mdc`** that Phase 4 closes
mechanically.

---

## §13 `docs/FOLLOWUPS.md` sweep — V3.0 queue and Phase 4 co-landing items

The V3.0 queue (lines 48–1184 of `FOLLOWUPS.md`) was swept for
items that should ride alongside Phase 4 or be explicitly deferred.
Results:

### Phase 4 closes (fully resolves these items)

- **"Difficulty algorithm: replace inherited CryptoNote cut-windowed
  average with LWMA-1"** (lines 891–1085). This is the V3.0
  followup item the entire DAA workstream addresses. Phase 4's
  landing closes the item; the entry moves to **"Recently resolved
  (audit trail)"** at the bottom of `FOLLOWUPS.md` in work-item 14.

- **"Lens E finding E.4-C-1 — pre-genesis Rule-60 residue cleanup
  for `cryptonote_config.h` DIFFICULTY_* V1 parameters"** (line
  ~1019, embedded in the DAA followup). Phase 4 deletes
  `DIFFICULTY_TARGET_V1` and the `_V1` lock-delta constant per §3
  drift finding F2. Item closes alongside the DAA close-out.

### Phase 4 does not touch (V3.0 items deferred)

The V3.0 queue contains 22 other items at the time of this
pre-flight, none of which overlap Phase 4's enumerated surface
(verified by the grep against `blockchain.cpp`,
`cryptonote_config.h`, `block_validation.*`,
`FUTURE_TIME_LIMIT`, `TIMESTAMP_CHECK_WINDOW`, and
`CRYPTONOTE_LOCKED_TX_ALLOWED`). The other V3.0 items address the
refresh / scan / wallet-state surfaces; they are unrelated to the
consensus-rule cutover. **No "while we're here" expansion of
Phase 4's scope per `15-deletion-and-debt.mdc`.**

### Phase 4 creates (new FOLLOWUPS items, if any)

None anticipated at pre-flight time. The Phase 4 surface is
enumeration-bounded; new findings during implementation that fall
outside the enumerated surface fail
`07-consensus-atomic-cutovers.mdc` criterion 3's
scope-bounding and are deferred to a separate PR.

---

## §14 CI invariant infrastructure — workflow file does not yet exist

`DAA_LWMA1_PLAN.md` work-items 8/9/10 add three CI invariants:

- **Item 8 — Symbol-isolation.** Daemon binary contains no
  `next_difficulty_64`, `next_difficulty`, or
  `check_difficulty_checkpoints` exported symbols (verifies the C++
  deletion completed).
- **Item 9 — No-C-ABI in `shekyl-difficulty`.** The Rust crate
  contains no `#[no_mangle]`, `extern "C" fn`, or `#[export_name]`
  declarations (verifies the C ABI lives in `shekyl-ffi`, not the
  algorithm crate).
- **Item 10 — No-orphaned-magic-numbers.** Source tree contains no
  references to the deleted `#define` names (verifies the deletion
  swept all consumers).

The plan says these share a workflow file with the RandomX v2 §7.1
/ §7.2 invariants. **The RandomX v2 workflow file does not yet
exist** — `RANDOMX_V2_PLAN.md` Phase 2f has not landed. Phase 4's
disposition per the plan ("if RandomX v2's workflow hasn't landed
yet, this PR creates the workflow file and the RandomX v2 PR adds
to it") applies; the workflow file is **created fresh** by Phase 4.

Proposed workflow file: `.github/workflows/consensus-invariants.yml`,
co-named to make the future RandomX v2 additions self-locating. The
file's initial scope contains the three Phase 4 invariants;
RandomX v2 Phase 2f appends the symbol-isolation and no-C-ABI checks
for `shekyl-pow-randomx` and the daemon's `randomx_*` symbol
deletion.

The workflow file's naming and structure are recorded here so the
Phase 4 PR doesn't reinvent them mid-review; the structure follows
the established
`.github/workflows/zeroize-check.yml` pattern (single-job,
single-OS-matrix, fast-running).

---

## §15 Reviewer-map for the Phase 4 PR description

Per `07-consensus-atomic-cutovers.mdc` sub-clause 4.3, the PR
description partitions the diff into three categories. This is
the working draft for the Phase 4 PR; the Phase 4 PR description
copies this section verbatim with line numbers updated to match
the actual diff.

### A. Consensus-affecting changes (priority reviewer attention)

These are the changes that alter what nodes accept or compute.
**A reviewer who sees substantive consensus changes outside this
subsection has identified a map-failure (criterion 4.3 enforcement
clause); the response is to re-open the PR with corrected
enumeration, not to amend the map mid-review.**

| Site | Change | Consensus property |
| --- | --- | --- |
| `src/cryptonote_core/blockchain.cpp:965` | `next_difficulty` → `shekyl_difficulty_lwma1_next` | Algorithm change |
| `src/cryptonote_core/blockchain.cpp:1021` | Same | Algorithm change |
| `src/cryptonote_core/blockchain.cpp:1325` | Same | Algorithm change |
| `src/cryptonote_core/blockchain.cpp:4275` | `CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT` → `SHEKYL_DAA_FTL_SECONDS` | **FTL value change (7200 → 540)** |
| `src/cryptonote_core/blockchain.cpp:1981, 1985, 4222, 4229, 4239, 4258, 4284, 4292` | `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW` → `SHEKYL_DAA_MTP_WINDOW` | **MTP value change (60 → 11)** |
| `tests/core_tests/block_validation.cpp:137` | FTL fixture rewire | FTL value-change test impact (assertion keyed to FTL-violation error code per §5) |
| `tests/core_tests/block_validation.h:92, 97` + `tests/core_tests/block_validation.cpp:106, 120, 122` | MTP fixture rewire | MTP value-change test impact |
| `src/cryptonote_basic/difficulty.{h,cpp}` | Full deletion | Algorithm body removed |
| `src/cryptonote_config.h:51, 56, 82–87, 95` | Nine `#define`s deleted | Value source removed; consumers rewire |

### B. Mechanical changes (rewire-only, value-unchanged)

| Site | Change | Property |
| --- | --- | --- |
| `src/cryptonote_basic/cryptonote_basic_impl.cpp:78, 79` | `DIFFICULTY_TARGET_V2` → `SHEKYL_DAA_TARGET_SECONDS` | Value-unchanged (120) |
| `src/cryptonote_core/blockchain.cpp:1020, 1322, 4239, 4243, 5893` | Same | Value-unchanged |
| `src/cryptonote_core/cryptonote_core.cpp:1817, 1829, 1838` | Same; stall-detection math `T`-dependent but `T` unchanged | Value-unchanged |
| `src/rpc/core_rpc_server.cpp:1452` | Same (RPC `block_target` field) | Value-unchanged; wire-contract preserved (§9.8 test) |
| `src/daemon/rpc_command_executor.cpp:1319, 2039` | Same (CLI display) | Value-unchanged |
| `src/cryptonote_protocol/cryptonote_protocol_handler.inl:524` | Same (sync UI) | Value-unchanged |
| `src/wallet/wallet2.cpp:181, 182, 5975, 11548` | Same (wallet unlock-time / spend-window math) | Value-unchanged |
| `src/wallet/wallet_rpc_server.cpp:163` | Same (wallet RPC) | Value-unchanged |
| `src/cryptonote_config.h:90–91` (drift F2) | `CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V[12]` deletion / rewire | Value-unchanged for `_V2`; `_V1` is dead per `60-no-monero-legacy.mdc` |
| `tests/core_tests/block_reward.cpp:256, 257` | Same | Value-unchanged |
| `tests/core_tests/block_validation.cpp:627` | Same | Value-unchanged |
| `tests/unit_tests/block_reward.cpp:63, 71` | Same | Value-unchanged |
| `tests/core_tests/chaingen.h:425` | `current_difficulty_window` simplified / inlined per §12 | Value-unchanged for HF≥2 path; HF=1 branch deleted |
| `src/cryptonote_core/blockchain.h:1564, 1597` + `blockchain.cpp:890, 1976, 4266` | Comment-only updates (stale-symbol references) | No compilation impact |
| `tests/difficulty/CMakeLists.txt` | Drop `difficulty-tests` target; preserve `lwma1-cross-check` | Build-system surface |

### C. Deletions

| Path | Reason |
| --- | --- |
| `src/cryptonote_basic/difficulty.cpp` | Inherited DAA implementation; replaced by `shekyl-difficulty` |
| `src/cryptonote_basic/difficulty.h` | Header for the above |
| `tests/difficulty/difficulty.cpp` | Tests for the inherited DAA; replaced by Rust unit tests + cross-check harness |
| `tests/difficulty/gen_wide_data.py` | Inherited test-vector generator |
| `tests/difficulty/generate-data` | Inherited test-vector data |
| `tests/difficulty/data.txt` | Inherited test-vector data |
| `tests/difficulty/wide_difficulty.py` | Inherited test-vector generator |
| `tests/core_tests/block_validation.cpp:48, 178, 537, 552` | Pre-genesis `next_difficulty(V1)` test cases; dead per `60-no-monero-legacy.mdc` |

### D. New artifacts

| Path | Purpose |
| --- | --- |
| `.github/workflows/consensus-invariants.yml` | Symbol-isolation + no-C-ABI + no-orphaned-magic-numbers CI invariants (§14) |
| `tests/core_tests/<rpc_contract_block_target_test>.{h,cpp}` (or equivalent) | RPC-contract wire-byte regression test (§9.8) |
| Stall-detection regression test (location TBD by Phase 4 work-item-11 implementation per §7's stall-detection note) | Coverage for `cryptonote_core.cpp:1817–1838` |

---

## §16 Criterion-mapping for `07-consensus-atomic-cutovers.mdc`

Per sub-clauses 4.1–4.4 of the rule, the Phase 4 PR description
contains this section verbatim.

- **Rule citation (4.1).** This PR invokes
  `07-consensus-atomic-cutovers.mdc`. The history-entry commit
  adding this PR to the rule's "Approved invocations" section
  lands in the same PR (rule sub-clause 4.1).

- **Per-criterion justification (4.2).**

  1. **Criterion 1 — consensus-rule boundary.** Met. The PR
     changes the FTL value (7 200 → 540), the MTP window value
     (60 → 11), and the difficulty-computation algorithm. All
     three are consensus-rule values/behavior that
     correctly-implementing nodes must reproduce byte-identically
     on the same input.
  2. **Criterion 2 — indivisible under flag decomposition.** Met
     structurally per the rule's criterion-2 framing: a flag that
     gates consensus behavior cannot be simultaneously valid in
     both states, so no flag decomposition produces
     consensus-safe intermediates for any of the three changes.
  3. **Criterion 3 — surface enumerated in advance, with
     evidence.** Met. `DAA_LWMA1.md` §§9.1–9.8 (linked from this
     pre-flight's §§2–9) enumerate every consensus-affecting
     symbol, file, and constant. This pre-flight (§§2–13)
     verifies the enumeration against the base commit
     `96555a829a4`, surfaces five drift findings (F1–F5), and
     records the consolidated enumeration with line-number
     accuracy for the Phase 4 PR description's reuse.
  4. **Criterion 4 — disposition documented in PR with
     reversibility plan.** Met by sub-clauses 4.1 (this rule's
     citation), 4.2 (this section), 4.3 (§15 reviewer-map), and
     4.4 (§17 rollback procedure).

- **Reviewer-map (4.3).** §15 of this pre-flight document is the
  reviewer-map source; the Phase 4 PR description copies it
  verbatim with line numbers updated to match the actual diff.

- **Rollback procedure (4.4).** §17 of this pre-flight document
  is the rollback-procedure source; the Phase 4 PR description
  copies it verbatim.

---

## §17 Rollback procedure (for sub-clause 4.4)

If the Phase 4 PR lands and consensus breaks post-merge, the
rollback is the inverse of the reviewer-map diff. The procedure is
executable as-written by a reviewer who has not seen the PR
before; sub-clause 4.4 requires this property.

**Threshold for rollback.** Phase 4 reversion is invoked when (a)
the daemon fails to validate canonical block headers it accepted
before the merge, or (b) the §9.8 RPC-contract regression test
fails post-merge with byte-disagreement on the `block_target`
field. Either condition is sufficient. A consensus-rule change is
the kind of change that breaks consensus when it breaks; partial
recovery is not a meaningful state.

**Procedure.**

1. **Revert the Phase 4 merge commit.** `git revert -m 1
   <merge-commit-sha>` against the `dev` branch in a hotfix
   short-lived branch named `hotfix/daa-lwma1-phase4-revert`.
   The revert restores `src/cryptonote_basic/difficulty.{h,cpp}`,
   restores the nine `#define`s in `src/cryptonote_config.h`,
   un-rewires the three `next_difficulty` blockchain.cpp call
   sites, un-rewires the FTL/MTP/`DIFFICULTY_TARGET_V2`
   consumers, restores the deleted `tests/difficulty/` files,
   restores the four deleted `next_difficulty(V1)` test cases in
   `tests/core_tests/block_validation.cpp`, and reverts the
   CI-invariant workflow additions.

2. **Re-run `ctest` against the post-revert tree.** The
   restored inherited DAA's test corpus should pass; if it
   does not, the daemon's build is broken in addition to the
   consensus issue, and the revert is itself incomplete.

3. **File a new design review** revisiting `DAA_LWMA1.md` §1.4
   (reversion criterion 1: a Shekyl-specific simulation
   demonstrates LWMA-2 or LWMA-4 has materially better behavior
   under Shekyl's hashrate profile). The revert restores the
   inherited algorithm; the next design pass decides whether
   the next attempt is LWMA-1 with the discovered fix, a
   different LWMA variant, or a non-LWMA replacement.

4. **Do not re-attempt Phase 4 without addressing the failure
   root cause in a new design doc.** The "bar for reverting is
   serious" framing in `DAA_LWMA1_PLAN.md` Phase 4
   ("Reversibility" subsection) applies; a re-attempt without
   root-cause analysis is the failure mode the discipline exists
   to prevent.

The rollback procedure does not require the PR author's tacit
knowledge to apply. Sub-clause 4.4's enforcement clause is met.

---

## §18 Commit decomposition for the Phase 4 branch

`07-consensus-atomic-cutovers.mdc` relaxes the *PR* splitting
guidance but not the commit-level scope discipline from
`90-commits.mdc`: "within the PR, commits still respect
single-purpose scope per the commit rule." Phase 4's recommended
commit decomposition:

1. **Add `.github/workflows/consensus-invariants.yml`** with the
   three invariants (items 8, 9, 10 from the plan). Lands first
   so the invariants are active for the subsequent commits' CI
   runs. The "no-orphaned-magic-numbers" check is initially
   permissive (greps against the pre-cutover tree would fail
   it); the check is gated behind a marker the plan-driven
   commits below clear.

2. **Add the RPC-contract regression test** (work-item 11,
   §9.8). Lands before the rewire so the pre-cutover wire bytes
   are captured as the fixture's pinned-state.

3. **Add the stall-detection regression test** (§7 disposition).
   Lands before the §9.7 consumer sweep so the post-rewire test
   asserts the value-preserving property.

4. **Rewire `next_difficulty` call sites** (work-item 1; three
   blockchain.cpp sites). FFI-substitution commit; no `#define`
   removal yet.

5. **Rewire FTL consumers** (work-item 5; two sites). Value
   change 7 200 → 540 takes effect here.

6. **Rewire MTP consumers** (work-item 6; thirteen sites). Value
   change 60 → 11 takes effect here.

7. **Rewire `DIFFICULTY_TARGET_V2` consumers** (work-item 4;
   ~17 daemon-source sites + 5 test sites). Value-unchanged
   mechanical sweep; includes the drift-F2 `_V2` lock-delta
   rewire and the drift-F5 4239/4243 additions; includes the
   §12 `chaingen.h:425` `60-no-monero-legacy.mdc` cleanup.

8. **Delete inherited `#define`s** in `cryptonote_config.h`
   (work-items 3, 5, 6; nine main defines + the `_V1` lock-delta).
   Build-broken commit (transient): the deletion compiles only
   after steps 4–7 have completed the rewires. Lands here in
   commit-history order so the deletion is its own
   commit, not folded into a rewire.

9. **Delete `src/cryptonote_basic/difficulty.{h,cpp}`**
   (work-item 2). Final consensus-affecting deletion.

10. **Delete inherited `tests/difficulty/` files and `tests/core_tests/block_validation.cpp` V1 cases** (work-items 7, 12; drift F1, F3). Includes the `tests/difficulty/CMakeLists.txt` reduction to keep `lwma1-cross-check` only.

11. **Documentation pass** (work-item 14). `CHANGELOG.md` entry
    (consensus-delta framing), `FOLLOWUPS.md` close-record for
    the V3.0 DAA item, `DAA_LWMA1.md` and `DAA_LWMA1_PLAN.md`
    amendments for the drift findings F1–F5 above, and the
    `07-consensus-atomic-cutovers.mdc` "Approved invocations"
    history-entry commit.

Each commit's message subject is ≤72 chars per `90-commits.mdc`;
body cites the work-item number and the spec section per the rule.

---

## §19 Open questions

None at pre-flight close. All Phase 4 dispositions are resolved
from the plan + spec doc + this pre-flight's drift findings.
Implementation begins on `feat/daa-lwma1-phase4` after this
pre-flight commits to `dev`.

If implementation surfaces a finding outside this pre-flight's
scope, the disposition (per
`07-consensus-atomic-cutovers.mdc` "Compensating discipline when
the exception is invoked"):

- **In-scope surfaces** (anything covered by §§2–13 of this doc):
  the implementation commits absorb the finding without amending
  this pre-flight.
- **Out-of-scope surfaces** (anything that would expand the
  enumerated surface beyond §§2–13): the PR loses the exception
  and is re-opened against the standard `06-branching.mdc` size
  guidance. Scope creep within an exception-invoking PR is
  grounds for rejecting the PR, not for re-arguing the exception.

---

## §20 Pre-flight commit and Phase 4 branch creation

This pre-flight doc lands on `dev` in a single commit per
`06-branching.mdc` default workflow (one new file, under 200
lines of *change* — the doc is large but the change is "create
this file"; the workflow's branch-or-no-branch threshold counts
diff-touched lines, and a single new doc file doesn't accumulate
the diff complexity that justifies a short-lived branch).

After the pre-flight lands:

1. Cut `feat/daa-lwma1-phase4` off `dev` at the pre-flight's
   landing SHA.
2. Execute the §18 commit decomposition.
3. Open the Phase 4 PR with the description structured per
   §§15–17 of this doc (reviewer-map verbatim from §15,
   criterion-mapping verbatim from §16, rollback procedure
   verbatim from §17).
4. Add the history-entry commit to
   `.cursor/rules/07-consensus-atomic-cutovers.mdc`'s "Approved
   invocations" section as part of the Phase 4 PR (sub-clause
   4.1's self-anchoring requirement).
