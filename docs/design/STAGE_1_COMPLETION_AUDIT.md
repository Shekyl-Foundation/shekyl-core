# Stage 1 Completion Audit (as of PR #88 on `dev`)

Date: 2026-05-29

## Scope

This audit records what Stage 1 has delivered on `dev`, what remains open,
and which items are no longer "missing Stage 1 PR" work but V3.0/V3.1 follow-
through.

Stage 1 reference substrate:

- `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` (status banner + §8.1 ordering)
- Per-PR design docs under `docs/design/STAGE_1_PR_*`
- `docs/FOLLOWUPS.md` V3.0 wallet-stack section
- `docs/design/WALLET_REWRITE_PLAN.md` (Stage 1 as prerequisite for Phases 1-6)

## Stage 1 Objective Matrix

| Area | Status on `dev` | Evidence |
| --- | --- | --- |
| PR 1 - `DaemonEngine` extraction | Landed | `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` status banner; merged chain references |
| PR 2 - `LedgerEngine` extraction | Landed | `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` status banner + §2.2 notes |
| PR 3 - `KeyEngine` extraction (`M3a-M3e`) | Landed | `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` status banner; `engine/traits/key.rs` |
| PR 4 - `RefreshEngine` extraction | Landed | `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` status banner; `engine/traits/refresh.rs` |
| PR 5 - `PendingTxEngine` extraction | Landed | `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` status banner; `engine/traits/pending_tx.rs` |
| PR 6 - `PersistenceEngine` extraction and file-layer substrate | Landed | merged PR #83; `engine/traits/persistence.rs` |
| PR 7 - Economics C2/C2a' (`base_block_reward`, dual-leg KAT, accumulation harness, CI) | Landed | merged PR #88; `tests/unit_tests/economics_c2a_prime.cpp`, `tests/core_tests/economics_c2a_prime.cpp`, `rust/shekyl-economics/src/emission.rs`, `ci/economics-c2a-prime` checks |
| PR 7 - C2c cutover (`get_block_reward` wrapper to Rust base-reward FFI) | **Open** | `src/cryptonote_basic/cryptonote_basic_impl.cpp` still computes base reward in C++; `shekyl_base_block_reward` exists but current production call sites are tests/FFI only |
| `EconomicsEngine` trait module (`engine/traits/economics.rs`) | **Open / optional per §8.1 off critical path** | `engine/traits/mod.rs` re-export list has no economics module |

## Audit conclusion

Stage 1's critical-path trait extraction objective is achieved on `dev`:

`DaemonEngine` -> `LedgerEngine` -> (`RefreshEngine` || `PendingTxEngine`)

with `KeyEngine` landed in parallel and `PersistenceEngine` substrate landed.

PR 7 landed the C2/C2a' economics substrate and CI hardening. The remaining
economics cutover is the explicit C2c migration item:

- replace live C++ base-subsidy computation in `get_block_reward` with a thin
  wrapper over `shekyl_base_block_reward` (+ release multiplier),
- then retire duplicated C++ base-subsidy body.

That item remains a V3.0 pre-genesis follow-up, not a blocker to recording
Stage 1 closeout status.

## Still-open post-Stage-1 follow-through (not "missing Stage 1 PR")

Tracked in `docs/FOLLOWUPS.md` and/or `docs/design/WALLET_REWRITE_PLAN.md`:

- C2c economics cutover (above)
- P1 async refresh post-pass
- wallet BIP-39 FFI
- optional persistence/economics trait PRs
- economics §3.3 benchmark follow-through

## Closure checkpoint — 2026-05-30 (RefreshEngine P1/P2/P3 + tracker consolidation)

Post-PR-#88 audit re-run after the RefreshEngine follow-ups landed on `dev`.
Ground-truthed against code, not doc claims (per the inter-stage cleanup PR).

| Item | Status on `dev` | Evidence |
| --- | --- | --- |
| P1 - async-path refresh post-pass skipped | Closed (2026-05-29) | `refresh/p1-async-path-post-pass`; `LedgerEngine::apply_scan_result` trait method + `LocalLedger` impl removed; async path routes through `Engine::apply_scan_result` |
| P3 - `apply_scan_result_to_state` `Vec<usize>` discard | Closed (2026-05-29) | Same commit as P1 (shape (b)); discard sites disappeared with the removed trait method |
| P2 - wallet-birthday plumbing into producer start-height | Closed (2026-05-30) | merged PR #91 (`refresh/p2-wallet-birthday-plumbing`); Shape A ledger anchor — `effective_scan_floor` + `ensure_birthday_anchor` in `engine/scan_floor.rs`; producer derives start from anchored `snapshot.synced_height + 1` (TOCTOU-safe; `scan_range_start`/`effective_floor_at_tip` helpers removed in `87264a3a2`) |
| C2c economics cutover (`get_block_reward` -> Rust FFI) | **Still open** | `src/cryptonote_basic/cryptonote_basic_impl.cpp:77-122` still computes base reward in C++; `shekyl_base_block_reward` (`rust/shekyl-ffi/src/lib.rs:797`) exists but no consensus call site wires it. Remains a **standalone 7-cutover PR** per `STAGE_1_PR_7_ECONOMICS_ENGINE.md` §6.2 Option B (bundling rejected); H1-H3 hazards apply |

**Stage 1 disposition unchanged:** critical-path trait extraction is complete;
the sole remaining V3.0 pre-genesis economics item is the C2c cutover, which is
explicitly scoped as its own consensus-path PR (not eligible for doc/chore
bundling per `20-rust-vs-cpp-policy.mdc` and `07-consensus-atomic-cutovers.mdc`).

**Tech-debt tracker consolidation (this PR):** open structural-debt
*tracking* now lives in a single place — `docs/FOLLOWUPS.md`. The three
orphan MSVC/Windows build items (`libunbound` stub, vendored-code warnings,
vcpkg manifest-mode) migrated from `docs/STRUCTURAL_TODO.md` into the
FOLLOWUPS V3.2 section. `STRUCTURAL_TODO.md` is **repurposed** (not deleted)
as a structural-reference / reviewer-rubric doc — it retains the 32-bit
"bit-width carve-out" security argument and migration-on-touch rubric that
`CHANGELOG.md`, `USER_GUIDE.md`, `contrib/depends/README.md`,
`CPP_INHERITANCE_INVENTORY.md`, the four 32-bit tripwire comment blocks, and
`FOLLOWUPS.md` cite as canonical. Git history remains the authoritative
archive.

## Notes for future edits

- Keep this document append-only for closure checkpoints.
- When C2c lands, add a dated section here and update `FOLLOWUPS.md` to close
  the base-emission migration item.
