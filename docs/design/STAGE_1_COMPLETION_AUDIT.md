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
| PR 7 - C2c cutover (`get_block_reward` wrapper to Rust base-reward FFI) | Landed | `feat/stage-1-pr7-economics-cutover` (off post–7-base `dev`); `cryptonote::get_block_reward` delegates base subsidy to `shekyl_base_block_reward` via `shekyl::base_subsidy_before_penalty` (`src/shekyl/economics.h`); C++ ESF body deleted from `cryptonote_basic_impl.cpp`; see dated section below |
| `EconomicsEngine` trait module (`engine/traits/economics.rs`) | **Open / optional per §8.1 off critical path** | `engine/traits/mod.rs` re-export list has no economics module |

## Audit conclusion

Stage 1's critical-path trait extraction objective is achieved on `dev`:

`DaemonEngine` -> `LedgerEngine` -> (`RefreshEngine` || `PendingTxEngine`)

with `KeyEngine` landed in parallel and `PersistenceEngine` substrate landed.

PR 7 landed the C2/C2a' economics substrate and CI hardening; C2c then
completed the base-emission cutover (see dated section below):

- live C++ base-subsidy computation in `get_block_reward` now delegates to
  `shekyl_base_block_reward` via a thin wrapper (+ release multiplier),
- the duplicated C++ base-subsidy body is retired.

The base-emission migration is delivered for V3.0 pre-genesis.

## Still-open post-Stage-1 follow-through (not "missing Stage 1 PR")

Tracked in `docs/FOLLOWUPS.md` and/or `docs/design/WALLET_REWRITE_PLAN.md`:

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
| C2c economics cutover (`get_block_reward` -> Rust FFI) | Closed (2026-05-30) | `feat/stage-1-pr7-economics-cutover` (PR #93, off post–7-base `dev`); `cryptonote::get_block_reward` (4-arg) delegates the base subsidy to `shekyl_base_block_reward` via `shekyl::base_subsidy_before_penalty` (`src/shekyl/economics.h`); C++ ESF body deleted from `cryptonote_basic_impl.cpp`. Landed as the **standalone 7-cutover PR** per `STAGE_1_PR_7_ECONOMICS_ENGINE.md` §6.2 Option B; H1-H3 satisfied (C2a′ ancestor; dual-leg KAT green). See dated section below |

**Stage 1 disposition:** critical-path trait extraction is complete, and the
last V3.0 pre-genesis economics item — the C2c base-subsidy cutover — has now
landed as its own consensus-path PR (kept out of doc/chore bundling per
`20-rust-vs-cpp-policy.mdc` and `07-consensus-atomic-cutovers.mdc`).

**Tech-debt tracker consolidation (inter-stage cleanup PR #92):** open
structural-debt *tracking* now lives in a single place — `docs/FOLLOWUPS.md`.
The three orphan MSVC/Windows build items (`libunbound` stub, vendored-code
warnings, vcpkg manifest-mode) migrated from `docs/STRUCTURAL_TODO.md` into the
FOLLOWUPS V3.2 section. `STRUCTURAL_TODO.md` is **repurposed** (not deleted)
as a structural-reference / reviewer-rubric doc — it retains the 32-bit
"bit-width carve-out" security argument and migration-on-touch rubric that
`CHANGELOG.md`, `USER_GUIDE.md`, `contrib/depends/README.md`,
`CPP_INHERITANCE_INVENTORY.md`, the four 32-bit tripwire comment blocks, and
`FOLLOWUPS.md` cite as canonical. Git history remains the authoritative
archive.

## C2c cutover landed (2026-05-30)

The base-emission migration (Stage 1 PR 7 §5.8) is complete. C2c, the
7-cutover consensus artifact, branched from the post–7-base `dev` tip
(7-base merge `fed6f594b`; C2a′ ancestor by branch topology, satisfying the
H3 gate) and:

- replaced the duplicated C++ ESF base-subsidy formula in
  `cryptonote::get_block_reward` (4-arg) with a delegation to
  `shekyl_base_block_reward` through the `shekyl::base_subsidy_before_penalty`
  thin wrapper (`src/shekyl/economics.h`), mirroring the `compute_fee_burn` /
  `compute_emission_split` shape;
- deleted the C++ ESF body
  (`(MONEY_SUPPLY - already_generated) >> esf` + tail floor) from
  `src/cryptonote_basic/cryptonote_basic_impl.cpp`;
- left the weight penalty (`mul128` / `div128_64`) and the 5-arg release
  multiplier path in C++, behavior-identical to the C2a′ witnesses.

Per-site target quantities (§5.8 quantity map) were preserved: only the
4-arg definition body (site D) changed; call sites 1–7 are untouched
(signatures unchanged), and fix α (`:1608–1609`) was already landed in
7-base. No production path computes the ESF curve in C++.

Verification (local, Debug build tree): `scripts/ci/run_economics_c2a_prime.sh
all` green (preflight + Layer 1–3, including pop-replay reorg); `block_reward`
+ `mining_parity` unit suites green; `cargo test -p shekyl-economics` green;
`gen_block_low_coinbase` core test green. Leg A of the Layer 1 dual-leg KAT
(`get_block_reward` vs `shekyl_base_block_reward`) remains bit-identical.

## Closure checkpoint — 2026-05-31 (EconomicsEngine trait + 7-parameter orchestrator)

Post-#88 landing recorded per the append-only checkpoint discipline: the
Objective Matrix above is an "as of PR #88" snapshot, so the `EconomicsEngine`
row (then "Open / optional per §8.1 off critical path") is **closed here**
rather than rewritten in place.

| Item | Status on `dev` | Evidence |
| --- | --- | --- |
| `EconomicsEngine` trait module (`engine/traits/economics.rs`) | Closed — Landed (PR #94) | merge `24a342529` (`feat/stage-1-pr7-economics-engine`); `rust/shekyl-engine-core/src/engine/traits/economics.rs`; re-export at `engine/traits/mod.rs:49,57`; `E: EconomicsEngine = LocalEconomics` slot + `economics: E` field at `engine/mod.rs:314,514` |
| Orchestrator type shape | Updated — `Engine<S, D, L, E, R, P, F>` (7 params) | `engine/mod.rs:310-323`; `E` = PR #94 economics slot, `F = WalletFile` = persistence slot |
| "optional persistence/economics trait PRs" (still-open list above) | Closed | persistence trait wired as `F` (PR #83); economics trait wired as `E` (PR #94) |

The economics `E` slot is **added, not wired**: no V3.0 production path invokes
the `EconomicsEngine` trait through the `economics` field (R6 — the base-subsidy
consensus cutover #93 routes `get_block_reward` to the Rust *primitive*
`shekyl_base_block_reward`, not through this trait). The field is carried under
`#[allow(dead_code)]` for struct-shape stability and the eventual Stage 4
`EconomicsActor` handle that replaces it behind the same trait surface.

`KeyEngine` remains the one extracted trait **not** wired into the orchestrator
(`engine/mod.rs` holds `keys: Arc<AllKeysBlob>`, no `K` parameter; `KeyEngine`
is the only `engine/traits/` module not re-exported in `traits/mod.rs`). This is
a deliberate Stage 2 deferral, not missing Stage 1 work — see the `KeyEngine`
inline-integration reversion-clause entry in `docs/FOLLOWUPS.md`.

## Notes for future edits

- Keep this document append-only for closure checkpoints.
