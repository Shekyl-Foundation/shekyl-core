---
name: Electrum-words removal — CryptoNote 25-word mnemonic subsystem deletion
overview: "Delete the inherited CryptoNote 25-word `Electrum-style` mnemonic subsystem from `shekyl-core` and migrate the active consumer (`shekyl-gui-wallet`) to the existing BIP39 path. Genesis-time landing per `60-no-monero-legacy.mdc` (no Monero legacy from genesis), `16-architectural-inheritance.mdc` (inherited architecture migrates when it contradicts the threat model), and `15-deletion-and-debt.mdc` (pre-genesis discount). Audit origin: Phase 0 Mission Audit Lens B finding B-1; disposition `b1_disposition_settled_delete` (DELETE, not retain) made by user fiat (`GUI/mobile WILL route through BIP39`). Companion substrate: [`ELECTRUM_WORDS_REMOVAL.md`](./ELECTRUM_WORDS_REMOVAL.md). Phase 0 produces both docs; implementation cascades through Phase 1 (wallet2 internal rewire with Phase-1-hard-error on non-empty language parameter), Phase 2 (RPC surface deletion), Phase 3 (FFI surface deletion + cross-repo atomic cutover with shekyl-gui-wallet), Phase 4 (wallet2 core method + field deletion in 3-commit decomposition), Phase 5 (`src/mnemonics/` subsystem deletion + tests + CMake), Phase 6 (docs + CI invariants). Each phase is a separate PR per `06-branching.mdc`. B-1 is a parallel track to Stage 1 PR 4 (Refresh Engine) and PR 5 (Pending TX Engine); merge-conflict surface at `wallet2.cpp` is empirically zero per §1 sequencing check."
todos:
  - id: phase0-design
    content: "Phase 0: Write docs/design/ELECTRUM_WORDS_REMOVAL.md AND docs/design/ELECTRUM_WORDS_REMOVAL_PLAN.md. Cover: (a) inheritance disposition per `60-no-monero-legacy.mdc` + `16-architectural-inheritance.mdc`; (b) deletion surface inventory across `src/mnemonics/` (21 files), `wallet2` (8 methods + 1 field + JSON ser/de), RPC surface (4 commands), FFI surface (3 functions + 2 param drops), tests, CMake; (c) BIP39 replacement path via existing `shekyl_account_generate_from_bip39` + `shekyl_bip39_*` FFI bridge (verified to exist as of 2026-05-19); (d) per-consumer migration map: shekyl-gui-wallet (active consumer; substantial migration), shekyl-mobile-wallet (future consumer; no migration), shekyl-web (not a consumer; no migration); (e) permanent architectural decisions: BIP39-only from genesis, wallet2::generate() retains orchestrator role (disposition (a) from Round 1 review), Phase 1 hard-error on non-empty language parameter (not silently-ignored — production-software graceful-degradation default leak inverted), seed_language field removed, query_key string-key kept as `mnemonic` with routing changed to Rust BIP39, no 25-word fallback, cross-boundary zeroization contract for BIP39 phrase; (f) cross-repo coordination: atomic-with-justified-exceptions default (staged cutover requires explicit named third-party dependency justification), coordinated dev-tip merge for pre-genesis with commit-revert as reversion mechanism, post-genesis paired-signed-tag mechanism documented as forward template; (g) alternatives considered with explicit reversion clauses per `21-reversion-clause-discipline.mdc`; (h) test surface: nm symbol-isolation invariants, git grep no-orphans invariants, BIP39 round-trip tests, memory-residency invariant per KEY_ENGINE.md §7.5 audit pattern, zero-production-keyfile confirmation; (i) reviewer-discipline framing (no external-audit dependency; BIP39 is well-vetted industry standard; Phase 0 design + author review is audit-of-record). Target close: 4-6 review rounds per `20-rust-vs-cpp-policy.mdc`."
    status: in_progress
  - id: phase1-wallet2-internal-rewire
    content: "Phase 1: Rewire wallet2::generate() and wallet2::restore() Electrum-words branches (src/wallet/wallet2.cpp:600-669) to call shekyl_account_generate_from_bip39 / shekyl_bip39_mnemonic_to_pbkdf2_seed instead of crypto::ElectrumWords::*. Behavior at wallet2::create_wallet FFI surface: the `language` parameter is preserved in signature (no FFI ABI break at Phase 1) but the implementation returns a hard error (not silently-ignored) on any non-empty value — empty/None/nullptr is the only accepted value. wallet2_ffi.cpp:648 query_key(\"mnemonic\") dispatch returns the BIP39 phrase derived from the wallet's seed material (substrate §4.5 routing decision). Add tests/unit_tests/wallet_bip39.cpp (BIP39 round-trip tests per substrate §7.3) and tests/unit_tests/wallet_bip39_residency.cpp (cross-boundary zeroization invariant per substrate §7.4). Delete the #include `mnemonics/electrum-words.h` from wallet2.cpp:79 (other consumers still need it until their phases). Multi-commit decomposition: (1) wallet2::generate/restore rewire to BIP39; (2) query_key(\"mnemonic\") routing change; (3) hard-error on non-empty language parameter at create_wallet/generate_from_keys FFI level; (4) BIP39 round-trip + memory-residency tests. PR scope: shekyl-core only. No consumer impact requiring coordination (shekyl-gui-wallet sees hard-error at runtime, fixes its callers in Phase 3 PR). Branch: `feat/electrum-words-removal-phase1-wallet2-rewire` off dev."
    status: pending
  - id: phase2-rpc-deletion
    content: "Phase 2: Delete the Electrum-words RPC surface. Drop COMMAND_RPC_GET_LANGUAGES (wallet_rpc_server_commands_defs.h:2074), COMMAND_RPC_RESTORE_DETERMINISTIC_WALLET (:2223), and the language-validation branches in wallet_rpc_server.cpp at lines 3661, 4082, 4162-4225, 2324-2358 (Electrum-words restore paths). Delete the get_wallet_words handler at wallet_rpc_server.cpp:2214,2220. Drop the COMMAND_RPC_QUERY_KEY mnemonic-string-routing branch only if a Rust-routed BIP39 dispatch lands in the same PR (otherwise defer the dispatch-branch deletion to Phase 4 alongside wallet2::get_seed deletion). Delete the #include `mnemonics/electrum-words.h` from wallet_rpc_server.cpp:64. PR scope: shekyl-core only. No consumer impact: the project's Rust wallet-rpc-server (`rust/shekyl-rpc-server`) does not bind these legacy RPC commands. Multi-commit decomposition: (1) delete restore-deterministic-wallet RPC + helper functions; (2) delete get-languages + set-language RPC; (3) delete wallet-words handler; (4) cleanup include. Branch: `feat/electrum-words-removal-phase2-rpc-deletion` off dev."
    status: pending
  - id: phase3-ffi-deletion-cross-repo-cutover
    content: "Phase 3: FFI surface deletion + cross-repo atomic cutover with shekyl-gui-wallet. This is the load-bearing phase per substrate §5. shekyl-core PR deletes: wallet2_ffi_restore_deterministic_wallet (wallet2_ffi.h:98-104 + wallet2_ffi.cpp:414-431), the `language` parameter on wallet2_ffi_create_wallet (signature change), the `language` parameter on wallet2_ffi_generate_from_keys (signature change), the language-list export at wallet2_ffi.cpp:1197-1198, and all crypto::ElectrumWords::* calls in wallet2_ffi.cpp. Delete #include `mnemonics/electrum-words.h` from wallet2_ffi.cpp:38. shekyl-gui-wallet PR (in the shekyl-gui-wallet repo, coordinated sibling) deletes: src-tauri/src/wallet_bridge.rs::create_wallet language parameter (signature becomes create_wallet(wallet_path, password)), src-tauri/src/wallet_bridge.rs::restore_deterministic_wallet wrapper (replaced with a wrapper around the new BIP39 entry that the shekyl-core side now provides via existing shekyl_account_generate_from_bip39), src-tauri/src/commands.rs `language: Option<String>` parameters on import/create/restore flows, `seed_language: String` field on SeedInfo struct, UI flows that show seed-language picker. Cutover mechanism: coordinated dev-tip merge per substrate §5.3. Both PRs run CI to green; same-day merge to dev in both repos; shekyl-gui-wallet's shekyl-core pin updates to the post-merge dev SHA after shekyl-core merges. Reversion mechanism: commit-revert in coordinated order per substrate §5.4. Pre-flight: empirical verification that PR 4 (Refresh Engine) and PR 5 (Pending TX Engine) have not touched the wallet2_ffi.cpp deletion sites — `git log --oneline -- src/wallet/wallet2_ffi.cpp` since this PR's branch-cut, audit for refresh / pending-tx work; if clean, proceed; if conflict surface exists, rebase against dev tip. Branch: `feat/electrum-words-removal-phase3-ffi-cutover` off dev. shekyl-gui-wallet branch: `feat/electrum-words-removal-bip39-migration` off shekyl-gui-wallet's dev."
    status: pending
  - id: phase4-wallet2-core-deletion
    content: "Phase 4: wallet2 core method + state + JSON ser/de deletion. Three-commit decomposition per substrate §6 Spec-Gap-6 disposition: (Commit A) wallet2 method deletion — drop is_deterministic, get_seed, get_seed_language, set_seed_language from wallet2.h (lines 1001-1011) + wallet2.cpp (lines 1362, 1372, 1425, 1433). Each commit green independently; bisect-clean. (Commit B) JSON ser/de drop — delete seed_language from wallet2.cpp:4793-4802 (write) and :5344-5347 (read). Field is now in-memory-only state. (Commit C) seed_language field deletion — drop field from wallet2.h:1728 and all in-memory references. Also at this phase: delete the `query_key(\"mnemonic\")` dispatch branch in wallet2_ffi.cpp if not already handled in Phase 1 (the dispatch returns a BIP39 phrase via Rust routing post-Phase-1 per substrate §4.5; Phase 4 removes the branch entirely since `wallet2::get_seed` no longer exists). Also: delete legacy CryptoNote-25-word comment at wallet2.cpp:6479. PR 5 (Pending TX Engine) stabilization gate: before branch-cut, verify PR 5 has merged or has not touched wallet2.cpp lines 1300-1450 (the method-deletion region) or wallet2.h around line 1000-1011. If conflict surface exists, rebase against dev tip after PR 5 lands. PR scope: shekyl-core only. No consumer impact (Phase 3 already migrated the only active consumer). Branch: `feat/electrum-words-removal-phase4-wallet2-core` off dev."
    status: pending
  - id: phase5-mnemonics-subsystem-deletion
    content: "Phase 5: Delete the src/mnemonics/ subsystem entirely. 21 files removed (14 language word-list headers + 4 framework files + 1 implementation pair + 1 CMakeLists + 1 unit test file in tests/unit_tests/mnemonics.cpp). Update src/CMakeLists.txt to drop `add_subdirectory(mnemonics)`; update src/wallet/CMakeLists.txt to drop `mnemonics` from link dependencies if listed; update tests/unit_tests/CMakeLists.txt to drop `mnemonics.cpp` from test sources. Verify the build is green with `mnemonics` library completely removed (no transitive consumers; per pre-flight grep on `crypto::ElectrumWords::` only wallet2.cpp + wallet2_ffi.cpp + wallet_rpc_server.cpp + the mnemonics/ subsystem itself touch it, all of which are handled by Phase 4 or this phase). Multi-commit decomposition: (1) delete src/mnemonics/ directory; (2) update CMakeLists.txt files; (3) delete tests/unit_tests/mnemonics.cpp; (4) verify build green. PR scope: shekyl-core only. Branch: `feat/electrum-words-removal-phase5-mnemonics-deletion` off dev."
    status: pending
  - id: phase6-docs-and-ci-invariants
    content: "Phase 6: Documentation pass per `91-documentation-after-plans.mdc` + CI invariants per substrate §7. Update docs/CHANGELOG.md with a comprehensive `### Removed` entry under `## [Unreleased]` documenting the Electrum-words subsystem removal across Phases 1-5 (cite the PRs by number). Audit docs/USER_GUIDE.md, docs/SHEKYLD_PREREQUISITES.md, docs/DESIGN_CONCEPTS.md (or equivalents) for any references to Electrum-words / 25-word mnemonic / seed-language picker / language list; update to reflect BIP39-only seed flow. Add tests/symbol_isolation/electrum_words_removed.sh CI script: runs `nm` against build artifacts; greps for the substrate §7.1 symbol list; fails build if any match. Add tests/grep_invariants/electrum_words_no_orphans.sh CI script: runs `git grep -E` for the substrate §7.2 identifier list; fails build if any non-allowlisted match. Wire both into the CI runner config. Update docs/FOLLOWUPS.md to mark the B-1 finding as closed (cite Phase 1-6 merge SHAs). PR scope: shekyl-core only. Branch: `feat/electrum-words-removal-phase6-docs-ci-invariants` off dev."
    status: pending
isProject: false
---


# Electrum-words removal — multi-phase plan

## Sequencing rationale

B-1 (Electrum-words removal) is **independent** of the Stage 1
Rust-migration PR series (Refresh Engine, Pending TX Engine,
Key Engine, etc.) and **independent** of the wallet2 cluster
(B-2/C-1/C-3/C-4/C-5 stop-gap migration) and the B-3
architectural workstream (Rust owns wallet-file orchestration).
The independence is by inspection:

- **Stage 1 PR 4 (Refresh Engine)** touches `wallet2.cpp` refresh
  paths and `wallet2_ffi.cpp` refresh-related FFI surface. B-1
  touches `wallet2.cpp` mnemonic/seed-management paths (lines
  600–669 generate/restore branches; 1362–1435 method bodies;
  4793–4802 + 5344–5347 JSON ser/de) and `wallet2_ffi.cpp`
  generate/restore/query_key surface. **Functional non-overlap;
  merge-conflict surface empirically zero**, verified at each
  phase's branch-cut.

- **Stage 1 PR 5 (Pending TX Engine)** touches `wallet2.cpp`
  transfer-pipeline paths and `wallet2_ffi.cpp` transfer FFI
  surface. B-1 does not touch transfer paths. **Functional
  non-overlap.**

- **wallet2 cluster (B-2/C-1/C-3/C-4/C-5)** is the stop-gap
  migration of password-KDF / sign-message / encrypt-decrypt /
  cn_fast_hash domain-separation paths. B-1 is the Electrum-words
  deletion path. No shared call sites; no shared FFI surface.

- **B-3 architectural workstream** (Rust owns wallet-file
  orchestration) is the longer-term migration that subsumes the
  wallet2 cluster's stop-gap shapes. B-1's `wallet2::generate()`
  disposition (a) — retain orchestrator role — is itself a stop-gap
  for the B-3 architectural target. When B-3 lands, the B-1 (a)
  shape becomes dead intermediate code that B-3 deletes.

B-1 lands now because:

1. **Pre-genesis discount.** Per
   `15-deletion-and-debt.mdc` and `16-architectural-inheritance.mdc`,
   the pre-V3-launch migration path is `rm -rf ~/.shekyl` and
   re-sync. Pre-genesis, structural-deletion work is bounded;
   post-genesis, it requires migration tooling that runs forever
   to handle state that exists for a finite period.

2. **No external-audit dependency.** Electrum-words deletion is
   project-internal; BIP39 is the well-vetted industry standard
   already in production via `shekyl-crypto-pq::bip39` (which is
   itself a vendored implementation of BIP-0039). Phase 0 design
   and author review is the audit-of-record.

3. **Cross-repo migration scope is minimal.** Pre-flight
   (2026-05-19) confirms the cross-repo migration matrix has one
   active consumer (shekyl-gui-wallet). shekyl-mobile-wallet and
   shekyl-web are future consumers that pick up the post-deletion
   FFI surface without migration work in this PR series.

4. **The discipline-application timeline.** Per
   `16-architectural-inheritance.mdc`'s "continuous discipline
   as inheritance prevention" framing, each pre-genesis deletion
   PR shrinks the surface that future PRs have to migrate.
   Deferring B-1 to V3.x defers the discipline pay-back and
   compounds the migration cost.

```mermaid
flowchart LR
  P0[Phase 0: Two design docs<br/>ELECTRUM_WORDS_REMOVAL.md<br/>ELECTRUM_WORDS_REMOVAL_PLAN.md] --> R0{Phase 0 review<br/>4-6 rounds<br/>landed on dev?}
  R0 -- no --> P0
  R0 -- yes --> P1
  P1[Phase 1: wallet2 internal rewire<br/>BIP39 path + hard-error on language] --> P2
  P2[Phase 2: RPC surface deletion<br/>4 commands + helpers] --> P3
  P3[Phase 3: FFI surface deletion<br/>+ shekyl-gui-wallet migration<br/>coordinated dev-tip merge] --> R1{Both repos CI green<br/>+ rebase verified?}
  R1 -- no --> P3
  R1 -- yes --> P4
  P4[Phase 4: wallet2 core deletion<br/>3-commit decomp<br/>method then JSON then field] --> P5
  P5[Phase 5: src/mnemonics/ deletion<br/>21 files + CMake cleanup] --> P6
  P6[Phase 6: Docs + CHANGELOG<br/>+ CI invariants symbol-isolation + grep-orphans]
```

Decision diamonds match the LWMA-1 / RandomX-v2 plan structure:
`R0` gates code-landing on Phase 0 review-rounds close; `R1`
gates Phase 4+ on the cross-repo Phase 3 cutover being verifiably
clean.

Phases 1, 2, 4, 5, 6 are sequential by deletion-leaf dependency
— the mnemonics subsystem leaf (Phase 5) cannot delete cleanly
until its callers (Phases 1–4) are gone; the wallet2 core methods
(Phase 4) cannot delete cleanly until their RPC/FFI callers
(Phases 2, 3) are gone; the RPC/FFI callers (Phases 2, 3) cannot
delete cleanly until the wallet2 internal use (Phase 1) is
rewired. Phase 3 sits in the middle because it is the cross-repo
atomic-cutover phase that gates everything depending on FFI
removal.

## Permanent architectural decisions

These decisions are made now and locked. The substrate doc
[`ELECTRUM_WORDS_REMOVAL.md`](./ELECTRUM_WORDS_REMOVAL.md) §4
carries the substantive disposition rationale; the entries below
are the **plan-level** decisions (PR shape, sequencing, cutover
mechanism) that the substrate doc's §4 references rather than
restates.

### 1. Five implementation PRs after Phase 0

Five PRs total post-Phase 0: Phase 1 (wallet2 internal),
Phase 2 (RPC), Phase 3 (FFI + cross-repo), Phase 4 (wallet2
core), Phase 5 (mnemonics subsystem), Phase 6 (docs + CI). Phase
6 is bundled with Phase 5's PR if the docs delta is small; if
the CHANGELOG entry plus the two CI scripts plus the
USER_GUIDE/DESIGN_CONCEPTS sweep is large, Phase 6 is its own
sixth PR. Determined at Phase 5 close, not pre-decided here.

Each PR fits `06-branching.mdc` rule 2 (short-lived; expected
< 5 working days; < 10 commits).

### 2. Cross-repo coordination at Phase 3 only

Phase 3 is the sole cross-repo coordination phase. Phases 1,
2, 4, 5, 6 are shekyl-core internal and have no cross-repo
implications. This minimizes the cross-repo blast radius to a
single boundary.

### 3. Pre-genesis cutover mechanism (coordinated dev-tip merge)

Per substrate §5.3. Documented here at plan level so the Phase
3 PR description can cite this section.

### 4. PR 4 / PR 5 merge-conflict gates as verification, not blocking

Per substrate §1 (Sequencing rationale) and the PR-4 / PR-5
checks in todos `phase3` and `phase4`: verification gates, not
blocking. If conflict surface is found at branch-cut time, the
phase rebases against dev tip; the phase does not wait for PR
4 / PR 5 to complete unless rebase is non-trivial.

### 5. Phase 1 hard-error inversion

Per substrate §4.3. Phase 1's behavior is signature-preserving,
hard-error on non-empty `language` parameter. Not silently-ignored.
This is the discipline-correct disposition for pre-genesis;
the alternative (graceful degradation) is the production-software
default that leaks into pre-genesis when not explicitly inverted.

### 6. shekyl-mobile-wallet / shekyl-web consumption freeze convention

Per substrate §3.3 and §5.1. During Phase 0 → Phase 3 flight,
neither repo initiates wallet2_ffi consumption work. If a repo's
roadmap forces this during flight, the matrix re-expands per
substrate §3.3.

## Phase 0 — Two design docs

**Status.** In flight (this PR is Round 1).

**Scope.** Write
[`ELECTRUM_WORDS_REMOVAL.md`](./ELECTRUM_WORDS_REMOVAL.md)
(substrate) and this plan doc. Both must close the Phase 0
review cycle (target 4–6 rounds per
`20-rust-vs-cpp-policy.mdc`'s migration-is-a-planning-activity
discipline) before any deletion code lands.

**Closure criteria:**

1. Both docs land on `dev` after the review cycle.
2. Substrate §4 architectural decisions are unchallenged through
   at least one no-changes review round.
3. Plan doc's todo list reflects the final phase decomposition;
   no late-stage phase additions or splits.

**Branch:** `feat/electrum-words-removal-phase0-design` (already
cut, off `dev` tip 2026-05-19 = post-RandomX-v2-Phase-1 +
post-LWMA-1-Phase-4 + post-Batch-α PRs #46/47/48 merge).

## Phase 1 — wallet2 internal rewire

**Scope:** signature-preserving, behavior-narrowing internal
rewire of `wallet2::generate()` and `wallet2::restore()`
Electrum-words branches to the existing Rust BIP39 FFI bridge.
Phase 1 is the discovery-point phase: consumer code that passes
non-empty `language` parameter breaks here, not at Phase 3.

**Detailed work items:**

1. `src/wallet/wallet2.cpp:600–669` Electrum-words branches in
   `wallet2::generate_new` / `wallet2::restore` rewire to
   `shekyl_account_generate_from_bip39` /
   `shekyl_bip39_mnemonic_to_pbkdf2_seed`. The `language` /
   `old_language` local variables become unused (and are
   deleted alongside the FFI parameter at Phase 3).

2. `src/wallet/wallet2.cpp:1372` `wallet2::get_seed` body is
   replaced with a call to the Rust BIP39 path that returns the
   wallet's BIP39 phrase as `epee::wipeable_string`. The function
   signature is preserved (Phase 4 deletes the method outright).

3. `src/wallet/wallet2_ffi.cpp:648` `query_key("mnemonic")`
   dispatch routes through the Rust BIP39 entry per substrate
   §4.5 (routing decision: Rust BIP39; string-key decision:
   keep as `"mnemonic"`).

4. `src/wallet/wallet2_ffi.cpp` `wallet2_ffi_create_wallet`
   implementation returns a hard error
   (`WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR` or equivalent) if
   `language != nullptr && language[0] != '\0'`. Same for
   `wallet2_ffi_generate_from_keys`. Function signatures are
   preserved at Phase 1; Phase 3 drops the parameters.

5. `src/wallet/wallet2_ffi.cpp:309–319`
   `wallet2_ffi_create_wallet` Electrum-words-language-validation
   path: replace with the hard-error branch from item 4.

6. `src/wallet/wallet2.cpp:79` `#include "mnemonics/electrum-words.h"`
   is deleted. The other two include sites (wallet2_ffi.cpp:38,
   wallet_rpc_server.cpp:64) remain until their respective phases.

7. Add `tests/unit_tests/wallet_bip39.cpp` per substrate §7.3
   (BIP39 round-trip tests: generate, query, restore, assert
   wallet identity).

8. Add `tests/unit_tests/wallet_bip39_residency.cpp` per substrate
   §7.4 (cross-boundary zeroization invariant; modelled on
   `STAGE_1_PR_3_KEY_ENGINE.md §7.5` audit pattern).

**Multi-commit decomposition (4 commits):**

1. `wallet: rewire wallet2::generate_new and ::restore Electrum-words branches to BIP39 FFI`
2. `wallet: route query_key("mnemonic") through Rust BIP39 entry`
3. `wallet: hard-error on non-empty language parameter at create_wallet / generate_from_keys`
4. `wallet: add BIP39 round-trip and memory-residency invariant tests`

Each commit independently green; bisect-clean per
`90-commits.mdc`'s scope-per-commit discipline.

**PR scope:** shekyl-core only. shekyl-gui-wallet sees the
hard-error at runtime; the gui-wallet fix lands in the Phase 3
coordinated migration PR.

**Branch:** `feat/electrum-words-removal-phase1-wallet2-rewire`
off `dev`.

## Phase 2 — RPC surface deletion

**Scope:** delete the Electrum-words RPC commands and their
handlers in `wallet_rpc_server`.

**Detailed work items:**

1. Delete `COMMAND_RPC_GET_LANGUAGES` struct
   (`src/wallet/wallet_rpc_server_commands_defs.h:2074`) and its
   handler.
2. Delete `COMMAND_RPC_RESTORE_DETERMINISTIC_WALLET` struct
   (`src/wallet/wallet_rpc_server_commands_defs.h:2223`) and its
   handler.
3. Delete the `get_wallet_words` handler at
   `src/wallet/wallet_rpc_server.cpp:2214,2220`.
4. Delete the language-validation branches at
   `src/wallet/wallet_rpc_server.cpp:3661, 4082`.
5. Delete the Electrum-words restore paths at
   `src/wallet/wallet_rpc_server.cpp:2324–2358, 4162–4225`
   (the `words_to_bytes` / `get_is_old_style_seed` calls + the
   explanatory comments).
6. Delete `#include "mnemonics/electrum-words.h"` from
   `src/wallet/wallet_rpc_server.cpp:64`.
7. The `COMMAND_RPC_QUERY_KEY` mnemonic-string-routing branch is
   either:
   - (a) updated to route through the Rust BIP39 entry (if the
     wallet2 RPC handler still exposes this path post-Phase-1);
     defer the dispatch-branch deletion to Phase 4 alongside
     `wallet2::get_seed` deletion, **OR**
   - (b) deleted entirely if the Rust-routed BIP39 dispatch is
     not exposed via the wallet RPC at all (in which case the
     `query_key("mnemonic")` RPC reply is "key type not
     supported").

   Decision deferred to Phase 2 implementation time, dependent
   on whether Phase 1's `wallet2::get_seed` rewire (item 2 of
   Phase 1) carries through to the RPC layer.

**Multi-commit decomposition (4 commits):**

1. `wallet-rpc: delete restore_deterministic_wallet RPC + helper functions`
2. `wallet-rpc: delete get_languages + language-set RPC commands`
3. `wallet-rpc: delete get_wallet_words handler`
4. `wallet-rpc: cleanup mnemonics/electrum-words.h include`

**PR scope:** shekyl-core only. The project's
`rust/shekyl-rpc-server` does not bind these legacy RPC commands
(per pre-flight grep, 2026-05-19), so no consumer impact.
Third-party `wallet-rpc` clients that depend on these RPC
commands (none known) would see RPC method-not-found errors at
the moment of attempted use.

**Branch:** `feat/electrum-words-removal-phase2-rpc-deletion`
off `dev`.

## Phase 3 — FFI surface deletion + shekyl-gui-wallet migration

**Scope:** the cross-repo atomic-cutover phase per substrate §5.

### 3.1 shekyl-core PR work items

1. Delete `wallet2_ffi_restore_deterministic_wallet` declaration
   (`src/wallet/wallet2_ffi.h:98–104`) and definition
   (`src/wallet/wallet2_ffi.cpp:414–431`).
2. Drop the `language` parameter from `wallet2_ffi_create_wallet`
   (signature change; declaration at `src/wallet/wallet2_ffi.h:87`,
   definition at `src/wallet/wallet2_ffi.cpp:309–319`).
3. Drop the `language` parameter from
   `wallet2_ffi_generate_from_keys` (signature change; declaration
   at `src/wallet/wallet2_ffi.h:113`, definition at
   `src/wallet/wallet2_ffi.cpp:523–527`).
4. Delete the language-list export at
   `src/wallet/wallet2_ffi.cpp:1197–1198`.
5. Delete all remaining `crypto::ElectrumWords::*` calls in
   `wallet2_ffi.cpp` (the `is_valid_language` and `words_to_bytes`
   calls in the deleted functions).
6. Delete `#include "mnemonics/electrum-words.h"` from
   `src/wallet/wallet2_ffi.cpp:38`.
7. Update FFI consumer tests (any test that calls
   `wallet2_ffi_create_wallet` / `wallet2_ffi_generate_from_keys`
   with a `language` argument): drop the argument.

### 3.2 shekyl-gui-wallet PR work items (coordinated sibling)

In the `shekyl-gui-wallet` repository, on a parallel branch:

1. `src-tauri/src/wallet_bridge.rs::create_wallet` drops
   `language` parameter; signature becomes
   `create_wallet(wallet_path, password)`. Updates the FFI call
   to match.
2. `src-tauri/src/wallet_bridge.rs::restore_deterministic_wallet`
   wrapper deleted in its current form. Replaced with a wrapper
   around the BIP39 restore entry. The Rust-side caller routes
   through `shekyl_account_generate_from_bip39` on the shekyl-core
   side (since `wallet2_ffi_restore_deterministic_wallet` no
   longer exists).
3. `src-tauri/src/commands.rs` Tauri command signatures lose
   their `language: Option<String>` parameters on import / create
   / restore flows (lines 498, 618, 666).
4. `SeedInfo { seed, seed_language }` data structure loses the
   `seed_language` field (line 64, 72, 527, 598, 652, 703).
5. UI flows that show a "select seed language" picker before
   wallet creation are deleted.
6. UI flows that show a 25-word display for backup are repointed
   to the BIP39 24-word display.
7. `Cargo.toml` shekyl-core pin updates to the post-Phase-3-merge
   `dev` SHA on shekyl-core.

### 3.3 Cutover mechanism

Per substrate §5.3 (coordinated dev-tip merge for pre-genesis):

1. shekyl-core PR opens against `dev` with §3.1 work items.
2. shekyl-gui-wallet migration PR opens against
   `shekyl-gui-wallet`'s `dev` with §3.2 work items. PR body
   cites the shekyl-core PR by URL. The gui-wallet PR pins its
   `Cargo.toml` `shekyl-core` dep to the specific
   `shekyl-core` commit hash that is the FFI-deletion PR's head
   (the pre-merge SHA on shekyl-core's PR branch); this lets
   gui-wallet's CI build and test against the post-deletion FFI
   surface before either repo merges.
3. Both PRs run CI to green.
4. **Merge order is shekyl-core first, then shekyl-gui-wallet
   within the same session.** Concretely: (a) CI green on both
   PRs and reviewer-approval on both PRs are the prerequisites;
   (b) shekyl-core merges to `dev`; (c) shekyl-gui-wallet's
   `Cargo.toml` pin updates from the pre-merge SHA to the
   post-merge `dev`-tip SHA on shekyl-core (mechanical commit on
   the gui-wallet PR branch); (d) shekyl-gui-wallet's CI
   re-runs against the updated pin; (e) shekyl-gui-wallet
   merges. The intent is to confine the cross-repo inconsistency
   window to a single failure mode (gui-wallet `dev` references
   freshly-deleted FFI symbols, producing immediate compile
   failure on any local build during the gap) rather than the
   reversed order's failure mode (gui-wallet `dev` references
   not-yet-existing FFI symbols, allowing silent linker resolution
   against pre-deletion shekyl-core artifacts in stale build
   caches). The chosen order's failure mode is loud and bounded
   to the gap window; the reversed order's failure mode is
   silent and risks shipping pre-deletion shekyl-core binaries
   against post-deletion gui-wallet code.

### 3.4 Reversion mechanism

Per substrate §5.4 (commit-revert in coordinated order). If a
revert is needed:

1. shekyl-gui-wallet revert PR restores Electrum-words consumption.
2. shekyl-core revert PR restores the FFI surface.
3. Verify both repos compile + tests pass against the post-revert
   `dev` tip.

### 3.5 Pre-flight check: PR 4 / PR 5 merge-conflict surface

Before opening the Phase 3 PR, run:

```sh
git log --oneline -- src/wallet/wallet2_ffi.cpp src/wallet/wallet2_ffi.h \
  $(git merge-base HEAD origin/dev)..origin/dev
```

Audit the output for commits that touch lines in the deletion
sites enumerated in §3.1 (lines 98–104 for `wallet2_ffi.h`;
lines 309–319, 414–431, 523–527, 1197–1198 for `wallet2_ffi.cpp`).
If overlap exists, rebase against `dev` tip; if not, proceed.

**Multi-commit decomposition (shekyl-core PR, 4 commits):**

1. `wallet-ffi: delete wallet2_ffi_restore_deterministic_wallet`
2. `wallet-ffi: drop language parameter from create_wallet and generate_from_keys`
3. `wallet-ffi: delete language-list export + remaining ElectrumWords calls`
4. `wallet-ffi: cleanup mnemonics/electrum-words.h include`

**Multi-commit decomposition (shekyl-gui-wallet PR, 4–5 commits):**

1. `wallet-bridge: drop language parameter from create_wallet`
2. `wallet-bridge: migrate restore_deterministic_wallet to BIP39 entry`
3. `commands: drop language parameters and seed_language fields`
4. `ui: remove seed-language picker; update seed display to BIP39 24-word`
5. `deps: bump shekyl-core pin to post-merge dev SHA`

**PR scope:** shekyl-core + shekyl-gui-wallet (coordinated unit).

**Branches:**

- shekyl-core: `feat/electrum-words-removal-phase3-ffi-cutover`
  off shekyl-core's `dev`.
- shekyl-gui-wallet: `feat/electrum-words-removal-bip39-migration`
  off shekyl-gui-wallet's `dev`.

## Phase 4 — wallet2 core deletion (3-commit)

**Scope:** delete the wallet2 core methods, JSON ser/de, and
`seed_language` field, per substrate §6 Spec-Gap-6 disposition.

### 4.1 Pre-flight: PR 5 (Pending TX Engine) stabilization gate

Before opening the Phase 4 PR, verify PR 5 has either:

- (a) merged to `dev`, **OR**
- (b) not touched `src/wallet/wallet2.cpp` lines 1300–1450 (the
  method-deletion region) or `src/wallet/wallet2.h` lines
  1000–1011 (the declaration-deletion region).

If conflict surface exists, rebase against `dev` tip after PR 5
lands. Phase 4 does not wait for PR 5 unless the conflict
surface is non-trivial.

### 4.2 Three commits in order

**Commit A — wallet2 method deletion.** Drop:

- `wallet2.h:1001` `bool is_deterministic() const;` declaration.
- `wallet2.h:1002` `bool get_seed(...)` declaration.
- `wallet2.h:1007` `const std::string &get_seed_language() const;` declaration.
- `wallet2.h:1011` `void set_seed_language(...)` declaration.
- `wallet2.cpp:1362` `is_deterministic()` body.
- `wallet2.cpp:1372` `get_seed()` body (which was rewired in
  Phase 1; now deleted outright since callers have migrated).
- `wallet2.cpp:1425` `get_seed_language()` body.
- `wallet2.cpp:1433` `set_seed_language()` body.

Also at this commit: delete the legacy CryptoNote-25-word comment
at `wallet2.cpp:6479`. Also: delete the `query_key("mnemonic")`
dispatch branch in `wallet2_ffi.cpp:648` if Phase 2 left it in
place (item 7 of Phase 2 deferred this decision).

After Commit A: `seed_language` field is dead state (no setters
/ getters / accessors); JSON ser/de still writes/reads it.

**Commit B — JSON ser/de drop.** Drop:

- `wallet2.cpp:4793–4802` `seed_language` JSON write.
- `wallet2.cpp:5344–5347` `seed_language` JSON read.

Regenerate any touched test fixtures that previously serialized
`seed_language` (e.g., keyfile fixtures under
`tests/data/wallet/*.keys` or `tests/functional_tests/data/`).
At Commit A the field is dead state but JSON ser/de still
roundtrips fixtures cleanly; at Commit B the JSON read no
longer recognizes `seed_language`, so any fixture containing
that field either (a) regenerates without the field via the
post-Phase-1 wallet-creation path, or (b) is hand-edited to
drop the `"seed_language": "..."` entry. The pre-genesis posture
per substrate §7.5 means fixture regeneration is the
discipline-correct path (no production-keyfile concern); the
silently-skip-unknown-field alternative is forward-compat
hygiene that does not buy anything pre-genesis. This is the
spec-gap-6 fold-in disposition.

After Commit B: `seed_language` field is in-memory-only state,
never persisted; all fixtures roundtrip cleanly without the
field.

**Commit C — `seed_language` field deletion.** Drop:

- `wallet2.h:1728` `std::string seed_language;` field.
- All in-memory references to `seed_language` (initializer-list
  removals, any direct field access elsewhere in `wallet2.cpp`).

After Commit C: `seed_language` does not exist anywhere in
wallet2.

Each commit independently green; bisect-clean.

**PR scope:** shekyl-core only. No consumer impact (Phase 3
already migrated the only active consumer; shekyl-gui-wallet
does not access these wallet2 methods directly post-Phase-3).

**Branch:** `feat/electrum-words-removal-phase4-wallet2-core`
off `dev`.

## Phase 5 — Mnemonics subsystem deletion

**Scope:** delete the `src/mnemonics/` subsystem entirely.

### 5.1 Pre-flight verification

Before deleting `src/mnemonics/`, verify by grep that no
non-self-referential consumers remain:

```sh
git grep -E 'mnemonics/electrum-words|crypto::ElectrumWords' \
  -- ':!src/mnemonics/' ':!docs/' ':!tests/unit_tests/mnemonics.cpp'
```

Expected output: empty (all consumers handled by Phases 1–4).
If matches exist, the deletion is unsafe — investigate and
resolve before proceeding.

### 5.2 Deletion work items

1. Delete `src/mnemonics/` entire directory (21 files; see
   substrate §2.1).
2. Update `src/CMakeLists.txt` to drop
   `add_subdirectory(mnemonics)`.
3. Update `src/wallet/CMakeLists.txt` to drop `mnemonics` from
   link dependencies (if listed).
4. Update `tests/unit_tests/CMakeLists.txt` to drop
   `mnemonics.cpp` from test sources.
5. Delete `tests/unit_tests/mnemonics.cpp`.
6. Verify full-tree build is green with the `mnemonics` library
   completely absent: `cmake --build build/ -j$(nproc)`.

### 5.3 Multi-commit decomposition (3–4 commits)

1. `mnemonics: delete src/mnemonics/ directory (21 files)`
2. `build: remove mnemonics library from CMake configuration`
3. `tests: delete unit_tests/mnemonics.cpp and CMakeLists.txt entry`

If the build-system commit and the deletion commit produce a
transient unbuildable intermediate state (e.g., CMakeLists.txt
still references the deleted directory), combine commits 1 and
2 into a single commit. Bisect-cleanliness wins over fine-grained
decomposition here.

**PR scope:** shekyl-core only.

**Branch:**
`feat/electrum-words-removal-phase5-mnemonics-deletion` off
`dev`.

## Phase 6 — Documentation + CI invariants

**Scope:** per `91-documentation-after-plans.mdc` (docs update
after plans) + substrate §7 (CI invariants).

### 6.1 Documentation updates

1. **`docs/CHANGELOG.md`** — add a comprehensive `### Removed`
   entry under `## [Unreleased]`:

   ```markdown
   ### Removed
   - **Electrum-words (CryptoNote 25-word) mnemonic subsystem.** The
     inherited 25-word seed encoding and its 14-language word-list
     infrastructure have been removed from shekyl-core. BIP39 is now
     the sole seed format. Cross-references: `docs/design/ELECTRUM_WORDS_REMOVAL.md`,
     `docs/design/ELECTRUM_WORDS_REMOVAL_PLAN.md`. Phases 1–6 merged
     as PRs #<N1>, #<N2>, #<N3>, #<N4>, #<N5>.
   ```

2. **`docs/USER_GUIDE.md`** (and any other user-facing docs) —
   audit for references to:
   - "25-word seed", "Electrum-words", "seed language"
   - Seed-restoration flows that mention language selection
   - Seed-display flows that show 25 words
   Update to BIP39-only language.

3. **`docs/DESIGN_CONCEPTS.md`** (or equivalent) — audit for
   architectural references to the mnemonic subsystem; update
   to reflect BIP39-only seed flow.

4. **`docs/FOLLOWUPS.md`** — mark the B-1 finding as closed;
   cite Phase 1–6 merge SHAs.

### 6.2 CI invariants

1. **`tests/symbol_isolation/electrum_words_removed.sh`** — runs
   `nm` against build artifacts; greps for the substrate §7.1
   symbol list; fails build if any symbol matches. Pattern from
   LWMA-1 Phase 4 §7.1 precedent.

2. **`tests/grep_invariants/electrum_words_no_orphans.sh`** —
   runs `git grep -E` for the substrate §7.2 identifier list;
   fails build if any non-allowlisted match exists. Pattern from
   LWMA-1 Phase 4 §7 precedent.

3. Wire both scripts into the CI runner config (Drone / GitHub
   Actions / wherever lints + grep-invariants run today). The
   scripts join the existing LWMA-1 / RandomX-v2 isolation
   invariants.

### 6.3 Decision: PR boundary

If Phase 5's PR carries fewer than ~5 commits, fold Phase 6 into
the same PR as a sixth commit (or commit pair). If Phase 5's PR
is at or near the `06-branching.mdc` rule 2 commit-count limit,
Phase 6 is its own PR.

Decision deferred to Phase 5 close, not pre-decided here.

**Branch:** `feat/electrum-words-removal-phase6-docs-ci-invariants`
off `dev` (if separate PR; otherwise Phase 5 branch carries
Phase 6).

## Reviewer-discipline framing

### No external-audit dependency

Electrum-words deletion is project-internal. BIP39 is the
well-vetted industry standard, deployed for ~13 years across
all major cryptocurrencies. No Monero-funded audit equivalent
applies. Phase 0 design + author-side review + BIP39 round-trip
tests + the memory-residency invariant test are the
audit-of-record.

This matches the LWMA-1 reviewer-discipline framing
(`DAA_LWMA1_PLAN.md` "Reviewer-discipline framing" section):
zawy12-canonical-LWMA-1 was a community-vetted, ~8-year-deployed
specification; BIP39 is similarly a community-vetted,
~13-year-deployed specification. The audit pattern is the same.

### Review round expectations

Phase 0: 4–6 review rounds per
`20-rust-vs-cpp-policy.mdc`'s migration-is-a-planning-activity
discipline. Round 1 (this PR's initial draft) addresses the
critical-gap review surfaced 2026-05-19. Rounds 2+ address
specification refinements + line-number drift + cross-reference
correctness.

Phases 1–6: per-phase Copilot review + author review per the
`06-branching.mdc` default workflow. Each phase PR is bounded
enough that 1–2 review rounds suffice (LWMA-1 Phase 1 closed in
1 round; LWMA-1 Phase 4 took 5 Copilot rounds because of
cross-cutting cutover discipline; B-1's phases are simpler than
LWMA-1 Phase 4).

### Cross-repo review (Phase 3 specifically)

Phase 3's cross-repo coordination is reviewed by:

1. shekyl-core PR review: standard Phase 1–5 reviewer discipline.
2. shekyl-gui-wallet PR review: standard shekyl-gui-wallet
   reviewer discipline (the gui-wallet repo's own
   `.cursor/rules/` apply).
3. Cross-PR coherence review: author confirms the two PRs
   describe the same coordinated migration (cite each other's
   URLs; both reference the substrate doc §3.2.1 migration
   shape).

No new reviewer role is needed for cross-repo work; existing
per-repo discipline suffices when both PRs cite the substrate
doc as the shared specification.

---

*Plan doc end. Substrate-level rationale in
[`ELECTRUM_WORDS_REMOVAL.md`](./ELECTRUM_WORDS_REMOVAL.md).*
