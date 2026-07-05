# Implementation index and phase map

**Purpose.** One page that answers "what does this identifier mean, which doc
owns it, and what has actually landed on `dev`?" The wallet/staking work spans
several plan documents whose numbering schemes evolved independently; this
index is the disambiguation layer. It is a *map*, not a status-of-record —
each track's own plan doc remains authoritative for design detail, and where
a plan doc's status table disagrees with landed code, **code wins** (§6 lists
the known disagreements at the verification date rather than editing those
docs from here).

**Verification stamp.** Statuses below were verified against landed code at
`dev` = `e22549a79` (merge of PR #257), 2026-07-05. Since the prior stamp
(`13ccb1ddb`, PR #254) the GF-7 scheduler seam (PR #255) and the submit
lifecycle driver (PR #257) have landed and are reflected below. When you
update a status here, re-verify against code (`git grep`, not plan prose) and
move this stamp.

**Maintenance discipline** (institutionalized as
[`.cursor/rules/94-tracking-index.mdc`](../../.cursor/rules/94-tracking-index.mdc) —
new identifier families register here at birth; Phase 3+ / Stage 3+ work
items start with an index row).

- **Row format:** every status cell *leads* with the current status and its
  as-of date (e.g. `Landed (as of 2026-08-01)`); dated `UPDATE YYYY-MM-DD:`
  entries append *below/after* that line as the history chain. Readers get
  the answer without parsing the chain.
- **Two verification classes:** *code-anchored* items cite a `git grep`
  target on `dev`; *decision-anchored* items (round closures, wire freezes,
  contract docs — no code artifact) cite the commit hash or PR number of the
  doc edit that closed them.
- **Section contract:** rule 94 refers to §2 (identifier-family registry),
  §4–§5 (live / built-unwired / missing inventory), and §6
  (known-stale-statuses ledger) by role. Their meanings — and this numbering
  — are load-bearing; a restructuring that moves them updates
  `.cursor/rules/94-tracking-index.mdc` in the same PR.
- This doc never carries design content — link to the owning doc instead.
- New identifier families (a new prefix series in any plan doc) get a §2 row
  in the same PR that introduces them, after the rule-94 prefix-uniqueness
  check.

---

## 1. The collision this index untangles

Two independent schemes both used the bare tokens `2a / 2b / 2c / 2d`, and
one token (`2c-2b`) was reused *within* a single scheme:

| Token | Engine-layer meaning (`WALLET_REWRITE_PLAN.md`) | Bond-construction meaning (`ARCHIVAL_BOND_PR2_CHAIN.md`) |
| --- | --- | --- |
| 2a | Phase 2a — send path | Bond-PR 2a — synthetic-tree round-trip KAT (#156) |
| 2b | Phase 2b — stake lifecycle | Bond-PR 2b — StakeEngine actor, seed-owning model (#157) |
| 2c | Phase 2c — addresses/proofs | Bond-PR 2c-1 / 2c-2a / 2c-2b — real-tree KAT, Model D wiring, request path |
| 2d | Phase 2d — cold bundles | Bond-PR 2d-1 / 2d-2 — `P`-scan layer, `P`-isolated transport |

**Resolution (pinned 2026-06-19, `ARCHIVAL_BOND_PR2_CHAIN.md` §0):** the bond
chain is prefixed **`Bond-PR`** in doc prose; bare **`Phase 2x`** always means
the engine layer. Branch names are immutable history and keep their original
(unprefixed) names.

**The `2c-2b` double-use.** Within the bond chain itself, `2c-2b` names two
different deliverables in sequence:

1. **Bond-PR 2c-2b (request path)** — JoinMarket bond request layer, landed
   `feat/archival-bond-request` #163, plan doc
   [`ARCHIVAL_BOND_REQUEST_2C2B_PLAN.md`](ARCHIVAL_BOND_REQUEST_2C2B_PLAN.md).
2. **2c-2b re-scope (GF-7 scheduler seam)** — block-timed entry-seam planning
   plus GF-7 measurement hooks, landed PR #255, plan doc
   [`ARCHIVAL_BOND_2C_GF7_HOOKS.md`](ARCHIVAL_BOND_2C_GF7_HOOKS.md).

When you see `2c-2b` in prose, the linked plan doc disambiguates; new prose
should say "request path" or "GF-7 seam" explicitly.

---

## 2. Identifier families

| Family | Reads as | Owning doc | Notes |
| --- | --- | --- | --- |
| **Phase 0–6** | Engine-layer wallet-rewrite phases: 0 baseline, 1 wallet domain model, 2 core operations, 3 `shekyl-cli`, 4 `shekyl-wallet-rpc`, 5 C++ deletion, 6 tests+docs. Phase 2 splits into 2a send / 2b stake lifecycle / 2c addresses+proofs / 2d air-gapped bundles | [`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md) | The original scheme; always prefixed `Phase` post-2026-06-19 |
| **Stage 0–5** | Orchestration/actor architecture stages: 0 harness, 1 per-engine trait extraction, 2 KeyEngine actor, 3 `StakeEngine` implementation, 4 actor swaps (e.g. `PendingTxActor`), 5 `ArchivalEngine` | [`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md), [`STAGE_0_HARNESS.md`](STAGE_0_HARNESS.md), `docs/completed/STAGE_2_KEY_ENGINE_ACTOR.md` | — |
| **Stage 1 PR 3–7** | Per-engine trait-extraction PRs: 3 KeyEngine, 4 RefreshEngine, 5 PendingTxEngine, 6 PersistenceEngine, 7 EconomicsEngine | `STAGE_1_PR_{4,5,6,7}_*.md`, [`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md) | PR 3's docs (KeyEngine + M3 preflights) archived under `docs/completed/` |
| **M3a–M3e** | Stage 1 PR 3's architectural-inheritance migration steps | `docs/completed/STAGE_1_PR_3_MIGRATION_PLAN.md` | Referenced from `.cursor/rules/16` |
| **Bond-PR 0–2d** | Bond-construction chain: 0 `P`-derivation, 1 bond builder, 2a–2c KATs+wiring+request, 2d-1 `P`-scan, 2d-2 transport | [`ARCHIVAL_BOND_PR2_CHAIN.md`](ARCHIVAL_BOND_PR2_CHAIN.md) | The chain's §2 arc table is the per-sub-PR record |
| **SP-0…SP-7, SP-R0** | `P`-scan pipeline slices (2d-1); SP-R0 is the durable-removal GC follow-on | [`ARCHIVAL_BOND_2D1_PSCAN_PLAN.md`](ARCHIVAL_BOND_2D1_PSCAN_PLAN.md) | Shipped grouped as PR-A / PR-B, not one-PR-per-SP |
| **PR-A / PR-B** | The two validation-surface bundles that shipped SP-0…SP-7 (#201, #205) | [`ARCHIVAL_BOND_2D1_PSCAN_PLAN.md`](ARCHIVAL_BOND_2D1_PSCAN_PLAN.md) | Named per rule 19 (validation-surface bundling) |
| **SP-T0…SP-T5** | `P`-isolated transport slices (2d-2): Tor bootstrap, circuit isolation, fetch, …, broadcast | [`ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md`](ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md) | Sub-docs: `_SP_T0_TOR.md`, `_SP_T2_FETCH.md`, `_SP_T4_BROADCAST.md` |
| **PR-E0…PR-E3** | Reward-emission implementation PRs; C-1 (ML-DSA equality + membership-only verify) is PR-E3 step 8 | [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md), [`REWARD_EMISSION_VIN_PLAN.md`](REWARD_EMISSION_VIN_PLAN.md) | C-1 is the hard Stage-3 emission blocker |
| **CT-1…CT-5 (5a–5d)** | Curve-tree client series | [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md); closeouts in `docs/completed/CT*` | Series closed (`CT5_SERIES_CLOSEOUT.md`) |
| **GF-1…GF-12** | Gate-6 firewall findings; **GF-7** = the funding-seam (principal↔`P`) unlinkability property, a genesis gate | [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) | GF-7's measurement hooks: [`ARCHIVAL_BOND_2C_GF7_HOOKS.md`](ARCHIVAL_BOND_2C_GF7_HOOKS.md) |
| **S-1…S-6** | Gate-6 §10.12 seam-scenario rows (adversary fusion analysis) | [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) §10.12 | Not to be confused with S6 the certify-draw plan (`docs/completed/ARCHIVAL_BOND_S6_CERTIFY_DRAW_PLAN.md`) |
| **Round N / R N** | Per-doc adversarial design rounds; each design doc numbers its own | Owning doc's round table | Gate-6 R1 closed; R2 = the 2d-2 work; R3–R5 open |
| **F-N** | Findings within a specific design doc's review (e.g. F40 `AlreadyInChain`, F41 `Conceal` constant-work in the daemon-submit series) | The doc that numbered them, e.g. [`DAEMON_SUBMIT_VERDICT.md`](DAEMON_SUBMIT_VERDICT.md) | F-numbers are doc-scoped, not global |
| **DQ-N** | Design questions in the 2d-2 transport plan | [`ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md`](ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md) | — |

---

## 3. Phase map (engine layer, `WALLET_REWRITE_PLAN.md`)

| Phase | Scope | Status (per plan doc + code, 2026-07-05) |
| --- | --- | --- |
| 0 | Close out previous plan; align baseline | Closed |
| 1 | Wallet domain model (`shekyl-engine-core::Engine`) | Closed 2026-06-10 (`docs/completed/PHASE_1_ORCHESTRATOR_STATUS.md`) |
| 2a | Send path | Done for phase scope (2026-07-01) — curve-tree client wired into production sends; residue in `PHASE_2A_SEND_PATH.md` §10 |
| 2b | Stake lifecycle | Design rounds 0–4 closed / largely closed; implementation = Stage 3, **partially landed** (see §5) |
| 2c | Addresses / proofs | Per plan doc |
| 2d | Air-gapped flow (`UnsignedTxBundle`/`SignedTxBundle`) | Per plan doc — **not** the bond chain's 2d-1/2d-2 |
| 3 | `shekyl-cli` binary | Per plan doc |
| 4 | `shekyl-wallet-rpc` binary | Per plan doc |
| 5 | C++ deletion (single commit) | Not started; gated on 1–4 completeness |
| 6 | Tests and docs | Per plan doc |

---

## 4. Bond-construction chain (Bond-PR track)

History (all landed): Bond-PR 0 `archival_p` derivation #152 → 1 bond builder
+ `shekyl-rct-balance` #155 → 2a synthetic-tree KAT #156 → 2b StakeEngine
actor #157 (partly superseded by Model D) → 2c-1 real-tree KAT #158 → 2c-2a
Model D wiring (`feat/archival-stake-wiring`) → 2c-2b request path #163.

Current front:

| Item | Plan doc | Status (code-verified 2026-07-05) |
| --- | --- | --- |
| GF-7 scheduler seam (2c-2b re-scope) | [`ARCHIVAL_BOND_2C_GF7_HOOKS.md`](ARCHIVAL_BOND_2C_GF7_HOOKS.md) | **Landed (as of 2026-07-05)** — PR #255. `plan_entry_seam`/`EntrySeamPlan`, `BroadcastTimelineObserver` seam, `--gf7-timeline` sim scenario, `gf7-no-emit-guard` workflow. UPDATE 2026-07-05: landed #255 (verified: git grep `plan_entry_seam`/`BroadcastTimelineObserver` on dev → `shekyl-staking-sim/src/gf7_timeline.rs`, `shekyl-standoff::gf7`; `.github/workflows/gf7-no-emit-guard.yml`) |
| 2d-1 `P`-scan layer | [`ARCHIVAL_BOND_2D1_PSCAN_PLAN.md`](ARCHIVAL_BOND_2D1_PSCAN_PLAN.md) | **Built, unwired** — SP-0…SP-7 landed via #192/#194/#195 (design + CT compare + SP-1 adapter) and PR-A #201 / PR-B #205; `pscan/` modules on `dev`; `start_pscan` exists but is `dead_code` (no lifecycle caller) |
| 2d-2 `P`-isolated transport | [`ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md`](ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md) | **Partially built, inert** — SP-T1 circuit isolation #204/#209; SP-T4a `BroadcastSubmitter` #254; `shekyl-p-transport` (`PTorClient`) and `PBlockSource` on `dev` but `dead_code`; block-timed dispatch driver not built (`TODO(2d)` in `stake_engine.rs`) |

---

## 5. What is live vs. built-but-unwired vs. missing (Stage 3 slice + wallet submit-verdict path)

Verified at `dev` = `e22549a79`:

| Layer | State | Evidence anchor |
| --- | --- | --- |
| `StakeEngine` persona/bond/scan surface | **Live** — spawned by orchestrator lifecycle for staker wallets | `engine/lifecycle.rs` (`spawn_stake_engine_if_staker`) |
| Bond signing (`sign_bond` → `JoinMarketVin`) | **Live** (inert output — signed vin not yet assembled into a broadcastable tx in production) | `engine/stake_engine.rs` |
| `P`-scan pipeline (SP-0…SP-7) | **Built, unwired** — `start_pscan` has no production caller | `engine/pscan/start.rs` (`#[allow(dead_code)]`) |
| `P` transport (`PTorClient`, `PRpc`, `PBlockSource`) | **Built, unwired** | `shekyl-p-transport`, `engine/pscan/` |
| `BroadcastSubmitter` / `BroadcastPosture` (SP-T4a) | **Built, inert** — persona-bound submit seam exists, nothing feeds it yet | `engine/transaction_submitter.rs` (`for_posture`/`submit_bound`), `engine/posture.rs`; landed #254 |
| Block-timed dispatch driver (consume seam plan → submit at height) | **Missing** — the seam between signing and broadcasting | `TODO(2d)` marker, `stake_engine.rs` |
| Submit lifecycle driver (§5.3 watchdog + F40 re-scan / F40-R2 breaker) — *distinct from the staking dispatch driver above* | **Built + wired to `Engine`, no production cadence caller (as of 2026-07-05)** — `pub run_submit_lifecycle_tick` drives the watchdog kernel over held F14 locks (escape ladder, presence branching, F40 targeted re-scan, F40-R2 fruitless-rescan breaker); the post-refresh call site is documented but not yet invoked in production (tests drive `tick` directly). UPDATE 2026-07-05: landed #257 (verified: git grep `run_submit_lifecycle_tick` on dev → `engine/mod.rs`; driver in `engine/submit_lifecycle.rs`) | `engine/submit_lifecycle.rs`, `engine/mod.rs` (`run_submit_lifecycle_tick`), `engine/submit_watchdog.rs` |
| Production bond-tx assembly | **Missing** — full assembly exercised only in KATs | `local_pending_tx.rs` tests |
| Reward-emission leg (PR-E1…E3, C-1 verifier) | **Missing** — the hard Stage-3 blocker | `REWARD_EMISSION_LEG.md` |
| Principal stake/unstake/drain lifecycle | **Missing — not yet homed in any plan doc** | `WALLET_REWRITE_PLAN.md` timeline note |

---

## 6. Known stale statuses in other docs (to fix separately)

Recorded here rather than edited in place, per the scope of the PR that adds
this index:

- [`ARCHIVAL_BOND_PR2_CHAIN.md`](ARCHIVAL_BOND_PR2_CHAIN.md) §2 arc table
  lists **2d-1 as "not started"**; SP-0…SP-7 landed via PR-A #201 / PR-B #205
  (built, unwired — see §4/§5). The same row's "2d-2 not started" understates
  SP-T1/#204/#209 and SP-T4a/#254.

---

## 7. Doc directory (active fronts)

| Doc | Owns |
| --- | --- |
| [`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md) | Engine-layer phase plan; Stage architecture; Stage-3 gating |
| [`ARCHIVAL_BOND_PR2_CHAIN.md`](ARCHIVAL_BOND_PR2_CHAIN.md) | Bond-PR chain record + per-sub-PR statuses |
| [`ARCHIVAL_BOND_2C_GF7_HOOKS.md`](ARCHIVAL_BOND_2C_GF7_HOOKS.md) | GF-7 measurement-hook design (PR #255) |
| [`ARCHIVAL_BOND_2D1_PSCAN_PLAN.md`](ARCHIVAL_BOND_2D1_PSCAN_PLAN.md) | `P`-scan pipeline (SP-0…SP-7, PR-A/PR-B) |
| [`ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md`](ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md) | Transport slices (SP-T0…SP-T5, DQ-N) |
| [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) | Gate-6 rounds, GF-N findings, S-N seam scenarios |
| [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) / [`REWARD_EMISSION_VIN_PLAN.md`](REWARD_EMISSION_VIN_PLAN.md) | Emission leg (PR-E0…E3, C-1) |
| [`DAEMON_SUBMIT_VERDICT.md`](DAEMON_SUBMIT_VERDICT.md) | Daemon submit-verdict series (F-N findings incl. F40/F41) |
| [`PRINCIPAL_STAKE_LIFECYCLE.md`](PRINCIPAL_STAKE_LIFECYCLE.md) | Principal-side stake lifecycle design |
| [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) | Staking/archival simulation harness |
| `docs/completed/` | Closed-out tracks (CT series, DAA/LWMA-1, RandomX v2 phases, …) |
