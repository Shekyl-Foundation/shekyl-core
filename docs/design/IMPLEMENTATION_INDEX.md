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
   plus GF-7 measurement hooks, landed PR #255 (2026-07-05), plan doc
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
| **WI-1…WI-4** | Post-#255 archival-bond work items: 1 `start_pscan` lifecycle wiring, 2 production bond assembly + pending-post persistence, 3 block-timed dispatch driver, 4 GF-7 measurement round | This index §4 (rows) + the carrying design docs per row | Registered 2026-07-05; prefix `WI` passes the rule-94 uniqueness check against Phase/Stage/M/Bond-PR/SP/SP-T/PR-A/PR-B/PR-E/CT/GF/S/F/DQ. **Ephemeral family (rule 21 retire criterion):** one plan's work breakdown over already-durable §5 gaps, not a durable cross-doc family — the row retires when WI-4 lands (its items live on as the §5 gap closures and per-doc rows they map to) |

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
| GF-7 scheduler seam (2c-2b re-scope) | [`ARCHIVAL_BOND_2C_GF7_HOOKS.md`](ARCHIVAL_BOND_2C_GF7_HOOKS.md) | **Landed (as of 2026-07-05)** — PR #255 merged (`6d5ecac5f`): `plan_entry_seam`/`EntrySeamPlan`, `BroadcastTimelineObserver` seam behind `gf7-hooks`, `--gf7-timeline` sim scenario, `gf7-no-emit-guard` workflow. UPDATE 2026-07-05: landed #255 (verified: git grep `plan_entry_seam`/`BroadcastTimelineObserver` on dev → `shekyl-staking-sim/src/gf7_timeline.rs`, `shekyl-standoff::gf7`; `.github/workflows/gf7-no-emit-guard.yml`) |
| 2d-1 `P`-scan layer | [`ARCHIVAL_BOND_2D1_PSCAN_PLAN.md`](ARCHIVAL_BOND_2D1_PSCAN_PLAN.md) | **Built, unwired** — SP-0…SP-7 landed via #192/#194/#195 (design + CT compare + SP-1 adapter) and PR-A #201 / PR-B #205; `pscan/` modules on `dev`; `start_pscan` exists but is `dead_code` (no lifecycle caller) |
| 2d-2 `P`-isolated transport | [`ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md`](ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md) | **Partially built, inert** — SP-T1 circuit isolation #204/#209; SP-T4a `BroadcastSubmitter` #254; `shekyl-p-transport` (`PTorClient`) and `PBlockSource` on `dev` but `dead_code`; block-timed dispatch driver not built (`TODO(2d)` in `stake_engine.rs`) |
| WI-1 `start_pscan` lifecycle wiring | [`ARCHIVAL_BOND_2D1_PSCAN_PLAN.md`](ARCHIVAL_BOND_2D1_PSCAN_PLAN.md) (SP-5 completion, §"WI-1" note) | **Implemented — in review (2026-07-05)** — closes the §5 "Built, unwired" `P`-scan gap: `start_pscan_if_staker` (auto-start) + `start_pscan` (on-demand), embedder-held `PScanHandle` (close-stops-task by ownership), dead-code chain un-deadened |
| WI-2 production bond assembly + pending-post persistence | [`ARCHIVAL_BOND_WI2_ASSEMBLY.md`](ARCHIVAL_BOND_WI2_ASSEMBLY.md) (the design addendum) + [`ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md`](ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md) (P-1/P-2 pins) | **Design addendum drafted (2026-07-05)** — dispositions D-A1..D-A5 (per-output funding records + `PSCAN_STATE_VERSION` 4, selection policy, actor-side assemble with P-1 mint site, sibling-sealed pending-post block, persist-before-dispatch); closes the §5 "Production bond-tx assembly: Missing" gap when the implementation lands |
| WI-3 block-timed dispatch driver | [`ARCHIVAL_BOND_WI3_DISPATCH.md`](ARCHIVAL_BOND_WI3_DISPATCH.md) (design rounds 1–2 + implementation status) + [`ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md`](ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md) (SP-T4b/T5 seam) | **Implemented — in review (2026-07-05, `feat/wi3-dispatch-driver`)** — gates 1–11 landed: driver + locked seal path (`pscan/dispatch.rs`), `PENDING_POST_VERSION` 2 (v1 fails closed), `DispatchTick` sweep wiring + production `WalletFile` store / `Local`-posture broadcast (`pscan/task.rs` / `pscan/start.rs`), per-submit `BondPostDispatched` emission-completeness test, gate-11 single-write-path grep gate (`scripts/ci/check_pending_post_write_path.sh`). Closes the §5 "Block-timed dispatch driver" gap; **GF-7 acceptance stays open** per the reconvergence gate below. Design rounds 1–2 (closed 2026-07-05): dispositions D-B1..D-B7 (D1 one-per-tick + dispersal draw, seal-before-send with `PENDING_POST_VERSION` 2, observed-not-claimed confirmation, late-is-noise/stale-is-terminal/re-anchor-is-re-assemble, live `BondPostDispatched`); round 2 (doc §7) pinned the clock's daemon trust as a **named invariant, sound under the recommended local-daemon posture** (R2-1: raw tip kept; the sweep-corroborated clamp `min(claimed_tip, verified_frontier + reorg_depth)` is pre-designed and held in reserve for the 2d-2 remote/untrusted-daemon reopen shared with D-B6) and pinned single-blob crash-atomicity / derived-reservation against the actual AEAD-envelope + atomic-rename seal path (R2-2/R2-4 — the round's load-bearing, posture-independent item). Closes the §5 "Block-timed dispatch driver: Missing" gap (`TODO(2d)` in `stake_engine.rs`) when the implementation lands; consumes WI-2's sealed pending posts. **Reconvergence gate (rule 21):** WI-3 may land in parallel with WI-4, but its GF-7 acceptance does **not close** until WI-4's threshold artifact exists — the D1 coordination is only validatable against a defined `P(link \| T_obs)` bound (no armed-gate-without-trigger). **D1 invariant (design-round scope):** the dispatch driver must not co-launch correlated events off a shared sweep tick — the entry-gap draw decorrelates bond-post-vs-funding *ordering* only, not the principal's lifecycle timeline (`stake_engine.rs` `SignBond` handler note), so D1 requires independent submitters/circuits **and** independently-anchored dispatch times (discharged in `ARCHIVAL_BOND_WI3_DISPATCH.md` §3.2); the adversarial check (submission-timestamp observer gains no better-than-prior linkage) is exactly what WI-4 measures |
| WI-4 GF-7 measurement round | [`ARCHIVAL_BOND_WI4_MEASUREMENT.md`](ARCHIVAL_BOND_WI4_MEASUREMENT.md) (a-priori threshold + correlator spec + §13 result) + [`ARCHIVAL_BOND_2C_GF7_HOOKS.md`](ARCHIVAL_BOND_2C_GF7_HOOKS.md) §5.1 (the binding constraints) | **Graded — PROVISIONAL-PASS, local-daemon posture only (2026-07-05; re-graded 2026-07-06 post-adversarial-review, `feat/wi4-gf7-measurement`)** — the §11 round landed the posture-conditioned S-3 correlator (§4.1.1: session/refresh markers excluded as direct anchors is a *posture theorem* — loopback under the local-daemon posture, D-B1 2d-2 reopen family; the **remote/non-isolated-daemon posture is a named unmet residual on the verdict**, expected re-grade shape `r ≈ 5`), the funding-seam-blind null, the oracle-panel stress arm (§4.3.1: MAP + density-corrected + exact seam-consistency-gated; `lr > s3` on every gate row), the D-B3 `resume` sweep group (session-lattice resubmit exposure, `r = 1.57`, under bound), both validity controls, and the pre-committed sweep in `shekyl-staking-sim/src/gf7_timeline.rs`. The indirect session channel is coupled in the generator and graded (blind `0.237` at window 0 → `≈0.13` under full jitter — not a refresh-free world). Controls valid; every gate-relevant row clears `r = P(link)·N < 2` on all three arms; worst gate row `r = 1.86` (panel; honestly thin margin). Threshold provenance settled a-priori (§13.4: spec commit predates correlator code; `r < 1` pre-rejected as grading the conceded floor). **Cold-start reclassified (§13.2):** low-activity **fails** (panel `r = 3.54`) and cold-start is the genesis regime ⇒ disposition is the **§14 founder-cover launch posture** (refuse the regime: production-path-identical staggered founder cover with permanent consented attributability, shard-schedule structural gate, and the §14.4 **partition-adversary arm** — a-priori bounds committed, implementation gated on review). Block-unit `dispersal>0` is a coarse-tick counterfactual (real dispersal is sub-block ⇒ the emitted `at` is the due block, so the realistic gate sits at `dispersal=0`). **Reconvergence leg (b), severity sharpened:** the block-time sealing re-run is confirmatory by construction (live `BondPostDispatched.at` = due block, per the `gf7_emits_bond_post_dispatched_per_submit` engine test) ⇒ **no block-resolution re-run can close leg (b)**; the wall-clock sweep-phase channel — the one dispersal defends — is the **primary open uncertainty**; closing requires sub-block wall-clock emission + re-grade (FOLLOWUPS, pre-genesis). **Binding constraints (GF7_HOOKS §5.1, pinned 2026-07-05):** (1) threshold derived a priori from a stated adversary-advantage claim and committed in the acceptance doc **before** any grading runs — a failed sweep is a decorrelation-redesign signal, never a move-the-bar signal; (2) correlator adversarially specced: joint-axis fusion (never per-axis-multiplied) + a stronger-than-S-3 stress arm alongside the funding-seam-blind null; (3) known-linked / known-independent instrumentation controls gate the run's own validity; (4) pessimistic principal-lifecycle distributions, stated; (5) the pre-WI-3 pass is **provisional** — sealing measurement re-runs against WI-3's live `BondPostDispatched` emission. **WI-3 R2-3 obligation:** the synthesis must model WI-3's intra-tick dispersal draw and sweep its *distribution* as a parameter — a pre-live "dispersal range suffices" conclusion drawn from a dispersal-free timeline is invalid (`ARCHIVAL_BOND_WI3_DISPATCH.md` §5/§7). WI-3's GF-7 acceptance gates on this artifact (see WI-3 row). **R3 scope pin (§18, 2026-07-06):** the `1.86` is a bound on one seam (entry; exit/drain is GF-4, unmeasured), one scope (per-post; promotes to per-principal **only where GF-4 holds** — conditional now on the verdict line §13.1/§13.5), one channel (timing; the reward value channel is loud by design, verified at source), one instant (not lifetime-cumulative), one stratum (unstratified by `holdings`/`bond_floor`); GF-4 exit seam + value channel are co-equal sealing-path rounds; strata + lifetime ride the §14.4 round. **§18.7 addendum:** tiers-vs-continuous answered at source — accrual reads shard age not persona duration (`g(age)` linear), duration structurally epoch-quantized; four pins (curve shape, epoch width a-priori-derived, claim-timing seam, correlated-exit wargame) routed to the GF-4/§14.4 rounds. **§18.8 correction:** P-is-public reframing — only the `P`→user link is protected; §18.3 stratification narrowed to bridge-axis screening, §18.7 curve pin downgraded to economic-with-bridge-check; entry amount bridge verified **closed structurally** (bond amount consensus-forced to `bond_floor(holdings)`); surviving V-2a membership prior + V-2b exit lifetime-total match routed to GF-4. **§18.9 mechanism pin:** the bond term is loud-but-constant (transparent `amount·H` in the CT balance, `bond_ct_balance.rs`), not CT-hidden-above-floor; `commitment_mask` is HKDF-derived, never user-chosen — the mask-consistency wargame is unrepresentable-by-construction (reopen on any user-supplied blinding factor / above-floor bonding); on-chain bridges timing-only, V-2a/V-2b survive off-chain |

---

## 5. What is live vs. built-but-unwired vs. missing (Stage 3 slice + wallet submit-verdict path)

Verified at `dev` = `e22549a79`:

| Layer | State | Evidence anchor |
| --- | --- | --- |
| `StakeEngine` persona/bond/scan surface | **Live** — spawned by orchestrator lifecycle for staker wallets | `engine/lifecycle.rs` (`spawn_stake_engine_if_staker`) |
| Bond signing (`sign_bond` → `JoinMarketVin`) | **Live** (inert output — signed vin not yet assembled into a broadcastable tx in production) | `engine/stake_engine.rs` |
| `P`-scan pipeline (SP-0…SP-7) | **Built, unwired** — `start_pscan` has no production caller | `engine/pscan/start.rs` (`#[allow(dead_code)]`) |
| `P` transport (`PTorClient`, `PRpc`, `PBlockSource`) | **Built, unwired** | `shekyl-p-transport`, `engine/pscan/` |
| `BroadcastSubmitter` / `BroadcastPosture` (SP-T4a) | **Live (`Local` posture)** — the WI-3 dispatch driver feeds `submit_bound`; `PerP` posture still awaits 2d-2 | `engine/transaction_submitter.rs` (`for_posture`/`submit_bound`), `engine/posture.rs`; landed #254, fed by `pscan/dispatch.rs` |
| Block-timed dispatch driver (consume seam plan → submit at height) | **Implemented — in review** (WI-3, `feat/wi3-dispatch-driver`; GF-7 acceptance open per the WI-3 row's reconvergence gate) | `engine/pscan/dispatch.rs`; WI-3 row above |
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
| [`ARCHIVAL_BOND_WI4_MEASUREMENT.md`](ARCHIVAL_BOND_WI4_MEASUREMENT.md) | WI-4 GF-7 graded genesis gate: a-priori threshold, posture-conditioned correlator spec (§4.1.1/§4.3.1 incl. the pinned in-model ceiling), §13 result (PROVISIONAL-PASS, local-daemon posture only), §14 founder-cover launch posture + partition-adversary arm spec (§14.4 hypothesis class widened pre-implementation), §15 remote-daemon structural-refusal disposition, §16 mechanization addendum (M1 reward-eligibility-by-shard-count consensus rule pre-flight pin + M2–M7; global-and-blind constraint), §17 review-closure rounds R1–R2 (the three §16.10 attacks answered attack-shaped: N-sweep added, family widened to five members + two label-free channels closed structurally, `K_COVER` cycle traced to its breaking joint; §17.5 the r<2 mean-vs-max challenge run to land — exchangeability named as the load-bearing step, regime-splitting as the mean-to-max carrier), §18 distinct-position round R3 (five-qualifier scope pin on the `1.86`: entry-seam-only / per-post-not-per-principal (cross-seam GF-4 conditional landed on the verdict line) / timing-not-value (loud reward channel verified at source) / per-instant / unstratified; GF-4 + value channel named co-equal sealing-path rounds) — §§15–16 proposed review-gated; §§17–18 conducted, ratification pending |
| [`ARCHIVAL_BOND_2D1_PSCAN_PLAN.md`](ARCHIVAL_BOND_2D1_PSCAN_PLAN.md) | `P`-scan pipeline (SP-0…SP-7, PR-A/PR-B) |
| [`ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md`](ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md) | Transport slices (SP-T0…SP-T5, DQ-N) |
| [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) | Gate-6 rounds, GF-N findings, S-N seam scenarios |
| [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) / [`REWARD_EMISSION_VIN_PLAN.md`](REWARD_EMISSION_VIN_PLAN.md) | Emission leg (PR-E0…E3, C-1) |
| [`DAEMON_SUBMIT_VERDICT.md`](DAEMON_SUBMIT_VERDICT.md) | Daemon submit-verdict series (F-N findings incl. F40/F41) |
| [`PRINCIPAL_STAKE_LIFECYCLE.md`](PRINCIPAL_STAKE_LIFECYCLE.md) | Principal-side stake lifecycle design |
| [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) | Staking/archival simulation harness |
| `docs/completed/` | Closed-out tracks (CT series, DAA/LWMA-1, RandomX v2 phases, …) |
