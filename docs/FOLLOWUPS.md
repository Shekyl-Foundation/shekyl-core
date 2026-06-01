# Follow-ups

Open work items and tracked decisions that did not fit the PR in which they
were discovered. Per `.cursor/rules/15-deletion-and-debt.mdc`, every item has a
target version; items without one get one within 30 days or get closed as
"won't fix." Resolved items are removed — git history is the archive. A short
audit trail is retained at the bottom for items whose resolution is worth
citing in a review.

## Queue structure

The follow-up queue is two queues that share a file but not a risk profile.
The split is load-bearing, not cosmetic; the section headers below reflect
it explicitly.

- **V3.0 pre-genesis queue** is load-bearing. Each item must land before
  genesis cut. Each item carries fixed per-PR overhead (pre-flight + review
  + CI); accumulation compounds the pre-genesis trajectory cost. The
  V3.0 queue's growth rate against resolution rate determines whether
  the discipline pattern is sustainable. When V3.0 items hide inside a
  long undifferentiated list, accumulation looks manageable when it is
  not. Items here are reviewed for "does this still need to land before
  genesis?" on every queue pass; structural deferral (V3.0 → V3.1+)
  requires an explicit decision and a brief rationale.

- **V3.1+ post-genesis queue** is a sustainable backlog. Items are
  well-anchored to precedent PRs; re-derivation cost is low; no
  near-term deadline compounds. The queue can grow indefinitely without
  pre-genesis cost. Items here include rules-queue work (consolidated
  as 1–2 PRs per §11.3 of
  [`docs/design/STAGE_1_PR_3_M3E_PREFLIGHT.md`](./design/STAGE_1_PR_3_M3E_PREFLIGHT.md)),
  post-genesis architecture work (wallet-RPC cutover, `KeyImage`
  `Option`-promotion, `transfer_details` C++ → Rust migration), and
  structural design passes that warrant their own pre-flight
  (non-`Clone` ban re-evaluation).

The calibration shift recorded at the M3e boundary (per
[`STAGE_1_PR_3_M3E_PREFLIGHT.md`](./design/STAGE_1_PR_3_M3E_PREFLIGHT.md)
§11) bends the V3.0 queue's accumulation trajectory: closing PRs in a
migration series fold their own mechanical residue (path renames,
comment-level rationale rewrites, doc-string past-tensing) rather than
deferring it; only genuinely structural items that don't fit the
closing PR's scope are tracked in V3.0 FOLLOWUPS. The V3.1+ queue's
sustainability is unaffected by the recalibration.

---

## V3.0 — wallet stack greenfield Rust rewrite

- **Stage 1 trait-extraction chain — closeout audit (2026-05-29,
  post–PR #88; economics-trait update 2026-05-31, post–PR #94).** The
  §8.1 critical-path chain is landed on `dev`:
  `DaemonEngine` → `LedgerEngine` → (`RefreshEngine` ∥
  `PendingTxEngine`), with the `KeyEngine` trait + `LocalKeys`
  implementor in parallel (landed but not orchestrator-wired at Stage 1
  closeout — **wired in Stage 2, RESOLVED 2026-05-31**; see the `KeyEngine`
  inline-integration entry below); `PersistenceEngine` landed (PR #83) and `EconomicsEngine`
  landed (PR #94), so the orchestrator is now the seven-parameter
  `Engine<S, D, L, E, R, P, F>`.
  Inventory, orchestrator shape (`Engine<S, D, L, E, R, P, F>`), ordered
  next steps, and off-critical-path trait status:
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](./V3_ENGINE_TRAIT_BOUNDARIES.md) §8.1 /
  §1 status banner; per-PR design docs under `docs/design/STAGE_1_PR_*`.
  **Dedicated audit markdown landed:**
  [`docs/design/STAGE_1_COMPLETION_AUDIT.md`](./design/STAGE_1_COMPLETION_AUDIT.md).
  **Still V3.0 pre-genesis but not “missing Stage 1 PR”:** wallet
  BIP-39 FFI, economics §3.3 benches (the persistence and economics
  trait PRs both landed — PR #83 / PR #94; P1 async refresh post-pass
  closed 2026-05-29 by `refresh/p1-async-path-post-pass`).
  **Rewrite plan:**
  [`docs/design/WALLET_REWRITE_PLAN.md`](./design/WALLET_REWRITE_PLAN.md)
  Phases 0–6; Stage 1 was prerequisite, Phase 1+ continues `Engine`.

- **`KeyEngine` inline orchestrator integration — rejected for Stage 1;
  RESOLVED 2026-05-31 by the Stage 2 actor migration.** Shape per
  [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc).

  *Resolution (2026-05-31).* The reversion clause's positive decision was
  taken exactly as specified: the orchestrator now holds
  `key: KeyEngineHandle` (not an inline `K: KeyEngine` parameter) — `Engine`
  stays seven-parameter `Engine<S, D, L, E, R, P, F>`, the
  `Arc<AllKeysBlob>` field is gone, and the blob lives solely in the
  `KeyActor`. See `docs/design/STAGE_2_KEY_ENGINE_ACTOR.md` §6 (steps 3–4)
  and the "Stage 2 — `KeyEngine` migration to actor" entry below, which
  records the completed DoD (including the B9 dispatch-overhead benchmark —
  PASS, ratio 1.039). The reject-the-inline-shape rationale below is retained
  as the historical record of why the deferral was correct.

  *Rejection (current substrate).* `KeyEngine` is the one extracted Stage 1
  trait deliberately **not** wired into the orchestrator. `Engine` holds
  `keys: Arc<AllKeysBlob>`
  (`rust/shekyl-engine-core/src/engine/mod.rs:344`) rather than a
  `K: KeyEngine` generic parameter with a `LocalKeys` field, and `KeyEngine`
  is the only `engine/traits/` module not re-exported from
  `engine/traits/mod.rs`. `LocalKeys` exists and is exercised by tests but
  carries `#[allow(dead_code)]` in production builds. Wiring an inline
  `K: KeyEngine = LocalKeys` parameter now is rejected on two
  substrate-anchored grounds:
  1. *Throwaway shape.* The Stage 2 end-state holds key material behind a
     `KeyEngineHandle` actor handle, **not** an inline field (see the
     "Stage 2 — `KeyEngine` migration to actor" entry below). An inline `K`
     parameter would be added in Stage 1 and deleted in Stage 2 — the
     pre-provision-for-flexibility failure mode the discipline rejects, and
     the cost-benefit-defer inversion `16-architectural-inheritance.mdc`
     names.
  2. *No production work to dispatch.* The two workflow methods that would
     make an integrated `KeyEngine` load-bearing — `try_claim_output` and
     `sign_transaction` — depend on Phase 2 tx-construction/signing that
     does not exist yet (`sign_transaction` is a stub; output-claim is
     currently served by `derive_output_handle` on the scanner merge path).

  *Reopening criteria (substrate-anchored).* The rejection reverts to a
  positive decision when **all** of: (a) the Stage 1 actor-friendly
  trait-boundary refactor lands (between Branch 2 close and Phase 2b); (b)
  `kameo` becomes a live workspace consumer (pin / MSRV / bounded-mailbox
  preconditions already satisfied — see the `kameo` dependency-pin entry
  below); and (c) Stage 2 opens the `KeyEngine`→actor migration. The
  orchestrator then gains a `KeyEngineHandle`, **not** an inline `K`
  parameter — the deferral is against the inline shape specifically, not
  against integration as such.

  *Re-evaluation shape.* The Stage 2 `KeyEngine`-actor PR (design-doc-first
  per `05-system-thinking.mdc`, reviewed against the `00-mission.mdc`
  security hierarchy) takes the decision; its definition of done is the
  "Stage 2 — `KeyEngine` migration to actor" entry below. The trait surface
  is frozen now precisely so the migration swaps in-process composition for
  an actor-mailbox dispatcher without touching method signatures (per
  [`STAGE_1_PR_3_KEY_ENGINE.md`](./design/STAGE_1_PR_3_KEY_ENGINE.md) §3.1.2
  handle-indirected workflow contract).

  *Target:* before Phase 2b stake-lifecycle work begins (same gate as the
  Stage 2 actor migration it reopens into).

- **Base emission migration (Stage 1 PR 7 §5.8) — CLOSED 2026-05-30 by
  C2c cutover.** PR #88 landed C2 and C2a′ on `dev` (Rust `base_block_reward`
  + `projected_already_generated`, dual-leg KAT harnesses
  `tests/unit_tests/economics_c2a_prime.cpp` /
  `tests/core_tests/economics_c2a_prime.cpp`, required CI checks, and the
  `shekyl_base_block_reward` FFI). C2c (`feat/stage-1-pr7-economics-cutover`,
  off the post–7-base `dev` tip; 7-base merge `fed6f594b`, C2a′ ancestor by
  topology) completes the migration:

  - `cryptonote::get_block_reward` (4-arg) now delegates the base subsidy to
    `shekyl_base_block_reward` via the `shekyl::base_subsidy_before_penalty`
    thin wrapper in `src/shekyl/economics.h` (same shape as
    `compute_fee_burn` / `compute_emission_split`);
  - the duplicated C++ ESF body (`(MONEY_SUPPLY - already_generated) >> esf`
    + tail floor) is deleted from
    `src/cryptonote_basic/cryptonote_basic_impl.cpp`;
  - the weight penalty (`mul128` / `div128_64`) and the 5-arg release
    multiplier path stay in C++ (per §5.8, behavior-identical to C2a′
    witnesses);
  - fix α (`:1608–1609` un-overwrite) was already landed in 7-base.

  No production path computes the ESF curve in C++ after this cutover. The
  C2a′ dual-leg KAT (`leg A` compares `get_block_reward` to
  `shekyl_base_block_reward`) remains bit-identical post-cutover.

  **Design:**
  [`docs/design/STAGE_1_PR_7_ECONOMICS_ENGINE.md`](./design/STAGE_1_PR_7_ECONOMICS_ENGINE.md)
  §5.8 / §6.2 item 1 (7-cutover). **Delivered:** V3.0 (PR 7 base-emission
  completion). Wallet-only permanent cross-check bridge remains rejected.

- **Post-2g adversarial-corpus methodology + implementation
  (trigger: RandomX v2 Phase 2g Round 7 R7-D1/R7-D2 reopening
  of R1-D5 + R1-D6; *closed by Phase 2h implementation PR*).**
  *Phase 2h closes this item by replacement: the methodology
  lands as the recipe-based adversarial corpus per
  [`docs/design/RANDOMX_V2_PHASE2H_PLAN.md`](./design/RANDOMX_V2_PHASE2H_PLAN.md)
  R1-D1 (specified-outliers composition); the accessor lands
  at C2 as `PreparedCache::from_raw_for_testing`
  (`rust/shekyl-pow-randomx/src/prepared_cache.rs` under the
  `test-internals` feature gate, with C-side symmetry via
  `randomx_get_cache_memory` per R1-D2 close); the recipe
  corpus + evaluator land at C3/C4
  (`rust/shekyl-randomx-differential/src/adversarial/`); the
  canonical-output pinning lands at C5
  (`adversarial_canonical_outputs.rs`); the worst-case-ratio
  measurement mode lands at C6
  (`mode_adversarial_ratio`); T2/T6 reactivate at C7 with
  inherited `#[ignore]` gating behind the (then-open) V3.0
  `shekyl-pow-randomx::compute_hash`-divergence-from-C-reference
  FOLLOWUP; the CI workflow wiring lands at C8
  (per-PR T2 step in `randomx-v2-differential.yml` +
  workflow_dispatch T6 in `randomx-v2-adversarial-ratio.yml`,
  both `if: false`-gated until the divergence FOLLOWUP closes);
  the M5 mechanical citation-validation script lands at C9
  (`scripts/ci/check_phase2h_citations.sh`). The divergence
  FOLLOWUP itself closed on `dev` via PR #79 (`989610cac`,
  2026-05-26; root cause: `RANDOMX_FLAG_V2` missing at
  `randomx_create_vm`). PR #78's post-rebase work (`c71ce2413`
  extending the same fix to `COracleSession::from_raw_for_testing`
  plus the operational close: lifting T2's `#[ignore]`,
  reframing T6's docs, and lifting both workflows' `if: false`
  gates) discharges the activation-surface contract recorded
  above. Original framing preserved below for historical
  context.* Phase 2g
  [`docs/design/RANDOMX_V2_PHASE2G_PLAN.md`](./design/RANDOMX_V2_PHASE2G_PLAN.md)
  §3.19 R7-D1 reopens R1-D5 (adversarial seedhash corpus) under
  two independent substrate findings: (i) the verifier-accessor
  gap (the grinding methodology requires a `test-internals`-gated
  opcode-stream accessor on `shekyl-pow-randomx` whose
  implementation duplicates `compute_hash_inner` under a feature
  gate); (ii) the statistical-infeasibility gap (R1-D5's
  ≥40% per-class / ≥60% combined acceptance criteria were
  calibrated against V1's PROGRAM_SIZE = 256 and are unreachable
  by random grinding against V2's PROGRAM_SIZE = 384 — per-class
  σ-gaps run from 6.8σ (CACHE_MISS) to ~125σ (CFROUND); zero
  threshold-meeting candidates expected within any realistic
  compute budget). §3.19 R7-D2 reopens R1-D6 (u128 / `__int128_t`
  edge-case data corpus) by structural analogy — same
  program-generation pipeline, same V2 substrate. §3.19 R7-D3
  defers R1-D8 (worst-case timing) along with them, since R1-D8's
  required input is the deferred R1-D5 + R1-D6 union corpus.

  **Scope.** The post-2g design round produces:

  1. **A V2-substrate-anchored adversarial-corpus methodology.**
     The class-heaviness framing is V1-shaped. A V2 framing is
     required. Candidate shapes named for the round's consideration
     (not closed here): tail-percentile grinding (define
     "adversarial" as the top 99.99th percentile of class-X
     density across a fixed candidate budget, reachable by
     construction); hybrid synthetic + grinded construction;
     spec-derived rare-path enumeration. The round closes one of
     these or names a new shape with substrate evidence.
  2. **The verifier-side or C-shim accessor** the chosen
     methodology requires. The R7-D1 sketch
     (`compute_hash_opcode_streams_for_testing` under `cfg(feature
     = "test-internals")`) is one shape; the round re-derives the
     accessor under the new methodology's constraints, which may
     differ.
  3. **The grinding tool** (if the chosen methodology grinds) at
     `rust/shekyl-randomx-differential/src/bin/grind_adversarial_corpus.rs`
     or analogous.
  4. **The adversarial corpus contents** committed as hex bytes
     in `rust/shekyl-randomx-differential/src/adversarial_corpus.rs`.
  5. **Reactivate §6 T2** (`adversarial_corpus_byte_equality`)
     and §6 T6 (`worst_case_ratio`) in the test plan; reactivate
     §5.1.11 `mode_worst_case` at the harness binary.
  6. **Plan-doc amendment**: append a Round-N close documenting
     the post-2g resolution; close R7-D1 + R7-D2 + R7-D3 + R7-D4
     by replacement.

  **Pre-genesis target rationale.** The 2g harness ships with
  common-path leg-3 coverage (random corpus + canonical outputs
  + cache-equivalence). Rare-path coverage is carried in the
  interim by legs 1 (spec-faithful implementation discipline)
  and 2 (C-reference audit). Per
  [`docs/design/RANDOMX_V2_PHASE2G_PLAN.md`](./design/RANDOMX_V2_PHASE2G_PLAN.md)
  §2.5's corpus-coverage-as-leg-3-completeness pin, the deferral
  reduces leg-3's residual catch capacity until the post-2g
  round lands. Landing pre-genesis preserves the "Shekyl's
  verifier is canonical RandomX v2" claim's full audit-posture
  evidence at genesis cut.

  **Reopening criterion (escalation ahead of V3.0 target).**
  Per [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)'s
  priority-1 security override rule: a Phase-2 audit finding
  that surfaces a rare-path divergence at genesis the random +
  canonical-output corpus misses forces this item ahead of its
  V3.0 target version.

  **Cross-references.**
  [`docs/design/RANDOMX_V2_PHASE2G_PLAN.md`](./design/RANDOMX_V2_PHASE2G_PLAN.md)
  §3.19 R7-D1 + R7-D2 + R7-D3 + R7-D4 + R7-D5; §2.5 Round 7
  amplification; §3 R1-D5 / R1-D6 / R1-D8 close annotations
  (reopened banners); §6 T2 / T6 (deferred); §8.1 C5b / C7
  commit rows (rescoped).

- **Refresh bandwidth tradeoff under α — round-trip-bound block
  fetches on cold sync (trigger: PR 4 Round 1 disposition;
  V3.0 RC stabilization).** Stage 1 PR 4 (`RefreshEngine`
  extraction) Round 1 disposed to **α — preserved current shape**
  per
  [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](./design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4. α retains the existing serial-fetch-serial-scan shape
  from
  [`rust/shekyl-engine-core/src/engine/refresh.rs`](../rust/shekyl-engine-core/src/engine/refresh.rs):
  each block costs one daemon RPC round-trip; cold-sync against
  a remote daemon is round-trip-bound rather than
  throughput-bound. β-style internal batching (parallel fetch +
  serial scan; sliding-window prefetch) amortizes this but is
  correctly out-of-scope for PR 4 per
  [`19-validation-surface-discipline.mdc`](../.cursor/rules/19-validation-surface-discipline.mdc) —
  it shares the feature topic "refresh" with α/β/γ but does not
  share the producer-redesign decision's validation surface
  (β's surface is amortized round-trip latency; α/β/γ's surface
  is the consumer pattern's contract shape).

  **Severity.** UX-grade on cold-sync against remote daemons
  (LAN-local or co-resident daemon round-trips are sub-millisecond
  and amortize out under any reasonable scan cost; remote
  daemon round-trips dominate when each is on the order of tens
  of milliseconds and the wallet is fetching tens of thousands
  of blocks). Not a correctness property — α produces the same
  `ScanResult` β/γ would, just over more wall-clock time.

  **Disposition.** This entry is the cost-benefit-analysis
  artifact PR 4 Round 1's α-disposition consumed; recording it
  in V3.0 makes the tradeoff load-bearing on RC stabilization
  rather than open-ended on the post-genesis backlog. Pre-RC1
  work: profile cold-sync bandwidth against the Foundation
  reference daemon (per the multi-source archival disposition
  elsewhere in this file). If the cold-sync experience is
  unacceptable on commodity remote-daemon configurations,
  escalate to β as a follow-up PR (own scope, own validation
  surface, own design rounds — not retroactive amendment to
  PR 4). The pruning-vocabulary disambiguation in
  [`docs/design/REFRESH_DESIGN_LANDSCAPE.md`](./design/REFRESH_DESIGN_LANDSCAPE.md)
  §7 is the reference for which prune-shape (β internal batching
  vs. wallet-side prune-by-birthday vs. daemon-side
  `--prune-blockchain` vs. archival `--no-prune`) applies to
  which segment of the cold-sync cost.

  **Originating context.** PR 4 Round 1 disposition commit on
  `feat/stage-1-pr4-refresh-engine-design` (this commit). The
  validation-surface guard rule on `dev` cites α/β as a
  worked-example surface separation for exactly this entry;
  PR 4 Round 1 §5.4.2 records the rule citation as the
  primary reason β/γ are independent surfaces, not bundled
  into PR 4.

  **Cross-references.**
  [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](./design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4 (α disposition), §5.5 (work-list table);
  [`docs/design/REFRESH_DESIGN_LANDSCAPE.md`](./design/REFRESH_DESIGN_LANDSCAPE.md)
  §6 (the producer-pattern axis), §7 (pruning vocabulary).

  **Target.** V3.0, RC stabilization window (or earlier
  follow-up PR if cold-sync profile escalates the disposition).

- ~~**P1 (latent): refresh post-pass skipped on async path —
  `populate_engine_handle_fields` does not run when refresh
  dispatches through `LedgerEngine::apply_scan_result` (re-anchored
  2026-05-20 after PR 4 Phase 1 landed without absorption; **hard
  precondition: P1 closes before any binary integrates
  `RefreshHandle`**; pre-RC1).**~~ **CLOSED 2026-05-29 by shape (b)
  (`refresh/p1-async-path-post-pass`).** The `LedgerEngine`
  trait's `apply_scan_result` mutator was removed (the trait is now
  read-only: `synced_height` / `snapshot` / `balance`), and
  `run_refresh_task` / `Engine::start_refresh` were specialized to
  `LocalLedger`. The async refresh path now merges through the
  `LocalLedger`-specialized inherent `Engine::apply_scan_result`
  (`engine/merge.rs`), which runs `apply_scan_result_to_state`
  **and** the M3b post-pass `populate_engine_handle_fields` under a
  single `LocalLedger` write guard — the same path the synchronous
  `Engine::refresh_with` already used. Newly-merged transfers on the
  async path now get `output_handle` / `source_ciphertext`
  populated. Shape (b) was chosen over shape (a) because routing the
  carryout `Vec<usize>` back through a trait method would split the
  merge and post-pass across the trait boundary, violating the
  single-write-guard atomicity the M3b disposition requires
  (`docs/design/STAGE_1_PR_3_M3B_PREFLIGHT.md` §3 rejected
  alternative (ζ)). The ledger-side `FaultInjecting<LocalLedger>`
  test wrapper (whose only purpose was injecting `ConcurrentMutation`
  at the removed trait seam) and the now-dead `replace_ledger`
  test helper were deleted; the hybrid retry tests now drive the
  retry producer-side via a stale `ScanResult` the real merge
  rejects. P3 closes in the same commit. The async refresh task in
  `rust/shekyl-engine-core/src/engine/refresh.rs` calls
  `g.ledger.apply_scan_result(result).await` (trait dispatch on
  `L: LedgerEngine`, generalized in PR 4 C5β / C6β so the
  retry-loop dispatches against `FaultInjecting<LocalLedger>` for
  hybrid fault-injection tests). The trait method returns
  `Result<(), _>`, discarding the inserted-indices `Vec<usize>`
  produced by `apply_scan_result_to_state`. The engine post-pass
  (`populate_engine_handle_fields`) lives above the trait per
  M3b's "engine post-pass at the orchestrator layer" disposition —
  consumers of `LedgerEngine` other than the engine have no use
  for the post-pass, so the trait surface stays bookkeeping-only.
  The two decisions together skip the post-pass on the production
  async refresh path: newly-merged transfers do not get their
  `output_handle` / `source_ciphertext` populated. The two paths
  diverge by construction at
  `rust/shekyl-engine-core/src/engine/local_ledger.rs:356–367`
  (trait-method `apply_scan_result` — discards the `Vec` via
  `.map(|_| ())`) vs.
  `rust/shekyl-engine-core/src/engine/merge.rs:181–215`
  (inherent `Engine::apply_scan_result` — runs
  `populate_engine_handle_fields` against the captured
  `inserted` indices).

  **Severity.** P1 *latent*. Correctness-breaking but currently
  dormant: as of `dev` tip and the post-PR-4-Phase-1 substrate,
  no Shekyl binary calls `start_refresh`. The gap becomes live
  the moment any binary integrates `RefreshHandle` and relies on
  post-merge transfers having their engine-handle fields
  populated.

  **Post-PR-4-Phase-1 substrate.** PR 4 Phase 1 (commits C0–C9
  on `feat/stage-1-pr4-refresh-engine`; close-out at PR #60)
  landed the α producer-shape disposition: the producer/consumer
  pattern settled on α (preserved current shape) per
  [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](./design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4 Round 1, and the `LedgerEngine::apply_scan_result` trait
  surface was not changed by Phase 1. Phase 1 therefore did not
  absorb P1 by reshape, as the pre-Phase-1 disposition
  ("defer to PR 4") anticipated. P1 remains open against the
  same trait-method discard pattern in `local_ledger.rs:356–367`.

  **Disposition (re-anchored 2026-05-20).** Defer to a focused
  follow-up PR off `dev` named
  `refresh/p1-async-path-post-pass` (or equivalent), landing
  V3.0 pre-genesis. The §8 named-home table on the PR 4 design
  doc enumerates the two shapes that both close P1 against the
  PR 4 substrate: (a) `LedgerEngine::apply_scan_result` grows
  to surface the insertion-range carryout — the `Vec` is
  consumed, P1 and P3 close together; (b) the merge post-pass
  moves onto `RefreshEngine` (the new trait landed in PR 4
  C1 / C4) and `LedgerEngine::apply_scan_result` is removed —
  the discard sites disappear with the trait method, P1 and P3
  close together. Either shape is a focused PR (≤ ~5 files;
  ≤ ~200 lines) and respects `06-branching.mdc`'s splitting
  guidance. The shape selection itself is a small design round
  (1–2 rounds) sized to the cost-benefit tradeoff between (a)
  cross-trait surface growth and (b) cross-trait responsibility
  migration; both shapes preserve the M3b "engine post-pass at
  the orchestrator layer" architectural invariant.

  **Hard precondition.** P1 must close before any binary
  integrates `RefreshHandle`. Treating this as a rule-grade
  precondition (rather than a "we'll get to it") is what makes
  the deferral discipline-grade per
  `.cursor/rules/15-deletion-and-debt.mdc`'s "deferred without
  a named home is the failure mode" framing. A binary that
  integrates `RefreshHandle` before this entry resolves is
  itself a rule violation. The precondition survived PR 4
  Phase 1 landing intact — Phase 1 was the *first* of two
  necessary substrate changes (RefreshEngine trait exists,
  enabling shape (b); LedgerEngine trait surface still in scope
  for shape (a)); P1 closure is the second.

  **Reopening criteria (per
  [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)).**
  This entry closes when **either** (a) or (b) lands (close P1
  and P3 in the same focused PR — they are downstream of the
  same trait-surface choice) **or** when a Shekyl binary
  integrates `RefreshHandle` and the integration PR's
  pre-flight surfaces the gap as blocking (escalates the
  precondition into a rule violation). The entry **reopens
  with higher severity (P0)** if a binary integrates
  `RefreshHandle` while P1 is still open.

  **Originating context.** Surfaced during the
  `perf/merge-insertion-indices` interim PR (commit `b9b0704b7`,
  which added `.map(|_| ())` to `LocalLedger::apply_scan_result`
  to preserve the trait signature when the underlying merge body
  began returning `Vec<usize>`). The `.map(|_| ())` made the
  silent skip explicit; the explicitness is why it surfaced. See
  `docs/design/PERF_MERGE_INSERTION_INDICES_PREFLIGHT.md` §9.2
  for the full trace, and the PR 4 design doc §5.5 named-home
  table row for P1 for the substrate-post-Phase-1 cross-ref.

- ~~**P2: wallet-birthday plumbing not wired into producer
  start-height**~~ **Closed (2026-05-30, branch
  `refresh/p2-wallet-birthday-plumbing`).** Landed Shape A
  (ledger anchor before scan): `effective_scan_floor` from
  `sync_state.restore_from_height` plus
  `WalletFile::effective_skip_to_height` /
  `effective_refresh_from_block_height`; `scan_start_floor` on
  `LocalRefresh::new`; `ensure_birthday_anchor` before refresh.
  The producer derives its scan start from the anchored snapshot
  (`snapshot.synced_height + 1`) rather than re-deriving a floor at
  producer time, and progress `blocks_total` reflects the post-anchor
  range — this closed the residual TOCTOU race between the anchor's
  daemon-height read and the producer's start computation (the
  earlier `scan_range_start` / `effective_floor_at_tip` helpers were
  removed in commit `87264a3a2`). `Engine::create` seeds
  `sync_state.restore_from_height` from `restore_height_hint`.

  **Reopening criteria (unchanged).** Reopens as P1 if a binary
  integrates `start_refresh` on restored-from-seed wallets and
  cold-sync latency still dominates wallet open despite this
  plumbing (regression or incomplete wiring).

- ~~**P3: `apply_scan_result_to_state` allocates `Vec<usize>` even
  for trait-impl callers that discard it (re-anchored 2026-05-20
  after PR 4 Phase 1 retained the discard shape; downstream of
  P1; pre-RC1).**~~ **CLOSED 2026-05-29 by shape (b)
  (`refresh/p1-async-path-post-pass`), same commit as P1.** The
  discard sites disappeared with the removed
  `LedgerEngine::apply_scan_result` trait method and its
  `LocalLedger` impl. `apply_scan_result_to_state` retains its
  `Vec<usize>` return, but the only remaining callers
  (`Engine::apply_scan_result` and the merge unit tests) consume the
  indices — the async refresh path now routes through
  `Engine::apply_scan_result`, so no caller constructs-then-discards
  the Vec. PR #37 (perf interim) changed
  `apply_scan_result_to_state`'s return from `()` to `Vec<usize>`
  so the engine post-pass can walk inserted indices in O(k). The
  trait-impl callers (`LocalLedger::apply_scan_result` at
  `rust/shekyl-engine-core/src/engine/local_ledger.rs:356–367`,
  and `FaultInjecting<LocalLedger>::apply_scan_result` by
  delegation through the inner) discard the Vec via
  `.map(|_| ())` to preserve the `LedgerEngine::apply_scan_result`
  trait signature `Result<(), _>`. The discard wastes
  `Vec::with_capacity(new_transfers.len())` allocation per merge
  on those paths — at most ~100 entries per typical refresh
  batch, so ~hundreds of bytes at sub-Hz frequency.

  **Severity.** P3 — measurable but negligible perf cost
  (~hundreds of bytes per refresh batch). Surfaced by Copilot
  PR #37 review as a candidate factoring (separate
  `apply_scan_result_to_state_no_indices` variant or a generic
  sink parameter).

  **Why not fold into PR #37.** The discard sites are
  architectural shims awaiting PR 4. PR 4 was anticipated to
  resolve the async-path-skip P1 by either (a) routing the
  post-pass through the trait dispatch (Vec gets used →
  optimization is dead code), or (b) removing the trait impl's
  `apply_scan_result` entirely (optimization is irrelevant).
  Optimizing the shim then would have been the
  cost-benefit-defer-to-later anti-pattern's inverse: doing
  incremental work now that PR 4 reshapes anyway. Per
  `.cursor/rules/16-architectural-inheritance.mdc`, the fix was
  to ride with PR 4's reshape.

  **Post-PR-4-Phase-1 substrate.** PR 4 Phase 1 (commits C0–C9
  on `feat/stage-1-pr4-refresh-engine`; close-out at PR #60)
  landed the α producer-shape disposition per
  [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](./design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4 Round 1, and the `LedgerEngine::apply_scan_result` trait
  surface was not changed by Phase 1. The pre-Phase-1
  disposition's own reversion criterion ("If PR 4's α/β/γ
  producer-redesign Round 1 chooses a pattern that retains the
  discard shape (i.e., the trait method continues to return
  `()`), revisit this entry as a separate factoring PR") fired
  explicitly — the chosen α retains the discard shape, and the
  trait method still returns `Result<(), _>`. P3 is therefore
  no longer "wait for PR 4"; it is "downstream of P1's
  resolution."

  **Disposition (re-anchored 2026-05-20).** Downstream of P1.
  Both candidate P1-closing shapes ((a) trait grows insertion-
  range carryout; (b) `RefreshEngine` owns the merge post-pass)
  close P3 as a side effect, so P3 does not need an independent
  fix or a separate factoring PR. The focused PR that closes
  P1 (`refresh/p1-async-path-post-pass` or equivalent) also
  closes P3. P3 stays catalogued separately rather than folded
  into P1's entry to preserve the Copilot PR #37 audit trail
  (comment ID 3215308856 → P3 entry → P1 closure) per
  `15-deletion-and-debt.mdc`'s "deferred without a named home
  is the failure mode" framing.

  **Reopening criteria (per
  [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)).**
  This entry closes alongside P1 (same focused PR). The entry
  reopens as an independent factoring PR only if P1's closure
  PR for some reason fails to consume the `Vec<usize>` at the
  trait boundary (e.g., the PR introduces an intermediate
  shape where the Vec is still constructed-then-discarded on
  the trait-dispatch path) — substrate-anchored to the PR's
  diff, not to schedule pressure.

  **Originating context.** Copilot PR #37 review (second pass,
  2026-05-10), comment ID 3215308856 on `merge.rs:336`. See
  the PR 4 design doc §5.5 named-home table row for P3 for
  the substrate-post-Phase-1 cross-ref.

- **F11-S Windows-midrange-PC measurement revisit at stressnet
  (trigger: PR 4 lands the Linux-laptop F11-S measurement evidence
  at design-doc §7.Y, 2026-05-20; close-condition: stressnet phase
  captures the matching Windows-midrange-PC measurement against the
  same bench harness; Phase 7.7).** Per
  [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](./design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §4184–§4238 (F11-S sub-pin), Phase 1 commit-author for C4 decides
  per-tx vs. per-output safe-point granularity against benchmarked
  `recover_outputs_in_tx` cost. The reference measurement captured
  on the Phase 1 author's Linux laptop on AC against the bench
  harness landed at commit `46c64760d`
  (`rust/shekyl-scanner/benches/scan_transaction.rs`, group
  `worst_case_all_view_tags_match`, F11-S binding identified in
  code via the `F11S_BINDING_GROUP` constant; per-output worst-case
  cost = full hybrid PQC slow path with subaddress-lookup miss).
  **Measurement disposition (2026-05-20):** worst-case per-tx scan
  time at `N = MAX_OUTPUTS = 16` measures 12.95 ms cold p99 (~13×
  the §3.1 1 ms target); C4 lands the per-output safe-point
  granularity per §4209–§4217 of the F11-S sub-pin. The durable
  measurement evidence (environment, four data points × two
  groups × two cache variants, iai-callgrind cross-check, sanity
  check, governor-sensitivity analysis, re-measurement protocol)
  lives at design-doc §7.Y; the C4 commit message summarizes and
  cites §7.Y per the §4222–§4238 audit-trail discipline.

  **Why the Linux-laptop measurement alone is not the audit floor.**
  The §3.1 millisecond-scale lock-latency target is a property of
  the wallet experience on commodity user hardware. A laptop-class
  measurement on Linux + AC overstates the hardware floor relative
  to the commodity-Windows-midrange configuration that dominates the
  real wallet-user population. Per `00-mission.mdc` priority 3 ("the
  system must outlast the team"), the lock-latency property must
  hold against the hardware Shekyl users actually run, not against
  the developer's laptop. The Linux-laptop measurement is sufficient
  for C4's Phase-1-author-time disposition (the bench harness's
  worst-case cost is constant-time-bounded and scales linearly with
  single-thread crypto throughput, so a Linux-laptop measurement
  plus C4's 2× safety margin should cover the Windows-midrange floor
  with headroom by construction); it is **not** sufficient as the
  audit-trail floor.

  **Disposition.** Defer the Windows-midrange-PC measurement to
  stressnet (Phase 7.7), the V3.0 phase that exercises the full
  wallet-refresh path under realistic reorg and varied-
  reference-block conditions per the existing Phase 7.7 entries
  (`FCMP_REFERENCE_BLOCK_MAX_AGE = 100` cluster, cross-referenced
  below). At stressnet, the designated Windows midrange PC re-runs
  the `scan_transaction` bench harness (criterion + iai-callgrind
  companion) on the same `worst_case_all_view_tags_match` and
  `typical_case_view_tag_filtered` groups against the same
  `OUTPUT_COUNTS = {1, 4, 8, 16}` sweep, and the resulting
  measurement is captured into the stressnet audit trail using the
  same commit-message template C4 used (four data points + slow-
  path-to-fast-path ratio sanity check + decision threshold + chosen
  granularity).

  **Re-evaluation per
  [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc).**
  C4 lands per-output safe-point granularity on the Linux-laptop
  measurement (820 µs cold p99 per-output marginal cost, within
  the §3.1 1 ms raw target by 0.82× but exceeding the strict 2×
  safety-margin decision-line by 1.64×). The Windows-midrange
  re-measurement either confirms (per-output cost remains within
  the §3.1 1 ms raw target on commodity Windows hardware ⇒ this
  entry closes with the Windows-midrange data points appended to
  §7.Y and no code change) or escalates (per-output cost exceeds
  the §3.1 raw target on commodity Windows hardware ⇒ further
  safe-point granularity refinement, per-N-output batching, or
  per-output crypto-cost optimization is required, landing in a
  focused PR off `dev` named
  `refresh/f11s-stressnet-granularity-escalation`). The escalation
  PR is wallet-internal scope; not a chain-rule change.

  **Close-condition.** A stressnet commit captures the Windows-
  midrange-PC F11-S measurement against the bench harness and
  appends the data points to design-doc §7.Y as a new
  `§7.Y.N`-shape sub-section per the §7.Y.10 re-measurement
  protocol. Either (a) the Windows-midrange per-output cold p99
  remains within the §3.1 1 ms raw target, in which case the audit
  trail extends and this entry closes; or (b) the Windows-midrange
  per-output cold p99 exceeds the §3.1 raw target, in which case
  the escalation PR closes both this entry and the F11-S sub-pin.

  **Cross-references.**
  [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](./design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §4184–§4238 (F11-S sub-pin and per-output escalation criterion);
  §7.Y (durable Phase 1 author measurement evidence and
  re-measurement protocol);
  `rust/shekyl-scanner/benches/scan_transaction.rs` and
  `rust/shekyl-scanner/src/bench_fixtures.rs` (bench harness; F11-S
  binding named in code via the `F11S_BINDING_GROUP` constant);
  `rust/shekyl-scanner/src/scan.rs` (`MAX_OUTPUTS = 16` scanner-side
  gate at `scan_transaction` entry, the consensus-binding bound the
  bench's N sweep is anchored to); the existing Phase 7.7 stressnet
  entry above (FCMP++ historical-tree-path cluster) as the
  precedent that stressnet is the V3.0 phase where wallet-side
  measurements against commodity hardware are captured.

  **Target.** V3.0, Phase 7.7 stressnet.

- **Stage 1 PR 3 engine-property test re-location (trigger: V3.2
  unified `KeyEngine` / `LedgerEngine` / `DaemonEngine`
  `pub(crate) → pub` visibility-promotion bundle per
  `STAGE_1_PR_3_KEY_ENGINE.md` §7.7; pre-RC1).** Two Stage 1 PR 3
  property tests landed as unit tests in
  `rust/shekyl-engine-core/src/engine/local_keys.rs`'s `mod tests`
  rather than the integration-test placement their pre-flights
  specified, both forced by the same M3a Round 4a `pub(crate)`
  lock on `KeyEngine`, `LocalKeys`, `SourceSecretsBundle`, and
  `KeyEngineError`: integration tests run as external crates and
  cannot reach `pub(crate)` items. The properties the tests pin
  are identical regardless of placement; the locations are purely
  visibility artifacts.

  **Tests covered by this entry.**

  - *M3b D5 — byte-identical bundle-derivation test.*
    `derive_source_secrets_bundle_byte_identical_against_legacy_chain`
    at `rust/shekyl-engine-core/src/engine/local_keys.rs:1258`.
    Pre-flight specification:
    `docs/design/STAGE_1_PR_3_M3B_PREFLIGHT.md` §D5
    (`rust/shekyl-engine-core/tests/byte_identical_derivation.rs`).
    Pins bundle-byte identity between engine and legacy derivation
    paths field-by-field. The pre-flight estimated a separate
    `..._subaddress` peer test for the subaddress sweep; in
    implementation the sweep over
    `subaddress_idx ∈ {PRIMARY, 1, 42}` was consolidated into
    this single test's inner loop (see test body at lines
    1278–1322), so the entry covers one test, not two.
  - *M3c-via-C — engine-bundle end-to-end signing test.*
    `engine_derived_bundle_signs_through_tx_builder_end_to_end`
    at `rust/shekyl-engine-core/src/engine/local_keys.rs:1554`.
    Pre-flight specification:
    `docs/design/STAGE_1_PR_3_M3C_PREFLIGHT.md` §2.1 (Option C
    disposition; `rust/shekyl-engine-core/tests/` integration
    placement, suggested name `key_engine_sign_e2e.rs`). Pins
    end-to-end recovery-correctness through
    `tx_builder::sign_transaction` plus BP+ / FCMP++ verifier
    acceptance — the property M3d's removal of the legacy
    bundle-derivation fallback depends on.

  **Trigger condition (substrate-anchored).** When the **unified
  V3.2 visibility-promotion bundle** lands per
  `STAGE_1_PR_3_KEY_ENGINE.md` §7.7 ("V3.x full-PQC trait churn
  acknowledgement") and §3.4 Decision 4 — the bundle promotes
  `KeyEngine`, `LedgerEngine`, and `DaemonEngine` from
  `pub(crate)` to `pub` together when the actor abstraction
  surfaces concrete external consumers. **Unilateral `KeyEngine`
  widening does not satisfy this trigger** — Stage 1's Trust-class
  A classification (PR 3 §2.1 trust-class table row for `KeyEngine`)
  and the unified-bundle disposition both lock all three engine traits
  to move together; promoting `KeyEngine` alone re-introduces the
  trust-model incoherence the lock prevents. When the V3.2 bundle
  lands and `SourceSecretsBundle` / `KeyEngineError` ride along
  with the trait per the bundle's enumerated surface, both
  property tests should be re-located to their pre-flights'
  planned integration-test placements so they exercise the same
  surface external consumers will exercise. The re-location is
  one PR covering both tests (not two separate PRs): the
  visibility flip is the trigger for both, and bundling them
  keeps the migration-tail discipline cost bounded. The
  deviations are recorded inline in each test docstring
  (`local_keys.rs:1243-1251` and `:1538-1541`) so a future
  maintainer cross-referencing either pre-flight finds the
  tracking link. Pre-RC1.

- **`RecoveredWalletOutput.key_image`: promote to `Option<KeyImage>`
  (target: V3.1).** Today the field is typed `KeyImage` and the test
  helper `RecoveredWalletOutput::new_for_test` produces a zero
  `KeyImage` to mean "no key image computed yet." The boundary in
  `shekyl-scanner::ledger_ext` filters that zero out before
  populating `TransferDetails.key_image: Option<KeyImage>`, so the
  no-image-yet semantics propagate one hop. The runtime scanner path
  always computes a real key image, so the sentinel exists purely to
  serve the test fixture and a hypothetical view-only path that
  doesn't currently flow through `RecoveredWalletOutput`. Promoting
  the scanner field to `Option<KeyImage>` (and updating the test
  helper to `key_image: None`) lets us delete the
  `if ki.as_bytes() != &[0u8; 32]` filter at the boundary and aligns
  the wire-state shape with `TransferDetails`. Tracked here because
  the Stage 1 PR 3 sweep that landed `KeyImage` newtypes deliberately
  preserved the existing semantics rather than changing two contracts
  (typing + Option-promotion) in one commit. Target: V3.1, alongside
  the `transfer_details` Rust migration that will already be touching
  every consumer of `TransferDetails.key_image`.

- **`shekyl-fcmp`: resolve `useless_conversion` clippy warnings in
  `frost_sal.rs` (target: V3.1).** `cargo clippy --workspace
  --all-targets --features multisig` (or `--all-features`) surfaces
  ~12 `useless_conversion` warnings in `shekyl-fcmp/src/frost_sal.rs`
  (e.g. `(*bytes).into()` where `*bytes` is already `[u8; 32]`,
  `c.to_bytes().into()` likewise). Default `cargo clippy --workspace
  --all-targets` (without features) is clean — these only fire under
  the multisig feature combination. Pre-existing on `dev`; the
  Stage 1 PR 3 KeyImage call-site sweep did not introduce them and
  did not fix them per `15-deletion-and-debt.mdc`'s "while we're
  here is the enemy" rule. Scope: drop the redundant `.into()` calls
  on already-sized arrays under the `multisig` feature path. Target:
  V3.1, as a focused clippy-cleanup PR scoped to `shekyl-fcmp`.

- **Full migration of remaining `SHEKYL_*` FFI constants to the
  JSON-authority pattern (target: post-stressnet, pre-audit-final).**
  The 2026-05-05 FFI constant-drift audit
  (`docs/audit_trail/2026-05-ffi-constant-drift-audit.md`) found two
  real bugs (Bug 1: `SHEKYL_CLASSICAL_ADDRESS_BYTES` off-by-one,
  Bug 2: `SHEKYL_SEED_FORMAT_*` 0/1 vs 1/2) where hand-maintained
  `#define` constants in `src/shekyl/shekyl_ffi.h` had drifted from
  authoritative `pub const` constants in the Rust crates. The
  reduced-scope sibling branch `chore/cbindgen-consensus-constants`
  introduced `config/consensus_constants.json` as a JSON authority
  for the silent-wrong-output subset (`FCMP_REFERENCE_BLOCK_*_AGE`,
  `RCT_TYPE_FCMP_PLUS_PLUS_PQC`) and shipped before audit, sharing
  the Python-generator + Rust-build.rs pattern with
  `config/economics_params.json`. `ADDRESS_VERSION_V1` is single-
  source in Rust with no C++ duplicate, so there's nothing to
  align today; would join the JSON only if a C++ duplicate appears.

  The remaining ~40 constants are all fail-closed-on-misuse (drift
  causes load failure or assertion failure, never silent corruption),
  so their migration to the JSON authority can land post-stressnet
  without audit-window pressure. Scope: extend `consensus_constants.json`
  (or split into `wallet_constants.json` if the file gets too large
  for a single audit-quality review) to cover all `SHEKYL_WALLET_ERR_*`
  (29), `SHEKYL_WALLET_CAPABILITY_*` (4), `SHEKYL_WALLET_KDF_*` and
  `_FILE_FORMAT_VERSION` (5), all `SHEKYL_LOG_LEVEL_*` and `_ERR_*`
  (~17), and the byte-length constants (`MASTER_SEED_BYTES`,
  `RAW_SEED_BYTES`, `PQC_PUBLIC_KEY_BYTES`, `ML_KEM_768_*_BYTES`,
  `BIP39_*_BYTES`, etc.). Delete the now-redundant C++ `#define`s
  and Rust `pub const`s; replace each with a `static_assert` /
  `const _: () = assert!(...)` sentinel against the generated value.
  Close-condition: every `SHEKYL_*` constant in
  `src/shekyl/shekyl_ffi.h` is either generated or an
  authoritatively-JSON-valued `static_assert` mirror, and
  `git grep '^#define SHEKYL_' src/shekyl/shekyl_ffi.h` returns only
  the generated header's include guard. Target: V3.0, post-
  stressnet, pre-audit-final.

  **Open question for V3.x:** the JSON-as-authority direction is a
  pragmatic middle ground between the current C++/Rust dual-source
  pattern and the longer-term "Rust-as-authority + cbindgen-emitted
  C headers" direction implied by `20-rust-vs-cpp-policy.mdc`.
  Whether to advance to Rust-as-authority is a separate V3.x agenda
  item; it doesn't gate this followup.

- **`wallet_storage`: cover loaded-wallet save-as branches in
  `wallet2::store_to`.** When `fix/wallet-storage-test` deleted the
  three Monero-era keys-file fixtures and their `GTEST_SKIP()`-gated
  tests (`store_to_file2file`, `change_password_same_file`,
  `change_password_different_file`), two `store_to` branches lost
  their only direct unit-test coverage even though the surviving
  `store_to_mem2file` / `change_password_mem2file` /
  `change_password_in_memory` cases superficially look similar:
    - `!same_file && !force_rewrite_keys` save-as on a *loaded*
      wallet (the surviving tests run on freshly-`generate()`'d
      wallets only).
    - `same_file && force_rewrite_keys` rewrite-keys-in-place on a
      *loaded* wallet.
  Both branches still execute on the production load → re-store
  path, but no unit test exercises them directly. Add two new tests
  that (a) `generate()` a wallet to disk under SHKW1, (b) `load()`
  it into a fresh `wallet2`, then (c) drive each branch. Block on
  this *only if* it doesn't conflict with the V3.2 wallet2 → Rust
  cutover schedule; if the cutover lands first, the gap retires
  with `wallet2.cpp` itself and the entry closes as won't-fix.
  Cross-references: `tests/unit_tests/wallet_storage.cpp` deletion
  comment around line 126; `docs/CI_BASELINE.md` Cluster B; the
  Copilot review on PR #27 that surfaced the gap. Target: V3.0
  pre-stressnet, or retired by the V3.2 cutover, whichever comes
  first.

- **Stage 1 performance baseline measurement before Stage 1 PRs land.**
  The §3.3 *interior-mutability measurement gate* in
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
  is binding:
  [`docs/PERFORMANCE_BASELINE.md`](PERFORMANCE_BASELINE.md) must
  carry per-bench frozen baselines (one per bench, captured at the
  bench's introducing-PR merge SHA per §4.5 of
  [`docs/design/STAGE_0_HARNESS.md`](design/STAGE_0_HARNESS.md))
  before any Stage 1 trait-implementation PR opens. As of Stage 0
  PR-2's merge, `engine_trait_bench_ledger_synced_height` is
  populated; the four deferred benches
  (`engine_trait_bench_ledger_balance`,
  `engine_trait_bench_economics_current_emission`,
  `engine_trait_bench_economics_parameters_snapshot`,
  `engine_trait_bench_key_account_public_address`) populate at
  their introducing per-trait PRs. Cumulative-delta thresholds
  (10% warn / 25% fail) apply per-bench against each bench's
  frozen-baseline SHA per §3.3.1's Round 4b refinement (further
  refined in Stage 0 PR-B). Reviewer responsibility: per §3.3.1
  and `PERFORMANCE_BASELINE.md`'s Reviewer-responsibility section,
  the Stage 1 PR reviewer confirms each in-scope bench's
  cumulative-delta row is appended with PR-current's measurements
  and that the §3.3.1 threshold-of-concern check is satisfied (or
  justified per the responsibility-allocation rule). Close-condition:
  the four deferred-bench sections in `PERFORMANCE_BASELINE.md` are
  populated by their introducing per-trait PRs; the first Stage 1
  PR review consumes the document. Target: V3.0, pre-Stage-1-PRs.

  **Partial-close note (close-out PR, 2026-05-12).** Two of the
  four deferred-bench slots have landed:
  - `engine_trait_bench_ledger_balance` — landed at Stage 1 PR 2
    (LedgerEngine PR, merged 2026-05-05).
  - `engine_trait_bench_key_account_public_address` — landed at
    this close-out PR (`chore/stage-1-pr3-closeout`, 2026-05-12),
    folded inline under the trinary rule-15 reading
    (mode-2 mechanical residue of the M3-series KeyEngine work; see
    §19's "Applied-disposition table (PR #40, two review-response
    cycles)" for the calibration anchor). The bench is a
    criterion + iai-callgrind pair classified under the
    `engine_trait_bench_*` threshold class via the `compare.py`
    `classify()` function-name routing (per
    `STAGE_0_HARNESS.md` §3.3.1) despite the substrate-forced
    fixture-shape divergence to `Box<LocalKeys>` documented in
    `STAGE_1_PR_3_CLOSEOUT_PREFLIGHT.md` §1.2. Baseline transcription
    to `PERFORMANCE_BASELINE.md` deferred to first CI
    workflow_dispatch capture under N=3 invariance.
    **Capture-script gap (noted 2026-05-31, Stage 2 close-out audit):**
    this pair is absent from `scripts/bench/capture_rust_baseline.sh`'s
    `BENCHES` array, so the CI captures to date (incl. run 26732235292)
    did not include it. Closing this slot requires adding the row before
    a capture run — out of Stage 2 scope, owned by this entry.

  Remaining slots:
  - `engine_trait_bench_economics_current_emission` — pinned to
    the EconomicsEngine PR (Stage 1 PR-equivalent for the
    economics trait surface).
  - `engine_trait_bench_economics_parameters_snapshot` — same PR
    as above.

  Entry stays open until both EconomicsEngine slots populate; close-
  condition is unchanged. Forward-template lesson for the rules-
  queue work in the V3.1+ post-genesis queue: this entry was missed
  by every M-series sub-PR's pre-flight because no pre-flight
  grepped FOLLOWUPS for entries naming its own merge as a
  resolution point; see the new V3.1 "pre-flight-FOLLOWUP-scope
  discipline" entry for the lemma that generalizes from this
  recurrence.

- **`kameo` dependency pin and MSRV alignment before Stage 2 cuts.**
  The Path B boundary decision (*2026-04-27 — Engine binary boundary:
  pure message-passing over shared handle* in
  `docs/V3_WALLET_DECISION_LOG.md`) commits the engine to the `kameo`
  actor framework. Before Stage 2 (`KeyEngine` migration) cuts, three
  preconditions must be verified and the verification commit must land
  on `dev`:

  1. **Version pin.** `kameo >= 0.20.0` is added to the workspace
     `Cargo.toml` with an exact patch-level cap chosen at the time of
     pinning. Rationale: supervision support shipped in v0.20.0
     (2026-04-07); v0.19.x and v0.20.0 included deadlock fixes
     relevant to the no-cycle DAG topology this project commits to.
     **Satisfied (chore/stage_1_cleanup, 2026-05-29):** `kameo =
     "=0.20.0"` declared in `[workspace.dependencies]`. Verified at
     source via the crates.io index — 0.20.0 is the newest stable
     (2026-04-07, not yanked); no newer version to re-pin to.
  2. **MSRV alignment.** kameo requires Rust `>= 1.88`. Confirm the
     Shekyl workspace MSRV is at or above 1.88 (or raise it explicitly
     in the same commit, with a `rust-toolchain.toml` update and a
     CHANGELOG entry under "Changed").
     **Satisfied (chore/stage_1_cleanup, 2026-05-29):** workspace
     `rust-version` raised 1.85 → 1.88; CHANGELOG "Changed" entry
     added. The declaration is inherited per-crate via
     `rust-version.workspace = true` in every first-party member's
     `[package]` (not only the 3 RandomX crates that previously opted
     in) — cargo enforces a crate's MSRV only when the crate declares
     `rust-version`, so the propagation is what makes the gate real
     rather than a virtual-root annotation. `rust-toolchain.toml`
     intentionally *not* added — CI builds on
     `dtolnay/rust-toolchain@stable` (≥ 1.88 in 2026); a pinned
     channel file would change CI/local build behavior without serving
     the gate's intent (the MSRV declaration), and no such file exists
     today.
  3. **Bounded-mailbox sizing default.** Choose a workspace-wide
     bounded-mailbox default (e.g., `mailbox(64)`) with documented
     rationale, and capture the per-actor override convention. Pure
     unbounded mailboxes are forbidden under Path B for memory-pressure
     reasons.
     **Satisfied (chore/stage_1_cleanup, 2026-05-29):** `mailbox(64)`
     default + per-actor override convention documented inline at the
     `kameo` `[workspace.dependencies]` entry.

  **CLOSED 2026-05-31 (Stage 2 `KeyActor` migration).** All three
  preconditions were satisfied by the `chore/stage_1_cleanup`
  verification commit; the close condition — Stage 2's first commit
  adds the live `kameo = { workspace = true }` consumer and verifies
  the supervision/mailbox API surface at source — is now met.
  `shekyl-engine-core` consumes `kameo` via the `KeyActor`
  (`rust/shekyl-engine-core/src/engine/key_actor.rs`), so the pin is
  no longer inert in the build graph. The API surface was verified at
  source per `17-dependency-discipline.mdc` and the `#[actor(mailbox =
  …)]` convention drift corrected (kameo 0.20.0 has no such attribute;
  `spawn` is bounded-64 by default, overrides via `spawn_with_mailbox`)
  — recorded at `STAGE_2_KEY_ENGINE_ACTOR.md` §0.5 (B6 finding) and the
  `rust/Cargo.toml` `kameo` note.

- **View/HW lifecycle bodies in `shekyl-wallet-core`.**
  `Wallet::open_view_only` and `Wallet::open_hardware_offload` ship as
  signature stubs that return `OpenError::CapabilityNotYetImplemented`
  pending the matching `shekyl-crypto-pq` `AllKeysBlob` constructors
  (a view-only constructor that omits `spend_sk` and `ml_kem_dk`; a
  hardware-offload constructor that additionally retains the device
  descriptor). When those constructors land, the stub bodies are
  replaced with end-to-end paths mirroring `open_full` (envelope open
  → rederivation inputs extraction → blob population from the
  per-capability constructor → public-bytes cross-check against the
  envelope's expected classical address → prefs load → ledger and
  indexes assembly), and `OpenError::CapabilityNotYetImplemented` is
  deleted from `error.rs` in the same commit. The variant carries a
  doc comment naming this follow-up explicitly so the deletion target
  is grep-able from the code site, not only from this file. Target:
  V3.0.

- **`Wallet::change_password` integration tests against
  `WalletFile::rotate_password`.** The lifecycle commit's unit tests
  for `change_password` exercise the orchestrator path (rotate, then
  reopen with the new password and refuse the old one) but rely on
  `WalletFile::rotate_password`'s own test coverage for the underlying
  envelope rewrap correctness. A small integration suite in
  `shekyl-wallet-core` should drive `change_password` against a real
  on-disk wallet across all three capabilities (FULL today; ViewOnly /
  HardwareOffload once their `open_*` bodies land), verifying that the
  rotated envelope round-trips against an independently-constructed
  `WalletFile::open` call rather than only against `Wallet::open_full`.
  This pins the full I/O ↔ KDF ↔ AEAD chain at the orchestrator layer.
  Target: V3.0.

- **Revisit `rust/hard-coded-cryptographic-value` CodeQL suppression
  when the Rust extractor gains `cfg(test)` awareness.** The repo-wide
  suppression added in `.github/codeql/config.yml` (commit
  `fb53977b9`) is the pragmatic answer to the CodeQL Rust extractor
  not distinguishing `#[cfg(test)]` items from production code. In
  shekyl-core, test fixtures (test vectors, password literals) live
  in production source files — e.g. the bottom ~380 lines of
  `rust/shekyl-wallet-core/src/wallet/lifecycle.rs` are inside
  `#[cfg(test)] mod tests { ... }` — so workflow-level
  `paths-ignore` cannot carve them out at file granularity (the
  alternative Copilot suggested in the PR #16 review). The
  defense-in-depth that backs the suppression — `Credentials::password_only`
  as the only constructor for authentication material,
  `.zeroize-allowlist` + the `zeroize-check.yml` workflow audit, and
  the wallet-file Argon2id → SHA3-256 → ChaCha20-Poly1305 envelope
  — catches hard-coded production credentials at three stronger
  layers than a single string-literal lint. **Revisit condition**: a
  CodeQL release whose Rust extractor distinguishes `cfg(test)`
  items, at which point the repo-wide `exclude:` in
  `.github/codeql/config.yml` is replaced with a precise
  `cfg(test)`-aware filter and production coverage is restored.
  Track CodeQL release notes for "Rust" + "test" extractor
  capabilities; this rule is also visible at
  `https://codeql.github.com/codeql-query-help/rust/rust-hard-coded-cryptographic-value/`.
  Target: V3.0 if the upstream change lands in time, otherwise
  rolled into the V3.1 audit-response cleanup batch.

- **Stage 2 — `KeyEngine` migration to actor.** Migrate key material
  + signing operations from a composed field on `Engine<S>` into a
  true actor with its own task and message protocol. The
  `KeyEngine` actor owns `AllKeysBlob` privately; exposes the
  post-M3 trait surface (`account_public_address`,
  `derive_subaddress(idx, purpose) -> SubaddressFor`,
  `try_claim_output(input) -> OutputClaimResult`,
  `sign_transaction(tx) -> TxSignatures` — per
  `rust/shekyl-engine-core/src/engine/traits/key.rs:616`) via
  message channels; never reveals raw key material outside its
  own task. The "no secret material crosses the trait boundary"
  property activated by the M3-series (per
  [`STAGE_1_PR_3_KEY_ENGINE.md`](./design/STAGE_1_PR_3_KEY_ENGINE.md)
  §3.1.2 handle-indirected workflow contract) survives the
  Stage-1-to-actor transition by construction — the trait surface
  is unchanged; Stage 2 swaps the in-process composition for an
  actor-mailbox dispatcher without touching method signatures.
  Validates the actor pattern on the smallest, cleanest subsystem
  (per the three-grounds defense in the 2026-04-27
  actor-architecture decision-log entry — smallest internal state,
  cleanest privacy boundary, framework friction surfaces with
  bounded blast radius). Sets up the view-key-vs-spend-key
  separation as a Stage 4 sub-decision. Tests `kameo` (the
  framework choice locked at Stage 2) against a real subsystem;
  if framework limitations surface here, the cost of switching is
  bounded because only one actor exists.

  *Blocks on:* Stage 1 actor-friendly trait boundaries — **satisfied**
  (the framework-agnostic trait refactor landed on `dev`; see STAGE_2
  §0.3).

  *Target:* before Phase 2b stake-lifecycle work begins — **met** (this
  entry RESOLVED; see status below).

  *Definition of done:* `KeyEngine` runs as a `kameo` actor with
  its own task; `Engine<S>` holds a `KeyEngineHandle` instead of
  `keys: AllKeysBlob`; all cross-subsystem key access routes
  through message protocols; the unsafe surface that
  `AllKeysBlob` lives in is fully contained within the actor's
  task — no `&AllKeysBlob` escapes; tests cover the actor's
  protocol (mock receivers, contract tests); message-overhead
  benchmark establishes the actor signing path within 5% of the
  composition baseline relative to the underlying FCMP++
  verification cost (the messaging cost should be lost in the
  noise of the actual signing work). The benchmark threshold is
  bench-vs-bench against the composition baseline rather than an
  absolute latency target; absolute targets at this layer are
  speculative.

  *Reference:* `docs/V3_WALLET_DECISION_LOG.md` *2026-04-27 —
  Engine architecture: actor model with staged migration from
  composition*. Design: `docs/design/STAGE_2_KEY_ENGINE_ACTOR.md`.

  **Status (2026-05-31) — RESOLVED; all six §10 DoD items met; pending merge
  to `dev`.** The actor migration is on the branch (`torvaldsl/stage-2-key-engine-actor`):
  `KeyActor` owns `AllKeysBlob` in its own task with fail-stop-on-panic
  zeroization (`key_actor.rs`); `Engine<S, …>` holds `key:
  KeyEngineHandle` plus the construction-time `HandleDerivationViewSecret`
  for the 6-i merge post-pass; `LocalSigner` holds the handle, not the
  blob; no `&AllKeysBlob` escapes the actor. The §5.2 contract/protocol
  tests landed (equivalence vs `LocalKeys`, no-secret-crosses, post-stop
  handle resolution, panic→fail-stop→zeroize, terminal-non-retryable).
  Runtime hosting took the **require-ambient** disposition (§4.2, Round 8):
  `KeyEngineHandle::spawn` asserts an ambient runtime rather than self-hosting
  an owned one (an owned long-lived runtime panics on drop inside the
  production async context); `rt-multi-thread` is promoted to production deps
  as an *independent* `block_in_place` fix, decoupled from the spawn decision.
  **DoD residue — RESOLVED 2026-05-31 (B9 benches landed).** The §5.3
  **B9 dispatch-overhead benchmark** is in the harness behind
  `bench-internals`: `engine_trait_bench_key_dispatch` (criterion — three
  IDs: `baseline_claim_mine`, `actor_claim_mine`, `actor_claim_not_mine`),
  `engine_trait_bench_key_dispatch_baseline_iai` (iai, deterministic-crypto
  baseline only), and the 6-i merge-path pair
  `engine_trait_bench_key_merge_projection` (criterion) +
  `engine_trait_bench_key_merge_projection_iai` (iai). The
  `KeyDispatchBenchHarness` / `KeyBaselineBenchFixture` /
  `MergeProjectionBenchFixture` shims are exported through
  `__bench_internals`. The actor `ask` paths are **criterion-only** (no iai
  actor sibling — a cross-thread async round-trip's Callgrind count folds in
  nondeterministic scheduling; reversion-claused: reopen if a deterministic
  async-dispatch measurement method lands); only the synchronous crypto
  baseline and the merge projection get iai siblings. `compare.py` routes
  all five IDs into the `engine_trait_bench` class by prefix (no script
  change). Baselines **captured by CI `workflow_dispatch`** (run
  26732235292, SHA `d377edfdb`, AMD EPYC 9V74 / rustc 1.96.0 / valgrind
  3.22.0) and transcribed into `docs/PERFORMANCE_BASELINE.md`: **B9 ratio =
  1.039 — PASS** (actor 1.386 ms / baseline 1.334 ms, ≤ 1.05); baseline iai
  15,163,668 instr; merge projection ≈ 1.71 µs/output (iai 5,160,059),
  confirming eager-6-i. The baseline iai driver was corrected from a
  current-thread Tokio `block_on` (which collapsed the Callgrind count to
  ~4.8k handshake instructions under valgrind) to a no-op-waker single
  poll. Re-confirm at the merge SHA if the branch tip advances materially.
  *Entry
  resolved; the CI baseline capture rides the merge per the deferred-capture
  pattern.* Target: V3.0, before Phase 2b.

- **Subaddress mechanism under PQC — dedicated design round (2026-05-31,
  surfaced during Stage 2 `KeyEngine`-actor pre-flight).** The scanner and
  the address format have made *incoherent* choices about where the KEM lives,
  and the incoherence is currently masked only because the recipient-context
  subaddress path is an unimplemented stub
  (`KeyEngineError::RecipientSubaddressKemKeygenNotImplemented`,
  `error.rs:615`). This round must resolve the incoherence **before** that stub
  is implemented.

  *Design doc (when the round opens):* `docs/design/SUBADDRESS_UNDER_PQC.md`.

  *The finding.* Monero's subaddress scheme is cheap because ECDH composes: the
  scanner computes `a·R` with the single account view secret `a` regardless of
  which subaddress an output targeted (one scalar-mult per output, then recover
  `B'`, then table lookup; scan cost is independent of subaddress count).
  ML-KEM has **no** such homomorphism — each KEM keypair is independent, and a
  ciphertext encapsulated against `pk_i` requires exactly `sk_i` to decapsulate.
  There is no account-level secret that decapsulates ciphertexts for all
  subaddress public keys. This forces a choice with no clean Monero analogue:
  - **Option A — account-level KEM + classical subaddress diversity** (what the
    scanner implements today, `scan.rs:525-528`): one decap per output
    (account-level `ml_kem_dk`), then `B' = O − ho·G − y·T` recovery gives the
    subaddress via the `HashMap<CompressedPoint, Option<SubaddressIndex>>`
    lookup. Scan cost is independent of subaddress count; on-chain
    unlinkability holds (distinct `B'_i = D + m_i·G`). But every subaddress
    encoding shares the *same* account ML-KEM PK bytes, so two of the wallet's
    own addresses are linkable by byte comparison.
  - **Option B — per-subaddress KEM** (what `RecipientSubaddress` /
    `STAGE_1_PR_3_KEY_ENGINE.md` §3.1.3 currently assume, and what the address
    layer already decided — "carrying a wallet-level ML-KEM PK… would make any
    two encodings… trivially linkable; per-subaddress derivation is rule-forced
    by `00-mission.mdc`"): each subaddress gets its own KEM keypair from
    `(view_secret, idx)`; addresses are byte-unlinkable. But scanning must try
    **every active subaddress's `sk_i`** per output — `O(active_subaddresses)`
    ML-KEM decaps per output, with no Monero-style shortcut and no help from
    the X25519 view-tag pre-filter unless it too is made per-subaddress (which
    re-introduces the cost). **Unpriced, unbounded per-output scan-cost
    multiplier.**

  *The sharp question to put on the table.* The threat Option B closes —
  comparing two of *your own* addresses byte-for-byte — requires an adversary
  who already holds two addresses you handed out (an off-chain, weaker
  adversary than the chain observer). The on-chain threat is already closed by
  classical `B'` diversity under Option A. So: is per-subaddress KEM buying
  privacy worth an unbounded scan-cost multiplier, or is it hardening an
  out-of-scope (address-collection) threat model? Monero gets address-byte
  distinctness for free because ECDH composes; Shekyl cannot, so it must decide
  whether it actually wants it. At least three coherent end-states exist and the
  current design assumes the most expensive one without pricing it:
  1. Classical-only subaddresses + account KEM (Option A): cheap,
     on-chain-unlinkable, accept address-byte linkability.
  2. Per-subaddress KEM with a bounded active-window (Option B, mitigated):
     pre-derive KEM keys only for the last N issued subaddresses; scan tries
     those N. Bounds cost but caps concurrent active subaddresses — a real
     merchant-UX constraint.
  3. Drop subaddresses entirely; recipient diversity via a different primitive
     (one-address-per-wallet + out-of-band channel, or stealth-address-style
     diversity needing no per-recipient KEM key). Most "not just copying
     Monero."

  *Scope boundary with Stage 2.* This round is **explicitly out of scope** for
  the Stage 2 `KeyEngine`-actor migration. Stage 2 takes the faithful
  Option-(a) handle fix (the handle serves non-primary audit derivation from a
  secret-bearing `AuditSubaddressSecret` projection; see
  `STAGE_2_KEY_ENGINE_ACTOR.md` §2.4/§3.1) and does **not** reshape the
  subaddress mechanism. `derive_subaddress` is cold (zero production callers),
  so a faithful actor port is correct regardless of how this round resolves.
  The Stage-2 pre-flight surfaced the finding (even "read-only inspection"
  cannot be served from public material alone, because the view secret enters
  the non-primary derivation); it does not own the fix.

  *Why a dedicated round (not a mechanical port).* This is the same shape as the
  Stage 1 "do we copy Monero's subaddresses?" question, but sharper: *the
  cryptographic property that made Monero's subaddresses cheap does not exist in
  our KEM, so the inherited design is quietly buying something expensive.* That
  is exactly the inherited-assumption interrogation that
  `05-system-thinking.mdc` ("why is this here?") and
  `16-architectural-inheritance.mdc` (inheriting code ≠ inheriting
  architecture) require, and it deserves its own adversarial round.

  *Blocks:* implementation of `RecipientSubaddress` / per-subaddress KEM keygen
  (`derive_subaddress(_, Recipient)`); the `RecipientSubaddressKemKeygenNotImplemented`
  stub stays until this round resolves.

  *Target:* V3.0 pre-genesis — the choice is structural and the cost is bounded
  pre-genesis, unbounded after launch (a subaddress reshape or drop is a
  consensus-and-wallet-format decision). Must resolve before the Recipient stub
  is implemented; does not block the Stage 2 actor migration.

  *Sequencing (decided 2026-05-31, post–Stage 2 close-out).* This round runs
  **before Stage 3 / Phase 2b**, ahead of the Phase 2b planning session. The
  rationale: `StakeEngine` and the stake-lifecycle wallet surface assume a
  settled recipient/subaddress model; resolving the Option-A/B/3 incoherence
  first avoids designing the Phase 2b state machine and persistence against a
  subaddress shape that may still change. Pre-genesis the cost is bounded; doing
  it after Stage 3 risks reworking Phase 2b's wallet-format decisions.

  *Definition of done:* a design doc (spec-first per `05-system-thinking.mdc`)
  that (a) prices each of the three end-states against scan cost, on-chain
  unlinkability, address-byte linkability, and merchant UX; (b) names the
  binding `00-mission.mdc` priority and why the alternatives were rejected;
  (c) reconciles the scanner (`scan.rs`) and address-format choices so they are
  coherent; (d) pins the disposition for the `RecipientSubaddress` stub. Carries
  its own review cycle (4–6 rounds) per `20-rust-vs-cpp-policy.mdc`'s
  migration-is-a-planning-activity discipline.

  *Reference:* `docs/design/STAGE_2_KEY_ENGINE_ACTOR.md` §2.4 (the
  secret-touching audit finding that surfaced this); `STAGE_1_PR_3_KEY_ENGINE.md`
  §3.1.3 (the per-subaddress KEM assumption being interrogated).

- **Phase 2b planning session — stake state-machine shape (gate for
  Stage 3).** Pin the design of the stake lifecycle before any `StakeEngine`
  code lands. This is named as a *Blocks on* in the Stage 3 entry below but had
  no tracked row of its own; this entry is that row (added 2026-05-31, Stage 2
  close-out audit).

  *Scope.* Spec-first (per `05-system-thinking.mdc`): the explicit
  `StakeState` enum and its transitions (`PendingBroadcast` → `Unconfirmed` →
  `Locked` → `Accruing` → `Claimable` → `Unstaking` → `FullyUnstaked`);
  refresh-time reconciliation in `apply_scan_result` (scanned-height vs
  lock/accrual rules advance each `StakeInstance.state`); `StakeInstance` as a
  first-class persisted type in `WalletLedger`; the user-facing surface
  (`Wallet::stakes(filter)`, `claimable_rewards`, `stake`/`claim`/`unstake`
  each returning `PendingTx`, not a finalized tx); and the `StakeEvent` merge
  protocol into `LedgerEngine`. Per `WALLET_REWRITE_PLAN.md` Phase 2b this is
  "the largest single sub-phase by scope" — *not* thin wrappers — so budget the
  review accordingly (4–6 rounds per `20-rust-vs-cpp-policy.mdc`).

  *Consumes:* `EconomicsEngine` (trait landed, PR #94) for stake parameters and
  derived yield values — a dependency, not a sub-trait (per
  `V3_ENGINE_TRAIT_BOUNDARIES.md` §2.7).

  *Blocks on:* (1) Stage 2 merged to `dev` (validates `kameo`); (2) the
  **subaddress-under-PQC design round** above — decided 2026-05-31 to run
  before Stage 3, so the stake state machine and `WalletLedger` persistence are
  designed against a settled recipient/subaddress model.

  *Target:* before the first Stage 3 / Phase 2b commit.

  *Definition of done:* a Phase 2b stake-lifecycle design doc whose spec the
  Stage 3 `StakeEngine` implementation targets; the `StakeState` FSM,
  reconciliation rules, persistence schema, and user-facing method signatures
  are pinned and reviewed before code.

  *Reference:* `docs/design/WALLET_REWRITE_PLAN.md` Phase 2b;
  `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §2.7 / §10.5.1.

- **Stage 3 — `StakeEngine` native actor build.** Build the Phase
  2b stake-lifecycle subsystem as a native actor from inception,
  not as composition-then-migrate. The `StakeEngine` owns the
  stake state machine (broadcast, unconfirmed, locked, accruing,
  claimable, unstaking, fully unstaked) for **consensus-bond
  responsibilities only** (principal lock, lock-tier yield,
  unstake schedule, principal-yield disbursement). Receives stake
  registration / claim / unstake messages; produces `StakeEvent`
  values consumed by `LedgerEngine` via the merge protocol.
  Archival service responsibilities are deliberately out of scope;
  they live in the sibling `ArchivalEngine` (V3.x; Stage 5). Phase
  2b is the natural validation point for "actor-from-inception"
  vs "composition-then-migrate"; building stake-lifecycle
  actor-shaped from the start avoids a redundant migration later
  and lets Phase 2b's design surface inform Stage 4 sequencing.

  *Blocks on:* (1) Stage 2 `KeyEngine` migration complete (validates
  the pattern) — RESOLVED, pending merge to `dev`; (2) the **Phase 2b
  planning session** row above (stake state-machine shape); (3) the
  **subaddress-under-PQC design round** above (sequenced before Stage 3
  per the 2026-05-31 decision, so Phase 2b designs against a settled
  subaddress model).

  *Target:* as the first major commit in Phase 2b.

  *Definition of done:* `StakeEngine` runs as a `kameo` actor with
  its own task; the stake state machine lives entirely within the
  actor (no external code holds direct references to stake state);
  `StakeEvent` flows from `StakeEngine` to `LedgerEngine` via the
  message protocol; tests cover stake state-machine transitions in
  isolation (no full `Engine<S>` setup required); refresh-time
  reconciliation routes through the actor's message protocol (no
  direct field access); `is_active_staker(entity_id) -> bool`
  query exposed as a public message for `ArchivalEngine` (Stage 5)
  consumption.

  *Reference:* `docs/V3_WALLET_DECISION_LOG.md` *2026-04-27 —
  Engine architecture: actor model with staged migration*.

- **Stage 4 — Remaining-subsystem migrations.** Migrate
  `LedgerEngine`, `RefreshEngine`, `PendingTxEngine`,
  `DaemonEngine`, and `PersistenceEngine` from composition to
  actors, one at a time, each in its own focused commit. End
  state: `Engine<S>` holds only actor handles plus runtime
  configuration; all business logic lives in actors. Each
  migration is independently reviewable; the mid-state always
  runs.

  *Suggested sequence:*
    1. `DaemonEngine` — small state, pure I/O wrapper, low risk.
    2. `PersistenceEngine` — small state, file-bound, naturally
       isolated.
    3. `PendingTxEngine` — moderate state, well-defined protocol
       (per the 2026-04-27 *Pending-tx protocol* decision-log
       entry).
    4. `RefreshEngine` — coordinates `LedgerEngine` + `KeyEngine`,
       tests cross-actor message flow at scale.
    5. `LedgerEngine` — largest state surface, most consumers;
       migrate last after everything else is tested.

  *Blocks on:* Stage 3 `StakeEngine` complete; Phase 2b shipped.

  *Target:* post-Phase-2b, incremental. No fixed deadline; each
  migration lands when the prior one's validation is complete.

  *Definition of done (per migration):* subsystem runs as a
  `kameo` actor; all consumers route through the actor's message
  protocol; the composition field on `Engine<S>` is removed; tests
  validate the actor's protocol in isolation; no regression in
  end-to-end Engine tests.

  *Definition of done (overall, when all five complete):*
  `Engine<S>` holds only actor handles + runtime configuration;
  all business logic lives in actors; **view-key vs spend-key
  separation across actors is enforced** — the `LedgerEngine`
  actor receives a derived view-key capability for scanning
  operations; the spend key never escapes `KeyEngine`'s task;
  compromise of `LedgerEngine` cannot leak spend authority. This
  is the privacy-architecture rationale realized as a concrete
  invariant. Decision log entry confirms the migration is complete
  and pins the resulting architecture as canonical.

  *Reference:* `docs/V3_WALLET_DECISION_LOG.md` *2026-04-27 —
  Engine architecture: actor model with staged migration*.

  *Named landmine — `drive_persistence` owned-runtime vs. the ambient
  `KeyActor` (cross-runtime `ask`).* Surfaced during the Stage 2
  `KeyEngine`-actor runtime-hosting round (`STAGE_2_KEY_ENGINE_ACTOR.md`
  §4.2). In Stage 2 it is **latent**: `try_claim_output` is cold and the
  scanner-merge post-pass reads the synchronous `HandleDerivationViewSecret`
  projection (the 6-i disposition), so the `KeyActor` and `drive_persistence`
  never interact. But `drive_persistence`'s *else*-branch
  (`lifecycle.rs:811-822`, the non-multi-thread / sync-`close` path reached
  when no ambient runtime or a current-thread one is present) spawns an
  **owned current-thread runtime on a scoped thread**, while the `KeyActor`
  lives on the **outer ambient runtime**. When a Stage-4 migration makes the
  actor path hot and a persistence-driven path needs to `ask` the
  `KeyActor` (or any other actor), an `ask` issued from inside the owned
  scoped runtime targets an `ActorRef` whose task is parked on the *outer*
  runtime — the cross-runtime-`ask` mismatch (`block_on` waiting on a oneshot
  that only the other runtime drives). This is the same substrate-contract
  mismatch the Stage 2 runtime round was about (sync entry point vs. async
  actor), one altitude up. Stage 4 must reconcile it explicitly — e.g. route
  the sync `close`/`change_password` path's actor interactions through the
  ambient runtime rather than the owned scoped one, or eliminate the
  owned-runtime else-branch entirely once the `PersistenceEngine` actor
  migration (sequence item 2) removes the sync-driven flush. Open Stage 4
  with this named, not rediscovered.

  *Blocks on (this sub-item):* nothing in Stage 2 (latent); becomes live the
  first time a Stage-4 actor `ask` is reachable from a `drive_persistence`
  else-branch caller. *Target:* reconcile in the Stage 4 `PersistenceEngine`
  migration (sequence item 2) at the latest.

- **RPC boundary refinements — idle eviction, `engine_lock`,
  multi-engine registry, snapshot reads, multi-peer archival
  routing.** Implement the refinements to the shared-handle model
  that the 2026-04-27 actor-architecture decision-log entry pins
  as architectural commitments:

  1. **Idle eviction.** `shekyl-engine-rpc` server (post-rename
     name) tears down `Engine` instances after a configurable
     idle timeout, zeroing secrets via the actor topology
     shutdown. Subsequent requests re-open from the file (paying
     the KDF cost once per idle cycle). Bounds secret residency
     without per-request overhead. **Default interval: TBD with
     documented rationale at implementation** — chosen against
     observed open-cost and observed access patterns rather than
     fixed by speculation.
  2. **`engine_lock` RPC method.** New method that immediately
     tears down a specific `Engine` instance and zeros its
     secrets. Subsequent operations on that engine require
     re-open. Use case: high-value operations followed by
     explicit lock-down.
  3. **Multi-engine registry.** Server holds a
     `HashMap<EngineId, EngineHandle>` rather than a single shared
     handle. Each RPC request specifies its target engine. Engines
     are independently created, opened, locked, and evicted.
  4. **Snapshot reads from `LedgerEngine`.** Read-only operations
     (balance queries, transfer history) bypass the actor message
     queue by reading immutable snapshots that `LedgerEngine`
     exposes atomically. This is the concurrency-on-read-paths
     benefit the actor architecture enables, made concrete on the
     highest-traffic queries.
  5. **Multi-peer archival routing (Stage 5 dependency).** The
     wallet's daemon-selection logic supports multi-peer archival
     routing alongside single-daemon for non-archival use. The
     `assemble_tree_path_for_output` RPC path is designed against
     a multi-source model from the start — foundation `--no-prune`
     archival nodes are the floor; staker peers
     (`ArchivalEngine` instances per `docs/V3_STAKER_ARCHIVAL.md`)
     are the primary path. This refinement ships in V3.x with
     `ArchivalEngine` (Stage 5) but the RPC client surface is
     designed in Stage 4 so the V3.x ship is purely additive.

  *Blocks on:* items 1-3 require Stage 4 `Engine<S>` to be a thin
  coordinator over actors. Item 4 requires Stage 4 `LedgerEngine`
  migration specifically. Item 5 requires Stage 4
  `DaemonEngine` migration (the multi-peer routing surface) and
  pairs with Stage 5 (`ArchivalEngine`) when the V3.x archival
  mechanism ships.

  *Target:* items 1-4 within Stage 4 work or immediately
  following; load-bearing for V3.0 ship security properties. Item
  5 client-side surface lands in Stage 4; activation lands with
  Stage 5 in V3.x.

  *Definition of done:* idle timeout configurable via
  `shekyl-engine-rpc` config with documented default-rationale;
  secrets verifiably zeroed on eviction; `engine_lock` JSON-RPC
  method present, documented in OpenAPI spec, tested; multi-engine
  registry implemented with integration tests for multiple
  concurrent engines; `LedgerEngine` snapshot read API exposed
  with concurrent-read tests verifying queries do not block during
  writes; multi-peer routing surface designed and tested against
  a mock multi-source archival oracle (real activation gated on
  Stage 5).

  *Reference:* `docs/V3_WALLET_DECISION_LOG.md` *2026-04-27 —
  Engine architecture: actor model with staged migration* §"RPC
  boundary model under actor architecture"; `docs/V3_STAKER_ARCHIVAL.md`.

- **`Hybrid*` secret types: `Vec<u8>` for fixed-size scalars —
  refactor to `[u8; N]` (sequencing trigger: Cluster 2 PR A
  lands `from_zeroizing` constructors; Lens D ml-dsa upstream
  API check informs idiomatic landing).** The `HybridSecretKey`
  struct (`rust/shekyl-crypto-pq/src/signature.rs:31-36`) and
  adjacent Classification-C Hybrid types per the Phase 0 Mission
  Audit Cluster 2.5 sub-investigation carry fixed-size scalars
  (Ed25519 secret = 32 bytes, ML-DSA-65 SK = 4032 bytes) as
  `Vec<u8>` rather than `[u8; N]`. Three structural costs:

  1. **Field-level `Vec<u8>::clone()` inside `sign()`.** Per
     `rust/shekyl-crypto-pq/src/signature.rs:265-275`, the sign
     path does `secret_key.ed25519.clone().try_into()` and
     `secret_key.ml_dsa.clone().try_into()` to materialize fixed-
     size arrays for the underlying crypto primitives. Fixed-size
     storage at the struct level consumes the bytes directly
     without the clone-and-try_into dance.
  2. **`Vec<u8>::zeroize` zeroes the heap allocation but does
     not shrink-and-realloc.** The wipe semantics are weaker
     than fixed-array `Zeroize` because intermediate
     reallocations during construction can leave fragments. Fixed-
     array storage (stack for Ed25519's 32 bytes; `Box<[u8; N]>`
     for ML-DSA's 4032 bytes if stack residency is undesirable)
     tightens the wipe contract.
  3. **Misalignment with `MlKem768DecapKey` canonical-post-
     discipline pattern.** `MlKem768DecapKey::from_zeroizing(Zeroizing<[u8;
     ML_KEM_768_DK_LEN]>)` is the canonical shape established in
     PR #33; `HybridSecretKey`'s `Vec<u8>` shape predates that
     discipline and hasn't been swept forward. Convergence on the
     `from_zeroizing` pattern across all secret-bearing types is
     the discipline goal.

  *Disposition.* Pre-genesis V3.0 refactor. Migration is one PR's
  scope (struct definition change + `sign()` inline-update +
  call-site refactor at construction sites). The Cluster 2.5
  classification has already verified zero `HybridSecretKey::clone()`
  callers, bounding the call-site refactor scope.

  *Sequencing.* After Cluster 2 PR A (`shekyl-crypto-pq`) lands
  the `from_zeroizing` constructors for `SpendSecret` /
  `ViewSecret`; the `Vec`→array refactor reuses the same pattern.
  Lens D's ml-dsa upstream API check confirms whether the
  upstream `ml_dsa::SigningKey` type exposes a `from_zeroizing`-
  shaped constructor or whether a bridging helper is needed
  (informs the idiomatic landing site).

  *Reversion criterion* (per
  `.cursor/rules/21-reversion-clause-discipline.mdc`). If Lens D
  surfaces that the ml-dsa upstream crate's API is structurally
  incompatible with the `from_zeroizing(Zeroizing<[u8; N]>)`
  shape (e.g., the upstream type holds private state that can't
  be reconstructed from raw bytes without a public constructor),
  the disposition reverts to documenting the `Vec<u8>` retention
  with explicit rationale citing the upstream API constraint,
  rather than forcing an awkward bridge. The reversion is named
  here at write time; future re-evaluation requires no
  re-derivation of the rationale.

  *Audit-doc link.* Surfaced during PR 4 Round-4-close + Phase 0
  Mission Audit B-3 sub-investigation (Cluster 2.5 Clone-derive
  walk; Hybrid* policy gap finding). Not in current Cluster 2
  PR A's mechanical scope; warrants separate PR for the `sign()`
  refactor surface.

- ~~**Difficulty algorithm: replace inherited CryptoNote cut-windowed
  average with LWMA-1 (sequencing trigger: A-4/A-5/A-7/A-8 PoW
  workstream PR; pre-genesis).**~~ **CLOSED 2026-05-18 by the LWMA-1
  Phase 4 C++ cutover (`feat/daa-lwma1-phase4`).** The four-phase
  migration spec'd in [`docs/design/DAA_LWMA1_PLAN.md`](design/DAA_LWMA1_PLAN.md)
  and [`docs/design/DAA_LWMA1.md`](design/DAA_LWMA1.md) is fully
  landed on `dev`:
  - Phase 0 (design): `dev` SHA `b0eb29b` (2026-05-15), spec +
    integration plan.
  - Phase 1 (Rust crate `shekyl-difficulty`): `dev` SHA `c8849896e`
    (PR #51, merged 2026-05-18), LWMA-1 Rust implementation +
    timestamp-validation primitives.
  - Phase 2 (FFI surface): `dev` SHA `96555a829` (PR #52, merged
    2026-05-18), `shekyl_difficulty_lwma1_next` C-ABI in
    `shekyl-ffi` plus the `lwma1-cross-check` C++ harness verifying
    Rust ↔ canonical zawy12 reference equivalence over ~5000
    blocks.
  - Phase 4 (C++ cutover): `dev` SHA `ef6f6bb66` (PR #53, merged
    2026-05-18), the consensus-atomic cutover described in the
    `CHANGELOG.md` `[Unreleased]` Phase 4 entry. All three Lens E findings
    (E.4-C-1, E.4-C-2, E.4-C-3) are dispositioned: V1 parameters
    deleted with the algorithm replacement; `DIFFICULTY_LAG`
    `// !!!` warning marker disappears with the parameter; Rule 75
    rationale-doc forward-template is carried on the new
    `SHEKYL_DAA_*` constants in
    [`shekyl-consensus/build.rs`](../rust/shekyl-consensus/build.rs)
    via the `consensus_constants_generated.h` codegen pipeline.

  The original item is retained below for audit-trail context; the
  three rationales remain the binding justification for the
  algorithm choice, and the reversion criteria remain named for
  post-genesis re-evaluation if simulation surfaces structural
  defects.

  The inherited difficulty algorithm
  at [`src/cryptonote_basic/difficulty.cpp:122-163,203-240`](../src/cryptonote_basic/difficulty.cpp)
  is the original CryptoNote cut-windowed average (sort timestamps;
  cut 60 outliers per `DIFFICULTY_CUT`; compute time_span vs
  total_work; scale by target_seconds). Parameters live in
  [`src/cryptonote_config.h:82-95`](../src/cryptonote_config.h)
  (`DIFFICULTY_TARGET_V2 = 120`, `DIFFICULTY_WINDOW = 720`,
  `DIFFICULTY_LAG = 15 // !!!`, `DIFFICULTY_CUT = 60`,
  `DIFFICULTY_BLOCKS_COUNT = DIFFICULTY_WINDOW + DIFFICULTY_LAG`).
  Replacement target is LWMA-1 (Linear Weighted Moving Average,
  zawy12 canonical implementation per the
  [`zawy12/difficulty-algorithms`](https://github.com/zawy12/difficulty-algorithms)
  reference repository), implemented in Rust per `20-rust-vs-cpp-policy`
  rule #2 (difficulty algorithm defines a cryptographic contract
  that other code consumes → Rust).

  **Three primary rationales aligned with the mission hierarchy
  per [`.cursor/rules/00-mission.mdc`](../.cursor/rules/00-mission.mdc):**

  1. **Commitment 1 (security): no regression; defensive parity.**
     The difficulty algorithm is PoW-input-independent (operates
     on timestamps + cumulative difficulties only); LWMA-1's
     security posture against timestamp-manipulation attacks is
     well-characterized through ~8 years of real-world deployment
     (Masari, multiple Monero forks, smaller CPU-mineable
     projects) and through the simulation tooling in the canonical
     zawy12 repository (hundreds of thousands of historical-data
     blocks). The replacement does not weaken the PQC posture
     (orthogonal to the difficulty surface) and does not weaken
     timestamp-attack resistance.
  2. **Commitment 2 (privacy): material side-benefit.** LWMA-1's
     linear weighting introduces natural jitter in block intervals
     compared to smoother algorithms (e.g., ASERT). For a
     privacy-focused chain where transactions are broadcast over
     anonymity networks (Tor, I2P), more variable block production
     adds natural obfuscation against statistical timing attacks
     that correlate broadcast-time with block-find-time. This is
     a recognized DAA-design side-effect rather than a primary
     LWMA goal, but it aligns with mission commitment 2's "privacy
     is the product" framing — the inherent noise is privacy
     surface that costs nothing else.
  3. **Commitment 3 (outlast the team): mature substrate, low
     reasoning load.** LWMA-1 is a 2017-vintage algorithm with
     extensive post-2017 community testing (LWMA-2/3/4 were
     evaluated and found not consistently superior; LWMA-1 remains
     the recommended baseline as of 2025-2026). Simpler than
     exponential algorithms (ASERT, EMA variants) to reason about,
     debug, and audit — which matters disproportionately for an
     unknown future maintainer who inherits the codebase. The
     zawy12 reference repository is still actively referenced in
     2025-2026 papers and projects (including post-quantum
     experiments), so the canonical source remains a maintained
     dependency-of-knowledge rather than a frozen reference.

  **Tuning parameters (specific values pending PoW PR scope):**

  | Parameter | Inherited (CryptoNote) | LWMA-1 candidate range | Notes |
  | --- | --- | --- | --- |
  | `N` (window) | `DIFFICULTY_WINDOW = 720` (24h at 120s) | 60–120 blocks (2–4h at 120s) | LWMA-1's fast-response design benefits from shorter windows; final value tuned during PoW PR against simulation data |
  | Difficulty clamp | None | Max 3× change per block (zawy12 standard) | Prevents runaway adjustments on adversarial timestamps |
  | Target block time | `DIFFICULTY_TARGET_V2 = 120s` | Inherit 120s | No coupling to algorithm choice; PoW PR may revisit independently |
  | Outlier cut (`DIFFICULTY_CUT`) | 60 timestamps | n/a — not part of LWMA-1 | LWMA-1 handles timestamp manipulation via clamp + weighting, not via outlier excision |
  | Lag (`DIFFICULTY_LAG`) | 15 blocks (carries `// !!!` warning) | n/a — not part of LWMA-1 | Disappears with algorithm replacement |

  **Alternatives considered and rejected, with reversion criteria
  per [`.cursor/rules/21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc):**

  - **LWMA-2 / LWMA-3 / LWMA-4.** Community testing across multiple
    coins did not establish consistent superiority over LWMA-1;
    later variants introduced complexity (additional weighting
    schemes, more aggressive adjustments) that produced oscillation
    artifacts in some hashrate regimes. Rejected because LWMA-1
    delivers the load-bearing properties with lower reasoning
    load. *Reversion criterion:* if a Shekyl-specific simulation
    against the canonical zawy12 tooling demonstrates LWMA-2+ has
    materially better behavior under Shekyl's specific hashrate
    profile (CPU-only RandomX v2; small-chain bootstrap regime),
    reopen the disposition.
  - **ASERT (Absolutely Scheduled Exponentially Rising Targets).**
    Theoretically smoother long-term stability; strong deployment
    record on Bitcoin Cash; respected in DAA literature. Rejected
    for Shekyl-specific reasons: (a) ASERT's smoothness reduces
    the privacy-jitter side-benefit material to commitment 2
    above; (b) LWMA-1's faster response to hashrate changes is
    better-shaped for the small-chain bootstrap regime where CPU
    miners join and leave on short timescales; (c) ASERT's
    exponential math raises the reasoning-load floor for future
    maintainers more than LWMA-1's linear-weighted average does.
    *Reversion criterion:* if Shekyl's hashrate volatility damps
    to long-term equilibrium (post-bootstrap stable regime; e.g.,
    several years post-genesis with consistent CPU miner
    participation), and the privacy-jitter benefit is no longer
    load-bearing (e.g., transaction-broadcast timing analysis is
    mitigated by other privacy mechanisms), revisit ASERT for its
    long-term stability advantages.
  - **Keep inherited CryptoNote cut-windowed algorithm.** Rejected
    per [`.cursor/rules/16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc):
    inherited algorithm carries three Lens E findings
    (`DIFFICULTY_TARGET_V1` Rule-60 residue per E.4-C-1;
    `DIFFICULTY_LAG = 15 // !!!` warning marker per E.4-C-2;
    Rule-75 rationale-documentation gap per E.4-C-3). Replacement
    subsumes E.4-C-1 and E.4-C-2 (V1 parameter and LAG marker
    both disappear when the algorithm is replaced) and transforms
    E.4-C-3 into a forward-template requirement on the new Rust
    implementation (rationale + bounds-for-safe-adjustment docs
    per Rule 75; matches the canonical positive-reference shape
    of [`rust/shekyl-economics/build.rs`](../rust/shekyl-economics/build.rs)).
    *Reversion criterion (named for completeness):* if the LWMA-1
    Rust implementation surfaces a structural defect against
    Shekyl's specific PoW threat model that the inherited
    algorithm doesn't share, revisit the keep-vs-replace decision.

  *Disposition.* Replace pre-genesis as part of the
  A-4/A-5/A-7/A-8 PoW workstream PR (RandomX v2 + LWMA-1 paired
  decisions; same workstream landing on `dev` shortly). New Rust
  implementation in `shekyl-consensus` per the
  `20-rust-vs-cpp-policy` rule #2 routing. Forward-template
  requirement: the new implementation must carry per-constant
  rationale + bounds-for-safe-adjustment docs per Rule 75, ideally
  via the build-time-codegen pattern from `shekyl-economics` /
  `shekyl-staking` for tuning parameters that may need future
  community consensus to adjust.

  *Sequencing.* Lands with the PoW PR (paired with RandomX v2
  from genesis per `docs/DOCUMENTATION_TODOS_AND_PQC.md` §1.10
  and Phase 0 Mission Audit Lens A finding A-8). The pre-genesis
  Rule-60 residue cleanup for `cryptonote_config.h` DIFFICULTY_*
  V1 parameters (Lens E finding E.4-C-1) folds into the same
  PR by definition (V1 parameters disappear when the algorithm
  is replaced); the `DIFFICULTY_LAG // !!!` semantic verification
  (E.4-C-2) also folds in by definition (LAG is CryptoNote-
  specific). The Rule 75 rationale-doc forward-template (E.4-C-3)
  applies to the new implementation's constants, not to the
  inherited constants being deleted.

  *Three-timeframe verification per [`.cursor/rules/05-system-thinking.mdc`](../.cursor/rules/05-system-thinking.mdc).*

  - **Now (V3.0 genesis):** LWMA-1's fast hashrate response is the
    right shape for small-chain bootstrap; privacy-jitter side-
    benefit is most-valuable when anonymity-set is smallest.
  - **Mining era end (~30 years):** LWMA-1's simplicity + mature
    real-world data lower the reasoning load for difficulty-
    adjustment review by maintainers who may not be the original
    team. Algorithm is PoW-independent so survives any future
    PoW change.
  - **Post-quantum era (V4):** difficulty algorithm operates on
    timestamps + cumulative difficulties only — no cryptographic
    primitives in the computation path — so LWMA-1 transitions
    cleanly when the PoW itself transitions to PQ-secure
    primitives. The reversion criteria above name what would
    trigger re-evaluation; nothing about the V4 transition itself
    triggers them.

  *Cross-references.*
  [`docs/DOCUMENTATION_TODOS_AND_PQC.md`](./DOCUMENTATION_TODOS_AND_PQC.md)
  §1.10 (paired RandomX-from-genesis pin);
  [`src/cryptonote_basic/difficulty.cpp:122-163,203-240`](../src/cryptonote_basic/difficulty.cpp)
  (inherited algorithm being replaced);
  [`src/cryptonote_config.h:82-95`](../src/cryptonote_config.h)
  (inherited tuning constants being deleted);
  [`rust/shekyl-economics/build.rs`](../rust/shekyl-economics/build.rs)
  (positive-reference forward-template for build-time-codegen
  tunable-parameter discipline per Rule 75);
  [`zawy12/difficulty-algorithms`](https://github.com/zawy12/difficulty-algorithms)
  (canonical reference implementation + simulation tooling);
  [`.cursor/rules/05-system-thinking.mdc`](../.cursor/rules/05-system-thinking.mdc)
  (three-timeframe analysis);
  [`.cursor/rules/16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)
  (inherited-code disposition rule);
  [`.cursor/rules/21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)
  (named reversion criteria for LWMA-2+ and ASERT);
  [`.cursor/rules/75-system-autonomy.mdc`](../.cursor/rules/75-system-autonomy.mdc)
  (no manual difficulty resets in normal operation;
  per-parameter rationale + bounds discipline).

  *Audit-doc link.* Pinned during Phase 0 Mission Audit Lens E
  (E.4-C/D/E parallel-batch closure phase). The LWMA-1 design
  decision subsumes E.4-C-1 and E.4-C-2 disposition work into the
  PoW PR scope rather than treating those as separate cleanup
  items, and transforms E.4-C-3 from a remediation finding into
  a forward-template requirement on the replacement
  implementation. Pre-PR pin lets the PoW PR author inherit the
  full design substrate (tuning ranges + rationale + alternatives
  rejected with reversion criteria) without re-deriving it at PR
  open time.

- **`fips204` features-list discipline: drop `default-rng` and
  unused parameter sets (sequencing trigger: Cluster 2 PR A —
  `shekyl-crypto-pq` `Box<fips204::ml_dsa_65::PrivateKey>`
  refactor; pre-genesis).** The current
  [`rust/shekyl-crypto-pq/Cargo.toml`](../rust/shekyl-crypto-pq/Cargo.toml)
  pin is `fips204 = "0.4.6"` without an explicit `features` list,
  which implicitly enables `default-rng` plus the `ml-dsa-44` and
  `ml-dsa-87` parameter sets that Shekyl does not consume. Phase 0
  Mission Audit Lens D originally classified this under
  D-fips204-discipline as Cargo.toml-only δ-trivial scope alongside
  D-9 / D-10 / D-13 (drop `default-rng`; pin
  `features = ["ml-dsa-65"]`).

  **Pre-flight finding (Batch α PR 1 implementation).**
  `rust/shekyl-crypto-pq/src/signature.rs:243` calls
  `fips204::ml_dsa_65::try_keygen()` and `signature.rs:285` calls
  `private_key.try_sign(message, &[])`. Both convenience
  surfaces are gated by `#[cfg(feature = "default-rng")]` in
  `fips204 v0.4.6` per inspection of
  `~/.cargo/registry/src/.../fips204-0.4.6/src/lib.rs` and
  `src/traits.rs`. Dropping `default-rng` from the features list
  without first refactoring the consumption sites to the
  explicit-RNG variants (`try_keygen_with_rng(rng)` and
  `try_sign_with_rng(rng, msg, ctx)`) would break compilation.
  The Cargo.toml-only framing is therefore wrong for this
  finding; the real change is consumption-site + Cargo.toml.

  **Revised disposition.** Defer to Cluster 2 PR A
  (`shekyl-crypto-pq` ML-DSA-65 + `SpendSecret` / `ViewSecret`
  workstream; D-19 directional disposition `Box<fips204::ml_dsa_65::PrivateKey>`).
  Cluster 2 PR A already touches `signature.rs` for the D-19
  refactor; folding the `default-rng` drop into the same PR
  preserves bisect coherence (one PR covers all
  `signature.rs` + `fips204` consumption-site discipline edits)
  and keeps Batch α PR 1 strictly Cargo.toml + rules in scope.
  Two-step within Cluster 2 PR A: (a) refactor `signature.rs`
  keygen + sign sites to take an `&mut R: CryptoRngCore`
  parameter, threading the workspace-canonical CSPRNG choice; (b)
  set `fips204 = { version = "0.4.6", default-features = false,
  features = ["ml-dsa-65"] }` and verify clean build.

  **Meta-observation: rule 17 §4 verification gap.** Per
  [`.cursor/rules/17-dependency-discipline.mdc`](../.cursor/rules/17-dependency-discipline.mdc) §4
  ("Feature-flag plumbing"), the audit-time check that the
  explicit features list does not include `default-rng` is
  necessary but not sufficient; the load-bearing check is whether
  consumption sites depend on `#[cfg(feature = "...")]`-gated
  surfaces of the dependency. The Lens D audit performed the
  enumerate-explicit-features check correctly and concluded
  `default-rng` was unused; pre-flight implementation surfaced
  the consumption-site dependency that the explicit-features
  check missed. **Discipline refinement (pin):** rule 17 §4
  verification should call out consumption-site cfg-gate trace
  as an explicit check, not as an implicit consequence of
  enumerating features. Future Lens D-style dependency-discipline
  audits should `git grep -nE '(fips204|fips203|ml_dsa|ml_kem)' rust/`
  (or the equivalent per-dep query) and trace each call to the
  upstream `#[cfg(...)]` gate before classifying a feature as
  drop-safe. Worth folding into the next 17-rule edit cycle as a
  protocol clarification under §4.

  **Batch α PR 1 scope reduction.** This deferral reduces Batch α
  PR 1's scope from 6 items to 5: D-9 `bip39 features = ["zeroize"]`,
  D-10 `argon2 features = ["zeroize"]`, D-13 `chacha20 features = ["zeroize"]`,
  F.5-A rule example name correction, F.5-B rule glob cleanup.
  The D-fips204-discipline item migrates to Cluster 2 PR A's scope
  per the two-step above. Batch α PR 1 commit message references
  this entry by anchor so the deferral is bisect-locatable.

  *Reversion criterion* (per
  [`.cursor/rules/21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)).
  If Cluster 2 PR A's scope shifts to not touch `signature.rs`
  (e.g., the D-19 directional disposition reverts or the PR is
  split across multiple PRs that don't include the keygen/sign
  refactor), this deferral fires and the work surfaces as a
  separate ~1-day PR (signature.rs RNG-parameterization refactor +
  fips204 features-list edit + workspace CSPRNG threading
  verification). The reversion is named at write time; future
  re-evaluation requires no re-derivation of the rationale.

  **Cross-references.**
  [`rust/shekyl-crypto-pq/Cargo.toml`](../rust/shekyl-crypto-pq/Cargo.toml)
  (target features-list edit);
  [`rust/shekyl-crypto-pq/src/signature.rs`](../rust/shekyl-crypto-pq/src/signature.rs)
  (consumption-site refactor target);
  [`.cursor/rules/17-dependency-discipline.mdc`](../.cursor/rules/17-dependency-discipline.mdc) §4
  (verification protocol — pending §4 refinement on
  consumption-site cfg-gate trace);
  [`.cursor/rules/21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)
  (named-reversion shape);
  the Hybrid `Vec<u8>`→fixed-size FOLLOWUP entry above
  (D-19 directional disposition for `Box<fips204::ml_dsa_65::PrivateKey>`,
  the sibling Cluster 2 PR A scope item that absorbs this
  deferral).

  *Audit-doc link.* Surfaced during Phase 0 Mission Audit Batch α
  PR 1 pre-flight implementation (Lens D δ-trivial scope
  refinement). Revises the original Lens D disposition for
  D-fips204-discipline from Cargo.toml-only δ-trivial to
  consumption-site + Cargo.toml, deferred to Cluster 2 PR A. The
  rule 17 §4 verification gap is the substrate-evolution observation
  the deferral surfaces; rule 17 amendment cycle is the natural home
  for §4 protocol clarification.

- **`wallet2_ffi_create_wallet` / `on_create_wallet` mainnet-broken
  FFI cleanup (post-Electrum-words-removal cleanup series; pre
  Stage 1 PR 4 kickoff).** The wallet2 FFI / RPC fresh-wallet
  entry points (`wallet2_ffi_create_wallet` per
  [`src/wallet/wallet2_ffi.cpp:299`](../src/wallet/wallet2_ffi.cpp);
  `on_create_wallet` per the RPC handler) route through
  `wallet2::generate(...)` → `account_base::generate(...)` →
  `shekyl_account_generate_from_raw_seed`, which is testnet /
  fakechain-only per the raw-seed-on-mainnet restriction in
  [`src/cryptonote_basic/account.cpp:443–446`](../src/cryptonote_basic/account.cpp).
  On Mainnet/Stagenet the call rejects; on Testnet/Fakechain it
  succeeds but without BIP-39 entropy persistence (so
  `query_key("mnemonic")` post-creation returns the §4.10 hard
  error). This is a callable-but-mainnet-broken FFI surface that
  the Electrum-words-removal series leaves in place per
  [`docs/design/ELECTRUM_WORDS_REMOVAL.md`](./design/ELECTRUM_WORDS_REMOVAL.md)
  §4.10's "Why `wallet2_ffi_create_wallet`'s mainnet-broken
  state is out of B-1 scope" sub-paragraph: the brokenness
  derives from the raw-seed restriction in `account.cpp`, not
  from Electrum-words infrastructure, and the cleanup is design
  work (the new FFI shape) rather than deletion work (B-1's
  scope).

  **Cleanup scope.** Design and ship a BIP-39-aware new-wallet
  FFI (provisional name `wallet2_ffi_create_wallet_from_bip39`),
  rewire shekyl-engine-rpc and shekyl-gui-wallet's
  `wallet_bridge.rs` to the new entry, **delete**
  `wallet2_ffi_create_wallet` and `on_create_wallet` in the
  same atomic PR per
  [`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)'s
  default-delete discipline. The PR's own scope is bounded
  (one new FFI + two delete sites) so it fits the 5-day / 10-commit
  ceiling of
  [`06-branching.mdc`](../.cursor/rules/06-branching.mdc) without
  invoking the consensus-atomic-cutover exception (the FFI
  isn't a consensus rule).

  **Severity.** Mid-grade. The mainnet-broken state is
  pre-existing and known; users on shekyl-gui-wallet bypass the
  broken entry via the Rust-side BIP-39 path per
  `ELECTRUM_WORDS_REMOVAL.md` §4.10. The cleanup is a
  surface-shrinkage / audit-attention-budget item, not a
  user-facing bug fix.

  **Reversion criterion** (per
  [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)).
  If the cleanup slips past Stage 1 PR 4 kickoff without
  explicit re-justification, the
  [§6.1 "Keep Electrum-words for backward compat"](./design/ELECTRUM_WORDS_REMOVAL.md#61-keep-electrum-words-for-backward-compat-rejected)
  rejection-shape recurs (callable-but-discouraged surface that
  creates a permanent attack surface), the
  [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc) §"The
  'cost-benefit-defer-to-later' anti-pattern" classification
  fires, and the
  [`ELECTRUM_WORDS_REMOVAL.md`](./design/ELECTRUM_WORDS_REMOVAL.md)
  §4.10 disposition reopens.

  **Cross-references.**
  [`src/wallet/wallet2_ffi.cpp:299`](../src/wallet/wallet2_ffi.cpp)
  (`wallet2_ffi_create_wallet` definition);
  [`src/wallet/wallet2_ffi.h`](../src/wallet/wallet2_ffi.h)
  (corresponding declaration);
  [`src/cryptonote_basic/account.cpp:443–446`](../src/cryptonote_basic/account.cpp)
  (the raw-seed-on-mainnet restriction that drives the
  brokenness);
  [`rust/shekyl-engine-rpc/src/ffi.rs`](../rust/shekyl-engine-rpc/src/ffi.rs)
  (in-tree Rust consumer that needs the new FFI rewire);
  [`docs/design/ELECTRUM_WORDS_REMOVAL.md`](./design/ELECTRUM_WORDS_REMOVAL.md)
  §4.10 (substrate disposition).

  *Audit-doc link.* Surfaced during Electrum-words-removal
  Phase 1 pre-flight verification at `dev` tip `60943cb16`,
  flagged against
  [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc) §"The
  'cost-benefit-defer-to-later' anti-pattern". The substrate
  amendment that produced this entry sharpened
  `ELECTRUM_WORDS_REMOVAL.md` §4.10's disposition from mixed
  framing (1)+(3) to framing (3)-with-discipline-tracking
  per the named-criteria principle.

- **`epee::wipeable_string` mlock-backed allocator
  (post-Electrum-words-removal cleanup series; pre Stage 1 PR 4
  kickoff).** Pre-flight verification at `dev` tip `60943cb16`
  found that
  [`contrib/epee/include/wipeable_string.h:83`](../contrib/epee/include/wipeable_string.h)
  backs `epee::wipeable_string` with `std::vector<char>` and
  applies no `mlock` / `MADV_DONTDUMP` / `prctl(PR_SET_DUMPABLE)`
  (zero matches across the implementation file for any of
  those primitives). Phrase-string transit buffers across the
  BIP-39 FFI boundary are wipe-on-drop only; pages are
  swap-eligible during the brief window between user input and
  BIP-39 normalization and during `query_key("mnemonic")`
  regeneration. Earlier substrate text in
  [`docs/design/ELECTRUM_WORDS_REMOVAL.md`](./design/ELECTRUM_WORDS_REMOVAL.md)
  §4.8 claimed `wipeable_string` was mlock-wrapped on the C++
  side; that claim was factually incorrect and has been
  corrected in the substrate-amendment PR that produced this
  entry.

  **Cleanup scope.** Add an mlock-backed allocator wrapper
  alongside `epee::wipeable_string` (or refactor the existing
  type to use an mlock-backed allocator under the hood), so
  the wipe-on-drop discipline is paired with the swap-resistance
  discipline that `35-secure-memory.mdc` §"OS-level protection"
  pins as the standard mitigation. The change is
  `wipeable_string`-internal (the allocator swap, plus
  per-call-site review for layout-sensitive callers); BIP-39
  paths consume the result without API change.

  **Severity.** Mid-grade. `m_bip39_entropy` is independently
  mlock-backed via
  `epee::mlocked<tools::scrubbed_arr<uint8_t, 32>>` per
  `ELECTRUM_WORDS_REMOVAL.md` §4.10's wallet-state addition, so
  the high-residency surface is covered. The transit-time
  exposure window is bounded (a few hundred microseconds per
  FFI call), but the residual is documented-not-mitigated for
  V3.0 by `ELECTRUM_WORDS_REMOVAL.md` §4.8's corrected
  disposition; closing the residual before PR 4 keeps the
  discipline visible.

  **Reversion criterion** (per
  [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)).
  If the allocator cleanup is deferred past Stage 1 PR 4
  kickoff without explicit re-justification, the §4.8
  documented-residual disposition is structurally wrong (no
  longer pending bounded closure) and the substrate amendment
  is reopened to either commit to the residual permanently or
  schedule the cleanup to a different bounded milestone.

  **Cross-references.**
  [`contrib/epee/include/wipeable_string.h:83`](../contrib/epee/include/wipeable_string.h)
  (`std::vector<char>` backing store);
  [`contrib/epee/src/wipeable_string.cpp`](../contrib/epee/src/wipeable_string.cpp)
  (implementation file lacking mlock);
  [`contrib/epee/include/mlocker.h`](../contrib/epee/include/mlocker.h)
  (existing `epee::mlocked<T>` template — model for the
  allocator wrapper);
  [`.cursor/rules/35-secure-memory.mdc`](../.cursor/rules/35-secure-memory.mdc)
  §"OS-level protection" (canonical mitigation discipline);
  [`docs/design/ELECTRUM_WORDS_REMOVAL.md`](./design/ELECTRUM_WORDS_REMOVAL.md)
  §4.8 (corrected substrate disposition).

  *Audit-doc link.* Surfaced during Electrum-words-removal
  Phase 1 pre-flight verification at `dev` tip `60943cb16`.
  The substrate-amendment PR that produced this entry replaced
  `ELECTRUM_WORDS_REMOVAL.md` §4.8's incorrect "wipeable_string
  is mlock-wrapped" claim with the corrected entropy-mlocked /
  phrase-string-wipe-on-drop split, and explicitly named this
  FOLLOWUPS entry as the bounded closure path for the residual.

- **RandomX v2 Phase 3c — `aes`-crate symbol-surface check on the
  linked `shekyld` binary** (trigger: Phase 2b PR landing; target:
  V3.0 / Phase 3c PR closes this item). Phase 2b added `aes-0.9.0`
  as a workspace dependency of `shekyl-pow-randomx`. The Rust-
  mangled symbols (`_ZN3aes...`) and AES-NI intrinsics
  (`_mm_aesenc_si128`, which lowers to a bare `aesenc` CPU
  instruction without an external symbol) **never match any of the
  10 banned `randomx_*` names** in
  [`docs/design/RANDOMX_V2_RUST.md`](design/RANDOMX_V2_RUST.md) §7.1
  by construction — §7.1 uses an explicit-list grep, not an
  `aes*` or `randomx_*` glob. The structural concern about
  symbol collision is precluded.

  **Runnable check** (one-shot, when Phase 3c links the verifier
  through the daemon for the first time). The Shekyl daemon
  (`shekyld`) is built via CMake, not `cargo`, per
  [`docs/COMPILING_DEBUGGING_TESTING.md`](COMPILING_DEBUGGING_TESTING.md);
  the canonical command from a clean checkout is:

  ```bash
  make release && \
    nm build/$(uname -s)/release/bin/shekyld | grep -iE '(aes|randomx)'
  ```

  (Substitute the appropriate `<platform>` segment manually if
  `uname -s` doesn't match the CMake output directory — the
  pattern is `build/<platform>/release/bin/shekyld`.)

  **Expected disposition.** No matches against any name in §7.1's
  10-symbol banned list. AES-crate symbols (Rust-mangled
  `_ZN3aes...`) are expected to appear and are benign — they are
  the `aes-0.9.0` crate's internal surface, not the C-ABI banned
  `randomx_*` symbols §7.1 forbids. The check confirms nothing
  leaks into the daemon by surprise; a regression that surfaces
  here is a Phase 3c rewire bug, not a Phase 2b correctness defect.

  **Why deferred.** The check is by definition a post-link
  observation; pre-Phase-3c there is no `shekyld` binary that
  links the Rust verifier. Recording the disposition in
  FOLLOWUPS.md (rather than in the Phase 2b PR description) makes
  the Phase 3c author's runbook auditable without "rely on the
  Phase 3c author re-reading the Phase 2b PR description months
  later" failure mode per `21-reversion-clause-discipline.mdc`'s
  named-criteria principle.

  **Sequencing relationship to the existing Phase 2f symbol-
  isolation item.** The V3.1+ entry "Binary-level `nm`-on-
  `shekyld` symbol-isolation invariant for the deleted CryptoNote
  DAA functions" (see V3.1+) names the same post-link `nm` shape
  as the natural landing site for the Phase 2f symbol-isolation
  binary check. Phase 3c can fold this F7 check into the same
  post-link CI step or run it as a one-shot at PR-open time; the
  disposition is "no `randomx_*` matches" either way.

  **Cross-references.**
  [`docs/design/RANDOMX_V2_RUST.md`](design/RANDOMX_V2_RUST.md) §7.1
  (10-symbol explicit-list grep);
  [`docs/design/RANDOMX_V2_PHASE2B_PLAN.md`](design/RANDOMX_V2_PHASE2B_PLAN.md)
  §5.7 (F7 finding and forward-action rationale);
  [`docs/design/RANDOMX_V2_PLAN.md`](design/RANDOMX_V2_PLAN.md)
  Phase 3c (the wiring PR that closes this item).

  **Target.** V3.0 / Phase 3c. Closes when the post-link `nm`
  check above runs against the verifier-linked `shekyld` with
  zero `randomx_*` matches and aes-crate symbols visibly present
  per the expected disposition.

- **Promote 2c-emergent sub-PR design disciplines to project-level
  documentation** — **Closed (V3.0).** Landed in
  [`.cursor/rules/26-sub-pr-design-discipline.mdc`](../.cursor/rules/26-sub-pr-design-discipline.mdc)
  via branch `chore/sub-pr-design-discipline` (sibling PR off
  `dev` at `e9917097f`, post-PR-#66). Option A selected over
  `docs/conventions/` — disciplines fit the standard rules shape
  with substantial prose, precedents, and reversion clauses per
  `21-reversion-clause-discipline.mdc`. **Opt-in** (`alwaysApply:
  false`): cite explicitly when scoping multi-round per-trait PRs
  (same injection model as `07-consensus-atomic-cutovers.mdc`).

  **Coverage.** Five design-round disciplines (function-body
  replacement contract; audit-against-actual-code; threat-model
  addenda framing; reversion-clause for sub-PR boundary changes;
  forward-action propagation) plus nine pre-flight disciplines
  (R0-D5–R0-D12 disposition IDs; R0-D8 split into results-fidelity
  vs per-commit build cleanliness). Pre-flight pass shape documented
  for future per-trait PRs (plan-doc "Round 0" naming preserved for
  audit-trail IDs only).

  **Substrate artifacts (historical).**
  [`docs/design/RANDOMX_V2_PHASE2C_PLAN.md`](./design/RANDOMX_V2_PHASE2C_PLAN.md)
  (R3-D1, F4, Round 4 addenda, forward-path, R0-D5–R0-D12, R5-D1);
  [`docs/design/RANDOMX_V2_PHASE2C_AUDIT.md`](./design/RANDOMX_V2_PHASE2C_AUDIT.md);
  [`docs/design/RANDOMX_V2_PHASE2D_PLAN.md`](./design/RANDOMX_V2_PHASE2D_PLAN.md)
  R1-D3 (post-promotion audit example). Downstream authors cite
  `26-sub-pr-design-discipline.mdc` explicitly for process shape.

  **Pending amendment (V3.0 pre-genesis queue).** Phase 2d's R0-D5
  pre-flight pass and Phase 2g's Round 4 implementation-correctness
  round are now two instances of a "pre-implementation round" discipline
  not yet named in `26-sub-pr-design-discipline.mdc`. Two instances is
  the rule-26 promotion threshold. The amendment adds: "Substantive
  design rounds close architecture and threat model. A pre-implementation
  round (Pre-Flight or Implementation-Correctness) closes specification
  gaps surfaced by reading the actual substrate the implementation will be
  written against. The pre-implementation round is not optional; it is the
  gate between design-phase close and implementation-PR open."
  Source: `RANDOMX_V2_PHASE2G_PLAN.md` §11 Round 4 history row. Target:
  the next `26-sub-pr-design-discipline.mdc` amendment PR (sibling off
  `dev`, separate from 2g implementation PR).

- **CL-7 forward-compat audit of trait-owned value/error types
  (`PendingTxEngine` / `PersistenceEngine`).** The seven-lens
  conformance pass on the three trait surfaces (branch
  `docs/engine-trait-cip-triad`) brought `PersistenceEngine`,
  `PendingTxEngine`, and `KeyEngine` to CL-1…CL-6 conformance, but
  was scoped doc-only to the three **trait files**. CL-7
  (forward-compat on public value/error types — `#[non_exhaustive]`
  on value structs/enums, the unit-variant-only pin on error types
  intended to stay payload-free) covers types defined **off** the
  trait files: `PendingTxEngine`'s `SendError` / `SubmitError` /
  `PendingTxError` / `DiscardReason` (in
  [`engine/error.rs`](../rust/shekyl-engine-core/src/engine/error.rs)
  and [`engine/pending.rs`](../rust/shekyl-engine-core/src/engine/pending.rs))
  and `PersistenceEngine`'s `PersistenceError`. The audit: for each
  trait-owned value/error type, confirm it carries the appropriate
  forward-compat attribute **with a documented rationale** per CL-7's
  pass criterion, or document why it is exempt. Tracked as the
  `—³` cells in the
  [`V3_ENGINE_TRAIT_CONFORMANCE_LENSES.md`](./V3_ENGINE_TRAIT_CONFORMANCE_LENSES.md)
  §2 scorecard (footnote 3).

  **Target.** V3.0 pre-genesis. Forward-compat attributes are a
  pre-genesis-cheap / post-genesis-forever decision (per
  `16-architectural-inheritance.mdc`'s pre-genesis discount): adding
  `#[non_exhaustive]` before the API ossifies is bounded work, while
  retrofitting it after external consumers exist is a breaking change.
  Scoped as its own doc/attribute PR (touches `engine/error.rs` +
  `engine/pending.rs`, outside the trait-file-only scope of the
  conformance pass that surfaced it).

---

## V3.1 — audit response and stressnet gates

- **Wallet file backup-exclusion markers (PR 6 lessons canvass §5.12 F1).**
  Users sync `~/.shekyl` via Dropbox/iCloud; encrypted blobs still leak to
  third-party storage. **Work:** at `WalletFile::create`, set platform markers
  (macOS `com.apple.metadata:com_apple_backup_excludeItem`, Linux `chattr +d`
  where supported, Windows `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED`, `.nobackup`
  sentinel). `PersistenceEngine` trait rustdoc pins implementor responsibility.
  **Target:** V3.1. **Reopen when:** PR 6 lands and wallet path creation is
  stable. **Ref:**
  [`STAGE_1_PR_6_PERSISTENCE_ENGINE.md`](./design/STAGE_1_PR_6_PERSISTENCE_ENGINE.md)
  §5.12 F1.

- **Process core-dump disable at wallet-RPC startup (PR 6 §5.12 F2).**
  Default Linux core dumps can capture stack copies of secrets after Argon2 /
  sealing-key use. **Work:** `prctl(PR_SET_DUMPABLE, 0)` (and platform
  equivalents) in `shekyl-wallet-rpc` main before wallet open. **Target:**
  V3.1. **Reopen when:** wallet-RPC binary hardening pass.

- **Argon2 stack-resident secret copies — cryptographer review (PR 6 §5.12 F3).**
  Heap `ZeroizeOnDrop` does not bound stack copies inside the Argon2id
  implementation. Add to the external cryptographer engagement bundle alongside
  F5(b) ritual and HKDF region derivation. **Target:** V3.1. **Reopen when:**
  cryptographer scope is finalized.

- **Rust `WalletFile` vs C++ `wallet2` advisory-lock cross-test (PR 6 §5.12 F4).**
  Rewrite-era may have both stacks live. **Work:** open with Rust
  `WalletFile`, attempt C++ open on same path, expect lock failure. **Target:**
  V3.1. **Reopen when:** C++ wallet path still coexists with Rust engine file
  handle.

- **Async `Engine::close` / `change_password` lifecycle (PR 6 PR #83).**
  Sync close/rotate now use `drive_persistence` with `block_in_place` on
  multi-thread runtimes and a scoped-thread fallback otherwise (PR #83
  robustness pass). **Remaining work:** dedicated async entry points with
  cooperative cancellation when wallet-RPC stops wrapping the whole sync call
  in `spawn_blocking`. **Target:** V3.1. **Reopen when:** wallet-RPC needs
  in-runtime close or password rotation without a blocking wrapper.
  **Ref:** [`V3_ENGINE_TRAIT_BOUNDARIES.md`](./V3_ENGINE_TRAIT_BOUNDARIES.md)
  §4.2; [`STAGE_1_PR_6_PERSISTENCE_ENGINE.md`](./design/STAGE_1_PR_6_PERSISTENCE_ENGINE.md).

- **Shekyl-native end-to-end wallet/daemon test harness
  (replacement for the deleted `tests/functional_tests/`).**
  The Monero-inherited Python+C++ functional-test harness under
  `tests/functional_tests/` (29 files, 6,786 lines) was deleted
  outright in Phase 2 of the Electrum-words removal series
  (PR #58, `feat/electrum-words-removal-phase2-rpc-deletion`).
  Pre-flight investigation (recorded in
  [`ELECTRUM_WORDS_REMOVAL_PLAN.md`](./design/ELECTRUM_WORDS_REMOVAL_PLAN.md)
  Phase 2 work item 9 reassessed) found four blockers that
  flipped the disposition from migrate to delete: (a) the harness
  invoked `monerod` / `monero-wallet-rpc` binaries that don't
  exist in the Shekyl tree; (b) `functional_tests_rpc` and
  `check_missing_rpc_methods` were silently skipped in CI for
  the lifetime of the Shekyl tree because the build environment
  lacked the `requests` / `psutil` / `monotonic` / `deepdiff`
  Python deps at `cmake` configure time — inherited dead code
  with no live caller; (c) `shekyl-wallet-rpc` lacks a
  `--regtest` / `--fakechain` flag, defaults to mainnet, and the
  `shekyl_account_generate_from_raw_seed` FFI rejects
  `(mainnet, raw)` per the permitted network/seed-format matrix
  in `rust/shekyl-crypto-pq/src/account.rs`, so any migrated
  test that restored a wallet against a `shekyld --regtest`
  daemon would fail-closed at the FFI; (d) the harness was
  Monero-shaped end-to-end (Python 2/3 compat residue, ad-hoc
  daemon orchestration, Monero-format addresses) and warranted
  a Shekyl-native rewrite under its own design doc per
  `20-rust-vs-cpp-policy.mdc`'s "migration is a planning
  activity" rule, not a "while we're here" revival here.

  The Shekyl-native harness's design contract:

  - **Binaries:** spawns `shekyld` and `shekyl-wallet-rpc`
    directly (per `src/daemon/CMakeLists.txt:74` and
    `src/wallet/CMakeLists.txt:98`).
  - **Network:** `--regtest` (fakechain) for proof-of-life and
    `--testnet` for raw-seed restore coverage, since
    `shekyl_account_generate_from_raw_seed` permits `(testnet,
    raw)` and `(fakechain, raw)` per the FFI matrix. Mainnet
    coverage is gated on Bug 4's BIP-39 wrapper landing
    (separate V3.2 item).
  - **Test fixtures:** raw-seed restore via the FFI, not a
    25-word Electrum seed; `generate_from_keys` for spend+view
    restoration; password-only `stop_background_sync`.
  - **Placement:** likely `tests/integration/wallet_e2e/` (the
    placement referenced in
    [`SHEKYLD_PREREQUISITES.md`](./SHEKYLD_PREREQUISITES.md)
    §"Pre-existing harness gaps"); final layout is design-doc
    output, not a pre-decided invariant.
  - **Language:** Rust (`shekyl-wallet-rpc-test` integration
    crate or similar) per `20-rust-vs-cpp-policy.mdc`'s
    Rust-by-default posture; no Python harness.
  - **CI gating:** target is the same gate that today
    silently-skipped `functional_tests_rpc` was *supposed* to
    occupy; the new harness must run by default in CI, not be
    gated behind unverified Python deps.

  This is a planning activity per `20-rust-vs-cpp-policy.mdc`;
  the design doc is a separate artifact (4–6 review rounds before
  implementation) and is itself a deliverable, not a pre-PR
  spec. **Trigger:** kicked off when a maintainer opens the
  design doc; this entry is a placeholder so the gap surfaces in
  CI / audit reviews until the harness exists.

  **Target version:** V3.1 (audit-response + stressnet gates is
  the natural home for an end-to-end harness; the deleted
  Python harness was nominally aimed at the same surface).
  Cross-references: PR #58 (Phase 2 RPC deletion);
  [`SHEKYLD_PREREQUISITES.md`](./SHEKYLD_PREREQUISITES.md)
  §"Pre-existing harness gaps"; tests/README.md "Functional
  tests" section.

- **RandomX v2 — Guix reproducible-build obligation pickup (trigger:
  Guix integration design pass lands).** When Guix infrastructure
  arrives, the RandomX v2 work creates the obligations recorded in
  [`docs/design/RANDOMX_V2_RUST.md`](./design/RANDOMX_V2_RUST.md) §22:
  pin the `external/randomx-v2` source hash in the Guix manifest at
  the same commit as the git submodule (`aaafe71` at Phase 0 close);
  make `BUILD_RANDOMX_V2_MINER_LIB` a reproducible-build variant so
  daemon-only and miner-bundle builds are separate reproducible
  artifacts; vendor or pin `shekyl-pow-randomx` Rust dependencies in
  the same manifest with no build-time network access. This entry
  exists because §22 is forward-looking — Guix isn't present today —
  and the obligation can only fire when someone re-reads §22 at
  Guix-integration time. The Guix-integration design doc rewrites
  §22 to point at the actual manifest paths and closes this entry.
  Target: V3.1 if Guix integration lands then; bumps to V3.x
  otherwise. Cross-reference:
  [`RANDOMX_V2_RUST.md`](./design/RANDOMX_V2_RUST.md) §22.

- **Rules-queue: elevate per-gate reviewer-discipline calibration
  into a workspace-wide rule (trigger: RandomX v2 Phase 0 review
  signs off on `RANDOMX_V2_RUST.md` §23).** Probable home:
  `.cursor/rules/24-reviewer-discipline.mdc`. The rule statement,
  drawn from §23.1 of the RandomX v2 design doc: _consensus-critical
  plans calibrate each external-review gate explicitly — which are
  waivable to self-review (with the written-note + 24-hour
  sleep-on-it discipline) and which are not — and distinguish
  inherited external review (via fork non-divergence or upstream
  dependency tracking) from Shekyl-direct external review in the
  audit trail._ Rationale: pre-launch, Shekyl operates with a small
  core team. No workspace rule today codifies an "at least one
  reviewer who is not the author" requirement — `06-branching.mdc`
  governs branch flow and release operations but does not define a
  reviewer-count rule, and `.cursor/rules/` has no
  `24-reviewer-discipline.mdc` yet. The "non-author reviewer"
  requirement is currently an aspirational project convention,
  applied per-PR by the author's discipline; the RandomX v2 plan
  names that convention explicitly so the audit trail records when
  it was satisfied and when it was waived to self-review. Promoting
  to a rule formalizes the convention and adds the per-gate
  calibration on top, so other consensus-critical work (PQC
  primitives, FCMP++, staking) reuses the same shape without
  re-deriving it. The RandomX v2 plan demonstrates the calibration
  works (Phase 2 implementation has no external-review gate; the
  release-time algorithm-review gate does; the latter is inherited
  via Monero's audit). Cross-references:
  [`RANDOMX_V2_RUST.md`](./design/RANDOMX_V2_RUST.md) §23 (the
  per-gate calibration list), §23.1 (the promotion disposition);
  [`06-branching.mdc`](../.cursor/rules/06-branching.mdc) (the
  adjacent branch-and-release rule the new rule sits alongside —
  not the source of the reviewer-count requirement, which the new
  rule introduces). Target: V3.1 (sibling to the other rules-queue
  entries in this section).

- **Rules-queue: elevate the public-material typed-wrapper exclusion
  into a workspace-wide rule.** Probable home:
  `.cursor/rules/18-type-placement.mdc` (in-queue draft), with the
  public-material exclusion as a sub-clause. The rule statement,
  drawn from
  [`docs/design/STAGE_1_PR_3_KEY_ENGINE.md`](./design/STAGE_1_PR_3_KEY_ENGINE.md)
  §3.5's closure subsection: _typed wrappers attach to
  identity-bearing primitives where rule-grounded; uniformity-driven
  wrapping of public material is the wrapper-shape recapitulation of
  `15-deletion-and-debt.mdc`'s "while we're here is the enemy."_
  (See [`.cursor/rules/15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)
  for the parent rule.) Rationale: the
  `chore/allkeysblob-zeroize-realignment` chore's "Out of scope"
  section pinned a five-reason `ml_kem_ek` exclusion (rule reach;
  audit boundary; no type-confusion partner; FFI uniformity cutting
  the wrong way; permanent type-system signal collision). Future "wrap
  THIS public byte array too" arguments will recapitulate the same
  five points; the §3.5 closure pins the disposition for that
  specific decision but is a per-PR document rather than a workspace-
  wide discipline anchor. Elevating into the rules corpus lets
  future similar decisions cite precedent without re-deriving the
  five points each time. Cross-references: `KEY_ENGINE.md` §3.5
  closure subsection;
  [`35-secure-memory.mdc:21-22`](../.cursor/rules/35-secure-memory.mdc)
  (the secrets-only reach this rule sub-clauses);
  [`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)
  ("while we're here is the enemy"). Target: V3.1 (the rules-queue
  work's expected landing window; bumps to V3.x if 18-type-placement
  defers).

- **Rules-queue: elevate the plan-vs-state-divergence pattern into a
  workspace-wide rule.** Probable home:
  `.cursor/rules/19-plan-vs-state-divergence.mdc` (in-queue draft, sibling
  to `18-type-placement.mdc`), or folded into the `18-type-placement.mdc`
  rules-queue work as a sub-clause. The rule statement, drawn from the
  recurrence pattern across Stage 1 PR 3's M3a–M3d sub-PRs:
  _plan-document wording predates substrate changes; pre-flights catch
  divergences by re-anchoring to current state; the surgical shape is to
  deliver the underlying property at the PR-3 sub-PR boundary, and to
  amend the plan-document wording in the landing-notes commit by
  deleting vacuous bullets rather than annotating around them (per
  [`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)
  "default: delete" applied to plan-document text)._ The pattern's
  recurrence: M3b sub-commit 11 (test-placement divergence under the M3a
  Round 4a `pub(crate)` lock), M3c commit 3 (`SignedProofs` byte-identity
  divergence under `OsRng`-driven signing), and M3d commit 5 (the
  "remove fallback" bullet's vacuousness against the PR-5-pinned stub).
  All three share one root cause: the migration plan was written before
  the M3a Round 4a workflow-shape pivot (per
  [`docs/design/STAGE_1_PR_3_KEY_ENGINE.md`](./design/STAGE_1_PR_3_KEY_ENGINE.md)
  §2.1.1), which deferred the bridge impl past every subsequent PR; the
  surgical shape is consistent across all three. The framework-
  attribution observation is captured in
  [`docs/design/STAGE_1_PR_3_M3D_PREFLIGHT.md`](./design/STAGE_1_PR_3_M3D_PREFLIGHT.md)
  §11 with cross-references to the three precedents; future similar PRs
  (likely candidates: PR-3's M3e docs-realignment commit; future per-trait
  extraction PRs' pre-flight passes) can cite the precedent without
  re-deriving the discipline each time.

  **Code-comment-level extension (surfaced 2026-05-11 by M3d PR #39
  round-2 Copilot review; commit `ad7f6ba7a`).** The same root pattern
  surfaces at the code-comment-rationale surface, not just at the
  plan-document surface. The §19 rule's "plan wording predates substrate
  changes" framing generalizes to any explanatory text authored
  against a substrate that subsequently changes, including doc-comment
  rationales for type-system decisions. When the §19 artifact cuts,
  fold this extension in as a sub-clause: **the rules-queue rule
  applies to code-level rationale comments, not just migration plan
  documents.** Same root pattern, different surface; one rule covers
  both. Two precedents from M3d's round-2 review:

  1. **`TransferDetails`' non-`Clone` rationale (M3d Finding 5;
     `transfer.rs::TransferDetails` doc).** The pre-M3d "`Zeroizing`
     second allocation the compiler can't track" rationale was
     load-bearing under the pre-M3d substrate (the schema carried
     `Option<Zeroizing<[u8; N]>>` secret fields whose duplication
     would have bypassed the drop-time zeroization discipline). M3d
     changed the substrate (removed those fields); the rationale
     became vacuous; the discipline (the no-`Clone` ban itself)
     survived but needed re-anchoring against the post-M3d substrate.
     Carrying forward the original framing — as the pre-rewrite
     comment did — is the comment-level equivalent of an
     annotate-around shape: preserves the stale framing. The rewrite
     in `ad7f6ba7a` is delete-and-annotate at the comment level
     (acknowledge the pre-M3d framing no longer applies; re-anchor to
     the two distinct still-load-bearing reasons under the post-M3d
     substrate). Same surgical shape as D1's delete-and-annotate
     applied to plan §3.4: substrate moves → rationale moves with it
     or gets rewritten.

  2. **Enumeration-claim brittle-shape (M3d Finding 4;
     `ledger_ext.rs::from_wallet_output` comment).** Comments
     asserting field-set completeness ("X is the only `Option` field
     aside from Y", "the only N fields are …") are an attractive
     nuisance: high authoring value (concise framing of what's
     present), low maintenance reliability (decays silently as the
     struct grows). The pre-rewrite comment was the broken shape (a
     factually-wrong enumeration). Three forward-template remediation
     shapes worth pinning in the §19 artifact: **(a)** regenerate by
     code-gen from the type definition; **(b)** replace with
     non-enumerating framing ("among other `Option` fields, X and Y
     are the load-bearing inputs"); **(c)** carry a doc-comment-side
     test that fails when the enumeration goes stale. The
     `ad7f6ba7a` rewrite is shape (b): drops the enumeration claim,
     focuses on the load-bearing content (X and Y are the inputs;
     other fields exist for unrelated reasons), and explicitly
     enumerates the "unrelated reasons" fields so a reader doesn't
     have to count them.

  **Commit-history-level extension (surfaced 2026-05-11 by PR #40's
  Copilot review and the post-PR-#40 audit; commits `82693bab7`
  through `1f9a7ad59`).** The same root pattern surfaces at the
  commit-decomposition surface of doc-only PRs. Plan-document
  wording — including the M3e preflight's own §4 commit-decomposition
  table — predates the *forward-templates capture* and
  *amendment-bundle* commits that surface during late-round Copilot
  review or user-disposition messaging; planned-but-executed-as-N
  commits diverge from the actual on-tree commit count as the PR
  accumulates review-response artifacts. When the §19 artifact
  cuts, fold this extension in as a third sub-clause: **the rules-
  queue rule applies to commit-history-level decompositions, not
  just plan-document text or code-rationale comments.** Same root
  pattern, different surface.

  The PR #40 instance, on-tree: the M3e preflight's §4 commit table
  documented **four logical units** (preflight + design-doc
  realignment + rules+FOLLOWUPS realignment + path-rename sweep);
  the on-tree history at preflight-amendment time documented
  **six actual commits**; the final merged history landed **eight
  actual commits** (six + two Copilot review-response commits
  added during PR #40's review cycles):

  1. `82693bab7` — original preflight (M3e §4 commit 1, logical
     unit "preflight + review-response + amendment").
  2. `4b931b1b5` — forward-templates capture for M3d round-2
     Copilot review artifacts (§19 comment-level extension; non-
     `Clone` ban design-pass FOLLOWUP) — landed as part of
     logical unit 1 but is its own commit because the M3d round-2
     dispositions surfaced after the original preflight.
  3. `1f9a7ad59` — amendment commit recording the user's Q1/Q2/Q3
     dispositions and the §11 calibration framework shift — same
     logical unit 1.
  4. `8e6780062` — substantive design-doc realignment cluster
     (M3e §4 commit 2, logical unit "post-migration design-doc
     state": KEY_ENGINE.md, V3_ENGINE_TRAIT_BOUNDARIES.md,
     MIGRATION_AUDIT.md).
  5. `582c19caf` — rule realignment and FOLLOWUPS structuring
     (M3e §4 commit 3, logical unit "42-serialization rule + V3.0/V3.1
     queue split").
  6. `c61f0d38f` — path-rename residue sweep + CHANGELOG entry
     (M3e §4 commit 4, mode-2 mechanical-residue per the rule-15
     trinary calibration).
  7. `5ab5b43a2` — Copilot round-1 review-response (CHANGELOG
     count, commit-count narrative ambiguity, WALLET_REWRITE_PLAN.md
     L295 mechanical-residue) — beyond the preflight's planned
     count.
  8. `67be1c0b3` — Copilot round-2 review-response (heading
     taxonomy, line anchors, date format normalization,
     WALLET_REWRITE_PLAN.md L58/L71 narrow link fix) — beyond
     the preflight's planned count.

  The surgical shape (per the §19 amendment commit `1f9a7ad59`'s
  own §4 row 1 update): annotate the divergence post-execution in
  the preflight's commit-decomposition table by enumerating the
  actual commits inside the logical unit, rather than restructuring
  the four-logical-unit framing. The four-logical-unit framing
  remains the operative review surface; the eight-actual-commit
  reality is the audit-trail surface. The divergence-amendment
  amendment is itself a sub-instance of the §19 pattern: the
  preflight's `1f9a7ad59` amendment was written when the on-tree
  reality was 6 commits; the final two Copilot review-response
  commits surfaced after the amendment but follow the same
  surgical shape (enumerate the actual commits; preserve the
  logical-unit framing).

  The discipline anchor: planned-N-commit decomposition is a
  prediction made at pre-flight authoring time about how the PR
  will execute; review-response artifacts (forward-templates
  captures, amendment-bundle commits) are surfaced after authoring
  and add commits the plan didn't anticipate. The §19 amendment
  shape applies: deliver the underlying property (the logical-unit
  decomposition serves review attention), and amend the plan's
  literal commit-count to match the on-tree reality. The literal
  count is the means; the logical-unit framing is the end. Future
  multi-commit doc-only PRs should expect 1-2 review-response
  commits beyond the planned count and budget the preflight's §4
  table to accommodate that divergence.

  All three extensions pair under one rule: **discipline patterns
  surfaced by M-series review-response.** The §19 artifact's rule
  statement, extended: _explanatory text (plan documents, code
  rationale comments, type-system decision docs) and plan-vs-state
  commit-decomposition predict the PR's shape against the substrate
  at authoring time; substrate changes that invalidate the
  prediction's load-bearing premise — whether the premise is a
  rationale's substrate-state assumption, an enumeration's
  field-set assumption, or a plan's commit-count assumption —
  demand rewrite-or-delete of the prediction, not retention with
  the premise carried forward as stale framing._

  Cross-references:
  [`docs/design/STAGE_1_PR_3_M3D_PREFLIGHT.md`](./design/STAGE_1_PR_3_M3D_PREFLIGHT.md)
  §2 D1 + §11;
  [`docs/design/STAGE_1_PR_3_M3C_PREFLIGHT.md`](./design/STAGE_1_PR_3_M3C_PREFLIGHT.md)
  §2.1.1 (Trim-1 disposition);
  [`docs/design/STAGE_1_PR_3_M3B_PREFLIGHT.md`](./design/STAGE_1_PR_3_M3B_PREFLIGHT.md)
  §D5 (test-placement divergence);
  [`docs/design/STAGE_1_PR_3_MIGRATION_PLAN.md`](./design/STAGE_1_PR_3_MIGRATION_PLAN.md)
  §3.3.1 (M3c landing-notes cross-reference) and §3.4.1 (M3d landing-notes
  cross-reference, landed 2026-05-11);
  [`.cursor/rules/15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)
  ("default: delete" applied to plan-document text);
  [`.cursor/rules/16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)
  ("pre-flight literal vs underlying property", "what does this deliver
  against the threat model?"); M3d PR #39 round-2 Copilot review
  thread (rewrite commit `ad7f6ba7a` is the authoritative on-tree
  artifact for the round-2 dispositions, including Finding 5's
  rationale rewrite in `rust/shekyl-engine-state/src/transfer.rs` and
  Finding 4's comment rewrite in `rust/shekyl-scanner/src/ledger_ext.rs`);
  M3e PR #40 commit-history (`82693bab7` original preflight →
  `1f9a7ad59` amendment, plus three substantive commits
  `8e6780062`/`582c19caf`/`c61f0d38f`, plus two Copilot
  review-response commits `5ab5b43a2`/`67be1c0b3` — the
  commit-history-level instance at the 4-vs-6-vs-8 plan-state
  divergence);
  [`docs/design/STAGE_1_PR_3_M3E_PREFLIGHT.md`](./design/STAGE_1_PR_3_M3E_PREFLIGHT.md)
  §4 (amended commit-decomposition table) and §11 (the calibration
  shift recording the divergence pattern as forward-template
  content). Target: V3.1 (the rules-queue work's expected landing
  window; co-lands or sequences against `18-type-placement.mdc`).

- **Rules-queue: encode the rule-15 trinary reading
  (in-scope-substantive / in-scope-mechanical-residue /
  out-of-scope-structural-tangent) in
  [`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc).**
  The current rule reads as binary: "in-scope" vs "while we're here is
  the enemy." That binary calibration was over-strict against
  mechanical residue of substrate changes — work that is mechanically
  derivable from the just-finished substrate change, bounded, directly
  traceable, and surfaced during the substrate-change PR's review.
  The M3-series surfaced the pattern concretely (M3e's D5: 19-file /
  82-occurrence path-rename residue from the
  `shekyl-wallet-state` → `shekyl-engine-state` /
  `shekyl-wallet-file` → `shekyl-engine-file` rename that pre-dated the
  M3 sub-PRs); reading the rule strictly would defer mode-2 residue
  indefinitely, generating exactly the V3.0-queue accumulation pattern
  the M3e preflight §11.1 records. The calibration shift, recorded in
  [`STAGE_1_PR_3_M3E_PREFLIGHT.md`](./design/STAGE_1_PR_3_M3E_PREFLIGHT.md)
  §11.1, distinguishes three modes:

  - **Mode 1: in-scope substantive.** Direct PR-scope work; lands in
    the PR.
  - **Mode 2: in-scope mechanical-residue.** Mechanically derivable
    from the substrate change; bounded; directly traceable; surfaced
    in the substrate-change PR's review window. Folds into the
    closing PR rather than deferring. The discriminating tests are
    derivability + boundedness + traceability + surface-during-review.
  - **Mode 3: out-of-scope structural-tangent.** Independent design
    decisions; new properties; scope expansion. Defers to its own PR
    with its own pre-flight.

  The rule text amendment, drawn from the §11.1 calibration shift:
  _mechanical residue of the just-finished substrate change folds
  inline; structural design passes get their own pre-flight._ Three
  worked examples for the rule body: M3e D5 (path-rename residue,
  mode-2), the §19 plan-vs-state-divergence pattern (mode-2 across
  M3a → M3d sub-PRs), the non-`Clone` ban re-evaluation (mode-3 →
  warrants its own design pass).

  **Applied-disposition table (PR #40, two review-response cycles).**
  The trinary calibration was applied iteratively across PR #40's
  Copilot review cycles (round 1 = commits before merge, surfaced
  by Copilot; round 2 = commits before merge, second pass) and the
  post-merge audit. Eight dispositions on-tree, classified by mode:

  | # | Round | Finding | Mode | Disposition |
  | --- | --- | --- | --- | --- |
  | 1 | R1-F1 | M3e preflight §4 commit-count narrative ambiguity (4 logical vs 5 implied vs 6 actual) | 1 (substantive) | Updated narrative + table; added §11 plan-vs-state divergence section pinning the framework-level pattern. |
  | 2 | R1-F2 | CHANGELOG entry stated "5 commits" against 6 actual | 1 (substantive) | Rewrote CHANGELOG entry with 6 commit hashes; cross-referenced preflight's §11 divergence record. |
  | 3 | R1-F3 | `WALLET_REWRITE_PLAN.md` L295 missed path-rename (`shekyl_wallet_file::WalletFile`) | 2 (mechanical-residue) | Folded inline per D5 sweep's mode-2 classification; same substrate as M3e D5 (workspace-wide path-rename residue from the same pre-M3 rename event). |
  | 4 | R1-F3-adj | Agent-identified `shekyl-scanner/README.md` L35 `shekyl_wallet_state::TransferDetails` (caught during F3 verification) | 2 (mechanical-residue) | Folded inline; surface-during-review test passed; bounded scope (one additional line); same substrate as F3. |
  | 5 | R2-F1 | CHANGELOG heading taxonomy regression (M3d entry under `### Changed` instead of `### Removed`) | 1 (substantive) | Inserted `### Removed` heading restoring Keep-a-Changelog taxonomy; corrected categorization without changing entry content. |
  | 6 | R2-F2 + R2-F4 | Missing `#L616` line anchors on `key.rs:616` URLs in `STAGE_1_PR_3_KEY_ENGINE.md:20` and `V3_ENGINE_TRAIT_BOUNDARIES.md:674` | 1 (substantive) | Added `#L616` to both URLs; matches the documented link-text. |
  | 7 | R2-F3 | `WALLET_REWRITE_PLAN.md` L58 + L71 pre-existing broken relative links (`docs/X.md` resolves to `docs/design/docs/X.md`) | 2 (mechanical-residue, narrow scope) + 3 (structural-tangent, broad scope) | Two-specific-line fix folded inline per Rule 15's "leave the file in good shape" carve-out (mode-2; bounded; surface-during-review). The broader 34-occurrence systemic broken-link pattern deferred to a new V3.1 FOLLOWUP (mode-3; warrants its own bounded pre-flight; doc-wide link audit). |
  | 8 | R2-F5 | Date-format inconsistency (prose "May 11, 2026" vs ISO `2026-05-11`) | 1 (substantive) | Normalized both occurrences to ISO format; project-wide convention. |

  The table's discriminating value: mode-2 mechanical-residue
  (entries 3, 4, and the bounded part of 7) folded inline without
  manufacturing per-PR overhead; mode-3 structural-tangent (the
  broad part of 7) deferred to its own bounded pre-flight rather
  than ballooning PR #40's scope. The 8-disposition shape concretely
  demonstrates the trinary calibration in operation: same root
  rule applied to substrate-related residue (fold inline) vs
  unrelated structural pattern (defer with traceability), with
  the discriminating test (derivability + boundedness + traceability
  + surface-during-review) yielding clean classifications. When the
  rule-15 trinary-reading amendment cuts, this table provides the
  worked-examples surface for the rule body.

  **Pairing with `18-type-placement.mdc` and `19-plan-vs-state-divergence.mdc`.**
  The rule-15 calibration consolidates with the §18 and §19 rules-queue
  drafts because all three address discipline calibration rather than
  net-new rule content. Probable consolidation shape: one
  rules-corpus PR landing `15-deletion-and-debt.mdc` amendment +
  `18-type-placement.mdc` (public-material exclusion sub-clause) +
  `19-plan-vs-state-divergence.mdc` (or sub-clause of 18).
  Cross-references:
  [`docs/design/STAGE_1_PR_3_M3E_PREFLIGHT.md`](./design/STAGE_1_PR_3_M3E_PREFLIGHT.md)
  §11.1 (trinary reading), §11.3 (rules-queue consolidation guidance);
  M3e D5 disposition (the concrete mode-2 precedent);
  PR #40 applied-disposition table above (eight on-tree applications
  of the trinary calibration across two review-response cycles + a
  post-merge audit; the worked-examples surface for the rule body);
  [`docs/design/STAGE_1_PR_3_CLOSEOUT_PREFLIGHT.md`](./design/STAGE_1_PR_3_CLOSEOUT_PREFLIGHT.md)
  §1.3 (the V3.1-prep extension surfacing where the applied
  dispositions get pinned);
  [`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)
  (the parent rule to amend);
  [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)
  ("what does this deliver against the threat model?" — the
  framework anchor that the trinary reading operationalizes).
  Target: V3.1 (rules-queue work's expected landing window; consolidates
  with §18 and §19 entries).

- **Rules-queue: consolidate the rules-queue itself into 1–2 PRs.**
  The rules-queue is now ~6 deep (the §18 public-material exclusion;
  the stateless-actor preference; the §19 plan-vs-state-divergence
  pattern + the comment-level extension; the enumeration-claim
  brittleness forward-template; the rule-15 trinary reading;
  the non-`Clone` ban re-evaluation as a design pass). Six queued
  rule artifacts shipping as six PRs is six times the per-PR overhead
  (pre-flight + review + CI) without proportional review benefit for
  pure-documentation work. Pure-docs commits don't have meaningful
  intermediate compile boundaries; consolidation preserves bisection
  granularity (the commits inside the consolidated PR are still
  small), reduces context-switching across reviews, and ships the
  rules as a coherent corpus rather than scattering them. The
  consolidation target, per
  [`STAGE_1_PR_3_M3E_PREFLIGHT.md`](./design/STAGE_1_PR_3_M3E_PREFLIGHT.md)
  §11.3:

  - **PR 1: rules-corpus consolidation** (likely 4–6 commits, one per
    rule artifact). Lands `15-deletion-and-debt.mdc` trinary-reading
    amendment, `18-type-placement.mdc` (public-material exclusion
    sub-clause), `19-plan-vs-state-divergence.mdc` (or folded into §18),
    enumeration-claim brittleness forward-template (folded into §19
    or its own sub-rule), and the stateless-actor preference rule.
  - **PR 2 (optional): non-`Clone` ban design pass.** Cuts only if
    the design pass's scope warrants its own pre-flight (three
    dimensions per the non-`Clone` ban FOLLOWUP entry below).
    Otherwise, the design pass's outcome can be encoded in PR 1's
    `18-type-placement.mdc` body.

  The discipline anchor: rules-queue overhead is dominated by per-PR
  fixed cost, not per-rule marginal cost. Consolidation amortizes the
  fixed cost across the queue. The current scattered shape — implied
  by the per-entry V3.1 targets without an explicit consolidation
  pin — would land each rule as its own PR by default; the
  consolidation pin reverses the default. Cross-references:
  [`STAGE_1_PR_3_M3E_PREFLIGHT.md`](./design/STAGE_1_PR_3_M3E_PREFLIGHT.md)
  §11.3; the §18, §19, and rule-15-trinary-reading FOLLOWUPS above.
  Target: V3.1 (queue-internal coordination decision; lands as the
  rules-queue's first PR or as a planning artifact ahead of it).

- **Rules-queue: encode the pre-flight-FOLLOWUP-scope discipline.**
  FOLLOWUPS accumulates entries with "resolve at X" close-conditions
  (where X is a PR ID, trait, feature, or milestone). When a PR
  matching one of those close-conditions executes without actively
  pulling those entries into its pre-flight scope, the entries
  orphan — filed but never claimed by the PRs they target. The
  FOLLOWUP discipline becomes one-sided: items go in but don't come
  out at the boundaries that were named as their resolution points.

  The precedent: L353-379 of this file (the per-bench frozen-baseline
  FOLLOWUP from Stage 0 PR-2) names "the trait-introducing per-trait
  PR's merge SHA" as the resolution point for each of four deferred
  bench slots. The M3-series (M3a–M3e) was the KeyEngine trait-
  introducing PR per Stage 1's §8.1 chain, and four sub-PRs landed
  without claiming the L353-379 KeyEngine slot. M3a's pre-flight
  didn't grep this file for entries naming "KeyEngine trait-introducing
  PR" as their resolution point; M3b–M3e's pre-flights didn't catch
  it because their scope was M-series-specific work, not M-series-
  mandated FOLLOWUP closures. The post-PR-#40 audit (2026-05-11)
  surfaced the L353-379 KeyEngine slot as still-open; the
  `chore/stage-1-pr3-closeout` PR satisfies the KeyEngine slot
  retroactively. The pattern was caught only because the audit
  explicitly enumerated open FOLLOWUPS by close-condition match,
  which is what every per-trait PR's pre-flight should have done.

  The forward-template: pre-flight checklists should include an
  explicit grep step against this file (`docs/FOLLOWUPS.md`) for
  entries naming the current PR (by ID, trait, feature, or
  milestone) as their resolution point. The grep takes seconds; the
  retroactive close-out PR took days. The fixed overhead of one
  grep at pre-flight time is dominated by the per-FOLLOWUP fixed
  cost of authoring a retroactive close-out PR when the orphaned
  entry surfaces post-merge in a downstream audit.

  This lemma generalizes the §19 pattern at a higher abstraction:
  §19 catches plan-document text predating substrate changes, and
  the comment-level and commit-history-level extensions catch the
  same pattern at adjacent surfaces. The pre-flight-FOLLOWUP-scope
  discipline catches FOLLOWUP-resolution-point bindings not actively
  claimed by their target PRs. Both are instances of "commitments
  to future work that go stale or unclaimed when their target
  boundary arrives." The §19 artifact's body is the natural home
  for this rule, with the framing: _explanatory text and binding
  commitments (plan documents, code rationale comments, commit
  decompositions, FOLLOWUP-resolution-point bindings) predict or
  schedule work against the substrate at authoring time; substrate
  changes that invalidate the prediction's load-bearing premise —
  or boundary changes that activate the commitment's trigger —
  demand active reconciliation at the boundary, not retention of
  the prediction as stale framing or implicit orphaning of the
  commitment._

  Cross-references: L353-379 of this file (the surfacing
  precedent); the rule-15 trinary-reading FOLLOWUP above (the
  V3.1 rules-queue work this folds into); the §19
  plan-vs-state-divergence FOLLOWUP (the parent pattern this is
  the higher-abstraction instance of); the rules-queue-
  consolidation FOLLOWUP above (this folds into the V3.1 rules-
  corpus PR's scope);
  [`docs/design/STAGE_1_PR_3_CLOSEOUT_PREFLIGHT.md`](./design/STAGE_1_PR_3_CLOSEOUT_PREFLIGHT.md)
  §2 D3 + §6.7 (the closeout PR's discipline binding language
  satisfying the KeyEngine slot of L353-379, written explicitly
  so future trait-introducing PRs inherit the pattern). Target:
  V3.1 (rules-queue work; folds into the V3.1 rules-corpus PR's
  scope per the consolidation FOLLOWUP above).

- **Non-`Clone` ban on `TransferDetails` — post-M3d structural
  re-evaluation.** M3d Finding 5 (PR #39 round-2 Copilot review, commit
  `ad7f6ba7a`) rewrote the rationale for `TransferDetails`' non-`Clone`
  status because the pre-M3d framing ("`Zeroizing` second allocation
  the compiler can't track") was load-bearing under the pre-M3d
  substrate (the schema carried `Option<Zeroizing<[u8; N]>>` secret
  fields) and became vacuous post-M3d (those fields were removed). The
  rewrite re-anchored the ban to two distinct, still-load-bearing
  reasons: (1) privacy-correlation discipline on `OutputHandle`
  (forcing duplication through a serialize/deserialize ceremony keeps
  each handle's flow visible at the call site); (2) snapshotting-
  explicit discipline (engine bookkeeping that legitimately needs two
  views of a `TransferDetails` should make that intent visible rather
  than hide it behind an implicit `Clone`). The rewrite landed the
  disciplinary conclusion forward; the standalone design pass is to
  re-evaluate whether the two reasons are the right framing under the
  post-M3d substrate, or whether a tighter framing exists. Three
  dimensions worth surfacing in the design pass's pre-flight when it
  cuts:

  1. **Type-level vs use-level discipline.** Both the privacy-
     correlation and snapshotting-explicit framings are partly about
     how callers use the type, partly about properties inherent to
     the type. A purely type-level rationale would anchor to something
     like "`TransferDetails` is the canonical reference to a single
     output; duplication creates ambiguous source-of-truth that
     conflicts with the ledger's append-only model." Use-level
     rationale is plausibly enforceable via Clippy lints rather than
     type-system prohibition. The choice affects whether the ban is
     structurally permanent or transitionally helpful pending better
     tooling. Worth being explicit about which level the design pass
     anchors to.

  2. **Which load-bearing concern does the `OutputHandle` property
     motivate?** The privacy-correlation framing is two-step: (i)
     `OutputHandle` is privacy-correlating in principle (correlation
     requires `view_secret` knowledge but the property exists at the
     type), (ii) therefore the containing type's replication should
     be structurally explicit. Step (ii) doesn't strictly follow from
     step (i) on its own — explicit serialization vs implicit
     `Clone` both create in-memory replicas that could leak through
     the same vectors. The actual load-bearing link is **chokepoint
     visibility**: explicit serialization concentrates replication at
     audited points; implicit `Clone` diffuses it across the
     codebase. If that's the discipline, the framing tightens from
     "privacy-correlation discipline" to "privacy-correlating data
     flows audit-via-chokepoints; no-`Clone` is the mechanism." Same
     conclusion, more precise about which property is doing which
     work.

  3. **Why `TransferDetails` specifically vs other wallet-state
     types?** Snapshotting-explicit discipline is general-purpose; if
     it's load-bearing for `TransferDetails`, why not `LedgerBlock`,
     `WalletLedger`, `ScanResult`? Either it's
     `TransferDetails`-specific for reasons not yet articulated
     (e.g., it's the only type that flows across the orchestrator-
     engine boundary regularly), or it's a general principle that's
     been selectively applied. The design pass should surface the
     asymmetry — either justify the specific application with type-
     level reasoning, or generalize the rule across the wallet-state
     type family. The latter is a bigger scope; the former requires
     explicit justification.

  **V3.0-vs-V3.1 disposition.** If the design pass lands as V3.0, it
  cuts before genesis with the answer locked in (whichever
  disciplinary framing it adopts becomes the canonical rationale for
  the schema's lifetime). If V3.1, the current rewrite carries through
  to genesis with the rationale anchored to the two reasons (privacy-
  correlation + snapshotting-explicit) and the design pass refines
  later. Both are defensible; this entry forces the decision rather
  than letting it drift past genesis as un-named technical debt.
  Cross-references:
  `rust/shekyl-engine-state/src/transfer.rs::TransferDetails` doc
  (post-`ad7f6ba7a` rewrite is the entry-point text the design pass
  refines);
  [`docs/design/STAGE_1_PR_3_M3D_PREFLIGHT.md`](./design/STAGE_1_PR_3_M3D_PREFLIGHT.md)
  §3.3 (post-M3d engine-confined-secrets property delivery framing,
  which makes the `Option`-secret-field memory-safety rationale
  vacuous);
  [`.cursor/rules/16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)
  ("what does this deliver against the threat model?" — the design
  pass should re-derive the answer under the post-M3d substrate
  rather than carry the pre-M3d rationale forward);
  the §19 rules-queue entry above (this design pass is itself an
  instance of the §19 pattern at the type-decision-rationale level —
  substrate moved, rationale needs re-anchoring or rewriting). Target:
  V3.0 (preferred — locks the framing pre-genesis) or V3.1 (acceptable
  fallback — current rewrite holds in the interim). Trigger: M3d PR
  #39 round-2 Copilot Finding 5 disposition pass.

- **`fips203` interior `into_bytes()` Copy on the ML-KEM-768 decap-key
  flow.** `shekyl_crypto_pq::account::ml_kem_keypair_from_d_z`
  produces an `MlKem768DecapKey` from `fips203`'s typed
  `DecapsulationKey` via `dk.into_bytes()`. The upstream API returns
  the 2400-byte canonical encoding by value, briefly producing a
  stack-resident `[u8; ML_KEM_768_DK_LEN]` outside any `Zeroize`
  wrapper before `Zeroizing::new(...)` moves it. Under `--release`
  the move *typically* gets RVO'd to the return-value slot (no
  separate temporary), but this is not guaranteed — `--debug`
  builds, panic unwind paths, and unfortunate codegen all leave the
  raw stack slot alive until the function returns and the frame is
  reused. Resolution path: either (a) `fips203` exposes an
  `encode_into(&mut [u8; ML_KEM_768_DK_LEN])` API on
  `DecapsulationKey` (upstream PR), or (b) Shekyl-side wrapper that
  constructs `MlKem768DecapKey` from `fips203`'s typed form without
  going through `into_bytes` (potentially via `unsafe` over
  `#[repr(transparent)]` if `fips203` documents that guarantee).
  Cross-references:
  [`docs/design/STAGE_1_PR_3_KEY_ENGINE.md`](./design/STAGE_1_PR_3_KEY_ENGINE.md)
  §3.5 closure;
  [`.cursor/rules/35-secure-memory.mdc`](../.cursor/rules/35-secure-memory.mdc)
  §21–22; PR #33 round-4 Copilot finding closure narrative
  (Option D: typed wrapper from producer to consumer; this entry
  is what Option D *did not* fix). Target: V3.1.

- **`derive_output_handle` Python reference script.** Stage 1 PR 3
  M3a commit 2 lands the Rust implementation of `derive_output_handle`
  (cSHAKE256, per `STAGE_1_PR_3_KEY_ENGINE.md` §7.12) with self-generated
  reference vectors locked in `rust/shekyl-crypto-pq/src/handle.rs`'s
  test module. A cross-language reference script in
  `tools/reference/derive_output_handle.py` was the originally-intended
  companion deliverable, deferred at landing time because Python's
  `hashlib` does not include cSHAKE (SP 800-185) and the existing
  `tools/reference/` stdlib-only convention precludes reaching for
  `pycryptodome`. Resolution path: either (a) implement `KECCAK[c=512]`
  + cSHAKE construction over `hashlib.shake_256`'s underlying primitive
  in pure Python (~150 LOC), or (b) update `tools/reference/README.md`
  to permit `pycryptodome` as a documented dep and use its `cSHAKE256`
  directly. (a) preserves the stdlib-only invariant; (b) is faster to
  ship. The script's value is forward-investment — cross-implementation
  reproducibility for future non-Rust consumers (Python tooling,
  JavaScript wallet, hardware-wallet integration) — so urgency is
  bounded by when such a consumer materializes. The Rust implementation
  remains the canonical version; the Python script documents the
  byte-exact invocation in a second language. Cross-references:
  M3a commit 2; `tools/reference/derive_output_secrets.py` (precedent
  pattern); `STAGE_1_PR_3_KEY_ENGINE.md` §7.12. Target: V3.1.

- **`Engine::ledger()` accessor cleanup.** Stage 1 PR 2 (commit
  `8632b8692`) preserved the previously-public `Engine::ledger()
  -> &WalletLedger` accessor by replacing the field projection
  with a `pub fn ledger(&self) -> LedgerReadGuard<'_>` wrapper
  that holds the `LocalLedger`'s read lock for the borrow's
  lifetime. Pre-flight surveyed every Rust workspace
  (`shekyl-core`, `shekyl-gui-wallet`, `shekyl-dev`,
  `shekyl-web`, `shekyl-mobile-wallet`, `monero-oxide`) and found
  zero remaining callers; the wrapper exists to absorb any
  external downstream binder that might still reference the
  accessor by name. At V3.1, re-survey the workspace and (a) if
  no caller has emerged, delete `Engine::ledger()` and
  `LedgerReadGuard` outright per
  [`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)'s
  "default: delete" rule; (b) if a caller has emerged, document
  the use case in this file and re-evaluate the lifetime of the
  wrapper. The path of least surprise is (a). Cross-references:
  Stage 1 PR 2 commit 2 pre-flight survey;
  [`docs/design/STAGE_1_PR_2_LEDGER_ENGINE.md`](design/STAGE_1_PR_2_LEDGER_ENGINE.md)
  §7. Target: V3.1.

- **PQC Multisig V3.1: external adversarial review (Phase 5).**
  Round 4 wargame against the V3.1 multisig implementation per
  `PQC_MULTISIG_V3_1_ANALYSIS.md` §5.4. Review targets:
  - Attacks on Solution C mechanism (grinding on `tx_secret_key_hash`)
  - Attacks on §2.7 invariant enforcement
  - Unknown-version silent-skip exploits
  - Relay directory signing process attacks
  - DKG ceremony failure modes

  Status: code complete, awaiting human coordination to schedule the review.

- **PQC Multisig V3.1: cryptographer review (Phase 6).**
  Four targeted reviews per `PQC_MULTISIG_V3_1_ANALYSIS.md` §7:
  1. KDF domain separation soundness
  2. HKDF-derived Ed25519 scalar for FCMP++ prover (bit-clamping question)
  3. FCMP++ proof binding to Y_prover
  4. Rotation-rule grinding cost analysis

  Status: outreach should begin immediately; does not block other work.
  Findings are folded in via targeted `fix/ms31-crypto-review-*` branches.

- **PQC Multisig V3.1: headless co-signer service.**
  Build a `shekyl-cosigner-headless` reference implementation (CLI, no
  GUI) to validate the "co-signer service" model where one of N
  participants is a dedicated automated signing service. Validates:
  - Policy-based auto-signing (amount limits, allowlists, time delays)
  - HSM key storage integration (PKCS#11 or similar)
  - Subscription/billing hooks (out of protocol scope but must not conflict)
  - Headless heartbeat and CounterProof handling

  The protocol already supports this model (a service is just another
  participant), but practical validation is needed.

- **PQC Multisig V3.1: wire `shekyl_pqc_verify_with_group_id` into
  consensus verifier.** (Audit response.)
  The FFI export `shekyl_pqc_verify_with_group_id` exists and accepts an
  `expected_group_id` parameter, but the daemon's C++ verifier
  (`tx_pqc_verify.cpp`) still calls `shekyl_pqc_verify` for `scheme_id == 2`
  without passing a group ID. This means defense-in-depth group binding
  (`PQC_MULTISIG.md` §16.3) is implemented in the Rust library but not
  enforced at the consensus verification layer. Wiring it in requires the
  C++ verifier to extract `group_id` from the multisig key blob and pass it
  through — a small change but consensus-touching, requires its own review
  cycle.

- **Historical tree path assembly uses current LMDB state.**
  `assemble_tree_path_for_output` (in both `chaingen.cpp` and
  `core_rpc_server.cpp`) reads sibling hashes from the current LMDB tree
  state even when the reference block predates the chain tip. When
  `ref_leaf_count < current_leaf_count`, the sibling structure differs
  between historical and current state, and the assembled witness hashes
  to a root that matches neither the historical nor the current tree
  root. The current tests pass because they use
  `ref_leaf_count == current_leaf_count` (reference block always at the
  tip). This will fail for any real wallet that uses a historical
  reference block (allowed by `FCMP_REFERENCE_BLOCK_MAX_AGE = 100`).
  Stressnet (Phase 7.7) with realistic reorg and varied reference-block
  usage will exercise this. Approach: reconstruct historical tree state
  on demand using per-block root snapshots already stored by
  `store_curve_tree_root_at_height`.

- **Resolution: FCMP++ historical-reference cutover via Stage 5
  `ArchivalEngine` (V3.x).** The bug above ("Historical tree path
  assembly uses current LMDB state") is resolved by the V3.x staker-
  distributed archival mechanism, not by an in-place fix to
  `assemble_tree_path_for_output`. Architecture pin:

  1. **Foundation `--no-prune` archival as floor.** The Foundation
     runs full-history archival nodes from V3.0 launch. These serve
     as the always-available floor for historical tree-path queries;
     the bug's failure mode is masked at the wallet RPC layer
     because the wallet routes historical reference-block queries to
     a `--no-prune` source that *does* hold the state at the
     reference height.
  2. **Staker-distributed archival via `ArchivalEngine` sibling
     actor as the primary path.** Stakers opt into archiving shards
     of chain history (per `docs/V3_STAKER_ARCHIVAL.md`); the
     `ArchivalEngine` Stage 5 actor (sibling to `StakeEngine`,
     bifurcated for slashing-domain integrity per the 2026-04-27
     actor-architecture decision-log entry) responds to historical
     tree-path queries from wallet clients. As staker archival
     coverage grows, the Foundation floor recedes from primary path
     to fallback.
  3. **`assemble_tree_path_for_output` RPC routing designed against
     multi-source model from the start.** The wallet client's
     daemon-selection logic for historical-reference queries
     supports multi-peer archival routing — it can interrogate
     multiple staker peers, cross-validate the assembled path
     against the per-block root from `store_curve_tree_root_at_height`,
     and prefer staker peers over the Foundation floor when
     coverage exists. The multi-peer routing client surface is
     drafted in Stage 4 (`DaemonEngine` migration); activation
     pairs with Stage 5 (`ArchivalEngine`) shipping in V3.x.
  4. **Per-block root snapshots remain the verification anchor.**
     `store_curve_tree_root_at_height` continues to store
     per-block roots; the verification protocol for an assembled
     historical path is "the assembled path hashes to the snapshot
     root for the reference height" — this is unchanged from the
     bug's proposed approach. The change is *who computes the
     assembly* (staker peers, not the local LMDB) and *how the
     wallet routes the query* (multi-peer, not single-daemon).

  *Target:* V3.x — pairs with Stage 5 `ArchivalEngine` ship.
  Simulation work (per `docs/V3_STAKER_ARCHIVAL.md`) gates the
  exact V3.x dot-version.

  *Definition of done:* the wallet's
  `assemble_tree_path_for_output` RPC client routes through the
  multi-peer archival mechanism; cross-validates against per-block
  root snapshots; integration tests cover historical-reference
  queries against multi-source archival mocks; stressnet (Phase
  7.7) exercises the path against realistic reorg and varied
  reference-block usage.

  *Reference:* `docs/V3_STAKER_ARCHIVAL.md` (canonical archival-
  mechanism design home); `docs/V3_WALLET_DECISION_LOG.md`
  *2026-04-27 — Engine architecture: actor model with staged
  migration* (Stage 5 `ArchivalEngine`, sibling-not-child
  rationale, multi-peer RPC routing).

- **Audit FCMP++ integration for paired computations.**
  Five integration bugs were found during the first CI green effort, all
  sharing the shape "two functions answer the same question differently."
  A deliberate sweep of remaining paired computations would surface
  similar latent bugs. Key surfaces to audit: any function that computes
  leaf count, layer count, or tree depth independently of another that
  answers the same question. Document the canonical answer and delete
  the duplicate, or add cross-check assertions.

- **Regression test: `compute_leaf_count_at_height` vs LMDB drain.**
  Add a test that, for a chain with outputs at varied maturity heights,
  asserts
  `compute_leaf_count_at_height(H) == count_of(drain_pending_tree_leaves(H))`
  for every height. This is the invariant the off-by-one bug violated
  and is the highest-value regression gate for this class of bug.

- **Expose FCMP++ verification cache stats via daemon RPC (stressnet F14).**
  Add `verification_cache_hits` and `verification_cache_misses` fields to
  `get_info` (or a new `get_cache_stats` JSON-RPC method). Currently the
  verification cache hit/miss counters (`fcmp_verified`,
  `fcmp_verification_hash`) are internal to `tx_pool.cpp` with no RPC
  exposure. The stressnet wallet exerciser (`shekyl-dev/stressnet/`) uses
  block validation p95 as an indirect proxy until this endpoint exists.

- **MFA / hardware-token integration for wallet file decryption.**
  V3.0 ships with password-only authentication on the wallet file
  envelope. V3.1 adds an optional FIDO2 / WebAuthn capability where
  the file's encryption KEK is derived from
  `KDF(password, fido2_assertion)` rather than `KDF(password)` alone:
  without the hardware token, the wallet file cannot be decrypted
  regardless of password. This defends against the threat model that
  matters most for a privacy-focused wallet — a host compromised by
  malware capable of keylogging the password — for which plain
  password-at-open offers zero protection. Specifically: the V3.1
  design uses the CTAP2 `hmac-secret` extension to bind the KEK to a
  registered credential.

  **Format.** The V3.0 wallet file format does not reserve fields for
  MFA. V3.1 introduces them via a format-version bump, mirroring the
  precedent already encoded in `docs/WALLET_FILE_FORMAT_V1.md` for
  multisig (`CAPABILITY_RESERVED_MULTISIG = 0x04` and the
  forward-looking `wrap_count` reserved byte). Two paths are open:
  V3.1 either re-uses one of those slots (for example, treating the
  hardware-token requirement as a wrap-count discriminator) or adds a
  new capability mode behind the same format-version bump. The
  decision lands when the V3.1 design starts.

  **Recovery model.** Seed-phrase restoration is the canonical
  recovery path for token loss: lose the FIDO2 token, restore the
  wallet from BIP-39, pair a new token. Multi-token enrollment (N
  tokens, any of which can decrypt) is a possible enhancement
  deferred to V3.2 if the V3.1 single-token UX surfaces sufficient
  friction. The V3.1 design discussion starts from "single-token +
  seed-phrase recovery" as the default; do not relitigate.

  **Forward compatibility.** The lifecycle commit ships
  `Credentials<'_>` as the parameter type for every lifecycle entry
  point (`Wallet::create`, `open_full`, `open_view_only`,
  `open_hardware_offload`, `change_password`, `close`). Today the
  struct has a single private `password` field reachable through
  `Credentials::password_only(...)` / `.password()`. V3.1 adds an
  `authenticator: Option<AuthenticatorRequest<'_>>` field and a
  sibling `Credentials::password_with_authenticator(pwd, auth)`
  constructor; existing `password_only` call sites compile unchanged.
  Target: V3.1.

- ~~**`wallet_storage` tests pinned to wallet2 hardening-pass `2l /
  2m-keys / 2m-cache`.**~~ **CLOSED 2026-05-05 by fix, not by the
  hardening pass.** Three earlier triage rounds attached this failure
  to wrong root causes (daemon-fragility in `estimate_blockchain_height`;
  later, rederive-step view-secret corruption). The actual root cause
  was two C++/Rust constant disagreements in `src/shekyl/shekyl_ffi.h`:
  `SHEKYL_CLASSICAL_ADDRESS_BYTES` was `64` but Rust's
  `CLASSICAL_ADDRESS_BYTES` is `65`, shifting every later field of
  `ShekylAllKeysBlob` by one byte and feeding non-canonical scalars
  into `secret_key_to_public_key`; `SHEKYL_SEED_FORMAT_BIP39 / RAW32`
  were `0 / 1` but authoritative Rust uses `1 / 2`, so a stored RAW32
  seed format silently round-tripped as BIP39 and was rejected by
  `permitted_seed_format(Fakechain, Bip39)`. The tests additionally
  needed `tools::wallet2 w(cryptonote::FAKECHAIN, 1, false)` because
  `wallet2::generate("", password)` routes through
  `account_base::generate(..., m_nettype)`, which the post-Bug-4-adjacent
  fix correctly rejects on `(MAINNET, RAW32)`.
  See [`docs/CI_BASELINE.md`](./CI_BASELINE.md) Cluster B for the
  full post-mortem of the three falsified hypotheses. No on-disk
  wallets exist pre-V3 launch; no migration code is required.

- **Rust replacements for chaingen-deleted validation invariants.**
  (Test hygiene Δ1, 2026-05-05.) Closed `core_tests/{tx_validation,
  fcmp_tests, staking}` by deletion (see CI_BASELINE.md cluster C). The
  invariants those tests covered need to land as Rust unit tests once
  the corresponding daemon validation paths exist in Rust. Per cluster:
  - **tx-validation invariants** (9 worth-keeping from the 11 deleted
    `gen_tx_*` — the 2 dropped, `gen_tx_invalid_input_amount` and
    `gen_tx_output_with_zero_amount`, encode pre-RingCT semantics that
    don't apply in v3): tx-version-check, input-type-must-be-`txin_to_key`,
    empty-vin rejection, missing-key-offsets rejection, key-offset-out-of-
    range rejection, key-image-must-derive-from-input-key, key-image-must-
    be-on-curve, output-key-must-be-on-curve, output-type-must-be-
    `txout_to_key`/`txout_to_tagged_key`. Spec-anchors live in
    `cryptonote_format_utils.cpp` (line 295 et al.) and `fcmp::rctSigs.cpp`.
    Target: V3.x — lands with the `cryptonote_core` Rust port, since the
    invariants are daemon-side.
  - **FCMP++ tx-pool invariants** (from the 5 deleted `gen_fcmp_*`):
    valid FCMP++ tx accepted, double-spend rejected, reference-block-too-
    old rejected, reference-block-too-recent rejected, timestamp-unlock
    rejected. Spec-anchors in `tx_pool.cpp::add_tx`. Target: V3.x — lands
    with the tx-pool Rust port.
  - **Staking lifecycle / claim invariants** (from the 16 deleted
    staking tests): full lifecycle, claim range bounds, claim height
    bounds, claim watermark, claim amount, claim output type, claim
    pool exhaustion, claim key-image double-spend, tier validation,
    rollback restoration, mempool key-image dedup, sorted-input
    requirement. Spec-anchors in `staking/`. Target: V3.x — lands with
    the staking Rust port.

- **Coordinated `TestLedgerBuilder` test-infrastructure substrate
  design (V3.1 pre-first-daemon-Rust-port substrate-design
  FOLLOWUP).** The three V3.x invariant-test entries above
  (tx-validation, FCMP++ tx-pool, staking lifecycle) share a
  common test-infrastructure need: each set of unit tests
  requires deterministic synthetic blocks/transactions whose
  shape is rich enough to exercise the named invariants. PR 4
  C6β lands the minimum-substrate
  [`LocalLedger::from_test_blocks(blocks: Vec<Block>) -> Self`](../rust/shekyl-engine-core/src/engine/local_ledger.rs)
  per [`STAGE_1_PR_4_REFRESH_ENGINE.md`](./design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §7.X C6β (sufficient for `RefreshEngine` merge tests; "Need A"
  per the design doc's Round 5 sub-pin extension framing). The
  V3.x invariant-test entries above need richer substrate
  ("Need B"): test ledgers carrying transactions with valid
  FCMP++ membership proofs, valid PQC auth signatures, and
  valid curve-tree state — the structural-validity floor below
  which most daemon validation paths cannot be meaningfully
  exercised.

  **Disposition (three-prong).**

  1. **Coordinated, not per-port.** Design one
     `TestLedgerBuilder` / `TestBlockBuilder` /
     `TestTransactionBuilder` substrate that produces valid
     Shekyl-format artifacts and is shared across all three
     V3.x port queues. Building three ad-hoc per-port substrates
     is the discipline-drift answer (per
     [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)
     "continuous discipline as inheritance prevention" — substrate
     decisions made DURING the first consumer create per-consumer
     inconsistency that subsequent consumers inherit).
  2. **Designed BEFORE the first daemon Rust port.** The
     substrate-design doc lands as a stand-alone V3.1 design
     activity (its own design rounds, its own pre-flight
     against `25-rust-architecture.mdc` and
     `35-secure-memory.mdc`) before any of the three port queues
     consume it. The cost asymmetry from
     [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)
     §"The 'cost-benefit-defer-to-later' anti-pattern" applies:
     substrate decisions are cheap pre-consumer and expensive
     post-consumer.
  3. **Forward-composable with PR 4 C6β
     `LocalLedger::from_test_blocks`.** The V3.1 substrate
     should produce `Vec<Block>` (or a richer type wrapping
     it) such that `from_test_blocks` consumes the substrate's
     output naturally. The PR 4 C6β constructor signature is
     designed to compose forward; the V3.1 substrate
     pre-flight verifies composition is preserved when the
     richer substrate types layer on top.

  **Middle-ground option to flag in the design conversation.**
  Between "Need A" (no structural validity at all; sufficient
  for ledger-state merge tests) and "Need B" (full chaingen-
  equivalent infrastructure with real wallet-derived outputs and
  end-to-end transaction generation), a third class exists:
  **structurally-valid-but-semantically-stubbed** fixtures —
  transactions whose proofs verify, signatures verify, and FCMP++
  membership proofs are valid, but whose semantic content is
  canned (deterministic seeds, no real wallet state, no
  scan-recoverable outputs). Many of the deleted invariant tests
  (the "tx X is rejected because invariant Y fires" class) need
  a valid-shaped tx with one invariant violated, not a
  fully-real wallet-derived tx. The structurally-valid-but-
  semantically-stubbed builder unblocks a substantial fraction
  of the disabled-test backlog at lower cost than full Need B.
  The trade-off (which class of tests is unblocked at what
  cost) is the substrate-design conversation's load-bearing
  question; flagged here so the V3.1 design rounds enter with
  the option on the table rather than defaulting to a binary
  "Need A only or full Need B" framing.

  **Target version:** V3.1 (substrate-design activity; lands as
  a design doc + design rounds; implementation may stretch
  across V3.1 and V3.2 depending on scope). **Triggering
  conditions:** any of the three V3.x invariant-test entries
  above being scheduled for an upcoming PR cycle; failure to
  land the substrate-design doc before the first of those PRs
  opens triggers a discipline-drift finding per
  [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc).
  **Cross-reference:** PR 4 C6β prose at
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](./design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §7.X C6β and the Round 5 sub-pin extension's ledger-generator
  disposition paragraph in the Status banner.
- **(Closed by deletion 2026-05-05.) `core_tests` synthetic-block
  harness rewrite for v3-only flows.** Original framing retained for
  audit-trail context: 19 `core_tests` tests (`gen_tx_*` × 11,
  `gen_fcmp_*` × 5, `gen_staking_*` × 3) failed with `couldn't fill
  transaction sources` and `Block <hash> failed to pass prevalidation`,
  often preceded by `cn: Shekyl requires tx version >= 3`. The harness
  in [`tests/core_tests/chaingen.cpp`](../tests/core_tests/chaingen.cpp)
  constructed synthetic blocks against pre-rewire flows: it mined
  v1/v2 transactions that v3-from-genesis prevalidation rejects,
  and relies on outputs that the v3 scan path no longer recovers.
  The Track 0a working hypothesis ("Cluster A and Cluster C share
  one canonical-invariant root cause") was tested with a
  predict-then-recheck step on `gen_tx_big_version` and falsified —
  Cluster C remains red after the Track 0a fix because the harness
  never calls `shekyl_account_public_address_check`. Rebuilding the
  harness against v3-only flows is a planned activity for the
  wallet2 hardening / wallet2 removal cycle, not a Track 0 fix.
  Close condition: turns green after the chaingen harness is
  rewritten for v3 flows, OR closes with `wallet2.cpp` removal at
  V3.2 — whichever lands first. See
  [`docs/CI_BASELINE.md`](./CI_BASELINE.md) Cluster C. Target: V3.1.

- **Define formal escalation policy for `shekyl-oxide` divergence
  canary.** (Track 0 CI triage, 2026-04-28.) Today the canary in
  `.github/workflows/shekyl-oxide-divergence.yml` only fires on SHA
  divergence between the vendored snapshot and the upstream
  `Shekyl-Foundation/monero-oxide` `fcmp++` tip; it does not flag
  security-relevant upstream changes inside a divergence window. The
  interim spot-check policy recorded in
  [`docs/CI_BASELINE.md`](./CI_BASELINE.md) ("Interim shekyl-oxide
  divergence policy") is the floor — every sync includes a spot-check
  of the diff for security-flavored commit messages, dependency
  bumps, and changes to `unsafe` / cryptographic / consensus-relevant
  code, with delay-and-escalate on anything concerning — but it is
  **not** a substitute for a formal policy. The follow-up: design and
  land an escalation policy that (a) categorizes upstream commits by
  risk class (advisory-tagged commits flip the canary from
  informational to blocking), (b) names the maintainer(s) on rotation
  for divergence review, and (c) defines the grace-period contract
  the spot-check imposes today. Replacement condition for the interim
  policy: divergence frequency rises above ~one bump per quarter, OR
  upstream ships a security advisory inside a divergence window we
  hadn't yet synced. Target: V3.1.

- **Migrate C++ `transfer_details` consumers to
  `shekyl-engine-state::TransferDetails`.** ([`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)
  cites *"V3.1: transfer_details Rust migration, audit response"* as
  V3.1 scope; this row makes the work item explicit.) Today two parallel
  representations of "a wallet's view of one of its own outputs" coexist:
  the inherited C++ `struct transfer_details` in
  [`src/wallet/wallet2.h`](../src/wallet/wallet2.h) and
  [`src/wallet/wallet_rpc_server_commands_defs.h`](../src/wallet/wallet_rpc_server_commands_defs.h)
  (Monero-genesis layout, owns the wallet2 spend-detection / balance /
  payment-id-matching / change-password / store-load paths), and the
  Rust `TransferDetails` in
  [`rust/shekyl-engine-state/src/transfer.rs`](../rust/shekyl-engine-state/src/transfer.rs)
  (V3-native layout, owned by `shekyl-engine-state::WalletLedger` and
  driven by the Phase 1 lifecycle / Phase 2a `Engine::refresh` pipeline).
  Both are secret-bearing — `transfer_details` carries the recovered
  output secret material, `TransferDetails` carries the ZeroizeOnDrop
  Rust equivalent — so per [`20-rust-vs-cpp-policy.mdc`](../.cursor/rules/20-rust-vs-cpp-policy.mdc)
  rule 1 the long-term home is unambiguously Rust. Scope: rewrite each
  C++ consumer to drive the Rust type through FFI (balance, output
  selection, key-image / spend tracking, payment-id surface, password
  rotation, persistent wallet-cache load/store), then delete the C++
  `struct transfer_details` definitions and their epee serialization
  paths from both headers. Dependencies: depends on the wallet2 storage
  rewire (CHANGELOG commits 2l / 2m-keys / 2m-cache; close target
  commit `8167c1502`) being far enough along that there is a single
  canonical persistent representation; depends on
  [`docs/FOLLOWUPS.md`](./FOLLOWUPS.md) §V3.1 *"`wallet_storage` test
  fragility"* (Cluster B) being closed by the same hardening pass so
  the migration can verify the round-trip end-to-end. Exit criteria:
  `struct transfer_details` removed from both C++ headers; every
  surviving C++ caller in `wallet2.cpp` and `wallet_rpc_server.cpp`
  routes through the FFI to the Rust `TransferDetails`; the JSON-RPC
  `get_transfers`/`get_payments` responses are serialized from the
  Rust type's already-defined wire format. Close condition: lands on
  V3.1, OR — if the V3.2 wallet2 removal lands first — closes by
  superseding deletion of the C++ surface entirely (the migration is
  a stepping stone; the deletion is the destination). Target: V3.1.

- **`WALLET_REWRITE_PLAN.md` systemic broken relative-link sweep.**
  The file lives at `docs/design/WALLET_REWRITE_PLAN.md`; ~34 relative
  links use bare `](rust/...)` and `](docs/...)` paths which resolve
  to `docs/design/rust/...` / `docs/design/docs/...` and are broken.
  The two links Copilot flagged during PR #40 review (`docs/WALLET_FILE_FORMAT_V1.md`
  at L58 and `docs/WALLET_PREFS.md` at L71) were repaired inline as
  mode-2 mechanical-residue per the rule-15 trinary calibration
  (surface-during-review + bounded scope per the two specific lines);
  the broader file-wide sweep is mode-3 structural-tangent (doc-wide
  link audit; deserves its own bounded pre-flight) and is deferred
  here. The sweep is mechanical (each link is a single-path-prefix
  edit: `](rust/` → `](../../rust/` and `](docs/` → `](../`). Target:
  V3.1, paired with the broader `docs/` link-correctness pass that
  the V3.1 audit-response work surfaces. Cross-references: PR #40
  Copilot review (commit `5ab5b43a2`, discussion thread
  `r3221693336` and adjacent comments).

---

## V3.1.x — dependency migrations

- **rand 0.9 migration and curve25519-dalek 5 cascade.**
  Seven Dependabot alerts on `shekyl-core` cite
  [GHSA-cq8v-f236-94qc](https://github.com/advisories/GHSA-cq8v-f236-94qc)
  ("Rand is unsound with a custom logger using rand::rng()"), vulnerable
  range `>= 0.7.0, < 0.9.3`. We currently pin `rand = "0.8"` in five
  workspace crates and `rand 0.8.5` is transitively selected in the
  `rust/Cargo.lock` and `rust/shekyl-crypto-pq/fuzz/Cargo.lock` lockfiles.
  CVSS for all seven is 0 (Dependabot severity label "low"). These alerts
  have been dismissed on GitHub with reason "risk tolerated" and a link
  to this follow-up.

  ### Affected manifests (all seven alerts)

  - `rust/Cargo.lock` (alert #3)
  - `rust/shekyl-crypto-pq/fuzz/Cargo.lock` (alert #4)
  - `rust/shekyl-crypto-pq/Cargo.toml` (alert #5)
  - `rust/shekyl-chacha/Cargo.toml` (alert #6)
  - `rust/shekyl-fcmp/Cargo.toml` (alert #7)
  - `rust/shekyl-proofs/Cargo.toml` (alert #8)
  - `rust/shekyl-tx-builder/Cargo.toml` (alert #9)

  ### Not exploitable today

  The `rand::rng()` function named in the advisory is the 0.9+
  thread-local RNG API and does not exist in rand 0.8. Shekyl's crypto
  paths obtain randomness two ways:

  - `rand::rngs::OsRng` passed directly to dalek's `Scalar::random` and
    to `SigningKey::generate` (see `rust/shekyl-crypto-pq/src/montgomery.rs`,
    `kem.rs`, `signature.rs`, `multisig.rs`).
  - `rand_chacha::ChaCha20Rng::from_seed([...])` for deterministic key
    derivation (see `rust/shekyl-crypto-pq/src/derivation.rs`).

  Neither codepath calls `rand::rng()` and the Shekyl daemon does not
  install a custom `log::Log` implementation, so the logging-induced
  soundness bug described in the advisory has no path to the RNG state
  in any Shekyl binary.

  ### Why we can't just bump rand to 0.9

  rand 0.9 moved `RngCore` / `CryptoRng` trait definitions and renamed
  several methods (`gen` → `random`, `gen_range` → `random_range`,
  `thread_rng` → `rng`). The rest of the crypto ecosystem we depend on
  is still pinned to the rand 0.8 `rand_core` trait set:

  - `curve25519-dalek = "4"` (and its `Scalar::random` wiring)
  - `ed25519-dalek = "2.2.0"` with the `rand_core` feature
  - `rand_chacha = "0.3"`
  - `fips204 = "0.4.6"`, `fips203 = "=0.4.3"` (NIST PQC implementations)

  Attempting to bump rand to 0.9 in isolation fails to compile because
  `Scalar::random(&mut rand::rngs::OsRng)` expects the 0.8 trait set. A
  real migration cascades into bumping curve25519-dalek to 5.x (plus its
  downstream consumers) and re-auditing every crypto call site.

  Per `.cursor/rules/20-rust-vs-cpp-policy.mdc`, a migration of this
  size is a planning activity — its own design document, 4–6 review
  rounds, its own test gates, its own PR. Folding it into any other
  change produces an unreviewable diff.

  ### Gate

  Do not start this migration until:

  1. `curve25519-dalek 5.x` has at least one stable release with a
     reviewable changelog against 4.x.
  2. `ed25519-dalek`, `rand_chacha`, and the `fips204`/`fips203` crates
     have released versions that advertise rand 0.9 compatibility.
  3. We have a test plan that confirms every `OsRng` / `from_seed`
     call site produces byte-identical output against pre-migration
     test vectors (HKDF vectors, signing round-trip vectors, FCMP++
     blinding-factor vectors).

  ### Scope when picked up

  - Bump rand, rand_chacha, and rand_core in all five workspace crates.
  - Update `Scalar::random`, `SigningKey::generate`, and
    `ChaCha20Rng::from_seed` call sites to the new trait API.
  - Re-run the full test-vector regeneration path and confirm no drift.
  - Dedicated PR; the "rand migration" lands on `dev` behind no feature
    flag, but must not be bundled with any other security or feature
    change.

  ### Residual: digest_auth transitive

  Even after our workspace crates migrate, `digest_auth v0.3.1` (a
  transitive dependency of `shekyl-simple-request-rpc` via the
  `shekyl-oxide` vendor tree) selects rand 0.8.5 for cnonce generation.
  It has no newer crates.io release. Alerts #3 and #4 (the two
  `Cargo.lock` alerts) will reappear until `digest_auth` is either:

  - upstream-patched and a new version published,
  - replaced with a different HTTP-digest library (evaluate
    `http-auth`, `reqwest-middleware` auth patterns), or
  - vendored and patched in-tree under `shekyl-oxide/`.

  Track that replacement as a sub-task of this item, not as a separate
  follow-up; both will land together. Target version: **V3.1.x**,
  specific minor decided when the curve25519-dalek 5.x release window
  becomes visible.

- **Two `unmaintained` advisories surfaced by `cargo audit`
  (`atomic-polyfill 1.0.3` / `bincode 1.3.3`; trigger: PR #57 CI
  output review on commit `b71ecd892`, `2026-05-19`).** Both are
  `unmaintained`-class advisories, allowed by default in
  `cargo-audit` (which only blocks on `vulnerability`-class), so
  they print as `warning: 2 allowed warnings found` and the
  `cargo audit` step exits `0` — the audit gate stays green. Neither
  is exploitable on the Shekyl threat model today; both are upstream
  maintenance signals worth tracking for a deliberate upgrade window
  rather than letting them accumulate.

  ### Advisory A — `RUSTSEC-2023-0089` `atomic-polyfill 1.0.3`

  Pulled transitively via `heapless 0.7.17 → postcard 1.1.3`,
  consumed by `shekyl-ffi` and `shekyl-engine-state` (and through
  `shekyl-engine-state` by `shekyl-scanner`, `shekyl-engine-rpc`,
  `shekyl-engine-file`, `shekyl-engine-core`) for deterministic
  serialization at the FFI / engine-state boundary. The advisory's
  upstream remediation summary is "the crate is unmaintained;
  consider `portable-atomic`-based alternatives." Closing the
  advisory in-tree means riding a `heapless` / `postcard` release
  pair that no longer pins `atomic-polyfill`; the API surface and
  the deterministic-serialization byte-identity must be verified
  per `.cursor/rules/17-dependency-discipline.mdc` before bumping.

  ### Advisory B — `RUSTSEC-2025-0141` `bincode 1.3.3`

  Pulled transitively via `iai-callgrind 0.16.1`, consumed only by
  benchmark targets (the `engine_trait_bench_*` family per
  [`docs/design/STAGE_0_HARNESS.md`](./design/STAGE_0_HARNESS.md)
  §3.3.1). No production binary links `bincode`; the consumer is
  the iai-callgrind harness. Closing the advisory means riding an
  `iai-callgrind` release that drops `bincode 1.3.3`, or replacing
  the bench harness if upstream readiness is far out. Bench-only
  scope; no consensus or wallet path is touched.

  ### Why these are not folded into PR #57

  PR #57 is the wallet2 BIP-39 rewire / Phase-1 Electrum-words
  removal. Touching the lockfile to address transitive-dep
  advisories would put dep-discipline review on the same PR as
  consensus-touching wallet code, which
  `.cursor/rules/15-deletion-and-debt.mdc` ("'while we're here' is
  the enemy") and `.cursor/rules/17-dependency-discipline.mdc`
  (verification at source for every new feature flag / version bump)
  both reject. Each advisory closure is its own dep-housekeeping PR.

  ### Gate (per advisory)

  Do not start either upgrade until upstream readiness is visible:

  - **Advisory A:** a `postcard` release that no longer pins
    `heapless 0.7.x` (and therefore no longer transitively pins
    `atomic-polyfill`) is crates.io-published with a reviewable
    changelog against the current `postcard 1.1.3` API surface.
  - **Advisory B:** an `iai-callgrind` release that drops
    `bincode 1.3.3` is crates.io-published, or a bench-harness
    alternative is selected and pre-flight-reviewed.

  ### Scope when picked up (per advisory)

  Each advisory is a single small dep-housekeeping PR:

  - **A** bumps `heapless` / `postcard` in
    `rust/shekyl-engine-state/Cargo.toml`,
    `rust/shekyl-ffi/Cargo.toml` (and any other consumers the
    pre-flight surfaces); re-runs the deterministic-serialization
    round-trip tests; confirms `cargo audit` no longer emits
    `RUSTSEC-2023-0089`.
  - **B** bumps `iai-callgrind` in every `shekyl-*-bench`
    consumer; re-runs `capture_rust_baseline.sh` invariance (per
    [`STAGE_0_HARNESS.md`](./design/STAGE_0_HARNESS.md) §3.3.1)
    to confirm the bench harness still produces stable iai counts;
    confirms `cargo audit` no longer emits `RUSTSEC-2025-0141`.

  Each PR closes its half of this entry; when both advisories are
  gone from `cargo audit` output, delete the whole entry per the
  file's "git history is the archive" policy. The two upgrades are
  independent and may land in either order.

  Target version: **V3.1.x**, scheduled per advisory when upstream
  readiness becomes visible.

- **Chore #3: retire every 32-bit target — leading with the security argument (`v3.1.0-alpha.5`, landed on `chore/retire-32bit-targets`).**
  **Status: landed.** Closure narrative in
  `docs/audit_trail/RESOLVED_260419.md` §"Chore #3 (v3.1.0-alpha.5) —
  32-bit target retirement: security closure"; this entry is retained
  in place through V3.1.x as the canonical pre-landing design record
  cross-referenced from the `CHANGELOG` and from all four tripwire
  comment blocks. Do not delete on "it's done now" grounds — the
  design record is how a future cleanup-PR author discovers the
  structural-not-observable rationale for Tripwire B and the
  node-only-defense pre-emption. **Original framing, preserved:**

  **The reason is security, not maintenance.** Shekyl's PQC primitives
  (`fips203` / ML-KEM-768, and the ML-DSA-65 implementation consumed by
  `shekyl-tx-builder` and `shekyl-crypto-pq`) rely on 64-bit arithmetic
  for their constant-time guarantees. On 32-bit targets the compiler
  lowers `u64` operations through **compiler-emitted libgcc helpers
  (`__muldi3`, `__udivdi3`, `__ashldi3`) with no constant-time
  guarantee, plus variable-latency `u64` multiply on common 32-bit
  ARM cores**. That is a CT-violation introduced by the code generator,
  not the source, and it is the exact class of violation source-level
  CT audits cannot catch. **KyberSlash (Bernstein et al., 2024)**
  demonstrates remote-timing key recovery against ostensibly
  constant-time implementations broken by this shape; the earlier
  Cortex-M4 Kyber timing-attack line (2022–2024) is supporting
  context. The **X25519+ML-KEM hybrid does not save us** — the
  "hybrid is secure if either half is secure" framing protects
  against algorithmic breaks, not side-channel breaks. If ML-KEM
  leaks via timing on 32-bit, X25519 is offline-attackable against
  captured ciphertexts with unlimited time. FCMP++ / Bulletproofs+
  proof generation **has not been audited for constant-time
  properties on 32-bit targets, and Shekyl will not take
  responsibility for that audit across all 32-bit toolchains we
  would otherwise ship** — policy framing, not speculation. And
  `MDB_VL32` (LMDB's 32-bit mmap strategy) is an untested storage
  path no CI runner has ever exercised against a real chain; the
  CryptonightR 32-bit software fallback in `src/crypto/slow-hash.c`
  is untested consensus-adjacent PoW code. **32-bit Shekyl wallet
  users are at meaningfully elevated risk of key extraction compared
  to 64-bit users; supporting the platform is a tacit lie about the
  security posture of users on it.**

  **Node-only defense, pre-empted.** A contributor will argue "I
  just want to run a 32-bit pruned node on a Pi, I'm not doing
  wallet operations, the CT argument doesn't apply." That is
  partially true — node code does not touch secret PQC keys. But
  (a) `MDB_VL32` paging on a multi-GB chain makes sync time measured
  in weeks, which is not a supported posture; and (b) shipping a
  32-bit daemon binary creates a reasonable user expectation that
  wallet operation is supported, which it is not. The operational
  complexity of splitting "32-bit daemon supported, 32-bit wallet
  refused" outweighs any benefit.

  **Discovered during Chore #2** (easylogging++ retirement) when
  MSYS2 CI surfaced a `FSCTL_SET_COMPRESSION` regression. The first
  two diagnoses were both wrong (`9284d781d` include-order hoist,
  reverted; `a68314e3f` `_WIN32_WINNT` re-tiering, also wrong). The
  actual fix is a self-contained `#ifndef FSCTL_SET_COMPRESSION`
  fallback in `src/blockchain_db/lmdb/db_lmdb.cpp` —
  `FSCTL_SET_COMPRESSION` is gated by `#ifndef _FILESYSTEMFSCTL_`
  in MinGW-w64's `<winioctl.h>` and something upstream in the
  boost/lmdb chain pre-defines that sentinel on MSYS2 builds; the
  FSCTL value hasn't changed since NT 4.0, so re-supplying it from
  `CTL_CODE` primitives is safe. The pattern the bug exposes is
  tabulated in `STRUCTURAL_TODO.md` §"32-bit targets cannot safely
  run Shekyl"; Chore #3 closes the whole pattern, not just the
  specific symptom.

  **Scope** — all in one chore, symmetric across Windows and
  ARM32 because the security argument is symmetric:

  - Delete `cmake/32-bit-toolchain.cmake`.
  - Delete the six 32-bit `Makefile` targets that actually exist
    on `dev`: `debug-static-win32` (L84),
    `release-static-linux-armv6` (L117),
    `release-static-linux-armv7` (L121),
    `release-static-android-armv7` (L125),
    `release-static-linux-i686` (L151), and
    `release-static-win32` (L159). Earlier drafts named
    `release-static-armv7` / `release-static-armv6` *without* the
    `linux-` prefix; those two identifiers are phantoms and no
    deletion is needed because they were never present. The
    landed scope list has been corrected.
  - Delete the `i686-w64-mingw32-*` alternatives in
    `contrib/gitian/gitian-win.yml`, the ARMv7 entries in
    `gitian-linux.yml` and `gitian-android.yml`.
  - Delete `_config_opts_i686_mingw32`, `_config_opts_mingw32`
    (where purely 32-bit), the `_cflags_mingw32` line in
    `contrib/depends/packages/unbound.mk` (arch-asymmetric
    carve-out — deletion target, not a typo), and the
    `i686_mingw32` variants in the other
    `contrib/depends/packages/*.mk`.
  - Delete `MDB_VL32` from
    `external/db_drivers/liblmdb/CMakeLists.txt`. Vendored-LMDB
    code paths inside the vendored tree become unreachable
    without the define; leaving them untouched preserves the
    upstream-merge posture. `docs/VENDORED_DEPENDENCIES.md`
    grows a one-beat note to re-verify no new `MDB_VL32`-gated
    paths have been reached unconditionally by a future vendor
    refresh.
  - Delete the CryptonightR 32-bit software-fallback body in
    `src/crypto/slow-hash.c` (between the L374 x86_64 AES-NI
    gate and the L1015 ARM gate), and tighten L1015 from
    `__arm__ || __aarch64__` to `__aarch64__`. Gated by an
    execution-time `nm` verification on both x86_64 and aarch64
    builds confirming no 64-bit target links the fallback
    symbols, per `81-no-protocol-knowledge.mdc`. **The
    `tests/hash/main.cpp:192, 206` `sqrt_result` inline-asm
    block is *not* being deleted — those lines are 64-bit SSE
    gates, not 32-bit gates; the earlier framing that lumped
    them with the 32-bit retirement was imprecise.**
  - Delete the `#if ARCH_WIDTH != 32` branch in
    `src/blockchain_utilities/blockchain_import.cpp:64`.
  - Delete the Clang + `ARCH_WIDTH==32` `libatomic` pull in
    `CMakeLists.txt` (around L1357–L1360 on current `dev`;
    anchor on the condition, not the line).
  - **Collapse `BUILD_64` / `ARCH_WIDTH` / `BUILD_WIDTH` to
    unconditionally-true and delete the conditional guards
    entirely.** Leaving dead `#if ARCH_WIDTH == 64` around is
    the same inherited-correctness disease the chore exists to
    cure. This is the part of the chore it is tempting to skip;
    do not skip it.
  - **Add four defense-in-depth tripwires.** Rust `compile_error!`
    in `rust/shekyl-crypto-pq/src/lib.rs` (Tripwire A, primary),
    `rust/shekyl-ffi/src/lib.rs` (Tripwire B, structural-not-
    observable — duplicated-by-design, do not delete on "never
    fires in CI" grounds), `rust/shekyl-tx-builder/src/lib.rs`
    (Tripwire C, independent `fips204` consumer); plus
    `message(FATAL_ERROR …)` at the top of the root
    `CMakeLists.txt` (Tripwire D, C++-side gate). Each message
    cross-references the other three and leads with the
    KyberSlash citation. A new CI job
    (`.github/workflows/cmake-gate-test.yml` +
    `tests/cmake-gate-test/run.sh`) asserts Tripwire D fires on
    a fake 32-bit toolchain before `find_package` runs — a PR
    that moves the gate below `find_package(...)` fails that
    test.
  - Strip 32-bit paragraphs from `README.md`,
    `docs/INSTALLATION_GUIDE.md`, `contrib/depends/README.md`,
    and any daemon/wallet user-facing docs that reference
    `i686` or `armv7`.
  - `docs/CHANGELOG.md v3.1.0-alpha.5` `### Security` entry
    leads with the tacit-lie framing. Suggested argument chain
    in `STRUCTURAL_TODO.md` §"32-bit targets cannot safely run
    Shekyl"; the entry names all four tripwires, cites
    KyberSlash (2024) as headline, pre-empts the node-only
    defense, and lists maintenance benefits as secondary.

  **Verification**: independent-failure tests for all four
  tripwires (each must fire on its own on `i686-unknown-linux-gnu`),
  `nm`/`objdump` on x86_64 + aarch64 confirming `__divmoddi4` and
  the `slow-hash.c` fallback symbols absent, an
  `aarch64-linux-gnu-gcc -dM -E` check that `__arm__` is not
  defined on aarch64, positive `cargo build`/`cargo test` on
  x86_64 and aarch64, and an expanded `rg` sweep returning no
  Shekyl-side 32-bit residue outside `external/`,
  `docs/audit_trail/`, and `docs/CHANGELOG.md`.

  Precedent: V3.0 `i686-linux-gnu` retirement, see
  `docs/audit_trail/RESOLVED_260419.md` §"Dead `i686_linux_*`
  target in `contrib/depends/hosts/linux.mk`". Full motivation
  in `docs/STRUCTURAL_TODO.md` §"32-bit targets cannot safely
  run Shekyl, and the wider 'bit-width carve-out without
  coverage' pattern". Target: **`v3.1.0-alpha.5`** — the
  security closure merits being surfaced in the active alpha
  cycle rather than deferred to V3.2's Rust-cutover grab-bag.

---

## V3.1+ — Legacy C++ → Rust rewrite scope

Items captured from the
[shekyl-v3-wallet-rust-rewrite plan](../.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md)
(2026-04-25) when the `wallet-state-promotion` plan halted at 2k.c
on the basis that further `wallet2.cpp` rewires generate audit
surface for a file scheduled for deletion. The rewrite plan deletes
`wallet2.cpp` wholesale at its Phase 5 — these items name the
scoped follow-ups that ride alongside that deletion or land in
its wake.

- **`wallet2` has no `generate_from_bip39` entry point — by design;
  do not add one.** Surfaced 2026-05-05 (Bug 4 in
  `docs/audit_trail/2026-05-ffi-constant-drift-audit.md`) when an
  attempt to add C++/FFI coverage for the wallet2 BIP-39 round-trip
  uncovered that the wrapper has never existed: the Rust derivation
  (`shekyl-crypto-pq::generate_account_from_bip39`), the FFI
  (`shekyl_account_generate_from_bip39`), and the lower-level C++
  glue (`account_base::generate_from_bip39`) all exist and are
  tested, but the `wallet2`-level wrapper was never wired through
  when the original wallet2-from-Electrum-mnemonic path was retired.
  Pre-mainnet, no production caller is broken by the absence; this
  is a coverage-gap report against a layer that is being deleted by
  the Rust rewrite at Phase 5, not a bug in the conventional sense.

  **Architectural decision (2026-05-05):** new BIP-39 wallet
  creation will happen via the Rust wallet path post-migration. The
  wallet2-level wrapper will not be added pre-migration, because:
  (a) any wallet2 wrapper added now will be deleted by Phase 5 of
  the Rust rewrite — a transitional API that becomes a removal-as-
  breaking-change rather than a removal-as-no-op; (b) the Rust
  derivation path is the actual functional guarantee and is tested
  end-to-end (`shekyl-crypto-pq::tests::generate_from_bip39_mainnet_roundtrips_to_rederive`);
  (c) no mainnet wallets exist yet, so no production user is
  affected by the absence; (d) the next beta ships before the Rust
  rewrite lands, so any "transitional" wrapper would have a
  lifespan shorter than its review burden.

  **CI tripwire:** `tests/unit_tests/wallet_storage.cpp` carries a
  `static_assert` against a SFINAE detector for
  `wallet2::generate_from_bip39`. If a future contributor adds the
  wrapper without thinking about the migration, the build fails
  with a message pointing back at this entry. The tripwire is
  designed to delete itself when the Rust rewrite Phase 5 lands and
  `wallet2.cpp` goes away.

  **Closure point:** Phase 5 of the Rust rewrite (the wallet2.cpp
  deletion). At that point this entry retires; the tripwire deletes
  with `wallet_storage.cpp`; the Rust BIP-39 round-trip test is the
  only remaining functional artifact, which is correct.

- **`wallet2` 0-change dummy-destination address generation should
  migrate to a deterministic per-network burn address.**
  `src/wallet/wallet2.cpp::transfer_selected_rct` calls the
  network-aware `account_base::generate(...)` overload with
  `cryptonote::FAKECHAIN` hardcoded to produce a dummy
  `account_public_address` for 0-change destinations (a one-shot
  transient: only the public keys feed the output's one-time key +
  ML-KEM ciphertext derivation; the dummy's secret keys are
  discarded). The transaction serializes only the derived output
  key and PQC ciphertext, not any human-readable address or network
  prefix, so the FAKECHAIN-vs-other-network choice has **no
  observable on-wire effect** — it only selects the HKDF salt
  driving the dummy's internal key derivation, and the resulting
  output is unspendable for everyone (the dummy's secret keys are
  never retained). FAKECHAIN is required here today because RAW32
  isn't permitted on MAINNET / STAGENET by the network-aware
  generator. The fix wants either (a) a deterministic per-network
  burn address (preferable: removes the per-tx randomness from the
  dummy slot and saves a derivation per transfer), or (b) an
  architectural change that removes the 0-change-dummy pattern
  entirely. This is an efficiency / cleanliness item, not a
  correctness or privacy bug.

  **Closure point:** Phase 4 of the Rust rewrite (transaction
  construction migration). The `splitted_dsts` 0-change path lives
  in the C++ tx-construction code that gets rewritten in Rust;
  whatever the Rust transfer pipeline picks for this slot replaces
  the C++ dummy.

- **Add a BIP-39 / raw-seed recovery entry to
  `stop_background_sync` in the Rust JSON-RPC server.** Pre-Phase-2
  this entry was framed as "replace the Electrum-words seed-
  recovery branch with BIP-39." The Electrum-words branch
  (`crypto::ElectrumWords::words_to_bytes` →
  `account_base::generate(recovery_key, true, false, nettype)` →
  spend-key match check) was deleted outright in Phase 2 of the
  Electrum-words removal series (PR #58); the C++
  `wallet_rpc_server::on_stop_background_sync` handler now only
  forwards `crypto::null_skey` to `wallet2::stop_background_sync`,
  i.e., password-only recovery. Seed-based recovery via the JSON-RPC
  surface is not currently exposed at all.

  The forward-looking work is therefore additive: the V3.2
  Rust JSON-RPC server gets to define a BIP-39 / raw-seed
  recovery shape from scratch (route through the
  `shekyl_account_generate_from_raw_seed` FFI for testnet/fakechain;
  define the BIP-39 mnemonic + passphrase entry shape for
  mainnet/stagenet once Bug-4's BIP-39 wrapper lands per the
  separate V3.2 "wallet2 BIP-39 entry point" item). The C++ shim
  retires with `wallet_rpc_server.cpp` in the same release; nothing
  to migrate, since Phase 2 already removed the legacy surface.

  **Closure point:** V3.2 alongside the `shekyl-wallet-rpc` Rust
  cutover. Cross-references: PR #58 (Phase 2 RPC deletion);
  [`docs/design/ELECTRUM_WORDS_REMOVAL.md`](./design/ELECTRUM_WORDS_REMOVAL.md)
  §2.4 G1; commit `255ea0abb` (`wallet-rpc: drop seed-recovery
  branch from stop_background_sync`).

- **Replace `wallet_rpc_server::on_create_wallet` and
  `wallet2_ffi::create` raw-seed wallet creation with a BIP-39
  entry on MAINNET / STAGENET.** Bug 4-adjacent in
  `docs/audit_trail/2026-05-ffi-constant-drift-audit.md`. Both RPCs
  call `wallet2::generate(name, password, dummy_key, /*recover=*/false,
  ...)` which routes through `account_base::generate(..., m_nettype)`.
  Pre-fix the call silently produced FAKECHAIN-salted accounts on
  MAINNET / STAGENET that failed to round-trip on `wallet2::load`;
  post-fix it throws cleanly with a clear FFI error pointing at the
  `(network, seed_format)` rejection (RAW32 isn't permitted on
  MAINNET / STAGENET). Both paths were already broken on MAINNET
  pre-fix; the post-fix behaviour is a strict improvement (fail-loud
  vs fail-silent) but it is not a finished feature: fresh-wallet
  creation on MAINNET / STAGENET via these RPCs simply does not work
  by design. The proper fix is the wallet2 BIP-39 entry point (Bug
  4 in the audit, deferred per the Rust wallet migration). Until
  then, MAINNET / STAGENET wallet creation must go through the
  view-only / spend+view restore paths
  (`wallet2::generate(name, password, address, viewkey, ...)` and
  `wallet2::generate(name, password, address, spendkey, viewkey, ...)`)
  which bypass `account_base::generate` entirely.

  **Closure point:** V3.2 alongside the `shekyl-wallet-rpc` Rust
  cutover. The Rust wallet-RPC will expose BIP-39 wallet creation as
  the MAINNET / STAGENET native flow; the C++ raw-seed RPCs retire
  with `wallet_rpc_server.cpp` / `wallet2_ffi.cpp`.

- **`wallet2::get_daemon_blockchain_target_height` lets asio
  `system_error` escape the `err`-string contract.**
  `tools::wallet2::get_daemon_blockchain_target_height(string& err)`
  documents an `err`-out-parameter contract: on RPC failure, `err`
  is populated and the function returns 0 cleanly. In practice the
  inner `m_node_rpc_proxy.get_target_height(target_height)` call
  reaches `epee::net_utils::http::http_simple_client_template::invoke`
  → `blocked_mode_client::connect`, where asio raises
  `boost::system::system_error` directly on a connect failure. The
  exception bypasses the `err`-string code path and propagates up
  through `estimate_blockchain_height()` and into every caller of
  `wallet2::generate(name, password)` with `recover = false`. CI
  flakes on `tests/unit_tests/wallet_storage.cpp::change_password_*`
  surfaced this in May 2026 (PR #29 CI run 25407980061); the tests
  were deflaked by pre-setting `m_refresh_from_block_height = 1` to
  short-circuit the daemon call, but the underlying robustness gap
  remains: any caller of `wallet2::generate(...)` on a host without
  a reachable daemon can have an unhandled asio exception escape.
  The fix is to wrap `m_node_rpc_proxy.get_target_height` (and any
  other `NodeRPCProxy` call inside `get_daemon_blockchain_*`) in a
  try/catch that converts the asio exception into the documented
  `err` string return path.

  **Closure point:** Either V3.1 wallet hardening pass (cheap fix
  in `wallet2.cpp`), or naturally with Phase 5 of the Rust rewrite
  when the equivalent Rust path uses `Result` propagation by
  construction.

**Index of how each follow-up interacts with the rewrite** (entries
themselves carry the detail; this table is the at-a-glance view used
by the rewrite plan's half-day review gate, item 3):

| Status | Entry | Closure point |
| --- | --- | --- |
| Absorbed (already by rewrite plan) | `wallet2.cpp` absorption (2l/2m/2n) | Phase 5 deletion |
| Absorbed | `WalletPrefs` round-trip property test (2k.a2) | Phase 1 (`RuntimeWalletState` audit) |
| Absorbed | `shekyl-daemon-rpc` staticlib `tracing` silently dropped (V3.2 below) | Phase 1 (logging deliverable, re-targeted from V3.2) |
| Closed by Phase 5 | `shekyl-cli` key image export binary format (V3.2 below) | Phase 5 — Monero binary format dies with `wallet2.cpp`; air-gapped flow uses `UnsignedTxBundle`/`SignedTxBundle` |
| Closed by Phase 5 | `wallet_tools.cpp` mixin/decoy infrastructure (V3.2 below) | Phase 5 — swept with `tests/unit_tests/wallet*.cpp` |
| Closed (Operation A) | `monero-oxide` vendor-bump `87acb57` → `3933664` | Phase 0 PR 0.6 (mechanical, fork-tip only) |
| Cross-linked, not absorbed | `shekyld` `fee_policy_version` daemon-side exposure | V3.1 daemon release (wallet uses `Option<u32>` forward-compat) |
| Cross-linked, not absorbed | `tx_pool` / `blockchain_db` LMDB transactional wrapper | V3.1.x peer plan (separate from rewrite) |
| Cross-linked, not absorbed | `monero-oxide` un-pin Operation B (40 upstream commits) | V3.1.x un-pin plan (peer to rewrite, parallelizable) |
| Cross-linked, not absorbed | Workspace clippy `-D warnings` cleanup | V3.1.x dedicated pass (after rewrite stabilizes) |
| Cross-linked, optional | `shekyl-cli` offline signing QR-chunked transfer (V3.2 below) | Phase 3b (optional `--format=qr-chunks` on bundles) |
| Independent of rewrite | `removed_flags` shim sunset (V3.2 below) | V3.2 cleanup pass — naturally retires when `shekyl-wallet-rpc` Rust cutover lands |
| Independent of rewrite | Chore #4 platform-gate audit (V3.2 below) | V4 pre-audit |
| Independent of rewrite | Restore semantic thread labels (V3.2 below) | V3.2 |
| Independent of rewrite | `rand` 0.9 / `curve25519-dalek` 5.x migration (V3.1.x above) | Gated on upstream releases |
| Independent of rewrite | Stack trace / unwinder LibUnwind (V3.1.x above) | Daemon-side diagnostics |

The PQC Multisig V3.1 hardware wallet integration (TBD section) and
the tx-pool / monero-oxide / clippy items keep their existing target
versions; they are listed here only so the rewrite's review gate has
one place to confirm each item's relationship to the wallet stack.

- **`wallet2.cpp` absorption — sub-commits 2l/2m/2n.** The
  `wallet-state-promotion` plan's
  [2l cache rewire](../.cursor/plans/2l-cache-rewire_80a08559.plan.md)
  (sub-commits 2l.b, 2l.c, 2l.d, 2l.e), 2m-keys (legacy keys-side
  ser/des deletion), 2m-cache (legacy boost-cache deletion), and 2n
  (transitional `pub use ... as WalletState` alias deletion) are
  **deferred and absorbed**. They are replaced by:
  - The native Rust cache-load and cache-emit path on
    `shekyl-wallet-core::Wallet` (Phase 1–2 of the rewrite plan).
  - The single-commit C++ deletion at Phase 5 of the rewrite plan,
    which removes `wallet2.cpp`, `wallet2_ffi.cpp`,
    `src/wallet/api/`, `src/simplewallet/`,
    `wallet_rpc_server*.cpp`, and the `shekyl_wallet_*` C-ABI
    surface that existed only because `wallet2.cpp` consumed it.
  No incremental in-`wallet2.cpp` work is planned between now and
  Phase 5. **Target: V3.1.x (Rust wallet stack feature parity →
  C++ deletion).**

  **Phase 5 inventory pre-emptions.** Individual items from the
  Phase 5 deletion inventory may be deleted earlier when their
  callers are conclusively gone (zero `.cpp` callers per `git grep`,
  evidence in PR description). The rule and its first application are
  pinned in `docs/V3_WALLET_DECISION_LOG.md` under
  *"Phase 5 pre-emption rule"*. Items already pre-empted:
  - `rust/shekyl-ffi/src/wallet_ledger_ffi.rs` — the typed
    cache-handle FFI surface from sub-commit 2l.a, deleted as part
    of the Phase 1 `primitives` task on 2026-04-25 once the
    `SubaddressIndex` flatten work confirmed zero `.cpp` callers
    had ever materialized. The Phase 5 commit's deletion list
    drops this file from its enumeration.

- **Hardening-pass commit 8 follow-up: WalletPrefs round-trip
  property test (`2k.a2` deferred test).** The wallet-prefs round-trip
  proptest mentioned in the 2l.a / 2l.e design pin land list was
  deferred during the wallet-state-promotion plan and was scheduled
  to land in 2l.e. With 2l.e absorbed, the test now lands wherever
  the `shekyl-wallet-prefs` crate-level test surface ships next —
  most naturally as part of the rewrite plan's Phase 1 `RuntimeWalletState`
  audit when `WalletPrefs` integration is exercised. Track in the
  rewrite plan, not here. **Target: V3.1.x (Phase 1 of rewrite).**

- **`tx_pool` / `blockchain_db` LMDB transactional wrapper — typed
  commit-or-abort.** Lesson surfaced by the Dandelion++ relay
  timestamp finding (silent rollback in `tx_pool.cpp::get_relayable_transactions`
  via `LockedTXN` destructor abort-on-drop without an explicit
  `lock.commit()`). The fix that landed in the C++ daemon was a
  one-line `lock.commit()` add. The **structural fix** is a Rust
  wrapper for the LMDB transaction pattern where forgetting to
  commit is a compile error: the wrapper's `Drop` impl aborts (so
  unwind safety is preserved), but the type-level API requires
  consuming the transaction with an explicit `commit()` to signal
  success — `?`-propagation on a `Result` automatically routes to
  abort-via-Drop, while the success path consumes the transaction.
  This eliminates the entire bug class rather than fixing the one
  symptom; Monero's `LockedTXN` callers all have the same shape and
  the upstream-inheritance audit surface is non-trivial.

  Scope of the work: redesign the LMDB transactional wrapper as a
  Rust crate (under `rust/shekyl-lmdb-tx/` or similar), audit every
  `LockedTXN` call site in `tx_pool.cpp`, `blockchain_db.cpp`,
  and adjacent daemon code, port them to the new wrapper, and
  delete `LockedTXN` from C++. Same shape as the wallet rewrite (a
  separate plan, separate review cycle, separate PR). **Target:
  V3.1.x — does not block the wallet rewrite, but should land in
  the same V3.1 cycle since the audit-defensibility argument is
  identical.**

- **`shekyld` `fee_policy_version` daemon-side exposure.** Surfaced
  by the Phase 0 `shekyld` prerequisites audit (PR 0.3 of the wallet
  rewrite plan,
  [`docs/SHEKYLD_PREREQUISITES.md`](SHEKYLD_PREREQUISITES.md) §3).
  The daemon's `get_fee_estimate` RPC (and its sibling RPCs `get_info`,
  `get_block_template_backlog`, etc.) does **not** advertise a
  versioned identifier for the fee policy / fee-rules-set in force —
  no `fee_version` field on the response, no `fee_policy_id` on
  `get_info`, no separate `get_fee_policy` RPC. A wallet that queried
  fee estimates yesterday cannot detect, from RPC alone, whether the
  consensus rules governing those estimates have shifted via hard fork
  today; today the only detection mechanism is the wallet's own
  hardcoded knowledge of which `hf_version` runs which fee policy.

  Why this matters now: the V3 wallet rewrite's Phase 2a builds a
  forward-compatible client (`Option<u32> fee_policy_version`) so that
  a future daemon supplying the field is consumed gracefully without a
  client-side change — but the daemon side, where the field is
  _missing_, is the actual gap.

  Scope of the daemon work:
  1. Decide whether `fee_policy_version` rides on `get_fee_estimate`
     (most natural — same response, scoped to the same query) or on
     `get_info` (broader — every wallet queries `get_info` at startup,
     so the field becomes self-advertising for clients that never
     request fees explicitly). The audit recommends the former; the
     decision is daemon-team's.
  2. Define the version-numbering scheme: monotonic `u32` keyed off
     `hf_version` (so V3.0 = 1, V3.1 fee-rule shift = 2, …) is the
     simplest stable shape. Document the canonical mapping in a
     daemon-side `docs/FEE_POLICY_VERSIONS.md` so client-side hardcoded
     knowledge stays auditable.
  3. Wire the field into the existing `get_fee_estimate` /
     `get_info` epee-RPC response handlers; no consensus rule change
     and no breaking RPC change is required (the field is additive).
  4. Land before any V3.x hard fork that touches fee rules — the
     entire point of the field is to give the wallet observability
     across the fork boundary.

  This is **not a Phase 0 blocker** for the wallet rewrite. The
  rewrite ships against the existing daemon surface; the wallet
  consumes the field if/when the daemon supplies it. **Target: V3.1
  daemon release. Cross-link: PR 0.3 audit
  ([`docs/SHEKYLD_PREREQUISITES.md`](SHEKYLD_PREREQUISITES.md) §3),
  V3 wallet decision log entry "shekyld fee policy version absence"
  ([`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md),
  2026-04-25).**

- **`ActivityMetric` producer actor (wallet-side coherent bundle).** Surfaced by
  Stage 1 PR 7 segment **2i** G4 disposition
  ([`docs/design/STAGE_1_PR_7_ECONOMICS_ENGINE.md`](design/STAGE_1_PR_7_ECONOMICS_ENGINE.md)
  §6.3). `ActivityMetric` is a validated four-field bundle (`tx_volume`,
  `circulating_supply`, `total_staked`, `as_of_height`); all four must reflect
  one chain state at `as_of_height`. `EconomicsEngine` trusts the bundle by type;
  **production construction** belongs to a wallet actor with atomic-read capability
  over its upstream (local LMDB mirror: one read transaction; daemon RPC: see
  conditional entry below). Responsibility: read upstream atomically, call
  `ActivityMetric::new`, pass to `burn_amount` / display paths. Natural owner:
  post–Rust-cutover chain-state mirroring actor (descendant of M3a refresh/mirror
  work). **Trigger:** Stage 4 actor mesh design (post-V3.0). **Target: V3.1+**
  actor-mesh PR. Cross-link: PR 7 C1 (`ActivityMetric::new`), §5.5 R6 (no V3.0
  consumer).

- **Daemon atomic activity snapshot RPC (conditional on RPC upstream).** Same G4
  substrate. If the wallet's `ActivityMetric` producer reads from **daemon RPC**
  rather than a local LMDB mirror, the daemon must expose a **single** endpoint
  that returns all four fields from **one** LMDB read transaction on its side
  (e.g. `get_activity_at_height(h)` or equivalent). Three sequential RPCs
  (`get_tx_volume`, `get_info` fields, stake query, …) are **not** equivalent —
  the daemon can advance between calls and produce an inconsistent snapshot that
  passes `ActivityMetric::new` invariants but not consensus. If the producer's
  upstream is exclusively a local mirror, this entry is **moot**. **Target: V3.1**
  daemon release when V3.0 wallet runs against `shekyld` without a mirror.
  Cross-link: [`docs/WALLET_RPC_RUST.md`](WALLET_RPC_RUST.md) / daemon RPC rust
  cutover docs when scoped.

- **Workspace clippy `-D warnings` cleanup.** Surfaced by the Phase 0
  comprehensive audit (2026-04-25). The Rust workspace is **not**
  `cargo clippy --workspace --all-targets --no-deps -- -D warnings`
  clean, and CI does not currently enforce that gate. `shekyl-ffi`
  carries roughly a dozen pre-existing warnings (bool-to-u8 casts,
  `clippy::too_many_arguments`, unnecessary closures, etc.) inherited
  from its FFI shape; none are introduced by Phase 0. The
  `chore/phase0-audit-cleanup` PR fixes one isolated
  `clippy::needless_return` in `rust/shekyl-wallet-file/src/handle.rs`
  for readability but explicitly does not chase the rest, since each
  `shekyl-ffi` warning is its own scoped decision (silence with
  `#[allow]` and a comment, restructure the FFI signature, or accept
  the lint). Scope of the work: a dedicated pass that either makes
  the workspace `-D warnings` clean or documents per-crate exemptions
  with rationale, then turns on the CI gate so future drift is
  caught at PR time. **Target: V3.1.x (after the wallet rewrite
  stabilizes; doing it earlier conflicts with the rewrite's own
  churn).**

  *2026-05-01 update (Stage 0 PR-2 commit 2):* Stage 0 PR-2's bench
  work observed approximately 30 additional clippy sites in
  `rust/shekyl-engine-core/src/engine/refresh.rs` — primarily
  `clippy::clone_on_copy` on `RefreshProgress` and
  `clippy::let_underscore_must_use` on `tokio::sync::watch::Sender::send`
  / oneshot `Sender::send` results. These accumulated through the
  refresh-driver work after the 2026-04-25 audit and are correctly
  scoped out of Stage 0 PR-2 per `15-deletion-and-debt.mdc`. The
  observation validates this item's "earlier conflicts with the
  rewrite's own churn" reasoning in real time: each Stage 1 per-trait
  PR will continue producing similar drift in the engine subsystem,
  and the V3.1.x cleanup PR is the right place to absorb it all at
  once. The future cleanup PR drafter should re-run the workspace
  clippy command above to get the current full list rather than
  treating either the 2026-04-25 or 2026-05-01 enumerations as
  exhaustive.

- **`monero-oxide` un-pin / fork-and-attribute / drop-unused-crates
  (Operation B).** The vendor work splits into two distinct
  operations with different risk/value profiles, and the rewrite
  plan deliberately keeps them separate.
  - **Operation A — vendor-bump to fork tip.** Sync vendored
    `rust/shekyl-oxide/` from `87acb57` to
    `Shekyl-Foundation/monero-oxide` `fcmp++` HEAD `3933664`. Five
    commits, none crypto-substantive except `182b648`'s base58
    decoder hardening. **Mechanical, cheap, unblocked.** Scoped
    into Phase 0 of the wallet rewrite plan as **PR 0.6** —
    *not* this follow-up. The audit produces the operation; the
    plan executes it.
  - **Operation B — un-pin / fork-rebase against upstream.** The
    actual un-pin work this entry describes: pick up the 40
    upstream commits since the 2025-11-22 merge base
    (cypherstack `cba7117`, Veridise `HelioseleneField::invert`
    cluster `00bafcf`/`af44fb4`/`f58f2a9`/`e5d533c`, missing
    `ConditionallySelectable` bound `0d6f5e8`, WCG library
    invariant fix `1ac294e`, the upstream restructure that split
    `rpc` into `interface`+`/daemon` and moved `fcmp++` into
    `ringct/`); decide which crates are forked under
    Shekyl-Foundation attribution, which are upstreamed back to
    `kayabaNerve/monero-oxide`, which are dropped from the
    workspace. The `00bafcf` field-inversion bug is **active in
    the vendored code** (Operation A doesn't fix it — only
    Operation B does), but the bug exists today on `dev` and
    would continue to exist if this plan didn't touch it; folding
    a 40-commit upstream merge across an architectural restructure
    into Phase 0 of the wallet rewrite breaks the "single coherent
    thing per phase" principle. The wallet rewrite's Phase 1 API
    shape is determined by what the wallet stack does, not by which
    version of `HelioseleneField::invert` is correct (the bug fix
    is below the wallet stack's API surface — confirmed during the
    rewrite plan's half-day review gate, item 5). Operation B runs
    in parallel with rewrite Phases 1–3 if bandwidth allows; not
    sequentially blocking. **Target: V3.1.x (after the wallet
    rewrite stabilizes; lattice-only V4 transition may force
    re-evaluation regardless). Cross-links: PR 0.4 audit
    [`docs/MONERO_OXIDE_VENDOR_STATUS.md`](MONERO_OXIDE_VENDOR_STATUS.md);
    PR 0.6 vendor-bump in the rewrite plan
    [`.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md`](../.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md).**

- **`shekyl_difficulty_lwma1_next` FFI shim allocates `Vec<u128>` per
  call.** Surfaced 2026-05-18 (Phase 2 PR
  [#52](https://github.com/Shekyl-Foundation/shekyl-core/pull/52),
  Copilot review). The shim widens the C-ABI `[ShekylU128]` input
  into a `Vec<u128>` (length `N + 1 == 91`) before invoking
  [`shekyl_difficulty::lwma1_next`](../rust/shekyl-difficulty/src/lwma1.rs).
  Reinterpret-casting `&[ShekylU128]` (`#[repr(C)]`, two-`u64`
  layout, align 8) to `&[u128]` (align 16) violates Rust's slice
  alignment invariant; the materialized copy is unavoidable under
  the Round 5 ABI choice
  ([`docs/design/DAA_LWMA1.md`](design/DAA_LWMA1.md) §6.1).

  **Performance impact.** ~1.5 KiB per call (`91 × 16` bytes),
  satisfied from the system allocator's small-object freelist.
  Phase 4 (the C++ daemon cutover) calls this once per block
  validation; at the production block target (`T = 120s`) the
  allocation is amortized to negligible relative to the algorithm's
  own 90-iteration weighted-sum loop.

  **Dispositions worth comparing at the V3.1+ pass:**

  1. Promote `shekyl_difficulty::lwma1_next` to accept a stack-
     buffer iterator (e.g., a `&dyn ExactSizeIterator<Item = u128>`
     or a const-generic-bounded `[u128; N_PLUS_ONE]`). Eliminates
     allocation; couples the algorithm crate to the window-size
     constant in a non-`#![no_std]`-friendly way.
  2. Use `heapless::Vec<u128, 91>` in the FFI shim. Eliminates
     allocation without changing the algorithm signature; adds a
     `heapless` workspace dep and a stack frame of ~1.5 KiB at the
     FFI entry.
  3. Bypass the widening entirely by adding a parallel
     `lwma1_next_decomposed(&[u64], &[(u64, u64)])` entry that
     reads the two-u64 halves directly. Eliminates allocation and
     keeps the algorithm crate `#![no_std]`; doubles the algorithm
     crate's public surface.

  **Target: V3.1** (post-genesis perf work). Closure point is the
  V3.1 difficulty/perf pass that benchmarks LWMA-1's per-block
  cost end-to-end on the production daemon path; the disposition
  is chosen by data, not by a-priori preference. Until then, the
  per-call allocation is documented at the FFI surface
  ([`rust/shekyl-ffi/src/difficulty_ffi.rs`](../rust/shekyl-ffi/src/difficulty_ffi.rs)
  module docs § "Performance / allocation") so callers and
  reviewers see the cost explicitly. **This is not a correctness
  bug** — the algorithm result is byte-identical to the
  zero-allocation alternative; only throughput changes.

- **C++ bridge `lwma1_next_difficulty` helper allocates two heap
  buffers per call.** Surfaced 2026-05-18 (LWMA-1 Phase 4 PR #53,
  Copilot review C-11). The template helper in
  [`src/cryptonote_core/blockchain.cpp`](../src/cryptonote_core/blockchain.cpp)
  (anonymous namespace, around line 124) allocates two
  `std::vector` buffers (`std::vector<shekyl_u128> cum_u128` and
  `std::vector<uint64_t> ts_vec`) per call to widen the
  cumulative-difficulty entries from `boost::multiprecision::uint128_t`
  to the FFI's `shekyl_u128` and to copy timestamps to contiguous
  storage (necessary because the cached call sites pass `std::deque`).
  Each buffer is ~1.5 KiB at `N = 90` (91 entries × 16 bytes).
  Called once per `get_difficulty_for_next_block`, once per alt-chain
  validation, and `N + 1` times per full-chain recalculation in
  `recalculate_difficulties`. Companion to the Rust-side
  `Vec<u128>` allocation tracked in the entry above; both fall in
  the same V3.1+ perf scope.

  **Dispositions worth comparing at the V3.1+ pass:**

  1. Promote both buffers to `thread_local static` and `clear()`
     between calls. Costs nothing in code complexity; eliminates
     allocation churn but holds the worst-case footprint per
     thread. The bridge is called from a single Blockchain lock
     so thread-local cost is bounded by the validator thread
     count.
  2. Make the bridge accept an out-buffer reference (callers own
     the buffer; bridge clears + reuses). Zero per-call allocation
     and zero global state; adds a parameter to each call site.
  3. Combine with the Rust-side `Vec<u128>` follow-up above: a
     stack-buffer iterator at the FFI surface would eliminate
     both allocations together at the cost of coupling the
     algorithm crate to the window-size constant.

  **Target: V3.1** (same pass as the entries above). Closure point
  is the V3.1 difficulty/perf pass that benchmarks end-to-end
  per-block cost; the disposition is chosen by data. **Not a
  correctness bug** — algorithm result is byte-identical to the
  zero-allocation alternative.

- **CLOSED (2026-05-18 — landed in same PR #53): `Blockchain`
  LWMA-1 cache `vector` → `deque` migration.** Surfaced 2026-05-18
  (LWMA-1 Phase 4 PR #53, Copilot review C-1); my initial
  disposition was to defer per `15-deletion-and-debt.mdc`'s
  "while we're here is the enemy" rule. The user landed the
  disposition in-PR as commit `308385c26` ("perf: use std::deque
  for LWMA-1 window caches for O(1) pop_front") plus the
  follow-on `29edd517d` ("perf: add ts_vec.reserve before assign
  in lwma1_next_difficulty"). Both `m_timestamps` /
  `m_difficulties` cache members in
  [`src/cryptonote_core/blockchain.cpp`](../src/cryptonote_core/blockchain.cpp)
  are now `std::deque`; the corresponding `erase(begin())` while-
  loops are replaced with `pop_front()`. The `lwma1_next_difficulty`
  helper became a template accepting either `std::vector` (alt-
  chain path) or `std::deque` (cached paths). The cache roll-
  forward is now O(1) per block as the access pattern intended.
  Closure record retained for traceability; no V3.x work remains
  for this item.

- **Binary-level `nm`-on-`shekyld` symbol-isolation invariant for the
  deleted CryptoNote DAA functions.** Surfaced 2026-05-18 (LWMA-1
  Phase 4 PR, Commit 10 design discussion). The current
  consensus-invariants CI gate
  ([`.github/workflows/consensus-invariants.yml`](../.github/workflows/consensus-invariants.yml)
  +
  [`scripts/ci/check_consensus_invariants.sh`](../scripts/ci/check_consensus_invariants.sh))
  invariant 1 is a **source-level** grep: it verifies there are no
  live `next_difficulty` or `next_difficulty_64` call sites in
  `src/**`. This is a necessary precondition for binary absence but
  is not the strongest available statement of the invariant: the
  load-bearing property the threat model wants is that *the linked
  daemon binary* doesn't contain a reachable
  `cryptonote::next_difficulty(...)` symbol from which a future code
  path could resurrect the deleted DAA.

  **Disposition.** Add a binary-level CI step to the existing
  workflow once CI infrastructure exposes a linked `shekyld` to a
  post-link grep:

  ```bash
  if nm shekyld | rg -q '^.* (T|U) (next_difficulty_64|next_difficulty)\b'; then
    echo "ERROR: linked daemon contains deleted DAA symbol"
    exit 1
  fi
  ```

  The check fails on either a defined (`T`) or referenced (`U`)
  symbol matching the deleted DAA family. `nm` is preferred over
  `readelf -s` for cross-toolchain portability (works on the
  upcoming MSVC Windows build via `llvm-nm` and on macOS via
  Apple's `nm`).

  **Why not now.** The PR's reviewer-attention budget is loaded with
  the consensus-rule changes (FTL/MTP/DAA); the source-level
  invariant catches the same defection class with zero binary
  artifact wrangling. The binary-level enhancement is value-add but
  not load-bearing; deferred to a V3.x CI-hygiene pass.

  **Target: V3.x** (CI hygiene). Closes when the
  consensus-invariants workflow is extended with a post-build job
  that links `shekyld` for the host triple and runs the `nm` check
  above. The same job is the natural landing site for the upcoming
  RandomX v2 Phase 2f symbol-isolation binary check; sharing the
  job amortizes the link cost and avoids two parallel sub-workflows
  doing similar things. No correctness issue exists today — the
  source-level grep gives strong evidence the binary won't contain
  the symbols, since unreferenced functions in C++ translation
  units that lack `extern "C"` exports are eligible for dead-code
  elimination.

- **RandomX v2 `ExternalProject_Add`: per-`CONFIG` install path and
  `IMPORTED_LOCATION_<CONFIG>` for multi-config generators.**
  Surfaced 2026-05-18 (RandomX v2 Phase 1 PR #54, Copilot review
  findings C-1 (commit-3) and C-6 (commit-4)). The Phase 1 wiring
  in [`external/CMakeLists.txt`](../external/CMakeLists.txt) uses
  a single, config-agnostic install path
  (`${CMAKE_BINARY_DIR}/external/randomx-v2-install/`) and a
  single `IMPORTED_LOCATION` on the `shekyl_randomx_v2` target.
  On single-config generators (Ninja, Make — the production
  Shekyl build pipeline including Guix) this is correct by
  construction. On multi-config generators (MSVC's "Visual Studio"
  generator, Xcode, "Ninja Multi-Config"), building Debug and
  Release in the same build tree would have the second install
  step overwrite the first, and `IMPORTED_LOCATION` would resolve
  to whichever was built last regardless of which configuration
  the consumer is linking from. The phrase "correct by
  construction" holds today only because no Shekyl C++ component
  links `shekyl_randomx_v2` in Phase 1 — the multi-config
  collision is latent until the first consumer lands.
  
  **Phase 1 disposition (fail-fast).** As of PR #54 commit 4,
  `external/CMakeLists.txt` refuses with `FATAL_ERROR` when
  `BUILD_RANDOMX_V2_MINER_LIB=ON` is combined with a multi-config
  generator (`CMAKE_CONFIGURATION_TYPES` non-empty), and names
  this FOLLOWUPS entry in the error message. The escalation from
  a STATUS warning (the commit-3 disposition) to a fail-fast
  refusal (the commit-4 disposition) is `00-mission.mdc`
  priority 1: silently producing wrong-configuration artifacts is
  a correctness defect even without a current consumer, and the
  right place to enforce a correctness precondition is at the
  entry point (CMake configure) rather than the exit point (when
  the latent bug eventually manifests). Developers who want to
  exercise the v2 build on Windows in Phase 1 use `-G Ninja` with
  an explicit `-DCMAKE_BUILD_TYPE`; the `FATAL_ERROR` message
  names this path.
  
  **Phase 2 disposition (per-`CONFIG`).** Replace the
  `FATAL_ERROR` with the per-`CONFIG` split alongside the first
  real consumer (`rust/shekyl-pow-randomx/` cross-check tests
  against the canonical v2 implementation, per
  [`docs/design/RANDOMX_V2_PHASE1_PLAN.md`](design/RANDOMX_V2_PHASE1_PLAN.md)
  §6.3). The minimal correct shape is:
  
  - Make `RANDOMX_V2_INSTALL` include `$<CONFIG>` (or, since
    `ExternalProject_Add`'s `INSTALL_DIR` does not expand
    generator expressions, switch to a per-config sub-build by
    detecting `CMAKE_CONFIGURATION_TYPES` and emitting one
    `ExternalProject_Add` per listed configuration).
  - Set `IMPORTED_LOCATION_<CONFIG>` (and
    `IMPORTED_LOCATION_DEBUG` / `_RELEASE` / `_RELWITHDEBINFO` /
    `_MINSIZEREL` as needed) on `shekyl_randomx_v2` instead of
    the single `IMPORTED_LOCATION`.
  - Drop the Phase 1 `FATAL_ERROR` guard.
  - Update the Phase 2 build-smoke procedure to exercise the
    Debug + Release dual-config path on MSVC and Xcode
    generators.
  
  **Why not now.** Phase 1's scope envelope is ≤250 lines, ≤5
  commits, and explicitly forbids "while we're here"
  architectural expansions (`RANDOMX_V2_PHASE1_PLAN.md` §9).
  Adding per-`CONFIG` handling now without a consumer would be
  speculative scaffolding (the kind `25-rust-architecture.mdc`
  rejects) — the correct per-`CONFIG` shape depends on what shape
  the consumer wants (single-config Rust harness vs. multi-config
  MSVC daemon), and Phase 1 commits to neither.
  
  **Target: V3.x — RandomX v2 Phase 2** (`docs/design/RANDOMX_V2_PLAN.md`
  Track A Phase 2). Closes when `rust/shekyl-pow-randomx/`'s
  cross-check tests build cleanly under MSVC's multi-config
  generator with both Debug and Release in the same build tree
  AND the Phase 1 `FATAL_ERROR` guard has been removed.

---

## V3.2 — Rust cutover and cleanup

- **`atomic_write_file` power-loss crash-injection tests.** PR 6 cites
  existing unit tests in `shekyl-engine-file/src/atomic.rs` (overwrite
  semantics, no stray temps) but not simulated crash mid-fsync. If audit
  requires stronger durability evidence than unit tests, add fault-injection
  tests (e.g. kill between tmp write and rename) in `shekyl-engine-file`.
  **Target:** V3.2. **Reopen when:** external audit names power-loss simulation
  as a release gate.

- **Wallet on network filesystems (NFS / SMB).** Advisory lock + atomic
  rename semantics are validated for local POSIX filesystems only. PR 6
  segment 2i (G5) records that multi-client network mounts can break
  single-writer assumptions. **Work:** document "local disk only" in user-
  facing wallet docs; evaluate `flock` vs `fcntl` posture if remote home
  directories are a deployment target. **Target:** V3.2. **Reopen when:**
  a supported deployment explicitly requires network-backed wallet paths.

- **Wallet file metadata obfuscation (PR 6 §5.12 F5–F6).** File size and mtime
  leak wallet presence and activity without decryption. **Work:** pad `.wallet`
  to fixed size classes; optional mtime scheduling independent of saves; fresh-
  wallet fingerprint mitigation. **Target:** V3.x. **Reopen when:** threat
  model review names local filesystem observer as in-scope.

- **`WalletFile` handle slimming (post–PR 6 `PersistenceEngine`).**
  `shekyl-engine-file::WalletFile` retains `keys_file_bytes`, opened
  `file_kek`, and other material beyond what steady-state
  `PersistenceEngine` methods need. Memory disclosure of the **whole
  handle** is a strictly larger blast radius than orchestrator-held
  `StateWrapKey` / `PrefsHmacKey` alone (see
  `docs/design/STAGE_1_PR_6_PERSISTENCE_ENGINE.md` §5.9; post-HKDF amendment,
  steady-state cache is `wrap_key_region_2`, not `file_kek`).
  **Work:** narrow `WalletFile`'s held state to the minimum the trait
  implementor requires; keep open/rotate paths able to re-derive sealing
  keys without retaining redundant secret-bearing fields across
  steady-state sync. **Target:** V3.2. **Reopen when:** PR 6 lands and
  `PersistenceEngine` call sites are stable enough to measure what the
  implementor actually reads per method.

- **FFI C ABI symbol rename: `shekyl_wallet_*` → `shekyl_engine_*`,
  `ShekylWallet` → `ShekylEngine` (paired with `wallet2.cpp` retirement).**
  The `2026-04-27` Wallet → Engine rename held the FFI C ABI surface
  stable on purpose: the `#[no_mangle]` exports in
  [`shekyl-ffi`](../rust/shekyl-ffi/) and the `ShekylWallet` opaque-handle
  struct remain the contract that the C++ wallet shim and the GUI
  / mobile bindings consume today. Renaming those symbols requires a
  coordinated cut across `shekyl-core`, `shekyl-gui-wallet`, and
  `shekyl-mobile-wallet`, and the cleanest moment to do that cut is
  the same release where the C++ `wallet2.cpp` shim is retired and
  the Rust-native lifecycle owns the FFI surface end-to-end. Doing
  both at once means the symbol churn happens exactly once for
  downstream embedders, not twice. Target: V3.2 (Phase 5 of the
  wallet rewrite plan, where `wallet2.cpp` retirement lands). Cross-
  references: decision log *"Wallet → Engine rename"* (2026-04-27)
  §"Deferred work" entry 1; CHANGELOG `[Unreleased]` BREAKING block.

- **C++ JSON-RPC method-name rename: `wallet_*` → engine-shaped names
  (folded into Phase 4b's Shekyl-native RPC method-set work).** The
  `2026-04-27` Wallet → Engine rename did not touch the C++ JSON-RPC
  method strings (`wallet_get_balance`, `wallet_create_address`,
  `change_wallet_password`, ...). Those strings are the externally
  exposed wire surface today, served by the C++
  `shekyl-wallet-rpc.exe` binary; the Rust `shekyl-engine-rpc`
  forwards anonymously to the C++ binary via `Wallet2::json_rpc_call`.
  Phase 4b of the wallet rewrite plan replaces that binary with a
  Rust-native JSON-RPC server whose method set is redesigned wholesale
  (Shekyl-native JSON shapes, OpenAPI spec) — at which point the
  `wallet_*` method names are *deleted*, not aliased, consistent with
  the locked "no JSON-RPC compatibility aliases" decision. Renaming
  the strings in the V3 mechanical rename PR would have pre-empted
  Phase 4b's redesign call. Target: V3.2 (Phase 4b of the wallet
  rewrite plan). Cross-references: decision log *"Wallet → Engine
  rename"* (2026-04-27) §"Deferred work" entry 2; CHANGELOG
  `[Unreleased]` BREAKING block.

- **Retire `shekyl-engine-rpc::rust-scanner` Cargo feature (Phase 4b).**
  The `rust-scanner` feature on `shekyl-engine-rpc` gates a JSON-RPC-side
  `(LedgerBlock, LedgerIndexes)` cache (`scanner_state::LiveLedger`,
  the `scanner_*` JSON-RPC handlers) that the daemon RPC server reads
  from while the underlying crate is still routed through `wallet2.cpp`
  FFI for mutation. It is a *read-side* cache, distinct from the
  `shekyl-scanner::rust-scanner` feature retired in the Phase 2a
  refresh driver landing — that feature gated the standalone
  `shekyl-scanner::sync::run_sync_loop` driver, which was deleted
  outright once `shekyl-engine-core::Engine::refresh` became the
  single producer of ledger mutations. The two features happen to
  share a name and a `LiveLedger` type alias by historical
  coincidence, but `shekyl-engine-rpc::scanner_state::LiveLedger` is
  a local definition inside that crate and is not affected by the
  Phase 2a deletion.

  When `shekyl-engine-rpc` migrates off `wallet2.cpp` FFI in Phase 4b
  (target: V3.2) the JSON-RPC server reads directly from
  `Engine<S>` rather than from a side-cache, the
  `scanner_state` module is deleted along with its handlers, and the
  `rust-scanner` feature on `shekyl-engine-rpc` retires alongside.
  See `docs/V3_WALLET_DECISION_LOG.md` *"Retire
  `shekyl-scanner::sync::run_sync_loop` (Phase 2a/4b boundary)"*
  (2026-04-27) for the rationale that pins the boundary. Target:
  V3.2 (Phase 4b of the wallet rewrite plan).

- **Chore #4: platform-gate audit sweep — reduced scope after Chore #3 (V4 pre-audit).**
  Chore #3 eliminates the worst offenders (every bit-width
  carve-out). Chore #4 is the residual systematic pass over
  every `#if`, `#ifdef`, CMake `if()`, and Makefile conditional
  that gates on a platform predicate still in force after Chore
  #3 — principally `__APPLE__`, `__ANDROID__`, `_MSC_VER`,
  `__FreeBSD__`, `BSD`, `__linux__`, plus any residual
  host-triple patterns in `contrib/depends/`. Produces a
  coverage report with three columns — site, claimed platform,
  CI-covered y/n — and classifies each row as **delete**
  (platform not actually claimed), **CI add** (claimed and
  about to be tested), or **document-as-unverified** (claimed
  but deliberately unverified, with explicit severity and
  target version in `STRUCTURAL_TODO.md`). Highest-value
  audit-defensibility deliverable before the V4 external
  audit; worth doing once, well. See `STRUCTURAL_TODO.md`
  §"32-bit targets..." for the governing rubric. Target:
  V4 pre-audit.

- **Restore semantic thread labels in the Rust subscriber (V3.2).**
  `MLOG_SET_THREAD_NAME(label)` in
  `contrib/epee/include/misc_log_ex.h` is a `((void)(x))` no-op
  after Chore #2. Call sites (`abstract_tcp_server2.inl` ~L1399 /
  L1459, `miner.cpp` ~L529, `download.cpp` ~L62) still compile and
  still evaluate their argument, but the human-readable label
  (`[SRV_MAIN]` / `[miner 3]` / `DL12`) no longer reaches the log
  stream. easylogging++ used this hook to stamp the label into
  every subsequent emit; `tracing-subscriber`'s `fmt::layer` reads
  the OS-level thread name instead, and the Chore #2 shim is not
  populating those names. Impact is diagnostic (thread-scoped log
  lines show a generic thread ID rather than the semantic role),
  never correctness.

  Two reasonable implementations, to be picked up together:
  - Teach `MLOG_SET_THREAD_NAME(x)` to call the platform thread-
    name API (`pthread_setname_np` on Linux/glibc and musl,
    `pthread_set_name_np` on *BSD, `pthread_setname_np(self, name)`
    on Darwin, `SetThreadDescription` on Windows 10+). The label
    becomes part of the OS process view too, which is the right
    answer for `perf` / `htop` / `Process Explorer` inspection.
  - Route the label through the Rust subscriber as a `tracing`
    `span` field (`tracing::info_span!("worker", name = label)`
    or equivalent), so the subscriber emits it whether or not the
    OS-level thread name made it through. Chore #2 already
    interns per-`(target, level)` callsites in
    `rust/shekyl-logging/src/ffi.rs::shekyl_log_emit`; a
    `shekyl_log_set_thread_name` counterpart would slot in next to
    it.

  Target: V3.2. Cross-linked from the V3.x alpha.0 CHANGELOG
  entry "Known regressions".

- **Stack-trace hook: re-route `ST_LOG` back through the logging subsystem once the FFI boundary is safe mid-throw (V3.2).**
  `src/common/stack_trace.cpp` emits its `[stacktrace]` lines with
  a direct `std::fwrite(..., stderr)` rather than through
  `shekyl_log_emit`. The reason is documented inline: calling
  into Rust's `tracing` subscriber from inside the `__cxa_throw`
  hook — per throw, once up-front plus once per unwound frame —
  exercises subscriber-install ordering, `NonBlocking`
  worker-thread state, and `OnceLock` callsite interning during
  the window when a C++ exception is already half-constructed
  and about to start unwinding. The Ubuntu `unit_tests` subprocess
  abort at CI run `24723150982` (root-caused while fixing the
  `FSCTL_SET_COMPRESSION` regression) was one symptom of that
  hazard class.

  A second, independent hazard surfaced at CI run `24728543538`
  and was *misdiagnosed twice* before the real root cause landed
  in the Debian 13 local repro (run 24728543538 + commit
  `02a02e3c2` successor). The failing test was
  `apply_permutation.bad_size`, which throws `std::runtime_error`
  inside a `try` / `catch`. Symptom: gtest emits "Subprocess
  aborted" and the rest of the suite never runs.

  **Misdiagnosis 1 (commit `a68314e3f`):** I assumed `ST_LOG` was
  re-entering Rust logging during the throw (real hazard, see
  above, but not the crashing path here). I re-routed `ST_LOG`
  through `std::fwrite` and shipped `std::call_once` caching for
  `dlsym`. The `ST_LOG` reroute was independently correct. The
  cache introduced a new, unrelated question (see below).

  **Misdiagnosis 2 (commit `02a02e3c2`):** I then assumed
  `std::call_once` inside `__cxa_throw` was the crash, via the
  C++ ABI's one-shot guard path (`__cxa_guard_acquire` /
  `__cxa_guard_release`) re-entering from inside a throw and
  corrupting libstdc++'s in-flight exception state. Plausible,
  but not the crashing path either. I reverted to per-call
  `dlsym(RTLD_NEXT, "__cxa_throw")`. The revert itself is still
  the right call (see below), just for a different reason than
  I claimed in the commit message.

  **Actual root cause (found locally on Debian 13 with
  `libunwind-dev` installed and `-DSTACK_TRACE=ON`):** a linker
  configuration bug in `cmake/FindLibunwind.cmake` — the module
  unconditionally prepended `gcc_eh` (the static libgcc_eh
  archive) to `LIBUNWIND_LIBRARIES` under GCC. That static
  archive exports the *unversioned* `_Unwind_*` personality-ABI
  surface (`_Unwind_RaiseException_Phase2`,
  `_Unwind_GetLanguageSpecificData`, `__gxx_personality_v0`'s
  dependencies) into the main executable. At runtime, those
  unversioned copies interleave with (a) the *versioned*
  (`@@GCC_3.0`) copies in `libgcc_s.so.1` that `libstdc++.so.6`
  was linked against, and (b) the *namespaced* (`__libunwind_*`)
  wrapper copies in `libunwind.so.8`. The observed crash path:

    our `__cxa_throw` hook
      → real `__cxa_throw` in libstdc++
      → `_Unwind_RaiseException` (resolves to libgcc_eh in our
        binary)
      → `_Unwind_RaiseException_Phase2`
      → `__gxx_personality_v0` (libstdc++.so.6)
      → `_Unwind_GetLanguageSpecificData` (resolves via global
        symbol interposition to libunwind.so.8's
        `__libunwind_Unwind_GetLanguageSpecificData`)
      → SIGSEGV dereferencing an `_Unwind_Context*` whose
        layout was built by libgcc_eh, not libunwind

  Fix: drop the `gcc_eh` prepend from `FindLibunwind.cmake` so
  libstdc++ pulls `libgcc_s.so.1` in on its own and the
  unwinder provider stays singular and version-matched. We still
  link `libunwind.so.8` for the `unw_*` local-backtrace API the
  hook calls via `UNW_LOCAL_ONLY`; libunwind's `_Unwind_*`
  exports are harmless when there's no competing in-binary copy
  to race them.

  **Why we keep the per-throw `dlsym` anyway:** the `std::call_once`
  caching and the function-local `static` pointer alternatives
  are still the wrong shape for this call site, just for a
  defensive reason rather than an observed-crash reason. Both
  expand to `__cxa_guard_acquire` / `__cxa_guard_release` /
  pthread_once-equivalent paths, and re-entering any of that
  from inside a throw is the kind of ABI-private plumbing we
  shouldn't exercise in the pre-throw window even if it doesn't
  crash on today's glibc. Per-call `dlsym` takes libc's internal
  `_dlmopen` lock and nothing else. The cost is negligible
  compared to the libunwind walk that follows it; the explicit
  `abort` + stderr diagnostic on NULL stays (matters under
  `-Wl,--no-export-dynamic` or full libstdc++ static absorption).

  The stderr-direct path is safe, low-noise, and locked in by
  `tests/unit_tests/stack_trace.cpp` (see
  `stack_trace.emits_to_stderr_not_rust_log` for the negative
  assertions against the Rust tracing formatter's markers, and
  `stack_trace.repeated_throws_do_not_crash_and_emit_once_per_throw`
  for the regression guard — a loop of 16 `throw` / `catch`
  cycles that fails fast if *either* the unwinder collision
  returns or the init-machinery hazard above ever becomes a real
  crash rather than a defensive concern). The tradeoff is that
  stack traces no longer
  land in the rolling log file, only on stderr — fine for
  operator-visible crashes, less useful for post-mortem analysis
  of long-running daemons that only write stderr to a log
  managed by the init system.

  The follow-up is to add a dedicated "crash sink" to
  `shekyl-logging` that the hook can write to without going
  through the full `tracing::Dispatcher::event` path (a direct
  append-only writer with no subscribers, no filters, no
  callsite interning), and re-route `ST_LOG` to that sink so
  the file log captures crashes too. Any such sink API must be
  callable from inside `__cxa_throw` without triggering the
  C++ ABI's guard init (so: plain globals + atomics, no
  function-local statics, no `std::call_once`, no lazy
  `OnceLock` in the consumer crate). Target: V3.2.

- **`shekyl-cli` offline signing uses hex blobs on the command line.**
  A future improvement should support QR-code-sized chunked transfer
  for air-gapped signing (e.g. `--qr` flag that splits into scannable
  chunks). Currently, unsigned/signed transaction sets are passed as
  hex strings which can be very long for multi-output transactions.

  **Hex-blob format dies with the wallet rewrite; QR is a UX surface
  on the new typed bundles.** Phase 2d of the wallet rewrite replaces
  the hex blob with `UnsignedTxBundle` / `SignedTxBundle` (typed
  byte-format, single file per stage). QR-chunked transfer becomes a
  serialization channel — `--format=qr-chunks` on `export_unsigned` /
  `submit_signed` — flagged in the Phase 3b deliverables as an
  optional UX add-on. If it lands alongside Phase 3b, this entry
  closes there. If it's deferred for cost reasons, this entry
  re-targets to a post-rewrite UX pass — but with the bundle format
  as the persisted shape, not hex. **Target: V3.2 → Phase 3b of
  wallet rewrite (optional) or post-rewrite UX pass.**

- **`shekyl-cli` key image export uses JSON-RPC format, not C++ binary.**
  ~~The current implementation exports key images via the
  `export_key_images` JSON-RPC method and writes JSON. For byte-identical
  interop with the C++ binary format
  (`"Shekyl key image export\003"` magic + view-key encrypted), add FFI
  functions `wallet2_ffi_export_key_images_to_file` and
  `wallet2_ffi_import_key_images_from_file` that call the underlying C++
  file-based export/import. This preserves interop with hardware-wallet
  and cold-spend workflows built on the binary format.~~

  **Closed by the wallet rewrite, not deferred.** The C++ binary format
  dies with `wallet2.cpp` at Phase 5 of the wallet rewrite plan. The
  air-gapped flow is replaced by `UnsignedTxBundle` / `SignedTxBundle`
  (Phase 2d), which is a Shekyl-native typed shape, not a Monero
  binary-format port. Adding `wallet2_ffi_*` FFI exports for byte-identical
  Monero interop conflicts with [.cursor/rules/60-no-monero-legacy.mdc](
  ../.cursor/rules/60-no-monero-legacy.mdc) — no Monero-shaped APIs because
  they exist upstream. The Phase 5 commit message names this closure in
  its inventory. **Target: closed at Phase 5 of the wallet rewrite.**

- **Test code `wallet_tools.cpp` still uses mixin/decoy infrastructure.**
  The `gen_tx_src` function constructs fake outputs for ring-style
  source entries. This is legacy test infrastructure that works but is
  conceptually dead for Shekyl (no rings).

  **Naturally swept by the wallet rewrite's Phase 5 deletion.**
  `wallet_tools.cpp` is `wallet2`-adjacent test code; it gets deleted
  alongside `tests/unit_tests/wallet*.cpp` at Phase 5 of the wallet
  rewrite plan. The Rust port writes per-crate tests against the typed
  source-entry constructor in `shekyl-tx-builder`, not a `gen_tx_src`
  shim. The Phase 5 commit message names this closure in its inventory.
  **Target: closed at Phase 5 of the wallet rewrite.**

- **`removed_flags` shim sunset.**
  `src/common/removed_flags.{h,cpp}` is a transitional utility
  introduced in V3.1 to give operators a friendly migration message
  when they pass `--detach`, `--pidfile`, or the Windows `--*-service`
  flags that the daemonizer removal retired. The flag list is
  maintained there as a single source of truth — `CHANGELOG.md` entries
  reference the file rather than duplicating the list. The file is
  deleted in V3.2 alongside the `shekyl-wallet-rpc` Rust cutover (which
  removes one of the two call sites); `shekyld`'s call site is deleted
  in the same V3.2 cleanup pass. Greppable as `TODO(v3.2)` in the file
  header.

- **`shekyl-daemon-rpc` staticlib: `tracing::*` calls silently dropped.**
  The Rust `shekyl-daemon-rpc` crate at `rust/shekyl-daemon-rpc` is
  linked into `shekyld` as a staticlib. It emits structured diagnostics
  via `tracing::debug!` / `tracing::error!`, but `shekyld` (C++) never
  installs a `tracing::Subscriber`, so every event from inside the
  staticlib goes to `tracing`'s no-op global dispatcher and is
  discarded. The symptom is invisible: the daemon runs, the RPC surface
  responds, and the absence of diagnostics looks like "nothing
  interesting happened in the Rust code" rather than "nothing was
  recorded." Caught during the stressnet logging-reconciliation sweep
  against shekyl-dev `stressnet/wallet_manager.py`.

  Two reasonable shapes for the fix, pick during V3.2 scoping:
  - Have the daemon's C++ entry point (after `mlog_configure` runs)
    call a `shekyl_daemon_rpc_init_logging` FFI export that either
    installs a `tracing_subscriber` forwarding into `shekyl-logging`
    or, more cheaply, sets `tracing::subscriber::set_global_default`
    to the same `shekyl-logging` subscriber the Rust RPC binaries use.
    The first is cleaner; the second is a two-line change.
  - Or: drop the staticlib's `tracing` calls in favour of
    `shekyl_log_emit` (the existing FFI entry `shekyl-cli` and the
    Rust wallet-rpc already route through), skipping the subscriber
    question entirely. Matches the discipline of the rest of the
    core → shekyl-logging boundary.

  Out of scope for the V3.1 alpha stressnet; the exerciser does not
  read daemon logs for its derivations (state is learned via
  JSON-RPC), so the gap has no effect on the gate result — but any
  operator debugging an unexpected RPC response from `shekyld` today
  will find no Rust-side breadcrumbs to follow.

  **Absorbed into Phase 1 of the wallet rewrite.** Phase 1 ships the
  `tracing` subscriber + per-crate spans for the wallet stack; the
  daemon-side fix (a `shekyl_daemon_rpc_init_logging` FFI export, or
  the equivalent shared-subscriber install path) lands in the same
  deliverable. Solving the subscriber question once for the whole
  codebase is cleaner than solving it for the wallet rewrite and
  re-solving it for the daemon. **Re-target: V3.1 / Phase 1 of wallet
  rewrite (was V3.2). Cross-link: rewrite plan
  [`.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md`](
  ../.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md)
  Phase 1 deliverables.**

- **Re-examine `/FIiso646.h` and `rct::` → `ct::` deferrals.** Both
  deferrals rest on the same "upstream cherry-pick preservation"
  framing that
  [`docs/STRUCTURAL_TODO.md`](./STRUCTURAL_TODO.md)'s framing note
  (top of file) calls largely notional given Shekyl's actual
  divergence from Monero (~3 substantive commits across 8 inherited
  files in the last 2 years; several files 88–100% diverged by line
  count). At V3.2 the question is no longer "cherry-pick risk vs.
  rename cost" but "do these mechanical changes earn their place in
  the V3.2 release on their own merits."

  Two items in scope, evaluated independently against the V3.2 release
  window:

  1. **`/FIiso646.h` MSVC workaround** — hundreds of call sites use
     `not` / `and` / `or` instead of `!` / `&&` / `||`. The workaround
     in `CMAKE_CXX_FLAGS` is the simplest disposition but fragile;
     the audit-discovered alternatives are (a) `/permissive-` for
     full C++ conformance on MSVC, or (b) mechanical replacement
     across the call sites. Disposition rule for V3.2: pick (a), (b),
     or "stay on the workaround" by name; `[[deprecated]] without a
     deletion date is debt that compounds`
     ([`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)),
     so a fourth "defer again to V3.3" disposition is allowed only
     with a written reason that does not reduce to cherry-pick-risk.

  2. **`rct::` → `ct::` namespace rename** — the type-alias bridge
     `using ct_signatures = rct::rctSig;` ships today
     ([`docs/STRUCTURAL_TODO.md`](./STRUCTURAL_TODO.md) §"`rct_signatures`
     field name is a Monero-era misnomer — partially addressed"); the
     full caller migration and the namespace rename in
     `src/fcmp/rctTypes.h` / `rctOps.h` / `rctSigs.h` are currently
     V4-targeted on the same "end of Monero upstream activity"
     premise. Disposition rule for V3.2: confirm or revise the V4
     target. If the framing-note premise holds, the rename is
     orthogonal to V3.2 ship-readiness and can stay V4. If the V3.x
     line accumulates more `rct::` sightings in fresh code, the
     rename's deferral cost is rising and the V4 target should
     compress to V3.x.

  Cross-references (by section header, robust against line drift):
  [`docs/STRUCTURAL_TODO.md`](./STRUCTURAL_TODO.md) framing note (top of
  file; cousin-not-downstream premise),
  §"C++ alternative tokens (`not`, `and`, `or`) used extensively"
  (alternative-tokens decision),
  §"`rct_signatures` field name is a Monero-era misnomer — partially
  addressed" (rct/ct rename status). Exit criteria: each of the two
  items has a written V3.2 disposition (do, defer-with-reason, or
  stay-on-workaround); the STRUCTURAL_TODO citations point at a real
  section header. Target: V3.2.

- **MSVC / Windows build-debt cluster (migrated from
  `STRUCTURAL_TODO.md`, 2026-05-30).** Consolidated here so open debt
  lives in one tracker; `STRUCTURAL_TODO.md` is now a structural-
  reference doc (32-bit security argument, migration-on-touch rubric,
  naming reference), not an open-todo list. Three Windows/MSVC items:

  1. **`libunbound` stubbed on MSVC (V3.2).** `dns_utils.cpp` is wrapped
     in `#ifdef HAVE_DNS_UNBOUND` with no-op stubs in the `#else`
     branch, so wallet DNS resolution (OpenAlias lookup, DNS checkpoint
     fetch) silently does nothing on MSVC/Windows builds. Options:
     (a) port `libunbound` to vcpkg; (b) Windows-native DNS backend
     (`DnsQuery_A` / `DnsQueryEx`); (c) accept the limitation
     (GUI-wallet-first posture; Tor/I2P transports are independent).
     Option (c) is lowest-effort and likely correct, but unratified.
     Whichever wins, the `#else` stubs must declare the contract
     explicitly rather than silently returning empty strings. Target:
     V3.2.

  2. **MSVC warnings in vendored dependencies (V3.2).**
     `liblmdb/mdb.c:1745` (C4172: returning address of local `buf` —
     genuine dangling-pointer bug, debug-only path) is the only one with
     correctness risk and deserves an upstream report + local patch;
     `mdb.c:8417` (C4333), `mdb.c:939,7840` (C4146),
     `randomx/blake2.h:82,84` (C4804) are cosmetic. None are in
     wallet-core hot paths. Target: V3.2 (address the dangling-pointer
     case; cosmetic ones may stay open).

  3. **vcpkg builds take 45+ minutes — partially resolved (V3.3).** Even
     with `actions/cache`, vcpkg install is 45+ min cold / 10–15 min
     warm. A root `vcpkg.json` manifest was attempted (April 2026) but
     broke MSVC CI and was reverted; packages are listed explicitly in
     `.github/workflows/build.yml`. Manifest-mode migration remains
     possible but low priority — CI timing is acceptable with warm
     caches and the explicit YAML list is easier to audit. No action
     unless CI times degrade or the package list grows. Target: V3.3.

---

## V3.x — staker archival and visualization ship

- **`ReorgAmplificationDetector` consumer actor (Stage 1 PR 4 R5
  composition home; supersedes the Round 2 first-pass "extend
  checkpoint 3" deferral).** PR 4's Round 2 reframe of
  [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.7 R5 resolved the reorg-amplification scenario by
  composition under the two-channel error/diagnostic shape:
  the producer emits `RefreshDiagnostic::ReorgObserved`
  events to `DiagnosticSink` whenever `find_fork_point`
  detects a fork during scanning; a `ReorgAmplificationDetector`
  actor consumes those events, maintains a windowed
  reorg-count (per peer once PR 1's `DaemonEngine` peer-aware
  surface lands, per attempt otherwise), and signals
  cancellation back to the orchestrator via the existing
  `CancellationToken` checkpoint-3 plumbing. The producer's
  §7 checkpoint discipline does not grow. **Trigger:** *when
  Stage 4 actor mesh stabilizes.* No telemetry gate; the
  consumer-side implementation is policy-driven, not
  evidence-driven. **Note:** this entry replaces the Round 2
  first-pass deferral "if hostile-daemon work-amplification
  scenarios become measurable… R5 extends checkpoint 3 with
  one tip-poll per checkpoint-3 hit and §7's discipline grows
  accordingly" — the reframe withdraws the extend-checkpoint-3
  path and lands the composition seam in PR 4 instead.
  Cross-references:
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.5 (reorg-amplification adversarial scenario), §5.4.7
  R5 reframe, §5.4.7 R6 reframe (two-channel shape), §5.4.8
  attack-surface enumeration,
  [`engine/refresh.rs:980 / :1140 / :1186`](../rust/shekyl-engine-core/src/engine/refresh.rs)
  (current checkpoint-3 cancel-only sites, preserved
  unchanged).

- **`PeerReputationActor` consumer actor (Stage 1 PR 4 R6
  reframe; intra-session fail2ban-style mitigation).** PR 4's
  Round 2 reframe of
  [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.7 R6 introduced the diagnostic-stream seam; the
  `PeerReputationActor` is the natural fail2ban-style consumer.
  Subscribes to `RefreshDiagnostic`, maintains per-peer event
  history with decay, applies threshold-based graduated
  response (rate-limit → temp-ban → rotate). PR 1's
  `DaemonEngine` peer-rotation contract becomes the *output*
  of this actor rather than the orchestrator's primary
  decision logic. **Hard mitigation pin (§5.4.8 #1):**
  state is **in-memory only**, scoped to the wallet session;
  drop on wallet close. **No persistence beyond the wallet
  session** unless a future review explicitly justifies a
  coarse-grained current-state-only relaxation (e.g.,
  "daemon X banned until time T") on review grounds — V3.x
  default is no persistence. Conflicts with classical
  fail2ban's "remember bad actors across sessions"
  disposition; privacy-first per
  [`00-mission.mdc`](../.cursor/rules/00-mission.mdc) §2
  wins. **Rotation-timing pin (§5.4.8 #3):** jittered
  rotation, batched decisions, decoupled
  event-observation-time from rotation-action-time. **PeerId
  pin (§5.4.8 #2):** depends on PR 1 growing a peer-aware
  `DaemonEngine` surface; `PeerId` must be transport-defined
  opaque tokens with decay calibrated to circuit-rotation
  cadence. **Trigger:** *when Stage 4 actor mesh stabilizes
  and PR 1's peer-aware DaemonEngine surface lands.*
  Cross-references:
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.7 R6 reframe, §5.4.8 attack-surface enumeration
  (1, 2, 3),
  [`ANONYMITY_NETWORKS.md`](ANONYMITY_NETWORKS.md) (peer-
  identity-under-Tor/I2P framing).

- **`RecoveryActor` consumer actor (Stage 1 PR 4 R6 reframe;
  pattern-based recovery / Byzantine-fault-tolerance).** PR 4's
  Round 2 reframe of
  [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.7 R6 also enables pattern-based recovery as a
  consumer-actor pattern. `RecoveryActor` watches for
  sequences like `DaemonMalformed { block_height = H }` from
  peer A → re-request block H from peer B → cross-check
  with peer C → apply if N-of-M agree. Byzantine-fault-tolerance
  recovery driven by the event stream's temporal structure,
  not by single error events. **Mailbox-policy pin (§5.4.8
  #5):** event-sequence-aware drop policy preserves enough
  temporal structure to detect pattern matches; drops
  redundant within-pattern events. **Trigger:** *when Stage 4
  actor mesh stabilizes.* Cross-references:
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.7 R6 reframe, §5.4.8 #5 (mailbox-saturation DoS).

- **`ViewTagAnomalyDetector` consumer actor (Stage 1 PR 4
  reframe; view-tag-DoS composition mitigation).** PR 4's
  Round 2 reframe of
  [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.5 names view-tag DoS (an adversarial daemon crafting
  blocks with high false-positive view-tag rates to force
  trial-decrypt on each output) as an implementation-level
  scenario that the trait surface does not address directly,
  but that admits a composition-side mitigation via the
  diagnostic stream. `ViewTagAnomalyDetector` consumes a
  `RefreshDiagnostic::ViewTagFalsePositive { observed_rate,
  expected_rate }` (or equivalent) event variant, maintains
  per-peer / per-block-batch false-positive-rate windows,
  and signals cancellation when the rate exceeds threshold.
  Same shape as `ReorgAmplificationDetector`'s R5
  resolution.

  **Producer-side dependency (binding on this entry).** The
  variant the detector consumes is **not** in PR 4's Phase
  0e seed variant set — the existing
  [`engine/refresh.rs`](../rust/shekyl-engine-core/src/engine/refresh.rs)
  scan loop does not yet have an observation point that
  measures view-tag false-positive rate against expected.
  Before `ViewTagAnomalyDetector` lands, the producer must
  grow the observation point and emit the new event variant.
  The `RefreshDiagnostic` enum's `#[non_exhaustive]`
  attribute lets the variant land additively without trait-
  surface revision; the work is a producer-side scan-loop
  amendment plus a Phase 0e variant addition. **Trigger:**
  *when Stage 4 actor mesh stabilizes; producer-side
  observation point lands as a coordinated prerequisite.*

  **Mitigation pin (§5.4.8 #1 / #2 / #3).** The detector
  shares the `PeerReputationActor`'s constraints:
  in-memory-only state, coarse-window detection (not
  credit-history-based — see the restart-amnesia note in
  the `PeerReputationActor` entry), aggressive decay
  calibrated to transport-rotation cadence, jittered
  rotation actions. Cross-references:
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.5 (view-tag DoS scenario), §5.4.7 R6 reframe
  (diagnostic-stream contract; non-blocking + coherence
  pins are binding), §5.4.8 #1 (restart-amnesia design
  constraint).

- **Diagnostic-stream specification document
  (`docs/design/DIAGNOSTIC_STREAM.md`, V3.x; renamed in
  PR 5 Round 2 segment 2g — was
  `REFRESH_DIAGNOSTIC_STREAM.md`).** PR 4's Round 2 reframe
  of
  [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.7 R6 defines the `RefreshDiagnostic` / `DiagnosticSink`
  trait contract; PR 5's Round 1 + Round 2 segments 2b–2f
  extend the pattern to `PendingTxDiagnostic` /
  `DiscardReason` / `SubmitError` / `SubmitErrorKind` per
  [`docs/design/STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.0.2 + §5.0.2.1 + §5.0.3. The implementation-side spec
  doc captures the variant taxonomy, consumer-actor design
  space, mailbox-policy templates, the trust-boundary
  discipline (in-process-only for full-fidelity, recursively
  per §5.4.8 #4 — including in-process aggregator-republisher
  actors whose external surface crosses the boundary;
  projection-only across trust boundaries), and the
  emergent-behaviour analysis framework when multiple
  consumers coexist (§5.4.8 "Cross-cutting" note).

  **Segment-2g rename rationale.** The contracts at §5.0.3
  are general properties of any `DiagnosticSink`-shaped seam
  (non-blocking emit, emission/return coherence, recursive
  trust boundary, restart-amnesia detection, producer
  panic-safety, concurrent emit); they apply to PR 4's
  `RefreshDiagnostic` and PR 5's `PendingTxDiagnostic`
  identically. A single `DIAGNOSTIC_STREAM.md` doc with a
  shared-contracts-at-the-top + per-stream-sections
  structure is the lower cross-reference cost shape than a
  parent-and-children factoring. The factoring discipline
  remains available retroactively if growth justifies.

  **Doc structure (V3.x introduction PR).** The doc opens
  with the shared contract bullets from PR 4 §5.4.6 /
  §5.4.7 R6 / §5.4.8 and PR 5 §5.0.3 (a single set; the
  contracts are identical). Per-stream sections follow:
  `RefreshDiagnostic` (PR 4 variant taxonomy + emission-
  site discipline); `PendingTxDiagnostic` + `DiscardReason`
  (PR 5 variant taxonomy + emission-site discipline; R8
  / R9 closure dispositions; segment-2i G1 adds
  `DiscardReason::MempoolEvicted` and `tx_hash`
  projection fields on `SubmitSucceeded` /
  `SubmitPendingResolution`);
  `LedgerDiagnostic` (Phase 0g `SnapshotMerged` variant +
  segment-2i G2 `TxReorgedOut { tx_hash,
  prior_block_height }` forward-template variant — both
  pending the consumer-actor PR per PR 5 segment-2g
  introduction-PR disposition). V3.x consumer-actor PRs
  extend per-stream sections additively as new variants
  land.

  **Segment-2i G2 `LedgerDiagnostic::TxReorgedOut`
  forward-template (Stage 1 PR 5 segment 2i G2
  amendment).** PR 5 segment 2i G2 disposes long-range-
  reorg of confirmed txs as `LedgerDiagnostic`-domain,
  not `PendingTxDiagnostic`-domain (preserving the (γ)
  lean state shape's no-rid-retention-past-terminal
  property; see segment-2i §5.4 R5 scope-extension
  named-and-rejected). The V3.x consumer-actor PR
  introducing `LedgerDiagnostic` adds the
  `TxReorgedOut { tx_hash: TxHash, prior_block_height:
  BlockHeight }` variant alongside `SnapshotMerged`. The
  consumer (typically a wallet-UI tx-history-view
  consumer or the segment-2i G6 `TxConfirmationTrackerActor`)
  subscribes and updates its view; PR 5 segment-2i §5.6.10
  G2 explicitly accepts the V3.0 UX-roughness surface
  (brief "confirmed → unconfirmed → re-confirmed"
  indicator) ahead of the V3.x consumer-actor closing the
  UX gap. **Variant emission disposition.** Emitter is the
  `LedgerEngine` / `RefreshEngine` reorg-detection path
  (out-of-PR-5 scope); the variant lands in the same V3.x
  introduction-PR-deferred enum (`LedgerDiagnostic`) as
  `SnapshotMerged` per Phase 0g; consumer-side
  responsibility per the recursive trust-boundary
  discipline.

  **Load-bearing contract pins (binding on every V3.x
  consumer-actor PR sink implementation).** The spec doc
  records the following as binding constraints, derived
  from PR 4's §5.4.6 / §5.4.7 R6 / §5.4.8 content:

  - **Non-blocking `emit` contract.** `DiagnosticSink::emit`
    MUST NOT block; implementations use `try_send`-shaped
    semantics with silent drop on back-pressure. Rationale:
    a blocked sink pins the producer holding spend material
    across the emission call and defeats the §3.1 wallet-
    lock-latency property by blocking cancellation-token
    observation at checkpoints 2 and 3.
  - **Emission/return coherence contract.** `RefreshEngine`
    implementations MUST emit at least one corresponding
    `RefreshDiagnostic` event for every non-`Cancelled`
    `RefreshError` returned, before returning the error.
    The pin closes the silent-error and phantom-error
    failure modes that the unit-variant trait return
    cannot rule out at the type-system level.
  - **Recursive trust-boundary.** Full-fidelity events flow
    only to actors whose external surface is itself inside
    the wallet trust boundary, recursively. Adding a new
    consumer or extending an existing consumer's external
    surface triggers a per-consumer recursive trust-boundary
    audit at the touching PR's review.
  - **Restart-amnesia is deliberate (consumer-actor design
    constraint).** Detection logic is coarse-window-based,
    not credit-history-based; no "trust accumulation" over
    time. Forecloses adversary evasion via wallet-restart
    cycles. Binding on `PeerReputationActor` and
    `ViewTagAnomalyDetector` design rounds in particular.
  - **Temporal- and distributional-projection disciplines
    (Stage 1 PR 5 segment 2h F5+F6 scope expansion).** Field
    projection (PR 4 §5.4.8 #4's recursive trust boundary)
    bounds *which fields* cross a trust boundary; it does
    not bound *when* events fire or *which variant
    distribution* a longitudinal observer sees. PR 5
    segment 2h pinned the V3.0 prose-level discipline at
    §5.0.3's seventh contract (event coalescing, bucketed
    emission, strategy-aligned emission delay, projection-
    time noise injection on the temporal axis;
    variant-distribution rate-limiting, `DiscardReason`
    aggregation policy, distributional-noise injection on
    the distributional axis). V3.x's first cross-trust-
    boundary consumer-actor PR is the per-consumer
    threat-model trigger; the consumer's projection MUST
    address temporal + distributional axes alongside field
    projection. `DIAGNOSTIC_STREAM.md`'s per-stream
    sections record the per-consumer projection
    disposition. Binding on `ReorgAmplificationDetector`,
    `PeerReputationActor`, `ViewTagAnomalyDetector` (any
    consumer whose external surface admits a longitudinal
    observer).

  **Trigger:** *when the first V3.x consumer actor
  (`ReorgAmplificationDetector`, `PeerReputationActor`,
  `RecoveryActor`, or `ViewTagAnomalyDetector`) enters
  design rounds.* The doc seeds with PR 4's §5.4.6 / §5.4.7
  R6 / §5.4.8 content + PR 5 segment 2h's §5.0.3 seventh
  contract (temporal- and distributional-projection
  discipline) and grows additively as consumers are
  designed. Cross-references:
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.6 (trait-surface contract pins, including the four
  pins recorded above), §5.4.7 R6 reframe (trait contract
  definition), §5.4.8 (attack-surface enumeration with
  mitigation pins);
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.0.3 seventh contract (segment 2h F5+F6
  temporal/distributional projection pin), §5.6.5 F5+F6
  (V3.x reopening criteria), §5.6.7 (V3.x FOLLOWUPS
  scope expansion substrate).

- **`RefreshEngine` (c) split-producer/recoverer view-material
  shape (Stage 1 PR 4 R4 deferral; migration cost reduced by
  PR 5 R11 (b)).** Round 2 of
  [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.7 R4 landed (a-instance-scoped) for V3.0 — the producer
  holds view + spend material in a `ViewMaterial` captured at
  `LocalRefresh::new`. The (c) shape — producer emits view-tag-
  matched candidates; orchestrator does final hybrid-decap and
  key-image computation via `KeyEngine` before
  `apply_scan_result` — is the threat-model-cleanest answer
  (the producer holds **only** view material) but requires
  changing
  [`Scanner`'s output shape](../rust/shekyl-scanner/src/scan.rs)
  to emit candidates rather than recovered outputs and changing
  `ScanResult`'s wire shape to carry that intermediate stage.
  **Trigger:** *if HW-wallet-backed signing or a post-V3
  threat-model refinement requires producer-side spend-key
  isolation*; in that case the (c) migration becomes
  load-bearing and lifts the `Scanner` + `ScanResult` shape
  changes alongside. Until then, the (a-instance-scoped) shape
  is the operative answer; the producer's spend-key holding is
  bounded to `LocalRefresh`'s lifetime and zeroized on drop
  via `Scanner`'s `ZeroizeOnDrop`.

  **Migration cost update (PR 4 Round 3, 2026-05-14).** PR 5
  Round 2 segment 2b landed `LocalSigner` (Stage 1) /
  `SigningActor` (Stage 4) as a sole spend-material holder
  with a narrow `Signer` trait surface (`sign_tx(&self, tx:
  TransactionToSign) -> Result<SignedTransaction,
  SignerError>`), per [`docs/design/STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.4 R11 (closed as (b) — separate-signing-actor from
  Stage 1). The R4 (c) V3.x migration target therefore
  becomes *"`Scanner` stops holding spend material; delegates
  key-image generation via the existing `Signer` trait"*
  rather than designing the spend-key-isolated actor from
  scratch. The migration's V3.x cost shrinks to:
  (i) extending the `Signer` trait surface with a
  `key_image(&self, output: &OutputCandidate) -> KeyImage`
  method (or, more conservatively, exposing key-image
  generation through the existing `sign_tx` shape if the
  signing-actor's API permits); (ii) reshaping `Scanner`'s
  output type to emit `OutputCandidate` rather than
  `RecoveredOutput`; (iii) reshaping `ScanResult` to carry
  the candidate intermediate stage and reshaping the merge
  gate at `Engine::apply_scan_result` to call into the
  `Signer` for the final key-image computation. The
  *architectural* cost was paid in PR 5 R11 (b); V3.x cost
  is the producer-side shape change, not the spend-key-
  isolated actor design. Cross-references:
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §3.1 (master-secret-isolation framing; dual-holder V3.0
  acknowledgment added in Round 3), §5.4.3 R4 (Round 1 review
  pass surfacing), §5.4.7 R4 (Round 2 disposition with
  (c) deferral), §8 (Round 3 R4 (c) cross-reference);
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.4 R11 (segment 2b reframe to (b)), §5.4 R11 cross-
  reference to PR 4 R4 (c) (segment 2b mutual cross-link);
  [`engine/refresh.rs:1254`](../rust/shekyl-engine-core/src/engine/refresh.rs)
  (`build_scanner_from_keys`),
  [`shekyl-scanner/src/scan.rs:506`](../rust/shekyl-scanner/src/scan.rs)
  (`Scanner::new`).

- **`ReservationTTLActor` consumer actor (Stage 1 PR 5 R8
  composition home; reservation TTL / leak prevention; closure
  amended in segments 2e and 2h).** PR 5's Round 1 reframe of
  [`docs/design/STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.4 R8 reframed reservation TTL / leak prevention as a
  composition-side disposition under the §5.0 actor-mesh
  framing; segment 2e (2026-05-14) closed R8 by pinning all
  V3.0 deliverables (including the new
  `DiscardReason::TTLAutoDiscard` variant) so the V3.x
  consumer-actor PR is additive-only — no V3.x trait revision,
  no V3.x enum revision, no V3.x consumer-side breaking change
  per [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)'s
  continuous-discipline corollary. **Segment 2h (2026-05-26)
  amended the closure with (i) the Phase 0l per-collection
  `ReservationTTLConfig { consumer_held: Duration, in_flight:
  Duration }` V3.0 surface (F7 disposition), (ii) the
  `InFlightSubmit { snapshot_id, created_at, submitted_at }`
  field set permitting either age-from-creation or
  age-from-submission V3.x policy (P5 disposition), (iii)
  removal of `DiscardReason::SnapshotRotationAutoDiscard`
  under lazy R5 (V3.x eager-discard opt-in reintroduces it
  per the eager-discard FOLLOWUPS entry below), and (iv) the
  payload-bearing `DiscardReason::DaemonRejectedTerminal {
  kind: TerminalErrorKind }` variant shape replacing the
  segment-2f bare `DaemonRejectedTerminal` variant.**
  `ReservationTTLActor` subscribes to **both
  reservation-creation events and reservation-terminal
  events** on `PendingTxActor`'s diagnostic-stream surface,
  maintains in-memory per-reservation age tracking, emits
  `PendingTxDiagnostic::ReservationOutstanding {
  reservation_id, age }` warnings on stale reservations, and
  signals `PendingTxActor` (via `AutoDiscardMessage {
  reservation_id }` mailbox message) to auto-discard if TTL
  policy permits; `PendingTxActor` then emits `Discarded {
  reason: TTLAutoDiscard }` (the variant added in segment
  2e). Same shape as PR 4's `PeerReputationActor` /
  `RecoveryActor` consumer-actor pattern — the
  `PendingTxEngine` trait surface stays minimal; the
  capability composes.

  **Subscription contract (Copilot-fix follow-up refinement
  to segment-2e closure).** Subscribing only to
  `BuildSucceeded` would leak closed reservations into the
  actor's in-memory map forever, producing stale
  `ReservationOutstanding` warnings on already-terminated
  reservations and spurious `AutoDiscardMessage` round-trips
  to `PendingTxActor`. The complete subscription contract:

  - **`PendingTxDiagnostic::BuildSucceeded { reservation_id,
    snapshot_id, outputs_count }`** — insert
    `{reservation_id → started_at}` into the in-memory
    age-tracking map (tracking-start transition).
  - **`PendingTxDiagnostic::SubmitSucceeded { reservation_id,
    tx_hash }`** — remove `reservation_id` from the
    age-tracking map (terminal — reservation consumed by
    submit).
  - **`PendingTxDiagnostic::Discarded { reservation_id,
    reason }`** — remove `reservation_id` from the
    age-tracking map regardless of `reason`. Under segment 2h
    the surviving `DiscardReason` variants are
    `ConsumerExplicit`, `DaemonRejectedTerminal { kind:
    TerminalErrorKind }` (R9 reshape), and `TTLAutoDiscard`
    (the actor's own auto-discard fires; self-cleanup).
    `SnapshotRotationAutoDiscard` is removed under lazy R5;
    no V3.0 emitter.

  **What `SubmitPendingResolution` does *not* close (segment
  2h reshape).** Per the segment-2h collection-moves table,
  `SubmitPendingResolution { reservation_id, kind:
  AmbiguousErrorKind }` is emitted on daemon timeout /
  unavailable where the reservation stays in the actor's
  `in_flight` collection (Finding-2 daemon-side authority
  disposition). The TTL actor **does not** remove the
  reservation on `SubmitPendingResolution`; terminal cleanup
  is only `SubmitSucceeded` or `Discarded` per the contract
  above. **Per-collection TTL pin (segment 2h F7
  disposition).** The V3.0 surface is the Phase 0l
  `ReservationTTLConfig { consumer_held: Duration, in_flight:
  Duration }` constructor parameter on `LocalPendingTx`.
  V3.x's `ReservationTTLActor` reads the config and applies
  per-collection aging policy (age-from-`created_at` or
  age-from-`submitted_at` for `in_flight`) without trait or
  enum revision.

  **Memory-bound property.** With the full subscription
  contract above, the actor's age-tracking map is bounded
  by the count of currently-outstanding reservations
  (i.e., `PendingTxActor::outstanding()`'s return value),
  not by the cumulative count of all reservations the
  wallet has ever created.

  **Phase 1 landed (2026-05-27).** V3.0 substrate items (1)–(5)
  below shipped on `feat/stage-1-pr5-pending-tx-engine` (C5β =
  `a137cc234` through C7 = `ca7622558`). This FOLLOWUPS entry
  remains open for the V3.x **consumer actor** (`ReservationTTLActor`);
  trigger unchanged: Stage 4 actor mesh stabilizes.

  **V3.0 deliverables (pinned at segment-2e closure; updated
  under segment 2h).** PR 5 shipped: (1)
  `PendingTxDiagnostic::BuildSucceeded` emitted at the
  `build`-success path in `LocalPendingTx::build` /
  `PendingTxActor::handle_build` (Phase 1 call-site review
  confirms); (2) `PendingTxDiagnostic::SubmitSnapshotInvalidated`
  emitted at `submit`'s snapshot-mismatch path with rich
  `(reservation_snapshot, current_snapshot)` context (R5's
  lazy disposition under segment 2h; the prior
  `Discarded { SnapshotRotationAutoDiscard }` emission at
  this site is dropped under segment 2h, since lazy R5
  requires consumer-explicit `discard(rid, ConsumerExplicit)`
  to release `output_locks`); (3)
  `PendingTxDiagnostic::ReservationOutstanding` variant
  exists in the `#[non_exhaustive]` enum (no V3.0 emitter;
  V3.x `ReservationTTLActor` is the first emitter); (4)
  `DiscardReason::TTLAutoDiscard` variant in the
  `#[non_exhaustive] DiscardReason` set so V3.x's
  `ReservationTTLActor` can trigger `Discarded { reason:
  TTLAutoDiscard }` without a V3.x enum revision; (5)
  **new in segment 2h:** Phase 0l `ReservationTTLConfig {
  consumer_held: Duration, in_flight: Duration }` constructor
  parameter; `InFlightSubmit { snapshot_id, created_at,
  submitted_at }` field set; `DiscardReason::DaemonRejectedTerminal
  { kind: TerminalErrorKind }` payload-bearing variant
  shape; `PendingTxDiagnostic::SubmitPendingResolution {
  reservation_id, kind: AmbiguousErrorKind }` ambiguous-
  outcome diagnostic; `DiscardReason::SnapshotRotationAutoDiscard`
  removed under lazy R5 (V3.x eager-discard opt-in
  reintroduces it).

  **R5 ↔ R8 coherence (segment 2e verification; segment 2h
  refinement).** R5's lazy disposition emits
  `SubmitError::SnapshotInvalidated` + the
  `SubmitSnapshotInvalidated` diagnostic; the consumer's
  follow-up `discard(rid, ConsumerExplicit)` emits
  `Discarded { ConsumerExplicit }` and releases the
  reservation's `output_locks`. R8's `TTLAutoDiscard` is
  the proactive complement (per-collection age-based policy
  via the Phase 0l `ReservationTTLConfig`). Both paths
  share the `DiscardReason`/`Discarded` event infrastructure;
  downstream consumers see a unified `Discarded` event
  stream with discriminated reasons.

  **Hard mitigation pins (binding on this entry).**
  - **Restart-amnesia per PR 4 §5.4.8 #1 (binding on PR 5 too).**
    State is **in-memory only**, scoped to the wallet session;
    drop on wallet close. No persistence beyond the wallet
    session. Privacy-first per
    [`00-mission.mdc`](../.cursor/rules/00-mission.mdc) §2.
  - **Recursive trust boundary per PR 4 §5.4.8 #4 (binding on
    PR 5 too).** Full-fidelity events flow only to actors whose
    external surface is itself within the wallet trust boundary,
    recursively. `ReservationTTLActor`'s warnings are
    operational-state events about reservation age — they
    must not flow to off-host loggers, telemetry, or debug UIs
    with IPC channels without first projecting away
    `reservation_id` / `snapshot_id` correlation surface.
  - **Bounded mailbox per PR 4 §5.4.8 #5.** A consumer with a
    per-reservation-age tracking surface unbounded against a
    reservation-spam scenario (consumer with a build/discard
    bug spawning reservations at high rate) is itself an OOM
    surface. Drop-oldest-on-overflow policy with aggregate
    age-band counts preserves the warning function at scale.

  **Round 2 disposition for PR 5 (trait-side dependency).**
  Confirm that `PendingTxDiagnostic::BuildSucceeded` /
  `ReservationOutstanding` / `SubmitSnapshotInvalidated` /
  `SubmitPendingResolution` / `Discarded` events are emitted
  from the right call sites; the variant set in PR 5 §5.0.2
  is `#[non_exhaustive]` so future variants land additively
  without trait revision.

  **Trigger:** *when Stage 4 actor mesh stabilizes.*
  Cross-references:
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.0 (actor-mesh framing), §5.0.2 (`PendingTxDiagnostic`
  variant set), §5.0.3 (cross-cutting `DiagnosticSink`
  contracts), §5.4 R8 (reframed disposition);
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.6 / §5.4.7 R6 reframe / §5.4.8 (the cross-cutting
  contracts inherited verbatim).

- **`SubmitFailureAnalyzer` consumer actor (Stage 1 PR 5 R9
  composition; pattern detection on submit failures).** PR 5's
  Round 1 reframe of
  [`docs/design/STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.4 R9 named the daemon-side submit-failure path and the
  per-error-class disposition; the analyzer is the
  composition-side counterpart that detects patterns across
  failures rather than reacting to single events.

  **Segment-2f closure status (2026-05-14).** R9 closed in
  Round 2 segment 2f with two-stage submit flow + internal
  `ReservationState` machine + daemon-side authority
  disposition for Finding 2 ambiguous outcomes.

  **Phase 1 landed (2026-05-27).** V3.0 diagnostic substrate and
  per-error-class disposition table shipped on
  `feat/stage-1-pr5-pending-tx-engine` (C7 = `ca7622558` property-
  test coverage). This entry remains open for the V3.x
  **`SubmitFailureAnalyzer` consumer actor**; trigger unchanged:
  Stage 4 actor mesh stabilizes.

  **Segment-2h reconciliation (2026-05-27; supersedes the
  segment-2f variant-set narrative above).** Segment 2h's
  (γ) lean three-collection state shape (`output_locks` +
  `consumer_held` + `in_flight`) dissolved the internal
  `ReservationState` enum into collection membership, and
  segment 2h's `SubmitErrorKind` reshape split the unified
  enum into **terminal** vs. **ambiguous** kinds with
  diagnostic-variant-level reflection of the split:

  - `SubmitErrorKind` → `TerminalErrorKind { DoubleSpend |
    FeeTooLow | Malformed }` (lifecycle-gone) + `AmbiguousErrorKind
    { DaemonTimeout | DaemonUnavailable }` (lifecycle-in-flight).
  - `PendingTxDiagnostic::SubmitFailed` **removed** — the
    variant had no surviving emission site under the P4
    collection-moves table. Terminal failures emit
    `PendingTxDiagnostic::Discarded { rid,
    DaemonRejectedTerminal { kind: TerminalErrorKind } }`;
    ambiguous failures emit
    `PendingTxDiagnostic::SubmitPendingResolution { rid,
    kind: AmbiguousErrorKind }`.
  - `ReservationState::SubmitPendingDaemonAck` (the
    segment-2f state-machine state) → `in_flight` collection
    membership. F2 ownership-boundary: consumer-initiated
    `discard` on an `in_flight` reservation returns
    `PendingTxError::DiscardBlockedPendingDaemonAck`.

  `SubmitFailureAnalyzer` subscribes to the **post-segment-2h**
  variant set:
  `PendingTxDiagnostic::Discarded { reason:
  DaemonRejectedTerminal { kind } }`,
  `PendingTxDiagnostic::SubmitPendingResolution { kind }`,
  `PendingTxDiagnostic::SubmitSnapshotInvalidated`. Pattern
  detection re-anchored to the new variant shape:

  - **Many `SubmitSnapshotInvalidated` in a row** →
    adversarial reorg-churn signal; surfaces to
    `PeerReputationActor` (via cross-actor signal or shared
    event consumption) for rotation-policy input.
  - **Recurring
    `Discarded { reason: DaemonRejectedTerminal { kind:
    TerminalErrorKind::FeeTooLow } }`** → fee estimator
    drift signal; surfaces to a fee-estimator actor (when
    one exists) or to user-facing UI as a fee-update
    suggestion.
  - **Recurring
    `Discarded { reason: DaemonRejectedTerminal { kind:
    TerminalErrorKind::Malformed } }`** → wallet-side bug
    or daemon-byzantine path; logs loudly (subject to
    recursive trust-boundary discipline) and may trigger
    error-reporting if per-consumer policy allows.
  - **Recurring
    `SubmitPendingResolution { kind:
    AmbiguousErrorKind::DaemonTimeout }` or
    `SubmitPendingResolution { kind:
    AmbiguousErrorKind::DaemonUnavailable }`** → daemon
    transient failure or peer-rotation candidate; signals
    `PeerReputationActor` for graduated response. (Both
    ambiguous-failure kinds carry the same operational
    signal under daemon-side authority disposition; the
    analyzer treats them as a single pattern source. The
    underlying reservations remain in `in_flight`, awaiting
    consumer-explicit `discard(rid, ConsumerExplicit)` or
    `signal_mempool_evicted(rid)` per segment-2i's G1
    handler.)

  **Hard mitigation pins (binding).**
  - **Recursive trust boundary per PR 4 §5.4.8 #4 (binding).**
    Per-failure-kind counts and per-peer correlation are
    in-process-only; cross-boundary projections drop
    `reservation_id` / `tx_hash` correlation surface and emit
    only aggregate counts per error-class.
  - **Restart-amnesia per PR 4 §5.4.8 #1 (binding).** Pattern
    detection is coarse-window-based; no persistence across
    wallet restarts.

  **Trigger:** *when Stage 4 actor mesh stabilizes;
  `PeerReputationActor` (PR 4 R6) is a coordinated
  prerequisite for the rotation-policy signal path.*
  Cross-references:
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.0.2 (`PendingTxDiagnostic` variant set), §5.4 R9
  (per-error-class semantics);
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.7 R6 reframe (`PeerReputationActor` cross-reference).

- **`TimeoutResolverActor` consumer actor (Stage 1 PR 5 R9
  Finding 2 composition; ergonomic complement for daemon-
  side authority disposition; V3.x).** PR 5's Round 2
  segment 2f closure of
  [`docs/design/STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.4 R9 closed Finding 2 (mailbox-ordering vs daemon-side
  authority for terminal-rejection visibility) as
  **daemon-side authority**. **Post-segment-2h shape**
  (the segment-2f-narrative substrate is superseded; see
  `SubmitFailureAnalyzer` entry above for the full
  reconciliation): on
  `AmbiguousErrorKind::{DaemonTimeout, DaemonUnavailable}`,
  the reservation stays in the `in_flight` collection;
  consumer-explicit `discard(id, ConsumerExplicit)` is the
  resolution path; R8's `ReservationTTLActor` is the
  safety net for forgotten resolutions. Segment 2i adds
  `signal_mempool_evicted(rid)` as a second resolution
  path for the mempool-eviction subclass (per the F2
  ownership-boundary discipline pinned at Phase 0m).
  `TimeoutResolverActor` is the V3.x ergonomic complement
  that automates the consumer-side resolution loop:

  - Subscribes to
    `PendingTxDiagnostic::SubmitPendingResolution { rid,
    kind: AmbiguousErrorKind::DaemonTimeout |
    AmbiguousErrorKind::DaemonUnavailable }` events
    (the post-segment-2h variant carrying the ambiguous-
    failure signal; the pre-segment-2h
    `PendingTxDiagnostic::SubmitFailed { kind: ... }`
    variant was removed under the P4 collection-moves
    table).
  - **Chain-observation mechanism (design owned by the
    V3.x consumer-actor PR; Copilot-fix follow-up note).**
    To determine whether the timed-out `tx_hash` landed on
    chain, the actor needs a mechanism that
    `LedgerDiagnostic::SnapshotMerged { new, prior, height }`
    does **not** provide on its own — `SnapshotMerged`
    carries snapshot identity and height, not transaction
    hashes per Phase 0g binding. The V3.x consumer-actor
    PR will design the correlation mechanism as one of:
    - An **additive `LedgerDiagnostic` variant** (e.g.,
      `LedgerDiagnostic::TransactionConfirmed { tx_hash,
      height }`) emitted by the `LedgerEngine` when a
      previously-pending transaction lands on chain. The
      `TimeoutResolverActor` subscribes to this new variant
      directly.
    - An **additive `LedgerEngine` chain-query accessor**
      (e.g., `LedgerEngine::tx_in_chain(tx_hash) ->
      Result<Option<BlockHeight>>`) that the resolver
      polls on each `SnapshotMerged` event to check
      whether the timed-out tx has landed.
    - **Both** (event-driven for low-latency notification;
      polling for catch-up after restart-amnesia).

    Pinning the mechanism in PR 5 would overspecify a V3.x
    consumer-actor that doesn't ship in V3.0; the
    `LedgerEngine` and `LedgerDiagnostic` surfaces have
    their own additive-extension discipline that the
    consumer-actor PR composes against.
  - On observing the timed-out `tx_hash` in chain state
    (by whichever mechanism the V3.x PR pins) → calls
    `discard(id, ConsumerExplicit)` to release the
    reservation entry (the on-chain tx is now the
    authoritative record).
  - On observing **no** chain landing after a configurable
    grace period (default: N blocks ≈ M minutes; consumer-
    policy-configurable) → calls `discard(id,
    ConsumerExplicit)` to release outputs back to the pool;
    consumer's rebuild loop picks up.

  **Phase 1 landed (2026-05-27).** Segment 2f/2h daemon-side
  authority disposition and `SubmitPendingResolution` / `in_flight`
  substrate shipped on `feat/stage-1-pr5-pending-tx-engine` (C5β/C7).
  This entry remains open for the V3.x **`TimeoutResolverActor`**
  ergonomic complement; trigger unchanged: Stage 4 actor mesh
  stabilizes plus chain-observation mechanism design in the V3.x
  consumer-actor PR.

  **Why V3.x, not V3.0.** Segment 2f's daemon-side authority
  disposition is wallet-correct without the resolver actor —
  R8's `ReservationTTLActor` already covers forgotten
  resolutions via per-collection TTL configuration with
  shorter TTL on `in_flight` (the post-segment-2h
  equivalent of the segment-2f `SubmitPendingDaemonAck`
  state). The `TimeoutResolverActor`
  is **operational ergonomics**, not a wallet-correctness
  primitive; deferring it to V3.x preserves V3.0's "do less,
  do it right" posture and lets the actor's design land
  alongside `SubmitFailureAnalyzer` once Stage 4 actor mesh
  stabilizes.

  **Hard mitigation pins (binding).**
  - **Recursive trust boundary per PR 4 §5.4.8 #4 (binding).**
    `TimeoutResolverActor` operates in-process on the
    wallet's own reservation IDs and tx hashes; cross-
    boundary projections (e.g., telemetry that a particular
    reservation timed out and was resolved by chain
    observation) drop `reservation_id` / `tx_hash`
    correlation surface and emit only aggregate counts.
  - **Restart-amnesia per PR 4 §5.4.8 #1 (binding).** The
    actor's grace-period timers are in-memory only;
    restart drops them. R8's `ReservationTTLActor` is the
    durable safety net (per-state TTLs run on the
    restart-amnesia substrate too — they're event-driven
    via timestamp comparison against the reservation's age,
    not wall-clock timers).
  - **Recursive consumer-policy.** Grace-period duration is
    consumer-policy-configurable; default values are sized
    conservatively (longer than typical reorg-depth + mempool
    propagation delay) to minimize false-resolution risk.

  **Trigger:** *when Stage 4 actor mesh stabilizes;
  `LedgerDiagnostic::SnapshotMerged` (PR 4) is a
  prerequisite for the chain-observation correlation path.*
  Cross-references:
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.0.2 (`AmbiguousErrorKind` variant set: `DaemonTimeout` /
  `DaemonUnavailable` per segment-2h split of the segment-2f
  unified `SubmitErrorKind`), §5.4 R9 (Finding 2 daemon-side
  authority closure; segment-2f V3.x deliverable named the
  V3.x ergonomic-API candidate `resolve_pending(id,
  chain_observation)`); R8 `ReservationTTLActor` entry above
  (safety-net role).

- **`ReservationAuditActor` consumer actor (Stage 1 PR 5 §5.0.2
  composition; in-memory wallet-action audit log).** Subscribes
  to all `PendingTxDiagnostic` events and maintains an
  in-memory wallet-action audit log: build / submit / discard
  events with timestamps and outcomes. Useful for UI
  transaction-history view; useful for forensic investigation
  when a wallet exhibits unexpected behaviour.

  **Hard mitigation pins (binding).**
  - **Recursive trust boundary per PR 4 §5.4.8 #4 (binding —
    most load-bearing on this entry).** Full-fidelity audit
    log carries `reservation_id` / `snapshot_id` / `tx_hash`
    correlation surfaces. **Persistence beyond wallet session
    requires explicit threat-model review** — the audit log
    is exactly the kind of state an adversary with file-system
    access wants to read. Default disposition: in-memory only.
    Persistence path requires either (a) projection to a
    coarse-grained per-day transaction count export (UI
    history shape) or (b) full encrypted-at-rest storage with
    explicit threat-model justification.
  - **Restart-amnesia per PR 4 §5.4.8 #1 (binding under default
    in-memory disposition).** Audit log resets on wallet
    restart unless persistence is explicitly enabled per the
    review above.
  - **Mailbox saturation per PR 4 §5.4.8 #5.** Audit log is a
    bounded ring buffer with drop-oldest-on-overflow; the UI
    transaction-history view shows the most-recent-N entries.

  **Trigger:** *when Stage 4 actor mesh stabilizes; UI history
  view in scope.*
  Cross-references:
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.0.2 (`PendingTxDiagnostic` variant set), §5.0.3
  (cross-cutting `DiagnosticSink` contracts);
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.8 #4 (recursive trust-boundary discipline).

- **Cancel-during-`in_flight` ergonomic alternative
  ((c) shape; Stage 1 PR 5 segment 2h F2 V3.x trigger).**
  PR 5 segment 2h closed F2 (consumer `discard` arriving
  during the in-flight daemon round-trip) as **ownership-
  boundary disposition (a)**: `PendingTxError::DiscardBlockedPendingDaemonAck
  { reservation_id }` is returned; the consumer must wait
  for daemon resolution or R8 TTL safety-net. Disposition
  (c) — `discard_requested: bool` flag on `InFlightSubmit`
  that records the consumer's intent and reconciles at
  `SubmitCompleted` arrival — is the V3.x ergonomic-refinement
  candidate.

  **V3.x implementation sketch.**

  ```rust
  struct InFlightSubmit {
      snapshot_id: SnapshotId,
      created_at: Instant,
      submitted_at: Instant,
      discard_requested: bool,    // V3.x
  }
  ```

  Reconciliation at `SubmitCompleted` arrival:

  - `Accepted ∧ discard_requested` → tx is live on network;
    consumer's discard intent is unenforceable. Outputs are
    spent on-chain. Emit
    `SubmissionAcceptedDespiteDiscard { rid }` (new V3.x
    diagnostic) for consumer transparency; suppress standard
    `SubmitSucceeded` in favor of the override-class.
  - `Accepted ∧ !discard_requested` → standard
    `SubmitSucceeded`.
  - `TerminalErrorKind::* ∧ discard_requested` → treat as
    consumer's intent satisfied; emit
    `Discarded { ConsumerExplicit }` (not
    `Discarded { DaemonRejectedTerminal { kind } }`; the
    daemon's rejection is moot to the consumer's intent).
    **Audit/debug-visibility sub-note (V3.x design-rounds
    question).** The daemon's rejection reason is
    structurally hidden in this case; whether V3.x emits
    dual events (`Discarded { ConsumerExplicit }` plus a
    separate `DaemonRejectionMooted { rid, kind:
    TerminalErrorKind }` diagnostic for audit visibility)
    is a V3.x design-rounds question. The decision interacts
    with the temporal/distributional projection discipline
    (F5+F6) — dual emission adds a wallet-attributable
    event class that consumer-actor projection must handle.
  - `TerminalErrorKind::* ∧ !discard_requested` → standard
    `Discarded { DaemonRejectedTerminal { kind } }`.

  **Threat-model regression note (V3.x design-rounds
  question).** V3.x's `SubmissionStrategyActor` deliberately
  delays broadcast to obscure wallet-network correlation.
  Under (c), a consumer's discard arriving before strategy-
  actor-broadcast could legitimately cancel; arriving
  after-broadcast is unenforceable. Distinguishing these
  cases at the consumer-visible API level (e.g.,
  `Discarded { ConsumerExplicit, broadcast_avoided: bool }`)
  would create a timing side-channel that leaks the
  strategy actor's broadcast timing back to the consumer.
  **(c)'s V3.x implementation MUST present the two cases
  identically at the consumer surface, OR the strategy
  actor's timing-obscurity property is degraded.** The
  design-rounds work to settle (c) reopens the strategy-
  actor threat model — the V3.x PR is necessarily a
  coordinated `PendingTxEngine` + `SubmissionStrategyActor`
  + `DIAGNOSTIC_STREAM.md` design-rounds pass.

  **Reopening criteria (per
  [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)).**

  - Telemetry surfaces consumer-impatience patterns under
    the V3.0 disposition (a) — `DiscardBlockedPendingDaemonAck`
    errors observed in production at non-trivial frequency
    across operational deployments.
  - AND the coordinated V3.x design-rounds bandwidth is
    available (`PendingTxEngine` + `SubmissionStrategyActor`
    + `DIAGNOSTIC_STREAM.md`).

  **Re-evaluation shape.** A V3.x design-rounds pass owned
  jointly by the per-trait PR template
  ([`shekyl-core/.cursor/rules/26-sub-pr-design-discipline.mdc`](../.cursor/rules/26-sub-pr-design-discipline.mdc))
  and the strategy-actor introduction PR.

  **Trigger:** *V3.x telemetry surfaces (a) friction at
  production scale.*
  Cross-references:
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.6.5 F2 (ownership-boundary disposition under lean
  shape), §5.6.7 (segment 2h V3.x FOLLOWUPS substrate); R15
  `SubmissionStrategyActor` FOLLOWUPS entry above.

- **Eager-discard-on-`SnapshotMerged` opt-in (Stage 1 PR 5
  segment 2h P9 V3.x trigger).** PR 5 segment 2h preserved
  segment-2e's lazy R5 disposition: snapshot rotation drives
  no automatic collection moves at V3.0; consumer learns at
  submit-time via `SubmitError::SnapshotInvalidated` and
  releases `output_locks` via consumer-explicit
  `discard(rid, ConsumerExplicit)`. Eager-discard — where
  the `SnapshotMerged` handler unilaterally drops stale
  reservations from `consumer_held` and releases their
  `output_locks` — is the V3.x opt-in.

  **What V3.x lands.**

  - **`DiscardReason::SnapshotRotationAutoDiscard` variant
    reintroduction** (the variant was removed under segment-2h
    lazy R5; V3.x adds it back as the eager-discard handler's
    emission reason).
  - **`ConsumerHeldEntry { created_at, snapshot_id }`
    substrate refinement** — the V3.0
    `HashMap<ReservationId, Instant>` shape doesn't admit
    selective eager discard (otherwise eager becomes
    sweeping). V3.x expands `consumer_held` to
    `HashMap<ReservationId, ConsumerHeldEntry { created_at,
    snapshot_id }>` so the eager handler can filter "discard
    only entries built against prior snapshots."
  - **Eager-discard policy as opt-in** — the V3.x
    `ReservationPolicyConfig` (extension of the V3.0
    `ReservationTTLConfig`) gains an
    `eager_discard_on_rotation: bool` field; default off
    preserves V3.0 lazy semantics; opt-in users get
    eager-cleanup.

  **Reopening criteria (per
  [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)).**

  - V3.0 production telemetry surfaces a fast-snapshot-
    rotation workload where consumer rebuild rates against
    `SubmitError::SnapshotInvalidated` indicate the lazy-
    cleanup performance characteristics are load-bearing
    at scale.
  - OR a V3.x performance-policy design rounds names the
    lazy-vs-eager tradeoff as a reservation-policy
    configuration surface (parallel to F7's per-collection
    TTL).
  - AND the substrate refinement to support selective
    eager-discard lands as part of the V3.x reopen.

  **Re-evaluation shape.** A V3.x design-rounds pass on R5
  reservation-policy refinement; outcome either lands
  eager-discard as an opt-in policy (reintroducing
  `DiscardReason::SnapshotRotationAutoDiscard` +
  selective-discard substrate) or confirms lazy as the
  V3.x shape with consumer-policy-driven abandonment via
  `discard(rid)` as the alternative.

  **Trigger:** *V3.0 deployment telemetry surfaces fast-
  snapshot-rotation friction; OR V3.x performance-policy
  design rounds opens.*
  Cross-references:
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.4 R5 (lazy R5 preservation under lean shape), §5.6.5
  F5+F6 / §5.6.6 P9 (segment 2h disposition substrate),
  §5.6.7 P9 (V3.x reopening criteria);
  `ReservationTTLActor` FOLLOWUPS entry above (Phase 0l
  per-collection TTL config precedent).

- **Optional inverse-index seam under `PendingTxActor`'s
  (γ) lean state (Stage 1 PR 5 segment 2h perf trigger).**
  Under the segment-2h (γ) shape, discard operations scan
  `output_locks` for rid-matching entries — O(n) over the
  count of locked outputs. At V3.0 wallet scale (per
  `V3_ENGINE_TRAIT_BOUNDARIES.md` §2.4 implementation note;
  hundreds-to-low-thousands of locked outputs), the scan
  cost is nanoseconds and the actor's mailbox processing
  rate dominates by orders of magnitude. If V3.x telemetry
  surfaces wallet sizes where the scan dominates handler
  latency, V3.x adds a maintained-by-actor inverse index:

  ```rust
  reservation_to_outputs: HashMap<ReservationId, BTreeSet<OutputId>>
  ```

  **What V3.x lands.** The inverse index alongside the
  existing `output_locks` collection. Mutations are
  doubled: every `output_locks` insert/remove pairs with
  a `reservation_to_outputs` insert/remove. The audit
  obligation grows by the maintained-invariant property
  (`output_locks.iter().all(|(oid, rid)|
  reservation_to_outputs[rid].contains(oid))` and the
  reverse).

  **Why this is a perf shape, not an audit shape change.**
  `output_locks` remains the single source of truth for
  "which outputs are claimed by what reservation."
  `reservation_to_outputs` is a maintained-side index for
  scan-avoidance; correctness audits read against
  `output_locks` only. The denormalization (which the
  segment-2h (γ) shape rejected for the consumer_held +
  in_flight collections) is acceptable here because it's
  a perf optimization that doesn't change the safety
  property and the maintained invariant is auditable in a
  bounded scope.

  **Reopening criteria (per
  [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)).**

  - V3.0 telemetry surfaces wallet sizes where `output_locks`
    scan latency dominates handler processing.
  - The maintained-invariant audit obligation is named and
    accepted as the re-evaluation compensating discipline.

  **Re-evaluation shape.** A V3.x perf-optimization PR
  scoped to the `PendingTxEngine` actor; design rounds
  cover the maintained-invariant audit obligation and the
  test substrate that enforces it (`output_locks_inverse_index_invariant_holds`
  property test). The PR does not alter trait surfaces,
  enum shapes, or external contracts.

  **Trigger:** *V3.0 telemetry surfaces O(n) scan latency
  as load-bearing.*
  Cross-references:
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.6.2 ((γ) lean state shape; perf-seam disposition),
  §5.6.7 (V3.x perf-trigger substrate).

- **`MempoolMonitorActor` consumer actor (Stage 1 PR 5
  segment 2i G1 substrate; V3.x).** PR 5's Round 2
  segment 2i closes G1 (mempool-eviction without daemon
  notification) by pre-pinning three V3.0 substrate
  pieces — `DiscardReason::MempoolEvicted` variant
  (Phase 0f), `tx_hash: TxHash` projection field on
  `PendingTxDiagnostic::SubmitSucceeded` +
  `SubmitPendingResolution` (Phase 0f), and a narrow
  `PendingTxEngine::signal_mempool_evicted(rid) ->
  Result<(), PendingTxError>` trait method (Phase 0m).
  V3.0 has no in-process emitter; V3.x introduces the
  `MempoolMonitorActor` consumer-actor pattern that
  produces the eviction signals.

  **What V3.x lands.**

  - `MempoolMonitorActor` subscribes to
    `PendingTxDiagnostic::SubmitSucceeded` and
    `SubmitPendingResolution` (the segment-2i
    `tx_hash` projection is the load-bearing field).
  - Periodically queries
    `DaemonEngine::query_mempool_presence(tx_hash)`
    for each tracked rid (poll cadence is per-deployment
    configurable; cadence has a privacy fingerprint per
    PR 4 §5.4.8 #4's diagnostic-stream temporal-projection
    discipline — the V3.x consumer-actor PR must address
    cadence privacy explicitly).
  - On observed eviction (mempool query returns
    "not present" beyond a debounce window — the
    debounce avoids false-positives from transient
    daemon-side mempool churn), calls
    `PendingTxEngine::signal_mempool_evicted(rid)`. The
    F2 ownership-boundary adjudication (per
    segment-2i §5.6.10 G1 narrow-shape rationale) bounds
    what this method admits: observation-class signals
    only; decision-class signals (e.g., user-initiated
    cancel) take separate trait paths.

  **Why this is V3.x, not V3.0.** PR 5 has no V3.0
  in-process consumer of the eviction-signal trait method
  (no `MempoolMonitorActor` at V3.0; Stage 1's
  `LocalPendingTx` is invoked from the in-process call
  graph; no async polling loop exists at V3.0). Per
  `15-deletion-and-debt.mdc` "code with no live caller"
  default-delete rule, V3.0 ships the trait method
  + variant + projection field as the substrate that
  V3.x consumes additively. V3.0 unit tests hand-roll
  the call to exercise the trait method + handler body
  per the segment-2i §5.6.12 C5β test deliverable
  enumeration.

  **Threat-model framing.** Daemon-mempool query is a
  *daemon-observable signal*. The poll cadence reveals
  "this wallet is monitoring tx X" to the daemon; the
  privacy cost is the polling-rate fingerprint. The
  V3.x consumer-actor PR's design rounds MUST surface
  this fingerprint explicitly and either (i) jitter the
  poll cadence to mute the signal, (ii) batch queries
  across multiple in-flight reservations to amortize the
  cost, or (iii) accept the fingerprint with an explicit
  pin. The V3.x privacy review is the gate; segment 2i
  does not pre-close it.

  **Reopening criteria (per
  [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)).**
  The G1 V3.0 substrate (the trait method + variant +
  projection field) is **structurally final** at V3.0.
  Reopening conditions:

  - V3.x consumer-actor PR's privacy review finds the
    polling-cadence fingerprint un-mitigable to the
    project's privacy bar; the alternative substrate at
    that altitude is a different signal mechanism
    (e.g., daemon-pushed eviction notifications if a
    future daemon version admits the pattern); the
    V3.0 trait method may need revision to admit the
    different signal source.
  - A second observation-class consumer-signal candidate
    surfaces (e.g., `signal_peer_dropped` from a
    `PeerHealthMonitorActor`); the F2 adjudication
    against the new narrow method runs; consolidation
    into a wider shape is permitted only if three+
    narrow methods accumulate AND all pass F2
    adjudication on identical grounds.

  **Re-evaluation shape.** Either of the above triggers
  a fresh design round at the V3.x consumer-actor PR's
  altitude, with the substrate-change evidence on the
  table before the round opens; no retroactive PR 5
  revision.

  **Trigger:** *V3.x consumer-actor PR introducing the
  `MempoolMonitorActor`.*
  Cross-references:
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §4 Phase 0f (variant + projection field), §4 Phase 0m
  (trait method), §5.6.10 G1 (substrate disposition with
  narrow-shape rationale), §5.6.11 G6 (cross-reference
  to `TxConfirmationTrackerActor` which shares the
  `tx_hash` substrate).

- **`TxConfirmationTrackerActor` consumer actor (Stage 1
  PR 5 segment 2i G6 substrate; V3.x).** PR 5's Round 2
  segment 2i G6 disposition names the V3.x consumer-actor
  pattern for tx-confirmation tracking. The actor consumes
  the segment-2i `tx_hash` projection field on
  `PendingTxDiagnostic::SubmitSucceeded` (shared substrate
  with the G1 `MempoolMonitorActor` entry above) and the
  V3.x `LedgerDiagnostic::BlockObserved` /
  `RefreshDiagnostic::*` confirmation-count stream; it
  maintains a per-tx confirmation-count state and emits
  a `TxConfirmationDiagnostic` stream the wallet-UI
  consumes.

  **What V3.x lands.**

  - `TxConfirmationTrackerActor` subscribes to
    `PendingTxDiagnostic::SubmitSucceeded { tx_hash }`
    and observes block-arrival events from the
    `LedgerEngine` / `RefreshEngine`-side diagnostic
    stream.
  - Per-tx state machine: 0 confs → 1 conf → ... → N
    confs → finalized; configurable finalization
    threshold (per-deployment policy).
  - Emits `TxConfirmationDiagnostic` events (a new V3.x
    diagnostic stream the wallet-UI subscribes to);
    `DIAGNOSTIC_STREAM.md` documents the contract
    (parallel to `PendingTxDiagnostic`).
  - Handles the G2 disposition's reorg-out case (see
    `LedgerDiagnostic::TxReorgedOut` forward-template
    amendment to the diagnostic-stream specification
    entry below): a previously-confirmed tx whose
    block reorgs out drops back to lower confirmation
    count or to mempool-pending; the wallet-UI sees
    the count regress.

  **Why this is V3.x, not V3.0.** No V3.0 consumer
  exists; the `LedgerDiagnostic::BlockObserved` variant
  (which the actor consumes) is itself V3.x per Phase 0g's
  deferred-to-consumer-PR pattern. The V3.x consumer-actor
  PR introduces both additively.

  **Reopening criteria.** V3.x consumer-actor PR's
  design rounds address (i) per-tx state-machine
  granularity (count threshold for "confirmed"); (ii)
  reorg-out UX (the G2 disposition explicitly admits
  brief "confirmed → unconfirmed → re-confirmed" as
  V3.0-accepted-surface; V3.x can hide the regression
  in the UI or expose it).

  **Re-evaluation shape.** V3.x consumer-actor PR with
  its own design rounds; segment 2i's role is to record
  the foreclosure-pin that V3.0 PR 5 doesn't constrain
  V3.x's design options.

  **Trigger:** *V3.x consumer-actor PR introducing the
  `TxConfirmationTrackerActor` (typically alongside the
  Stage 4 actor-migration PR or the `LedgerEngine` /
  `RefreshEngine` consumer-actor PR).*
  Cross-references:
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.6.11 G6 (V3.x FOLLOWUPS disposition with
  cross-reference to G1 `tx_hash` substrate).

- **Transaction replacement / fee-bump (RBF/CPFP-equivalent)
  structural rejection (Stage 1 PR 5 segment 2i R18
  substrate; conditional-reopening bookmark, NO V3.x
  schedule entry).** PR 5's Round 2 segment 2i closes
  G3 (transaction replacement) as **structurally rejected
  at V3.0 per the R18 closure** in §5.4 of the PR 5 design
  doc. The rejection rationale is the priority hierarchy
  per
  [`00-mission.mdc`](../.cursor/rules/00-mission.mdc)
  as **ordering-not-magnitude-comparison**: any priority-2
  (privacy) cost for any priority-3 (UX) benefit is
  rejected by the ordering. Replacement creates a
  mempool-observer-visible linked-tx-pair fingerprint
  (two replacement txs share a key image; mempool
  observers see both sequentially before the second gets
  rejected as double-spend); the fingerprint is bounded
  but net-new privacy regression that does not exist if
  replacement is not admitted.

  This entry is a **conditional-reopening bookmark**,
  parallel in structure to the encrypted-persistence
  bookmark for PR 4 §5.4.8 #1 / PR 5 R17. **There is no
  V3.x schedule entry; conditional reopening only.**

  **V3.x reopening criteria (per
  [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)
  named-criteria principle; criteria are alternatives, not
  conjunctive).**

  1. **FCMP++ cryptographic fingerprint-unobservability
     analysis.** Demonstrates that under FCMP++'s proof-
     construction characteristics, mempool observers
     cannot link key images across mempool snapshots —
     i.e., the replacement fingerprint is
     cryptographically muted rather than just bounded.
     Substrate-change-class trigger; re-anchors the
     priority-2-cost calculus.

  2. **R16 V3.x `WalletSideEstimator` operational
     telemetry priority-class re-classification.** R16's
     V3.x telemetry demonstrates fee-estimation
     improvements are insufficient to prevent stuck-tx
     scenarios at a user-impact-significant rate —
     **re-classifying stuck-tx-recovery from priority-3
     UX to priority-1 security/integrity** (users lose
     funds to unrecoverable stuck txs). The load-bearing
     piece is the priority-class promotion, not the
     user-impact rate; the rate enables the promotion but
     doesn't substitute for it.

  **Re-evaluation shape.** Reopening lands a fresh design
  round at the per-trait PR altitude (analogous to PR 5's
  Round 2 segment-2b R11 split or PR 4's Round 4 review
  pass). The reopening evidence MUST include (i) the
  cryptographic-analysis citation or the
  telemetry-citation; (ii) a fresh threat-model review of
  the replacement fingerprint under the substrate change;
  (iii) an `AUDIT_SCOPE.md` amendment if the substrate
  change brings new surface into audit scope; (iv) a
  fresh `ReservationExtension::Replacement` variant
  proposal with the field-set substrate the new round
  names.

  **Phase 0 implication (closed).** No V3.0
  trait-surface change; no `replace` method on
  `PendingTxEngine`; no
  `ReservationExtension::Replacement` pre-pin on R14's
  extensibility seam. The R14 seam stands as the generic
  extensibility surface; replacement-specific variant
  addition is gated on the reopening criteria above.

  **Auto-closure.** This bookmark is automatically
  closed if V3.0 + V3.1 deployments do not surface either
  reopening criterion within the V3.0 + V3.1 window —
  parallel to the encrypted-persistence bookmark's
  auto-closure structure.

  **Cross-references:**
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.4 R18 (full closure with priority-ordering
  rationale), §5.6.10 G3 (substrate disposition with
  failure-mode framing), §5.6.11 (relationship to G6
  / G7 / G8). Adjacent FOLLOWUPS entries: PR 4 / PR 5
  encrypted-persistence bookmark (parallel structure);
  R16 V3.x `WalletSideEstimator` (the criterion-2
  telemetry source).

- **Build-cancel ergonomic refinement (Stage 1 PR 5
  segment 2i G7 substrate; V3.x).** PR 5's Round 2
  segment 2i G7 disposition pins the V3.0 trait surface
  against future-foreclosure of build-cancellation as a
  V3.x additive path. FCMP++ proof generation can take
  seconds; consumer needs an abort surface during the
  build call. The V3.0 synchronous `build() ->
  Result<Reservation, ...>` shape doesn't admit abort
  directly.

  **What V3.0 PR 5 pins.** The V3.0 trait surface uses
  **synchronous-return** (`Result<Reservation, _>`),
  not `async fn build(...)` or `impl Future<Output = ...>`.
  **The V3.0 trait method MUST NOT change to
  `async fn build(...)` or return a future without the
  V3.x additive-path design surfacing first.** An async-
  trait migration is a downstream consequence of the
  abort surface, not a precondition.

  **What V3.x lands.** Either:

  - An additive `build_with_handle() ->
    Result<BuildHandle, ...>` trait method that returns
    an abortable handle (`BuildHandle:
    Future<Output = Result<Reservation, _>> +
    Cancellable`).
  - A trait-extension introduction
    (`PendingTxEngineCancellable: PendingTxEngine`) that
    admits abort-capability as a separate trait.

  Both additive paths preserve the V3.0 `build` trait
  surface; consumers that don't need abort continue
  calling `build`; consumers that need abort opt into
  the new path.

  **Reopening criteria (per
  [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)).**

  - V3.x consumer demand surfaces from real deployments
    (FCMP++ proof generation observed as slow enough that
    abort is a real UX need, not anticipated demand).
  - The V3.x additive-path design (one of the two shapes
    above) lands ahead of any async-trait migration on
    the existing `build` method.

  **Re-evaluation shape.** V3.x design rounds at the
  per-trait PR altitude introduce the additive trait
  method or trait extension; the V3.0 trait surface stays
  unchanged.

  **Foreclosure-pin (load-bearing).** Without this
  bookmark, a future contributor might argue "we should
  just change `build` to `async fn build` to support
  cancellation later" — which would be the
  cost-benefit-defer-to-later anti-pattern (per
  `16-architectural-inheritance.mdc`) applied to a
  trait-surface revision. The bookmark explicitly names
  the async-trait migration as out-of-scope without the
  additive-path design surfacing first.

  **Trigger:** *V3.x consumer demand for build
  cancellation surfaces; design rounds for the additive
  path open.*
  Cross-references:
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.6.11 G7 (foreclosure-pin against async-trait
  migration without additive-path design surfacing
  first).

- **Wallet-locked-during-`in_flight` coordination
  (Stage 1 PR 5 segment 2i G8 substrate; V3.x).** PR 5's
  Round 2 segment 2i G8 disposition names the
  cross-component coordination question for the
  wallet-locked-while-`in_flight` case. Wallet locks (user
  steps away) while `in_flight` reservations exist; spend
  material clears from `SigningActor` state on lock;
  in-flight reservations whose daemon response arrives
  during the locked period need a coordinated wallet-
  state-machine + `PendingTxEngine` + `SigningActor`
  disposition.

  **What V3.x lands.** A wallet-state-machine PR (V3.x;
  not pre-built at V3.0) that coordinates the three
  components against the lock boundary. Three
  sub-questions the V3.x PR's design rounds resolve:

  1. **What happens to `in_flight` reservations on
     lock?** Open at V3.x. Options:
     - (a) Actor mailbox drains `submit_completed`
       self-messages but defers the reply until unlock.
     - (b) Actor mailbox processes `submit_completed`
       and projects to a "deferred-notifications" queue
       the unlock-handler drains.
     - (c) Actor mailbox suspends processing entirely on
       lock.
  2. **What happens to `consumer_held` reservations on
     lock?** Open at V3.x. The reservation payload
     includes the spend material's witness; the consumer
     (wallet UI) is already in the locked state. Defer
     to V3.x wallet-state-machine PR.
  3. **What happens to in-flight `SigningActor` requests
     when the device is unplugged / wallet locks during
     HW signing?** Open at V3.x. The G4 multi-step
     submit shape (per segment-2i §5.6.10 G4) provides
     the timeout substrate; the V3.x PR's design rounds
     name the unlock policy.

  **Foreclosure-pin (V3.0 substrate).** The V3.0 trait
  surface admits all three sub-question dispositions
  without trait revision: (i) deferred replies are an
  actor-pattern concern (G4 substrate; deferred-reply
  semantic confirmation already pinned); (ii)
  `consumer_held` state lives in the engine, not in
  the wallet-state-machine — the wallet-state-machine
  PR decides whether to clear it; (iii) `SigningActor`
  state is `SigningActor`-internal — the wallet-state-
  machine PR's design rounds coordinate.

  **Reopening criteria.** The V3.x wallet-state-machine
  PR's design rounds open with the three sub-questions
  as a substrate-completeness pass; no V3.0 PR 5
  revision is required regardless of which dispositions
  the V3.x PR adopts.

  **Re-evaluation shape.** V3.x wallet-state-machine
  PR with its own design rounds; segment 2i's role is to
  record that the three sub-questions are V3.x-domain
  and the V3.0 substrate doesn't constrain V3.x's
  resolution.

  **Trigger:** *V3.x wallet-state-machine PR (typically
  alongside or after the Stage 4 actor-migration PR).*
  Cross-references:
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.6.11 G8 (V3.x FOLLOWUPS disposition with
  sub-question enumeration); §5.0.1 Stage 4 prose (G4
  multi-step submit substrate); R11 (b) segment-2b
  closure (`SigningActor` locality discipline).

- **`LedgerEngine` candidate-fetch maturity-filter
  contract pin (Stage 1 PR 5 segment 2i G5 substrate;
  V3.x forward-template for the eventual `LedgerEngine`
  trait-extraction PR).** PR 5's Round 2 segment 2i G5
  disposition names output-maturity-filtering as
  `LedgerEngine` trait-contract domain rather than
  `PendingTxActor`-side build-flow filtering. The V3.x
  `LedgerEngine` trait-extraction PR's design rounds
  inherit this forward-template explicitly so they don't
  re-derive from scratch.

  **What V3.x lands.** `LedgerEngine`'s candidate-fetch
  method (whatever its eventual signature) returns
  **maturity-filtered outputs by contract**. The
  maturity filter excludes:

  - Outputs within `FCMP_REFERENCE_BLOCK_MIN_AGE`
    reorg-safety window.
  - Coinbase outputs within their unlock period.
  - Any V3.x staking-output maturity period (if /
    when staking-output unlock semantics land).

  **Why this is `LedgerEngine`-contract-domain.** P6
  (segment-2h filter-then-select-then-subset-check in
  `PendingTxActor`'s build flow) handles `output_locks`
  collision filtering. Adding maturity filtering at the
  `PendingTxActor` layer would duplicate the
  `LedgerEngine`-side responsibility — two implementations
  to keep in sync, two audit surfaces, two opportunities
  for the filters to drift. The contract-altitude
  disposition keeps the responsibility upstream at the
  altitude that owns the maturity-knowledge (the
  `LedgerEngine` already knows block heights, coinbase
  flags, and V3.x staking-output metadata).

  **Test substrate pin.** The maturity-filter regression
  test posture is **synthetic immature output in the
  `LedgerEngine` impl's response**, not a
  `PendingTxActor`-side filter test. PR 5's V3.0
  `LocalLedger` mock at C5β handles raw-output-set
  filtering by construction (no immature outputs in the
  test fixtures); the V3.x `LedgerEngine` extraction PR
  introduces both the maturity-filter contract pin and
  the corresponding test substrate (synthetic immature
  outputs reach the filter; the filter excludes them
  pre-return).

  **Failure mode foreclosed.** Bitcoin / Monero wallets
  have historically had subtle bugs where coinbase
  outputs got selected before unlock, producing daemon-
  rejected transactions and leaking "this wallet is
  mining" via the attempted submission's failure mode.
  The V3.x substrate puts the responsibility at the
  contract altitude that owns the maturity knowledge.

  **Reopening criteria (per
  [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)).**
  The forward-template is **structurally final** at the
  altitude that closes it (the V3.x `LedgerEngine`
  trait-extraction PR). Reopening conditions are
  limited to:

  - The `LedgerEngine` trait-extraction PR's design
    rounds discover that maturity is genuinely a
    cross-component concern that can't be cleanly
    localized at the `LedgerEngine` contract (e.g., the
    candidate fetch is partitioned across
    `LedgerEngine` + a new `StakingMaturityEngine` for
    V3.x staking-output maturity; the partition makes
    the contract-altitude responsibility ambiguous).
    In that case the disposition re-evaluates against
    the partition and may land the maturity-filter
    contract at a different altitude (or as a
    duplicate-by-contract at multiple altitudes with
    the maintained-invariant audit obligation named).

  **Re-evaluation shape.** V3.x `LedgerEngine`
  trait-extraction PR design rounds; segment 2i's role
  is to record the forward-template so the V3.x PR
  doesn't re-derive from scratch.

  **Trigger:** *V3.x `LedgerEngine` trait-extraction
  PR (the eventual PR that lifts `LedgerEngine`'s
  candidate-fetch surface into a first-class trait —
  parallel to PR 4 / PR 5's per-engine extractions).*
  Cross-references:
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.6.10 G5 (substrate disposition with failure-mode
  framing); §5.6.12 C5β test deliverables (the V3.0
  `LocalLedger` mock posture that V3.x extends);
  PR 5 P6 segment-2h filter-then-select-then-subset-
  check (the `PendingTxActor`-side filter that pairs
  with the contract-altitude maturity filter).

- **HW-wallet integration as a `Signer`-impl substitution
  (Stage 1 PR 5 R11 (b) substrate; V3.x).** **Phase 1 landed
  (2026-05-27):** `Signer` trait + `LocalSigner` shipped (C4α =
  `1b14d0113`); HW integration trigger is unchanged. PR 5's Round 2
  segment 2b reframe of
  [`docs/design/STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.4 R11 closed the signing-actor split question as **(b) —
  separate `SigningActor` from Stage 1**: `LocalPendingTx` /
  `PendingTxActor` does not hold spend material;
  `LocalSigner` / `SigningActor` is the sole holder. The trait
  surface and the architecture are designed to accept HW-wallet
  integration at the trigger as a `Signer`-impl substitution
  (`HardwareSigner`), not a refactor.

  **What V3.x lands.** A `HardwareSigner: Signer` impl that
  delegates `sign_tx` to a hardware device (trezor / ledger /
  YubiKey-class secure-storage path); wallet-side wiring to
  select the impl at startup based on user configuration; UX
  for device prompting / unlock / confirmation flows during
  signing. None of these change the `PendingTxEngine` trait
  surface or the actor topology; the existing `LocalSigner` is
  swapped for `HardwareSigner` at construction time.

  **Trigger.** HW-wallet implementation availability and
  integration scope (UX, device-API library selection,
  hardware-specific edge cases). The architectural cost was
  paid in PR 5 segment 2b; V3.x cost is implementation +
  integration work, not architectural change.

  **Relationship to PR 4 R4 V3.x deferred-(c).** PR 4 R4's V3.x
  deferred-(c) (split-producer/recoverer for view-tag matching
  vs. final hybrid-decap) benefits from PR 5 R11 (b)'s
  `SigningActor` infrastructure: the spend-key-isolated actor
  R4 (c) needs has a precedent and a target shape in PR 5's
  `SigningActor`; lifting PR 4 R4 (c) at the V3.x trigger
  becomes simpler because the spend-key-isolation shape
  already exists in the codebase.

  Cross-references:
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §3.1 (spend-secret-locality framing), §5.0 (actor-mesh
  framing as substrate), §5.0.1 (Stage 1 / Stage 4
  `signer`-field substrate), §5.4 R11 (Round 2 segment 2b
  closure as (b)), §5.5 (Round 1 disposition);
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §3.1, §5.4.7 R4 (Round 2 disposition with (c) deferral —
  remains V3.x-deferred; PR 5 R11 (b) provides the
  spend-key-isolation precedent for the eventual lift).

- **Output-selection alternatives under `OutputSelector` trait
  seam (Stage 1 PR 5 R13 substrate; V3.x).** PR 5 segment 2c
  named the output-selection algorithm as a first-class privacy
  decision and closed the disposition as **V3.0 ships
  wallet2-greedy carryover under an `OutputSelector` trait-
  parameter seam**; the seam is the architectural-integrity-
  now item, the algorithm choice is the V3.0-vs-V3.x decision.
  V3.x lands alternative `OutputSelector` impls:
  - `RandomizedSelector` — Knuth-shuffle within
    size-constrained candidates; defeats deterministic-
    correlation between reservations against the same
    available output set.
  - `EntropyMaximizingSelector` — optimize for output-set
    ambiguity under FCMP++ semantics (output age,
    transaction-graph distance, ring-membership
    plausibility); V3.x research territory.

  **Trigger.** Privacy-research outcomes (alternative
  selection algorithms validated under FCMP++ adversarial
  models); UX requirements (e.g., GUI "privacy mode"
  toggles); operational telemetry surfacing
  selection-correlation observable on-chain. None of these
  are V3.0 blockers; the seam preserves V3.0 shipping date
  while V3.x research advances.

  Cross-references:
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.4 R13 (segment 2c disposition);
  [`00-mission.mdc`](../.cursor/rules/00-mission.mdc) §2
  (privacy-as-product anchor).

- **Submission-strategy actors under
  `SubmissionStrategyActor` seam (Stage 1 PR 5 R15 substrate;
  V3.x).** **Phase 1 landed (2026-05-27):** V3.0 ships the submit
  path topology slot (direct `PendingTxEngine` → daemon); V3.x
  strategy actors remain deferred. PR 5 segment 2c named submission-time observability
  as a wallet-layer privacy weakness and closed the
  disposition as **V3.0 ships the
  `SubmissionStrategyActor` seam (intermediate actor in the
  submit path between `PendingTxActor` and `DaemonEngine`)
  with `DirectStrategy` as the V3.0 default** (matches
  wallet2 behavior; no privacy regression at V3.0 ship
  time). V3.x lands privacy-enhancing submission-strategy
  actors:
  - `JitteredSubmissionStrategy` — randomized delay within
    a configurable window; defeats single-event timing
    correlation.
  - `CircuitRotationStrategy` — request new Tor circuit
    before submission; separates submission-event identity
    from prior-connection identity.
  - `BroadcastStrategy` — submit through multiple peers
    simultaneously; defeats single-peer-eavesdrop
    attribution.
  - `BatchedStrategy` — coordinate submission timing with
    other Shekyl wallets through a coordination layer;
    defeats per-wallet timing correlation by reducing the
    population of submitters at any single timing window.

  **Trigger.** Anonymity-network deployment maturity
  (Shekyl-native Tor / Lokinet / I2P integration validated
  against the threat model); coordination-layer research
  (BatchedStrategy requires multi-wallet coordination
  infrastructure that does not yet exist); user-
  configuration UX for strategy selection.

  Cross-references:
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.4 R15 (segment 2c disposition);
  [`ANONYMITY_NETWORKS.md`](ANONYMITY_NETWORKS.md)
  (threat-model anchor).

- **Wallet-side fee estimator (`WalletSideEstimator`) under
  `FeeEstimator` trait seam (Stage 1 PR 5 R16 substrate;
  V3.x with conditional V3.0 lift).** **Phase 1 landed
  (2026-05-27):** `FeeEstimator` trait + `DaemonFeeEstimator`
  default shipped (C4γ = `df60d2424`); `WalletSideEstimator`
  trigger unchanged (`LedgerEngine` historical-block fee accessor).
  PR 5 segment 2c named
  daemon-recommended fees as a wallet-fingerprint exploit
  surface against an adversary-controlled daemon and closed
  the disposition as **V3.0 ships
  daemon-recommendation-with-explicit-override under a
  `FeeEstimator` trait-parameter seam** (default
  `DaemonRecommendationEstimator`; explicit override
  available via `ExplicitFeeEstimator` for explicit-fee
  workflows). V3.x lands `WalletSideEstimator` analyzing
  `LedgerEngine` historical block fee distribution
  directly; decouples wallet fee from daemon
  recommendation entirely; every wallet computes fees from
  the same chain-state inputs and produces statistically-
  indistinguishable outputs.

  **Conditional V3.0 lift.** If Phase 0 review (Stage 1
  PR 5 segment 2d) confirms the `LedgerEngine`
  historical-block-fee-distribution accessor cost is
  bounded and the estimator implementation is feasible at
  V3.0 review time, R16 (c) lifts to V3.0 ship.
  Segment-2c default is the conservative disposition;
  the lift is a discipline-driven amendment, not a
  reopening.

  **Trigger (V3.x default).** `LedgerEngine` historical-
  block-fee-distribution accessor cost confirmed bounded;
  fee-estimation algorithm validated against on-chain
  fingerprint analysis; fee-band-selection UX validated.
  None are V3.0 blockers under the segment-2c
  disposition; the seam preserves V3.0 shipping date.

  Cross-references:
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.4 R16 (segment 2c disposition);
  [`00-mission.mdc`](../.cursor/rules/00-mission.mdc) §2
  (privacy-as-product anchor).

- **Diagnostic-event encrypted-persistence — conditional
  reopening bookmark (Stage 1 PR 4 R17 / PR 5 R17;
  PR 4 Round 4 review pass F1 + F7 hardened, 2026-05-15).**
  PR 5 segment 2c (2026-05-14) originally framed an
  "encrypted-persistence opt-in" for `PendingTxDiagnostic`
  events as a V3.x scheduled deliverable
  (`PersistenceConsumerActor` for institutional / long-
  running / multi-day deployments). PR 4 Round 4 review
  pass F1 (2026-05-15) hardened that disposition to a
  structural rejection at V3.0, with the same six attack
  vectors named (crypto code-path expansion via persistence
  triggers; deserialization-on-startup as exploit primitive;
  metadata side-channel; cross-wallet correlation
  amplification; persistence as adversary-controlled DoS;
  forensic-attack primitive against seized wallets — full
  enumeration at PR 4 §5.4.8 #1 / §5.4.9 F1). F7 extended
  the same discipline to "encrypted cache for RPC recovery"
  candidates (PR 4 §5.4.8 #6 / §5.4.9 F7).

  **This entry is a conditional-reopening bookmark, not a
  scheduled deliverable.** No version target; closed
  automatically if V3.0 + V3.1 deployments do not surface
  the criterion-(a) use case. Reopening requires **all** of:

  - **(a) Demonstrated production use case.** Real V3.0
    deployment surface, not anticipated demand. Foundation
    treasury, institutional custody, multi-day tx
    workflows, mining-wallet long-uptime — these are
    *interesting consequences* of a reopening, not
    *triggers* for one. The trigger is the use case
    surfacing in V3.0 deployment.
  - **(b) Full threat-model review at the time of
    evaluation.** Including the metadata side-channel,
    cross-wallet correlation, deserialization-on-startup,
    forensic-artifact, and DoS attack vectors enumerated
    at PR 4 §5.4.9 F1.
  - **(c) Explicit `AUDIT_SCOPE.md` amendment.** If
    adopted, the persistence layer is brought into audit
    scope.
  - **(d) Privacy-first default supremacy
    acknowledgment.** Per
    [`00-mission.mdc`](../.cursor/rules/00-mission.mdc) §2,
    the privacy-first default discipline supersedes
    ergonomic-recovery considerations except in cases
    where (a)–(c) demonstrate the case.

  **The previous "wallet-internal encrypted-persistence
  opt-in is permitted if the consumer's surface is within
  the wallet's encrypted-state surface" framing is
  withdrawn.** PR 4 §5.4.8 #1's contract pin reverts to
  the structural drop-on-close rule. Any `V3.x` consumer
  attempting to satisfy a feature like this without
  walking the four-pronged criteria is non-compliant with
  the post-F1 hardening.

  **Segment 2h scope amendment (2026-05-26; F8 disposition
  pin).** Under the (γ) lean state shape pinned in PR 5
  segment 2h (§5.6.2), the `PendingTxActor` carries an
  `in_flight: HashMap<ReservationId, InFlightSubmit>`
  collection holding reservations awaiting daemon
  resolution. Per PR 4 §5.4.8 #1's structural drop-on-close
  rule, wallet restart during a non-empty `in_flight` drops
  the in-memory state while the daemon-side tx remains
  potentially live on-network — a re-sync-then-rebuild
  flow may re-select the same outputs and produce a
  `TerminalErrorKind::DoubleSpend` on the second submit
  (the on-chain outputs are already spent by the original
  in-flight tx that confirmed during the restart gap).
  Segment 2h §5.4 R17 explicitly accepts this consequence
  at V3.0; consumer-visible behavior is "submit appears to
  fail with double-spend; re-refresh and rebuild yields
  the post-confirmation balance." **This is the specific
  surface the encrypted-persistence opt-in would close.**
  The four-pronged reopening criteria above are unchanged;
  the segment 2h amendment names restart-during-`in_flight`
  as the specific class of (a) use case that, if surfaced
  at production scale, satisfies the criterion-(a)
  triggers. Per segment 2h §5.6.5 F8, the V3.0 disposition
  is accepted explicitly, not by oversight; the surface is
  load-bearing to the (γ) lean-state shape and the
  reopening criteria.

  Cross-references:
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.8 #1 (post-F1 hardened drop-on-close pin), §5.4.8 #6
  (encrypted-cache-for-RPC-recovery; F7 hardened
  rejection), §5.4.9 F1 / F7 (review-pass disposition);
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.4 R17 (post-F1-carryover hardened disposition;
  segment 2h F8 explicit V3.0 acceptance amendment),
  §5.6.5 F8 (restart-during-`in_flight` disposition
  substrate), §5.6.7 (V3.x FOLLOWUPS scope-grows-by
  surface naming).

- **Diagnostic-stream consumer-actor PR `diagnostic_consumer_discipline`
  CI lint (Stage 1 PR 4 Round 4 review pass F5 forward-
  template, 2026-05-15; scope-extended by F12 amendment,
  2026-05-15; V3.1+).** PR 4 §5.4.8 #4's recursive trust-
  boundary pin and §5.4.6's per-emitter FIFO contract pin
  together impose two consumer-actor disciplines that are
  type-system-unenforceable at V3.0: (i) full-fidelity
  diagnostic events flow only to actors whose external
  surface is itself within the trust boundary, **recursively**;
  (ii) consumer actors that need cross-emitter ordering
  derive it from explicit causal-context fields in the
  events (`SnapshotId`, `ReservationId` plus version,
  `BlockHeight`), not from sink-observed arrival order.
  Procedural enforcement (per-PR review checklist;
  per-consumer-actor PR external-surface audit) is the V3.0
  disposition; this entry queues the V3.1+ CI-lint
  enforcement covering both disciplines as a single
  `diagnostic_consumer_discipline` clippy-style check.

  **F5 sub-scope (recursive trust-boundary).** Static check
  that verifies any consumer binding to a `DiagnosticSink`
  either (i) declares no external surface, or (ii) declares
  its external surface carries projection-typed events only,
  never full-fidelity event types from the stream taxonomies.
  Detection shape: pattern-match on consumer-actor types
  implementing `DiagnosticSink` *and* `Write` /
  `serde::Serialize` / network-export / log-collection
  surfaces; require explicit `#[allow(diagnostic_external_surface)]`
  attribute with an inline rationale comment.

  **F12 sub-scope (cross-emitter ordering misuse).** Static
  check that verifies consumer-actor event-handler bodies
  do not branch on the relative arrival timing of events
  from distinct emitters without first constraining
  ordering via an explicit causal-context field. Detection
  shape: pattern-match on event-handler bodies that compare
  timestamps or use sink-observed arrival order across
  events whose emitter identity differs (statically-
  determinable from the event-class taxonomy plus the
  consumer's subscription set); flag such patterns and
  require either (a) a causal-context field added to the
  relevant event class with a matching update to the
  consumer's ordering derivation, or (b) explicit
  `#[allow(diagnostic_cross_emitter_ordering)]` with an
  inline rationale comment naming why per-emitter-only
  ordering is sufficient at this site.

  **Why a CI lint, not just a review process.** A
  procedural check requires every reviewer to apply the
  recursive-trust-boundary discipline and the cross-emitter
  causal-context discipline at every consumer-actor PR;
  both disciplines survive only as long as reviewer rigor
  holds. A CI lint moves both from reviewer-rigor-dependent
  to enforced-by-default, consistent with
  [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)'s
  "discipline operates with continuous coverage" framing.
  The lint becomes load-bearing as the consumer-actor
  ecosystem grows beyond what a single reviewer can hold
  in working memory; the F12 sub-scope catches a class of
  bug (deadlock or misbehave-under-reordering) that audit
  finds late and that CI catches immediately.

  **Implementation candidates.** A `clippy` lint targeting
  consumer constructors (`fn new(..., sink: Arc<dyn
  DiagnosticSink>)`); a per-crate `#[deny(...)]` directive
  with a project-defined `diagnostic_consumer_discipline`
  lint; a CI script over `cargo expand` output looking for
  full-fidelity event types crossing IPC / log / metrics
  boundary types and for cross-emitter timing comparisons
  in event-handler bodies.

  **The lint is conceptual, not necessarily monolithic
  (Stage 1 PR 4 Round 4 review pass meta-review post-
  amendment, 2026-05-15; F12 sub-pin).** The unification is
  at the contract level (one named discipline,
  `diagnostic_consumer_discipline`, two related properties
  it enforces), not necessarily at the implementation-pass
  level. The F5 sub-scope (recursive trust-boundary) is a
  type-level property — likely realized as a compile-time
  trait-bound or `clippy` lint over consumer constructors;
  the F12 sub-scope (cross-emitter ordering misuse) is a
  code-pattern property — likely realized as an AST-level
  pattern-match over event-handler bodies. The V3.1+
  consumer-actor PR may land them as two related checks
  under one configuration namespace rather than as a
  single literal lint pass; either factoring satisfies the
  contract. Pinned here so a future "the lint doesn't
  exist as a single pass" finding cannot retroactively
  invalidate a multi-check implementation that delivers
  the unified discipline.

  **Trigger.** When the second consumer actor enters
  design rounds (`ReorgAmplificationDetector` and
  `PeerReputationActor` together exhaust the single-
  consumer case where reviewer attention is sufficient;
  the multi-consumer case is where the CI lint pays back —
  per F12, the cross-emitter sub-scope specifically
  activates because two consumers with distinct
  subscription sets create the substrate the misuse
  pattern needs).

  Cross-references:
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.8 #4 (recursive trust-boundary pin + V3.x forward-
  template, items 1–4 including F12 cross-emitter
  scope-extension), §5.4.6 7th contract pin (per-emitter
  FIFO + cross-emitter undefined + F12 enforcement-gap
  amendment), §5.4.9 F5 (recursive-trust-boundary
  review-pass disposition), §5.4.9 F12 (cross-emitter
  contract-gap meta-finding); consumer-actor PR template
  (FOLLOWUPS entry above). Target: V3.1+.

- **Diagnostic-stream specification document — projection-
  type formalization per event class (Stage 1 PR 4 Round 4
  review pass F9 forward-template, 2026-05-15; V3.x).**
  PR 4 §6 (Round 4 review pass F9) records the V3.0
  per-class projections for `TracingDiagnosticSink`
  (`RefreshDiagnostic` projection set, `PendingTxDiagnostic`
  projection set, `LedgerDiagnostic` projection set). The
  F9 forward-template names the work to formalize these
  projections in `DIAGNOSTIC_STREAM.md` (per the existing
  V3.x spec-doc deliverable above) as a per-consumer
  audit obligation: every consumer-actor PR must declare
  its projection function for each event class it
  consumes, listing exactly which fields are elided for
  cross-boundary surfaces and naming the security property
  the elision delivers (anti-fingerprinting, anti-
  correlation, anti-timing-leak, etc.).

  **Why formalization rather than per-PR review.** Without
  formalization, every consumer-actor PR re-derives
  projection-type semantics from PR 4 §5.4.8 #4 prose; the
  re-derivation drift produces inconsistent projections
  across consumers (the same event class projected
  differently by `TracingDiagnosticSink` vs. a future
  `MetricsExportSink`). The formalization establishes a
  canonical projection function per event class that
  consumers compose against; per-class deviation requires
  explicit justification at the consumer's introduction
  PR.

  **Trigger.** When the V3.x consumer-actor design rounds
  begin (concurrent with the F5 CI-lint trigger above);
  earlier if the spec doc itself materializes before the
  first consumer-actor PR.

  Cross-references:
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §6 (V3.0 per-class projections under §6 review checklist),
  §5.4.9 F9 (review-pass disposition);
  diagnostic-stream specification document (FOLLOWUPS
  entry above). Target: V3.x (concurrent with first
  consumer-actor PR).

- **Sync refresh wrapper generalization over `L: LedgerEngine`.**
  Stage 1 PR 2 generalized `Engine::start_refresh` and the
  producer task `run_refresh_task` over `L: LedgerEngine` —
  sufficient generalization for the hybrid retry test to dispatch
  through the trait against `MockLedger`. The synchronous wrappers
  `Engine::refresh` and `Engine::refresh_with` retain their
  `LocalLedger`-specialized impl block because the trait method
  `LedgerEngine::apply_scan_result` is `async fn` and the sync
  entry points use `LocalLedger::write()`'s inherent (synchronous)
  guard directly. Threading a Tokio runtime handle through the
  sync wrappers, or alternatively introducing a sync-mutator
  surface on the trait (`fn apply_scan_result_blocking(&self,
  …)`), would generalize the wrappers over `L`. Either path
  requires its own design pass — neither is required for any
  Stage 1 PR's hybrid coverage, and both would expand the
  trait-surface attack area without an immediate consumer. Queued
  at V3.x; resolved by either a runtime-handle threading story
  (likely co-landing with Stage 4 actor wiring, where `kameo` is
  already in scope and the runtime handle is available) or an
  alternative trait-shape decision.   Cross-references:
  [`docs/design/STAGE_1_PR_2_LEDGER_ENGINE.md`](design/STAGE_1_PR_2_LEDGER_ENGINE.md)
  §1.2 (partial-generalization framing) and §7 (out-of-scope
  refinement). Target: V3.x.

- **`run_refresh_task` holds the engine read-guard across
  `apply_scan_result.await`.** Stage 1 PR 2's `run_refresh_task`
  in `engine/refresh.rs` performs the merge dispatch as
  `{ let g = engine_arc.read().await; g.ledger.apply_scan_result
  (result).await }`, holding the outer `tokio::sync::RwLock` read
  guard on `Engine` for the duration of the trait-method future.
  This is correct for Stage 1's `LocalLedger` and `MockLedger`
  implementors, both of whose `apply_scan_result` futures are
  wholly synchronous bodies (no `.await`) so the engine read-guard
  is held only as long as a synchronous merge call would take.
  Stage 4's actor-backed `LedgerEngine` implementor (per
  [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
  §1.5 / §2.8) will route through a `kameo` `ask` that genuinely
  awaits, which would extend the engine read-guard hold time and
  could starve writers waiting on the engine write-lock. The fix
  shape is to decouple the merge-future construction from the
  outer engine guard: clone an `Arc<L>` (where `L: LedgerEngine`
  is reachable through the `Engine` field via shared ownership) so
  the outer guard can be dropped before the trait-method future is
  awaited. Today the `Engine` owns `L` directly rather than through
  `Arc<L>`, so the refactor lands with Stage 4's actor wiring
  (where the `Arc<ActorRef<…>>` shape is the natural fit and the
  ownership rework happens once for all per-trait implementors,
  not per-trait). Surfaced via Copilot review on PR #26 (Stage 1
  PR 2). Cross-references:
  [`docs/design/STAGE_1_PR_2_LEDGER_ENGINE.md`](design/STAGE_1_PR_2_LEDGER_ENGINE.md)
  §3.4 (engine ownership of `L`) and §5 commit-7 row
  (refresh-path generalization scope). Target: V3.x — co-lands
  with Stage 4 `LedgerEngine` actor cutover.

- **`LedgerReadGuard` field type leaks crate-private
  `LedgerState`.** Stage 1 PR 2's `LedgerReadGuard` in
  `engine/mod.rs` carries a `std::sync::RwLockReadGuard<'a,
  LedgerState>` field, where `LedgerState` is `pub(crate)` in
  `engine/local_ledger.rs`. The field itself is private (no
  `pub`), so the `private_interfaces` lint does not fire today —
  the `pub(crate)` type only appears in private field positions,
  not in the public API surface. However, two related concerns
  remain visible: (a) `cargo doc --document-private-items` emits
  a "public documentation for `LedgerReadGuard` links to private
  item `local_ledger::LedgerState`" warning when the doc comment
  references `LedgerState` via intra-doc link (the doc-link was
  removed in the Copilot review-2 commit, but the underlying
  field-type structure still names the private type); and (b) a
  future stricter Rust edition or lint-policy change could promote
  `private_interfaces` to flag any private-type appearance in a
  public struct's body, including private fields. The fix shape
  is to project the inner guard directly to `WalletLedger` so
  `LedgerState` no longer appears in the field type. Two
  candidate paths:

  1. **`std::sync::RwLockReadGuard::map`** — once the
     `mapped_lock_guards` feature stabilizes (tracked at
     [rust-lang/rust#117108](https://github.com/rust-lang/rust/issues/117108)),
     `MappedRwLockReadGuard<'a, WalletLedger>` becomes the
     stable-only field type and the structural concern is
     fully resolved without adding a dependency.
  2. **`parking_lot::RwLock`** — switching `LocalLedger`'s
     state lock to `parking_lot::RwLock` gives us
     `MappedRwLockReadGuard` immediately, but adds a new direct
     dependency to the engine crate (today `parking_lot` is a
     transitive dep only). The dependency cost is borderline
     acceptable for a single guard projection; if other
     parking_lot features prove useful (e.g., poisoning-free
     locks, fairness controls) the case strengthens.

  Surfaced via Copilot review on PR #26 (Stage 1 PR 2). The
  workaround in PR 2 is the doc-only fix: drop the broken
  intra-doc link target so the rustdoc warning silences while
  the field-type structure stays the same. Cross-references:
  [`docs/design/STAGE_1_PR_2_LEDGER_ENGINE.md`](design/STAGE_1_PR_2_LEDGER_ENGINE.md)
  §3.4 (engine ownership / visibility decision tree).
  Target: V3.x — gated on `mapped_lock_guards` stabilization
  (preferred) or a separate decision to adopt
  `parking_lot::RwLock` workspace-wide (alternative). No
  hard deadline; not blocking any consumer or audit finding.

- **Stage 4 lifecycle async cutover requires `CHANGELOG.md`
  flagging.** Per
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.8.7 (lifecycle async-public reversal at Stage 4), the Stage 4
  cutover PR changes `Engine::create` and the `open_*` constructors
  from sync-public to async-public. This is a public-API signature
  change, even though it preserves the trait-surface invariants per
  §7 (lifecycle is inherent, not trait, so §7's invariants don't
  apply to it). The cutover commit must include a `CHANGELOG.md`
  `[Unreleased]` entry under "Changed" calling out the signature
  change explicitly:

  > ```
  > ### Changed
  > - **BREAKING:** `Engine::create`, `Engine::open_existing`,
  >   `Engine::open_view_only`, and `Engine::open_hardware_offload`
  >   are now `async fn` (previously sync). Callers must `.await`
  >   these constructors. Path B / Stage 4 cutover; see
  >   `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §2.8.7.
  > ```

  This entry exists so the Stage 4 cutover author remembers to
  update `CHANGELOG.md` at the cutover commit specifically — not
  later, not implicitly. Close-condition: Stage 4 cutover ships
  with the `CHANGELOG.md` entry above (or equivalent). Target:
  V3.x (Stage 4 cutover phase).

- **Stage 5 — `ArchivalEngine` native actor build (simulation-
  gated).** Build the staker-distributed chain-history archival
  service as a native actor, sibling to `StakeEngine` (not a
  child). The `ArchivalEngine` owns shard storage + serving + the
  archival-yield disbursement state machine; receives shard
  registration, query, and challenge-response messages; produces
  archival-yield events on a separate slashing domain from
  principal-yield. Cross-actor query
  `StakeEngine::is_active_staker(entity_id) -> bool` gates
  archival eligibility (a non-staker cannot serve archival; the
  gate is the message, not shared state). The `LedgerEngine`
  consumes `ArchivalEvent` values via the merge protocol the same
  way it consumes `StakeEvent` values.

  *Why sibling, not child of `StakeEngine`:* slashing-domain
  integrity (a bug in archival logic that slashes archival-yield
  cannot be misrouted to slash principal-yield if the engines
  share state); failure isolation (`ArchivalEngine` has more
  failure modes — network partitions on archival queries, shard
  storage corruption, challenge-response timeouts — and a failing
  `ArchivalEngine` must not bring down stake state); and the
  Hayekian shard-market property (the shard market priced by
  scarcity and opted into by stakers is conceptually distinct
  from stake lifecycle and benefits from independent supervision
  + message ordering).

  *Why Stage 5 (own stage), not Stage 3/4:* `ArchivalEngine` has
  substantially more open design questions than `StakeEngine`
  (shard granularity, query routing protocol, price curve shape,
  anonymization integration, foundation-node coordination).
  Pairing it with `StakeEngine` in Stage 3 would force design
  closure on archival before the simulation work has produced
  evidence; Stage 4 sequencing would intermix it with smaller
  subsystems that don't share its design risk. A dedicated stage
  with explicit gating ("simulation work has settled the open
  design questions") is the discipline-correct shape.

  *Blocks on:* simulation work per `docs/V3_STAKER_ARCHIVAL.md`
  has settled shard granularity, price curve shape, and routing
  protocol. Stage 4 RPC boundary refinements (multi-peer archival
  routing client surface) have shipped the client-side
  groundwork.

  *Target:* V3.x — first dot-release after simulation closes the
  design questions. No fixed deadline; gated on evidence quality.

  *Definition of done:* `ArchivalEngine` runs as a `kameo` actor
  with its own task; sibling to `StakeEngine` (no shared state);
  cross-actor `is_active_staker` query exposed and tested; shard
  registration, query, and challenge-response message protocols
  documented and tested; archival-yield slashing domain
  separated from principal-yield (independently testable);
  `assemble_tree_path_for_output` RPC routing activates the
  multi-peer client surface against staker peers; integration
  tests cover staker-distributed historical reference queries on
  a multi-staker testnet; stressnet (Phase 7.7) exercises the
  path. Decision log entry confirms the migration is complete and
  pins resulting architecture.

  *Reference:* `docs/V3_STAKER_ARCHIVAL.md` (canonical archival-
  mechanism design home); `docs/V3_WALLET_DECISION_LOG.md`
  *2026-04-27 — Engine architecture: actor model with staged
  migration*; `docs/V3_SHARD_VISUALIZATION.md` (companion shard-
  surface design); the V3.0 V3.0 sibling resolution entry above
  for `assemble_tree_path_for_output`.

- **No-tradeability invariant codification (placeholder).** The
  shard visualization in `docs/V3_SHARD_VISUALIZATION.md` is
  deterministic data art derived from public shard content. It
  must remain not-tradeable: it is not an NFT, has no
  per-instance scarcity, no transferable ownership, no
  on-chain registration. The visualization is reproducible from
  the shard content alone — possession of the shard is possession
  of the visual. This is a structurally load-bearing economic
  invariant (privacy-architecture commitment + economic-shape
  commitment); its enforcement points must be enumerated and
  codified when archival/visualization implementation begins.

  *Suggested enforcement point inventory at implementation:*
    - Library API surface in `shekyl-shard-visual`: no functions
      that mint, register, sign, or otherwise endorse an instance
      of a visualization. Pure
      `(shard_content) -> deterministic_image` only.
    - Wallet/daemon RPC surface: no methods that "own,"
      "transfer," "claim," or "register" visualizations.
    - Foundation messaging discipline: external materials must
      not market shard visualizations as collectibles or trade-
      able digital assets.
    - Block explorer / portfolio integrations: render-on-demand
      from the shard, not stored-and-served by per-user
      identifier.

  *Target:* V3.x — codified as enforced constraint when the
  archival/visualization implementation lands.

  *Definition of done:* enforcement point inventory complete;
  each enforcement point has a documented mechanism (test, lint,
  documentation rule, or design-time invariant); decision log
  entry pins the invariant as canonical.

  *Reference:* `docs/V3_SHARD_VISUALIZATION.md` (canonical
  visualization design home); `docs/V3_STAKER_ARCHIVAL.md`
  (companion archival design that produces the shards).

---

## V4+ — horizontal scaling

- **Horizontal scaling via stateless actor pools.** Once the
  actor architecture is settled and Stage 5 has shipped, scale
  stateless components (subaddress derivation, scan workers,
  proof verification) by running multiple instances of the
  actor and load-balancing requests across them. Stateful actors
  (`KeyEngine`, `LedgerEngine`, `StakeEngine`, `ArchivalEngine`)
  remain singletons; stateless ones become pools.

  *Blocks on:* Stage 5 `ArchivalEngine` shipped; production
  deployment data on which subsystems are CPU-bound vs message-
  bound. Premature pooling is over-engineering.

  *Target:* V4+ — driven by deployment evidence, not speculation.

  *Reference:* `docs/V3_WALLET_DECISION_LOG.md` *2026-04-27 —
  Engine architecture: actor model with staged migration*
  §"Future-version benefits enabled by actor architecture".

---

## V5+ — long-tier staker upgradability

- **Signed actor-patch distribution over staker P2P.** Long-tier
  stakers (multi-year locks) need an upgrade path that does not
  require unstake-and-restart for every bug fix or minor protocol
  evolution; a one-week lock-tier disruption for a one-line
  patch is operationally untenable at scale. The actor model
  (settled in V3.x) **enables** signed-patch distribution as the
  upgrade primitive: individual actors can be replaced
  independently while the rest of the engine continues running.

  V3 and V4 deliberately use the simpler restart-based upgrade
  path (operator runs a new binary, stake state recovers from
  chain). Hot-loading is a V5+ feature; the architecture from
  V3.0 must not foreclose it, but no V3 or V4 surface depends on
  it. The cost of getting hot-loading wrong (silent state
  corruption, signature-bypass, partial-upgrade inconsistency)
  is severe enough that this lands only when the underlying actor
  architecture has years of production evidence and the upgrade
  protocol has its own formal review.

  *Suggested protocol shape (subject to design review at V5
  planning):*
    - Foundation (or post-Foundation governance) signs actor
      patches with a release key.
    - Patches distribute over the staker P2P network (the same
      network archival uses).
    - Stakers verify the signature before loading; verified
      patches replace the corresponding actor in-place; the
      rest of the engine continues running.
    - Patch protocol covers: actor binary delta, message-protocol
      compatibility metadata (ABI version), and rollback
      manifest for failed patches.
    - Slashing-domain isolation property is preserved across
      patches: a patch to `ArchivalEngine` cannot affect
      `StakeEngine`'s slashing decisions.

  *Blocks on:* V3 and V4 in production with the actor
  architecture stable for at least one full V3.x cycle; formal
  protocol review of signed-patch distribution; threat model
  covering patch-supply-chain attacks.

  *Target:* V5+ — no fixed deadline; driven by accumulated
  evidence + governance maturity.

  *Reference:* `docs/V3_WALLET_DECISION_LOG.md` *2026-04-27 —
  Engine architecture: actor model with staged migration*
  §"Long-tier staker upgradability" (V5+ benefits enabled,
  V3/V4 restart-based path).

---

## TBD — vendor- or standardization-dependent

- **PQC Multisig V3.1: hardware wallet integration.**
  Current hardware wallets (Coldcard, Trezor, Ledger, Jade) cannot
  support V3.1 multisig signing. Constraints:
  1. **ML-DSA-65 computation cost.** Signing takes ~100ms on modern
     desktop CPUs. On Cortex-M class MCUs (ARM Cortex-M4 @ 120MHz),
     ML-DSA-65 signing is estimated at 1–5 seconds. ML-KEM-768
     decapsulation is faster (~50ms on Cortex-M4) but still significant.
     Coldcard Mk4 (STM32H753, 480MHz Cortex-M7) may be the first viable
     target.
  2. **Screen constraints.** Hardware wallet displays are typically
     128×64 pixels. The signing payload (§10.4 of `PQC_MULTISIG.md`)
     should be representable as: "Sign intent {hash_prefix} sending
     {amount} SKL to {address_prefix}, fee {fee}". The intent_hash is
     32 bytes; showing a 4-byte prefix is sufficient for verification.
  3. **Signing payload self-containment.** The §10.4 canonical signing
     payload is already self-contained — no network calls are needed
     during signing. A hardware wallet can verify the payload offline
     given only the persisted output state. This is by design and must
     not change.
  4. **Vendor outreach.** Recommend the Foundation contact Coinkite
     (Coldcard) and Blockstream (Jade) during V3.1 launch. Both have
     shown interest in post-quantum cryptography. Trezor and Ledger
     have larger teams but longer decision cycles.
  5. **Protocol impact:** none. V3.1 is designed so hardware wallet
     integration requires no protocol changes. The signing payload and
     hybrid signature format are stable.

  Status: documentation complete. Code work deferred to V3.2 at
  earliest; actual vendor integration timeline is vendor-controlled.

- **Hardware-wallet BIP-39 derivation parity (vendor- and
  standardization-dependent; hardware-wallet integration
  workstream).** Shekyl's host-side BIP-39 path
  (`shekyl_account_generate_from_bip39` per
  [`rust/shekyl-ffi/src/account_ffi.rs`](../rust/shekyl-ffi/src/account_ffi.rs))
  must produce the same Shekyl account that an eventual Trezor /
  Ledger / Coldcard / Jade firmware would derive when given the
  same 24-word BIP-39 phrase + passphrase. Cross-platform
  recovery requires alignment across four dimensions:

  1. **SLIP-0044 coin type.** Shekyl needs either a registered
     SLIP-0044 coin type or a self-claimed one in the unregistered
     range. The decision is registration-dependent (SatoshiLabs's
     SLIP-0044 maintenance is the standardization gate).
  2. **BIP-44 derivation path.** The
     [`account_base::generate_from_bip39`](../src/cryptonote_basic/account.cpp)
     pipeline (entropy → cSHAKE-256 normalize → spend/view secret
     derivation per
     [`docs/design/STAGE_1_PR_3_KEY_ENGINE.md`](./design/STAGE_1_PR_3_KEY_ENGINE.md)
     §7.12) must match what the device firmware derives at the
     corresponding `m/44'/<coin-type>'/<account>'/<change>/<index>`
     path. Today's pipeline is Shekyl-specific (PBKDF2-HMAC-SHA512
     → cSHAKE-256, not BIP-32 → BIP-44); the device firmware would
     need to mirror it, OR the host pipeline would need to add a
     BIP-32 → BIP-44 layer.
  3. **Network identifier interaction.** Mainnet / Stagenet /
     Testnet network discriminators must enter the derivation in
     the same way on host and device, or the same phrase derives
     three different accounts depending on which network the
     wallet was created against.
  4. **Passphrase semantics.** The host implements BIP-0039 §A
     standard passphrase semantics (passphrase concatenated into
     PBKDF2 salt); the device must implement the same. Trezor's
     "hidden wallet" passphrase semantics match; Ledger's vary by
     firmware version.

  **Why this is not Electrum-words-removal-scope.** None of
  these alignment dimensions are mnemonic-encoding questions;
  they exist regardless of whether Shekyl uses BIP-39,
  Electrum-words, or any other mnemonic scheme. They belong to
  the hardware-wallet integration workstream, which does not
  yet have a substrate document. Per
  [`docs/design/ELECTRUM_WORDS_REMOVAL.md`](./design/ELECTRUM_WORDS_REMOVAL.md)
  §4.10's "Hardware-wallet BIP-39 derivation parity"
  sub-paragraph, B-1 does not introduce the question and does
  not resolve it.

  **Cleanup scope.** Authoring `docs/HARDWARE_WALLETS.md`
  (substrate doc for the hardware-wallet integration workstream)
  is the prerequisite. The four alignment dimensions above
  become §-level dispositions in that doc, with cross-references
  back to this FOLLOWUPS entry once landed. Vendor outreach
  (Coinkite, Blockstream, Trezor, Ledger) is the same outreach
  cohort named by the PQC multisig hardware-wallet integration
  entry above; the two workstreams should likely share vendor
  conversations and `HARDWARE_WALLETS.md` should absorb both
  surfaces under a unified substrate.

  **Severity.** Forward-impact-grade. The cross-platform
  recovery story breaks silently if alignment is wrong:
  a user generates a phrase on shekyl-gui-wallet, records it,
  buys a Trezor at firmware support time, restores from the
  phrase, and gets a different Shekyl account. The failure is
  invisible to the user until they realize the restored wallet
  doesn't see their UTXOs. This is exactly the failure shape
  hardware-wallet recovery is supposed to prevent.

  **Reversion criterion** (per
  [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)).
  Reopened when (a) the hardware-wallet integration workstream
  opens with substrate authoring (`HARDWARE_WALLETS.md`), at
  which point this entry is migrated into the new substrate
  doc's disposition tables, or (b) a vendor commits to Shekyl
  firmware support (forcing the alignment decision regardless
  of substrate-doc readiness), or (c) the
  `shekyl_account_generate_from_bip39` pipeline changes shape
  in a way that affects derivation alignment (e.g., the cSHAKE
  customization string changes per
  [`docs/design/STAGE_1_PR_3_KEY_ENGINE.md`](./design/STAGE_1_PR_3_KEY_ENGINE.md)
  §7.12), forcing fresh alignment analysis.

  **Cross-references.**
  [`rust/shekyl-ffi/src/account_ffi.rs`](../rust/shekyl-ffi/src/account_ffi.rs)
  (host-side `shekyl_account_generate_from_bip39`);
  [`rust/shekyl-crypto-pq/src/bip39.rs`](../rust/shekyl-crypto-pq/src/bip39.rs)
  (host-side BIP-39 entropy / seed derivation);
  [`src/cryptonote_basic/account.cpp`](../src/cryptonote_basic/account.cpp)
  (account-keys derivation from seed);
  [`docs/design/STAGE_1_PR_3_KEY_ENGINE.md`](./design/STAGE_1_PR_3_KEY_ENGINE.md)
  §7.12 (cSHAKE-256 pipeline that's downstream of BIP-39 in
  Shekyl's host-side derivation);
  [`docs/design/ELECTRUM_WORDS_REMOVAL.md`](./design/ELECTRUM_WORDS_REMOVAL.md)
  §4.10 ("Hardware-wallet BIP-39 derivation parity"
  forward-reference sub-paragraph);
  the PQC multisig hardware-wallet integration entry above
  (same vendor outreach cohort).

  Status: substrate-pending. `docs/HARDWARE_WALLETS.md`
  authoring is the prerequisite; vendor outreach is vendor-controlled
  beyond that.

---

## Long-lived utilities (no target version required)

These items document intentional decisions rather than pending work. They
stay here as a reference; closing them is equivalent to deleting this
reference.

- **`dalek-ff-group` version isolation enforced via CI gate.**
  The Rust workspace carries two versions: 0.5.x (used directly by
  Shekyl crates) and 0.4.x (pulled transitively by vendored
  serai/`ciphersuite` internals). A CI grep gate in
  `.github/workflows/build.yml` checks all Shekyl crates
  (`shekyl-ffi`, `shekyl-fcmp`, `shekyl-crypto-pq`, `shekyl-proofs`,
  `shekyl-tx-builder`, `shekyl-scanner`, `shekyl-engine-rpc`,
  `shekyl-daemon-rpc`) and asserts that none of their normal dependency
  trees pull in 0.4. Direct `dalek_ff_group` usage in source is printed
  for visibility but does not fail (legitimate 0.5 usage is expected).
  The 0.4 version must stay hidden behind `Ciphersuite` trait
  abstractions (`<Ed25519 as Ciphersuite>::G`, etc.). Never reach into
  `ciphersuite`'s internals. If upstream `ciphersuite` upgrades to
  `dalek-ff-group` 0.5, remove the gate.

- **`sha2` 0.10.x has no `zeroize` feature; HKDF-SHA256 chaining-state
  residency is documented-acceptance per the reversion-clause
  discipline.** Phase 0 Mission Audit Lens D, finding D-6 (per
  [`.cursor/rules/21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)).
  Audit-at-source verification confirmed `sha2` 0.10.x has no
  `zeroize` feature or optional dep at all — in contrast to sibling
  `sha3` 0.10.x, which carries `zeroize` as an optional dep and which
  `shekyl-crypto-pq` already enables. HKDF-SHA256 derivation of
  secret material via the workspace's `hkdf` consumers
  (`shekyl-crypto-pq`, `shekyl-engine-prefs`, `shekyl-proofs`) leaves
  a per-call residency window in the SHA-256 internal chaining state
  (~32 bytes per `Sha256` instance; SHA-256 is Merkle–Damgård, not a
  sponge — the residency is the eight 32-bit chaining words plus the
  block buffer, not Keccak-style absorb/squeeze state). The derived
  material itself is held in `Zeroizing<…>` by the caller; no
  shekyl-side wrapper.

  *Rejected alternatives.* **(a)** Upstream-contribute `zeroize`
  feature to RustCrypto `sha2` is the right long-term answer and is
  pursued as a separate non-blocking workstream; not gating Shekyl
  audit closure on upstream review timeline. **(b)** A shekyl-side
  wrapper around `Sha256` with `Drop` overwrite breaks the upstream
  abstraction boundary, introduces version-bump fragility (sha2's
  internal layout could shift across minor versions in ways the
  wrapper depends on), and delivers marginal exposure reduction
  (~32 bytes vs D-10's Argon2id 64 MiB buffer concern, which is the
  real-volume risk and is addressed separately via D-10's
  zeroize-feature enablement on `argon2`).

  *Reversion criteria* (either suffices to reopen the disposition;
  both named explicitly so future audit cannot mistake the
  disposition for a hard refusal — mirroring the `AllKeysBlob`
  Not-Clone precedent at
  [`rust/shekyl-crypto-pq/src/account.rs:480-494`](../rust/shekyl-crypto-pq/src/account.rs)
  and the
  [`docs/design/STAGE_1_PR_3_KEY_ENGINE.md`](./design/STAGE_1_PR_3_KEY_ENGINE.md)
  §5.4.8 #1 reject-with-reopening precedent):

  1. **Upstream `sha2` adds a `zeroize` feature** (in any minor or
     major version). The workspace declarations in `shekyl-crypto-pq`,
     `shekyl-engine-prefs`, and `shekyl-proofs` adopt
     `features = ["zeroize"]` and this disposition closes as fixed.
  2. **A specific exposure pathway is identified that elevates the
     residency window beyond the per-call SHA-256 chaining state.**
     Examples: a fault-injection, memory-snapshot, or other attack
     model that can observe the chaining state after `finalize()`
     returns under conditions reachable by the threat model. The
     pathway must be specific (named threat vector plus
     memory-locality analysis), not speculative.

  *Cross-references.*
  [`.cursor/rules/17-dependency-discipline.mdc`](../.cursor/rules/17-dependency-discipline.mdc)
  §3 "Property existence" — `sha2` is the canonical example of a
  security-load-bearing dep whose property is absent at source,
  surfaced by audit-at-source verification rather than training-data
  recall. Sibling reversion-clause entry: V3.0 queue `Hybrid* secret
  types: Vec<u8> for fixed-size scalars`. The dependency-discipline
  lens surfaced three concentrated instances of the reversion-clause
  pattern (D-6 sha2 acceptance criteria, D-19 directional disposition
  for `Box<fips204::ml_dsa_65::PrivateKey>`, the D-1 /
  D-fips204-discipline naming-pattern amendment to rule 17); the
  meta-pattern is hardening into project-wide substrate across
  altitudes (type-derivation, design-round closure, work-item
  placement, dependency-discipline).

- **F.8-sub: exhaustive constant-time + secret-handling spot-check
  deferred with three named triggers per reversion-clause
  discipline.** Phase 0 Mission Audit Lens F, finding F.8 categorical
  verification (per
  [`.cursor/rules/21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)
  and
  [`.cursor/rules/30-cryptography.mdc`](../.cursor/rules/30-cryptography.mdc)
  §"Constant-time and trusted randomness"). The Lens F categorical
  verification confirmed (a) zero production CSPRNG-bypass uses
  (`thread_rng` / `StdRng` / `SeedableRng::seed_from` / `rand::random`
  absent from production code; 3 bench/test uses all properly
  justified inline); (b) CSPRNG sources verified across Rust
  (`OsRng`) and C++ (`/dev/urandom` on Unix per
  [`src/crypto/random.c:70-72`](../src/crypto/random.c) and
  `CryptGenRandom` on Windows per the same file's Win32 branch); and
  (c) `subtle::ConstantTimeEq` usage concentrated where load-bearing
  (shekyl-oxide crypto crates + `shekyl-engine-prefs/src/io.rs` for
  HMAC tag verification). The categorical verification is sufficient
  for V3.0 audit-readiness.

  *Exhaustive verification scope deferred.* A per-site walk for
  (1) any production comparison of secret/auth bytes that bypasses
  `subtle::ConstantTimeEq` in favor of bare `==` on byte arrays, and
  (2) any production `log::error!` / `format!` / `Display for
  SecretType` site that could exfiltrate secret material through
  log/error paths, is **deferred** as exhaustive-verification work
  that doesn't gate V3.0 audit closure.

  *Trigger criteria* (any one suffices to fire F.8-sub work; all
  three named explicitly so future audit cannot mistake the
  disposition for indefinite deferral — mirroring the
  acceptance-criteria precedent established by the D-6 `sha2`
  no-`zeroize` entry above ("`sha2` 0.10.x has no `zeroize`
  feature — accept-with-reversion-clause + parallel upstream
  workstream")):

  1. **External audit feedback.** If the V3.0 external audit
     surfaces a constant-time-comparison concern at any specific
     site, F.8-sub's methodology becomes the response artifact:
     walk the site's call surface, walk adjacent comparison sites
     under the same crate, document each as compliant or remediate.
  2. **New cryptographic primitive landing.** Any V3.x addition
     that introduces new secret-comparison or secret-formatting
     surfaces (new PQC primitive when V4 lattice-only NIST
     standardization closes; hardware-wallet integration per the
     V3.x C-1 disposition; FROST signing implementation per the
     B-3 Site 3 canonical-protocol-shape pin) triggers F.8-sub
     against the new surface as a per-PR pre-flight check.
  3. **Discipline-drift signal.** If a future PR review surfaces a
     single instance of `==` on secret material or `format!` on a
     secret-bearing type in production code, F.8-sub broadens to
     the surrounding crate to confirm the instance is isolated
     (not the visible tip of a larger discipline-drift pattern).

  *Why this shape vs. exhaustive-now.* Exhaustive constant-time
  walks return diminishing security per unit auditor-attention once
  the categorical disciplines are verified (CSPRNG source, type-
  enforced `subtle::ConstantTimeEq` at known load-bearing sites).
  The Lens F substrate-compounding observation applies: per-site
  walks that don't have a triggering signal produce mostly
  verification-confirmations rather than novel findings. The three
  named triggers cover the cases where per-site work is actually
  load-bearing (specific audit feedback, specific new-surface
  landing, specific drift signal) without spending pre-genesis
  audit-attention on speculative walks.

  *Cross-references.*
  [`.cursor/rules/30-cryptography.mdc`](../.cursor/rules/30-cryptography.mdc)
  §"Constant-time and trusted randomness" (the rule being deferred
  to triggers rather than exhaustively verified now);
  [`.cursor/rules/21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)
  (deferral shape: rejected-with-named-reopening-criteria);
  [`docs/CPP_INHERITANCE_INVENTORY.md`](./CPP_INHERITANCE_INVENTORY.md)
  (C++ secret-handling-adjacent files inventoried; trigger 2's
  "new cryptographic primitive" includes the F.C++-3 keep-
  transitional set when those files are migrated to Rust).

- **`shekyl-daemon-rpc/src/main.rs` uses `eprintln!` intentionally.**
  The standalone binary is a stub that exits with an error. No logging
  framework is initialized at that point. When standalone mode is
  implemented, replace with `tracing::error!` and proper logger init.
  This note is informational — there is no open action until standalone
  mode is specified.

- **`shekyl-economics-sim` uses `eprintln!` for CLI progress.**
  This is a batch CLI tool that writes JSON to stdout and progress to
  stderr. `eprintln!` is idiomatic for this pattern. No change planned;
  revisit only if the sim gains a long-running mode where structured
  logging is warranted.

---

## Recently resolved (audit trail)

Retained for citation in review; each links to the canonical record.

- **RandomX v2 Phase 2g "Investigate `shekyl-pow-randomx::compute_hash`
  divergence from C reference at large data sizes" — substrate-
  triage closure (closed 2026-05-26, resolution staged on
  `chore/randomx-v2-c-oracle-flag-v2`; merge SHA backfilled on
  `dev` merge).** Phase 2g's C7 smoke test surfaced a byte
  divergence between
  [`shekyl-pow-randomx::compute_hash`](../rust/shekyl-pow-randomx/src/vm.rs)
  and the C reference (`randomx-v2-sys::randomx_calculate_hash`).
  The investigation entry hypothesized "per-chunk Blake2b seed
  expansion or the AES-round chain across multi-chunk inputs"
  as the most likely Rust-side failure modes; the actual root
  cause was a substrate misconfiguration on the C side. The
  harness's C oracle (`c_oracle.rs::COracleSession`) and the
  canonical-output generator (`gen_canonical_outputs.rs`) both
  called `randomx_create_vm(RANDOMX_FLAG_DEFAULT, ...)`, which
  selects v1 (PROGRAM_SIZE = 256), against a Rust verifier
  implementing v2 (PROGRAM_SIZE = 384). The divergence was
  systematic by construction at every data size that triggered
  an opcode-stream long enough for v1/v2's PROGRAM_SIZE delta
  to register in the AES-round chain; T16's static 192-byte
  spec-vector fixture happened to land below that threshold
  and pass, masking the substrate gap until C7's nightly-
  cadence corpus pushed past it.

  **Triage trajectory.** The diagnostic branch
  `arbeit/randomx-v2-compute-hash-divergence-diagnostic`
  landed a single ignore-gated test
  ([`tests/divergence_triage.rs`](../rust/shekyl-randomx-differential/tests/divergence_triage.rs))
  that runs T16's seedhash + data triple through Rust, through
  the C oracle, and against the T16 static fixture, producing
  Outcome A (three-way agreement) / Outcome B (Rust ≡ fixture;
  C oracle diverges) / Outcome C (anything else). The first
  run produced Outcome B, which inverted the
  Rust-is-suspect hypothesis: Rust matched the static fixture
  byte-for-byte; only the C oracle diverged. T16's fixture
  metadata then named the substrate (the fixture was generated
  with `RANDOMX_FLAG_V2`); the C reference's `randomx.cpp:79`
  `(JIT | LARGE_PAGES)` mask at `randomx_alloc_cache` then
  named the asymmetry (cache memory is V2-flag-invariant; only
  `randomx_create_vm` honors the V2 bit). The fix exposed
  `RANDOMX_FLAG_V2 = 128` in `randomx-v2-sys::lib.rs` (with
  cache-vs-VM-flag rationale) and switched both callsites to
  pass it at VM creation. Outcome A confirmed; the
  canonical-output table regenerated under the v2 flag (cache
  SHAs unchanged, as predicted by the mask); end-to-end
  `--mode=correctness` re-ran the nightly corpus (32 seedhashes
  × 32 data = 1024 random pairs) with three-way agreement
  (exit 0) before this entry was written.

  **Substrate disposition.** The Rust verifier was correct
  throughout the investigation window; the FOLLOWUP's
  speculative Rust-side hypothesis is retired by replacement.
  No Rust implementation work was required. The generator-
  version pin bumped `v1-c5a-nightly-1024 → v2-flag-nightly-
  1024` to record the substrate change per §5.7's regeneration
  discipline; `canonical_outputs.rs`'s "Provenance lineage"
  section carries the audit trail. Per
  [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)'s
  continuous-discipline framing, the harness's design-time
  pre-flight should have caught this — the v1-vs-v2 flag
  asymmetry is exactly the kind of "what does this trait
  deliver against the threat model?" question that the §3.16
  R4-D5 light-mode-shape decision documented at one altitude
  (light-vs-full-mode) but not at the other (v1-vs-v2
  algorithm). The plan-doc post-mortem records the missed-
  altitude finding for future audits.

  **Lessons-into-substrate disposition (per
  [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)
  §"Continuous discipline as inheritance prevention").** Three
  surface improvements landed alongside the fix:

  1. `randomx-v2-sys::RANDOMX_FLAG_V2`'s doc explicitly
     enumerates the cache-vs-VM flag split with citations to
     `randomx.cpp:79` (cache-alloc mask) and the v2 algorithm-
     selection callsite in `randomx_vm.cpp`, so future
     consumers of the FFI surface cannot reasonably pass
     `RANDOMX_FLAG_DEFAULT` at VM creation without seeing the
     consequence in the type docs.
  2. `c_oracle.rs`'s module-level safety prose explains the
     cache-vs-VM flag selection in the same terms.
  3. `gen_canonical_outputs.rs`'s inline safety comment at
     the `randomx_create_vm` callsite cross-references the
     FOLLOWUP closure so a future regeneration cannot
     re-introduce the v1 flag without confronting the prior
     resolution.

  The pattern is "surface the substrate decision at every
  altitude where the wrong choice could land," and is now
  load-bearing for any future flag additions to
  `randomx-v2-sys` (per
  [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)'s
  named-substrate-change discipline: the reopening criterion
  for relaxing any of these three docstrings is a substrate-
  anchored reason they are no longer load-bearing, e.g.,
  upstream restructuring that collapses the cache-vs-VM
  flag distinction).

  **Cross-references.**
  [`docs/design/RANDOMX_V2_PHASE2G_PLAN.md`](./design/RANDOMX_V2_PHASE2G_PLAN.md)
  §11 Round history Round 8 entry (post-merge substrate-triage
  amendment — R8-D1 verifier-divergence root-cause closure +
  R8-D2 cache-vs-VM-flag asymmetry pin + R8-D3 missed-altitude
  finding queued for rule-26);
  [`docs/CHANGELOG.md`](./CHANGELOG.md) "RandomX v2 Phase 2g"
  entry (substrate-triage closure); the diagnostic-triage
  test at
  [`rust/shekyl-randomx-differential/tests/divergence_triage.rs`](../rust/shekyl-randomx-differential/tests/divergence_triage.rs);
  the lineage record in
  [`rust/shekyl-randomx-differential/src/canonical_outputs.rs`](../rust/shekyl-randomx-differential/src/canonical_outputs.rs)
  "Provenance lineage" section.

- **Stage 1 PR 4 Phase 0d — `RefreshEngine` checkpoint 3 mid-scan-
  reorg-abort extension: struck, not deferred (closed 2026-05-20,
  merged to `dev` 2026-05-21 at `fd6005e2a`).** PR 4's Round 1 review
  pass surfaced a conditional Phase 0d candidate — "extend
  producer-side checkpoint 3 with one daemon tip-poll per
  checkpoint-3 hit so a mid-scan reorg triggers an early abort" —
  pending the §5.4.5 R5 adversarial scenario disposition. Round 2's
  reframe of
  [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.7 R5 settled R5 by composition under the two-channel
  diagnostic shape rather than by extending checkpoint 3:
  `RefreshDiagnostic::ReorgObserved` is the seam; the
  `ReorgAmplificationDetector` V3.x consumer actor entry (above, in
  the V3.x staker-archival queue) is the composition home. Phase 0d
  is therefore **struck** (not deferred) — the producer's §7
  checkpoint discipline remains five-checkpoint (1 / 2 / 3 / 4 / 5
  per §5.4.9 F2), the trait surface gains no additional cancellation
  site, and no V3.x candidate exists to revisit "extend checkpoint
  3." This entry is the explicit retirement note distinct from the
  live V3.x deferrals (R5 composition consumer actor; R6 fail2ban
  consumer actor; R4 (c) view-material flow refinements), each of
  which remains open with named triggers per
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §4 Phase 0d, §5.4.7 R5 / R6 / R4 (c), and §8 closure. Per
  [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)
  the named reopening criterion for re-introducing the checkpoint-3
  extension would be the §5.4.7 R5 composition consumer actor
  failing to bound mid-scan reorg work in practice; that
  determination is data-driven and Stage-4-vintage, and no current
  evidence motivates re-evaluation. Cross-references:
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §4 Phase 0d (struck), §5.4.7 R5 reframe, §5.4.9 F2 (five-
  checkpoint discipline), §7.X C8 commit prose (this retirement
  note pinned in FOLLOWUPS).

- **Stage 1 retroactive Mock-X cleanup: `MockLedger` →
  `LocalLedger::from_test_blocks(...)` + `FaultInjecting<LocalLedger>`
  (closed 2026-05-20, merged to `dev` 2026-05-21 at `fd6005e2a`).**
  Landed in PR 4 §7.X commit C6β: `FaultInjecting<L: LedgerEngine>`
  extracted to
  [`engine/fault_injecting_ledger.rs`](../rust/shekyl-engine-core/src/engine/fault_injecting_ledger.rs);
  `LocalLedger::from_test_blocks(Vec<Block>)` added at
  [`engine/local_ledger.rs`](../rust/shekyl-engine-core/src/engine/local_ledger.rs)
  (V3.0 supports the empty-`Vec` case only; non-empty fixtures
  pending the V3.1 coordinated `TestLedgerBuilder` substrate design
  entry); `MockLedger` + `MockLedgerState` + `ROLE_LEDGER` deleted
  wholesale from `engine/test_support.rs`; the §5.2 hybrid retry
  test `hybrid_apply_scan_result_retries_on_concurrent_mutation`
  migrated to
  `FaultInjecting::new(LocalLedger::from_test_blocks(Vec::new()))`
  via the existing `Engine::replace_ledger` slot.

  **Substrate trajectory.** Stage 1 PR 3 (`KeyEngine`) Round 2 review
  surfaced that the Mock-X test-substrate pattern is wrong as a
  category: parallel test-only implementations conflate
  test-controlled inputs to real implementations with substitute
  implementations, add attack surface, don't compose with future
  implementors, and encourage tests to verify against fake semantics
  rather than real semantics. PR 3 landed the no-Mock pattern at its
  own cut-point (production-only `LocalKeys` with `from_seed` /
  `#[cfg(test)] from_test_seed` constructors + a composable
  `FaultInjecting<K: KeyEngine>` wrapper). PR 4's pre-flight
  surfaced the `MockLedger` cleanup naturally because C6/C7's new
  `RefreshEngine` test substrate would otherwise have compounded the
  Mock-X debt this entry existed to close, and the
  [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)
  cost-benefit-defer-to-later anti-pattern names the
  architectural-integrity-now disposition as the default for
  security-load-bearing substrate work pre-genesis. C6β was mostly
  extraction-and-rename, not re-implementation: the pre-deletion
  `MockLedger` was structurally already a
  `FaultInjecting<LocalLedger>`-shaped wrapper that delegated to the
  canonical `apply_scan_result_to_state`.

  Cross-references (historical):
  [`docs/design/STAGE_1_PR_3_KEY_ENGINE.md`](design/STAGE_1_PR_3_KEY_ENGINE.md)
  §2.1.2 (broader Mock-X rejection rationale), §6.4 (per-PR-3
  substrate disposition), §7.9 (test-substrate disposition open
  question);
  [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  Status banner, §6 no-Mock substrate inheritance discipline,
  §6.1 test-substrate paradigm pin, §7.X C6β commit prose.

- **Stage 1 retroactive Mock-X cleanup: `MockDaemon` → `TestDaemon`
  rename (closed 2026-05-20, merged to `dev` 2026-05-21 at
  `fd6005e2a`).** Landed in PR 4 §7.X commit C6γ: mechanical rename
  of the type and every call site in
  [`engine/test_support.rs`](../rust/shekyl-engine-core/src/engine/test_support.rs)
  (struct + `impl` blocks + module docstrings), `engine/refresh.rs`,
  `engine/lifecycle.rs`, `engine/mod.rs`,
  `benches/common/engine_fixture.rs`, and `Cargo.toml` (rationale
  comment); plus the active-doc trajectory references in
  [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md).
  The structural shape is unchanged — the type is still an
  alternative real implementation that serves canned / cached test
  responses without network — only the naming changed.

  **Substrate trajectory.** The `MockDaemon` case (Stage 1 PR 1
  substrate) was structurally different from `MockLedger`: real
  `DaemonClient` requires network connectivity, so the
  test-substitute is a legitimate alternative real implementation,
  not a parallel-implementation fake. The structural shape was fine;
  the "Mock" naming was the bug — it inherited the conflation that
  the broader Mock-X rejection identified. C6γ's fix renames the
  type so the name signals "alternative real implementation for
  tests" rather than "fake of an implementation," with the same
  shape. Bundled with the `MockLedger` cleanup (C6β) so PR 4's
  substrate-pass closes both FOLLOWUPS entries in one cut, per the
  Round 5 amendment.

  Cross-references (historical):
  [`docs/design/STAGE_1_PR_3_KEY_ENGINE.md`](design/STAGE_1_PR_3_KEY_ENGINE.md)
  §2.1.2 (broader Mock-X rejection rationale);
  [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  Status banner, §6 no-Mock substrate inheritance discipline,
  §7.X C6γ commit prose.

- **Stage 1 PR 3 architectural-inheritance migration: "secrets confined
  to engine" property activated at M3d (2026-05-11).** The
  headline property of the
  [`docs/design/STAGE_1_PR_3_MIGRATION_PLAN.md`](./design/STAGE_1_PR_3_MIGRATION_PLAN.md)
  M3-series (see §3.4 / §3.4.1) — orchestrator-side `TransferDetails`
  no longer carries derived per-output secrets — activated with the
  M3d landing on `feat/stage-1-pr3-m3d`. The five legacy
  `Option<Zeroizing<…>>` fields (`combined_shared_secret`, `ho`, `y`,
  `z`, `k_amount`) were removed from
  `rust/shekyl-engine-state/src/transfer.rs::TransferDetails` and its
  postcard schema mirror; the engine re-derives the spend material
  inside the signing-session boundary from `(view_secret,
  source_ciphertext)` via `LocalKeys::derive_source_secrets_bundle`
  per [`STAGE_1_PR_3_KEY_ENGINE.md`](./design/STAGE_1_PR_3_KEY_ENGINE.md)
  §7.10–§7.12.

  **Scope and audit trail.** Five-PR sequence (M3a–M3e) per
  [`docs/design/STAGE_1_PR_3_MIGRATION_PLAN.md`](./design/STAGE_1_PR_3_MIGRATION_PLAN.md)
  §3.1–§3.5; M3d activated the property and M3e completed the
  documentation-realignment-of-the-whole (M3-series complete,
  2026-05-11). Audit table in
  [`docs/design/STAGE_1_PR_3_MIGRATION_AUDIT.md`](./design/STAGE_1_PR_3_MIGRATION_AUDIT.md)
  §2.1 row 1 marks the five legacy fields "Removed at M3d (landed
  2026-05-11)". `LEDGER_BLOCK_VERSION` and
  `WALLET_LEDGER_FORMAT_VERSION` both bumped 3 → 4; two `.snap`
  schema snapshots regenerated; `.zeroize-allowlist` cleaned. Per-PR
  pre-flight investigations:
  [`STAGE_1_PR_3_M3A_PREFLIGHT.md`](./design/STAGE_1_PR_3_M3A_PREFLIGHT.md),
  [`STAGE_1_PR_3_M3B_PREFLIGHT.md`](./design/STAGE_1_PR_3_M3B_PREFLIGHT.md),
  [`STAGE_1_PR_3_M3C_PREFLIGHT.md`](./design/STAGE_1_PR_3_M3C_PREFLIGHT.md),
  [`STAGE_1_PR_3_M3D_PREFLIGHT.md`](./design/STAGE_1_PR_3_M3D_PREFLIGHT.md).

  **Threat-model delta.** Orchestrator compromise no longer discloses
  output-secret material (capability disclosure via `AllKeysBlob`
  remains an engine-confined property per Round 3 §7.10–§7.11).
  Discipline anchors:
  [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)
  (the rule whose "what does this deliver against the threat model?"
  framing the migration was designed against),
  [`35-secure-memory.mdc`](../.cursor/rules/35-secure-memory.mdc),
  [`36-secret-locality.mdc`](../.cursor/rules/36-secret-locality.mdc).

  **Residue tracked elsewhere.** The Rust-side schema cleanup
  completes here; the parallel C++ `transfer_details` consumer
  cutover (a separate work item) remains tracked at V3.1 above
  ("Migrate C++ `transfer_details` consumers to
  `shekyl-engine-state::TransferDetails`"). The two are
  distinguished by the
  [`20-rust-vs-cpp-policy.mdc`](../.cursor/rules/20-rust-vs-cpp-policy.mdc)
  boundary: M3d closes the Rust-side property; the V3.1 entry closes
  the C++-side migration. The framework-attribution rules-queue entry
  ("Rules-queue: elevate the plan-vs-state-divergence pattern into a
  workspace-wide rule" above) is the third discipline-discovery
  surfaced by the M3-series (M3b/M3c/M3d) and remains open as V3.1
  rules-queue work.

- **`42-serialization-policy.mdc` rule realignment (M3e, 2026-05-11).**
  The rule's `globs` frontmatter and body text carried 11 stale path
  references to `rust/shekyl-wallet-state/**` / `rust/shekyl-wallet-file/**`
  (renamed to `shekyl-engine-state` / `shekyl-engine-file` prior to the
  M3 sub-PRs); the stale `globs` field prevented the rule from
  auto-applying to any current file under the workspace's renamed
  trees, defeating the rule's intended reach. Closed by M3e's commit 3
  via mechanical rename
  (`s/shekyl-wallet-state/shekyl-engine-state/g`,
  `s/shekyl-wallet-file/shekyl-engine-file/g` against the rule body
  and frontmatter). Surfaced by Copilot review of PR #39 (M3d) on the
  CHANGELOG citation; originally held to a focused follow-up per
  [`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)
  ("while we're here is the enemy") then folded into M3e per the
  rule-15 trinary-reading calibration shift recorded in
  [`STAGE_1_PR_3_M3E_PREFLIGHT.md`](./design/STAGE_1_PR_3_M3E_PREFLIGHT.md)
  §11.1 — the realignment is mode-2 mechanical-residue (mechanically
  derivable from the substrate rename; directly traceable; bounded;
  surfaced inside M3e's review window) and folds into the closing PR
  rather than deferring.

- **`apply_scan_result` strict-contract enforcement (April 27, 2026).**
  PR #16 Copilot review surfaced two defensive-coding gaps in
  `rust/shekyl-wallet-core/src/wallet/merge.rs`: (1) `block_hashes`
  was collected into a `BTreeMap` via `BTreeMap::insert`, silently
  overwriting duplicate height entries instead of rejecting them;
  (2) `new_transfers` / `spent_key_images` / `block_hashes` entries
  with heights outside `processed_height_range` were silently
  dropped at scope end. Both are scanner / producer-bug signals
  that must surface rather than mask. Closed by the Phase 2a
  refresh-driver landing (commit `f9adfc195`,
  `feat/phase1-refresh-driver`): `apply_scan_result_to_state` now
  pre-validates `block_hashes` (length matches the range,
  in-range, no duplicates, every covered height present) and
  post-loop drains the per-height per-hash maps to assert no
  out-of-range residue, surfacing
  `RefreshError::MalformedScanResult { reason }` on any contract
  violation. New variant `RefreshError::MalformedScanResult` is
  reserved for producer bugs (a real `produce_scan_result` is the
  only producer in-tree; the contract is the boundary against
  future producers). Tests: `block_hashes_length_mismatch`,
  `block_hashes_duplicate_height`, `block_hashes_out_of_range`,
  `block_hashes_missing_height`, `transfer_out_of_range_block_height`,
  `key_image_out_of_range_block_height`, plus the existing
  `apply_scan_result_to_state` round-trip suite. Decision Log
  entry *"`MalformedScanResult`: producer-bug signal vs.
  `ConcurrentMutation`"* (2026-04-26).

- **Phase 1 bench harness re-review post-`RuntimeWalletState` fold
  (April 26, 2026).** The original FOLLOWUPS entry claimed four of the
  five `capture_rust_baseline.sh` iai-callgrind targets failed to
  compile against the post-fold APIs. A complete review of the bench
  tree (`rust/shekyl-{wallet-state,wallet-file,scanner,tx-builder}/
  benches/*.rs`, 10 files counting criterion + iai siblings) found
  every target builds cleanly with zero warnings: the fold commit
  `5ee692691` had already updated `scan_block.rs` /
  `scan_block_iai.rs`, and `ledger`, `balance`, and `transfer_e2e`
  never depended on `RuntimeWalletState` directly. The actual failure
  surfaced by smoke-running each criterion target was a runtime panic
  in `shekyl-wallet-state::ledger` (and its iai sibling) on the
  postcard-deserialize half of the round-trip:
  `WalletLedgerError::InvariantFailed { invariant:
  "tip-height-not-below-transfer", … }`. Hardening-pass commit 6
  (`def7d3379`, "feat(wallet-state): WalletLedger::check_invariants")
  wired invariant I-1 into `WalletLedger::from_postcard_bytes` after
  the bench harness was authored (commit `a9a81a17e`); the bench's
  `build_ledger` was inheriting `tip.synced_height = 0` from
  `WalletLedger::empty()` while the synthetic transfers carried
  `block_height ∈ [1_000, 1_000 + N)`. Fix on
  `chore/bench-rewire-phase1`: pin `tip.synced_height` to
  `max(transfers[*].block_height)` and set a non-`None` `tip_hash` in
  both `ledger.rs` and `ledger_iai.rs` `build_ledger` helpers.
  Verified: criterion `ledger` smoke runs serialize+deserialize across
  {100, 1k, 10k} sizes, iai sibling compiles. The other four bench
  pairs run unchanged. The "rewire" framing was incorrect; the actual
  finding is that bench-fixture coherence with aggregator invariants
  is its own discipline and should land alongside any future
  invariant addition.

- **Branch layer depth formula correction (April 12, 2026).** Commit
  `03d233652`. `shekyl-tx-builder` validation rule corrected from
  `c1 + c2 == depth` to `c1 + c2 + 1 == depth`, discovered by the FFI
  signing round-trip test (Phase 6). Two errors cancelled: wrong
  fixture + wrong rule = passing test that tests nothing. Hardening
  applied: `MAX_TREE_DEPTH=24` constant (single source of truth),
  C1/C2 alternation constraint enforced, parametric depth sweep test,
  spec-derived fixture rule added to `.cursor/rules/40-testing.mdc`.

- **FFI depth-to-layers convention fix (April 15, 2026).**
  `shekyl_fcmp_prove`/`_verify` were performing an internal
  `layers = tree_depth + 1` conversion that was opaque to C++ callers
  and led to double-conversion bugs. Fix: removed the internal
  conversion; FFI accepts `layers` directly; C++ callers convert
  explicitly. `shekyl_sign_fcmp_transaction` still accepts LMDB depth
  and converts internally.

- **`core_tests` FCMP++ proof verification failures.** Root cause:
  `test_generator::construct_block` set `blk.curve_tree_root` to a
  fixed placeholder, not the real Merkle root from the DB. FAKECHAIN
  skipped the root check, so block headers were stored with placeholder
  roots. The prover assembled witness paths from the real LMDB tree,
  producing inconsistent proofs. Fix: added per-height curve tree root
  storage (`m_curve_tree_roots` LMDB table) that records the real root
  at every block height. Both the prover (`apply_fcmp_pipeline`) and
  verifier (`check_tx_inputs`) read the root from this table instead of
  block headers. Also aligned `compute_leaf_count_at_height` with
  production `collect_outputs` logic.

- **MSVC CI covers the daemon target.** The `build-windows-msvc` job
  builds `--target daemon wallet`. Any new daemon code must compile
  under MSVC. If a future change introduces MSVC-only errors,
  shekyl-core CI will catch it before the GUI wallet release workflow
  does.

- **PQC Multisig V3.1: FFI returns typed error codes.** All three
  verification FFI functions (`shekyl_pqc_verify`,
  `shekyl_pqc_verify_with_group_id`, `shekyl_fcmp_verify`) now return
  `u8` error codes: 0 = success, nonzero = typed error discriminant.
  The debug-only `shekyl_pqc_verify_debug` was deleted. C++ callers
  log error codes in all build modes. Per
  `.cursor/rules/30-ffi-discipline.mdc`.

- **PQC Multisig V3.1: ephemeral seed stack copies hardened.** `ed_seed`
  and `ml_seed` in `multisig_receiving.rs` are now
  `Zeroizing<[u8; 32]>`, ensuring automatic zeroization on drop. Closes
  the theoretical side-channel surface identified during the V3.1 audit
  response review.

- **Genesis TX blobs now use real commitments and KEM ciphertexts.**
  The genesis pipeline consumes Bech32m addresses, derives X25519 from
  the Ed25519 view key via Edwards→Montgomery mapping, assembles the
  full 1216-byte `m_pqc_public_key`
  (`X25519_pub || ML-KEM_ek`), and routes through
  `build_genesis_coinbase_from_destinations`. See
  `scripts/verify_genesis.py` in `shekyl-dev` for reproducibility
  verification.

- **scheme_id binding confirmed active.** `expected_scheme_id` IS used:
  `blockchain.cpp` calls `verify_transaction_pqc_auth(tx, expected_scheme)`
  where `expected_scheme` is derived from `tx.pqc_auths[0].scheme_id`.
  This enforces cross-input scheme consistency — all inputs in a
  transaction must use the same scheme_id. Scheme downgrade protection
  across outputs is still provided by the `h_pqc` curve tree leaf
  commitment as described in `PQC_MULTISIG.md` Attack 1.

- **`on_get_curve_tree_path` RPC correctly reads reference-block state.**
  Fixed by computing `ref_leaf_count` at `reference_height` (subtracting
  leaves drained after reference block via
  `get_pending_tree_drain_entries`), capping all leaf/layer reads to
  `ref_leaf_count`, and applying boundary-chunk hash trimming via
  `shekyl_curve_tree_hash_trim_{selene,helios}` for sibling chunks that
  grew since the reference block.
