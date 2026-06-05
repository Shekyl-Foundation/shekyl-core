# Phase 2b — stake lifecycle (design)

**Status:** Re-based onto the **confidential staking** consensus redesign
(design session 2026-06-02). This is a **substrate-level reopen**: the model the
prior draft mirrored (cleartext staked amounts, public `staked_output_index`,
monotonic claim watermark, pool-denominator yield) is being replaced by committed
amounts, membership-unlinkable claims, per-epoch nullifiers, and a band-servo'd
public rate. **Upstream consensus Round 1 closed** (2026-06-02 — [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §14); wallet Round 1 design pins landed (§6.4, R0-D8). No Stage 3
implementation until Round 3 closes per
[`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md) §7.

**Process discipline:** [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
(Round 0 = pre-flight / R0-D#; adversarial rounds 1–6 before code).

**Binding constraint when arbitrating:** [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc)
priority-1 (security), then priority-2 (privacy). Under the confidential redesign
the wallet now holds **commitment-opening secrets** for its own stakes; the prior
"stakes are public ledger facts" posture no longer holds (see §0.10, §4, §7).
Stake principal commitments, lock boundaries, the per-epoch nullifier set, and the
public rate schedule are **consensus-load-bearing**; wallet-side display must not
invent economics the chain did not authorize.

---

## Revision note (what changed and why)

This rewrite threads one decision through every section: **staking moves from
cleartext-claim to confidential-claim.** The wallet consequences, stated once here
and applied throughout:

1. **Staked amount is committed, not public.** The chain stores `C_stake = z·G + amount·H`
   + range proof; the wallet knows its own `(amount, z)` (`amount` on `H`, `z` on `G` —
   upstream §2 notation; witness `a` is pseudo-out blinding only, not principal) and must
   protect them as secrets. `StakeInstance` is no longer secret-free.
2. **Claims are membership-unlinkable.** There is no public `staked_output_index`
   and no monotonic watermark. Double-claim prevention is a **per-settlement-epoch
   nullifier**; the wallet tracks *which epochs it has claimed* via its own
   nullifiers, not a chain-published index.
3. **Yield is exact and wallet-local.** Reward = `ρ_e (public) × own_weight ×
   accrued_epochs`. No pool denominator, no dependence on a daemon-reported
   `total_weighted_stake`. The `EconomicsEngine::pool_weighted_total()` consumption
   is replaced by the public rate schedule.
4. **A coarse public band rides each stake** for the governance/burn signal and as
   the rate denominator (servo). The wallet declares its band at stake time
   (range-proven to its commitment).
5. **The nullifier set is reorg-state.** On reorg, claimed epochs un-claim; the
   wallet mirror must rewind the claimed-epoch set, not a watermark.

The economics (servo, `ρ_cap`, band granularity, circuit relation) live **upstream**
in the confidential-staking consensus design — see §2.3 and §11. This document
mirrors that truth and owns only the wallet lifecycle.

---

## 0. Round 0 pre-flight — substrate audit

**Re-pre-flight complete (2026-06-04).** The prior §0 was verified at `dev @ 5f10af243`
(post–PR #99) against the cleartext model. The confidential redesign changed the
blast radius (new secret material in the stake actor; new consensus tx shapes the
scanner must parse), so §0.1–§0.9 below were **carried forward as structure** and
have now been **re-walked against the locked confidential consensus** (3C / `h_bind` /
`creation ≜ eligible` / collapsed-(A) / R0-D8). The re-walk reconciled clean except for
two stale-text gates and two completeness notes, all fixed in place; the close
disposition is §0.9. New material is in §0.10.

### 0.1 Engine identification ([`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md) §3.1)

- [x] **§2 trait binding (re-verified 2026-06-05):** [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §10.5.1 (`StakeEngine` additive trait); §2.7 (`EconomicsEngine` consumer framing —
  now consumes the **rate schedule**, not the pool denominator); §3.3 (cross-engine
  `.await` sequencing); §8.3 lens table row for `StakeEngine`. **Disposition:** §2.7 and
  §3.3 discharged by the §8.6 landing — `rate_at_epoch` is listed in §3.3.6's pure-read
  tuple (`base_emission_at`, `burn_amount`, `rate_at_epoch`, `parameters_snapshot`), so it
  carries no cross-engine `.await`-ordering obligation (pure-snapshot read, LedgerSnapshot
  pattern). §8.3 lens row clean (reorg + adaptive-burn quiescence; no pool-denominator
  claim). **One residual fixed in place:** §10.5.1's description still carried the stale
  "principal-pool aggregation state at Stage 4" — a dead pool-denominator reference the
  7-site `pool_weighted_total` sweep missed (it doesn't use the literal method name).
  Corrected to "per-stake commitment-opening secrets (`amount`, `z`), in-memory only; **no**
  network principal-pool aggregation — exact yield = `rate_at_epoch` × own (secret) weight
  (§7, §8.6)."
- [x] **§1.5 three-condition test (additive trait) — re-confirmed 2026-06-05:**
  - **(1) Distinct state ownership:** per-stake FSM + wallet-side stake registry **+
    per-stake commitment-opening secrets (`amount`, `z`) only**; distinct from
    `LedgerEngine` and `EconomicsEngine`. **No nullifier-derivation material in the
    stake actor** — `N_S = x·G_S` uses spend secret `x` (KeyEngine-owned, derived
    transiently at claim/resync; R0-D8, §0.10). **Pass — secret ownership confirmed:**
    `(amount, z)` is the actor's *only* secret state (in-memory, re-derived on hydration,
    never sealed — §3.3.1 / §4.2); `x` stays KeyEngine-transient (R0-D8 rejected persisting
    it). The ownership is genuinely distinct, not a slice of `LedgerEngine`/`EconomicsEngine`.
  - **(2) Failure isolation:** stake actor crash must not take down ledger or keys;
    recoverable via re-hydration from persisted stake records + chain replay.
    **Pass under fail-stop (§0.10, §4.5 row):** the actor `Break`s on panic and never
    restarts with stale secrets; the in-memory opening is re-derived on the next hydration
    (it was never at rest), so a crash loses no durable secret and the survivable state
    (`StakeInstance` records + `claimed_epochs`) rebuilds from persistence + chain replay
    (§5.2). Holding secrets does **not** weaken isolation because the secrets are
    reconstructable, not authoritative-at-rest.
  - **(3) Cross-cutting consumers:** `Engine<S>` orchestration, future
    `ArchivalEngine` via `is_active_staker(entity_id)`, JSON-RPC at V3.2+. **Pass.**
- [x] **Surface amendment — confirmed 2026-06-05:** introduces `StakeEngine` (eighth trait
  slot, per §10.5.1 / boundaries-doc §10.5); amends `ScanResult` / merge per §4; **new:**
  stake actor now holds secret opening material (changes the Stage 2 "no secrets in stake
  actor" inheritance — §0.10). **Disposition:** the inheritance change is real and recorded —
  Stage 2's "no secrets in stake actor" no longer holds; the replacement invariant is
  "secrets are **in-memory-only, re-derived, never sealed**" (§0.10, §3.3.1, §4.2), which the
  fail-stop posture (§4.5 row) and condition (2) above are the load-bearing guards for.

### 0.2 Plan-altitude principles ([`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md) op. 4–8)

- [x] **Principle 4 (architectural-integrity-now):** applies —
  `16-architectural-inheritance.mdc`, `21-reversion-clause-discipline.mdc`.
- [x] **Principle 5 (closure-rule discipline):** applies — the confidential redesign
  **is** the substrate finding that reopens the rounds (§9).
- [x] **Principle 6 (wider-substrate audit):** applies — §6 audit re-scheduled after
  the confidential-consensus design closes its own Round 1.
- [x] **Principle 7 (threat-model anchors):** applies, **expanded** — adversary
  daemon + memory-disclosure now also covers commitment-opening secrets and
  claim↔stake linkage (§7).
- [x] **Principle 8 (priority hierarchy):** applies — privacy posture materially
  changes (§1). **Inflation-safety primary defense** (3C locked; §9 premise established):
  verifier **`N/D` recompute** + **`h_bind`** tier/creation binding + **bounded-remainder
  entitlement** (upstream §6.4.1, §9). Consensus **range proofs + `ρ_cap` are the layered
  backstops**, not the primary argument (the pre-(C)-close "rests on range proofs + ρ_cap"
  framing is superseded).

### 0.3 §8.3 design lenses

- [x] **Lens 1 (actor-mesh):** **yes** — registration, claim, unstake, refresh
  reconciliation are cross-actor; Stage 3 is actor-from-inception.
- [x] **Lens 2 (state-as-collection-membership):** **yes** — discrete per-stake
  lifecycle stages (`StakeState`), **plus** claimed-epoch set membership (new).
- [x] **Lens 3 (diagnostic-stream / trust boundary):** **yes** — claimable amounts
  are RPC-visible **and now exact wallet-local values**; §7.3 projection axes apply.

### 0.4 Architectural-inheritance audit projection

| Inherited substrate | Shekyl disposition (confidential rebase) |
|---------------------|-------------------------------------------|
| Monero wallet2 "user tracks stake mentally" | **Rejected** — explicit FSM ([`V3_WALLET_DECISION_LOG.md`](../V3_WALLET_DECISION_LOG.md) 2026-04-25) |
| `TransferDetails::staked` / `stake_tier` / `stake_lock_until` on ledger rows | **Keep**, but the **amount becomes a commitment**; the wallet's cleartext amount + mask `z` live in `StakeInstance`, not on the public transfer row |
| `StakerPoolState` in `LedgerIndexes` (runtime accrual cache) | **Repurpose** — feeds from the public **rate/band** observation, not a pool-division denominator (§4.5) |
| Public `staked_output_index` + claim watermark | **Removed** — replaced by membership + per-settlement-epoch nullifiers |
| No `StakeEngine` / `StakeInstance` types in `rust/` yet | **Expected** — zero production trait; blast radius now includes scanner parsing of confidential claim/stake tx shapes |

**Audit shape:** *confirmation with bounded new persistence **and new secret
material*** — no Monero-shaped migration (none exists), but the secret-locality
posture changes (§0.10).

**Lock-view pin (canonical-height alignment).** The wallet's `stake_lock_until` /
`eff_lock` view **must derive from `eligible_height`** — the canonical
`creation_height ≜ eligible_height` ([`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md)
§2 canonical block), **not** the mining height — or the wallet's local lock view drifts
from consensus by the `MIN_AGE` deferral. UX disclosure: "lock begins when the stake
matures, ~`MIN_AGE` blocks after confirmation" (upstream §6.4.3 warm-up).

### 0.5 Branch posture

- [x] [`06-branching.mdc`](../../.cursor/rules/06-branching.mdc): design on `dev` or
  short-lived branch `feat/phase-2b-stake-lifecycle-confidential-rebase`; land doc on
  `dev`; **no push without explicit instruction**.

### 0.6 Trait-surface conformance lenses (CL-1–CL-7)

Deferred to Round 2 close-out when the §4.6 trait sketch is binding-pinned. Round 0
intent unchanged: `StakeEngine::Error: Into<StakeEngineError>` (CL-3),
`#[non_exhaustive]` on `StakeState` / `StakeEvent` where wire-evolving (CL-7).

### 0.7 Codebase blast radius (grep baseline — re-run required)

| Symbol | Production sites (prior baseline; re-run for confidential shapes) |
|--------|------------------------------------------------------------------|
| `StakeEngine` | **0** trait/impl — comments only in `economics.rs`, `chain_economics_source.rs` |
| `StakeInstance` | **0** — plan/decision-log prose only |
| `stake_events` | `scan.rs` (`ScanResult`), `merge.rs` (`apply_stake_events`), `refresh.rs`, `local_refresh.rs` |
| `StakeEvent` | `scan.rs` — only `Accrual { height, record }` variant today |
| `StakerPoolState` / `AccrualRecord` | `shekyl-engine-state` — pool-division `estimate_reward()` path; **retire** on confidential cutover (R0-D7) |
| `pool_weighted_total()` | `EconomicsEngine` trait — **retired** (R0-D5 finalized §8.6, 2026-06-05): boundaries-doc surface replaced by `rate_at_epoch`; code removal Stage 3 |
| **(new) confidential claim / nullifier / band parsing** | **0** — scanner does not yet parse confidential stake/claim tx; Stage 3 adds it |
| **Claim nullifier `N_S = x·G_S`** | **0** wallet path — uses existing spend secret `x` from witness/`OutputSecrets`; `G_S` domain + claim prove/verify surface pinned upstream §6.4 (R0-D1) |

**Implication:** Stage 3 adds a new engine module tree (`stake_engine.rs`,
`stake_actor.rs`, `StakeEngineHandle`) parallel to
[`key_actor.rs`](../../rust/shekyl-engine-core/src/engine/key_actor.rs); extends
`ScanResult` / merge / refresh; **and** the scanner must learn the confidential
stake-output and claim-tx wire shapes (owned upstream by the consensus design).

**3C-specific scanner/merge scope (re-run targets — now concrete).** Under the locked
separate-staking-subtree design ([`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md)
§6.4.3, [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §15):

- The scanner path-tracks membership in a **second tree** — the staking subtree — in
  addition to the main output tree (a separate set of membership paths to maintain and
  re-root on growth).
- For each owned stake leaf the wallet **recomputes the 5th leaf scalar
  `h_bind = H("stake-bind" ‖ tier ‖ eligible_height)`** from public `(tier,
  eligible_height)` — no secret input; must match the consensus-stamped value (KAT,
  R0-D# / Round 2).
- The **unstake flow spans two trees**: consume a staking-subtree leaf → emit a
  main-tree output. Merge/`ScanResult` must reconcile a cross-tree transition, not a
  single-tree spend.

### 0.8 Stage 2 actor template (reference only — [`STAGE_2_KEY_ENGINE_ACTOR.md`](STAGE_2_KEY_ENGINE_ACTOR.md))

| Pattern | Stage 2 pin | Phase 2b application (confidential) |
|---------|-------------|-------------------------------------|
| Handle vs actor | `KeyEngineHandle` + `KeyActor` | `StakeEngineHandle` + `StakeActor`; stake registry **+ opening secrets** inside task |
| Fail-stop | §4.5 — `Break` on panic; no restart with stale secrets | **Adopt — now mandatory**: actor holds commitment openings (`amount`, `z`) **in memory only** (re-derived at hydration, never at rest — §3.3.1 / §4.2); nullifier + `x` are transient `KeyEngine` operations (`x·G_S`), never sealed stake-actor state (§0.10, R0-D8). Fail-stop guards the in-memory opening + mutable `claimed_epochs`, not a sealed blob |
| Require-ambient runtime | §4.2 | Same for `StakeEngineHandle::spawn` |
| `pub(crate)` handles | Orchestrator-only | Same |
| Forward actions | §8 | §8 below |

**Inheritance change:** the prior draft said master-secret containment was *not*
inherited because "stakes are public ledger facts + amounts." **That is reversed.**
The stake actor holds per-stake **`(amount, z)` only**, **in memory** in `StakeOpening`
(§3.3.1) — re-derived on hydration, **never persisted** (no sealed stake region; §4.2
dissolution). Spend secret `x = ho + b` is likewise never persisted — derived
transiently via `KeyEngine` + output derivation at claim time. Nothing claim-grade or
theft-grade is at rest; master spend/view keys route through `KeyEngine`; signing
through `PendingTxEngine` + `KeyEngine`.

### 0.9 Round 0 disposition

**Round 0 closed (re-walk complete — 2026-06-04).** §0.1–§0.8 re-walked against the
locked confidential consensus (3C / `h_bind` / `creation ≜ eligible` / collapsed-(A) /
R0-D8); §0.10 delta signed off; the **R0-D pre-flight findings** (§0.11) dispositioned;
§8.0 blocking posture confirmed. The re-walk surfaced two stale-text gates — the
stake-actor "nullifier-derivation material" contradiction (Drift 1, §0.1(1) + §0.8,
fixed to `(amount, z)`-only per R0-D8) and the inverted inflation-safety framing
(Drift 2, §0.2 Principle 8, fixed to `N/D`-recompute + `h_bind` + bounded-remainder as
primary, range proofs + `ρ_cap` as backstop) — plus two completeness notes (§0.4
lock-view → `eligible_height`; §0.7 3C scanner/merge scope). All four landed; no design
decision reopened. **Wallet is clear into Round 1–2** — the `StakeState` FSM + transition
table sign-off (§10.1) is the next wallet milestone, distinct from this Round 0 close.
Implementation (Stage 3 code merge) remains gated on Round 3 (threat-model exhaustion
§7 + wider-substrate audit), not on this close.

### 0.10 Confidential-rebase delta (new)

The single source of the reopen. Wallet-relevant facts inherited from the
confidential consensus design ([`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §2.3):

- **Secret material in the stake actor (in memory, never at rest):** per-stake
  `amount` and Pedersen mask `z` only — **not** spend secret `x` (§3.3.1). The
  opening `(amount, z)` is **re-derived on hydration** from the staked output and held in
  memory for the session (zeroized on drop); it is **not persisted** — there is no sealed
  stake region (§4.2 dissolution). Per-epoch claim tags are **`N_{i,S} = x_i · G_S`** with
  `x = ho + b` derived transiently when needed.
  Public base
  `G_S = hash_to_ec("shekyl-stake-nullifier-base" ‖ S_le64)` ([`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md)
  §6.3–§6.4) — **no** separate `nullifier_seed` on `OutputSecrets`. Wallet must pin
  `G_S` domain + KAT and the claim prove/verify surface (R0-D1, §8.5). These are wallet
  secrets; they live **in memory only** (re-derived, never sealed) and never cross RPC or
  diagnostic surfaces as plaintext.
- **No public per-output index / watermark** to mirror; the wallet recognizes its
  own claims by watching for *its own* nullifiers on-chain.
- **Yield is exact**, computed wallet-local from the public rate schedule and the
  wallet's own (secret) weight — no daemon-trusted denominator.
- **Band declaration** is a wallet action at stake time (range-proven); the band is
  public; the exact amount is not.
- **Threat surface gains:** claim↔stake linkage, claim-timing correlation, band
  cohort-size leakage, **in-memory** opening exposure (no longer secret-*at-rest* —
  openings are re-derived, never persisted, §3.3.1 / §4.2), nullifier-reorg desync (§7).

### 0.11 Round 0 pre-flight findings (R0-D# — disposition required)

Substrate re-check after the confidential rebase (2026-06-02 review). Each item
must be **closed or explicitly deferred** before Round 0 closes.

| ID | Finding | Disposition (Round 0 pin) |
|----|---------|-------------------------|
| **R0-D1** | Claim nullifiers use **`N_S = x·G_S`** (spend secret `x` already in witness/`OutputSecrets`; no new HKDF field). Resync recomputes `{ x·G_S : S ∈ accrued_epochs }` and intersects the chain stake-claim nullifier set (§4.2, §5.2). | **Block implementation** on upstream [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §13 item 7 + §6.4 **(B)** (claim prove/verify, B1 preferred) + wallet §8.5 (`G_S` KAT). **Dissolves** prior `nullifier_seed` HKDF pin unless B1 infeasible (§6.3 fallback). |
| **R0-D2** | §4.2 "resync re-derives opening → no backlog loss" is **overbroad**. Pending (`PendingBroadcast` / `Unconfirmed`) stakes need `TxMetaBlock` / `PendingTxEngine`; confirmed stakes need scan + pinned derivation; **`claimed_epochs` must be rebuilt** from chain nullifier set ∩ locally derived `N_{i,S}`**, not only from persisted set. | **Pin §4.2 + §5.2** post-resync reconciliation pass. |
| **R0-D3** | Actor secret transport: `RegisterPendingStake(StakeInstance)` with `opening` in `ask` payloads must not be loggable plaintext in the mailbox. | **Pin §4.7** — opening is **never persisted/sealed** (§4.2 dissolution): `Restore` **re-derives** it in-task, `Snapshot` carries **no** opening, and `RegisterPendingStake` moves a `Secret<StakeOpening>` **in-process** from the orchestrator build context (zeroized, non-`Debug`, never logged — an in-RAM secret move, not a sealed disk blob). List/query messages return `StakeView` only. |
| **R0-D4** | Claim construction needs `x`, `z`, `a`, epoch set `S`, public `M` — must not duplicate openings in `PendingTxEngine`. | **Pin §4.6–§4.7** — `prepare_claim_build` returns stake-side material (`amount`, `z`, …); orchestrator derives **`x` transiently** from `KeyEngine` (`b`) + `ho` (output derivation) and feeds a **single** zeroized prover bundle to `PendingTxEngine` + `KeyEngine`. **`x` not in `StakeOpening`** (§3.3.1). |
| **R0-D8** | Persisting `x = ho + b` in `StakeOpening` duplicates **theft-grade** spend authority already held by `KeyEngine`; sealed-region compromise escalates from reward-claim forgery to principal spend. | **Rejected** (Round 1). `StakeOpening = (amount, z)` only; `x` derived at claim/resync (§3.3.1, §8.8). Reopen only if measured derivation cost is prohibitive across the full stake set on resync — not expected (§8.8). |
| **R0-D5** | `EconomicsEngine::rate_at_epoch` is proposed but `pool_weighted_total()` still exists; [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) still cites pool denominator for Phase 2b. | **Finalized Round 2 (§8.6, 2026-06-05):** `rate_at_epoch` semantics pinned (7 pins); `pool_weighted_total` retired across all 7 boundaries-doc sites (delete, not renarrate — rule 15; sole consumer eliminated, verified at source). **Stage 3 co-lands** the code: trait method swap + grep-retire enumeration in §8.6. |
| **R0-D6** | [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §7: accrued epochs remain claimable **after unstake**; FSM `FullyUnstaked` must not foreclose claims. | **Pin §3.1** — `principal_spent: bool` on instance or remain in claimable-equivalent state until `claimed_epochs` exhausted. |
| **R0-D7** | `RateEpochObserved { rho, band_sum }` is not a rename of `AccrualRecord` — retire `StakerPoolState::estimate_reward` pool-division path to avoid accidental reintroduction. | **Pin §4.3** — new `RateEpochRecord` type; explicit deletion target in Stage 3 grep plan. |

**Round 0 close checklist:** §0.1–§0.8 re-walked against [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md); R0-D1–D8 rows dispositioned in-doc; §8.0 blocking posture confirmed (§8.0).

---

## 1. Mission posture

**Priority-1 (security):** stake flows must not leak spend/view material **or
commitment openings (`amount`, `z`)** on RPC or logs; spend secret `x` stays in
`KeyEngine` / transient prover paths only (§3.3.1). Claim/unstake txs must use
consensus validation shapes from the confidential staking design, not
wallet-invented amounts. The wallet must never construct a claim that exceeds the
consensus-derived entitlement (`ρ_e × weight`); the consensus range proof is the
backstop, the wallet must not rely on it to mask a local accounting bug.

**Priority-2 (privacy) — upgraded.** Under the confidential redesign:

- A stake **event**, its **tier**, and its **coarse band** are public by protocol
  design. The **exact amount is confidential** (committed).
- **Claims are unlinkable** to the stake and to each other (membership + per-epoch
  nullifiers). The wallet must not re-introduce linkability — it must use fresh
  nullifiers, must not key any RPC/UI field on a stake↔claim correlation, and should
  support batching/jitter of claim broadcast timing (network-layer; §7).
- FA-1 still holds: stakes target **the wallet's single static address** (Shekyl has no
  account/subaddress hierarchy to index — §6 FA-1 reopen-pointer); no subaddress indices
  (subaddress recognition is subsumed by ML-KEM decap —
  [`SUBADDRESS_UNDER_PQC.md`](SUBADDRESS_UNDER_PQC.md) §3.7).

**Timeframes:** **Now** (HF1+ confidential claim-based staking). **Mining era**
(emission-share decay rides the public rate schedule). **V4** — lattice-only crypto
does not change the FSM shape; amount-hiding remains DL-computational (Pedersen),
the same post-quantum caveat as all FCMP++/RingCT amount privacy, and is stated in
the consensus design, not here.

---

## 2. Scope

### 2.1 In scope

- `StakeState` FSM and transition rules (§3)
- `StakeInstance` identity, **secret opening material**, persistence, and linkage to
  `TransferDetails` (§3–§4)
- `StakeEvent` vocabulary + `LedgerEngine` merge protocol (§4)
- Wallet-side **nullifier tracking** (claimed-epoch set) and **exact yield**
  computation from the public rate schedule (§3–§4)
- **Band declaration** at stake build time (§6)
- Refresh reconciliation ordering, including **nullifier-reorg rewind** (§5)
- Orchestrator user API: `Wallet::stakes`, `claimable_rewards`, `stake` / `claim` /
  `unstake` → `PendingTx` (§6)
- `StakeEngine` trait + `kameo` actor protocol (§4.6–§4.7)
- Threat model + diagnostic projections (§7)
- Stage 3 implementation DoD pointer (§10)

### 2.2 Out of scope

| Item | Disposition |
|------|-------------|
| **Confidential consensus rules** (commitment/range-proof on staked outputs, ZK claim relation, nullifier set, band range proof, servo'd rate, `ρ_cap`) | **Upstream** — owned by the confidential staking consensus design (§2.3, §11). Phase 2b **mirrors**, does not define. |
| `ArchivalEngine` | Stage 5; only `is_active_staker` query is forward-compatible |
| Multisig stake/claim ceremony | V3.1 — FOLLOWUPS |
| Subaddress indices in stake/recipient model | **Rejected** for V3.0 (FA-1) |
| Persisting the runtime rate/band cache in the wallet file | **Deferred** — reopen if rescan refill cost fails UX budget (§8.1) |
| Wallet RPC / CLI commands | Phase 3+ |

> **Reversal of the prior draft's §2.2 line.** The prior draft scoped consensus
> changes out and assumed "existing HF17 staking; wallet mirrors." Confidential
> staking **is** a consensus change. Phase 2b still does not *define* consensus
> here, but it now **depends on** the confidential consensus and must not be
> implemented against the cleartext model (doing so would build a wallet for a
> consensus shape that will not ship — a transitional state that cannot exist in a
> genesis launch).

### 2.3 Upstream consensus dependency (mirror only)

Phase 2b inherits the following from the confidential staking consensus design.
These are **proposed Round 1 pins** from the 2026-06-02 session and are owned by the
consensus/economics doc; values here are *for wallet planning* and track upstream.

- **Confidential staked output:** `C_stake = z·G + amount·H` (same Pedersen convention
  as [`proof.rs`](../../rust/shekyl-fcmp/src/proof.rs) / upstream §2 notation table) +
  range proof; **tier public**; **coarse band public** (range-proven to `C_stake`).
- **Reward model:** public per-rate-epoch rate `ρ_e`; reward `= ρ_e × weight ×
  active_blocks`; **no pool division, no aggregate `TWS` in the reward path.**
- **Rate calibration (servo):** `ρ_e = min( budget_e / band_sum , ρ_cap )`, where
  `band_sum` is the windowed coarse band aggregate (the public staking aggregate)
  and `ρ_cap = budget / TWS_max` is the supply-safety backstop. The servo recovers
  proportional economics confidentially; the cap guarantees no over-emission
  regardless of band error or manipulation.
- **Epochs (global boundaries):** **rate-epoch = 1,000 blocks** (`ρ_e` step;
  ~1.4 days; 262,800-block year ⇒ 262.8 rate-epochs/yr). **Settlement-epoch =
  10,000 blocks** — the nullifier granularity. A claim batches up to
  `MAX_EPOCHS_PER_CLAIM` settlement-epochs per tx (`= 1` recovers strict
  one-epoch-per-tx); `MAX_CLAIM_RANGE`-as-block-span is retired.
- **Nullifiers:** one per `(stake, settlement-epoch)`,
  `N_{i,S} = x_i · G_S` (`G_S` public per `S`; distinct from principal key image
  `x·Hp(O)`); replaces the public index + watermark; filed in a **stake-claim nullifier
  set** (not spent key images); **reorg-state** (consensus pop must revert it; wallet
  mirror in §5.2).
- **Nullifier counts per tier (full drain):** tier-1 (1,000 blk) → 1–2; tier-2
  (25,000) → ≤3; tier-3 (150,000) → ≤15.
- **Band:** 4–6 decade-log-spaced; geometric-midpoint weight in `band_sum`; coarse
  by design (cohort-size caveat at cold start).

Open upstream items the wallet must track (do not implement against until pinned):
byte-exact claim wire; **staking-subtree** path tracking + 5-scalar leaf / `h_bind` KATs;
cross-tree stake/unstake handling; Round 2 FSM bindings. **Closed:** economics §14;
**`G_S`/(B)**; **(C)** on **3C** (subtree + `h_bind`, window arithmetic; §6.4.3); **(A)**
reserve-DLEQ + bounded remainder. Still tracked: **claims after principal spent** (§7,
R0-D6) — survives 3C (append-only subtree leaf).

---

## 3. StakeState FSM (pinned draft for Round 1–2 review)

### 3.1 States

States are unchanged in shape from the prior draft; **fields change** to carry
confidential material and the claimed-epoch set instead of a watermark.

```rust
/// Wallet-observed stake lifecycle. Distinct from on-chain `TransferDetails::staked`
/// flags. Holds wallet-secret opening material (§4.1) in memory only — re-derived on
/// hydration, never at rest (§3.3.1 / §4.2 dissolution).
#[non_exhaustive]
pub enum StakeState {
    /// Stake tx built locally; not yet broadcast.
    PendingBroadcast {
        built_at_height: u64,
        pending_tx_id: PendingTxId,
    },
    /// Broadcast seen in mempool / wallet tx pool; not yet in scanned chain.
    Unconfirmed {
        broadcast_at_height: u64,
        stake_tx: TxHash,
    },
    /// Staked commitment seen on-chain; principal locked until `effective_lock_until`.
    Locked {
        confirmed_at_height: u64,
        effective_lock_until: u64, // creation_height + tier_lock_blocks (consensus rule)
    },
    /// Within lock window; weight still contributing to the public `band_sum`.
    Accruing {
        last_scanned_height: u64,
        accrued_rewards: AtomicUnits, // EXACT: ρ_e (public) × own_weight × accrued_epochs
    },
    /// Lock ended; principal still staked; reward backlog claimable per epoch.
    Claimable {
        frozen_accrual_since: u64,   // effective_lock_until + 1
    },
    /// Unstake tx entered (PendingTx or observed); principal commitment not yet spent.
    Unstaking {
        initiated_at_height: u64,
        unstake_tx: TxHash,
    },
    /// Principal commitment spent by unstake. Accrued epochs may still be claimable
    /// ([`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §7, R0-D6).
    FullyUnstaked {
        unstaked_at_height: u64,
        principal_spent: bool, // true once `StakedOutputSpent` observed
    },
}
```

The claim-progress field that was `claim_watermark_height` is **removed from the
state** and lives on `StakeInstance` as a **claimed-epoch set** (§3.3), because under
nullifiers there is no single monotonic height — claimed epochs are a set the wallet
maintains from its own nullifiers, and reorg edits the set non-monotonically.

**Round 1 load-bearing question (carried, re-framed):** whether `Accruing` and
`Claimable` remain separate or collapse to chain-derived views. **Provisional pin:**
keep separate for UX ("still earning new epochs" vs "frozen accrual, drain backlog").
The confidential model does not change this — both states now read exact wallet-local
yield, which if anything *strengthens* the case for a clear "drain backlog" UX.

### 3.2 Transition table (consensus-driven)

Heights are **chain heights** from scan/merge unless noted. `S` denotes a
settlement-epoch index.

| From | Event / condition | To |
|------|-------------------|-----|
| — | `Wallet::stake` builds `PendingTx` (commitment + range proof + band) | `PendingBroadcast` |
| `PendingBroadcast` | submit + mempool observe | `Unconfirmed` |
| `PendingBroadcast` | discard pending tx | **remove instance** — no terminal `Discarded` (§3.4 ratification): the stake never broadcast, left no chain trace; "you discarded a stake" is a transient UX notification, not FSM state |
| `Unconfirmed` | scan finds the staked commitment output | `Locked` → auto-advance to `Accruing` if `height <= effective_lock_until` |
| `Locked` | next scan `height > confirmed_at` and `<= effective_lock_until` | `Accruing` |
| `Accruing` | scan height `> effective_lock_until` | `Claimable` (set `frozen_accrual_since`) |
| `Accruing` / `Claimable` / `FullyUnstaked` | `Wallet::claim` builds + broadcasts claim tx for epoch set `S` | **add `S` to `claim_pending_epochs`** (runtime-only reservation, §3.4); stay in state |
| `Accruing` / `Claimable` / `FullyUnstaked` | scan observes **own nullifier** `N_{i,S}` on-chain | mark epoch `S` in `claimed_epochs`; **clear `S` from `claim_pending_epochs`**; stay in state |
| `Accruing` / `Claimable` / `FullyUnstaked` | claim tx discarded / staleness-rejected / reorged **before** confirm | **clear `S` from `claim_pending_epochs`** → epoch claimable again (§3.4); no chain trace, nullifier never landed |
| `*` | `Wallet::unstake` submitted | `Unstaking` |
| `Unstaking` | scan spends the principal commitment (key image observed) | `FullyUnstaked { principal_spent: true, … }` |
| `FullyUnstaked` | `ClaimConfirmed` (partial) | `FullyUnstaked` |
| `*` | reorg rewinds below `confirmed_at_height` **or un-confirms a claimed nullifier** | rewind per §5.2 |

**Consensus pins:**

- `effective_lock_until = creation_height + tier_lock_blocks` — never stored as
  authoritative; recompute from the tier table
  ([`shekyl-staking/src/tiers.rs`](../../rust/shekyl-staking/src/tiers.rs)).
- **`creation_height ≜ eligible_height`** (canonical single source —
  [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §2): the height the stake **matures**
  (past `MIN_AGE = 5`), **not** mining height. This is the same height the stake enters the
  public `band_sum`; the wallet must derive accrual start and `band_sum` participation from
  the **one** definition (drift between accrual and counting silently breaks conservation,
  §9). UX: effective lock = advertised `tier_lock` + ~5-block warm-up; surface as "lock
  begins when the stake matures, ~N blocks after confirmation."
- Reward claimability does **not** require the principal to remain staked on-chain
  ([`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §7): claims may proceed from
  `FullyUnstaked` while epochs remain in `accrued \ claimed_epochs`.
- A settlement-epoch `S` is claimable iff its nullifier `N_{i,S}` is **not** in the
  on-chain nullifier set and `S` lies in the stake's accrued settlement-epoch window
  `(creation, eff_lock]` (unchanged while principal is staked; same window after
  unstake for backlog drain).

### 3.3 `StakeId`, `StakeInstance`, claimed-epoch set

```rust
/// Stable wallet-local identifier. Derived from the staked output identity.
pub struct StakeId(pub [u8; 32]); // cSHAKE256(cust="shekyl/stake-id-v1", tx_hash ‖ le_u64(index)); §3.3.3

/// SECRET — runtime-only, re-derived on hydration, **never at rest** (§3.3.1 / §4.2).
/// Never serialized; never to RPC; never in actor messages as plaintext.
pub struct StakeOpening {
    pub amount: AtomicUnits,    // wallet-known principal; NOT public on-chain
    pub z: Scalar,              // Pedersen mask (OutputSecrets.z); C = z·G + amount·H
    // NO `x` here — spend secret x = ho + b is KeyEngine-owned; §3.3.1
}

pub struct StakeInstance {
    pub id: StakeId,
    pub tier: StakeTier,             // shekyl_staking::StakeTier (public)
    pub band: StakeBand,             // public coarse band declared at stake time
    pub state: StakeState,
    /// Principal commitment reference (FA-1: the wallet's single static address — Shekyl
    /// has no account/subaddress hierarchy to index).
    pub staked_output: OutputRef,    // { tx_hash, index_in_transaction }
    pub stake_tx: Option<TxHash>,
    /// Settlement-epochs already claimed (own nullifiers observed on-chain).
    /// Reorg-editable; not monotonic.
    pub claimed_epochs: EpochSet,    // fixed u16 relative bitmask, §3.3.2
    /// Settlement-epochs with a claim tx in flight (built/broadcast, not yet
    /// confirmed). **Runtime-only** — never persisted, never on the wire/sealed
    /// region (§3.4, §4.1). Conflict-prevention reservation only: blocks building
    /// a second claim for in-flight epochs. Folds into `claimed_epochs` on confirm;
    /// clears on discard / staleness-reject / reorg-before-confirm.
    pub claim_pending_epochs: EpochSet, // runtime-only; NOT serialized
    /// Secret opening material — **re-derived at hydration, never persisted** (§3.3.1,
    /// §4.2). Held in memory for the session, boxed/zeroized on drop; see §4.1.
    pub opening: Secret<StakeOpening>,
}
```

`band: StakeBand` is the public coarse band (4–6 decade-log values). `opening` is the
in-memory secret payload — its presence in RAM is what keeps the secret-locality /
fail-stop posture of §0.8 / §4.1, but it is **never at rest** (re-derived on hydration
from the staked output, §3.3.1 / §4.2 dissolution), so it is **not** a serialized field.
`claimed_epochs` replaces the watermark and is the reorg-edited set in §5.2.
`claim_pending_epochs` is the runtime-only claim reservation pinned in §3.4 — it is
**not** a second persisted set, so the `EpochSet` wire/sealed encoding carries one set
per stake (`claimed_epochs`), not two.

### 3.3.1 The stake opening is never persisted — re-derived, not sealed (R0-D8 + §4.2 dissolution)

Two exclusions, the **same reasoning at two severity grades**: nothing claim-grade or
theft-grade is written to rest. The wallet's durable stake record carries **public
fields + `claimed_epochs` only** (§4.2); the opening `(amount, z)` and the spend secret
`x` are both **re-derived, never persisted**.

**Exclusion 1 — `x` (theft-grade).** `x = ho + b` is the full spend secret — the same
scalar behind principal key image `x·Hp(O)` and unstake SAL. Persisting it would let a
wallet-at-rest compromise escalate from reward-claim forgery to **principal theft**.
`x` is derived transiently inside `PrepareClaimBuild` (and `claimed_epochs`
reconciliation) from **`ho`** (output derivation) + **`b`** (`KeyEngine`); never held
between operations, never written anywhere. (Original Round 1 R0-D8 pin.)

**Exclusion 2 — `(amount, z)` (claim-forgery-grade) — the dissolution.** The opening
was previously pinned to the **sealed wallet region**. That persist-half is **redundant
with a re-derive-half this doc already specifies**: `C_stake = z·G + amount·H` is plain
Pedersen with **`z = OutputSecrets.z`** — the *standard* output blinding, **not** a fresh
subtree mask and **no** `τ·H_t` term (verified at source —
[`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §"Pinned commitment construction
(staked outputs, Decision 3C)" + the `z` mask-table row). So `(amount, z)` recover from
the **staked output alone** via `derive_output_secrets(combined_ss, idx)` — the *same*
HKDF expand the §4.2 resync row (and every received-output scan) already performs — with
**no** whole-tx-balancing context. The wallet therefore **stops persisting the thing it
already re-derives on every resync**; it does not invent a new recovery path.

**Derivation cost (not prohibitive — now the authoritative path, not a fallback):**

| Step | When | Cost |
|------|------|------|
| `derive_output_secrets(combined_ss, idx)` → `ho`, `z`, `amount`, … | **Hydration** (`Restore`), and on resync — the authoritative opening recovery, not a cache rebuild | One HKDF expand per staked output (same as any received output) |
| `b` from `KeyEngine` | Claim build + nullifier reconciliation | Master-key lookup already on the hot path for signing |
| `x = ho + b` (scalar add mod ℓ) | Per stake per claim (transient, in `PrepareClaimBuild`) | O(1) per instance — negligible vs HKDF + scan |
| `N_S = x·G_S` | Per `(stake, S)` in accrued window | One scalar mult per settlement-epoch checked (≤15 tier-3); dominates add, still modest |

**Pin:** The stake record persists **nothing secret**. On hydration the actor
**re-derives `(amount, z)`** from the staked output (one `derive_output_secrets` per
instance) and holds the opening **in memory** for the session (zeroized on drop); on a
claim it re-derives `x` transiently. The held-on-hydration choice for `(amount, z)`
(re-derive once at `Restore`, hold for the session) is **deliberate over fully-transient**
(re-derive on every operation): `x` earns transient-per-claim because it is theft-grade
and the claim path already composes it; `(amount, z)` is claim-forgery-grade and is read
on every display poll, so holding the re-derived opening avoids a per-read `KeyEngine`
round-trip without weakening the at-rest posture — and crucially adds **no** marginal
at-rest exposure (nothing is persisted either way). The claim-build flow (R0-D4,
`PrepareClaimBuild` returns `(amount, z)` from the held opening) is **unchanged** by the
dissolution. **Exposure line flips:** worst-case wallet-at-rest exposure goes from
**claim-forgery-grade sealed material** to **no claim-grade secret at rest**.

**Two reopen criteria — distinct clauses, do not conflate:**

1. **(`x` transient cost — original R0-D8.)** Measured resync on mainnet-class stake
   counts shows `x` derivation dominates the UX budget *and* cannot be batched —
   evidence in `PERFORMANCE_BASELINE.md`, not a convenience argument. Reopens the
   *persist-`x`* question only.
2. **(`(amount, z)` re-derivability — the dissolution's own clause.)** A future
   ledger-pruning pass that evicts a **spent** staked output before all its accrued
   epochs are claimed breaks post-unstake opening re-derivation (the output's scan
   inputs are gone). Accrued epochs are claimable **indefinitely** after unstake (R0-D6,
   not age-bounded), so this reopener is **claim-completion-gated, not height-gated**: a
   pruning pass MUST check per-spent-staked-output claim-completion state before evicting,
   and reopens the *persist-`(amount, z)`* question only if that check is infeasible.

### 3.3.2 `EpochSet` wire/sealed encoding (Round 2 pin — fixed relative bitmask, not roaring)

**Decision: a fixed-width bitmask relative to the stake's creation settlement-epoch.
Reject roaring/croaring.**

**Size envelope (consensus-bounded).** `claimed_epochs ⊆ (creation, eff_lock]`, and the
lock window is consensus-pinned ([`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md)
§5–§6): tier-3 (longest) = 150,000 blocks ÷ 10,000 blocks/settlement-epoch =
**15 settlement-epochs**; tier-2 ≤ 3; tier-1 = 1–2. `MAX_EPOCHS_PER_CLAIM = 15` and
consensus rejects `|epochs| > 15`. So for **every** stake, `claimed_epochs` holds **≤15
elements drawn from a contiguous ≤15-wide window** — never sparse, never large.

**Encoding.** A **`u16` bitmask** anchored at the stake's first accrued settlement-epoch:
bit `i` set ⟺ settlement-epoch `(anchor + i)` is claimed, where `anchor` derives from the
canonical public `creation_height ≜ eligible_height` (§3.2 consensus pins; recoverable as
`effective_lock_until − tier_lock_blocks` and carried in `StakedOutputConfirmed`, §4.3) and
the §6.4 window arithmetic — **not stored in the set**. 16 bits ≥
the 15-epoch tier-3 maximum (one bit of headroom). Net: **2 fixed bytes per stake — no
base, no length prefix, no per-element payload.** (Width is the smallest standard integer
≥ the tier-3 window = `MAX_EPOCHS_PER_CLAIM`; if that constant grows, widen the fixed mask,
not the scheme.)

**Why not roaring.** Roaring/croaring compresses large *sparse* sets over a wide u32/u64
domain (thousands–millions of elements) via per-2¹⁶-chunk containers. At ≤15 elements over
a ≤15-wide window it is **pure overhead** — a container directory + header dwarfing the
data — plus a crate dependency (supply-chain + audit surface per
[`17-dependency-discipline.mdc`](../../.cursor/rules/17-dependency-discipline.mdc)) bought
for nothing. The fixed mask is smaller, dependency-free, and constant-size.

**Properties this buys.**

- **Payload-free (D2/D4 closure).** The absolute settlement-epoch index never enters the
  set: the anchor is the public `creation_height ≜ eligible_height`, the mask is purely
  relative. This is the
  concrete form of "heights live in the scanner, not `claimed_epochs`" (§4.7 D2) — there is
  literally no field in which a per-epoch height *could* be stored, which is what foreclosed
  the incremental reorg path (§5.2) by construction rather than by discipline.
- **Constant-size at rest.** The 2-byte mask does not vary with claimed-count, so the
  sealed-blob size leaks no claimed-epoch cardinality (sealed regardless — a clean bonus,
  not load-bearing).
- **Trivial reorg rebuild.** §5.2's clear-all/replay-all recomputes the mask from scratch
  (set bit `i` for each surviving `x·G_(anchor+i)` ∈ post-reorg chain) — no structural edit,
  no per-epoch height to reconcile.
- **Reorg-stable anchor (drain-gate construction).** The anchor `creation_height ≜
  eligible_height` is consensus-stamped at the staking subtree's deferred-insertion **drain**
  (`mining + MIN_AGE`, [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §6.4.3 ground
  iii / §11), and the drain anchor is **source-relative** — computed from the source block,
  not the drain-time tip (verified in `blockchain_db.cpp`). So the anchor is **stable under
  every reorg `≤ MIN_AGE` by construction**: a stake caught pre-drain has no anchor to move,
  and a drained stake's anchor is source-invariant under any reorg shallower than `MIN_AGE`
  (the same convergence that freezes `h_bind`). The **hot reorg path therefore pays nothing** —
  the 2-byte relative mask base does not move when only the drain block is popped, so §5.2's
  clear-all/replay-all recomputes the mask against an *unchanged* anchor. Only a reorg **deeper
  than `MIN_AGE`** re-mines the source and moves `eligible_height`; there the same §5.2
  full-rebuild re-derives the mask against the new anchor. That re-anchor is a **rare-path
  correctness item** — the `> MIN_AGE` catastrophic regime that already invalidates in-flight
  FCMP references broadly — **not a cost the common reorg path carries**, closing the
  anchor-mutability seam the `h_bind` re-stamp surfaced.

`claim_pending_epochs` (runtime-only) shares the in-memory `EpochSet` type but never
serializes (§3.4, D4), so this encoding governs exactly one set per stake.

**Reopen criterion.** A future tier whose lock exceeds the chosen mask width (widen the
fixed mask to `u32`/`u64`/`[u8; N]`, **same scheme** — still contiguous, still bounded),
**or** a redesign that makes `claimed_epochs` genuinely large-and-sparse over a wide domain
(it is not — the §6.4 lock arithmetic makes the window contiguous and ≤15). Roaring is
reconsidered only in the second case, which the consensus lock bounds currently forbid.

### 3.3.3 `StakeId` derivation (Round 2 pin — cSHAKE256, not cn_fast_hash, not BLAKE3)

**Decision:** `StakeId = cSHAKE256(customization = "shekyl/stake-id-v1",
input = tx_hash ‖ le_u64(index_in_transaction))`, **full 32-byte** output. Mirror the
in-workspace template `derive_output_handle`
([`shekyl-crypto-pq/handle.rs`](../../rust/shekyl-crypto-pq/src/handle.rs)) exactly:
`CShake256Core::new(cust)` → `update(tx_hash)` → `update(&index.to_le_bytes())` →
`finalize_xof` → read 32 bytes.

**Hash choice — modern, not inherited.** The Round-1 placeholder said BLAKE3; an
intermediate pass wrongly "corrected" it to `cn_fast_hash` on reuse grounds. Both are wrong.
`cn_fast_hash` ([`shekyl-crypto-hash`](../../rust/shekyl-crypto-hash/src/lib.rs)) is
**Keccak-256 with original CryptoNote padding (0x01, not SHA3's 0x06)** — a
**consensus-critical *inherited* primitive** whose stated purpose is byte-identity with
`src/crypto/keccak.c` / upstream Monero. Deriving a **new** wallet-local id with it drags
inherited legacy crypto into post-CryptoNote code, against the
[`00-mission.mdc`](../../.cursor/rules/00-mission.mdc) PQC-hardened / modern-not-inherited
posture. The correct primitive is **cSHAKE256** (FIPS 202 / SP 800-185), which is:

- **PQC-aligned.** SHAKE/Keccak-sponge is the hash family the PQC stack already uses
  (ML-KEM, SLH-DSA); cSHAKE256 is the workspace's established modern hash — `key_actor.rs`,
  `local_keys.rs`, `traits/key.rs`, and `handle.rs`'s `derive_output_handle` all use it.
- **Dependency-discipline-clean ([`17-dependency-discipline.mdc`](../../.cursor/rules/17-dependency-discipline.mdc)).**
  `sha3 = "0.10"` (exposing `CShake256` / `CShake256Core`) is **already a workspace
  dependency** (verified at source: `shekyl-crypto-pq`, `shekyl-shard-visual`), so no new
  crate. **`blake3` is *not* a workspace dependency** — adding it would incur a supply-chain
  / audit cost for *no* gain over the PQC-aligned primitive already in use. So the modern
  choice and the dependency-clean choice are the **same** choice; they only diverged in the
  intermediate cn_fast_hash misstep, which optimized reuse and ignored modern-not-inherited.
  The same misstep prompted a workspace-wide sweep tracked in
  [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) (V3.0): the wallet-local `SnapshotId`, the v31
  multisig / address fingerprints, **and** the consensus primitive itself (block/tx hash,
  `tree_hash`) — pre-genesis we *are* the hard fork, so the inherited consensus hash is a
  candidate too, not grandfathered (it earns its own spec-first consensus pass, since
  Keccak-256 is secure and the change is standards-alignment, not a security fix).

**Native domain separation (no hand-rolled prefix).** cSHAKE's `customization` parameter is
the SP 800-185 slot for application separation, so the domain lives there, not in a
`"domain ‖ …"` input prefix. `"shekyl/stake-id-v1"` is distinct from
`"shekyl/output-handle-v1"`, so `StakeId` cannot collide with `derive_output_handle` even
though both absorb `tx_hash`. Input fields are fixed-width (`OutputRef`'s index is a `u64`,
[`shekyl-scanner/output.rs`](../../rust/shekyl-scanner/src/output.rs)), so no length prefix
is needed. Output is the **full 32-byte** XOF read (`StakeId` is `[u8; 32]`; the primary key,
not a truncated dedup key). No `view_secret` in the input — `StakeId` is a non-secret
wallet-local key, not a secret-keyed handle.

**Stability is load-bearing.** The id derives **only** from the on-chain output identity
`(tx_hash, index)`, so re-derivation across rescans/sessions is byte-stable — which is what
lets `StakedOutputConfirmed` / `OwnNullifierObserved` events and the R0-D2 rebuild (§5.2)
map back to the **same** persisted `StakeInstance`. A derivation change silently orphans
persisted instances; the `v1` customization is the guard, pinned by a **wallet-internal KAT**
(the `customization_bump_produces_distinct_handle` pattern in `handle.rs`) — distinct from a
consensus KAT, as `StakeId` never reaches the wire or consensus.

**Reopen criterion.** A `v2` customization bump requires a persistence migration; pre-genesis
that is `rm -rf ~/.shekyl` + re-sync
([`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc)), so the bump is
cheap now and costly post-genesis — pin v1 deliberately.

### 3.4 Pending-claim model (Round 2 pin — Hybrid-B / E)

**Substrate (verified at source).** A claim is **non-spending** (§8.7) — it consumes no
output and has no `OutputId`. `PendingTxEngine`'s reservation is output-UTXO-keyed: the
runtime-only `BTreeMap<ReservationId, Reservation>` locks `selected_transfer_indices`
(spend outputs), and a concurrent build filters out indices "already cited by an existing
reservation" ([`engine/pending.rs`](../../rust/shekyl-engine-core/src/engine/pending.rs)
`Reservation`, `build_pending_tx_in_state`). A claim has no `selected_transfer_indices`,
so there is nothing for the output-reservation to lock. The resource a claim actually
reserves is the **epoch-nullifier set** (don't build a second claim for epochs already
in flight) — a staking-domain object, not an output. This rules out the three Round-1
options as written: track-in-`PendingTxEngine` (no lock exists for a non-spending tx),
sub-state-mirroring-`PendingBroadcast` (duplicates a lifecycle that, see below, is not
one thing), and per-claim mini-FSM (over-built).

**Pin — the reservation is domain-local and runtime-only.** The stake actor gains
`claim_pending_epochs` (§3.3): add `S` on claim broadcast, fold into `claimed_epochs` on
confirm, clear on discard / staleness-reject / reorg-before-confirm. The discard-clear is
**wired explicitly, not assumed**: the orchestrator's general pending-tx discard path
dispatches `AbandonClaim` (§4.7) for claim-type txs (§6), so "rides the normal path" does
not silently drop the staking side-effect. It is **runtime-only**,
mirroring `PendingTxEngine`'s own reservation crash model ([`engine/pending.rs`](../../rust/shekyl-engine-core/src/engine/pending.rs)
"Why runtime-only", lines 15–27): a built-but-unconfirmed tx self-heals on reopen because
it left no authoritative chain trace. On resync `claim_pending_epochs` starts empty; the
R0-D2 rebuild (§4.2, §5.2) re-derives `claimed_epochs` from the chain nullifier set ∩
`{x·G_S}`. A claim that landed → its nullifier is on-chain → folded into `claimed_epochs`
(not rebuilt); a claim broadcast-but-unlanded → epoch claimable again → wallet may rebuild
→ **consensus rejects the duplicate nullifier-spend**. This is the *identical* self-heal +
consensus-backstop posture the engine already accepts for forgotten output reservations
(double-spend attempt → rejected). Consequence: only `claimed_epochs` persists (to the
ledger region) / reaches the `Snapshot` wire; the opening is re-derived (§4.2) and
`claim_pending_epochs` is ephemeral, so the `EpochSet` encoding carries **one set per
stake, not two**.

**Privacy residual (checked, contained, not claim-specific).** A crash-rebroadcast of an
unlanded claim re-emits an **identical** nullifier `N_S = x·G_S` (deterministic; DDH only
hides *distinct-epoch* nullifiers), so the two attempts are trivially linkable. This is
**not** a claim-specific wrinkle: a duplicate spend re-exposes an identical key image with
the same trivially-linkable structure, a residual the engine already accepts. It is
contained — it links one claim's two attempts, never the stake's other (distinct-epoch,
DDH-unlinkable) claims. The spend analogy extends cleanly to privacy.

**Where the lifecycle lives — Hybrid-B, in the E shape.** `PendingTxEngine` stays
**spend-pure** (its `output_locks`-equivalent remains the single source of truth for
*output* ownership). The "broadcast→confirm→reorg lifecycle" is **not one thing** in
`PendingTxEngine`: its lifecycle is `build → submit → done`, and `in_flight` is only the
daemon-round-trip window ([`engine/pending.rs`](../../rust/shekyl-engine-core/src/engine/pending.rs)
`ReservationTTLConfig::in_flight`, "`submit` is mid-flight"), with the reservation removed
at submit. Decompose:

1. **Reservation / conflict-prevention** — `claim_pending_epochs`, stake actor (above).
   Forced domain-local.
2. **Confirm + reorg** — *already shared, by construction*: RefreshEngine scan observes
   the marker (key image for spends, **nullifier** for claims) and §5.2 rewinds it. The
   transition table (§3.2) and §5.2 already encode the claim side. **Zero duplication.**
   This leg's verification lives in the still-open §5 box (the R0-D2 rebuild re-run against
   the post-reorg nullifier set) — §3.4 leans on §5, the two are coupled, and §5 carries
   the sign-off of the leg, not a new mechanism.
3. **Submit-time staleness gate** — the *only* `PendingTxEngine`-specific pre-broadcast
   sliver (`built_at_height` / `built_at_tip_hash` / `snapshot_id` → `TooOld` /
   `ChainStateChanged` / `SnapshotInvalidated`). Those staleness tags are already cleanly
   separable from the output-lock part in the `Reservation` struct. The claim path
   **duplicates this ~10-line gate** rather than abstracting it (E shape) — see §8.9 for
   the factoring trigger.

**Rejected — Hybrid-A** (admit a lockless in-flight entry to `PendingTxEngine`): re-merges
at the wallet layer the claim/spend separation we drew at consensus (non-spending claim vs.
SAL spend), eroding "outputs = single source of truth for output ownership." **Rejected —
Option C** (the *honest* generalization of A: generalize the reservation to abstract
resources): drags epoch-nullifier-conflict semantics (staking-domain) into the spend
engine — a worse boundary break than A's exception. C is named to show A was not hiding a
clean form. Both reject; B preserves the separation.

**Consensus-backstop principle (why E and runtime-only are both safe).** Both decisions
ride one fact: **consensus is the source of truth; the wallet-side checks are best-effort.**
The staleness gate is a consensus-backstopped UX optimization — a stale claim is rejected
at consensus regardless, so the gate exists only to avoid wasting a broadcast, and drift
between a duplicated copy and `PendingTxEngine`'s is benign (worst case: one path
occasionally broadcasts a doomed tx). The same backstop makes runtime-only
`claim_pending_epochs` safe (forgotten reservation → duplicate → consensus rejects). The
corollary is the §8.9 reversion condition: the moment a future tx-type puts a
**soundness-load-bearing check with no consensus backstop** on that path, drift stops being
benign and the shared primitive earns its keep.

**Ratifications (not shape):** `Accruing` / `Claimable` stay separate (§8.3 — the
drain-backlog window is a genuine "earning, not yet claimable" state; collapsing it would
let the UI offer a claim the verifier rejects for an unsettled epoch). `PendingBroadcast`
discard drops the instance (transition table — a discarded pending stake/claim is a
non-event on-chain; a terminal `Discarded` would persist a non-event). R0-D6 (post-unstake
claims) is confirmed in the table, not re-decided.

---

## 4. Persistence and engine ownership

### 4.1 What lives where (architectural pin)

| State | Owner at runtime | Persisted | Secret? |
|-------|------------------|-----------|---------|
| Per-output chain flags (`staked`, `stake_tier`, `stake_lock_until`) | `LedgerEngine` / `TransferDetails` | `LedgerBlock.transfers` | No |
| Public rate / band-sum observation (per epoch) | `LedgerEngine` / `LedgerIndexes` (repurposed `StakerPoolState`) | **No** (rebuilt on scan) | No |
| Per-stake FSM (`StakeInstance`, incl. `band`, `claimed_epochs`) | **`StakeEngine` actor** | **Yes** — `LedgerBlock` field (§4.2) | Mixed |
| Per-stake **opening** (`amount`, `z` only) | **`StakeEngine` actor** (in memory) | **No — runtime-only** (re-derived at hydration, §3.3.1 / §4.2) | **Yes in memory; none at rest** (claim-grade; not `x`) |
| **Claim reservation** (`claim_pending_epochs`) | **`StakeEngine` actor** | **No — runtime-only** (§3.4) | No (epoch indices only) |
| Pending stake/unstake **spend** intents | `PendingTxEngine` (spend-pure, §3.4) | `TxMetaBlock` / pending metadata | partial |
| Public rate schedule `ρ_e` / band params | `EconomicsEngine` + chain mirror | N/A (derived) | No |

**Secret-locality pin** ([`36-secret-locality.mdc`](../../.cursor/rules/36-secret-locality.mdc),
R0-D3): `StakeOpening` is **never at rest** — re-derived on hydration (§3.3.1 / §4.2),
held in memory only, zeroized on drop, and never crosses RPC, logs, or **kameo `ask`
payloads** as plaintext. Openings enter the actor only by **in-task re-derivation** at
`Restore` (and at build-time registration, as a `Secret<StakeOpening>` moved in-process
from the orchestrator's build context — an in-RAM secret move, not a sealed disk blob,
since nothing is sealed) — not via `ListStakes` or other query messages, and **not**
carried by `Snapshot`. The orchestrator holds handles only. RPC projections (§7) expose
**public** fields and **derived amounts** (claimable totals) plus `principal_spent`;
never `z`. Neither the opening `(amount, z)` nor the spend secret `x` is in stake
persistence (§3.3.1).

### 4.2 Persistence schema (byte layout gate for Round 2)

**Pin:** extend [`LedgerBlock`](../../rust/shekyl-engine-state/src/ledger_block.rs)
with a stakes collection that persists **public fields + `claimed_epochs` only** — there
is **no sealed sub-region for stakes** (opening dissolution, §3.3.1):

```rust
pub stakes: Vec<StakeInstance>, // public fields + claimed_epochs in the ledger region;
                                // `opening` is NOT serialized — re-derived on hydration
```

- The public `StakeInstance` fields and `claimed_epochs` co-locate with the ledger
  region. The opening `(amount, z)` is **not written anywhere** — it is re-derived from
  the staked output on hydration (§3.3.1). No `file_kek`-protected stake blob exists.
- Bump `LEDGER_BLOCK_VERSION` + `WALLET_LEDGER_FORMAT_VERSION` per
  [`42-serialization-policy.mdc`](../../.cursor/rules/42-serialization-policy.mdc).
- Postcard schema snapshot co-lands in the same implementation PR as the struct.
- Pre-genesis: no migration loader — version mismatch → resync.

**Recovery / hydration (R0-D2 — the authoritative opening path, not a fallback):**

| Stake state at disconnect | Recovery path |
|---------------------------|---------------|
| `PendingBroadcast` / `Unconfirmed` | `PendingTxEngine` + `TxMetaBlock` (same as transfer path); stake actor does **not** infer from chain alone |
| `Active` / `FullyUnstaked` (confirmed on-chain) | Scan + `derive_output_secrets` → **re-derive** `StakeOpening` (`amount`, `z`). This is the *sole* opening path — open and resync are one operation, not cache-vs-rebuild |
| `claimed_epochs` (all confirmed states) | **Rebuild** from stake-claim nullifier set ∩ `{ x·G_S : S ∈ accrued_epochs }` where **`x` derived transiently** (`ho` + `b` via §4.7 / §8.8) — persisted set is cache, not authority |

Post-resync, run one reconciliation pass per restored instance (§5.2) before serving
claims. Pending stakes without tx meta may lose in-flight stake intents — same posture
as pending transfers.

**Hydration:** `Wallet::open*` loads stakes (public fields + `claimed_epochs`) →
`StakeEngineHandle::restore(instances)`, which **re-derives `opening`** from each staked
output inside the actor task (no sealed buffer to unseal — there is none).
**Flush:** `PersistenceEngine::save` snapshots the actor registry → ledger region only
(public fields + `claimed_epochs`); the opening is never written.

### 4.3 `StakeEvent` and merge protocol

Extend [`StakeEvent`](../../rust/shekyl-engine-core/src/scan.rs) (`#[non_exhaustive]`).
The cleartext `ClaimObserved { staked_output_index, watermark_to, claimed_amount }`
is **replaced** — there is no public index or cleartext amount to observe.

```rust
pub enum StakeEvent {
    /// Public rate / band-sum observation for the rate-epoch covering `height`.
    /// Repurposed from the old pool-accrual aggregate: carries the public rate and
    /// band aggregate the wallet needs to compute exact yield — NOT a pool denominator.
    RateEpochObserved { height: u64, rate_epoch: u64, rho: u64, band_sum: u128 },

    /// Staked commitment first observed at `height`.
    StakedOutputConfirmed {
        height: u64,
        output: OutputRef,
        commitment: [u8; 32], // C_stake; wallet opens with its own z
        tier: StakeTier,
        band: StakeBand,
        creation_height: u64,
    },

    /// One of the wallet's OWN nullifiers observed on-chain (a claim landed).
    /// Recognized by matching against locally derived N_{i,S}. No public index.
    OwnNullifierObserved {
        height: u64,
        stake_id: StakeId,
        settlement_epoch: u64,
    },

    /// Principal commitment spent (unstake), via membership proof.
    StakedOutputSpent {
        height: u64,
        output: OutputRef,
    },
}
```

**Merge split (load-bearing):**

1. **`LedgerEngine::apply_scan_result`** applies `RateEpochObserved` into the
   repurposed `LedgerIndexes` rate/band cache (public, rebuildable).
2. **Per-stake variants** (`StakedOutputConfirmed`, `OwnNullifierObserved`,
   `StakedOutputSpent`) are forwarded to `StakeEngine` after ledger apply (§5.3).
   *Round 1 may collapse to a single merge hook if cross-engine ordering is simpler —
   must not use a `tokio::join!` stale snapshot.*

> **Scanner note (upstream-dependent):** recognizing `StakedOutputConfirmed` and
> `OwnNullifierObserved` requires the scanner to parse the confidential stake/claim
> wire shapes and to derive `N_{i,S}` for the wallet's stakes. That parsing is gated
> on the consensus design closing its wire format. Until then this is design-only.

**R0-D7 — not a rename:** `RateEpochObserved` replaces cleartext `AccrualRecord` /
pool-division `StakerPoolState::estimate_reward()`. Stage 3 grep plan must **delete**
`AccrualRecord` and the estimate_reward path, not alias the old type. Introduce
`RateEpochRecord { rho, band_sum, rate_epoch }` in `shekyl-engine-state` when the
scanner lands.

### 4.4 `RefreshSummary::stake_events`

```rust
pub struct RefreshSummary {
    // existing fields…
    /// Count of `ScanResult::stake_events` processed this refresh (all variants).
    pub stake_events: usize,
    /// Stakes whose `StakeState` or claimed-epoch set changed (UI badges).
    pub stakes_updated: usize, // Round 2 — may defer
}
```

### 4.5 `EconomicsEngine` consumption (not a sub-trait) — **changed**

The pool-denominator consumption is **removed**. `StakeEngine` now calls:

- `rate_at_epoch(rate_epoch) -> Result<u64, Self::Error>` (public `ρ_e`) for **exact** yield
  computation — semantics finalized in §8.6 (`rate_epoch` is an index, `Ok(0)` ≠ `Err`).
- `parameters_snapshot()` for tier multipliers / band parameters / decay display.

The wallet computes its own claimable backlog as
`Σ_{unclaimed S ⊆ (creation, eff_lock]} own_weight × K_S`, where
`K_S = Σ_{rate-epochs e ∈ S} ρ_e × rate_epoch_blocks` (all public) and
`own_weight = amount × tier_multiplier / SCALE` (amount secret, multiplier public).

**Reversion clause (§8.2):** methods on `EconomicsEngine` that take `stake_id` or
encode per-stake state remain **rejected** — reopen only via §10.6.1 in the
trait-boundaries doc. The old `pool_weighted_total()` consumption is **retired** (R0-D5,
finalized §8.6): the [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
amendment has landed (all 7 sites); Stage 3 co-lands the corresponding **code** swap.

### 4.6 `StakeEngine` trait surface (draft)

```rust
// Async/sync convention (RATIFIED, not a choice): actor-routed methods return
// `impl Future<…> + Send` (RPITIT), matching the established KeyEngine /
// PendingTxEngine / RefreshEngine / PersistenceEngine / DaemonEngine idiom —
// the `Send` bound is part of the trait contract because the wallet-RPC / CLI /
// GUI call sites are async and require it. NOT bare `async fn` (drops the `Send`
// bound from the contract), NOT `async_trait` (a fifth-engine wart). The trait
// stays `Send + Sync + 'static`. Every method is async: no handle-side StakeView
// cache is built now (see the §4.6 note below — anti-pre-provisioning), so every
// call routes through the actor mailbox.
pub(crate) trait StakeEngine: Send + Sync + 'static {
    type Error: Into<StakeEngineError>;

    /// Register a new instance when the user builds a stake. The opening is a
    /// **runtime-only `Secret<StakeOpening>` from the build context** — moved in-process
    /// into the actor, never sealed/persisted (§4.2 dissolution; §4.7, R0-D3). On a later
    /// open it is re-derived, not restored from a blob.
    /// **Forced-async:** moves the opening secret into the actor — serializes through
    /// the actor turn (secret-locality-by-construction).
    fn register_pending_stake(
        &self,
        instance: StakeInstance,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Apply scan-derived events after ledger merge (ordered — §5.3).
    /// `reorg_rewind: Some(_)` is handled **rewind-first within this one call** (D1/D2,
    /// §5.2): one uninterruptible actor turn, so nothing interleaves between the rewind
    /// and the forward replay and `claimed_epochs` is never observed half-rebuilt. No
    /// separate rewind entry point exists — mirrors the ledger's `reorg_rewind` field
    /// (`merge.rs::apply_scan_result_to_state`), not a standalone message.
    /// **Forced-async:** mutates actor state under the rewind-first-atomicity turn.
    fn apply_stake_events(
        &self,
        tip_height: u64,
        events: Vec<StakeEvent>,
        reorg_rewind: Option<ReorgRewind>,
    ) -> impl std::future::Future<Output = Result<StakeApplySummary, Self::Error>> + Send;

    /// Query API backing `Wallet::stakes(filter)`. Public fields + derived amounts only.
    /// **Read (all-async now):** display-grade, stale-tolerant, consensus-backstopped —
    /// no read feeds an unvalidated security decision (the soundness lives in
    /// `prepare_claim_build` + consensus). Async via the mailbox until a measured
    /// performance gate earns a handle-side cache (see §4.6 note).
    fn list_stakes(
        &self,
        filter: StakeFilter,
    ) -> impl std::future::Future<Output = Result<Vec<StakeView>, Self::Error>> + Send;

    /// Exact claimable backlog across instances (sum of unclaimed-epoch entitlements).
    /// Returns the `AtomicUnits` domain newtype, not raw `u64`: the cross-instance sum
    /// is exactly where overflow / unit-confusion bugs live, so the checked-arithmetic
    /// newtype belongs here in the engine, not wrapped at the §6 boundary. `u64`
    /// reappears only at the true edges (postcard, FFI, consensus amount boundary).
    /// (The type carries the "atomic" meaning, so the `_atomic` method suffix is dropped.)
    /// **Read (all-async now):** display-grade per the `list_stakes` note — it does
    /// **not** feed an unvalidated decision; `prepare_claim_build` re-validates inside
    /// its turn, so this read is stale-tolerant (consensus-backstopped) like any other.
    fn claimable_rewards(
        &self,
        tip_height: u64,
    ) -> impl std::future::Future<Output = Result<AtomicUnits, Self::Error>> + Send;

    /// Set of unclaimed settlement-epochs for a stake (drives `Wallet::claim`).
    /// **Read (all-async now):** display/UX input only; authority is `prepare_claim_build`
    /// (re-validated against current `claimed_epochs`/`claim_pending_epochs`), so a stale
    /// answer at worst proposes a doomed claim consensus rejects — same backstop as §8.9.
    fn unclaimed_epochs(
        &self,
        stake_id: &StakeId,
        tip_height: u64,
    ) -> impl std::future::Future<Output = Result<EpochSet, Self::Error>> + Send;

    /// Single-use witness bundle for claim tx construction (R0-D4). Zeroized on drop;
    /// consumed by `PendingTxEngine` + `KeyEngine` — never persisted outside the actor.
    /// **Side-effect (D3):** unions `epochs` into the runtime-only `claim_pending_epochs`
    /// reservation (§3.4) — the one point already holding `(stake_id, epochs)`. Idempotent
    /// under set-union; a leaked reservation (build fails after prepare) self-heals.
    /// **Authoritative claim path (stands alone):** re-validates `epochs` against current
    /// `claimed_epochs`/`claim_pending_epochs` inside its own actor turn and does **not**
    /// consume read output as trusted — so no read feeds an unvalidated security decision.
    /// This is what makes all reads above display-grade (and, when a cache is built, lets
    /// it cover reads uniformly with this method as the single validation point).
    /// **Forced-async:** moves secret witness material out, in-turn.
    fn prepare_claim_build(
        &self,
        stake_id: &StakeId,
        epochs: EpochSet,
    ) -> impl std::future::Future<Output = Result<ClaimBuildSecrets, Self::Error>> + Send;

    /// Release a claim reservation when the orchestrator abandons the build/broadcast
    /// (staleness gate §8.9, or `PendingTxEngine` discard). Without it a discarded claim's
    /// epochs stay pending until restart. **Touches `claim_pending_epochs` ONLY — never
    /// `claimed_epochs`** (D3): the latter's sole authority is the on-chain nullifier via
    /// `OwnNullifierObserved`, so a mistimed abandon (declared stale while the claim
    /// actually lands) is harmless — it clears a reservation that would have cleared on
    /// confirm anyway. Wiring this to un-mark `claimed_epochs` would reintroduce a
    /// double-claim seam the consensus backstop would then have to catch.
    /// **Forced-async:** mutates actor state, in-turn.
    fn abandon_claim(
        &self,
        stake_id: &StakeId,
        epochs: EpochSet,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Projected yield for an **existing** stake over a horizon (divide-by-zero N/A under
    /// fixed rate; guarded anyway). Returns `AtomicUnits` (computed amount → domain type).
    /// No pre-stake projection exists: a forward estimate over an unstaked principal would
    /// have to project the public rate forward and overpromise (§8.6 forward-uncertain) —
    /// deliberately omitted, not overlooked.
    /// **Read (all-async now):** display-grade per the `list_stakes` note.
    fn projected_yield(
        &self,
        stake_id: &StakeId,
        horizon_blocks: u64,
    ) -> impl std::future::Future<Output = Result<AtomicUnits, Self::Error>> + Send;

    /// ArchivalEngine sibling query (Stage 5 consumer).
    /// **Read (all-async now):** display-grade. If Stage 5's `ArchivalEngine` polls this
    /// (and `stake_tier`) frequently, that is the **named measured-performance candidate**
    /// that first earns the handle-side cache its keep (§4.6 note reversion clause).
    fn is_active_staker(
        &self,
        entity_id: &EntityId,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send;
}
```

`StakeView` is the **owner-grade** projection of `StakeInstance`, for the owner's own UI
and owner-authenticated RPC. It is secret-free (never `opening` / `z` / `x` / raw
`amount`) and makes `stakes()` self-sufficient for the per-stake `claim(stake_id)`
decision — the completeness gap the global `claimable_rewards()` left open:

```rust
pub struct StakeView {
    pub id: StakeId,
    pub tier: StakeTier,             // public
    pub band: StakeBand,             // public coarse band
    pub state: StakeState,
    pub claimable: AtomicUnits,      // per-stake unclaimed-epoch entitlement (derived)
    pub claimed_epochs: EpochSet,    // per-stake claim progress (UX)
    pub unlock_height: u64,          // creation_height + tier_lock_blocks; unstake countdown
    // never: opening, claim_pending_epochs (runtime-only), z / x / raw amount
}
```

**Owner-grade caveat (trust boundary).** Per-stake `claimable` is a deterministic
function of the confidential principal and public params
(`amount = claimable / (tier_num · ΣK_S · |unclaimed|)`), so surfacing it **discloses the
staked amount**, and `claimed_epochs` **discloses the per-stake claim pattern**. That is
acceptable for the owner's own UI / owner-authenticated RPC and **forbidden** for the
§7 lens-3 diagnostic projection. The lens-3 projection is therefore a **distinct,
more-redacted shape** — global claimable total + coarse state only, **no** per-stake
`claimable`, **no** per-stake `claimed_epochs`. One struct cannot serve both trust grades;
`StakeView` must not be reused as the lens-3 projection. (`unlock_height` is
`creation_height + tier_lock_blocks` — both public — so it carries zero marginal privacy
cost and has a named consumer: the lock-gated `unstake()` readiness countdown.)

**Async/sync split (RESOLVED — last Phase 2b field residual).**

- **Idiom: ratified, not chosen.** RPITIT-`+ Send` for every actor-routed method,
  matching the established five-engine idiom (`KeyEngine`, `PendingTxEngine`,
  `RefreshEngine`, `PersistenceEngine`, `DaemonEngine` — each mixes sync reads with
  RPITIT-`+ Send` actor ops; `Send` is in the trait contract for the async call sites).
  A fifth-engine `async_trait` / bare `async fn` would be a consistency wart, not a
  neutral alternative. Trait stays `Send + Sync + 'static`.
- **Forced-async four:** `register_pending_stake`, `apply_stake_events`,
  `prepare_claim_build`, `abandon_claim` — architecture-forced (secret-locality-by-
  construction + rewind-first atomicity), not a call to make.
- **Reads: all-async now; no `StakeView` cache.** The anti-pre-provisioning default —
  every read routes through the mailbox. This is safe because **no read feeds an
  unvalidated security decision**: `prepare_claim_build` is the authoritative path
  (stands alone, re-validates against current `claimed_epochs`/`claim_pending_epochs`
  in-turn), so every read is display-grade / stale-tolerant / consensus-backstopped —
  the §8.9 staleness-gate-is-UX-not-soundness principle. The claim-feeding reads
  (`claimable_rewards`, `unclaimed_epochs`) are **not** a special async-forever
  case; they are display-grade like the rest.
- **Reversion clause (rule 21) — measured, with a named candidate.** Build the
  handle-side `StakeView` cache **when UI read-latency or mailbox contention is
  *measured* to be a problem** (`PERFORMANCE_BASELINE.md` evidence, not a passive "if a
  snapshot already exists"). Concrete candidate on the horizon: Stage 5's
  `ArchivalEngine` cross-actor `is_active_staker` / `stake_tier` polling — if frequent,
  that is the consumer that first earns the cache (the same way Stage 5 is the Option-E
  factoring candidate). **Cache shape is confirmed at build time, not pre-baked:**
  because the soundness lives in `prepare_claim_build` + consensus (never in a read),
  the claim-feeding-vs-public distinction collapses, so the cache almost certainly
  covers **all** reads uniformly with `prepare_claim_build` as the single validation
  point. The one fact that confirms uniform-vs-hybrid is build-time: does
  `prepare_claim_build` stand alone (it must, to be authoritative)? — so do not pre-bake
  the shape now.

### 4.7 Actor protocol (Stage 3 implementation target)

Mirror [`KeyEngineHandle`](../../rust/shekyl-engine-core/src/engine/key_actor.rs):

| Message | Direction | Notes |
|---------|-----------|-------|
| `RegisterPendingStake(StakeRegistration)` | orchestrator → actor | after `build_pending_tx`; carries a `Secret<StakeOpening>` moved in-process from the build context (not a sealed blob — nothing is sealed; R0-D3) |
| `ApplyStakeEvents { tip_height, events, reorg_rewind: Option<ReorgRewind> }` | orchestrator → actor | post-ledger-merge; **`reorg_rewind: Some(_)` handled rewind-first in one uninterruptible turn** (D1/D2) — no separate `RewindTo` |
| `ListStakes(StakeFilter)` | orchestrator → actor | read-only; returns `StakeView` |
| `ClaimableRewards { tip_height }` | orchestrator → actor | read-only; returns `AtomicUnits` |
| `UnclaimedEpochs { stake_id, tip_height }` | orchestrator → actor | read-only; feeds claim builder |
| `PrepareClaimBuild { stake_id, epochs }` | orchestrator → actor | returns zeroized `ClaimBuildSecrets` (R0-D4); **side-effect: unions `epochs` into `claim_pending_epochs`** (D3) |
| `AbandonClaim { stake_id, epochs }` | orchestrator → actor | release reservation on staleness/discard; **`claim_pending_epochs` ONLY, never `claimed_epochs`** (D3) |
| `ProjectedYield { stake_id, horizon }` | orchestrator → actor | uses rate snapshot — Round 2 plumbing |
| `IsActiveStaker(EntityId)` | orchestrator → actor | public for archival |
| `Restore(StakeSnapshot)` | orchestrator → actor | wallet open; **re-derives openings in-task** from each staked output (no sealed buffer — nothing is sealed); **`claim_pending_epochs` starts empty** (D4) |
| `Snapshot()` | orchestrator → actor | wallet save; returns **public fields + `claimed_epochs` only** — **no opening** (re-derived on `Restore`, §4.2 dissolution), **excludes `claim_pending_epochs`** (D4; one payload-free `EpochSet`/stake) |

**Reorg semantics (D1/D2) — fold, then clear-all/replay-all.** `reorg_rewind` rides on
`ApplyStakeEvents`, not a separate message: handled rewind-first in one actor turn it buys
**atomicity** — nothing interleaves between rewind and forward replay, so `claimed_epochs`
is never observed half-rebuilt (the race a standalone `RewindTo` would admit). The rewind
is **not** a height-selective trim: `claimed_epochs` is payload-free (§3.3), so there is no
per-epoch height to trim on (same forcing argument as §5.2). It is **clear-all / replay-all
of the full surviving own-nullifier set across the *whole* post-reorg chain** — *not* just
the re-scanned `[fork_height, tip]` window. An instance created below `fork_height` whose
lock straddles it has claimed epochs on **both** sides; replaying only the window would
clear-and-never-re-emit its below-fork survivors, leaving the wallet to build a doomed
re-claim (consensus rejects it, but at the cost of a wasted tx and the duplicate-nullifier
linkage residual). The full re-emit is affordable for the same reason the rebuild is: the
own-nullifier set is bounded by the wallet's own claim activity (≤15 tier-3/instance).
**Heights live in the scanner, not the actor:** the scanner is block-indexed, trims its
observation log to the post-reorg chain, and re-emits the surviving `OwnNullifierObserved`
set — which is exactly why `claimed_epochs` stays payload-free and the D4 wire is a clean
size/encoding call (a scanner-computed height-free epoch-index delta is possible, but not
worth the bug surface given the set is small).

**Fail-stop:** **mandatory** for the stake actor (Stage 2 §4.5) — a panic could leave
the claimed-epoch set or the **in-memory** opening inconsistent (the opening is never at
rest, but it is live in RAM during the session — §3.3.1 / §4.2).

**Secrets (R0-D3, R0-D4):** actor messages carry **no** master view/spend keys and **no
plaintext `StakeOpening` on query paths**. The opening is **never persisted/sealed**:
`RegisterPendingStake` moves a `Secret<StakeOpening>` **in-process** from the build
context; `Restore` **re-derives** the opening in-task from each staked output; `Snapshot`
carries **no** opening. Nullifier checks derive **`x` transiently** (`ho` for
`staked_output` + `b` from `KeyEngine` via orchestrator — not from `StakeOpening`;
§3.3.1). Claim construction: orchestrator calls `PrepareClaimBuild` → composes stake
material + derived `x` → passes one zeroized `ClaimBuildSecrets` to `PendingTxEngine` +
`KeyEngine`; openings are **not** duplicated in `PendingTxEngine` persistence.

**Cross-engine composition (R0-D4, R0-D8) — the deeper constraint.** A claim proof needs
stake opening (`amount`, `z` — stake actor, held in memory) **and** spend authority
(`b` / `x` — `KeyEngine` + output derivation) **together** in-process; **neither
`(amount, z)` nor `x` is persisted** (§4.2 dissolution). `prepare_claim_build` feeds a
**single prover invocation**
— a **new claim prove path** (not today's spend-only `shekyl_sign_fcmp_transaction`):
**staking-subtree** membership (current root, 5-scalar leaf) + **`h_bind`** equality +
**(A)** bounded-remainder + **(B)** emitting `N_S = x·G_S`; wallet recomputes `N/D` before
prove. Round 2: prove placement; staking-subtree path tracking + cross-tree atomicity.

---

## 5. Refresh reconciliation

### 5.1 Data flow

```mermaid
sequenceDiagram
    participant W as Wallet orchestrator
    participant R as RefreshEngine
    participant L as LedgerEngine
    participant S as StakeEngine actor
    participant E as EconomicsEngine

    R->>W: ScanResult
    W->>L: apply_scan_result(scan) .await
    Note over L: RateEpochObserved into rate/band cache
    W->>S: ApplyStakeEvents(per_stake + tip) .await
    Note over S: Advance FSM; mark claimed epochs from own nullifiers
    W->>E: rate_at_epoch (for exact yield summary)
```

### 5.2 Reorg — **expanded for nullifiers**

When `ScanResult.reorg_rewind` is `Some(fork_height)`:

1. Ledger merge runs `handle_reorg` (existing); the rate/band cache truncates.
2. Stake actor receives `ApplyStakeEvents { reorg_rewind: Some(ReorgRewind { fork_height }), .. }`
   (D1 — folded onto the apply call, **not** a separate `RewindTo`; handled rewind-first in
   one uninterruptible turn so `claimed_epochs` is never half-rebuilt, §4.7) and must:
   - drop/rewind instances confirmed at or above `fork_height`; reset pending states
     tied to the abandoned chain;
   - **rebuild `claimed_epochs` against the post-reorg nullifier set** — recompute
     `claimed_epochs = { S ∈ accrued_window : x·G_S ∈ post-reorg on-chain stake-claim
     nullifier set }` per affected instance. This is the **single authoritative un-claim
     mechanism**, *not* an incremental "remove epochs observed at/above `fork_height`":
     `claimed_epochs` is a pure settlement-epoch index set (§3.3) carrying **no per-epoch
     observation height**, so there is no field to filter incrementally on — and adding
     one would **foreclose the fixed `u16` relative bitmask** the wire encoding pins (§3.3.2;
     a height-carrying set is not a plain bitmask). The collapse is
     therefore **forcing, not preferential**: the incremental path requires a field that
     does not exist and should not, and the rebuild is the height-free operation §3.4
     already names; the wire de-risk is a consequence, not the rationale. The rebuild
     is the *same* operation as step 5 / R0-D2 — a surviving nullifier stays claimed; one
     reorged out (absent from the post-reorg set) returns to claimable. Mirrors the
     consensus requirement that the on-chain nullifier set is reorg-state; a
     reorged-then-re-mined claim must be re-claimable. Cost is the §3.3.1 derivation
     budget (one scalar mult per accrued epoch checked, ≤15 tier-3) per active instance —
     same posture as resync, bounded. The rebuild is **clear-all / replay-all of the full
     surviving set across the whole post-reorg chain**, never just `[fork_height, tip]`: a
     below-`fork_height` instance whose lock straddles the fork has claimed epochs on both
     sides, and a windowed replay would drop its below-fork survivors (§4.7 D2). The
     scanner supplies the surviving set — it is block-indexed, trims its observation log to
     the post-reorg chain, and re-emits `OwnNullifierObserved`; the heights live there, not
     in `claimed_epochs`.
   - **`claim_pending_epochs` (runtime-only) is never populated by reorg.** Both reorg
     sub-cases land at **claimable**, not at the reservation: (a) a *confirmed* epoch
     whose nullifier was reorged out drops from `claimed_epochs` (the rebuild above) →
     claimable; (b) an *in-flight* claim whose build the reorg invalidated (reference
     block reorged before its nullifier confirmed) clears from `claim_pending_epochs`
     (§3.2 row) → claimable. The reservation is set only by an active local
     build/broadcast (§3.4), never reconstructed by reorg or `Restore` (on `Restore` it
     starts empty). Self-heal is per §3.4: re-observed → claimed again; not re-mined →
     claimable and re-buildable, with consensus duplicate-nullifier rejection as backstop.
3. The exact yield re-derives automatically from the (now rebuilt) `claimed_epochs`
   and the public rate schedule.
4. **Persist last — same ordering as §5.3, no transaction needed.** Snapshot the rewound
   actor → `persist.save_stakes`, in the `ledger → stake → persist` order the forward path
   pins (§5.3; the §3.3.4 stale-snapshot anti-pattern applies identically). The reorg path
   needs **no transactional atomicity** across the rewind: a crash mid-rewind self-heals on
   reopen because the R0-D2 rebuild (step 5) re-runs before any claimable balance is
   exposed, regardless of how the prior session died. Do **not** harden the reorg path with
   transaction machinery it does not need — same falls-out-of-the-rebuild logic as the
   step-2 collapse.
5. **Post-resync reconciliation (R0-D2):** after `Restore`, the **same rebuild** runs —
   recompute `claimed_epochs` from the post-reorg/post-resync chain nullifier set ∩
   locally derived `{ x·G_S }` before exposing claimable balances; the persisted set is
   cache, not authority. In-session reorg (step 2) and post-`Restore` (step 5) are **one
   operation**, differing only in trigger — so there is no incremental-vs-rebuild
   divergence to reconcile.

> The wallet does **no reversal**. On reorg it rebuilds `claimed_epochs` forward from the
> canonical post-reorg chain (derive-don't-accumulate — the same pattern as
> [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md)'s `from_blocks`; the incremental-reversal
> alternative was rejected above). That the chain it rebuilds from has reverted the
> stake-claim nullifier set is **baseline daemon correctness** — the wallet relies on it
> exactly as the spend path relies on the spent-key-image set being reverted when a spend is
> reorged-then-respent. It is not a stake-specific dependency, and the daemon's `pop_block`
> mechanism is not the wallet's to track.

### 5.3 Cross-engine ordering ([`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §3.3)

**Required pattern (Stage 4-ready):**

```rust
let merge_out = engine.ledger.apply_scan_result(scan).await?;
engine.stake.apply_stake_events(merge_out.tip_height, merge_out.stake_events_for_actor).await?;
let stakes_snapshot = engine.stake.snapshot().await?;
engine.persist.save_stakes(stakes_snapshot).await?;
```

**Forbidden:** `tokio::join!(ledger.apply_scan_result(...), persist.save(...))` with a
ledger snapshot taken as a join argument (§3.3.4 stale-snapshot anti-pattern).

---

## 6. User-facing orchestrator API (not on `StakeEngine` trait)

| Method | Returns | Behavior pin |
|--------|---------|--------------|
| `stakes(filter: StakeFilter)` | `Vec<StakeView>` | Delegates `StakeEngine::list_stakes`; owner-grade `StakeView` (§4.6) — per-stake `claimable` bridges the global total to the `claim(stake_id)` decision |
| `claimable_rewards()` | `AtomicUnits` | Exact sum across instances (FA-1: single static address) |
| `stake(amount, tier)` | `PendingTx` | Builds the **confidential staked output** (commitment + range proof + **band declaration** range-proven to the commitment); `PendingTxEngine::build` + `register_pending_stake` |
| `claim(stake_id)` | `PendingTx` | Builds a **confidential claim** covering up to `MAX_EPOCHS_PER_CLAIM` unclaimed settlement-epochs in **one** tx (membership + per-epoch nullifiers + one batched entitlement on `M = tier_num · Σ_S K_S` + range proof). Entitlement is O(1) in epoch count; only nullifiers scale (~15 for a tier-3 full drain). **Production default:** batch the full window when `|epochs| ≤ 15` (§5 upstream). `MAX_EPOCHS_PER_CLAIM = 1` is **test-mode only**. Calls `prepare_claim_build`, then composes via `PendingTxEngine` + `KeyEngine` (§4.7). Does not finalize. |
| `unstake(stake_id)` | `PendingTx` | Spends the principal commitment via membership proof after lock; FSM → `Unstaking` on submit |

**FA-1 (single-address; vacuous now, reopen-pointer for later):** stake/claim/unstake
target **the wallet's single static address** — Shekyl has no on-chain account/subaddress
hierarchy to index, so there is no `SubaddressIndex` in `StakeInstance` or tx templates.
The constraint is *vacuous today* (there is one address), not an inherited account-0
default. **Reopen criterion (rule 21):** when the planned seed-derived **independent
accounts** land, staking from a non-default account becomes a new opsec decision —
cross-account staking could correlate otherwise-unlinkable accounts — to be designed with
that feature, not pre-provisioned here.

**`StakeFilter` (declared domain — total over `StakeState`, no open-ended param).** The
`filter` argument is a closed enum that mirrors `StakeState` **1:1** plus an `All`
list-everything sentinel, so filtering is **total**: there is no state a filter cannot
express, and no filter variant without a matching state.

```rust
#[non_exhaustive] // mirrors StakeState's #[non_exhaustive]; a new state adds a variant here
pub enum StakeFilter {
    All,             // list-everything sentinel (not a state)
    PendingBroadcast,
    Unconfirmed,
    Locked,
    Accruing,
    Claimable,
    Unstaking,
    FullyUnstaked,
}
```

No free-form predicate, no caller-supplied closure — a wider filter has no named consumer
and would be the pre-provisioning shape the discipline rejects (rule 21). The
1:1-with-`StakeState` constraint is load-bearing and must be held in review: a state with
no filter variant is an inexpressible query; a filter variant with no state is dead. Both
enums are `#[non_exhaustive]` and stay in lockstep — a new `StakeState` variant adds the
matching `StakeFilter` variant in the same change.

**Abandon-claim wiring (no dedicated §6 method — rides the general discard path).** A
built `claim()` is an ordinary `PendingTx`; discarding it rather than broadcasting must
clear the runtime-only `claim_pending_epochs` reservation (§3.4 FSM transition: *claim tx
discarded → clear `S`*), else those epochs stay reserved and block re-claiming until
restart. **Pin:** the orchestrator's general pending-tx discard path **dispatches
`AbandonClaim { stake_id, epochs }` (§4.7) for claim-type txs** — the staking side-effect
is not silently dropped by the "rides the normal path" decision.

**What the dispatch keys on (verified at source — the gap one level down).** `PendingTx`
(`engine/pending.rs`) carries **no** claim discriminator and **no** `(stake_id, epochs)`:
its fields are `id` / `built_at_height` / `built_at_tip_hash` / `fee` / `snapshot_id` /
`tx_bytes` / `recipients`. That is correct — `PendingTxEngine` stays **spend-pure** (§3.4),
and threading a claim ref through it (e.g. via `Reservation::extensions`) is the rejected
Option-C boundary break. So the discriminator + reservation key live **in the orchestrator**,
which is the one site already holding both halves at `claim()` build time: the `ReservationId`
returned by `PendingTxEngine::build` and the `(stake_id, epochs)` passed to
`prepare_claim_build`. The orchestrator records `ReservationId → (stake_id, epochs)` for
claim-type builds and consults it on discard to fire `AbandonClaim`; a non-claim discard
finds no entry and is a no-op. `AbandonClaim` touches `claim_pending_epochs` only, never
`claimed_epochs` (D3), so a mistimed or duplicate abandon is harmless.

**No pre-stake yield projection (deliberate, not overlooked).** `projected_yield` (§4.6)
takes an existing `stake_id`; there is **no** estimate before staking. A forward estimate
over an unstaked principal would have to project the public rate forward and would
overpromise (§8.6 rate is forward-uncertain), so it is omitted by decision.

**`AtomicUnits` is the amount type (landed).** The amount returns here
(`claimable_rewards`, `StakeView.claimable`, `projected_yield`) and `StakeOpening.amount`
carry the `AtomicUnits` domain newtype from `shekyl-units`: checked-only arithmetic,
`serde`/`repr(transparent)` wire-identical to the `u64` it replaced, type-distinct from the
`u64` epoch indices and block heights alongside it. It landed in the interim PR ahead of
broad wiring (see [`docs/design/ATOMIC_UNITS_NEWTYPE.md`](ATOMIC_UNITS_NEWTYPE.md)).

**Claim batching / timing (privacy):** claiming the **full unclaimed window** in one tx
(`MAX_EPOCHS_PER_CLAIM` permitting) is the **production default** — it removes the
partial-timing tell, tightens [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §6.2,
and reduces **per-stake claim-sequence** correlation (tier + contiguous epoch windows
accumulate across drip claims). `MAX_EPOCHS_PER_CLAIM = 1` is test-mode only. If a
backlog requires multiple txs, avoid fixed epoch-boundary broadcast cadence; Dandelion++
/jitter is the network-layer mitigation (§7).

---

## 7. Threat model (Round 1 wargaming seed) — **expanded**

| Threat | Mitigation pin |
|--------|----------------|
| Malicious daemon **misreports the rate `ρ_e`** | Yield uses the wallet's own (secret) weight × public `ρ_e`; `ρ_e` is consensus-derived from the on-chain `band_sum` and verifiable by full nodes. Light clients carry residual trust; warn on stale/inconsistent rate. (Replaces the old "understates `total_weighted_stake`" threat — there is no daemon-supplied denominator anymore.) |
| Wallet over-claims reward amount | Claim built from the public rate × the stake's own weight over **unclaimed** epochs; consensus range proof + entitlement relation reject over-claims. Wallet must not rely on consensus to mask a local accounting bug (priority-1). |
| **Claim↔stake linkage** | Membership-unlinkable claims + per-epoch nullifiers; wallet uses fresh `N_{i,S}`, exposes no RPC/UI field correlating a claim to a stake, batches/jitters broadcast timing. |
| **Per-stake claim sequence** | Piecemeal claims leak `(tier, contiguous-window)` serial signal even when nullifiers are DDH-unlinkable (upstream §6.2); mitigate via full-window batching default (§6). Round 3 wargame drip vs delay-then-batch. |
| **Nullifier / key-image cross-link** | **DDH split:** `N_S = x·G_S` vs unstake `x·Hp(O)` unlinkable under independent NUMS bases (upstream §6.3). Load-bearing for claim/unstake decoupling. |
| **Commitment-opening disclosure** | `StakeOpening` holds `(amount, z)` only — **not** `x` (§3.3.1); **never at rest** — re-derived on hydration, held in memory only, zeroized on drop, never in RPC or actor-message plaintext (§4.2 dissolution). Spend secret derived transiently for nullifier match / claim prove. |
| **Band cohort-size leakage** | Band is coarse (4–6 decade bands); at cold start, thin cohorts make even a coarse band revealing — wallet UI may warn early stakers; consensus may floor/suppress the signal at low participation (upstream). |
| **Nullifier-reorg desync** | Ordered §5.2 reorg folded onto `ApplyStakeEvents { reorg_rewind }` (D1); wallet rebuilds `claimed_epochs` clear-all/replay-all against the post-reorg nullifier set; mirrors consensus pop reverting the nullifier set. |
| Reorg desync between ledger and stake actor | Ordered §5.3; `reorg_rewind` field on `ApplyStakeEvents`, rewind-first in one uninterruptible turn (D1) — no separate message to race against the forward apply |
| Fake `StakeEvent` injection | Events originate from scanner parsing blocks tied to daemon headers; `OwnNullifierObserved` requires matching a locally derived nullifier (a forged event cannot fabricate the wallet's own nullifier) |
| **Silent inflation** | **`h_bind`** (tier+creation) + window arithmetic + recomputed `N/D` + **(A)** bounded-remainder (committed `ρ`, range `0≤ρ<D`) + `ρ_cap` (upstream §9) |

### 7.3 Diagnostic projection (lens 3)

RPC fields are **field-redacted** along *two* classes,
not one. (i) The **secret class** — no view/spend, no `z`. (ii) The **derived-value class**,
which the secret-class redaction does **not** cover and which must therefore be named
explicitly: **no per-stake `claimable`** (it is a deterministic function of the
confidential principal and public params — `amount = claimable / (tier_num · ΣK_S ·
|unclaimed|)` — so it discloses the staked amount) and **no per-stake `claimed_epochs`**
(it discloses the per-stake claim pattern). A redaction written only for "secrets" /
"per-output secret correlation" would read as covering this leak without covering it. The
lens is further **height-labeled**, **distribution-safe** (no per-output secret
correlation), and **claim-unlinkable** (no stake↔claim join key), and carries only a
**global** claimable total + coarse state. **Distinct from the owner-grade `StakeView`
(§4.6):** `StakeView` carries those two per-stake fields and is owner-only; this lens
carries **neither**. `StakeView` must not be widened into this lens.

### 7.4 Round 3 agenda (pre-staged 2026-06-05): threat-model exhaustion + wider-substrate audit

Round 3 is the threat-model-exhaustion + wider-substrate-audit round
([`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md) op. 5–7). This subsection
**pre-stages the agenda** — the vectors to wargame to exhaustion and the deployed-system
failure modes to disposition — but **does not pre-judge outcomes**: each item is `OPEN`
until Round 3 drives it to a disposition (mitigated-in-design / FOLLOWUP'd with a reopening
trigger / priority-rejected with reopening criteria, per `21-reversion-clause-discipline.mdc`).
**Round-3 closure** (§9 row + §10.1 box) requires every T- and G-item below to carry a
disposition. Pre-staging is **not** a round (Principle 5 closure-rule): it sets the surface;
it does not close it.

**Adversary models** (Principle 7 anchors; run each T-item against the applicable models):

- **A1 — adversary-controlled daemon** (expected deployment, Tor/I2P-first per
  [`ANONYMITY_NETWORKS.md`](../ANONYMITY_NETWORKS.md)): rate misreport, block withholding,
  selective/late delivery, header-timing manipulation.
- **A2 — passive network observer / chain analyst**: claim linkage, broadcast-timing
  correlation, band-cohort analysis across the public chain.
- **A3 — memory-disclosure adversary** (per `35-secure-memory.mdc`): in-memory opening
  `(amount, z)`, transient spend secret `x`, prover bundles.
- **A4 — collusion** (A1 + A2): daemon timing oracle composed with chain analysis.

**Threat-model-exhaustion agenda** (carried from the §7 seed table + the §0.10 new surfaces;
each `OPEN`):

| ID | Vector | Wargame question (drive to exhaustion in Round 3) |
|----|--------|---------------------------------------------------|
| **T1** | Per-stake claim-sequence correlation | Is full-window batching (§6 default) sufficient against A2, or does the residual `(tier, contiguous-window)` signal need a **pinned** jitter/Dandelion++ default? Drip vs delay-then-batch (the §7 seed row). |
| **T2** | Claim↔stake linkage across a sequence | Confirm DDH-unlinkability (`N_{i,S}=x_i·G_S`) holds across the *whole* claim sequence under A2/A4, not only per single claim. |
| **T3** | Band cohort-size leakage (cold start) | Thin-cohort de-anonymization under A2; wallet-UI early-staker warning vs consensus floor/suppress — **name the cross-track upstream ask** (do not assume the consensus floor). |
| **T4** | Claim-timing correlation | Broadcast cadence + epoch-boundary clustering under A1/A4; pin the wallet-side timing defaults; Dandelion++/jitter as the network-layer mitigation. |
| **T5** | In-memory opening exposure | Re-derive-on-hydration window + zeroize-on-drop coverage + no-plaintext-in-message/RPC under A3; confirm the `35-secure-memory.mdc` posture end-to-end (opening `(amount, z)`, transient `x`, prover bundle). |
| **T6** | Nullifier-reorg desync | Adversarial reorg shapes (straddling-lock, deep reorg, reorg-then-re-mine) against the §5.2 **forward rebuild** — does `claimed_epochs` recompute correctly from the post-reorg chain in every shape? **Wallet-side property**; daemon reorg correctness is assumed as for spent key images (§5.2), not tracked here. |
| **T7** | Nullifier / key-image cross-link | Confirm `x·G_S` (claim) vs `x·Hp(O)` (unstake) independent-NUMS-base unlinkability is not weakened by any wallet surface (no shared serial, no correlated broadcast). |
| **T8** | Silent inflation (wallet role) | Wallet must never construct over-entitlement and must not rely on the consensus range proof to mask a local accounting bug (priority-1); `h_bind` / `N·D`-recompute / bounded-remainder is upstream's argument, the wallet's job is not to undermine it. |
| **T9** | Fake `StakeEvent` injection | Confirm scanner-origin + own-nullifier-match forecloses forged events under A1 (no path fabricates the wallet's own nullifier). |

**§6 wider-substrate audit seed** (Principle 6 — "what have deployed staking systems / crypto
wallets taught us about staking-deployment failure modes this design hasn't named?"; each
candidate `OPEN`, dispositioned substrate-now / FOLLOWUP / priority-reject in Round 3).
Confidential-claim staking is **not delegated PoS**, so several canonical PoS failure classes
are expected N/A — recording the non-applicability *is* an audit result, not a skipped item:

| ID | Deployed-system failure mode | Pre-stage note (disposition lands in Round 3) |
|----|------------------------------|-----------------------------------------------|
| **G1** | Slashing / penalty tracking | Shekyl staking has **no slashing** (confirm vs [`STAKER_REWARD_DISBURSEMENT.md`](../STAKER_REWARD_DISBURSEMENT.md)); if confirmed, the "wallet tracks slashing risk" class is N/A — document and close. |
| **G2** | Validator / delegation UX | Not delegated PoS — expected N/A; confirm + document. |
| **G3** | Lock-up / unbonding surprise | Tier lock windows; wallet surfaces `unlock_height` (`StakeView`, §6). Wargame "funds locked longer than the user expected" — is the surfacing sufficient? |
| **G4** | Dust-reward / fee-starved claim | Claiming costs a tx fee; if `claimable < fee` the claim is uneconomic (a real Cosmos/ETH-staking failure mode). Does the wallet warn / batch / defer? Likely a substrate-now UX pin or a FOLLOWUP. |
| **G5** | Resync during in-flight claim | Covered by §3.4 (`claim_pending_epochs` runtime-only; `Restore` starts empty) + §5 — confirm exhaustively, do not assume. |
| **G6** | Mempool eviction of a claim tx | Does the claim path inherit `PendingTxEngine`'s staleness gate (§8.9)? Confirm the duplicated gate covers claim eviction, not only ordinary spends. |
| **G7** | Long-range reorg of a confirmed claim | Covered by the §5.2 forward rebuild — confirm no *additional* wallet gap. Daemon reorg correctness assumed as for spends (§5.2). |
| **G8** | HW-wallet signing latency (claim/unstake) | Claim prove needs `x` transiently via the `Signer` boundary (anchor 2); confirm the HW-wallet path and its latency posture for the time-sensitive claim window. |
| **G9** | Wallet-locked during claim window | Does a locked / passphrase-gated wallet block time-sensitive claims? UX-vs-security trade — disposition in Round 3. |
| **G10** | Fee-bump / replacement of a stuck claim | Expected **priority-3 rejection** mirroring the PR 5 G3 precedent (reopening criteria: FCMP++ fingerprint-unobservability analysis OR telemetry re-classification of stuck-tx-recovery into a higher priority class). Confirm the precedent transfers to claim txs. |

**Round-3 dependencies / cross-track asks:** (1) upstream Round 2 wire/KAT gates (§8.0) are
not blocking the *wargame*, but byte-exact claim/stake wire and entitlement vectors must be
cited where **T8** / **G7** reference consensus behavior; (2) **T3**'s cold-start cohort floor
may require an upstream consensus coordination ask — record it as a cross-track item, do not
assume it exists.

---

## 8. Forward actions and reversion clauses

### 8.0 Confidential-consensus dependency (Stage 3 merge gate)

**Stage 3 merge to `dev` is blocked** until this document's **Round 3** closes
(threat-model + wider-substrate audit). **Upstream consensus Round 1 is closed**
(2026-06-02): wire sketch (`txin_stake_claim_v2`), servo + `ρ_cap` pins, §6.4
**(A)** reserve-DLEQ + bounded remainder; **(C)** closed on **3C** (2026-06-04). Byte-exact
serialization, staking-subtree 5-scalar leaf / `h_bind` KATs, entitlement vectors are
upstream Round 2 gates; implementation against the cleartext HF17 model is forbidden.

**The reorg/`pop_block` nullifier-set revert is part of this gate, not a separate one.**
The wallet does no reversal — §5 rebuilds `claimed_epochs` forward from canonical chain
state and relies on daemon reorg correctness exactly as the spend path relies on
spent-key-image revert. The daemon's `pop_block` reversal
([`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §11) is inherited-architecture
consensus code, unimplemented together with the rest of the confidential mechanism and
gated together — not a §5-specific dependency.

**Parallel work allowed (design + isolated spikes):** Rounds 2–6 on this document,
trait sketches, FSM tests against mocks, opening re-derivation spikes (§4.2) — provided
spikes do not land cleartext `staked_output_index` / watermark paths on `dev`. Feature-branch
consensus implementation tracks upstream Round 2+; wallet Stage 3 lands after
**Round 3 closure here** (not upstream Round 1 alone).

**Reopen/track (Round 2+):** byte-exact claim/stake wire; `STAKE_CLAIM_GS.json`;
[`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §13 Round 2 rows. Economics
and crypto Round 1 pins are in upstream §14 — do not re-litigate without §14 reopen
criteria.

### 8.7 Rejected: claim as ordinary FCMP spend + re-stake (Round 1)

**Considered:** Model claim as a normal FCMP spend; use `x·Hp(O)` for double-claim;
re-stake principal in the same tx — avoids claim-mode SAL and a separate nullifier table.

**Rejected** ([`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §6.4.4):

- Worsens **(C)** — new stake must inherit hidden tier/`eff_lock` from the spent leaf.
- Remodels accrual; breaks claim/unstake decoupling (§7 upstream).

**Pin:** claims remain **non-spending** membership proofs; unstake remains full SAL +
`x·Hp(O)`. Recorded explicitly so the option is not silently dropped from the decision
record.

### 8.1 Persist the rate/band cache in the wallet file

**Rejection:** keep rebuild-on-scan ([`ledger_block.rs`](../../rust/shekyl-engine-state/src/ledger_block.rs)).

**Reopen when:** rescan refill exceeds the UX budget on mainnet-class history on V3.0
hardware — evidence in `PERFORMANCE_BASELINE.md`.

**Account-scan ceilings (FA-6, separate budget):** Per-output refresh cost for
`txout_to_tagged_key` receives (including claim-reward mints) is governed by
[`FA-6_VIEW_TAG_ML_KEM.md`](FA-6_VIEW_TAG_ML_KEM.md) §8.4.1 (45 s incremental /
20 min genesis-restore on the Pi 4 reference device). That gate does **not**
include stake-specific resync work: confidential stake/claim tx parsing,
`claimed_epochs` rebuild from the stake-claim nullifier set (§5.2, §8.5), or
rate/band cache refill (above). Full-wallet resync UX must be measured as
**FA-6 account scan + Phase 2b stake mirror** when evaluating §8.1 reopen criteria.

### 8.2 `EconomicsEngine` per-stake methods

**Rejection:** per [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
§2.7. The pool-denominator method is retired; per-stake methods remain rejected.

**Reopen when:** §10.6.1 three-part threshold met with a named consumer that cannot
compose `StakeEngine` + the public rate schedule.

### 8.3 Collapse `Accruing` / `Claimable`

**Rejection for V3.0:** separate for UX clarity; exact wallet-local yield strengthens
the case.

**Reopen when:** a production UI proves a single-state read model is strictly better.

### 8.4 Band declaration model (new)

**Pin:** the wallet declares the band, range-proven to the commitment, at stake time.

**Reopen when:** upstream selects tier-weighted count over the value-weighted band
(then `StakeInstance.band` is dropped and governance reads count/tier only) — tracked
in §2.3.

### 8.5 Stake nullifier base `G_S` (wallet — R0-D1)

**Block:** claim recognition, resync, and claim tx construction until pinned.

**Pin (Round 1 — supersedes `nullifier_seed` HKDF):**

- `N_S = x · G_S` with `x = ho + b` derived transiently (`KeyEngine` + output derivation —
  **not** stored in `StakeOpening`; §3.3.1).
- `G_S = hash_to_ec("shekyl-stake-nullifier-base" ‖ S_le64)` — domain separator + encoding
  KAT-locked ([`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §6.3–§6.4).
- Wallet recomputes `{ x·G_S }` on rescan/resync and intersects the **stake-claim**
  nullifier set (§4.2, §5.2) — not the spent key-image set.
- Claim prove/verify is a **new surface** (staking-subtree membership + **`h_bind`** + **(A)**
  bounded-remainder + **(B)**); B1 (claim-mode SAL / sibling for `x·G_S`) preferred over
  membership-only + sibling DLEQ.

**Fallback:** HKDF `nullifier_seed` + PRF only if B1 proves infeasible (upstream §6.3).

**Owner split:** `G_S`, `MAX_EPOCHS_PER_CLAIM`, claim verifier, **(C)** → upstream §6.4.
Wallet tracks closure; does not invent consensus constants.

### 8.8 The stake opening is never persisted (wallet — R0-D8 + §4.2 dissolution)

**Pin:** see §3.3.1. Persist **nothing secret** — public fields + `claimed_epochs` only.
Re-derive `(amount, z)` from the staked output on hydration (the authoritative path, not
a cache rebuild), held in memory for the session; derive `x = ho + b` transiently at
claim build. `z = OutputSecrets.z` (plain-Pedersen `C_stake`, verified at source —
[`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §"Pinned commitment construction"),
so the opening recovers from the staked output alone. Security over resync convenience at
two grades: no theft-grade `x` and no claim-grade `(amount, z)` at rest.

**Reopen — two distinct clauses (§3.3.1):** (1) `x`-persistence reopens only if
`PERFORMANCE_BASELINE.md` shows batch `x` derivation is the resync bottleneck and cannot
be amortized; (2) `(amount, z)`-persistence reopens only if a future **claim-completion-
gated** ledger-pruning pass cannot avoid evicting a spent staked output with unclaimed
accrued epochs (R0-D6 makes accrued epochs claimable indefinitely, so the pruning gate is
claim-completion, not height). Neither reopens on a convenience argument.

### 8.6 `EconomicsEngine::rate_at_epoch` (trait amendment — R0-D5, finalized Round 2)

**Signature (Stage 3 co-lands; aligns to the trait's `Self::Error` convention, not a bare
`EconomicsEngineError` — mirrors `base_emission_at` / `burn_amount`):**

```rust
/// Public per-epoch staking rate ρ_e for the settled rate-epoch `rate_epoch`.
/// The sole yield-schedule surface StakeEngine consumes (§4.5). Canonical-
/// derivation only — takes a rate-epoch index, never a `stake_id` (§8.2).
fn rate_at_epoch(&self, rate_epoch: u64) -> Result<u64, Self::Error>;
```

**Finalized semantics (the seven pins):**

1. **`rate_epoch` is a rate-epoch *index*, not a block height.** It is 0-based and aligned
   to the consensus rate-epoch schedule (tier-3 lock = 150k blocks / `rate_epoch_blocks`
   10k = 15 settlement-epochs, §3.3.2). Height→epoch conversion is the **caller's**
   (StakeEngine's) job, using the public `rate_epoch_blocks` from `parameters_snapshot()`;
   the method does not take a height and does not guess the epoch length.

2. **Return is the public rate `ρ_e`, a fixed-point `u64` — not an amount, so not
   `AtomicUnits`.** `ρ_e` is reward-per-unit-weight-per-block (`K_S = Σ_{e ∈ S} ρ_e ·
   rate_epoch_blocks`, §4.5). Its fixed-point **scale is consensus-defined upstream**; the
   wallet consumes the scale, it does not invent it (§8.5 "does not invent consensus
   constants"). A dedicated `Rate` newtype is **out of scope** for this amendment —
   reopen-pointer: if a `Rate` newtype lands wallet-wide (sibling to `AtomicUnits`), this
   return adopts it then, not now (rule 21).

3. **Fallible by design — the improvement over `pool_weighted_total`.** `pool_weighted_total`
   is infallible (`-> u128`) and so **overloads `0`** (no-stake vs not-synced; see its
   rustdoc). `rate_at_epoch` returns `Result`, so "unknown" is an explicit `Err`, never an
   overloaded value: `Err` arms are (a) **rate-epoch not yet settled** (future/in-progress
   epoch — its rate is not yet consensus-fixed), (b) **mirror not synced** to cover the
   epoch, (c) defensive arithmetic overflow.

4. **`Ok(0)` is valid and distinct from `Err`.** A *settled* epoch with an empty staker set
   legitimately has `ρ_e = 0` (no yield that epoch) — consensus burns rather than carries
   (cf. `pool_weighted_total` zero-semantics). `Ok(0)` = "settled, no yield"; `Err` =
   "cannot determine." This cleanly un-overloads the two meanings `pool_weighted_total`'s
   `0` conflated.

5. **Consensus-derived, not wallet-recomputed (Bug-2-class avoidance).** `ρ_e` is derived
   from the on-chain `band_sum` at the epoch (the denominator the network agrees on),
   verifiable by full nodes. The V3.0 implementor sources it from chain-mirror economics
   state (as `base_emission_at` will once a per-height mirror exists), **not** from a
   wallet-local `shekyl-staking::Registry`. Light clients carry residual trust → warn on
   stale/inconsistent rate (§7 malicious-daemon row).

6. **The `AtomicUnits` boundary is here (tailwind from the interim PR).** `rate_at_epoch`
   returns the *rate*; StakeEngine forms yield `own_weight · K_S` and that product is the
   crossing into `AtomicUnits` — exactly the checked-arithmetic centralization site the
   `AtomicUnits` newtype exists for. The multiply-then-scale uses `AtomicUnits` checked
   arithmetic; `ρ_e` (`u64`) and `own_weight` enter, an `AtomicUnits` claimable leaves.

7. **No per-stake state (§8.2 reversion preserved).** The method takes a rate-epoch index;
   per-stake yield is composed by StakeEngine over the public schedule. Methods on
   `EconomicsEngine` that take `stake_id` or encode per-stake state remain rejected (reopen
   only via §10.6.1 of the trait-boundaries doc).

**`pool_weighted_total` disposition — delete, not renarrate (rule 15 + rule 21).** Its
rustdoc names its **sole** intended consumer as "Phase 2b's `StakeEngine::projected_yield`"
denominator; the confidential redesign eliminated the daemon-supplied denominator entirely
(§7: "there is no daemon-supplied denominator anymore"), and it has **zero** V3.0
consumers today. A method whose only named consumer no longer exists is dead surface, not
superseded surface — so it is **removed**, not rewritten. **Reopen-criterion (rule 21):**
re-add a public pool-aggregate method only if a future consumer needs an aggregate
pool-weighted total that **cannot** be composed from `rate_at_epoch` + chain-mirror state.
The underlying `band_sum` mirror (`ChainEconomicsSource::active_weighted_stake`) is **not**
deleted by this — it is repurposed as `rate_at_epoch`'s internal `ρ_e`-derivation input
(internal state, not a public trait method).

**Stage-3 grep-retire / delete enumeration** (the code action; design is closed now, code
lands with Stage 3):

- `rust/.../traits/economics.rs` — remove `fn pool_weighted_total(&self) -> u128;` + rustdoc.
- `rust/.../local_economics.rs` — remove the impl (`:166`) + module-doc bullet (`:21`).
- `rust/.../economics_differential.rs` — drop the `pool_weighted_total` round-trip assertion
  (`:154-159`) + module-doc bullet (`:19`).
- `rust/.../chain_economics_source.rs` — retarget `active_weighted_stake` from "feeds
  `pool_weighted_total()`" to "feeds `rate_at_epoch`'s `ρ_e` derivation"; update the
  `:11/:33/:42/:86` doc references.
- `rust/.../mod.rs` (`:521`), `lifecycle.rs` (`:750`) — update the `pool_weighted_total`
  shared-state comments to `rate_at_epoch`.

**Boundaries-doc amendment (landed alongside this pin):**
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §2.7 "Ownership" — drop
"pool-weighted stake total" from the canonical-derivation list and name `rate_at_epoch` as
the per-epoch staking-rate surface that StakeEngine consumes.

**Reversion:** per §8.2 — no per-stake methods on `EconomicsEngine`.

### 8.9 Claim-tx staleness-gate factoring (E reversion trigger)

**Pin (E shape, §3.4):** the claim path **duplicates** `PendingTxEngine`'s ~10-line
submit-time staleness gate (`built_at_height` / `built_at_tip_hash` / `snapshot_id`
checks) rather than extracting a shared broadcast/staleness primitive. Building a shared
abstraction for exactly two consumers — when the substantial sharing (scan-driven
confirm/reorg, §3.4 leg 2) already exists elsewhere — is speculative extraction
([`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc),
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)).

**Why duplication is safe:** the staleness gate is a **consensus-backstopped UX
optimization** (§3.4 consensus-backstop principle) — a stale claim is rejected at
consensus regardless; the gate only avoids wasting a broadcast. Drift between the two
copies is therefore benign (worst case: one path occasionally broadcasts a doomed tx).

**Reopen when (whichever first):**

1. **A third claim-tx-type appears.** Live candidate: **Stage 5 `ArchivalEngine`**
   ([`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md)). Archival is additive by design
   (no V3.0 refactor; sibling actor, independent `ArchivalEvent` stream, read-only
   `is_active_staker` query), so it does **not** reopen this FSM. But archival
   *disbursement* is unpinned (the doc's open-questions cover granularity/routing/pricing,
   not "is the reward a staker-initiated claim tx"). If Stage 5 lands archival reward as a
   staker-initiated claim tx, that is a third consumer of the staleness gate, and the
   shared primitive gets factored **then** — which is exactly why E was chosen over
   building the abstraction speculatively. *Carry into Stage 5: when designing archival
   disbursement, check whether it adds a claim-tx-type; if so, that is this factoring
   coming due — not an FSM reopen.*
2. **A non-backstopped check appears on the path.** If a future tx-type puts a
   **soundness-load-bearing check with no consensus backstop** on the broadcast path,
   drift stops being benign and the shared primitive earns its keep. This is the sharper
   trigger than "third consumer": it is *third consumer OR non-backstopped check*.

---

## 9. Round record

| Round | Status | Summary |
|-------|--------|---------|
| **0** | **Closed** (2026-06-04) | Confidential redesign is a substrate finding (Principle 5). Re-pre-flight §0.1–§0.8 re-walked against the locked 3C / `h_bind` / `creation ≜ eligible` / collapsed-(A) consensus; §0.10 signed off; **R0-D1–D8 dispositioned in §0.11** (2026-06-02). Re-walk fixed two stale-text gates (Drift 1 stake-actor secrets → `(amount, z)`-only; Drift 2 inflation-safety framing → `N/D`-recompute primary) + two completeness notes (§0.4 lock-view, §0.7 3C scanner scope); no design reopen. Blast radius: stake-actor openings `(amount, z)` only (R0-D8), claim prove surface, two-tree scanner parsing, `AccrualRecord` retirement. |
| **1** | **Closed** (2026-06-02; **(C) 3C** 2026-06-04) | **§6.4:** **(C)** closed on **3C** (staking subtree + 5-scalar `h_bind`; Decisions 1–2 superseded); **(B)**; **(A)** collapsed to reserve-DLEQ + bounded remainder; R0-D8. Round 2: byte wire, tree/leaf impl, cross-tree atomicity. |
| **2** | Open | **Pending-claim model pinned (2026-06-04, §3.4):** Hybrid-B/E — runtime-only `claim_pending_epochs` on the stake actor; `PendingTxEngine` stays spend-pure; confirm/reorg already shared via scan + §5.2 (verification carried by the §5 box); staleness gate duplicated (E), factoring trigger §8.9. **§5.2 collapsed to a single full-rebuild** reorg-unclaim (`claimed_epochs = {S ∈ window : x·G_S ∈ post-reorg chain set}`, no per-epoch height — in-session reorg == post-`Restore`), which also keeps `claimed_epochs` a pure index set for the roaring-vs-bitset decision; `claim_pending_epochs` never repopulated by reorg. The full-rebuild collapse is **forcing, not preferential** (the incremental "observed ≥ fork_height" path needs a per-epoch height `claimed_epochs` does not carry and that would foreclose the bitset encoding); reorg persists `ledger → stake → persist` (§5.3 parity) with **no transactional atomicity** (self-heals via rebuild-on-reopen). `EpochSet` now one persisted set, not two. `Accruing`/`Claimable` + discard-drops-instance ratified. **`EpochSet` wire type pinned (§3.3.2):** fixed **`u16` relative bitmask** anchored at the public `creation_height` (2 bytes, one set/stake), **not roaring** — consensus bounds `claimed_epochs` to ≤15 elements over a contiguous ≤15-wide window (tier-3 = 150k blocks / 10k = 15 settlement-epochs = `MAX_EPOCHS_PER_CLAIM`), so roaring's sparse-domain compression has nothing to compress; payload-free by construction (no field for a per-epoch height). **`StakeId` derivation pinned (§3.3.3):** `cSHAKE256(cust="shekyl/stake-id-v1", tx_hash ‖ le_u64(index))`, full 32 bytes, mirroring `derive_output_handle` (`handle.rs`) — **cSHAKE256, not `cn_fast_hash`, not BLAKE3.** `cn_fast_hash` is **inherited** Keccak-256 (CryptoNote 0x01 padding, consensus byte-identity with `keccak.c`); using it for new wallet-local code violates the modern-not-inherited posture. cSHAKE256 (FIPS 202/SP 800-185) is the workspace's PQC-aligned hash (already used by `key_actor`/`local_keys`/`handle`) **and** dependency-clean (`sha3` already in-tree; `blake3` is not), so modern and dependency-discipline agree — they only split in the intermediate cn_fast_hash misstep. Native domain sep via `customization` (no input prefix; distinct from `shekyl/output-handle-v1`); fixed-width input (no length prefix); derives only from on-chain `(tx_hash, index)` so rescan-stable (load-bearing for event→instance mapping); wallet-local/non-consensus; `v1` customization + wallet-internal KAT guard persistence stability. **Opening persistence DISSOLVED (2026-06-04, §3.3.1 / §4.2 / §8.8):** the opening
`(amount, z)` is **never persisted** — no sealed stake region. `C_stake = z·G + amount·H`
with `z = OutputSecrets.z` (plain Pedersen, verified at source in `CONFIDENTIAL_STAKING.md`
§"Pinned commitment construction"), so the opening re-derives from the staked output via
`derive_output_secrets` — the same expand the resync row already runs. The wallet stops
persisting a half it already re-derives; exposure flips from claim-forgery-grade sealed
material to **no claim-grade secret at rest**. Held-on-hydration for `(amount, z)`
(re-derive once at `Restore`, hold in memory) over fully-transient: `x` stays
transient-per-claim (theft-grade), `(amount, z)` is display-read on every poll and adds no
at-rest exposure either way; claim flow (R0-D4) unchanged. Two distinct reopen clauses
(§3.3.1): measured-`x`-cost, and claim-completion-gated pruning of spent staked outputs.
**Async trait RESOLVED (§4.6):** RPITIT-`+ Send` across all methods, five-engine idiom.
**Both Round-2 R-residuals now closed.** **§4.7 message protocol pinned (D1–D4):** reorg **folded** onto `ApplyStakeEvents { reorg_rewind }` (no `RewindTo`; rewind-first in one uninterruptible turn — atomicity, not just ledger-mirror symmetry); reorg semantics **clear-all/replay-all of the full surviving own-nullifier set across the whole post-reorg chain** (windowed replay drops below-fork survivors of a straddling lock), **heights live in the scanner** not `claimed_epochs`; `claim_pending_epochs` lifecycle = `PrepareClaimBuild` side-effect (set) + `AbandonClaim` (clear, **claim_pending only, never claimed**); `Snapshot` excludes `claim_pending_epochs` / `Restore` starts it empty. **§5's §4.7 carry is thereby discharged; §5 reconciliation is fully wallet-design signed off** — it does **no reversal**, rebuilding `claimed_epochs` forward from the canonical post-reorg chain and relying on daemon reorg correctness exactly as the spend path relies on spent-key-image revert (baseline daemon correctness, not a §5-specific dependency). **§6 user API signed off (2026-06-05):** owner-grade `StakeView` pinned (per-stake `claimable` / `claimed_epochs` / `unlock_height`) **distinct** from the §7 lens-3 redaction (one struct cannot serve both trust grades); amounts are `AtomicUnits` end-to-end (engine/orchestrator/computation; `u64` only at postcard/FFI/consensus edges; `_atomic` suffix dropped); `StakeFilter` declared as a closed by-state enum; abandon-claim discard wiring pinned (§3.4/§6 — general pending-tx discard dispatches `AbandonClaim` for claim-type txs); pre-stake yield projection omitted by decision (§8.6 forward-uncertain); FA-1 regrounded to the single static address with an independent-accounts reopen-pointer (rule 21); stale §3.3 opening doc-comment fixed. **§8.6 `rate_at_epoch` finalized (2026-06-05):** the EconomicsEngine yield surface is pinned (7 pins — rate-epoch index in, public fixed-point `ρ_e` out, fallible with `Ok(0)`≠`Err`, consensus-`band_sum`-derived, `AtomicUnits` crossing at the yield product, no per-stake state); `pool_weighted_total` **retired** (rule 15 delete — sole consumer was the redesign-eliminated `projected_yield` denominator, verified at source in both docs) across all 7 `V3_ENGINE_TRAIT_BOUNDARIES.md` sites, code removal deferred to Stage 3. **Both wallet-design Round-2 boxes now closed; §5 reconciliation is wallet-design signed off (Rounds 1–2).** It does no reversal — forward-rebuild only (clarified 2026-06-05); daemon reorg correctness is assumed as for spent key images, not a §5-specific carry. No further wallet design work blocks Round 3. **§0.1 pre-flight re-verify trio closed (2026-06-05):** §2 trait-binding, the §1.5 three-condition test, and the surface-amendment re-confirmed against the §0.10 secret-ownership shift (the actor's only secret state is in-memory `(amount, z)`, re-derived on hydration, never sealed; fail-stop isolation holds because the secret is reconstructable, not authoritative-at-rest). §2.7 / §3.3 were discharged by the §8.6 landing (`rate_at_epoch` is a §3.3.6 pure-read, no `.await`-ordering obligation); §8.3 lens row clean. **One residual fixed:** boundaries-doc §10.5.1 still described `StakeEngine` as owning "principal-pool aggregation state at Stage 4" — an 8th dead pool-denominator reference the literal-name `pool_weighted_total` sweep missed — corrected to per-stake in-memory openings with **no** principal-pool aggregation (exact yield = `rate_at_epoch` × own weight). |
| **3** | Open — **agenda pre-staged (2026-06-05, §7.4)** | Threat-model exhaustion (§7) + §6 wider-substrate audit. **Pre-stage** enumerated the adversary models (A1 daemon / A2 observer / A3 memory-disclosure / A4 collusion), a **9-item threat-exhaustion agenda** (T1–T9: claim-sequence correlation, claim↔stake linkage, cold-start cohort leakage, claim-timing, in-memory opening exposure, nullifier-reorg shapes, nullifier/key-image cross-link, silent-inflation wallet role, fake-event injection), and a **10-item wider-substrate audit seed** (G1–G10, Principle 6 — slashing N/A, delegation N/A, lock-up surprise, dust/fee-starved claim, resync-in-flight, mempool eviction, long-range reorg, HW-wallet latency, locked-during-claim, fee-bump rejection). Every T/G item is `OPEN`; **pre-staging is not closure** (Principle 5) — Round 3 closes only when each carries a disposition. Cross-track deps: upstream Round 2 wire/KAT (T8/G7), possible cold-start cohort-floor upstream ask (T3). (Nullifier-reorg is a wallet-side forward-rebuild property — T6 — not a cross-track dep; daemon reorg correctness is assumed as for spent key images.) |
| **4** | Open | Binding pins (trait signatures, error enums, persistence version; **no stake sealed-region format** — opening dissolved, §4.2) |
| **5** | Open | Closure + Stage 3 PR decomposition |
| **6** | Open | External critique buffer (optional) |

---

## 10. Definition of done

### 10.1 Planning (this document)

- [x] §0 re-pre-flight complete against confidential consensus shapes (2026-06-04, §0.9)
- [x] **R0-D1–D8** dispositioned (§0.11) — implementation gates named in §8.5–§8.8
- [x] `StakeState` FSM + transition table signed off (Rounds 1–2), incl. post-unstake claims (R0-D6) — pending-claim model + discard + `Accruing`/`Claimable` pinned in **§3.4** (2026-06-04)
- [x] **Reconciliation rules incl. nullifier-reorg rewind — wallet design signed off (§5; Rounds 1–2, split 2026-06-05):** the §3.4 claim confirm/reorg leg verifies via the **single full-rebuild** un-claim mechanism (§5.2: `claimed_epochs = {S ∈ window : x·G_S ∈ post-reorg chain set}`, no per-epoch height — in-session reorg and post-`Restore` are **one operation**); reorg persists `ledger → stake → persist` with **no transactional atomicity**, self-healing via rebuild-on-reopen (§5.2 step 4); cross-engine ordering pinned (§5.3). The **§4.7 message-protocol leg is discharged** (2026-06-04): reorg folded onto `ApplyStakeEvents { reorg_rewind }` (D1) with clear-all/replay-all full-surviving-set semantics (D2), `OwnNullifierObserved` re-delivered by the scanner; D1–D4 pinned in §4.7. **No further wallet design work remains on §5.**
- [x] **§5 reorg reconciliation — forward-rebuild only; no reversal work (clarified 2026-06-05):** §5 does **no** reversal. On reorg it rebuilds `claimed_epochs` forward from the canonical post-reorg chain (derive-don't-accumulate; the incremental-reversal alternative was rejected — §5.2). Its reliance on daemon reorg correctness (that the chain it rebuilds from has reverted the stake-claim nullifier set) is **baseline daemon correctness**, identical to the spend path's reliance on spent-key-image revert when a spend is reorged-then-respent — not a §5-specific dependency or carry. The daemon's `pop_block` reversal ([`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §11) is inherited-architecture consensus code, gated with the rest of the unimplemented confidential mechanism (§8.0), not the wallet's to track. Wallet-side robustness across adversarial reorg shapes is verified at Stage-3 integration via §7.4 T6.
- [x] Persistence schema signed off (§4.2) with version-bump plan — **opening persistence DISSOLVED (2026-06-04):** no sealed `opening` region; persist public fields + `claimed_epochs` only; opening re-derived on hydration (§3.3.1 / §8.8). Was decided-in-principle → gate-confirmed-at-source (`z = OutputSecrets.z`) → **now landed** across §3.3.1 / §4.1 / §4.2 / §4.7 / §8.8.
- [x] User method signatures signed off (§6). **Batch landed (2026-06-05):** owner-grade `StakeView` pinned (per-stake `claimable` + `claimed_epochs` + `unlock_height`) with the owner-grade caveat and a **distinct** lens-3 redaction that names `claimable`/`claimed_epochs` as the **derived-value** class the secret-class redaction does not cover (Fork A); `StakeFilter` made **total 1:1 over `StakeState`** + `All` sentinel (item 5); abandon-claim discard wiring keyed on an **orchestrator-held** `ReservationId → (stake_id, epochs)` map — `PendingTx` carries no claim discriminator (verified at source, stays spend-pure; item 3); pre-stake projection omission documented (item 4); FA-1 regrounded to single-static-address + independent-accounts reopen-pointer (Fork B); stale §3.3 opening doc-comment fixed (item 1). **`AtomicUnits` landed (2026-06-05):** §6 `claimable` / `claimable_rewards` + `StakeOpening.amount` carry the `AtomicUnits` domain newtype from `shekyl-units` (interim PR before broad wiring; see [`ATOMIC_UNITS_NEWTYPE.md`](ATOMIC_UNITS_NEWTYPE.md)). The §6 method set and amount type are both signed off.
- [x] `StakeEngine` message protocol signed off (§4.7), incl. sealed transport + `PrepareClaimBuild` (R0-D3, R0-D4) — **D1–D4 pinned (2026-06-04):** reorg folded onto `ApplyStakeEvents { reorg_rewind }` (no `RewindTo`; rewind-first, one uninterruptible turn); clear-all/replay-all full-surviving-set, heights in scanner; `claim_pending_epochs` lifecycle = `PrepareClaimBuild` side-effect + `AbandonClaim` (claim_pending only, never claimed); `Snapshot` excludes `claim_pending_epochs`, `Restore` starts it empty
- [x] **`StakeOpening` excludes `x`** (§3.3.1 / §8.8, R0-D8)
- [x] **`G_S` + claim linkability + `MAX_EPOCHS_PER_CLAIM`** pinned with **(B)** (§8.5 / upstream §6.4.2)
- [x] **Tier/window / multiplier integrity** — upstream **(C)** closed on **3C** (staking subtree + `h_bind`, window arithmetic); **(A)** reserve-DLEQ + bounded remainder; impl Round 2
- [x] `EconomicsEngine::rate_at_epoch` + boundaries doc amendment (§8.6) **— finalized (2026-06-05).** Seven pins: rate-epoch *index* (not height); returns public `ρ_e` as fixed-point `u64` (a rate, not `AtomicUnits`; consensus-defined scale); fallible with `Ok(0)`≠`Err` (un-overloads `pool_weighted_total`'s `0`); consensus-derived from on-chain `band_sum`, not wallet-recomputed; the `AtomicUnits` crossing is the yield product `own_weight·K_S`; no per-stake state (§8.2). **`pool_weighted_total` retired (delete, not renarrate — rule 15):** its sole named consumer (`projected_yield`'s pool denominator) was eliminated by the confidential redesign, verified at source in *both* the trait rustdoc and `V3_ENGINE_TRAIT_BOUNDARIES.md`; reopen-criterion is rule-21-shaped. Boundaries doc amended across all 7 sites (§2.7 Ownership, method sketch, consumer narrative, discipline-test example, three classification tables) — framed "retired pending Stage-3 code removal." Code removal + `active_weighted_stake` repurposing enumerated in §8.6 for Stage 3.
- [x] **Upstream consensus Round 1 closed** (§8.0; [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §14)
- [x] **Round 3 agenda pre-staged (2026-06-05, §7.4):** adversary models A1–A4; threat-exhaustion agenda T1–T9; wider-substrate audit seed G1–G10 (Principle 6). All items `OPEN` — pre-stage sets the surface, does not close it (Principle 5).
- [ ] **Round 3 wargaming executed** — every §7.4 T1–T9 + G1–G10 item driven to a disposition (mitigated / FOLLOWUP+trigger / priority-reject+criteria)
- [ ] Round 3 design closure recorded in §9

### 10.2 Stage 3 implementation (after closure — separate PR(s))

- [ ] `StakeEngine` + `StakeEngineHandle` + `StakeActor` (`kameo`), fail-stop, re-derived (never-sealed) openings
- [ ] FSM transition tests in isolation (incl. nullifier-reorg un-claim)
- [ ] `StakeEvent` (confidential variants) wired through refresh → ledger → stake actor
- [ ] Exact-yield computation from the public rate schedule (no pool denominator)
- [ ] `is_active_staker` message exposed
- [ ] Cross-engine ordering per §5.3

---

## 11. References

| Doc | Use |
|-----|-----|
| [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) | Upstream; §6.4.3 **(C) 3C** (subtree + `h_bind`); §6.4.1 **(A)**; §9 multiplier; `N_S` (§8.5) |
| [`STAKER_REWARD_DISBURSEMENT.md`](../STAKER_REWARD_DISBURSEMENT.md) | **Superseded** by the confidential redesign for the reward/claim mechanism; retained for history until the successor lands |
| [`FOLLOWUPS.md`](../FOLLOWUPS.md) | Phase 2b planning + Stage 3 rows |
| [`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md) | Phase 2b scope |
| [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) | §2.7, §3.3, §10.5.1, §8.3, §10.6.1 |
| [`V3_WALLET_DECISION_LOG.md`](../V3_WALLET_DECISION_LOG.md) | 2026-04-25 stake lifecycle |
| [`DESIGN_CONCEPTS.md`](../DESIGN_CONCEPTS.md) | Components 3–4 |
| [`STAGE_2_KEY_ENGINE_ACTOR.md`](STAGE_2_KEY_ENGINE_ACTOR.md) | Actor template + fail-stop (§0.8, §4.7) |
| [`SUBADDRESS_UNDER_PQC.md`](SUBADDRESS_UNDER_PQC.md) | FA-1 |
| [`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md) | Round structure |
| [`36-secret-locality.mdc`](../../.cursor/rules/36-secret-locality.mdc) | Sealed `StakeOpening` |
| [`42-serialization-policy.mdc`](../../.cursor/rules/42-serialization-policy.mdc) | Version bump for new stakes field (public + `claimed_epochs`; no sealed opening region) |
