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

- [ ] **§2 trait binding (re-verify):** [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §10.5.1 (`StakeEngine` additive trait); §2.7 (`EconomicsEngine` consumer framing —
  now consumes the **rate schedule**, not the pool denominator); §3.3 (cross-engine
  `.await` sequencing); §8.3 lens table row for `StakeEngine`.
- [ ] **§1.5 three-condition test (additive trait):**
  - **(1) Distinct state ownership:** per-stake FSM + wallet-side stake registry **+
    per-stake commitment-opening secrets (`amount`, `z`) only**; distinct from
    `LedgerEngine` and `EconomicsEngine`. **No nullifier-derivation material in the
    stake actor** — `N_S = x·G_S` uses spend secret `x` (KeyEngine-owned, derived
    transiently at claim/resync; R0-D8, §0.10). **Pass (re-confirm secret ownership).**
  - **(2) Failure isolation:** stake actor crash must not take down ledger or keys;
    recoverable via re-hydration from persisted stake records + chain replay.
    **Re-verify under fail-stop now that the actor holds secrets (§0.10).**
  - **(3) Cross-cutting consumers:** `Engine<S>` orchestration, future
    `ArchivalEngine` via `is_active_staker(entity_id)`, JSON-RPC at V3.2+. **Pass.**
- [ ] **Surface amendment:** introduces `StakeEngine` (eighth trait slot); amends
  `ScanResult` / merge per §4; **new:** stake actor now holds secret opening
  material (changes the Stage 2 "no secrets in stake actor" inheritance — §0.10).

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
| `pool_weighted_total()` | `EconomicsEngine` trait — **retire** when `rate_at_epoch` lands (R0-D5) |
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
| Fail-stop | §4.5 — `Break` on panic; no restart with stale secrets | **Adopt — now mandatory**: actor holds commitment openings (`amount`, `z`) only; nullifier derivation is a transient `KeyEngine` operation (`x·G_S`), not sealed stake-actor state (§0.10, R0-D8) |
| Require-ambient runtime | §4.2 | Same for `StakeEngineHandle::spawn` |
| `pub(crate)` handles | Orchestrator-only | Same |
| Forward actions | §8 | §8 below |

**Inheritance change:** the prior draft said master-secret containment was *not*
inherited because "stakes are public ledger facts + amounts." **That is reversed.**
The stake actor holds per-stake **`(amount, z)` only** in `StakeOpening` (§3.3.1).
Spend secret `x = ho + b` is **not** persisted in the stake sealed region — derived
transiently via `KeyEngine` + output derivation at claim and resync time. Master
spend/view keys route through `KeyEngine`; signing through `PendingTxEngine` +
`KeyEngine`.

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

- **Secret material in the stake actor (sealed):** per-stake `amount_atomic` and
  Pedersen mask `z` only — **not** spend secret `x` (§3.3.1). Per-epoch claim tags are
  **`N_{i,S} = x_i · G_S`** with `x = ho + b` derived transiently when needed.
  Public base
  `G_S = hash_to_ec("shekyl-stake-nullifier-base" ‖ S_le64)` ([`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md)
  §6.3–§6.4) — **no** separate `nullifier_seed` on `OutputSecrets`. Wallet must pin
  `G_S` domain + KAT and the claim prove/verify surface (R0-D1, §8.5). These are wallet
  secrets; they live in the **sealed** wallet region and never cross RPC or diagnostic
  surfaces as plaintext.
- **No public per-output index / watermark** to mirror; the wallet recognizes its
  own claims by watching for *its own* nullifiers on-chain.
- **Yield is exact**, computed wallet-local from the public rate schedule and the
  wallet's own (secret) weight — no daemon-trusted denominator.
- **Band declaration** is a wallet action at stake time (range-proven); the band is
  public; the exact amount is not.
- **Threat surface gains:** claim↔stake linkage, claim-timing correlation, band
  cohort-size leakage, secret-at-rest for openings, nullifier-reorg desync (§7).

### 0.11 Round 0 pre-flight findings (R0-D# — disposition required)

Substrate re-check after the confidential rebase (2026-06-02 review). Each item
must be **closed or explicitly deferred** before Round 0 closes.

| ID | Finding | Disposition (Round 0 pin) |
|----|---------|-------------------------|
| **R0-D1** | Claim nullifiers use **`N_S = x·G_S`** (spend secret `x` already in witness/`OutputSecrets`; no new HKDF field). Resync recomputes `{ x·G_S : S ∈ accrued_epochs }` and intersects the chain stake-claim nullifier set (§4.2, §5.2). | **Block implementation** on upstream [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §13 item 7 + §6.4 **(B)** (claim prove/verify, B1 preferred) + wallet §8.5 (`G_S` KAT). **Dissolves** prior `nullifier_seed` HKDF pin unless B1 infeasible (§6.3 fallback). |
| **R0-D2** | §4.2 "resync re-derives opening → no backlog loss" is **overbroad**. Pending (`PendingBroadcast` / `Unconfirmed`) stakes need `TxMetaBlock` / `PendingTxEngine`; confirmed stakes need scan + pinned derivation; **`claimed_epochs` must be rebuilt** from chain nullifier set ∩ locally derived `N_{i,S}`**, not only from persisted set. | **Pin §4.2 + §5.2** post-resync reconciliation pass. |
| **R0-D3** | Actor secret transport: `RegisterPendingStake(StakeInstance)` with `opening` in `ask` payloads is plaintext in the mailbox unless openings enter only at `spawn`/`restore`/`Snapshot` as sealed blobs. | **Pin §4.7** — openings via `Restore`/`Snapshot` sealed buffers and `spawn`-time registration; list/query messages return `StakeView` only. |
| **R0-D4** | Claim construction needs `x`, `z`, `a`, epoch set `S`, public `M` — must not duplicate openings in `PendingTxEngine`. | **Pin §4.6–§4.7** — `prepare_claim_build` returns stake-side material (`amount`, `z`, …); orchestrator derives **`x` transiently** from `KeyEngine` (`b`) + `ho` (output derivation) and feeds a **single** zeroized prover bundle to `PendingTxEngine` + `KeyEngine`. **`x` not in `StakeOpening`** (§3.3.1). |
| **R0-D8** | Persisting `x = ho + b` in `StakeOpening` duplicates **theft-grade** spend authority already held by `KeyEngine`; sealed-region compromise escalates from reward-claim forgery to principal spend. | **Rejected** (Round 1). `StakeOpening = (amount, z)` only; `x` derived at claim/resync (§3.3.1, §8.8). Reopen only if measured derivation cost is prohibitive across the full stake set on resync — not expected (§8.8). |
| **R0-D5** | `EconomicsEngine::rate_at_epoch` is proposed but `pool_weighted_total()` still exists; [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) still cites pool denominator for Phase 2b. | **Stage 3 co-lands** trait extension + boundaries-doc amendment (§8.6); grep-retire `pool_weighted_total` consumers. |
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
- FA-1 still holds: stakes target the **primary account address** only; no
  subaddress indices (subaddress recognition is subsumed by ML-KEM decap —
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
/// flags. Holds wallet-secret opening material (§4.1) — sealed at rest.
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
        accrued_rewards_atomic: u64, // EXACT: ρ_e (public) × own_weight × accrued_epochs
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
| `PendingBroadcast` | discard pending tx | *(remove instance or terminal — Round 2)* |
| `Unconfirmed` | scan finds the staked commitment output | `Locked` → auto-advance to `Accruing` if `height <= effective_lock_until` |
| `Locked` | next scan `height > confirmed_at` and `<= effective_lock_until` | `Accruing` |
| `Accruing` | scan height `> effective_lock_until` | `Claimable` (set `frozen_accrual_since`) |
| `Accruing` / `Claimable` / `FullyUnstaked` | scan observes **own nullifier** `N_{i,S}` on-chain | mark epoch `S` claimed in `claimed_epochs`; stay in state |
| `Accruing` / `Claimable` / `FullyUnstaked` | `Wallet::claim` builds pending claim tx for epoch set | *(pending-claim sub-state — Round 2; mirrors PendingBroadcast)* |
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
pub struct StakeId(pub [u8; 32]); // BLAKE3(domain, tx_hash || le(index)) — domain sep Round 2

/// SECRET — sealed at rest (§4.1). Never serialized to RPC; never in actor messages
/// as plaintext.
pub struct StakeOpening {
    pub amount_atomic: u64,     // wallet-known principal; NOT public on-chain
    pub z: Scalar,              // Pedersen mask (OutputSecrets.z); C = z·G + amount·H
    // NO `x` here — spend secret x = ho + b is KeyEngine-owned; §3.3.1
}

pub struct StakeInstance {
    pub id: StakeId,
    pub tier: StakeTier,             // shekyl_staking::StakeTier (public)
    pub band: StakeBand,             // public coarse band declared at stake time
    pub state: StakeState,
    /// Principal commitment reference (FA-1: primary address; no subaddress index).
    pub staked_output: OutputRef,    // { tx_hash, index_in_transaction }
    pub stake_tx: Option<TxHash>,
    /// Settlement-epochs already claimed (own nullifiers observed on-chain).
    /// Reorg-editable; not monotonic.
    pub claimed_epochs: EpochSet,    // e.g. roaring/bitset over settlement-epoch indices
    /// Secret opening material (sealed). Boxed/zeroized; see §4.1.
    pub opening: Secret<StakeOpening>,
}
```

`band: StakeBand` is the public coarse band (4–6 decade-log values). `opening` is the
new secret payload; its presence is what flips the secret-locality posture in §0.8 /
§4.1. `claimed_epochs` replaces the watermark and is the reorg-edited set in §5.2.

### 3.3.1 `StakeOpening` excludes spend secret `x` (Round 1 pin — R0-D8)

**Rejected:** persisting `x = ho + b` in the stake sealed region so rescan can recompute
`N_S = x·G_S` without re-deriving.

**Why:** `x` is the full spend secret — the same scalar behind principal key image
`x·Hp(O)` and unstake SAL. A sealed-region compromise that today exposes `(amount, z)`
enables **reward-claim forgery** only; adding `x` enables **principal theft**. That
trade is convenience (skip one derivation on resync), not a security win.

**Derivation cost (not prohibitive):**

| Step | When | Cost |
|------|------|------|
| `derive_output_secrets(combined_ss, idx)` → `ho`, `z`, … | Already required on resync to rebuild `StakeOpening.z` | One HKDF expand per staked output (same as any received output) |
| `b` from `KeyEngine` | Claim build + nullifier reconciliation | Master-key lookup already on the hot path for signing |
| `x = ho + b` (scalar add mod ℓ) | Per stake per resync / claim | O(1) per instance — negligible vs HKDF + scan |
| `N_S = x·G_S` | Per `(stake, S)` in accrued window | One scalar mult per settlement-epoch checked (≤15 tier-3); dominates add, still modest |

**Pin:** `StakeOpening` persists **`(amount, z)` only**. For claim build and
`claimed_epochs` reconciliation, the orchestrator (or a one-shot composition inside
`PrepareClaimBuild`) derives `x` from **`ho`** (output derivation for `staked_output`) +
**`b`** (`KeyEngine`) — same §4.7 single-prover pattern; **`x` never written to the
stake sealed blob**. Worst-case sealed-region exposure stays at claim-forgery grade,
not principal-spend grade.

**Reopen criterion:** measured resync on mainnet-class stake counts shows derivation
dominates UX budget *and* cannot be batched — evidence in `PERFORMANCE_BASELINE.md`,
not convenience argument alone.

---

## 4. Persistence and engine ownership

### 4.1 What lives where (architectural pin)

| State | Owner at runtime | Persisted | Secret? |
|-------|------------------|-----------|---------|
| Per-output chain flags (`staked`, `stake_tier`, `stake_lock_until`) | `LedgerEngine` / `TransferDetails` | `LedgerBlock.transfers` | No |
| Public rate / band-sum observation (per epoch) | `LedgerEngine` / `LedgerIndexes` (repurposed `StakerPoolState`) | **No** (rebuilt on scan) | No |
| Per-stake FSM (`StakeInstance`, incl. `band`, `claimed_epochs`) | **`StakeEngine` actor** | **Yes** — `LedgerBlock` field (§4.2) | Mixed |
| Per-stake **opening** (`amount`, `z` only) | **`StakeEngine` actor** | **Yes — sealed region** | **Yes** (claim-grade; not `x`) |
| Pending stake/claim/unstake intents | `PendingTxEngine` | `TxMetaBlock` / pending metadata | partial |
| Public rate schedule `ρ_e` / band params | `EconomicsEngine` + chain mirror | N/A (derived) | No |

**Secret-locality pin** ([`36-secret-locality.mdc`](../../.cursor/rules/36-secret-locality.mdc),
R0-D3): `StakeOpening` is sealed at rest, zeroized on drop, and never crosses RPC,
logs, or **kameo `ask` payloads** as plaintext. Openings enter the actor only at
`spawn` / `Restore` / `Snapshot` (sealed buffers) or in-process at registration time
constructed inside the orchestrator before a sealed handoff — not via `ListStakes` or
other query messages. The orchestrator holds handles only. RPC projections (§7)
expose **public** fields and **derived amounts** (claimable totals) plus
`principal_spent`; never `z`. Spend secret `x` never in stake persistence (§3.3.1).

### 4.2 Persistence schema (byte layout gate for Round 2)

**Pin:** extend [`LedgerBlock`](../../rust/shekyl-engine-state/src/ledger_block.rs)
with a stakes collection whose **opening material is in the sealed sub-region**:

```rust
pub stakes: Vec<StakeInstance>, // public fields + claimed_epochs in the ledger region;
                                // `opening` written to the sealed wallet region
```

- The public `StakeInstance` fields and `claimed_epochs` co-locate with the ledger;
  `opening` is written to the **sealed region** (same `file_kek`-protected region as
  other wallet secrets — no separate per-region HKDF).
- Bump `LEDGER_BLOCK_VERSION` + `WALLET_LEDGER_FORMAT_VERSION` per
  [`42-serialization-policy.mdc`](../../.cursor/rules/42-serialization-policy.mdc).
- Postcard schema snapshot co-lands in the same implementation PR as the struct.
- Pre-genesis: no migration loader — version mismatch → resync.

**Resync recovery (R0-D2 — narrowed):**

| Stake state at disconnect | Recovery path |
|---------------------------|---------------|
| `PendingBroadcast` / `Unconfirmed` | `PendingTxEngine` + `TxMetaBlock` (same as transfer path); stake actor does **not** infer from chain alone |
| `Active` / `FullyUnstaked` (confirmed on-chain) | Scan + `derive_output_secrets` → rebuild `StakeOpening` (`amount`, `z` only) |
| `claimed_epochs` (all confirmed states) | **Rebuild** from stake-claim nullifier set ∩ `{ x·G_S : S ∈ accrued_epochs }` where **`x` derived transiently** (`ho` + `b` via §4.7 / §8.8) — persisted set is cache, not authority |

Post-resync, run one reconciliation pass per restored instance (§5.2) before serving
claims. Pending stakes without tx meta may lose in-flight stake intents — same posture
as pending transfers.

**Hydration:** `Wallet::open*` loads stakes → `StakeEngineHandle::restore(instances)`,
unsealing `opening` inside the actor task.
**Flush:** `PersistenceEngine::save` snapshots the actor registry → ledger + sealed
region.

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

- `rate_at_epoch(rate_epoch) -> u64` (public `ρ_e`) for **exact** yield computation.
- `parameters_snapshot()` for tier multipliers / band parameters / decay display.

The wallet computes its own claimable backlog as
`Σ_{unclaimed S ⊆ (creation, eff_lock]} own_weight × K_S`, where
`K_S = Σ_{rate-epochs e ∈ S} ρ_e × rate_epoch_blocks` (all public) and
`own_weight = amount × tier_multiplier / SCALE` (amount secret, multiplier public).

**Reversion clause (§8.2):** methods on `EconomicsEngine` that take `stake_id` or
encode per-stake state remain **rejected** — reopen only via §10.6.1 in the
trait-boundaries doc. The old `pool_weighted_total()` consumption is **retired** (R0-D5);
Stage 3 co-lands `rate_at_epoch` + [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
amendment (§8.6).

### 4.6 `StakeEngine` trait surface (draft)

```rust
pub(crate) trait StakeEngine: Send + Sync + 'static {
    type Error: Into<StakeEngineError>;

    /// Register a new instance (incl. sealed opening) when the user builds a stake.
    /// Handle passes a sealed registration blob; actor unseals in-task (§4.7, R0-D3).
    fn register_pending_stake(&self, instance: StakeInstance) -> Result<(), Self::Error>;

    /// Apply scan-derived events after ledger merge (ordered — §5.3).
    fn apply_stake_events(
        &self,
        tip_height: u64,
        events: Vec<StakeEvent>,
    ) -> Result<StakeApplySummary, Self::Error>;

    /// Query API backing `Wallet::stakes(filter)`. Public fields + derived amounts only.
    fn list_stakes(&self, filter: StakeFilter) -> Result<Vec<StakeView>, Self::Error>;

    /// Exact claimable backlog across instances (sum of unclaimed-epoch entitlements).
    fn claimable_rewards_atomic(&self, tip_height: u64) -> Result<u64, Self::Error>;

    /// Set of unclaimed settlement-epochs for a stake (drives `Wallet::claim`).
    fn unclaimed_epochs(&self, stake_id: &StakeId, tip_height: u64)
        -> Result<EpochSet, Self::Error>;

    /// Single-use witness bundle for claim tx construction (R0-D4). Zeroized on drop;
    /// consumed by `PendingTxEngine` + `KeyEngine` — never persisted outside the actor.
    fn prepare_claim_build(
        &self,
        stake_id: &StakeId,
        epochs: EpochSet,
    ) -> Result<ClaimBuildSecrets, Self::Error>;

    /// Projected yield for UI (divide-by-zero N/A under fixed rate; guarded anyway).
    fn projected_yield(
        &self,
        stake_id: &StakeId,
        horizon_blocks: u64,
    ) -> Result<u64, Self::Error>;

    /// ArchivalEngine sibling query (Stage 5 consumer).
    fn is_active_staker(&self, entity_id: &EntityId) -> Result<bool, Self::Error>;
}
```

`StakeView` is a **secret-free** projection of `StakeInstance` for queries (public
fields + claimable amount; never `opening`). Async/sync split: **Round 2** — likely
async `apply_stake_events`, sync queries if the actor snapshot is cheap.

### 4.7 Actor protocol (Stage 3 implementation target)

Mirror [`KeyEngineHandle`](../../rust/shekyl-engine-core/src/engine/key_actor.rs):

| Message | Direction | Notes |
|---------|-----------|-------|
| `RegisterPendingStake(SealedStakeRegistration)` | orchestrator → actor | after `build_pending_tx`; sealed blob unsealed in-task (R0-D3) |
| `ApplyStakeEvents { tip_height, events }` | orchestrator → actor | post-ledger-merge |
| `ListStakes(StakeFilter)` | orchestrator → actor | read-only; returns `StakeView` |
| `ClaimableRewardsAtomic { tip_height }` | orchestrator → actor | read-only |
| `UnclaimedEpochs { stake_id, tip_height }` | orchestrator → actor | read-only; feeds claim builder |
| `PrepareClaimBuild { stake_id, epochs }` | orchestrator → actor | returns zeroized `ClaimBuildSecrets` (R0-D4) |
| `ProjectedYield { stake_id, horizon }` | orchestrator → actor | uses rate snapshot — Round 2 plumbing |
| `IsActiveStaker(EntityId)` | orchestrator → actor | public for archival |
| `Restore(SealedStakeSnapshot)` | orchestrator → actor | wallet open; unseals openings in-task |
| `Snapshot()` | orchestrator → actor | wallet save; returns sealed snapshot |

**Fail-stop:** **mandatory** for the stake actor (Stage 2 §4.5) — a panic could leave
the claimed-epoch set or opening material inconsistent.

**Secrets (R0-D3, R0-D4):** actor messages carry **no** master view/spend keys and **no
plaintext `StakeOpening` on query paths**. `RegisterPendingStake`, `Restore`, and
`Snapshot` move **sealed** registration/snapshot buffers; the actor unseals inside the
task. Nullifier checks derive **`x` transiently** (`ho` for `staked_output` + `b` from
`KeyEngine` via orchestrator — not from `StakeOpening`; §3.3.1). Claim construction:
orchestrator calls `PrepareClaimBuild` → composes stake material + derived `x` → passes
one zeroized `ClaimBuildSecrets` to `PendingTxEngine` + `KeyEngine`; openings are **not**
duplicated in `PendingTxEngine` persistence.

**Cross-engine composition (R0-D4, R0-D8) — the deeper constraint.** A claim proof needs
stake opening (`amount`, `z` — stake actor) **and** spend authority (`b` / `x` —
`KeyEngine` + output derivation) **together** in-process, but only **`(amount, z)`**
persist in the stake sealed region. `prepare_claim_build` feeds a **single prover invocation**
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
2. Stake actor receives `RewindTo { fork_height }` and must:
   - drop/rewind instances confirmed at or above `fork_height`; reset pending states
     tied to the abandoned chain;
   - **un-claim epochs whose nullifier was observed at or above `fork_height`** —
     remove those settlement-epochs from `claimed_epochs`. This mirrors the consensus
     requirement that the on-chain nullifier set is reorg-state; a reorged-then-
     re-mined claim must be re-claimable, so the wallet must not leave the epoch
     marked claimed.
3. The exact yield re-derives automatically from the (now rewound) `claimed_epochs`
   and the public rate schedule.
4. **Post-resync reconciliation (R0-D2):** after `Restore`, recompute `claimed_epochs`
   from the chain nullifier set ∩ locally derived `N_{i,S}` before exposing claimable
   balances — do not treat the persisted set as authoritative.

> This is the wallet mirror of the consensus nullifier-reorg requirement. If the
> consensus pop path fails to revert nullifiers, a re-mined claim is permanently
> rejected; the wallet cannot fix that, but it must keep its own `claimed_epochs`
> consistent with the post-reorg chain.

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
| `stakes(filter)` | `Vec<StakeView>` | Delegates `StakeEngine::list_stakes`; secret-free |
| `claimable_rewards()` | `AtomicUnits` | Exact sum across instances; **primary-address only** |
| `stake(amount, tier)` | `PendingTx` | Builds the **confidential staked output** (commitment + range proof + **band declaration** range-proven to the commitment); `PendingTxEngine::build` + `register_pending_stake` |
| `claim(stake_id)` | `PendingTx` | Builds a **confidential claim** covering up to `MAX_EPOCHS_PER_CLAIM` unclaimed settlement-epochs in **one** tx (membership + per-epoch nullifiers + one batched entitlement on `M = tier_num · Σ_S K_S` + range proof). Entitlement is O(1) in epoch count; only nullifiers scale (~15 for a tier-3 full drain). **Production default:** batch the full window when `|epochs| ≤ 15` (§5 upstream). `MAX_EPOCHS_PER_CLAIM = 1` is **test-mode only**. Calls `prepare_claim_build`, then composes via `PendingTxEngine` + `KeyEngine` (§4.7). Does not finalize. |
| `unstake(stake_id)` | `PendingTx` | Spends the principal commitment via membership proof after lock; FSM → `Unstaking` on submit |

**FA-1:** stake/claim/unstake target the **primary account address** only; no
`SubaddressIndex` in `StakeInstance` or tx templates.

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
| **Commitment-opening disclosure** | `StakeOpening` holds `(amount, z)` only — **not** `x` (§3.3.1); sealed at rest, zeroized on drop, never in RPC or actor-message plaintext. Spend secret derived transiently for nullifier match / claim prove. |
| **Band cohort-size leakage** | Band is coarse (4–6 decade bands); at cold start, thin cohorts make even a coarse band revealing — wallet UI may warn early stakers; consensus may floor/suppress the signal at low participation (upstream). |
| **Nullifier-reorg desync** | Ordered §5.2 `RewindTo`; wallet un-claims epochs whose nullifier was reorged out; mirrors consensus pop reverting the nullifier set. |
| Reorg desync between ledger and stake actor | Ordered §5.3; explicit `RewindTo` message |
| Fake `StakeEvent` injection | Events originate from scanner parsing blocks tied to daemon headers; `OwnNullifierObserved` requires matching a locally derived nullifier (a forged event cannot fabricate the wallet's own nullifier) |
| **Silent inflation** | **`h_bind`** (tier+creation) + window arithmetic + recomputed `N/D` + **(A)** bounded-remainder (committed `ρ`, range `0≤ρ<D`) + `ρ_cap` (upstream §9) |

**Diagnostic projection (lens 3):** RPC fields are **field-redacted** (no view/spend,
no `z`), **height-labeled**, **distribution-safe** (no
per-output secret correlation), and **claim-unlinkable** (no stake↔claim join key).

---

## 8. Forward actions and reversion clauses

### 8.0 Confidential-consensus dependency (Stage 3 merge gate)

**Stage 3 merge to `dev` is blocked** until this document's **Round 3** closes
(threat-model + wider-substrate audit). **Upstream consensus Round 1 is closed**
(2026-06-02): wire sketch (`txin_stake_claim_v2`), servo + `ρ_cap` pins, §6.4
**(A)** reserve-DLEQ + bounded remainder; **(C)** closed on **3C** (2026-06-04). Byte-exact
serialization, staking-subtree 5-scalar leaf / `h_bind` KATs, entitlement vectors are
upstream Round 2 gates; implementation against the cleartext HF17 model is forbidden.

**Parallel work allowed (design + isolated spikes):** Rounds 2–6 on this document,
trait sketches, FSM tests against mocks, sealed-region layout — provided spikes do not
land cleartext `staked_output_index` / watermark paths on `dev`. Feature-branch
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

### 8.8 `StakeOpening` excludes `x` (wallet — R0-D8)

**Pin:** see §3.3.1. Persist **`(amount, z)` only**; derive `x = ho + b` at claim build
and `claimed_epochs` reconciliation. Security over resync convenience; derivation cost is
O(1) scalar add per stake atop HKDF already required for `z`.

**Reopen when:** `PERFORMANCE_BASELINE.md` shows batch derivation is the resync bottleneck
and cannot be amortized — not on convenience argument alone.

### 8.6 `EconomicsEngine::rate_at_epoch` (trait amendment — R0-D5)

**Stage 3 co-lands:**

```rust
fn rate_at_epoch(&self, rate_epoch: u64) -> Result<u64, EconomicsEngineError>;
```

- Amend [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §2.7 /
  Phase 2b rows: retire `pool_weighted_total()` narrative; document `rate_at_epoch` as
  the sole yield schedule surface for `StakeEngine`.
- Grep-retire `pool_weighted_total` production callers (`economics.rs`,
  `chain_economics_source.rs`, tests).

**Reversion:** per §8.2 — no per-stake methods on `EconomicsEngine`.

---

## 9. Round record

| Round | Status | Summary |
|-------|--------|---------|
| **0** | **Closed** (2026-06-04) | Confidential redesign is a substrate finding (Principle 5). Re-pre-flight §0.1–§0.8 re-walked against the locked 3C / `h_bind` / `creation ≜ eligible` / collapsed-(A) consensus; §0.10 signed off; **R0-D1–D8 dispositioned in §0.11** (2026-06-02). Re-walk fixed two stale-text gates (Drift 1 stake-actor secrets → `(amount, z)`-only; Drift 2 inflation-safety framing → `N/D`-recompute primary) + two completeness notes (§0.4 lock-view, §0.7 3C scanner scope); no design reopen. Blast radius: stake-actor openings `(amount, z)` only (R0-D8), claim prove surface, two-tree scanner parsing, `AccrualRecord` retirement. |
| **1** | **Closed** (2026-06-02; **(C) 3C** 2026-06-04) | **§6.4:** **(C)** closed on **3C** (staking subtree + 5-scalar `h_bind`; Decisions 1–2 superseded); **(B)**; **(A)** collapsed to reserve-DLEQ + bounded remainder; R0-D8. Round 2: byte wire, tree/leaf impl, cross-tree atomicity. |
| **2** | Open | R-residuals: `StakeId` domain sep, pending-claim sub-state, `EpochSet` wire type, sealed-region layout for `opening`, async trait |
| **3** | Open | Threat-model exhaustion (§7) + §6 wider-substrate audit (after upstream Round 1) |
| **4** | Open | Binding pins (trait signatures, error enums, persistence version, sealed-region format) |
| **5** | Open | Closure + Stage 3 PR decomposition |
| **6** | Open | External critique buffer (optional) |

---

## 10. Definition of done

### 10.1 Planning (this document)

- [x] §0 re-pre-flight complete against confidential consensus shapes (2026-06-04, §0.9)
- [x] **R0-D1–D8** dispositioned (§0.11) — implementation gates named in §8.5–§8.8
- [ ] `StakeState` FSM + transition table signed off (Rounds 1–2), incl. post-unstake claims (R0-D6)
- [ ] Reconciliation rules incl. **nullifier-reorg rewind** signed off (§5)
- [ ] Persistence schema incl. **sealed `opening` region** signed off (§4.2) with version-bump plan
- [ ] User method signatures signed off (§6)
- [ ] `StakeEngine` message protocol signed off (§4.7), incl. sealed transport + `PrepareClaimBuild` (R0-D3, R0-D4)
- [x] **`StakeOpening` excludes `x`** (§3.3.1 / §8.8, R0-D8)
- [x] **`G_S` + claim linkability + `MAX_EPOCHS_PER_CLAIM`** pinned with **(B)** (§8.5 / upstream §6.4.2)
- [x] **Tier/window / multiplier integrity** — upstream **(C)** closed on **3C** (staking subtree + `h_bind`, window arithmetic); **(A)** reserve-DLEQ + bounded remainder; impl Round 2
- [ ] `EconomicsEngine::rate_at_epoch` + boundaries doc amendment (§8.6)
- [x] **Upstream consensus Round 1 closed** (§8.0; [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §14)
- [ ] Round 3 design closure recorded in §9

### 10.2 Stage 3 implementation (after closure — separate PR(s))

- [ ] `StakeEngine` + `StakeEngineHandle` + `StakeActor` (`kameo`), fail-stop, sealed openings
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
| [`42-serialization-policy.mdc`](../../.cursor/rules/42-serialization-policy.mdc) | Version bump for new field + sealed region |
