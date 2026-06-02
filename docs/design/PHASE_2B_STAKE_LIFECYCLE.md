# Phase 2b — stake lifecycle (design)

**Status:** Re-based onto the **confidential staking** consensus redesign
(design session 2026-06-02). This is a **substrate-level reopen**: the model the
prior draft mirrored (cleartext staked amounts, public `staked_output_index`,
monotonic claim watermark, pool-denominator yield) is being replaced by committed
amounts, membership-unlinkable claims, per-epoch nullifiers, and a band-servo'd
public rate. **Round 0 requires re-pre-flight; Rounds 1–6 open.** No Stage 3
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

1. **Staked amount is committed, not public.** The chain stores a Pedersen
   commitment + range proof; the wallet knows its own `(amount, z)` (Pedersen mask,
   same role as `OutputSecrets.z`) and must protect them as secrets. `StakeInstance`
   is no longer secret-free.
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

**Re-pre-flight required.** The prior §0 was verified at `dev @ 5f10af243`
(post–PR #99) against the cleartext model. The confidential redesign changes the
blast radius (new secret material in the stake actor; new consensus tx shapes the
scanner must parse), so §0.1–§0.9 below are **carried forward as structure** but
must be re-walked against the confidential consensus before Round 1 closes. New
material is in §0.10.

### 0.1 Engine identification ([`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md) §3.1)

- [ ] **§2 trait binding (re-verify):** [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §10.5.1 (`StakeEngine` additive trait); §2.7 (`EconomicsEngine` consumer framing —
  now consumes the **rate schedule**, not the pool denominator); §3.3 (cross-engine
  `.await` sequencing); §8.3 lens table row for `StakeEngine`.
- [ ] **§1.5 three-condition test (additive trait):**
  - **(1) Distinct state ownership:** per-stake FSM + wallet-side stake registry **+
    per-stake commitment-opening secrets and nullifier-derivation material**;
    distinct from `LedgerEngine` and `EconomicsEngine`. **Pass (re-confirm secret
    ownership).**
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
  changes (§1); inflation-safety now rests on consensus range proofs + `ρ_cap` (§7).

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
| **`nullifier_seed` in `OutputSecrets`** | **0** — not in [`derivation.rs`](../../rust/shekyl-crypto-pq/src/derivation.rs) today; requires new HKDF label + KAT (R0-D1) |

**Implication:** Stage 3 adds a new engine module tree (`stake_engine.rs`,
`stake_actor.rs`, `StakeEngineHandle`) parallel to
[`key_actor.rs`](../../rust/shekyl-engine-core/src/engine/key_actor.rs); extends
`ScanResult` / merge / refresh; **and** the scanner must learn the confidential
stake-output and claim-tx wire shapes (owned upstream by the consensus design).

### 0.8 Stage 2 actor template (reference only — [`STAGE_2_KEY_ENGINE_ACTOR.md`](STAGE_2_KEY_ENGINE_ACTOR.md))

| Pattern | Stage 2 pin | Phase 2b application (confidential) |
|---------|-------------|-------------------------------------|
| Handle vs actor | `KeyEngineHandle` + `KeyActor` | `StakeEngineHandle` + `StakeActor`; stake registry **+ opening secrets** inside task |
| Fail-stop | §4.5 — `Break` on panic; no restart with stale secrets | **Adopt — now mandatory**: actor holds commitment openings + nullifier secrets (§0.10) |
| Require-ambient runtime | §4.2 | Same for `StakeEngineHandle::spawn` |
| `pub(crate)` handles | Orchestrator-only | Same |
| Forward actions | §8 | §8 below |

**Inheritance change:** the prior draft said master-secret containment was *not*
inherited because "stakes are public ledger facts + amounts." **That is reversed.**
The stake actor now holds per-stake `(amount, z, nullifier_seed)` and must
inherit Stage 2 secret-locality and fail-stop. Master spend/view keys still route
through `KeyEngine`; signing still routes through `PendingTxEngine` + `KeyEngine`.

### 0.9 Round 0 disposition

**Re-pre-flight in progress.** Round 0 closes only after §0.1–§0.8 are re-walked
against the confidential consensus shapes, §0.10 is signed off, and the **R0-D
pre-flight findings** (§0.11) are dispositioned.

### 0.10 Confidential-rebase delta (new)

The single source of the reopen. Wallet-relevant facts inherited from the
confidential consensus design ([`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §2.3):

- **Secret material now in the stake actor:** per-stake `amount_atomic`, Pedersen mask
  `z` (same role as `OutputSecrets.z` in [`derivation.rs`](../../rust/shekyl-crypto-pq/src/derivation.rs)),
  and a `nullifier_seed` (per-output secret from which
  `N_{i,S} = PRF(nullifier_seed, settlement_epoch_S)` derives). **`nullifier_seed` is
  not in `OutputSecrets` today** — upstream must pin a new HKDF label + KAT before
  implementation (R0-D1, §8.5). These are wallet secrets; they live in the **sealed**
  wallet region and never cross RPC or diagnostic surfaces as plaintext.
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
| **R0-D1** | `nullifier_seed` is **not** in `OutputSecrets` / `derive_output_secrets` today; resync cannot assume it exists until a labeled HKDF expansion is pinned ([`30-cryptography.mdc`](../../.cursor/rules/30-cryptography.mdc) domain separator + `PQC_OUTPUT_SECRETS.json` KAT). | **Block implementation** on upstream [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §13 item 7 + wallet §8.5. Phase 2b tracks; does not define the label here. |
| **R0-D2** | §4.2 "resync re-derives opening → no backlog loss" is **overbroad**. Pending (`PendingBroadcast` / `Unconfirmed`) stakes need `TxMetaBlock` / `PendingTxEngine`; confirmed stakes need scan + pinned derivation; **`claimed_epochs` must be rebuilt** from chain nullifier set ∩ locally derived `N_{i,S}`**, not only from persisted set. | **Pin §4.2 + §5.2** post-resync reconciliation pass. |
| **R0-D3** | Actor secret transport: `RegisterPendingStake(StakeInstance)` with `opening` in `ask` payloads is plaintext in the mailbox unless openings enter only at `spawn`/`restore`/`Snapshot` as sealed blobs. | **Pin §4.7** — openings via `Restore`/`Snapshot` sealed buffers and `spawn`-time registration; list/query messages return `StakeView` only. |
| **R0-D4** | Claim construction needs `nullifier_seed`, `z`, `a`, epoch set `S`, public `M` — must not duplicate openings in `PendingTxEngine`. | **Pin §4.6** — `prepare_claim_build(stake_id, epochs) -> ClaimBuildSecrets` (zeroized, single-use); `PendingTxEngine` + `KeyEngine` consume; never persisted outside stake actor. |
| **R0-D5** | `EconomicsEngine::rate_at_epoch` is proposed but `pool_weighted_total()` still exists; [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) still cites pool denominator for Phase 2b. | **Stage 3 co-lands** trait extension + boundaries-doc amendment (§8.6); grep-retire `pool_weighted_total` consumers. |
| **R0-D6** | [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §7: accrued epochs remain claimable **after unstake**; FSM `FullyUnstaked` must not foreclose claims. | **Pin §3.1** — `principal_spent: bool` on instance or remain in claimable-equivalent state until `claimed_epochs` exhausted. |
| **R0-D7** | `RateEpochObserved { rho, band_sum }` is not a rename of `AccrualRecord` — retire `StakerPoolState::estimate_reward` pool-division path to avoid accidental reintroduction. | **Pin §4.3** — new `RateEpochRecord` type; explicit deletion target in Stage 3 grep plan. |

**Round 0 close checklist:** §0.1–§0.8 re-walked against [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md); R0-D1–D7 rows dispositioned in-doc; §8.0 blocking posture confirmed (§8.0).

---

## 1. Mission posture

**Priority-1 (security):** stake flows must not leak spend/view material **or
commitment openings / nullifier seeds** on RPC or logs; claim/unstake txs must use
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

- **Confidential staked output:** Pedersen commitment `C_stake = a·H + r·G` + range
  proof; **tier public**; **coarse band public** (range-proven to `C_stake`).
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
  `N_{i,S} = PRF(nullifier_seed_i, S)`; replaces the public index + watermark; is
  **reorg-state** (consensus pop must revert it; wallet mirror in §5.2).
- **Nullifier counts per tier (full drain):** tier-1 (1,000 blk) → 1–2; tier-2
  (25,000) → ≤3; tier-3 (150,000) → ≤15.
- **Band:** 4–6 decade-log-spaced; geometric-midpoint weight in `band_sum`; coarse
  by design (cohort-size caveat at cold start).

Open upstream items the wallet must track (do not implement against until pinned):
whether the burn coupling needs the value-weighted band or tier-weighted count;
window shape/length; `ρ_cap`'s decay handling; cold-start floor policy; **nullifier
PRF + `nullifier_seed` HKDF label** ([`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md)
§13 item 7, wallet §8.5); **entitlement-binding mechanism** (§13 item 6); **claims
after principal spent** ([`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §7, R0-D6).

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
    pub z: Scalar,              // Pedersen mask; C_stake = a·H + z·G (OutputSecrets.z)
    pub nullifier_seed: [u8; 32], // N_{i,S} = PRF(nullifier_seed, S); HKDF label §8.5
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

---

## 4. Persistence and engine ownership

### 4.1 What lives where (architectural pin)

| State | Owner at runtime | Persisted | Secret? |
|-------|------------------|-----------|---------|
| Per-output chain flags (`staked`, `stake_tier`, `stake_lock_until`) | `LedgerEngine` / `TransferDetails` | `LedgerBlock.transfers` | No |
| Public rate / band-sum observation (per epoch) | `LedgerEngine` / `LedgerIndexes` (repurposed `StakerPoolState`) | **No** (rebuilt on scan) | No |
| Per-stake FSM (`StakeInstance`, incl. `band`, `claimed_epochs`) | **`StakeEngine` actor** | **Yes** — `LedgerBlock` field (§4.2) | Mixed |
| Per-stake **opening** (`amount`, `z`, `nullifier_seed`) | **`StakeEngine` actor** | **Yes — sealed region** | **Yes** |
| Pending stake/claim/unstake intents | `PendingTxEngine` | `TxMetaBlock` / pending metadata | partial |
| Public rate schedule `ρ_e` / band params | `EconomicsEngine` + chain mirror | N/A (derived) | No |

**Secret-locality pin** ([`36-secret-locality.mdc`](../../.cursor/rules/36-secret-locality.mdc),
R0-D3): `StakeOpening` is sealed at rest, zeroized on drop, and never crosses RPC,
logs, or **kameo `ask` payloads** as plaintext. Openings enter the actor only at
`spawn` / `Restore` / `Snapshot` (sealed buffers) or in-process at registration time
constructed inside the orchestrator before a sealed handoff — not via `ListStakes` or
other query messages. The orchestrator holds handles only. RPC projections (§7)
expose **public** fields and **derived amounts** (claimable totals) plus
`principal_spent`; never `z` or `nullifier_seed`.

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
| `Active` / `FullyUnstaked` (confirmed on-chain) | Scan + `OutputSecrets` + pinned `nullifier_seed` derivation (§8.5); rebuild `StakeOpening` |
| `claimed_epochs` (all confirmed states) | **Rebuild** from chain nullifier set ∩ `{ PRF(nullifier_seed, S) : S ∈ accrued_epochs }` — persisted `claimed_epochs` is a cache, not authority |

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
task. Nullifier derivation for `OwnNullifierObserved` runs inside the actor from
`nullifier_seed`. Claim construction: orchestrator calls `PrepareClaimBuild` → passes
`ClaimBuildSecrets` once to `PendingTxEngine` + `KeyEngine` → secrets zeroized; openings
are **not** duplicated in `PendingTxEngine` persistence.

**Cross-engine composition (R0-D4) — the deeper constraint.** `ClaimBuildSecrets` cannot
be *split* between engines: a claim proof needs the stake opening (`amount`, `z`,
`nullifier_seed` — stake actor) **and** spend authority (master spend `b` — `KeyEngine`)
**together**, and neither engine holds both. So `prepare_claim_build` feeds a **single
prover invocation** — the existing collapsed-signing pattern (`shekyl_sign_fcmp_transaction`
takes the spend secret + per-input `combined_ss` and derives/proves in Rust, secrets
meeting only in-process) — rather than a witness bundle that `KeyEngine` merely signs.
Exact placement (in-actor proving vs a dedicated claim-prover receiving both sealed
inputs) is a Round 1 load-bearing question, and it rests on confirming
`shekyl_sign_fcmp_transaction`'s shape extends from a spend to a claim proof
(entitlement + nullifier relations on top of membership).

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
| `claim(stake_id)` | `PendingTx` | Builds a **confidential claim** covering up to `MAX_EPOCHS_PER_CLAIM` unclaimed settlement-epochs in **one** tx (membership + per-epoch nullifiers + one batched entitlement on `M = tier_num · Σ_S K_S` + range proof). Entitlement is O(1) in epoch count; only nullifiers scale (~15 for a tier-3 full drain). `MAX_EPOCHS_PER_CLAIM = 1` recovers strict one-epoch-per-tx — a Round-1 value choice ([`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §5–§6). Calls `prepare_claim_build`, then composes via `PendingTxEngine` + `KeyEngine` (§4.7). Does not finalize. |
| `unstake(stake_id)` | `PendingTx` | Spends the principal commitment via membership proof after lock; FSM → `Unstaking` on submit |

**FA-1:** stake/claim/unstake target the **primary account address** only; no
`SubaddressIndex` in `StakeInstance` or tx templates.

**Claim batching / timing (privacy):** claiming the **full unclaimed window** in one tx
(`MAX_EPOCHS_PER_CLAIM` permitting) is privacy-preferred — it removes the partial-timing
tell and tightens the [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §6.2
anonymity bound (a partial epoch set narrows the cohort more than a full window). If
`MAX_EPOCHS_PER_CLAIM = 1` is chosen for proof-size predictability, the wallet queues
multiple claim txs for a backlog and must not broadcast on a fixed epoch-boundary
cadence that fingerprints the stake. Broadcast jitter / Dandelion++ is the
network-layer mitigation (§7).

---

## 7. Threat model (Round 1 wargaming seed) — **expanded**

| Threat | Mitigation pin |
|--------|----------------|
| Malicious daemon **misreports the rate `ρ_e`** | Yield uses the wallet's own (secret) weight × public `ρ_e`; `ρ_e` is consensus-derived from the on-chain `band_sum` and verifiable by full nodes. Light clients carry residual trust; warn on stale/inconsistent rate. (Replaces the old "understates `total_weighted_stake`" threat — there is no daemon-supplied denominator anymore.) |
| Wallet over-claims reward amount | Claim built from the public rate × the stake's own weight over **unclaimed** epochs; consensus range proof + entitlement relation reject over-claims. Wallet must not rely on consensus to mask a local accounting bug (priority-1). |
| **Claim↔stake linkage** | Membership-unlinkable claims + per-epoch nullifiers; wallet uses fresh `N_{i,S}`, exposes no RPC/UI field correlating a claim to a stake, batches/jitters broadcast timing. |
| **Commitment-opening / nullifier-seed disclosure** | `StakeOpening` sealed at rest, zeroized on drop, never in RPC or actor-message plaintext; nullifier derivation occurs inside the actor task. |
| **Band cohort-size leakage** | Band is coarse (4–6 decade bands); at cold start, thin cohorts make even a coarse band revealing — wallet UI may warn early stakers; consensus may floor/suppress the signal at low participation (upstream). |
| **Nullifier-reorg desync** | Ordered §5.2 `RewindTo`; wallet un-claims epochs whose nullifier was reorged out; mirrors consensus pop reverting the nullifier set. |
| Reorg desync between ledger and stake actor | Ordered §5.3; explicit `RewindTo` message |
| Fake `StakeEvent` injection | Events originate from scanner parsing blocks tied to daemon headers; `OwnNullifierObserved` requires matching a locally derived nullifier (a forged event cannot fabricate the wallet's own nullifier) |
| **Silent inflation** (now load-bearing) | Per-claim range proof + entitlement relation + the consensus `ρ_cap` backstop bound total staker emission ≤ budget regardless of `band_sum` error or manipulation. This is the inflation-safety argument; it lives upstream but the wallet must never broadcast a claim that would violate it locally. |

**Diagnostic projection (lens 3):** RPC fields are **field-redacted** (no view/spend,
no `z`, no `nullifier_seed`), **height-labeled**, **distribution-safe** (no
per-output secret correlation), and **claim-unlinkable** (no stake↔claim join key).

---

## 8. Forward actions and reversion clauses

### 8.0 Confidential-consensus dependency (Stage 3 merge gate)

**Stage 3 merge to `dev` is blocked** until [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md)
closes **consensus Round 1**: wire format (confidential staked output, claim tx,
nullifier set, band), servo + `ρ_cap`, and **§6.4 entitlement-binding** (highest-risk
open item). Implementation against the cleartext HF17 model is forbidden.

**Parallel work allowed (design + isolated spikes):** Rounds 1–6 on this document,
trait sketches, FSM tests against mocks, sealed-region layout — provided spikes do not
land cleartext `staked_output_index` / watermark paths on `dev`. Feature-branch
consensus work tracks upstream; wallet Stage 3 lands after upstream Round 1 + Round 3
closure here.

**Reopen/track:** §2.3 and [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §13
(value-weighted vs count band; window shape; `ρ_cap` decay; cold-start floor;
nullifier PRF; entitlement binding).

### 8.1 Persist the rate/band cache in the wallet file

**Rejection:** keep rebuild-on-scan ([`ledger_block.rs`](../../rust/shekyl-engine-state/src/ledger_block.rs)).

**Reopen when:** rescan refill exceeds the UX budget on mainnet-class history on V3.0
hardware — evidence in `PERFORMANCE_BASELINE.md`.

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

### 8.5 `nullifier_seed` derivation (wallet — R0-D1)

**Block:** claim recognition and resync until pinned.

**Requirements:**

- New labeled HKDF expansion from the hybrid output secret domain (same posture as
  `OutputSecrets` in [`derivation.rs`](../../rust/shekyl-crypto-pq/src/derivation.rs));
  domain separator + `PQC_OUTPUT_SECRETS.json` KAT.
- `derive_output_secrets` (or successor) emits `nullifier_seed: [u8; 32]`.
- Wallet must recompute identically on rescan/resync (§4.2, §5.2).

**Owner split:** PRF definition + consensus binding → [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md)
§13 item 7. Wallet derivation path → this section. Phase 2b does **not** invent the
label; it tracks upstream closure.

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
| **0** | **Reopened** | Confidential redesign is a substrate finding (Principle 5). Re-pre-flight §0.1–§0.8; sign off §0.10; **R0-D1–D7 dispositioned in §0.11** (2026-06-02). Blast radius: stake-actor secrets, `nullifier_seed` derivation gap, scanner parsing, `AccrualRecord` retirement. Closes when checklist in §0.11 is satisfied. |
| **1** | Open | Accruing vs Claimable (carried); merge split (§4.3); **secret-locality of `StakeOpening`**; **nullifier-reorg rewind (§5.2)**; dependency on upstream wire format (§8.0) |
| **2** | Open | R-residuals: `StakeId` domain sep, pending-claim sub-state, `EpochSet` wire type, sealed-region layout for `opening`, async trait |
| **3** | Open | Threat-model exhaustion (§7) + §6 wider-substrate audit (after upstream Round 1) |
| **4** | Open | Binding pins (trait signatures, error enums, persistence version, sealed-region format) |
| **5** | Open | Closure + Stage 3 PR decomposition |
| **6** | Open | External critique buffer (optional) |

---

## 10. Definition of done

### 10.1 Planning (this document)

- [ ] §0 re-pre-flight complete against confidential consensus shapes
- [ ] **R0-D1–D7** dispositioned (§0.11) — implementation gates named in §8.5–§8.6
- [ ] `StakeState` FSM + transition table signed off (Rounds 1–2), incl. post-unstake claims (R0-D6)
- [ ] Reconciliation rules incl. **nullifier-reorg rewind** signed off (§5)
- [ ] Persistence schema incl. **sealed `opening` region** signed off (§4.2) with version-bump plan
- [ ] User method signatures signed off (§6)
- [ ] `StakeEngine` message protocol signed off (§4.7), incl. sealed transport + `PrepareClaimBuild` (R0-D3, R0-D4)
- [ ] `nullifier_seed` HKDF label pinned (§8.5 / upstream §13 item 7)
- [ ] `EconomicsEngine::rate_at_epoch` + boundaries doc amendment (§8.6)
- [ ] **Upstream consensus Round 1 closed** (§8.0) — unblocks Stage 3 **merge**
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
| [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) | Upstream truth for commitment/range-proof, ZK claim relation, nullifiers, band, servo'd rate, `ρ_cap` (§2.3, §8.0, §8.5) |
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
