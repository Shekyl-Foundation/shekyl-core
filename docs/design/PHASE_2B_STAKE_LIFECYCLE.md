# Phase 2b — stake lifecycle (design)

**Status:** Genesis staking substrate is **pay-for-service archival rebasing +
firewalled pseudonym `P`**, in the **transfer-shaped admission** form (§2.4 —
leading genesis shape). Pre-genesis there is **one** ship target — not a
confidential-yield stack built now and replaced at genesis. The **reserve-DLEQ
entitlement / `tier_num` claim path** (`CONFIDENTIAL_STAKING.md` §6.4 claim wire
+ `rust/shekyl-staking/` `entitlement.rs` / `tiers.rs` / `rewards.rs`) is
**deletion target**, not interim implementation. Decision **3C** (staking subtree,
`h_bind`, 5-scalar leaf) is **docs-only** — un-building planned work, not ripping
out shipped code.

This document still records the **2026-06-02 confidential-principal redesign**
(committed stake amounts, membership proofs, FCMP++ spend/unstake path, wallet
opening discipline §3.3.1) because that machinery **survives** rebasing: principal
lock, `C_stake`, stealth payouts, `KeyEngine` boundaries. What rebasing **replaces** is the **confidential-reward superstructure** (entitlement
claims, `tier_num`, `band_sum` servo, exact-yield-from-secret-weight) — see §2.1
*Carry-over / delete*.

**Identity — three-way split (do not collapse to "P solves F0"):**

1. **The pay-for-service model dissolves F0** — not mitigated. F0 was the
   confidential claim wire leaking `(tier, creation_height)` into a `{tier ×
   creation-window}` cohort. Work-based reward removes `tier_num` from the reward
   path (per-shard bonds replace the staker tier); there is no confidential claim
   left to leak. F0's substrate is **deleted**.
2. **`P` addresses a different problem** archival creates — archival cannot be
   unlinkable like a claim (reachability + persistence + challengeability require a
   stable holder). The goal flips from **anonymity** (hide the actor — what
   confidential staking attempted and F0 defeated) to **firewalled pseudonymity**
   (`P` is public by function; `P`↔principal is hidden).
3. **The firewall is conditional, unbuilt, and is the privacy work** — network /
   timing / output / membership-proof hygiene maintained over `P`'s whole life
   (gate 6; Tier 1 soundness). Failure mode: long-lived correlation of `P`'s
   public activity against the principal, plus cross-pseudonym intersection. Bonds
   — not `P`-uniqueness — carry Sybil-resistance, so multi-`P` is privacy hygiene,
   not security. **Do not under-budget gate 6** because the model "solves identity."

Wallet Rounds 0–2 pins (FSM skeleton, persistence discipline, §4.7 actor shape,
§5 reorg forward-rebuild, §6 API *intent*) remain load-bearing **where §2 says
retain** — **§3 FSM** and **§7 threat model** are rebased (P2B-3/6, 2026-06-07);
**§4–§6** body text is still **claim-centric** until retooled — **STRATUM** per
[`ARCHIVAL_CORPUS_FOSSIL_SWEEP.md`](ARCHIVAL_CORPUS_FOSSIL_SWEEP.md) §4; implement from
[`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md), not §3.3–§8.5 nullifier paths. §2 is
authoritative for rebased scope. No Stage 3 until **Round 3–4 closes on the rebased substrate**
(gate-list + gate 6 to soundness depth + **T-A1** F1 gate) per
[`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md) §7.

**Process discipline:** [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
(Round 0 = pre-flight / R0-D#; adversarial rounds 1–6 before code).

**Binding constraint when arbitrating:** [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc)
priority-1 (security), then priority-2 (privacy). Post-rebase, priority-2 on the
reward path is **firewall discipline**, not hidden reward amounts. Principal
commitment shape, `P` registration, per-shard bond lifecycle, and reorg atomicity
on registration/counting nullifiers are **consensus-load-bearing**; wallet display
must not invent economics the chain did not authorize.

---

## Revision note

### 2026-06 — pay-for-service rebasing (authoritative for scope)

**§2 is the authoritative scope statement** for genesis. **§3 FSM retooled (2026-06-07)**
against [`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md) + gate-4 custody. §4–§6 and §7
below remain **claim-era** until the next retool passes. **Gate-6:** [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md)
(Round 1 — §9 `P` derivation). **Timing cluster:** [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md).

Genesis staking = **transfer-shaped admission + archival service under firewalled
`P`**. One reward stream: work scored on `P`'s public history, funded via `Σwork`
servo, paid to stealth outputs `P` controls. Not: build entitlement claims, then
replace.

### 2026-06 — transfer-shaped admission (leading genesis form)

Elevates §2.4 as the **leading genesis staking shape** (Round 3–4 ratification
pending three close-conditions below). Supersedes discrete on-chain registration +
`txin_stake_claim_v2` + Decision **3C** staking subtree for genesis. **Codebase
grounding:** 3C/`h_bind`/5-scalar leaf exist in design docs only; live C++ is
cleartext `txout_to_staked_key` + `txin_stake_claim` — pivot deletes planned work
and retires two legacy paths, not a built subtree.

**Two irreducible consensus-special surfaces:** (1) **per-shard bond** (gate 4 —
slashable, consensus-tracked); (2) **reward emission** (mint authorized by public
work + backing). Everything else — principal→`P` stake-in, `P`→principal unstake
drain, reward sweeps — is **ordinary `RCTTypeFcmpPlusPlusPqc` transfer**, firewalled
by base FCMP++ privacy.

**Reward-leg crypto (substantive pin):** no published backing/reward-dedup tag on
the emission. `N_arch = x·G_arch` conflated two jobs (backing consistency vs
per-epoch double-claim); both are wrong for the fused model — stake-keyed tags
collide under shared admission stake and do not dedup epochs. **Reward dedup** =
per-`P` **claimed-epoch bitmap** on the bond record (gate 4 keys state by `P`),
reusing the `EpochSet` relative-bitmask machinery (§3.3.2) with §5.2/§11
reorg-revert atomicity. Claim epoch *E* ⟺ check-and-set bit *E*. **`R_market`** is a
**derived ledger count** (gate 3 dissolved — no `ν` primitive; see
[`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) §2).
Consequence: the reward leg owes **membership-only control** (prove spend authority,
**omit** key image from spent set) — a **subtraction** from today's verify path —
not a tag-producing ClaimLinkability / non-spending SAL sibling.

**Registration fusion:** eliminates the **on-chain registration tx**, not
registration. Before the first reward emission, `P` must be a known, serving,
backed archiver — **off-chain peer-presented backing** (otherwise peers won't
challenge or get spammed). First on-chain reward emission **anchors** bond +
claimed-epoch state; it does not replace prior peer-visible backing.

**Soft admission + intra-epoch window:** between settlement-epoch emissions (~14
days at default cadence), backing is not re-verified on-chain; `P` may spend
admission principal after a payout and serve **unbacked** until the next emission.
This is acceptable **only because the bond** enforces honesty in that window —
challenge failure slashes bond regardless of admission state. **Bond, not
stake-tree, is the maintained anchor.**

**Admission principal — gate 7 reopen:** dropping or softening the admission lock is
not a footnote ("monetary sink weakens") — it **re-prices** the V3 economy when
bond-locked supply becomes the **sole** locked-supply sink. Flag explicitly to
[`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) iteration 5 / gate 7 at the
same severity as per-reward aggregate sizing.

**Bond-funding firewall (residual):** bond is now `P`'s central collateral; lump
principal→`P` bond funding is a correlation channel — weigh **fund-from-earnings
ramp** vs lump initial bond in gate 6 / wallet hygiene.

**Round 3–4 close-conditions (ratify before Stage 3):**

| # | Condition | Disposition |
|---|-----------|-------------|
| (i) | Reward dedup = per-`P` claimed-epoch state on bond record; **no published tag** | **[`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md)** — Layer 1 **closed** at spec; implement blocked on [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) (contract **pinned**; gate 3 ν dissolved) |
| (ii) | Per-reward backing-proof aggregate at target `N_P` × settlement-epoch cadence | Sim gate — same severity as (iii) |
| (iii) | Admission-principal decision + **gate 7 locked-supply re-pricing** | Bonds-only vs soft MIN transfer; not "optional resilience" |

**Reward-emission spec:** [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) — Layer 1
closed (2026-06-07). **Archival read contract:** [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md)
**pinned** (gate 3 ν dissolved; `MAX_CLAIM_AGE_W` shape pinned). FSM retool (§3–§7)
**unblocked** in parallel. **Next:** implement schema + timing cluster codegen;
close (ii)–(iii).

### 2026-06-02 — confidential principal redesign (partial carry-over)

Superseded for **reward path**; retained for **principal machinery**:

1. **Staked principal is committed, not cleartext-public** — `C_stake` Pedersen +
   range proof (exact wire shape **open** under rebasing — §2.1 *Open: principal
   role*).
2. **Unstake is FCMP++ membership spend** — SAL key image `x·Hp(O)`; no stake↔unstake
   point-equality link (T11 resolved).
3. **No public `staked_output_index` / watermark** — membership + nullifiers.
4. **Wallet opening discipline** — `(amount, z)` re-derived, never sealed (§3.3.1),
   pending refinement if principal wire simplifies.

**Deleted with rebasing** (dead code, not adapted): confidential claim wire
(`txin_stake_claim_v2`, tier/`h_bind` reward path); entitlement stack
(reserve-DLEQ, bounded-remainder, `entitlement.rs`); tier machinery; exact-yield
from secret weight × public rate; `band` + `band_sum` servo on the reward path.
Claim-tag nullifiers (`N_{i,S} = x·G_S`, `G_arch` / `N_arch`) **do not** ship;
reward dedup is bond-record epoch bitmap (§2.4); `R_market` derived from retention
ledger (no wallet-minted ν).

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

Phase 2b owns the **wallet staking form** on the **transfer-shaped admission**
substrate (§2.4) — not the whole archival system, but **more than principal FSM
alone**: gate 6 (`P` lifecycle + firewall + off-chain backing) is unbuilt archival
crypto that **is** the staking identity surface (replaces
`is_active_staker(entity_id)`). Sort gates by whether they pin the staking form or
are archival-internal (interface only).

### 2.1 In scope

#### Carry-over — retain (crypto foundation + lifecycle)

| Piece | Role post-rebase (§2.4) |
|-------|-------------------------|
| Principal→`P` stake-in / `P`→principal unstake-out | Ordinary FCMP++ main-tree transfers; firewall = base privacy |
| Terminal unstake spend | Full SAL + `x·Hp(O)` **only** when draining `P`→principal (decorrelated, not lump sweep) |
| `P` HKDF sub-wallet | Independent keypair from seed; dual scan (principal + `P`) |
| FCMP++ membership + **membership-only control** on reward leg | Backing at emission; **no** key image; **no** published dedup tag |
| Per-`P` claimed-epoch bitmap on bond record | Reward double-claim dedup (`EpochSet` class, §3.3.2 — relocated to bond state) |
| `R_market` derived count | Ledger-derived at epoch close — **no** `ν` primitive (gate 3 dissolved) |
| Reorg / `pop_block` atomicity (§5.2 / §11) | Bond record + claimed-epoch bitmap revert with block |
| Adversarial method + firewall hygiene | Gate 6 — network / timing / output / **bond-funding** |
| `StakeState` FSM skeleton (§3 — **re-spec pending**) | Retool off claim-centric states |

#### Delete — dead code, not adapted

| Piece | Why gone |
|-------|----------|
| `txin_stake_claim_v2` + cleartext `txin_stake_claim` | No entitlement / cleartext claim reward path |
| `entitlement.rs` / `tiers.rs` / `rewards.rs` | Reserve-DLEQ superstructure |
| Decision **3C** staking subtree, `h_bind`, 5-scalar leaf | **Docs-only** — never ship for genesis (§2.4) |
| `txout_to_staked_key` cleartext stake outputs | Retire C++ legacy; genesis uses main-tree stealth |
| Staker-wide **tier** machinery | Per-shard retention **bonds** (gate 4) |
| F0 `{tier × creation}` substrate | Deleted with claim wire |
| `band` + `band_sum` on reward path | `Σwork` servo (gate 1) |
| `N_{i,S} = x·G_S`, `G_arch`, **`N_arch` published tag** | Reward dedup → bond-record epoch bitmap; no stake-keyed emission tag |
| On-chain **registration tx** as separate type | Fused into first reward emission + off-chain backing |
| ClaimLinkability / non-spending SAL **sibling** for reward | Membership-only control suffices when dedup is state-based |

#### Staking-form — 2b must ground (not defer)

| Item | Gate / anchor | Notes |
|------|---------------|-------|
| **Admission principal** | **Open — Round 4 + gate 7** | Soft MIN transfer to `P` vs bonds-only; **re-prices locked supply** — not optional |
| **Reward emission wire** | **[`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md)** | Membership-only backing + public work payload + mint; epoch dedup on bond record |
| **Off-chain backing presentation** | Gate 6 | Peers see backing before first on-chain emission |
| **Per-shard bond lifecycle + slash hook** | Gate 4 (**pinned**); intra-epoch honesty anchor | Slash independent of admission spend |
| **Reward receipt + unstake drain** | Gate 6 | Stealth outputs; **decorrelated** principal return |
| **Firewall hooks** | Gate 6 | Separate circuits; stake↔`P` timing decoupling; bond-funding hygiene |
| **Per-reward proof aggregate** | Sim (close-condition ii) | `N_P` × settlement-epoch cadence |
| `StakeEngine` + orchestrator API | Round 4 | stake-in / bond / emit-reward / drain / unstake |
| Threat model | §7 (after reward-emission spec) | Soft admission window explicit; bond-as-anchor |
| Stage 3 DoD | §10 | Blocked on §2.4 close-conditions |

**Discipline:** for each staking interface, ask whether **exactly one** archival-internal
decision is load-bearing on it; pull only that decision forward. Most plausible pinch:
**retention-proof shape (gate 2)** constraining what `P` commits to before first emission.

#### Identity (precise — not "P solves F0")

See status block. **F0 dissolved by model deletion.** **`P` + firewall** address
archival's public-holder problem. Budget **gate 6** as the unbuilt privacy work.

### 2.2 Out of scope (archival-internal — interface only)

2b **interfaces** to these; does not internalize construction/serving unless a row
in §2.1 *Staking-form* pulls it forward.

| Item | 2b needs | Owner |
|------|----------|-------|
| Set-B shard definition / challenge cadence | Slash-hook + first-emission commitment surface | Consensus + Stage 5 |
| Retention-proof construction | What failure triggers bond slash | Archival verifier; **may** bind off-chain backing statement |
| Transport (Tor/Arti, seed fast-fetch) | Firewall **hooks** only | Tier 4 / ops |
| Foundation floor sizing | Policy constant | Gate 5 / genesis workbook |
| `Σwork` servo + `R` counting/pricing internals | Wallet **receives reward**; does not compute `R` or mint counting tags | Gate 1 / economics upstream |
| `ArchivalEngine` query serving | Stage 5 | Registration backing still via `StakeEngine` at genesis |
| Multisig stake ceremony | V3.1 — FOLLOWUPS | |
| Subaddress indices in stake model | **Rejected** V3.0 (FA-1) | |
| Wallet RPC / CLI commands | Phase 3+ | |

**Explicitly out — do not implement on `dev`:** entitlement prove/verify; F0 bucketing
on the retired claim wire; extending `band_sum` reward servo in wallet code.

### 2.3 Upstream mirror (rebased genesis substrate)

Authoritative economics/identity spec:
[`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md) §*Pay-for-service rebasing*;
[`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) soundness pass + gate ledger.
Principal carry-forward pins still in [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md)
where not superseded below.

**Principal (§2.4 — admission wire open):**

- Stake-in: principal → **`P`** stealth outputs on **main tree** (ordinary FCMP++
  transfer); optional `≥ ADMISSION_MIN` economics-only lock — **not** consensus
  unspent enforcement.
- Unstake: `P` drains to principal via **decorrelated** FCMP++ spends (SAL key images
  at terminal leg only).

**Reward (rebased — replaces confidential claim model):**

- **One stream:** `reward_P = budget · work_P / Σwork` (gate 1); bonds at
  `ARCHIVAL_BOND_FLOOR` (gate 4 **pinned**).
- **Emission:** consensus-special leg — membership-only backing + public work +
  mint to `P` stealth output(s); **no** `txin_stake_claim`.
- **Dedup:** per-`P` claimed-epoch bitmap on **bond record** — not a published tag.
- **First emission:** on-chain anchor after **off-chain** peer-presented backing.
- **Inflation:** loud **8c** retention-proof unforgeability.

**Counting (unchanged):**

- `R_market` — derived ledger count; no `ν` primitive.

**Reorg:** bond record + claimed-epoch bitmap revert with `pop_block` (§11);
wallet §5 forward-rebuild adapts.

**Retired for genesis:** 3C subtree; §6.4 claim wire; `G_S` / `G_arch` / `N_arch`
emission tags; cleartext stake/claim C++ paths.

**Open before Stage 3:** archival consensus state schema; §2.4 **(ii)–(iii)**;
reward-emission **implementation** (after schema); `P` HKDF (gate 6); `Σwork` hook (gate 1).

### 2.4 Transfer-shaped admission (leading genesis form)

Authoritative staking **shape** for genesis. Full pin history: revision note
2026-06 above; adversarial decomposition in design session 2026-06.

#### Tx legs

| Leg | Tx shape | Consensus role |
|-----|----------|----------------|
| Stake-in | Ordinary FCMP++ transfer (principal → `P`) | Value move; privacy = base RingCT |
| join-Market / re-bond / unbond | `txin_archival_bond_post` (gate 4) | Join creates record; re-bond after slash; **Unbond** returns collateral after cooldown |
| Bond slash | Gate 4 consensus mutation | Involuntary unbond; `good_standing` interval log |
| Reward emission | **Special** — mint + membership-only backing + work payload | Paying claim only; record must exist; dedup on bond record |
| Reward sweep / principal return | Ordinary FCMP++ transfer (`P` → principal or fresh stealth) | Decorrelated drains — no lump correlation beacon |
| Terminal drain | Ordinary FCMP++ spend(s) draining `P`'s **non-escrowed** outputs | Decorrelated exit; **bond** returns via gate-4 `Unbond`, not drain |

#### Two irreducible special surfaces

Only **bond** and **reward emission** require consensus-marked state or mint
authorization. Stake-in and unstake-out are indistinguishable from normal transfers
on-chain.

#### Reward leg — crypto bill

1. **FCMP++ membership** against main-tree root at emission time.
2. **Membership-only control** — prove knowledge of spend secret **without**
   publishing `x·Hp(O)` (subtraction from `FcmpPlusPlus::verify` — gap today at
   `shekyl-oxide/.../fcmp/fcmp++/src/lib.rs`).
3. **Threshold proof** (optional) — controlled value `≥ ADMISSION_MIN` if admission
   principal retained for economics.
4. **No published dedup tag** — double-claim prevention is
   `bond.claimed_settlement_epochs.check_and_set(E)` on the consensus bond record
   (encoding: [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §6.3;
   FSM retool: [`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md) P2B-2/3).

**Not owed:** ClaimLinkability, `N_arch = x·G_arch`, or any stake-keyed emission
tag. **`R_market`** is ledger-derived (gate 3 dissolved).

#### Soft admission and the intra-epoch window

Backing is verified at **settlement-epoch cadence**, not every block. Between
emissions, `P` may spend admission principal; service may be **unbacked** for up to
~one epoch. **Load-bearing safety argument:** challenge failures slash **bond**
regardless of whether admission outputs remain unspent. Spec must state this
explicitly — it is why soft admission + bond is sound.

#### Registration without a registration tx

`P` must present backing to peers **before** serving (off-chain). **join-Market**
(`txin_archival_bond_post`) creates the on-chain bond record (holdings, empty dedup,
`E_join`) — **before** the first **paying** reward emission (§4.5 lag;
[`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md)). Fusion removes a discrete
*registration transaction type*; it does **not** remove the registration **event**.

#### §6.4.4 reopening (rule 21)

`CONFIDENTIAL_STAKING.md` §6.4.4 rejected "claim as ordinary FCMP spend + **re-stake
in same tx**." Reasons 1–3 were confidential-substrate (tier inherit, accrual window,
claim/unstake collapse). This shape does **not** re-stake in the claim tx; stake-in
and unstake-out are separate transfer legs. Reopening is valid. §6.4.5 discipline
(spend-authority binding, nullifier separation) holds: terminal unstake publishes key
image; reward leg does not.

#### Codebase pivot cost

| Asset | Disposition |
|-------|-------------|
| 3C / `h_bind` / 5-scalar leaf | Design docs only — delete from genesis plan |
| `entitlement.rs`, claim wire | Deletion target |
| `txout_to_staked_key`, `txin_stake_claim` (C++) | Retire — cleartext legacy |
| `FcmpPlusPlus::verify` membership-only branch | **Build** — smaller than ClaimLinkability sibling |

#### Round 3–4 ratification gates

See revision note 2026-06 — conditions (i) reward-emission spec with state dedup,
(ii) sim aggregate at `N_P` × cadence, (iii) admission principal + gate 7 re-pricing.

**Spec:** [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) + [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md).
Schema pin + (ii) sim + (iii) admission principal remain before Stage 3 emission code.

---

## 3. Archival `P` FSM (rebased — 2026-06-07)

**Authority:** [`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md) P2B-1–5;
[`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) (join-Market, custody, Unbond);
[`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) §9 (`P` keys).

**Deleted (claim era):** `StakeId` / `shekyl/stake-id-v1`; `Locked` / `Accruing` /
`Claimable` / `FullyUnstaked`; nullifier-derived `claimed_epochs`; tier-lock yield;
`OwnNullifierObserved` transitions. See P2B-0 diagnosis in the retool doc.

**Tx lifecycle vs P-state:** build → broadcast → confirm substates live on
`PendingTxEngine` for **spends** only. **Emission** and **bond-post** are non-spending
vins with their own confirm handlers. P-state moves on load-bearing confirms (join-Market,
drain, slash), not on every mempool observe.

### 3.1 States

Four **P-states** plus predicates and sub-conditions — not a ladder.

```rust
/// Wallet-observed archival instance lifecycle. Keyed by P_canonical_id (§3.3).
#[non_exhaustive]
pub enum ArchivalPState {
    /// HKDF-derived; no on-chain bond record yet (gate-6 §9.4).
    AdmissionPending,
    /// join-Market confirmed; serving (may hold reduced holdings after partial slash).
    Bonded,
    /// Terminal slash only: bonded_total == 0; out of Market until re-bond.
    /// Partial slash (one shard) stays Bonded — gate-4 §4.2.
    Slashed,
    /// Decorrelated drain confirmed; emit-backlog and/or bond cooldown may persist.
    Exited {
        /// Until release cooldown elapses — collateral not yet Unbond-able (gate-4 §4.3).
        collateral_in_cooldown: bool,
    },
}
```

| State | Defining predicate | Consensus footprint |
|-------|-------------------|---------------------|
| `AdmissionPending` | No `ArchivalBondRecord` | Gate-2 bits may exist but **don't count** (`P ∉ Market`) |
| `Bonded` | Record exists ∧ `bonded_total > 0` | Counted retention; `Σwork`; bond `== bond_floor`; **partial slash** shrinks holdings here |
| `Slashed` | Record exists ∧ `bonded_total == 0` | Terminal slash (last shard / CompleteTree); out of Market until re-bond |
| `Exited` | Drain confirmed | Record until terminal prune; backlog within `W`; bond cooldown |

**Not FSM states:**

| Concept | Treatment |
|---------|-----------|
| `good_standing` | Bond-record **predicate**; grace window stays `Bonded`, blocks emit-new; wallet surfaces **challenge pending, N blocks** (P2B-4 R4 / §7 G1a) |
| Partial slash | **Not a state** — `Bonded` with fewer shards; emit-backlog on honest pre-slash epochs (E-3) |
| "Joined, not yet paid" | `Bonded` with empty `claimed_settlement_epochs` |
| Emit / rotate / exit | **Actions** (§3.2), not states |
| Terminal retirement | Bond released ∧ backlog exhausted/lapsed → `p_slot` burn (new `P` = new slot) |

**`Exited` is not terminal until two independent completions:**

1. **Claim backlog** — pre-exit good epochs claimable within `W` (E-3).
2. **Collateral** — `Unbond` after release cooldown (**< `W`**); drain does not release bond.

### 3.2 Transition table and actions

#### P-state transitions (consensus-driven)

| From | Event | To |
|------|-------|-----|
| — | HKDF derive `P` (`master_seed_64` + `p_slot`) | `AdmissionPending` |
| `AdmissionPending` | **join-Market** confirm (`txin_archival_bond_post`) | `Bonded` |
| `Bonded` | **Partial** slash (shard dropped; `bonded_total > 0`) | `Bonded` (holdings reduced) |
| `Bonded` | **Terminal** slash (`bonded_total → 0`) | `Slashed` |
| `Slashed` | Re-bond confirm | `Bonded` |
| `Bonded` / `Slashed` | Decorrelated drain confirm | `Exited { collateral_in_cooldown: true }` |
| `Exited` | Release cooldown elapsed + **Unbond** confirm | `Exited { collateral_in_cooldown: false }` |
| `Exited` | Bond released ∧ backlog done/lapsed | Terminal (`p_slot` retired) |
| `Bonded` | Reorg disconnects **join-Market** block | `AdmissionPending` |
| `*` | Other reorg | Re-fetch bond record → prior state (§3.4) |

**Re-entry:** `Exited` → **new `p_slot` / new `P`** only (R2) — never revive old id.

#### Actions (tx types — not P-state)

| Action | P-states | On-chain / notes |
|--------|----------|------------------|
| Fund admission | `AdmissionPending` | Ordinary FCMP++ → `P` |
| **join-Market** | `AdmissionPending` | `txin_archival_bond_post` JoinMarket; `E_join` stamped |
| Emit (paying) | `Bonded` / `Slashed` / `Exited` | `txin_archival_reward_emission`; batch ≤ 15 epochs |
| Rotate backing | `Bonded` | Membership-only; `backing_outputs` update; same `P_canonical_id` |
| Exit / drain | `Bonded` / `Slashed` | `P`→principal; **non-bond** outputs only |
| **Unbond** | `Exited` (post-cooldown) | `txin_archival_bond_post` Unbond; `bond_debit` refund |
| Re-bond | `Slashed` | `txin_archival_bond_post` Rebond |

**Emit rules:**

- **Emit-new:** `Bonded` ∧ `good_standing` — earliest epoch `E_join + 1` (gate-4 §2.2).
- **Emit-backlog:** `Bonded` / `Slashed` / `Exited` ∧ `good_through(E)` ∧ dedup ∧ `W`.

**join-Market vs first paying mint:** separate events (lag-forced). Rows 1–4 of bond
presence (bond, gate-2 bits, Market, slash) fire at join; dedup + first mint at first
paying emission. See [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §1.

### 3.3 `ArchivalPInstance` — identity and fields

**Primary key:** `P_canonical_id` — same 32-byte id as consensus `ArchivalBondRecord`
(emission §6.1; gate-6 §9.5). **Not** output-derived `StakeId`.

```rust
/// cSHAKE256(cust = "shekyl/archival-p-id-v1", input = hybrid_sign_pk.canonical_bytes())
pub struct PCanonicalId(pub [u8; 32]);

pub struct ArchivalPInstance {
    pub p_canonical_id: PCanonicalId,   // primary key; wallet + consensus agree
    pub p_slot: u32,                    // HKDF rotation index (gate-6 §9.2); persisted
    pub state: ArchivalPState,
    pub holdings: HoldingsDescriptor,   // shard set served
    /// Stable bond-record reference (consensus-owned fields read via RPC).
    pub bond_ref: BondRecordRef,
    /// Rotatable admission / membership outputs on main tree (E-4 hygiene).
    pub backing_outputs: Vec<OutputRef>,
    /// Cache of bond.claimed_settlement_epochs — **not authoritative** (P2B-2).
    pub claimed_epochs_cache: ClaimedEpochSetView,
    /// Runtime-only: epochs with emission vin in flight (§3.4).
    pub emission_pending_epochs: BTreeSet<u64>,
    // ArchivalPKeys (spend/view/kem/hybrid) — re-derived from master_seed_64 + p_slot;
    // never persisted at rest (gate-6 §9.4).
}
```

**Bond vs backing (never conflate):**

| Object | Role | Rotates? |
|--------|------|----------|
| **Bond** | Consensus balance `bonded_total_atomic`; slash collateral | No — same record until terminal |
| **Backing** | Membership-only proof inputs at emission | Yes — `backing_outputs` update |

**`P` pseudonym rotation** (`p_slot` increment) creates a **new** `P_canonical_id` and new
instance — distinct from backing rotation on the same `P`.

#### `P_canonical_id` derivation (replaces §3.3.3 `StakeId`)

```text
p_canonical_id = cSHAKE256(
  customization = "shekyl/archival-p-id-v1",
  input         = HybridPublicKey::to_canonical_bytes()   // scheme_id = 1
)[0..32]
```

Wallet-internal KAT required; `v1` bump = migration (`rm -rf ~/.shekyl` pre-genesis).

#### `ClaimedEpochSet` (replaces §3.3.2 `EpochSet`)

Absolute sparse settlement-epoch indices on the bond record (emission §6.3). Wallet holds a
**cache** refreshed after emission confirm and reorg — **not** rebuilt from nullifiers.
Encoding deferred until `W` pinned ([`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md)).

### 3.4 Pending emission and reorg (replaces claim-era §3.4 / §5.2)

**Pending emission (Hybrid-B analogue).** `txin_archival_reward_emission` is **non-spending**.
`PendingTxEngine` stays spend-pure. The stake actor holds **`emission_pending_epochs`**
(runtime-only): add epochs on emission broadcast; clear on confirm, discard, or reorg-before-confirm.
Consensus dedup on `bond.claimed_settlement_epochs` is the backstop — duplicate epoch → reject.

**Reorg (P2B-5 — largely closed).** No nullifier replay. On reorg notification:

1. **Re-fetch** `ArchivalBondRecord` per live `P_canonical_id` (daemon RPC).
2. Refresh `claimed_epochs_cache` from consensus state.
3. Clear `emission_pending_epochs` for disconnected heights.
4. `Bonded` → `AdmissionPending` **only** when join-Market block at `join_market_height` is
   disconnected (gate-4 §5).

Consensus: per-block `pop_block` is **all-types-atomic** (bond credit/debit,
`total_bonded_atomic`, record mutations, retention bits, FCMP outputs). Cross-block join
cascade via archival state §6 ordered pop (tip → `H`).

---

### 3.A Archived claim-era §3 reference (do not implement)

The following subsections were **deleted** from the rebased FSM and remain in git history
only: `StakeOpening` persistence debate (§3.3.1), `EpochSet` u16 mask (§3.3.2),
`StakeId` / `shekyl/stake-id-v1` (§3.3.3), nullifier `claim_pending_epochs` (§3.4).
Disposition: [`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md) P2B-0–P2B-2. Full text:
`git show dev:docs/design/PHASE_2B_STAKE_LIFECYCLE.md` (pre-§3 retool).

---

<!-- SECTION_4_CLAIM_ERA: §4–§7 below are claim-era until retool pass P2B-3+ -->

## 4. Persistence and engine ownership — **claim-era (pending retool)**

**Status:** Tables and §4.2–§4.7 still describe `StakeInstance`, sealed `claimed_epochs`,
and nullifier reconciliation. Archival target: `ArchivalPInstance` keyed by `P_canonical_id`;
consensus-owned `claimed_settlement_epochs` cache only; see §3 and
[`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md) P2B-2–P2B-3.

### 4.1 What lives where (architectural pin) — claim-era snapshot

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
broad wiring (see [`docs/completed/ATOMIC_UNITS_NEWTYPE.md`](../completed/ATOMIC_UNITS_NEWTYPE.md)).

**Claim batching / timing (privacy):** claiming the **full unclaimed window** in one tx
(`MAX_EPOCHS_PER_CLAIM` permitting) is the **production default** — it removes the
partial-timing tell, tightens [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §6.2,
and reduces **per-stake claim-sequence** correlation (tier + contiguous epoch windows
accumulate across drip claims). `MAX_EPOCHS_PER_CLAIM = 1` is test-mode only. If a
backlog requires multiple txs, avoid fixed epoch-boundary broadcast cadence; Dandelion++
/jitter is the network-layer mitigation (§7).

---

## 7. Threat model (archival re-center — P2B-6)

**Status:** **Landed (2026-06-07).** Replaces claim-era Round 3 wargame (§7.A archive).
Authority: [`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md) P2B-6;
[`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md); [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md)
§4.5; [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md);
[`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md).

### 7.1 Substrate change — what moved

| Retired with claim wire | Rebased threat focus |
|-------------------------|----------------------|
| F0 `{tier × creation}` cohort on confidential claim | **Deleted** — model removal, not mitigation |
| Nullifier dedup / `N_S = x·G_S` / DDH claim↔unstake split | **Deleted** — consensus `claimed_settlement_epochs` on bond record |
| `h_bind` + entitlement 8a / tier-forgery 8b | **Deleted** — loud emission amounts + work vector |
| `StakeOpening` / sealed `claimed_epochs` reorg replay | **Deleted** — P2B-5 re-fetch bond record |
| Band cohort / `ρ_e` × secret weight yield | **Deleted** — `Σwork` servo + per-shard bonds |

**Carried forward (reframed):** priority-1 silent inflation (emission + bond_credit/debit
conservation); priority-2 firewall discipline (`P`↔principal correlation); A1/A3/A5 economic
actors with archival semantics; wider-substrate audit habit.

### 7.2 Identity framing (do not collapse)

Three mechanisms — same as §0 status block; do not shorthand as "P solves privacy."

1. **F0 dissolved** — confidential claim wire not shipped.
2. **`P` is public by function** — firewalled pseudonymity, not claim-style anonymity.
3. **Gate 6 is the unbuilt privacy work** — `P`↔principal correlation + cross-pseudonym
   intersection. Bonds carry Sybil cost; multi-`P` is hygiene.

### 7.3 Adversary models

| ID | Model | Archival instantiation |
|----|-------|------------------------|
| **A1** | Adversary-controlled daemon | Stale/wrong bond record, `Σwork`, `R_market`; withholds join-Market confirm |
| **A2** | Passive chain / network analyst | Correlates `P_id` retention timeline, emission cadence, bond events, drain/Unbond |
| **A3** | Memory-disclosure | `master_seed_64`, HKDF `P` keys, emission build state, prover bundles |
| **A4** | A1 + A2 collusion | Timing oracle on emission/drain + public `P` timeline |
| **A5** | Rational economic actor | Slash-evasion, bond floor gaming, workload split, lapse/forfeit arbitrage |
| **A6** | Archival peer / challenger | Grief challenges, false retention disputes, reachability probing |

### 7.4 Seed threat table

| Threat | Mitigation pin |
|--------|----------------|
| **F1 — gate-3 holdings publicity through rotation** | Form-C holdings consensus-public. T-A1: portfolio ≈ identity at lean eq; lifetime `T_obs`. **Provisionally accepted; finally accepted iff T-A3–T-A7 pass.** |
| **A6 — challenge grief** | T-A16; `CHALLENGE_RESOLUTION_BLOCKS` + L16 + consensus-witnessed delivery |
| **`P`↔principal correlation** | Gate 6 four layers + bond-funding; Tor/onion (L16); decorrelated drains |
| **Cross-pseudonym intersection** | Per-`P` path, emission batching, rotation; bonds do not make multi-`P` free |
| **Emission timing tell** | Batch ≤ `MAX_SETTLEMENT_EPOCHS_PER_EMISSION`; wallet jitter / Dandelion++ (open) |
| **Bond-funding correlation** | Admission transfers must not become standing linkage (gate 6 §2.5) |
| **Unbond refund linkage** | Loud `bond_floor` refund — same decorrelation as rewards (gate 6 §2.4) |
| **Silent inflation (emission)** | Loud vin; verifier recomputes `reward_P(E)`; wallet G11-E1 |
| **Silent inflation (bond)** | `bond_credit`/`bond_debit` in RCT balance equation; conservation law; G11-E2/E3 |
| **Double emission** | `claimed_settlement_epochs` on bond record (P2B-2) |
| **Work forgery** | Gate 2 retention proofs + `good_through(E)` |
| **Daemon misreports economics** | Wallet recomputes from public state + own `P` keys |
| **Reorg desync** | Re-fetch bond record; P2B-5; join-Market disconnect → `AdmissionPending` |
| **Memory exposure of `P` keys** | Session-only; never persist `P` secrets (gate-6 §9.4) |
| **Slash rewriting history** | Slash mutates bond only; no rewrite of past `R_market`/`Σwork` (E-3) |
| **Over-bond fingerprint** | `bonded_total == bond_floor(holdings)` (not `≥`) |
| **Join-Market lag bypass** | First mint cannot bundle with join (gate-4 §1) |

### 7.5 Threat-exhaustion agenda (T-A items)

Each item: **mitigated-in-design** / **FOLLOWUP** / **cross-track** / **priority-reject**
/ **gated-on-sim** before Stage 3.

| ID | Vector | Disposition summary |
|----|--------|---------------------|
| **T-A1** | **F1 instrument** | **CLOSED** — [`F1_TA3_TA7_LIFETIME_WINDOW.md`](F1_TA3_TA7_LIFETIME_WINDOW.md) §1 |
| **T-A2** | Cosmetic `P` rotation (E-4) | Portfolio re-link; timeline irrelevant (T-A1) |
| **T-A3** | Firewall — network path | **PASS (qual)** — L16 onion; §9.1 |
| **T-A4** | Firewall — timing | **PASS (consensus leg)** — cluster pinned; wallet defaults gate-6 R3–4 |
| **T-A5** | Firewall — output graph | **PASS (qual)** — decorrelated drains; §9.3 |
| **T-A6** | Firewall — bond funding | **CONDITIONAL** — fund-from-earnings ramp; Round 4 pin |
| **T-A7** | Cross-pseudonym intersection | **PASS (qual)** — per-`P` hygiene default; §9.5 |
| **T-A8** | Silent inflation — emission | Mitigated-in-design + G11-E1 KAT |
| **T-A9** | Silent inflation — bond | Mitigated-in-design + G11-E2/E3 KAT |
| **T-A10** | Dedup / double-emit | Mitigated-in-design (§3.4 pending + consensus) |
| **T-A11** | Reorg | Mitigated-in-design (P2B-5) |
| **T-A12** | Daemon lie — bond record | Mitigated-in-design — refuse emit build |
| **T-A13** | Memory — `P` keys | Open — HW path (G8) |
| **T-A14** | Economic — slash / lapse | Open — UX trade explicit |
| **T-A15** | Bond floor gaming | Mitigated-in-design (G4-7) |
| **T-A15b** | HoldingsUpdate slash evasion | Open — cooldown on dropped shard |
| **T-A16** | A6 challenge grief | Open — bounded rate + resolution window |
| **T-A17** | Join-Market censorship | Open — lowest priority |

**Retired (genesis path N/A):** T1–T4, T7, T14 (claim/DDH); T6 → T-A11; T8 → T-A8/T-A9;
T9 (fake `StakeEvent`) superseded.

### 7.6 Wider-substrate audit (G-items)

| ID | Disposition |
|----|-------------|
| **G1** | Three-tier surfacing: (a) pre-slash grace warning, (b) partial slash stays `Bonded`, (c) terminal slash → `Slashed` |
| **G2** | N/A — not delegated PoS |
| **G3** | Reframed — bond + release cooldown + `W` backlog surfacing |
| **G4** | Warn on uneconomic emission fee |
| **G5** | `emission_pending_epochs` runtime-only + consensus dedup |
| **G6** | FOLLOWUP — mempool staleness primitive |
| **G7** | Mitigated — P2B-5 re-fetch |
| **G8** | OPEN — HW-wallet `P` sign path |
| **G9** | FOLLOWUP — locked wallet during emit |
| **G10** | Priority-reject fee-bump for emission |
| **G11** | Extended — conservation law + G11-E1/E2/E3 wallet KATs; full vs light client split (G12) |
| **G12** | Split by client mode — see draft G11 §8.2 |
| **G13** | FOLLOWUP V3.1+ GUI fingerprint |

Historical analogs: Zcash 2018 / Monero 2017 inflation → G11; wallet2 fingerprint → G13.

### 7.7 F1 — gate-3 holdings publicity through rotation

Archival state publishes settlement-epoch-resolution retention bits for `Σwork` and **per-`P`
holdings** (Form C, gate-3). **Not F0** (no confidential claim). **Not hide retention or
holdings** (consensus-public by construction).

T-A1/T-A2 ([`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) §*T-A1 / T-A2*): at lean
equilibrium, scarcity pricing spreads archivers across under-replicated deep shards → **unique
portfolios** (~98% singleton). Timeline channel is empty (homogeneous serving); **portfolio =
public identity** across rotation when storage is preserved. The reward mechanism
disincentivizes the only decorrelating move (re-storing a different shard-set).

**Observation window (load-bearing):** rotation does **not** bound `P`↔principal correlation
for fixed-portfolio operators. Effective `T_obs` = operator archival **lifetime**. T-A3–T-A7
must be run under that premise ([`F1_TA3_TA7_LIFETIME_WINDOW.md`](F1_TA3_TA7_LIFETIME_WINDOW.md)).

**Disposition:** provisionally accepted + honest residual disclosed. **Conditionally finally
accepted** (2026-06-07): T-A3/T-A5/T-A7 pass qualitatively under lifetime `T_obs` + wallet
defaults; T-A4/T-A6 conditional on timing-cluster + funding-ramp pins. Form-C reopen **not
triggered**. Full final accept when pins land — [`F1_TA3_TA7_LIFETIME_WINDOW.md`](F1_TA3_TA7_LIFETIME_WINDOW.md) §9.

### 7.8 G11 — inflation and conservation

**Conservation law (consensus):**

```text
already_generated_coins == circulating + bonded + burned
```

Bond events move circulating ↔ bonded; slash bonded → burned; emission mint increases
circulating via `already_generated`. Audit: `total_bonded_atomic == Σ_P bonded_total_atomic`.

**Wallet preview invariants (KAT-backed):**

| ID | Invariant |
|----|-----------|
| **G11-E1** | `loud_vin_total == Σ recomputed reward_P(E)` for eligible epochs |
| **G11-E2** | Bond-post: `bond_credit == bond_floor(holdings)` or Unbond debit matches |
| **G11-E3** | Per-tx conservation neutrality in preview |

Full node: strong recompute from validated state. Light client: warn + refuse on inconsistency;
consensus is backstop.

Retired 8a/8b (entitlement wire) — §7.A only.

### 7.9 Diagnostic RPC projection (rebase of old §7.3)

**Secret class:** no `P` spend/view/KEM; no principal spend secrets.
**Correlation class:** no field joining principal graph to `P_id` in one query.

Owner `ArchivalPView` may show grace-window pending slash, partial-slash holdings — owner-only.
Lens-3: global totals + coarse counts; no per-`P` retention export amplifying chain-public bits.

### 7.10 Dispositions summary

| Tier | Items |
|------|-------|
| **Closed in design** | Join-Market lag; dedup; conservation; `== bond_floor`; slash no history rewrite; P2B-5 |
| **Conditionally finally accepted** | **F1** — qual wargame §9.8; full accept on T-A4 + Round 3–4 pins |
| **Closed** | **T-A1/T-A2** instrument; **T-A3/T-A5/T-A7** qual pass |
| **Conditional pass** | **T-A6** (funding ramp pin); T-A4 wallet defaults (gate-6 R3–4) |
| **Mitigated pending pin** | Firewall wallet defaults (gate-6 Round 3–4); T-A16 bounds |
| **OPEN wargame** | T-A15b, T-A16, G8 |
| **FOLLOWUP** | G6, G9, G13 |
| **Priority-reject** | G10 |

### 7.11 FSM rebase + LMDB substrate verification (2026-06-07)

**FSM:** subtraction rebase — four states, consensus balance, no claim nullifiers. Structural
discovery: join-Market distinct from first mint (R1).

**LMDB on `dev` — VERIFIED (integration pattern clean; bond wire greenfield):**

| Mechanism | `dev` location | Status |
|-----------|----------------|--------|
| `already_generated_coins` | Per-height `block_info.bi_coins`; `get_block_reward` on connect; capped `MONEY_SUPPLY` | **Exists** |
| `total_burned` | `m_properties` `"total_burned"`; incremented on connect from `burn.actually_destroyed` | **Exists** — slash sink precedent |
| `staker_pool_balance` | `m_properties` `"staker_pool_balance"`; connect increment / `pop_block` revert via `staker_accrual` | **Exists** — **precedent for `total_bonded_atomic`** |
| `total_bonded_atomic`, `bond_credit`/`bond_debit`, `ArchivalBondRecord` table | — | **Not wired** — implementation per gate-4 |
| Claim-era `m_staker_accrual` / `m_staker_claims` | LMDB integer-key tables | **Deletion target** at archival cutover |

**Conservation integration:** `get_block_reward` / miner subsidy path uses `already_generated`
only — archival `bond_credit` stays below mint bar (gate-4 §4.5), no collision with subsidy
accounting. `pop_block` already reverts `total_burned` and `staker_pool_balance` from per-height
accrual records — archival bond deltas should follow the same per-block audit + revert shape.

Pre-genesis: no migration from `main`; claim-era pool balance is deleted with entitlement wire,
not carried forward.

**Remaining risk:** (1) gate-6 Round 3–4 wallet defaults (T-A4/T-A6 non-consensus leg); (2) gate-2 slash
trigger / T-A16 on 8c.

### 7.A — Archive pointer (claim-era wargame)

The 2026-06-05 Round 3 wargame (old §7.4–§7.5.3) executed against the **confidential
entitlement claim wire**. Historical record for F0, T8 8a/8b, DDH/nullifier/`StakeOpening` rows.

**Do not implement** F0 bucketing, `txin_stake_claim_v2`, or claim nullifier dedup on genesis.
Full text: git history pre-P2B-6 land; summary retained in [`PHASE_2B_SECTION7_DRAFT.md`](PHASE_2B_SECTION7_DRAFT.md).

---
## 8. Forward actions and reversion clauses

### 8.0 Genesis substrate dependency (Stage 3 merge gate)

**Stage 3 merge to `dev` is blocked** until this document's **Round 3** closes on the
**rebased substrate** (F-ARCHIVAL gate-list ratified; Tier 1 soundness pass step 3
specified) and Rounds 4–5 complete per §9.

**Ship target (one substrate, pre-genesis):**

| Layer | Genesis disposition | Deletion / never-ship |
|-------|---------------------|----------------------|
| Principal lock + `C_stake` | Retain from confidential principal redesign | Cleartext `staked_output_index`, watermark |
| Unstake / spend | FCMP++ membership path (§7.5.1 T11 resolved) | — |
| Reward identity | Firewalled **`P`** + membership backing | Public `entity_id` lookup |
| Reward economics | `Σwork` servo, per-shard bonds, loud 8c retention | Reserve-DLEQ entitlement, `tier_num` claim wire |
| Wallet secrets | §3.3.1 `(amount, z)` re-derived, never sealed | Sealed opening region |

**Do not implement** `txin_stake_claim_v2` entitlement claims, `entitlement.rs` prove
paths, or F0 bucketing as Stage 3 work — that is the **retired** confidential-yield
subsystem. Existing `shekyl-staking` entitlement code is **exploratory / deletion
target** until rebased reward modules replace it.

**Upstream carry-forward:** principal commitment + range proof pins from
[`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §14 (servo history, `ρ_cap`
where still load-bearing on non-reward surfaces). **Upstream superseded for genesis
reward path:** §6.4 **(A)** entitlement + **(C)** claim `h_bind` tier multiplier wire.

**The reorg/`pop_block` nullifier-set revert** applies to **whatever nullifier set
the rebased payout path uses** (claim epochs on the retired wire; challenge/retention
state under `P` on the rebased wire). Wallet §5 forward-rebuild discipline carries
forward; exact fields are a Round 4 pin on the rebased wire.

**Parallel work allowed (design + isolated spikes):** Rounds 4–6, trait sketches,
FSM tests against mocks, opening re-derivation spikes (§4.2), archival Tier 1 crypto
spec — provided spikes do not land the **entitlement claim path** on `dev`. Wallet
Stage 3 lands after **Round 3–5 closure on the rebased substrate**.

**Reopen/track:** rebased reward/challenge wire (replaces byte-exact entitlement
claim wire); `P`/`G_arch` KATs; [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md)
soundness pass step 3. Economics
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

**Stage-3 grep-retire / delete enumeration** (the code action; `pool_weighted_total`
design pin complete — code lands with Stage 3 on the rebased substrate; add
`entitlement.rs` / claim-wire paths to the delete list per §8.0):

- `rust/.../traits/economics.rs` — remove `fn pool_weighted_total(&self) -> u128;` + rustdoc.
- `rust/.../local_economics.rs` — remove the impl (`:166`) + module-doc bullet (`:21`).
- `rust/.../economics_differential.rs` — drop the `pool_weighted_total` round-trip assertion
  (`:154-159`) + module-doc bullet (`:19`).
- `rust/.../chain_economics_source.rs` — retarget `active_weighted_stake` from "feeds
  `pool_weighted_total()`" to "feeds `rate_at_epoch`'s `ρ_e` derivation"; update the
  `:11/:33/:42/:86` doc references.
- `rust/.../mod.rs` (`:521`), `lifecycle.rs` (`:750`) — update the `pool_weighted_total`
  shared-state comments to `rate_at_epoch`.
- `rust/shekyl-staking/src/entitlement*` — **delete or replace** with rebased `P`/`Σwork`
  reward modules; do not extend for genesis (§8.0).

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
| **3** | **Wargame executed (2026-06-05); transfer-shaped form elevated (2026-06)** | §7 wargame + §7.5.3 (F0 **dissolved**). **§2.4 leading genesis shape.** **Open for Round 3–4 ratification:** §2.4 close-conditions (i) reward-emission spec + state dedup, (ii) per-reward aggregate sim, (iii) admission principal + **gate 7** re-pricing; gate 6 soundness; Tier 1 step 3. **Next spec:** reward-emission leg. Retool: §2.4 → reward wire → gate 6 → §3–§7. **Not genesis:** F0 bucketing, 8a, 3C subtree, `entitlement.rs`. |
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
- [x] User method signatures signed off (§6). **Batch landed (2026-06-05):** owner-grade `StakeView` pinned (per-stake `claimable` + `claimed_epochs` + `unlock_height`) with the owner-grade caveat and a **distinct** lens-3 redaction that names `claimable`/`claimed_epochs` as the **derived-value** class the secret-class redaction does not cover (Fork A); `StakeFilter` made **total 1:1 over `StakeState`** + `All` sentinel (item 5); abandon-claim discard wiring keyed on an **orchestrator-held** `ReservationId → (stake_id, epochs)` map — `PendingTx` carries no claim discriminator (verified at source, stays spend-pure; item 3); pre-stake projection omission documented (item 4); FA-1 regrounded to single-static-address + independent-accounts reopen-pointer (Fork B); stale §3.3 opening doc-comment fixed (item 1). **`AtomicUnits` landed (2026-06-05):** §6 `claimable` / `claimable_rewards` + `StakeOpening.amount` carry the `AtomicUnits` domain newtype from `shekyl-units` (interim PR before broad wiring; see [`ATOMIC_UNITS_NEWTYPE.md`](../completed/ATOMIC_UNITS_NEWTYPE.md)). The §6 method set and amount type are both signed off.
- [x] `StakeEngine` message protocol signed off (§4.7), incl. sealed transport + `PrepareClaimBuild` (R0-D3, R0-D4) — **D1–D4 pinned (2026-06-04):** reorg folded onto `ApplyStakeEvents { reorg_rewind }` (no `RewindTo`; rewind-first, one uninterruptible turn); clear-all/replay-all full-surviving-set, heights in scanner; `claim_pending_epochs` lifecycle = `PrepareClaimBuild` side-effect + `AbandonClaim` (claim_pending only, never claimed); `Snapshot` excludes `claim_pending_epochs`, `Restore` starts it empty
- [x] **`StakeOpening` excludes `x`** (§3.3.1 / §8.8, R0-D8)
- [x] **`G_S` + claim linkability + `MAX_EPOCHS_PER_CLAIM`** pinned with **(B)** (§8.5 / upstream §6.4.2)
- [x] **Tier/window / multiplier integrity** — upstream **(C)** closed on **3C** (staking subtree + `h_bind`, window arithmetic); **(A)** reserve-DLEQ + bounded remainder; impl Round 2
- [x] `EconomicsEngine::rate_at_epoch` + boundaries doc amendment (§8.6) **— finalized (2026-06-05).** Seven pins: rate-epoch *index* (not height); returns public `ρ_e` as fixed-point `u64` (a rate, not `AtomicUnits`; consensus-defined scale); fallible with `Ok(0)`≠`Err` (un-overloads `pool_weighted_total`'s `0`); consensus-derived from on-chain `band_sum`, not wallet-recomputed; the `AtomicUnits` crossing is the yield product `own_weight·K_S`; no per-stake state (§8.2). **`pool_weighted_total` retired (delete, not renarrate — rule 15):** its sole named consumer (`projected_yield`'s pool denominator) was eliminated by the confidential redesign, verified at source in *both* the trait rustdoc and `V3_ENGINE_TRAIT_BOUNDARIES.md`; reopen-criterion is rule-21-shaped. Boundaries doc amended across all 7 sites (§2.7 Ownership, method sketch, consumer narrative, discipline-test example, three classification tables) — framed "retired pending Stage-3 code removal." Code removal + `active_weighted_stake` repurposing enumerated in §8.6 for Stage 3.
- [x] **Upstream consensus Round 1 closed** (§8.0; [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §14)
- [x] **Round 3 agenda pre-staged (2026-06-05, §7.4):** adversary models A1–A4; threat-exhaustion agenda T1–T9; wider-substrate audit seed G1–G10 (Principle 6). All items `OPEN` — pre-stage sets the surface, does not close it (Principle 5).
- [x] **Round 3 wargaming executed (2026-06-05, §7.5):** every §7.4 T1–T9 + G1–G10 item driven to a disposition, **plus** privacy-crypto-survey additions T10–T14 / G11–G13 (Zcash shielded-set + counterfeiting, Monero burning-bug / malicious-remote-node / temporal-analysis / wallet2-fingerprint, MimbleWimble graph-reconstruction, Janus). Each disposition is mitigated / FOLLOWUP+trigger / cross-track / priority-reject per rule 21. Residuals (§7.5.2): 7 FOLLOWUPS (V3.1), 2 cross-track asks (T3, T10; **T11 resolved at source**), 5 Stage-3 pins, 1 priority-reject (G10), 3 N/A.
- [x] **First clean close recorded in §9 (2026-06-05).** The candidate gating finding — **T11** (stake↔unstake commitment re-randomization) — was investigated and **resolved at source** (§7.5.1 #2: unstake is an unlinkable FCMP++ membership spend appending a fresh output; the literal `C_stake` is never re-published — no point-equality link, no Priority-2 finding).
- [x] **Dual-wargamer synthesis executed (2026-06-05, §7.5.3).** Confirmed/sharpened the §7.5 dispositions, added adversary **A5** (economic/rational), split inflation **T8 → 8a entitlement-soundness + 8b band-declaration binding**, and surfaced **top finding F0** (the claim anonymity set is the `{tier × creation-window}` cohort — confirmed at source).
- [x] **F0 reveal-vs-ZK resolved at source (2026-06-05, §7.5.3 / §6.4).** `tier` (u8) and `creation_height` (u64) are **cleartext public wire fields** (`CONFIDENTIAL_STAKING.md` §6.4.8); the verifier recomputes `h_bind` and the multiplier from them (§6.4.3). Revealed-by-design and **load-bearing for inflation-safety** (single revealed `tier` excludes tier-forgery; the 3C-over-3A "no new primitive" win) — hiding them re-opens 3C-vs-3A, so L4 is V4 co-design, not a v1 bolt-on. Claim↔claim linkage is therefore **deterministic exact-match**, cohort `→ 1` at cold start.
- [x] **F0 baseline-budget calibration (2026-06-05, §7.5.3).** Priced F0 against the staking-exposure budget the project accepted *before* confidential staking: F0 is the **same category** of cost (staking is the exposed overlay; spend path untouched; core promise intact), exceeding baseline only in **scale-resistance** (block-granular `{tier × exact-height}` cohort does not dilute with growth — a steady-state, not just cold-start, thinness) and **targeted-cascade**. Marginal delta over the realistic already-linkable counterfactual (timing/fingerprint/circuit-reuse) is "exact-vs-statistical" + the creation-anchor — **most penalizing the privacy-conscious staker**. **De-escalates the decision.**
- [ ] **Round 3–4 design closure — transfer-shaped substrate (2026-06).** Close on: **(1)** F-ARCHIVAL gate-list ratified; **(2)** §2.4 close-conditions (i)–(iii) — reward-emission spec (state dedup, no published tag), per-reward aggregate sim, admission principal + gate 7 re-pricing; **(3)** Tier 1 soundness step 3; **(4)** entitlement / 3C / F0 bucketing explicitly **not** genesis. **Next:** reward-emission leg spec. Stage 3 gated on closure + Rounds 4–5.

### 10.2 Stage 3 implementation (after closure — separate PR(s))

- [ ] `StakeEngine` + `StakeEngineHandle` + `StakeActor` (`kameo`), fail-stop, re-derived (never-sealed) openings
- [ ] FSM transition tests in isolation (incl. reorg rebuild on rebased payout state)
- [ ] `StakeEvent` + archival challenge events wired through refresh → ledger → stake actor
- [ ] **`P` lifecycle** — HKDF sub-wallet; off-chain backing; reward emission (membership-only control); bond-record epoch dedup; firewall + bond-funding hygiene
- [ ] Reward computation from **public `P` work history** + `Σwork` servo (not entitlement / `tier_num`)
- [ ] `is_active_staker` via bond good-standing + work record (not public `entity_id`)
- [ ] Cross-engine ordering per §5.3
- [ ] **Do not land** reserve-DLEQ entitlement prove/verify or `txin_stake_claim_v2` tier claim wire

---

## 11. References

| Doc | Use |
|-----|-----|
| [`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md) | **Genesis reward substrate** — pay-for-service rebasing, `P`, per-shard bonds, `Σwork` servo |
| [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) | Economics sim + soundness pass (Tier 1 gate) |
| [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) | Principal lock / `C_stake` / unstake membership carry-forward; **§6.4 (A) entitlement claim wire retired** for genesis |
| [`STAKER_REWARD_DISBURSEMENT.md`](../STAKER_REWARD_DISBURSEMENT.md) | **Superseded** — history only |
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
