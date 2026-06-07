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
retain** — but §3–§7 body text below §2 is still **claim-centric** until retooled;
§2 is authoritative for rebased scope. No Stage 3 until **Round 3 closes on the
rebased substrate** (gate-list + gate 6 to soundness depth) per
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

**§2 is the authoritative scope statement** for genesis. §3–§7 below are still
written against the **intermediate confidential-claim model** (2026-06-02 principal
redesign + entitlement superstructure). Retool order: **§2 + §2.3 first** (this
pass), then **gate 6 (`P` registration + firewall)** — fixes secret material and
threat model everything downstream depends on — then §3 FSM, §7 threat model, §4–§6
protocol. **Gate-6 design doc:** [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md)
(Round 1 draft — §9 `P` hybrid derivation pinned 2026-06-07).

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
**unblocked** in parallel. **Next:** implement schema + pin numeric `W` / `REORG_HORIZON`;
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
| Bond post / slash | Gate 4 consensus object | **Maintained anchor** — slashable collateral |
| Reward emission | **Special** — mint + membership-only backing + work payload | Authorize payout; epoch dedup on bond record |
| Reward sweep / principal return | Ordinary FCMP++ transfer (`P` → principal or fresh stealth) | Decorrelated drains — no lump correlation beacon |
| Terminal unstake | Ordinary FCMP++ spend(s) draining `P` | SAL key image only here |

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

`P` must present backing to peers **before** earning (off-chain). The **first reward
emission** creates/updates the on-chain bond record (holdings, claimed-epoch state).
Fusion removes a discrete registration transaction; it does **not** remove the
registration **event**.

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

## 3. StakeState FSM (pinned draft for Round 1–2 review)

> **⚠ SUPERSEDED PENDING RETOOL (2026-06-07).** §3–§5.2 below are **claim-era** FSM text —
> output-keyed `StakeId`, nullifier-derived `claimed_epochs`, tier-lock yield states. They
> **contradict** rebased §2.4 and [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §6.
> Authoritative retool disposition:
> [`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md) (P2B-1–6). **Do not implement §3
> as written.** P2B-1 master finding: wallet primary key → `P_canonical_id`.

### 3.1 States

States are unchanged in shape from the prior draft; **fields change** to carry
confidential material and the claimed-epoch set instead of a watermark.

*(Stale — see retool doc P2B-4.)*

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
- **A5 — economic / rational internal actor** (added in §7.5.3 synthesis): yield-optimizing
  agents (stake vs. unstake/other uses — bank-run dynamics), MEV extractors, stake-rental
  markets. Not a confidentiality adversary; an incentive-and-liveness adversary against the
  economic servo. Run against A5: mass-unstaking shock, claim/unstake MEV.

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

### 7.5 Round 3 wargame (executed 2026-06-05): dispositions

This subsection **executes** the §7.4 agenda — every T- and G-item is driven to a
disposition — and **augments** it with a survey of attacks that deployed privacy chains
(Monero, Zcash, Grin/MimbleWimble) and PoS/DeFi staking systems have actually suffered, so
the threat model is exhausted against history, not only against the design's own internal
seed. Each disposition is one of (per [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)):
**mitigated-in-design** (mechanism cited), **FOLLOWUP** (target version + reopening trigger),
**cross-track upstream** (consensus ask, not assumed), or **priority-reject** (reopening
criteria). Adversary models **A1–A4** are §7.4. Real-world analogs are named so a future
maintainer can see *which* historical failure each pin defends against.

**Threat-model-exhaustion dispositions (T1–T9 from §7.4):**

| ID | Real-world analog | Disposition |
|----|-------------------|-------------|
| **T1** Per-stake claim-sequence correlation | Monero temporal analysis + EAE (Eve-Alice-Eve) anonymity-set shrinkage | **Mitigated-in-design (default) + FOLLOWUP (jitter).** Full-window batching (claim all unclaimed ≤ `MAX_EPOCHS_PER_CLAIM=15` in one tx — §6/§6.2) collapses the common case to a single event. Residual: tier-3 backlogs > 15 epochs force multiple txs carrying a `(tier, contiguous-window)` serial signal. Wallet pin: **no fixed epoch-boundary broadcast cadence**; randomized delay + Dandelion++ (network layer). **FOLLOWUP V3.1**: pin the jitter distribution + Dandelion++ default. **Reopen:** testnet shows residual serial correlation under A2 despite batching (mirrors `CONFIDENTIAL_STAKING.md` §14.4 reopen-if). |
| **T2** Claim↔stake linkage across a sequence | Zcash nullifier-analysis / repeated-shielded-action linkage | **Mitigated-in-design.** `N_{i,S}=x_i·G_S` is pairwise-unlinkable across **independent per-epoch bases** `G_S` (§6.3 DDH split, KAT-locked). Confirmed across the *whole* sequence: the nullifier vector exposes no cross-epoch join key beyond the claimed set `{S}` itself. Residual linkage is **not cryptographic** — it is the tier+window scope (T1) and the claim-tx-type tell (T10). **Reopen:** the DDH/RO heuristic on `hash_to_ec` bases breaks (consensus-crypto event, not wallet). |
| **T3** Band cohort-size leakage (cold start) | Zcash small-shielded-pool deanonymization | **Cross-track upstream + wallet-UI FOLLOWUP.** Structural fix (floor `band_sum_eff`, suppress burn-signal publication below a cohort threshold) is consensus-owned (`CONFIDENTIAL_STAKING.md` §14.1/§14.4 P2). **Cross-track ask (record, do not assume):** confirm the cohort-floor/suppression is active at genesis. **FOLLOWUP V3.1**: wallet surfaces an early-staker thin-cohort warning before a stake lands (cohort estimable from public participation). **Reopen:** testnet residual fingerprinting despite the consensus floor. |
| **T4** Claim-timing correlation | Monero broadcast-timing + first-seen origin heuristic | **Mitigated-in-design (network layer) + wallet pin.** Global settlement-epoch boundaries cluster claimers, *growing* the temporal anonymity set (§6.2). Wallet must not undermine it: **no auto-claim at a deterministic height** tied to a stake's unlock; jitter + Dandelion++ + Tor/I2P-first ([`ANONYMITY_NETWORKS.md`](../ANONYMITY_NETWORKS.md)). Folds into the T1 jitter FOLLOWUP. |
| **T5** In-memory opening exposure | Heap-disclosure / cold-boot / swap-leak of wallet secrets | **Mitigated-in-design.** `(amount, z)` in-memory only, re-derived on hydration, **never sealed** (§3.3.1/§4.2); transient `x` zeroized after claim build; no plaintext opening in messages/RPC (R0-D3). **Stage-3 test (load-bearing):** verify the prover bundle wipes after proof emission — the one place a copy of `(amount, z, x)` transits. **Reopen:** a measured zeroization gap in the prover-bundle path. |
| **T6** Nullifier-reorg desync | (no external analog — wallet-internal) | **Mitigated-in-design (forward rebuild).** §5.2 clear-all/replay-all recomputes `claimed_epochs` from the post-reorg chain ∩ `{x·G_S}`, height-free, so it self-heals across adversarial shapes; the sharp case — a **straddling-lock reorg** that moves `eligible_height` across a tier boundary — re-derives the window from post-reorg `creation` (§3C arithmetic), so it is correct by construction. Daemon reorg correctness assumed as for spent key images (§5.2). **Stage-3 test:** the three §7.4 shapes. |
| **T7** Nullifier / key-image cross-link | **Janus attack** (Monero subaddress-linkage); "shared secret across two surfaces" class | **Mitigated-in-design.** `x·G_S` (claim) vs `x·Hp(O)` (unstake/spend) unlinkable under independent NUMS bases (§6.3, KAT-locked, `G_S ≠ Hp(O)`). Wallet must never emit both tags in a correlated context nor expose a join field. **Janus specifically N/A:** FA-1 single static address ⇒ no subaddresses to cross-test; the Janus surface does not exist. **Reopen:** DDH-base independence break (consensus-crypto). |
| **T8** Silent inflation (wallet role) | **Zcash 2018 counterfeiting vuln**; **Monero 2017 RingCT inflation bug** | **Mitigated-in-design (wallet non-masking) — priority-1.** Soundness of the entitlement relation is consensus-owned (`h_bind` + `N/D`-recompute + bounded-remainder + `ρ_cap`, §9). Wallet obligations: (a) never construct over-entitlement (recompute `N/D` before prove); (b) **never rely on the consensus range proof to mask a local accounting bug**. See G11. **Reopen:** any wallet code deriving claimable from a daemon-supplied figure rather than its own secret weight × public `ρ_e`. |
| **T9** Fake `StakeEvent` injection | Light-client false-event injection by a malicious server | **Mitigated-in-design.** Events are scanner-origin (blocks tied to daemon headers); `OwnNullifierObserved` requires matching a locally derived `N_{i,S}` — a forged event cannot fabricate the wallet's own nullifier (adversary lacks `x`). A1 can **withhold/delay** (liveness, not safety) but cannot fabricate a claimed epoch. **Reopen:** any path that sets `claimed_epochs` from an event not gated on local nullifier match. |

**Privacy-crypto-survey vectors (new in Round 3 — T10–T14):** vectors that deployed privacy
systems suffered and the §7.4 seed had not named.

| ID | Real-world analog | Disposition |
|----|-------------------|-------------|
| **T10** Claim-tx-type distinguishability / staker-set anonymity | **Zcash transparent↔shielded distinguishability** (the *act* of shielding was observable; low usage collapsed the effective set) | **Accept v1 scope (consensus) + V4/L4 FOLLOWUP + wallet non-worsening.** A claim is a distinct input type (`txin_stake_claim_v2`), so the act of staking/claiming is publicly classifiable and the claim anonymity set is "stakers in the same tier+window," never "all txs." **Mission note (Priority 2):** this is *not* "privacy as a setting" — *within* staking every staker gets identical guarantees; non-participation is a user choice, not a downgrade of the base transfer. Structural hide (conceal tier/window) = **L4, deferred to V4** (`CONFIDENTIAL_STAKING.md` §14.4). Wallet's job: add **no** further fingerprint (T14/G12) and surface to the user that staking is publicly observable as such. **Reopen:** product requires full-staker-set indistinguishability before genesis (§14.4 item-9 reopen-if). |
| **T11** Stake/unstake/claim amount & commitment linkage | **MimbleWimble tx-graph reconstruction**; Monero pre-RingCT amount correlation | **Mitigated-in-design — confirmed at source (2026-06-05).** Unstake is a **normal post-lock FCMP++ membership spend**: it consumes the staked leaf via a ZK membership proof that **does not reveal which leaf** (`CONFIDENTIAL_STAKING.md` §6.3 step 1) + key image `x·Hp(O)`, and **appends a fresh main-tree principal output** (§6.4.3 cross-tree transition) — the literal `C_stake` is **never re-published**, so there is **no point-equality stake↔unstake link** (the unlinkability an ordinary transfer enjoys; §7 pins the spend "unlinkable"). The "re-stake principal in the same tx" model that *would* have coupled them was explicitly **rejected** (§6.4.5). Residual: the unstake's membership anonymity set is the **staking subtree** (3C separate tree), not the whole main tree — that is the **T10/T3 staker-set/cold-start scoping**, already dispositioned, **not** a commitment-linkage leak. (b) Band→amount bounding = T3/T10. Wallet never surfaces a stake↔unstake/claim join key (lens-3, §7.3). **Reopen:** consensus changes unstake to re-publish or re-stake the principal commitment in-place. |
| **T12** One-time-key collision / dust-stake | **Monero 2018 burning bug** (multiple outputs to the same one-time key) | **Mitigated-in-design (key by OutputRef) + Stage-3 test.** `StakeInstance` is keyed on `OutputRef=(tx_hash, index)` (§3.3 byte-stable derivation), **not** the one-time key, so two outputs colliding on a one-time key are distinct instances — the burning-bug collision cannot corrupt stake tracking. (An attacker cannot create a stake bearing the victim's spend authority; the staker holds the opening.) **Stage-3 test:** two staked outputs sharing a one-time key resolve to two `StakeInstance`s. **Reopen:** any scanner path that dedups stakes by one-time key. |
| **T13** Remote-node query-pattern leakage | **Monero malicious-remote-node** key-image/output-query deanonymization | **Mitigated-in-design (bulk-fetch invariant) — load-bearing.** Wallet recomputes `{x·G_S}` locally and intersects the chain nullifier set; it must fetch the **whole** set (bulk/contiguous), **never** query "is *this* nullifier present?" per-item — else A1/A4 learns the wallet's claimed epochs. Adopt [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md)'s "bulk/contiguous only, never per-output query" invariant verbatim for the nullifier set + stake scan. **Stage-3 pin (load-bearing).** **Reopen:** any RPC path querying nullifier membership per-item. |
| **T14** Whole-lifecycle broadcast-origin linkage | Monero broadcast-origin / IP↔tx correlation across a wallet's activity | **Mitigated-in-design (network layer) + wallet pin.** stake-create / claims / unstake from one wallet over a correlated origin (IP/Tor circuit) or at correlated heights link the whole lifecycle. Tor/I2P-first + Dandelion++ + fresh circuit per tx; **wallet must not chain stake→auto-claim→auto-unstake at deterministic offsets.** Folds into the T1/T4 jitter FOLLOWUP. |

**Wider-substrate audit dispositions (G1–G10 from §7.4):**

| ID | Real-world analog | Disposition |
|----|-------------------|-------------|
| **G1** Slashing / penalty tracking | Cosmos/ETH validator slashing | **N/A — confirmed.** Shekyl confidential staking is reward-only; no slashing/penalty. The "wallet tracks slashing risk" class does not exist. Recording N/A *is* the audit result. |
| **G2** Validator / delegation UX | Delegated-PoS delegation flows | **N/A — confirmed.** Not delegated PoS; no validators, no delegation surface. |
| **G3** Lock-up / unbonding surprise | Cosmos/ETH unbonding-period confusion | **Mitigated-in-design + FOLLOWUP (UX).** `StakeView.unlock_height` surfaces the lock boundary (§6). **FOLLOWUP V3.1**: GUI/CLI shows lock duration + unlock height at stake time and warns on long tier-3 locks. **Reopen:** usability testing shows lock surprise. |
| **G4** Dust-reward / fee-starved claim | Cosmos/ETH "claiming costs more than the reward" | **FOLLOWUP V3.1 (UX pin).** Wallet compares `claimable` to the estimated claim-tx fee; if `claimable < fee`, **never auto-broadcast** — warn / defer / accrue more epochs ("not yet worth claiming"). Implemented at Stage 3. |
| **G5** Resync during in-flight claim | — | **Mitigated-in-design.** `claim_pending_epochs` runtime-only; `Restore` starts empty; R0-D2 rebuild recomputes `claimed_epochs` from chain ∩ `{x·G_S}`; an in-flight claim either landed (folded) or did not (epoch claimable again; consensus rejects a duplicate nullifier). **Reopen:** any persistence of `claim_pending_epochs`. |
| **G6** Mempool eviction of a claim tx | — | **Mitigated-in-design (inherits staleness gate) + Stage-3 test.** Claim path runs through `PendingTxEngine`'s staleness/eviction handling (§8.9); on eviction the epoch returns to claimable with no chain trace. **Stage-3 test:** evicted claim ⇒ epoch re-claimable. **Reopen:** claim path bypasses the staleness gate. |
| **G7** Long-range reorg of a confirmed claim | — | **Mitigated-in-design (forward rebuild).** Same as T6; no additional wallet gap. Daemon correctness assumed as for spends. |
| **G8** HW-wallet signing latency (claim/unstake) | Hardware-wallet round-trip latency | **FOLLOWUP V3.1 + design note.** Claim-prove needs `x` transiently via the `Signer` boundary; HW round-trips add latency. Claims are **not deadline-tight** (settlement epochs are coarse and epochs stay claimable in the accrued window), so this is **not a Stage-3 blocker**. **FOLLOWUP V3.1**: measure HW claim-prove latency. **Reopen:** a HW path where claim-prove exceeds a settlement epoch. |
| **G9** Wallet-locked during claim window | — | **Mitigated-by-window + FOLLOWUP.** Because claims are not deadline-tight, a locked wallet claims when next unlocked — no loss/expiry in v1. **FOLLOWUP V3.1**: optional reminder. **Reopen:** any v1 mechanism that expires a claim. |
| **G10** Fee-bump / replacement of a stuck claim | RBF / CPFP fee-bumping | **Priority-3 reject (precedent transfers).** Per the PR 5 G3 precedent: claims inherit the no-RBF posture; a stuck claim is handled by the staleness gate + re-claim (epoch stays claimable). **Reopen criteria (PR 5 G3):** FCMP++ fingerprint-unobservability analysis **OR** telemetry re-classification of stuck-tx recovery into a higher priority class. |

**Privacy-crypto-survey wider-substrate items (new — G11–G13):**

| ID | Real-world analog | Disposition |
|----|-------------------|-------------|
| **G11** Proof-system soundness / inflation bug | **Zcash 2018 counterfeiting vuln**; **Monero 2017 inflation bug** | **Consensus-owned; wallet priority-1 non-masking (cross-ref T8).** A soundness break in entitlement/range/membership proofs would mint coins — consensus-track (audit + KATs + §9 conservation). Wallet role: non-masking (T8) + **loud failure** on any local accounting inconsistency rather than trusting the proof. Naming it ensures the worst historical class is on record. **Reopen:** consensus audit finding. |
| **G12** Wallet/tx-construction fingerprint | **Monero wallet2 fingerprinting** (ordering/fee/extra-field tells partition the anonymity set by wallet) | **FOLLOWUP V3.1 (canonicalization pin) + Stage-3 test.** Claim txs carry `settlement_epochs[]` + `nullifiers[]`; ordering must be **canonical (sorted)**, fee per the 2A canonical model, no wallet-specific padding. **Reopen:** any non-canonical ordering or wallet-specific field in the claim/stake wire (cross-ref the upstream byte-exact wire, §8.0). |
| **G13** Claim front-running / censorship (MEV) | DeFi claim front-running / miner censorship | **Mitigated-by-construction + retry.** A claim's reward binds to the wallet's own nullifier — no observer extracts value by front-running (idempotent to ordering, non-competitive). Censorship: a miner can omit a claim, but the epoch stays claimable ⇒ retry. **Reopen:** a consensus change that makes claims order-dependent or competitive. |

#### 7.5.1 Load-bearing findings (the four that warrant depth)

1. **Inflation is the worst historical class — the wallet's role is non-masking (T8/G11).**
   Both major privacy chains shipped silent-inflation vulnerabilities (Zcash's 2018 zk-SNARK
   counterfeiting flaw; Monero's 2017 RingCT bug). The wallet cannot prevent a consensus
   soundness break, but it **must not become the layer that hides one**: it derives
   `claimable` only from its own secret weight × the public, full-node-verifiable `ρ_e`
   (§8.6) — never from a daemon-supplied figure — and it loud-fails any local accounting
   inconsistency rather than letting the consensus range proof absorb it (priority-1,
   `00-mission.mdc`). This is the single most important wallet-side privacy/soundness pin.
   **The *consensus*-side soundness is the existential surface and must not be scored
   "strong" on mechanism-presence:** the entitlement proof (8a) and the band-declaration
   binding (8b), split out in §7.5.3, are **unverified** and carry the round's **top audit
   rigor** — "the mechanism exists" is not "the mechanism is sound," and a soundness break
   here is undetectable infinite inflation (the Zcash/Monero lesson). The wallet pin above is
   necessary but does not discharge 8a/8b.
2. **Stake↔unstake commitment linkage — investigated and closed (T11, 2026-06-05).** The
   Round-3 concern was that unstake might re-publish the *literal* `C_stake` (a
   MimbleWimble-class point-equality link no wallet redaction could close). **Confirmed at
   source it does not:** unstake is a normal FCMP++ membership spend — the staked leaf is
   consumed via a ZK membership proof that does not reveal which leaf
   (`CONFIDENTIAL_STAKING.md` §6.3 step 1), and a **fresh** main-tree principal output is
   appended (§6.4.3 cross-tree transition); §7 pins the spend "unlinkable," and the coupling
   "re-stake in the same tx" alternative was explicitly **rejected** (§6.4.5). The only
   residual is that the unstake's anonymity set is the **staking subtree** (3C), not the
   whole main tree — already captured as the T10/T3 staker-set/cold-start property, not a
   linkage bug. **No Priority-2 finding from T11.** (The clean close T11 would have permitted
   was subsequently re-gated by the §7.5.3 synthesis on the unrelated top finding F0.)
3. **Remote-node query-pattern leakage is a load-bearing Stage-3 pin (T13).** Monero's
   malicious-remote-node deanonymization came from light wallets revealing *which* outputs /
   key images they cared about. The confidential-staking nullifier scan must inherit the
   curve-tree client's **bulk/contiguous-only, never-per-item-query** invariant verbatim;
   a per-nullifier "is this present?" RPC would hand A1 the wallet's exact claimed-epoch set.
   Recorded here as load-bearing so Stage-3 implementation cannot quietly add a per-item query.
4. **Staking is publicly observable as a class — accepted for v1, hidden in V4 (T10).** The
   distinct claim input type makes "this wallet stakes" public; the claim anonymity set is
   tier+window-scoped, not global. This is the Zcash shielded-set lesson applied honestly:
   v1 accepts it (with full intra-cohort uniformity, so it is not "privacy as a setting"),
   and the structural hide (L4: conceal tier/window) is a V4 lattice-path gate. The wallet's
   obligation is to add no *further* fingerprint (T14/G12) and to tell the user the truth
   about observability.

#### 7.5.2 Residuals and forward actions

- **FOLLOWUPS (target V3.1)** — `docs/FOLLOWUPS.md` entries: jitter/Dandelion++ broadcast
  default (T1/T4/T14); thin-cohort early-staker warning (T3); dust/fee-starved-claim UX (G4);
  lock-up surfacing UX (G3); HW-wallet claim-prove latency measurement (G8); locked-wallet
  claim reminder (G9); claim-tx canonical-ordering fingerprint pin (G12).
- **Cross-track upstream asks (record, do not assume):** cohort-floor/suppression active at
  genesis (T3); L4 hide-tier/window for V4 (T10). *(T11 principal-commitment
  re-randomization was investigated and confirmed at source 2026-06-05 — §7.5.1 #2 — so it
  is no longer an open ask.)*
- **Stage-3 implementation pins (load-bearing):** bulk-fetch-only nullifier scan (T13);
  `OutputRef`-keying not one-time-key (T12); prover-bundle zeroization (T5); claim via the
  `PendingTxEngine` staleness gate (G6); canonical wire ordering (G12).
- **Priority-rejects:** fee-bump/RBF of a stuck claim (G10), with the PR 5 G3 reopening
  criteria.
- **N/A confirmed (audit results):** slashing (G1), delegation UX (G2), Janus subaddress
  linkage (T7) — all structurally absent.

**Closure status:** all T1–T14 and G1–G13 carry a disposition; the wargame is **executed**,
and **T11** (the candidate gating finding) was investigated and **resolved at source**
(§7.5.1 #2: unstake is an unlinkable FCMP++ membership spend with a fresh output; no
point-equality link, no Priority-2 finding). A first clean close was recorded 2026-06-05 —
then **re-gated the same day by the dual-wargamer synthesis in §7.5.3**, which surfaced a new
top finding **F0** (the claim's effective anonymity set is the `{tier × creation-window}`
cohort, confirmed at source, which reframes T1/T2/T3 into one structural problem and can
approach a cohort of one at cold start). **Historical note (2026-06-05):** closure was
re-gated on F0 bucketing on the **confidential-entitlement claim wire**. **Superseded
(2026-06):** F-ARCHIVAL pay-for-service rebasing retires that wire for genesis; F0
bucketing is **not** the Round 3 closure item on the rebased substrate (see §7.5.3
*F0 disposition on the rebased substrate*). The other residuals (FOLLOWUPS V3.1,
Stage-3 pins on principal/unstake path) carry reopening triggers where still
load-bearing. Stage 3 *merge* remains gated on §8.0 (rebased substrate + Tier 1
soundness), not on F0 bucketing.

#### 7.5.3 Round 3 synthesis (dual-wargamer adversarial pass, 2026-06-05)

Two independent adversarial passes over §7.5 (one privacy-crypto-graveyard-led, one
PoS/economic-research-led) were synthesized. The pass **confirmed** the §7.5 dispositions
that hold, **sharpened** several, surfaced **one finding that outranks the entire pre-staged
T-list** (F0), and added an adversary model (**A5**, economic/rational actors). F0 re-gates
Round 3 closure; everything else lands as a sharpening or a new forward action.

##### F0 — The claim anonymity set is the `{tier × creation-window}` cohort, not the staking subtree (top finding; reframes T1/T2/T3)

FCMP++ gives *spends* a whole-chain anonymity set — the design's crown jewel. A **claim**
does not inherit it. A claim proves membership in the **staking subtree** (already strictly
smaller), and the claim-verify surface then narrows it further. **The reveal-vs-ZK question
is now settled at source — and the answer is the worst case: both partitioning fields are
transmitted in cleartext.**

- **`tier` and `creation_height` are explicit public wire fields.** `CONFIDENTIAL_STAKING.md`
  §6.4.8 `txin_stake_claim_v2`: **`tier` (u8, "Public")** and **`creation_height` (u64,
  "Public")**. §6.4.3 confirms the verifier path — "**At claim (public `(tier, creation)`
  from wire):** verifier recomputes `h_bind`, … checks the window arithmetically"; "Verifier
  reads **one** `tier` scalar; uses it for the `h_bind` recompute **and** `tier_num`." So
  `creation_height` is **not** merely brute-forceable from a published `h_bind` (my earlier
  §7.5.3 hedge) — it is **published directly**. The membership proof hides *which leaf* (so
  `C_stake`/principal stays unlinked), but the two partitioning fields are in the clear on
  every claim.

**Consequence — this reframes three pre-staged threats into one structural variable.** The
`{tier × creation_height}` **cohort size** is the master variable behind T1 (claim-sequence
correlation), T2 (claim↔stake linkage), and T3 (cold-start). Because **every claim of one
stake carries the identical cleartext `(tier, creation_height)`**, a stake's claims **link to
each other by deterministic exact-match on two public fields, regardless of the DDH-unlinkable
nullifiers** — so T2 is **structural, not residual** (the §7.5 T2 disposition under-weighted
this: the §6.3 DDH split protects claim↔*unstake-key-image* linkage, **not** claim↔claim
linkage within a stake's sequence). The doc's own §6.2 "a weak serial signal that accumulates"
is **understated**: it is an exact-match join key, not a statistical signal. At cold start the
cohort of stakes sharing an exact `(tier, creation_height)` approaches **one** — the **Zcash
small-shielded-pool lesson with a Shekyl-specific multiplier**: the pool is not merely small,
it is **partitioned by tier and exact creation-height**.

**Why it is revealed — the security/privacy coupling (do not "just add ZK").** The reveal is
**load-bearing for inflation-safety**, not an oversight. §6.4.3 excludes tier-forgery
*because* the **single revealed `tier`** drives **both** the `h_bind` hash-equality **and** the
multiplier `N = tier_num(tier)·ΣK_S` (recompute-and-reject); the revealed `creation_height`
makes the window check `creation < S ≤ creation + tier_lock` **pure arithmetic** rather than an
in-circuit relation. This is precisely the **3C** win over **3A** (§6.4.3): "no new primitive."
Moving `(tier, creation)` into zero knowledge pushes the multiplier-consistency and
window-membership checks **in-circuit** — reintroducing the **novel-consensus-ZK-primitive cost
that 3A was rejected for**. So **L4-hide-tier/window is not a bolt-on**; it re-opens the
3C-vs-3A decision and must be co-designed with the entitlement circuit.

**The reveal also shrinks the existential audit surface (the coupling is stronger than
"cheaper consensus").** Every check that stays cleartext is a check that is **not in the
entitlement circuit** — and the circuit is exactly where **8a soundness** lives, the one item
that "must not be waved through." So the reveal does not merely buy inflation-safety
*without a new primitive*; it buys a **smaller, more auditable 8a circuit** — a **tighter
soundness perimeter on the existential item.** The corollary is a **named cost on any future
V4 hide-(tier, creation) design:** hiding those fields **grows the 8a surface it must
re-audit** (multiplier-consistency and window-membership move inside the circuit). That is a
security cost of the privacy fix, not a privacy-neutral move — it must be priced into the V4
design up front, not discovered during its audit.

Under [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc) the hierarchy is explicit: the
reveal serves **Priority 1** (inflation-safety, cheap + auditable + smaller circuit); F0 is a
**Priority 2** privacy cost. Priority 2 cannot override Priority 1 unless a construction
delivers **both** — which is the V4/L4 work, not a v1 patch. **But the hierarchy ranks the
*conflict resolution*; it does not *price the residual*.** "It's a P2 cost" correctly licenses
*why the reveal ships in v1* — it does **not** establish that the cost is small. For a privacy
coin, "staking is deterministically deanonymizable into small cohorts by an exact-match join on
two cleartext fields" is a **material degradation of the staking feature's headline value** for
the subset of users who stake — confidentiality **weaker than the spend path's whole-chain
set**. That can be the right product call, but the F0 "document-and-accept" option must clear a
**high, eyes-open product bar** — it must not be **defaulted-to because the leak sorts under
P2.**

**Disposition — confirmed finding; re-opens `§14.4` item-9; cross-track decision (not an open
factual question).** The reveal-vs-ZK *question* (the merged-list #2, the cheapest existential
check) is **answered: revealed-by-design, Priority-1-justified.** What remains is a **consensus
policy decision**, which per `21-reversion-clause-discipline.mdc` **re-opens**
`CONFIDENTIAL_STAKING.md` §14.4 item 9 ("accept tier+window-scoped anonymity for v1") with the
scope now known to be **exact `(tier, creation_height)`** — tighter than the pin acknowledges,
and `cohort → 1` at cold start collides with **Priority 2** (same guarantees for every user).
**Cross-track ask (the gating item for clean closure):**
- **The `band_sum_eff` floor (§14) does *not* address this — it is a different leak.** The
  floor smooths the **public-rate readout** (T3's rate-channel); it does **nothing** for the
  **cohort-membership collapse**, because flooring the aggregate `band_sum` does not enlarge
  the `{tier × creation_height}` set a claim narrows to. Cold-start therefore needs **two**
  mitigations: the band floor (rate channel) **and** a claim-cohort mechanism (reveal channel).
- The decision is **three-way**, not the binary "new mechanism vs. accept" an earlier draft
  implied. In increasing cost:
  1. **Accept-exact** (`{tier × creation_height}`). The high-bar product decision above —
     deterministic cross-claim linkage, cohort `→ 1` at cold start, on record. Cheapest to
     ship, weakest privacy.
  2. **Cleartext `creation` bucketing (the cheap middle — no circuit, no new primitive).**
     Bind a **bucketed** creation into `h_bind` (bucket width `W`), not the exact height; the
     cohort enlarges from `{tier × exact-height}` to `{tier × bucket}`, `W` is the
     **cohort-size ⇄ cost dial**, and it is **all cleartext arithmetic** — just a coarsening
     rule plus a rounding direction. **The rounding direction is the hard inflation
     constraint:** round creation **UP** to the bucket ceiling and make that single bucketed
     value canonical for the lower bound, `eff_lock`, **and** the consensus lock-enforcement
     together. Then `S > ceiling ≥ true_creation` (no claiming pre-stake epochs — inflation
     safe) and accrual `(ceiling, ceiling+tier_lock]` stays `≤` the consensus-enforced lock
     (no over-claim); the cost is a **bounded ≤W lock-shift**, not unbounded yield loss. Round
     **down** and `S > floor` admits epochs in `(floor, true_creation]` — **claiming before
     the stake existed = silent inflation** (the forbidden direction). Two residuals to name
     if taken: **(i)** the **tier factor is irreducible** to ~⅓ (per-tier) without V4 — the
     multiplier needs `tier_num` in clear regardless of any creation bucketing; **(ii)**
     round-up gives a mild incentive to time stake creation near a bucket ceiling to minimize
     the lock-shift, **re-clustering creation timing inside the bucket** (harmless to cohort
     size; a faint stake-tx-timing tell). ***Recommended v1 disposition*** *— it attacks the
     one property that exceeds the already-accepted staking budget (scale-resistance): it
     restores dilution-with-growth so the crowd covers a claim again as the network grows. See
     the baseline-budget calibration below.*
  3. **V4 in-circuit hiding** of `(tier, creation)` — the only path that removes the **tier**
     axis too, at the 3A circuit cost + the 8a re-audit cost named in the coupling note.
  (A `{tier × bucket}` k-anonymity *gate* can compose on top of option 2, but the band floor
  is **not** it.) "Incentivize more staking" fixes absolute size, **not** the partition.
- **Adjacent economic-redesign question raised 2026-06-05 (cross-track to consensus/economics,
  own design round): can the `tier` axis be removed at the source?** F0's irreducible residual
  (2(i)) is the tier reveal, forced because the multiplier is tier-specific. If reward were
  **derivative** (a single global rate / function of already-committed quantities, not a
  staker-declared discrete tier), `tier_num` would not be per-stake and the **`tier` field
  could leave the wire** — collapsing the cohort to `{creation_bucket}` with **no tier
  subdivision**. **Structural finding:** removing tiers removes the tier axis, but **does not
  remove `creation`** — a *time-accrued* reward needs a provable accrual-start, and proving it
  is the **same 3C-vs-3A choice already settled** (reveal `creation` cleartext, or adopt the
  rejected non-membership primitive). So the end state is **`{creation_bucket}`**, not
  "nothing," unless reward also stops being time-accrued (a larger economic change). The
  trade is real: tiers exist to **price duration commitment**; removing them trades that
  incentive lever for the privacy win. **This is a consensus-economics change, not a wallet
  change** — recorded here as an F0-motivated alternative; it needs its own spec-first design
  round (`05-system-thinking.mdc`) before any disposition. See the §7.5.3 economic-redesign
  note below.

**Wallet-side forward action (FOLLOWUP V3.1, does not substitute for the consensus decision):**
surface a **cohort-size warning before a *claim*** when the observable cohort
(`{tier × creation_height}`, or `{tier × bucket}` / `{creation_bucket}` under options 2/tier-
removal) is small (estimable from public chain state) — the honest-UX analog of the T3
thin-cohort stake warning, elevated to the headline and extended to the claim path.

###### F0 baseline-budget calibration — membership cost (already accepted) vs. linkage cost (the excess)

F0's magnitude must be priced against the **staking-exposure budget the project accepted
*before* confidential staking existed** (staking as "a public notice of support"), not against
zero-reveal. Separating the two cleanly de-escalates the finding and re-targets the mitigation.

- **The accepted baseline is a membership-and-aggregate cost, and it is *scale-friendly*.** The
  original posture priced: you are observably a staker; the **band aggregate** and the **public
  rate** are public *by design*; stake/claim/unstake txs are identifiable *as staking*. This was
  the right thing to accept — staking is an **overlay**, it cannot match the spend path (the
  headline product), and the cost **dilutes with growth**: at maturity you are one of thousands
  of stakers and the crowd is your cover. It gets *better* as the network grows.
- **F0's cohort-collapse is a different *category* — a linkage cost — and the part that exceeds
  baseline is specifically its *scale-resistance*.** The reveal (a) joins your claims into an
  **attributable sequence**, (b) **bridges that sequence back to your stake-creation event**,
  and (c) pins it to a `{tier × exact-height}` cohort. The budget-breaking property is (c)'s
  scale-resistance: the cohort is *one block's stake-creations ÷ 3 tiers* — governed by the
  **per-block creation rate, not the accumulated total**. Ten thousand lifetime stakers do not
  help; your cohort is the two or three stakes minted *in your block at your tier*. **The crowd
  never becomes your cover.** The membership cost dilutes with growth; this one does not — that
  is the qualitative difference, and (per the block-granularity of `creation_height ≜
  eligible_height`, `CONFIDENTIAL_STAKING.md` §2/§6.4.3) it is a **steady-state** thinness, not
  only a cold-start one.
- **Second escalation the baseline lacked: targeted-cascade force-multiplier.** Under pure
  set-membership, deanonymizing one claim tells the adversary nothing about the others. Under
  the reveal, **one foothold** — a single linked claim, or merely watching your stake tx —
  **cascades to your entire claim history** via the deterministic join. Set-membership does not
  cascade; this does.
- **Net the other way (correcting the prior "headline #2" overstatement).** A stake's claims
  were **already substantially linkable without the reveal** — timing cadence, claim-tx
  fingerprint + epoch-count (T10/G12), network circuit reuse (T1/T4/T14). Against that realistic
  counterfactual, the reveal's **marginal** contribution is "**exact-and-deterministic instead
  of strong-statistical**," plus the **creation-anchor** bridging to the stake side. For a
  careless staker it adds **modestly**; for a careful one (batches, fresh circuits, irregular
  timing) the reveal is the **whole** leak — the one channel behavior cannot defeat. **So the
  reveal most penalizes the privacy-conscious staker** (the wrong population to penalize), but
  it is a **smaller delta over baseline than the "headline" framing implied** for everyone else.

**Honest calibration.** F0 is the **same category of cost the team already accepted** — staking
is the exposed overlay, the spend path is untouched, **nothing here breaches the core privacy
promise** — at a **larger magnitude** than "staking reveals something" naturally priced. The
magnitude excess is specifically **scale-resistance + targeted-cascade**, *not the existence of
exposure per se*.

**Reframed mitigation target (this lowers the temperature).** The goal was **never zero
reveal** — it is "**do not sit above the staking-exposure budget already set.**"
**Creation-bucketing (option 2 — cheap cleartext, no economic redesign) attacks exactly the
budget-exceeding feature:** it **restores dilution-with-growth**, because the cohort becomes a
*bucket's worth* of creations rather than *one height's*, so the crowd starts to cover you again
as the network grows. Bucketing brings the cost **back toward the membership-shaped baseline**,
residual = the **within-tier, within-bucket** cohort.

**Settled decision shape (de-escalates the F0 gate).** F0 is **not** "perfect claim privacy vs.
accept a deanonymization hole." It is: **(1) bucket creation to restore scale-dilution — cheap,
no redesign — the recommended v1 disposition**; then **(2) decide whether the residual tier-⅓
sits inside the staking-reveals-something budget.** Honest read: it **probably does** — a
within-tier, within-bucket cohort that **grows with the network** is close in spirit to the
set-membership cost already accepted. The **exact-height, scale-resistant** version is what
genuinely **broke** the budget, and bucketing fixes that **without touching the economics**
(which are a designed counterweight — not to be unbalanced). **De-tiering (the economic
redesign) is therefore *not* a forced move** — per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)
it is **reject-now-with-reopening-criterion**: reopen **only if a specific high-value-target
threat model shows the within-tier within-bucket cohort is unacceptable for a staking population
the project must protect.** For the general posture, bucketing likely closes the gap; the
economic redesign stays a **V-future option**, not a v1 dependency.

###### F0 option-2 (bucketing) — mitigation, quantified

Mechanism (restated for the math): `h_bind` binds a **bucket ceiling**
`creation_bucket = ⌈ eligible_height / W ⌉ · W` instead of the exact `creation_height`,
where `W` is the bucket width in blocks. The window check then reads `S > creation_bucket`
(round **up**, §"hard inflation rule" below). The claim cohort coarsens from
`{tier × exact-height}` to `{tier × bucket}`.

**Cohort size.** Let `λ` = network-wide stake-creation rate (stakes/block) and `B` = number of
tiers (`B = 3`). With creations spread roughly evenly across tiers, the expected cohort a claim
falls into is

```
cohort(W) ≈ (W · λ) / B          # within-tier, within-bucket creations
```

The **exact-height baseline is `W = 1`**: `cohort ≈ λ/3`, governed by the *per-block* creation
rate — a handful regardless of how many lifetime stakers exist. Two effects of `W > 1`:

1. **Tunable multiplier (immediate).** `cohort` scales linearly in `W`. Picking `W` to span,
   e.g., a day's creations turns a per-block handful into a per-day crowd. Illustrative
   (assume ~720 blocks/day, flag block-time as an assumption to confirm):

   | `W` (blocks) | span (≈) | cohort at `λ=0.05/blk` | cohort at `λ=0.5/blk` |
   |---|---|---|---|
   | 1 | per-block | ~0.02 (→ floor of 1, i.e. *you*) | ~0.17 |
   | 180 | ~6 h | ~3 | ~30 |
   | 720 | ~1 day | ~12 | ~120 |
   | 5040 | ~1 week | ~84 | ~840 |

2. **Restores dilution-with-growth (the load-bearing fix).** `λ` rises with adoption, so for a
   fixed `W` the cohort *grows with the network* — the property the accepted baseline had and the
   exact-height reveal destroyed (per the calibration above, scale-resistance was the specific
   budget-breaker). Bucketing is the cheapest mechanism that puts the crowd back in front of you.

**Targeted-cascade is divided by the cohort.** Under exact height, one deanonymizing foothold
cascades to a staker's entire claim history via the deterministic join (calibration §2). Under
bucketing, the foothold lands on a *commingled* `(tier, bucket)` cohort of `cohort(W)` stakes, so
the cascade's certainty is divided by ≈`cohort(W)` — the adversary recovers "one of these `k`,"
not "this exact account."

**What it does *not* fix (residuals to name with the disposition):**

- **Tier ⅓ is irreducible without V4.** The multiplier needs `tier_num` in clear regardless of
  bucketing; the `1/B` factor stays. De-tiering is the only lever on it, and it is deferred
  (reversion-clause above).
- **Within-stake self-linkage becomes cohort-linkage, not unlinkage.** A single stake's separate
  claims still share `(tier, bucket)`, so they remain mutually linkable — but now *commingled with
  `cohort(W)−1` other stakes' claims*, which is the point. Distinguishing one stake's claims from
  its cohort-mates' **inside the bucket** rests on DDH (distinct `N_S` per epoch-base), i.e. on T7.
- **DDH-dependence (T7) is load-bearing here.** Bucketing widens the cohort; it does not unlink
  claims *within* the cohort — only the DDH split (`x·G_S` vs `x·Hp(O)`, independent NUMS bases)
  does. This is exactly why T7 climbed to the soundness tier (sharpenings table): it is the **sole
  on-chain protection for within-cohort claim unlinkability**.
- **Network layer is orthogonal.** Cohort↔identity is network-owned; bucketing does nothing for it
  (Tor/I2P + per-claim circuit hygiene remain necessary, now scoped as "don't let the network undo
  DDH," per the sharpenings table).
- **Band/amount surfaces unchanged.** Bucketing touches only `creation_height` exposure; it has no
  effect on the inflation surfaces (8a/8b) or the band aggregate.

**Cost is a bounded, tier-relative lock-shift — and this picks `W`.** Rounding `creation` up to
`creation_bucket` extends the effective lock by up to `W` blocks (the stake is treated as created
at the ceiling). Reward accrues over `tier_lock` epochs either way, so there is **no yield-rate
loss** — but capital is locked up to `W` longer, which is an **APY hit that is large for short
locks and negligible for long ones.** Against the archival-doc tier locks
(`V3_STAKER_ARCHIVAL.md`: tier-1 = 1,000-block lock, tier-2 = 25,000, tier-3 = 150,000), a flat
`W = 720` is **~72 % extra on a tier-1 lock** but **~0.5 % on tier-3** — flat `W` breaks the
tier-1 short-lock value proposition.

The clean resolution falls out of the cohort formula: **scale `W` per tier.** Tier-1 (hot-set,
short lock) has the **highest** creation density, so it reaches a target cohort at the **smallest**
`W`; tier-3 (deep-archival, long lock) has the **lowest** density and needs the **largest** `W` —
which it can absorb (0.5 % of 150k). `W(tier)` is publicly computable (tier is already revealed),
so it adds **no new leak**, and it aligns the lock-shift cost with each tier's lock budget. The v1
ratification therefore picks **a per-tier `W(tier)` targeting a cohort floor `k`**, not a single
flat `W`.

**Fixed vs. adaptive `W` — sliding the window to a participant floor.** The natural follow-on is to
*size the window to maintain a minimum cohort `k`* rather than fix it. Two forms, with very
different safety:

- **Hard form (close a bucket once `k` creations land) — rejected.** It makes the ceiling a function
  of *future* chain state, breaking four things at once: **(1) non-causal binding** — a stake created
  as the bucket's 1st member cannot commit `creation_bucket` at creation (the ceiling isn't reached
  yet), defeating the single-canonical-value rule the round-up guard below depends on; **(2)
  reorg-unstable membership** — a stake's bucket (hence `h_bind`, window lower-bound, `eff_lock`)
  would depend on *other* stakes' creations and could flip on reorg, unlike fixed-`W`'s `⌈h/W⌉·W`
  which depends only on the stake's own height; **(3) cold-start deadlock** — the open bucket near the
  tip (and in any quiet period) may never reach `k`, so a new staker cannot finalize a ceiling or
  claim — failing in exactly the regime F0 is worst in; **(4) a new aggregate leak** — the *sequence
  of bucket widths* becomes a high-resolution public readout of `λ(t)` (boundary spacing ∝ `1/λ`) and
  pins each staker's temporal precision to the instantaneous rate. It also hands a Sybil the binning
  knob (flood `k−1` to define the boundary) and, objectively, *caps* the cohort at `k` — spending the
  growth dividend on time-resolution instead of banking it as larger cohorts.
- **Soft form (DAA-style adaptive width) — candidate.** Derive `W` from a *trailing, public* rate
  estimate: `W(tier, epoch) = clamp(⌈k·B / λ̂_tier⌉, W_min, W_max)`, recomputed on an epoch schedule
  and **frozen at binding** (a stake uses the `W` of its creation epoch forever). Because `W` is a
  function of *past, agreed* state it is knowable at creation, reorg-stable over the averaging window
  (the property LWMA-1 DAA and adaptive burn rely on, per
  [`75-system-autonomy.mdc`](../../.cursor/rules/75-system-autonomy.mdc)), and adds **no new aggregate
  leak** — `λ̂_tier` is already public (every creation reveals `tier`; per-tier counts are on-chain)
  and `tier` is already revealed, so `W = f(λ̂_tier, tier)` exposes nothing an observer couldn't
  already compute. It yields a **soft floor** (lagged, not hard-guaranteed), degrades gracefully at
  cold-start (large `W`, clamped at `W_max`, ceiling still known immediately), and **adapts the
  lock-shift cost to need**: `W` is small when staking is busy (the rate alone delivers the cohort, so
  forfeiture is cheap) and large only when quiet (where cover is actually needed) — which directly
  softens the tier-1 lock-shift problem above.

**Estimator primitive — reuse LWMA (the difficulty algorithm), estimator-half only.** `λ̂_tier`
should not be a novel estimator: the LWMA-1 difficulty algorithm already in consensus solves the
*same problem class* — responsive-but-stable rate estimation of a roughly-Poisson arrival process as
a deterministic, reorg-stable function of past chain state — and reusing the ratified primitive
shrinks design and audit surface (and supplies the lag/smoothing the servo discipline above demands).
Three deliberate differences from its difficulty use:

- **Estimator, not controller.** Difficulty LWMA estimates a rate *then retargets to a setpoint*
  (target solve-time). Here there is **no setpoint** — LWMA's recency-weighted average yields
  `λ̂_tier`, and `W = ⌈k·B/λ̂_tier⌉` replaces the retarget. Take the weighted-average half; do not
  import the retarget law. (The only closed loop is through staker behavior — the feedback the clamp
  and slew bound — not a protocol setpoint.)
- **Apply over per-tier, *height-keyed creation counts*, not inter-arrival times.** Creations are
  sparse (tier-3, cold-start), so an inter-arrival LWMA divides by near-zero in quiet windows; a
  per-epoch *count* series degrades gracefully (a zero count is a valid observation → large `W`,
  clamped). Keying on `creation_height` (consensus-ordered height, not wall-clock) makes the estimator
  **immune to the timestamp-manipulation surface difficulty LWMA must defend** (the reason the LWMA-1
  cutover tightened FTL 7200→540 / MTP 60→11) — a place the staking estimator is *cleaner* than
  difficulty.
- **Re-tune the window; responsiveness is double-edged here.** For difficulty, fast hashrate tracking
  is purely good. For an anonymity estimator it is double-edged: fast tracking aids cold-start
  dilution, but a Sybil creation-flood would *quickly* shrink `W` and thin a target's real cohort. So
  the **weight curve is LWMA's linear recency, but the window `N` is the dial and points longer** (more
  smoothing, epoch-scale not block-scale given per-tier sparsity) to resist flood-thinning — tuned for
  the anonymity objective, not copied from difficulty's `N`. This window/weight tuning is a simulation
  item (below), distinct from the difficulty tuning.

**Two honest limits on any window scheme.** **(a)** No bucketing manufactures `k`-anonymity from
*fewer than `k` total stakers* — at genuine cold-start the cohort is the whole population regardless
of `W`; the floor is soft and population-bounded. **(b)** Rate→`W`→staking-incentive is a **feedback
loop** (high `W` in quiet periods raises the cost of staking *when quiet*, further suppressing the
rate and raising `W`); an *unclamped* adapter is self-destabilizing — this is the real "the math
itself creates an aggregate problem" case, bounded the same way the other servos are: clamp
`[W_min, W_max]` + averaging lag + slew-rate limit, per `75-system-autonomy.mdc`.

**Window disposition.** The floor `k` is the *target*; the open choice is **fixed `W(tier)` vs. soft
`W(tier, λ̂)`**, with soft the candidate (it banks growth as cohort *and* trims cost when busy, with
no new aggregate leak — but inherits servo-stability discipline), and the **LWMA estimator-half
(above) is the recommended `λ̂_tier` primitive** (ratified, reorg-stable, audit-surface-reducing).
Exact `k`, the clamps, the slew limit, and the **LWMA window `N`/weight tuning for the anonymity
objective** (longer than difficulty's, to resist flood-thinning) defer to consensus-policy review and
the archival simulation (`docs/V3_STAKER_ARCHIVAL.md` already models staker-population dynamics — the
right tool for the parameter sweep).

**Hard inflation rule (the one thing that must be exactly right): round `creation` *up*.** Round
**down** and `S > bucket_floor` admits epochs in `(true_creation, bucket_floor]` — claiming epochs
*before the stake existed*, which is silent inflation (the 8a/8b class). Round **up** and the
staker simply **forfeits** the sub-bucket epochs `(eligible_height, creation_bucket]` —
inflation-safe, at the bounded yield cost above. This is a coarsening rule plus a rounding
direction: **no circuit, no new primitive.**

**Net judgment.** Bucketing closes the *specific* F0 excess (scale-resistance and
targeted-cascade — the two features that exceeded the accepted staking-exposure budget) at the cost
of a tier-scaled, bounded lock-shift and a publicly-derived `W(tier)`. It does not restore
spend-path-grade privacy (tier ⅓ + within-bucket residual remain), and it relies on T7 for
within-cohort unlinkability. Recommended v1 disposition; ratify `k` (cohort floor) and the
`W(tier)` schedule at consensus-policy review.

###### F0 threat-model input — stakers self-advertise (the share feature is deliberate)

A realism check that bears directly on the F0 calibration: **Shekyl's own staking product is
designed to manufacture a self-advertising staker population.** Shard visualizations
(`docs/V3_SHARD_VISUALIZATION.md`) are deterministic data-art whose stated purpose is cultural
resonance — "cool pictures people share" — with **"print/share rendering" an explicit open
question** (Twitter screenshots, blog portfolios). And archival ties an identity-legible *role* to
tier (`docs/V3_STAKER_ARCHIVAL.md`: **tier-3 = deep critical-history archivist, tier-1 = hot-set**),
so ordinary bragging ("I'm a deep archivist," "just started staking") leaks `tier` and an
approximate `creation_height` for free. The honest expectation is that **a substantial fraction of
stakers will voluntarily reveal they stake**, and some will reveal tier and rough creation time
through normal social behavior. Four consequences for F0:

1. **For self-advertisers, F0's marginal privacy cost ≈ 0.** They have voluntarily made the
   membership disclosure the baseline already priced; the on-chain `(tier, creation)` cohort leak
   adds nothing they did not broadcast. This **reinforces the calibration**: F0 penalizes the
   *privacy-conscious* staker, and we now have a *structural* reason to expect a large self-doxxing
   crowd — the feature is built to encourage it.

2. **For the silent tail, self-doxxing by *others* erodes the cohort by elimination.** Classic
   anonymity-set erosion: if a `(tier, bucket)` cohort has `k` members and `j` self-identify
   publicly, the silent members' effective set shrinks to `k − j`. This is **sharpest exactly where
   F0 is sharpest** — a thin exact-height cohort of 3 where 2 self-identify exposes the 3rd
   completely. Voluntary disclosure by the proud crowd is a direct tax on the private minority.

3. **This strengthens the bucketing case and feeds the `W` choice.** `W` must widen the cohort
   enough to survive **self-doxx attrition**, not merely to reach a nominal `k`: target
   `k − E[self-doxxers]` ≥ floor, not `k` ≥ floor. The self-advertising population is thus a direct
   input to the `W(tier)` schedule above — and note the adverse interaction with the tier-scaled
   refinement: **tier-3 deep-archivists are the most likely to publicly brag** about rare-shard
   holdings, so the long-lock tier (which can afford the widest buckets) is also the tier that most
   needs them.

4. **Second-order vector — cross-track to archival (flag, do not solve here).** The shard-visual
   itself leaks no wallet secret (`V3_SHARD_VISUALIZATION.md` §Privacy derives parameters from
   public shard content only). But the **act of sharing** bridges real-world identity ↔ "a staker
   holding shard-set `{S}`." For active rare-shard hunters the held set is distinctive, and a
   candidate query-routing design is an **on-chain holder registry**
   (`V3_STAKER_ARCHIVAL.md` open question) — which would let an observer bridge
   shared-picture → on-chain holder → (composed with F0) claim-cohort. That is an **archival /
   shard-visual privacy concern that composes with F0** and belongs to *their* privacy review, not
   Phase 2B's wallet path. Recorded cross-track (FOLLOWUPS).

**Disposition.** Threat-model input, not a wallet-code change. It (a) confirms the calibration
direction (sharers opt out of staking privacy by choice; F0's residual harm concentrates on the
silent), (b) makes self-doxx attrition a named input to the `W(tier)` choice, and (c) raises a
cross-track archival item: the share feature + holder-registry + shard-set identity must get their
own privacy review against claim-cohort linkage before `ArchivalEngine` / `shekyl-shard-visual`
ship.

##### F-ARCHIVAL — archival commitment binding is the load-bearing whole-system tier/membership question (gates the F0 `W`-choice) — RESOLVED IN DESIGN (see resolution subsection below)

Reading `docs/V3_STAKER_ARCHIVAL.md` and `docs/V3_SHARD_VISUALIZATION.md` *together* surfaces a leak
that neither addresses alone, and it **outranks the F0 `W`-choice** because it determines whether the
entire chain-side cohort analysis is *sharing-gated* (only self-doxxers expose) or
*sharing-independent* (every staker exposed on-chain by construction). The leak has moved off the
visual artifact and onto three structural couplings the sharing reality activates:

1. **Archival *is* staking.** "If you stake, you archive" (`V3_STAKER_ARCHIVAL.md` — the staking
   software *is* the archival client, not a separate service). So any archival visibility is a
   **staking-membership disclosure**, now wired to a feature engineered for virality — the accepted
   membership baseline gets **opted into at scale** rather than reluctantly.
2. **The portfolio is a tier oracle, by economic design (the one that matters).** The tier-interaction
   design sorts tiers onto shard types (tier-1 → hot/recent, tier-3 → deep/historical; "the reward
   formula should weight by tier, naturally driving critical-history shards toward long-tier holders").
   Economically elegant — but it makes **which shards you hold strong Bayesian evidence of your tier.**
   This is a channel **entirely separate from the claim wire**, and it is *precisely the channel the
   product gamifies you into advertising.* (Weaker secondary signal: shard time-ranges correlate
   loosely with staking era → `creation`.) **Implication for the F0 tier-⅓ "irreducible" finding:**
   tier privacy was never just a claim-wire property — it is a **whole-system property**, and the
   archival layer re-exposes it. The claim-wire tier (`tier_num` in `h_bind` + multiplier, F0) and the
   archival tier-weighted pricing are **two separable levers**; whole-system tier privacy needs **both**
   weakened. This **further devalues de-tiering-the-claim-alone** (you would pay the economic cost *and*
   still leak tier via portfolio composition) — reinforcing the existing reversion-clause parking of
   de-tiering, not reopening it.
3. **Gamification selects for the wrong population.** The most shareable shard is the rarest, and the
   rarest is by definition the **most identifying** (few others hold it). The stakers who opt out of
   quick-pick to hunt rare shards are the engaged, often larger stakers — disproportionately
   **high-value targets** — with the most distinctive, fingerprintable portfolios and the most
   motivation to post them. The feature's social appeal is mechanically a fingerprint disclosure,
   concentrated where it hurts most.

**The load-bearing question (undecided in the docs; the existing draft *leans the dangerous way*).**
Is the archival commitment **publicly address-bound** or **privately bound by a membership proof**?
The archival privacy section covers only *query metadata* (who-asks-for-which-block, closed with
mandatory Tor/I2P); it says nothing about how the *commitment* ("I archive shard X, I earn the
reward") ties to identity. And the existing draft mechanisms — **on-chain challenge-response** to
"shards they claim," an **on-chain holder registry** ("each shard's holders publish presence"), and
reward routing to identified servers — all **lean public address-bound**, which is the default
trajectory unless private binding is *actively designed*. The two outcomes:

- **Public address-bound** ("address A archives shard X, A earns the reward" on-chain): the tier oracle
  and membership disclosure fire for **every staker, on-chain, with no sharing required**. Mandatory
  archival + public binding + tier-sorted shards = every staker's membership and approximate tier are
  **public by construction.** This **dwarfs F0** — we would have hardened the claim's cleartext
  `(tier, creation)` while a sibling layer publishes membership-and-tier for everyone; bucketing and
  de-tiering would both be downstream of a larger leak.
- **Privately bound** (the commitment proves "a bonded stake of mine covers shard X" *without*
  revealing which stake/address; rewards route to stealth outputs; the archival identity is
  **HKDF-separated** from the claim/spend identity): non-sharers stay protected, only sharers expose
  themselves, and all chain-side work retains its value.

**Architectural-consistency presumption favors private; the burden is on public to justify breaking
the pattern.** The rest of staking (claim/unstake) is already a privacy-first membership-proof +
nullifier + stealth model; public archival binding would be the *inherited "it's easier to count if
public" convenience* — the cost-benefit-defer-to-later / user-protection-default anti-patterns of
`16-architectural-inheritance.mdc`. Private binding is **not exotic** — it is the same
membership-proof + stealth-output pattern already in the staking design (data availability is a
public good answerable by anyone holding the shard; only *reward eligibility* needs identity, and that
can be proven privately). **The genuinely hard part — the open cryptographic question — is private
replication counting:** scarcity pricing needs a per-shard replication count (reward ∝ `1/R`), and
counting distinct holders *without identifying them* (private set cardinality / proof-of-distinct-
holders) is the non-trivial primitive public binding gets for free. That tension is *why* public is
tempting and is the thing a private design must solve; it does not change the presumption, but it is
the cost to weigh. **Superseded (2026-06-07):** form **C** makes per-`P` holdings
consensus-public; gate 3 dissolved — `R_market` is a derived ledger count, not ν-hiding
([`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) §2). Privacy is gate 6
(P ↔ principal), not P-holdings hiding.

**Organizing principle — graceful degradation.** A user who shares should disclose *what they chose*
— "I stake, here's cool art" — and not have it silently cascade into tier, claim history, and
inferable amounts. Today the couplings make it non-graceful:
`share → distinctive portfolio → tier (via shard-type) → identity foothold → cohort-collapse → full
attributed history`. **Bucketing softens only the last link; it does nothing for the first three.**

**Reprioritization (this is the clean consequence).**
- **For the sharing majority,** further chain-side cohort refinement is **near-moot** — they have
  handed over a foothold more precise than any cohort. Spending consensus complexity to protect people
  who post their portfolios is misallocated → **reinforces keeping de-tiering parked.**
- **For the non-sharing minority** — the high-value targets the privacy actually exists for —
  chain-side privacy is **load-bearing, but it now depends on (a) the archival binding being private
  and (b) weakening the tier⟺shard-price coupling enough that *mandatory* archival doesn't out their
  tier even when they never share.** **Bucketing alone no longer carries non-sharer privacy** — the
  archival layer can undo it.
- **Timeline.** Archival is V3.x (ships after the V3.0/V3.1 claim path), so this does not retroactively
  break the claim work — but the binding decision must be made **before archival ships** and made
  *consistent with* the claim-privacy posture, and the **pre-genesis discount** (`16-architectural-
  inheritance.mdc`) says design private binding from the start rather than retrofit it forever.

**Disposition — record, do not decide here; highest-priority cross-track open item.** This is an
archival-mechanism design decision with whole-system staking-privacy consequences; it belongs to the
`ArchivalEngine` / `shekyl-shard-visual` design review, not the Phase 2B wallet path. The actionable
set, in priority:

1. **Resolve public-vs-private archival commitment binding** (gates everything else; presumption =
   private, per architectural consistency).
2. **Weaken tier-weighted shard pricing** so portfolio composition stops being a tier oracle — an
   explicit **economics-vs-privacy** choice (it trades the "elegant" tier-archival alignment for
   portfolio privacy).
3. **HKDF-separate the archival identity** from the claim/spend identity so archival visibility cannot
   be joined to stake linkage.
4. **Treat share-UX as a privacy surface** — warn that posting a portfolio links social identity to
   staking history, and that the rarer the shard, the more uniquely it identifies the holder.

Recorded cross-track to `V3_STAKER_ARCHIVAL.md` / `V3_SHARD_VISUALIZATION.md` and `FOLLOWUPS.md`; it
**gates the F0 `W`-choice** (bucketing's value for non-sharers is conditional on private binding +
weakened tier-pricing).

###### F-ARCHIVAL resolution — pay-for-service + firewalled pseudonym (the intended design; supersedes the two-stream framing)

The binding question resolves **private**, and the resolution is bigger than binding: it follows
*Problem 1* ("what useful work do stakers do?") to its end and **rebases the staking reward itself.**
The canonical build-out lives in `V3_STAKER_ARCHIVAL.md` §*Pay-for-service rebasing and the
firewalled-pseudonym identity model*; this is the finding-side summary and gate-list.

**The enumeration.** Archival is the **only** service staking provides. Consensus is PoW's job
(staking has no block-production/fork-choice/finality role — the reason the classic-PoS attack class
was retired). The capital-at-risk "bond" is slashable for nothing, so it bonds nothing (just locked
coins). Supply/monetary effects are achievable by just-holding (no claims/tiers/nullifiers needed).
Governance signaling is downstream of staking existing. Only **archival** is a genuine, growing,
structural network need. So the staking reward **is** payment for archival, "stake without archiving"
is paid-for-nothing (the *Problem 1* rent the design exists to kill), and there is **no opt-out
privacy tier** — privacy is won inside a firewalled pseudonym, not an escape hatch.

**The model (low-new-primitive).** One staker type (archiver); one reward (performance-scaled,
retention-based, scarcity-weighted, banded plateau-cap); principal = locked collateral that **never
slashes** (resilience) and serves as the (small) eligibility/admission gate, **not** a yield
multiplier. Archival cannot be unlinkable like a claim (reachability + persistence + challengeability
require a stable holder), so the goal is a **firewalled pseudonym P**: replace the direct
`StakeEngine::is_active_staker(entity_id)` lookup with **membership-proof registration** ("some active
stake backs me") + an **archival nullifier `N_arch = x·G_arch`** over a base independent of `Hp(O)` and
`G_S` + **HKDF-derived independent keypair** P (no algebraic link to the stake key) + **periodic
liveness re-proof** that lapses on unstake. This **extends T7's DDH requirement to a third base
`{Hp(O), G_S, G_arch}`** that must be mutually independent. **P needs unlinkability + backing-proof,
not uniqueness** — the keystone below carries Sybil-resistance, so one-P-per-stake is no longer
load-bearing. The **firewall is a stack** — network (P's circuits separate from spend/claim
broadcasts), timing (randomized registration delay vs. stake creation), output (reward → stealth
output, no linkable consolidation).

**The keystone — per-shard retention bonds (corrects the longevity framing).** An earlier draft priced
the critical-shard premium on demonstrated **holding-longevity**; that is **insufficient** — longevity
is a *past* signal and deep history needs a commitment to *future* retention. The fix is a **slashable
per-shard retention bond** (post collateral against retaining a deep-history shard for a duration; drop
it → lose the *archival* bond, principal untouched). One mechanism resolves three gaps: (a) the
deep-history guarantee becomes real (bond-at-risk, not inferred); (b) the **staker-wide tier
disappears**, so F0 + the portfolio tier-oracle both close *because bonds replace tier*, not "for
free"; (c) Sybil-splitting buys nothing — **total bond = shards × rate, independent of pseudonym
count** — flipping the scarce input back to expensive-countable capital and **de-overloading the lock**
(small eligibility lock vs. scaling per-shard bonds = two separate parameters). This **re-bases
capital** from "wealth as yield multiplier" to "**slashable service-collateral**" — the accurate
slogan is "pay for work, where doing the work requires proportional capital-at-risk that bonds the
work" (not the earlier "pay for work, not wealth"). The residual is **bond-rate calibration** (a
sim-and-design bind).

**What this replaces, and what dissolves (replace, not converge).** This **replaces** the
confidential-yield subsystem — the entitlement machinery (reserve-DLEQ, bounded-remainder,
`entitlement.rs`/`tiers.rs`/`rewards.rs`) becomes **dead code**, not adapted; a reader who sees
"converge" would wrongly assume the entitlement proof still applies to a subsystem that no longer
exists. What transfers is the **adversarial method** and the **primitives** (membership proofs,
DDH-independent nullifiers, firewall hygiene). Work-based reward is **publicly computable**, dissolving
**three** threads: **F0** (tier left the claim wire — reward no longer needs `tier_num`); the
**portfolio tier-oracle** (no staker tier to signal, *because per-shard bonds replace it*); and
**F-INFLATION 8a → a loud 8c** (no confidential amount in the entitlement — reward recomputable from
public archival history, so silent inflation becomes **detectable** inflation; the existential item
moves to retention-proof unforgeability, public not silent). The only ZK left on the reward path is
membership/backing + stealth payout. Reward is publicly computable **globally** (via the `Σwork` servo,
gate 1), not locally — but *public, not local,* is what kills silent inflation. Privacy stops being
"hide the amounts" and becomes entirely "firewall the identity."

**Gate-list — must be blessed by sim + a fresh soundness pass before consensus-real** (full text in
`V3_STAKER_ARCHIVAL.md`):

1. **Σwork supply servo (supply-safe *and* differencing-clean)** — a per-staker cap does not bound the
   aggregate; the servo is forced, re-based from `band_sum` onto `Σwork` (`reward_P = budget · work_P /
   Σwork`), conceding the "locally computable" claim. But the `band_sum`-differencing leak does **not**
   transfer: `band_sum` leaked because it aggregated *confidential* amounts; `Σwork` sums
   *continuously-public* numbers (challenge-responses, replication counts), so differencing reveals
   nothing not already on P's public record. Strictly better than `band_sum` on privacy.
2. **Retention-proof soundness + state cost (8a → loud 8c)** — reward is "loud" only if every node
   recomputes every P's challenge-pass + replication record → per-P/per-shard retention state **in
   consensus**; the existential item is now **retention-proof unforgeability**, detectable not silent.
3. **`R_market` derived ledger count (gate 3 dissolved)** — count at epoch close from
   retention ledger keyed by public `P_id`; no `ν` primitive. Holdings are consensus-public
   under form **C**; privacy is gate 6 (P ↔ principal). See
   [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) §2–§3.
4. **Per-shard retention bond replacing tier (keystone — collapses old G-D/G-E)** — slashable
   per-shard collateral gives the *future*-retention commitment longevity could not; kills the staker
   tier (→ F0 + oracle close); makes Sybil-splitting worthless (`total bond = shards × rate`); flips
   the scarce input to expensive-countable capital; de-overloads the lock. Residual: **bond-rate
   calibration** (sim output). *Supersedes the old "tier decision / longevity-pricing" framing.*
5. **Bootstrap shape (months 0–6) — overlapped, flat, sunset** — not a cliff if the foundation floor
   **overlaps** (foundation stays full-archival, sheds only as staker coverage is demonstrated); the
   subsidy is **flat per-active-bonded-shard** (privacy-clean; amount-scaled resurrects F0).
6. **`P` backing-and-firewall design (unbuilt; uniqueness relaxed)** — transfer-shaped
   admission (§2.4): off-chain backing presentation + first reward emission on-chain anchor;
   reward dedup on bond-record epoch bitmap (**no** `N_arch` published tag); membership-only
   control on emission. Bonds carry Sybil-resistance; multi-`P` is privacy hygiene only.
7. **Economic sim re-priced for capital-collateralizes-work (gate 7 — foundational)** —
   **couples to admission-principal decision (§2.4 close-condition iii):** if admission lock
   goes soft or away, **bond-locked supply is the sole sink** — re-price `stake_ratio` /
   circulating-supply assumptions in macro sim, not a footnote. Bond-rate (gate 4) is a sim
   output. The strongest pre-genesis argument:
   capital-bonded yield has no justification in the fee-only era (it is the rent the mission forbids,
   the one part that cannot re-justify itself once the subsidy ends), so this is a **genesis-class**
   decision, not a deferrable refinement. The sim is specified (spec-first, pre-code) in
   `STAKER_ARCHIVAL_SIM.md`; iteration 1 isolates **coverage dynamics**, gates 1/4/5/7 layered after.

**Honest residual.** An opted-in staker has a long-lived **public pseudonymous profile** (shard-set,
longevity, performance) *by function*; pseudonym count ≈ active-stake count (an aggregate, accepted-leak
column, like `band_sum`). No individual is deanonymized if the firewall holds across all four layers,
but it is a **discipline maintained over the pseudonym's life**, not a one-time property — and
cross-pseudonym intersection (one person, multiple Ps) re-merges profiles if network/timing/output
hygiene fails per-pseudonym. The keystone makes this a *privacy* hygiene concern, not a *security* one
(multiple Ps buy no bond savings, so running many is not itself an attack).

**Scope — genesis binding (2026-06).** This **replaces** the confidential-yield subsystem
(reserve-DLEQ entitlement, bounded-remainder, `tier_num·amount`; `rust/shekyl-staking/`
`entitlement.rs`/`tiers.rs`/`rewards.rs`) rather than extending it — a large audit-surface
deletion, which is the point. **Pre-genesis discipline:** implement **once** against this
substrate; do **not** land Stage 3 on the entitlement claim path and plan a post-genesis
migration. `CONFIDENTIAL_STAKING.md` is edited **surgically** — retain principal
lock / `C_stake` / unstake membership machinery; **delete or never implement** the
claim-entitlement wire (`txin_stake_claim_v2` tier/`h_bind` reward path) in favor of
the `P`-mediated pay-for-archival reward surface. Sim gate 4 (bond rate) and gate 1
(`Σwork` normalizer) pins are **closed or in flight**; Tier 1 crypto soundness
([`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) step 3) gates consensus-real
implementation. Nutshell: **staking is the opt-in to archival because staking =
archiving**. Reward is accounted under public **`P`**; **privacy on the reward path
is gate 6 firewall discipline** — not "P solves F0" (F0's substrate is deleted).

##### F0 disposition on the rebased substrate (supersedes bucketing gate for genesis)

**Do not read this as "P solves F0."** Three mechanisms — see §2.1 *Identity* and
status block:

1. **F0 dissolved by model deletion.** F0 was structural leakage on the confidential
   claim wire (`tier`, `creation_height` → `{tier × creation-window}` cohort). Work-based
   reward removes `tier_num`; per-shard bonds replace the tier oracle; the claim wire
   is **not shipped**. F0 is not mitigated — its substrate is gone. Bucketing
   (`CONFIDENTIAL_STAKING.md` §14.4 item-9) is **moot** for genesis.
2. **`P` addresses archival's problem, not F0's.** Archival requires a stable,
   reachable holder; privacy becomes **firewalled pseudonymity** (public `P`, hidden
   principal link) — a threat **substitution**, not F0 closure.
3. **Gate 6 firewall is the unbuilt privacy work** — long-lived `P` profile +
   cross-pseudonym intersection if hygiene slips; bonds carry Sybil-resistance so
   multi-`P` is hygiene-only.

**Genesis Round 3 closure:** F-ARCHIVAL gate-list + **§2.4 close-conditions (i)–(iii)** +
gate 6 to soundness-pass depth (Tier 1 step 3). Not F0 bucketing. **(i) spec:**
[`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md).

##### F-INFLATION — split T8 on the **retired** entitlement substrate (historical wargame record)

Silent inflation is the existential class — the two worst bugs in privacy-crypto history are
both invisible-inflation (**Zcash's BCTV14 counterfeiting flaw**, patched in secret; **Monero's
2017 RingCT inflation bug**). When amounts are hidden, a soundness flaw is undetectable
infinite inflation — you learn it from the price chart, not the chain. Confidential staking
adds **two** fresh soundness surfaces beyond the spend path; T8 is split along this line and
gets the round's heaviest rigor (both are consensus-owned; the wallet's role is non-masking
per §7.5 T8, but the round must name both surfaces so the audit covers them):

- **(8a) Entitlement-proof soundness.** Can a prover make the verifier accept a `C_claim`
  committing to more than `floor(N·amount/D)`? Bounded-remainder + range proof close `ρ ≥ 0`
  and `reward < 2⁶⁴`, but **`full reward ≤ entitled` rests on the reserve-DLEQ-class
  soundness** (§6.4.1). This is the heaviest audit item.
- **(8b) Band-declaration binding (co-equal, newly elevated).** If a staker can declare a
  **more-favorable band than the committed amount warrants**, they inflate their `M` / `ρ_e`
  allocation **at zero cost and invisibly** (the amount is committed). The defense exists —
  §4.4's "range proof binding the band to `C_stake` (anti-lie)" — but the round's pin is that
  **this band↔amount range proof must carry the same rigor as the value range proof**, not be
  treated as a lesser check. Inflation via band-lie is as catastrophic as inflation via
  entitlement-lie.

##### Sharpenings to existing dispositions

| Item | Sharpening from the synthesis | Added pin / disposition |
|------|-------------------------------|-------------------------|
| **T9** (+ A1) | **Induced-duplicate knife.** A lying daemon (A1) reports a nullifier `N_S` as *unused* when it is not, inducing the wallet to broadcast a **duplicate claim**. Consensus rejects it — but the duplicate `N_S` is now **revealed**, which trivially links the two claim attempts (the one thing nullifier-unlinkability was protecting). | **Wallet pin:** daemon-reported claimability is **advisory, never a license to reveal a second nullifier**. The wallet treats its own derived `{x·G_S}` ∩ chain as authoritative and must not re-emit an `N_S` it has already broadcast on daemon say-so. |
| **T13** (+ A1) | **A1 has three distinct knives:** (i) broadcast **origin** (T1/T4/T14), (ii) **query-leak** (asking "is epoch `S` of this stake claimed?" links the wallet to its stake), (iii) **induced-duplicate** (T9 above). | **Pin (sharpens T13):** full **local scan, no selective per-stake/per-nullifier queries** — already the bulk-fetch invariant; the synthesis confirms it defends knife (ii). |
| **T1 / T4 / T14** (A1/A2) | **F0 re-scopes the network layer — three layers separate cleanly.** With `(tier, creation)` in clear, **cohort linkage is chain-owned** (on-chain deterministic; only F0 moves it — circuit hygiene buys *nothing* against cohort-level linkage). But hygiene is **not** futile: **within a cohort, a single stake's separate-batch claims stay unlinkable *only* by DDH** (distinct `N_S` per epoch-base), and the network re-links exactly what DDH protects if the **same circuit submits them**. So: **(a) cohort linkage = chain-owned**, **(b) within-cohort claim unlinkability = DDH-owned, network-preserved**, **(c) cohort↔identity = network-owned.** | **Per-claim circuit hygiene earns its keep as "don't let the network undo DDH," not "break the claim sequence"** (the chain already linked the sequence to the cohort). **Two questions folded into the T1/T4/T14 FOLLOWUP (V3.1):** (a) does the broadcast path obscure origin **beyond "send over Tor"** (Dandelion++-equivalent — defends layer (c))? (b) is **circuit hygiene per-claim** (fresh circuit per broadcast — defends layer (b))? **Batch-default value narrows** to fewer identity-correlation events + fewer claim-tx fingerprints, **not** sequence-unlinkability. |
| **T10 / G12** (A2) | **The claim tx leaks stake age off the wire.** A claim is structurally distinguishable (membership + per-epoch nullifiers + entitlement + reward output), and **nullifier count = epoch count**, which leaks the stake's **age and claim cadence** directly — "claims every 30 epochs in fixed batches" is a signature. | **Round decision (FOLLOWUP V3.1):** explicitly decide **accept the epoch-count leak vs pad** to a fixed count with dummy nullifiers (uniform but expensive), and **standardize claim construction deterministically** so wallet-version fingerprints don't add a second axis (G12). |
| **T3** (A2/A4) | **Public-rate whale/cold-start readout.** `band_sum` drives `ρ_e`, so a staker large enough to move `band_sum` makes their entry/exit visible in the public rate; at cold start `ρ_e` is a low-noise readout of a small staker set (dynamics observable, not just the static cohort). | **Cross-track confirm (sharpens T3):** the §14 servo + `band_sum`-differencing gate must be confirmed to **bound single-staker observability**, not merely smooth the aggregate. |
| **T5** (A3) | **Two named residuals + a constant-time requirement.** (i) `Copy` `AtomicUnits` can leave un-zeroized copies (**accepted**). (ii) the **view key is resident**, so an A3 who reaches `KeyEngine` RAM has everything regardless — the reason full-transient bought less than it seemed (**recorded, not re-solved**). (iii) **claim-build crypto must be constant-time** — a co-located timing/cache side-channel on the Schnorr / membership / nullifier scalar work extracts `x` or `z` directly. | **Stage-3 pin (added):** claim-build scalar operations **constant-time** (`30-cryptography.mdc`). Residuals (i)/(ii) recorded as accepted/known. |
| **T7** (elevated by F0) | **No longer a hygiene footnote — F0 makes DDH the *sole on-chain protection* for within-cohort claim unlinkability.** Once the chain links a stake's claim *sequence* to its cohort (F0), the only thing keeping a stake's separate-batch claims unlinkable *within* that cohort is DDH across independent NUMS bases (distinct `N_S = x·G_S` per epoch-base). T7 therefore **climbs toward the soundness tier** — it is co-load-bearing with the inflation surfaces, not an assumption footnote. | **On record (priority-elevated):** `G_S` must be a **verifiable nothing-up-my-sleeve** generator with **no relation to `Hp`**, and DDH must hold for the curve; if independence is fudged, **(i)** claim and unstake link by construction **and (ii)** within-cohort claim unlinkability collapses (the chain having already supplied cohort linkage). `AUDIT_SCOPE.md` load-bearing assumption, ranked adjacent to 8a/8b. |
| **T6** | The reorg-double-claim defense (claim epoch `S`, induce reorg that keeps the minted reward but reverts the nullifier, re-claim `S`) **rests entirely on §11's all-five-members-in-one-txn atomicity** (reward output + nullifier revert together or not at all). | **Audit pin:** this atomicity is **load-bearing and cannot be hand-waved** — the audit must confirm **no member (reward output, nullifier, `band_sum`, subtree leaf, key image) can revert independently of the nullifier**. |

##### A5 — economic / rational adversary (new model)

Added to A1–A4: **rational agents optimizing yield** (staking vs. unstaking/other uses),
**MEV extractors**, **stake-rental markets**. Real-world parallels: deep-reorg double-spends
via hashrate rental (ETC/BTG/VTC), LST depeg/bank-run dynamics, MEV-driven reorgs/sandwiching
of claims/unstakes, coordinated unstaking waves when yields drop.

- **Mass-unstaking / bank-run dynamics.** Yield-chasing can produce coordinated unstaking
  waves **without malice**. Shekyl's decaying-emission share + fee-burn servo + `ρ_cap` are
  designed to self-stabilize, **but this is unverified under a rational mass-unstaking
  shock**. **Disposition: cross-track to economics + FOLLOWUP (simulation required)** — the
  burn-servo stability under a coordinated-exit scenario must be **simulated**, not asserted
  (the economics design docs already call for stability simulation; this names the specific
  scenario).
- **MEV on claims/unstakes.** Re-confirms §7.5 G13: claims bind to the staker's own
  nullifier (non-competitive, idempotent to ordering) → no extractable front-run value;
  censorship → retry. **No change.**

##### Architectural advantages — recorded, not just N/A

The §7.5 "N/A" results for slashing (G1) and delegation (G2) are not gaps — they are a
**genuine architectural advantage** worth stating as a result: confidential-claim staking
(an economic overlay on PoW, not validator-PoS) **structurally excludes an entire class** of
attacks that delegated-PoS systems spend enormous effort on — **slashing-griefing /
correlation-penalty backfire, nothing-at-stake / cheap fork-voting, long-range history
revision, stake-bleeding / equivocation, 33% BFT disruption, and stake-grinding.** There is
no validator, no cheap fork-vote primitive, and PoW + the `h_bind`/`eligible_height` canonical
height (§2) make long-range revision expensive and detectable. Naming this tells an auditor
the classes were **considered and excluded by construction**, not missed.

##### Economic-redesign note — can the `tier` axis be removed at the source? (deferred V-future; reopening criterion below)

F0's irreducible privacy residual (option-2(i) above) is the **tier** reveal: the multiplier
`N = tier_num(tier)·ΣK_S` is tier-specific, so `tier` must be in clear regardless of any
`creation` bucketing. This raises an economic-redesign question (raised 2026-06-05): **tiers
exist to price duration commitment — what if reward were *derivative* (a single global
rate/function of already-committed quantities) instead of a staker-declared discrete tier?**

**Structural analysis (the answer to "tier, then height, then nothing?"):**
- **Removing `tier` removes the tier axis — a real F0 win.** A derivative/uniform reward needs
  no per-stake `tier_num`, so the `tier` field leaves the wire and the cohort drops from
  `{tier × creation_height}` to `{creation_height}` (or `{creation_bucket}` with option 2). The
  ~⅓ per-tier partition disappears.
- **Removing `tier` does *not* remove `creation`/height.** Any **time-accrued** reward needs a
  **provable accrual-start**, and proving it is the **same 3C-vs-3A choice already settled**
  (§6.4.3): either reveal `creation` in cleartext (the lower-bound window check stays pure
  arithmetic, inflation-safe, no new primitive) or adopt the **rejected** non-membership-at-
  historical-root primitive. Tree membership alone never proves *when* a leaf entered — that is
  exactly why 3C stamps `creation` into `h_bind`. So **"leaving only height" is the answer**;
  the cohort reduces to `{creation_bucket}`, fully tunable by the option-2 width dial with **no
  tier subdivision** — the cleanest cleartext end state.
- **"Nothing" only if reward stops being time-accrued** (e.g., a one-shot principal-proportional
  bonus with no duration component) — a larger economic change that abandons the duration
  incentive entirely, not just the tier discretization.

**The cost is economic, not cryptographic.** Tiers are the lever that **prices duration
commitment** (longer lock → higher yield, reducing velocity / stabilizing the staked set). A
single uniform rate removes that lever; a continuous derivative-of-*declared-duration* reward
**re-introduces a per-stake duration reveal that is finer-grained (worse for privacy) than the
3-valued tier** — so the only privacy-improving derivative is one whose rate does **not** depend
on a staker-chosen duration. That is the crux the economics track must weigh.

**Disposition (decided 2026-06-05): deferred V-future — *not* a forced move; the round is *not*
opened now.** The economics are a **designed counterweight** and de-tiering would unbalance the
system for a privacy delta that the baseline-budget calibration (above) shows **bucketing
likely already closes**. Per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)
this is **reject-now-with-reopening-criterion**, not refuse-forever: **reopen only if a specific
high-value-target threat model shows the within-tier within-bucket cohort (the residual after
option-2 bucketing) is unacceptable for a staking population the project must protect.** If
reopened, it is a **consensus-economics change** (`CONFIDENTIAL_STAKING.md` + the economics
docs), needs its own spec-first design round per `05-system-thinking.mdc`, and composes with
option 2 (no-tier + `creation` bucketing → `{creation_bucket}`). Logged as a V-future
cross-track FOLLOWUP under F0; it does **not** gate Phase 2B or Round 3 closure.

##### Synthesis closure status

The synthesis **confirms** the §7.5 wargame's dispositions except where sharpened above, and
surfaces **F0 as the round's top finding on the then-current confidential-entitlement
substrate** (2026-06-05). **Genesis substrate update (2026-06):** F-ARCHIVAL pay-for-service
rebasing **supersedes F0 as a Round 3 closure gate** — tier leaves the reward path, identity
moves to **`P`**, entitlement claims are not shipped. The wargame record (F0 analysis,
8a/8b inflation split, T7/`G_S` on the claim wire) remains **audit history** for the retired
path; do not implement against it.

**Round 3 closure on the rebased substrate** ratifies the F-ARCHIVAL gate-list (§7.5.3 /
`V3_STAKER_ARCHIVAL.md`) and pins Stage 3 against:

1. **Tier 1 crypto soundness** — `P` registration/backing, archival-state contract
   ([`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md); gate 3 dissolved), L14
   crediting, retention-proof unforgeability (loud 8c); [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md)
   soundness pass step 3.
2. **`Σwork` supply servo** — gate 1; replaces `band_sum`-differencing normalizer on the
   reward path.
3. **Per-shard retention bonds** — gate 4 pin closed (`ARCHIVAL_BOND_FLOOR`); calibration
   record in sim.
4. **Gate 6 firewall stack** — network / timing / stealth payout for `P` (**the**
   unbuilt priority-2 work; privacy = firewall discipline, not hidden amounts).
5. **Principal-path carry-forward** — committed `C_stake`, unstake membership spend, wallet
   §3.3.1 opening discipline, §5 nullifier rebuild **where still applicable** on the rebased
   payout path (exact claim-tx shape is a Round 4 pin, not the retired `txin_stake_claim_v2`
   entitlement wire).

Residual forward actions that **still apply** on the rebased substrate: T5 constant-time
secret-touching crypto; T9 advisory daemon claimability (adapted to `P`/challenge state);
A5 mass-unstaking / `Σwork` shock sim; reorg + `AtomicUnits` boundary tests. **Retired with
the entitlement path:** F0 bucketing, 8a/8b entitlement circuit, tier on claim wire.

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
- [x] User method signatures signed off (§6). **Batch landed (2026-06-05):** owner-grade `StakeView` pinned (per-stake `claimable` + `claimed_epochs` + `unlock_height`) with the owner-grade caveat and a **distinct** lens-3 redaction that names `claimable`/`claimed_epochs` as the **derived-value** class the secret-class redaction does not cover (Fork A); `StakeFilter` made **total 1:1 over `StakeState`** + `All` sentinel (item 5); abandon-claim discard wiring keyed on an **orchestrator-held** `ReservationId → (stake_id, epochs)` map — `PendingTx` carries no claim discriminator (verified at source, stays spend-pure; item 3); pre-stake projection omission documented (item 4); FA-1 regrounded to single-static-address + independent-accounts reopen-pointer (Fork B); stale §3.3 opening doc-comment fixed (item 1). **`AtomicUnits` landed (2026-06-05):** §6 `claimable` / `claimable_rewards` + `StakeOpening.amount` carry the `AtomicUnits` domain newtype from `shekyl-units` (interim PR before broad wiring; see [`ATOMIC_UNITS_NEWTYPE.md`](ATOMIC_UNITS_NEWTYPE.md)). The §6 method set and amount type are both signed off.
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
