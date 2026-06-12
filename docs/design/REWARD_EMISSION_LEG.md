# Reward emission leg — consensus specification (genesis)

**Status:** Design spec — **Layer 1 structural core closed** for
[`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §2.4 close-condition **(i)**.
**Pinned:** form **C** (§4.0); state dedup (§6); lagged §4.4 read (§4.5 collapsed).
**Un-implementable until:** [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md)
(archival read contract + `MAX_CLAIM_AGE_W`) — emission **consumes** archival state it does not define.
**Gate 3 dissolved (2026-06-07):** no `ν` primitive; `R_market` derived from serve-credit ledger.
**Admission wire:** ordinary transfer, **no consensus minimum, no `C_stake`** (§7.2–§7.4;
gate 7 closed bonds-only 2026-06-11, §10.2).
**Layer 2:** margin-robustness band **closed 2026-06-11** (§1.2 #4) — spread gate re-anchored
on direct whale gauges; `g` sealed as band `[1.5, 2.5]`, target `≈ 2`; `Curve` reserve untriggered.

**Scope:** The **consensus-special reward emission transaction leg** for pay-for-service
archival under firewalled pseudonym **`P`**. This document is the byte-layout and
verifier contract. It **supersedes** the confidential claim wire (`txin_stake_claim_v2`,
entitlement circuit, `N_S = x·G_S`, published `N_arch`) for genesis.

**Out of scope here (separate specs):** gate 6 off-chain backing presentation; gate 4
bond post/slash object wire (except fields this leg reads/writes); gate 1 `Σwork`
budget schedule source; gate 2 retention-proof **construction** bytes (interface in
[`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md)); wallet FSM (`PHASE_2B`
§3 — **unblocked**, retool in parallel).

**Upstream:** [`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md) §*Pay-for-service
rebasing*; [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §2.4;
[`FOUNDATION_GENESIS_IDENTITY_SET.md`](FOUNDATION_GENESIS_IDENTITY_SET.md) §4
(`HoldingsDescriptor`).

---

## 1. Close-condition (i) — what this spec must establish

| Requirement | Disposition in this doc |
|-------------|-------------------------|
| Reward dedup = per-`P` **claimed-settlement-epoch state** on bond record | §6 — `check_and_set(E)`; **no** published cryptographic tag |
| **No** `N_arch`, **no** `N_S`, **no** stake-keyed emission nullifier | §9 — explicit rejection table |
| Crypto bill = **membership-only control** + public work + public mint | §5, §7 |
| Verifier can detect inflation (loud 8c) | §4 — amounts recomputed from public state |
| Reorg atomicity | §8 |
| Nothing on the wire **forces** a published dedup tag | §5.3, §9 |

Close-condition **(ii)** (per-reward proof aggregate at `N_P` × cadence) **closed
(2026-06-11)** via the worked byte sweep — see §10.1. Close-condition **(iii)** **closed
bonds-only (2026-06-11)** via the gate-7 iteration-5 sim — see §10.2.

### 1.1 Design sequencing (four layers, gated)

Work is **not** parallel-equal. Lower layers gate higher ones.

| Layer | Scope | Gate |
|-------|--------|------|
| **1 — Consensus structural core** | **Closed at spec layer** — this doc. **Implement blocked on** [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) implementation (contract pinned). Owed crypto: `FcmpMembershipOnly::verify`; 8c construction may trail interface pin. | Spec right pre-genesis; code waits on schema impl. |
| **2 — Economic keystone** | **Margin-robustness gate closed** (§1.2 #4, 2026-06-11): band run confirmed the decomposition — spread gate **re-anchored on direct whale gauges** (`mxSW`, `wB4`, per-band seats; `gini_actor` → trend); **`g` sealed as band `[1.5, 2.5]`, target `≈ 2`** (`g ≥ 3.0` fails coloc coverage at any purse); purse confirmed as spread lever. `Curve` reserve not triggered (stays V3). Gate 7 **closed bonds-only**; byte aggregate (ii) **closed** (§10.1–§10.2). | Layer 2 fully closed; reversion clauses live in the sim doc results section. |
| **3 — Operational / firewall** | Gate 6: `P` HKDF, multi-`P` hygiene, announce-before-anchor. **FSM retool unblocked** — ordinary-transfer admission, reward reception, `EpochSet` → absolute sparse set on bond record. | Load-bearing for privacy. |
| **4 — Document rebase** | Round 0 / threat model → F-ARCHIVAL+`P`; claim-centric `PHASE_2B` §3–§7 historical; FCMP §15 / 3C retirement. V3 gate-1 / form **C** reconciled. | Corpus consistency; parallel with schema pin. |

**2026-06-07 Layer 2 discipline gate (spread windowing):** `sprdW` = mean `gini_actor` + peak
`max_actor_share` over `churn_window` (L9 lesson). Full sweep **266** scenarios: snapshot
**138**/266 vs windowed **139**/266 pass spread; **zero** snap-pass→win-fail flips; **one**
snap-fail→win-pass (`gate4_coloc_5.50`, far above pin). At **`bond_rate* = 0.75`**: benign
rows `giniW ≈ 0.593–0.599` (snapshot grazes at **0.600**); at **1.00** both fail (`≈ 0.626`);
thin lean `l11_bud_b50` fails both at `≈ 0.84`. **Verdict:** keystone **holds** — Layer 2 is
**calibration, not shape reopen** — but the margin is a **hair**, not a plateau.
*(Definition superseded 2026-06-11: the band run re-anchored `sprd`/`sprdW` on the direct
whale gauges — `max_actor_share < 0.20`, `wB4 < 0.20` — with `gini_actor` demoted to trend;
implemented in the sim same day. The pass counts above are the pre-re-anchor record.)*

**Sim reconciliation (2026-06-07 — load-bearing for calibration reads):**

1. **`gate4_fine_*` is endogenous L11** (`l11_base()`, `init_active_frac=0`, `ρ=0.02`) — not
   fixed-pop. The keystone pin scenarios are the right family for spread at genesis economics.
2. **`l11_bud_b100` `giniW ≈ 0.71` is not a conflicting attractor** — that sweep uses default
   `bond_rate=2.0` from `baseline()`, not pin `0.75`. At `bond_rate=0.75`, `gate4_fine_0.75`
   parks at `giniW ≈ 0.593` steady-state (tail series stable below 0.6) — **not** a bootstrap
   transient.
3. **`churn_stable` metric (2026-06-07 bank):** was coded as participation abandonment
   (`churn < 0.05`) but certifies **coverage oscillation** (`max(oUmx, serving_oUmx) < 0.05`).
   At pin, `oUmx = 0` while participation churn ≈ 0.17 — benign rotation with backfill slack
   (L9/L11). Sim re-pointed; pin rows pass `all_pass` on spread + coverage oscillation.
4. **Declining-tail `Curve`:** off the lean-margin lever set (V3 §912–917 population gate) — reserved
   for mature-network hoarding only.
5. **Budget lever:** strongest participation lever but gate-1/7 monetary decision (more archival
   emission). At pin bond `0.75`, spread may clear at `budget=100`; budget sweeps at `bond_rate=0.75`
   still needed for margin headroom and coverage/churn — not to fix a failing 0.71 attractor.

**Thin-margin read (carry into calibration, not file as closed):**

1. **Edge of feasible pocket.** `gate4_coloc_0.75` windowed **0.599** against threshold **0.600**
   — a parameter nudge loses spread. Bond **1.00** fails both reads; thin purse fails badly.
   Room at the pin: **~0.001–0.007** on `giniW`.
2. **Whale is the binding scenario under windowing.** `gate4_fine_0.75_whale`: snapshot
   **0.581** → windowed **0.594** (windowing **worsened** concentration). Benign means improved
   or held; adversarial trend eats the margin. **`g(age)` calibration for deep coverage must be
   checked against whale-window trend**, not the benign mean alone — the deep↔spread entanglement
   is the **active Layer-2 constraint**.

**Sim ↔ spec coherence (load-bearing):** Track 1’s windowing verdict transfers to this spec
only if `shekyl-staking-sim` uses form **C** with **Σ capped** in the denominator. **Verified
(2026-06-07):** `reward.rs` sets `sum_capped = Σ_a capped[a]` where `capped[a] =
Curve(work_a)` (plateau-cap), then `price = budget / sum_capped` and `reward_a = price ·
capped[a]` — i.e. `budget·capped_P/Σcapped`, **not** `budget·work_P/Σwork_raw`. The spec sync
corrected prose drift; the sim predates the explicit §4.0 pin but was already aligned. Form **C**
is anti-concentration at the budget layer (capped whale share redistributes via the rate); if
anything, it should **widen** margin vs a miscomposed servo — the reported thin margin is real,
not a sim/spec mismatch artifact.

### 1.2 Forward path — four consequences of pinning Layer 1

Nothing to re-litigate on form **C** or `sprdW` verdict. Pinning the emission leg
changes what is next:

1. **Archival consensus read contract is the critical path.** Loud 8c recompute reads
   serve-credit ledger, shard registry, derived `R_market`, and bond-record `good_through`
   from state this doc does not define (§5.4). The leg is fully specified **at its layer**
   and **un-implementable** until [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md)
   is implemented. Gate 3 **ν dissolved** — `R_market` is ledger-derived. 8c **soundness**
   (proof construction) may defer; the **read contract** cannot.

2. **§4.5 is smaller than its old three-row table.** §4.4 already commits the
   all-recorded accumulator finalized at epoch close. §4.5 is only **lagged read** of
   that table + boundary/reorg rules (§4.5). Claimed-only / two-phase options are
   **named reopen**, not a live architectural fork.

3. **Unbounded reward-accounting state needs `MAX_CLAIM_AGE_W`.** `ClaimedEpochSet`,
   per-`(P, shard, E)` serve-credit rows, and per-epoch `Σwork` accrete without bound — the
   gate-2 "irony" (archival accounting in replicated state) made concrete. Pin
   consensus-visible `W`: epochs older than `W` unclaimable; state prunes; tradeoff
   with gate-6 deliberate `P` lapse. See archival-state doc §2.4.

4. **Thin spread margin is genesis-seal robustness risk.** Reframe Layer 2 from
   "find the `g(age)` that passes" to **margin-robustness across the operating band**
   with whale-trend bounded throughout. **Run and closed 2026-06-11**
   (`STAKER_ARCHIVAL_SIM.md` §*Layer-2 margin-robustness band — results*): the
   decomposition held decisively across the band — whale gauges flat (`mxSW`
   0.013–0.018 vs 0.20 bar, `wB4 = 0`, whale Δ`giniW` ≤ 0.003) while `giniW`
   tracked leanness (`bondA`) in both sweep directions. Disposition: **spread
   gate re-anchored on the direct whale gauges** (`gini_actor` demoted to trend);
   **`g` sealed as a band `[1.5, 2.5]`, target `g ≈ 2`** (upper bound is coloc
   coverage oscillation at `g ≥ 3.0`, purse-incurable); budget cross confirms the
   gate-1/7 purse as the spread lever (+30 % purse ⇒ `giniW` 0.598 → 0.475, the
   L13 servo's static image). The declining-tail `Curve` reserve was **not
   triggered** and stays a V3 reserve. The 2026-06-07 single-point readings are
   superseded (banded PL Curve repair moved the equilibrium — the reframe's
   warning made empirical); the `bond 0.75` pin stands under the re-read.

**Genuinely unblocked:** §3–§7 FSM retool (principal form, reward-reception state);
gate 6 firewall rigor; V3 form **C** reconciliation.

**Single next move:** pin [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md)
— gates implementability and carries remaining Tier-1 crypto interface (8c home).

---

## 2. Design principles

1. **Loud reward.** Emission carries **public** work and **public** mint amounts.
   Verifiers **recompute** payout from consensus archival state + gate-1 budget; the
   prover does not author an unbounded confidential entitlement.
2. **State-based dedup.** Double-claim prevention is `bond.claimed_settlement_epochs`
   updated atomically at verify time — not a spend-tree nullifier and not a
   stake-keyed tag on the vin.
3. **Membership-only backing.** The prover shows spend authority over backing outputs
   on the **main FCMP++ tree** without inserting `x·Hp(O)` into the spent key-image
   set. This is a **strict subtraction** from today's `FcmpPlusPlus::verify` (which
   always requires key images per input).
4. **Registration fusion.** **join-Market** ([`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md))
   creates the on-chain bond record (holdings + bond posture + empty dedup set) via
   `txin_archival_bond_post` — **before** the first **paying** emission (§4.5 lag).
   There is no separate *registration transaction type* in the retired stake sense.
   **Gate 6 requires** off-chain announce + backing **before** join-Market.
5. **Bond posture vs mint.** Bond create/update/slash/re-bond is gate 4; reward mint +
   dedup is this leg only — never bundled as “first emission creates everything.”
6. **Bond is the intra-epoch honesty anchor.** Between settlement-epoch emissions,
   funds at `P` may be spent freely; backing is not re-verified every block. Challenge
   failure slashes **bond** regardless of `P`'s UTXO state (§7.5).

---

## 3. Time granularity

| Constant | Value (genesis pin) | Role |
|----------|---------------------|------|
| `SETTLEMENT_EPOCH_BLOCKS` | **10_000** | Global boundary; inherited from confidential-staking epoch table ([`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §5) until migrated to `config/consensus_constants.json` |
| `settlement_epoch(height)` | `height / SETTLEMENT_EPOCH_BLOCKS` | Integer division; boundaries are chain-wide |
| `MAX_SETTLEMENT_EPOCHS_PER_EMISSION` | **15** | Max epochs batched in one emission vin; bounds work vector and dedup batch size (same envelope as retired `MAX_EPOCHS_PER_CLAIM`) |

**Cadence:** At default 120 s block time, one settlement epoch ≈ **13.9 days**.
Emission is **expected once per settlement epoch per `P` with positive work**, not every
block.

**Wallet default:** batch all unclaimed epochs with `work > 0` in one tx when
`|epochs| ≤ 15`; single-epoch emission is test-mode only (timing tell — same discipline
as retired claim drip).

---

## 4. Economics — three-channel reward stack (verifier-side)

### 4.0 Genesis pin — `Curve` ∘ servo composition (E-1)

Three expressions appeared across authoritative docs; **one** is genesis-pinned. The
wrong orderings have different monetary consequences — this is not housekeeping.

| Form | Expression | Verdict |
|------|------------|---------|
| **A — post-servo cap (rejected)** | `raw_P = budget·work_P/Σwork_raw` then `reward_P = Curve(raw_P)` | **Rejected.** When any cap binds, `Σ_P raw_P = budget` but `Σ_P Curve(raw_P) < budget` — **budget strands** with no pinned disposition (burn? roll? redistribute?). Anti-concentration is implicit at best. |
| **B — servo only (rejected)** | `reward_P = budget·work_P/Σwork_raw` (no `Curve`) | **Rejected.** Per-staker aggregate unbounded; V3 gate-list item 1’s servo without the plateau-cap. |
| **C — cap in numerator, normalize (pinned)** | `reward_P = budget·Curve(work_P)/Σ_{P'} Curve(work_{P'})` | **Genesis pin.** `Σ_P reward_P = budget` whenever `Σ Curve > 0`. A capped whale’s foregone share flows **proportionally** to other market archivers via the rate — the redistribution V3’s “leaves *S* scarce for someone else” prose describes, as a **budget** property not only coverage. |

**Notation below:** `capped_P(E) := Curve(work_P(E))` and `Σwork(E) := Σ_{P'∈Market} capped_{P'}(E)`.
Then `reward_P(E) = budget(E)·capped_P(E)/Σwork(E)` (integer floor per payout; rounding
disposition pinned at gate 1).

**Reversion clause:** A **deflationary** cap that **burns** the residual
(`Σ Curve < Σ raw` ⇒ unminted budget destroyed) is a deliberate gate-1/7 monetary policy —
not the default. It must be chosen explicitly; it must not fall out of an unstated
composition.

**Sim coherence:** `shekyl-staking-sim` (`reward.rs`) implements form **C** with denominator
`Σ_a Curve(work_a)` — confirmed at `reward.rs` (`sum_capped` / `price = budget/sum_capped`).
Spread sub-claims (`sprdW`, 2026-06-07) are evaluated under this composition; see §1.1
coherence verification.

### 4.1 Stack (channels 1–3)

The reward is **not** generic “budget × work / Σwork.” It is the pinned three-channel
stack (form **C** above), aligned with
[`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md) §*reward curve*:

```text
scarcity(s,E)  = (1 / R_market(s,E)) · g(age(s))     // channel 1: self-diluting scarcity
work_P(E)      = Σ_{s ∈ held(P,E)} scarcity(s,E) · serve_credit_bit(P,s,E)
capped_P(E)    = Curve(work_P(E))                     // channel 2: concave plateau-cap (per P)
Σwork(E)       = Σ_{P'∈Market} capped_{P'}(E)         // channel 3: market-only denominator (§4.2)
reward_P(E)    = budget(E) · capped_P(E) / Σwork(E)   // integer floor; loud on vin; Σ = budget
```

**Channel 1 — scarcity.** `R_market` is the public replication count; holding a shard
raises `R` and dilutes its own `1/R`. `g(age) = 1 + age_weight·age` (public shard
property) is the privacy-clean deep-history premium replacing retired tier weighting;
`age` is the shard's **relative depth fraction** `∈ [0, 1]` (settlement epochs since
freeze over chain depth in settlement epochs — `ARCHIVAL_REWARD_ARITHMETIC.md`
§Shard age), so `g` spans `[1, 1 + age_weight]` for the life of the chain.
`serve_credit_bit` is the challenge-pass bit from consensus archival state (gate 2), not
retrieval volume.

**Channel 2 — `Curve`.** Per-`P` concave-to-plateau cap on credited work (the sim’s
`cap` parameter). Marginal credited work above the plateau is zero unless the operator
opens another pseudonym — which carries gate-6 firewall cost, not a free Sybil split.

**Channel 3 — competitive share.** `budget(E)` from gate 1; each market `P` receives
`budget · capped_P / Σwork`. Adding credited work raises `Σwork` and dilutes everyone
(including self). When one `P` hits the plateau, others’ shares rise — explicit
anti-concentration at the budget layer (form **C**).

**Inflation posture (8c):** Verifiers recompute all three channels; any mismatch between
`reward_P(E)` and minted outputs is a **consensus error visible to all verifiers**.

**Hints:** The vin may carry `budget`, `Σwork`, or intermediate values as **hints** for
light clients; full nodes recompute authoritatively.

### 4.2 Market-only denominator — foundation excluded (E-2)

`Σwork(E)` sums **market archivers only** (`P' ∈ Market`). The foundation holds the
complete tree but is **reward-invisible** (gate 5) and excluded from `market_R`; the
servo denominator inherits the same exclusion — extending the two-count discipline
([`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md) consumer table) to the
**denominator explicitly**.

If foundation work entered `Σwork`, it would dilute every market archiver’s share while
earning nothing — a silent tax. **Genesis pin:** foundation `P` ids (if any on-chain
bond record) do not contribute to `Σwork`.

**Bootstrap consequence (form C):** With few market archivers, `Σwork` is small but ≥
`Curve(positive work) > 0`, so the first market archiver with positive work earns
`≈ budget` (bounded, not a raw-share blow-up). Whether early-epoch full-budget payout
wants a gate-5 **budget ramp** is a separate call; denominator scope is not.

### 4.3 `WorkClaimVector` maps to channel 1

§5.4 carries per-shard `scarcity_milli` (fixed-point `(1/R)·g(age) × 1000`) and
`serve_credit_bit` so verifiers recompute `work_P(E)` before applying `Curve`.

**Fixed-point pin:** `scarcity_milli = floor((1/R)·g(age) · 1000)` (integer, zero
tolerance at verify). Effective **R ceiling:** for `g(age) ≥ 1`, `R > 1000·g(age)` rounds
scarcity to zero — a dead zone where the `1/R` signal vanishes at high replication. Genesis
pin: **3 decimal places** suffice while `R_market` stays within protocol replication
bounds (deep `R_target` ≪ 1000); reopen if gate 3/5 permits `R` large enough to zero
most shards’ scarcity under this scale.

### 4.4 `Σwork` accumulator — maintained state (minor pin)

`Σwork(E)` is **not** recomputed from scratch on every emission vin (which would re-walk
the full archiver ledger per tx). Consensus maintains a **per-settlement-epoch
accumulator**:

```text
Σwork_acc(E)  finalized at epoch E close from continuous recording
              (each market P's capped_P(E) updated as challenge/serve-credit state settles)
```

Emission vins **read** the finalized accumulator; they do not author it.

### 4.5 Lagged read, boundaries, reorg (genesis pin)

§4.4 **is** the all-recorded mechanism: at settlement-epoch `E` close, finalize
`Σwork(E) = Σ_{P'∈Market} capped_{P'}(E)` from DB state for every market `P` with
recorded work, claimed or not. §4.5 adds only **how emissions cite it**:

**Lagged read:** Emissions for earned epoch `E` cite `Σwork(E)` stored at **close of
`E`**, typically in settlement epoch **`E+1`** or later within **`MAX_CLAIM_AGE_W`**
(§6.6). Batching up to 15 epochs in one vin uses the per-epoch stored totals for each
`E` claimed.

**Monetary consequence (accepted):** Offline or forfeiting `P` still contributed
`capped_P(E)` at close → claimers slightly diluted; that share **unminted** (supply-safe).

**E-3 coupling:** Slashed `P`'s recorded `capped_P(E)` **stays in** `Σwork(E)` for that
epoch — determinism over slash-order-dependent denominator surgery.

**Boundary rules (gate 1 seal — small):** Late emitters after epoch close use the same
stored `Σwork(E)`; no wallet-local recompute. Reorg: revert finalization and accumulator
with epoch disconnect ([`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) §2.3).

**Named reopen (not carried as live fork):** **Claimed-only** denominator — full budget
to claimers, but requires two-phase / provisional+true-up machinery and inflation-bound
proofs. Reopen only with explicit spec for that machinery; §4.4 does not implement it.

---

## 5. Transaction envelope

### 5.1 Accepted tx type

`RCTTypeFcmpPlusPlusPqc` only ([`60-no-monero-legacy.mdc`](../../.cursor/rules/60-no-monero-legacy.mdc)).

### 5.2 Vin layout

A reward emission transaction contains:

1. **Exactly one** `txin_archival_reward_emission` (this spec).
2. **Zero or more** `txin_to_key` inputs paying **fee** from `P` (or principal) with
   ordinary FCMP++ proofs and **key images** in the spent set.
3. **Forbidden:** `txin_stake_claim`, `txin_stake_claim_v2`, cleartext stake claim inputs.

### 5.3 `txin_archival_reward_emission` — logical fields

```text
ArchivalRewardEmissionVin {
  P_pubkey:           HybridPublicKey,     // wire version per FOUNDATION_GENESIS §5
  holdings:           HoldingsDescriptor,  // must match bond record after first emission
  settlement_epochs:  u64[MAX],            // 1 ≤ MAX ≤ 15, strictly increasing, unique
  work_claim:         WorkClaimVector,     // per-epoch public work breakdown (§5.4)
  backing:            MembershipOnlyBacking, // FCMP++ membership, NO key image (§7)
}
```

**Not present on the wire (rejected if required by legacy code paths):**

| Field | Why absent |
|-------|------------|
| `tier`, `tier_num`, `creation_height`, `h_bind` | F0 substrate deleted |
| `N_S`, `G_S`, nullifier vector | Dedup is bond state |
| `N_arch`, `G_arch` | Conflated backing vs dedup; both jobs replaced |
| `entitlement`, `ρ_blind`, `C_claim` confidential leg | Loud reward |
| Staking-subtree membership root | 3C not genesis; backing is **main tree** |
| `admission_proof` | Gate-7 closed bonds-only (§10.2); admission has no consensus role |

### 5.4 `WorkClaimVector` (public)

For each `E` in `settlement_epochs`, the vin carries a **public** breakdown sufficient
for verifiers to recompute `work_P(E)`:

```text
WorkEpochClaim {
  epoch:              u64,
  shard_entries:      ShardWorkEntry[],  // bounded by holdings descriptor
}
ShardWorkEntry {
  shard_id:           ShardId,           // consensus shard identifier (gate 2)
  serve_credit_bit:   bool,              // must match challenge state at E
  scarcity_milli:     u32,               // fixed-point scarcity × 1000 (integer recompute)
}
```

**Consensus rule:** Recomputed `work_P(E)` from archival DB **must equal** the vin's
implied work (within fixed-point tolerance **zero** — integers only at consensus). Mismatch
→ `invalid_emission_work`.

**Gate 2/3 (interface deferred to archival-state spec):** `shard_id` encoding,
challenge-record keying, and `R_market` at `E` are pinned in
[`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md). This leg **consumes** that
ledger; retention-proof **construction** bytes may trail the interface pin.

### 5.5 Vout layout

- **One or more** FCMP++ outputs credited to **`P`**'s stealth address material.
- **Plaintext reward amounts:** `reward_amount_plain: u64` per epoch (or one total +
  epoch list) carried in the vin **and** reflected in output amounts such that:

```text
Σ vout.amount_plain == Σ_{E ∈ settlement_epochs} reward_P(E)
```

Pedersen commitments still serialize for RCT balance, but **emission mint is not
confidential** — range proofs bind non-negativity; the **entitled amount is public**
on the vin (loud inflation check).

**Stealth addressing:** Outputs use `P`'s output derivation (same as ordinary receives);
privacy is **recipient hiding on the output set**, not hidden reward mathematics.

---

## 6. Bond record — dedup and lifecycle

### 6.1 Keying

Consensus archival state maps **`P_canonical_id`** → `ArchivalBondRecord`.

```text
P_canonical_id = cSHAKE256(
  customization = "shekyl/archival-p-id-v1",
  input         = P_pubkey.canonical_bytes()
)[0..32]
```

(Same discipline as `StakeId` / foundation pubkey commitments — [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §3.3.3.)

### 6.2 `ArchivalBondRecord` (consensus)

```text
ArchivalBondRecord {
  P_pubkey:                 HybridPublicKey,
  holdings:                 HoldingsDescriptor,
  bonded_total_atomic:      u64,       // gate 4 accounting
  good_standing:            bool,
  join_market_height:        u64,       // gate 4 JoinMarket block
  join_settlement_epoch:     u64,       // E_join; counting/claims from E_join + 1 (gate-4 §2.2)
  first_paying_emission_height: Option<u64>,  // set on first mint vin
  claimed_settlement_epochs: ClaimedEpochSet,  // §6.3; empty at join
  // gate-4-owned extensions: bond_event_log, escrow, last_served_epoch — gate-4 §4.1
}
```

### 6.3 `ClaimedEpochSet` — dedup semantics (amends wallet `EpochSet` reuse)

**Semantics** (relocated from wallet `claimed_epochs` / §3.3.2):

```text
check_and_set(E): bool
  // returns false if E already claimed; else inserts E and returns true
```

**Encoding (genesis pin):** Per-`P` **sparse set of absolute settlement-epoch indices**
`E`. Consensus-visible semantics only; **not** the retired 2-byte **relative** `u16`
mask from tier-bounded stake claims.

**Concrete encoding (decided 2026-06-11, `W = 26` pinned):** an **inline field on
`ArchivalBondValue`** — strictly-increasing list of absolute epoch indices, `u32` count +
`u64` BE per entry, hard cap **32** entries (`W = 26` plus reorg slack; cap violation is a
decode error like the existing `kMax*` bounds). `ArchivalBondValue` bumps **v3 → v4**; v3
rejected at decode per the pre-genesis posture (no migration; reset data-dir). Pruning to
`E > tip_settled − W` rides the existing §6.6 forfeiture sweep and is an optimization only —
correctness comes from E-3 forfeiture rejecting out-of-window claims *before* dedup is
consulted, so a stale entry can never enable or block a valid claim. Why inline, not the
alternatives:

- **Emission verify reads the bond record anyway** (`good_through`, `E_join`); one decode
  covers the whole ≤15-epoch batch. A separate table costs up to 15 point reads per vin on
  the verify hot path plus its own `pop_block` revert plumbing; inline reverts atomically
  with the record rewrite the reorg path already performs.
- **Size is a non-issue:** ≤ 26×8 = 208 bytes against a record already carrying a ~2 KB
  hybrid pubkey, and the counted-vector shape matches `held_shard_ids` / `bad_intervals`
  precedent.

**Rejected encoding options (pre-genesis):**

- **Fixed bitmap over `(tip − W, tip]`** (`u32` fits `W = 26`) — requires a base-epoch
  rebase as the window slides (per-record mutation at epoch close, or lazy-rebase logic
  whose failure mode is exactly the double-claim-after-window-slide bug the relative mask
  was retired for); saves ~200 bytes per record, which is noise.
- **Separate LMDB table, composite key `P_canonical_id ‖ BE(E)`** (the
  `archival_serve_credit` precedent) — viable but strictly worse here: see hot-path and
  revert-plumbing costs above.
- **LMDB `MDB_DUPSORT` dup-keys `(P_id, E)`** — collides with Shekyl composite-key
  discipline ([`LMDB_SCHEMA.md`](../LMDB_SCHEMA.md): no DUPSORT on Shekyl-native tables).
- **Roaring bitmap** — dependency unjustified at `W = 26`
  ([`17-dependency-discipline.mdc`](../../.cursor/rules/17-dependency-discipline.mdc)).

**Reversion clause:** reopen the encoding (bitmap or separate table re-enter) only if `W`
is re-pinned above ~64 epochs (inline cap stops being trivially bounded) or if measured
emission-verify cost shows record decode dominating; re-evaluation is a constants-cluster
amendment plus this section, not a semantics change.

**Why not reuse the u16 relative mask:** Stake claims were bounded to ≤15 epochs over
a **tier lock window**. Archival `P` accrues settlement epochs **without a tier lock
upper bound**; a 16-bit relative window would allow double-claim after window slide.
The wallet §3.3.2 encoding remains valid for **historical documentation** of the
retired claim path only.

**Reopen criterion:** If consensus proves an upper bound on simultaneous unclaimed
epochs per `P` ≤ 16 at all times, a relative mask may return; until then, absolute sparse
set is genesis.

**Growth bound:** Without a claim-age window the set grows without bound. §6.6 pins
`MAX_CLAIM_AGE_W` and prune semantics jointly with gate-2 serve-credit state.

### 6.6 `MAX_CLAIM_AGE_W` — claim-age window (genesis pin)

**Problem:** State dedup as absolute sparse sets plus per-`(P, shard, E)` serve-credit
and per-epoch `Σwork` accumulators accrete forever — archival reward accounting in
replicated consensus state with no prune rule.

**Pin (2026-06-07 — [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md)):**

```text
MAX_CLAIM_AGE_W : u64 = 26    // settlement epochs; ~361 d @ 120 s/block, SEB 10_000
```

For current settlement epoch `C`, emission for epoch `E` is rejected if `E < C - W`
(unclaimable — forfeited). Effects:

- `ClaimedEpochSet` semantics bounded in practice (verify rejects ancient `E`).
- Finalized `Σwork(E)` for `E < C - W` droppable from hot consensus tables.
- Per-`(P, shard, E)` serve-credit rows reclaimable after `W`.

**Tradeoff:** `P` offline longer than `W` loses older unclaimed epochs. Gate-6 decorrelation
may deliberately lapse `P` — `W` trades **state growth** against **lapse forfeiture**.
`W` is consensus-visible (not wallet policy). Full keying and prune sweep in
[`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) §5.

**Drain vs batch cap (F4, 2026-06-07):** `W` and `MAX_SETTLEMENT_EPOCHS_PER_EMISSION` (§3,
**per `P` per emission**, cap 15) are one invariant. A continuously-honest `P` with a
`W`-deep backlog must drain before the oldest epoch crosses `tip − W`, given settlement-
epoch cadence and the per-`P` batch limit. **Signed** at `W = 26`, batch `15`, `SEB = 10_000`
(`shekyl-staking-sim --timing-cluster`).

### 6.4 join-Market (gate 4 — not this vin)

Bond record **creation** is **`txin_archival_bond_post` / `JoinMarket`**
([`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §2–§3). This leg **does not**
create records. Precondition for any paying emission: record exists with
`join_settlement_epoch = E_join` stamped; counting and claims from **`E ≥ E_join + 1`**
([`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §2.2).

### 6.4.1 First and subsequent paying emissions

**Requires** existing `ArchivalBondRecord` for `P_canonical_id`. Reject if missing
(operator must join-Market first).

1. Verify `holdings` compatible with stored record (no silent portfolio swap without
   gate-4 `HoldingsUpdate` / re-bond flow).
2. For each claimed epoch `E`: require `E ≥ E_join + 1`; `good_through(E)`; dedup; lagged
   `Σwork(E)` read (§4.5).
3. On first paying emission: set `first_paying_emission_height = current_height` if `None`.
4. Apply `claimed_settlement_epochs.check_and_set(E)` for each epoch in vin.

**Dependency (consume, not define):** slash, re-bond, holdings mutation — gate 4 bond-post
vin; this leg reads resulting `ArchivalBondRecord` fields only.

### 6.5 Good standing — per-epoch eligibility (E-3)

**Genesis pin:** Eligibility for epoch `E` in a batched vin is evaluated **per epoch at
epoch close**, not by current `good_standing` gating the entire batch.

For each `E` in `settlement_epochs`, emission is rejected unless, for every shard in
`work_claim(E)`:

- `P` held the shard through `E` per archival state, and
- The challenge for `(P,s)` relevant to `E` **passed** (grace window pinned at gate 4), and
- `good_through(E) == true` — `P` was not slash-invalidated **before the end** of
  settlement epoch `E` (slash timestamp / height recorded in bond state).

**Slash after honest service does not forfeit earned epochs.** A `P` that served epochs
`E₁…Eₖ` honestly, then fails a later challenge and is slashed, may still claim
`E₁…Eₖ` in one batched emission **provided** `good_through(Eᵢ)` held for each claimed
epoch. Slash blocks **future** epochs and new service; it does not retroactively void
epochs already earned under per-epoch rules.

**Denominator interaction (§4.5):** A slashed `P` that **never claims** earned epochs still
left its `capped_P(E)` in the all-recorded `Σwork(E)` at epoch close — honest claimers were
slightly diluted; that portion of `budget` was unminted. Determinism over “remove on slash.”

**Batching vs forfeiture (§3):** The default batch (up to 15 epochs) is compatible with
this pin — operators are **not** forced to claim frequently to avoid losing honest work
to a later slash. Frequent single-epoch claims remain test-mode (timing tell).

**Current posture** (`good_standing` on the bond record) still gates **new** emission
attempts for epochs **after** slash and bond re-establishment flows (gate 4).

**Interval encoding (F3):** `good_through(E)` is derived from a bonded/slashed/re-bond
**event log** with interval semantics at epoch close — not `slash_epoch > E`. Re-bond
after slash must restore good-standing for post-rebond epochs without retroactively
voiding pre-slash honest epochs (example and verifier rule in
[`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) §3.4).

---

## 7. Cryptographic verification

### 7.1 Order of checks (consensus)

Apply in order; fail-fast:

1. **Structural** — tx type, vin counts, epoch list monotone unique, `|epochs| ≤ 15`.
2. **Bond posture** — record **exists** (join-Market already done); holdings match;
   `E ≥ E_join + 1` for all claimed epochs.
3. **Dedup** — for each `E`, `claimed_settlement_epochs.check_and_set(E)` (atomic with
   block connect).
4. **Archival work** — recompute `work_P(E)` from state; compare to `work_claim`.
5. **Economics** — recompute three-channel `reward_P(E)` (§4); compare to `reward_amount_plain` and vout sum.
6. **Membership-only backing** — §7.2.
7. **FCMP++ balance** — ordinary RCT balance equation including mint; fee inputs use
   standard key-image path.

(There is **no admission-threshold step**: gate 7 closed bonds-only — §7.4, §10.2.)

On `pop_block`, reverse **3** (revert dedup bits) and bond mutations from **4–6** in
block disconnect order (§8).

### 7.2 Membership-only backing (ordinary transfer, not `C_stake`)

**Disposition (gate 7 closed bonds-only, 2026-06-11 — §10.2):** admission funding is an
**ordinary FCMP++ transfer** to `P`’s stealth address on the **main tree**, with **no
consensus minimum**. There is **no `C_stake` / confidential admission opening** on the
genesis path unless gate 4/7 reopens with a demonstrated monetary reason to keep the
admission stake confidential.

**Statement:** Prover knows opening for one or more **ordinary** outputs on the current
main-chain FCMP++ root that collectively satisfy:

```text
backing_ok(P, roots) :=
  each output is spendable by P's key material (ordinary transfer to P)
  ∧ membership valid under FcmpMembershipOnly at reference block
```

The membership proof attests **spend authority and bond posture only**:
`bonded_total_atomic == bond_floor(holdings)`
([`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §3.2) — there is no admission UTXO
threshold (the `Σ amount ≥ ADMISSION_MIN_ATOMIC` conjunct was deleted at the gate-7
close; reinstatement requires the gate-7 reversion clause to fire).

**Unspent-proof wall:** The transfer-shaped admission model plus the unspent-proof
discipline lean **away** from settled-retained confidential principal machinery.
Pedersen commitments and range proofs on the admission path survive **only** if a named
gate 4/7 reopen supplies a monetary reason for confidential admission amounts.

**Verify API (new):** `FcmpMembershipOnly::verify(input, witness, reference_root)` —
proves spend authority **without** producing a key image consumed by the spent set.
Today's `FcmpPlusPlus::verify` **must gain** a per-input mode flag or sibling type;
reward emission is the first consumer.

**Independence:** Backing outputs are **main-tree** leaves, not staking-subtree (3C
deleted).

### 7.3 Backing proofs and linkability (E-4)

**Consensus does not require backing-output rotation.** `FcmpMembershipOnly` is
zero-knowledge over the FCMP++ anonymity set: repeated membership proofs of the same
leaf do **not** publish a key image and are **not** linkable by the proof statement
alone.

**Gate-6 hygiene (optional, named threats only):** Wallet policy may rotate backing
UTXOs for **non-proof** correlation — timing, amount clustering, mempool metadata,
fee-input linkage — per the gate-6 firewall spec. Those are operational threats, not
consensus lemmas; they must be named there. This leg does not impose rotation as a
verify rule.

### 7.4 `ADMISSION_MIN` amount proof — deleted (gate 7 closed bonds-only)

**Resolved 2026-06-11 (§10.2):** gate 7 closed close-condition (iii) **bonds-only**, so
the optional amount proof this section held open is **deleted, not gated**: no
`admission_proof` vin field (§5.3), no `ADMISSION_MIN` branch in `backing_ok` (§7.2), no
admission-threshold verify step (§7.1). `ADMISSION_MIN_ATOMIC` has **no consensus role**,
and gate-6 §2.5 pins **no wallet-policy minimum either** — there is no funding minimum
at any layer. Reinstatement requires the gate-7 reversion clause
([`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) ledger G7) or the gate-6 §2.5
reversion clause to fire.

**Wallet FSM implication:** Stage 3 manages **ordinary-transfer funding** of `P`, not
`C_stake` openings or claim-pending state. See §11.

### 7.5 Intra-epoch unbacked window (explicit safety lemma)

Between emissions, `P` may spend its funding outputs while still listed as serving. The
verifier **does not** re-check full retention on every block. Safety relies on:

> Challenge failure at any time → bond slash (gate 4) → `good_standing` false → **future**
> epochs ineligible; **past** epochs with `good_through(E)` remain claimable (§6.5).

Document in threat model §7 retool; this spec states the **consensus dependency** on
slash hooks.

---

## 8. Reorg

On block disconnect at height `H`:

1. For each `txin_archival_reward_emission` in the block, for each epoch `E` claimed,
   remove `E` from `bond.claimed_settlement_epochs` for that `P`.
2. Revert minted amounts from monetary supply accounting (same path as coinbase undo).
3. Re-run forward on reconnect.

**Bond record creation revert** is gate 4: delete record on **join-Market** block
disconnect (`join_market_height == H`) — [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §5.
Paying-emission disconnect reverts dedup only (step 1); does not delete the record.

Wallet ([`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md) P2B-5): re-fetch bond record;
refresh claimed-epoch cache; `Bonded` → `AdmissionPending` on join-Market revert.

---

## 9. Rejected surfaces (genesis)

| Surface | Disposition |
|---------|-------------|
| `txin_stake_claim` / `_v2` | Delete — not consensus |
| Entitlement / reserve-DLEQ / bounded remainder | Delete |
| `N_S = x·G_S` stake-claim nullifier set | Delete |
| `N_arch = x·G_arch` published tag | Delete — dedup is §6 |
| ClaimLinkability / non-spending SAL sibling | Not built — membership-only suffices |
| 3C staking subtree, `h_bind`, 5-scalar leaf | Docs-only deletion |
| Tier fields on reward path | Delete |
| Confidential reward amount | Delete — §5.5 |

---

## 10. Hooks for remaining close-conditions

### 10.1 Close-condition (ii) — proof aggregate: CLOSED (2026-06-11)

**Resolved by the worked byte sweep**
([`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) §*Close-condition (ii)*, ledger row
AGG). Per-emission size is dominated by **constant-size crypto** (hybrid pubkey + two
ML-DSA-65 auths + FCMP++ membership ≈ 15 kB), not the work claim
(`|epochs| × portfolio × 13 B` — ≤ 780 B/epoch at year-30 lean portfolio). At a 20 kB
per-emission margin, the aggregate across the `N_P` envelope {40, 79, 154} amortizes to
**80–310 B/block = 0.027–0.103 %** of the 300 kB penalty-free zone; single-tx max
(15-epoch batch) ≈ 29 kB; boundary burst drains in ≈ 11 blocks at thick with zero
spreading. The wire as specced is confirmed: `SETTLEMENT_EPOCH_BLOCKS = 10_000` and
`MAX_SETTLEMENT_EPOCHS_PER_EMISSION = 15` stand as pinned (§3); no format change.

**Caveat carried:** `FcmpMembershipOnly` is sized at 1-input `FcmpPlusPlus` order until
built (it proves strictly less). **Reversion:** reopen iff the built proof exceeds 3×
that estimate, the `N_P` envelope re-pins above ~1 500, the epoch re-pins below
1 000 blocks, or **the operating envelope extends below `N_P` ≈ 25–30** (thin
direction, swan-2/W9 — the L13 servo floor is 17 and L17 swan troughs reach ~9;
per-archiver claims scale as `1/N_P`, a 15-epoch batch ≈ 70 kB at `N_P` = 17
year-30 and grows with chain age; the named guard is a per-emission claim cap
forcing batch splitting); re-evaluation is a sweep re-run with measured sizes.

### 10.2 Close-condition (iii) — admission principal: CLOSED bonds-only (2026-06-11)

**Resolved by the gate-7 iteration-5 sim**
([`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) §*Gate 7 iteration-5 — results*,
ledger row G7): the derived archival lock collapses to `bond_floor × R × shards(t)` at
`lock/circ ≤ 10⁻⁴` in every arm, and all three macro gauges (burn servo, release factor,
net inflation) are insensitive to both admission arms at every `N_P` — the pre-named
indeterminate criterion resolves **bonds-only**. Consequences executed in this spec:

- `admission_proof` removed from the vin (§5.3) and the verify order (§7.1).
- `backing_ok` loses the `Σ amount ≥ ADMISSION_MIN_ATOMIC` conjunct (§7.2).
- §7.4's optional amount proof is deleted, not gated.
- `ADMISSION_MIN_ATOMIC` is **not a consensus constant**; gate-6 §2.5 additionally
  pins **no wallet-policy minimum** (no funding minimum at any layer).

**Reversion:** reopen only per the gate-7 reversion clause (bond floor / shard geometry
re-pinned ≥ 3 OOM upward combined, or a new archival lock class lands); re-evaluation is
a `--gate7` re-run plus this section, not a new design round unless a gauge moves.

---

## 11. Wallet / `StakeEngine` build flow (informative)

Not consensus — orients Stage 3 (Layer 3 FSM retool):

**Delete:** `claim_pending_epochs`, `PrepareClaimBuild`, claim-staleness, entitlement
rescan, `C_stake` admission openings.

**Add:** `P` lifecycle (HKDF derivation, multi-`P` hygiene), **ordinary-transfer
funding** of `P` (no minimum at any layer — gate-6 §2.5 pin; funding shape/timing
hygiene still applies), off-chain announce-before-anchor, reward reception (loud
amounts), bond post/slash reaction.

1. Gate 6: announce `P` + present backing off-chain; ensure recognized before first emission.
2. Wait until settlement epoch `E` closes (or batch unclaimed `E…`); apply §4.5 accumulator rule.
3. Read public challenge state → build `work_claim` (channel 1).
4. Locally compute `capped_P` and expected `reward_P(E)` via `Curve` + gate-1 `Σwork`.
5. Select ordinary backing UTXOs on `P`; build `MembershipOnlyBacking`.
6. Assemble `txin_archival_reward_emission` + fee `txin_to_key` + stealth vouts.
7. Broadcast; on confirm, wallet marks epochs claimed in local bond mirror.

---

## 12. Implementation checklist (pre-code)

- [ ] **Pin gate 2/3 archival-state schema** — [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) (blocks all emission implementation).
- [ ] Pin `MAX_CLAIM_AGE_W` + prune rules (joint with schema).
- [ ] Seal §4.5 boundary/reorg at gate 1 (lagged §4.4 read; slash stays in denominator).
- [ ] Add `SETTLEMENT_EPOCH_BLOCKS`, `MAX_SETTLEMENT_EPOCHS_PER_EMISSION` to
      `config/consensus_constants.json` + generators.
- [ ] C++ / Rust vin deserializer for `txin_archival_reward_emission`.
- [ ] `ArchivalBondRecord` LMDB table + `pop_block` revert.
- [ ] **`FcmpMembershipOnly::verify`** in `shekyl-oxide` FCMP++ crate (line-441 gap).
- [ ] Delete / gate `check_stake_claim_input`, `txin_stake_claim`, `C_stake` admission paths.
- [ ] KAT vectors: minimal valid emission + double-claim reject + work mismatch reject.
- [ ] Update `AUDIT_SCOPE.md` §staking — entitlement out, emission in.
- [x] Layer 2: gate-7 admission re-pricing sweep — **closed bonds-only 2026-06-11** (§10.2).
- [x] Layer 2: per-reward byte aggregate — **closed 2026-06-11** (§10.1; ≤ 0.11 % of
      penalty-free zone across the `N_P` envelope).
- [x] Layer 2: margin-robustness band — **closed 2026-06-11** (§1.2 #4; spread gate
      re-anchored on direct whale gauges, `g` band `[1.5, 2.5]` sealed, target `≈ 2`).

---

## 13. Related documents

| Doc | Relationship |
|-----|----------------|
| [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §2.4 | Parent shape |
| [`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md) | Economics + `P` model |
| [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §5–§6 | **Retired** claim wire; §5 epoch length still authoritative until constant migrated |
| [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) | **Critical path** — gate 2/3 schema + `W` |
| [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) | Gate 6 — `P`↔principal firewall (parallel) |
| [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) | Layer 2 margin-robustness; (ii) byte sweep |
| [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) | Membership proof base |

---

## Revision note

**2026-06-06:** Initial reward-emission leg spec — PHASE_2B §2.4 close-condition (i)
structural core.

**2026-06-07:** Sync to three-channel reward stack + sim-validated economics; §4.5
accumulator timing fork open (joint gate 1); ordinary-transfer admission (no `C_stake`);
four-layer sequencing; spread windowing discipline gate (keystone holds at `bond_rate*`);
P announce-before-anchor.

**2026-06-07 (E-1–E-4):** Pin form **C** `Curve`∘servo composition (§4.0); reject
post-servo cap and servo-only; market-only `Σwork` (§4.2); per-epoch `good_through(E)`
(§6.5); drop consensus backing-rotation rule (§7.3); `Σwork` accumulator (§4.4);
`scarcity_milli` scale pin (§4.3); gate-4 holdings-mutation dependency (§6.4).

**2026-06-07 (analysis pass):** Thin-margin spread calibration (§1.1; whale-window binding);
sim↔spec coherence verified (`reward.rs` Σ capped); §4.5 reframed as denominator **scope**
(all-recorded lagged leading; claimed-only rejected); E-3 slash stays in denominator.

**2026-06-07 (forward path):** Layer 1 closed at spec layer; §1.2 four consequences;
§4.5 collapsed to lagged §4.4 read + boundaries; §6.6 `MAX_CLAIM_AGE_W`; Layer 2 →
margin-robustness gate; [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) as
single next move; FSM retool unblocked.
