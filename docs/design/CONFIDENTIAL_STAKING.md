# Confidential staking — consensus & economics design

**Status:** Round 1 in progress. **§6.4 source review closed** (2026-06-02): **(A)**
entitlement dispositioned off-circuit; **(B)** claim nullifier surface + `N_S = x·G_S`;
**(C)** tier/creation on hidden leaf remains the architectural gate. Other §13 items
open.
This is the **upstream consensus/economics truth** that
[`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §2.3 mirrors. It
**supersedes the reward/claim mechanism** of
[`STAKER_REWARD_DISBURSEMENT.md`](STAKER_REWARD_DISBURSEMENT.md) (proportional
pool-division, cleartext amounts, public `staked_output_index`, monotonic watermark),
which is retained for history until this lands.

**Process discipline:** [`26-sub-pr-design-discipline.mdc`](../.cursor/rules/26-sub-pr-design-discipline.mdc).
**Binding constraint:** [`00-mission.mdc`](../.cursor/rules/00-mission.mdc) priority-1
(security) then priority-2 (privacy). Pre-genesis: this is structural work in the
bounded window; hard forks signal planning failure, so the construction is designed
to be launch-final.

**Origin:** design session 2026-06-02. Code-site citations are to `blockchain.cpp`
(6322 lines) and the `shekyl-staking` / `shekyl-economics` FFI verified that session;
FCMP++ / SAL / witness layout were **source-reviewed** for §6.4 (2026-06-02;
`main` @ `34b2b3c`); **(C)** and claim wire format remain open (§13).

---

## 0. Threat model anchor

Adversary: a global passive chain observer plus an adaptive participant who can
stake / unstake / claim and may later compromise a wallet. Consensus state is public.

**Confidential (must hide):**
- individual staked **amount**;
- the **link** between a claim and the stake it draws on, and between a staker's
  successive claims;
- the claim **reward amount**.

**Public by necessity (the ceiling — stated, not worked around):**
- the **existence** and **tier** of a stake event (v1; hiding stake-existence/tier is
  L4, deferred — §13);
- a **coarse band** of the staked amount (governance + rate servo — §4, §8);
- the **per-epoch aggregate** `band_sum` (an aggregate over all stakers; identifies
  no individual above a cohort threshold — §0.2);
- claim **timing**, modulo network-layer defenses (§6.5).

### 0.1 The irreducible constraint

You cannot have (a) hidden individual amounts, (b) an **exact** per-epoch aggregate
`TWS` revealed as plaintext, and (c) no new trust assumption, simultaneously: `TWS` is
a sum of Pedersen commitments, and revealing its value needs the aggregate blinding,
which no single party holds. The proportional model
(`reward = pool × w / TWS`, `blockchain.cpp:4366–4376`) buys a public `TWS` with the
amount leak. This design does **not** try to extract an exact aggregate from hidden
amounts; it routes around the wall (§3, §4).

### 0.2 The privacy principle (pinned)

> Protect the **unlinkability** of individuals to their actions and the **absence of
> persistent per-individual fingerprints**; treat population aggregates as public
> **unless they can be differenced or fingerprinted down to an individual.**

Consequences: the exact amount is hidden (a strong fingerprint that amplifies
off-chain linkage); a coarse band is tolerable (a weak fingerprint, and it is what
governance needs); the `band_sum` aggregate is public but must resist **differencing**
(coarse + windowed) and is only safe **above a cohort-size threshold** (cold-start
caveat — §4.4).

---

## 1. Design fork resolution

Three coherent models were considered; this design selects **(B)** with a **pull
(claim)** settlement and a **band-servo'd public rate**.

- **(A) Budget-tied proportional yield** (stakers collectively get ~15% of emission,
  split by weight). Requires revealing exact `TWS` each epoch → a threshold/MPC opener
  → new trust + liveness assumption. **Rejected** for a permissionless privacy chain.
- **(B) Public per-weighted-unit rate `ρ_e`; total floats** (this design). No exact
  `TWS` in the reward path → individual amounts hide with cheap proofs, no opener.
- **(C) Lottery (Crypsinous-style):** strongest privacy, no aggregate needed, but
  probabilistic payout — wrong product shape. **Rejected.**

**Settlement is pull, not push.** A push model (consensus emits the reward
homomorphically as `(ρ·tier)·C_stake`) deletes the claim circuit but creates a
**public stake↔reward link** (the reward is publicly derivable from `C_stake`),
which is linkage-amplifying — deanonymizing the stake unwinds the whole reward trail
— and reintroduces an `O(stakers)` consensus-emit cost. Pull keeps the stake↔reward
link **inside the membership proof** (unlinkable) and is the standard scalable shape.
**Rejected: push.**

**The synthesis that makes (B) economically faithful.** The proportional reward is
`(budget/TWS)·w`, and `budget/TWS` is a rate. Setting `ρ_e = budget_e / band_sum`
(the coarse **public** aggregate as the `TWS` proxy) makes `reward ≈ proportional
reward` with **no opener** — and recovers the dilutive dynamic (more participation →
lower per-unit yield). So (B) does not abandon the proportional economics; it
reconstructs them confidentially through the one public aggregate the governance
signal already requires. One mechanism (`band_sum`) does three jobs: governance
coupling (§8), rate denominator (§4), supply-safety reference (§9).

---

## 2. The confidential staked output

A stake is created by a transaction that produces a `txout_to_staked_key` output
carrying, **instead of a cleartext amount** (current `blockchain.cpp:3476–3478`):

- **`C_stake = a·H + z·G`** — Pedersen commitment to the staked amount `a` with mask
  `z` (Shekyl convention: amount on `H`, mask on `G`, matching the regular output
  commitment `C = z·G + amount·H`). The stake tx's RCT balance prevents committing to
  more than is locked; the commitment form is **uniform** with regular and coinbase
  outputs (preserving the single output-format anonymity posture).
- **range proof** on `C_stake` (Bulletproof+) — `a ∈ [0, 2^k)` — bounding the amount
  so the supply-safety reference in §9 is real.
- **`tier`** (public; one of 3) and **`creation_height`** (public; block height).
- **`band`** (public; §4.4) — a coarse band with a **range proof binding the band to
  `C_stake`** (anti-lie; the staker cannot declare a band their commitment is not in).
- **No extra nullifier secret on the output.** Claim anti-double-spend uses per-epoch
  tags `N_S = x·G_S` (§6.3–§6.4), where `x` is the existing spend secret (`ho + b`)
  and `G_S` is a public per-settlement-epoch base — not a new HKDF field on
  `OutputSecrets`.

**Weight.** `w = a · tier_num / SCALE`, `tier_num ∈ {1_000_000, 1_500_000,
2_000_000}` (the existing `yield_multiplier` fixed point, `SCALE = 1e6`,
[`shekyl-staking/src/tiers.rs`](../rust/shekyl-staking/src/tiers.rs)). Tier is public,
so the **weight commitment** is the public scalar multiple `tier_num · C_stake`
(committing to `tier_num·a`); the `/SCALE` is folded into the rate (§3) so the
per-claim entitlement scalar is an exact integer (no division inside the proof).

**Decision (pinned): tier public.** Committing the tier would turn the entitlement
scalar-mult into a multiplication gadget for a ~1.6-bit privacy gain that lock
duration already leaks. Tier stays public.

---

## 3. Reward model

Reward accrues at a **public per-rate-epoch rate** `ρ_e` (atomic per weighted-atomic
per block), not by dividing a pool:

```
entitlement over epoch set {S} = weight · Σ_{S} K_S
  where K_S = Σ_{rate-epoch e ∈ S ∩ (creation, eff_lock]} ρ_e · rate_epoch_blocks
```

`ρ_e` and the epoch boundaries are public, so each `K_S` is a **public scalar**.

**No division at claim.** Because the reward is `weight · K` (multiplication, not
`pool / TWS`), there is **no per-claim flooring and no claim-split rounding**: claiming
`{S₁} then {S₂}` equals claiming `{S₁ ∪ S₂}` exactly. The only rounding in the system
is the single deterministic division when `ρ_e` is set per rate-epoch (§4), done once
at consensus level, not per claim. This eliminates the claim-split rounding hazard of
the proportional model.

**Per-unit-fixed, then servo'd dilutive.** A staker's per-unit rate `ρ_e` does not
depend on who else is staked at claim time — but because `ρ_e` is **set** by the servo
as `budget/band_sum` (§4), it falls as participation rises, restoring the proportional
"fewer stakers, higher yield" behavior at the epoch granularity.

---

## 4. Rate calibration — the servo and the cap

### 4.1 The servo

```
ρ_e = min( budget_e / band_sum_e ,  ρ_cap_e )
```

- **`budget_e`** = `target_share_e · block_emission_e`, the intended staker emission
  for the rate-epoch. `target_share_e = STAKER_EMISSION_SHARE · 0.90^year` carries the
  existing Component-4 decay (`emission_share.rs`).
- **`band_sum_e`** = the **windowed** sum of active stakes' band representatives
  (§4.4), the public `TWS` proxy.
- **`ρ_cap_e`** = the supply-safety backstop (§4.2).

The servo makes total staker emission `≈ budget_e` at any participation level (closes
the under-payment failure of a flat rate), with no opener.

### 4.2 The cap (supply-safety backstop)

```
ρ_cap_e = budget_e / (circulating_supply_e · max_tier_mult)
```

Using **circulating** supply (public, `already_generated_coins`) rather than the
ceiling makes the cap tight early-chain. Since `TWS_actual ≤ circulating · max_tier_mult`
always (you cannot weight-stake more than exists), for any band value:

```
total staker emission_e = ρ_e · TWS_actual
                        ≤ ρ_cap_e · (circulating · max_tier_mult)
                        = budget_e
```

So **band error or manipulation can never breach `budget_e`** — at worst it shifts
emission between miners and stakers *within* the budget. The cap is what lets the
band be **coarse** (privacy) without endangering supply: banding accuracy affects how
close yield lands to target, never safety.

### 4.3 Planning numbers (proposed pins)

From verified substrate: `ESF = 22`, `COIN = 1e9`, supply ceiling `2³²` SHEKYL
(`MONEY_SUPPLY = 2³²·1e9 = 4.294_967_296e18` atomic), 120 s blocks, 720 blocks/day,
`BLOCKS_PER_YEAR = 262_800`.

| Quantity | Value (genesis) |
|----------|-----------------|
| Block emission `= MONEY_SUPPLY >> ESF` | `2¹⁰·1e9 = 1,024` SHEKYL/block |
| Staker budget `= 15% · 1,024` | `153.6` SHEKYL/block |
| `ρ_cap` floor yield (100% staked @ 2×) | `≈ 0.47%/yr` |
| Servo'd yield @ ~20% weighted participation | `≈ 3.6%/yr` |

The cap floor (~0.47%) is the worst-case yield when the chain is saturated; the servo
lifts yield to ~target at realistic participation. These are calibration anchors, not
locks — the `target_share` decay and exact participation reference are §13 opens.

### 4.4 The band

- **4–6 decade-log-spaced bands** over the realistic stake range.
- Each band's contribution to `band_sum` is its **geometric midpoint**
  `√(floor·ceil)` (an unbiased `TWS` estimate; a floor would bias `ρ` high → over-pay
  up to the cap; a midpoint lands the servo near target).
- `band_sum` is fed through a **windowed moving average** (the LWMA-analog) so `ρ_e`
  and the burn signal (§8) do not whipsaw on cascades and resist flash-manipulation.
- **Cold-start caveat:** a band over a thin cohort is revealing, and `band_sum`
  differencing is trivial with few actors. Below a participation threshold the signal
  should be floored/suppressed (§13).

### 4.5 Manipulation analysis

- **Drive `band_sum` low** (→ `ρ` high → over-pay stakers): bounded by `ρ_cap`
  (≤ budget); and a staker cannot declare a band below their true amount (range proof,
  §2). Self-limiting and capped.
- **Drive `band_sum` high** (→ `ρ` low → under-pay): achievable only by staking real
  coins (range-proven), which the attacker pays for by locking; the window smooths
  transient pushes.
- **Flash manipulation:** damped by the window. **Slow manipulation:** the window's
  lag is the residual surface (§13 — window shape is the privacy↔responsiveness dial).

---

## 5. Epochs

Two global granularities (boundaries are chain-wide, not per-stake):

| Epoch | Length | Role |
|-------|--------|------|
| **rate-epoch** | **1,000 blocks** (~1.4 d; 262.8/yr) | `ρ_e` step; smooth decay; divides all tiers |
| **settlement-epoch** | **10,000 blocks** | nullifier granularity (one `N_S` per settlement-epoch) |

Global boundaries make claims cluster at shared boundaries, **growing** the temporal
anonymity set rather than giving each stake a unique offset.

**One claim may batch many settlement-epochs (`MAX_EPOCHS_PER_CLAIM`).** The entitlement
is **O(1)** in epoch count — a single commitment-to-zero on `M = tier_num · Σ_S K_S` —
so only the nullifier count scales (one `N_S` per epoch; ~15 for a tier-3 full drain,
trivial in one tx). The old `MAX_CLAIM_RANGE`-as-block-span was an artifact of the
per-block pool loop and is **retired**; `MAX_EPOCHS_PER_CLAIM` replaces it as a
proof/nullifier-size budget (`tiers.rs` repurposes the constant). Batching the **full
window** in one tx is privacy-preferred — it removes the partial-timing tell and
tightens the §6.2 anonymity bound. **`MAX_EPOCHS_PER_CLAIM = 1` recovers strict
one-epoch-per-tx** (predictable proof size, more txs, a partial-timing tell); this is a
Round-1 **value** choice, not a structural one. *(Open conflict flagged for
adjudication: the drafter's prior formalization fixed one-epoch-per-tx; this
synthesis generalizes to the parameter and defaults to full-window batching.)*

**Nullifier counts (full drain)** off the binding constraint (tier-3 = 150k blocks):

| Tier | Lock blocks | Settlement-epochs | Nullifiers |
|------|-------------|-------------------|------------|
| 1 (1.0×) | 1,000 | sub-epoch (pro-rated) | 1–2 |
| 2 (1.5×) | 25,000 | 2.5 | ≤3 |
| 3 (2.0×) | 150,000 | 15 | ≤15 |

A single claim may cover up to `MAX_EPOCHS_PER_CLAIM` of a stake's unclaimed
settlement-epochs (a tier-3 full drain, ≤15 nullifiers, fits comfortably in one tx);
`MAX_EPOCHS_PER_CLAIM = 1` is the conservative one-epoch-per-tx setting (§5).

---

## 6. The claim

Replaces the proportional loop (`blockchain.cpp:4366–4376`) and the
watermark/`staked_output_index` machinery (`check_stake_claim_input`,
`blockchain.cpp:4214–4247`; `get_staker_claim_watermark`, `:4238`).

### 6.1 Statement of knowledge

A claim transaction proves, in zero knowledge, knowledge of `(a, z, x, z_claim)` and a
membership witness such that:

1. **Membership.** `C_stake` is a leaf under the staked-output tree root (FCMP++
   membership over the same 4-scalar leaf as spends — §6.4) — does **not** reveal which.
2. **Window.** every claimed settlement-epoch `S` satisfies `S ⊆ (creation, eff_lock]`,
   `eff_lock = creation + tier_lock_blocks` (§6.4 **(C)** binds tier/creation to the
   hidden leaf).
3. **Nullifiers.** for each claimed `S`, `N_S = x·G_S` with `G_S =
   hash_to_ec("shekyl-stake-nullifier-base" ‖ S_le64)` (public base, distinct from
   `Hp(O)`); each `N_S` is filed in the **stake-claim nullifier set** (not the spent
   key-image set) and must be absent before inclusion (no double-claim). Principal
   `x·Hp(O)` is **not** published on claim (§7).
4. **Entitlement.** `C_claim ≡ M · C_stake`, where `M = tier_num · Σ_S K_S` is a
   **public** integer scalar (§3). Implemented via the membership-exposed rerandomized
   commitment `C~` (§6.4 **(A)**): prove `C_claim − M·C~ ∈ ⟨G⟩` by an off-circuit
   commitment-to-zero Schnorr (same proof class as reserve DLEQ — §6.4).
5. **Range.** `C_claim` carries a Bulletproof+ range proof (non-negative, bounded).
6. **Mint.** the claim mints `C_claim` as a normal, self-addressed FCMP++ reward
   output (two-component `O = ho·G + B + y·T`, KEM-self-encap; the staker opens it
   from the public `M` and known `a`), entering the unified deferred-insertion tree.

Settlement is **pull**: the staker builds the claim and the reward output and proves
entitlement; consensus verifies. The membership proof hides which stake funds the
reward, so the reward output is **not** publicly linked to the stake.

### 6.2 What the claim reveals (anonymity bound — stated honestly)

The claim reveals the **tier** (already public) and the **claimed epoch set `{S}`**.
Revealing `{S}` scopes the anonymity set to *staked outputs of the same tier whose
active window overlaps `{S}`* — **not** 1/N over all stakes. Mitigations: claim full
windows (avoid partial-timing tells); global settlement-epoch boundaries (§5) batch
claimers of the same epochs. Widening this to the full staker set requires hiding the
tier/window (L4-adjacent) and is a §13 open.

### 6.3 Nullifiers

`N_S = x · G_S`, where:

- `x = ho + b` is the per-output spend secret already in the FCMP witness (`x` in
  [`WITNESS_HEADER.json`](../test_vectors/WITNESS_HEADER.json)) and in
  `OutputSecrets` (`derivation.rs` — no new secret field).
- `G_S = hash_to_ec(domain ‖ S_le64)` with domain separator
  `shekyl-stake-nullifier-base` (C++ `crypto::hash_to_ec`, same family as `Hp(O)`).

Because `G_S ≠ Hp(O)`, publishing `N_S` does **not** reveal the principal key image
`x·Hp(O)`; unstake still uses a normal FCMP spend that publishes `x·Hp(O)` separately
(§7). `G_S` must be domain-separated and KAT-locked (§13 item 7; wallet §8.5 in
[`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md)).

The nullifier set is a **new consensus table** (distinct from spent key images), is
**reorg-state** (§11), and is deterministically **recomputable on rescan** from `x` and
public `S` (wallet: intersect chain set with `{ x·G_S : S ∈ accrued_epochs }` — §4.2
there).

**Rejected alternative (Round 1 review):** `N_S = PRF(nullifier_seed, S)` with a new
HKDF-derived `nullifier_seed` on `OutputSecrets`. Superseded by the key-image-variant
construction above unless claim-mode SAL extension (§6.4 **(B)**) proves infeasible —
then reopen §13 item 7 as fallback only.

### 6.4 Claim proof bindings (Round 1 source review)

**Status:** Review closed on source (2026-06-02; verified on `main` @ `34b2b3c` and
equivalent on `dev`). §6.4 decomposes the old monolithic "entitlement-binding gap" into
three bindings to one hidden staked leaf. **(C)** remains the architectural gate;
**(A)** and **(B)** have pinned dispositions.

#### 6.4.0 Source facts (consensus-locked; any change is a consensus change)

| Fact | Source | Claim use |
|------|--------|-----------|
| Witness `[O][I][C][h_pqc][x][y][z][a]` | [`WITNESS_HEADER.json`](../test_vectors/WITNESS_HEADER.json) | Opening material for membership |
| `r_c = a − z`, `C~ = a·G + amount·H` | `rust/shekyl-fcmp/src/proof.rs` (`ProveInput` docs) | **(A)** uses public `C~` as `pseudo_outs` |
| `I = Hp(O)` in witness; SAL uses rerandomized `I~` | `rctSigs.cpp`, `sal/mod.rs` | Linkability algebra |
| `L = (I~·x) − (U·(r_i·x)) = x·Hp(O)` ∀ `r_i` | `shekyl-oxide/.../fcmp/fcmp++/src/sal/mod.rs:233` with `I~ = I + U·r_i` (`:65`) | **(B)** tag is **not** re-baseable by tweaking `r_i` |
| `FcmpPlusPlus::verify` always runs `spend_auth_and_linkability.verify(…, key_image)` | `shekyl-oxide/.../fcmp/fcmp++/src/lib.rs` | No membership-only mode today |
| Staked leaf = same 4-scalar `{O.x, I.x, C.x, H(pqc)}` | [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §15 | **(C)** tier/creation not in leaf |
| Cleartext claims today: `txin_stake_claim`, no FCMP | `cryptonote_basic.h`, wallet stake-claim path | Confidential claim is **new** tx + verifier surface |

Reserve proofs already ship a standalone two-base Schnorr DLEQ (`rust/shekyl-proofs/src/dleq.rs`,
domain `shekyl-reserve-proof-dleq-v1`; [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §21) —
the proof class for **(A)** entitlement.

#### 6.4.1 (A) Entitlement — **solved off-circuit**

**Pin:** Membership already exposes the rerandomized pseudo-out `C~` per input
(`shekyl_fcmp_prove` → `pseudo_outs`; verifier checks them). With public integer `M`,
prove `C_claim − M·C~ ∈ ⟨G⟩` via a **commitment-to-zero Schnorr** (knowledge of
`z_claim − M·a` in the Shekyl `C = z·G + a·H` convention). Same auditable family as
reserve DLEQ; **no FCMP++ circuit extension required** for v1.

In-circuit entitlement remains a future hardening option, not the Round 1 blocker.

#### 6.4.2 (B) Nullifiers — **new claim prove/verify surface** (not a parameter tweak)

**Pin:** `N_S = x·G_S` with public `G_S` (§6.3). This **dissolves** the wallet R0-D1
`nullifier_seed` / HKDF-stream requirement ([`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md)
§8.5).

**Why SAL cannot be re-based:** Spend-Authorization and Linkability proves tag
`L = x·Hp(O)` algebraically (§6.4.0). The vendored `FcmpPlusPlus` bundle is
`(Input, SpendAuthAndLinkability) + Fcmp`; verify **unconditionally** couples SAL to the
supplied `key_images`. There is no branch for "membership only" or alternate linkability
base. Emitting `x·G_S` in the nullifier table while reusing today's spend verifier would
incorrectly treat claim nullifiers as spent key images or fail verification.

**Required:** a **claim-specific** prove/verify path that:

1. Runs FCMP **membership** on a **referenced, unspent** staked leaf (same tree).
2. Exposes **`C~`** for **(A)**.
3. Proves / checks **`N_S = x·G_S`** against the **stake-claim nullifier set** without
   inserting `x·Hp(O)` into the spent-key-image set.

**Disposition options** (Round 1 — prefer **B1**):

| ID | Shape | Disposition |
|----|-------|-------------|
| **B1** | Extend SAL (or sibling `ClaimLinkability`) so the proved tag is `x·G_S` for public `G_S`, keeping SAL's existing `x ↔ O` spend-authority binding | **Preferred** — preserves spend-authority guarantee instead of reconstructing it |
| **B2** | Omit/weaken SAL; membership + standalone DLEQ rebinding `x` to `O` | **Rejected as primary** — splits spend-authority out of SAL then forces a sibling proof that re-derives most of what SAL already delivers; "faster to prototype" is not a design axis (§6.4.3) |
| **B3** | In-circuit scalar-mult vs public `G_S` inside FCMP | Heavier audit surface; fallback if B1 infeasible |

**Still to pin for (B):** `G_S` domain separator + `S_le64` encoding + KAT; claim-tx
wire layout (nullifier vector, proof blob); C++ verifier hook parallel to
`shekyl_fcmp_verify`.

#### 6.4.3 (C) Tier + creation-height — **real residual** (architectural fork)

Tier and `creation_height` are **public on the staked output** (§2), but the claim is
membership-unlinkable: the verifier sees public `tier` / `M` on the claim tx but not
**which** leaf. Without a binding, a prover could open stake A (tier 1) while claiming
with tier-3 `M`.

The FCMP leaf is only `{O.x, I.x, C.x, H(pqc_pk)}` (§6.4.0). **Rejected cheap routes:**

- Fold tier/creation into `h_pqc` and reveal preimage — exposes `ml_dsa_pk`, deanonymizes
  claims.
- In-ZK hash of metadata only — heavy.

**Viable paths (pick one in Round 1):**

1. **Extended staked leaf** — fifth scalar or committed metadata hash in the unified tree.
2. **Separate staking Merkle tree** — leaf carries `{C, tier, creation, band, h_pqc}`.
3. **Rerandomizable tier/creation commitment** at stake time, opened at claim via an
   **(A)-class** Schnorr (still requires a stake-time commitment in output or leaf).

**(C) blocks closing §6.4** even when **(A)** and **(B)** are implemented.

#### 6.4.4 Rejected: claim as ordinary FCMP spend + re-stake

**Considered:** Model claim as a normal FCMP spend; use `x·Hp(O)` in the key-image set
for double-claim prevention; re-stake principal in the same tx — avoids new SAL mode and
a separate nullifier table.

**Rejected (Round 1):**

- Makes **(C) strictly harder:** the new staked output must provably inherit the **hidden**
  spent stake's tier and original `eff_lock` (consistency between a public new output and
  a hidden spent leaf).
- Remodels accrual (principal moves; `(creation, eff_lock]` semantics break).
- Collapses claim/unstake decoupling (§7).

Claims remain **non-spending** membership proofs; unstake remains a full SAL spend
publishing `x·Hp(O)`.

#### 6.4.5 Design discipline (security over velocity)

**Pin:** Shekyl does **not** accept dispositions of the form "weaken this
security/privacy property to ship faster." Options that omit spend-authority binding,
skip nullifier separation, or defer **(C)** while claiming §6.4 closed are **out of
scope** regardless of prototype convenience. "Get it right, not get it now" applies to
claim-circuit work the same as consensus work.

#### 6.4.6 Audit scope

The claim verifier (membership + **(A)** Schnorr + **(B)** claim linkability + **(C)**
binding) is a **derivative** of upstream FCMP++ and must be listed in
[`AUDIT_SCOPE.md`](../AUDIT_SCOPE.md) alongside x-only leaf flattening and transcript
ordering — Veridise lineage covers base primitives, not this relation.

### 6.5 Timing

Claim timing is the residual the ZK does not hide: batch claims to settlement-epoch
boundaries, jitter broadcast, route over Dandelion++ / Tor.

---

## 7. Unstake & claimability

Fully **decoupled** (the disposition the prior disbursement doc wanted):

- Accrual is bounded by `eff_lock`; claims are gated **only** by nullifiers and the
  window; a settlement-epoch is claimable iff its `N_S` is unused and `S ⊆ (creation,
  eff_lock]`.
- **Unstake** spends the principal commitment as a normal post-lock FCMP++ membership
  spend (unlinkable). It is independent of claiming; the lock (`eff_lock`) is the only
  gate on principal.
- "Claim before unstake" is a **wallet UX** rule, not consensus — accrued epochs remain
  claimable after unstake (the reward accrued during the lock), bounded by the window
  and gated by nullifiers.

**Wallet FSM pin:** [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §3.1
`FullyUnstaked` + R0-D6 — claims allowed while `principal_spent`; `claimed_epochs`
unchanged.

---

## 8. Governance coupling

The burn coupling (`calc_burn_pct`, `burn.rs`, takes a `stake_ratio` input) reads a
band-derived proxy instead of the old cleartext `total_staked / circulating`:

```
stake_ratio_proxy = windowed band_sum / circulating_supply   →   (1 + stake_ratio_proxy)
```

`band_sum` is the same windowed aggregate the servo uses (§4) — one public aggregate,
not two. **Open (§13):** whether the burn genuinely needs the value-weighted band, or
whether tier-weighted **count** of active staked outputs (zero amount leak, already
public) is a sufficient confidence signal — if so, the band can be dropped entirely
and there is no amount aggregate to reason about.

---

## 9. Conservation & inflation safety (load-bearing)

This is the argument an auditor will attack; it is now the *only* thing standing
between the design and silent inflation (the staker stream is no longer publicly
summable — §10).

1. **Per-claim bound.** Each claim mints `C_claim = M · C_stake` with `M` public and a
   range proof; the entitlement equality (§6.1.4) forbids minting more than `M · a` for
   the membership-proven, range-proven `a`.
2. **Per-epoch bound.** `total staker emission_e = ρ_e · TWS_actual ≤ budget_e` by the
   cap (§4.2), for **any** `band_sum` (honest, stale, or manipulated).
3. **Lifetime bound.** `Σ_e budget_e ≤ Σ_e target_share_e · block_emission_e ≤
   STAKER_EMISSION_SHARE · (total emission) < MONEY_SUPPLY` (since `target_share < 1`
   and total emission ≤ ceiling).

The miner stream (coinbase) remains publicly summable (§10), so total supply is
**auditably bounded** even though the staker stream is hidden. The range proof (1) and
the cap (2) are therefore consensus-critical; a bug in either is an inflation bug.
**Pin:** these two are first-class audit targets (§6.4).

---

## 10. Post-quantum posture

A clean split, consistent with the project's existing stance:

- **Amount-hiding & entitlement** (Pedersen `C_stake`/`C_claim`, range proofs,
  membership, the commitment-to-zero equality) ride the **discrete-log** system
  (curve-trees / Bulletproofs). These are **computationally hiding under DL — not
  post-quantum.** A future quantum adversary could unblind committed amounts; this is
  the *same* caveat as all FCMP++/RingCT amount privacy and is stated, not hidden.
- **Nullifier derivation & claim authorization** ride the **hybrid PQC** layer
  (spend secret `x` is PQ-protected via the output's hybrid KEM derivation; claim tags
  `N_S = x·G_S` are distinct from principal key images `x·Hp(O)`; spend authority via
  ML-DSA-65 + Ed25519), so theft-resistance and nullifier-forgery-resistance are
  PQ-hybrid.

**Supply-auditability consequence:** because staker rewards are committed (hidden), the
**exact** circulating supply is no longer publicly summable — only the miner stream
(public) plus the §9 bound. Supply moves from "every coin publicly counted" to
"auditably bounded." (Monero lives with the same property; the 2017 inflation-bug class
is why §9 must be airtight.)

---

## 11. Reorg / `pop_block` atomicity

The nullifier set is **new reorg-state** (the structural form of the prior C-2
finding). On `pop_block` (`blockchain.cpp:800–822` accrual-reversal path), a single
atomic LMDB transaction must revert, for popped claim/stake txs:

- nullifier-set **insertions** (so a reorged-then-re-mined claim is re-claimable;
  failure here = permanent claim rejection);
- `band_sum` / active-stake changes and the rate-epoch records;
- minted **reward outputs** (tree insertions) and staked-output insertions.

This extends the existing atomic-reversal discipline; the nullifier table is the new
member.

---

## 12. Code-site impact map

| Site (verified this session) | Change |
|------------------------------|--------|
| `blockchain.cpp:4366–4376` (proportional pool loop) | **Replace** with the §6 entitlement-proof verifier |
| `shekyl_calc_per_block_staker_reward` (FFI, `lib.rs`) | **Retire** — no pool division |
| `check_stake_claim_input` `:4214–4247` (range + watermark) | **Rewrite** — range → settlement-epoch window; watermark `:4238` → nullifier-set membership |
| `get_staker_claim_watermark` | **Replace** with nullifier-set table (+ reorg reversal, §11) |
| `txout_to_staked_key` `:3476–3478` (cleartext amount) | **Replace** with `C_stake` + range proof + `tier` + `band` |
| accrual record `:5045–5051` | **Replace** with rate-epoch record `{ρ_e, band_sum}`; pool fields retired |
| `m_stake_ratio_cache_total_weighted` `:5048–5049` | **Replace** with plaintext `band_sum` maintenance |
| `pop_block` `:800–822` | **Extend** to revert nullifiers + `band_sum` + minted rewards atomically (§11) |
| `distribute_staker_rewards` / `StakeRegistry` (`rewards.rs`, `registry.rs`) | **Confirm sim-only** then **retire** — the direct-distribution model is obsolete under the rate model (was already not on the consensus path; zero `blockchain.cpp` hits) |
| `tiers.rs` (`TIERS`, `MAX_CLAIM_RANGE`) | **Keep** `TIERS`; **repurpose** `MAX_CLAIM_RANGE` → `MAX_EPOCHS_PER_CLAIM` (proof/nullifier budget, not a block-span; §5) |

---

## 13. Open decisions (Round 1 targets)

1. **Burn signal granularity** — value-weighted `band` vs tier-weighted **count**
   (zero amount leak). If count suffices, drop the band entirely (§8). Economics-side;
   gates whether bands exist.
2. **Window shape/length** — flat vs LWMA-linear; the direct privacy↔responsiveness
   dial (recent-weighting helps the signal, worse for differencing).
3. **`ρ_cap` form** — `circulating·max_tier_mult` (proposed, §4.2) and whether the
   `0.90/yr` decay applies to the cap as well as the servo target.
4. **Band scheme** — count (4–6) and exact decade spacing; midpoint vs other
   representative (§4.4).
5. **Cold-start floor** — participation threshold below which `band_sum` / the burn
   signal is suppressed or floored (§4.4).
6. **Entitlement binding** (§6.4.1 **(A)**) — **disposition closed:** off-circuit
   commitment-to-zero Schnorr vs membership `C~` (reserve-DLEQ class). Implement + KAT;
   in-circuit optional hardening only.
7. **Stake nullifier base + claim linkability** (§6.4.2 **(B)**) — `G_S` domain
   separator + `S_le64` encoding + KAT; claim-specific prove/verify (**B1** preferred:
   claim-mode SAL / sibling emitting `x·G_S` while preserving `x ↔ O` binding). **Wallet
   mirror:** [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §8.5 (R0-D1).
   **Supersedes** `nullifier_seed` HKDF unless B1 proves infeasible (§6.3 fallback).
8. **Tier/creation binding on hidden leaf** (§6.4.3 **(C)**) — extended leaf vs staking
   subtree vs tier/creation commitment; **blocks** claim circuit closure. *Highest risk.*
9. **Claim anonymity widening** (§6.2) — accept the tier+window-scoped set for v1, or
   pursue L4 (hide tier/window) later.

---

## 14. References

| Doc / site | Use |
|-----------|-----|
| [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) | Wallet mirror (§2.3); R0-D1–D7; `N_S = x·G_S` §8.5; §6.4 review pins |
| [`STAKER_REWARD_DISBURSEMENT.md`](STAKER_REWARD_DISBURSEMENT.md) | **Superseded** reward/claim mechanism (retained for history) |
| [`DESIGN_CONCEPTS.md`](DESIGN_CONCEPTS.md) | Four-component economic model (Components 2–4) |
| [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) | Membership proof / leaf structure; SAL linkability (§6.4) |
| [`WITNESS_HEADER.json`](../test_vectors/WITNESS_HEADER.json) | Consensus-locked witness layout |
| [`AUDIT_SCOPE.md`](../AUDIT_SCOPE.md) | Claim verifier (§6.4.6) + §9 inflation-safety targets |
| `blockchain.cpp` (`:800–822`, `:3476`, `:4214–4247`, `:4366–4376`, `:5045–5051`) | Code sites superseded (§12) |
| `shekyl-staking` (`tiers.rs`, `registry.rs`, `rewards.rs`), `shekyl-economics`, FFI `lib.rs` | Tier/economics primitives; retirements (§12) |
| [`00-mission.mdc`](../.cursor/rules/00-mission.mdc), [`26-sub-pr-design-discipline.mdc`](../.cursor/rules/26-sub-pr-design-discipline.mdc) | Priority hierarchy; round discipline |
