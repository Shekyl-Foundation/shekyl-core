# Confidential staking — consensus & economics design

**Status:** **Genesis reward path superseded (2026-06).** Leading genesis staking is
**transfer-shaped admission** ([`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md)
§2.4): main-tree transfers principal ↔ `P`, reward emission with membership-only
backing, bond-record epoch dedup — **not** this document's §6.4 claim wire or Decision
**3C** staking subtree. **Do not implement** 3C / `txin_stake_claim_v2` / entitlement
for genesis.

**Historical — confidential-claim design (archived for audit trail):** Round 1 closed
(2026-06-02) on economics and **(B)**. **(C)** closed on 3C (2026-06-04, §6.4.3).
**(A)** collapsed to reserve-DLEQ + bounded remainder (§6.4.1). §6.4.4 rejected
re-stake-in-claim-tx; §6.4.4 reopening is valid for transfer-shaped admission per
rule 21 (reasons 1–3 were confidential-substrate only).

This doc **supersedes** cleartext [`STAKER_REWARD_DISBURSEMENT.md`](STAKER_REWARD_DISBURSEMENT.md)
for history. Principal/unstake membership pins may still inform optional admission
transfer discipline where not superseded by §2.4.

**Process discipline:** [`26-sub-pr-design-discipline.mdc`](../.cursor/rules/26-sub-pr-design-discipline.mdc).
**Binding constraint:** [`00-mission.mdc`](../.cursor/rules/00-mission.mdc) priority-1
(security) then priority-2 (privacy). Pre-genesis: this is structural work in the
bounded window; hard forks signal planning failure, so the construction is designed
to be launch-final.

**Origin:** design session 2026-06-02. Code-site citations are to `blockchain.cpp`
(6322 lines) and the `shekyl-staking` / `shekyl-economics` FFI verified that session;
FCMP++ / SAL / witness layout were **source-reviewed** for §6.4 (2026-06-02;
`main` @ `34b2b3c`); Round 1 closed 2026-06-02 (§14).

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

**Pedersen scalar names** (Shekyl / [`proof.rs`](../../rust/shekyl-fcmp/src/proof.rs);
same symbols at stake, spend, and claim):

| Symbol | Meaning | Not |
|--------|---------|-----|
| `amount` | Committed value (atomic units) on `H` | — |
| `z` | Commitment mask on `G` (`OutputSecrets.z`, witness `z`) | — |
| `a` | Pseudo-out blinding (`pseudo_out_blind`, witness `a`) | **Never** the staked amount |
| `x` | Spend secret `ho + b` (witness `x`) | — |

**Commitment form (Decision 3C — §6.4.3):**

- **Regular / coinbase:** `C = z·G + amount·H`
- **Staked (`txout_to_staked_key`):** **plain Pedersen, identical basis** —
  `C_stake = z·G + amount·H`. No `τ·H_t` term.

```text
C_stake = z·G + amount·H          // staked C commits value + mask only
```

Tier and creation are **not** in the commitment. They live in the staking-subtree leaf's
**5th scalar** `h_bind = H("stake-bind" ‖ tier ‖ creation_height)`, set by **consensus at
inclusion** (Decision 3C; [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §15). Membership in the
**staking subtree** *is* the "is-staked" marker that the demoted `H_t` term used to carry;
subtree membership + `h_bind` hash-equality replace `(C_tier)`/`H_t` entirely.

**Staking subtree leaf (5-scalar, 160 B):** `{ O.x, I.x, C.x, h_pqc, h_bind }`. The main
tree (all non-staked outputs) keeps the **128-byte / 4-scalar** leaf, unchanged. The locked
witness header `[O][I][C][h_pqc][x][y][z][a]` is **untouched** — `h_bind` is public claim
data (verifier-recomputable from revealed `(tier, creation)`) entering membership as a
**public input**, not a witness field.

A stake is created by a transaction that produces a `txout_to_staked_key` output
carrying, **instead of a cleartext amount** (current `blockchain.cpp:3476–3478`):

- **`C_stake`** as above — Pedersen commitment to principal + tier type.
- **range proof** on `C_stake` (Bulletproof+) — `amount ∈ [0, 2^k)` — bounding the
  principal so the supply-safety reference in §9 is real.
- **`tier`** (public; one of 3) and **`creation_height`** (public; block height).
- **`band`** (public; §4.4) — a coarse band with a **range proof binding the band to
  `C_stake`** (anti-lie; the staker cannot declare a band their commitment is not in).
- **No extra nullifier secret on the output.** Claim anti-double-spend uses per-epoch
  tags `N_S = x·G_S` (§6.3–§6.4), where `x` is the existing spend secret (`ho + b`)
  and `G_S` is a public per-settlement-epoch base — not a new HKDF field on
  `OutputSecrets`.

> **Canonical stake-creation height (single source of truth — load-bearing).**
> `creation_height ≜ eligible_height` — the height at which the stake **matures** (clears
> the `MIN_AGE = 5` reorg buffer after its including block), not the mining height of that
> block. This **one** definition is referenced by **both** the claim verifier (accrual
> window start, stamped into `h_bind`) **and** the servo / economics path (the height a
> stake enters `band_sum`). They **must not** carry independent height formulas: a
> definitional drift between them silently breaks the §9 conservation argument with no
> reject (§9, §4.1). The pattern mirrors `00-mission.mdc`'s single-source priority
> hierarchy — one named definition, two consumers, no drift. **`accrual-before-counted`
> (accrual anchored earlier than `band_sum` entry) is forbidden outright** (§9). Rationale,
> alternatives, and the deterministic-deferral reversion clause: §6.4.3.

**Weight / entitlement scalar.** Public `tier` on the output and claim tx determines
`tier_num`; accrual uses the rational multiplier `N/D = tier_num_reduced · Σ_S K_S_scaled / D`, `D = D_tier·SCALE_rate = 2⁴⁹` (§3,
§6.4.1). Tier is bound to the **hidden** leaf by `h_bind` (subtree membership + hash
equality, §6.4.3 Decision 3C); the **single revealed `tier`** scalar drives **both** the
`h_bind` recompute and `tier_num` in `N` — this single-source rule is the load-bearing
tier-forgery bind that the demoted `H_t` residual used to provide (§6.4.1).

**Decision (pinned): tier + creation public on wire.** Lock duration already leaks tier
class; `h_bind` binds the public `(tier, creation)` to the hidden leaf for inflation
safety without re-hiding either on-chain.

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
  (§4.4), the public `TWS` proxy. A stake enters `band_sum` at its canonical
  **`eligible_height`** — the **same** height that anchors its accrual window (§2 canonical
  definition). This identity is what makes the §9 step-2 conservation bound hold:
  `band_sum_S` counts **precisely** the stakes accruing in `S`. Counting from an earlier
  height (e.g. mining) is **safe only** if accrual also starts no earlier (it under-pays
  during the deferral); the reverse — accrual before counting — over-pays and is forbidden
  (§9).
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
close yield lands to target, never safety. **Per-claim** inflation still requires **(C)**
+ validated `M` (§9); the cap does not substitute for wire-`M` or tier-leg integrity.

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
- **Cold-start caveat (cross-cutting):** a band over a thin cohort is revealing, and
  `band_sum` differencing is trivial with few actors (priority-2 privacy gate — §14.4).
  Below a participation threshold the signal must be floored/suppressed (§14.1 economics
  pin + §0.2).

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
is **O(1)** in epoch count — a **single floor** over the batched `N = tier_num · Σ_S K_S`
(one remainder, one Schnorr + one range proof; §6.4.1) — so only the nullifier count scales
(one `N_S` per epoch; ~15 for a tier-3 full drain). Per-epoch flooring would break O(1).
**`MAX_EPOCHS_PER_CLAIM = 15`** is pinned with **(B)** (§6.4.2: bounds wire vectors and
ClaimLinkability size).

**Default: batch the full unclaimed window in one tx** when `|epochs| ≤ 15`. This is not
only cheaper — piecemeal claims emit a **per-stake sequence** of `(tier, contiguous
epoch-window)` tuples (§6.2); fewer claims means less serial correlation surface.
`MAX_EPOCHS_PER_CLAIM = 1` is **test-mode only** (partial-timing tell + maximal sequence
exposure). Consensus rejects `|epochs| > MAX_EPOCHS_PER_CLAIM`.

**Nullifier counts (full drain)** off the binding constraint (tier-3 = 150k blocks):

| Tier | Lock blocks | Settlement-epochs | Nullifiers |
|------|-------------|-------------------|------------|
| 1 (1.0×) | 1,000 | sub-epoch (pro-rated) | 1–2 |
| 2 (1.5×) | 25,000 | 2.5 | ≤3 |
| 3 (2.0×) | 150,000 | 15 | ≤15 |

A single claim may cover up to `MAX_EPOCHS_PER_CLAIM` settlement-epochs (tier-3 full
drain ≤ 15 nullifiers). Wallets **should not** drip one epoch per tx in production.

---

## 6. The claim

Replaces the proportional loop (`blockchain.cpp:4366–4376`) and the
watermark/`staked_output_index` machinery (`check_stake_claim_input`,
`blockchain.cpp:4214–4247`; `get_staker_claim_watermark`, `:4238`).

### 6.1 Statement of knowledge

A claim transaction proves, in zero knowledge, knowledge of the stake/claim scalars
`(z, amount, x, a, z_claim, ρ_blind)` — where **`amount`** is the hidden principal,
**`z`** the stake commitment mask, **`x`** the spend secret, **`a`** the membership
pseudo-out blinding (`C~ = a·G + amount·H` for staked leaves under 3C; §6.4.3),
**`z_claim`** the claim-output mask, **`ρ_blind`** the remainder commitment blind
(§6.4.1) — and a membership witness such that:

1. **Membership.** `C_stake` is a leaf under the **staking-subtree** root (FCMP++
   commit-and-prove; 5-scalar 160-byte leaf — §6.4.3) — does **not** reveal which.
2. **Window.** every claimed settlement-epoch `S` satisfies `creation < S ≤ creation +
   tier_lock(tier)` by **arithmetic** on the `h_bind`-bound `creation` (both bounds; no
   historical root — §6.4.3 Decision 3C).
3. **Nullifiers.** for each claimed `S`, `N_S = x·G_S` with `G_S =
   hash_to_ec("shekyl-stake-nullifier-base" ‖ S_le64)` (public base, distinct from
   `Hp(O)`); each `N_S` is filed in the **stake-claim nullifier set** (not the spent
   key-image set) and must be absent before inclusion (no double-claim). Principal
   `x·Hp(O)` is **not** published on claim (§7).
4. **Entitlement.** Consensus **recomputes** `N = tier_num_reduced(tier)·Σ_S K_S_scaled`,
   `D = D_tier·SCALE_rate = 2⁴⁹` from `h_bind`-validated `tier` and `settlement_epochs` (§9).
   **(A)** bounded-remainder relation: `N·C~ − D·C_claim − C_ρ ∈ ⟨G⟩` with `ρ ≥ 0`
   range-proven (`C_ρ` folded into the reward output's 64-bit range proof — §6.4.1 1(b)),
   `reward = floor(N·amount/D)` (§6.4.1).
5. **Range.** `C_claim` carries a Bulletproof+ range proof (non-negative, bounded).
6. **Mint.** the claim mints `C_claim` as a normal, self-addressed FCMP++ reward
   output (two-component `O = ho·G + B + y·T`, KEM-self-encap; the staker opens it
   from the public `M` and the proven principal `amount`), entering the unified
   deferred-insertion tree.

Settlement is **pull**: the staker builds the claim and the reward output and proves
entitlement; consensus verifies. The membership proof hides which stake funds the
reward, so the reward output is **not** publicly linked to the stake.

### 6.2 What the claim reveals (anonymity bound — stated honestly)

**Per-claim bound.** The claim reveals the **tier** (already public) and the **claimed
epoch set `{S}`**. Revealing `{S}` scopes the anonymity set to *staked outputs of the
same tier whose active window overlaps `{S}`* — **not** 1/N over all stakes. Mitigations:
full-window batching (§5); global settlement-epoch boundaries batch claimers of the same
epochs. **Round 1 pin (§14.4):** accept tier+window-scoped anonymity for v1; L4
(hide tier/window) deferred.

**Per-stake sequence (Round 3 threat pass).** §6.2 above is **per claim**; the adversary
tracks **per stake over time**. A long-lived tier-3 bond claiming piecemeal emits a
sequence of `(tier, contiguous-epoch-window)` claims. Nullifiers `N_S = x·G_S` are
pairwise unlinkable across independent `G_S` (§6.3 DDH split), but **tier plus
contiguous-window adjacency** is a weak serial signal that **accumulates** across claims.
This is a fresh argument for the **full-window batching default** (§5): maximize
`MAX_EPOCHS_PER_CLAIM` utilization, minimize claim count. Round 3 threat model must
wargame delay-then-batch vs steady-drip strategies.

### 6.3 Nullifiers and the two-surface split

`N_S = x · G_S`, where:

- `x = ho + b` is the per-output spend secret already in the FCMP witness (`x` in
  [`WITNESS_HEADER.json`](../test_vectors/WITNESS_HEADER.json)) and in
  `OutputSecrets` (`derivation.rs` — no new secret field).
- `G_S = hash_to_ec(domain ‖ S_le64)` with domain separator
  `shekyl-stake-nullifier-base` (C++ `crypto::hash_to_ec`, same family as `Hp(O)`).

**Named security argument — DDH split across bases.** The claim/unstake decoupling rests
on **`x·G_S`** (stake-claim nullifier table) and **`x·Hp(O)`** (spent key-image set)
being **computationally unlinkable** to any party that does not know `x`, given:

- `G_S = hash_to_ec("shekyl-stake-nullifier-base" ‖ S_le64)` and `Hp(O) = hash_to_ec(O)`
  are independent NUMS bases (domain-separated Keccak path, same as existing key-image
  unlinkability assumptions);
- `G_S ≠ Hp(O)` as points.

Under the **DDH / random-oracle heuristic** on independent bases, observing `N_S` does
not reveal whether the same `x` produced a later unstake key image, and vice versa. This
is the same assumption class Monero-style key-image unlinkability already rides; here it
**separates nullifier spaces** rather than ring positions. Auditors must treat it as an
explicit load-bearing assumption (also [`AUDIT_SCOPE.md`](../AUDIT_SCOPE.md) §Confidential
stake claim verifier).

Publishing `N_S` does **not** spend principal; unstake still uses a full SAL spend
publishing `x·Hp(O)` separately (§7). `G_S` must be domain-separated and KAT-locked
(§6.4.2; wallet §8.5 in [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md)).

The nullifier set is a **new consensus table** (distinct from spent key images), is
**reorg-state** (§11), and is deterministically **recomputable on rescan** from `x` and
public `S` (wallet: intersect chain set with `{ x·G_S : S ∈ accrued_epochs }` — §4.2
there). Wallet **does not persist `x`** in `StakeOpening`; derives `x = ho + b`
transiently ([`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §3.3.1).

**Rejected alternative (Round 1 review):** `N_S = PRF(nullifier_seed, S)` with a new
HKDF-derived `nullifier_seed` on `OutputSecrets`. Superseded by the key-image-variant
construction above unless claim-mode SAL extension (§6.4 **(B)**) proves infeasible —
then reopen §13 item 7 as fallback only.

### 6.4 Claim proof bindings (Round 1 source review)

**Status:** Round 1 **closed** on economics and **(B)**. **(C)** decision record §6.4.3
**closed on 3C** (staking subtree + `h_bind`; Decisions 1–2 superseded). **(A)** collapsed to
reserve-DLEQ class + bounded remainder (§6.4.1), coupled to 3C.

#### 6.4.0 Source facts (consensus-locked; any change is a consensus change)

| Fact | Source | Claim use |
|------|--------|-----------|
| Witness `[O][I][C][h_pqc][x][y][z][a]` | [`WITNESS_HEADER.json`](../test_vectors/WITNESS_HEADER.json) | Opening material for membership |
| `r_c = a − z`, `C~ = a·G + amount·H` | `rust/shekyl-fcmp/src/proof.rs` (`ProveInput` docs) | **(A)** uses public `C~` as `pseudo_outs` |
| `I = Hp(O)` in witness; SAL uses rerandomized `I~` | `rctSigs.cpp`, `sal/mod.rs` | Linkability algebra |
| `L = (I~·x) − (U·(r_i·x)) = x·Hp(O)` ∀ `r_i` | `shekyl-oxide/.../fcmp/fcmp++/src/sal/mod.rs:233` with `I~ = I + U·r_i` (`:65`) | **(B)** tag is **not** re-baseable by tweaking `r_i` |
| `FcmpPlusPlus::verify` always runs `spend_auth_and_linkability.verify(…, key_image)` | `shekyl-oxide/.../fcmp/fcmp++/src/lib.rs` | No membership-only mode today |
| Staked subtree leaf (5-scalar, 160 B) | [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §15 | 5th scalar `h_bind` binds `(tier, creation)`; tier no longer in `C.x` (Decision 3C) |
| Cleartext claims today: `txin_stake_claim`, no FCMP | `cryptonote_basic.h`, wallet stake-claim path | Confidential claim is **new** tx + verifier surface |

Reserve proofs already ship a standalone two-base Schnorr DLEQ (`rust/shekyl-proofs/src/dleq.rs`,
domain `shekyl-reserve-proof-dleq-v1`; [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §21) —
the **audit class and transcript discipline** for **(A)** entitlement (the entitlement uses
its own FS domain, not this string — see below).

#### 6.4.1 (A) Entitlement — off-circuit (reserve-DLEQ class + bounded remainder)

**Decided (Decision 3C, §6.4.3):** Under 3C the staking subtree carries the "is-staked"
marker (subtree membership) and `h_bind` carries `(tier, creation)`, so **`C_stake` is
plain Pedersen** (`z·G + amount·H`, no `τ·H_t`) and the entitlement **collapses** to a
reserve-DLEQ-class relation on `C~`. **Coupling (rule 21):** this collapse is sound **only
because 3C** moved the is-staked marker into subtree membership; in a unified tree, dropping
`H_t` would leave no way to prove a hidden leaf is a stake. **The collapse reverts if 3C
reverts.**

**Tier binding moves to `h_bind`.** The membership proof proves the leaf's 5th scalar equals
`H("stake-bind" ‖ tier ‖ creation)` recomputed from the **revealed** `tier`. The **same
single revealed `tier`** scalar feeds `tier_num` in the multiplier. This **single-source-of-
tier** rule is the load-bearing tier-forgery bind that `H_t`'s residual used to provide; the
verifier **must** assert one tier source for both `h_bind` recompute and the multiplier
(loud reject on mismatch; KAT-locked — §6.4.3 mechanical pins).

**The multiplier is rational — the relation is not a plain integer-scalar Schnorr.** The
four-component yield makes `M_frac = N / D`. The reward is an **integer atomic amount**:

```text
N          = tier_num_reduced(tier) · Σ_{S} K_S_scaled        (public scalar)
D          = D_tier · SCALE_rate = 2 · 2^k = 2^(k+1)           (power of two)
reward     = floor( N · amount / D )         // single floor over the BATCHED sum N
N · amount = D · reward + ρ,    0 ≤ ρ < D     // bounded remainder
```

**`D` is a product of two scales — the "`D = SCALE`" earlier framing was underspecified
(Round 2 correction).** It is only `= SCALE` if `Σ_S K_S` is a plain integer, which it is
**not**: the per-weighted-atomic rate `ρ_e = budget_e/band_sum_e ≈ 1e-8 … 1e-3` (atomic per
weighted-atomic per block) is **sub-integer**, so `Σ_S K_S` must carry a rate-precision scale
`SCALE_rate` or every reward floors to zero. The tier factor carries its own scale. Hence
`D = D_tier · SCALE_rate` intrinsically. Two levers minimize `D` (and the range-proof width):

- **`D_tier = 2`** — the LCD of the pinned tier multipliers `{1.0, 1.5, 2.0}` (§3 /
  [`tiers.rs`](../../rust/shekyl-staking/src/tiers.rs)); `tier_num_reduced ∈ {2, 3, 4}`
  represents them **exactly** (one bit). The 1e6 fixed-point tier scale is a representation
  artifact, not a denominator the entitlement needs.
- **`SCALE_rate = 2^k`** — the **sole** precision dial. Both being powers of two makes
  `D = 2^(k+1)` a power of two; `D = 2⁴⁹` is the **value** bound on the honest remainder
  (`ρ < D`). The range **proof** is *not* a tight `(k+1)`-bit proof — `C_ρ` folds into the
  native 64-bit reward-output proof (decision 1(b) below); `D` only needs `⌈log2 D⌉ ≤ 64` so
  the honest `ρ` fits that slot.

**Floor loss is always sub-atomic.** `floor(N·amount/D)` discards `< 1` atomic unit
**regardless of `D`**, so `D` does **not** govern payout rounding (always sub-atomic); it
governs **rate quantization** — the smallest representable `ρ_e` increment.

**`D = 2⁴⁹` (k = 48) — data-determined, at the floor-dominated knee.** The precision sweep
([`shekyl-staking/src/entitlement.rs`](../../rust/shekyl-staking/src/entitlement.rs),
`precision_sweep` / `recommend_k_knee`) sweeps `SCALE_rate` over the realistic rate range
(per-block staker emission ÷ weighted band, from `config/economics_params.json` magnitudes),
excluding rates below 0.001 % per-unit yield as economically negligible. **Decision 1(b)
fixed the range-proof width at 64, dissolving the precision-vs-width tradeoff** — so `k` is no
longer "smallest clearing an (arbitrary) 0.1 % floor" (the old `k = 38`); precision is **free**
up to the field-wrap margin (`187 − k`). The sweep shows the worst-case *relative*
rate-quantization error falling until **`k = 48` (2.1e-5)** and then **plateauing** (identical
at `k = 48, 52, 56, 60`): past the knee the irreducible reward floor `floor(N·amount/D)`, not
the rate scale, sets the error, so finer quantization cannot improve payout accuracy. `k = 48`
is the smallest `k` at that knee — rate quantization as fine as it can matter — with a **139-bit**
field-wrap margin and a **132-bit** `N·amount` overflow headroom (both test-locked,
[`SCALE_RATE_K`](../../rust/shekyl-staking/src/entitlement.rs)). `2⁴⁹ < 2⁶⁴` folds into the
64-bit slot with 15 bits to spare. The `9.7e-4` error at the former `k = 38` is now a stale
optimum — the right call only while precision traded against proof width. **Lifetime
invariance:** the knee is set by the smallest *meaningful* rate, floored by the
**era-independent** meaningful-yield cutoff (`rate · window ≥ 1e-5`). Emission decays 0.90/yr,
but the sweep grid already spans down to the terminal tail subsidy and the cutoff admits no
meaningful rate below the floor regardless of era — so `k = 48` is the **lifetime** knee, not
the genesis knee (`entitlement.rs::knee_is_lifetime_invariant_not_genesis_only`). **Reversion:**
re-pin only if (a) the meaningful-yield cutoff is lowered to admit a far-future low-budget
regime currently deemed negligible (the cutoff, not the passage of time, is the lever), or
(b) the reward-output range width (hence the margin) changes; band is any `k` with
comfortably-positive margin (the sweep harness is faithful to `k ≈ 60`, above which the
analytic margin governs). Committed sweep (with margin column):
[`docs/test_vectors/staking/entitlement_precision_sweep.json`](../test_vectors/staking/entitlement_precision_sweep.json).

**Reversion (`21-reversion-clause-discipline.mdc`):** `D` is a consensus constant. Re-run
the sweep and re-pin `k` **only if** the tier multiplier set changes (re-derive `D_tier` from
the new LCD; `tier_num_reduced` rejects non-exact tiers loudly) **or** the rate magnitudes in
`economics_params.json` shift enough to move the meaningful-rate floor.

**Batching pin:** one floor over the summed `N` (one remainder `ρ`), **not** per-epoch
floors — this preserves the O(1)-in-epochs single proof. Per-epoch flooring would force a
remainder vector and change the statement.

**Overflow:** at the extremes (tier-2, capped scaled rate over `MAX_EPOCHS_PER_CLAIM ·
rate_epoch_blocks`, `amount ≤ money_supply`), `N · amount ≈ 2¹⁰⁶` — `> 64` bits of headroom
below the Ed25519 scalar order `ℓ ≈ 2²⁵²`, so the cancel relation never wraps
(`entitlement.rs::overflow_headroom_bits`, test-locked).

**Entitlement relation (commit the remainder; do not reveal it):**

```text
N · C~  −  D · C_claim  −  C_ρ  ∈  ⟨G⟩
  C~     = a·G + amount·H            (public, from membership; G-leg only rerandomized)
  C_claim= z_claim·G + reward·H      (the claimed reward output commitment)
  C_ρ    = ρ_blind·G + ρ·H           (committed remainder; honest ρ ∈ [0,D), ρ < 2⁴⁹)
                                     proven ρ ≥ 0 via the folded 64-bit range proof (1(b))
```

Prove the difference is in `⟨G⟩` via a Schnorr on the residual `G`-exponent
(`d = N·a − D·z_claim − ρ_blind`); the `H`-components cancel exactly
(`N·amount − D·reward − ρ = 0`).

**Two traps the "plain reserve-DLEQ" framing hides — both closed here:**

- **(a) Rounding over-claim (P1 inflation).** Omitting `C_ρ` lets a prover absorb the
  remainder into `reward`. The remainder term + a range proof proving **`ρ ≥ 0`** is
  **mandatory** (the lower bound is the inflation-critical half — over-claim forces `ρ < 0`;
  see decision 1(b)). **Rounding is defined toward under-claim** (`floor`), so the chain
  mints **at most** `floor(N·amount/D)` and never over-mints.
- **(b) Remainder-disclosure deanonymization (P2).** Revealing `ρ` instead of committing it
  leaks `amount mod (D/gcd(N,D))` — partial deanonymization of the hidden principal. `ρ`
  **must** be committed (`C_ρ`) and range-proven, never revealed.

So the entitlement is **reserve-DLEQ class + a bounded-remainder range proof** (a **distinct
relation**), under a **fresh Fiat-Shamir domain** `shekyl-stake-entitlement-v1` — it reuses
the reserve-DLEQ **audit class and transcript discipline**, **not** the literal
`shekyl-reserve-proof-dleq-v1` string (sharing a transcript domain across two statements is a
soundness footgun).

**Remainder range-proof construction — decision 1(b) ✅ CLOSED: fold `C_ρ` into the
reward-output's native 64-bit `AggregateRangeProof`.** The soundness-critical content of the
remainder bound is the **lower** bound `ρ ≥ 0`, **not** a tight upper bound `ρ < D`.

- **Why `ρ ≥ 0` is the load-bearing half.** Over-claiming `reward + j` (`j ≥ 1`) forces the
  integer remainder `ρ' = N·amount − D·(reward+j) < 0` (since honest `ρ < D ≤ D·j`). A
  non-negative range proof of **any** width rejects a negative `ρ'`; the only escape is a
  field wrap making `ρ' + ℓ` land back in `[0, 2⁶⁴)`, which needs
  `reward+j > (ℓ − 2⁶⁴)/D ≈ 2²⁰³`. But the **reward output's own range proof** already bounds
  `reward+j < 2⁶⁴` — a **139-bit margin** (`252 − 49 − 64` at the pinned `k = 48`;
  [`entitlement.rs::wraparound_over_claim_margin_bits`](../../rust/shekyl-staking/src/entitlement.rs),
  test-locked). So **any** width `w ∈ [⌈log2 D⌉ … ~203]` is inflation-sound, and the honest
  `ρ < D = 2⁴⁹ < 2⁶⁴` always fits the 64-bit slot.
- **Therefore fold, don't add a proof.** `C_ρ = ρ_blind·G + ρ·H` matches Monero's commitment
  convention `mask·G + amount·H`
  ([`Commitment`](../../rust/shekyl-curve-primitives/src/lib.rs)) with
  `mask = ρ_blind`, `amount = ρ` (`ρ < 2⁴⁹` fits `u64`), so `C_ρ` is **one more aggregated
  commitment** in the claim tx's existing reward-output `AggregateRangeProof`
  ([`aggregate_range_proof.rs`](../../rust/shekyl-bulletproofs/src/plus/aggregate_range_proof.rs),
  `COMMITMENT_BITS = 64`, `MAX_COMMITMENTS = 16` — a claim has ≤ 2 outputs, ample room). The
  marginal wire/verify cost is one commitment in an aggregate that already exists. **The folded
  `C_ρ` is the *same* group element the entitlement relation `N·C~ − D·C_claim − C_ρ ∈ ⟨G⟩`
  consumes** — bound across both sub-proofs in one transcript (decision 3), *not* a
  free-floating aggregated commitment. Without that shared binding a prover could range-prove
  one commitment and entitlement-relate another; the single-public-point identity (§6.4.1
  decision 3) forecloses it.
- **Rejected: (i)** a `generalized-bulletproofs` width-`⌈log2 D⌉` arithmetic-circuit range and
  **(ii)** a dedicated `⌈log2 D⌉`-bit BP+ (49 bits at the pinned `k`). Both add a proof system /
  consensus crypto surface to buy
  a *tight* `ρ < D` bound, whose only extra effect is forbidding **under**-claim
  (`reward < floor`) — which mints *less*, is the prover's own loss, preserves
  `Σ reward ≤ budget`, and is **not** load-bearing (`entitlement.rs::under_claim_is_representable_but_not_inflationary`).
  This is the §6.4.3 **minimize-novel-consensus-crypto** discipline: the cheapest sound proof
  is the existing one. The empirical proof-cost benchmark is moot — folding is cheapest by
  construction and the soundness analysis (not a width sweep) decides it.
- **Reversion (`21-reversion-clause-discipline.mdc`):** re-pin to a tight `⌈log2 D⌉`-bit range
  (construction (i) or (ii)) **only if** a future mechanism makes the rounding remainder `ρ`
  or under-claim load-bearing — e.g. remainder carry-forward/refund, or a consensus
  `reward == floor` equality that must be enforced *in-proof* (the verifier cannot recompute
  `floor` since `amount` is hidden).

**Why off-circuit (not in-circuit).** Membership already exposes public `C~`; entitlement is
a **linear relation on public Pedersen points** plus a range proof. The mature disposition is
standalone (reserve-DLEQ class + BP+ remainder) — **no FCMP++ circuit delta**. Same
**minimize novel consensus crypto** discipline that chose Decision **3C** over **3A**
(§6.4.3): spend the ZK budget on membership + **(B)** + the remainder range proof, not on a
redundant in-circuit re-derivation. **Reopen in-circuit (A)** only if `C~` ceases to be a
public input or a monolithic single-blob proof becomes a hard audit requirement.

**Transcript composition / anti-splicing — decision 3 ✅ CLOSED: one shared binding root
`μ_claim = signable_tx_hash`, absorbed by every component; not a monolithic transcript.** A
claim carries four Fiat-Shamir components — staking-subtree **membership** (FCMP++ GSP),
**ClaimLinkability** (B1, SAL-class GSP), the **entitlement** Schnorr
(`shekyl-stake-entitlement-v1`), and the folded **remainder range proof** (in the reward
output's `AggregateRangeProof`). They must all bind to *this* claim so an attacker cannot
splice a valid component from claim A onto claim B.

- **The binding root.** Reuse the existing FCMP++ message
  `μ_claim = signable_tx_hash = H(prefix_hash ‖ base_rct_hash ‖ bp_plus_hash)` (the FFI
  `signable_tx_hash` parameter, [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §"Transaction Hash
  Computation"). For a claim, `μ_claim` covers — and therefore binds — every public field of
  the statement:
  - **prefix** → `txin_stake_claim_v2`: `tier`, `creation_height`, `settlement_epochs`, the
    **nullifier vector** `{N_S}`, and the staking-subtree **root** (§6.4.8);
  - **rct base** → the pseudo-out `C~`, the reward output `C_claim`, and the remainder
    commitment `C_ρ`;
  - **bp_plus_hash** → the folded `AggregateRangeProof` (so `C_ρ` *and its range proof* are
    inside the message the other three sign).

  `μ_claim` **excludes** the membership / ClaimLinkability / entitlement responses themselves
  (those *sign* `μ_claim`) — the standard Monero pre-signature-hash split; no circularity.

- **Per-component binding.**
  - **Range proof (4):** bound by being hashed *into* `μ_claim`; its own transcript seeds from
    `C_ρ`. Computed **first** (it must exist before `μ_claim` is formed).
  - **Membership (1):** existing FCMP++ discipline — challenges absorb `μ_claim`.
  - **ClaimLinkability (2):** SAL-class GSP, absorbs `μ_claim` (sibling to SAL, which already
    binds the spend message).
  - **Entitlement (3):** distinct domain + all public inputs + the root, mirroring the
    reserve-DLEQ challenge shape (`c = H(domain ‖ bases ‖ points ‖ msg)`):
    ```text
    c = keccak256_to_scalar(
          "shekyl-stake-entitlement-v1" ‖ G ‖ H ‖ N_le ‖ D_le
          ‖ C~ ‖ C_claim ‖ C_ρ ‖ R ‖ μ_claim )
    ```
    The byte field-set and order are locked dependency-free in
    [`entitlement::transcript`](../../rust/shekyl-staking/src/entitlement/transcript.rs)
    (KAT-tested) so the prover and the C++/FFI verifier cannot drift on *what* is hashed —
    dropping any public input or `μ_claim` is the splicing hole this layout forecloses.

- **Why a shared root, not a single monolithic transcript.** The three proof systems are
  heterogeneous and the BP+ is **self-contained** (its transcript seeds from the commitments
  `V`); upstream FCMP++/SAL already bind to `signable_tx_hash`. A single Merlin-style
  transcript threaded through all four would require re-architecting the upstream proofs for
  **zero** soundness gain: anti-splicing needs only that *every* challenge depend on a value
  (`μ_claim`) that uniquely identifies the claim. This is the established Monero
  pre-MLSAG-hash pattern, not a Shekyl invention.

- **Anti-splice argument (the trap this closes).**
  - *Move entitlement A → claim B:* `μ_A ≠ μ_B` (different nullifiers / outputs / root) ⇒
    `c_A ≠ c_B` ⇒ the spliced response fails. **Double cover:** the entitlement also binds
    `C~_A`, but B's membership proves `C~_B`; the verifier reads a **single** public `C~` per
    claim, so the mismatch is caught directly even ignoring `μ_claim`.
  - *Mutate the nullifier set, keep the proofs:* `{N_S}` is in the prefix ⇒ in `μ_claim` ⇒ all
    three challenges change ⇒ reject. (This is exactly the "tx hash + nullifier set" binding
    the round-2 agenda required.)
  - *Swap `C_ρ` between the entitlement and the range proof:* `C_ρ` is **one** public point
    referenced by both; there is no second copy to disagree.
  - *Reuse one component's challenge as another's:* distinct domain separators per component
    make challenges non-transferable.

- **Verifier ordering** (§6.4.8): range proof verifies → `μ_claim` is recomputed from the
  revealed prefix/base/bp → membership, ClaimLinkability, and entitlement each verify against
  that recomputed `μ_claim`. A claim with any field altered yields a different `μ_claim` and
  fails all three.

- **Reversion (`21-reversion-clause-discipline.mdc`):** the shared-root design holds **iff**
  every claim field is covered by `signable_tx_hash`. If a future component introduces an
  out-of-band public input *not* in prefix/base/bp (e.g. an auxiliary epoch-set blob carried
  outside the tx body), extend `μ_claim`'s preimage to cover it (and re-KAT), or move to an
  explicit sequential transcript. Substrate trigger: a claim public input that is not in the
  signed message.

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
| **B2** | Omit/weaken SAL; membership + standalone DLEQ rebinding `x` to `O` | **Rejected as primary** — splits spend-authority out of SAL then forces a sibling proof that re-derives most of what SAL already delivers; "faster to prototype" is not a design axis (§6.4.5) |
| **B3** | In-circuit scalar-mult vs public `G_S` inside FCMP | Heavier audit surface; fallback if B1 infeasible |

**Round 1 pins (B1 + constants):**

| Item | Pin |
|------|-----|
| **`G_S` domain** | UTF-8 `"shekyl-stake-nullifier-base"` concatenated with **`S_le64`** (settlement-epoch index, **uint64 little-endian**), then `crypto::hash_to_ec` (Category 2 Keccak path — same family as `Hp(O)`) |
| **`N_S` encoding** | 32-byte compressed Ed25519 point (same as key images) |
| **B1 surface** | New **`ClaimLinkability`** proof (sibling to SAL): proves `x ↔ O` spend-authority **and** emits tag `L_claim = x·G_S` for the tx's public `G_S` values; **does not** publish `x·Hp(O)` |
| **Verifier entry** | `shekyl_fcmp_verify_stake_claim(...)` (name TBD Round 2): staking-subtree membership + `h_bind` hash-equality + ClaimLinkability + entitlement (reserve-DLEQ class + bounded remainder, §6.4.1); **not** spend path. **No historical-root membership** (3C: window is `h_bind` arithmetic — Decision 2 subsumed) |
| **KAT** | `docs/test_vectors/STAKE_CLAIM_GS.json` (Stage 2); Round 1 pins domain + `S_le64` only |
| **`MAX_EPOCHS_PER_CLAIM`** | **`15`** — pins `|settlement_epochs| = |nullifiers|` on wire; tier-3 full-window drain; bounds **(B1)** ClaimLinkability + nullifier-vector size (not a separate economics constant). Wallets default to batching all unclaimed epochs when `≤ 15`; `= 1` is conservative test-mode only (partial-timing tell, §6.2) |

Wire layout: §6.4.8.

#### 6.4.3 (C) Tier + creation — **decision record**

**Record ID:** `CONFIDENTIAL_STAKING.md` §6.4.3 (2026-06-02; **Decision 3 closed 2026-06-04**).  
**Status:** **Tier + creation window — decided (3C).** Decision 3 closes on **3C** (separate
staking subtree + consensus-stamped creation; **3A** and **3B** rejected). Decision 1's
`(C_tier)`/`H_t` and Decision 2's historical-root lower bound are **superseded** by 3C
(`h_bind` carries `(tier, creation)`; window is pure arithmetic).  
**Unblocks:** §9 premise (validated multiplier requires honest tier + admissible accrual
window — both now closed via `h_bind`).

---

##### Requirement (why (C) exists)

Membership-unlinkable claims hide **which** staked leaf is opened. Without **(C)**, a
prover can satisfy **(A)** on a **forged multiplier** (e.g. tier-1 leaf, tier-3 `tier_num`)
while the range proof still passes moderate inflation. §9 step 1 therefore **requires**
consensus to bind the multiplier and accrual window to the opened leaf — not merely check a
proof on a wire-supplied multiplier. **(C)** is **P1 inflation-safety**
([`00-mission.mdc`](../.cursor/rules/00-mission.mdc)), not a yield-correctness optional.

**Verifier order (load-bearing):** staking-subtree **membership** + **`h_bind`
hash-equality** (binds `tier`, `creation`) → **window arithmetic**
(`creation < S ≤ creation + tier_lock`) → **multiplier recompute** (`N = tier_num(tier)·ΣK_S`,
**same revealed `tier`**) → **(B)** → **(A)** entitlement (§6.4.1, §6.4.8).

---

##### Pinned commitment construction (staked outputs, Decision 3C)

**Generators (Ed25519 curve):**

| Symbol | Definition |
|--------|------------|
| `G`, `H` | Standard Pedersen bases (value on `H`, mask on `G`) |

**At stake (consensus stamps `creation` at inclusion):**

```text
C_stake = z·G + amount·H                       // plain Pedersen — no τ·H_t
h_bind  = H("stake-bind" ‖ tier ‖ creation_height)   // consensus-set, 5th leaf scalar
```

- Staking-subtree leaf (5-scalar, 160 B): `Leaf = { O.x, I.x, C.x, h_pqc, h_bind }` with
  `h_pqc` at `[96:128]`, `h_bind` at `[128:160]`.
- Main tree (all non-staked outputs): **4-scalar, 128 B, unchanged.**
- Locked witness header `[O][I][C][h_pqc][x][y][z][a]` **unchanged** — `h_bind` is a public
  membership input, not a witness field.

**At membership (pseudo-out rerandomization on `G` only):**

```text
C~ = a·G + amount·H
```

**At claim (public `(tier, creation)` from wire):** verifier recomputes `h_bind`, proves
subtree membership against the **current** root, checks the window arithmetically, then runs
the bounded-remainder entitlement (§6.4.1). No `C~_amt` strip; no historical root.

**Entitlement (A):** bounded-remainder reserve-DLEQ relation `N·C~ − D·C_claim − C_ρ ∈ ⟨G⟩`
with `0 ≤ ρ < D` range-proven (§6.4.1). Tier forgery is excluded by the **single revealed
`tier`** driving both `h_bind` and `N` (below).

**Multiplier (public, recomputed by verifier):**

```text
N = tier_num_reduced(tier) · Σ_{S ∈ settlement_epochs} K_S_scaled
D = D_tier · SCALE_rate = 2 · 2⁴⁸ = 2⁴⁹      // power of two (§6.4.1)
reward = floor(N · amount / D)               // rounding toward under-claim
```

Verifier reads **one** `tier` scalar; uses it for the `h_bind` recompute **and** `tier_num`.
Reject on any mismatch before entitlement.

---

##### Decision 1 — Tier binding ✅ **CLOSED → superseded by 3C**

**Originally chosen (pre-3C):** CA-style `τ·H_t` generator in `C_stake`. **Superseded by
Decision 3C:** tier is bound by `h_bind` (subtree membership + hash equality), `C_stake` is
plain Pedersen, and the entitlement collapses to the §6.4.1 form. The `H_t` term is **dropped**.

| Alternative | Disposition |
|-------------|-------------|
| **`τ·H_t` in `C_stake`** (original C_tier) | Worked, but **superseded by 3C** — redundant once subtree membership marks "is-staked" and `h_bind` binds tier. Removing it collapses (A) to reserve-DLEQ (§6.4.1). |
| **`(C1)` `h_stake_bind` in unified-tree `leaf[96:128]`** | Unified-tree fallback only; **not** 3C (which uses a separate subtree + 5th scalar). |
| **Metadata Schnorr only** | Cannot tie a **hidden** opening to `(tier, creation)` without revealing index or changing leaf bytes. |

**Lineage (not shipping Zarcanum):** Shekyl inherits **RingCT-era Pedersen machinery**
(`G`, `H`, mask `z`/`a`, pseudo-outs `C~`, output derivation) and SAL spend paths —
still load-bearing. **Not inherited:** MLSAG/CLSAG rings, decoys, Borromean proofs.

---

##### Decision 2 — Creation lower bound ✅ **CLOSED → subsumed by 3C**

**Originally chosen (pre-3C):** historical-root membership at `S_min` ⇒ `creation ≤ S_min`.
That mechanism existed **only because** the unified tree could not carry creation in the leaf
(staker doesn't know mining height at build time). **3C dissolves that constraint:** consensus
stamps **exact** `creation` into `h_bind` at inclusion, so the lower bound (and the upper) are
**pure arithmetic** on the revealed, leaf-bound `creation`. **The historical-root mechanism is
no longer needed** — the claim proves only **current**-root subtree membership.

**Rule-21 note:** this is a substrate-change supersession (the M3d-Finding-5 pattern) — the
chosen mechanism's rationale went vacuous when 3C landed; it is recorded as subsumed, not
silently dropped. Per-epoch historical-root checkpointing leaves the consensus surface
entirely under 3C (it was a 3A cost).

---

##### Decision 3 — Creation window (`eff_lock`) ✅ **CLOSED → 3C (2026-06-04)**

**Requirement:** every claimed `S` must satisfy `S ⊆ (creation_height, eff_lock]` with
`eff_lock = creation_height + tier_lock_blocks(tier)`, where
**`creation_height ≜ eligible_height`** (§2 canonical definition).

**Chosen: 3C — separate staking subtree + consensus-stamped creation.** Both window bounds
become **arithmetic** on the `h_bind`-bound `creation`; Decision 2's historical root and
Decision 1's `H_t` are subsumed.

| Option | Mechanism | Disposition |
|--------|-----------|-------------|
| **3A — Non-membership** | Prove leaf **not** in root at `eff_lock` (Curve Forests, eprint 2024/1647) | **❌ Rejected.** Introduces a **novel consensus ZK primitive** with no production audit trail + per-epoch historical-root checkpointing; spawns a V3.0 pre-genesis crypto obligation. Loses lenses 2/4/5; silent-fail (inflation) on a subtle bug. |
| **3B — Coarse public window** | Cap claims by tier-class max lock without per-stake `creation` | **❌ Rejected (P1).** Late-created stake in a tier class claims epochs **past** its true `eff_lock` → **§9 step 2 inflation** (delay-proportional over-claim). Consensus soundness break, not a privacy tradeoff. |
| **3C — Separate staking subtree** | **Second curve tree** for staked outputs. **5-scalar leaf** (160 B): `{O, I, C, h_pqc, h_bind}`, `h_bind = H("stake-bind" ‖ tier ‖ creation_height)` **consensus-set at subtree drain** (`creation_height ≜ eligible_height = mining + MIN_AGE`, §6.4.3 — *drain*, not block-inclusion). Claim: subtree membership + `h_bind` equality + arithmetic window. **ZK surface:** Pedersen + existing membership + hash — **no new primitive**. **Cost:** second accumulator + cross-tree stake/unstake atomicity — **state/ops**. | **✅ CHOSEN.** Wins/ties 6 of 7 lenses (privacy wash); the contested consensus-complexity lens is a state-vs-crypto trade the discipline resolves toward **state** (pattern-replicates the main tree's deferred-insertion + atomic pop). Fail-loud (rejected claim). |

**7-lens summary:** 1 security (tight, loud-fail) **3C**; 2 cryptography (no new primitive)
**3C**; 3 consensus/atomicity (2 trees vs 1 tree + non-membership + hist-roots) **leans 3C**;
4 dependency (reuses existing) **3C**; 5 debt/pre-genesis (bounded state vs novel crypto)
**3C**; 6 privacy **wash** (both anonymize within staked-tier-in-window — the entitlement
already scoped the set); 7 UX/failure-mode (marginal proof, loud-fail) **3C**.

**Performance corollary (FA-6):** the 5th scalar is staking-subtree leaf-layer only
(~+25% on that Selene MSM per [`tree.rs`](../../rust/shekyl-fcmp/src/tree.rs)
`SCALARS_PER_LEAF`); main tree unchanged; **off the wallet-scan/decap path** — no
block-loading impact ([`FA-6_VIEW_TAG_ML_KEM.md`](FA-6_VIEW_TAG_ML_KEM.md)).

**Cross-tree atomicity:** stake-creation (spend main-tree input → append subtree leaf) and
unstake (publish subtree-leaf key image → append main-tree principal output) are **symmetric
cross-tree transitions**; `pop_block` must rewind both directions atomically with the
nullifier set and `band_sum` (§11). Curve-tree leaves are **append-only**, so
**claim-after-unstake (R0-D6) survives** — the subtree leaf persists; the nullifier set
prevents epoch re-claim.

**Entitlement collapse (coupled to 3C, rule 21):** with the is-staked marker in subtree
membership and tier in `h_bind`, `C_stake` drops `τ·H_t` and **(A)** collapses to the
reserve-DLEQ-class + bounded-remainder relation (§6.4.1). **Reverts if 3C reverts.**

**Reopen criteria (reversion-clause):** reopen only if implementation surfaces a cross-tree
atomicity hazard that cannot be closed with the main tree's existing pop discipline, or if a
later audited non-membership primitive makes a unified tree strictly cheaper end-to-end
(unlikely — 3C is now the substrate).

---

##### Transfer, liquid staking, and **(C)** recurrence

**Confidential stake-UTXO transfer** (FCMP spend of principal + re-insert as staked) is
**privacy-compatible** and **not** the same as receipt-token liquid staking (which remains
out of scope — public fungible receipts leak cohorts). Transfer **does** compound **(C)**:

- **`creation_height` is inherited**, not reset at re-insert — accrual window follows the
  original bond, not the transfer block.
- **Decision 3C** (consensus-stamped `h_bind` at **first subtree drain**, `eligible_height`)
  **conflicts** with naive re-stake-after-transfer unless the spend path carries
  `(tier, creation)` in the new leaf's 5th scalar (owner-proven continuity, not a fresh
  consensus stamp).

Spec target: [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) — *confidential stake-UTXO transfer*.
Round 2 closes Decision 3 before wallet transfer UX; creation inheritance is load-bearing
either way.

---

##### §9 premise — what this record establishes

| §9 assumption | Satisfied by (3C) |
|---------------|--------------|
| Multiplier's `tier_num` matches the opened leaf's tier | **`h_bind`** equality + **single revealed `tier`** drives both `h_bind` and `N` |
| Claimed epochs relate to **this** stake's life | **`h_bind`** exact `creation` → `creation < S ≤ creation + tier_lock` (pure arithmetic; both bounds) |
| Per-claim mint bounded given honest multiplier | **(A)** bounded-remainder relation `N·C~ − D·C_claim − C_ρ ∈ ⟨G⟩`, `0 ≤ ρ < D` (§6.4.1) |

§9 steps 2–3 (`ρ_cap`, lifetime) unchanged. **Pin:** per-claim inflation from tier/window
forgery and rounding over-claim is **designed closed** under 3C; no residual window gap.

---

##### Implementation disposition (3C)

| Item | Status |
|------|--------|
| **(C) P1** | Closed (this record; 3C) |
| **Staking subtree** (own root, deferred insertion, LMDB tables; cross-tree stake/unstake atomicity) | Round 2 implementation |
| **5-scalar leaf** + `h_bind` (consensus-set at inclusion) | Round 2 implementation |
| **`SCALARS_PER_LEAF`** const → per-tree param (`=5` staking subtree) + 5th-position Selene NUMS generator | Round 2; cbindgen consensus-constant guard + KAT |
| **Window arithmetic** `creation < S ≤ creation + tier_lock`, `creation ≜ eligible_height` | Round 2 (replaces historical-root lb); canonical height shared with servo (§2, §9) |
| **Entitlement** reserve-DLEQ class + bounded remainder, FS domain `shekyl-stake-entitlement-v1` | Round 2 (§6.4.1); decisions **1(a)** `D=2⁴⁹`, **1(b)** fold `C_ρ` into 64-bit BP+, **3** shared `μ_claim` transcript — ✅ closed |
| ~~`H_t` / `C~_amt` / historical-root lb~~ | **Dropped** — superseded by 3C |

**Round 2 mechanical pins (bundle):**

- `SCALARS_PER_LEAF` const → per-tree parameter; 5th-position Selene generator is a NUMS
  consensus constant → cbindgen guard + KAT.
- **`creation_h = eligible_height` (RESOLVED).** The accrual-window start (stamped into
  `h_bind`) **and** the `band_sum`-entry height are **one canonical definition**
  (§2 canonical block), referenced by both the claim verifier and the servo so they cannot
  drift. **`accrual-before-counted` is forbidden** (§9 step 2 — silent over-pay). Chosen on
  three independent grounds: **(i) conservation** — the safe direction is to start accrual no
  earlier than the stake is counted, the same conservatism as round-toward-under-claim
  (§6.4.1); **(ii) tree-consistency** — the claim proves staking-subtree membership, so
  "in the tree ⟺ accruing ⟺ counted" is **one** fact, not three that can drift;
  **(iii) reorg-stability (via deferred insertion, not assertion).** The protection is
  **structural on the insertion side** (the drain-gate), *not* on the reference side. The
  staking subtree reuses the main tree's deferred-insertion + journaled-pop **mechanism**
  (`add_pending_tree_leaf(maturity)` / `drain_pending_tree_leaves` / per-block journals,
  `blockchain_db.cpp` — **verified source-anchored**: `maturity` is computed from the
  *source block* height, never the drain-time tip, and the drain fires only at
  `maturity ≤ current_height`). The staking subtree's drain buffer is its own value,
  `eligible_height = mining + MIN_AGE` (the live main tree uses larger per-type *spend*
  maturities — staked outputs drain at `max(effective_lock_until, H + DEFAULT_TX_SPENDABLE_AGE)`
  in the pre-3C single tree — but by the **same** source-anchored gate; only the buffer
  constant differs). So a staked output mined at `H` becomes membership-provable **only at
  `H + MIN_AGE`**, and `h_bind` is frozen at that drain. Because the gate admits only leaves
  whose source is already `≥ MIN_AGE` deep, **every root — current included — contains only
  stable-`h_bind` leaves**; that is why claims proving membership against the **current root**
  (§6.4.3 verifier) and `h_bind`-stability coexist with no tension — the buffer never had to
  sit on the reference side. **Convergence within bound.** Because the anchor is
  source-relative, it is invariant under any reorg shallower than `MIN_AGE`: such a reorg
  cannot touch the source block (already `≥ MIN_AGE` deep by drain), so a pop-then-re-extend
  re-drains at the **identical** `eligible_height` and re-derives the **identical** `h_bind`.
  "Restore the stamped leaf" and "recompute on re-insert" are therefore **two spellings of the
  same value within bound** — pop-correctness is *unobservable* within bound, so the guarantee
  does not depend on the pop code being careful. A **shallow reorg (`≤ MIN_AGE`) catches the
  output undrained in `pending_tree_leaves`**; `pop_block` restores/removes the journaled
  pending entry and re-mine re-derives `h_bind` at the new `eligible_height` on re-drain —
  **no drained-leaf `h_bind` mutation ever occurs.** (*Beyond* bound — a `> MIN_AGE` reorg
  re-mining a *drained* leaf's source — `eligible_height` genuinely changes and the two
  spellings diverge: re-drain-recompute self-heals by re-deriving from the new source;
  store-stamped would carry an `h_bind` no honest claim ever recomputes = **permanent
  corruption**. §11 pins re-drain-recompute for exactly this reason. That regime inherits the
  FCMP reorg envelope — a `> MIN_AGE` reorg already invalidates in-flight FCMP references
  broadly — so stakes carry no stake-specific new exposure.) The argument is
  **tier-independent**: the buffer is the `mining → eligible` deferral, which carries no tier
  term; `tier_lock` governs only the claim *validity* window
  (`creation < S ≤ creation + tier_lock`), and the smallest tier (~1,000 blocks) is
  `≫ MIN_AGE`. **UX cost:**
  effective lock = `tier_lock + deferral` (~5-block warm-up, <0.5% even on the 1,000-block
  tier) — disclose "lock begins when the stake matures, ~N blocks after confirmation"; not a
  reason to anchor on mining. **Reversion clause (rule 21):** if exact advertised-lock
  duration ever becomes a hard UX requirement, the deferral is deterministic, so `eff_lock`
  may derive from `mining_h + tier_lock` **while accrual stays on `eligible_height`** — but
  do **not** split the two roles unless that UX genuinely matters, since one bound height
  with one canonical definition is the lower-drift design.
- `h_bind` hash-to-field reduction canonical / collision-safe (KAT).
- Verifier uses the **single revealed `tier`** for both the `h_bind` recompute and `N`
  (loud-reject invariant; KAT).
- Entitlement: single floor over batched `N`; remainder **committed** (`C_ρ`), **never
  revealed**; `ρ ≥ 0` proven by folding `C_ρ` into the reward-output 64-bit
  `AggregateRangeProof` (1(b)); honest `ρ < D = 2⁴⁹`; rounding toward under-claim.

**Amendment targets:** §2 (plain `C_stake`); [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §15
(staking subtree + 5-scalar leaf, witness header untouched); §6.4.8 wire;
[`AUDIT_SCOPE.md`](../AUDIT_SCOPE.md) (drop `τ·H_t` vectors, add `h_bind`/`creation` +
bounded-remainder vectors).

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
skip nullifier separation, or ship claim verification without **(C)** tier/window binds
are **out of scope** regardless of prototype convenience. "Get it right, not get it now" applies to
claim-circuit work the same as consensus work.

#### 6.4.6 Audit scope

The claim verifier ( subtree membership + **`h_bind`** + window arithmetic + multiplier
recompute + **(A)** bounded-remainder + **(B)** ) is a **derivative** of upstream FCMP++ and
is listed in [`AUDIT_SCOPE.md`](../AUDIT_SCOPE.md) §Confidential stake claim verifier.

#### 6.4.8 Claim transaction wire sketch (Round 1)

Replaces cleartext `txin_stake_claim` + watermark path (§12). Byte-exact layout is
Round 2; structural fields:

**`txin_stake_claim_v2` (per claim input):**

| Field | Type | Notes |
|-------|------|-------|
| `tier` | u8 | Public; **single source** for `h_bind` recompute **and** `tier_num` (§6.4.1) |
| `creation_height` | u64 | Public; `h_bind` recompute + window arithmetic (both bounds) |
| `settlement_epochs` | `u64[]` | `|·| ≤ MAX_EPOCHS_PER_CLAIM` (15) |
| `nullifiers` | `point[32][]` | `N_S = x·G_S` per epoch; stake-claim set |
| `fcmp_membership` | blob | **Staking-subtree** membership at **current** root (5-scalar leaf); `h_bind` public input |
| `claim_linkability` | blob | **(B1)** ClaimLinkability |
| `entitlement` | blob | **(A)** `N·C~ − D·C_claim − C_ρ ∈ ⟨G⟩` (Schnorr); `C_ρ` is **folded into the reward output's 64-bit `AggregateRangeProof`** (`ρ ≥ 0`; §6.4.1 decision 1(b)), not a separate proof; FS domain `shekyl-stake-entitlement-v1`, challenge binds `μ_claim = signable_tx_hash` (decision 3) |

`N = tier_num_reduced(tier)·Σ_S K_S_scaled` and `D = D_tier·SCALE_rate = 2⁴⁹` are
**verifier-recomputed**, not wired.

**Transaction body (unchanged shape):** one `C_claim` reward output + BP+ range proof;
RCT balance ties `C_claim` mint to pseudo-outs; **no** principal spend / **no** key image
in spent set.

**Consensus checks (ordered):** nullifier absence → **recompute `μ_claim = signable_tx_hash`**
(over prefix + base + folded BP+; decision 3) → subtree membership (current root, binds
`μ_claim`) + **`h_bind`** equality (from revealed `tier`,`creation`) → **window arithmetic** →
multiplier recompute (`N`,`D`; same `tier`) → **(A)** entitlement (binds `μ_claim`) + remainder
range (folded BP+) → **(B)** ClaimLinkability (binds `μ_claim`) → range → mint → `band_sum` /
rate accounting. The membership, entitlement, and ClaimLinkability challenges all absorb the
**single** recomputed `μ_claim`; a claim with any field altered yields a different `μ_claim` and
fails all three (anti-splicing, §6.4.1 decision 3).

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

**Premise (P1 — §6.4.3 decision record, 3C):** Before **(A)**, the verifier:

1. **Subtree membership + `h_bind`** — proves the opened leaf is in the staking subtree and
   its 5th scalar equals `H("stake-bind" ‖ tier ‖ creation)` for the **revealed**
   `(tier, creation)`.
2. **Window arithmetic** — `creation < S ≤ creation + tier_lock(tier)` for every claimed `S`
   (both bounds; no historical root).
3. **Recomputes** `N = tier_num(tier) · Σ_S K_S` using the **same revealed `tier`**;
   `reward = floor(N·amount/D)`.

Step 1 below assumes validated multiplier + window.

1. **Per-claim bound (given validated multiplier and window).** Entitlement **(A)** — the
   bounded-remainder relation `N·C~ − D·C_claim − C_ρ ∈ ⟨G⟩` with `0 ≤ ρ < D` — forbids
   minting more than `floor(N·amount/D)` for the membership-proven principal, and the
   committed remainder closes the **rounding over-claim** path. **Tier forgery** (tier-1 leaf,
   tier-3 `tier_num`) is excluded by `h_bind` + the single-revealed-tier rule.
   **`ρ_cap` (step 2)** caps epoch-total emission independently.
2. **Per-epoch bound.** `total staker emission_e = ρ_e · TWS_actual ≤ budget_e` by the
   cap (§4.2), for **any** `band_sum` (honest, stale, or manipulated). This is the bound
   `Σ_S accrued_S = ρ_e · (Σ accruing weights) ≤ budget_S`, which holds **only if
   `band_sum_S` counts precisely the stakes accruing in `S`** — i.e. the accrual-window
   start and the `band_sum`-entry height are the **same** canonical `eligible_height` (§2,
   §4.1). **Forbidden configuration (asymmetric, silent):** *accrual-before-counted* —
   accrual anchored at a height earlier than `band_sum` entry (e.g. accrue from mining,
   count from eligible). Stakes in `[earlier, entry)` then draw `ρ_e·weight` while **absent
   from the denominator** → `Σ accrued > budget` → **silent over-pay (inflation)**, no
   reject. The reverse (counted-before-accrued) merely inflates the denominator → safe
   under-pay. The canonical single-source height (§2) is the **structural** defense: the
   claim verifier and the servo reference one definition and cannot drift independently.
3. **Lifetime bound.** `Σ_e budget_e ≤ Σ_e target_share_e · block_emission_e ≤
   STAKER_EMISSION_SHARE · (total emission) < MONEY_SUPPLY` (since `target_share < 1`
   and total emission ≤ ceiling).

The miner stream (coinbase) remains publicly summable (§10), so total supply is
**auditably bounded** even though the staker stream is hidden. Per-claim **(A)**
bounded-remainder relation + range (1), epoch **`ρ_cap`** (2), and **(C)** tier/window
integrity via `h_bind` are therefore all consensus-critical. **Pin:** **(C)** is P1, closed
on **3C** (§6.4.3); **(A)** is the reserve-DLEQ-class + bounded-remainder relation, coupled
to 3C (§6.4.1).

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

## 11. Reorg / `pop_block` atomicity (unified 3C reversal spec)

**Status: spec-only.** 3C state (staking subtree, nullifier table, `h_bind`) is **not yet
implemented** — the live `pop_block_from_blockchain` (`blockchain.cpp`, accrual-reversal
block) reverts the **pre-3C** accrual/pool/burn model (`get_staker_accrual` →
`set_staker_pool_balance` → `remove_staker_accrual`), which 3C **replaces**. This section is
the complete reversal surface to instantiate at Round 2; the atomicity audit re-run is a
Round-2 task and is **mechanical**, because every element below maps onto a pattern the main
tree already implements and the `LMDB_WRITE_ATOMICITY_AUDIT.md` already PASSed for one tree.

**The reusable pattern.** The main tree's deferred-insertion + atomic-pop is the template:
per-block journals (`m_pending_tree_drain` records what each block drained; the
block-pending-additions journal records what each block added to `pending_tree_leaves`), so
`pop_block` trims drained leaves back to pending and deletes block-added pending entries by
primary key — exact, DUPSORT-free, atomic within the block's write txn. 3C instantiates the
same shape for a second tree and adds journaled tables.

On `pop_block`, **one atomic LMDB transaction** (the existing `batch_start`/`batch_stop`
wrap, with the `db_wtxn_guard` defensive guard) must revert, for popped claim/stake txs:

1. **Staking subtree leaves** — its own `pending_tree_leaves` / `pending_tree_drain` /
   block-pending-additions triple, mirroring the main tree. Because `h_bind` is frozen at
   **drain** (`eligible_height = mining + MIN_AGE`, §6.4.3), a shallow reorg (`≤ MIN_AGE`)
   touches only **undrained** pending entries — pop restores/removes the journaled entry and
   re-mine re-derives `h_bind` on re-drain. No drained-leaf `h_bind` mutation (§6.4.3 ground
   iii). **Pin (load-bearing): re-drain MUST recompute `h_bind` from the re-mined source
   height — never cache or restore the previously-stamped leaf across a pop.** Within the
   `MIN_AGE` bound the two are identical (source-anchored convergence, §6.4.3 iii), so the
   distinction is a within-bound no-op; *beyond* bound (a `> MIN_AGE` reorg re-mining a drained
   leaf's source) they diverge — recompute self-heals to the new `eligible_height`, while a
   cached stamped leaf carries an `h_bind` no honest claim ever recomputes (**permanent
   corruption**). The pin exists precisely so a future implementer does not "optimize" the pop
   by stashing the stamped leaf in pending — a within-bound no-op that silently becomes a
   beyond-bound corruption. The beyond-bound regime is **not a stake-specific exposure**: a
   `> MIN_AGE` reorg already invalidates in-flight FCMP references broadly, so stakes inherit
   the same envelope the FCMP buffer assumes everywhere.
2. **Cross-tree stake/unstake transitions, both directions** (§6.4.3): stake = spent
   main-tree input → appended subtree leaf; unstake = consumed subtree-leaf key image →
   appended main-tree principal output. `pop_block` rewinds **both** directions atomically
   with (1).
3. **Nullifier-set insertions** — the stake-claim nullifier table is **new reorg-state** (the
   structural form of the prior C-2 finding), reverted via its own per-block journal so a
   reorged-then-re-mined claim is **re-claimable** (failure here = permanent claim rejection).
4. **`band_sum` / active-stake changes and rate-epoch records** (`{ρ_e, band_sum}`,
   replacing the retired accrual/pool fields).
5. **Minted reward outputs** (main-tree insertions) and staked-output insertions — covered by
   (1)/(2)'s leaf journals plus the output-table reversal.

Every member is journaled per-block and reverts inside the one block txn; nothing escapes it.
The audited curve-tree machinery is **live and reused**; only the staking-economics half
(accrual/pool) is superseded.

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
| `pop_block_from_blockchain` (accrual-reversal block; re-ground offset at Round 2 — `:800–822` is stale) | **Replace** the pre-3C accrual/pool/burn reversal with the unified 3C reversal: subtree leaves + cross-tree transitions + nullifier table + `band_sum`/rate-epoch + minted rewards, all journaled and atomic (§11) |
| `distribute_staker_rewards` / `StakeRegistry` (`rewards.rs`, `registry.rs`) | **Confirm sim-only** then **retire** — the direct-distribution model is obsolete under the rate model (was already not on the consensus path; zero `blockchain.cpp` hits) |
| `tiers.rs` (`TIERS`, `MAX_CLAIM_RANGE`) | **Keep** `TIERS`; **repurpose** `MAX_CLAIM_RANGE` → `MAX_EPOCHS_PER_CLAIM` (proof/nullifier budget, not a block-span; §5) |

---

## 13. Open decisions (post–Round 1)

Round 1 closures are in **§14**. Remaining items are Round 2+ implementation or
calibration refinements.

| # | Item | Status |
|---|------|--------|
| 1 | Burn signal: value-weighted `band` vs tier-weighted count | **Closed R1** — value-weighted band v1 (§14.1) |
| 2 | Window shape/length | **Closed R1** — LWMA-analog, 30 rate-epochs (§14.2) |
| 3 | `ρ_cap` decay handling | **Closed R1** — decay on budget only (§14.3) |
| 4 | Band scheme (count, spacing) | **Closed R1** — 5 decade-log bands, geometric midpoint (§14.1) |
| 5 | Cold-start floor | **Closed R1** — cross-cutting: servo (§14.1) + **P2** `band_sum` differencing gate (§14.4) |
| 6 | Entitlement **(A)** | **Closed** — reserve-DLEQ class + bounded remainder (§6.4.1); coupled to 3C |
| 7 | Nullifier **(B)** + `G_S` + `MAX_EPOCHS_PER_CLAIM` | **Closed R1** — pins §6.4.2; **KAT** Stage 2 |
| 8 | Tier/creation **(C)** | **Closed** — §6.4.3 **3C** (subtree + `h_bind`); Decisions 1–2 superseded; impl Round 2 |
| 9 | Claim anonymity widening | **Closed R1** — accept v1 scope (§14.4) |
| — | Byte-exact claim/stake serialization | **Round 2** |
| — | `STAKE_CLAIM_GS.json` / `h_bind` / 5-scalar-leaf + Selene-generator KATs | **Round 2** |
| — | **`eff_lock` window** | **Closed — 3C** (staking subtree + `h_bind` arithmetic, both bounds; 3A/3B rejected; §6.4.3). Impl Round 2. |

---

## 14. Round 1 closure record (2026-06-02)

Consensus Round 1 closes economics and **(B)**; **(C)** mechanism and **`eff_lock` upper**
close in Round 2 (§6.4.3). Wallet mirror: [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md)
§9 Round 1.

### 14.1 Economics & band (§13 items 1, 4; item 5 economics leg)

| Pin | Value | Reopen if |
|-----|-------|-----------|
| **Burn / servo signal** | **Value-weighted `band`** (geometric midpoint per §4.4) | Tier-weighted **count** alone is shown sufficient for governance **and** servo accuracy without amount leak (§8) — target **V3.2** review |
| **Band count** | **5** decade-log-spaced bands | UX/audit shows unusable cohorts |
| **Cold-start floor** | `band_sum_eff = max(band_sum, BAND_SUM_FLOOR)` with `BAND_SUM_FLOOR` = midpoint of tier-1 band × **1_000** (planning anchor; recalibrate at genesis). **Economics:** prevents servo/divide-by-near-zero blowups. **Privacy:** suppresses differencing/fingerprinting when cohorts are thin (§0.2, §14.4) | Mainnet-class participation shows floor distorts servo after 90 rate-epochs **or** privacy review shows floor still leaks cohorts |
| **Governance** | `stake_ratio_proxy = windowed_band_sum / circulating` (§8) | Count-only signal adopted per burn pin row |

### 14.2 Rate window (§13 item 2)

| Pin | Value | Reopen if |
|-----|-------|-----------|
| **Window type** | LWMA-analog on `band_sum` (§4.4) | Flash-manipulation study shows residual |
| **Window length** | **30 rate-epochs** (30,000 blocks ≈ 44 d) | Servo too sluggish or too whipsaw in simulation |

### 14.3 `ρ_cap` (§13 item 3)

| Pin | Value | Reopen if |
|-----|-------|-----------|
| **Cap formula** | `ρ_cap_e = budget_e / (circulating_e · max_tier_mult)` (§4.2) | Supply audit requires terminal-cap variant |
| **Decay** | `0.90/yr` applies to **`budget_e` / `target_share` only**; **cap denominator uses current circulating** (no decay on `circulating` in cap) | Calibration shows cap must track decayed ceiling |

### 14.4 Privacy (§13 items 5, 9)

| Pin | Value | Reopen if |
|-----|-------|-----------|
| **Cold-start / thin cohorts (item 5 — P2)** | Do not publish or governance-read raw `band_sum` deltas when effective participation is below a **cohort threshold**; use `band_sum_eff` floor (§14.1) and/or suppress burn-signal publication until threshold met | Empirical testnet shows residual individual fingerprinting despite floor |
| **v1 anonymity (item 9)** | Accept tier+window-scoped claim sets (§6.2) | Product requires full-staker-set indistinguishability before genesis |
| **Per-stake claim sequence (Round 3)** | Full-window batching default (§5); wargame drip vs delay-then-batch | Residual serial correlation persists under any finite `MAX_EPOCHS_PER_CLAIM` |
| **L4** | Deferred — hide tier and/or window in claim | External spec for hidden-metadata claims lands with lattice-only path (V4 gate) |

### 14.5 Cryptographic summary

| Binding | Round 1 disposition |
|---------|---------------------|
| **(A)** | Off-circuit reserve-DLEQ class + bounded remainder `N·C~ − D·C_claim − C_ρ ∈ ⟨G⟩`, `ρ ≥ 0` folded into the reward output's 64-bit BP+ (`D=2⁴⁹`; decisions 1(a)/1(b)); FS domain `shekyl-stake-entitlement-v1`, challenge binds shared `μ_claim = signable_tx_hash` (decision 3, anti-splicing); coupled to 3C (§6.4.1) |
| **(B)** | `N_S = x·G_S`; ClaimLinkability (B1); `MAX_EPOCHS_PER_CLAIM = 15`; DDH split §6.3 |
| **(C)** | **P1** — §6.4.3 **3C**: staking subtree + 5-scalar `h_bind` (tier+creation); window arithmetic. Decisions 1 (`H_t`) & 2 (historical root) superseded |
| **Rejected** | **3A** non-membership (novel ZK); **3B** coarse window (P1 inflation); spend-and-restake; B2-primary; `nullifier_seed` HKDF; persist `x` in wallet; reveal remainder `ρ` (deanon) |

---

## 15. References (doc index)

| Doc / site | Use |
|-----------|-----|
| [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) | Wallet mirror (§2.3); R0-D1–D7; `N_S = x·G_S` §8.5; §6.4 review pins |
| [`STAKER_REWARD_DISBURSEMENT.md`](STAKER_REWARD_DISBURSEMENT.md) | **Superseded** reward/claim mechanism (retained for history) |
| [`DESIGN_CONCEPTS.md`](DESIGN_CONCEPTS.md) | Four-component economic model (Components 2–4) |
| [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) | Membership / curve trees; staking subtree + 5-scalar `h_bind` leaf (§15) |
| [`WITNESS_HEADER.json`](../test_vectors/WITNESS_HEADER.json) | Consensus-locked witness layout |
| [`AUDIT_SCOPE.md`](../AUDIT_SCOPE.md) | Claim verifier (§6.4.6); Confidential stake claim verifier section (Round 1) |
| `blockchain.cpp` (`:800–822`, `:3476`, `:4214–4247`, `:4366–4376`, `:5045–5051`) | Code sites superseded (§12) |
| `shekyl-staking` (`tiers.rs`, `registry.rs`, `rewards.rs`), `shekyl-economics`, FFI `lib.rs` | Tier/economics primitives; retirements (§12) |
| [`00-mission.mdc`](../.cursor/rules/00-mission.mdc), [`26-sub-pr-design-discipline.mdc`](../.cursor/rules/26-sub-pr-design-discipline.mdc) | Priority hierarchy; round discipline |
