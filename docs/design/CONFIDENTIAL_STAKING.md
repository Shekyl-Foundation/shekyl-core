# Confidential staking — consensus & economics design

**Status:** **Round 1 closed** (2026-06-02) on economics and **(B)**. **(C)** §6.4.3
(tier + window lb **closed**; `eff_lock` ub **open**, **3A/3C** co-equal, **3B rejected**).
**(A)** off-circuit, sound modulo **(C_tier)**. Round 2: close Decision 3, byte wire, KATs.
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
| `τ` | Tier scalar committed on `H_t` at stake time (matches public `tier`; §6.4.3 **(C_tier)**) | — |
| `x` | Spend secret `ho + b` (witness `x`) | — |

**Commitment form:**

- **Regular / coinbase:** `C = z·G + amount·H`
- **Staked (`txout_to_staked_key`):** extend the generator basis (Confidential Assets /
  typed-output pattern — §6.4.3):

```text
C_stake = z·G + amount·H + τ·H_t
H_t     = hash_to_ec("shekyl-stake-tier")   // NUMS; single generator, discrete τ ∈ {τ₁,τ₂,τ₃}
```

`τ` is fixed when the staker builds the tx (they choose tier). The **128-byte curve-tree
leaf is unchanged:** `{ O.x, I.x, C.x, h_pqc }` — only `C.x` commits to one more base.

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

**Weight / entitlement scalar `M`.** Public `tier` on the output and claim tx determines
`tier_num`; accrual uses `M = tier_num · Σ_S K_S` (§3). **(C_tier)** binds the **hidden**
opened commitment to the same `τ` as the public tier used in `M` (§6.4.1, §9) — tier
stays **public on the wire** (lock duration already leaks tier class; §2 prior pin).

**Decision (pinned): tier public on wire.** The CA-style generator binds the **membership
opening** to the claimed tier for inflation safety; it does not re-hide tier on-chain.

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
is **O(1)** in epoch count — a single Schnorr on `M = tier_num · Σ_S K_S` after `C~_amt`
strip (§6.4.1) — so only the nullifier count scales (one `N_S` per epoch; ~15 for a
tier-3 full drain). **`MAX_EPOCHS_PER_CLAIM = 15`** is pinned with **(B)** (§6.4.2:
bounds wire vectors and ClaimLinkability size).

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
`(z, amount, x, a, z_claim)` — where **`amount`** is the hidden principal,
**`z`** the stake commitment mask, **`x`** the spend secret, **`a`** the membership
pseudo-out blinding (`C~ = a·G + amount·H + τ·H_t` for staked leaves; §6.4.3), **`z_claim`**
the claim-output mask — and a membership witness such that:

1. **Membership.** `C_stake` is a leaf under the unified curve-tree root (FCMP++
   commit-and-prove; standard 128-byte leaf — §6.4.3) — does **not** reveal which.
2. **Window.** every claimed settlement-epoch `S` satisfies `S ⊆ (creation, eff_lock]`
   (`eff_lock = creation + tier_lock_blocks`); **(C_window)** binds `creation` from below
   via historical-root membership; **upper bound on `eff_lock`** is Round 2 open (§6.4.3).
3. **Nullifiers.** for each claimed `S`, `N_S = x·G_S` with `G_S =
   hash_to_ec("shekyl-stake-nullifier-base" ‖ S_le64)` (public base, distinct from
   `Hp(O)`); each `N_S` is filed in the **stake-claim nullifier set** (not the spent
   key-image set) and must be absent before inclusion (no double-claim). Principal
   `x·Hp(O)` is **not** published on claim (§7).
4. **Entitlement.** `C_claim ≡ M · C_stake` (homomorphic sense on opened amount leg).
   Consensus **recomputes `M`** from **(C)**-validated `tier` and `settlement_epochs`
   (§9). **(C_tier)** then **(A)** on the amount leg: define `C~_amt := C~ − T·H_t` for
   public claim tier scalar `T`; prove `C_claim − M·C~_amt ∈ ⟨G⟩` (§6.4.1).
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
(tier + window lb **closed**; `eff_lock` ub **open**, 3A/3C co-equal). **(A)** off-circuit
on `C~_amt` — **closed** (sound modulo **(C_tier)**).

#### 6.4.0 Source facts (consensus-locked; any change is a consensus change)

| Fact | Source | Claim use |
|------|--------|-----------|
| Witness `[O][I][C][h_pqc][x][y][z][a]` | [`WITNESS_HEADER.json`](../test_vectors/WITNESS_HEADER.json) | Opening material for membership |
| `r_c = a − z`, `C~ = a·G + amount·H` | `rust/shekyl-fcmp/src/proof.rs` (`ProveInput` docs) | **(A)** uses public `C~` as `pseudo_outs` |
| `I = Hp(O)` in witness; SAL uses rerandomized `I~` | `rctSigs.cpp`, `sal/mod.rs` | Linkability algebra |
| `L = (I~·x) − (U·(r_i·x)) = x·Hp(O)` ∀ `r_i` | `shekyl-oxide/.../fcmp/fcmp++/src/sal/mod.rs:233` with `I~ = I + U·r_i` (`:65`) | **(B)** tag is **not** re-baseable by tweaking `r_i` |
| `FcmpPlusPlus::verify` always runs `spend_auth_and_linkability.verify(…, key_image)` | `shekyl-oxide/.../fcmp/fcmp++/src/lib.rs` | No membership-only mode today |
| Staked leaf (4-scalar, 128 B) | [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §15 | `C.x` may use **`H_t`** basis (§2); **(C_tier)** preferred over type-dependent 4th scalar |
| Cleartext claims today: `txin_stake_claim`, no FCMP | `cryptonote_basic.h`, wallet stake-claim path | Confidential claim is **new** tx + verifier surface |

Reserve proofs already ship a standalone two-base Schnorr DLEQ (`rust/shekyl-proofs/src/dleq.rs`,
domain `shekyl-reserve-proof-dleq-v1`; [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §21) —
the proof class for **(A)** entitlement.

#### 6.4.1 (A) Entitlement — off-circuit (**sound modulo (C_tier)**)

**Round 1 status:** The commitment-to-zero Schnorr is **not** a standalone inflation
closure. It is **sound only when `M` is verifier-recomputed** and the membership
pseudo-out's tier leg matches the claim's public tier **(C_tier)** (§9). Wire `M` is
checked against the recompute **before** **(A)**.

**Pin (staked pseudo-out).** Membership exposes rerandomized `C~`. FCMP pseudo-out
rerandomization acts on the **`G` mask only**, so for a staked leaf:

```text
C~ = a·G + amount·H + τ·H_t
```

At claim, public tier scalar **`T`** (from wire `tier`, maps to committed `τ`):

```text
C~_amt := C~ − T·H_t = a·G + amount·H     // amount leg only
```

Prove `C_claim − M·C~_amt ∈ ⟨G⟩` via commitment-to-zero Schnorr with
**`d = z_claim − M·a`** (`a` = `pseudo_out_blind`; **`amount`** is the hidden principal on
`H`, not `a`). If a prover asserts **`T′ ≠ τ`**, then `C~_amt` retains `(τ−T′)·H_t`, the
difference is not in `⟨G⟩`, and the Schnorr **fails** — tier forgery for **(A)** is
algebraically excluded without a new FCMP++ circuit.

Scalar names match [`proof.rs`](../../rust/shekyl-fcmp/src/proof.rs) on the **amount**
leg; staked outputs add **`H_t`** to the commitment basis only (§2).

**Why off-circuit (not in-circuit).** Membership already exposes public `C~` as
`pseudo_outs`; entitlement is a **linear relation on public Pedersen points**. The
mature disposition is a standalone two-base Schnorr (reserve-DLEQ class in
`shekyl-proofs`) — **no FCMP++ circuit delta**. In-circuit entitlement would re-prove
inside the membership ZK what the verifier already holds, expanding the Veridise-scoped
circuit surface for zero privacy gain on `C~`. Same **minimize novel consensus crypto**
discipline that ranks Decision **3C** ahead of **3A** for the window upper bound (§6.4.3):
spend the ZK budget on membership + **(B)**, not on a redundant linear check.

**Reopen in-circuit (A)** only if pseudo-outs cease to be public inputs or a monolithic
single-blob proof becomes a hard audit requirement — not for leaf-format elegance.

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
| **Verifier entry** | `shekyl_fcmp_verify_stake_claim(...)` (name TBD Round 2): membership + historical-root membership + ClaimLinkability + `C~_amt` entitlement Schnorr (§6.4.1–§6.4.3); **not** spend path |
| **KAT** | `docs/test_vectors/STAKE_CLAIM_GS.json` (Stage 2); Round 1 pins domain + `S_le64` only |
| **`MAX_EPOCHS_PER_CLAIM`** | **`15`** — pins `|settlement_epochs| = |nullifiers|` on wire; tier-3 full-window drain; bounds **(B1)** ClaimLinkability + nullifier-vector size (not a separate economics constant). Wallets default to batching all unclaimed epochs when `≤ 15`; `= 1` is conservative test-mode only (partial-timing tell, §6.2) |

Wire layout: §6.4.8.

#### 6.4.3 (C) Tier + creation — **decision record**

**Record ID:** `CONFIDENTIAL_STAKING.md` §6.4.3 (2026-06-02).  
**Status:** **Tier + creation lower bound — decided.** **`eff_lock` upper — open fork**
(Round 2: **3A/3C** co-equal, lean **3C**; **3B rejected**).  
**Unblocks:** §9 premise (validated `M` requires honest tier + admissible accrual window;
tier closed; window closed from below; upper pending).

---

##### Requirement (why (C) exists)

Membership-unlinkable claims hide **which** staked leaf is opened. Without **(C)**, a
prover can satisfy **(A)** on a **forged wire `M`** (e.g. tier-1 witness, tier-3 `M`) while
the range proof still passes moderate inflation. §9 step 1 therefore **requires** consensus
to validate **`M`** against bindings on the opened leaf — not merely check a Schnorr on
wire `M`. **(C)** is **P1 inflation-safety** ([`00-mission.mdc`](../.cursor/rules/00-mission.mdc)),
not a yield-correctness optional.

**Verifier order (load-bearing):** **`M` recompute** ← **(C_tier)** + **(C_window)** →
**(B)** → **(A)** on `C~_amt` (§6.4.8).

---

##### Pinned commitment construction (staked outputs)

**Generators (Ed25519 curve):**

| Symbol | Definition |
|--------|------------|
| `G`, `H` | Standard Pedersen bases (value on `H`, mask on `G`) |
| `H_t` | `hash_to_ec("shekyl-stake-tier")` — NUMS; single tier-type generator |

**At stake (staker knows `τ`, not `creation_height`):**

```text
C_stake = z·G + amount·H + τ·H_t
```

- `τ ∈ {τ₁, τ₂, τ₃}` — tier scalars KAT-locked to `StakeTier` wire enum (Round 2).
- **Curve-tree leaf unchanged:** `Leaf = { O.x, I.x, C.x, h_pqc }` with
  `h_pqc = shekyl_fcmp_pqc_leaf_hash(ml_dsa_pk)` at bytes `[96:128]`.

**At membership (pseudo-out rerandomization on `G` only):**

```text
C~ = a·G + amount·H + τ·H_t
```

**At claim (public tier scalar `T` from wire `tier`):**

```text
C~_amt := C~ − T·H_t = a·G + amount·H
```

**Entitlement (A), sound modulo (C_tier):** prove `C_claim − M·C~_amt ∈ ⟨G⟩` (Schnorr on
`d = z_claim − M·a`). If `τ ≠ T`, residual `(τ−T)·H_t ∉ ⟨G⟩` → Schnorr fails.

**`M` (public, recomputed by verifier):**

```text
M = tier_num(T) · Σ_{S ∈ settlement_epochs} K_S
```

Reject if wire `M ≠ M_recomputed` before **(A)**.

---

##### Decision 1 — Tier binding **(C_tier)** ✅ **CLOSED**

**Chosen:** CA-style typed generator in `C_stake` (above). No leaf-format fork.

| Alternative | Why not |
|-------------|---------|
| **(C1) `h_stake_bind` in unified-tree `leaf[96:128]`** | Binds tier+creation via hash equality after opening — works on the **128-byte** leaf, but type-dependent 4th scalar and dual drain logic. **Demoted:** reserve for unified-tree fallback only; **not** the same as Decision **3C** (separate subtree, §6.4.3). |
| **Fifth scalar / 160-byte leaf in unified tree** | Breaks universal 128-byte curve-tree leaf; chunk geometry fork for one output class. **Rejected for Decision 1** (tier lives in `C.x`). **Reconsidered under Decision 3C** on a **separate staking subtree** where 5-scalar leaves are the norm. |
| **Separate staking Merkle tree (tier-only)** | Second accumulator for tier alone — disproportionate when `H_t` in `C_stake` suffices (Decision 1). **Not rejected** when the tree carries **consensus-stamped creation** (Decision 3C). |
| **Metadata Schnorr only** | Cannot tie a **hidden** opening to `(tier, creation)` without revealing index or changing leaf/commitment bytes. |

**Lineage (not shipping Zarcanum):** Shekyl inherits **RingCT-era Pedersen machinery**
(`G`, `H`, mask `z`/`a`, pseudo-outs `C~`, output derivation) and SAL spend paths —
still load-bearing. **Not inherited:** MLSAG/CLSAG rings, decoys, Borromean proofs.
The **`H_t` typed-generator fragment** follows Confidential Assets / Elements / Zano
Zarcanum-adjacent **commitment** patterns; **membership is FCMP++ curve trees**, not
Zarcanum ring proofs.

---

##### Decision 2 — Creation binding lower bound **(C_window, lb)** ✅ **CLOSED**

**Chosen:** **Historical-root membership** at earliest claimed settlement-epoch `S_min`.

Prove the same leaf is a member of the curve-tree root **checkpointed as of `S_min`**
(per-height roots from deferred insertion — [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §15).
Leaves appear in roots only from insertion height onward ⇒ **`creation_height ≤ S_min`**
(accrual window bounded from below).

| Alternative | Why not (for lower bound) |
|-------------|---------------------------|
| **Commit `creation` in `C_stake`** | Staker does not know mining height at tx build time — attribute is determined at **inclusion**, not commit time (unlike `τ`). |
| **`(C1)` hash bind only** | Can bind `creation` in `leaf[96:128]`, but forfeits uniform leaf + clean tier story; reserve for upper-bound fallback (Decision 3). |
| **Public `creation_height` on wire alone** | No link to hidden opening under unlinkable membership — inflation path unchanged. |

---

##### Decision 3 — Creation binding upper bound (`eff_lock`) ⚠️ **OPEN FORK (Round 2)**

**Requirement:** every claimed `S` must satisfy `S ⊆ (creation_height, eff_lock]` with
`eff_lock = creation_height + tier_lock_blocks(tier)` (§6.1). Lower bound is Decision 2;
**this decision is the top of the window.**

| Option | Mechanism | Status / lean |
|--------|-----------|---------------|
| **3A — Non-membership** | Prove leaf **not** in root at `eff_lock` (Curve Forests-style extension; eprint 2024/1647) | **Co-equal fork.** Strongest semantics on the **unified** 128-byte tree. **Cost:** novel non-membership ZK in consensus — no audited production path in Shekyl today. **If chosen:** spawns a **V3.0 pre-genesis** follow-up (non-membership primitive + audit scope + KATs before genesis) — see queue corollary below. |
| **3B — Coarse public window** | Cap claims by tier-class max lock or policy without per-stake `creation` on wire | **❌ REJECTED (P1).** A stake created late in its tier class can claim epochs **after** its true `eff_lock` while still passing Decision 2's lower bound: wire `M` and **(A)** use full `band_sum` weight, but only a subset of epochs are legitimately accrual-eligible → **§9 step 2 inflation** (delay-proportional over-claim), not merely a weaker anonymity story. Not a utility floor — a consensus soundness break. |
| **3C — Separate staking subtree + consensus-stamped creation** | **Second curve tree** for staked outputs only. **5-scalar leaf** (160 B): `{O, I, C, h_pqc, h_bind}` where `h_bind = H("stake-bind" ‖ tier ‖ creation_height)` is set by **consensus at inclusion** (not by the staker at commit time). Claim proves membership + `h_bind` matches revealed `(tier, creation)` + Decision 2 lb. **ZK surface:** Pedersen + FCMP membership + hash equality — no new proof system. **Cost:** second accumulator, dual historical roots, reorg journals — **state/ops**, not novel crypto. **Perf ([`FA-6`](FA-6_VIEW_TAG_ML_KEM.md)):** 5th scalar is staking-subtree leaf-layer only (~+25% on that Selene MSM per [`tree.rs`](../../rust/shekyl-fcmp/src/tree.rs) `SCALARS_PER_LEAF`); main tree unchanged; off wallet-scan/decap path — **no FA-6 block-loading impact**. | **Co-equal fork; Round 2 default lean** on crypto maturity + queue trajectory ([`FOLLOWUPS.md`](../FOLLOWUPS.md) preamble). Distinct from **(C1)**. **If chosen:** §15 staking-subtree amendment — bounded state/ops (see queue corollary). |

**Performance corollary (FA-6):** Wallet block-loading is dominated by per-output hybrid
ownership (ML-KEM decap + view tag) — [`FA-6_VIEW_TAG_ML_KEM.md`](FA-6_VIEW_TAG_ML_KEM.md).
3C's leaf-layer delta is daemon insertion/validation and infrequent claim-time work; 3A's
non-membership and checkpointed roots sit on the same non-scan paths. **FA-6 does not break
the 3A/3C tie** — crypto-maturity vs state-surface still governs; the 5-scalar leaf is not
a reason to reconsider 3C.

**Queue-trajectory corollary (FOLLOWUPS):** Round 2's **(C_window) ub** choice spawns
**different queue items** — neither is listed in [`FOLLOWUPS.md`](../FOLLOWUPS.md) yet,
correctly, while the fork is open. Per the preamble's **V3.0 pre-genesis queue**
discipline (load-bearing; accumulation compounds the genesis trajectory):

| If Round 2 picks | Spawned item (added on close) | Queue class |
|------------------|-------------------------------|-------------|
| **3A** | Land Curve Forests-style **non-membership** in consensus with explicit audit scope + KATs **before genesis** | **V3.0 pre-genesis** — new load-bearing crypto obligation |
| **3C** | Amend [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §15 for **staking subtree** (5-scalar leaf, dual accumulator, dual historical roots) | **Bounded state/ops** — reviewable implementation work, not a novel pre-genesis primitive |

This **reinforces the 3C lean** alongside crypto maturity and FA-6: 3C adds bounded,
reviewable state work; 3A adds a pre-genesis crypto deliverable the queue preamble warns
against accumulating casually. **Round 2 should decide with this queue cost visible.**

**Round 2 must close 3A or 3C** before the claim verifier is inflation-complete on the
window upper bound. Until then, §9 treats **tier/`M` forgery** as closed (Decision 1) and
flags **post-`eff_lock` epoch claims** as the residual soundness gap.

**Reopen criteria (reversion-clause):** audited Curve Forests non-membership lands with
consensus-grade test vectors **and** review shows ops cost ≤ separate subtree; or
empirical claim-fuzzing shows a simpler cap closes the 3B inflation class without
per-stake binding (unlikely — 3B is designed-closed).

---

##### Transfer, liquid staking, and **(C)** recurrence

**Confidential stake-UTXO transfer** (FCMP spend of principal + re-insert as staked) is
**privacy-compatible** and **not** the same as receipt-token liquid staking (which remains
out of scope — public fungible receipts leak cohorts). Transfer **does** compound **(C)**:

- **`creation_height` is inherited**, not reset at re-insert — accrual window follows the
  original bond, not the transfer block.
- **Decision 3C** (consensus-stamped `h_bind` at **first** inclusion) **conflicts** with
  naive re-stake-after-transfer unless the spend path carries `(tier, creation)` in the
  new leaf's 5th scalar (owner-proven continuity, not a fresh consensus stamp).

Spec target: [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) — *confidential stake-UTXO transfer*.
Round 2 closes Decision 3 before wallet transfer UX; creation inheritance is load-bearing
either way.

---

##### §9 premise — what this record establishes

| §9 assumption | Satisfied by |
|---------------|--------------|
| Wire `M` matches tier used in entitlement | **Decision 1** — `T` on wire + `C~_amt` + recompute |
| Claimed epochs relate to **this** stake's life | **Decision 2** — `creation ≤ S_min`; **Decision 3** — `S ≤ eff_lock` (pending) |
| **(A)** closes per-claim mint given honest `M` | **Decision 1** — Schnorr on `C~_amt` |

§9 steps 2–3 (`ρ_cap`, lifetime) unchanged. **Pin:** per-claim inflation from tier/`M`
forgery is **designed closed**; window **top** remains the audit focus until Decision 3
lands.

---

##### Implementation disposition

| Item | Status |
|------|--------|
| **(C) P1** | Closed (this record) |
| **(C_tier)** commitment + `C~_amt` + KAT | Round 2 implementation |
| **(C_window) lb** historical root | Round 2 implementation |
| **(C_window) ub** | **Open** — Decision 3 (**3A** or **3C**; 3B rejected) |
| **(C1) unified-tree fallback** | Only if both 3A and 3C blocked |

**Amendment targets:** §2; [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §15 (`C.x` basis);
§6.4.8 wire (`fcmp_membership_at_Smin`).

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

The claim verifier ( **`M` recompute + (C_tier) + (C_window)** + **(A)** + **(B)** ) is a
**derivative** of upstream FCMP++ and is listed in
[`AUDIT_SCOPE.md`](../AUDIT_SCOPE.md) §Confidential stake claim verifier (Round 1).

#### 6.4.8 Claim transaction wire sketch (Round 1)

Replaces cleartext `txin_stake_claim` + watermark path (§12). Byte-exact layout is
Round 2; structural fields:

**`txin_stake_claim_v2` (per claim input):**

| Field | Type | Notes |
|-------|------|-------|
| `tier` | u8 | Public; **(C_tier)** via `C~_amt` (§6.4.1) |
| `creation_height` | u64 | Public metadata; **(C_window)** via historical-root membership (lower bound); upper bound Round 2 open |
| `settlement_epochs` | `u64[]` | `|·| ≤ MAX_EPOCHS_PER_CLAIM` (15) |
| `nullifiers` | `point[32][]` | `N_S = x·G_S` per epoch; stake-claim set |
| `M` | u128 or le-int | **Verifier-recomputed** `tier_num · Σ_S K_S`; wire value checked (§9) |
| `fcmp_membership` | blob | Unified-tree membership at **current** root |
| `fcmp_membership_at_Smin` | blob | **(C_window)** — same leaf at root checkpoint for earliest claimed `S` (Round 2 layout) |
| `claim_linkability` | blob | **(B1)** ClaimLinkability |
| `entitlement_schnorr` | blob | **(A)** on `C~_amt` |
| `tier_surjection` | blob | Optional explicit CA surjection step if not folded into membership (Round 2) |

**Transaction body (unchanged shape):** one `C_claim` reward output + BP+ range proof;
RCT balance ties `C_claim` mint to pseudo-outs; **no** principal spend / **no** key image
in spent set.

**Consensus checks (ordered):** nullifier absence → **(C_window)** lower bound →
**`M` recompute** vs wire → membership (current root) → **(C_tier)** / **(A)** on
`C~_amt` → **(B)** → range → mint → `band_sum` / rate accounting. **`eff_lock` upper**
when Round 2 closes (§6.4.3).

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

**Premise (P1 — §6.4.3 decision record):** Before **(A)**, the verifier:

1. **(C_tier)** — forms `C~_amt = C~ − T·H_t`; wire `tier` → `T` (Decision 1).
2. **(C_window)** — historical-root membership at `S_min` (Decision 2); **`eff_lock`
   upper** per Decision 3 when closed (until then: residual window-top gap only).
3. **Recomputes** `M = tier_num(T) · Σ_S K_S`; rejects wire `M` on mismatch.

Step 1 below assumes validated **`M`** and tier bind; window top is explicit in Decision 3.

1. **Per-claim bound (given validated `M` and (C_tier)).** Each claim mints against the
   amount leg; entitlement **(A)** on `C~_amt` forbids minting more than `M · amount` for
   the membership-proven principal. **Latent path without (C_tier):** open tier-1 witness,
   assert tier-3 `M`, run **(A)** on full `C~` (or wrong `T`) — Schnorr can still close.
   **`ρ_cap` (step 2)** caps epoch-total emission but does not repair per-claim tier/`M`
   forgery.
2. **Per-epoch bound.** `total staker emission_e = ρ_e · TWS_actual ≤ budget_e` by the
   cap (§4.2), for **any** `band_sum` (honest, stale, or manipulated).
3. **Lifetime bound.** `Σ_e budget_e ≤ Σ_e target_share_e · block_emission_e ≤
   STAKER_EMISSION_SHARE · (total emission) < MONEY_SUPPLY` (since `target_share < 1`
   and total emission ≤ ceiling).

The miner stream (coinbase) remains publicly summable (§10), so total supply is
**auditably bounded** even though the staker stream is hidden. Per-claim **(A)** on
`C~_amt` + range (1), epoch **`ρ_cap`** (2), and **(C)** tier/window integrity are
therefore all consensus-critical. **Pin:** **(C)** is P1; **(C_tier)** + **(C_window)**
preferred Round 2; **`eff_lock` upper** open; **(A)** is **sound modulo (C_tier)** (§6.4.1).

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
| 6 | Entitlement **(A)** | **Closed R1 modulo (C_tier)** — `C~_amt` Schnorr (§6.4.1) |
| 7 | Nullifier **(B)** + `G_S` + `MAX_EPOCHS_PER_CLAIM` | **Closed R1** — pins §6.4.2; **KAT** Stage 2 |
| 8 | Tier/creation **(C)** | **Partial close** — §6.4.3 (tier + window lb ✅); **open:** Decision 3 ub (**3A/3C**; **3B rejected**) |
| 9 | Claim anonymity widening | **Closed R1** — accept v1 scope (§14.4) |
| — | Byte-exact claim/stake serialization | **Round 2** |
| — | `STAKE_CLAIM_GS.json` / `H_t` / historical-root KATs | **Round 2** |
| — | **`eff_lock` upper bound** | **Round 2 open** — **3A** (non-membership) vs **3C** (staking subtree + stamped creation); **3B rejected** (§6.4.3) |

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
| **(A)** | Off-circuit Schnorr on `C~_amt` — **closed**; sound modulo **(C_tier)**; in-circuit = reversion only (§6.4.1) |
| **(B)** | `N_S = x·G_S`; ClaimLinkability (B1); `MAX_EPOCHS_PER_CLAIM = 15`; DDH split §6.3 |
| **(C)** | **P1** — §6.4.3: **(C_tier)** ✅; **(C_window) lb** ✅; **ub** open (**3A/3C** co-equal, lean **3C**) |
| **Rejected** | **3B** coarse window (P1 inflation); spend-and-restake; B2-primary; `nullifier_seed` HKDF; persist `x` in wallet; wire `M` without recompute |
| **Fallback** | **(C1)** unified-tree `h_stake_bind` if **both** 3A and 3C blocked |

---

## 15. References (doc index)

| Doc / site | Use |
|-----------|-----|
| [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) | Wallet mirror (§2.3); R0-D1–D7; `N_S = x·G_S` §8.5; §6.4 review pins |
| [`STAKER_REWARD_DISBURSEMENT.md`](STAKER_REWARD_DISBURSEMENT.md) | **Superseded** reward/claim mechanism (retained for history) |
| [`DESIGN_CONCEPTS.md`](DESIGN_CONCEPTS.md) | Four-component economic model (Components 2–4) |
| [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) | Membership / curve trees; staked `C.x` + `H_t` (§15); CA lineage §6.4.3 |
| [`WITNESS_HEADER.json`](../test_vectors/WITNESS_HEADER.json) | Consensus-locked witness layout |
| [`AUDIT_SCOPE.md`](../AUDIT_SCOPE.md) | Claim verifier (§6.4.6); Confidential stake claim verifier section (Round 1) |
| `blockchain.cpp` (`:800–822`, `:3476`, `:4214–4247`, `:4366–4376`, `:5045–5051`) | Code sites superseded (§12) |
| `shekyl-staking` (`tiers.rs`, `registry.rs`, `rewards.rs`), `shekyl-economics`, FFI `lib.rs` | Tier/economics primitives; retirements (§12) |
| [`00-mission.mdc`](../.cursor/rules/00-mission.mdc), [`26-sub-pr-design-discipline.mdc`](../.cursor/rules/26-sub-pr-design-discipline.mdc) | Priority hierarchy; round discipline |
