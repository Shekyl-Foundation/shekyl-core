# Confidential staking — consensus & economics design

**Status:** Round 0 pre-flight / Round 1 entry. **Proposed pins, not closed.**
This is the **upstream consensus/economics truth** that
[`PHASE_2B_STAKE_LIFECYCLE.md`](design/PHASE_2B_STAKE_LIFECYCLE.md) §2.3 mirrors. It
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
FCMP++ circuit internals (`shekyl-fcmp`) were **not** re-read and are flagged where
the construction depends on them (§6.4, §13).

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
- a **`nullifier_seed`** commitment: the per-output secret from which claim nullifiers
  derive (§6.3) is bound to the output's spend authority, not stored in clear.

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

A claim transaction proves, in zero knowledge, knowledge of `(a, z, nullifier_seed,
z_claim)` and a membership witness such that:

1. **Membership.** `C_stake` (with its public `tier` and `creation_height`) is a leaf
   under the staked-output tree root (FCMP++ membership) — does **not** reveal which.
2. **Window.** every claimed settlement-epoch `S` satisfies `S ⊆ (creation, eff_lock]`,
   `eff_lock = creation + tier_lock_blocks`.
3. **Nullifiers.** for each claimed `S`, `N_S = PRF(nullifier_seed, S)` with
   `nullifier_seed` bound to the membership-proven output's spend authority; each `N_S`
   is **absent** from the on-chain nullifier set (no double-claim).
4. **Entitlement.** `C_claim ≡ M · C_stake`, where `M = tier_num · Σ_S K_S` is a
   **public** integer scalar (§3). Equivalently `C_claim − M·C_stake ∈ ⟨G⟩`, proven by
   a Schnorr proof of knowledge of `(z_claim − M·z)` — a **commitment-to-zero**: no
   division, no `TWS`.
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

`N_S = PRF(nullifier_seed, S)`. **The `nullifier_seed` derivation is unspecified today
and is a blocking Round 0 item (R0-D1), not a verification debt.** `OutputSecrets`
(`derivation.rs`) currently has `ho, y, z, k_amount`, label keys, and PQC seeds — **no
`nullifier_seed`**. Pinning it requires a **new labeled HKDF expansion** in the
info-string registry ([`30-cryptography.mdc`](../.cursor/rules/30-cryptography.mdc),
e.g. `shekyl-stake-nullifier`), **KAT vectors** (`PQC_OUTPUT_SECRETS.json` row), and an
explicit **stake-vs-normal-output rule** (shared derivation namespace or a stake-only
label). It must derive from the output's hybrid-KEM shared secret so it is PQ-protected
and deterministically **recomputable on rescan** (required by the wallet resync
reconciliation, [`PHASE_2B_STAKE_LIFECYCLE.md`](design/PHASE_2B_STAKE_LIFECYCLE.md)
§4.2, §8.5). PRF candidate: keyed CShake256 (`sha3 0.10`, already vendored). The
nullifier set is a **new consensus table** and is **reorg-state** (§11).

### 6.4 The construction gap (open, audit-scoping)

Constraint (4) must bind to the **membership-proven, unrevealed** `C_stake`. Two
bindings are possible: (i) an **in-circuit** scalar-mult-and-compare constraint inside
the FCMP++ proof (keeps unlinkability; extends the circuit), or (ii) composition with
the membership proof's commitment **rerandomization** (if `shekyl-fcmp` exposes the
committed `C` suitably). The exact mechanism **cannot be closed without reading
`shekyl-fcmp`'s proof structure** and is the highest-risk open. Either way, the claim
circuit is a **derivative** of upstream FCMP++ and must be **explicitly in the audit
scope** ([`AUDIT_SCOPE.md`](AUDIT_SCOPE.md)) alongside the x-only leaf flattening and
transcript-ordering changes — the Veridise lineage covers base primitives, not this
relation.

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

**Wallet FSM pin:** [`PHASE_2B_STAKE_LIFECYCLE.md`](design/PHASE_2B_STAKE_LIFECYCLE.md) §3.1
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
  (`nullifier_seed` behind the hybrid KEM; spend authority via ML-DSA-65 + Ed25519),
  so theft-resistance and nullifier-forgery-resistance are PQ-hybrid.

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
6. **Entitlement-binding mechanism** (§6.4) — in-circuit constraint vs membership-proof
   rerandomization composition; **requires reading `shekyl-fcmp`**; gates audit scope.
   *Highest risk.*
7. **Nullifier PRF** — confirm keyed CShake256 and the `nullifier_seed` derivation path
   from the hybrid output-secret domain (must be deterministically recomputable on
   rescan). **Wallet mirror:** [`PHASE_2B_STAKE_LIFECYCLE.md`](design/PHASE_2B_STAKE_LIFECYCLE.md)
   §8.5 (R0-D1) — `OutputSecrets` does not yet carry `nullifier_seed`; blocked until
   this item closes with HKDF label + KAT.
8. **Claim anonymity widening** (§6.2) — accept the tier+window-scoped set for v1, or
   pursue L4 (hide tier/window) later.

---

## 14. References

| Doc / site | Use |
|-----------|-----|
| [`PHASE_2B_STAKE_LIFECYCLE.md`](design/PHASE_2B_STAKE_LIFECYCLE.md) | Wallet-side mirror (§2.3); R0-D1–D7 pins in §0.11; `nullifier_seed` §8.5 |
| [`STAKER_REWARD_DISBURSEMENT.md`](STAKER_REWARD_DISBURSEMENT.md) | **Superseded** reward/claim mechanism (retained for history) |
| [`DESIGN_CONCEPTS.md`](DESIGN_CONCEPTS.md) | Four-component economic model (Components 2–4) |
| [`FCMP_PLUS_PLUS.md`](FCMP_PLUS_PLUS.md) | Membership proof / leaf structure (entitlement binding, §6.4) |
| [`AUDIT_SCOPE.md`](AUDIT_SCOPE.md) | Must add the claim circuit + §9 inflation-safety targets |
| `blockchain.cpp` (`:800–822`, `:3476`, `:4214–4247`, `:4366–4376`, `:5045–5051`) | Code sites superseded (§12) |
| `shekyl-staking` (`tiers.rs`, `registry.rs`, `rewards.rs`), `shekyl-economics`, FFI `lib.rs` | Tier/economics primitives; retirements (§12) |
| [`00-mission.mdc`](../.cursor/rules/00-mission.mdc), [`26-sub-pr-design-discipline.mdc`](../.cursor/rules/26-sub-pr-design-discipline.mdc) | Priority hierarchy; round discipline |
