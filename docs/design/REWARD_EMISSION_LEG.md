# Reward emission leg — consensus specification (genesis)

**Status:** Design spec — **structural core** for [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md)
§2.4 close-condition **(i)**. **Not genesis-sealed:** the **Σwork denominator mechanic**
(§4.3) is an open structural fork (joint with gate 1 supply-safety). **Admission wire**
leans ordinary transfer ≥ `MIN` with **no `C_stake`** (§7.2–§7.4; gate 4/7 reopen).
Implementation is gated on Layer 2 keystone validation (`STAKER_ARCHIVAL_SIM.md` §*Layer 2*)
and gate 2 retention-proof bytes.

**Scope:** The **consensus-special reward emission transaction leg** for pay-for-service
archival under firewalled pseudonym **`P`**. This document is the byte-layout and
verifier contract. It **supersedes** the confidential claim wire (`txin_stake_claim_v2`,
entitlement circuit, `N_S = x·G_S`, published `N_arch`) for genesis.

**Out of scope here (separate specs):** gate 6 off-chain backing presentation; gate 4
bond post/slash object wire (except fields this leg reads/writes); gate 1 `Σwork`
budget schedule source; gate 2 retention-proof construction bytes; wallet FSM
(`PHASE_2B` §3 — retooled after this lands).

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

Close-condition **(ii)** (per-reward proof aggregate at `N_P` × cadence) and **(iii)**
(admission principal + gate 7) are **not** closed here; §10 names the hooks.

### 1.1 Design sequencing (four layers, gated)

Work is **not** parallel-equal. Lower layers gate higher ones.

| Layer | Scope | Gate |
|-------|--------|------|
| **1 — Consensus structural core** | This doc: public `work_P` recompute, membership-only ≥`MIN` backing, state dedup, consensus-applied rate → mint. Bond/slash is gate 4 (spec elsewhere — do not duplicate). **Open:** Σwork denominator (§4.3). **Owed crypto:** `FcmpMembershipOnly::verify`. | Must be right pre-genesis. |
| **2 — Economic keystone** | Three-channel reward shape validated in `shekyl-staking-sim` (not generic “work-based”). Spread graze vs windowed mean (2026-06-07); deep↔spread via `g(age)` calibration at `bond_rate* = 0.75`; gate 7 fee-era + admission re-pricing; per-reward byte aggregate (calc, not agent sim). | Shape reopen if keystone fails. |
| **3 — Operational / firewall** | Gate 6: `P` HKDF, multi-`P` hygiene, announce-before-anchor, bond-funding decorrelation. Wallet FSM: delete claim machinery; ordinary-transfer admission + reward reception + bond slash. | Load-bearing for privacy. |
| **4 — Document rebase** | Round 0 / threat model → F-ARCHIVAL+`P`; claim-centric `PHASE_2B` §3–§7 historical; FCMP §15 / 3C retirement. **Gated on Layer 2** — full rebase round is premature while the keystone is open. | Corpus consistency. |

**2026-06-07 Layer 2 discipline gate (spread windowing):** `sprdW` = mean `gini_actor` + peak
`max_actor_share` over `churn_window` (L9 lesson). Full sweep **266** scenarios: snapshot
**138**/266 vs windowed **139**/266 pass spread; **one** flip (`gate4_coloc_5.50`, far above
`bond_rate*`). At **`bond_rate* = 0.75`**: snapshot grazes (`gini_act ≈ 0.600`), windowed
**passes** (`giniW ≈ 0.593–0.599`); at **1.00** both fail (`≈ 0.626`). **Verdict:** spread
graze at the pin survives the windowed read; failures above 1.00 and at thin-budget lean
(`l11_bud_b50`, `gini ≈ 0.84`) are **real concentration**, not snapshot artifacts. **Keystone
holds** at the pinned operating point → Layer 2 is **calibration**, not shape reopen.

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
4. **Registration fusion.** The **first** valid emission for `P` **creates** the on-chain
   bond record (holdings + bond posture + empty dedup set). There is no separate
   on-chain registration transaction. **Gate 6 requires** `P` to be a **recognized,
   backed archiver** (off-chain announce + backing presentation) **before** the first
   on-chain anchor — “first reward anchors” understates the precondition.
5. **Bond is the intra-epoch honesty anchor.** Between settlement-epoch emissions,
   admission principal may be spent; backing is not re-verified every block. Challenge
   failure slashes **bond** regardless of admission UTXO state (§7.5).

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

The reward is **not** generic “budget × work / Σwork.” It is the **specific three-channel
stack** exercised in `shekyl-staking-sim` (`reward.rs`) and
[`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md) §*reward curve*:

```text
scarcity(s,E)  = (1 / R_market(s,E)) · g(age(s))     // channel 1: self-diluting scarcity
work_P(E)      = Σ_{s ∈ held(P,E)} scarcity(s,E) · proven_retention(P,s,E)
capped_P(E)    = Curve(work_P(E))                     // channel 2: concave plateau-cap (per P)
Σwork(E)       = Σ_{P'} capped_{P'}(E)                // channel 3: competitive-share denominator
reward_P(E)    = budget(E) · capped_P(E) / Σwork(E)   // integer floor; loud on vin
```

**Channel 1 — scarcity.** `R_market` is the public replication count; holding a shard
raises `R` and dilutes its own `1/R`. `g(age) = 1 + age_weight·age` (public shard
property) is the privacy-clean deep-history premium replacing retired tier weighting.
`proven_retention` is the challenge-pass bit from consensus archival state (gate 2), not
retrieval volume.

**Channel 2 — `Curve`.** Per-`P` concave-to-plateau cap on credited work (the sim’s
`cap` parameter). Marginal credited work above the plateau is zero unless the operator
opens another pseudonym — which carries gate-6 firewall cost, not a free Sybil split.

**Channel 3 — competitive share.** `budget(E)` from gate 1; each `P` receives
`budget · capped_P / Σwork`. Adding work raises `Σwork` and dilutes everyone (including
self) — the servo share channel.

**Inflation posture (8c):** Verifiers recompute all three channels; any mismatch between
`reward_P(E)` and minted outputs is a **consensus error visible to all verifiers**.

**Hints:** The vin may carry `budget`, `Σwork`, or intermediate values as **hints** for
light clients; full nodes recompute authoritatively.

### 4.1 Sim validation (done — not a to-do)

`shekyl-staking-sim` implements this stack end-to-end. Economics re-simulation is
**complete** for Layer 2 keystone questions: `g(age)` clearing deep, lean equilibrium
(L11), `bond_rate* = 0.75` spread pin, co-location binding (P1), fee-era spiral (L13).
See [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) adjustment ledger — not a pending
“re-run economics” item.

### 4.2 `WorkClaimVector` maps to channel 1

§5.4 carries per-shard `scarcity_milli` (fixed-point `(1/R)·g(age) × 1000`) and
`proven_retention` so verifiers recompute `work_P(E)` before applying `Curve`.

### 4.3 Open structural fork — `Σwork(E)` denominator timing

The competitive-share line uses a **global denominator** for epoch `E`. An epoch’s
`Σwork(E)` is not knowable until **all** qualifying emissions for `E` are processed
(late emitters, batching, reorgs). This is the **same decision** as gate-1 supply-safety,
not a separate economics knob.

**Disposition (open — pick one before genesis seal):**

| Option | Mechanism | Tradeoff |
|--------|-----------|----------|
| **Lagged denominator** | `Σwork(E)` computed from **finalized** archival state at end of settlement epoch `E` (or `E−1` for emissions in `E+1`); emissions in epoch `E` cite the lagged total | Simple; late movers get deterministic share; boundary rules must be explicit |
| **Two-phase settlement** | Phase A: provisional accrual; Phase B: finalization pass when epoch closes adjusts mint | Exact share; more consensus state and reorg surface |
| **Capped provisional + true-up** | Mint to provisional `Σwork` with bounded true-up in `E+1` | Middle ground; needs inflation bound proof |

This spec **does not** choose among them. Gate 1 implementation must pin the choice and
document reorg behavior. Until pinned, §5.4 `reward_amount_plain` semantics assume the
verifier applies the **same** denominator rule as gate 1 (no wallet-local `Σwork`).

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
  admission_proof:    OptionalAmountProof,     // §7.4; ordinary-transfer ≥ MIN only if policy on
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
  proven_retention:   bool,              // must match challenge state at E
  scarcity_milli:     u32,               // fixed-point scarcity × 1000 (integer recompute)
}
```

**Consensus rule:** Recomputed `work_P(E)` from archival DB **must equal** the vin's
implied work (within fixed-point tolerance **zero** — integers only at consensus). Mismatch
→ `invalid_emission_work`.

**Gate 2 pin (deferred):** `shard_id` encoding and challenge-record keying are owned by
the retention-proof spec; this leg **consumes** the consensus challenge ledger, not defines
it.

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
  first_emission_height:    u64,       // anchor for registration fusion
  claimed_settlement_epochs: ClaimedEpochSet,  // §6.3
  // gate 4 extensions (slash hooks, per-shard bond breakdown) colocated in same record
}
```

### 6.3 `ClaimedEpochSet` — dedup semantics (amends wallet `EpochSet` reuse)

**Semantics** (relocated from wallet `claimed_epochs` / §3.3.2):

```text
check_and_set(E): bool
  // returns false if E already claimed; else inserts E and returns true
```

**Encoding (genesis pin):** Per-`P` **sparse set of absolute settlement-epoch indices**
`E`. Implementation may use LMDB dup-keys `(P_id, E)`, a roaring bitmap, or append-only
log — consensus-visible semantics only; **not** the retired 2-byte **relative** `u16`
mask from tier-bounded stake claims.

**Why not reuse the u16 relative mask:** Stake claims were bounded to ≤15 epochs over
a **tier lock window**. Archival `P` accrues settlement epochs **without a tier lock
upper bound**; a 16-bit relative window would allow double-claim after window slide.
The wallet §3.3.2 encoding remains valid for **historical documentation** of the
retired claim path only.

**Reopen criterion:** If consensus proves an upper bound on simultaneous unclaimed
epochs per `P` ≤ 16 at all times, a relative mask may return; until then, absolute sparse
set is genesis.

### 6.4 First emission

If no `ArchivalBondRecord` exists for `P`:

1. Verify off-chain backing policy is out of consensus scope but **gate 6** requires
   wallet/daemon to have presented backing before building this tx.
2. Create record from vin `holdings` + gate-4 bond requirements (`bonded_total_atomic ≥
   bond_floor(holdings)`).
3. Set `first_emission_height = current_height`.
4. Apply dedup for claimed epochs in this vin.

Subsequent emissions require `holdings` **compatible** with stored record (no silent
portfolio swap without bond update flow).

### 6.5 Good standing

Emission for epoch `E` is rejected unless, for every shard in `work_claim(E)`:

- `P` held the shard through `E` per archival state, and
- Most recent challenge for `(P,s)` before `E` boundary **passed** (exact grace window
  pinned at gate 4), and
- `good_standing == true` (no unbonded/slash posture).

---

## 7. Cryptographic verification

### 7.1 Order of checks (consensus)

Apply in order; fail-fast:

1. **Structural** — tx type, vin counts, epoch list monotone unique, `|epochs| ≤ 15`.
2. **Bond posture** — record exists or first-emission path valid; bond sufficiency; holdings
   match.
3. **Dedup** — for each `E`, `claimed_settlement_epochs.check_and_set(E)` (atomic with
   block connect).
4. **Archival work** — recompute `work_P(E)` from state; compare to `work_claim`.
5. **Economics** — recompute three-channel `reward_P(E)` (§4); compare to `reward_amount_plain` and vout sum.
6. **Membership-only backing** — §7.2.
7. **Admission threshold** — §7.4 if enabled.
8. **FCMP++ balance** — ordinary RCT balance equation including mint; fee inputs use
   standard key-image path.

On `pop_block`, reverse **3** (revert dedup bits) and bond mutations from **4–6** in
block disconnect order (§8).

### 7.2 Membership-only backing (ordinary transfer, not `C_stake`)

**Leading disposition (gate 4/7 reopen):** admission is an **ordinary FCMP++ transfer ≥
`ADMISSION_MIN_ATOMIC`** to `P`’s stealth address on the **main tree**. There is **no
`C_stake` / confidential admission opening** on the genesis path unless gate 4/7 reopens
with a demonstrated monetary reason to keep the admission stake confidential.

**Statement:** Prover knows opening for one or more **ordinary** outputs on the current
main-chain FCMP++ root that collectively satisfy:

```text
backing_ok(P, roots) :=
  Σ backing_outputs.amount ≥ ADMISSION_MIN_ATOMIC   // if admission policy active (gate 7)
  ∧ each output is spendable by P's key material (ordinary transfer to P)
  ∧ membership valid under FcmpMembershipOnly at reference block
```

When admission principal is **not** consensus-required (gate 7 bonds-only sink), the
membership proof may attest **bond posture only**: `bonded_total_atomic ≥
bond_required(holdings)` without a separate admission UTXO threshold.

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

### 7.3 Within-`P` privacy (DDH)

Membership-only backing does **not** publish key images, but repeated emissions still
must not link backing outputs across epochs by reusing the same leaf opening in a
correlatable way. Wallet **should** rotate backing UTXOs on `P` where practical (gate 6
hygiene); consensus does not enforce rotation.

### 7.4 Optional `ADMISSION_MIN` amount proof

If gate 7 pins an admission minimum **ordinary transfer** to `P`:

- Vin includes a **public** sum check or amount proof that backing outputs total ≥
  `ADMISSION_MIN_ATOMIC` (loud amounts align with §2 loud-reward discipline).
- This is **economics-only** — not unspent-enforcement on those outputs (soft admission
  per §2.4). Outputs may be spent after first emission; bond slash is the intra-epoch
  honesty anchor (§7.5).

If admission principal is dropped (close-condition iii / bonds-only sink), remove
`admission_proof` and the `ADMISSION_MIN` branch of `backing_ok`.

**Wallet FSM implication:** Stage 3 manages **ordinary-transfer admission** to `P`, not
`C_stake` openings or claim-pending state. See §11.

### 7.5 Intra-epoch unbacked window (explicit safety lemma)

Between emissions, `P` may spend admission outputs while still listed as serving. The
verifier **does not** re-check full retention on every block. Safety relies on:

> Challenge failure at any time → bond slash (gate 4) → `good_standing` false → future
> emission rejected until re-bond.

Document in threat model §7 retool; this spec states the **consensus dependency** on
slash hooks.

---

## 8. Reorg

On block disconnect at height `H`:

1. For each `txin_archival_reward_emission` in the block, for each epoch `E` claimed,
   remove `E` from `bond.claimed_settlement_epochs` for that `P`.
2. Revert bond record creation if this block contained `P`'s **first** emission (delete
   record iff no prior emission at lower height — track `first_emission_height == H`).
3. Revert minted amounts from monetary supply accounting (same path as coinbase undo).
4. Re-run forward on reconnect.

Wallet forward-rebuild ([`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §5)
mirrors: rescan emission vins, rebuild claimed-epoch set from chain.

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

### 10.1 Close-condition (ii) — proof aggregate

Per-emission vin size is dominated by:

- `|settlement_epochs| × |shard_entries| × sizeof(ShardWorkEntry)`
- `+ sizeof(MembershipOnlyBacking)` per FCMP++ input (gate 2 + curve tree depth)

Sim sweep (`STAKER_ARCHIVAL_SIM.md` adjustment ledger) should use:

```text
N_P ≈ active market archivers at settlement boundary
cadence = SETTLEMENT_EPOCH_BLOCKS
bytes_per_emission ≈ f(holdings shards, FCMP proof size)
```

This spec **pins cadence** (§3) so (ii) can run; it does not size proofs.

### 10.2 Close-condition (iii) — admission principal

`ADMISSION_MIN_ATOMIC` and `admission_proof` presence are **policy constants** left
open for gate 7. Emission verification branches on whether admission is load-bearing
(§7.2, §7.4).

---

## 11. Wallet / `StakeEngine` build flow (informative)

Not consensus — orients Stage 3 (Layer 3 FSM retool):

**Delete:** `claim_pending_epochs`, `PrepareClaimBuild`, claim-staleness, entitlement
rescan, `C_stake` admission openings.

**Add:** `P` lifecycle (HKDF derivation, multi-`P` hygiene), **ordinary-transfer
admission** ≥ `MIN` to `P`, off-chain announce-before-anchor, reward reception (loud
amounts), bond post/slash reaction.

1. Gate 6: announce `P` + present backing off-chain; ensure recognized before first emission.
2. Wait until settlement epoch `E` closes (or batch unclaimed `E…`); apply §4.3 denominator rule.
3. Read public challenge state → build `work_claim` (channel 1).
4. Locally compute `capped_P` and expected `reward_P(E)` via `Curve` + gate-1 `Σwork`.
5. Select ordinary backing UTXOs on `P`; build `MembershipOnlyBacking`.
6. Assemble `txin_archival_reward_emission` + fee `txin_to_key` + stealth vouts.
7. Broadcast; on confirm, wallet marks epochs claimed in local bond mirror.

---

## 12. Implementation checklist (pre-code)

- [ ] **Pin §4.3** `Σwork` denominator mechanic (joint gate-1 design).
- [ ] Add `SETTLEMENT_EPOCH_BLOCKS`, `MAX_SETTLEMENT_EPOCHS_PER_EMISSION` to
      `config/consensus_constants.json` + generators.
- [ ] C++ / Rust vin deserializer for `txin_archival_reward_emission`.
- [ ] `ArchivalBondRecord` LMDB table + `pop_block` revert.
- [ ] **`FcmpMembershipOnly::verify`** in `shekyl-oxide` FCMP++ crate (line-441 gap).
- [ ] Delete / gate `check_stake_claim_input`, `txin_stake_claim`, `C_stake` admission paths.
- [ ] KAT vectors: minimal valid emission + double-claim reject + work mismatch reject.
- [ ] Update `AUDIT_SCOPE.md` §staking — entitlement out, emission in.
- [ ] Layer 2 remaining: gate-7 admission re-pricing sweep; per-reward byte aggregate (§10.1).

---

## 13. Related documents

| Doc | Relationship |
|-----|----------------|
| [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §2.4 | Parent shape |
| [`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md) | Economics + `P` model |
| [`CONFIDENTIAL_STAKING.md`](../CONFIDENTIAL_STAKING.md) §5–§6 | **Retired** claim wire; §5 epoch length still authoritative until constant migrated |
| [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) | (ii) sweep after this doc |
| [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) | Membership proof base |

---

## Revision note

**2026-06-06:** Initial reward-emission leg spec — PHASE_2B §2.4 close-condition (i)
structural core.

**2026-06-07:** Sync to three-channel reward stack + sim-validated economics; §4.3
`Σwork` denominator fork open (joint gate 1); ordinary-transfer admission (no `C_stake`);
four-layer sequencing; spread windowing discipline gate (keystone holds at `bond_rate*`);
P announce-before-anchor.
