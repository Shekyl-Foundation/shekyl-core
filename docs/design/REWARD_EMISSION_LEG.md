# Reward emission leg — consensus specification (genesis)

**Status:** Design spec — closes [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md)
§2.4 close-condition **(i)**. Implementation is gated on Tier 1 soundness step 3
(`STAKER_ARCHIVAL_SIM.md`) and gate 2 retention-proof wire (challenge material
referenced here; proof bytes pinned at gate 2).

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
   on-chain registration transaction; off-chain backing precedes first emission (gate 6).
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

## 4. Economics — verifier-side reward computation

For each settlement epoch `E` claimed in the vin:

```text
work_P(E)  = Σ_{s ∈ held(P,E)} scarcity(s,E) · proven_retention(P,s,E)
Σwork(E)   = Σ_{P'} work_{P'}(E)   // public aggregate from consensus archival state
budget(E)  = archival_budget(E)    // gate 1 servo input; public schedule
raw(E)     = budget(E) · work_P(E) / Σwork(E)   // integer division; floor toward zero
reward(E)  = Curve(raw(E))         // piecewise-linear banded plateau-cap; public parameters
```

- **`held(P,E)`** — shards `P` held and was **good-standing** for epoch `E` per bond
  record + retention state (gate 4 / gate 2).
- **`proven_retention`** — challenge-pass bit(s) in consensus archival state, not
  retrieval volume ([`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md) §*reward curve*).
- **`scarcity(s,E)`** — public function of `market_R(s,E)` and shard age `g(age)` (gate 3
  counting uses `ν = H(P, shard)` separately; scarcity uses public `R`).
- **`Curve`** — concave-to-plateau; parameters are consensus constants (same class as
  retired decade-log bands — exact breakpoints pinned at gate 1 implementation).

**Inflation posture (8c):** Any mismatch between recomputed `reward(E)` and minted outputs
is a **consensus error visible to all verifiers** — not a silent ZK soundness break.

**Σwork servo:** The prover **must not** supply `Σwork` or `budget` as authoritative;
the vin may include them only as **hints** for light-client checks. Full nodes recompute.

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
  admission_proof:    OptionalThresholdProof, // §7.4; present iff ADMISSION_MIN policy on
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
Σ vout.amount_plain == Σ_{E ∈ settlement_epochs} reward(E)
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
5. **Economics** — recompute `reward(E)`; compare to `reward_amount_plain` and vout sum.
6. **Membership-only backing** — §7.2.
7. **Admission threshold** — §7.4 if enabled.
8. **FCMP++ balance** — ordinary RCT balance equation including mint; fee inputs use
   standard key-image path.

On `pop_block`, reverse **3** (revert dedup bits) and bond mutations from **4–6** in
block disconnect order (§8).

### 7.2 Membership-only backing

**Statement:** Prover knows opening for one or more outputs on the **current main-chain
FCMP++ root** that collectively satisfy the backing predicate:

```text
backing_ok(P, roots) :=
  Σ backing_outputs.amount ≥ ADMISSION_MIN_ATOMIC   // if admission policy active
  ∧ each output is spendable by P's key material
  ∧ membership valid under FcmpPlusPlus at reference block
```

When admission principal is **not** consensus-required (gate 7 / Round 4 option), replace
threshold with **bond-only** posture: `bonded_total_atomic ≥ bond_required(holdings)`.

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

### 7.4 Optional `ADMISSION_MIN` threshold proof

If economics pins an admission minimum transfer to `P`:

- Vin includes Bulletproof+ (or FCMP++-compatible) proof that backing outputs sum to ≥
  `ADMISSION_MIN_ATOMIC`.
- This is **economics-only** — not an unspent-enforcement on those outputs (soft
  admission per §2.4).

If admission principal is dropped (close-condition iii), remove this field entirely.

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

Not consensus — orients Stage 3:

1. Wait until settlement epoch `E` closes (or batch unclaimed `E…`).
2. Read public challenge state → build `work_claim`.
3. Locally compute expected `reward(E)` from daemon archival index + public `Σwork`.
4. Select backing outputs on `P`; build `MembershipOnlyBacking`.
5. Assemble `txin_archival_reward_emission` + fee `txin_to_key` + stealth vouts.
6. Broadcast; on confirm, wallet marks epochs claimed (no `claim_pending_epochs` /
   `PrepareClaimBuild` — retired FSM).

---

## 12. Implementation checklist (pre-code)

- [ ] Add `SETTLEMENT_EPOCH_BLOCKS`, `MAX_SETTLEMENT_EPOCHS_PER_EMISSION` to
      `config/consensus_constants.json` + generators.
- [ ] C++ / Rust vin deserializer for `txin_archival_reward_emission`.
- [ ] `ArchivalBondRecord` LMDB table + `pop_block` revert.
- [ ] `FcmpMembershipOnly::verify` in `shekyl-oxide` FCMP++ crate.
- [ ] Delete / gate `check_stake_claim_input`, `txin_stake_claim` paths.
- [ ] KAT vectors: minimal valid emission + double-claim reject + work mismatch reject.
- [ ] Update `AUDIT_SCOPE.md` §staking — entitlement out, emission in.

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

**2026-06-06:** Initial reward-emission leg spec — closes PHASE_2B §2.4 close-condition
(i): state-based dedup on bond record, membership-only backing, public work + mint,
registration fusion, explicit rejection of published dedup tags and confidential claim
surfaces.
