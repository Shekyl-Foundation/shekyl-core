# Archival consensus state — emission read contract (genesis)

**Status:** **Gating spec — contract pinned (2026-06-07).** The reward-emission leg
([`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md)) is structurally closed at Layer 1
but **un-implementable** until this schema is **implemented**. Tier-1 **8c
retention-proof unforgeability** (construction bytes) may still defer relative to Phase 2b
wallet work; the **consensus interface** — what state emission reads, how it is keyed,
how it prunes — **cannot**.

**Scope:** Consensus LMDB (or equivalent) tables, keying, invariants, and growth bounds
for everything the emission leg **consumes** (does not write except `ClaimedEpochSet`
mutations and first-emission bond-record creation per emission leg §6).

**Out of scope here:** retention-proof **construction** wire (prover bytes); gate 6
off-chain firewall; gate 4 bond post/slash **wire** (except fields this contract reads);
wallet FSM ([`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §3–§7 retool).

**Upstream:** [`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md) §*Pay-for-service
rebasing*, loud 8c; [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §4–§6.

---

## 1. Why this is the critical path

Pinning the emission leg promoted archival consensus state onto the **critical path**.
Loud 8c recompute in emission §5.4 **consumes** state this doc defines:

| Emission read | Source in this contract |
|---------------|-------------------------|
| `proven_retention(P, shard, E)` | Retention ledger (gate 2) |
| `shard_id`, `g(age)` inputs | Shard registry (gate 2) |
| `R_market(shard, E)` | Derived view (§3.3) — **not** a separate ν table |
| `holdings`, `good_through(P, E)` | `ArchivalBondRecord` (gate 4) |
| `Σwork(E)` | §4.4 accumulator (emission-owned state; inputs from above) |

**8c deferral boundary:** This doc pins **what** verifiers read at recompute time. The
**proof object** that authorizes flipping a retention bit is a separate deliverable; the
interface must not change when construction lands.

---

## 2. Gate 3 dissolution — `ν` primitive dropped

**Finding (2026-06-07):** Form **C** applies `Curve` per `P` (channel 2). Computing
`capped_P(E)` requires summing a given `P`'s shards, then capping. The accumulator
`Σ_{P'} capped_{P'}(E)` requires that grouping for **every** market `P`. Anything
consensus computes is public. Per-`P` holdings are therefore **consensus-public by
construction** — which the honest residual (V3 §1038–1046) already concedes
("long-lived public pseudonymous profile — shard-set").

The prior gate-3 primitive `ν = H(P_seckey, shard)` existed to count `R_market` without
revealing which `P` holds a shard. **That privacy goal is incompatible with form C:**
you cannot group a `P`'s shards to cap them while hiding that they belong to one `P`.
`R_market(s,E)` collapses to a **plain count** over the public retention ledger keyed by
public `P_id`.

**Same dissolution pattern as `N_arch`:** a privacy-preserving primitive carried from the
hidden model, made redundant by the firewall-not-hide model. **Privacy that remains:**
`P` ↔ principal (gate 6 firewall), **not** `P`-holdings hiding.

**Consumer check:** No reward-path consumer needs a hidden-`P` count. `durability_count`
is a **different symbol** (foundation-inclusive observability/SLA) and does not require
ν either.

**Disposition:** Delete `ν = H(P, shard)` from the genesis crypto bill. Re-spec
`market_R` / `R_market` as the derived ledger count (§3.3). Wallet does **not** mint ν.

**Honest residual — two axes (F1, 2026-06-07).** Dropping ν improves honesty on the
**holdings** axis with no new exposure beyond the V3 honest residual (shard-set profile).
On the **timeline** axis, ν's only job was hiding per-`P` counts while leaving
per-`(P, shard, E)` attribution hidden. Keying the retention ledger by public `P_id`
(§3.1) makes the per-`P`, per-shard, per-epoch retention record **publicly attributable**
at **settlement-epoch resolution**. The residual concedes a public performance profile;
what changes is temporal resolution — one bit per epoch per held shard. Under L14
(retrieval-as-proof), on-chain proof submission largely disappears; the ledger bit at
epoch granularity becomes the **primary public liveness signal**, with resolution set
entirely by settlement-epoch length. Rotation (gate 6) is the named decorrelation tool
against E-4 timing linkage; fine-grained per-epoch retention timelines are behavioral
fingerprints (shard-set adjacency across `P_old` → `P_new` rotation). See §9.2.

**Reversion clause:** Reopen only if a **production consumer** emerges that requires
hidden-`P` counting **and** form C is simultaneously rejected — i.e. a full reward-shape
reopen, not a gate-3 patch.

---

## 3. Read surface — what the emission leg consumes

Keying is **`P_canonical_id`** throughout (emission leg §6.1):

```text
P_canonical_id = cSHAKE256(
  customization = "shekyl/archival-p-id-v1",
  input         = P_pubkey.canonical_bytes()
)[0..32]
```

The emission leg **reads** these records; it does **not** define gate-2 challenge
mechanics or gate-4 slash wire.

### 3.1 Retention ledger (gate 2)

```text
retention_bit(P_id, shard_id, E) : bool
```

- Set when the challenge for `(P, shard)` relevant to settlement epoch `E` **passed**
  (grace window per gate 4).
- Challenge metadata (which leaf, which block) stays **gate-2-internal** — not in this
  contract.

### 3.2 Shard registry (gate 2)

```text
shard_id → { age, boundary/existence }
```

`g(age)` is a consensus constant the emission leg applies; this contract does not define
what bytes a shard is (set-B boundary).

### 3.3 `R_market` view — derived, not stored separately

```text
R_market(shard_id, E) =
  |{ P_id : retention_bit(P_id, shard_id, E)
         ∧ good_through(P_id, E)
         ∧ P_id ∈ Market }|
```

- **One consensus value** per `(shard, E)` — identical for every claimer.
- **Pinned measure:** count at **epoch close** with `retention ∧ good_through` — not
  time-weighted over `E` (rejected: buys little, costs determinism).
- **`Market` membership:** market archivers with `ShardSetCompact` holdings. Foundation
  `CompleteTree` identities are **excluded** from `R_market` and `Σwork` (E-2) — they
  do not accrue market scarcity rows on this path.
- **Materialization:** may be stored per `(shard_id, E)` at epoch close or computed on
  read from the ledger; semantics are fixed either way.

### 3.4 Holdings + good-standing (gate 4)

```text
P_id → ArchivalBondRecord
```

Per-shard bond posture, `holdings` descriptor, and data to derive **`good_through(P, E)`**
per settlement epoch. Gate 4 owns slash/unbond mutations; emission reads the result.

**Genesis pin (read requirement):** `good_through(P, E)` must be **derivable at epoch
close** from bond state — not merely a current `good_standing` flag. See emission leg
§6.5 (E-3).

**Encoding (F3, 2026-06-07):** **Bonded/slashed event log with interval semantics**
evaluated at `E`-close — **not** a scalar `slash_epoch` cutoff (`slash_epoch > E` is
wrong). Re-bond is a first-class lifecycle event (CompleteTree resume; market "replace
shard bond"); good-standing is an **interval set**, not a monotone cutoff. Example:
good in `[0,10]`, slashed at `11`, re-bonded at `20` — `good_through(25)` must be true
while `good_through(8)` stays true (E-3: slash at `11` does not retroactively void
honestly-earned epochs in `[0,10]`). Verifier at close: `good_through(P,E) ⇔` no slash
event with `epoch ≤ E` falls in a bad-standing interval that covers `E`, per the
logged bond/slash/re-bond timeline.

### 3.5 `Σwork` accumulator (emission leg §4.4)

```text
Σwork(E) → Σ_{P'∈Market} Curve(work_{P'}(E))
```

Finalized at settlement epoch `E` **close**. Inputs are the three record families above;
arithmetic is owned by [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §4.0.

**Implementation choice (not consensus-visible):** epoch-close sweep **or** incremental
per-`P` delta when retention settles (re-cap one `P`, apply delta to `Σwork`) — the
per-`P` cap is nonlinear. Reorg revert order must match the chosen path (§6).

---

## 4. Invariants — gate 2/4 must guarantee

These are the **load-bearing half** of the contract; the read surface is useless without
them.

1. **Single-valued `R_market(s,E)`** — one consensus value per `(shard, E)`, identical
   for all `P`. Deriving from the ledger gives this for free; a separate count source
   would not. Divergence ⇒ claimers compute different scarcity and `Σwork` stops
   reconciling.

2. **Finalized-and-immutable at E-close** — retention bits and derived `R_market` for
   `E` are fixed once `E` closes (within the reorg horizon). Per E-3, they are immune to
   **later** slashes via `good_through(E)` evaluated at close. This boundary is **the
   same** as emission §4.5's lagged `Σwork` read — pin together, not separately.

3. **Canonical stable `shard_id`** — same shard, same id, for all `P` and all time;
   otherwise holdings cannot be matched across emissions (§6.4 "compatible holdings").

4. **`good_through(P,E)` derivable at close** — gate-4 slash state exposes a per-epoch
   good-standing view, not only a current flag (E-3 pin as read requirement).

---

## 5. `MAX_CLAIM_AGE_W` — claim window (genesis constant)

```text
W = MAX_CLAIM_AGE_W   // settlement epochs; consensus constant (value TBD)
```

Epochs with `E < tip_epoch − W` are **unclaimable** (forfeited). This is what makes the
structure **prunable**:

| Structure | Prune after `tip − max(W, REORG_HORIZON)` |
|-----------|---------------------------------------------|
| Retention ledger rows | Yes |
| Derived / stored `R_market` views | Yes |
| Per-epoch `Σwork(E)` | Yes |
| Per-`P` `ClaimedEpochSet` entries | Yes (verify rejects ancient `E`) |

**Tradeoff (consensus-visible):** A `P` offline (or deliberately lapsing for gate-6
decorrelation) longer than `W` **forfeits** older unclaimed epochs. `W` couples **state
growth** against **firewall lapse discipline**.

**Open pin:** numeric `W` and `REORG_HORIZON` jointly with finalization boundary (§4
invariant 2 + emission §4.5 + §8).

**Drain vs forfeiture (F4, 2026-06-07):** `W` forfeits epochs older than `tip − W`. If
claims drain at a bounded batch rate, a continuously-honest `P` with a backlog must
drain it before the oldest entry crosses the horizon. Emission leg §3 pins
`MAX_SETTLEMENT_EPOCHS_PER_EMISSION = 15` as **per-`P` per emission** (max epochs in
one vin). Joint invariant (value pin deferred with `W`):

```text
∀ P continuously honest: drainable_epochs_per_wall_clock ≥ epochs_accruing_per_wall_clock
  while backlog_depth ≤ W
```

Couple numeric `W`, batch cap, and settlement-epoch length (§9.2 cadence) in one
pre-code check — not three independent constants.

**State cost (gate-2 "irony," now bounded):**

```text
replicated_hot_state ≈
  active_(P,shard)_records × W
  + per_P ClaimedEpochSet (≤ W entries)
  + W accumulator values (Σwork)
```

---

## 6. Gate-2-internal (not in this contract)

- How a retention bit is **earned** (proof-of-retrievability challenge, future-block-hash
  leaf selection, 8c unforgeability argument).
- Challenge **cadence** (L14 retrieval-as-proof reduction).
- Shard **definition** (what bytes/leaves a shard is).

The emission leg consumes **outputs** — bits, counts, ids — and depends on the four
invariants; it defines none of the mechanisms.

---

## 7. `market_R` vs `durability_count` (unchanged separation)

| Symbol | Definition | Foundation |
|--------|------------|------------|
| **`market_R` / `R_market`** | Derived ledger count (§3.3) for **market** archivers | `CompleteTree` **excluded** from `Market` |
| **`durability_count`** | Bonded-and-good-standing archivers covering *s* | Includes genesis `CompleteTree` when active |

Reward paths use **`market_R` only**. SLA, audit, and local-pruning policy use
**`durability_count`** (or explicit policy). Never interchange.

---

## 8. Parallel work

| Workstream | Status |
|------------|--------|
| **§3–§7 FSM retool** | Unblocked — principal form, reward reception, absolute sparse `ClaimedEpochSet` |
| **Gate 6 firewall** | Load-bearing privacy |
| **§4.5 collapse** | Done in emission leg — lagged §4.4 read + boundary/reorg |
| **ν dissolution** | **Pinned** — corpus synced (2026-06-07) |
| **Numeric `W`** | Shape pinned; value open |

**Blocked on implementation of this schema:** emission vin, `work_P` recompute, bond-record
integration tests, 8c verifier hookup.

---

## 9. Open pins (pre-code)

### 9.1 Implementation checklist

- [x] Gate-3 dissolution disposition — derived `R_market`, no ν primitive.
- [ ] Pin `ShardId` + retention-ledger key `(P_id, shard_id, E)` + epoch indexing.
- [ ] Pin `R_market` snapshot at epoch close (count with `retention ∧ good_through`).
- [ ] Pin `good_through` encoding — bonded/slashed/re-bond **event log with interval
      semantics** at `E`-close (§3.4; not scalar `slash_epoch`).
- [ ] Pin `MAX_CLAIM_AGE_W` + `REORG_HORIZON` + prune semantics + **drain-vs-forfeiture**
      joint check with `MAX_SETTLEMENT_EPOCHS_PER_EMISSION` (§5; emission §3, §6.6 W pin).
- [ ] Pin `Σwork(E)` finalization (sweep vs incremental) + reorg revert order (emission §8).
- [ ] Pin finalization boundary **jointly** with emission §4.5 lagged read.
- [ ] Retention-proof construction bytes (8c) — may follow interface pin.
- [ ] KAT: emission recompute against fixture ledger state.

### 9.2 Settlement-epoch length — joint gate 2 / gate 6 (F1)

**Promotion (2026-06-07):** `SETTLEMENT_EPOCH_BLOCKS` (emission leg §3; inherited
10_000 blocks) is no longer only a gate-2 challenge-cadence knob. It is a **joint
gate-2 / gate-6 parameter**:

| Finer epochs | Coarser epochs |
|--------------|----------------|
| Faster reward settlement | Slower reward settlement |
| Finer public retention timeline (E-4 fingerprint risk) | Blurs per-epoch liveness fingerprint (rotation-favorable) |

L14 retrieval-as-proof makes the on-chain retention bit the primary public liveness
signal; epoch length sets that signal's resolution. **Defer numeric pin** until the
joint decision with `W`, `REORG_HORIZON`, and finalization boundary (§9.1) — coarser
`E` may trade acceptable forfeiture/lapse headroom against firewall decorrelation.
Record disposition here before choosing the constant; gate-6 firewall spec owns the
threat-model argument, this doc owns the consensus read-surface coupling.

---

## 10. Related documents

| Doc | Relationship |
|-----|----------------|
| [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) | Consumer; owns `Σwork` arithmetic and dedup |
| [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) | Wallet FSM; gate 2 registration shape |
| [`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md) | Economics; two-count table; honest residual |
| [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) | Layer 2 margin-robustness; participation attractor |

---

## Revision history

- **2026-06-07 (initial):** Schema gating doc; `MAX_CLAIM_AGE_W`; §4.4/§4.5 collapse.
- **2026-06-07 (contract pin):** Gate-3 ν dissolution; two-half contract (read surface +
  invariants); public `P_id` keying; derived `R_market`; `good_through` read requirement;
  prune horizon `max(W, REORG_HORIZON)`.
- **2026-06-07 (F1–F4 pins):** Timeline-axis honest residual (§2); §9.2 epoch-length
  joint gate-2/6; `good_through` interval event log (§3.4); `W` × per-`P` batch drain
  invariant (§5).
