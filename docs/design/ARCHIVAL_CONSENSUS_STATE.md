# Archival consensus state — gate 2 / gate 3 schema (genesis)

**Status:** **Next move** — gating spec. The reward-emission leg
([`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md)) is structurally closed at Layer 1
but **un-implementable** until this schema is pinned. Tier-1 **8c retention-proof
unforgeability** (construction bytes) may still defer relative to Phase 2b wallet work;
the **consensus interface** — what state emission reads, how it is keyed, how it
prunes — **cannot**.

**Scope:** Consensus LMDB (or equivalent) tables and keying for:

1. **Gate 2** — per-`(P, shard, E)` retention / challenge outcome (`proven_retention`).
2. **Gate 3** — `R_market(shard, E)` replication counts; `shard_id` identity.
3. **Growth bounds** — `MAX_CLAIM_AGE_W` and pruning of reward-accounting state.
4. **§4.4 accumulator** — per-epoch `Σwork(E)` finalized at epoch close (interface
   only; arithmetic owned by emission leg §4.0).

**Out of scope here:** retention-proof **construction** wire (prover bytes); gate 6
off-chain firewall; gate 4 bond post/slash wire; wallet FSM ([`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §3–§7 retool).

**Upstream:** [`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md) §*Pay-for-service
rebasing*, loud 8c; [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §5.4, §6.

---

## 1. Why this is the critical path

Pinning the emission leg promoted gate-2/gate-3 archival state onto the **critical
path**. Loud 8c recompute in §5.4 **consumes** consensus archival state it does not
define:

| Emission read | Owner | Deferred in emission leg |
|---------------|-------|---------------------------|
| `proven_retention(P, shard, E)` | Gate 2 challenge ledger | §5.4 — "consumes, not defines" |
| `shard_id` keying | Gate 2 shard registry | Same |
| `R_market(shard, E)` for scarcity | Gate 3 counting | §4.3 `scarcity_milli` recompute |
| `Σwork(E)` finalized total | §4.4 accumulator | Lagged read rule §4.5 |

**Distinction that matters:** 8c **soundness** (proof unforgeability, verifier
construction) can defer relative to 2b implementation sequencing. The **interface**
(table names, key tuples, epoch indexing, prune rules) cannot — nothing downstream
(vin deserializer, `work_P` recompute, wallet FSM) is implementable without it.

This schema is simultaneously:

- The emission leg's **missing input**,
- The home of the last open Tier-1 **crypto soundness** item (8c), and
- Where **`MAX_CLAIM_AGE_W`** and per-`(P, shard, E)` layout are decided **together**.

---

## 2. State surfaces (to pin at genesis)

### 2.1 Gate 2 — retention / challenge ledger

**Semantic:** For each market archiver `P`, shard `s`, settlement epoch `E`:

```text
proven_retention(P, s, E) : bool
```

Set when the challenge for `(P, s)` relevant to `E` **passed** (grace window per gate 4).
Emission §6.5 `good_through(E)` is orthogonal (slash); retention is per-shard challenge
outcome.

**Must pin:**

- `ShardId` encoding and stable `shard_id` assignment (set-B shard registry).
- Challenge-record **key**: e.g. `(P_canonical_id, shard_id, settlement_epoch)` or
  height-bounded variant — one choice, no wallet-local interpretation.
- When the bit flips (challenge close vs epoch close ordering).
- **Prune rule** joint with §2.4 `W` (below).

**8c deferral boundary:** This section pins **what** verifiers read at recompute time.
The **proof object** that authorizes flipping the bit is a separate deliverable; the
interface must not change when construction lands.

### 2.2 Gate 3 — `R_market` and counting

**Semantic:** Active replica count per shard at epoch boundary for scarcity:

```text
R_market(shard, E) : u32   // ≥ 1 when shard exists in market
```

`ν = H(P, shard)` counting primitive stays **separate** from reward epoch dedup
(`ClaimedEpochSet` on bond record).

**Must pin:**

- Whether `R` is snapshot at epoch close or block-height keyed.
- Interaction with holdings descriptor (only shards in `P`'s portfolio accrue work).

### 2.3 §4.4 — `Σwork` accumulator (interface)

§4.4 already commits: per-settlement-epoch accumulator **finalized at epoch close**
from continuous recording of each market `P`'s `capped_P(E)`.

§4.5 collapses to: emissions in `E+1` (within claim window) **read** the stored
`Σwork(E)` from this table — lagged one epoch, all-recorded denominator. Remaining
genesis-seal work: **boundary rules** (late emitters after close, batching cap 15) and
**reorg** (revert finalization with epoch disconnect). See emission leg §4.5.

**Rejected default (named reopen only):** claimed-only denominator → two-phase /
provisional+true-up machinery. Reopen only if all-recorded dilution is unacceptable
*and* inflation-bound proofs for claimed-only are specified.

### 2.4 `MAX_CLAIM_AGE_W` — bounded reward-accounting state

**Gap exposed by pinned state dedup:** Archival reward-accounting state **grows
unbounded** without a claim-age window:

| Structure | Growth without `W` |
|-----------|-------------------|
| `ClaimedEpochSet` per `P` | Absolute sparse set, all-time |
| Per-`(P, shard, E)` retention | One row per served epoch |
| Per-epoch `Σwork(E)` | One row per settlement epoch forever |

V3 flags this loosely (§1264, "claim windows probably right"); the emission leg had no
`W` until this pin.

**Genesis pin (proposed shape):**

```text
MAX_CLAIM_AGE_W : u64   // in settlement-epoch units
```

Epochs with `E < current_epoch - W` are **unclaimable**. Effects:

- `ClaimedEpochSet` need only retain epochs ≥ `current - W` (or full history with
  reject-at-verify for old `E`).
- Settled `Σwork(E)` rows with `E < current - W` **droppable** from hot state (archive
  or delete per ops policy; consensus need not serve ancient claims).
- Old per-`(P, shard, E)` retention rows **reclaimable** after `W`.

**Tradeoff (consensus-visible):** A `P` offline longer than `W` **forfeits** unclaimed
epochs older than the window. Gate-6 hygiene may have `P` **deliberately lapse** for
decorrelation — `W` trades **consensus-state growth** against **lapse-forfeiture**.
`W` is not wallet policy; it is a consensus constant (like `MAX_SETTLEMENT_EPOCHS_PER_EMISSION`).

**Interaction:** `W` ≥ practical batch size (15) but tight enough to bound LMDB;
sim sweep for operator pain vs state size is Layer 2 / ops input, not a substitute for
pinning `W`.

---

## 3. Parallel work (not blocked on this doc landing)

| Workstream | Status after emission Layer 1 pin |
|------------|-----------------------------------|
| **§3–§7 FSM retool** | Unblocked — principal form decided (ordinary transfer ≥ `MIN`, no `C_stake`); reward reception defined; `EpochSet` → absolute sparse set on bond record; reorg reverts bitmap |
| **Gate 6 firewall** | Load-bearing privacy — invariant rigor + FAQ privacy conditionality |
| **§4.5 collapse** | Done in emission leg — lagged §4.4 read + boundary/reorg |
| **V3 §883 / gate-1 form C** | Reconciled |

**Blocked on this schema:** emission vin implementation, `work_P` consensus recompute,
`ArchivalBondRecord` integration tests against real challenge state, 8c verifier hookup.

---

## 4. Implementation checklist (pre-code)

- [ ] Pin `ShardId` + challenge-ledger key tuple + epoch indexing.
- [ ] Pin `R_market(shard, E)` snapshot rule at epoch close.
- [ ] Pin `MAX_CLAIM_AGE_W` + prune semantics for retention rows and `Σwork` history.
- [ ] Pin `Σwork(E)` finalization sweep at epoch close (all-recorded; E-3 slash stays in denominator).
- [ ] Document reorg revert order joint with [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §8.
- [ ] Retention-proof construction bytes (8c) — may follow interface pin.
- [ ] KAT: emission recompute against fixture ledger state.

---

## 5. Related documents

| Doc | Relationship |
|-----|----------------|
| [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) | Consumer of this schema |
| [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) | Wallet FSM; gate 2 shape at registration |
| [`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md) | Economics; loud 8c; claim-window intuition §1264 |
| [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) | Layer 2 margin-robustness (spread band) |

---

## Revision note

**2026-06-07:** Initial schema gating doc — promoted by emission-leg Layer 1 pin;
`MAX_CLAIM_AGE_W`; §4.4/§4.5 collapse; interface vs 8c construction deferral.
