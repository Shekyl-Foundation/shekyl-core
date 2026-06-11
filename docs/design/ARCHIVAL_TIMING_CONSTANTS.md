# Archival timing constants — joint cluster

**Status:** **Values pinned (2026-06-07, reorg/retention split).** Sim-backed checks:
`cargo run -p shekyl-staking-sim -- --timing-cluster` (see §6).

**Authority:** This doc is the **single enumeration** for the interdependent timing cluster.
Consumers cite this file; they do not re-derive couplings locally. Superseded-model rationale
audit: [`ARCHIVAL_CORPUS_FOSSIL_SWEEP.md`](ARCHIVAL_CORPUS_FOSSIL_SWEEP.md).

| Doc | Consumes |
|-----|----------|
| [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) | Release cooldown vs `W`; `pop_block` depth |
| [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) | Prune horizon (`W`); retention floor |
| [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) | Settlement cadence; batch cap; §4.5 lagged read |
| [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) | Decorrelation vs lapse; T-A16 |
| [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) | Numeric pin + inequality checks |
| [`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md) P2B-5 | Wallet reorg refresh depth |

**Forward order** (per [`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md)): PHASE_2B §3 FSM
rewrite → P2B-6 §7 threat re-center → **this cluster's values** (sim-backed).

---

## 1. Cluster table

| Constant | Genesis value | Role | Primary owner |
|----------|---------------|------|---------------|
| `SETTLEMENT_EPOCH_BLOCKS` | **10_000** (inherited) | Global settlement boundary; `E_join = height / SEB` | Emission §3 |
| `MAX_SETTLEMENT_EPOCHS_PER_EMISSION` | **15** | Max epochs per emission vin; work vector + dedup batch | Emission §3 |
| `MAX_CLAIM_AGE_W` (`W`) | **26** | E-3 forfeiture horizon (settlement epochs); **hot prune** | Archival state §5 |
| `RETENTION_HORIZON_BLOCKS` | **420_000** | Min block-span archival derived state survives before prune sweep | Archival state §5 |
| `ARCHIVAL_REORG_DEPTH_BLOCKS` | **720** | Max processable reorg depth (blocks); `pop_block` + wallet refresh | Gate-4 §5, P2B-5 |
| `RELEASE_COOLDOWN_EPOCHS` | **2** | Grace after last serve before `Unbond` (settlement epochs) | Gate-4 §3.4–§4.3 |
| `CHALLENGE_RESOLUTION_BLOCKS` | **10_000** (gate-2 interface) | Worst-case slash challenge window (blocks) | Gate-2 (interface) |
| `BOND_DURATION_BASE_EPOCHS` | **4** (provisional¹) | Flat floor of per-shard retention-commitment horizon (settlement epochs) | Gate-4; sim L9/L10 |
| `BOND_DURATION_AGE_SCALE` | **4** (provisional¹) | Age multiplier: `bond_duration(age) = BASE · (1 + SCALE·age)`, `age ∈ [0,1]` normalized shard age | Gate-4; sim L9/L10 |

¹ **Shape pinned, numerics provisional (2026-06-11).** Shape is **age-scaled-constant**
([`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) §*L10 hardening* disposition); the numeric
pair is the sim-exercised H2 plateau arm and is re-confirmed or re-pinned when testnet measures
`fetch_latency_per_unit`. Drift within the plateau band (scale ∈ [2,8]) amends this table only;
a shape change requires the L10 reversion clause.

**Derived (not independent constants):**

```text
settlement_epoch(height) = height / SETTLEMENT_EPOCH_BLOCKS    // integer division
prune_horizon_epochs     = W                                   // = 26
retention_horizon_epochs = ceil(RETENTION_HORIZON_BLOCKS / SEB) // = 42 (audit / sweep only)
```

At default **120 s** block time (`daa_target_seconds`), `SEB = 10_000` ⇒ one settlement
epoch ≈ **13.9 days** (~2 weeks).

| Derived (wall clock @ 120 s/block) | Value |
|------------------------------------|-------|
| `W` = 26 epochs | ~**361 days** (~1 year claim headroom) |
| `RETENTION_HORIZON_BLOCKS` | ~**583 days** (~19 months block-span floor) |
| `ARCHIVAL_REORG_DEPTH_BLOCKS` | ~**24 hours** |
| `RELEASE_COOLDOWN_EPOCHS` = 2 | ~**28 days** |
| `CHALLENGE_RESOLUTION_BLOCKS` = 10_000 | ~**13.9 days** (one SEB) |
| `bond_duration` range (base 4, scale 4) | ~**8 weeks** (youngest deep) → ~**9 months** (oldest) |

### 1.1 Reorg depth vs retention horizon (load-bearing split)

**`REORG_HORIZON` is deleted.** The prior pin conflated two unrelated jobs:

| Job | Constant | Question it answers |
|-----|----------|---------------------|
| **Processable reorg** | `ARCHIVAL_REORG_DEPTH_BLOCKS` | How far back may consensus `pop_block` and the wallet re-fetch bond/emission caches? |
| **Retention floor** | `RETENTION_HORIZON_BLOCKS` | How long must archival derived state remain before a prune sweep may drop it? |

A 19-month **reorg** depth asserted clean revert of 19 months of chain history — moot in
PoW (an attacker who out-hashed that window has already won). A 19-month **retention**
floor is correct: it is `W` claim epochs plus join lag and in-flight batch window expressed
in blocks (§2.3).

Wallet refresh (P2B-5) tracks **`ARCHIVAL_REORG_DEPTH_BLOCKS`**, not `RETENTION_HORIZON_BLOCKS`.
Ordinary scan safety (`NetworkSafetyConstants::max_reorg_depth`, default 10 confirmations)
is a separate, shallower UX finality knob — see §2.3.

### 1.2 SEB and F1 (emission cadence — not a structural F1 lever)

[`PHASE_2B_SECTION7_DRAFT.md`](PHASE_2B_SECTION7_DRAFT.md) §7: retention fingerprint **F1**
has a fixed **shard** axis (per-`(P,s,E)` — not coarsenable without breaking Σwork / `R_market`)
and an **epoch** axis at settlement granularity.

**T-A1 update (2026-06-07, v2 instrument).** Coarser SEB does **not** materially change
portfolio cohort size. SEB governs **emission cadence and wallet UX**, not structural
re-linkage decorrelation.

**T-A4 coupling:** with `W = 26` and settlement-epoch batching, standing emission events are
~**26 samples/year** — sparse relative to principal graph activity. Wallet jitter / drain-spacing
defaults remain gate-6 Round 3–4 (non-consensus); see §7.

---

## 2. Couplings (verified at pin — §6)

### 2.1 Release cooldown vs backlog (`W`)

```text
RELEASE_COOLDOWN_EPOCHS  <  W     ✓  (2 < 26)
```

Collateral return and reward backlog are **independent** value flows
([`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §3.4).

### 2.2 L16 floor on release cooldown; T-A16 margin

```text
RELEASE_COOLDOWN_EPOCHS × SEB  >  CHALLENGE_RESOLUTION_BLOCKS     ✓  (20_000 > 10_000)
```

`CHALLENGE_RESOLUTION_BLOCKS = 10_000` (~14 d at 120 s/block) is **generous** relative to
onion rendezvous latency (L16): a transient DoS on `P`'s rendezvous cannot force slash within
the challenge window (T-A16 forced-slash-via-liveness). Re-verify at gate-2 challenge cadence
pin.

### 2.3 Retention horizon floor (blocks — not reorg depth)

```text
RETENTION_HORIZON_BLOCKS  ≥  W × SETTLEMENT_EPOCH_BLOCKS
                            + join_lag_blocks
                            + emission_batch_window_blocks

420_000  ≥  26 × 10_000 + 10_000 + 15 × 10_000  =  420_000     ✓  (tight pin)
```

`join_lag_blocks = SEB` (`E_first ≥ E_join + 1`). `emission_batch_window_blocks =
MAX_SETTLEMENT_EPOCHS_PER_EMISSION × SEB`.

This is a **retention** bound only. It does **not** set reorg processing depth.

### 2.4 Reorg depth vs settlement epoch (finality)

```text
ARCHIVAL_REORG_DEPTH_BLOCKS  ≪  SETTLEMENT_EPOCH_BLOCKS     ✓  (720 ≪ 10_000)
```

**Why deep reorg depth is not needed for emission safety** (docs-level trace; confirm against
`pop_block` implementation before codegen):

1. **Claiming an old epoch `E` (up to `W` back)** in a *recent* emission block: `Σwork(E)`,
   `R_market(s,E)`, and retention bits for `E` are **finalized-and-immutable at E-close**
   (archival state invariant 2; emission §4.5 lagged read). Reorg reverts only the **recent**
   emission's `claimed_settlement_epochs` mutation and mint (emission §8 step 1–2) — not
   finalized epoch-`E` tables. The new branch re-emits against unchanged final state.

2. **Claiming a recent epoch** within reorg depth: emission block and earned epoch co-revert
   atomically (gate-4 §5 all-types-atomic `pop_block`).

3. **Settlement lag:** first paying emission requires `E ≥ E_join + 1`; any sane
   `ARCHIVAL_REORG_DEPTH` (hundreds of blocks) is `≪ SEB`. By the time an epoch is
   claimable, it is already final relative to reorg depth.

Emission verify order (§7.1 steps 3–5) reads **stored** `Σwork(E)` and bond record fields;
it does not reach back into mutable pre-finalization state for ancient `E`.

**Wallet (P2B-5):** on reorg, re-fetch `ArchivalBondRecord`; refresh `claimed_epochs` cache;
clear `emission_pending_epochs` for heights `> tip − ARCHIVAL_REORG_DEPTH_BLOCKS`.

**Caveat:** if implementation audit finds a path where recent-block validity reads
non-final `W`-deep mutable state, reopen this split before genesis.

### 2.5 Drain vs forfeiture (F4)

With `W = 26`, batch cap `15`: offline burst through full `W`, and slow catch-up after
25-epoch offline — **PASS** (`timing_cluster.rs`).

### 2.6 Prune semantics

Hot consensus structures pruned for epochs with `E < tip_epoch − W`:

- serve-credit ledger rows
- derived `R_market` / `Σwork` views
- per-`P` `ClaimedEpochSet` entries (verify rejects ancient `E`)

`prune_horizon_epochs = W = **26**`. `RETENTION_HORIZON_BLOCKS` is the block-span floor for
retention sweeps and audit — it does **not** inflate `prune_horizon_epochs` via `max()`.

---

## 3. Conservation law cross-reference

Unchanged — bond timing moves value between terms; it does not add supply.

---

## 4. Pin procedure

1. ✅ Sim cluster checks — `shekyl-staking-sim --timing-cluster`.
2. ✅ §2 inequalities + reorg/retention split documented.
3. ⏳ `config/consensus_constants.json` — documented §6.3; codegen deferred.
4. ⏳ `pop_block` / emission-validity implementation audit (§2.4 caveat).
5. ⏳ Gate-6 Round 3–4 wallet defaults.

---

## 5. Checklist

- [x] Numeric `W` = 26
- [x] `RETENTION_HORIZON_BLOCKS` = 420_000
- [x] `ARCHIVAL_REORG_DEPTH_BLOCKS` = 720
- [x] `RELEASE_COOLDOWN_EPOCHS` = 2
- [x] `CHALLENGE_RESOLUTION_BLOCKS` = 10_000 (+ T-A16 margin §2.2)
- [x] F4 signed in sim
- [ ] `pop_block` implementation confirms §2.4 trace
- [ ] `ClaimedEpochSet` wire encoding (PHASE_2B §3.3)
- [ ] Consensus codegen
- [ ] Gate-6 Round 3–4 wallet defaults

---

## 6. Pin record (2026-06-07)

### 6.1 Rationale summary

| Constant | Why this value |
|----------|----------------|
| **`W = 26`** | ~1 calendar year claim headroom at 13.9 d/settlement-epoch; bounds hot `ClaimedEpochSet` / retention state; F4 passes burst and slow catch-up. **Not** a decorrelation dial — lapse without portfolio change does not re-link (F1 T-A1); `W` bounds **forfeiture economics** and state growth. |
| **`RETENTION_HORIZON_BLOCKS = 420_000`** | Tight §2.3 retention floor in blocks (`W×SEB + join + batch`). Governs minimum survival before prune **sweep**; distinct from reorg depth. |
| **`ARCHIVAL_REORG_DEPTH_BLOCKS = 720`** | ~24 h at 120 s/block — PoW finality-scale processable reorg (`≪ SEB`). P2B-5 wallet archival refresh bound. |
| **`RELEASE_COOLDOWN_EPOCHS = 2`** | Two settlement epochs (~28 d) > one SEB challenge window; `< W`; L16 + Unbond decorrelation headroom. |
| **`CHALLENGE_RESOLUTION_BLOCKS = 10_000`** | One SEB; aligns slash challenge to settlement cadence; T-A16 transient-DoS margin (§2.2). |

### 6.2 Sim verification

```bash
cargo run -p shekyl-staking-sim -- --timing-cluster
```

### 6.3 `config/consensus_constants.json` (pre-codegen)

```json
"settlement_epoch_blocks": 10000,
"max_settlement_epochs_per_emission": 15,
"max_claim_age_w": 26,
"retention_horizon_blocks": 420000,
"archival_reorg_depth_blocks": 720,
"release_cooldown_epochs": 2,
"challenge_resolution_blocks": 10000
```

---

## 7. T-A4 / gate-6 wallet defaults (non-consensus — Round 3–4)

| Default | Floor from cluster | Round |
|---------|-------------------|-------|
| Emission batching | `MAX_SETTLEMENT_EPOCHS_PER_EMISSION = 15` | landed |
| Archival reorg refresh | `ARCHIVAL_REORG_DEPTH_BLOCKS` | P2B-5 |
| Min spacing join-Market ↔ principal spend | ≥ 1 settlement epoch | gate-6 R4 |
| Emission jitter | ± fraction of `SEB` (wallet-local) | gate-6 R3 |
| Decorrelated drain min delay | ≥ `RELEASE_COOLDOWN × SEB` from last emission | gate-6 R4 |
| Fund-from-earnings ramp | ≥ 2 settlement epochs of `P`-local earnings | gate-6 R4 (T-A6) |

---

## Revision history

- **2026-06-07 (reorg/retention split):** Delete `REORG_HORIZON`; add `RETENTION_HORIZON_BLOCKS`,
  `ARCHIVAL_REORG_DEPTH_BLOCKS`; `prune_horizon_epochs = W`; §2.4 emission/reorg trace; T-A16
  note; fix `W` rationale (forfeiture not decorrelation).
- **2026-06-07 (values pin):** Initial numeric pin + sim harness.
- **2026-06-07:** Initial stub — cluster enumeration, couplings.
