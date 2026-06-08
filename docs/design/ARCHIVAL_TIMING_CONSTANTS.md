# Archival timing constants — joint cluster

**Status:** **Values pinned (2026-06-07).** Sim-backed inequality checks:
`cargo run -p shekyl-staking-sim -- --timing-cluster` (see §6).

**Authority:** This doc is the **single enumeration** for the interdependent timing cluster.
Consumers cite this file; they do not re-derive couplings locally.

| Doc | Consumes |
|-----|----------|
| [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) | Release cooldown vs `W`; reorg horizon |
| [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) | Prune horizon; drain vs forfeiture |
| [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) | Settlement cadence; batch cap |
| [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) | Decorrelation vs lapse |
| [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) | Numeric pin + inequality checks |
| [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) | Wallet staleness / reorg refresh |

**Forward order** (per [`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md)): PHASE_2B §3 FSM
rewrite → P2B-6 §7 threat re-center → **this cluster's values** (sim-backed).

---

## 1. Cluster table

| Constant | Genesis value | Role | Primary owner |
|----------|---------------|------|---------------|
| `SETTLEMENT_EPOCH_BLOCKS` | **10_000** (inherited) | Global settlement boundary; `E_join = height / SEB` | Emission §3 |
| `MAX_SETTLEMENT_EPOCHS_PER_EMISSION` | **15** | Max epochs per emission vin; work vector + dedup batch | Emission §3 |
| `MAX_CLAIM_AGE_W` (`W`) | **26** | E-3 forfeiture horizon (settlement epochs) | Archival state §5 |
| `REORG_HORIZON` | **420_000** (blocks) | Consensus + wallet reorg depth (blocks) | Archival state §5 |
| `RELEASE_COOLDOWN_EPOCHS` | **2** | Grace after last serve before `Unbond` (settlement epochs) | Gate-4 §3.4–§4.3 |
| `CHALLENGE_RESOLUTION_BLOCKS` | **10_000** (gate-2 interface) | Worst-case slash challenge window (blocks) | Gate-2 (interface) |

**Derived (not independent constants):**

```text
settlement_epoch(height) = height / SETTLEMENT_EPOCH_BLOCKS    // integer division
prune_horizon_epochs     = max(W, ceil(REORG_HORIZON / SEB)) = 42
```

At default **120 s** block time (`daa_target_seconds`), `SEB = 10_000` ⇒ one settlement
epoch ≈ **13.9 days** (~2 weeks).

| Derived (wall clock @ 120 s/block) | Value |
|------------------------------------|-------|
| `W` = 26 epochs | ~**361 days** (~1 year) |
| `RELEASE_COOLDOWN_EPOCHS` = 2 | ~**28 days** |
| `REORG_HORIZON` = 420_000 blocks | ~**583 days** (~19 months) |
| `CHALLENGE_RESOLUTION_BLOCKS` = 10_000 | ~**13.9 days** (one SEB) |

### 1.1 SEB and F1 (emission cadence — not a structural F1 lever)

[`PHASE_2B_SECTION7_DRAFT.md`](PHASE_2B_SECTION7_DRAFT.md) §7: retention fingerprint **F1**
has a fixed **shard** axis (per-`(P,s,E)` — not coarsenable without breaking Σwork / `R_market`)
and an **epoch** axis at settlement granularity.

**T-A1 update (2026-06-07, v2 instrument).** Coarser SEB (`ta1_f1_seb_coarse`, 20_000 blocks)
does **not** materially change timeline baseline/lapse metrics or portfolio cohort size. The
binding F1 variable in sim is **shard-set portfolio co-holder cohort**, not epoch resolution.
SEB therefore governs **emission cadence and wallet UX** (claim batching, calendar rhythm), not
structural re-linkage decorrelation.

| SEB disposition | F1 consequence |
|-----------------|----------------|
| **10_000 is a genuine emission-cadence lock** | F1 finally accepted **iff T-A3–T-A7 pass** under lifetime `T_obs` ([`F1_TA3_TA7_LIFETIME_WINDOW.md`](F1_TA3_TA7_LIFETIME_WINDOW.md)). T-A1 instrument closed. |
| **"Inherited" is placeholder** | Coarser SEB is **emission-policy** only — not an F1 privacy dial. |

**T-A4 coupling:** emission batching, `W`, and drain cadence set *secondary* correlation
rhythms inside `T_obs`; they do not shorten the window below operator lifetime. With `W = 26`
and settlement-epoch batching, standing emission events are ~**26 samples/year** — sparse
relative to principal graph activity. Wallet jitter / drain-spacing defaults remain gate-6
Round 3–4 (non-consensus); see §7.

---

## 2. Couplings (verified at pin — §6)

### 2.1 Release cooldown vs backlog (`W`)

**Asymmetry (load-bearing):** collateral return and reward backlog are **independent**
value flows ([`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §3.4).

```text
RELEASE_COOLDOWN_EPOCHS  <  W     ✓  (2 < 26)
```

Release cooldown is ~one grace window after `P`'s last served epoch; `W` governs when
unclaimed **reward** epochs forfeit. `Unbond` must not be blocked until challenges for
post-serve epochs can no longer land.

### 2.2 L16 floor on release cooldown

`RELEASE_COOLDOWN_EPOCHS` (in blocks via `× SEB`) must exceed:

- worst-case onion-rendezvous / decorrelated-drain latency (sim **L16**), and
- `CHALLENGE_RESOLUTION_BLOCKS` (gate-2 slash path).

```text
RELEASE_COOLDOWN_EPOCHS × SEB  >  CHALLENGE_RESOLUTION_BLOCKS     ✓  (20_000 > 10_000)
```

**L16 margin (qualitative):** `fetch_latency_per_unit` is post-testnet measured; release
cooldown of **two settlement epochs** (~28 d) exceeds one SEB challenge window plus headroom
for onion round-trip and decorrelated-drain spacing at the L10 `L2–L6` operating band.
Re-verify if live transport sits at `L6` ceiling *and* gate-2 challenge cadence tightens.

See [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) §2.4 (Unbond refund
decorrelation) and [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) L16.

### 2.3 Reorg horizon

```text
REORG_HORIZON  ≥  W × SETTLEMENT_EPOCH_BLOCKS
                 + join_lag_blocks
                 + emission_batch_window_blocks

420_000  ≥  26 × 10_000 + 10_000 + 15 × 10_000  =  420_000     ✓  (tight pin)
```

Where `join_lag_blocks = SEB` covers at least one settlement-epoch lag between join-Market and
first paying mint (`E_first ≥ E_join + 1`), and `emission_batch_window_blocks =
MAX_SETTLEMENT_EPOCHS_PER_EMISSION × SEB`.

Wallet reorg handling (P2B-5): re-fetch bond record; refresh `claimed_epochs_cache`; clear
`emission_pending_epochs` for disconnected heights — assumes horizon covers in-flight work.

**Note:** Ordinary wallet `DEFAULT_MAX_REORG_DEPTH` (100 blocks) is **not** this constant.
Archival emission refresh must track `REORG_HORIZON` separately (PHASE_2B §5).

### 2.4 Drain vs forfeiture (F4)

Continuously-honest `P` with a backlog must drain before the oldest accrued epoch crosses
`tip_epoch − W`:

```text
∀ P honest: drainable_epochs_per_wall_clock ≥ epochs_accruing_per_wall_clock
  while backlog_depth ≤ W
```

With batch cap `MAX_SETTLEMENT_EPOCHS_PER_EMISSION = 15` and `W = 26`:

| Scenario | Sim result |
|----------|------------|
| Offline up to **26** settlement epochs, burst-drain on return | **PASS** |
| Offline **25** epochs, emit every settlement epoch while serving (catch-up + accrual) | **PASS** |
| `W > 15` (batch cap headroom) | **PASS** |

See `rust/shekyl-staking-sim/src/timing_cluster.rs` and `--timing-cluster` harness.

### 2.5 Prune semantics

Structures pruned after `tip − prune_horizon_epochs` ([`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) §5):

- retention ledger rows
- derived `R_market` / `Σwork` views
- per-`P` `ClaimedEpochSet` entries (verify rejects ancient `E`)

`prune_horizon_epochs = max(26, ceil(420_000 / 10_000)) = **42**`.

---

## 3. Conservation law cross-reference

Bond timing does **not** add a fifth supply term. Collateral immobilization is
`bonded` in ([`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §4.5):

```text
already_generated_coins == circulating + bonded + burned
```

`W` and release cooldown affect **when** value moves between terms, not whether mint/slash
balance.

---

## 4. Pin procedure (completed)

1. ✅ Sim cluster checks — `shekyl-staking-sim --timing-cluster` (§6).
2. ✅ §2 inequalities with proposed numerics + L16 qualitative margin.
3. ⏳ Write values to `config/consensus_constants.json` — **documented** (§6); C++/Rust codegen
   wiring deferred to PHASE_2B implementation (no `KEYS_INTEGER` entry yet).
4. ⏳ Update emission §6.6, archival state §5, gate-4 §8.2 checkboxes, and sim fixtures in
   implementation commit series.

---

## 5. Checklist

- [x] Numeric `W` = 26
- [x] Numeric `REORG_HORIZON` = 420_000 blocks
- [x] Numeric `RELEASE_COOLDOWN_EPOCHS` = 2 (L16 + gate-2 floor proof §2.2)
- [x] F4 drain inequality signed in sim (`timing_cluster.rs`)
- [ ] `ClaimedEpochSet` wire encoding (depends on sparse `W` envelope — PHASE_2B §3.3)
- [ ] Consensus codegen (`generate_consensus_constants.py` / `build.rs`)
- [ ] Gate-6 Round 3–4 wallet defaults (jitter, drain spacing, fund-from-earnings ramp)

---

## 6. Pin record (2026-06-07)

### 6.1 Rationale summary

| Constant | Why this value |
|----------|----------------|
| **`W = 26`** | ~1 calendar year of claim headroom at 13.9 d/settlement-epoch; bounds hot `ClaimedEpochSet` / retention state; F4 passes burst and slow catch-up; deliberate lapse > 1 y is meaningful gate-6 decorrelation cost without making accidental offline forfeiture the norm. |
| **`REORG_HORIZON = 420_000`** | Tight satisfaction of §2.3 floor — covers full `W` window of in-flight emission state plus join lag and max batch window. |
| **`RELEASE_COOLDOWN_EPOCHS = 2`** | Two settlement epochs (~28 d) > one SEB slash-challenge window; `< W`; room for L16 onion rendezvous + decorrelated Unbond. |
| **`CHALLENGE_RESOLUTION_BLOCKS = 10_000`** | One settlement epoch — challenge deadlines align with emission cadence; consumed by gate-2 when landed. |

### 6.2 Sim verification

```bash
cargo run -p shekyl-staking-sim -- --timing-cluster
```

Machine-readable JSON on stdout; human summary on stderr. All couplings and F4 scenarios
**PASS** as of pin date.

### 6.3 `config/consensus_constants.json` (pre-codegen)

Documented for SSOT; not yet in `KEYS_INTEGER` / generated headers:

```json
"settlement_epoch_blocks": 10000,
"max_settlement_epochs_per_emission": 15,
"max_claim_age_w": 26,
"reorg_horizon_blocks": 420000,
"release_cooldown_epochs": 2,
"challenge_resolution_blocks": 10000
```

---

## 7. T-A4 / gate-6 wallet defaults (non-consensus — Round 3–4)

These are **not** cluster constants; they consume the pinned cluster for spacing floors:

| Default | Floor from cluster | Round |
|---------|-------------------|-------|
| Emission batching | `MAX_SETTLEMENT_EPOCHS_PER_EMISSION = 15` | landed (consensus) |
| Min spacing join-Market ↔ principal spend | ≥ 1 settlement epoch | gate-6 Round 4 |
| Emission jitter | ± fraction of `SEB` (wallet-local) | gate-6 Round 3 |
| Decorrelated drain min delay | ≥ `RELEASE_COOLDOWN × SEB` from last emission | gate-6 Round 4 |
| Fund-from-earnings ramp before join | ≥ 2 settlement epochs of `P`-local earnings | gate-6 Round 4 (T-A6) |

T-A4 **quantitative** pass/fail on timing correlation is **unblocked** for the consensus
leg; full T-A4 closure still requires gate-6 Round 3–4 wallet-default pins
([`F1_TA3_TA7_LIFETIME_WINDOW.md`](F1_TA3_TA7_LIFETIME_WINDOW.md) §9.2).

---

## Revision history

- **2026-06-07 (values pin):** `W=26`, `REORG_HORIZON=420_000`, `RELEASE_COOLDOWN_EPOCHS=2`,
  `CHALLENGE_RESOLUTION_BLOCKS=10_000`; sim harness; §6 pin record; T-A4 wallet-default table.
- **2026-06-07:** Initial stub — cluster enumeration, couplings, conservation cross-ref.
