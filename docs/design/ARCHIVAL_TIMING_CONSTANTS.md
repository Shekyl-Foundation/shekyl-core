# Archival timing constants — joint cluster (stub)

**Status:** **Shape + couplings pinned (2026-06-07).** Numeric **values** open — pin in one
cluster pass (sim + L16 transport + reorg), not per-doc in isolation.

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
| `MAX_CLAIM_AGE_W` (`W`) | **TBD** | E-3 forfeiture horizon (settlement epochs) | Archival state §5 |
| `REORG_HORIZON` | **TBD** | Consensus + wallet reorg depth (blocks) | Archival state §5 |
| `RELEASE_COOLDOWN_EPOCHS` | **TBD** | Grace after last serve before `Unbond` (settlement epochs) | Gate-4 §3.4–§4.3 |
| `CHALLENGE_RESOLUTION_BLOCKS` | **TBD** (gate-2) | Worst-case slash challenge window (blocks) | Gate-2 (interface) |

**Derived (not independent constants):**

```text
settlement_epoch(height) = height / SETTLEMENT_EPOCH_BLOCKS    // integer division
prune_horizon_epochs     = max(W, REORG_HORIZON / SETTLEMENT_EPOCH_BLOCKS)   // round up at pin time
```

At default **120 s** block time, `SEB = 10_000` ⇒ one settlement epoch ≈ **13.9 days**.

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
rhythms inside `T_obs`; they do not shorten the window below operator lifetime. Quantitative
T-A4 pass/fail thresholds pin with this cluster's values.

SEB is **not** TBD in the same sense as `W` or `REORG_HORIZON`; it is pinned pending the
emission-cadence inheritance review above.

---

## 2. Couplings (must pass jointly at pin time)

### 2.1 Release cooldown vs backlog (`W`)

**Asymmetry (load-bearing):** collateral return and reward backlog are **independent**
value flows ([`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §3.4).

```text
RELEASE_COOLDOWN_EPOCHS  <  W
```

Release cooldown is ~one grace window after `P`'s last served epoch; `W` governs when
unclaimed **reward** epochs forfeit. `Unbond` must not be blocked until challenges for
post-serve epochs can no longer land.

### 2.2 L16 floor on release cooldown

`RELEASE_COOLDOWN_EPOCHS` (in blocks via `× SEB`) must exceed:

- worst-case onion-rendezvous / decorrelated-drain latency (sim **L16**), and
- `CHALLENGE_RESOLUTION_BLOCKS` (gate-2 slash path).

See [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) §2.4 (Unbond refund
decorrelation) and [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) L16.

### 2.3 Reorg horizon

```text
REORG_HORIZON  ≥  W × SETTLEMENT_EPOCH_BLOCKS
                 + join_lag_blocks
                 + emission_batch_window_blocks
```

Where `join_lag_blocks` covers at least one settlement-epoch lag between join-Market and
first paying mint (`E_first ≥ E_join + 1`), and `emission_batch_window_blocks` covers
`MAX_SETTLEMENT_EPOCHS_PER_EMISSION` epochs of in-flight emission.

Wallet reorg handling (P2B-5): re-fetch bond record; refresh `claimed_epochs_cache`; clear
`emission_pending_epochs` for disconnected heights — assumes horizon covers in-flight work.

### 2.4 Drain vs forfeiture (F4)

Continuously-honest `P` with a backlog must drain before the oldest accrued epoch crosses
`tip_epoch − W`:

```text
∀ P honest: drainable_epochs_per_wall_clock ≥ epochs_accruing_per_wall_clock
  while backlog_depth ≤ W
```

With batch cap `MAX_SETTLEMENT_EPOCHS_PER_EMISSION = 15`, pin `W` such that a `P` emitting
once per settlement epoch never forfeits while catching up from max backlog **15** (sim
inequality — numeric check at cluster pin).

### 2.5 Prune semantics

Structures pruned after `tip − prune_horizon_epochs` ([`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) §5):

- retention ledger rows
- derived `R_market` / `Σwork` views
- per-`P` `ClaimedEpochSet` entries (verify rejects ancient `E`)

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

## 4. Pin procedure (when values land)

1. Run sim cluster checks (`STAKER_ARCHIVAL_SIM.md` — joint pin item).
2. Verify §2 inequalities with proposed numerics + L16 measured latency.
3. Write values to `config/consensus_constants.json` (migration from doc pins per emission
   §3 note on `SETTLEMENT_EPOCH_BLOCKS`).
4. Update emission §6.6, archival state §5, gate-4 §8.2 checkboxes, and sim fixtures in
   **one commit series** (bisectable per constant group if needed, but no intermediate
   consensus state where nodes disagree on `W` or `REORG_HORIZON`).

---

## 5. Open checklist

- [ ] Numeric `W`
- [ ] Numeric `REORG_HORIZON`
- [ ] Numeric `RELEASE_COOLDOWN_EPOCHS` (with L16 + gate-2 floor proof)
- [ ] F4 drain inequality signed in sim
- [ ] `ClaimedEpochSet` wire encoding (depends on sparse `W` envelope — PHASE_2B §3.3)

---

## Revision history

- **2026-06-07:** Initial stub — cluster enumeration, couplings, conservation cross-ref;
  values deferred to sim pin pass.
