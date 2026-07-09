# Archival budget schedule (gate 1) — `budget(E)` production

**Status:** DRAFT — spec-first round opened 2026-07-08 per the F-C1a
ratification ([`REWARD_EMISSION_E3_GATING_ROUND.md`](REWARD_EMISSION_E3_GATING_ROUND.md)
§9.3: direction ratified — accumulator, frozen-close-row, under-mint-on-expiry
— **not build-ready** until this spec pins the straddle transition, the
reorg-across-fork KAT, and zero-budget-epoch handling). Awaiting ratification;
C-1's budget commit-block builds against this document, not against §9.3's
recommendation bullet.

**Scope:** the gate-1 budget schedule source that
[`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) (:20–21) scopes out of the
emission-leg spec. This document defines what `budget(E)` **is**, where every
one of its component writes lands, its byte layout at rest, and the armed KATs.
It is the other half of the supply-conservation equation the M-2 arc protected:
`Σwork(E)` bounds the *shares*; `budget(E)` bounds the *coins*. An ambiguity
here is an inflation bug.

**Timeframes (per `05-system-thinking.mdc`):** now — defines the emission
funding path C-1 activates; mining-era end — `staker_emission` decays
(`SHEKYL_STAKER_EMISSION_DECAY`, 0.90/yr) toward zero and `budget(E)` becomes
fee-driven (`staker_pool_amount`), which §5's zero-budget handling covers
structurally; V4 — untouched (the schedule is arithmetic over amounts, no
cryptographic dependence).

---

## 1. The quantity

Every block already computes a **staker inflow** at its connect site
(`blockchain.cpp:5011–5041`):

```text
staker_inflow(h) = em_split.staker_emission + burn.staker_pool_amount
```

- `staker_emission`: the staking share of block emission,
  `compute_emission_split` (`src/shekyl/economics.h:69–91`) — zero when
  `hf_version < HF_VERSION_SHEKYL_NG` or `block_emission == 0`, else the
  decayed share (`shekyl_calc_emission_share`).
- `staker_pool_amount`: the staker share of the fee burn,
  `compute_fee_burn` (`economics.h:55–60`) — **fee-dependent, per-block,
  not recomputable from schedule alone.**

Today the inflow is **destroyed**: added to `burn.actually_destroyed`,
recorded in the per-height burn row, accumulated into `total_burned`
(`:5026–5040`), with the in-code comment naming the C-1 activation as the
redirect that funds `txin_archival_reward_emission` payouts.

**Provenance of the amounts.** The constants (15% emission share, 0.90/yr
decay, 25% fee-pool share — `config/economics_params.json`) are the
Component-4 bootstrap-subsidy economics (`DESIGN_CONCEPTS.md`: the ~50×
fee-yield-gap analysis). [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md)
consumed this purse as a sim-unit abstraction and validated its
**structure** — gate-1 supply safety (`Σreward ≤ budget` under growth),
the `budget → APR → entry → coverage` and `budget → bondA → spread`
transfer curves, and the fee-era thinning behavior (L11/L13) — but did
**not** derive the absolute values; the sim's own residue lines name the
absolute calibrations as post-testnet work. This spec defines how the
purse **accrues and freezes**; the amount inside it is Component-4's.

**Definition.**

```text
budget(E) = Σ  staker_inflow(h)   over h ∈ [E·SEB, (E+1)·SEB) with redirect active at h
```

where `SEB = SETTLEMENT_EPOCH_BLOCKS` (10 000) and epoch membership is
`settlement_epoch_at_height(h) = h / SEB` (`consensus_state.rs:25–27`).
The "redirect active at h" qualifier is the load-bearing clause — §2.

## 2. The transition — redirect the write, don't run a parallel accumulator

### 2.1 The straddle problem this pins

Activation is gated on the block's hard-fork version — a height that is
**not epoch-aligned by construction** (no epoch-boundary constraint exists
on fork heights). The epoch containing the activation height (`E_flip`)
has pre-activation blocks whose inflow was **burned** and post-activation
blocks whose inflow is **emittable**. A naive
"`budget(E) = Σ staker_inflow` over all of E's blocks" includes the burned
portion in `budget(E_flip)`: emitting it mints coins that were already
destroyed — **a straight over-mint, genesis-frozen.**

### 2.2 The pin

There is exactly **one per-height `staker_inflow` write**, and the fork
switches its **target**:

```text
pre-activation block:   staker_inflow(h) → burn record      (destroyed;   landed idiom)
post-activation block:  staker_inflow(h) → budget accrual   (emittable;   this spec)
```

Target selection is by **that block's own height's fork status** —
`m_hardfork->get_version(h)`, not tip state. Three properties follow by
construction:

1. **The straddle is correct.** Each block's inflow lands in exactly one
   of {destroyed, emittable}; `budget(E_flip)` is automatically the
   post-activation-only portion — exactly what may legitimately be
   emitted. No block's inflow goes two places, so no epoch double-counts.
2. **Burn-stop and accrual-start are atomic.** They are the *same write,
   redirected* — not two separately-gated behaviors that could desync
   (a gap between independent "stop burning" and "start accruing" flips
   either destroys inflow twice or emits-and-burns the same inflow).
3. **Reorg symmetry is inherited, not re-proven.** The burn record's
   pop path (`blockchain.cpp:820–827`: read the height row, decrement
   `total_burned`, remove the row) is the landed idiom; the accrual row
   mirrors it (§3.1). A parallel always-running accumulator would need
   its own symmetry proof and would record emittable budget for blocks
   whose inflow was actually burned — the precise ambiguity this section
   forecloses.

**Conservation invariant (armed by KAT B1):** for every connected block,

```text
staker_inflow(h) = burn-side share(h) + accrual-side share(h),  exactly one term nonzero
```

so over any chain prefix, `Σ inflow = total destroyed + total emittable`
holds with no overlap and no gap.

### 2.3 Pre-genesis posture note

The mainnet fork table is single-entry, all-features-from-genesis
(`src/hardforks/hardforks.cpp:35–37`; `HF_VERSION_SHEKYL_NG = 1`). If C-1
ships in the genesis feature set — the expected pre-genesis outcome — the
straddle epoch is **empty by alignment** (activation at height 1, epoch 0).
The per-block pin is kept anyway: correctness must not depend on that
alignment (testnets fork mid-chain; a post-genesis activation would
reintroduce the straddle), and the pin costs nothing when the straddle is
empty. This is the spec decision §2.1 exists to record: the semantics are
per-block, **never** per-epoch.

## 3. Persistence — three writes, each pop-symmetric

### 3.1 Per-height accrual row (the redirected write)

Mirror of the burn record (`add_block_burn` / `get_block_burn` /
`remove_block_burn`, `blockchain_db.h:1928–1930`):

- **Table** `archival_budget_accrual`: key `BE(height)` → value `u64-BE`
  amount.
- **Connect:** written only when `staker_inflow(h) > 0` (absent key reads
  as 0, the burn-row convention). The burn row for the same block carries
  only the genuinely destroyed portion — `staker_inflow` is **not** added
  to `actually_destroyed` post-activation, and `total_burned` no longer
  includes it.
- **Pop:** remove the height row (exact mirror of `remove_block_burn` at
  `blockchain.cpp:827`).

No running total is kept for the accrual side pre-close: the per-height
rows *are* the state, and their pop symmetry is key deletion — nothing to
prove.

### 3.2 Frozen close row (the operand verify reads)

At `process_archival_epoch_close_at_height` (close of `E` runs at height
`(E+1)·SEB`, `db_lmdb.cpp:6486–6533`), after the `Σwork` row is written:

- **Table** `archival_budget`: key `BE(epoch)` → value `u64-BE`, computed
  as the bounded range-sum of `archival_budget_accrual` over
  `[E·SEB, (E+1)·SEB)` (10 000 keys, once per epoch, same write txn as the
  sigma row — the M1 same-snapshot pin).
- **Revert:** `revert_archival_epoch_close_at_height`
  (`db_lmdb.cpp:6535–6561`) deletes the budget row for the epoch alongside
  the `r_market` and `sigma` deletes, keyed off the same close-log row. A
  pop-and-re-close re-sums the (still present) accrual rows and reproduces
  the row byte-identically (KAT B3).
- **Prune:** joins `prune_archival_epochs_before` (`db_lmdb.cpp:5934–5942`)
  with the same retention window as `sigma` / `r_market` (the window
  already covers `MAX_CLAIM_AGE_W`, since verify reads those rows for the
  same claims). Accrual rows prune with it: heights below
  `prune_below_epoch · SEB` — they are only needed for re-close within the
  reorg window, which the retention window dominates.

### 3.3 Verify-side read — no new live operand

`EmissionEpochSource.budget` (`emission_verify.rs:223`) is sourced from the
frozen `archival_budget` row in `gather_archival_emission_epoch_snapshot`
(`db_lmdb.cpp:6434`, beside the persisted-`Σwork` read at `:6451`). Budget
and denominator are frozen in the **same close event**, read from the
**same table family**, as-of-E — the discipline that makes the M-2
conservation conjunction (§5.4 of the round) hold gains no new live
operand. Absent row (epoch never closed / pruned) is a gather failure →
reject, the NOTFOUND-is-not-zero posture of M1.

## 4. Expiry — implicit under-mint (ratified)

Budget unclaimed when the epoch exits the claim window
(`MAX_CLAIM_AGE_W = 26`) is **supply never created**: no roll-forward
state, no expiry sweep, no burn-on-expiry event. This extends the R1.B
floor-remainder posture (under-mint, never over-mint; the remainder simply
never mints) from intra-epoch remainders to whole epochs, and keeps the
purse stateless beyond the per-epoch row.

**Rule-21 reopening:** reopens iff measured genesis-era claim rates show
systematic budget stranding that changes the archival-incentive calculus —
economics evidence, not preference — via a design round on the economics
surface with [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) re-run.

## 5. Zero-budget epochs — structurally non-claimable

`staker_emission` decays and `staker_pool_amount` is fee-dependent, so
`budget(E) = 0` is reachable (and becomes likelier toward mining-era end).
The handling is already structural, inherited from M1:

- **Verifier:** Form-C recompute yields `floor(0 · capped/Σwork) = 0` for
  every `P`; the wire positivity rule
  (`ARCHIVAL_REWARD_GATE_M1.md` §2.3; `emission_wire.rs:222–225`, enforced
  at `:439`) makes a zero-amount row **unencodable** — a claim on a
  zero-budget epoch cannot be expressed, and any positive claimed amount
  fails the zero-tolerance economics compare. No new verifier logic.
- **Builder (forward obligation, extends M1's builder row):** the wallet
  claim-builder derives claimable epochs from the positive-share recompute
  `floor(budget(E)·capped_P(E)/Σwork(E)) > 0` — **one predicate** that
  uniformly omits `budget == 0`, `Σwork == 0` (M1-gated), and
  floored-to-zero epochs. This names explicitly what M1's builder
  obligation implies: the predicate includes the budget factor, so a
  zero-budget epoch is omitted by the *same* path as an M1-gated epoch —
  the builder must not beacon a zero row into the thin timing window the
  M1 arc closed (KAT B4 arms the omission).

## 6. Armed KATs

| # | KAT | Property armed |
|---|-----|----------------|
| **B1** | **Straddle / conservation.** Synthetic activation mid-epoch (unit-level fork-height injection): connect blocks on both sides of the boundary; assert `budget(E_flip)` equals the post-activation-only inflow sum, the pre-activation portion sits in `block_burn`/`total_burned`, and per block exactly one of {burn row, accrual row} carries the inflow. | §2.2's redirect-the-write; the over-mint class |
| **B2** | **Reorg across the fork.** Pop a post-activation block → accrual row removed, `total_burned` untouched; pop through the activation height → earlier blocks' burn rows roll back by the landed idiom; reconnect (same or alt chain) re-applies burn-or-redirect per block height, byte-identical end state. | §2.2 property 3; the one place burn-record × budget-accrual interaction is exercised |
| **B3** | **Close/revert symmetry.** Close `E` → frozen `archival_budget` row written in the same txn as sigma; pop the close block → row deleted by the close revert; re-close → byte-identical row re-created from the retained accrual rows. | §3.2; the frozen-operand discipline |
| **B4** | **Zero-budget epoch.** `budget(E) = 0` (no accrual rows in E): builder predicate omits E; a hand-built vin claiming E rejects at wire positivity (zero row unencodable) and a positive-amount forgery rejects at the economics compare. | §5; the M1 §2.3 timing-window closure extended to the budget factor |

B1/B2/B3 are C++ substrate KATs (`archival_substrate_lmdb.cpp` family);
B4 spans the Rust wire/verify KATs (landed classes) plus the builder-side
omission test when the claim-builder lands.

## 7. Rule-21 reopenings

- **Roll-forward on expiry** — §4's clause (economics evidence).
- **Budget source composition** — reopens iff a second inflow stream is
  routed to the archival purse (e.g. a terminal-subsidy allocation at
  mining-era end): the new stream must land as a second addend **inside**
  `staker_inflow(h)` at the same single write site, preserving §2.2's
  one-write-one-target invariant; re-evaluation is a design round on this
  document with B1 re-run.
- **Adaptive budget servo (the sim's L13 disposition).** Genesis ships
  the **passive** schedule (Component-4 constants: emission share 15%
  decaying 0.90/yr + 25% of the burned fee pool —
  `config/economics_params.json`; the sim consumed this purse as an
  abstraction and validated its transfer curves, it did **not** derive
  the constants). [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) L13
  names the fee-era durability requirement as an **adaptive
  reward-share servo + backstop** (`budget_eff = base·(1 +
  gain·shortfall)`), with hard conditionals the sim measured: the servo
  must key off a *sticky/smoothed* trust signal (a raw-shortfall servo
  oscillates and underperforms a constant purse) and needs an adequate
  fee-market ceiling (below it, saturation → graceful loud failure) —
  and the fiat-cost leg (L17 P2) is only partially dampable by any
  token-denominated servo. Reopens when the fee-era servo lands (its
  own design round on this document, `75-system-autonomy` jurisdiction —
  the servo's gain/signal/ceiling are the sim's named post-testnet
  empirics): the servo modifies the **amount** computed at the same
  single write site (`staker_inflow(h)` → `budget_eff(h)`), never adds
  a second write; §2.2's invariant and B1 re-run are the re-evaluation
  gate.
- **Per-height row retention** — reopens iff the finality boundary lands
  (the round's §6.5/§8.2 trigger): prune-against-finalized may shorten
  accrual-row retention to the finality depth; same round that retires the
  claimed-set journal.

## 8. Relation to C-1

This spec is **commit-block 1 of the C-1 PR** once ratified (the accrual
and frozen rows are consensus-inert until the whitelist flip — nothing
reads `archival_budget` until dispatch lands — so the atomic-flip shape of
the round's §9.6 rule-07 check is unchanged). The rest of the §9.5 build
list consumes `budget(E)` **as defined here**: "emittable inflow for E,"
never "all inflow for E."
