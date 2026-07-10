# Archival budget schedule (gate 1) — `budget(E)` production

**Status:** RATIFIED 2026-07-08 — spec-first round opened same day per the
F-C1a ratification ([`REWARD_EMISSION_E3_GATING_ROUND.md`](REWARD_EMISSION_E3_GATING_ROUND.md)
§9.3: direction ratified — accumulator, frozen-close-row, under-mint-on-expiry),
refined through review (provenance/source-chain verification, §6
integer-determinism pins, §2.2 coinbase-foreclosure pin + KAT B5, servo-scale
note), and ratified with the C-1 build opening (PR #273 merged; the C-1
budget commit-block builds against this document, not against §9.3's
recommendation bullet).

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

Every non-genesis block computes a **staker inflow** at its connect site —
since the F-B1a/F-B1b remediation, in `handle_block_to_main_chain`'s
pre-`add_block` accrual block, so the version operand is the connecting
block's own validated version and the amount can ride into `add_block`
ahead of the epoch-close hook:

```text
staker_inflow(h) = em_split.staker_emission + burn.staker_pool_amount
```

- `staker_emission`: the staking share of block emission,
  `compute_emission_split` (`src/shekyl/economics.h:69–91`) — zero when
  `hf_version < HF_VERSION_SHEKYL_NG` or `block_emission == 0`, else the
  decayed share (`shekyl_calc_emission_share`). The split operand is
  verify's **modulated** `base_reward` (6-arg `get_block_reward`:
  weight-penalized, release-scaled — the F-B1c-c2 disposition-(a)
  remediation, gating round §9.9), the same quantity the coinbase is
  bound against and `already_generated_coins` advances by. Conservation
  is by construction: `base_reward = miner_emission (coinbase) +
  staker leg (accrued)`, so `budget(E)` is exactly "ledger
  minus coinbase" and claiming cannot inflate. Consequence: `budget(E)`
  floats with the release multiplier and weight penalty — the §9.9
  (b)-reopen sim question, **resolved 2026-07-09: the swing is
  tolerable and (a) stands permanently** (the float is clamped to
  `[release_min, release_max]` = a 0.8× floor on the emission leg only,
  and the deep-throttle regime and the coverage-knee regime are
  disjoint under the 0.90/yr share decay — gating round §9.9
  reopen-resolution addendum; evidence:
  `shekyl-economics-sim --fb1c-c2`,
  `shekyl-staking-sim --budget-throttle`). Genesis (h = 0) computes no
  inflow: its emission is the hardcoded `GENESIS_TX` amount, paid whole
  by the genesis coinbase.
- `staker_pool_amount`: the staker share of the fee burn,
  `compute_fee_burn` (`economics.h:55–60`) — **fee-dependent, per-block,
  not recomputable from schedule alone.**

The inflow is **accrued unconditionally**: passed into
`BlockchainDB::add_block` as the `archival_budget_accrual` operand and
written to the per-height accrual row before the connect hooks fire
(§3.1), funding `txin_archival_reward_emission` payouts. The block's
burn row carries only the fee-burn's `actually_destroyed` share. The
original C-1 shape gated this write on `HF_VERSION_ARCHIVAL_EMISSION`
with a pre-activation leg that destroyed the inflow instead (the
claim-era posture, inherited from the scrapped direct-distribution
model's no-staker burn); with the constant fixed at 1 and the block
version floor at 1, that leg was unreachable-by-construction through
the real connect path and was **deleted 2026-07-09** along with the
constant (rule 60; §2 records the retired transition machinery). The
pre-F-B1c-c2 shape also burned an unmodulated, over-sized leg — benignly
deflationary as a burn, an inflation surface as a budget; the modulated
operand fix predates and survives the leg's deletion.

**Provenance of the amounts.** The constants (15% emission share, 0.90/yr
decay, 25% fee-pool share) are the Component-4 bootstrap-subsidy economics
(`DESIGN_CONCEPTS.md`: the ~50× fee-yield-gap analysis).
[`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) consumed this purse as
a sim-unit abstraction and validated its **structure** — gate-1 supply
safety (`Σreward ≤ budget` under growth), the
`budget → APR → entry → coverage` and `budget → bondA → spread` transfer
curves, and the fee-era thinning behavior (L11/L13) — but did **not**
derive the absolute values; the sim's own residue lines name the absolute
calibrations as post-testnet work. This spec defines how the purse
**accrues and freezes**; the amount inside it is Component-4's.

**Source chain (verified at source, 2026-07-08).** The single source of
truth is `config/economics_params.json`
(`shekyl_staker_emission_share: 150000`, `shekyl_staker_emission_decay:
900000`, `shekyl_staker_pool_share: 250000`). The values are **scaled
fixed-point integers**, `SCALE = 1 000 000` (`SHEKYL_FIXED_POINT_SCALE`;
`shekyl-economics/src/params.rs` `SCALE`) — `150000` ≡ 15 %, `900000` ≡
0.90, `250000` ≡ 25 %. This is the same `SCALE` the write site's
`mul_scale` divides by (`params.rs:110–113`), so a grep for the decimal
forms will not find them; grep the fixed-point integers. Two build-time
generators consume the JSON — no hand-written copy exists on either side
of the FFI:

- **C++ consensus path:** `cmake/generate_economics_params.py`
  (wired at `CMakeLists.txt:776–778`) emits
  `economics_params_generated.h`, included by `cryptonote_config.h:37`;
  the write site passes the macros to the FFI **as arguments**
  (`compute_emission_split`, `economics.h:79–85` →
  `shekyl_calc_emission_share(…, initial_share, annual_decay,
  blocks_per_year)`, `shekyl-ffi/src/lib.rs:727–733`; same shape for
  `SHEKYL_STAKER_POOL_SHARE` at `economics.h:57`). The Rust FFI computes
  from what it is handed — it holds no second copy of the values on the
  consensus path.
- **Rust-side consumers (sim / local economics):**
  `shekyl-economics/build.rs` reads the **same JSON** at build time and
  writes `GENERATED_STAKER_EMISSION_{SHARE,DECAY}` into
  `OUT_DIR/params_generated.rs`; `params.rs:21–26` merely **aliases**
  those generated consts. The in-file comment cites the 2026-05 FFI
  constant-drift audit as the reason it reads the JSON rather than
  literal-coding.

**To change the amounts, edit the JSON — never the consts.** The
`GENERATED_*` values are build artifacts regenerated on every build
(`cargo:rerun-if-changed` on the JSON); a maintainer who traces
`STAKER_EMISSION_SHARE` to `params.rs`, sees `= GENERATED_…`, and edits
there has found an alias of the artifact, not the source.

**Drift binding (why the source-of-truth claim is durable, not just true
today).** `shekyl-economics/src/digest.rs` hashes the **resolved**
`EconomicParams` values — canonical fixed-width LE preimage, Blake2b-256,
format-version tag; it deliberately does **not** hash the raw JSON bytes
(whitespace/key-order drift would false-positive, per the module's
rejected-alternatives note). `params_digest` covers `staker_pool_share`
directly; the emission share/decay ride the **composed**
`snapshot_calibration_digest` (`shekyl-engine-core`), which layers the
staker-emission constants and tier table on top. Today this binding is a
**calibration-drift detector and C4 fixture-lineage guard**
(`CalibrationStamp.params_digest`), not a consensus check — so it catches
a JSON⁄build divergence at fixture/test time, not at block validation.
When the servo lands (§8) its gain/signal parameters become a **new
generated field family** and must join this digest surface (a breaking
layout change per `digest.rs`'s format-version rule); whether the digest
should also be consensus-checked is a question for that round.

**Definition.**

```text
budget(E) = Σ  staker_inflow(h)   over h ∈ [E·SEB, (E+1)·SEB)
```

where `SEB = SETTLEMENT_EPOCH_BLOCKS` (10 000) and epoch membership is
`settlement_epoch_at_height(h) = h / SEB` (`consensus_state.rs:25–27`).

## 2. The write discipline — one write site, one target

### 2.1 The retired transition machinery (historical record)

The C-1 shape of this section pinned a **redirect**: one per-height
`staker_inflow` write whose *target* the fork switched — pre-activation
blocks destroyed the inflow (burn record), post-activation blocks
accrued it (this spec). The pin existed to make the activation-straddle
epoch correct (no burned inflow leaking into `budget(E_flip)` — the
over-mint class) and to make burn-stop/accrual-start atomic.

Archival emission is a **genesis fact**: `HF_VERSION_ARCHIVAL_EMISSION`
was fixed at 1, the block version floor is 1, and versions never
decrease — so no pre-activation block was constructible through the
real connect path, the burn leg was unreachable-by-construction, and
both the leg and the constant were **deleted 2026-07-09** (rule 60; the
leg's origin was the scrapped direct-distribution model's conditional
no-staker burn, carried forward as a placeholder). Git history and the
gating round §9.9 hold the full shape. A future *post-genesis*
activation-gated inflow change (e.g. the §8 servo) re-derives the
redirect discipline from this record rather than resurrecting the code.

### 2.2 The pin (current form)

There is exactly **one per-height `staker_inflow` write**, unconditional
for every non-genesis block, and its target is the **budget accrual
row**:

```text
every non-genesis block:  staker_inflow(h) → budget accrual   (emittable; this spec)
```

The block's burn row carries only the fee-burn's `actually_destroyed`
share — the two tables are independent, and a fee-bearing block writes
both.

Implementation note (F-B1b, hardened during the c2 review and still
load-bearing): the connect site's version operand is
**`bl.major_version`** — the block's own declared version,
consensus-bound by `m_hardfork->check(bl)` (`do_check`:
`bl.major_version ==` the voted current version) before the accrual
block is reachable. It feeds `compute_emission_split` /
`compute_fee_burn`, so per-block anchoring still matters even with the
target selection gone. The rejected alternatives:
`get_current_version()` read pre-`add_block` *happens* to equal
`bl.major_version` (the previous block's `HardFork::add` advanced
`current_fork_index` via `get_voted_fork_index(height + 1)`, the
connecting block's own voted version) — correct-but-fragile, resting on
the height+1 advance convention this pin was written to stop depending
on, and outright wrong if read post-add (the original F-B1b bug: the
*next* block's version). `get_ideal_version(h)` is the static-table
lookup and ignores the vote threshold, so it can disagree with the
version the block was validated as. A CI tripwire
(`scripts/ci/check_archival_reward_gates.sh`) fails the gate on any
`get_current_version` / `get_ideal_version` / `get_block_reward`
reintroduction inside the accrual block.

Two properties hold by construction:

1. **No parallel accumulator.** The per-height rows *are* the state; a
   second always-running accumulator would need its own symmetry proof.
2. **Reorg symmetry is inherited, not re-proven.** The burn record's
   pop path (`blockchain.cpp`: read the height row, decrement
   `total_burned`, remove the row) is the landed idiom; the accrual row
   mirrors it at the DB layer (§3.1: connect write in
   `BlockchainDB::add_block`, pop removal in `BlockchainDB::pop_block`,
   both inside the block's wtxn).

**Conservation invariant (armed by KAT B1 and the conservation core
test):** for every connected block, new coins and pre-existing fee
coins conserve on separate axes, and the destination map ties them
together:

```text
new coins:     base_reward(h) = miner_emission(h) + staker_emission(h)   (= ledger advance)
fees (pre-existing): total_fees(h) = miner_fee_income(h) + staker_pool(h) + destroyed(h)

destinations:  coinbase(h)    = miner_emission(h)  + miner_fee_income(h)
               accrual row(h) = staker_emission(h) + staker_pool(h)      (staker_inflow, whole, once)
               burn row(h)    = destroyed(h)

combined:      coinbase(h) + accrual row(h) + burn row(h)
                 = ledger advance(h) + total_fees(h)
```

no overlap and no gap. Fees do **not** advance
`already_generated_coins` (they are coins re-entering circulation, not
new emission), which is why the combined form carries `total_fees` on
the ledger side; for a fee-free block it reduces to
`ledger advance = coinbase + accrual row` — the form the (fee-free)
conservation core test asserts directly.

**Coinbase-foreclosure pin (cross-function dependency — the invariant's
silent-break point).** The accrual is supply-safe only because the
staker portion **never enters the coinbase**: `validate_miner_transaction`
(`blockchain.cpp:1595–1613`) rejects any coinbase that is not *exactly*
`em_split.miner_emission + burn.miner_fee_income` — both staker halves
are structurally excluded from what the miner may claim. This pin lives
in the coinbase validation, **not** in the budget code; nothing in the
accrual path references it, so a C-1-era edit to the emission split or
coinbase validation is where it breaks without any budget test noticing.
Standing assertions that hold it today:
`tests/unit_tests/economics_c2a_prime.cpp`
(`Layer1PerQuantityLegAComposesSplitAndCoinbase`: split conservation
`Q_miner_base + Q_staker_emission = Q_full` with the fee legs
independently pinned to zero) and `tests/core_tests/economics_c2a_prime.cpp`
(connect-path `already_generated` delta equals the *full* subsidy, with
the defense-in-depth `Q_full > miner_coinbase` proving the carve-out is
real through the production path). **Coverage gap → C-1 build KAT:**
both run fee-free blocks, so the fee-side half (`staker_pool_amount`
excluded from a *fee-bearing* block's coinbase through
`validate_miner_transaction`) is pinned only at the helper level. The
C-1 build arms a fee-bearing-block KAT: coinbase paying exactly
`miner_emission + miner_fee_income` accepts; a coinbase additionally
claiming `staker_pool_amount` (or `staker_emission`) rejects at `:1609`.
KAT B1's per-block conservation check then closes the loop on the
accrual side.

### 2.3 Pre-genesis posture note

The mainnet fork table is single-entry, all-features-from-genesis
(`src/hardforks/hardforks.cpp:35–37`; `HF_VERSION_SHEKYL_NG = 1`), and
C-1 shipped in the genesis feature set — which is what made §2.1's
transition machinery dead-on-arrival and drove its deletion. The
semantics remain per-block, **never** per-epoch: the accrual write and
its pop are keyed at the block's own height, so nothing depends on
epoch alignment.

## 3. Persistence — three writes, each pop-symmetric

### 3.1 Per-height accrual row (the staker-inflow write)

Mirror of the burn record (`add_block_burn` / `get_block_burn` /
`remove_block_burn`, `blockchain_db.h:1928–1930`):

- **Table** `archival_budget_accrual`: key `BE(height)` → value `u64-BE`
  amount.
- **Connect:** the amount rides into `BlockchainDB::add_block` as the
  `archival_budget_accrual` parameter and is written **before the
  slash/close hooks fire**, in the same wtxn — so the close of epoch E
  (fired while connecting E's final block) sees that block's row in its
  range-sum (F-B1a: writing after `add_block` returned dropped the final
  block of every epoch from its own `budget(E)`). Written only when
  `staker_inflow(h) > 0` (absent key reads as 0, the burn-row
  convention). The burn row for the same block carries only the
  genuinely destroyed fee-burn portion — `staker_inflow` never enters
  `actually_destroyed` or `total_burned`.
- **Pop:** remove the height row in `BlockchainDB::pop_block` (keyed at
  the block's index, the claim-journal convention), mirroring the
  connect-side write in the same layer and wtxn.

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

## 6. Integer determinism — three pins

All budget arithmetic is integer fixed-point, and that is load-bearing,
not hygiene: the conservation argument (§2.2, and Form-C's
`reward_P = floor(budget · capped_P / Σwork)`) is a theorem about integer
arithmetic with a fixed rounding direction. Two nodes must compute the
**bit-identical** mint or the zero-tolerance recompute rejects honest
claims (or admits divergent ones) — floats do not reproduce across
compilers/architectures/optimization levels, and a last-ULP divergence is
a fork. Being integer is necessary but not sufficient; three seams can
lose determinism with every value still nominally an integer:

1. **Rounding direction is pinned per operation, not per policy.**
   `reward_share_floor` floors and the dust never mints
   (`reward_arithmetic.rs:128–134`); `mul_scale` floors by `/SCALE`
   (`params.rs:110–113`). Every future consensus-visible fixed-point
   operation — the servo's mul and division first among them — pins its
   direction the same way at spec time. "It's integer division" is not a
   pin; *which way, at which step* is.
2. **Evaluation order is part of the consensus rule.** `a·b/d` and
   `(a/d)·b` produce different integers under floor, so the operand
   order of every composed fixed-point expression is **frozen — do not
   reassociate**. A "simplify this expression" refactor that
   reassociates changes the rounding without changing any type; treat it
   as a consensus change (the integer analogue of the transcript-ordering
   discipline). The landed shapes are the templates: `mul_div_floor(a,
   b, d)` = multiply-then-divide, one divide, last
   (`reward_arithmetic.rs:119–125`); `burn.rs:73–76` chains `mul_scale`
   in documented order.
3. **One evaluator across the FFI; intermediates at pinned width.** Both
   helpers promote to **u128 before the divide** (verified:
   `mul_div_floor` `u128::from(a).saturating_mul(…) / u128::from(d)`;
   `mul_scale` likewise), so the multiply cannot wrap at u64 on any
   platform. The C++/Rust seam is foreclosed **structurally**: the
   consensus arithmetic has exactly one implementation (Rust); C++
   passes operands as FFI arguments and consumes results
   (`compute_emission_split` → `shekyl_calc_emission_share`), it never
   re-evaluates the formula. **Pin:** if any future work gives C++ a
   parallel evaluation of any budget/emission expression, it requires a
   cross-language KAT running identical inputs through both paths and
   asserting bit-equality — but the preferred disposition is to never
   create the second evaluator.

The servo (§8's reopening) is the next place all three pins apply at
once: a new composed fixed-point expression, consensus-visible, crossing
the FFI.

## 7. Armed KATs

| # | KAT | Property armed |
|---|-----|----------------|
| **B1** | **Burn/accrual partition and conservation.** Heights carrying fee-burn rows, accrual rows, or both at the same height (the production shape for a fee-bearing block): assert `budget(E)` sums only the accrual side, the destroyed portion sits in `block_burn`/`total_burned`, and each table reads back its own rows independently. Reframed 2026-07-09 from the activation-straddle form (`budget_straddle_partition_and_conservation`) when the burn leg was deleted. | §2.2's table independence; the over-mint class |
| **B2** | **Reorg pop symmetry.** Pop an accrual-carrying block → accrual row removed, `total_burned` untouched; pop a fee-burn-carrying block → burn row rolls back by the landed idiom; reconnect re-applies each height's writes, byte-identical end state; the side a block didn't write is a tolerated missing key. Reframed 2026-07-09 from the across-the-fork form (`budget_reorg_across_fork_pop_symmetry`). | §2.2 property 2; the one place burn-record × budget-accrual interaction is exercised |
| **B3** | **Close/revert symmetry.** Close `E` → frozen `archival_budget` row written in the same txn as sigma; pop the close block → row deleted by the close revert; re-close → byte-identical row re-created from the retained accrual rows. | §3.2; the frozen-operand discipline |
| **B4** | **Zero-budget epoch.** `budget(E) = 0` (no accrual rows in E): builder predicate omits E; a hand-built vin claiming E rejects at wire positivity (zero row unencodable) and a positive-amount forgery rejects at the economics compare. | §5; the M1 §2.3 timing-window closure extended to the budget factor |
| **B5** | **Fee-bearing coinbase foreclosure.** A fee-bearing block whose coinbase pays exactly `miner_emission + miner_fee_income` accepts; a coinbase additionally claiming `staker_pool_amount` (or `staker_emission`) rejects at `validate_miner_transaction`'s exact-equality check. Closes the fee-side gap the standing `economics_c2a_prime` tests leave (they run fee-free blocks; §2.2's pin). | §2.2's coinbase-foreclosure pin; the cross-function dependency nothing in the budget code references |

B1/B2/B3 are C++ substrate KATs (`archival_substrate_lmdb.cpp` family)
that drive the accrual/close/revert DB API directly — which is why none
of them could see the F-B1a connect-*ordering* bug. The production-path
complement
(`budget_epoch_boundary_includes_final_block_through_real_block_path`,
same file) drives accrual amounts through the real
`add_block`/`pop_block` and asserts the close of epoch E includes E's
final block's row, plus pop/re-connect byte-identity of the frozen row.

B1's **full-connect-path counterpart** landed 2026-07-09:
`archival_budget_conservation_boundary`
(`tests/core_tests/archival_budget_conservation.{h,cpp}`, chaingen
harness; CI: the `conservation` subcommand of
`run_economics_c2a_prime.sh`). It drives `handle_block_to_main_chain`
across a v1→v2 fork table (fork height 8, epoch-unaligned) and asserts
the §2.2 identity per block in **labeled-row** form — each of
{accrual row, burn row} checked against its own expected value, not
just their sum — plus the genesis exclusion, coinbase =
`miner_emission`, ledger advance = independently-recomputed modulated
subsidy, and pop/reconnect row restoration across the boundary. With
the burn leg deleted the expectations are unconditional (whole inflow
in the accrual row, zero in the burn row for the fee-free fixture);
the labeled form remains the guard against the destination-error class
(F-B1b: inflow routed into the burn row keeps the sum identity green).
The fork table still crosses v1→v2 because `major_version` is a live
operand of the split/fee-burn and the pop/reconnect leg replays the
boundary through the rewound fork machinery. Fee-leg gap (disclosed):
the fixture is fee-free, so the KAT exercises only the emission half
of `staker_inflow` (`staker_emission + staker_pool_amount`)
end-to-end — the same chaingen FCMP++ fee-transaction gap that defers
B5's connect-path block form (below) defers the fee-pool half here; it
rides the E4/E5 regtest-e2e residue, with the unit-level B5 KATs and
the F-B1c-c1 operand pin as the interim guards.
B4 spans the Rust wire/verify KATs (landed classes) plus the builder-side
omission test when the claim-builder lands. B5 landed as unit-level KATs
(`economics_b5_fee_coinbase.cpp`) driving `validate_miner_transaction`
directly; the connect-path block form defers with the chaingen FCMP++
fee-transaction gap (see the commit-block 6 landed status in §2.2's
follow-on notes below).

## 8. Rule-21 reopenings

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
  gate. **Topup-source pin (same-site is necessary, not sufficient):**
  the servo raises `budget_eff` above `base`, and the topup is not
  created from nothing — per L13/L17 it is a **larger draw on available
  fees**, bounded by the fee-market ceiling (below it the servo
  saturates; the sim's graceful loud failure). The marginal draw must
  ride the **same removed-from-circulation-once discipline as the base
  accrual**: every fee unit the servo pulls into the purse is a fee
  unit *not* paid to the miner and *not* burned — the §2.2 conservation
  invariant extends to
  `budget_eff(h) ≤ accrued staker_inflow(h) + marginal fee draw(h)`,
  with each addend landing in exactly one of {miner income, destroyed,
  emittable}. A servo implementation that writes at the single site but
  draws its topup from fees that the coinbase also pays to the miner
  double-counts the fee — one write site while re-minting the same
  unit. This is the coinbase-forecloses-staker-payout pin applied one
  level up, to the servo's marginal draw; the servo's design round must
  arm a B1-shaped conservation KAT over the widened three-way split.
  **Arithmetic pin:** `budget_eff` is the numerator cap, so a one-unit
  divergence between nodes computing it independently is a consensus
  split — the servo's new mul and division carry §6's three pins in
  full: rounding direction pinned per operation (the
  `reward_share_floor` discipline — u128 intermediate, floor, dust
  never mints), evaluation order frozen at spec time, and a single Rust
  evaluator behind the FFI. "Same write site" without "same pinned
  rounding" is half the invariant. The servo's parameters also join the
  §1 digest surface (format-version bump per `digest.rs`).
  **Scale note: the servo is a design round, not a commit.** Count what
  this clause already obligates: it reopens the §2.2 conservation
  invariant (fee-draw source, three-way split), the one-write-one-target
  invariant, the §6 integer-determinism pins (a new composed
  fixed-point expression crossing into consensus), and the §1 digest
  surface (a fourth generated field family with a format-version bump)
  — four load-bearing surfaces at once, the same shape at which the
  budget schedule itself turned from "a finding disposition" into this
  document. Whoever picks it up budgets for a spec-first round with its
  own review cycle, not a PR.
- **Per-height row retention** — reopens iff the finality boundary lands
  (the round's §6.5/§8.2 trigger): prune-against-finalized may shorten
  accrual-row retention to the finality depth; same round that retires the
  claimed-set journal.

## 9. Relation to C-1

This spec is **commit-block 1 of the C-1 PR** once ratified (the accrual
and frozen rows are consensus-inert until the whitelist flip — nothing
reads `archival_budget` until dispatch lands — so the atomic-flip shape of
the round's §9.6 rule-07 check is unchanged). The rest of the §9.5 build
list consumes `budget(E)` **as defined here**: "emittable inflow for E,"
never "all inflow for E."

**Landed status (C-1 commit-block 1, 2026-07-08):** §3.1 accrual row
(`add/get/remove_archival_budget_accrual`, burn-record idiom, pop wired
beside `remove_block_burn`), §2.2 redirect-the-write at the connect site
(gated on `HF_VERSION_ARCHIVAL_EMISSION`, the connecting block's own fork
version), §3.2 frozen close row (bounded range-sum in the sigma txn;
revert deletes with the close family; prune joins the epoch family), §3.3
snapshot gather (`has_budget_row` stored-shape probe + `budget_atomic`),
and KATs **B1/B2/B3** (`archival_substrate_lmdb.cpp` budget family). B4's
builder half arms with the claim-builder.

**Landed status (burn-leg deletion, 2026-07-09):** §2.1's transition
machinery retired: the pre-activation burn leg and
`HF_VERSION_ARCHIVAL_EMISSION` deleted (rule 60 — unreachable-by-
construction with emission a genesis fact; the leg's origin was the
scrapped direct-distribution model's conditional no-staker burn). The
accrual write is now unconditional per non-genesis block; the raw-import
guard in `blockchain_import.cpp` refuses all non-genesis blocks without
the constant; the CI tripwire re-anchored to the accrual block (same
banned symbols — the version operand still feeds the split); KATs B1/B2
reframed to the burn-leg-free shape and the conservation core test's
expectations made unconditional (its fork table retained for the
version-operand and fork-machinery coverage).

**Landed status (C-1 commit-block 6, 2026-07-09):** KAT **B5** landed as
unit-level KATs (`economics_b5_fee_coinbase.cpp`) driving the production
decision site `validate_miner_transaction` directly (via the standing
`IN_UNIT_TESTS` seam) with fee-bearing operands recomposed through the
same single-evaluator helpers the check calls
(`compute_emission_split`/`compute_fee_burn`): exact
`miner_emission + miner_fee_income` accepts (with the fix-α full-subsidy
out-param pinned), coinbase additionally claiming `staker_pool_amount`
or `staker_emission` rejects, and an underclaim rejects — §2.2's
"exactly" is two-sided. The connect-path *block* vehicle
(`economics_c2a_prime.cpp` family) defers with the chaingen FCMP++
fee-transaction gap: the harness cannot build fee-paying FCMP++
transactions, so a fee-bearing block cannot be assembled there; the
*decision* B5 arms is the same `:1611`/`:1616` exact-equality check the
connect path calls with the block's fee summary.
