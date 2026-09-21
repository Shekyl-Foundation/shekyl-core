# `shekyl-chain-rules` slice 4 — census 4.F, the miner transaction (DRS-E6 increment 5)

**Status:** OPEN — Round 0 pre-flight, written 2026-09-21 against `dev` @
`ea140396b` (post-#814). Nothing implemented; §8 is the question set.
Template: [`CHAIN_RULES_CRATE.md`](CHAIN_RULES_CRATE.md) §7.5.1; predecessors
[`CHAIN_RULES_SLICE_1.md`](../completed/CHAIN_RULES_SLICE_1.md),
[`CHAIN_RULES_SLICE_2.md`](../completed/CHAIN_RULES_SLICE_2.md),
[`CHAIN_RULES_SLICE_3.md`](CHAIN_RULES_SLICE_3.md). Parent plan:
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §7.5 table 3 (*"slice 4 —
emission / burn arithmetic in `shekyl-economics` (adopt); needs header +
weights"*). Cites `26-sub-pr-design-discipline.mdc`. The living contract is
[`CHAIN_RULES_CRATE.md`](CHAIN_RULES_CRATE.md); do not implement from this
file. Owner: the DRS-E6 lane.

**Scope (table 3).** The twenty-two surface-free rows of 4.F — CEN-F1 … F21
with F14b — all `pending` at `rust/shekyl-chain-rules/src/census.rs:340`–`:361`
(13 bucket 1, 4 bucket 2, 5 bucket 4). Plus the store-side consequence
S-CHAIN-W already names: `ConnectFacts.coins_generated` is *deleted by*
`CEN-F13`/`F14`/`F14b` and `ConnectFacts.burned` by `CEN-F17`/`G11`
(`connect.rs:196`–`:240`, `DELETED_BY`) — two of the six passed-through
facts become derivations when their rows land.

**What this pre-flight found, in one paragraph.** The bodies are Rust and
already the daemon's one implementation — `shekyl-economics`
(`paid_block_reward`, `calc_release_multiplier`, `TxVolume`,
`emission_share::{calc_effective_emission_share, split_block_emission}`,
`burn::{calc_burn_pct, compute_burn_split_at}`) and `shekyl-ct-balance`
(`check_output_keys`, `check_commitment_masks`) — reached from C++ through
`legacy_core.rs` / `ct_balance_ffi.rs` shims, so this slice **adopts**, as
slice 2 did. What it cannot do is evaluate the whole family: the coinbase's
*exact-pay* verdict (F18) is a function of four operands, and **two have no
source in the Rust pipeline yet** — the effective weight median in force for
the candidate (F14/F14b) is CEN-G6's derivation over the long-term window
(slice 7; the store records only the median *for* each connected block, not
the one for the next), and the fee-burn's `frozen_segment_count` (F17) is a
function of the curve-tree leaf count, whose daemon-side tables are
unshaped in the redb store (S-CURVE, `PDM-Q12`). So 4.F splits along its
operands: **eighteen rows** are landable now — the coinbase's structure
(F1–F10), the genesis arm (F11), the base subsidy and its operand (F13), the
volume window (F15, F20), the split (F16), the epoch constant (F21), the
read-point discipline that Rust makes structural (F19), and the dead
denomination gate (F12, as a disposition) — and **four** (F14, F14b, F17,
F18) wait on G6 and on the curve-tree read, *unless* this slice pulls the
median machinery forward (§8 Q1). Three design findings shape the eighteen:
the C++ `economics.h` shims carry **rule content** (the `== 0`
short-circuits, F16/F17's constant marshaling) that must move into
`shekyl-economics` with fixtures, not be re-marshaled (F5); the genesis
block's identity per network is data of exactly `ReleaseAnchors`' kind, and
F11 asks whether genesis *is* the height-0 anchor (F6, §8 Q3); and F19's
"read at parent state or halt" is what the branded view **is** — a row true
by construction needs a registry status that says so (§8 Q4).

---

## 1. Parents — landed? (§7.5.1 (a))

| Parent | Needed for | State at `ea140396b` |
| --- | --- | --- |
| Slices 1–3 (`BlockRule`/`FormRule`, `BlockContext`, `Trust`, B6 on the token, `RowStatus::EnforcedAt`) | every row here; F19's status vocabulary | **Landed** (#768, #777, #814). |
| `shekyl-economics` (`emission.rs`, `release.rs`, `volume.rs`, `burn.rs`, `emission_share.rs`, `escalation.rs`, `params.rs` — `EconomicParams::default()` generated from `config/economics_params.json` by `build.rs`) | the 4.F arithmetic | **Landed**; no `redb`, no store; `Cargo.toml` deps to verify for the G1 closure (§3 F2). |
| `shekyl-ct-balance` (`check_output_keys :250`, `check_commitment_masks :284`, `amount_commitment :129`) | F9, F10 | **Landed**; the C++ reaches it through `ct_balance_ffi.rs:178`/`:215`. Dependency closure: `curve25519-dalek` — heavier than `shekyl-difficulty`; the rules crate already reaches it through `shekyl-wire` (§3 F2 verifies). |
| `shekyl-wire` `Transaction`: `Input::Gen(u64)`, `Ct::Null(CtBase)` / `Ct::Fcmp { fee, .. }`, `Transaction::weight()` (size + Bp+ clawback, `:1471`), `TxPrefix { version, unlock_time, .. }` | F1–F8 read the coinbase's shape; F17 sums `fee`; F14 sums `weight()` | **Landed**. |
| S-CHAIN-R (#772): `BlockInfo { coins_generated, weight, long_term_weight, long_term_effective_median, cumulative_tx_count, .. }` (`codec/chain.rs:76`–`:101`) | F13 (parent's `coins_generated`), F15/F20 (`cumulative_tx_count` differences), F14 (weights — *recorded*, but see G6) | **Landed** as recorded facts; `RecordedBlock` (`view.rs:132`) projects `hash`, `header`, `cumulative_difficulty` only — **grows** by `coins_generated` and `cumulative_tx_count` here ("fields grow with rows"). |
| **CEN-G6 / G6b** — the effective median in force for the *next* block (long-term window 100 000, short-term 100, `S = 4` ratified vs the shipped ×50 divergence, floor at the 300 000-byte zone) | F14, F14b, and therefore F18 | **Not landed** (slice 7). The store records `long_term_effective_median` *for* block `h` (SCR-19: the value `h` was judged against, never the recompute after `h` enters the window); the candidate at `h + 1` needs that recompute. `shekyl-economics::block_weight::{effective_median, long_term_weight}` are the clamps; the two rolling medians over recorded `weight` / `long_term_weight` are what no Rust path builds. |
| **S-CURVE** — the daemon-side curve tree in the redb store (`CURVE_TREE_{LEAVES,LAYERS,META}`, `schema.rs:463`–`:471`, **Unshaped**); `PDM-Q12` re-unitised the tree (`CURVE_TREE_STORE_SHAPES.md` CLOSED → `WALLET_SIDE_STORE.md`) | F17's `frozen_segment_count = shekyl_archival_frozen_segment_count(leaf_count at parent state)` (`blockchain.cpp:1492`–`:1503`) | **Not landed** as a view read. `ChainView::root_at` exists; no leaf count. |
| 4.H (fee semantics: CEN-H* CT balance `sum(pseudoOuts) = sum(masks) + fee·H`) | F17's `fee` sum is *the candidate's* `Ct::Fcmp.fee` values — readable today; whether a fee is *valid* is 4.H's (slice 5) | Summing is landable; the sum's trustworthiness is slice 5's. Recorded as a dependency of the **verdict**, not of the read. |

Two parents block four rows; none blocks the other eighteen.

---

## 2. Row-body audit (§7.5.1 (b)) — 22 rows at `ea140396b`

The census pins its C++ lines at `02c086f4b`; every 4.F pin has drifted
(`prevalidate_miner_transaction` is at `blockchain.cpp:1391`,
`validate_miner_transaction` at `:1506`, `parent_frozen_segment_count` at
`:1492`) — F1 below, a census amendment in the landing PR.

| Row | b | Statement (short) | Body (Rust, landed) | Stage | Disposition |
| --- | --- | --- | --- | --- | --- |
| F1 | 4 | exactly one input, `txin_gen` | — (`vin.len() == 1 && matches!(vin[0], Input::Gen(_))`) | `form` | **Land** — predicate on the coinbase; bucket 4 ports as-is with a fixture |
| F2 | 2 | coinbase `version ≥ 3` | — | `form` | **Land** |
| F3 | 2 | coinbase CT type `Null` | — (`matches!(ct, Ct::Null(_))`) | `form` | **Land** |
| F4 | 1 | exactly 1 output; height 0 exempt; height is *caller-derived* | — | `validate` | **Land** — the height is `cx.connecting`, never `Input::Gen`'s claim (that is F5's subject) |
| F5 | 4 | `txin_gen.height == connecting` | — | `validate` | **Land** — the spoof closure F4/F6 rest on; refusal `Locus::Miner`? (§8 Q6) |
| F6 | 4 | `unlock_time == height + 60` | constant `CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW` in `cryptonote_config.h`, *not* `config/` (census note) | `validate` | **Land** — the window becomes a `RuleSet` parameter (`mined_money_unlock_window: BlockCount`), pinned to 60 by the fixture (§8 Q5) |
| F7 | 4 | output amounts sum without overflow | `checked_add` fold | `form` | **Land** |
| F8 | 2 | outputs are `txout_to_tagged_key` | — (the wire type admits one output kind — verify at source whether the predicate is *unfailable* in Rust, §3 F7) | `form` | **Land**, possibly as a definition row |
| F9 | 1 | output keys canonical, prime-order, non-identity | `shekyl_ct_balance::check_output_keys` | `form` | **Land as adopted** |
| F10 | 1 | commitment masks canonical, ≠ identity, ≠ G, ≠ `zeroCommit(amount)` | `shekyl_ct_balance::check_commitment_masks` | `form` | **Land as adopted** |
| F11 | 1 | genesis (height 0) emission accepted as configured (`GENESIS_TX` per nettype); structure validated, amount not recomputed | none in Rust (`GENESIS_TX` lives in `cryptonote_config.h:367`/`:501`/`:512`) | `validate` | **Two halves** — (a) *amount not recomputed*: the genesis arm of F13–F18, a `connecting.is_zero()` short-circuit, lands here; (b) *as configured*: the genesis block per network is release-carried data of `ReleaseAnchors`' kind — **§8 Q3** |
| F12 | 4 | decomposed-denomination gate is **dead code** (`version == 3` where `version` is the HF version, always 1) | — | — | **Disposition, not a port** (§8 Q2): a dead branch has no fixture that fires |
| F13 | 1 | base subsidy `(MONEY_SUPPLY − already_generated) >> 21`, tail floor | `emission::base_block_reward` | `validate` | **Land** — a definition row (like D4): operand `block_at(tip).coins_generated` (view grows), value carried on the verdict |
| F14 | 1 | weight `> 2·median` rejects; `== 2·median` accepted at zero subsidy (recorded divergence) | `emission::paid_block_reward` (`apply_weight_penalty`) | `validate` | **Blocked on G6** (the median) — or pulled forward, §8 Q1 |
| F14b | 2 | the penalty curve | same | `validate` | **Blocked on G6** |
| F15 | 1 | release-rate multiplier over the exact window, capped to remaining supply | `release::calc_release_multiplier`, `TxVolume::window` | `validate` | **Land** — operand from F20 |
| F16 | 1 | emission split into miner / staker legs | `emission_share::{calc_effective_emission_share, split_block_emission}` + the C++ shim's `block_emission == 0` short-circuit (`economics.h:97`–`:110`) | `validate` | **Land as adopted, shim content moved into Rust** (§3 F5) |
| F17 | 1 | fee burn split; coinbase pays only `miner_fee_income` | `burn::calc_burn_pct`, `compute_burn_split_at` + shim's `total_fees == 0` short-circuit (`economics.h:64`–`:88`) | `validate` | **Function lands; row blocked on S-CURVE** (leaf count → `frozen_segment_count`) |
| F18 | 1 | coinbase pays **exactly** `miner_emission + miner_fee_income` | — | `validate` | **Blocked** (F14b, F17) |
| F19 | 1 | `frozen_segment_count` read at **parent state** or the node halts; single-read discipline | — | — | **True by construction in Rust**: `validate` runs inside the write transaction over a view branded `'id` that *is* the parent state; the reorder the C++ guards against (`m_db->height() != block_height`) is unrepresentable. Needs a status (§8 Q4) |
| F20 | 1 | volume operand `(tx_count_sum, blocks)` over the prior `min(h, 720)` blocks; `(0, 0)` at height 0 | `TxVolume::window(sum, blocks)`; sum = `cumulative_tx_count(tip) − cumulative_tx_count(tip − 720)` | `validate` | **Land** — a definition row; two view reads (`RecordedBlock.cumulative_tx_count`) |
| F21 | 1 | `genesis_ng_height` is **1** (the emission-split epoch operand) | — (`hardfork.cpp:383`–`:394`) | data | **Land as a `RuleSet` parameter** (`emission_split_epoch: BlockHeight::from_raw(1)`), consumed by F16; the C++ derives it from the one-row hardfork table, Rust states it |

Row-count check: 22 = the `pending` entries `F1`–`F21` + `F14b`.

---

## 3. Findings from the code sweep

- **F1 — every 4.F census line pin has drifted.** `prevalidate_miner_transaction` `:1391`–`:1428`, `validate_miner_transaction` `:1506`–`:1560`, `parent_frozen_segment_count` `:1492`; the census cites `1642`–`1803`. Amendment in the landing PR (the slice-2/3 F3/F2 shape).
- **F2 — the G1 closure grows by two crates; verify before adopting.** `shekyl-economics` (deps to read at source: `serde`? `build.rs` reads `config/economics_params.json` — a *build-time* file read, no runtime file; confirm nothing reaches a store) and `shekyl-ct-balance` (`curve25519-dalek`, already in the closure via `shekyl-wire`). `check_chain_rules_no_store.sh` is the gate; run it in commit 1.
- **F3 — the store already records three of the four missing operands, and `RecordedBlock` projects none of them.** `coins_generated` (F13), `cumulative_tx_count` (F15/F20), `weight`/`long_term_weight`/`long_term_effective_median` (F14, via G6) are `BlockInfo` fields at `codec/chain.rs:76`–`:101`. The view grows two fields this slice (`coins_generated`, `cumulative_tx_count`); the weight trio grows with G6, whoever lands it.
- **F4 — the median in force for the candidate is nowhere.** `long_term_effective_median` at `block_info[h]` is the median `h` was judged against (SCR-19); the candidate at `h + 1` needs the recompute *including* `h`, which the C++ holds in `m_current_block_cumul_weight_median` after connect and which no Rust path builds. This is CEN-G6/G6b's body: two rolling medians (100 000 and 100 blocks) over recorded weights, `effective_median(long, short)` and `long_term_weight` (`shekyl-economics/src/block_weight.rs:36`/`:47`) as the clamps. **F14, F14b and F18 cannot be evaluated without it.** §8 Q1.
- **F5 — the C++ `economics.h` shims carry rule content.** `compute_fee_burn` returns `{fees, 0, 0}` when `total_fees == 0` *before* any Rust runs; `compute_emission_split` returns `{emission, 0}` when `block_emission == 0`; both marshal the `SHEKYL_*` constants from `cryptonote_config.h`. Those short-circuits are consensus (the zero-fee coinbase pays zero; a zero-subsidy block splits nothing) and are not in `shekyl-economics` — the Rust functions are called *around* them. Adoption means `shekyl-economics` gains `compute_emission_split(reward, height, epoch, &params)` and `compute_fee_burn(fees, volume, supply, frozen, &params)` **with** the short-circuits and fixtures, and the C++ shims become one-call marshaling (rule 20: advance the boundary). Their constants come from `EconomicParams`, which `build.rs` already generates from `config/` — confirm the C++ `SHEKYL_*` values equal the generated ones (a constant-parity test, the F13-of-slice-2 shape).
- **F6 — F11's "as configured" is the genesis block's identity per network, which is release-carried data.** `GENESIS_TX` per nettype is in `cryptonote_config.h`; the store's init compares its height-0 block to it (`blockchain.cpp:508`–`:517`). Nothing in Rust holds the genesis identity. `ReleaseAnchors` is exactly the shape: a `(BlockHeight::ZERO, genesis_hash)` entry per public network, the ur-anchor "trusted with the binary". It would make E1 judge genesis (already fixtured in slice 3: `a_genesis_anchor_judges_the_genesis_candidate`) and E5 refuse a wrong-network file at open (`Remedy::RefuseToRun`, already fixtured) — **and it would refute `no_release_has_shipped_an_anchor_yet`**, deliberately. Whether genesis is an anchor or a separate `GenesisBlock::for_network` is §8 Q3.
- **F7 — F8 may be unfailable in Rust.** The C++ `check_output_types` refuses output variants the wire type may not be able to represent (`shekyl_wire` outputs are tagged keys by construction?). Verify at source in commit 1; if unrepresentable, F8 is a *definition* row recorded at parse (the B6 shape), not a predicate — and the census row gains that note.
- **F8 — the volume window is two view reads, not 720.** `Σ tx_hashes.size()` over the prior `min(h, 720)` blocks equals `cumulative_tx_count(h − 1) − cumulative_tx_count(h − 1 − min(h, 720))` (with the lower term `0` when the window reaches genesis); the store's `cumulative_tx_count` is the prefix sum built for exactly this (S-CHAIN-W). Height 0 → `(0, 0)` as the census states.
- **F9 — F19 is a structural property, not a check.** The C++ asserts `m_db->height() == block_height` because its read point can drift past `add_block`; the Rust `validate` runs inside the write transaction over a `ChainView<'id>` that *is* the parent state, and `connect` takes the branded verdict — the drift has no expression. The row is enforced by the type system, with a `compile_fail` doctest as its falsifier (the G4/PDM-Q3 shape). `RowStatus` has no word for it: `EnforcedAt` names a site and a runtime test; this has neither. §8 Q4.
- **F10 — F12 is dead code the census already convicted.** The gate `if (version == 3)` compares the *hard-fork* version (always 1) — `is_valid_decomposed_amount` and the `valid_decomposed_outputs[]` table never run. Bucket 4 "port as-is with a fixture" has no fixture for a branch that never fires. Rule 60 (*"when you encounter `if (version < N)` … delete the dead branch"*) and rule 15's default both say delete; deleting is a C++ edit to `blockchain.cpp` / `cryptonote_format_utils.cpp` — small, rule-20-shaped ("leave the file better"), but a C++ deletion inside an E6 slice is a scope question. §8 Q2.
- **F11 — F17's operand chain reaches the curve tree.** `frozen_segment_count = shekyl_archival_frozen_segment_count(leaf_count)` (`archival_ffi/schedule.rs:221`); the leaf count is the daemon-side tree's, whose redb tables are `Unshaped` (S-CURVE) and whose unit `PDM-Q12` moved. `ChainView` has `root_at` and no leaf count. The *function* `compute_fee_burn` is adoptable now (F5) with fixtures over a supplied count; the *row* is evaluable when the view can answer. Two owners meet here (E6, the S-CURVE increment); the pre-flight names the seam — `ChainView::frozen_segment_count(height)` or `leaf_count(height)` — and leaves the method for S-CURVE to mint with its data (rule 22: a callee without its data is staging without a substrate).
- **F12 — the coinbase's fee operand is the candidate's own.** `Σ Ct::Fcmp.fee` over the listed transactions is stateless and readable today; whether each fee is *right* (CT balance, H rows) is slice 5's. F17/F18's verdict inherits 4.H's trust; recorded, not a blocker on the read.
- **F13 — `F4`/`F6` read the connecting height, `F5` checks the claim.** The census note ("the height operand is caller-derived, not `txin_gen.height`; spoof closed by F5") maps exactly to `cx.connecting` vs `Input::Gen(h)`: F5 is the only row that *reads* the claim, and it compares it to the view's height. All three are `validate`-stage (they need the height); F1/F2/F3/F7/F8/F9/F10 are stateless (`form`).

---

## 4. Substrate this slice adds (sketch; shaped by §8)

- **`RecordedBlock` grows `coins_generated: AtomicUnits` and
  `cumulative_tx_count: u64`** (projection edits in `BatchView::block_at` and
  the mock; the F11 conformance harness of slice 2 covers both sides).
- **`RuleSet` grows two parameters:** `mined_money_unlock_window: BlockCount`
  (60; F6) and `emission_split_epoch: BlockHeight` (1; F21). Both are data the
  C++ derives from constants / the one-row hardfork table; Rust states them.
- **Definition rows carried on the verdict** (the D4 shape): `base_subsidy`
  (F13), `tx_volume` (F20), and — when their operands exist — the paid
  reward (F14b/F15), the split (F16) and the burn (F17), which is what
  `connect` needs to derive `coins_generated` and `burned` (S-CHAIN-W's
  `DELETED_BY`) and drop two more passed-through facts. **This slice can
  delete neither**: `coins_generated` needs the *paid* reward (F14b), and
  `burned` needs F17's operand. The record at close states `passed_through`
  6 → 6, with the deletions owed to the increments that land F14b and F17.
- **A miner-transaction rule class.** F1–F10 judge `block.miner_transaction`
  with `Locus::Miner`-shaped refusals; `tx_form` is the per-listed-tx path
  the pool shares and the coinbase "never passes the H path" (census F8
  note), so these are block-level rules reading one field, not `TxRule`s.
- **`shekyl-economics` gains** `compute_emission_split` and
  `compute_fee_burn` with the shims' short-circuits (F5) and a constants
  parity test against `cryptonote_config.h`'s `SHEKYL_*`.

---

## 5. Fixtures per row and commit plan — deferred to Round 1

Written once §8 settles which rows land in this slice. Every landed
predicate row gets its negative fixture first; every definition row a value
pin against the C++ (the 81-vector emission KAT already pins
`block_reward_with_penalty`; F15/F16/F17 need KATs at the shim boundary).

---

## 6. What this slice does not build

- G6/G6b (the medians) unless Q1 pulls them in; F14/F14b/F18 with them.
- The curve-tree leaf-count read (S-CURVE's); F17's *row* with it.
- 4.H fee validity (slice 5); 4.G aggregation (slice 7).
- The `coins_generated` / `burned` `ConnectFacts` deletions (owed to the
  landings of F14b and F17).

---

## 7. Round log

- **Round 0 (2026-09-21, `ea140396b`).** Sweep; §1–§4; §8 questions posed.

---

## 8. Questions for the reviewer — Round 0

- **Q1 — the median (F4).** F14, F14b and F18 need the effective median in
  force for the candidate, which is CEN-G6/G6b's derivation and exists
  nowhere in Rust. Three arms: **(a)** land the eighteen operand-complete
  rows here; F14/F14b/F18 stay `pending` with a `blocked-by G6` registry
  comment and land in slice 7 with the weights machinery, where table 3 put
  them; **(b)** pull G6/G6b into this slice — two rolling medians over the
  recorded `weight` / `long_term_weight` (100 000- and 100-block windows,
  read through `ChainView::block_at` or a new bulk `weights(range)` method),
  the `S = 4` ratified clamp (a **divergence from the shipped ×50** the
  census already records — landing it here makes the Rust validator refuse
  blocks the C++ accepts near the surge bound, which is a CSR-3a pass
  condition, not a defect); **(c)** an interim `ChainView::effective_median_for_next()`
  fed from the store's recorded value — **rejected before asking**: it would
  be the wrong median by one block (SCR-19) and a passed-through fact
  dressed as a derivation. **Default: (a).** G6 is 4.G's heaviest row and
  the one with the recorded divergence; landing it as a side effect of the
  coinbase slice would bury the divergence in the wrong PR. The cost is
  that F18 — the row that *is* "the coinbase is right" — waits one slice.
- **Q2 — F12, the dead gate.** **(a)** census amendment: F12 → bucket 3
  (*"dead code; deleted"*) **and** delete the branch, `is_valid_decomposed_amount`
  and `valid_decomposed_outputs[]` in the same PR (rule 60's instruction;
  ~40 C++ lines, a deletion not a rewrite); **(b)** amend the census only and
  leave the C++ for cutover (E4); **(c)** register `implemented` with a
  vacuous rule. (c) is a fixture that cannot fire. **Default: (a)** — the
  C++ deletion is the smallest rule-20-shaped touch there is, and bucket 3
  moves the denominator honestly (153 → 152, `validator-enforced` 151 →
  150) rather than counting a rule that never ran as ported.
- **Q3 — genesis as the height-0 anchor (F6).** F11's "as configured" is a
  per-network block identity the binary carries — the definition of an
  anchor. **(a)** put `(0, genesis_hash)` into `ReleaseAnchors::for_network`
  for the three public networks: E1 then judges genesis, E5 refuses a
  wrong-network file at open, both already fixtured; the slice-3 test
  `no_release_has_shipped_an_anchor_yet` is refuted *by design* and replaced
  by `the_only_anchor_is_genesis_until_the_first_checkpoint_release`; PDM-Q5's
  "`C`" becomes "the last anchor above genesis" where the distinction
  matters (band 1 = `≤ C` still reads correctly: below genesis is nothing).
  **(b)** a separate `GenesisBlock::for_network(net) -> BlockHash` beside
  `RuleSchedule`, consumed by an F11 rule at `connecting.is_zero()`, leaving
  the anchor table for checkpoints only. **Default: (a)** — one mechanism
  for one kind of fact ("a block the binary vouches for"), and the two
  behaviours F11 asks for are exactly E1 and E5. The genesis hashes come
  from `GENESIS_TX` + the genesis header per network; the Rust side derives
  them once (the genesis tool's pins or a KAT against `cryptonote_config.h`)
  and the table holds the result as data. PDM lane to confirm the reading of
  `C`.
- **Q4 — a status for a row true by construction (F9).** F19 is enforced by
  the view brand and the transaction boundary, falsified by a
  `compile_fail` doctest, with no runtime site and no per-block coverage.
  **(a)** `RowStatus::ByConstruction { property, falsifier }` — like
  `EnforcedAt` in leaving `RuleSet::enforced()`, counted as implemented,
  with the gate asserting the named doctest exists; the PDM-Q3 instrument
  ("true by construction at `645d09dc3`, held as a standing property with a
  compile-shaped falsifier") is the same class and would take the status
  too; **(b)** `EnforcedAt { site: <the view brand>, test: <a runtime test
  that a mis-ordered read cannot be written> }` — stretches "site" past a
  function; **(c)** `implemented` with a rule whose check is a no-op —
  a fixture that cannot fire. **Default: (a).**
- **Q5 — constants as `RuleSet` parameters.** F6's unlock window (60) and
  F21's split epoch (1) become `RuleSet` fields with a fixture each,
  following `header_major_version` and `difficulty`. F6's constant lives in
  `cryptonote_config.h`, not `config/` (the census says so); the parameter
  is pinned by test to the C++ value. **Default: yes, both.**
- **Q6 — the coinbase's locus.** Refusals on F1–F10 point at the miner
  transaction; `Locus::Block` is imprecise, `TxSlot::Miner` exists for the
  per-tx path. Does the block-level miner rule refuse at `Locus::Tx(TxSlot::Miner)`
  (reusing the slot vocabulary) or does `Locus` grow a `Miner` arm?
  **Default: reuse `TxSlot::Miner`** — one vocabulary for "which transaction".
- **Q7 — sequencing.** No in-flight PR touches `shekyl-chain-rules` or the
  store's view today (`gh pr list`: #808 refactor, #810 wallet). The E2
  driver calls `validate` and will pick up new coverage rows automatically;
  no cross-lane edit is foreseen. **Default: land as one PR after Round 1**,
  rules-crate commits first, view growth (store projection) after — the
  store side is a projection edit, not a schema change.
