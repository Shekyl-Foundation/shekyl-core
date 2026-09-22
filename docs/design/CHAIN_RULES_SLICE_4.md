# `shekyl-chain-rules` slice 4 — census 4.F, the miner transaction (DRS-E6 increment 5)

**Status:** OPEN — Round 0 pre-flight, written 2026-09-21 against `dev` @
`ea140396b` (post-#814); **Round 0.5 (2026-09-21): the shim-layer sweep the
review ordered before Round 1 — §3.1.** Nothing implemented; §8 is the
question set, re-posed against the swept count.
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

**What this pre-flight found, in one paragraph** *(the count and the
"adopted" claim are corrected by §3.1's sweep — read that section as the
current state; this paragraph is Round 0's record).* The bodies are Rust and
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
| F12 | **3** (was 4) | decomposed-denomination gate was **dead code** (`version == 3` where `version` is the HF version, always 1) | — | — | **RULED Q2 (a), 2026-09-21; DELETED (P4).** Branch, predicate, table, header declaration and `canonical_amounts.cpp` gone; census row → bucket 3; registry variant removed; denominator 153 → 152 |
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

### 3.1 The shim-layer sweep (Round 0.5, 2026-09-21) — what "adopted" actually contains

**Why this section exists.** F5 found two rule-bearing arms in the C++ shim
layer by reading two functions. The review's prior after two-found-by-reading
is that there are more (the FFI-export sweep two lanes back: two found by
accident, eight by sweeping), and that Round 1 cannot rule on a landable
count until the shim layer is *enumerated*, not sampled. So every site of
control flow between a 4.F caller and its Rust call was read, in
`src/shekyl/economics.h`, `cryptonote_basic_impl.cpp` (`get_block_reward`),
`blockchain.cpp` (`prevalidate_miner_transaction`,
`validate_miner_transaction`, the connect call site), the C++ side of
`ct_balance_ffi.rs` (`check_outs_valid`, `check_commitment_mask_valid`,
`check_outs_overflow`, `check_output_types`), and the Rust side of the shims
(`legacy_core.rs`, `ct_balance_ffi.rs` — Rust, but in `shekyl-ffi`, which
the rules crate cannot reach).

**The discriminator (R8's).** *Would this still be required if the consensus
rules changed?* A null-pointer guard survives any rule change and is
**marshaling**. A zero-fee arm that decides the burn split does not and is
**rule content**. A constant the C++ supplies that has no Rust home is rule
content as *data*. A branch no rule can reach is **dead** (rule 60). The
question turns a judgement per site into a test.

| # | Site | What sits between the caller and Rust | Class | Row(s) | Disposition |
| --- | --- | --- | --- | --- | --- |
| S1 | `economics.h:70` `compute_fee_burn` | `if (total_fees == 0) return {total_fees, 0, 0};` — the zero-fee burn outcome decided before any Rust runs | **RULE** | F17, G11 | Relocate into `shekyl-economics::compute_fee_burn` with a fixture |
| S2 | `economics.h:74`–`:82` | `SHEKYL_TX_VOLUME_BASELINE`, `…_ASYMPTOTE`, `…_BURN_BASE_RATE`, `…_BURN_CAP` passed as arguments | marshaling | F17 | Both sides generate these from `config/economics_params.json` (`cmake/generate_economics_params.py` ↔ `build.rs`); the Rust function takes `&EconomicParams` and the arguments go |
| S3 | `economics.h:74`–`:87` | the **composition** `calc_burn_pct → compute_burn_split_escalated` (the pct feeds the split) | **RULE** | F17 | Relocate: one Rust function owns the pipeline |
| S4 | `economics.h:103` `compute_emission_split` | `if (block_emission == 0) return {block_emission, 0};` | **RULE** | F16 | Relocate into `shekyl-economics::compute_emission_split` with a fixture |
| S5 | `economics.h:107`–`:111` | `SHEKYL_STAKER_EMISSION_SHARE`, `…_DECAY`, `SHEKYL_BLOCKS_PER_YEAR` as arguments | marshaling | F16 | as S2 |
| S6 | `economics.h:107`–`:114` | the composition `calc_emission_share → split_block_emission` | **RULE** | F16 | Relocate with S4 |
| S7 | `cryptonote_basic_impl.cpp:93` `get_block_reward` (5-arg) | substitutes `tx_volume_window{BASELINE, 1}` — the "`M_r`-neutral view" for fee/relay floors | **RULE** (policy) | CEN-M3's held machinery, not 4.F | Out of this slice; recorded for slice 10 / E5: a policy operand chosen in C++ |
| S8 | `cryptonote_basic_impl.cpp:81`–`:86`, `:143` | `get_min_block_weight(version)` → `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5` (300 000), a hand-written `#define` in `cryptonote_config.h` — **`EconomicParams` has no zone field**; `paid_block_reward` takes it as an argument on every call | **RULE as data** (a consensus constant with no Rust home) | F14b, G6b | `full_reward_zone` joins `config/economics_params.json` → `EconomicParams`; the argument goes. Precursor to F14b regardless of Q1 |
| S9 | `cryptonote_basic_impl.cpp:150`–`:163` | `BLOCK_TOO_BIG → false`, other status `→ false` | marshaling | F14 | Rust already classifies (`EmissionError::BlockTooBig` vs the rest); the rules crate reads the `Result` directly. Note: the C++ folds *every* other error into a refusal; the Rust rule must decide verdict-vs-fault per variant (slice 2's "unproven ≠ disproven") |
| S10 | `blockchain.cpp:1509` | `block_height = txin_gen.height` — `validate_miner_transaction` reads the **claim**, safe only because `prevalidate` ran F5 first | **RULE** (operand source by ordering) | F11, F4, F6 | Moot in Rust: `cx.connecting` is the operand; F5 checks the claim. Recorded so the ordering dependency does not get re-created |
| S11 | `blockchain.cpp:1513`–`:1517` | `if (block_height == 0) { base_reward = money_in_use; return true; }` — genesis skips the reward and **defines** genesis's `coins_generated` as its coinbase sum | **RULE** (two facts) | F11, F13 | Port as F11's genesis arm; the `coins_generated` definition at height 0 is a store-side fact `connect` needs when `coins_generated` is derived — recorded on the S-CHAIN-W row |
| S12 | `blockchain.cpp:1511` | `money_in_use += o.amount` **unchecked** — safe only because `check_outs_overflow` (F7) ran first | ordering | F7, F18 | `checked_add` in Rust; the ordering is not carried |
| S13 | `blockchain.cpp:1519`–`:1527` | `if (version == 3)` decomposed-denomination gate | **dead** | F12 | Q2 (a) — **deleted (P4)** |
| S14 | `blockchain.cpp:1529` | `median_weight = m_current_block_cumul_weight_median` — cached daemon state | **RULE** operand | F14, F14b | G6's derivation (§3 F4); no Rust source |
| S15 | `blockchain.cpp:1534` (validation), `:1821` (template) | `circulating_supply = already_generated_coins` — the **definition** of F17's "circulating supply" operand, **gross** emission ignoring burn, assigned at two sites | **RULED DEFECT** — FL-R16c (`FEE_LADDER_DERIVATION.md` §8, review round 4: *"the sweep must not walk past the pre-existing definitional bug … record — binds the implementing PR"*), rediscovered here as a fresh finding because the ruling's pins (`:1787`, `:2074`) had drifted | F17 | **Not an amendment — the binding disposition, landed (P1c):** `circulating_supply = coins_generated − total_burned`, derived **once** in `shekyl-economics::supply::CirculatingSupply::derive` from two store facts, `checked_sub` with the `None` arm a `SupplyInvariantViolation` (never a saturating zero: zero would sail through `calc_burn_pct`'s `total_supply == 0` guard and return a burn of `0` that looks valid). Both C++ sites pass `shekyl::supply_facts`; the accrual shares one read. The clamp at `burn.rs:83` **stays** — the two halves of FL-R16c are independent (the saturation is the perpetual tail's, not the gross operand's; `supply::tests::net_supply_exceeds_the_asymptote_under_the_tail`) — with its comment rewritten so it no longer names an operand that left |
| S16 | `blockchain.cpp:1540` | `genesis_ng_height = get_earliest_ideal_height_for_version(HF_VERSION_SHEKYL_NG)` | **RULE** as data | F21 | `RuleSet` parameter (Q5) |
| S17 | `blockchain.cpp:1553`–`:1565` | `miner_base_reward + effective_fee` **unchecked**; `<` then `!=` (two arms, one outcome) | **RULE** | F18 | `checked_add`; one `!=` arm |
| S18 | `blockchain.cpp:5470`, `:5675`–`:5676` (connect) | `cumulative_block_weight = weight(miner_tx) + Σ tx_weight`; `fee_summary = Σ fee` | **RULE** (operand definitions) | 4.G (weight), F17/F18 (fee) | Block weight is 4.G's definition (slice 7); the fee sum is the candidate's own and lands as a definition read here |
| S19 | `blockchain.cpp:5837` | `frozen_segment_count = parent_frozen_segment_count(h)` → `shekyl_archival_frozen_segment_count(leaf_count)` | **RULE** operand; the read-point guard is F19 | F17, F19 | The leaf→segment function is Rust (`archival_ffi/schedule.rs:221`, in `shekyl-ffi`); the *read* is S-CURVE's (§3 F11) |
| S20 | `blockchain.cpp:1394`–`:1428` `prevalidate_miner_transaction` | F1–F6's predicates, in C++ | **RULE** | F1–F6 | The port itself — these were never "adopted" |
| S21 | `blockchain.cpp:1421` | `check_tx_extra_pqc_field_shape(b.miner_tx)` — **CEN-I19 applied to the coinbase** | RULE (another family's) | I19 | Not a 4.F row; in Rust the per-tx path judges `TxSlot::Miner` too (`validate.rs`), so I19 covers the coinbase when 4.I lands. Recorded so slice 6 knows the coinbase is in its domain |
| S22 | `cryptonote_format_utils.cpp:841` `check_outs_valid` | `if (tx.vout.empty()) return true;` before `shekyl_check_output_keys` | marshaling | F9 | Redundant: `check_output_keys(&[])` is `Ok` (`chunks_exact` over nothing). Goes |
| S23 | `cryptonote_format_utils.cpp:1021`–`:1050` `check_output_types` | a **four-arm hard-fork ladder** (`≥ NG`, `> VIEW_TAGS`, `< VIEW_TAGS`, `==`) of which one arm is reachable | **dead** ×3 + RULE ×1 | F8 | Three arms are rule-60 deletions (a `version < N` ladder for Monero-era forks); the live arm is F8's predicate, ported |
| S24 | `cryptonote_format_utils.cpp:907` `check_outs_overflow` | `if (money > o.amount + money)` — the overflow test written as a wrapping compare | **RULE** | F7 | Port as `checked_add`; same verdict on every input (u64 wrap is total) |
| S25 | `blockchain.cpp:3238` `check_commitment_mask_valid` | `if (outPk.size() != vout.size()) return false;` — **one mask per output** | **RULE** (uncensused for the coinbase) | F10 | Census F10 does not state it; either F10's text gains the clause or it is CEN-H*'s CT-shape row applied to the coinbase. Amendment either way |
| S26 | `blockchain.cpp:3244` | `if (outPk.empty()) return true;` | marshaling | F10 | Redundant: `check_commitment_masks(&[], _)` is `Ok`. Goes |
| S27 | `blockchain.cpp:3250`–`:3255` | `if (rv.type == CTTypeNull) → coinbase_amounts` — **the decision that the `zeroCommit(amount)` fingerprint gate applies to the coinbase** is made in C++; Rust takes `Option<&[u64]>` and does what it is told | **RULE** (selection) | F10 | Relocate: `shekyl-ct-balance` gains a typed entry (`check_coinbase_commitment_masks(masks, amounts)` / the spend form) so the caller cannot pass the wrong selection; the `Option` parameter goes |
| S28 | `blockchain.cpp:3259`–`:3275` | `rc → bool` with per-variant messages | marshaling | F10 | — |
| S29 | `legacy_core.rs:452` `shekyl_base_block_reward` | `.unwrap_or(0)` — an `EmissionError` becomes a reward of **0** | **RULE-shaped** (fault → value) | F13's C++ consumers | Callers: `economics.h:48` names it for "raw base curve" consumers; verify each accepts 0 as "error". Not the rules crate's path (it calls `base_block_reward` directly); recorded for the FFI lane |
| S30 | `legacy_core.rs:534` `shekyl_block_reward` | null-pointer guard; `Err(BlockTooBig) → TOO_BIG`, `Err(_) → INVALID` | marshaling | F14 | — |
| S31 | `legacy_core.rs:426`, `:732`, `:749` | `EconomicParams::default()` supplied Rust-side for the escalation/share params while C++ supplies the burn/share constants (S2, S5) — **two entry points, two sources for one parameter set** | marshaling, inconsistent | F16, F17 | Resolved by S2/S5: one `&EconomicParams` in Rust |

**Tally.** Thirty-one sites; **fifteen are rule content** (S1, S3, S4, S6,
S8, S10, S11, S14, S15, S16, S17, S18, S20, S24, S25, S27 — sixteen counting
S27's selection separately from S25's shape clause), **four are dead** (S13;
S23 ×3), the rest marshaling. Of the rule content, **five live in the shim
layer proper** — S1, S3, S4, S6 in `economics.h`, S27 in
`check_commitment_mask_valid` — and **one is a consensus constant with no
Rust home** (S8). F5's "two" was five in the shims and one missing parameter.

**What this does to "the bodies are Rust, adopted".** It was describing the
shim layer's *intent*. Read by contents: of the rows this slice can evaluate,
**three** adopt a Rust body end-to-end (F9 `check_output_keys`, F13
`base_block_reward`, F15 via `effective_emission` — which is exactly
`max(M_r·curve, TAIL)`, the pre-penalty paid emission, computable **without
the median**); **F10, F16, F17 adopt a Rust body wrapped in C++ rule content**
(S27; S4+S6; S1+S3+S15) and cannot be registered `implemented` until that
content moves — the validator would otherwise lack behaviour the C++ has;
**F1–F8, F11, F18, F20 are ports** of C++ predicates and definitions (the
slice-1 shape, never adoption); F14b needs a constant only C++ holds (S8).

**What this does to the landable count.** Operand availability is unchanged
by the sweep — but one row moves: **F16 is operand-blocked** (the split's
operand is the *paid* reward, after F14b's penalty), which Round 0 missed.
So: **operand-complete now: F1–F11, F13, F15, F19, F20, F21 = 16 rows, plus
F12 as a disposition; blocked: F14, F14b, F16, F18 (the median) and F17 (the
leaf count) = 5.** Of the sixteen, F10 needs S27 relocated first.

**The precursor, and why it is cheap.** Moving S1/S3/S4/S6/S27 and S8 out of
C++ is **behaviour-preserving**: the same outcome computed one layer down,
a C++ deletion plus a Rust addition with fixtures, no observable change and
therefore no census divergence and no consensus review — rule 20's
advance-the-boundary in its plainest form. It lands as commits **before
Round 1**, so Round 1 rules on the actual landable set:

- **P1** `shekyl-economics`: `full_reward_zone` in `config/economics_params.json`
  → `EconomicParams` (S8); `compute_emission_split(block_emission, height,
  epoch, &params) -> EmissionSplit` with the zero arm (S4, S6);
  `compute_fee_burn(total_fees, tx_volume, circulating_supply, frozen,
  &params)` with the zero arm (S1, S3). KATs at the former shim boundary
  (zero fee; zero emission; the `[0.8, 1.3]` clamp edges). `economics.h`
  shrinks to two one-call marshals; the `SHEKYL_*` arguments go (S2, S5,
  S31).
- **P2** `shekyl-ct-balance`: the coinbase/spend selection typed at the
  entry (S27); the vacuous guards go from the C++ callers (S22, S26).
- **P3** census amendments: F17's operand definition (S15), F10's
  one-mask-per-output clause (S25), every 4.F line pin (§3 F1).
- **P4** (rule 60, Q2's shape): the three dead `check_output_types` arms
  (S23) and — if Q2 (a) — the decomposed gate (S13).

P1–P2 are the "commit rather than a PR" case the review anticipated if the
sweep came back small; it came back with five shim sites and one missing
constant, which is one PR's worth of relocation with fixtures, sequenced
ahead of the slice's rule commits and reviewable on its own.

**Precursor LANDED on the branch 2026-09-21 (P1a, P1b/c, P2, P3):**

- **P1a (S8)** — `block_weight_full_reward_zone_bytes` in
  `config/consensus_constants.json` (the surge factor's precedent: one key,
  both generators); `EconomicParams::full_reward_zone`; the argument gone
  from `paid_block_reward` / `block_reward_with_penalty` /
  `block_weight_limit` / `shekyl_block_reward`; the C++ macro defined from
  the generated header; params digest `0x02 → 0x03` (the zone selects the
  penalty, so a stamp that omitted it would let two nodes agree while paying
  differently); `PINNED_DIGEST` re-pinned with the chain question answered.
  Behaviour unchanged. **Residue for the fee-ladder lane:**
  `checked_corrected_fee_ladder` / `checked_relay_fee_floor` and their FFI
  still take the zone as an argument (the policy path).
- **P1b (S4, S6)** — `shekyl-economics::compute_emission_split` owns the
  zero arm and the composition; `shekyl_compute_emission_split` FFI;
  `economics.h` marshals one call.
- **P1c (S1, S3, S15)** — `compute_fee_burn` / `calc_burn_pct_at` own the
  zero-fee arm, the percentage from `params`, and the composition;
  `CirculatingSupply::derive` is FL-R16c's definitional half, landed (see
  the S15 row); `shekyl_compute_fee_burn` / `shekyl_calc_burn_pct_at` take
  the two store facts and return a status (`SUPPLY_INVARIANT` writes
  nothing — the caller halts); `validate_miner_transaction` gains
  `total_burned`, read **once** at the connect site beside
  `frozen_segment_count` and shared with the accrual; the template reads
  its own at parent state; the info RPC's `burn_pct` is over the derived
  supply. **Not moved, recorded on FL-R16c:** the relay-floor ring and the
  fee estimate form `C` over the gross operand through the raw
  `shekyl_calc_burn_pct` — the ring recomputes rungs at historical heights,
  and neither store has a per-height cumulative-burn fact (only per-block
  `block_burn` rows). A fee-ladder question with a store dependency.
- **P2 (S22, S25, S26, S27)** — `shekyl_ct_balance::check_commitment_masks_for(masks, n_outputs, MaskSubject)`
  is the entry: the arity gate (`MaskCountMismatch`, new) and the
  fingerprint selection by subject; the `Option<&[u64]>` primitive is
  crate-private. The FFI takes the CT type byte and the output count as
  facts and derives the subject (`ERR_MASK_COUNT`, `ERR_CT_TYPE` new);
  `check_commitment_mask_valid` and `check_outs_valid` lose their arms.
- **P3** — census F10 (arity clause; selection), F16, F17 (the FL-R16c
  definition; the shim content) amended with re-resolved pins; FL-R16a/b/c
  pins re-resolved and R16c → BUILT (both halves, independence recorded);
  FOLLOWUPS: the census-method question (owner: the census, §3.4). The
  remaining 4.F line pins (F1) are the slice PR's.
- **P4 — LANDED (Q2 ruled (a), 2026-09-21).** One rule-60 commit: F12's
  gate, `is_valid_decomposed_amount`, `valid_decomposed_outputs[]`, the
  header declaration and `tests/unit_tests/canonical_amounts.cpp` (which
  exercised only them); S23's three dead `check_output_types` arms and the
  `hf_version` parameter that selected among them (three callers). Census
  F12 → bucket 3 with the deletion recorded in the row; `CenRow::F12`
  removed; the gate reports `validator-enforced 150 / enforced 152`; §3.1
  and Table 3 figures moved (`4.F 13/4/4/21`).


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
- **Round 0.5 (2026-09-21).** The shim-layer sweep the review ordered
  before Round 1 (§3.1): 31 sites under R8's discriminator; five rule-bearing
  shim sites and one homeless constant (F5 had found two); F16 moves to the
  blocked set; "adopted" corrected to three rows; the precursor P1–P4 named
  and sequenced ahead of Round 1.

---

## 8. Questions for the reviewer — Round 0

- **Q1 — the median (F4), re-posed against §3.1's count.** F14, F14b, F16
  and F18 need the effective median in force for the candidate, which is
  CEN-G6/G6b's derivation and exists nowhere in Rust (F16 joined the blocked
  set in the sweep: its operand is the *paid* reward). Three arms: **(a)**
  land the **sixteen** operand-complete rows here (F1–F11, F13, F15, F19,
  F20, F21; F12 as a disposition), after the §3.1 precursor relocations;
  F14/F14b/F16/F18 stay `pending` with a `blocked-by G6` registry comment
  and land in slice 7 with the weights machinery, where table 3 put them; **(b)** pull G6/G6b into this slice — two rolling medians over the
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
  **Q1 is not asked until the §3.1 precursor has landed** (the review's
  ordering: the sweep changes what Round 1 rules on).
- **Q2 — F12, the dead gate.** **(a)** census amendment: F12 → bucket 3
  (*"dead code; deleted"*) **and** delete the branch, `is_valid_decomposed_amount`
  and `valid_decomposed_outputs[]` in the same PR (rule 60's instruction;
  ~40 C++ lines, a deletion not a rewrite); **(b)** amend the census only and
  leave the C++ for cutover (E4); **(c)** register `implemented` with a
  vacuous rule. (c) is a fixture that cannot fire. **Default: (a)** — the
  C++ deletion is the smallest rule-20-shaped touch there is, and bucket 3
  moves the denominator honestly (153 → 152, `validator-enforced` 151 →
  150) rather than counting a rule that never ran as ported.
  **RULED (a), 2026-09-21. Landed as P4 (§3.1).**
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
