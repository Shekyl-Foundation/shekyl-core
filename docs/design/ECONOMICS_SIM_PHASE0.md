# Economics sim, Phase 0 — where the sim stands before the build-out

**Status:** **OPEN — Phase 0 of the economics-sim lane, read-only, 2026-10-23.**
Anchors pinned to `dev` `465b77eba`; every figure below was produced or read
at that commit unless its row names another. Nothing in the sim or in
production changes in Phase 0. The design owner rules on §P0.9's questions,
and only then does Phase 1 start.

**What Phase 0 is for.** The lane's goal (Rick): bring the economics sim up to
the current build and designs; re-run it and validate the algorithm; derive
the key settings. The sim was last aligned at ESR-9 (#1104, merged as
`52b3c73bb`). This document establishes from code, not from documents, where
the sim stands now: what it reproduces, what production changed under it,
which constants a sweep has to reach, which of its declared departures still
stand, what it does not model, what it costs to run, and which instrument
will decide each setting. §P0.9 turns the findings into the build order.

**Reading conventions.**

- Paths are repo-relative. A `crate file:line` cell (for example
  `shekyl-economics params.rs:210`) is under `rust/<crate>/src/`.
- *Production* is the arm that charges `shekyl_economics::corrected_fee_ladder`;
  *flat control* is `--control-flat-fee`.
- PROD and FLAT are the committed narration fixtures,
  `rust/shekyl-economics-sim/tests/fixtures/stage2_narration.txt` and
  `stage2_narration_flat_control.txt`; JSON is
  `docs/test_vectors/economics/baseline_steady_state.json`.
- Runtimes are wall seconds on one development machine, release build,
  `rustc 1.94.0`, one run each.

---

## P0.1 Ground truth: does today's sim reproduce itself?

### Build, tests, gates

| Check | Result at `465b77eba` |
| --- | --- |
| `cargo build --locked --release -p shekyl-economics-sim` | ok, 107 s |
| `cargo test --locked --release -p shekyl-economics-sim` | 162 passed, 0 failed, 5 ignored (57 s) |
| The ignored set (`--list --ignored`) | exactly the nightly lane's three plus its two regeneration helpers (`record::tests::regen_baseline_fixture`, `stage2::tests::regen_stage2_narration_fixtures`) |
| `stage2::tests::stage2_narration_matches_the_committed_fixture` | ok, 117 s |
| `stage2::tests::stage2_narration_flat_control_matches_the_committed_fixture` | ok, 100 s |
| `secret_draw_production::tests::the_esr11_timing_set_runs_and_the_table_renders` | ok, 14 s |
| `record::tests::committed_fixture_matches_recorder` (not ignored) | ok |
| `scripts/ci/check_sim_integer_seams.py` | ok; one allowed float boundary, `whole_transactions` (`rust/shekyl-economics-sim/src/fee_floor.rs:271`) |

The narration fixtures are held only by the nightly lane: both tests are
`#[ignore]`, so a PR that moves them is green until the next nightly run.
#1158, in flight, moves the nightly lane's ignored-test list into the tree.

### Every report mode

"Moved since ESR-9" compares each mode's full output at `52b3c73bb` and at
the pin.

| Mode | Exit, runtime | Committed fixture | Fixture last regenerated | Moved since ESR-9 | Seed-dependent |
| --- | --- | --- | --- | --- | --- |
| default (all scenarios, JSON) | 0, 20 s | none | — | yes | no |
| default `--control-flat-fee` | 0, 17 s | none | — | yes | no |
| `--gate7` | 0, 73 s | none | — | yes | no |
| `--fb1c-c2` | 0, 17 s | none | — | yes | no |
| `--fee-ladder` | 0, 3 s | none | — | **no** (byte-identical) | no |
| `--fee-floor` | 0, 4 s | none | — | **no** (byte-identical) | yes: FL-E2–E4 traffic; FL-E1 no |
| `--secret-draw` | 0, 13 s | none | — | **no** (byte-identical) | yes: 8 seeds a cell |
| `--secret-draw-production` | 0, 158 s | none | — | **no** (identical but for its wall-time lines) | yes: 8 seeds a cell |
| `--stage2` | 0, 151 s | PROD, matches byte for byte | `0540a6e71` (2026-10-22) | yes | no |
| `--stage2 --control-flat-fee` | 0, 168 s | FLAT, matches byte for byte | `0540a6e71` (2026-10-22) | yes | no |
| recorder (`record_baseline_fixture`) | test | JSON, matches | `5eeb3d3eb` (2026-10-22) | yes | no |

**Every move since ESR-9 is #1152's.** The six modes that moved were run
again at `5abcb6e51` (the first parent of #1152's merge) and at `11f8fd1f0`
(the merge). Each is byte-identical from `52b3c73bb` to `5abcb6e51` and from
`11f8fd1f0` to the pin, so #1152 alone moved them: the fill prices the
coinbase and the medians record that weight. Runtimes in this table are one
run each; the same `--stage2` took 113 s to 170 s across these runs, so
read them as an order of magnitude.

### Seed spread

The sim has two generators and no `rand` crate
(`rust/shekyl-economics-sim/src/rng.rs`). `SplitMix64` drives the
secret-draw evidence; `PoissonTrace` drives the fee-floor slew traces from one
fixed seed, `POISSON_TRACE_SEED`. `--stage2`, the default mode, `--gate7` and
`--fb1c-c2` draw from neither: their demand is the scenarios' deterministic
closures, so they are deterministic.

**`--fee-floor`, five seeds** (the pinned seed and four others, set through
an uncommitted probe that overrides `POISSON_TRACE_SEED` and was reverted):

| Seed | FL-E2–E4 worst 1-block rise | grace max G = 3 / 4 / 5 | FL-E1 not converged / worst |
| --- | --- | --- | --- |
| `5EEDF1FEED1E5EED` (pinned) | 210 bp | 634 / 855 / 1 076 bp | 4 of 600 / 87 bp |
| `1` | 208 | 624 / 835 / 1 058 | 4 / 87 |
| `9E3779B97F4A7C15` | 218 | 657 / 876 / 1 090 | 4 / 87 |
| `DEADBEEFCAFEF00D` | 219 | 658 / 865 / 1 068 | 4 / 87 |
| `0123456789ABCDEF` | 217 | 632 / 845 / 1 061 | 4 / 87 |
| **spread** | **208–219** | **624–658 / 835–876 / 1 058–1 090** | **none** |

FL-E1's feedback loop does not read the Poisson trace, so its four
non-converged cells (all at age 12, `ε` = 3, `D` = 400, displaced start) are
a property of the grid, not of a seed.

**`--secret-draw`**: every cell already runs 8 seeds and prints mean / min /
max of pairs short. The seeds are common random numbers across cells, so the
cells share one realised dropout and are not independent samples.

| `D` | dropout | short % mean | min–max | seeds over the 3 % bar |
| --- | --- | --- | --- | --- |
| 4 096 | 0 % | 0.45 | 0.29–0.54 | 0 |
| 4 096 | 10 % | 1.08 | 0.85–1.27 | 0 |
| 4 096 | 30 % | 3.69 | 3.37–4.08 | 8 |
| 324 000 | 0 % | 0.46 | 0.43–0.47 | 0 |
| 324 000 | 10 % | 1.07 | 1.00–1.13 | 0 |
| 324 000 | 30 % | 3.70 | 3.48–3.82 | 8 |

The bar (max over seeds ≤ 3.0 % short at 10 % dropout, `D` = 324 000) holds.

### Figures that live only in documents

Every figure in `ECONOMICS_SIM_PRODUCTION_REBASE.md`,
`ECONOMY_UMBRELLA_PLAN.md`, `FEE_LADDER_DERIVATION.md` and
`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` that is stated as current was
checked against the pin's output. Dated experiment records (a heading with a
date or commit: the rebase doc's §5.x, Appendix A2 and B, the umbrella plan's
§3.1–§4.2, the derivation's §10–§11, the escalation doc's §12.13–§12.14, OQ-1,
A2, A6 and §12.5) are records and were not graded.

**Reproduces, and nothing holds it** (a regression would go unseen):

| Where | Figure | Mode |
| --- | --- | --- |
| rebase doc §2, ESR-9 Landed | FL-E1: 600 cells, 4 not converged, worst 87 bp | `--fee-floor` |
| rebase doc §5.15 | clearing bounds 0.2076, `c ≤ 0.692`, `ρ ≤ 0.661` | `--secret-draw` |
| umbrella §2 row G | 18 of 600 feedback cells, worst 833 bp | `--fee-ladder` |
| derivation §4.7 | c9 divisors ×1.25 / ×6.7 / ×20 | `--fee-ladder` |
| rebase doc §1 (via `ECONOMY_EXPLAINED.md`) | gate-7 lock, 117 coins | `--gate7` |

**Moved** (the document's figure is not what the sim prints):

| Where | Document says | The pin prints | Moved by |
| --- | --- | --- | --- |
| rebase doc finding 1 | long-term median 314–322 KB, then 732–764 KB | 315–324, then 733–765 (PROD growth-gate table) | `0540a6e71`; §5.23 recorded it, finding 1 was not updated |
| rebase doc finding 1 | flat control carries 20 a block for 60 years | 21.0 in year 1, then 20 (FLAT block-space table) | not a move: year 1 was 21.0 at `52b3c73bb` too; the sentence was loose when written |
| rebase doc finding 1 | ordinary transaction 12.6–15.3 KB | 14 256–15 288 B implied by the printed `θ` | walk owed: no mode prints the weight, and 12.6 has no printed source |
| umbrella §2 row 3 | `ρ`'s rise is "two-thirds burn, one-third σ" | 0.625 / 0.375; the rebase doc's own finding 2 says three-fifths / two-fifths | walk owed: ESR-9 re-measured the decomposition and this row was not updated with it |
| escalation doc §12.4.1, A4 row | at most 3.07×, `fee×→1` 0.0→7.7 | 3.0304, 0.0→7.5 (PROD) | `0540a6e71` (the figures were written at ESR-9 against the pre-#1152 fixture) |
| escalation doc §12.4.1, A5 row | ~6.9 KB opening | 6 784 B (PROD; const-asserted at `rust/shekyl-economics-sim/src/proxy.rs:105`) | rounding in the row |
| escalation doc §6 / §8 / §12.6 / §12.11.1 (live prose) | 13.6 GB held; ~3 KB opening; A6 slew 1.41 / 2.82 pts and 114×; `q*` 0.098–0.278; §12.6 `margin < 0` at every fetch price | 12.3 GB; 6 784 B; 0.0504 / 0.1008 pts and ≈ 11.9×; `q*` 0.105–0.271; margin +0.003660 at 0.10 $/GB | leaf-era figures, left in the prose when the byte re-key was recorded (`c0e5704b4`) |
| escalation doc OQ-2, OQ-4 (undated live rows) | 16 struck; ROI 0.6671 / 1.1963 | min viable `h` 1; neither arm prints 0.6671 | walk owed: stale before `52b3c73bb`, and these lines have not moved since |
| escalation doc A6 prose | the flood ceiling "falls with depth, pinned in a test" | `flood_ceiling_is_finite_and_nearly_depth_flat` (`rust/shekyl-economics-sim/src/swing.rs:281`) pins the opposite | contradicted by its own test |
| derivation §4.1 | reachable `C` over [0.680, 12.92] | [0.692, 12.917] (`--fee-ladder` line 1) | **the instrument, not the chain** (both ends: the high end is also a grid artefact, see the class below). Bisected (`7c668a460` → `52b3c73bb`) to `783053554` (2026-10-09), which made the genesis block pay no staker share. The sampler takes heights on a year grid (`rust/shekyl-economics-sim/src/fee_ladder.rs:272`): height 0, where `σ` is now 0 and `C` = 0.800, then year 1, where `σ` = 0.135 and `C` = 0.692. Block 1 (`σ` = 0.150, `C` = 0.680 at the 0.8 rail) is never sampled. The chain's low end is still 0.680, as the derivation says |
| derivation §4.6 | tail era 2 097 152 blocks; tail entry years 65 / 73 | 4 194 304 blocks; year ≈ 119 (FL-V7) | the ESF per-block fix (EUP-1, finding A) |
| derivation FL-V1 and §5 | wallet cap 109 226 666 and 220 000 000 | 88 746 666 (asserted at `rust/shekyl-engine-core/src/engine/fee_policy.rs:407`) | walk owed: the derivation's own FL-R28 row already quotes 88 746 666, so the earlier figures are the round's history left in live text |
| umbrella §2 row A | ESF-22 milestone at 5 788 000 blocks | 2 907 270 (JSON) | the ESF per-block fix |
| rebase doc Appendix A2 prose | the first sample lists 24 | 23 (JSON; the A2 update says 23 too) | `5eeb3d3eb` |

**Nothing in the tree takes 0.692 as the chain's low end.** The derivation
quotes 0.680 / 0.68 wherever it reasons from the low end (§1.8, §3, §4.1,
§4.2, §5, §11), which is right for the chain. Its one sentence about the
instrument, §4.1's "the JSON's `c_reachable_min` now prints 0.680 directly",
is what has been false since `783053554`; the sampler fix makes it true
again. The other 0.692 in the tree, `c ≤ 0.692` (rebase doc §5.15,
`ARCHIVAL_SERVE_CREDIT_SPEC.md`), is the secret draw's retry-correlation bound,
a different quantity. The year-1 operating point (`C₀ ≈ 0.70` in
`ESR10_PREDICTIONS.md` §1, `C` = 0.692 at the end of year 1) is the fee level
the chain runs at, not its reachable minimum, and no document uses it as one.

**Cannot be produced** (no mode prints it, or its field is gone):

| Where | Figure |
| --- | --- |
| umbrella §2 row 3 | year-1 ordinary fee ≈ 3.3 SKL, 2.36, "falls 4.9×" (ESF-21; no mode prints a year-1 fee) |
| derivation §4.4–§4.5 (undated live) | dwell 446 / 274 / 464; thin-margin 25 of 800, 2.10×; FL-C7 on the pow2 map (20 cells, 1 177 / 1 161) — the arms were deleted with FL-R21 |
| derivation §4.2 | `genesis_fh_of_the_legacy_transliteration` is cited as the pin for `Fh` = 6 900 000; the test was deleted at `7bcea06e9` |
| escalation doc §12.4.1 A4 build pins | "1-in/16-out" at `FEE_PER_BYTE = 300` (the shape is searched, 8-in / 1-out, and the rate is the relay floor) |

**Text the code contradicts** (not a figure, but a live statement):

- rebase doc line 23 and §4's "A block's weight is its bodies'" row: the
  coinbase is priced and recorded since #1152 (§P0.4).
- `rust/shekyl-economics-sim/src/chain_cursor.rs:70` and Appendix A2 R10:
  "at the bodies' weight" — the cursor prices `filled.block_weight`
  (`rust/shekyl-economics-sim/src/chain_cursor.rs:127`).
- rebase doc §2, "one implementation fact for the re-derived arm", and
  `ESR10_PREDICTIONS.md` §0.2: `medians_from` floors at
  `params.full_reward_zone` since `55d5266a7`
  (`rust/shekyl-chain-rules/src/rules/block_weight.rs:301`). ESR-10's §0.2
  prerequisite has landed.
- `ESR10_PREDICTIONS.md` §1: boom-bust crosses in year 17; the pin prints
  year 15 (PROD growth-gate table).
- `rust/shekyl-economics-sim/src/fee_model.rs:19` says "three places" and
  lists two.
- umbrella §3.2 row b: "batches the penalty-free part … Done". The ruled item
  was the penalty *zone* (§P0.6).

### Instruments that report an extreme from sampled heights

The `--fee-ladder` low end is one case of a class: an instrument reports a
reachable minimum or maximum but evaluates the quantity only at sampled
heights, and misses a height where the economics change. Both sims were
searched for every extreme taken over sampled heights, ages or years, and
each was checked against the heights where a quantity steps or bends:

- genesis, height 0, where the staker share is 0;
- block 1, where it starts at 0.150 (the only true step in `σ`);
- the share's decay: per block, with whole years multiplied by 0.9 and
  interpolated between, so kinks at year boundaries and no steps; integer
  truncation makes it exactly 0 from `1 + 97·BLOCKS_PER_YEAR`;
- tail onset (a kink in the reward, near year 119 on the neutral trajectory
  and year 132 on the fold);
- the growth-gate crossing (year 19 on the baseline), and the tree-depth step
  in `θ` at year 23.

Per-block folds, year sums and parameter sweeps are not the class and were
excluded. What misses a boundary:

| Instrument | Mode | Misses | Effect |
| --- | --- | --- | --- |
| reachable `C`, low end (`rust/shekyl-economics-sim/src/fee_ladder.rs:272`, ages 0/1/4/12/30) | `--fee-ladder` | block 1 | prints 0.692; the chain's low end is 0.680 |
| reachable `C`, high end (same) | `--fee-ladder` | the height where `σ` reaches 0 | prints 12.917 (age 30); the structural maximum, 13.000 (`σ` = 0, `M_r` = 1.3, burn at its 0.9 cap), is the derivation's own FL-R28 figure |
| FL-E2–E4 roll-ups `worst_1block_rise_bp`, `grace_bp_max` (`fee_floor.rs`) | `--fee-floor` | ages past 30 | both rise with every sampled age (rise 160 → 210 bp, grace at G = 3 479 → 634 bp, years 0 → 30), so the printed worst is the grid's edge, not the chain's |
| FL-E1 / FL-C7 tail amplitude | `--fee-floor`, `--fee-ladder` | the tail era | the amplitude grows as the floor falls; the 87 bp and 833 bp are labelled as grid figures, which holds them to the grid |
| the onset horizon, `ONSET_HORIZON_YEARS = 60` (`rust/shekyl-economics-sim/src/onset.rs:87`) | `--stage2` | tail onset | its comment says the tail is reached by year 60 (at a stale 12.5 %/yr); the same file puts it near year 132, so A1-T's "never" and its minima to 60 years are pre-tail readings |
| A5 / TJ `max_per_epoch_skl` (year budget over year-end `n`) | `--stage2` | the in-year crossing of `n` = 4 096 | the printed 226.47 is a lower bound; at baseline year 1 (year-end `n` 22 349) the true maximum is several times larger (derived from the code, not run) |
| OQ-2 `recommend_min_holding` (year-end `n` at year 1, middle, last) | `--stage2` | the same crossing | recommends 2; at `n` = 4 096 the same rule gives 10 (derived from the code, not run) |
| staking sim: windowed worst/peak coverage series (one mid-epoch sample, taken before `process_exits`) | `shekyl-staking-sim` | the post-exit state | the code's own comment says the next epoch's re-acquisition hides it |
| staking sim: shock peaks and troughs | `shekyl-staking-sim` | the shock instant | read after the same epoch's re-seat |

Covered: `--fee-floor`'s per-cell traces (per block; the age-0 trace crosses
block 1, so its own `c_range` low is 0.680), A4's maximum ROI (sampled at the
year's cheapest block before the tail), the growth gate's first crossing
(genesis `ρ` = 1.0 is below `θ`, so height 0 cannot fake a crossing), and the
secret draw.

**A selection defect found by the same search.** A6, OQ-4 and A2 each take
the "steepest candidate" with `max_by_key(|c| c.asymptote)`
(`rust/shekyl-economics-sim/src/swing.rs:157`; `stage2.rs:1545`, `:1773`).
Three candidates share the 90 % asymptote; Rust returns the last maximum,
knee 10 000 000, the shallowest. Measured with the selection corrected to the
smallest knee (an uncommitted probe, reverted):

| Reading | Printed (knee 10 000 000) | Steepest (knee 500 000) | Verdict |
| --- | --- | --- | --- |
| A6 worst slew, penalty-free / at the 2× limit | 0.0504 / 0.1008 pts per epoch | **1.0080 / 2.0160** | **flips**: "no measurable adversarial slew" fails the `< 1.0` gate (`rust/shekyl-economics-sim/src/swing.rs:229`) |
| A6 reorg down-swing | 0.0036 pts | 0.0725 | — |
| OQ-4 ROI, small bonds / capped | 0.0008 / 0.0048 | 0.0076 / 0.0482 | unchanged (below 1) |
| A2 distribution, one column | — | about 4 % higher | unchanged |

The escalation ships flat (asymptote at the floor), so the chain itself has no
slew today. The figures are about the candidate band GF-7 will choose from,
and the escalation doc's §12.4.1 A6 row, §6.0 and §12.11.1 read the shallow
candidate.

---

## P0.2 Change census since ESR-9

First-parent merges from `52b3c73bb` to the pin that touch a crate the sim
builds against (`shekyl-economics`, `-block-template`, `-tx-weight`,
`-archival-retention`, `-chain-rules`, `-wire`, `-units`, `-types`) or
`config/*.json`. Twelve merges; none touches `shekyl-economics`,
`shekyl-tx-weight` or `shekyl-units`. #1096 (PR C, `d2ac8b45d`) is not in the
range: it merged before ESR-9 branched, so ESR-9 was aligned after it.

The sim imports, from the crates in range: `shekyl_chain_rules::{medians_from,
medians_over, median, even_pair_median, EffectiveMedian, tx_volume_span,
tx_volume_window, closed_shards_before}`; `shekyl_block_template::Fill`;
`shekyl_wire::transaction::COINBASE_RESERVE`; from
`shekyl_archival_retention` the draw (`draw_count`, `draw_horizon`,
`draw_target`, `select_draw`), the bond floor, reward arithmetic and timing
constants; from `shekyl_types` `shard_of`, `SHARD_LENGTH`, `COUNTED_DRAWS`
and the weight newtypes.

| Merge | What changed (sim-relevant crates) | Does the sim call it? | Moves a sim figure? | Class |
| --- | --- | --- | --- | --- |
| #1107 `ef1ef0052` | `config/tor_pins.json` | not read | no | not an economics input |
| #1106 `42e103295` | `shekyl-chain-rules` `relay_floor.rs` (the floor window off the view) | not read: the sim prices the floor through `shekyl-economics` | no (`--fee-floor`, `--fee-ladder` byte-identical) | aligned |
| #1113 `24961a9a8` | release journal: `archival-retention` draw/bundle files, `chain-rules` archival delta/slash, `shekyl-types` release/slash | calls the draw functions in `secret_draw.rs`, unchanged in substance | no (`--secret-draw*` identical) | aligned |
| #1114 `1e7bc0148` | frozen membership: `chain-rules` archival close/delta/drawable/slash, bond rules | not read | no | aligned |
| #1123 `79a1c4dfa` | DRS-X arrival path: `chain-rules` alt/substrate, `shekyl-wire` block | not read | no | not an economics input |
| #1138 `3ec540d92` | `config/tor_pins.json` | not read | no | not an economics input |
| #1145 `cc176a881` | CS-1 header path: `chain-rules` header rules, `shekyl-wire` block/sync body | not read | no | not an economics input |
| #1146 `86fdf4199` | SO-D12 count writer: `chain-rules` archival count; `archival-retention` drawable epoch; the sim's `secret_draw_production.rs` runs more than one epoch (`39804d32b`), and two sim tests hold that a later epoch starts from a full shortfall | through production's draw count, as before | no (`--secret-draw-production` identical) | aligned |
| #1152 `11f8fd1f0` | C2-R2 coinbase reserve: `Fill` prices the block with the coinbase; `medians_from` reads the zone from params; `COINBASE_RESERVE` derived; the sim passes the reserve (`0540a6e71`, `e72e5a256`, `a56e12b30`, `5eeb3d3eb`) | yes, through the owner | yes: both narrations and the JSON regenerated; every move since ESR-9 is this merge's (§P0.1) | aligned (one residue, U1 in §P0.4) |
| #1150 `32cfa46cf` | SO-D12 bundle admission: `chain-rules` admission rule, `archival-retention` bundle | not read: the sim models whether a bundle is admitted as behaviour (§4's ESR-13 row) | no | aligned |
| #1148 `1045d90f0` | CS-2 sync model: `chain-rules` header facts/path, `shekyl-wire` transaction | not read | no | not an economics input |
| #1155 `465b77eba` | `config/tor_pins.json` | not read | no | not an economics input |

**#1154 (support draws), in flight.** Open and not an ancestor of the pin. Its
new public items (`support_span`, `support_slot`, `select_support_shard`,
`settle_support`, `SUPPORT_*`, and the rest) have no caller in either sim: the
only hits in `rust/shekyl-economics-sim` and `rust/shekyl-staking-sim` are
comments, and the support-family grep finds no call. The draw functions the
sims do call (`select_draw`, `draw_count`, `draw_horizon`, `draw_target`) are
defined in `archival-retention`'s `secret_draw.rs`, which #1154 does not
touch, and no file under either sim is in its diff. When it lands, the sim
needs nothing. This rests on reading the source, not on compiling the sims
against its head.

---

## P0.3 Constant inventory

Every economic constant a production composition reads, and every constant
the economics sim reads. Class: **P** parameter (should become an
`EconomicParams` field, per the 2026-10-22 ruling), **D** derived, **S**
structural, **U** unit or lattice, **L** an unnamed literal named here so the
sweep can see it. "EP" marks a field `EconomicParams` already has.

### How the configuration reaches the code

- `config/economics_params.json` is generated into
  `shekyl-economics params.rs` (`GENERATED_*`) by `rust/shekyl-economics/build.rs`,
  and into C++ by `cmake/generate_economics_params.py`.
- `config/consensus_constants.json` is read independently by eleven build
  scripts and the C++ generator. The ones that generate the constants below
  are `shekyl-economics` (DAA target, surge, zone, median windows),
  `shekyl-wire` (the zone again, into `MIN_BLOCK_WEIGHT`),
  `shekyl-archival-retention` (bond floor, age weight, timing, failure
  window), `shekyl-engine-core` (a second generated bond floor) and
  `shekyl-types` (shard length, holdings cap).
- `EconomicParams` has 13 fields (`rust/shekyl-economics/src/params.rs:207`):
  `release_min`, `release_max`, `tx_volume_baseline`, `burn_base_rate`,
  `burn_cap`, `staker_pool_share`, `emission_curve_asymptote`,
  `emission_speed_factor_per_block`, `final_subsidy_per_minute`,
  `daa_target_seconds`, `escalation_knee_n`, `escalation_asymptote_share`,
  `full_reward_zone`.
- **Every production composition resolves `EconomicParams::default()`.** The
  validator's `economics()` is a `OnceLock` of the default set
  (`rust/shekyl-chain-rules/src/rules/miner.rs:106`), used by the median, the
  relay floor, the fee ladder and block pricing; the FFI builds the default
  at nine sites in `economics_ffi.rs`; the wallet's `absolute_fee_rate_cap`
  does the same (`rust/shekyl-engine-core/src/engine/fee_policy.rs:85`).
  Production already reads only the default set. A sweep that moves a field
  reaches production only after that resolution point moves.
- A new field changes `params_digest` (`DIGEST_FORMAT_VERSION`, 13 × 8-byte
  preimage in `shekyl-economics digest.rs`), and the C4 fixtures follow.
- The sim's sweep surface is `SimParams` (`rust/shekyl-economics-sim/src/engine.rs:136`):
  `SimParams::economic` writes nine fields and leaves `daa_target_seconds`,
  `full_reward_zone` and the escalation fields at the default.

### Emission, release, burn, split

| Name | Owner | Value | Class | EP | Sim reader | Derivation status |
| --- | --- | --- | --- | --- | --- | --- |
| release rails | `shekyl-economics params.rs:210-211` | 0.8 / 1.3 | P | yes | `SimParams` | "Resolved" by the April sweep (`DESIGN_CONCEPTS.md` §11); that sweep ran on the flat fee and the deleted stake term (umbrella finding E) |
| `tx_volume_baseline` | `params.rs:212` | 50 | P | yes | `SimParams` | provisional, April sweep |
| `TX_VOLUME_WINDOW` | `params.rs:63` | 720 | P | **no** | imports (`volume_window.rs`, `fee_floor.rs`, `fee_ladder.rs`) | form ruled (FL-R24); length owed to EUP-5 §4.2 |
| `emission_curve_asymptote` | `params.rs:216` | 2³² SKL | P | yes | `SimParams` | landmark under FL-R12′ |
| ESF per block | `params.rs:220` | 22 | P | yes | `SimParams` | "Resolved" by the April sweep; fixed at EUP-1 |
| `final_subsidy_per_minute` | `params.rs:221` | 0.3 SKL/min | P | yes | `SimParams` | provisional; size owed to the tail multiple `k` |
| tail multiple `k` | not in code | — | P (criterion) | no | no | owed: §3.2 item 3, §4 tail row |
| `daa_target_seconds` | `params.rs:222` | 120 | P | yes | not swept (`SimParams::economic` keeps the default) | DAA ruling |
| `STAKER_EMISSION_SHARE` | `params.rs:105` | 15 % | P | **no** | imports for A1-L only; the fold uses `emission_share_at` and cannot sweep it | "Resolved" by the April sweep |
| `STAKER_EMISSION_DECAY` | `params.rs:110` | 0.90/yr | P | **no** | A1-L band only | "Resolved" by the April sweep; the sim notes it "was never derived against a bond burden" |
| `BLOCKS_PER_YEAR` | `params.rs:115` | 262 800 | D (365·86 400 / DAA) stated as its own JSON key | no | imports | nothing ties it to `daa_target_seconds` |
| `EMISSION_SPLIT_EPOCH` | `emission_share.rs:40` | 1 | S | no | no | CEN-F21 |
| burn base / cap | `params.rs:213-214` | 50 % / 90 % | P | yes | `SimParams` | "Resolved" by the April sweep |
| `staker_pool_share` | `params.rs:215` | 25 % | P | yes | `SimParams`; also the escalation floor | "Resolved" by the April sweep |
| `escalation_knee_n` | `params.rs:231` | 2 250 000 | P | yes | restated as `KNEE_BAND[1]`, pinned by test | owed to EUP-5 F |
| `escalation_asymptote_share` | `params.rs:235` | 25 % (= floor, flat) | P | yes | swept through `ASYMPTOTE_BAND` | owed to EUP-5 F |

### Fee ladder and relay admission

| Name | Owner | Value | Class | EP | Sim reader | Derivation status |
| --- | --- | --- | --- | --- | --- | --- |
| `RELAY_FLOOR_REFERENCE_TX_WEIGHT` (`w_ref`) | `rust/shekyl-economics/src/fee/floor.rs:44` | 3 000 | P | **no** | imports (`fee_floor.rs`, `fee_ladder.rs`, `fee_model.rs`, `growth_gate.rs`, `calibration.rs`) | inherited; owed to EUP-5 G (FL-R13) |
| `STANDARD_RUNG_OVER_ECONOMY` | `rust/shekyl-economics/src/fee/ladder.rs:22` | 4 | P | **no** | imports (`growth_gate.rs`) | inherited (`Fn = 4·Fl`), kept under FL-R17; no row rules 4 as a number |
| Priority factor 2 in `2·R·C/M` | `rust/shekyl-economics/src/fee/ladder.rs:96` | 2 | L / D | no | through `corrected_fee_ladder` | derived FL-R5: the same 2 as the block-weight limit, not tied in code |
| `RELAY_FLOOR_LOOKBACK` (G) | `rust/shekyl-economics/src/fee/relay.rs:18` | 5 | P | **no** | imports; sweeps 3–5 in `--fee-floor` | ruled FL-R23 |
| `RELAY_FLOOR_WINDOW` | `fee/relay.rs:21` | 6 | D (G + 1) | no | no | derived |
| `RELAY_ADMISSION_SLACK_BP` | `rust/shekyl-economics/src/fee/relay.rs:26` | 0 | P | **no** | imports | ruled (FL-R23 implementation) |
| `FEE_DECIMAL_PLACES` | `rust/shekyl-economics/src/fee/quantization.rs:21` | 6 | P (relay policy) | no | no | FL-R27 ruled where it lives, not its size; inherited from C++ `PER_KB_FEE_QUANTIZATION_DECIMALS` |
| `FEE_QUANTIZATION_MASK` | `rust/shekyl-economics/src/fee/quantization.rs:30` | 1 000 atomic | U (from the above) | no | **not read**: the sim pays unrounded (ESR-15) | FL-R27 |
| `EMISSION_CLAIM_FEE_FLOOR` | `rust/shekyl-economics/src/fee/ladder.rs:19` | 3.6 SKL | D as a literal (the genesis Economy rung × the claim envelope) | no | **not read** (§4's claim row) | no test recomputes it, so it does not follow a `w_ref` or zone sweep |

### Block weight, penalty, limit

| Name | Owner | Value | Class | EP | Sim reader | Derivation status |
| --- | --- | --- | --- | --- | --- | --- |
| full-reward zone | field `params.rs:245`; bare `FULL_REWARD_ZONE` `params.rs:17` | 300 000 B | P | **yes** (read by `medians_from` since #1152) | the bare const in `floor_rate`, `x_served_row`, `standard_units_per_floor_unit`, `degenerate_pins`, the `--fee-floor`/`--fee-ladder` reports and `swing.rs` | owed to EUP-5 G (capacity leg) |
| `BLOCK_WEIGHT_SURGE_FACTOR` | `shekyl-economics block_weight.rs:33` | 4 | P | **no** | imports (`swing.rs`) | ruled C2-R2 Q3 |
| limit multiple 2 | literals at `shekyl-economics emission.rs:132`, `:362`; `rust/shekyl-chain-rules/src/rules/block_weight.rs:133`; `rust/shekyl-block-template/src/fill.rs:137` | 2 | L (P if swept) | no | through the owners | ruled C2-R2 Q4 |
| penalty shape `(2m − c)·c/m²` | `shekyl-economics emission.rs:142` | — | L (shape) | no | through `paid_block_reward` | derived C2-R2 Q4 |
| long-term clamp 1.7 | `shekyl-economics block_weight.rs:54-55` | 1.7 | L (P if swept) | no | through `long_term_weight` | derived C2-R2 Q2 |
| `BLOCK_WEIGHT_LONG_TERM_WINDOW` | `params.rs:30` | 100 000 | P | **no** | imports (`median_window.rs`) | ruled C2-R2 Q2 / CEN-G6 |
| `BLOCK_WEIGHT_SHORT_TERM_WINDOW` | `params.rs:41` | 100 | P | **no** | imports | ruled C2-R2 Q3 / CEN-G6b |
| `COINBASE_RESERVE` | `rust/shekyl-wire/src/transaction.rs:263` | 1 386 B | D (the coinbase grammar's maximum) | no | imports (`block_space.rs`, `miner_stuffer.rs`) | derived, held by `the_maximal_coinbase_weighs_what_the_grammar_sums` |
| `COINBASE_RESERVE_MARGIN` | `rust/shekyl-wire/src/transaction.rs:256` | 0 | P (a stated margin) | no | no | ruled §3.2 item 2 |
| `MIN_BLOCK_WEIGHT` | `rust/shekyl-wire/src/transaction.rs:216` | 300 000 | D: **the zone read from the JSON a second time** | no | no | held equal to the zone by a legacy FFI test |
| `TX_WEIGHT_LIMIT` | `rust/shekyl-wire/src/transaction.rs:273` | 148 614 | D (`MIN_BLOCK_WEIGHT`/2 − reserve), compile-time: **does not follow `params.full_reward_zone`** | no | no | derived C2-R2 Q7; zone leg owed to G |
| `MAX_TX_SIZE` | `shekyl-wire transaction.rs:206` | 1 000 000 | S | no | no | C2-R2 Q6 |
| `REPRICING_PASSES` | `shekyl-economics reward.rs:47` | 10 | S | no | no | inherited |

### Units and lattice

| Name | Owner | Value | Class | Sim reader |
| --- | --- | --- | --- | --- |
| `SCALE` | `params.rs:7` | 1 000 000 | U | imports (ten files) |
| `ATOMIC_UNITS_PER_SKL` | `shekyl-units` build | 10⁹ | U | imports |
| `DISPLAY_DECIMAL_POINT` | `shekyl-units` build | 9 | U | no |
| `CALIBRATION_GENERATION` | `params.rs:139` | 1 | S | imports (`record.rs`) |

### Archival and staking constants the sim reads

| Name | Owner | Value | Class | Sim reader | Derivation status |
| --- | --- | --- | --- | --- | --- |
| `ARCHIVAL_BOND_FLOOR_ATOMIC` | `archival-retention` build (and a second generated copy in `engine-core`) | 0.75 SKL / shard | P | imports (seven files) | owed to EUP-5 I. **Two `const` asserts pin it to 750 000 000** (`archival-retention bond_floor.rs:40`, `engine-core consensus_constants.rs:16`), and a third holds the cover mirror `COVER_RUNG_ATOMIC` equal to it (`engine-core engine/principal_stake.rs:48`), so a JSON-only change fails the build |
| `ARCHIVAL_REWARD_AGE_WEIGHT_MILLI` | `archival-retention` build | 2 000 | P | imports (`population.rs`) | calibration band [1 500, 2 500] |
| `SETTLEMENT_EPOCH_BLOCKS` | `rust/shekyl-archival-retention/src/constants.rs:248`, a hand literal | 10 000 | P | imports (six files) | the JSON key `settlement_epoch_blocks` is digested but read by no generator: two sources, never compared |
| `MAX_CLAIM_AGE_W` | `archival-retention` build | 26 epochs | P | imports | pinned (ARCHIVAL_TIMING_CONSTANTS) |
| `FAILURE_WINDOW_M` / `_N` | `archival-retention failure_window.rs:450`, `:453` | 11 / 13 | P | imports | provisional; owed to EUP-5 H |
| `CHALLENGES_PER_PAIR_PER_EPOCH` | `archival-retention constants.rs:28` | 3 | P | imports | jointly pinned with `COUNTED_DRAWS`; owed to H |
| `COUNTED_DRAWS` | `shekyl-types archival/settlement.rs:22` | 3 | S/P | restated in `secret_draw.rs`, const-asserted equal | ruled with the above |
| `SHARD_LENGTH` (W) | `shekyl-types archival/mod.rs:128` | 3 000 000 B | P (provisional) | imports | SHT-Q2; pins at the Round-2 testnet |
| `MAX_HOLDINGS_SHARDS` | `shekyl-types archival/mod.rs:78` | 4 096 | S | imports | L2 ruled |
| `ARCHIVAL_REORG_DEPTH_BLOCKS` / `D_MAX` | `archival-retention` build; `chain-rules reorg.rs:71` | 720 | P | imports (`swing.rs`) | provisional |
| `ARCHIVAL_PROVISIONAL_CURVE` | `archival-retention reward_arithmetic.rs:120` | plateau 8 000 | S (counterfactual only) | imports (`population.rs`) | retired in production (D3/R2) |

### The sim's own constants that mirror production

| Sim constant | Relation |
| --- | --- |
| `MEMPOOL_TX_LIVETIME_SECS` (`rust/shekyl-economics-sim/src/block_space.rs:31`) | restates the C++ `CRYPTONOTE_MEMPOOL_TX_LIVETIME`, pinned to the header by test; no Rust owner |
| `KNEE_BAND[1]` (`escalation.rs`) | restates the JSON knee, pinned by test |
| `TAIL_FLOOR_BAND[0] = 150_000` (`onset.rs`) | numerically equal to `STAKER_EMISSION_SHARE`, **neither imported nor pinned** |
| `floor_rate` and `x_served_row` | restate the floor formula and `clamped_median` on the bare zone constant; `floor_rate` is pinned to the owner by test |
| control-arm values (`SECTION_12_14_FLAT_FEE_ATOMIC`, `SECTION_12_13_ADMISSION_RATE`) | declared control arm; nothing in the chain charges them |

### Sweep work list

For each parameter that is not yet an `EconomicParams` field, the
production compositions that read it as a bare constant today.

| Parameter | Compositions reading the bare constant |
| --- | --- |
| `w_ref` | `relay_floor_from`, `fee_ladder_from` (`rust/shekyl-economics/src/fee/floor.rs:126`, `:140`); FFI `shekyl_corrected_fee_ladder`, `shekyl_relay_fee_floor`; wallet `absolute_fee_rate_cap`; through them chain-rules `relay_floor_at`, `fee_ladder_at`, `relay_floor_window` |
| `STANDARD_RUNG_OVER_ECONOMY` | `checked_corrected_fee_ladder` (`rust/shekyl-economics/src/fee/ladder.rs:73`), the one function every ladder goes through |
| G (`RELAY_FLOOR_LOOKBACK`) | chain-rules `relay_floor_window`; FFI `shekyl_relay_floor_lookback`; (derived window) FFI `shekyl_relay_floor_admits` |
| `RELAY_ADMISSION_SLACK_BP` | `relay_floor_admits` (`rust/shekyl-economics/src/fee/relay.rs:82`), and through it chain-rules policy, daemon-rpc `fee_clears` / `fee_meets_floor`, the FFI |
| `FEE_DECIMAL_PLACES` | `quantized_fee`, and through it relay admission and the wallet's `tx_fee` |
| `TX_VOLUME_WINDOW` | chain-rules `tx_volume_span` (`rust/shekyl-chain-rules/src/rules/miner.rs:739`); C++ |
| long-term median window | chain-rules `effective_median_at`; C++ |
| short-term median window | chain-rules `medians_over`; `blocks_to_surge_saturation`; C++ |
| surge factor | `effective_median`, reached by `medians_from` and the FFI; chain-ingest `of_long_term`; C++ |
| staker share, decay, `BLOCKS_PER_YEAR` | `emission_share_at`, reached by `compute_emission_split` → `price_emission` (validator and template), `correction_factors_at` (every floor and ladder), `project_at_tip`, two FFI entries; engine-core `parameters_snapshot`; C++ |
| bond floor | `bond_floor_of` and its seven callers (bond post, release, reinstate, bond builder, funding sweep); chain-rules `apply_slash`; engine-core `principal_for_bond_count` through its own copy; two value asserts and the cover-mirror assert; C++ |
| limit multiple 2, clamp 1.7 | four copies of 2 and the Priority 2 (above); `long_term_weight` |
| zone (already a field) | bypassed by `MIN_BLOCK_WEIGHT` → `TX_WEIGHT_LIMIT` (chain-rules `max_tx_weight`, daemon-rpc `gather`, engine-core claim budget), by the C++ macro, by `EMISSION_CLAIM_FEE_FLOOR`, and in the sim by the bare-const readers above |
| archival timing and doctrine (`SETTLEMENT_EPOCH_BLOCKS`, `MAX_CLAIM_AGE_W`, failure window, challenge count, age weight, `SHARD_LENGTH`) | file-level only: 161, 107, 98, 15, 25 and 77 reader lines; a function-level list is Phase 1 work if the sweep takes them |

**The component constants rest on a superseded sweep.** ESF, burn base and
cap, pool share, staker share and decay, and the release rails are
"Resolved" by the April sweep (`DESIGN_CONCEPTS.md` §11). Umbrella finding E
records that sweep as run on the flat 0.10 SKL fee and the deleted stake-ratio
term, to be re-graded at EUP-4. EUP-5's decision list (D, F, G, H, I and the
720 window) does not name them.

---

## P0.4 The sim's declared departures (§4 of the rebase doc), re-checked

| §4 row | Disposition at the pin |
| --- | --- |
| A block's weight is its bodies' | **Closed by #1152**, and replaced by a smaller departure (U1 below). `BlockSpace::fill` passes `COINBASE_RESERVE` to `Fill::empty` (`rust/shekyl-economics-sim/src/block_space.rs:114`), the medians record `fill.block_weight()`, and the cursor prices that weight. Phase 1's first commit deletes the row and declares U1 |
| Fee multiplier on Standard; rung mix; every transaction pays Standard | **ESR-10.** Only `×1` is built outside tests; the pool is one class (`rust/shekyl-economics-sim/src/block_space.rs:52`) |
| Fee paid unrounded | **ESR-15.** `quantized_fee` appears only in a doc comment |
| A claim is one ordinary transaction at the admission rate | **Still needed, and no step is planned.** The owner, `EMISSION_CLAIM_FEE_FLOOR`, exists; the sim does not read it |
| Gate-7 one shard per `blocks_per_shard`; A3/A4 through the plateau curve | **Still needed**; EUP-4 items in `FOLLOWUPS.md` |
| Maturity operands | **Still needed; the row's text is stale.** `MATURITY_D` was deleted with the urn reproduction (`eba3d3822`); the operands are now `EVIDENCE_PAIRS` (`rust/shekyl-economics-sim/src/secret_draw.rs:254`) and `projected_pairs` in `mn_feasibility.rs` |
| Control arm (flat fee; 300 atomic/B); `AdmissionAtShards`; admission rate at the year's last block; empty windows at a mid-chain start; waiting transactions pay the offered block's fee; pool livetime; budget (b) unpenalised; floor enforced in consensus; exogenous terms; floor at `SCALE` resolution; the secret-draw rows (ESR-11, ESR-13); the f64 m-of-n forms; demand does not respond | **Still needed**, each reason re-read at the code. ESR-10's per-rung pool does not close "waiting transactions pay the offered block's fee": it keeps one fee per class, priced at the offered block |

**Departures in the sim that §4 does not list.** §4 says a missing row is a
defect; each needs a row or a reason it is not a departure.

| # | Departure | Where |
| --- | --- | --- |
| U1 | The coinbase is priced at the reserve (the grammar's maximum, 1 386 B), where the template prices the coinbase it built (1 364 B at height 5; the gap narrows as the varints widen) | `rust/shekyl-block-template/src/fill.rs:16`; `rust/shekyl-economics-sim/src/block_space.rs:114` |
| U2 | The engine, budget and recorder folds pass zero closed shards to `price_emission`; only stage-2 passes the byte-fold count. Inert while the escalation ships flat, and guarded by `the_shipped_split_is_flat_at_every_count` | `rust/shekyl-economics-sim/src/engine.rs:283`; `budget.rs:205`; `record.rs:208` |
| U3 | The FL-C7 and FL-E1 feedback instruments run with no fill and a fixed median: all elastic demand is carried and the emission advances unpenalised | `rust/shekyl-economics-sim/src/fee_ladder.rs:434` |
| U4 | The miner-stuffer envelope is one block: its bodies never enter the median or the volume window (the scope is stated only in the rebase doc §5.10) | `rust/shekyl-economics-sim/src/miner_stuffer.rs:334` |

---

## P0.5 Mechanism coverage

| Mechanism | In the sim | EUP-4 needs it? / step |
| --- | --- | --- |
| Emission curve, tail subsidy | through production (`price_emission` → `base_block_reward`) | — |
| Release multiplier, 720-block window | through production (`TxVolume::window`, `tx_volume_span`) | the window's length stress is EUP-5 §4.2 |
| Medians, penalty, limit | through production (`medians_from`, `Fill`) | — |
| Fill rule | through production (`Fill::admit_up_to`) | the penalty zone is walked one body at a time (§P0.6) |
| Standard rung, fee correction, growth gate | through production (`corrected_fee_ladder`, `fee_correction`) | rounding: ESR-15 |
| Burn and its split, staker emission share, net supply, corpus, escalation share | through production (`calc_burn_pct_at`, `compute_burn_split_at`, `emission_share_at`, `CirculatingSupply::derive`, `shard_of`, `staker_pool_share_at`) | — |
| Secret draw | through production (`draw_count`, `draw_horizon`, `select_draw`); behaviour modelled | — |
| Escalation band | design: a sweep (`escalation.rs`) | the live-escalation run (F) |
| Floor enforcement arms, ESR-7 envelope | design, priced through production (`miner_stuffer.rs`) | — |
| Reward division, gate-7 lock, stake schedule | design (`redistribution.rs`, `distribution.rs`, `ArchivalLockModel`, `scenarios.rs`) | gate-7 on the byte fold: EUP-4 |
| Fee multiplier | design arm, only `×1` run | yes (capacity, usability): ESR-10 |
| Rung mix; per-rung pool | **not modelled** (one-class pool) | yes: ESR-10, after `ESR10_PREDICTIONS.md` §0.1's pool |
| Staking coupling (purse into the staking sim) | **not modelled**: the staking sim takes its purse by hand | yes: EUP-3 |
| Challenge egress against the budget (H) | **not modelled** here (the staking sim has `--f34-calibrated`) | yes: EUP-3 |
| Tail criterion: per-block fee revenue, median and variance, to ≈ year 135 | **not modelled**; the sim prints yearly sums and a decade-sampled mean fee | yes: **no step builds it** |
| Emission-gain stuffing at the window's edge | **not modelled** (scenario 4's fake volume is ordinary demand) | yes (goal 5 is graded at EUP-4), but it is placed at EUP-5 §4.2: **a sequencing gap** |
| Demand elasticity, wallet rung escalation | not modelled, declared out | no: the wallet does not escalate, and the criteria read fixed demand schedules |

---

## P0.6 What blocks the long arms: performance

**Measured at the pin.** Each cell is one fold of one scenario through
`stage2::a1_year_aggs` with its `sim_years` raised to the horizon, timed by
an uncommitted probe test (reverted). Umbrella §4.1's 64 / 337 / 500 s were
taken on the flat control with a knob that was not recorded (the likeliest is
`ONSET_HORIZON_YEARS`, `rust/shekyl-economics-sim/src/onset.rs:87`), so the
comparison with them is approximate. A run was stopped at 1 200 s (exit 124, a
timeout, not a crash). One run per cell.

| Scenario | production, 60 y | production, 135 y | flat control |
| --- | --- | --- | --- |
| baseline_steady_state | 11 s | 37 s | 135 y: 41 s (§4.1: 64 s) |
| boom_bust_cycle | 12 s | 38 s | — |
| sustained_growth | 14 s | **> 1 200 s** (63 y: 33 s; 66 y: 27 s; 80 y: 63 s) | 60 y: 11 s; **63 y: 273 s** (§4.1: 337 s); **66 y: > 1 200 s** (§4.1: > 500 s); 135 y: > 1 200 s |
| stuffing_attack | 13 s | 41 s | — |
| stake_concentration | 24 s | 43 s | — |
| mass_unstaking | 11 s | 42 s | — |
| chain_bootstrap | 13 s | 48 s | — |
| late_chain_tail | 20 s | 72 s | — |
| high_history_low_activity | 18 s | 41 s | — |

**Reading.** Every scenario but sustained growth reaches 135 years in about a
minute on either arm, so the 135-year arms are affordable except for growth.
Growth blows up once its demand outgrows the penalty-free room: from year 61
on the flat control, and somewhere past year 80 on production, whose blocks
grow later. That is the shape umbrella §4.1 recorded and attributed to
`Fill::admit_up_to` offering the penalty zone one body at a time (not profiled
here). #1152 did not change it. **The closed form is still needed** for any growth arm past
year 80 on production or year 61 on the flat control.

**The closed form approved on 2026-10-05 was never built.** The ruling
(`82ad0876e`) approved "`Fill::admit_up_to` batches **the penalty zone**,
held to the single-offer walk". `1f7718f2e` (2026-10-22) restated umbrella
§3.2 row b as "batches **the penalty-free part** … Done", which is what the
code already did on 2026-10-04. The loop at
`rust/shekyl-block-template/src/fill.rs:242` still walks the penalty zone one
body at a time; `admit_up_to_is_the_single_offer_walk`
(`rust/shekyl-block-template/src/fill.rs:302`) pins the free-part batch
against the walk and does not cover a zone batch. No 135-year arm exists: every
horizon caps at `ONSET_HORIZON_YEARS = 60`
(`rust/shekyl-economics-sim/src/onset.rs:87`).

The parity test the closed form owes: for every offered count, weight and fee
on a grid spanning the penalty-free part, the penalty zone and the 2× limit
(including the coinbase operand and fees that do and do not cover the
marginal penalty), `admit_up_to(w, f, n)` returns the same count, block weight
and fees as `n` single offers of `admit(w, f)`.

---

## P0.7 The settings to derive, each mapped to an instrument

The default mode runs each scenario to its own length (2–60 years);
`--stage2` extends every scenario to 60 years. The growth-gate table prints
on the production arm only; the fee-horizon closed form on the control arm
only.

| Setting | What decides it | Exists today | Missing → step |
| --- | --- | --- | --- |
| **G** zone and `w_ref` (FL-R13) | the year blocks first carry demand and the growth-gate operands under the inherited and a re-derived (zone, `w_ref`) pair; FL-V12's rate resolution against the 50 bp bar | BLOCK SPACE (`onset_report`) and the growth gate (`growth_gate::write_report`, production only) in `--stage2`; `--fee-ladder` labels the FL-V12 cells; `--fee-floor`. Inherited pair only | a re-derived arm: **ESR-10** (`w_ref` is a constant in five sim files; `--fee-ladder` hard-codes the zone). Floor-basis options and a resolution read over the run's own states: **parameter sweep** |
| **D** floor in consensus (C2-R2 Q9) | ESR-7's cheapest archival byte, floor unenforced vs enforced, per era | `miner_stuffer::print_envelope` in `--stage2`, both arms | four rows only, and the row labelled "tail" is year 45 while the emission tail arrives near year 119: true tail rows need the 135-year horizon (**EUP-4 prep**) |
| tail multiple **`k`** | per-block fee revenue, median and variance, to ≈ year 135 | yearly sums (`A1YearAgg`) and a per-transaction mean fee at y10–y60 | the per-block distribution and the horizon: **EUP-4 prep**, after the zone closed form |
| **F** knee and GF-7 asymptote | A1 clearance per candidate; A4 and A5; the knee band by its definitions on an uncapped chain | `print_escalation_family`, `a1_clearance_report`, A1-T and A1-L (`onset.rs`), `a4_stuffing_report`; the band is printed only by a test | no run with the escalation live (the ledger is flat); the band needs the uncapped chain (**ESR-10**) and its 135-year high (**EUP-4 prep**) |
| **I** bond floor | A1 with a reward-proportional principal beside the fixed one; TJ-4 / TJ-7; the staking population fed this sim's purse | A1 burden at 0.75 × R6 × n × rate; A1-L; `cartel::tj_inequalities_report`; `--gate7` (≈ 900× low) | no reward-proportional arm (**EUP-4 prep**); the purse coupling (**EUP-3**) |
| **H** challenge doctrine | L19i egress against `budget(E)` | only in the staking sim (`--f34-calibrated`) | egress as a burden term: **EUP-3** |
| 720-block window (umbrella §4.2) | step response, sub-window boom/bust, an edge-timed stuffer | the window is imported with no length knob; step response is a unit test | per-block traces, step and surge schedules, edge stuffer: **EUP-4 prep** |
| fee lattice size | the lattice step as a fraction of the ordinary fee, against a bar | `FEE_DECIMAL_PLACES = 6`, inherited; the sim does not round | rounding: **ESR-15**; a step-over-fee column: ESR-15 or the sweep. From PROD, the ordinary fee falls to 0.0001 SKL by y30–y60, where one 1 000-atomic step is 100 bp, above the 50 bp bar G uses |

---

## P0.8 The assessment criteria: is each measurable today?

Goals 1 and 4 are code properties and are not graded by the sim. No values
are proposed here.

| Criterion (umbrella §4) | Output, horizon, arms | Exists? | Gap → step |
| --- | --- | --- | --- |
| 2. Security budget | default `YearSnapshot.miner_income_pct_of_no_share` | **partial**: miner emission over paid reward at the year's last block, **excluding kept fees**, though the row reads "reward + kept fees"; no tail-era share | income with kept fees, tail era: **EUP-4 prep** |
| 3. Predictability | default `supply_emitted_pct`, `release_multiplier` | **partial**: only two scenarios reach year 11 and one year 25; no crossing-year column; the multiplier is a last-block sample | every scenario to ≥ 26 years, a crossing year, in-year min/max: **EUP-4 prep** |
| 5. Demand-responsive | multiplier and burn under step, boom/bust and stuffing; window step response; edge stuffer | **partial**: year-end values; step response is a unit test; no edge stuffer | the §4.2 instrument: **EUP-4 prep** |
| 6. Self-regulating | (a) staker yield; (b) A1-T flat-25 at 10 % by decade, and onset; (c) coverage | (a) exists but divides by the deleted stake-ratio term (finding E); (b) **exists**, both arms; (c) only in the staking sim | **EUP-3** |
| Capacity | BLOCK SPACE, growth gate | **exists** on the inherited pair | the re-derived pair and the rung mix: **ESR-10** |
| Usability | mean ordinary fee (`onset.rs`) | **partial**: from year 10, unrounded, a mean | years 1–9: **EUP-4 prep**; rounding: **ESR-15**; rung mix: **ESR-10** |
| Tail | per-block fee revenue to ≈ year 135 | **missing** | **EUP-4 prep**, after the zone closed form |
| Stuffing | `print_envelope`, today / fixed vs relay | **partial**: SKL per shard, not floors per byte; four rows; "tail" is year 45 | every scenario, a floors-per-byte column, true tail rows: **EUP-4 prep** plus the horizon |

---

## P0.9 The plan, re-sequenced, and the questions

**The order in the brief** (`claude/ESR15_ESR10_BRIEF.md`, as relayed):
ESR-15 with the unified fee loop; the parameter sweep; ESR-10; EUP-4 prep
(the zone closed form, gate-7 on the byte fold, the 135-year arms); EUP-4.
The brief itself is not on this machine or in the repository; §A.2a's seven
properties and the order are taken from the relay.

**Phase 0 keeps that order and adds a step in front of it.** Each step is its
own PR, predictions first, fresh clone last.

0. **Truth commit** (Phase 1's first). No committed fixture moves: documents,
   declarations, one instrument fix and the tests that hold quoted figures.
   - Delete §4's "bodies' weight" row; declare U1–U4 or state why each is
     not a departure; restate the maturity row.
   - Bring every live sentence §P0.1 lists as moved or contradicted to the
     pin's output, or move it under a dated record.
   - `ESR10_PREDICTIONS.md`: §0.2 has landed (say so); boom-bust crosses in
     year 15; the operands P2 reads (`ρ` 0.879, `θ` 1.188) are unchanged.
   - The ESR-15 row reads "before ESR-10 runs": ESR-10's predictions are
     already registered (`ca95d9997`).
   - Umbrella §3.2 row b names what was built and leaves the zone closed form
     open.
   - The grid-sampled extremes in this lane's sim (the class above) take
     the boundary heights: `--fee-ladder`'s reachable `C` samples block 1
     and the height where `σ` reaches 0 (its range becomes [0.680, 13.000]);
     the `--fee-floor` roll-ups gain ages past 30 or say "to year 30";
     the onset horizon's comment states the tail year. No fixture holds
     those modes. The A5/TJ maximum and OQ-2 move the `--stage2` fixture and
     go with step 0b. The staking-sim rows go to EUP-3 as findings.
   - Give the document-quoted figures a hold. The A4 row written at ESR-9
     was stale four days later, the narration fixtures are held only by the
     nightly lane, and five figures above reproduce with nothing holding
     them. A non-ignored test asserts the headline values the design leans
     on: the growth-gate operands ESR-10's P2 reads (`ρ` and `θ` in year 1,
     the crossing year), FL-E1's counts, the secret draw's clearing bounds,
     the gate-7 lock.
   - *Predictions owed:* none. Every fixture byte-identical; the new tests
     pass on the pin's output.
0b. **Instrument corrections that move the fixtures.** The steepest-candidate
   selection (A6, OQ-4, A2) and the in-year `n` = 4 096 crossing (A5/TJ,
   OQ-2). The escalation doc's A6 readings follow the corrected run.
   - *Predictions owed:* the selection's are measured above (A6 to 1.0080 /
     2.0160 / 0.0725 pts and its verdict flips; OQ-4 to 0.0076 / 0.0482; A2
     one column about 4 % up); the crossing's: A5/TJ's maximum rises, OQ-2
     recommends more than 2.
1. **ESR-15: one fee loop over a pricing function**, judged against §A.2a's
   seven properties (never under-pays, least, bounded over-payment, exact,
   fails closed, terminates by agreement, one lattice on both sides).
   - *Predictions owed:* the fixture lines that move and by how much; that no
     onset year, no crossing year and no A1 verdict moves; the
     `--fee-floor` / `--fee-ladder` outputs, which do not round today.
2. **The parameter sweep** (§B.3a of the brief), with the guard that
   production reads only `EconomicParams::default()` and a gate that holds it.
   - Scope from §P0.3: which non-fields become fields, which bare-constant
     readers in the sim move to the field, and what happens to the digest and
     the C4 fixtures.
   - *Predictions owed:* every default-valued sweep cell equals the default
     report byte for byte; the sweep's own falsifier per parameter.
3. **ESR-10**, the multi-class pool (`ESR10_PREDICTIONS.md` §0.1) first, then
   both constant arms. #1152 delivered the one-zone reader (C2-R2 R3), so the
   re-derived arm needs only `w_ref` as a parameter, which step 2 provides.
   - *Predictions owed:* the registered set, amended against the post-#1152
     fixture before the run (year-1 operands unchanged; boom-bust year 15).
4. **EUP-4 prep**, from §P0.6–§P0.8:
   - the penalty-zone closed form with the parity test above;
   - the 135-year horizon arms;
   - per-block fee revenue (median, variance) for the tail criterion;
   - the window-edge stuffer and step/surge traces;
   - gate-7 on the byte fold; A3 and A4 on linear work;
   - miner income with kept fees;
   - the predictability columns;
   - true tail rows and a floors-per-byte column in the stuffer envelope;
   - a reward-proportional bond arm.
   - *Predictions owed:* the closed form changes no output byte (it is a
     speed-up); each new instrument states its expected reading before its
     first run.
5. **EUP-4**, graded against the criteria Rick ratifies.

### Questions for Rick

Only what Phase 0 could not settle from code and the design.

1. **Where does `claude/ESR15_ESR10_BRIEF.md` live?** It is not on this
   machine or in the repository, and its §B numbering does not match
   `ESR10_PREDICTIONS.md`'s §0–§5. Steps 1–3 read it.
2. **How far should the parameter sweep reach into production?** Production
   already resolves the default set through one `OnceLock` in the validator,
   nine FFI sites and the wallet cap. Several parameters are not fields at all
   (`w_ref`, the windows, the surge factor, G, the slack, the fee decimals),
   promoting one moves the params digest and the C4 fixtures, and the bond
   floor is pinned by two `const` asserts and mirrored by the cover rung. What should the sweep vary in
   production, and what only in the sim?
3. **What should hold the constants that have two sources?** The zone reaches
   `TX_WEIGHT_LIMIT` through `MIN_BLOCK_WEIGHT` from the JSON, not from the
   field. `settlement_epoch_blocks` is digested but the code uses a hand
   literal. `BLOCKS_PER_YEAR` is its own key, not derived from the DAA target.
4. **What re-derives the component constants** (ESF, burn base and cap, pool
   share, staker share and decay, release rails)? They are "Resolved" by an
   April sweep that finding E retired, and EUP-5's list does not name them.
5. **Who builds the penalty-zone closed form, and when?** The approved item
   was restated as done. The 135-year growth arms wait on it.
6. **Which step owns the instruments no step builds today:** the tail
   criterion's per-block fee distribution, and the window-edge stuffer that
   EUP-4 grades but EUP-5 §4.2 owns?
7. **Where is the open ruling on the fee lattice's size recorded?** The brief
   calls it open from ESR-15's §A.2a; no document on `dev` holds it, and the
   6 decimals are inherited from the C++ header.
8. **What does §6.0's no-swing claim require of the GF-7 candidate band?**
   On its steepest candidate, a flood moves the share 1.008 points an epoch,
   and A6's verdict flips. The band, the gate (`< 1.0` point an epoch) and
   §12.11.1's structural closure were all read on the shallowest candidate.
9. **What should the sim charge for an emission claim?** §4's claim row has
   no planned step, and `EMISSION_CLAIM_FEE_FLOOR` is a literal that does not
   follow a `w_ref` or zone change.
