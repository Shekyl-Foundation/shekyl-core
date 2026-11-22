# CEN-I4 — deriving the transaction input cap (`ICD-`)

**Status:** OPEN — Round 0 RULED IN PART (Rick, 2026-11-22), docs only.
Consensus surface: the design is ruled here before any code moves, then one
rule-07 cutover PR moves every consumer together. Identifier family `ICD-`
(registered in [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2):
`ICD-R*` rulings, `ICD-F*` findings, `ICD-Q*` questions for Rick.

**Ruled before this round (`ICD-R0`, Rick, 2026-11-22):** CEN-I4 is derived in
its own lane before genesis, and the answer is a derived constant, not a
chosen number.

**Ruled in this round (§9):** `ICD-R1` the weight model moves into
`shekyl-wire` and the cap is computed there; `ICD-R2` the generator counts are
derived from the cap; `ICD-R3` the maximum tree depth is derived here;
`ICD-R4` relay verification gets its own round in the relay lane; `ICD-R5` one
named floor device for every embargo cell. **Handed to EUP-5 G (§10):**
`ICD-Q6`, `ICD-F15`. **Still open (§11):** `ICD-Q1` whether CEN-I4 stays an
explicit rule; `ICD-Q3` the snap to a padding boundary; `ICD-Q5` the coupling
to EUP-5 G's weight limit; `ICD-Q7` the maximum tree depth; the standoff
reserve's value; the cover carrier's fragment count.

## 0. What the cap is, and why it is decided now

`MAX_INPUTS = 8` has no derivation. Its only stated reason is the inherited
comment *"bounds proof gen time and tx size"* (`rust/shekyl-fcmp/src/lib.rs:40`).
Raising or deleting a consensus cap widens what consensus accepts: free before
genesis, a hard fork after. The concrete pressure is a miner or staker
consolidating many coinbase-sized outputs. At a cap of 8, merging 1 000 outputs
into one takes ⌈999 / 7⌉ = 143 transactions; at 22 it takes ⌈999 / 21⌉ = 48.

The round takes the cap's possible jobs one at a time (§3 to §6), derives the
number from the weight model (§2), lists every consumer that moves with it
(§7), and records Rick's rulings (§9) and what is still open (§11).

**Answer in one paragraph.** The derived maximum is **22**: the largest input
count the transaction weight limit admits at the lightest legal shape, reached
at tree depths 2, 3 and 4 (§2.3). It is computed at compile time in
`shekyl-wire` from the weight model, whose proof-size term is the closed form
instead of an 8-row table (§2.1, `ICD-R1`), and the generator counts are
derived from it exactly (`ICD-R2`). The cap bounds no relay work worth keeping
a consensus rule for: the relay verifies received transactions on the
transport runtime's two workers, and a clearnet flood of invalid ones already
outruns them at today's 8, so the relay lane designs that bound in its own
round (§4, `ICD-R4`). It does move
the worst block's verification time a little, through the proof's padding,
and the GAP-7 sweep has to be re-run at the new shapes (§3). One large
consolidation discloses less than a burst of capped ones (§6).

## 1. Ground, and where the brief and the code disagree

Reviewed at **`27a832cf81`** (`dev`, 2026-11-22).

The brief was checked anchor by anchor. Where it and the code disagree, the
code wins:

- **`ICD-F1` — the weight limit is 148 614, not 149 400.**
  `shekyl_wire::transaction::TX_WEIGHT_LIMIT` is `MIN_BLOCK_WEIGHT / 2 −
  COINBASE_RESERVE` = 300 000 / 2 − 1 386 (`rust/shekyl-wire/src/transaction.rs:237`).
  The census row CEN-H3 already says 148 614. The 149 400 in the brief and in
  `docs/completed/CHAIN_RULES_SLICE_6.md` §5.4 predates the derived coinbase
  reserve. Slice 6's conclusion (22 inputs) still holds: §2.3 re-derives it.
- **`ICD-F2` — the generators admit 85 inputs at depth 24, not about 95.**
  The 95 is 65 536 / 683, the Selene side alone. The Helios side binds first:
  24 layers need 12 × 32 = 384 Helios rows per input, and 85 × 384 = 32 640 ≤
  32 768 < 86 × 384 (§2.4).
- **`ICD-F3` — the slice 6 analysis lives in `docs/completed/`**
  ([`../completed/CHAIN_RULES_SLICE_6.md`](../completed/CHAIN_RULES_SLICE_6.md)
  §5.4), not `docs/design/completed/`.
- **`ICD-F4` — the embargo table pins 4 cells in-tree, not 48.**
  `shekyl-relay-privacy`'s `SPEC_VERIFY_COST` populates the four corners
  (1 and 8 inputs at depth 2 and depth 7); the other 44 are owed
  (`docs/FOLLOWUPS.md`, "Relay: populate the 48-cell Pi verification surface").
  Its depth axis is depth 2 to 7, not to `MAX_TREE_DEPTH`.
- **`ICD-F5` — the floor's verification figures have moved since slice 6.**
  Slice 6 measured 621 ms for an 8-input spend at depth 3 on the floor; the
  embargo table's door sequence is 425.86 ms at depth 2 and 818.56 ms at
  depth 7, with the range proof now batched (18.8 ms instead of 34.9 ms). The
  relay arithmetic in §4 uses the table's figures and states the depth.
- **`ICD-F6` — the lightest legal tree depth is 2.** `layer_count_for_leaves`
  returns 1 only for an empty tree, which has nothing to spend
  (`rust/shekyl-fcmp/src/tree.rs:393-409`). A spend proves under at least two
  layers.

## 2. The derivation

### 2.1 The weight model can be evaluated past 8, and the closed form is exact

The weight model's owner is `shekyl-tx-weight` (`predict_weight`,
`rust/shekyl-tx-weight/src/lib.rs:369`). The fee path, the economics sim and
the P-lane ceiling all read it, and its weight gate
(`rust/shekyl-tx-weight/tests/weight_gate.rs`) pins it byte-exact against what
the builder emits. Two things stop it answering past 8 today:

- its proof-size term reads `FCMP_PROOF_SIZE_KAT`, a measured table of 8 × 24
  cells, const-asserted to `MAX_INPUTS + 1` rows
  (`rust/shekyl-tx-weight/src/lib.rs:191`, `:234`);
- `InputCount` clamps to `1..=MAX_INPUTS`, and nothing in the model is a
  `const fn`.

**`ICD-F7` — the proof size is a closed form, and it equals the table.**
`shekyl_fcmp_proofs::FcmpPlusPlus::proof_size(inputs, layers)`
(`rust/shekyl-fcmp-proofs/src/lib.rs:247`) computes it from the circuit's
shape: the membership proof's padded row counts (`Fcmp::ipa_rows`, a `const
fn`) plus `Input::PARTIAL_WIRE_SIZE + SpendAuthAndLinkability::WIRE_SIZE`
(96 + 384 bytes) per input. Evaluated in Rust, it matches all 192 measured KAT
cells exactly. Past 8 it was checked against real proofs: 14 transactions of
1 to 22 inputs, 10 of them past 8, built through the production builder over
real depth-2 and depth-3 trees with the caps lifted in a scratch build, every
proof's length equal to the closed form (§2.5). The table is therefore a set of test vectors
for the closed form, not a source of its own.

### 2.2 The lightest legal shape

The cap is a closed-domain maximum, so every ambiguity resolves toward the
lighter shape. A maximum set too low becomes the rule by accident.

- **Signer:** solo. A multisig input carries a group key blob and `m`
  signatures, which is heavier.
- **Outputs:** 2. CEN-I1 requires at least two outputs on every non-coinbase
  transaction, bond posts and emissions included (`I1`'s scope is
  `TxScope::NonCoinbase`, `rust/shekyl-chain-rules/src/rules/tx_inputs.rs:66-75`).
- **Fee:** a 1-byte varint. Consensus sets no fee floor (CEN-M3 is policy).
- **Depth:** every legal depth, 2 to 24. Proof size is not monotone in depth,
  so no depth is assumed to be the argmax.
- **Input kind:** `ToKey`. CEN-I4 counts the whole `vin`, but CEN-H6 allows at
  most one archival input (a bond post or an emission) per transaction, beside
  key-imaged spends only. A bond-post input carries its canonical-length hybrid
  public key (CEN-J11, `rust/shekyl-chain-rules/src/rules/tx_inputs.rs:366`),
  so it is over 2 000 bytes, and its `pqc_auths` slot carries that same key
  again (CEN-J13, `rust/shekyl-chain-rules/src/rules/tx_bond.rs:476`) with a
  hybrid signature, 5 389 bytes. Together that is more than any slack below
  (6 054 bytes at most), so it cannot be a 23rd input.
  An emission input carries a membership-only backing proof and is larger still.

### 2.3 What the weight limit admits, per depth

Weight is monotone in the input count at every depth. `N(d)` is the largest
`n` with `predict_weight(n, 2, d, 0) ≤ TX_WEIGHT_LIMIT`; the weights past 8 use
the closed-form proof size, and the model was checked equal to the Rust
`predict_weight` on all 384 cells it can evaluate today.

| depth | N(d) | weight at N | slack (bytes) |
| ---: | ---: | ---: | ---: |
| 2 | **22** | 142 560 | 6 054 |
| 3 | **22** | 145 632 | 2 982 |
| 4 | **22** | 148 512 | 102 |
| 5 | 21 | 143 920 | 4 694 |
| 6 | 21 | 147 248 | 1 366 |
| 7 | 20 | 143 232 | 5 382 |
| 8–9 | 20 | | |
| 10–11 | 19 | | |
| 12–15 | 18 | | |
| 16–19 | 17 | | |
| 20–23 | 16 | 148 608 at 23 | 6 at 23 |
| 24 | 15 | 141 776 | 6 838 |

**The derived maximum is `max_d N(d)` = 22**, reached at depths 2, 3 and 4. At
depth 5 and deeper the weight limit binds below it, so the per-depth limit a
wallet meets is `N(d)`, which the wallet already computes through the same
weight model. The slack at depth 4 (102 bytes) holds any realistic fee varint;
the 6 bytes at depth 23 hold a fee up to a 7-byte varint, about 562 000 SKL.

### 2.4 The generators: today's table, and the derived count (`ICD-R2`)

Today the FCMP generators are built for `MAX_FCMP_INPUTS = 128` inputs at
`MAX_FCMP_LAYERS = 12` (`rust/shekyl-curve-generators/src/lib.rs:136`, `:149`),
which is 65 536 Selene rows and 32 768 Helios rows. The same `ipa_rows` gives
the largest input count those rows prove at each depth: 160 or more up to depth
12, 154 at 13, 93 at 23 and 85 at 24 (the Helios side binds). A proof that
needs more fails cleanly with `FcmpError::NotEnoughGenerators`; it does not
truncate. Nothing checks the table against the cap today.

Under `ICD-R2` the table is sized to the need, exactly: per curve, the largest
`ipa_rows(N(d), d)` over every legal depth. At today's weight limit and
`MAX_TREE_DEPTH = 24` that is 16 384 Selene and 8 192 Helios rows (both at
depth 24); at a maximum depth of 12 (`ICD-Q7`) it is 8 192 and 4 096. The
python model of `ipa_rows` used for these tables matches the Rust `const fn`
on all 3 840 cells it was compared on (1 to 160 inputs, depths 1 to 24).

Note the name collision: `shekyl_curve_generators::MAX_FCMP_INPUTS = 128` is the
generator sizing inherited from upstream and is not the consensus cap
`shekyl_wire::transaction::MAX_FCMP_INPUTS = 8`.

### 2.5 The proof pads to a power of two of rows, and the cost follows the padding

`Fcmp::ipa_rows` pads each curve's row count to the next power of two, with a
floor of 256 Selene and 128 Helios rows. The padding boundaries fall at
different input counts at each depth:

| depth | rows step at n = (Selene, Helios) |
| ---: | --- |
| 2 | 3 (512, 128); 5 (1 024, 256); 9 (1 024, 512); 10 (2 048, 512); 17 (2 048, 1 024); **19 (4 096, 1 024)**; 33 (4 096, 2 048); 37 (8 192, 2 048) |
| 3 | 2; 4; 5; 7 (2 048, 256); 9 (2 048, 512); **13 (4 096, 512)**; 17 (4 096, 1 024); 26 (8 192, 1 024) |
| 7 | 2; 3; 4; 6; 8 (4 096, 1 024); 11 (4 096, 2 048); 16 (8 192, 2 048); **22 (8 192, 4 096)**; 31 (16 384, 4 096) |
| 24 | 2; 3; 6 (8 192, 4 096); 11 (8 192, 8 192); 12 (16 384, 8 192); **22 (16 384, 16 384)**; 24 (32 768, 16 384) |

The proof's bytes barely notice a boundary (two group elements per doubling).
Verification time notices it a great deal.

**Measured, x86** (i9-11950H, release, rustc 1.95, 2026-11-22; `shekyl-wire`'s
`input_cap_cost` with both caps lifted to 24 in a scratch build, never
committed; proof verification the median of 7 runs, the other terms one run).
This is the diagnostic arm. The floor's values are in §2.6.

| depth | n | rows | tx bytes | proof bytes | verify (total) | of which proof | µs per weight byte | prove |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | 1 | 256 / 128 | 13 200 | 4 512 | 23.9 ms | 22.1 ms | 1.81 | 0.49 s |
| 2 | 8 | 1 024 / 256 | 58 784 | 11 904 | 71.5 ms | 68.1 ms | 1.22 | 2.15 s |
| 2 | 16 | 2 048 / 512 | 107 425 | 16 896 | 130.1 ms | 125.0 ms | 1.21 | 4.01 s |
| 2 | 17 | 2 048 / 1 024 | 112 913 | 16 928 | 148.3 ms | 143.1 ms | 1.31 | 4.43 s |
| 2 | 18 | 2 048 / 1 024 | 119 105 | 17 664 | 152.2 ms | 145.7 ms | 1.28 | 4.56 s |
| 2 | 19 | 4 096 / 1 024 | 123 953 | 17 056 | 207.0 ms | 201.5 ms | 1.67 | 5.57 s |
| 2 | 22 | 4 096 / 1 024 | 142 529 | 19 264 | 216.5 ms | 210.3 ms | 1.52 | 6.02 s |
| 3 | 1 | 256 / 128 | 13 584 | 4 896 | 24.3 ms | 22.5 ms | 1.78 | 0.51 s |
| 3 | 8 | 2 048 / 256 | 58 720 | 11 840 | 100.2 ms | 96.9 ms | 1.70 | 2.68 s |
| 3 | 12 | 2 048 / 512 | 83 936 | 15 232 | 120.6 ms | 116.6 ms | 1.44 | 3.63 s |
| 3 | 13 | 4 096 / 512 | 89 168 | 15 008 | 179.8 ms | 174.7 ms | 2.02 | 4.66 s |
| 3 | 16 | 4 096 / 512 | 108 385 | 17 856 | 194.6 ms | 189.6 ms | 1.80 | 5.28 s |
| 3 | 17 | 4 096 / 1 024 | 113 873 | 17 888 | 214.7 ms | 209.5 ms | 1.88 | 5.77 s |
| 3 | 22 | 4 096 / 1 024 | 145 601 | 22 336 | 228.3 ms | 221.9 ms | 1.57 | 6.65 s |

(The test's hand-assembled transaction is a constant 31 bytes lighter than
`predict_weight`'s at every cell; the per-byte column divides by the model's
weight, which is what the builder's transactions weigh.)

What this shows:

- **`ICD-F8` — a Selene step costs 38–50 %, a Helios step 10–14 %.** At depth 2,
  18 → 19 inputs takes the proof from 146 ms to 201 ms; at depth 3, 12 → 13
  takes it from 117 ms to 175 ms. Between steps the cost is nearly flat: 19 → 22
  at depth 2 adds 9 ms for three inputs.
- **No input count is a boundary at every depth.** 22 sits mid-band at depths 2
  and 3, and exactly on a Helios step at depths 7 and 24 (where the weight
  limit admits only 20 and 15 anyway). A snap cannot be stated once for all
  depths; `ICD-Q3` asks whether to snap at all.
- **Splitting still costs verifiers more.** Every split adds a transaction's
  fixed cost (about 22 ms here, 100 to 130 ms on the floor, §2.6), and the per-input cost
  within a band is lower than across one.

### 2.6 The floor arm — measured 2026-11-22

**Measured, floor** (Raspberry Pi 4 Model B, Cortex-A72 ×4 at 1.5 GHz, not
throttled, 56–59 °C, rustc 1.94 aarch64, release; a fresh clone at
`27a832cf81` with the same scratch patch, built on the device; proof
verification the median of 5 runs, the other terms one run; the raw captures
are archived in the estate's measurement records). Rule 76: these are the
values; the x86 table above is the diagnostic beside them.

| depth | n | rows | verify (total) | of which proof | auths | range proof | µs per weight byte | prove |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | 1 | 256 / 128 | 176.4 ms | 152.0 ms | 1.5 ms | 22.8 ms | 13.33 | 3.4 s |
| 2 | 8 | 1 024 / 256 | 524.9 ms | 491.4 ms | 10.6 ms | 22.9 ms | 8.92 | 14.6 s |
| 2 | 16 | 2 048 / 512 | 959.0 ms | 915.2 ms | 20.9 ms | 22.9 ms | 8.92 | 27.6 s |
| 2 | 17 | 2 048 / 1 024 | 1 096.4 ms | 1 051.4 ms | 22.1 ms | 22.9 ms | 9.71 | 30.5 s |
| 2 | 18 | 2 048 / 1 024 | 1 122.8 ms | 1 076.5 ms | 23.4 ms | 22.9 ms | 9.42 | 31.5 s |
| 2 | 19 | 4 096 / 1 024 | 1 492.7 ms | 1 445.2 ms | 24.7 ms | 22.9 ms | 12.04 | 38.0 s |
| 2 | 22 | 4 096 / 1 024 | 1 576.2 ms | 1 524.8 ms | 28.6 ms | 22.9 ms | 11.06 | 41.4 s |
| 3 | 1 | 256 / 128 | 180.4 ms | 156.0 ms | 1.5 ms | 22.9 ms | 13.25 | 3.7 s |
| 3 | 8 | 2 048 / 256 | 720.7 ms | 687.3 ms | 10.6 ms | 22.9 ms | 12.27 | 18.5 s |
| 3 | 12 | 2 048 / 512 | 894.4 ms | 855.8 ms | 15.8 ms | 22.9 ms | 10.65 | 25.0 s |
| 3 | 13 | 4 096 / 512 | 1 263.7 ms | 1 223.7 ms | 17.1 ms | 22.9 ms | 14.17 | 31.8 s |
| 3 | 16 | 4 096 / 512 | 1 355.1 ms | 1 311.2 ms | 21.0 ms | 22.9 ms | 12.50 | 35.7 s |
| 3 | 17 | 4 096 / 1 024 | 1 497.2 ms | 1 452.1 ms | 22.2 ms | 22.9 ms | 13.14 | 38.5 s |
| 3 | 22 | 4 096 / 1 024 | 1 650.5 ms | 1 599.0 ms | 28.7 ms | 22.9 ms | 11.33 | 45.3 s |

What the floor adds:

- **The steps are the same size on the floor.** A Selene step costs +34 % at
  depth 2 (18 → 19) and +43 % at depth 3 (12 → 13); a Helios step +15 % and
  +11 %. x86 measured +38 %, +50 %, +14 % and +10 %. The floor-to-x86 ratio of
  the proof term is 6.9 to 7.4 across every cell, so the A72 does not amplify
  the padding.
- **The fixed per-transaction cost is about 100 to 130 ms on the floor**
  (176 ms for one input, against a marginal 50 ms per input at depth 2 and
  77 ms at depth 3 between 1 and 8 inputs). That is what each extra
  transaction of a split consolidation costs every verifier.
- **`ICD-F12` — this Pi 4 reads about 19 % slower than the floor device of
  record; the absolute values above carry that, the ratios do not.** The same
  harness on the same x86 workstation reads within 8 % of slice 6's x86 cells
  (1 input at depth 3: 22.5 ms here against 23.3 ms; 8 inputs: 96.9 against
  104.6), while on the floor it reads 19 % above slice 6's floor cells (156.0
  against 130.6 ms; 687.3 against 578.1). A change in the proof would move both
  arms; only the floor moved, so the difference is the device or its
  conditions (a different Pi 4 unit, Ubuntu 26.04 and kernel 7.0, rustc 1.94,
  the `ondemand` governor), not the workload. The floor-to-x86 ratio here is
  6.9 to 7.4 against §80.6's pinned 5.56, which is §80.6's check firing as
  designed. The same gap shows against the embargo table's door cells (176.4
  and 524.9 ms here against 144.31 and 425.86 at depth 2). The padding steps
  and the per-byte comparison in §3 are ratios within this device and stand;
  every absolute floor figure in this document that comes from §2.6 is read on
  a device about 19 % slower than the one the table was measured on. Which
  Pi 4, under which governor, is *the* floor is a rule-76 question this round
  raises and does not answer (§8). It has a consumer beyond this round: the
  relay's embargo floor (#1516, merged) takes its verification term from the
  table's door cells, so whichever way the question resolves reaches it.

## 3. Job 1: work per block

**The weight limit bounds a block's bytes, not its verification time.** A
block's verification time is its weight times the verification cost per weight
byte of the shapes in it. Slice 6 read the per-byte cost as flat across input
counts, which made the cap irrelevant to per-block work. With the padding in
view it is not flat:

- **`ICD-F9` — a larger cap admits shapes that cost more per byte.** On the
  floor at depth 3, a 13-input spend costs 14.17 µs per weight byte; the
  costliest of the shapes measured that the cap of 8 admits costs 13.33 (a
  1-input spend at depth 2). Only 1 and 8 inputs were measured below the cap;
  7 inputs at depth 3 sits just past a Selene step and was not.
  A block filled with 13-input spends would verify about 6 % slower than the
  worst block today. (x86 shows 12 %; the floor's larger fixed range-proof cost
  raises the 1-input shape's per-byte cost more than the 13-input one's.) At
  depth 2 the costliest shape stays the 1-input spend: 19 inputs, just past the
  Selene step, costs 12.04.
- **The worst block was measured at today's shapes.** GAP-7's zone-point worst
  cold block (7.23 s on the floor, 6.0 % of T) and the transient leg that
  re-signed the surge factor at S = 3 (depth 24) come from
  `shekyl-verify-cost`'s `block_connect_verify` sweep, whose shapes stop at 8
  inputs. At about 6 % more, 7.23 s becomes about 7.7 s, still near 6.4 % of T.
  Depths beyond 3 were not measured here, and S = 3 was signed on a
  conservative bracket at depth 24, where the cost per byte has to be measured,
  not assumed.

**Disposition proposed:** the cap is not the per-block bound, and it does not
need to be one, because the margin is large. The cutover re-runs the GAP-7
sweep with the new shapes added (every Selene step up to N at the depths the
sweep covers) on the floor, and S = 3 is re-checked against it. If the
re-run moved S, that would be a finding for the C2-R2 owners, not a reason to
keep the cap at 8.

## 4. Job 2: the work a relay wastes on one invalid transaction

### 4.1 What one invalid transaction costs, at the floor

Two floor sources: the embargo table's door sequence (`SPEC_VERIFY_COST`,
2026-11-08 operands) and this round's harness (§2.6), read on a Pi 4 about 19 %
slower than the table's (`ICD-F12`).

| inputs | depth 2, table | depth 2, §2.6 | depth 3, §2.6 | depth 7, table (synthesized tree) |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 144.31 ms | 176.4 ms | 180.4 ms | 163.11 ms |
| 8 | 425.86 ms | 524.9 ms | 720.7 ms | 818.56 ms |
| 22 | — | 1 576.2 ms | 1 650.5 ms | owed with the new rows (§8) |

### 4.2 How the relay meets it today

A transaction arriving from a peer is parsed and judged by the pool door. Its
first step is `stateless` (`rust/shekyl-mempool/src/door.rs:129`), which runs,
in order, `tx_form` (the form rows, CEN-H3's weight and CEN-I4's count among
them), the hybrid signatures, the FCMP++ proof, and the lone range proof
(`judge_slot_stateless`, `rust/shekyl-chain-rules/src/validate.rs:342-362`).
So the count and weight refusals are cheap and come first; a transaction that
passes them buys a full verification. One that then fails is
`Admit::RefusedForm` (`rust/shekyl-node/src/pool_door.rs:156-160`, `:169`), and
the relay owner closes that session at the first such refusal in a batch
(`rust/shekyl-relay/src/owner/port.rs:150-165`). So **one session buys at most
one failed verification**, and a peer that wants another needs a new session.

**`ICD-F13` — the verification runs on the transport runtime.** The session's
read loop dispatches a `NewTransactions` notification straight into the relay
owner (`rust/shekyl-p2p-session/src/session.rs:588-594`), which calls the pool
door inline (`port.rs:139`). Session tasks run on the transport runtime
(`rust/shekyl-p2p-session/src/layer.rs:246`), whose worker count is
`spans::WORKERS = 2` (`rust/shekyl-transport-layer/src/spans.rs:83`, a recorded
assumption, §97). A proof verification therefore holds one of the two
transport workers for its whole length: 0.18 s to 1.65 s on the floor (§2.6).
Two in flight hold both, and every session's reads, writes, handshakes and
timed syncs on that runtime wait behind them.

**A second caller is in flight (#1520, open, not on `dev`).** It holds the
`NewTransactions` batches that arrive while the node is behind and admits them
when it turns synchronised, in `Port::admit_held_on_sync`, a task the relay
owner spawns beside its actor on the runtime it is started with. The node
starts the relay owner on the transport runtime (`shekyl-p2p`'s `network.rs`,
`relay::start` with the transport handle; read on #1520's head), so held
batches verify there too, serially on one task. The hold is bounded per session
at one message (the payload cap, 1 000 044 bytes since #1489), and a node is
behind at every block, so each turn to synchronised can bring up to one
message's worth of transactions per session to verify. At the 9 to 14 µs per
weight byte measured in §2.6, a full message is roughly 9 to 14 s of one
transport worker. A held batch refused on form closes its session and drops
its other held batches, so one failed verification per session holds on this
path too. Whatever moves verification off the transport runtime (`ICD-R4`)
covers both callers.

What a new session costs the peer is the accept-rate bound
(`rust/shekyl-transport-layer/src/accept_rate.rs`):

- clearnet, per connector: one accept per 100 ms, burst 20;
- clearnet, per host (an IPv4 address or an IPv6 /64): one per 6 s, burst 3;
- Tor: no daemon-side limiter; the onion service's proof of work charges the
  peer.

**`ICD-F10` — the accept rate was budgeted for handshakes, not for the first
transaction.** Its recorded basis (`DAEMON_RELAY_PRIVACY.md` §97, the clearnet
accept-rates row) is about 1 % of a floor core for 10 handshakes a second. A
peer that sends one invalid transaction per session at the connector rate
demands verification at 10 per second. The table is that **demand**, in
worker-seconds per second; the transport runtime supplies 2:

| shape (source) | demand at the connector rate | per host (one per 6 s) |
| --- | ---: | ---: |
| 1 input, depth 2 (table / §2.6) | 1.44 / 1.76 | 0.024 / 0.029 |
| 8 inputs, depth 2 (table / §2.6) | 4.26 / 5.25 | 0.071 / 0.087 |
| 8 inputs, depth 3 (§2.6) | 7.21 | 0.120 |
| 8 inputs, depth 7 (table) | 8.19 | 0.136 |
| 22 inputs, depth 2 (§2.6) | 15.76 | 0.263 |
| 22 inputs, depth 3 (§2.6) | 16.51 | 0.275 |

What saturates is the transport runtime, not the device's cores. **At today's
cap of 8, a clearnet flood from many addresses already demands more than the
two transport workers supply, two to four times over at 8 inputs**; the queue
grows without bound and every session on the node stalls behind it. Even
1-input garbage takes 1.4 to 1.8 of the 2 workers. The cap moves the multiplier, not the conclusion. A single
address stays under a third of one worker at any shape measured.

**Disposition (`ICD-R4`, ruled):** the bound belongs in relay policy and is
missing there at any cap. The relay lane designs it in its own round, with the
requirements §9 hands it (where verification runs for both callers, what makes
a session verified, the unverified queue, the privacy cost of a dropped or
delayed stem, Tor, and the budget in core-time from `f(n_in, depth)`). Nothing
is built before that round is ruled. Once the bound exists, a larger input
count simply costs more of it, and the consensus cap has no relay job left.

## 5. Job 3: the closed domains

Three tables need a known maximum: the generators (§2.4), the embargo table
(`f(n_in, depth_tier)`, which refuses a cell it has not measured, by design),
and the proof-size vectors. Each of them must cover `1..=N` for the derived `N`,
and each asserts it at compile time or in its pin tests (§7). This is the job
that makes a named maximum necessary even if CEN-I4 is deleted: the domain has
to be closed by something consensus enforces, and the weight limit closes it at
22 by arithmetic.

## 6. Job 4: privacy

Input count is public at any cap. Under FCMP++ the spent outputs are not
identified, so a transaction's input count says only that its author held that
many outputs.

**One consolidation of `m` outputs, `m ≤ N`:** one event. An observer learns
that one wallet held `m` outputs of unknown amounts. A large `n_in` is rare, so
the event is visible, but a single event cannot be clustered: clustering needs
same-class repetition (decision log, 2026-09-20, the bond-immutability ruling).

**The same consolidation under a cap `c < m`:** ⌈(m − 1) / (c − 1)⌉
transactions in a window, each at or near the cap. That is a run of rare-shaped
transactions close in time, which is exactly the repeated same-class pattern
clustering needs. It also costs more, per extra transaction:

- weight: about 7.1 KB of fixed overhead (two outputs, their KEM ciphertexts,
  leaf entries and range proof, and the proof base), paid as fee;
- verification: about 100 to 130 ms on the floor (§2.6), paid by every verifier;
- latency: a wallet chaining the transactions waits out each output's
  maturity.

| outputs to merge | transactions at a cap of 8 | at 22 |
| ---: | ---: | ---: |
| 20 | 3 | 1 |
| 100 | 15 | 5 |
| 1 000 | 143 | 48 |

**What the cap does not buy is uniformity.** At any cap the count stays public
and correlates with wallet state. Uniformity would mean fixed-count
transactions padded with dummy inputs, each needing a real membership proof
(6.2 KB and 50 to 77 ms on the floor per input), which this round does not
propose.

**Disposition proposed:** the privacy side favors the larger cap. Fewer,
larger consolidations disclose a count once instead of a cluster. The wallet's
consolidation design is out of scope here (its own round, priced; FOLLOWUPS),
and reads the cap from the constant, so this round changes how many
transactions it makes, not its design.

## 7. Every consumer that moves with the cap

Found by a sweep of `rust/`, `scripts/`, `config/`, `tests/` and the GUI wallet
at `27a832cf81`. "Reads" means the site reads one of the three constants;
"copy" means it carries its own literal or a shape sized to 8.

**The three constants.** `shekyl_wire::transaction::MAX_FCMP_INPUTS`
(`rust/shekyl-wire/src/transaction.rs:145`, refused in `Transaction::validate`);
`shekyl_fcmp::MAX_INPUTS` (`rust/shekyl-fcmp/src/lib.rs:41`);
`shekyl_tx_builder::MAX_INPUTS`, defined as the second and const-asserted
equal to the first (`rust/shekyl-tx-builder/src/lib.rs:119`, `:139-142`).

**Consensus and proving (read):**

- CEN-I4, `rules/tx_inputs.rs::I4` (`rust/shekyl-chain-rules/src/rules/tx_inputs.rs:113`);
- the prover and verifier refusals in `rust/shekyl-fcmp/src/proof.rs` (three
  prove sites, two verify sites) and `batch_weights.rs`;
- the builder's `TooManyInputs` (`validate.rs`, `error.rs`).

**Weight and fee (read, or sized to 8):**

- `shekyl-tx-weight`: `InputCount`, the `FCMP_PROOF_SIZE_KAT` table and its
  dimension assert, and `FCMP_PROOF_SIZE_MAX` (copy: fails to compile until
  replaced, `ICD-R1`);
- `shekyl-engine-core`: `p_lane_weight_ceiling_bytes` and its test
  `p_lane_ceiling_covers_the_heaviest_legal_shape`, which ties the ceiling to
  the exit-fee reserve; `tx_fee_model.rs`'s KAT emit and validation loops
  (`1..=8`, copy) and `tx_weight_kat.rs`'s `n_in > 8` refusal (copy);
- `EMISSION_NON_CLAIMS_RESERVE_BYTES` (two fee inputs at depth 24; reads the
  table, unaffected unless the fee-side shape changes).

**The standoff exit-fee reserve** (`rust/shekyl-standoff/src/reserve.rs:24-62`):
0.05 SKL from a worst-case `Release` of 80 456 bytes, priced at ≥ 600 atomic per
weight byte. **`ICD-F11` — the P-lane ceiling scans cells the weight limit
refuses.** `p_lane_weight_ceiling_bytes` takes the maximum of `predict_weight`
over every `(n_in, n_out, depth)` cell up to the cap, without asking whether
the cell is legal. At 8 that is harmless (the scan's maximum, 8 inputs at
depth 24, is legal). At 22 the unbounded scan returns 204 128 bytes, a 22-input
spend at depth 24 that CEN-H3 refuses; restricted to legal cells the ceiling is
148 608 (16 inputs at depth 23). The cutover bounds the scan by the weight
limit. The reserve's head-room at 0.05 SKL then falls from about 600 to about
336 atomic per weight byte: either the reserve rises to about 0.09 SKL to keep
600, or the 600 is restated, and the rule-75 bounds (`0 < reserve < rung`) are
re-checked. (The reserve's comment gives today's ceiling as 80 456 bytes; the
weight model gives 79 625 for the same shape at a 10-byte fee varint. The
comment likely predates the 2026-09-14 proof-size re-measurement; the cutover
recomputes it rather than carrying either figure.)

**Wallet (read):** the engine's selection and refusals (`curve_tree_actor.rs`,
`drain_select.rs`, `bond_assembly.rs`'s `MAX_RETENTION_FUNDING_INPUTS`, the
wallet lane's new refusal at selection, `-29123 TOO_MANY_INPUTS`, which reads
`shekyl_tx_builder::MAX_INPUTS`); `shekyl-wallet-contract`'s error limit;
`shekyl-wallet-rpc`'s `n_inputs` range. The transfer engine prices with
`InputCount::clamped`, which silently prices a 9-input selection as 8; the
refusal at selection now stops that before pricing.

**Multisig (copy):** `MAX_INPUTS: u32 = 8` in `shekyl-multisig/src/intent/mod.rs:73`,
pinned by `max_inputs_is_the_consensus_cap`. It becomes a read of the constant.

**Relay privacy (copy):** `MAX_TABLE_INPUTS = 8` and the cells it sizes
(`shekyl-relay-privacy/src/verify_cost.rs:215`), `DoorInputCount::Eight` and the
8-input operands, the `[7]` row named as "the consensus maximum", the
diagnostic x86 array in `tests/spec_decision_matrix.rs`, and
`tests/carrier_window.rs`'s fragment count. **`ICD-F14` — the cover carrier's
`MAX_FRAGMENTS` is a coupling, not only a failing test.** `MAX_FRAGMENTS = 5`
(`shekyl-relay-privacy/src/params/carrier.rs:117`) is derived, not chosen:
⌈S_max / 20 480⌉, where S_max is the structural maximum transaction plus its
message envelope (97 658 bytes today, so 5), pinned as an equality by
`tests/carrier_window.rs`. At the derived cap the largest transaction is about
145 KB, so the constant becomes 8; the epoch's ceiling of 44 windows does not
bind at 8. A capacity decision then moves a cover constant, mechanically: the
§80.3 shape, named in `ICD-Q5`. Whether the carrier keeps a fragment train at
all is cover-by-shape's question (`CBS-`, not yet ruled), and it goes to Rick
with that design, not to this round.

**Benches and sims (copy):** `shekyl-verify-cost`'s
`relay_admission_verify.rs` (`1..=8`) and `block_connect_verify.rs`'s
`SWEEP_SHAPES` (the GAP-7 sweep, §3); `shekyl-economics-sim`'s calibration
domain (reads `InputCount::clamped`; under the cutover it reads the landed,
computed constant, so the sim tests the built structure);
`scripts/bench/test_rt_p5_classes.py`'s pinned 8-in/16-out cell.

**Generators and depth (`ICD-R2`, `ICD-R3`):** `shekyl-curve-generators`'s
`MAX_FCMP_INPUTS = 128` and `MAX_FCMP_LAYERS = 12` give way to the two derived
counts and the one depth constant; `shekyl_fcmp::MAX_TREE_DEPTH`
(`rust/shekyl-fcmp/src/lib.rs:50`) and its re-export through `shekyl-tx-weight`
read the one constant; the embargo table's `MAX_TABLE_DEPTH` stays its own
measured edge (depth 7), below the protocol's maximum.

**Fixtures and tests (copy):** `shekyl-chain-ingest`'s
`EXTRA_KEY_IMAGES: [[u8; 32]; MAX_FCMP_INPUTS]` (eight literal entries, fails
to compile), its committed 8-input corpora and iai benches; the four tests that
build a 9-input transaction expecting a refusal (`shekyl-wire`
`tests/validation.rs`, the I4 conformance trip, `proof.rs`, `wallet-contract`).

**Outside this repository:** the GUI wallet's `SecurityStatus`
(`src-tauri/src/commands.rs`): `max_inputs`, a literal `8`, and
`estimated_proof_size_kb: 4.5`, a literal too. The cutover pairs a GUI PR that
reads the cap from the core crates and computes the proof size from the same
model at the tree's current depth.

**Documents** that state 8 as the cap: the census row, FOLLOWUPS row (the
CEN-I4 row), `GENESIS_TX_WIRE_FORMAT.md` §10 (frozen: the freeze is amended by
the cutover, with this round as its reason), `FCMP_PLUS_PLUS.md`,
`DAEMON_RELAY_PRIVACY.md` §80, and about thirty others listing it in passing;
the cutover sweeps them.

**Stale on the way:** the comments at `proof.rs:1126` and `:1948` cite an FFI
`po_count` cap that no longer exists.

## 8. The measurements the cutover owes

- **The embargo table, every cell, on the named floor in one session
  (`ICD-R5`).** `n_in = 1..=N(d)` at every depth tier the table covers, since a
  cell no legal transaction fills is not measured: 22 cells at each of depths
  2, 3 and 4, 21 at depths 5 and 6, 20 at depth 7, so 128 cells, the existing
  four included. Measured on the device Rick names after the two-unit run,
  never scaled from x86 (§80.3's correction; the `Provenance` test refuses a
  scaled cell), never mixing devices, with the depth-7 column labelled a
  synthesized projection (§81.2); claimed in the estate's usage file before the
  run (rule 38). The embargo floor (#1516) follows from the table.
- **The GAP-7 sweep at the new shapes** (§3), on the floor.
- **The standoff reserve** re-derived (§7).
- **The model's test vectors:** the 192 KAT cells and the real proofs past 8
  inputs pinned against the `const` `FcmpPlusPlus::proof_size` (`ICD-R1`), and
  the two generator counts asserted equal to the computed need (`ICD-R2`).
- **Tests on the real pathway:** a transaction of `N` inputs built, proved,
  relayed and mined on regtest at a depth where the weight limit admits it
  (2 to 4), and `N + 1` refused at consensus with CEN-I4 named; at a depth
  where `N(d) < N`, the weight limit's refusal named instead.

## 9. Rulings — RULED 2026-11-22 (Rick)

Ruled on #1528 at `46e3b27d5f`. The standard for the round: build the
structure right, with no interim options. The numbers move again when EUP-5 G
rules, and that rebuild is accepted.

### `ICD-R1` — the weight model moves into `shekyl-wire`, and the cap is computed there (was `ICD-Q4`) — RULED

Neither option §9 first offered is taken.

- The field model (`spend_weight` and its parts) moves beside
  `Transaction::write`, as `const fn`s. `shekyl-wire` takes
  `shekyl-fcmp-proofs` for `FcmpPlusPlus::proof_size` and `shekyl-crypto-pq`
  for the multisig sizes. **No cycle, checked at `46e3b27d5f`:** neither crate,
  nor `shekyl-curve-generators`, reaches `shekyl-wire` through a normal, build
  or dev dependency (`cargo tree -p <crate> -e normal,build` and `-e dev`).
  `shekyl-wire` already depends on `shekyl-curve-generators` and
  `shekyl-bulletproofs`.
- `Fcmp::proof_size` (`rust/shekyl-oxide/crypto/fcmps/src/lib.rs:274`) becomes
  a `const fn`. Its body is integer arithmetic over `ipa_rows`, which is
  already `const`, and `usize::div_ceil`, which is `const`.
- `MAX_FCMP_INPUTS` is computed at compile time from that model and
  `TX_WEIGHT_LIMIT`, as `max_d N(d)` over the legal depths (§2.3). The parser,
  CEN-I4, the builder and the engine all read it. There is no separate, looser
  parser bound.
- `shekyl_fcmp::MAX_INPUTS` is deleted. The prover and verifier refuse at the
  generators' capacity for the proof's depth, which is what
  `Generators::reduce` already enforces as `NotEnoughGenerators`
  (`rust/shekyl-oxide/crypto/generalized-bulletproofs/src/lib.rs:254-273`). The
  pre-check in `proof.rs` asks the same question of `ipa_rows` before any work.
- **`batch_weights.rs:119` needs no cap at all.** It reads `MAX_INPUTS` only to
  pre-size a `Vec` for the framed lists. It can size from the generators'
  capacity, but the exact size is the lengths of the lists it frames, which it
  already has, so the cutover sizes it from those.
- `FCMP_PROOF_SIZE_KAT` stops being the model's source. Its 192 cells become
  test vectors for `FcmpPlusPlus::proof_size`, beside the 10 real proofs past 8
  inputs (§2.1, §2.5).
- **`shekyl-tx-weight` stays a crate (this lane's call).** It keeps the fee
  fixed point (`converge_weight_fee_by`, `converge_weight_fee`), the bounded
  shape types (`InputCount` and `OutputCount`, now bounded by the wire's
  computed cap; `GroupSize`, `Signer`, `SpendShape`), `predict_archival_len`,
  `marginal_input_weight_at_d_ref`, and the builder-backed weight gate
  (`tests/weight_gate.rs`). The reason is the surface: `shekyl-wire` is the
  consensus transport crate, and a fee loop and wallet shape types are
  wallet-side API. The economics sim and the engine already depend on
  `shekyl-tx-weight` for exactly that, and it adds nothing to the wire crate's
  surface.

### `ICD-R2` — the generator count is derived from the cap, exactly — RULED

- **The count, per curve, is the largest `ipa_rows(N(d), d)` over every legal
  depth `d`**, where `N(d)` is the cap at that depth (§2.3). It is not
  `ipa_rows(N, MAX_TREE_DEPTH)`, which overstates the Helios curve. At today's
  weight limit and `MAX_TREE_DEPTH = 24` it is **16 384 Selene and 8 192 Helios
  rows**, both reached at depth 24. That is a quarter of the 65 536 and 32 768
  built today for upstream's 128 inputs at 12 layers.
- `shekyl-curve-generators` holds the two counts, because it sits below the
  wire crate. `shekyl-wire` asserts at compile time that each equals the value
  it computes, so a weight-limit change fails the build until the counts move.
  `MAX_FCMP_INPUTS = 128` and `MAX_FCMP_LAYERS = 12` leave that crate; what
  remains there is the derived count, with its derivation cited.
- **Why this is not a consensus change.** A proof over `n` padded rows uses the
  first `n` generators: `Generators::reduce(n)` takes `g_bold[..n]` and
  `h_bold[..n]`. The derivation strings (`Monero {id} G {i}`, frozen) and the
  indices do not change. Shrinking the table removes only indices no legal
  proof reaches, and a proof that would need more was already refused by the
  cap before it.
- This replaces §2.4's "within the generator rows" check: the counts are equal
  to the need by construction, not merely large enough.

### `ICD-R3` — the maximum tree depth is derived in this round — RULED

`MAX_TREE_DEPTH = 24` is a chosen number ("over 10^30 outputs",
`rust/shekyl-fcmp/src/lib.rs:43-50`), and the generators were sized for
upstream's `MAX_FCMP_LAYERS = 12`, its figure for about 10^17 outputs. The cap's
floor, the generator count, the embargo's depth tiers and the proof-size
domain all read the depth. The derivation is `ICD-Q7` (§11), and one constant
results: `MAX_FCMP_LAYERS` and `MAX_TREE_DEPTH` stop being two numbers.

### `ICD-R4` — relay verification gets its own design round in the relay lane (was `ICD-Q2`) — RULED

Nothing is built until that round is ruled: no interim budget and no change to
the accept rate. This document keeps `ICD-F10` and `ICD-F13` as findings. The
budget value §9 first proposed is withdrawn. The relay lane's round takes
these requirements from here:

- **Where verification runs:** off the transport runtime, for both callers,
  the live path (`new_transactions`) and #1520's held batches
  (`admit_held_on_sync`).
- **What makes a session verified.** A duplicate of a transaction already in
  the pool is answered before its proofs run (`pool_door.rs`), so it proves
  nothing about its sender and cannot count.
- **The queue for unverified sessions:** its bound, and what is dropped when it
  is full.
- **The privacy cost, stated,** when a stem transaction is dropped or delayed.
- **Tor,** which has no daemon-side accept limiter.
- **The budget in core-time,** read from `f(n_in, depth)`.

### `ICD-R5` — one named floor, and every embargo cell measured on it in one session (from `ICD-F12`) — RULED

- **First,** the same binary is run on both Pi 4 units for the two door cells
  (1 and 8 inputs at depth 2), and the report says whether the 19 % is the unit
  or the OS and governor. **What is already known, read-only, 2026-11-22:** the
  two units run the same Ubuntu 26.04.1, kernel 7.0.0-1023-raspi, `ondemand`
  governor and rustc 1.94. They differ in the board: one is a Rev 1.4 (8 GB)
  whose clock tops out at 1.8 GHz, the other the Rev 1.2 (4 GB) used in §2.6, at
  1.5 GHz, and 1.8 / 1.5 = 1.20. The timed run is owed: the Rev 1.4 unit is a
  measuring host of the cover-by-shape run until 2026-11-24, and its slot
  follows that run (§11).
- **Then** Rick names the floor device.
- **The cutover measures all 128 cells** (`n_in = 1..=N(d)` at depths 2 to 7)
  on that device in one session. The table never mixes devices. The embargo
  floor (#1516) follows from the table.

## 10. Handed to EUP-5 G — findings

- **`ICD-Q6` — weight against verification cost.** The cost per weight byte
  already spreads from 8.92 to 13.33 µs across today's shapes on the floor
  (§2.6), and the cap adds about 6 % to the top of that spread (§3). Whether
  weight should carry an FCMP++ verification charge on the proof's padded
  rows, as it carries a clawback for range proofs, is G's question.
- **`ICD-F15` — the per-transaction limit's formula now sets five things.**
  `TX_WEIGHT_LIMIT = zone / 2 − coinbase reserve` is inherited, and it now
  determines the cap, the generator counts, the embargo rows, the cover
  carrier's fragment count and the standoff reserve. At three times today's
  zone (900 000) the limit is 448 614, the cap 72 (49 at depth 24), the
  generator counts 65 536 and 32 768 at depth 24 (32 768 and 16 384 at depth 12),
  and the embargo cells through depth 7 number 410. G rules how the limit is
  derived, not only the zone.

## 11. Still open with Rick

### `ICD-Q1` — does CEN-I4 stay an explicit rule?

**The problem.** At the derived value, CEN-I4 refuses exactly what CEN-H3
already refuses for the lightest shape, and nothing H3 admits. It becomes
redundant in effect. But the closed domains (§5) need a maximum consensus
enforces, and under `ICD-R1` the parser reads the real cap.

**The question.** Keep CEN-I4 at the computed cap, or delete it and let the
weight limit imply the maximum?

**The options.**

- **(a) Keep it, valued at the computed constant.** A cheap early refusal, a
  named maximum that the closed domains and the parser read, and a census row
  whose rationale is the derivation. The rule cannot bind before H3 for any
  legal shape, by construction, and a test pins that.
- **(b) Delete it.** The maximum is implied by H3; the parser and the closed
  domains read the computed constant without a consensus row naming it.

**Recommendation: (a).** The parser already refuses past the computed cap under
`ICD-R1`, so the rule costs nothing new, and a census row whose value is
derived and whose redundancy is tested is easier to read than an implication
through the weight model. The record says plainly that it binds nothing H3
does not.

### `ICD-Q3` — snap to a padding boundary?

**The problem.** §2.5: the proof's verification cost steps at padding
boundaries, and the boundaries fall at different counts at each depth. 22 is
mid-band at depths 2 and 3.

**The question.** Should the derived value be rounded down to a boundary?

**The options.**

- **(a) No snap: `N` = 22.** The cap is the weight limit's maximum; the
  padding governs cost per transaction, which the relay round prices
  (`ICD-R4`), the block sweep measures (§3), and G may price into weight
  (`ICD-Q6`).
- **(b) Snap to 18,** the top of the band below 19 at depth 2.
- **(c) Snap to 16,** a power of two: no depth-independent benefit, since the
  boundaries are not powers of two of inputs.

**Recommendation: (a).** A snap would trade a privacy and fee cost paid by every
consolidation for a per-transaction verifier saving that the relay round and
the weight limit already bound. The floor arm (§2.6) shows the steps are no
larger on the floor (+34 % and +43 % for a Selene step) than on x86. A snap to
18 would save about 30 % of verification at depth 2 per transaction (1 576 ms
to 1 123 ms) and nothing at depth 3, where 13 is already past the step.

### `ICD-Q5` — the weight limit moves at EUP-5 G

**The problem.** `TX_WEIGHT_LIMIT` "moves again when EUP-5 G rules the capacity
leg" (`rust/shekyl-wire/src/transaction.rs:228-236`). A derived cap moves with
it, and with the cap the generator counts, the embargo table's rows, the
reserve, the sweeps and the cover carrier's fragment count (`ICD-F14`,
`ICD-F15`). That is the coupling §80.3 removed from the embargo, returning
through the weight limit.

**The question.** Is the coupling accepted?

**The options.**

- **(a) Accept it, loudly.** Every table asserts its domain against the
  computed constant at compile time, so a weight-limit change fails the build
  until the new rows are measured: a visible act, as §80.5 wants.
- **(b) Decouple.** Freeze the cap at today's derived value and let a later
  weight-limit change leave it alone.

**Recommendation: (a).** A frozen value would be a chosen number again the
moment the weight limit moves, which is what `ICD-R0` rules out. The build
failure is the review. (The round's standard already accepts the rebuild at G.)

### `ICD-Q7` — what output count does the chain commit to, and so what maximum depth?

**The problem.** `MAX_TREE_DEPTH` is chosen and `MAX_FCMP_LAYERS` is
upstream's (`ICD-R3`). A tree at its maximum depth accepts no more outputs, so
the ceiling is a halt, not a slowdown, and its margin has to be generous. The
cost of a deeper ceiling is a lower cap at the deepest tree, a larger generator
table, and more embargo cells over the chain's life.

**The question.** What output-count ceiling does the chain commit to, and so
what maximum depth?

**The options, with their numbers.** Outputs at depth `D` are
38 × the product of the widths of layers 1 to D − 1 (18 at odd layers, 38 at
even ones), so depth 2 holds 684, as the curve-tree drift guard pins. Years to
fill are at 5 × 10^4 outputs a day (about Monero's) and 10^6 a day (about
Bitcoin's). Generator counts are `ICD-R2`'s, at today's weight limit. Embargo
cells are every `n_in = 1..=N(d)` at depths 2 to `D` (the table today stops at
depth 7, 128 cells, and extends as the tree grows).

| max depth | outputs | years at 5×10^4 a day | years at 10^6 a day | cap at the deepest tree | generators (Selene / Helios) | embargo cells, depths 2 to D |
| ---: | ---: | ---: | ---: | ---: | --- | ---: |
| 8 | 2.2 × 10^11 | 12 000 | 600 | 20 | 8 192 / 4 096 | 148 |
| 10 | 1.5 × 10^14 | 8.2 × 10^6 | 4.1 × 10^5 | 19 | 8 192 / 4 096 | 187 |
| **12** | **1.0 × 10^17** | **5.6 × 10^9** | **2.8 × 10^8** | **18** | **8 192 / 4 096** | **224** |
| 14 | 7.0 × 10^19 | 3.8 × 10^12 | 1.9 × 10^11 | 18 | 8 192 / 4 096 | 260 |
| 16 | 4.8 × 10^22 | 2.6 × 10^15 | 1.3 × 10^14 | 17 | 16 384 / 8 192 | 295 |
| 24 (today) | 1.0 × 10^34 | 5.7 × 10^26 | 2.9 × 10^25 | 15 | 16 384 / 8 192 | 425 |

The cap itself is 22 at every candidate (it is set at depths 2 to 4). The
generator counts do not distinguish depths 8 to 14: the `ipa_rows` padding puts
them all at 8 192 / 4 096.

**Recommendation: 12, about 10^17 outputs.** It is 280 million years at
Bitcoin's output rate and 2.8 million at a hundred times it, which no
assumption about adoption reaches. Beyond 12 the margin buys nothing a
reader could name. It costs three inputs at the deepest tree (15 against 18)
and doubles the generator table at 16 or deeper. Below 12 the margin shrinks
toward rates a successful chain could see over its life: depth 10 is about
4 000 years at a hundred times Bitcoin's rate. The tree's eventual
replacement at the V4 lattice-only transition is not counted on.
Under `ICD-R1` and `ICD-R2` the one constant lives in `shekyl-curve-generators`
beside the counts it sizes, and every reader (the wire's model, `shekyl-fcmp`,
`shekyl-curve-tree`, the embargo table) reads it from there.

### The standoff reserve's value

The heaviest legal `P`-lane shape becomes about 148 608 bytes (§7, `ICD-F11`).
Keeping 600 atomic units per weight byte of head-room needs the reserve at
about 0.09 SKL; keeping 0.05 SKL means restating the head-room as about 336.
Recommendation: raise it to the value that keeps 600, computed in the cutover
from the bounded scan rather than rounded here, with the rule-75 bounds
re-checked against the rung.

### The cover carrier's fragment count

`MAX_FRAGMENTS` becomes 8 at the derived cap (`ICD-F14`). Whether the carrier
keeps a fragment train under cover-by-shape is that design's question, and its
measuring run ends 2026-11-24. This round asks for it to be ruled after that
run, with the cap's value in hand.

### The second Pi's slot

`ICD-R5`'s timed run on the Rev 1.4 unit waits for the cover-by-shape run to end
(2026-11-24T17:11Z), unless Rick accepts a five-minute deviation in that run's
registered plan. The owning lane will mark the window if he does.

## 12. Out of scope

Automatic consolidation in the wallet: its own design round, with its privacy
cost priced (FOLLOWUPS, the wallet's consolidation row). Relay verification:
the relay lane's round (`ICD-R4`).

## 13. Round log

- **2026-11-22 — Round 0 opened.** Brief from Rick, ground `27a832cf81`.
  Findings `ICD-F1`…`ICD-F14`; questions `ICD-Q1`…`ICD-Q5`; padding measured
  on x86 and on the Pi 4 floor (§2.5, §2.6).
- **2026-11-22 — Round 0 ruled in part (Rick, at `46e3b27d5f`).** `ICD-R1`
  (was `ICD-Q4`), `ICD-R2`, `ICD-R3`, `ICD-R4` (was `ICD-Q2`), `ICD-R5` (from
  `ICD-F12`). `ICD-Q6` and `ICD-F15` handed to EUP-5 G. `ICD-Q7` opened. Still
  open: `ICD-Q1`, `ICD-Q3`, `ICD-Q5`, `ICD-Q7`, the reserve's value, the
  fragment count.
