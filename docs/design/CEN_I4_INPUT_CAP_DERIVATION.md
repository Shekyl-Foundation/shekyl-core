# CEN-I4 — deriving the transaction input cap (`ICD-`)

**Status:** OPEN — Round 0 RULED except the fragment count (Rick, 2026-11-22; §11), docs only.
Consensus surface: the design is ruled here before any code moves, then one
rule-107 cutover PR moves every consumer together. Identifier family `ICD-`
(registered in [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2):
`ICD-R*` rulings, `ICD-F*` findings, `ICD-Q*` questions for Rick.

**Ruled before this round (`ICD-R0`, Rick, 2026-11-22):** CEN-I4 is derived in
its own lane before genesis, and the answer is a derived constant, not a
chosen number.

**Ruled in this round (§9):** `ICD-R1` the weight model moves into
`shekyl-wire` and the cap is computed there; `ICD-R2` the generator counts are
derived from the cap; `ICD-R3` the maximum tree depth is derived here;
`ICD-R4` relay verification gets its own round in the relay lane; `ICD-R5` one
named floor device for every embargo cell; `ICD-R6` CEN-I4 stays an explicit
rule; `ICD-R7` no rounding to a padding boundary; `ICD-R8` the coupling to the
weight limit is accepted; `ICD-R9` the maximum tree depth is 14; `ICD-R10` the
standoff reserve is computed; `ICD-R11` the cap is checked before the weight;
`ICD-R12` the row floors stay. **Handed to EUP-5 G (§10):** `ICD-Q6`,
`ICD-F15`. **Still open (§11):** the cover carrier's fragment count, after the
cover-by-shape run ends on 2026-11-24.

## 0. What the cap is, and why it is decided now

`MAX_INPUTS = 8` has no derivation. Its only stated reason is the inherited
comment *"bounds proof gen time and tx size"* (`rust/shekyl-fcmp/src/lib.rs:40`).
Raising or deleting a consensus cap widens what consensus accepts: free before
genesis, a hard fork after. The concrete pressure is a miner or staker
consolidating many coinbase-sized outputs. Every transaction needs two
outputs (CEN-I1) and the builder refuses a zero-valued one, so a consolidation
ends at two outputs the wallet owns and each transaction removes `c − 2`: at a
cap of 8, merging 1 000 outputs takes ⌈998 / 6⌉ = 167 transactions; at 22 it
takes ⌈998 / 20⌉ = 50 (§6).

The round takes the cap's possible jobs one at a time (§3 to §6), derives the
number from the weight model (§2), lists every consumer that moves with it
(§7), and records Rick's rulings (§9) and what is still open (§11).

**Answer in one paragraph.** The derived maximum is **22** at today's weight
limit: the largest input count the transaction weight limit admits at the
lightest legal shape, reached at tree depths 2, 3 and 4 (§2.3). The number is
provisional, since EUP-5 G moves the weight limit, and nothing built depends
on it: every consumer reads the computed value. It is computed at compile time in
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
today's `MAX_TREE_DEPTH = 24` that is 16 384 Selene and 8 192 Helios rows
(both at depth 24); at the ruled maximum depth of 14 (`ICD-R9`) it is 8 192 and
4 096. The
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
  depths; `ICD-R7` rules out snapping.
- **Splitting still costs verifiers more.** Every split adds a transaction's
  fixed cost (about 22 ms here, 100 to 130 ms on the diagnostic Pi, §2.6), and the per-input cost
  within a band is lower than across one.

**`ICD-F16` — the two row floors are the smallest the vector-commitment tape
accepts; lowering them is a circuit change, not a tuning. Traced 2026-11-22;
closed by `ICD-R12` (the floors stay).** `ipa_rows` raises the padded rows to at least 256 Selene
and 128 Helios (`C1_TARGET_ROWS`, `C2_TARGET_ROWS`,
`rust/shekyl-oxide/crypto/fcmps/src/lib.rs:74-75`). One input at depth 2
needs only 111 and 32 rows, which would pad to 128 and 32, so the question
was what the floors cost the smallest spends.

*Scope.* The Selene floor binds only for one input at depth 2. The Helios
floor binds while `inputs × (layers / 2) < 4`: one input at depths 2–3 (32
rows needed, the floor 4 times that), one input at depths 4–5 (64 rows, 2
times), and two inputs at depths 2–3 (64 rows, 2 times). From depth 6 on, one
input needs 96 rows, which pads to 128 without the floor. Depth 5 holds
17 778 528 outputs, so **the floors touch only small spends on a young chain,
and stop mattering at about 18 million outputs.** At most they cost one or
two Helios halvings, 11–15 % of verification each on the diagnostic Pi.

*Task 1, upstream's reason.* The floors arrived in upstream's
`ecf94345` (2024-11-21, "Fix prove/verify for when the targetted amount of
layers is exceeded"). Before it, the rows were fixed at `inputs × 256` and
`inputs × 128`, one input's need at upstream's 8 target layers; the commit made
the rows follow the layer count and kept those per-input sizes as floors,
without a comment. The commit records no soundness or batching reason, but the
code enforces one: **both floors are the minimum the vector-commitment tape
can lay out.**
- **Helios:** the tape places witness words of `COMMITMENT_WORD_LEN = 128`
  slots and starts a new commitment only when the offset equals the commitment
  length exactly (`tape.rs:47-58`). Fewer than 128 padded rows never closes a
  commitment, so 128 is the floor.
- **Selene:** `append_branch` asserts that the leaf branch fits one commitment
  (`tape.rs:75`). Shekyl's leaf branch is `LEAF_TUPLE_WIDTH × LAYER_ONE_LEN` =
  4 × 38 = 152 scalars, which needs 256 rows. Upstream's was 6 × 38 = 228, which
  needs 256 too.

*Task 2, the measurement.* Not run: with the floors lowered the prover refuses
the layout, so there is no "lowered" configuration to time. Lowering them
means changing the word length or the leaf branch's layout, a departure from
the circuit as upstream had it audited, for a saving that exists only below
depth 6. Ruled 2026-11-22: not worth it; the floors stay (`ICD-R12`). (The model also shows the trade's other
direction, for the record only: with more rows the same witness needs fewer
commitments, so raising the floors shrinks small proofs, by about 30 % for one
input at depth 2 at 2 048 / 512 rows, at the price of a larger inner-product
argument and a larger generator table. Nothing here proposes it.)

### 2.6 The diagnostic Pi arm — measured 2026-11-22; not the floor (`ICD-R5`)

**Measured on the estate's test-load Pi 4, not on the floor device** (Raspberry
Pi 4 Model B Rev 1.2, 4 GB, Cortex-A72 ×4 at 1.5 GHz, Ubuntu 26.04.1, kernel
7.0, `ondemand` governor, not throttled, 56–59 °C, rustc 1.94 aarch64,
release; a fresh clone at `27a832cf81` with the same scratch patch, built on
the device; proof verification the median of 5 runs, the other terms one run;
the raw captures are archived in the estate's measurement records). **This
unit is a diagnostic beside the floor, as the x86 table is** (`ICD-R5`, Rick,
2026-11-22: it exists to relieve test load and is never the worst case). Its
ratios are findings; **none of its absolute figures is a floor value**, here
or where §3 and §4 quote them. The floor device's cells are measured in the
cutover (§8).

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

What this arm adds, as ratios:

- **The steps are the same size on an A72 as on x86.** A Selene step costs +34 % at
  depth 2 (18 → 19) and +43 % at depth 3 (12 → 13); a Helios step +15 % and
  +11 %. x86 measured +38 %, +50 %, +14 % and +10 %. The floor-to-x86 ratio of
  the proof term is 6.9 to 7.4 across every cell, so the A72 does not amplify
  the padding.
- **The fixed per-transaction cost is about 100 to 130 ms on this unit**
  (176 ms for one input, against a marginal 50 ms per input at depth 2 and
  77 ms at depth 3 between 1 and 8 inputs), about two thirds of a one-input
  spend's whole verification. That is what each extra transaction of a split
  consolidation costs every verifier; the floor's absolute value is the
  cutover's measurement.
- **`ICD-F12` — this unit reads about 19 % slower than the floor device; RULED
  (`ICD-R5`): the floor is the other unit.** The same harness on the same x86
  workstation reads within 8 % of slice 6's x86 cells (1 input at depth 3:
  22.5 ms here against 23.3 ms; 8 inputs: 96.9 against 104.6), while on this
  Pi it reads 19 % above slice 6's floor cells (156.0 against 130.6 ms; 687.3
  against 578.1), and the same gap shows against the embargo table's door
  cells (176.4 and 524.9 ms here against 144.31 and 425.86 at depth 2). A
  change in the proof would move both arms; only the Pi moved. The two units
  run the same OS, kernel, governor and toolchain and differ in the board: the
  floor device is a Rev 1.4 at 1.8 GHz, this one a Rev 1.2 at 1.5 GHz, and
  1.8 / 1.5 = 1.20. Its floor-to-x86 ratio, 6.9 to 7.4 against §80.6's pinned
  5.56, is §80.6's check firing on the wrong device, as designed. The padding
  steps and the per-byte comparison in §3 are ratios within this unit and
  stand.

## 3. Job 1: work per block

**The weight limit bounds a block's bytes, not its verification time.** A
block's verification time is its weight times the verification cost per weight
byte of the shapes in it. Slice 6 read the per-byte cost as flat across input
counts, which made the cap irrelevant to per-block work. With the padding in
view it is not flat:

- **`ICD-F9` — a larger cap admits shapes that cost more per byte.** Two
  comparisons on the diagnostic Pi (§2.6; ratios, so they stand), measured on
  lone transactions, which bound the block case from both sides:
  - **Lone transactions, range proof included:** a 13-input spend at depth 3
    costs 14.17 µs per weight byte, against 13.33 for the costliest of the
    shapes measured that the cap of 8 admits (1 input at depth 2): +6 %.
  - **Range proofs batched, as a block verifies them** (`form` batches H19 over
    the block; only a lone transaction verifies its own,
    `rust/shekyl-chain-rules/src/validate.rs:357-360`): proof and signatures
    only, the 13-input spend costs 13.91 µs per byte against 11.88 for the
    costliest measured shape under the cap (8 inputs at depth 3): +17 %.
  Only 1 and 8 inputs were measured below the cap; 7 inputs at depth 3 sits
  just past a Selene step and was not, so the "today's worst" side of both
  comparisons is a lower bound. **No block-level figure follows from these:**
  a block's cost is the batched sweep's to measure.
- **The worst block was measured at today's shapes.** GAP-7's zone-point worst
  cold block (7.23 s on the floor, 6.0 % of T) and the transient leg that
  re-signed the surge factor at S = 3 (depth 24) come from
  `shekyl-verify-cost`'s `block_connect_verify` sweep, whose shapes stop at 8
  inputs. Depths beyond 3 were not measured here, and S = 3 was signed on a
  conservative bracket at depth 24, where the cost per byte has to be measured,
  not assumed.

**Disposition proposed:** the cap is not the per-block bound. The cutover
re-runs the GAP-7 sweep, batched as blocks are, with the new shapes added
(every Selene step up to `N(d)` at the depths the sweep covers, and the
current cap's own step shapes such as 7 inputs at depth 3) on the floor
device, and GAP-7's margin and S = 3 are re-checked against it. If the re-run
moved either, that would be a finding for the C2-R2 owners, not a reason to
keep the cap at 8.

## 4. Job 2: the work a relay wastes on one invalid transaction

### 4.1 What one invalid transaction costs, at the floor

Two sources: the embargo table's door sequence (`SPEC_VERIFY_COST`, 2026-11-08
operands, measured on the floor device) and this round's harness on the
diagnostic Pi (§2.6, **not floor values**; that unit is about 19 % slower,
`ICD-F12`). The 22-input row on the floor device is the cutover's
measurement (§8).

| inputs | depth 2, table (floor) | depth 2, §2.6 (diagnostic, not floor) | depth 3, §2.6 (diagnostic, not floor) | depth 7, table (floor, synthesized tree) |
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
(`rust/shekyl-relay/src/owner/port.rs:150-165`). So a transaction whose proof
*fails* buys one verification per session, and a peer that wants another needs
a new session.

**`ICD-F18` — a transaction whose proof is valid but which is refused on state
or fee policy can be re-verified without limit on one session.** Such a
transaction passes `stateless` and is then refused by the chain-bound or
policy step: a key image already spent, or a fee under the relay floor. It
comes back `Admit::RefusedState` and the session stays open
(`pool_door.rs:169-170`, `port.rs:149`). Nothing remembers the refusal: the
door's duplicate check asks only whether the pool or the chain holds the
transaction (`rust/shekyl-mempool/src/pool.rs:343-358`), and a refused one is
in neither. So a peer that built one valid transaction once (one input: about
3.4 s of proving on the diagnostic Pi) can send the same bytes in notification
after notification, and each costs a full verification (0.18 to 1.65 s of a
transport worker there) for the price of the bytes. The accept rate does not
bound it, and neither does the close on a failed proof. A fee under the floor
is the cheapest form: the transaction never needs to be spendable.

**`ICD-F13` — the verification runs on the transport runtime.** The session's
read loop dispatches a `NewTransactions` notification straight into the relay
owner (`rust/shekyl-p2p-session/src/session.rs:588-594`), which calls the pool
door inline (`port.rs:139`). Session tasks run on the transport runtime
(`rust/shekyl-p2p-session/src/layer.rs:246`), whose worker count is
`spans::WORKERS = 2` (`rust/shekyl-transport-layer/src/spans.rs:83`, a recorded
assumption, §97). A proof verification therefore holds one of the two
transport workers for its whole length: 0.18 s to 1.65 s on the diagnostic Pi (§2.6, not floor values; about a sixth less on the floor device).
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
its other held batches, so a failed proof buys one verification per session
on this path too, and a state or policy refusal is unbounded here as on the
live path (`ICD-F18`). Whatever moves verification off the transport runtime (`ICD-R4`)
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
worker-seconds per second; the transport runtime supplies 2. Rows marked §2.6
are read on the diagnostic Pi and are **not floor values**; on the floor device
they are about a sixth lower (`ICD-F12`):

| shape (source) | demand at the connector rate | per host (one per 6 s) |
| --- | ---: | ---: |
| 1 input, depth 2 (table / §2.6, not floor) | 1.44 / 1.76 | 0.024 / 0.029 |
| 8 inputs, depth 2 (table / §2.6, not floor) | 4.26 / 5.25 | 0.071 / 0.087 |
| 8 inputs, depth 3 (§2.6, not floor) | 7.21 | 0.120 |
| 8 inputs, depth 7 (table) | 8.19 | 0.136 |
| 22 inputs, depth 2 (§2.6, not floor) | 15.76 | 0.263 |
| 22 inputs, depth 3 (§2.6, not floor) | 16.51 | 0.275 |

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

**The same consolidation under a cap `c < m`:** ⌈(m − 2) / (c − 2)⌉
transactions in a window, each at or near the cap. Each transaction has to pay
two outputs (CEN-I1), and the builder refuses a zero-valued output
(`rust/shekyl-tx-builder/src/validate.rs:64-66`), so both outputs carry value
and both stay the wallet's: a consolidation removes `c − 2` outputs per
transaction and ends at two, not one. (One large consolidation, `m ≤ N`, ends
at two outputs as well.) That is a run of rare-shaped
transactions close in time, which is exactly the repeated same-class pattern
clustering needs. It also costs more, per extra transaction:

- weight: about 7.1 KB of fixed overhead (two outputs, their KEM ciphertexts,
  leaf entries and range proof, and the proof base), paid as fee;
- verification: about 100 to 130 ms on the diagnostic Pi (§2.6, not a floor value), paid by every verifier;
- latency: a wallet chaining the transactions waits out each output's
  maturity.

| outputs to merge | transactions at a cap of 8 | at 22 |
| ---: | ---: | ---: |
| 20 | 3 | 1 |
| 100 | 17 | 5 |
| 1 000 | 167 | 50 |

**What the cap does not buy is uniformity.** At any cap the count stays public
and correlates with wallet state. Uniformity would mean fixed-count
transactions padded with dummy inputs, each needing a real membership proof
(6.2 KB and 50 to 77 ms per input on the diagnostic Pi), which this round does not
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
the cell is legal, and prices every cell at one fee width, the 10-byte varint
of `u64::MAX` (`rust/shekyl-engine-core/src/engine/bond_orchestrator.rs:79-84`).
At 8 that is harmless (the scan's maximum, 8 inputs at depth 24, is legal). At
22 the unbounded scan returns 204 137 bytes, a 22-input spend at depth 24 that
CEN-H3 refuses. Filtering those cells at the 10-byte fee alone is not enough
either: it drops 16 inputs at depth 23 (148 617 bytes at that fee), which is
legal with a fee varint of 7 bytes or fewer, and would leave the ceiling below a
legal spend. Over today's depths 2 to 24 the heaviest legal `P`-lane spend
weighs exactly the weight limit, 148 614 bytes (16 inputs, two outputs, depth
23, a 7-byte fee); **with the maximum depth at 14 (`ICD-R9`) it is 148 521
bytes** (22 inputs, two outputs, depth 4). The cutover's scan reads the
legal-shape function (below), which answers per shape and fee width, so it
cannot fall below a legal spend. At a pinned 0.05 SKL the reserve's head-room
would fall from about 600 to about 337 atomic per weight byte; instead the
reserve is computed from the ceiling at 600 (`ICD-R10`: 89 113 000 atomic,
about 0.0891 SKL, with the rule-175 bounds re-checked against the rung). (The
reserve's comment gives today's ceiling as 80 456 bytes; the weight model gives
79 625 for the same shape at a 10-byte fee varint. The comment likely predates
the 2026-09-14 proof-size re-measurement; the computed reserve replaces both
figures.)

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
§80.3 shape, accepted with the rest under `ICD-R8`. Whether the carrier keeps a fragment train at
all is cover-by-shape's question (`CBS-`, not yet ruled), and it goes to Rick
with that design, not to this round.

**Benches and sims (copy):** `shekyl-verify-cost`'s
`relay_admission_verify.rs` (`1..=8`) and `block_connect_verify.rs`'s
`SWEEP_SHAPES` (the GAP-7 sweep, §3);
`scripts/bench/test_rt_p5_classes.py`'s pinned 8-in/16-out cell.

**The economics sim (read through `InputCount::clamped`; it never reads
`TX_WEIGHT_LIMIT`, `jg_report.rs` says so).** Listed with the sim lane
(ESR, 2026-11-22):
- `calibration.rs`: `all_shapes` (`1..=` the cap × `1..=MAX_OUTPUTS`), and the
  three readers of it: `stuffer_shape`, the one-shot W9 stuffer (the most
  archival bytes per fee); `max_archival_bytes_per_block`, the physical ceiling
  on the fold's slew; and `sustained_stuffer_cost_per_shard_atomic`, the
  output-conserving cycle, which consumes the cap minus one outputs per
  transaction at the 1-output shape it uses today and the cap minus two once it
  starts at CEN-I1's minimum (`ICD-F17`);
- `miner_stuffer.rs`: the miner's stuffing body, searched over `all_shapes()`
  at two sites (`:514`, `:1342`), which drives the A-stuffed economy;
- `MAX_TREE_DEPTH`, read through `shekyl-tx-weight` in `burden.rs` and in
  `calibration.rs`'s `tree_depth_for_leaves` and `stuffer_txs_before_deepening`.
  The ruled depth 14 (`ICD-R9`) does not move the sim's results: no fold reaches 10^17
  outputs.

Once the cap exceeds `N(d)` at some depth, a search over `1..=cap` picks
shapes consensus refuses, which is why the cutover gives the sim the
legal-shape function below instead of the bare cap. Under the cutover the sim
reads the landed, computed structure, so it tests what is built. Honest
traffic is fixed at 1-in / 2-out (`burden::normal_tx_shape`), so the honest
economies do not move.

**`ICD-F17` — the builder accepts shapes CEN-I1 refuses, and the sim prices
its stuffer on one.** The builder refuses only zero outputs
(`rust/shekyl-tx-builder/src/validate.rs:45`), while CEN-I1 refuses fewer than
two on every non-coinbase transaction. `all_shapes` runs from one output, and
`stuffer_shape`'s argmax is "`MAX_INPUTS`-in / 1-out" (`calibration.rs:17-21`),
a transaction no node admits. This is the census row's class (FOLLOWUPS, "The
census does not record which library-crate constants a consensus rule's value
depends on"), with the library looser rather than tighter. The legal-shape
function closes it at both ends. CEN-I1's minimum is itself a bare literal (`outputs.len() < 2`,
`rust/shekyl-chain-rules/src/rules/tx_inputs.rs:70`, and the literal 2 in
`shekyl-wire`'s pruned and full spend checks). **The cutover reads the constant
landed by #1534, the sim lane's minimum-output PR, and does not create it**
(Rick, 2026-11-22: one variable moves in one PR).
#1534, which lands first, names the minimum once as
`shekyl_wire::transaction::MIN_NON_COINBASE_OUTPUTS` beside `MAX_OUTPUTS`,
points CEN-I1, the two wire checks and the builder's `TooFewOutputs` refusals
(`sign_transaction`, `BuiltSpend::build`) at it, and starts the sim's
`all_shapes` there; the legal-shape function reads it, and when the function
lands the sim moves onto it. (#1534 also makes the weight table's measurement
cell sign two outputs: the proof length it measures is unchanged, and a
sign-time figure taken across it differs by one range-proof round.)

**The legal-shape function (cutover scope).** Under `ICD-R1`, `shekyl-wire`
exposes one function for the shapes legal at depth `d`: the outputs from
CEN-I1's minimum to `MAX_OUTPUTS`, and for each the largest input count the
weight limit admits at that depth, `N(d, n_out)`, never above the cap. Its
readers: the builder (refusing what consensus refuses, before signing), the
wallet's per-depth limit, the sim's `all_shapes`, the GAP-7 sweep's shapes,
and the P-lane ceiling's scan (`ICD-F11`), which then scans only legal cells.
Nobody copies the weight limit or the output minimum.

**What goes red in the sim at the cutover, and how it is regenerated.**
EUP-4 prep 3's whole-economy table (#1476): the A-stuffed rows, the stuffed
tail's floor, the C arms' adversary columns (C3's D2 escalation prices against
the W9 stuffer), and the nightly slice's narration and table; and the
narration pins that include stuffing (ESR-10, EUP-4, J×G, and any others the
economics-sim-narrations job names). Each is regenerated in the cutover PR
under `SHEKYL_PINNED_REGEN_DECISION`, citing a dated entry in
[`ECONOMICS_SIM_PRODUCTION_REBASE.md`](ECONOMICS_SIM_PRODUCTION_REBASE.md). The
full table (2 880 folds, about 14 hours on a 16-vCPU host) is an on-demand
fleet run the sim lane runs once the cutover branch is ready.

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

- **The embargo table, every cell, on the floor device in one session
  (`ICD-R5`).** `n_in = 1..=N(d)` at every depth tier the table covers, since a
  cell no legal transaction fills is not measured: 22 cells at each of depths
  2, 3 and 4, 21 at depths 5 and 6, 20 at depth 7, so 128 cells, the existing
  ones remeasured beside the new ones. On the floor device's configuration
  (§9, `ICD-R5`) and nowhere else, after its cover-by-shape run ends
  (2026-11-24T17:11Z); never scaled from x86 or from the diagnostic Pi (§80.3's
  correction; the `Provenance` test refuses a scaled cell), never mixing
  devices, with the depth-7 column labelled a synthesized projection (§81.2);
  claimed in the estate's usage file before the run (rule 38). The embargo
  floor (#1516) follows from the table.
- **The GAP-7 sweep at the new shapes** (§3), on the floor device.
- **The standoff reserve** re-derived (§7).
- **The model's test vectors:** the 192 KAT cells and the real proofs past 8
  inputs pinned against the `const` `FcmpPlusPlus::proof_size` (`ICD-R1`), and
  the two generator counts asserted equal to the computed need (`ICD-R2`).
- **Tests on the real pathway:** a transaction of `N` inputs built, proved,
  relayed and mined on regtest at a depth where the weight limit admits it
  (2 to 4). One input more is refused where the pathway actually refuses it,
  and each test names that refusal: on relay, the wire parser's count
  refusal (`Transaction::validate`, reading the computed cap) before any rule;
  in a block, CEN-I4, which the cutover judges immediately before CEN-H3
  (`ICD-R6`; today `tx_form` runs H3 first,
  `rust/shekyl-chain-rules/src/validate.rs:826-830`). The ruled test: a
  23-input transaction at depth 2, refused with CEN-I4 named in a block and
  cited at the parser. At a depth where `N(d) < N`, a transaction of `N(d) + 1`
  inputs is within the cap and over the weight limit, and CEN-H3 names it.

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
  weight limit and the ruled maximum depth of 14 (`ICD-R9`) it is **8 192
  Selene and 4 096 Helios rows**, an eighth of the 65 536 and 32 768 built
  today for upstream's 128 inputs at 12 layers. (At today's depth 24 it would
  be 16 384 and 8 192, both reached at depth 24.)
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
domain all read the depth. The derivation is `ICD-R9` (14, in two steps), and
one constant results: `MAX_FCMP_LAYERS` and `MAX_TREE_DEPTH` stop being two
numbers.

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
- **Repeated verification of a refused transaction (`ICD-F18`).** A
  transaction whose proof is valid but which state or fee policy refuses keeps
  the session open and is verified again on every resend. The budget is
  charged by verification work done, per session as well as per reconnect,
  whatever the outcome; a memory of refused transactions is one input to that
  design, not a substitute for it, since the bytes are free to vary for anyone
  willing to prove again.
- **The queue for unverified sessions:** its bound, and what is dropped when it
  is full.
- **The privacy cost, stated,** when a stem transaction is dropped or delayed.
- **Tor,** which has no daemon-side accept limiter.
- **The budget in core-time,** read from `f(n_in, depth)`.

### `ICD-R5` — one named floor device, and every embargo cell measured on it in one session (from `ICD-F12`) — RULED

**The floor is a configuration (Rick, 2026-11-22):**

| | the floor device | the diagnostic Pi (§2.6) |
| --- | --- | --- |
| board | Raspberry Pi 4 Model B **Rev 1.4** | Raspberry Pi 4 Model B Rev 1.2 |
| CPU | Cortex-A72 ×4, **1.8 GHz** maximum | Cortex-A72 ×4, 1.5 GHz maximum |
| RAM | **8 GB** | 4 GB |
| OS | Ubuntu 26.04.1 LTS, kernel 7.0.0-1023-raspi, 64-bit | the same |
| governor | `ondemand` | the same |
| toolchain | rustc 1.94.0 aarch64 | the same |
| role | **the floor: every floor measurement runs here, and only here** | relieves test load; usable for ratios, builds and tests; never the worst case |

Read on 2026-11-22 from each device. The floor's 8 GB meets Rick's standing
recommendation of at least 8 GB for a 64-bit system running the post-quantum
algorithms. The two units differ in board revision, clock and RAM, not in
software; the clock ratio (1.20) accounts for `ICD-F12`'s 19 %. The two-unit
comparison run first proposed here is dropped: the floor is named, so the
other unit's numbers are diagnostics whatever their cause.

- **The cutover measures every embargo cell on the floor device in one
  session,** after the cover-by-shape run on it ends (2026-11-24T17:11Z):
  `n_in = 1..=N(d)` at depths 2 to 7, 128 cells. The table never mixes devices.
  The embargo floor (#1516) follows from the table.
- **The existing cells are remeasured with the new ones (this lane's call).**
  The 48 cells already measured on that device stay valid as records, but the
  table's own notes record its masks-and-proof terms as pre-`PL-D3`, and one
  session on one binary is the only way every cell answers the same question.
  So all 128 are measured together, and the old cells are kept as the prior
  they are compared against, as §81.3 asks of a re-measurement.

## 10. Handed to EUP-5 G — findings

- **`ICD-Q6` — weight against verification cost.** The cost per weight byte
  already spreads from 8.92 to 13.33 µs across today's shapes on the diagnostic Pi
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

### Second rulings — RULED 2026-11-22 (Rick, at `97dda2dd76`)

These, with `ICD-R11` and `ICD-R12` after them, close every question the round
had open except the cover carrier's fragment count (§11).

#### `ICD-R6` — CEN-I4 stays an explicit rule at the derived value (was `ICD-Q1`) — RULED

The parser refuses on the input count, reading the computed cap (`ICD-R1`), and
a test pins that a 23-input transaction is refused with CEN-I4's name. This
document's later recommendation to delete the rule, made after review showed
that no path reaches the chain-rules I4 arm today, is superseded. The ruling's
test cannot pass on today's order, so the cutover makes CEN-I4 the refusal
that fires (the order is ruled as `ICD-R11`):

- **In a block,** `tx_form` judges CEN-I4 in its first band, immediately
  before CEN-H3: the count bound before the weight bound. Today H3 runs first
  (`rust/shekyl-chain-rules/src/validate.rs:826`), and every `N + 1`-input
  transaction is over the weight limit, so H3 names it. With I4 first, I4 names
  it. Only the row naming that refusal changes; what is accepted does not, and
  the class rows (H20 to H22) still come after both, as now.
- **On relay** the wire parser's count refusal (`Transaction::validate`,
  reading the computed cap) runs before any rule; its error cites CEN-I4, the
  row it enforces at the parser.
- The test: a 23-input transaction built at depth 2, refused in a block with
  CEN-I4 named, and refused at the parser with CEN-I4 cited.

#### `ICD-R7` — no rounding to a padding boundary (was `ICD-Q3`) — RULED

The cap is what the weight limit admits. The padding's cost per transaction is
priced by the relay round (`ICD-R4`), measured by the batched GAP-7 sweep (§3),
and may be priced into weight by EUP-5 G (`ICD-Q6`).

#### `ICD-R8` — the coupling to the weight limit is accepted (was `ICD-Q5`) — RULED

Every table checks its range against the computed constant at compile time, so
a weight-limit change fails the build until the new rows are measured: the
generator counts, the embargo table's rows, the proof-size vectors, the
reserve, the sweeps and the cover carrier's fragment count.

#### `ICD-R9` — the maximum tree depth is 14, derived in two steps (was `ICD-Q7`) — RULED

**Step 1, the floor: 12.** The margin is measured on Shekyl's own limit. An
output costs 1 269 bytes of weight (35 for the output, 50 of CT base, the
1 120-byte KEM ciphertext and a 64-byte leaf entry), so the store's write
budget, PB-R2 (`DAEMON_REDB_STORE.md` §1.3a: at most 1 GB a day on the floor
device at design load), bounds the chain at about 788 000 outputs a day. The
tree holds every output ever created, so the bound is on cumulative outputs:
depth 12 holds about 10^17, about 360 million years at that rate. (At today's
300 000-byte zone, full blocks every 120 s write about 216 MB a day, about
170 000 outputs, inside the budget.)

**Step 2, the maximum: the deepest tree that needs no more generators than the
floor does.** At today's weight limit that is **14**. Depths 12 to 14 all need
8 192 Selene and 4 096 Helios rows (`ICD-R2`); depth 15 doubles the Selene
count, since its cap of 18 inputs needs 18 × (111 + 7 × 52) = 8 550 rows. Depth
14 holds 7.0 × 10^19 outputs, about 2.4 × 10^11 years at the write budget, and
the cap at the deepest tree stays 18.

| max depth | outputs | years at the write budget | cap at the deepest tree | generators (Selene / Helios) | embargo cells, depths 2 to D |
| ---: | ---: | ---: | ---: | --- | ---: |
| 10 | 1.5 × 10^14 | 520 000 | 19 | 8 192 / 4 096 | 187 |
| 12 (the floor) | 1.0 × 10^17 | 3.6 × 10^8 | 18 | 8 192 / 4 096 | 224 |
| **14 (ruled)** | **7.0 × 10^19** | **2.4 × 10^11** | **18** | **8 192 / 4 096** | **260** |
| 15 | 2.7 × 10^21 | 9.2 × 10^12 | 18 | 16 384 / 4 096 | 278 |
| 24 (until the cutover) | 1.0 × 10^34 | 3.6 × 10^25 | 15 | 16 384 / 8 192 | 425 |

- **Why the extra margin is taken.** At the ceiling the chain accepts no new
  outputs, raising it is a hard fork, and between 12 and 14 the margin is
  free: the same generators, the same cap at the deepest tree, and embargo
  cells measured only if the tree ever gets that deep.
- **Where it lives.** The one constant sits in `shekyl-curve-generators`
  beside the counts (`ICD-R2`). `shekyl-wire` asserts at compile time that it
  equals step 2's derivation, so a weight-limit change that moves the free
  depth fails the build. `MAX_FCMP_LAYERS` and `MAX_TREE_DEPTH` become this one
  constant; every reader of either (the weight model and its re-export, the
  prover's and builder's depth checks, the P-lane ceiling, the engine's fee
  query and dust bar at `D_ref`, the sim's depth maps, the cover carrier's
  largest-transaction size) reads it.
- **What re-checks it.** Block size is dynamic and the write budget is a
  design budget, not a consensus limit, so step 1's floor is re-checked when
  EUP-5 G rules block growth, and step 2 follows any weight-limit change
  through the build.

#### `ICD-R10` — the standoff exit-fee reserve is computed, not pinned — RULED

**The reserve is the heaviest legal `Release` weight times a headroom rate**,
as a constant expression, rounded up to the fee lattice
(`shekyl_economics::FEE_QUANTIZATION_MASK`, 1 000 atomic units), because the
fee a `Release` actually pays is quantized up to it.

- **The heaviest legal `Release` weight** comes from the legal-shape function
  (below) over depths 2 to 14: **148 521 bytes** (22 inputs, two outputs,
  depth 4). With depths above 14 no longer legal, the 148 614-byte shape at
  depth 23 (`ICD-F11`) drops out.
- **The headroom rate stays 600 atomic units per weight byte, an Assumption.**
  Its basis, "600 times any observed floor", is replaced when the fee
  ladder's own maximum rate exists (EUP-5 G).
- **Today's value:** 148 521 × 600 = 89 112 600, rounded up to **89 113 000
  atomic units, about 0.0891 SKL** (from 0.05).
- **What it costs.** A fresh persona's protocol cover draw, uniform over
  `[1, rung)` with the rung at 0.75 SKL, clears the reserve with probability
  1 − 89 113 000 / 750 000 000 ≈ **88.1 %**, down from 93.3 %; the reserve is
  about 1/8.4 of the rung, against 1/15. The §7.2 zero-fee-input escape still
  funds a `Release` over an underfunded pool
  (`ARCHIVAL_BOND_CONSTRUCTION.md` §7.2), so the larger corner strands value
  until earnings or retirement but bricks nothing.
- **Rule-175 bounds re-checked:** `0 < 89 113 000 < 750 000 000`. The engine's
  assertion that the reserve is below one cover rung
  (`the_exit_fee_reserve_is_below_one_cover_rung`) holds.
- **Placement.** `shekyl-standoff` today depends on nothing and states that it
  reads no consensus constant (`reserve.rs`). The computed reserve needs the
  wire's legal ceiling and the fee lattice, so the cutover gives the crate those
  two dependencies and restates that sentence; the rung assertion stays in
  `shekyl-engine-core`, where the rung is visible.

#### `ICD-R11` — the cap is checked before the weight (was `ICD-Q8`) — RULED

`tx_form` judges CEN-I4 immediately before CEN-H3 in its first band, and the
wire parser's count refusal cites CEN-I4, so `ICD-R6`'s test holds on both
paths. Today H3 is in the first band and I4 in the third
(`rust/shekyl-chain-rules/src/validate.rs:826`, `:830`).

The comment at `validate.rs:807` ("Pulling I1 or I4 ahead of H21 would hide
the class failure") exists so that a malformed bond post is named by its shape
rule, not an input rule. For I4 it no longer applies: every transaction I4
refuses is also over the weight limit (§2.2, §2.3; a transaction carries at
most one bond-post or emission input, and those are heavier than a spend
input), and H3 already runs ahead of the shape rules, so an over-cap
transaction is named by H3 today, never by its shape. Moving I4 just before H3
hides nothing that is not hidden now: only the name on the refusal changes, and
the cheaper check runs first. **The reasoning does not cover CEN-I1** (the
two-output minimum), so I1 stays in the third band; the cutover rewrites the
comment to say so.

#### `ICD-R12` — the row floors stay; `ICD-F16` closed — RULED

`C1_TARGET_ROWS` and `C2_TARGET_ROWS` stay as they are. The trace holds: the
tape places witness values in `COMMITMENT_WORD_LEN = 128`-slot words
(`rust/shekyl-oxide/crypto/fcmps/src/tape.rs:20`), and the floors are the
smallest sizes that layout can hold, not a tuning knob. Going lower means
changing the circuit's word length, a departure from what upstream had audited,
for one or two 11–15 % steps on small spends that end at about 18 million
outputs. Not done.

#### Cutover additions (Rick, 2026-11-22)

- **The legal-shape function is scoped to consensus.** It answers what can be
  mined: the output count from `MIN_NON_COINBASE_OUTPUTS` to `MAX_OUTPUTS`,
  depths 2 to the ruled maximum, and the input count the weight limit admits
  for each, never above the cap. Relay policy (the weight gate, the fee floor)
  keeps its own narrower rules on top and does not go in it.
- **The builder reads it.** #1534 (the sim lane's, landing first) already makes
  the builder refuse fewer than `MIN_NON_COINBASE_OUTPUTS` outputs by name
  (`TooFewOutputs`); the cutover moves that refusal and the input-count refusal
  onto the function, so the builder asks one question.
- **The wallet's refusal at the cap** (#1527, the wallet lane: a selection
  longer than `shekyl_tx_builder::MAX_INPUTS` refuses as
  `SignFault::TooManyInputs`, `-29123`, in `build_select_sync`) reads the
  constant, so the computed cap moves it with no edit; whichever of #1527 and
  the cutover lands second takes the textual merge.
- **The engine's restated two-output floors are deleted.** `stake_engine/bond.rs`
  and `stake_engine/release.rs` split change and payout in halves
  (`change / 2`, `payout / 2`) under comments restating the daemon's
  `vout.size() < 2`. The split reads the minimum instead. **`ICD-F19`, an edge
  on those lines:** a change or payout under 2 atomic units halves to a
  zero-valued output, which the builder refuses with the generic
  `ZeroOutputAmount`; the cutover's split refuses that case by name before
  building.
- **The ordinary send cannot reach the builder with one output** (traced
  2026-11-22): `transfer/engine.rs` requires the selected inputs to cover the
  payments, the with-change fee and `MIN_CHANGE`, so a change output always
  exists, and no sweep surface exists (`sweep_all` was removed from the CLI).
  `fee_and_change`'s no-change branch (`fee_variant.rs:73-77`) is unreachable
  from that path with one recipient.
- **`ICD-F20` — a multisig intent with fewer than two recipients passes
  structural validation.** `SpendIntent::validate_structural` bounds the
  recipients above (`MAX_RECIPIENTS`) and not below, so a group can run a
  signing ceremony over an intent no transaction can carry, refused only at
  build (by #1534's `TooFewOutputs`). The intent's own principle, that an
  intent no transaction can carry is refused before anyone signs, puts a
  `MIN_NON_COINBASE_OUTPUTS` check there. **Owned by #1510** (the multisig
  lane): a new `SpendIntentError` variant refusing fewer than the minimum, in
  `validate_structural`. It shares no variable with the cutover's edit to
  `intent/mod.rs:73` (`MAX_INPUTS`), so whichever lands second takes only a
  textual merge.
- **The GUI wallet PR** reads the cap from the core crates and replaces the
  hard-coded `estimated_proof_size_kb: 4.5` with the model's figure at the
  tree's depth.
- **The economics sim's calibration domain** reads the landed constants and
  the legal-shape function, so the sim tests the built structure.
- **`ICD-F17`, the sim lane's calibration run — done 2026-11-22.** The shape
  search started at two outputs on #1534's constant, at cap 8, depths 1 to 13
  and three rates (20, 300 and 34 133 atomic per byte), which agree. The
  one-shot W9 stuffer costs 2.0 to 2.5 % more per shard and stays at 8 inputs,
  now 8-in / 2-out at every depth (its runner-up, 7-in / 2-out, is 0.44 to
  0.62 % dearer); the sustained cycle costs 1.1 to 2.7 % more; at the surge
  ceiling the archival bytes per block fall by up to 6.0 % by depth, and A6's
  worst slew goes from 0.7558 to 0.7326 points an epoch; the miner's own
  stuffing in full blocks (ESR-7) moved most, 8 to 10 % per shard. The
  ceiling's winning shape was never a stable 6-in versus 8-in pair, so the
  "≈3 % margin" was one depth's reading. No honest narration line moved. The
  instrument, `calibration::tests::stuffer_calibration_by_depth` (on demand,
  on #1476 at `85803a140c`), reruns unchanged at the cutover for the 22-input
  figures; the 2 880-run table stays with the cutover.

## 11. Still open

### The cover carrier's fragment count

`MAX_FRAGMENTS` becomes 8 at the derived cap (`ICD-F14`). Whether the carrier
keeps a fragment train under cover-by-shape is that design's question, and its
measuring run ends 2026-11-24. This round asks for it to be ruled after that
run, with the cap's value in hand.

## 12. Out of scope

Automatic consolidation in the wallet: its own design round, with its privacy
cost priced (FOLLOWUPS, the wallet's consolidation row). The sim does not model
consolidation either (its traffic has no mix of shapes); that is a modelling
question after the current sim series, raised with Rick by the sim lane. Relay verification:
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
- **2026-11-22 — `ICD-F12` ruled into `ICD-R5`; `ICD-F16` recorded and closed;
  `ICD-Q7` restated.** The floor device is the Rev 1.4, 8 GB, 1.8 GHz Pi 4
  (configuration in §9); §2.6's unit is a diagnostic, and every absolute figure
  taken from it is marked not a floor value. The two-unit run is dropped. The
  row floors are the vector-commitment tape's minimum (`ICD-F16`). `ICD-Q7`'s
  margin is measured against the store's write budget (PB-R2), not other
  chains' rates.
- **2026-11-22 — the sim's consumers and the legal-shape function.** From the
  sim lane, on Rick's word: §7 lists the sim's readers in full, `ICD-F17`
  (the builder and the sim accept 1-output shapes CEN-I1 refuses) is recorded,
  and the cutover gains one legal-shape function in `shekyl-wire` that the
  builder, the wallet, the sim, the GAP-7 sweep and the P-lane ceiling read.
- **2026-11-22 — review findings on #1528, each checked against the code.**
  `ICD-F18` recorded (a valid transaction refused on state or fee policy is
  re-verified without limit on one session) and handed to the relay round's
  requirements. `ICD-F9` restated as two lone-transaction brackets (+6 % with
  the range proof, +17 % with it batched), the block figure left to the
  batched GAP-7 sweep. The consolidation counts corrected for CEN-I1's second
  output (167 and 50 transactions for 1 000 outputs, not 143 and 48). The
  P-lane ceiling corrected to the weight limit itself, 148 614, with the
  scan's fee width named. The test plan names the refusal each path produces,
  and `ICD-Q1`'s recommendation changed to deleting the rule, since no
  transaction reaches it.
- **2026-11-22 — second rulings (Rick, at `97dda2dd76`).** `ICD-R6` (CEN-I4
  stays, with a test that names it; the later recommendation to delete is
  superseded, and `ICD-Q8` asks to confirm the rule order the test needs),
  `ICD-R7` (no snap), `ICD-R8` (coupling accepted), `ICD-R9` (maximum depth 14:
  floor 12 on the write budget, then the deepest tree needing no more
  generators), `ICD-R10` (reserve computed: 89 113 000 atomic today). Cutover
  additions recorded: the legal-shape function scoped to consensus, the builder
  on it (#1534 lands the minimum first), the engine's restated two-output
  floors deleted (`ICD-F19`, the zero-output edge on those lines), the send
  path traced (no one-output route), `ICD-F20` (a multisig intent with fewer
  than two recipients passes structural validation), the GUI's proof-size
  literal, and the sim's two-output calibration run. Still open: `ICD-Q8`, the
  row-floor decision, the fragment count.
- **2026-11-22 — `ICD-R11` and `ICD-R12` (Rick).** The cap is checked before
  the weight (was `ICD-Q8`); the comment that seemed to forbid it guards CEN-I1,
  not CEN-I4, and is rewritten in the cutover. The row floors stay and
  `ICD-F16` closes. The 360-million-year figure and the computed reserve's new
  `shekyl-standoff` dependency on the wire crate are confirmed. Open: the
  fragment count only.
