# The shard-count cutover — census and tracking

**Status:** OPEN — **Round 0 executed 2026-09-27 at `9d549ead2`** (census and
tracking). **AMENDED the same day** on the design owner's review: `SCC-4` widened
from two definitions to **six** and **fixed here** (the one code change this round
carries, `SCC-Q5`), and `SCC-Q1`, `SCC-Q3`, `SCC-Q4`, `SCC-Q5` answered — `SCC-Q2`
stands as Rick's ruling. Identifier families **`SCC-`** (findings) and
**`SCC-Q`** (questions), registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 with this file (rule 94
§1; `check_index_prefix_uniqueness.py` branch (a) — `SCC` parses as its own
prefix and is clear of `SCW`, `SCE` and `SCU`).

**Design owner:** Claude (claude.ai, Shekyl project). **Rick authorizes and
ratifies.** No consensus change lands without a rule-07 ratification.

**This document is the effort's durable record.** Anything decided in the
design-owner lane that is not written here does not exist. That is the whole
point of it: the rulings below were taken across several sessions, and a
conversation is not a record.

**One sentence.** The shard partition was re-defined by `SHT-Q1` and the segment
geometry it inherited is retiring, so every consumer that counts shards, closes
them, or reads a constant calibrated in *segment* units has to be found,
classified and cut over — in two atomic groups, because one of those constants
feeds the coinbase's fee split — harmlessly today, since the escalation ships
flat, and decisively the moment the GF-7 ceremony turns the ramp on.

---

## A. Scope and ruled inputs

Three rulings are inputs here, not questions. Each is recorded in full at its own
home; the operative consequences are restated only as far as this census needs.

| input | ruling | home |
|---|---|---|
| **`SHT-Q1`** | **RULED (Rick, 2026-09-27, design-owner lane): the partition is over transactions that carry archival good** — a non-empty prunable region or `pqc_auths`, decided from the **rows recorded at ingest**, never recomputed from a possibly-pruned body. Shard `k` is the domain's transactions `[k·T, (k+1)·T)` in chain order. **Shards close on count only; there is no clock.** The coinbase is outside by the definition, not by exclusion. Closed shards never change membership; any later change to what counts as good activates by height. The equality with the non-coinbase set is an **invariant, not a definition**, pinned by `rules::tx::tx_domain_tests` and leg (f). | [`ARCHIVAL_SHARD_T_DERIVATION.md`](ARCHIVAL_SHARD_T_DERIVATION.md) §2 |
| **`SHT-8`** | D2's operand `n` and `g(age)`'s no-segment branch are keyed on the **retired** segment count. `n` reaches consensus, and a shard-unit re-key would move `escalation_knee_n` ~65× sooner and make `T` a clock on monetary policy — **once the escalation is switched on**. It is flat at the shipped parameters (§G `SCC-Q2`), so the re-key is behaviour-neutral today. | same doc, §6 and §5 |
| **`L2`** | **RULED and withdrawn as a bound on `T`.** `MAX_HOLDINGS_SHARDS` is a **list-size bound** on one bond record and one transaction, not bond-size policy; personas are free (G-1) and splitting is rational, so no per-persona limit binds. The 13.6/13.7 GB byte products are retired from reasoning. Two couplings survive, owed **only if the cap's own value moves** (§E). | same doc, §3 `L2` |

**Out of scope for this round:** any code change, any re-derivation of a
constant's value, and the `PDM-Q-F34` sim arms (their own FOLLOWUPS rows).

---

## B. The census

**Method, and why it is grep-driven.** `PDM-Q6` item 4 produced a nine-row
re-key table by hand and **missed both D2's `n` and `escalation_knee_n`**
(`SHT-8`) — an economics operand in another crate was not on anyone's list. So
every hand-made list is treated as incomplete, **including this one**, and each
row below is a grep result at `9d549ead2` rather than a recollection.

### `SCC-1` — the census's own first hazard: "segment" is two different words

A bare grep for `segment` conflates two unrelated things:

- **curve-tree J-segments** — the retiring geometry: `SEGMENT_LEAF_COUNT`,
  `leaves_per_segment()`, `SEGMENT_LAYER_J`, `frozen_segment_count`.
- **transaction body segments** — permanent and unrelated: `write_segments()`,
  `TxPrunedSegment`, `TxPqcAuthsSegment`
  (`rust/shekyl-chain-store/src/store/connect.rs:403-414`, re-read
  2026-09-29 after E6 slice 7 wave B shortened the file).

This is not pedantry: it is how a seeded row in this round's own brief acquired a
false premise (`SCC-2`). Family 2's greps below therefore key on the **specific
symbols**, never on the word.

### Family 1 — shard closure and the domain

What changes under `SHT-Q1`: **which ids are in the domain**, and therefore which
ids a boundary falls between. Nothing here needs a shard to close by height —
verified as `SHT-Q1`'s own falsifier.

| consumer | file:line at the pin | what it computes | class | changes under `SHT-Q1` | old-unit constant |
|---|---|---|---|---|---|
| the partition constant | `rust/shekyl-types/src/archival.rs:94`, generated by `rust/shekyl-types/build.rs:70`, `> 0` assert at `:101` | `T`, the one home | consensus | value only (`T` is a count either way) | `archival_shard_tx_count` |
| storage-id arithmetic | `rust/shekyl-types/src/archival.rs:111` (`storage_ids_through`) | ids through a height = `listed + height + 1` | consensus | **yes** — the coinbase term is what the domain excludes | — |
| the discard range | `rust/shekyl-chain-store/src/store/prune.rs:267` | `shards.start·T .. shards.end·T` | consensus (node-local effect) | **yes** — the range is over domain ordinals, not storage ids | — |
| the id→shard map | `rust/shekyl-chain-store/src/store/prune.rs:415-416` | `⌊id / T⌋` for the boundary pair | consensus | **yes** — becomes `⌊ordinal / T⌋` | — |
| the last closed shard | `rust/shekyl-chain-store/src/store/prune.rs:490`, `:493` | `⌊hi_id / T⌋ − 1`, then its last id | consensus | **yes** | — |
| `first_tx_id` | `rust/shekyl-chain-store/src/store/prune.rs:434`, callers `:411-412`, `:489` | adds the coinbase term | consensus | **yes** — the addition **goes away** under the domain (`cumulative_tx_count` *is* the non-coinbase ordinal, `listed_before` at `:421-428`) | — |
| `h_scarce` | `rust/shekyl-chain-store/src/store/prune.rs:477`, public at `:380` and `:548` | the last discarded shard's close height, via `height_of_tx_id`'s binary search (`:498`) | node-local | **yes** (its operand) — but the search itself already exists and is reused | — |
| the domain predicate | `rust/shekyl-wire/src/transaction/txid.rs` (`carries_archival_good`), production path `rust/shekyl-chain-store/src/store/read.rs:735` → `tx_reads.rs` | domain membership from the two ingest rows | consensus | **landed** — this is `SHT-Q1` as built | — |
| shard identity and holdings | `rust/shekyl-archival-retention/src/**` — 156 `shard_id`, 103 `shards`, 51 `shard_ids`, 36 `shard_age_milli`, 18 `r_market_by_shard` | bond holdings, admission, challenge draw, settlement | consensus | **yes, by enumeration** — every site that names or iterates shard ids | `segment_leaf_count` via `shard_age_milli` (family 2) |
| wallet-side serve sets | `rust/shekyl-engine-core/src/engine/curve_tree_actor.rs:201`, `:378` (`pin_serve_set`), `rust/shekyl-engine-core/src/engine/bond_assembly.rs:584`, `rust/shekyl-engine-core/src/engine/bond_orchestrator.rs:427` | which shards a persona pins and posts | wallet | **yes** | — |
| the FFI archival shims | `rust/shekyl-ffi/src/archival_ffi/*` (bond, emission, attestation, epoch_close, ct_balance, codes), `archival_admission_ffi.rs` | the C++ boundary for all of the above | consensus | **yes, wherever a shard id crosses** | — |

**`SCC-2` — a correction to the brief's family-1 list.** It named
archival-retention's `bond_duration`, `failure_window`, `serve_credit_decisions`,
`emission_verify` and `consensus_state` under *shard closure*. What those read is
**`epoch_close_height`** (`rust/shekyl-archival-retention/src/consensus_state.rs:67`; callers `rust/shekyl-archival-retention/src/bond_duration.rs:112`,
`rust/shekyl-archival-retention/src/emission_verify.rs:471`) — the **settlement-epoch** close, `H_close(E) = (E+1)·SEB`,
which has nothing to do with a shard closing. Two different "close" notions share
a word. Those files are in family 1, but through **shard identity**
(`shard_age_milli`, `r_market_by_shard`), not through closure. Recorded because a
cutover that re-keys `epoch_close_height` would be changing the settlement
calendar by accident.

### Family 2 — the segment geometry and D2's operand

| consumer | file:line at the pin | what it computes | class | old-unit constant |
|---|---|---|---|---|
| the geometry constant | `config/consensus_constants.json:53` (`segment_leaf_count = 25992`), prose at `:52` | the level-2 subtree leaf count, `38·18·38` | consensus | itself |
| its generated home + the tripwire | `rust/shekyl-archival-retention/build.rs:234-249`, **compile-time assert at `rust/shekyl-archival-retention/src/segment_freeze.rs:63`** tying `SEGMENT_LEAF_COUNT == leaves_per_segment()` | ties the JSON key to the **proof topology** | consensus | `segment_leaf_count` |
| the operand itself | `rust/shekyl-archival-retention/src/segment_freeze.rs:91` (`frozen_segment_count`), labelled *"the D2 escalation operand"* at `:52` | `leaf_count / SEGMENT_LEAF_COUNT` | consensus | `segment_leaf_count` |
| **the C++ consensus read** | `src/cryptonote_core/blockchain.cpp:1494-1505` (`parent_frozen_segment_count` → `shekyl_archival_frozen_segment_count(m_db->get_curve_tree_leaf_count())`, under a **throwing** read-point assert), feeding `validate_miner_transaction` at `:1508` | the coinbase's fee-split validity | **consensus** | `segment_leaf_count`, `escalation_knee_n` |
| the escalation ramp | `rust/shekyl-economics/src/escalation.rs:269` (`staker_pool_share_at`), the type at `:48-58`, the split at `rust/shekyl-economics/src/burn.rs:188-191` | the staker share of the burn, saturating at `knee_n` | consensus | **`escalation_knee_n = 100000`** (`config/economics_params.json:17`) |
| block template | `rust/shekyl-block-template/src/lib.rs:142` (`frozen_segments`) | the template's operand, read at the same parent state | consensus | as above |
| ingest scenario | `rust/shekyl-chain-ingest/src/scenario.rs:414` | `FrozenSegmentCount::ZERO` | node-local (harness) | — |
| the curve-tree geometry | `rust/shekyl-curve-tree/src/segment.rs:20`, `:63`, `:81`; `rust/shekyl-curve-tree/src/store/ops.rs:8`, `:20`, `:77`; `rust/shekyl-curve-tree/src/client.rs:2111`; re-exports at `rust/shekyl-curve-tree/src/lib.rs:75-76` | `SEGMENT_LAYER_J`, `leaves_per_segment`, segment ids | consensus (proof topology) | — |
| the C++ segment registry | `src/blockchain_db/lmdb/db_lmdb.cpp:5720-5728` (`m_archival_shard_segment` cursor) | enumerates a `CompleteTree`'s shards for slash | consensus | — |
| the challenge leaf chunk | `rust/shekyl-archival-retention/src/challenge.rs:196`, `:273-294`; `rust/shekyl-archival-retention/src/lib.rs:193-194` | leaf-chunk bounds inside a segment | consensus | `segment_leaf_count` |
| the sims | `rust/shekyl-economics-sim/src/budget.rs:249`, `rust/shekyl-economics-sim/src/burden.rs:36`, `:168-170`, `rust/shekyl-economics-sim/src/proxy.rs:56-60`, `rust/shekyl-economics-sim/src/cartel.rs:702-703`, `rust/shekyl-economics-sim/src/stranding.rs:51`, `rust/shekyl-economics-sim/src/stage2.rs:1205`, `rust/shekyl-economics-sim/src/mn_feasibility.rs:269-273`, `:844-852`; `rust/shekyl-staking-sim` §L19 | calibration and populations | sim | `SHARD_BYTES` (3.33 MB), `MAX_HOLDINGS_SHARDS` |

---

## C. Seeded rows, each verified at the pin

Two of the five seeded rows did not survive verification as written.

| row | verdict at `9d549ead2` |
|---|---|
| **D2 `n` / `knee_n` (`SHT-8`)** | **CONFIRMED.** Re-key `n` to a `T`-independent burden count — listed transactions in closed shards, from `cumulative_tx_count` — and re-derive `knee_n` **once, in transactions**. Never shard units. It is monetary policy (`FL-V4`: the escalation splits the *burned* amount and cannot move a fee rung). **Corrected 2026-09-27:** the earlier "it changes coinbase validity" is true only **once the ramp is on** — at the shipped neutral parameters the split is 25 % whatever `n` is (§G `SCC-Q2`), so the re-key is behaviour-neutral now. The atomicity requirement is unchanged and its reason is sharper: the operand is computed on **both** sides, and a mismatch that is harmless while flat becomes a chain split the moment the ceremony raises the asymptote. |
| **`g(age)`** | **CONFIRMED.** `shard_age_milli`'s no-segment branch is segment-keyed (`rust/shekyl-archival-retention/src/admission.rs:305-341`, function at `rust/shekyl-archival-retention/src/consensus_state.rs:235-252`). Re-key under `SHT-Q1`. It is also one of `SHT-Q1`'s falsifiers: the ruling reopens if the re-keyed form needs height-driven closure. |
| **`CompleteTree` challenge/slash** | **CONFIRMED, mechanical only.** Enumerates via the segment registry (`src/blockchain_db/lmdb/db_lmdb.cpp:5720-5728`). Re-key to closed **domain** shards. Landed semantics to preserve: a failure **demotes the whole record** to `ShardSetCompact` and clears its shards (`src/blockchain_db/lmdb/db_lmdb.cpp:5515-5520`), and **`Reinstate` is refused** on a `CompleteTree` record (`rust/shekyl-archival-retention/src/bond_post.rs:75-76`, `:159-162`). `CompleteTree` is a non-economic backstop by construction — no shard ids, so nothing to claim. |
| **The segment-geometry deletion, incl. the E3 handoff** | **PARTLY REFUTED — `SCC-3`.** The deletion row stands (the JSON's own prose at `:52` already says `segment_leaf_count` "leaves this file when E4 / S-ARCH deletes the freeze"), and the falsifier *"two shard geometries in `consensus_constants.json`"* is right. But the handoff's premise does **not** hold: `connect.rs` carries **no** segment-geometry comment to correct. `:22` is the module doc's *"3. tree — the verdict's drain → `curve_tree_leaves`"* and `:409` is `// ---- 4. root ----`; the only `segment` tokens in that file are **transaction body** segments (`:556-568`). `SCC-1`'s overloaded word produced this row. **What survives:** the deletion must also remove `rust/shekyl-archival-retention/src/segment_freeze.rs:63`'s compile-time assert and the JSON key, and the digest re-pins when it goes. |
| **`SHARD_BYTES` / 3.33 MB residue** | **CONFIRMED, line numbers corrected.** `rust/shekyl-economics-sim/src/burden.rs:36` and `:168-170` (the 13.6 GB honest-cost figure), `rust/shekyl-economics-sim/src/proxy.rs:56-60` (`max_holdings_bytes`). Docs: `ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md:528`, `:543`; `ARCHIVAL_CHALLENGE_MECHANISM.md:1896`. (The brief's `:243`/`:585` and `:653`/`:1894` do not resolve to those figures.) |
| **The `F-A` anti-sybil argument** | **CONFIRMED.** `ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md:139` leans on `MAX_HOLDINGS_SHARDS = 4096` and `:145` concludes a bulk holder *"needs **≥ 4 bonds**, not one"*; `:544` makes it conditional on the cap never rising, and `:596` carries it into W1's disposition. Under `L2`'s ruling the cap bounds a **list**, so that argument must stand on the curve, not on a list bound. A finding for that round's owner. Note its cite points at `rust/shekyl-archival-retention/src/bond_wire.rs:33`, which is a **re-export**, not the definition. |
| **The equivalence invariant (`SHT-Q1`)** | **CONFIRMED and pinned.** The domain equals the non-coinbase transactions today; `tx_domain_tests` pins it class by class with an exhaustive `match` (no wildcard), and leg (f) pins the production path across a real prune. The **serve-credit end-to-end gap** is tracked in FOLLOWUPS. |

### `SCC-4` — the holdings cap had **six** definitions. FIXED here.

**As first written this row said two.** The design owner's review found four
more, and the corrected count is **six**:

| # | site | guarded? |
|---|---|---|
| 1 | `rust/shekyl-types/src/archival.rs:73` — `pub const MAX_HOLDINGS_SHARDS` | the canonical Rust home |
| 2 | `rust/shekyl-wire/src/transaction.rs:104` — crate-private `const`, and **it is what enforces the wire bound** (`:529`, `:745`) | **no** — tied to nothing |
| 3 | `src/blockchain_db/shekyl_types.h:1129` — `ArchivalBondValue::kMaxHoldings` | the C++ authority |
| 4–6 | `src/blockchain_db/shekyl_types.h:781`, `:899`, `:989` — the three revert-value codecs | **yes**, `static_assert` against site 3 (`:1461`, `:1466`, `:1469`) |

**The precise shape of the defect, which decides the fix.** The C++ four *could
not* drift from each other — three are `static_assert`-pinned to the authority.
What nothing tied was **the Rust pair to each other** and **either language to
the other**. So a re-pin would have moved one side silently: a holdings set the
store accepts and the wire refuses, which is a consensus split arriving through a
private literal. Delete-the-duplicate, not synchronize-it — and, as the design
owner observed, **not the one-line fix this row first claimed**.

**FIXED in this PR.** The value now has one authority and two generated readers:

1. **`config/consensus_constants.json`** gains `archival_max_holdings_shards =
   4096`, with both membership tests argued at the key: a different value admits a
   different set of bond posts (**a different chain**), and it is a **resource
   cap** — the `CEN-I4` input-count case this file's own rule names as passing the
   nameable-differently test, not a proof-system structural parameter.
2. **Rust** reads it through `rust/shekyl-types/build.rs`, which emits it as
   **`usize`** rather than `u64` like its neighbour: the consumer bounds a `Vec`
   length, so emitting the consumer's width leaves no cast to lint, and a value
   exceeding `usize` on a 32-bit target fails to compile **at the generated
   literal** instead of wrapping into a *smaller* bound — which is the direction
   that would make a decoder refuse holdings the store accepts.
3. **C++** reads `SHEKYL_ARCHIVAL_MAX_HOLDINGS_SHARDS` from
   `cmake/generate_consensus_constants.py`; **all four** `kMaxHoldings` are now
   defined from it, and the three `static_assert`s stay as belts against a
   hand-edit rather than as the only tie.
4. All five literals are deleted, and `git grep` finds no remaining copy under any
   name. The other `4096` hits in the tree are prose or
   `rust/shekyl-shard-visual/src/lib.rs:58`'s unrelated pixel cap.

**No behaviour change**: every definition already carried 4096. The
consensus-constants digest moved because the **binding grew**, and
`rust/shekyl-rpc-types/build.rs`'s `PINNED_DIGEST` is re-pinned with the
added-key case answered in place, as `VC-D12` requires.

---
## D. Calibrated constants whose units change

| constant | value | unit **today** | where it was derived | on cutover |
|---|---|---|---|---|
| `escalation_knee_n` | `100000` (`config/economics_params.json:17`) | **J-segments** (`frozen_segment_count`) ⇒ ~2.6 × 10⁹ leaves ⇒ ~1.3 × 10⁹ transactions at 2 outputs | **sim-derived: the middle of the Stage-2 `KNEE_BAND = [25_000, 100_000, 250_000]`** (`rust/shekyl-economics-sim/src/escalation.rs:63`), swept against `ASYMPTOTE_BAND` but **never selected** — Stage 3 froze the *shape* only | **re-expressed, not ported** (§G `SCC-Q2`): the sweep re-runs with its band in transactions below the discard frontier. Inert today — the ramp is flat |
| `segment_leaf_count` | `25992` (`config/consensus_constants.json:53`) | leaves per level-2 subtree (`38·18·38`) | the curve-tree widths, const-asserted to the proof topology | **leaves the JSON** with the freeze; the digest re-pins |
| `T` (`archival_shard_tx_count`) | `200`, PROVISIONAL | transactions per shard | `3.33 MB ÷ 16.7 KB/tx`, where 3.33 MB is the **retired leaf segment's** size (`SHT-1`) | value re-derived by the `T` round; the **unit does not change** (a count either way), but *which* transactions it counts does |
| `L` (`archival_attestation_anchor_lag`) | `4` blocks | blocks | its fetch-span component was sized on "~20 s for 3.33 MB" — the same retired byte count (`SHT-7`), which its own page's W₂ measurement contradicts 2.4–4.3× | restate the span **per byte**, or re-pin with `T` |
| `SHARD_BYTES` (sim only) | `3.33e6` (`rust/shekyl-economics-sim/src/burden.rs:36`) | bytes per **leaf segment** | `SEGMENT_LEAF_COUNT × ~128 B` | a modelling mean for a unit that no longer exists; re-baseline with the sims |
| `MAX_HOLDINGS_SHARDS` | `4096` (`config/consensus_constants.json`, `archival_max_holdings_shards`) | **list entries** — not bytes, not operators (`L2`) | the list budget; **no recorded derivation of the 4096 itself** | unchanged by this cutover. Since `SCC-4` it has **one** authority and two generated readers, so §E's couplings can now hold |

---

## E. Couplings owed if `MAX_HOLDINGS_SHARDS`'s value moves

Not owed if `T` moves — that coupling was struck by `L2`'s ruling.

1. **Re-anchor `m_min`.** The failure window's `m_min` is floor-set on the
   operator axis *at* the cap — *"false-slash at MAX_HOLDINGS <= target … every
   held pair is independently exposed; per-pair alone understates it by up to
   {MH}x"* (`rust/shekyl-economics-sim/src/mn_feasibility.rs:844-852`; the exposure at `:269-273`). Re-anchor to
   a **deliberately stated "largest honest operator holding"**, not a list bound,
   and re-run `mn_feasibility`.
2. **Re-point the sim populations** that read the cap as "the big archiver":
   `rust/shekyl-economics-sim/src/stranding.rs:51`, `rust/shekyl-economics-sim/src/stage2.rs:1205`, `rust/shekyl-economics-sim/src/cartel.rs:702-703`, `rust/shekyl-economics-sim/src/burden.rs:168-170`,
   `rust/shekyl-economics-sim/src/proxy.rs:56-60` — at that same stated figure.
3. ~~`SCC-4` first, or the wire will not move with it.~~ **Done** (`SCC-4`): the
   cap is one JSON key read by both languages, so a re-pin now moves every reader
   together instead of leaving the wire refusing at the old value.

---

## F. Atomic cutover boundaries (rule 07)

Two groups, each landing as one ratified change, because each contains a
consensus verdict that would otherwise disagree with itself mid-flight.

**Family 2 — validator + template + FFI + sim calibration, as one.** The binding
reason: `n` feeds `validate_miner_transaction` under a read-point assert that
*template and connect must read the same parent state*
(`src/cryptonote_core/blockchain.cpp:1494-1505`). A template built on one operand
definition and a connect validating on the other disagree about the coinbase's
fee split.

**Corrected 2026-09-27:** that disagreement is **latent, not live**. At the
shipped parameters the escalation is flat — `shekyl_escalation_asymptote_share`
equals the floor `shekyl_staker_pool_share` (`config/economics_params.json:16-18`,
*"the DELIBERATE pre-ceremony NEUTRAL value"*) — so the split is 25 % whatever `n`
is and a mismatched operand changes no coinbase's validity today. **The atomicity
requirement stands, and this is the better argument for it:** a split operand is
harmless while the ramp is flat and becomes a chain split the moment the GF-7
ceremony raises the asymptote, which is exactly the kind of defect that ships
unnoticed and detonates later. `escalation_knee_n`'s re-expression rides the same
change so the ceremony is never handed a number in the wrong unit.

**Family 1 — daemon + wallet, as one.** Bond admission checks domain membership,
and the wallet posts the holdings it will be judged on. A daemon on the domain
ordinal and a wallet on storage ids name different shards with the same integer.

**Order within the effort:**

1. **Counts defined once** in `shekyl-types` — one home for the domain ordinal, as
   `SHARD_TX_COUNT` already is for `T` (and `SCC-4` folded in).
2. **Constants re-derived** in their new units (§D) — `knee_n` in transactions
   before anything reads it.
3. **Sims re-baselined** against the re-derived constants, so the economics
   verdicts are not measured in retired units.
4. **Then the two cutovers**, family 2 before family 1: family 2 owns the operand
   family 1's economics read.

---

## G. Open questions for the design owner

Numbered, and none resolved here.

1. **`SCC-Q1` — `n`'s replacement burden count. ANSWERED (design owner,
   2026-09-27): transactions below the discard frontier, not transactions
   archived.** The escalation exists to redirect burned value toward stakers *as
   the burden on archivers grows*, and that burden starts when bodies **leave
   ordinary daemons** — not when shards close. Inside the retention window every
   daemon still holds them, so nothing is yet borne by archivers. Computable at the
   parent state from `cumulative_tx_count` and `D(E)` on both sides, and it moves
   in **epoch steps**, as the segment count did — so the operand keeps the step
   shape the ramp was built against.
2. **`SCC-Q2` RULED (Rick, 2026-09-27, design-owner lane): `knee_n` is
   re-expressed, not ported.**
   - The Stage-2 escalation sweep (`KNEE_BAND × ASYMPTOTE_BAND`,
     `rust/shekyl-economics-sim/src/escalation.rs:63`) is **re-run with the knee
     band in transactions below the discard frontier** — the `SCC-Q1` unit —
     derived from `ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §6.0's
     *wide-but-slow* constraint in that unit, as part of the sim re-baseline.
   - The config carries **that sweep's middle candidate**, provisional.
   - The escalation **stays neutral** (asymptote = floor = 250,000,
     `config/economics_params.json:16-18`) until the **GF-7 ceremony** (§11.4) pins
     both numbers.
   - Converting the old band (~13k transactions per J-segment) is a **sanity check
     only, not a derivation**: segments counted coinbase leaves and were never a
     burden measure.

   **Provenance correction.** `100,000` **is** sim-derived — it is the middle of
   the Stage-2 `KNEE_BAND = [25_000, 100_000, 250_000]`, swept against
   `ASYMPTOTE_BAND` but **never selected**, because Stage 2 recommends and Stage 3
   freezes, and Stage 3 froze the **shape** only. This round's earlier *"no
   recorded derivation"* was wrong: what is missing is a **selection**, not a
   derivation. The band's own doc comment carries the reasoning (*"a larger knee is
   a slower ratchet"*; `25_000` ≈ baseline traffic at ~10 y, `250_000` only
   saturates deep in a sustained-growth chain).
3. **`SCC-Q3` — does `g(age)`'s re-keyed form need a shard's close height?
   ANSWERED: no, and the question conflated two things (design owner,
   2026-09-27).** `SHT-Q1`'s falsifier (i) is about a shard needing **to close by
   height** — a clock. *Reading* the close height of a shard that closed **on
   count** is not that: under the domain it is the height of the block containing
   the domain's `((k+1)·T)`th transaction, found by the **existing** binary search
   over `cumulative_tx_count` (`rust/shekyl-chain-store/src/store/prune.rs:498`).
   An open shard has no age, so the explicit `age_milli = 0` branch carries over
   unchanged. **The ruling does not reopen.**
4. **`SCC-Q4` — the `F-A` anti-sybil argument. HANDED OFF (design owner,
   2026-09-27): not this effort's.** It goes to the owner of the `F-A` round as a
   **genesis-relevant finding** — under `L2` the argument can no longer rest on
   "≥ 4 bonds to plateau" and must stand on the curve — and **it does not block
   this cutover**. Recorded as handed off.
5. **`SCC-Q5` — is `SCC-4` in scope? ANSWERED: in scope, and landed here**
   (design owner, 2026-09-27) — as corrected, since it is six sites across two
   languages rather than the one line this round first claimed. See `SCC-4` for
   what shipped. It was a precondition of §E's couplings holding, and §E item 3 is
   now discharged.

**Standing after Round 0: every question is closed.** `SCC-Q1`, `SCC-Q3`,
`SCC-Q4`, `SCC-Q5` answered; **`SCC-Q2` RULED** 2026-09-27. Nothing in §G is open.
