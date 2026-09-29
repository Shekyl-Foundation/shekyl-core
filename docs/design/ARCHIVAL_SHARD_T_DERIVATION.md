# `T` — deriving the archival shard cardinality

**Status:** OPEN — Round 0 executed 2026-09-26 at `b72aac2fc` (the composition
arm with `origin/dev@ad557ac5a` merged in); **AMENDED on review the same day
(at `9e8c0bee0`)**; **`SHT-Q1` RULED (Rick, 2026-09-27, design-owner lane)** —
the partition is over transactions that **carry archival good**, a property
rather than a class list, with the equivalence to `cumulative_tx_count` recorded
as an invariant and pinned by a test (§2.1). **`L2` RULED the same day
(Rick, design-owner lane): withdrawn as a bound on `T`** (§3), leaving `L1`'s
threshold as the selection rule's only open lower-edge input. The 2026-09-26 amendment moved the conclusion. `U1a` was derived against the wrong
transport figure: W₂ has *measured* single-attempt fetch since 2026-09-16, and
on the measured numbers `U1a` is **unresolved at `T = 200`** rather than three
orders of magnitude slack. The selection rule is re-pointed at the **lower**
edge with the asymmetry argument it was missing, `SHT-Q1`'s price for the
ordinal domain is **withdrawn** (dev already does the lookup it was charged
for), and `SHT-7` is added. `SHT-Q1` (the partition domain) was posed by this round
and **RULED on 2026-09-27** (§2) — it came before the bounds because it decides
which constraints exist, and it now has. Findings `SHT-1`…`SHT-9` are at-pin
findings of this round; **`SHT-Q2` RULED 2026-09-29 (§8.6): shards are cut by archival length, bound through the txid.** **`SHT-10`…`SHT-12` and `SHT-Q2` (a byte-proportional partition —
computed weight, or a txid-bound declared length, the design owner's recommendation —
OPEN for Rick) were added 2026-09-28 after F34 (§8)**, with the input-count proposal
recorded as not adopted and `PDM-Q6` item 5's rejection re-read as one of *stored
lengths*, not of byte-proportional boundaries. Identifier families **`SHT-`** (findings) and
**`SHT-Q`** (questions), registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 with this file
(rule 94 §1; `check_index_prefix_uniqueness.py` branch (a) — 105 prefixes
unique at the pin, `SHT` clear of `SPR`, `SPR-Q` and `SP-T`). Template: the
I4 round's shape — state the objective, enumerate constraints at source,
measure what can be measured, derive bounds, pick by a stated rule,
pre-register falsifiers.

**One sentence.** `T = 200` (`archival_shard_tx_count`) was computed as
3.33 MB ÷ 16.7 KB/tx, and 3.33 MB is `SEGMENT_LEAF_COUNT × ~128 B` — the size
of the **retired leaf segment**; so `T`'s only justification is *"a shard holds
as many bytes as the old segment did"*, which is inheritance from a geometry
that no longer exists rather than a constraint on the archival obligation.

**What this round does not reopen.** `PDM-Q6` item 5 (a count, not bytes) — it
reopens only through its own falsifiers. A4/W9 (manufactured composition,
CLEARED §12.11) — no adversary framing on composition appears here. The
segment-geometry cleanup, which is E3/E4's. Channel 1, which is the reward
leg's. If a constraint below required a byte operand, that would be item 5's
**(g)** falsifier firing; none does, and §3 says so per row.

---

## 0. Round-0 pre-flight — what is landed

Pin `b72aac2fc`. Every row read at source before anything was proposed.

| Fact | Value | Source |
|---|---|---|
| `T`, the constant | `archival_shard_tx_count = 200`, PROVISIONAL | `config/consensus_constants.json:37`, comment `:36` |
| Its one home | `shekyl_types::SHARD_TX_COUNT` | `rust/shekyl-types/src/archival.rs:94` |
| How it is sourced | the leaf crate's own `build.rs` reads the JSON and emits `ARCHIVAL_SHARD_TX_COUNT` | `rust/shekyl-types/build.rs:60`, `:70` |
| Its only assertion | `SHARD_TX_COUNT > 0` | `rust/shekyl-types/src/archival.rs:101` |
| **Sole production consumer** | `shekyl-chain-store`'s prune: the discard range `shards.start·T .. shards.end·T`, the id→shard map `⌊id / T⌋`, the last-closed-shard id | `rust/shekyl-chain-store/src/store/prune.rs:267`, `:415-416`, `:490`, `:493` |
| Other mentions | the consensus-constants digest, the `shekyl-types` re-export, `prune_tests.rs` | `rust/shekyl-rpc-types/build.rs:88`; `rust/shekyl-types/src/lib.rs:908` |
| JSON membership | `T` passes both membership tests (a different value is a different chain; a network could legitimately name it differently) | `config/consensus_constants.json:2` |

**No consumer was missed.** `git grep -n SHARD_TX_COUNT -- 'rust/**'` at the
pin returns exactly the rows above, so §0's halt condition did not fire.

Numerics this round must reason against, all read at source:

| Symbol | Value | Source |
|---|---|---|
| block target | `daa_target_seconds = 120` | `config/consensus_constants.json:10` |
| `SEB` | `settlement_epoch_blocks = 10000` (~14 d) | `:23` |
| `D_max` / pass-anchor depth | `archival_reorg_depth_blocks = 720` | `:29` |
| `CRB` | `challenge_resolution_blocks = 10000` in the JSON; the **response** deadline is `CHALLENGE_RESPONSE_BLOCKS = SEB / 20 = 500` blocks | `:31`; [`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md):1991, [`ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md`](ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md):1266 |
| `L` | `archival_attestation_anchor_lag = 4` blocks, of which **two blocks are the fetch-plus-retry span** | `config/consensus_constants.json:33`; [`ARCHIVAL_SHARD_FETCH.md`](ARCHIVAL_SHARD_FETCH.md):1074-1090 |
| `N` | in-flight fetch cap `8` (`shekyl_p_fetch::MAX_INFLIGHT`) | [`ARCHIVAL_SHARD_FETCH.md`](ARCHIVAL_SHARD_FETCH.md):6, `:796` |
| holdings cap | `MAX_HOLDINGS_SHARDS = 4096`, over `ShardSet(Vec<u64>)` | `rust/shekyl-types/src/archival.rs:73`, `:205` |
| transport figure (the one `L`'s span was sized on) | **a burst floor near 180 KB/s** — "a floor from a null result, not a sustained figure", quoted as "~20 s for 3.33 MB" | [`ARCHIVAL_SHARD_FETCH.md`](ARCHIVAL_SHARD_FETCH.md):1079 |
| **transport figure, MEASURED** | **W₂, 2026-09-16, single-attempt, PR #746: cold p99 = 48.27 s, soak p99 = 86.06 s** for a 3.33 MB shard — i.e. **69.0 / 38.7 KB/s effective**, 2.4–4.3× worse than the 20 s premise on the same page | [`ARCHIVAL_SHARD_FETCH.md`](ARCHIVAL_SHARD_FETCH.md):1091-1095 |
| good per spend | ~16.7 KB/tx = ~6.1 KB prunable + ~10.6 KB `pqc_auths` of a ~17–18 KB 2-in/2-out | [`ARCHIVAL_PRUNED_DAEMON_MODE_ROUND.md`](../completed/ARCHIVAL_PRUNED_DAEMON_MODE_ROUND.md):525 |

---

## 1. What `T` is, and what is actually wrong with 200

`T` is **one** job seen from three sides: the partition function, the unit of
possession (a bond's `held_shard_ids`), and the unit of discard. A bond cannot
hold half a shard and the obligation is per-shard, so possession granularity
*is* partition granularity *is* discard granularity — one parameter, not three
sharing a value. Reward is priced separately, by the weight curve, with `T` an
input to it rather than the price. **None of that is in question here.**

### `SHT-1` — the derivation chain, and which link is rotten

`T = 200` is `3.33 MB ÷ 16.7 KB/tx = 199.4 → 200`
(`config/consensus_constants.json:36`: *"Chosen so a typical shard at
~16.7 KB/tx lands near 3.33 MB"*; [`DRS_E1_SPRUNE.md`](DRS_E1_SPRUNE.md):424
repeats it). Both inputs were checked:

- **16.7 KB/tx is sound in form and is *not* circular.** It is a component
  estimate of a spend's *good* — ~6.1 KB prunable region + ~10.6 KB
  `pqc_auths` of a ~17–18 KB 2-in/2-out
  ([`ARCHIVAL_PRUNED_DAEMON_MODE_ROUND.md`](../completed/ARCHIVAL_PRUNED_DAEMON_MODE_ROUND.md):525,
  `PDM-Q-F24`, 2026-09-13) — built from transaction anatomy and introduced ten
  days *before* item 5 chose `T = 200`. The arithmetic coincidence
  `3.33e6 / 200 = 16,650` is a consequence of the division, not evidence that
  16.7 was derived from it. Recorded explicitly because the coincidence invites
  the wrong finding.
- **3.33 MB is the rotten link.** It is `SEGMENT_LEAF_COUNT` (25,992 leaves)
  × ~128 B/leaf — the size of the **leaf segment**, the unit `PDM-Q6` item 3
  used and item 5 retired (`rust/shekyl-economics-sim/src/burden.rs:33-38`
  still carries that derivation; `RF-D6`'s fixed byte size is "retired
  entirely", [`ARCHIVAL_PRUNED_DAEMON_MODE.md`](ARCHIVAL_PRUNED_DAEMON_MODE.md):933-936).

So `T`'s justification reduces to **"a shard should hold as many bytes as the
old leaf segment held"**. That is not a statement about the archival
obligation, the possession test, the discard unit, or any participant's cost.
It is inheritance from a retired geometry — the `FCMP_MAX_INPUTS_PER_TX = 8`
shape: inherited, unjustified, load-bearing, carrying a reason that no longer
holds. **Grade: CONFIRMED defect.** It is what this round exists to replace.

### `SHT-2` — the sizing rationale silently assumes the domain `SHT-Q1` asks about

16.7 KB/tx is the good of **a 2-in/2-out spend**. Under the landed domain, a
shard is 200 **storage ids**, and storage ids are dense over *every recorded
transaction — one coinbase per block plus the listed ones*
(`config/consensus_constants.json:36`). A coinbase carries **no good at all**
(`prunable_hash` is `null_hash`, no `pqc_auths`). So 200 storage ids reach
3.33 MB only when **every id is a 2-in/2-out spend** — i.e. at saturation.

On a chain at 1 listed tx/block, a 200-id shard holds ~100 coinbases and
~100 spends: ~1.7 MB, half the target. At 0.1 listed tx/block it holds ~18
spends: ~0.3 MB, a tenth. **The JSON's "typical shard" is the *maximum* shard
under the landed domain**, and the claim as written is true only under the
non-coinbase ordinal — option (B) below, which is not what landed.
**Grade: CONFIRMED — the comment's derivation sentence is domain-conditional
and does not say so.** It is not merely stale; it presumes the answer to
`SHT-Q1`.

---

## 2. `SHT-Q1` — the partition domain — **RULED**

> **`SHT-Q1` RULED (Rick, 2026-09-27, design-owner lane): the partition is over
> transactions that carry archival good.** A transaction is in the domain **iff**
> it has a non-empty prunable region or `pqc_auths`. That is decidable from the
> skeleton (txid structure and prunable hash) without the body. Shard `k` is the
> domain's transactions `[k·T, (k+1)·T)` in chain order. **Shards close on count
> only; there is no time-based closure** (a clock is the zero floor by another
> name). The coinbase has no prunable region and is skeleton; it is outside the
> domain **by the definition, not by exclusion**.
>
> **Implementation equivalence (invariant, not definition):** today the domain
> equals the non-coinbase transactions. Every non-coinbase class carries good
> (CEN-H21, CEN-H22 and the class rules) and the coinbase carries none, so
> boundaries read from `cumulative_tx_count`. A test pins the equivalence. A
> class or coinbase change that breaks it must change the counter in the same
> cutover.
>
> **Stability:** closed shards never change membership. Any post-genesis change
> to what counts as archival good activates by height and applies only past it.
>
> **AMENDED by `SHT-Q2` (RULED 2026-09-29, §8.6):** "Shard `k` is the domain's
> transactions `[k·T, (k+1)·T)`" becomes **shard membership `⌊cum_before / W⌋` over
> the cumulative archival length**, bound through the txid. The domain itself is
> unchanged.
>
> **The predicate reads the two digests as recorded at ingest, never recomputed
> from a possibly-pruned body.** `Transaction::prunable_hash`'s own contract says
> why: when the prunable region is absent — *"a coinbase, or a storage-pruned
> spend"* — it returns `keccak256("")` while the txid substitutes the null hash,
> and under `PDM-Q6` the region and `pqc_auths` retire together,
> so a recomputation over a discarded body yields no component either. A node
> evaluating the predicate that way would place its **own discarded spends outside
> the domain** while an archival node keeps them inside: the two would disagree on
> shard boundaries, which is a consensus split. The rows
> (`txs_prunable_hash`, `txs_pqc_auth_hash`) are permanent — a prune deletes the
> regions and never them — so they are the only admissible input.
>
> **Falsifiers (any reopens):** (i) the re-keyed D2 `n` or `g(age)` requires
> shards to close by height; (ii) the equivalence breaks without a counter
> change; (iii) evidence that an unbondable frontier shard on a quiet chain has a
> real cost; (iv) a definition of archival good that cannot be decided from the
> skeleton.

The ruling is a **property**, which is why it is stronger than either option as
this round posed them: the partition follows the good itself, so a future
transaction type carrying prunable data joins automatically and one that does not
stays out, with no class list to maintain. What follows is the evidence the round
gathered, kept because the falsifiers are stated against it.

### 2.1 The ruling as built

**One predicate, one home, reachable only with row values.**
`shekyl_wire::carries_archival_good(pqc_auth_hash, prunable_hash)`
(`rust/shekyl-wire/src/transaction/txid.rs`), beside the txid structure it reads.
It takes **the two row values, not a `Transaction`**, so membership is
structurally decidable without a body — which is what lets bond admission check
it on a pruned node. No second classification is minted: it reads the
3-part/4-part arity that already exists.

**There is deliberately no `TxidParts` convenience method**, and the first
implementation's was deleted. `Transaction::txid_parts()` *recomputes* both
digests from the object in hand, so on a body whose regions have been discarded it
yields `keccak256("")` and `None` — the recompute-from-a-pruned-body hazard the
ruling's text now names (`Transaction::prunable_hash`'s contract states it for
exactly these cases). A method one call away from admission code is that hazard
in the most convenient possible form.

**The production path** is
`shekyl-chain-store`'s `ReadSnapshot::tx_carries_archival_good`
(`store/tx_reads.rs`, `carries_archival_good_at`), which reads
`txs_prunable_hash` (written at `store/connect.rs:575`, mandatory — its absence
below the count is SI-7) and `txs_pqc_auth_hash` (`:584-586`, present ⇔ the txid
is 4-part) and hands them to the predicate. A prune deletes the regions and never
these rows.

**One correction the ruling's wording needs.** The ruling says "a non-null
prunable hash". **The stored prunable hash is never null.**
`Transaction::prunable_hash`'s own contract is explicit: when the region is absent the *txid component* substitutes the null
hash, while the **row** is `keccak256("")` — "the C++ store's row for a coinbase
is the latter". A predicate written against non-null would therefore read **every
coinbase as carrying good** and the equivalence would be false at landing. The
predicate compares against `empty_region_prunable_hash()` instead, and
`the_empty_region_digest_is_the_coinbases_row` pins that value against the
coinbase's own row.

**The equivalence test** is `rules::tx::tx_domain_tests` in `shekyl-chain-rules`,
five cases:

| leg | what it pins |
|---|---|
| `the_domain_is_every_non_coinbase_class` | an **exhaustive `match` over `TxClass` with no wildcard arm**, each arm citing the rule that forces good for that class. Verified to be a compile-time guarantee, not a claim: adding a probe variant to `TxClass` fails the build with `E0004: non-exhaustive patterns`, pointing at this match |
| `each_leg_of_the_predicate_is_the_only_good_some_class_has` | both legs are independently load-bearing — the **fee-less emission** has the `pqc_auths` component and no region, the **serve-credit** form has the region and no component. Either leg alone puts one class outside the domain |
| `the_empty_region_digest_is_the_coinbases_row` | `keccak256("")` is the coinbase's row and is **not** the null hash (the correction above) |
| `the_coinbase_carries_no_good_however_large_its_extra` | the coinbase at one output and at a maximal-attestation `extra`: attestation records live in `extra`, which is skeleton, so the ct stays `Null` and both legs stay false |
| `the_counter_equals_the_predicate_over_a_mixed_chain` | over a synthetic chain mixing every class **with empty blocks**, boundaries from `cumulative_tx_count` equal boundaries from counting the predicate — compared **per transaction**, not only at the end, so offsetting errors cannot cancel. This is the leg that fails on divergence |
| **(f)** `the_predicate_survives_a_prune_on_the_stored_rows` (`shekyl-chain-store`) | the **production path across a real prune**. A chain with spends in shard 0, a spend in shard 1 and empty blocks connects; every id's answer is recorded; the epoch-3 boundary discards shard 0; **every answer is unchanged** — the whole vector, not a sample — and the **discarded** spend is still in the domain. Also asserts the accessor agrees with the whole-body predicate on the *unpruned* store, and that both rows survived, with the surviving `txs_prunable_hash` identified as what alone keeps a 3-part-with-region transaction (a serve-credit form) in the domain. **Verified to be able to fail:** mutating the accessor to recompute from the pruned body turns it red on the "domain answer moved" assertion |

**The negative leg (e) is cited, not re-asserted.** A non-coinbase transaction
with no good is refused today: `BondPost` by **CEN-H21**'s `spends >= 1` +
`prunable: Some` + non-empty `fcmp_proof`
(`rust/shekyl-chain-rules/src/rules/tx.rs:749-793`); a key-imaged `Spend` with no
prunable at `rust/shekyl-wire/src/transaction.rs:2056-2060`; the serve-credit
shape, including one **non-empty** pass record per credit vin, at
`rust/shekyl-wire/src/transaction.rs:1692-1722` and
`check_serve_credit_pruned_blob` (`:592-600`).

### 2.2 The evidence the ruling was taken on

The round posed the domain as two options. The ruling supersedes both with the
property above; the options are kept because `SHT-Q1`'s falsifiers and `SHT-8`
are stated against them.

- **(A) As landed.** Storage ids, dense over every recorded transaction, one
  coinbase per block included. `k = ⌊storage_id / T⌋`.
- **(B) The non-coinbase ordinal.** `k = ⌊ordinal / T⌋` with
  `ordinal = storage_id − (height + 1)` — the inverse of
  `storage_ids_through(listed, h) = listed + h + 1`
  (`rust/shekyl-types/src/archival.rs:103-111`). Derivable from retained
  headers with **zero new data**, exactly as (A) is.

### Precondition, re-verified at source

Every non-coinbase class carries a nonzero good, so under (B) a zero-good shard
is unrepresentable. Verified against the four classes that
`TxClass::from_inputs` can yield (`rust/shekyl-chain-rules/src/rules/tx.rs:130-180`):

| Class | Good | Why it cannot be zero | Source |
|---|---|---|---|
| `Spend` | `pqc_auths` (count == nvin) + full prunable | the shape arm requires both | `rust/shekyl-wire/src/transaction.rs:1978-2026` |
| `BondPost` | `pqc_auths` + a non-empty FCMP++ proof | **CEN-H21 requires `spends ≥ 1`**, `prunable: Some`, `pqc_auths == nvin`, non-empty `fcmp_proof` | `rust/shekyl-chain-rules/src/rules/tx.rs:749-793` |
| `Emission` | `pqc_auths` (count == nvin ≥ 1) | CEN-H22 pins `pqc_auths == vin count`; the FCMP proof is present only with fee inputs, so `pqc_auths` alone can be the good | `rust/shekyl-chain-rules/src/rules/tx.rs:798-830` |
| `ServeCreditOnly` | one non-empty pruned pass record per credit vin | `pqc_auths` is empty here, but the region holds exactly one record per vin and each is length-checked | `rust/shekyl-wire/src/transaction.rs:1692-1722` |

The **coinbase** (`Ct::Null(CtBase)`) is the unique zero-good shape.

Two precisions the ruling needs. **(i)** The wire crate contemplates "a
fee-only `bond_post` is 0-output" (`transaction.rs:1972`), which *would* be
empty `pqc_auths` and no prunable — zero good. **CEN-H21 forbids it**: the
comment describes a guard boundary the consensus layer closes, not a reachable
shape. **(ii)** (B) removes *zero*, not *smallness* — a shard of `T`
serve-credit transactions, or fee-input-less emissions, is a minimal-good
shard. And "ordinal" must count **all four** classes; if it counted only
`TxClass::Spend`, serve-credit and emission bodies would belong to no shard.

### Wargame

| Axis | (A) storage ids | (B) non-coinbase ordinal |
|---|---|---|
| **Closure liveness** | A shard closes within **at most `T` blocks** whatever the usage — at `T = 200`, ≤ 400 min. The frontier shard is never stuck. | Close cadence depends **only on usage**. A quiet chain keeps its frontier shard open indefinitely: unbondable, and retained on every daemon because discard needs `close_epoch`. Against Q2's freeze-one-epoch rule and `discard(k) ⇔ current_epoch ≥ close_epoch(k) + 2`, an open frontier shard simply never enters the pipeline. Whether that is harmless (the good is small, so "no market" is the correct answer) or a gap (an unbounded universal-retention tail on a quiet chain) is the ruling's question. |
| **The zero floor** | Admits coinbase-only shards with **zero good**, which a run of `T` empty blocks produces. Nothing in [`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md) says what the draw does with one — drawable and trivially passable, unposeable, or unbondable. Unresolved at the pin. | Unrepresentable by the table above. |
| **Consensus touch points** | `close_height`, the serve-credit preimage terms `(k·T, (k+1)·T)`, bond admission's closed-shard predicate (ruled 2026-09-19, unbuilt), and prune's range mapping — which must already tolerate interleaved coinbases having no body rows. Note `first_tx_id` must **add** the coinbase term (`listed + h + 1`) at every one of those sites. | Same four, re-keyed — but **cheaper, not dearer, and the round's first reading of this was wrong.** `cumulative_tx_count` *is* the non-coinbase ordinal (`prune.rs:421-428`, `listed_before`'s own contract), so under (B) a boundary is `⌊cumulative_tx_count / T⌋` read straight off the stored cell, with **no coinbase term to add**. Mapping a boundary ordinal back to a storage id is `height_of_tx_id`'s binary search over the running total — which **dev already performs under (A)**, on the `h_scarce` path (`prune.rs:490-500`). So (B) does not introduce a height lookup; it removes an addition from four sites. |
| **Sizing** | `SHT-2`: the shard's good scales with usage; 3.33 MB is the saturation case. | The shard's good is `T` × per-spend good in **any** era — the case the JSON comment describes. |

**Recommendation withheld — but the trade is now one-sided on everything except
liveness.** The prune-re-key cost charged against (B) above is **withdrawn**:
the lookup it was charged for is already in dev. So (B) wins the zero floor and
wins a size that means something (`SHT-2`), at the price of **closure liveness
on a quiet chain and nothing else**. `SHT-Q1` therefore reduces to a single
question for steering: *is an indefinitely-open frontier shard — unbondable,
undiscardable, retained on every daemon — acceptable on a quiet chain, given
that its good is small and "no market for it" may be the correct answer?*

### The falsifier for "(B) with no clock", run at the pin

The stated falsifier is **any consumer that needs a shard to close by height**.
Checked at source across the five surfaces, and **it does not fire** — every one
of them already has a defined answer for a shard that has not closed:

| surface | what it needs | an open frontier shard |
|---|---|---|
| `h_scarce` and the discard calendar `D(E) = { k : close_epoch(k) + 2 ≤ E ≤ close_epoch(k) + 3 }` | the `close_height` of shards **already closed**, reached by id arithmetic and one binary search | is not in the closed set, so not in `D(E)`. Never discarded — which is the cost, not a contradiction (`prune.rs:34-36`, `:472-500`) |
| `g(age)` | `shard_age_milli(close_block_height, freeze_height, SEB)` — a **freeze** height, *if* frozen. Its no-segment branch is keyed on a **J-segment** (`admission.rs:305-341`, `consensus_state.rs:235-252`) | ⚠️ **NOT A PASS — evaluated against the retired geometry.** "Scores `age_milli = 0` with no frozen segment" is a true statement about *segments*, the leaf partition `PDM-Q12` retired, and says nothing about how an open **T-shard** behaves. The re-keyed form does not exist, so this surface **has not been run** |
| D2 escalation | `compute_burn_split_at(total_fees, burn_pct, n: FrozenSegmentCount)` (`burn.rs:188-191`); `FrozenSegmentCount` counts **J-segments** (`escalation.rs:48-58`), and on the C++ side `n` is **derived from the curve-tree leaf count** — `Blockchain::parent_frozen_segment_count` returns `shekyl_archival_frozen_segment_count(m_db->get_curve_tree_leaf_count())` (`src/cryptonote_core/blockchain.cpp:1494-1505`) and feeds `validate_miner_transaction` (`:1508`), under a throwing read-point assert | ⚠️ **NOT A PASS — same defect.** "Not frozen, not counted" is true of segments. See `SHT-8`: the re-key is unspecified, and specifying it wrongly hands `T` a fifth job |
| Foundation `CompleteTree` / seed coverage | an owed set of *"every **closed**, final shard"* (`WALLET_SIDE_STORE.md`:463, WSS-Q10) | is not owed |
| Bootstrap | fills from closed shards through the same owed computation | likewise |

**Three of the five surfaces answer for T-shards and support (B):**
`h_scarce`/`D(E)`, the `CompleteTree` owed set, and bootstrap. For those the
shape is the same — an unclosed shard is *representable* as "not closed" and each
returns the right thing — and the one real consequence is the one already priced:
the frontier shard is retained on every daemon until it closes.

**Two of the five are not evidence at all**, and the round's previous version
reported them as passes. `g(age)` and D2 both key on the **J-segment**, the
partition `PDM-Q12` retired, so what was checked was the *old* geometry's
behaviour. Their re-keyed forms do not exist, so for those surfaces the falsifier
**has not been run** — it is not shown not to fire. `SHT-8` carries the
consequence, which is larger than the table error: specifying D2's re-key
carelessly makes `T` an economic parameter.

**This round does not claim (B)'s falsifier is discharged.** Three surfaces
support it; two are unrun and must be specified under the ruled domain before
the falsifier counts.

Recorded because it cuts the other way too: **adding "or `H` blocks" to (B)
would reintroduce exactly the defect (B) removes.** Any time-driven closure rule
closes a shard holding *fewer than `T` transactions of good*, and a coinbase-only
shard under (A) is precisely that rule firing on an empty chain. A clock is the
zero floor by another name.

---

## 3. Constraints on `T`

Each row: the operand, its source, the bound as a function of `T`, a value or a
labelled sweep, the domain it applies under, hard/soft with the reason, and a
falsifier. **No row required a byte operand in consensus**, so item 5's **(g)**
falsifier did not fire.

### Lower bounds — `T` too small

**`L1` — composition dispersion.** A shard's cost is a sum over `T`
consecutive transactions, so dispersion from per-transaction variance falls as
`CV_shard ≈ CV_tx / √T`. The threshold is **derived from what it protects**:
the smallest per-shard cost difference that flips a marginal holder's
acquisition decision. From the sim's agent model the holder compares
`value = price · (1/r_eff) · g(age)` against
`cost = storage_unit_cost · size + bond_carry`
(`rust/shekyl-staking-sim/src/agent.rs:180-196`), so the protected quantity is
the net margin `m` at the lean operating point, and the bound is

> `T ≥ ( CV_tx · storage_unit_cost / m )²`

At the sim's parameters (`storage_unit_cost = 0.03`, value term of order
0.2–0.5) the margin is thin, and with `CV_tx ≈ 1` this lands in the low
hundreds — the same neighbourhood as 200, which is why it is the lower bound
worth measuring rather than asserting. **The numbers are sim-parameter-sourced,
not corpus-measured**; `CV_tx` has no corpus behind it pre-genesis, so it is a
labelled bounding sweep (§7.7's sanctioned use), and #876's illustrative
`T ≥ 156` is **not** an input here.
*Domain:* under (B) this is the **only** composition constraint. Under (A) the
era-density term remains and **no `T` averages it away** — the premise being
that eras are much longer than a shard: 200 ids is hours at worst, while usage
density varies over days and months, so a shard never spans more than one era.
A `T` large enough to average eras would be a unit nobody could hold.
*Grade:* **soft** — a violation costs coverage dispersion (L19's banded result),
it does not break a rule. *Falsifier:* a measured `CV_tx` from a real corpus
whose implied bound exceeds the chosen `T`.

**`L2` — bookkeeping and per-shard state.** A bond record carries
`ShardSet(Vec<u64>)` capped at `MAX_HOLDINGS_SHARDS = 4096`
(`rust/shekyl-types/src/archival.rs:73`, `:205`). A holder wanting more shards
than that posts more bond records, each behind its own persona with the gate-6
firewall cost. So for a holder covering a fraction `f` of a corpus of `X`
storage ids:

> `bond records = ⌈ f · X / (T · 4096) ⌉`

At `T = 200`, one record covers 819,200 ids — about 3.1 years of chain at
1 listed tx/block and 120 s blocks. The Foundation `CompleteTree` floor does
**not** bind here: its owed set is *computed* ("a reconcile whose owed set is
every closed, final shard — a configuration of the same store",
[`WALLET_SIDE_STORE.md`](WALLET_SIDE_STORE.md):463), not listed on a wire. What
the cap prices is a **large market archiver's persona count**, which is a
privacy cost, not a capacity one.

#### `L2` RULED (Rick, 2026-09-27, design-owner lane) — **withdrawn as a bound on `T`**

> `MAX_HOLDINGS_SHARDS` is a **list-size bound on one bond record and one
> transaction** — decode, the per-block admission reads, the record encode. It is
> **not bond-size policy**. Personas are free (G-1) and splitting is the rational
> response, so no per-persona limit binds anything; the cap's value comes from the
> **list budget alone**. The byte products (13.6 GB, 13.7 GB) are **retired from
> reasoning**.

Verified at this pin. The sim states the premise outright — *"personas are free
(G-1) and sybil-per-shard is capital-bounded only (TJ-7), so a cartel abandons the
slashed record and bonds a FRESH pair on the same shard"*
(`rust/shekyl-economics-sim/src/cartel.rs:702-712`) — and the rational play is
modelled as partitioning across records: `Regime::RationalBestResponse` →
`best_partition_credit_milli` (`distribution.rs:73`, `:138`), with `:27` and
`:134` recording that the cap bounds **per-bond work**, structurally, and nothing
else.

**What this changes.** The round's earlier reading — that the cap prices a large
archiver's persona count, and that `4096 × T × bytes-per-tx ≈ 13.7 GB` is "the
most history a single persona can be obliged to" — is **withdrawn**. An operator
wanting more holdings posts another record; the cap bounds a **list**, not an
operator. So `L2` supplies **no lower bound on `T`**, the
`T ↔ MAX_HOLDINGS_SHARDS` coupling is struck from §5, and §4's lower edge has one
open input rather than two. What survives as a soft pull toward larger `T` is the
per-shard state count — which is `L3`, and was always the stronger of the pair.

*Domain:* both. *Grade:* **no longer a bound.** *Falsifier on the withdrawal:* a
surface where the cap bounds an **operator** rather than a list — one where
posting a second record is unavailable or not equivalent. Per-shard consensus state (`archival_r_market`
rows, serve-credit rows per `(P, shard, E)`, settlement work per epoch) scales
as rows ∝ shards × epochs ∝ `X/T` × epochs, so every one of those pulls the
same direction: larger `T`, fewer rows. *Domain:* both. *Grade:* **soft** —
it costs personas and settlement rows; nothing breaks. *Falsifier:* a holdings
encoding whose cap is reached by an honest single-persona archiver at the
chosen `T` within the mining era.

**`L3` — challenge and settlement work per shard per epoch.** Draws are
`k = λ·D/E` per block ([`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md):79)
and each drawable pair receives 3 derived challenges per epoch (`:243`), with
the settlement writer enumerating drawable pairs. Work scales as
pairs ∝ shards × holders ∝ `X/T`. Same direction as `L2`'s per-shard state count
— and since `L2` was **withdrawn as a bound** on 2026-09-27 (its cap bounds a
list, not an operator), this row and that count are what remain of the
bookkeeping floor. *Domain:* both. *Grade:* **soft**.
*Falsifier:* a settlement-writer cost measurement at the chosen `T` exceeding
the per-block budget on the rule-76 floor device.

### Upper bounds — `T` too large

**`U1a` — the requester's whole-shard read, bounded through `L`, not through
the resolution window.** The possession read is whole-shard (`SF-D1`) and
verification is per-transaction. Steering's expectation was that this bound
sets `T`. **It does not at 200, and the reason is worth stating precisely
because the conclusion is the one to distrust:**

- The deadline named is `CHALLENGE_RESPONSE_BLOCKS = SEB/20 = 500` blocks
  = 60,000 s. At the 180 KB/s floor that is a **10.8 GB** budget against a
  3.34 MB shard — three orders of magnitude of slack. This bound is not close.
- The memory leg is **gone by item 5's own ruling**: `SF-D1`'s whole-shard
  *read* stands, its whole-shard *materialise* does not
  ([`ARCHIVAL_PRUNED_DAEMON_MODE.md`](ARCHIVAL_PRUNED_DAEMON_MODE.md):933-936),
  and F32's reason 2 (`T × MAX_TX_SIZE` as an in-flight ceiling at `N = 8`) was
  **refuted** on exactly that ground (`:897-901`). So the in-flight cost is one
  transaction, not `T`.
- **What `T` is actually bounded by, on measured data.** W₂ has *measured*
  single-attempt fetch since 2026-09-16 and this round's first pass missed it,
  deriving the row against the 180 KB/s burst floor instead
  ([`ARCHIVAL_SHARD_FETCH.md`](ARCHIVAL_SHARD_FETCH.md):1091-1095): **cold
  p99 = 48.27 s, soak p99 = 86.06 s** for a 3.33 MB shard, graded against a
  **one-block (120 s)** criterion — "both under 120 s". That is 69.0 / 38.7 KB/s
  effective, **2.4–4.3× worse than the 20 s premise** on the same page.

  A single object size cannot separate circuit setup from transfer, and only
  the second scales with `T`:

> `t(T) = t_fixed + (T · bytes-per-tx) / v`, with `t(200) ∈ {48.27, 86.06} s`

  One measurement, two unknowns — so the bound is an interval, not a number.
  Against the 120 s criterion, on the **mean** shard and on a **heavy** shard
  taken at twice the mean:

| calibration | `t_fixed` | implied `v` | mean-basis ceiling | ×2 basis |
|---|---|---|---|---|
| soak p99 | 0 s | 38.7 KB/s | `T ≲ 278` | **`T ≲ 139`** |
| soak p99 | 60 s | 127.8 KB/s | `T ≲ 459` | `T ≲ 230` |
| cold p99 | 0 s | 69.0 KB/s | `T ≲ 496` | `T ≲ 248` |
| cold p99 | 30 s | 182 KB/s | `T ≲ 982` | `T ≲ 491` |

  **On the mean basis every reading clears `T = 200`, by 1.4× to 4.9×. It is
  only the heavy-shard multiplier that puts 200 inside the band** (~[140, 490]),
  which makes that multiplier the load-bearing quantity — and it is **not
  measured**. Two qualifications, both of which must be discharged before this
  row decides anything:

  **(i) The ×2 is a property of L19's shape function, not of any shard.** L19's
  size model is linear and *mean-preserving*, which caps its heavy end just
  under 2× the mean at every `S` — the cap L19 records as its own residue. So
  "~2× the mean" is a limit of that normalizer, not a measured shard size, and
  citing L19 for it (as this row's first version did) is citing the model for
  one of its artifacts. **What the row actually needs is a shard-level quantile
  of *good per shard*** — under (B), per-transaction composition averaged over
  `T` plus whatever era correlation survives that averaging. It is neither the
  per-transaction extreme (which `√T` suppresses) nor L19's normalizer. Until
  that quantile exists the [140, 490] band **rests on an assumption**, and the
  honest reading is the mean-basis row: clear at 200, by a factor this round
  cannot yet name precisely.

  **(ii) The criterion as stated stacks two worst cases.** A p99 circuit *and* a
  heavy shard at the same draw is a joint event; the criterion compounds them as
  if it were one. What the bound should be derived against is a **target
  witness-miss rate** — `P(t > 120 s) = P(slow circuit ∧ heavy shard)` — with the
  two components' dependence stated. If they are roughly independent the joint
  probability is small and **the ceiling loosens materially**. Either way the
  miss rate is a number someone must *choose*, the way `L = 4` chose "err
  large", rather than something that falls out of multiplying two p99s. **Owed
  before `U1a` is treated as a bound.**

  `L`'s two-block fetch-plus-retry span is the outer envelope, but deriving `T`
  from it would be **circular** — see `SHT-7`: that span was sized on the same
  retired 3.33 MB byte count `T` itself came from.

*Domain:* both — the read is of a shard's bytes either way, though under (A)
the same `T` buys fewer bytes. *Grade:* **hard; whether it is violated at 200 is
unresolved and rests on two undischarged quantities** (the heavy-shard quantile
and the target miss rate above) — exceeding it makes honest witness misses
systematic, and `L`'s own ruling forbids absorbing that by raising `L` ("the
answer is **not** raise `L`").
*What closes it:* **W₂ re-run at two or three object sizes.** One size gives one
equation in two unknowns; two sizes separate `t_fixed` from `v`, the 180 KB/s
floor drops out of every derivation that currently leans on it, and this row
becomes a number. The harness exists (PR #746). This is the single measurement
the round most wants, and it is cheap.

**`U1b` — the server's egress. No authority exists in the tree.** An honest `P`
on the rule-76 floor device (Pi 4, whose "binding constraint is uplink and Tor
circuit throughput", [`ARCHIVAL_SHARD_FETCH.md`](ARCHIVAL_SHARD_FETCH.md):758)
must serve, per epoch: 3 challenge reads per drawable `(P, shard)` pair, plus
organic reads, plus band-2 syncers filling from `(C, h_scarce]`. Each read is
`T` × per-tx good. The 180 KB/s figure is **requester-side and a burst floor
from a null result** — it is not a sustained-serve figure, and nothing in the
tree bounds an honest server's sustained uplink. **This is the unmeasured
half.** `U1b` is stated as a bound with no value:

> `T ≤ (sustained serve throughput × epoch) / (reads per epoch × bytes-per-tx)`

*Domain:* both. *Grade:* **hard if it binds, unknown whether it binds** — and
it is the row that must not be signed off on an assumption. *Falsifier / what
would close it:* a sustained Tor-serve throughput figure on the floor device at
the drawable-pair count the epoch implies. Recorded as a FOLLOWUPS row, because
this round cannot produce it.

**`U2` — the participation floor.** The smallest holding a small operator can
take is one shard: at `T = 200` and 16.7 KB/tx that is 3.34 MB against the
rule-76 device. Non-binding by four orders of magnitude; it would bind only at
`T ≳ 10⁵`. *Domain:* both. *Grade:* **soft, non-binding at any plausible `T`**.
*Falsifier:* a floor-device storage budget that one shard exceeds.

**`U3` — close latency, and its coupling.** Time from a transaction landing to
its shard being bondable. Under (A): the shard closes within `T` blocks
(≤ 400 min at 200), then freezes for an epoch, and is discardable at
`close_epoch + 2` — so `T`'s contribution is ≤ 0.05 % of the `SEB`-dominated
latency (10,000 blocks ≈ 14 d). Non-binding under (A). Under (B): unbounded on
a quiet chain, which is §2's closure-liveness item — **so `U3` is the bound
that (B) makes real and (A) makes vacuous.** *Domain:* (B) binds, (A) does not.
*Grade:* **hard under (B)** (an open frontier shard is never bondable and never
discardable), **soft under (A)**. *Falsifier:* a launch-era throughput profile
under which the frontier shard's open interval exceeds one epoch.

**`U4` — coverage granularity.** A larger shard means one lost holder loses
more contiguous history, and `R_market`'s resolution coarsens (fewer, bigger
units). This **shapes** `T` and does not bound it: no value of `T` violates a
rule, and L19 showed coverage tracks provisioning headroom rather than shard
size. *Domain:* both. *Grade:* **soft, shaping only**. *Falsifier:* a coverage
arm in which the per-band verdict at fixed headroom degrades monotonically in
`T`.

---

## 4. The feasible interval, and a proposed selection rule

**Under (A) and under (B) alike**, the only hard bound with numbers is `U1a`,
and on measured data its heavy-end ceiling is **~[140, 490]** — a band that
**contains 200**. `L1` sits in the low hundreds on sim-sourced parameters;
`L3` pulls upward; `L2` **no longer bounds `T` at all** (RULED, §3); `U1b` still
has no value. So the corrected state is:

> **`T = 200` is not comfortably inside the feasible interval — it is sitting on
> the edge of it, and which side is unresolved.** At the pessimistic reading of
> the measurement (all of the 86 s is transfer) the heavy end of composition
> already violates the one-block criterion at `T ≳ 139`. At the optimistic
> reading (most of it is circuit setup) there is 2.5× of room. The number is
> still not *derived*; what changed on review is that it is no longer obviously
> *safe* either.

### The direction, which the first pass left unargued

A rule of the form "the largest `T` transport allows" is the same move as "as
big as the old segment" with a better-sourced ceiling. The direction has to be
argued, and the tree already contains the argument in `L`'s own shape — *"the
asymmetry decides the direction"*:

- **Too large.** Honest witness misses: **unpriced, and they land on
  operators**. `L`'s ruling refuses to absorb them by raising `L`. They are
  invisible to the operator who suffers them, which is the same failure shape
  rule 76 exists to refuse — a cost that sorts by hardware and never surfaces.
- **Too small.** `L2`/`L3` rows: settlement rows, `r_market` rows, personas per
  large archiver. **Node-local, visible, and recoverable** — they cost disk and
  bookkeeping, and a wrong choice can be re-pinned without anyone silently
  missing a witness.

The asymmetry is decisive and it points **down**: err small on `T`. Which is
also the objective this round was opened against — *the smallest unit of
archival commitment a participant can take on*.

**Proposed selection rule** (steering's to accept, amend or reject):

> **Pick the smallest `T` that clears `L1`'s composition floor and `L3`'s
> per-shard-state floor, subject to `U1a` shown clear at the heavy end of
> composition by measurement, not by a floor.**
>
> (*`L2` was the second floor until it was ruled out on 2026-09-27; `L3` was
> always the stronger of the pair.*)

Why this and not the ceiling-seeking form: it takes the cheap direction of the
asymmetry above; it does **not** feed `L`'s 20 s premise — and so the retired
3.33 MB — back into `T`'s own bound, which the ceiling-seeking form did
(`SHT-7`); and it makes the binding quantity a *floor* that sim and bookkeeping
arithmetic can both produce, with the hard ceiling as a check rather than as the
selector.

**The rule is not ready to apply, and this section must not read as if it
were.** Pointing it down lands it squarely on the two edges this round could not
measure:

- **`L1`'s threshold is not derived.** The round removed the illustrative
  one-fifth and put the *form* in its place (the net margin that flips a
  marginal holder's decision); nothing has replaced the number. So `L1` names a
  floor it cannot yet evaluate.
- **`L2` no longer supplies a lower edge at all** — RULED 2026-09-27 and
  withdrawn as a bound on `T` (§3): the cap bounds a list, not an operator, so the
  byte product is retired and nothing in it pulls on `T`. What survives is `L3`'s
  per-shard state count.

So the rule has **one open input, not two**: `L1`'s threshold. A smaller gap than
the round first reported, and still a gap — a lower-edge rule whose lower edge is
an underived threshold. That is the correct
state of the work and not a defect in the rule — but the deliverable here is the
*rule plus its owed inputs* — `L1`'s threshold and `U1a`'s two undischarged
quantities — not a value for `T`. (*`L2`'s ruling was the third until
2026-09-27, when it was ruled and withdrawn as a bound; §3.*)

**Pre-registered falsifiers on any `T` this round selects.**

1. W₂ at multiple object sizes resolves `t_fixed` such that the heavy-end
   single-attempt read at the selected `T` exceeds the one-block criterion —
   `U1a` violated. **This is the live one: at the pessimistic reading it is
   already true at `T = 200`.**
2. A sustained serve-throughput figure on the floor device at which `U1b` binds
   below the selected `T`.
3. A measured `CV_tx` whose `L1` bound exceeds the selected `T`.
4. ~~An honest single-persona archiver reaching `MAX_HOLDINGS_SHARDS`~~ —
   **struck** with `L2`'s ruling: the cap bounds a list, and an operator posts
   another record. Replaced by the withdrawal's own falsifier (§3 `L2`): a surface
   where the cap bounds an *operator* rather than a list.
5. A second home for `T` appears, or a shard boundary is derived from anything
   but `cumulative_tx_count` and `T` — inherited from the landed row
   (`rust/shekyl-types/src/archival.rs:88-101`).

---

## 4.1 The W₂ re-run, pre-registered

This measurement now decides both `T` and `L` (`SHT-7`), so its analysis is
registered **before** it runs. Otherwise it is the one number in the round that
could be read after the fact to land on 200 — the shape rule 76 refuses in a
constant and the same reason `L`'s own falsifier says "the re-pin must not simply
track the measurement upward".

1. **Model.** `t = t_fixed + bytes / v`, fitted **per percentile** (a p99 fit,
   not a fit through means), over **two or three object sizes** spanning at
   least a 4× byte range. Two sizes identify the pair; a third tests linearity,
   and a poor fit is itself a result — it would say the transport does not
   decompose this way and the ceiling needs a different model.
2. **Governing regime: soak, not cold.** Witness fetches share circuits with
   the requester's other traffic and recur every epoch, so the steady-state
   figure is the one an honest holder lives under. Cold p99 is the outer bound
   and is reported, not used to select. (This is the stricter of the two, which
   is the point: it is the direction the asymmetry in §4 says to err.)
3. **Target witness-miss rate.** Stated as a probability before the fit, with
   the dependence between circuit latency and shard size stated (the §3 `U1a`
   qualification (ii)). The bound is then `P(t_fixed + bytes(T)/v > 120 s) ≤`
   that target over the joint distribution, **not** a product of two p99s.
4. **Decision thresholds, written down now.** If the fitted `t_fixed` is a
   *small* share of the measured p99, the per-byte term dominates, the heavy-end
   ceiling sits near the low end of [140, 490], and `T = 200` is at or over the
   edge — `U1a` fires and `T` must come down. If `t_fixed` is a *large* share,
   the ceiling is well above 200 and `U1a` stops being the binding constraint,
   which hands selection back to `L1`/`L3` (`L2` having been withdrawn as a bound,
§3). The threshold between those readings
   is where the heavy-end ceiling crosses the selected `T` at the target miss
   rate — computable from (1)–(3) the moment the fit exists, and not before.
5. **What it also re-grounds.** `L`'s fetch span, stated **per byte** instead of
   per 3.33 MB object (`SHT-7`), which is what stops `T` and `L` from resting on
   the same retired number.

## 5. Re-pin plan

`T` re-pins at the **Round-2 testnet gate** with `n`, `D_max` and `w_launch`
(`config/consensus_constants.json:36`). One coupling found, and it is new to
that gate's bookkeeping:

- **`T` ↔ `L`** (`archival_attestation_anchor_lag`, `SF-D8`). `L`'s fetch-span
  component was derived against a 3.33 MB shard; a `T` that changes the shard's
  bytes changes the span `L` must cover, and `L`'s own ruling forbids tracking a
  measurement upward. **They must re-pin together, or `T` must be selected
  inside the span `L` already states** — the selection rule in §4 takes the
  second option, which is why it is the cheaper one.
- **`T` ↔ `MAX_HOLDINGS_SHARDS` — STRUCK** by `L2`'s ruling: the cap bounds a
  list, not an operator, so their product bounds nothing and `T` does not couple to
  it. Two couplings replace it, and both are owed **only if the cap's own value
  moves**, never because `T` did:
  - **`m_min`'s anchor.** The failure window's `m_min` is floor-set on the operator
    axis *at* the cap — *"false-slash at MAX_HOLDINGS <= target … since every held
    pair is independently exposed; per-pair alone understates it by up to {MH}x"*
    (`rust/shekyl-economics-sim/src/mn_feasibility.rs:844-852`; the exposure itself
    at `:269-273`). If the cap moves, `m_min` is re-anchored to a **deliberately
    stated "largest honest operator holding"** rather than to a list bound, and
    `mn_feasibility` re-run.
  - **The sim populations that read the cap as "the big archiver"** —
    `stranding.rs:51` (*"5% at the per-bond cap"*), `stage2.rs:1205`,
    `cartel.rs:702-703`, `burden.rs:168-170` (the 13.6 GB honest-cost figure) and
    `proxy.rs:56-60` (`max_holdings_bytes`) — re-point at that same stated figure.
- **`T` ↔ `shekyl_escalation_knee_n`** — **the coupling that must not be created.**
  `staker_pool_share_at(n: FrozenSegmentCount, …)` (`escalation.rs:269`) ramps the
  staker share from floor to asymptote and saturates at
  `shekyl_escalation_knee_n = 100,000` (`config/economics_params.json:17`). Today
  `n`'s unit is **J-segments**: 100,000 × `segment_leaf_count` (25,992) ≈ 2.6 × 10⁹
  leaves, ~1.3 × 10⁹ transactions at two outputs each. Re-key `n` to *closed
  T-shards* and the same literal means 100,000 × 200 = **2 × 10⁷ storage ids** — the
  knee arrives roughly **65× sooner with no line of the economics changed**, and
  every future `T` re-pin silently moves when the staker share saturates. That is
  a **fifth job for `T`** — a clock on monetary policy — and exactly the rule-05
  failure this round exists to stop, so it is recorded here as a coupling to
  *refuse* rather than to re-pin. **Recommendation:** re-key `n` to a burden
  quantity **independent of `T`** — under (B) the natural one is the count of
  listed transactions in closed shards, read off `cumulative_tx_count` at the
  closure frontier, so `T` enters only as rounding at the frontier and `knee_n` is
  re-derived **once**, in transactions, against whatever burden the escalation was
  meant to track. Whether that is "transactions archived" or "transactions below
  the discard frontier" is the escalation owner's call; the unit must not be shards.
- **`T` ↔ `SEB`** only through `U3`, and only under domain (B).
- No coupling to `D_max`: `T` appears in no reorg-depth argument.

---

## 6. Findings

| id | finding | grade |
|---|---|---|
| **`SHT-1`** | `T = 200` is 3.33 MB ÷ 16.7 KB/tx, and 3.33 MB is the **retired leaf segment's** size (`SEGMENT_LEAF_COUNT × ~128 B`). `T`'s justification is inheritance from a retired geometry. 16.7 KB/tx is **not** circular — it is a component estimate predating `T` by ten days. | CONFIRMED — the round's subject |
| **`SHT-2`** | The JSON comment's *"typical shard at ~16.7 KB/tx lands near 3.33 MB"* holds only under the **non-coinbase ordinal**. Under the landed storage-id domain, 3.33 MB is the *saturation* case; at 1 listed tx/block a shard holds ~1.7 MB. The sizing rationale presumes the answer to `SHT-Q1`. | CONFIRMED |
| **`SHT-3`** | `SF-D7` still states *"`N` is also `N × SHARD_BYTES` on the Pi 4 floor (the client materialises the segment to verify `R_k`)"* ([`ARCHIVAL_SHARD_FETCH.md`](ARCHIVAL_SHARD_FETCH.md):183). Item 5 retired the whole-shard materialise and refuted F32's reason 2 on that ground. Stale premise on a RULED row, and it is the text a future reader would use to derive a memory bound on `T`. | STALE TEXT on a RULED row — owner `SF-` |
| **`SHT-4`** | `U1` is not bounded by `CHALLENGE_RESPONSE_BLOCKS` (500 blocks ⇒ a 10.8 GB budget against a 3.34 MB shard) and the memory leg is retired by item 5. **AMENDED on review:** the first pass then derived the real bound against the 180 KB/s *burst floor* and reported the row as slack, having missed W₂'s **measured** single-attempt figures on the same page (`:1091-1095`). On the measurement the heavy-end ceiling is ~[140, 490] and **`T = 200` is inside it** — `U1a` is unresolved at 200, not slack. The steering prediction that `U1` is the bound most likely to set `T` is **reinstated**; what was wrong in it was only the denominator. | CONFIRMED, then AMENDED — the amendment is the round's headline |
| **`SHT-7`** | **`L`'s fetch-span component is justified by a byte count from the retired segment, and its own page already contradicts it.** `L = 4`'s span was sized on "~20 s for 3.33 MB" (`ARCHIVAL_SHARD_FETCH.md`:1074-1090, the 180 KB/s floor); W₂ at `:1091-1095` then measured **48.27 / 86.06 s** for the same object — 2.4–4.3× worse — and `L` stayed 4 on a *different* argument ("seven attempts of the cold p99 fit under six minutes"). So the span text is stale relative to the measurement one paragraph below it, and **deriving `T` from that span would be circular**: it would feed the retired 3.33 MB back into `T`'s own bound, which is exactly what this round was opened to remove. The independent half is `SF-D6`'s retry budget; that is the part to keep. Restate `L`'s span **per byte**, or re-pin `T` and `L` together — but do not call selecting inside the current span "the cheaper option", which the first pass did. | CONFIRMED — owner `SF-`, and it is why §4's rule selects from the lower edge |
| **`SHT-5`** | `U1b` — an honest server's sustained egress on the rule-76 floor device — **has no authority anywhere in the tree**. The only transport figure (180 KB/s) is requester-side and a burst floor from a null result. This is the one bound that cannot be closed by reasoning. | OPEN — FOLLOWUPS row, measurement owed |
| **`SHT-6`** | `rust/shekyl-economics-sim/src/burden.rs:33-39`'s `SHARD_BYTES` comment derives 3.33 MB from `SEGMENT_LEAF_COUNT × ~128 B` — the retired **leaf-segment** estimate — while presenting it as the "§2 corpus figure". Corrected in this PR (the only code this round touches). | FIXED here |
| **`SHT-8`** | **Two of `SHT-Q1`'s five falsifier surfaces were evaluated against the retired partition, and fixing one of them can hand `T` a fifth job.** `FrozenSegmentCount` counts **J-segments** (`escalation.rs:48-58`), and `shard_age_milli`'s no-segment branch is segment-keyed (`admission.rs:305-341`) — the leaf partition `PDM-Q12` retired. So "not frozen, not counted" and "scores `age_milli = 0`" are true of segments and say nothing about an open **T-shard**; for those two surfaces the falsifier is **unrun**, not passed. The consequence is bigger than the table: `staker_pool_share_at` saturates at `shekyl_escalation_knee_n = 100,000`, and re-keying `n` from segments to closed T-shards turns 100,000 × 25,992 leaves (~1.3 × 10⁹ txs) into 100,000 × 200 = 2 × 10⁷ storage ids — the knee **~65× sooner once the ramp is on, with no economics changed** (it ships flat, so the effect is latent — `SCC-Q2`), and every `T` re-pin thereafter moving when the staker share saturates. **It is a consensus operand, not an economics knob.** `n` reaches consensus through `Blockchain::parent_frozen_segment_count` → `validate_miner_transaction` (`src/cryptonote_core/blockchain.cpp:1494-1508`), derived from `get_curve_tree_leaf_count()` — the **retired leaf geometry** — and read at a pinned parent state with a throwing assert (*"escalation operand read-point violated"*). So the coinbase's fee split depends on it. **CORRECTED 2026-09-27 (`SCC-Q2`'s ruling):** the stronger claim this row first made — *"a wrong re-key changes which coinbases are valid"* — holds only **once the escalation is switched on**. It ships **flat**: `shekyl_escalation_asymptote_share` equals the floor `shekyl_staker_pool_share` (`config/economics_params.json:16-18`, *"the DELIBERATE pre-ceremony NEUTRAL value"*), so the split is 25 % whatever `n` is and a wrong re-key changes no coinbase's validity **today**. The requirement that the re-key be one atomic C++/Rust change is unchanged, and its reason is sharper: the operand is computed on both sides, and a mismatch that is harmless while flat becomes a chain split the moment the GF-7 ceremony raises the asymptote. Likewise the ~65× figure bites only after the ceremony. **Blast radius, otherwise bounded:** per `FL-V4` the escalation splits the *burned* amount between destruction and the staker pool and **cannot move a fee rung** (miner income depends on `burn_pct` alone), so what it clocks is **monetary policy** — how much burned value is redirected rather than destroyed — a gate-1/7 concern, not a ladder one. **Also unlisted:** `n` appears in **no** row of `PDM-Q6` item 4's nine-row re-key table, and `knee_n` is named by no design doc that owns its unit — so this is a consumer of the retired geometry that the re-key census missed. Fix: re-key `n` to a `T`-independent burden quantity (§5). | CONFIRMED — found on review of this round's own falsifier table; the re-key specification is **E4 / S-ARCH's**, not this lane's |
| **`SHT-9`** | **A `shekyl-chain-rules` fixture carries a shape consensus refuses.** `harness::fixture::serve_credit_only` builds `prunable: None` with empty `pqc_auths` — the **pre-`RF-D1`** serve-credit form, identified by the *absence* of a prunable region. `RF-D1` inverted that: the region is now present and holds one non-empty pruned pass record per credit vin. Verified empirically rather than read off: `Transaction::validate_context_free_pruned` refuses it — *"serve_credit tx must be fee-only — no outputs, empty `pqc_auths`, no spend-proof material, and exactly one pruned pass record per serve-credit vin (§2.5, RF-D1)"*. It does **not** break `SHT-Q1`'s equivalence (a conforming serve-credit body carries good, and `tx_domain_tests` builds one), but a fixture that consensus would refuse is a false negative waiting for any test that assumes it is valid. | CONFIRMED — found while building the equivalence test; owner the `CHAIN_RULES_SLICE` lane, FOLLOWUPS |
| **`SHT-10`** | **An FCMP++ proof verifies with trailing bytes.** `Fcmp::read` consumes exactly `proof_size(n, layers)` bytes (`shekyl-oxide/crypto/fcmps/src/lib.rs`), and neither the verifier (`shekyl-fcmp/src/proof.rs`) nor any consensus rule compares `fcmp_proof.len()` with it — the rows check emptiness only (`rules/tx.rs`, `rules/tx_inputs.rs`; C++ `blockchain.cpp`). Probe: a valid proof extended by 1, 64 and 4,096 zero bytes verifies `Ok(true)`. Every hybrid signature binds `prunable_hash`, so only the signer can pad (paying fee), but the good is not a closed function of structure and the encoding is not canonical. Fix: `fcmp_proof.len() == proof_size(n_spend, depth + 1)`. | CONFIRMED by probe — consensus canonical-form gap; **fix directed by the design owner 2026-09-28**, built in PR #899 |
| **`SHT-11`** | **A serve-credit path verifies with zero scalars appended to a branch layer.** `recompute_subroot` hashes each layer as `hash_grow(init, 0, ZERO, chunk)`, a vector commitment on which a zero scalar contributes nothing (`shekyl-archival-retention/src/path.rs`); widths are bounded only by `MAX_BRANCH_SCALARS = 256`. Probe: the `assembled_path_crosscheck` fixture's Helios layer widened 5 → 6 and 5 → 45 verifies `Ok(())`. The ML-DSA countersignature binds `encode(path)`, so only the bonded signer can pad. Fix: canonical widths for a frozen segment, or refuse trailing zero scalars. | CONFIRMED by probe — consensus canonical-form gap; **fix directed by the design owner 2026-09-28**, built in PR #899 |
| **`SHT-12`** | **An input's authorization size is not skeleton-bound.** `scheme_id`, the multisig key container's `n_total` and threshold, and the signature count all live in the `pqc_auths` segment, which the archival prune discards (`shekyl-chain-store/src/store/prune.rs`). The spent output carries no marker (`Output` is amount, key, view tag) and FCMP++ hides which output is spent. So the skeleton cannot tell a 5,389 B single-sig authorization from a 27,083 B 5-of-5 one. The premise that "multisig parameters sit in prefixes the txid binds" does not hold at source. | CONFIRMED at source — the structural question inside `SHT-Q2` (§8.3) |
| **`SHT-Q1` price, withdrawn** | The first pass charged (B) with making prune's mapping "stop being pure arithmetic on the id". **Wrong:** `cumulative_tx_count` *is* the non-coinbase ordinal (`prune.rs:421-428`), and `height_of_tx_id`'s binary search over the running total is already on dev's `h_scarce` path (`prune.rs:490-500`). Under (B) a boundary reads straight off the stored cell with **no coinbase term to add**, so (B) removes an addition from four sites rather than adding a lookup. `SHT-Q1`'s only remaining price is **closure liveness on a quiet chain**. | WITHDRAWN on review |

---

## 7. Out of scope — recorded and moved past

Each is a FOLLOWUPS row, not work for this round:

- The `PDM-Q-F34` coverage row and its sim arms: the heavy-era-ages-into-deep
  arm (expressible since `be785f8e6`'s size-at-birth), the `storage_unit_cost`
  sweep that would separate the cost signal from the capacity leg, and the
  per-band gate read (max over pre-registered age × cost bands, aggregate
  reported but not graded).
- The segment-geometry deletion (E3 / E4) — **and with it `SHT-8`'s re-key
  specification for the escalation operand `n`.** It belongs beside the segment
  deletion in E4 / S-ARCH's re-key table, not in the `T` lane: this round's job was
  to find that the operand is segment-keyed and that a shard-keyed replacement
  would price monetary policy off `T`, not to design the replacement.
- Any change to channel 1.
- Composition "attacks" — A4/W9 CLEARED, §12.11.
- `SHT-5`'s measurement, and `SHT-3`'s stale-text correction in the `SF-` doc.
- **W₂ re-run at two or three object sizes** (`SHT-7` / `U1a`). One size is one
  equation in two unknowns, which is why `U1a` is an interval rather than a
  number and why the 180 KB/s floor is still load-bearing in `L`'s text. The
  harness exists (PR #746). This is the measurement that would make a derivation
  possible, and it also re-grounds `L`'s span per byte.

---

## 8. After F34: input count, item 5 re-read, and `SHT-Q2` (2026-09-28)

F34's lever test (`STAKER_ARCHIVAL_SIM.md` §L19b–§L19g, PR #893) found a
concentrated heavy era, aged into the deep band, under-held at fixed total bytes. Under
the governing all-seeds reading, no non-byte lever clears it at `S = 10`. Before that
result is turned into a case for pricing bytes, this section asks whether the
**partition** can make shards equal-cost instead. That would let the byte-blind price
clear coverage without a byte operand.

### 8.1 Counting inputs instead of transactions — done, not adopted

The proposal: close shards on cumulative **input** count, because `pqc_auths` holds one
authorization per input (`pqc_auths == nvin`, CEN-H21/H22).

Checked at source (tree depth 8 layers, single-sig, 2 outputs):

| component | size | scaling | source |
|---|---|---|---|
| PQC authorization, single-sig | **5,389 B** per input | exactly linear | `4 + v(1996) + 1996 + v(3385) + 3385`; `PQC_HYBRID_SINGLE_{KEY,SIG}_LEN`, `shekyl-wire/src/transaction.rs` |
| FCMP++ proof | 6,624 B at 1 input, 16,640 B at 8 | affine, strongly sublinear | `FcmpPlusPlus::proof_size(n, layers)`, `shekyl-fcmp-proofs/src/lib.rs` |
| BP+ range proof | ~640 B at 2 outputs | logarithmic in outputs | 6 + 2·⌈log₂(64·m)⌉ points, hand-derived from the layout |
| pseudo-outs | 32 B per spend input | linear | `Prunable.pseudo_outs` |

A single-sig spend's good is therefore **12.7 KB at 1 input and 60.7 KB at 8** (the cap,
`FCMP_MAX_INPUTS_PER_TX = 8` on total vins). Per input that is 12.7 KB down to 7.6 KB.

**Not adopted.** Counting inputs narrows the per-transaction shape spread from ~4.8× to
~1.7×, but:

- **It reverses the heavy direction.** The FCMP++ base is amortized over more inputs, so a
  consolidation wave becomes the *light* era per input and a period of single-input spends
  the heavy one.
- **It misses multisig.** A 3-of-5 authorization is 20,310 B, **~3.8×** a single-sig one
  (`MultisigKeyContainer::expected_blob_len`, `MultisigSigContainer::expected_sig_len`,
  `shekyl-crypto-pq/src/multisig.rs`).
- **It misses tree depth.** A one-input proof grows ~20 % from 4 to 8 layers, and depth
  tracks the chain's age.
- **It costs a schema cell anyway.** `cumulative_tx_count` also feeds the fee ladder's
  volume window (CEN-F20; `rules/miner.rs:553`), so an input cell is added, not swapped.
- **Correction to the figures reported with it.** The serve-credit record's "~9,965 B"
  (`ARCHIVAL_RESPONSE_FORMAT.md` §1.1) includes the leaf chunk, which `RF-D8` took off
  the wire (`shekyl-archival-retention/src/path.rs`). Today's record is the 3,309 B ML-DSA
  leg plus the branch layers.

### 8.2 What `PDM-Q6` item 5 rejected — the corrected reading

Item 5 (`ARCHIVAL_PRUNED_DAEMON_MODE.md`, RULED 2026-09-23) retired item 3's byte bound
because **"nothing the checkpoint reaches binds a *length*"**: `C` → block hashes → txids
→ `H(prefix) · H(base) · prunable_hash · pqc_auth_hash`. A peer serving the skeleton
below `C` "can state any length", and one wrong value forks the node at admission.

What it rejected is **boundaries computed from stored lengths**: values neither bound by
the checkpoint chain nor recomputable by a node that has discarded the bodies. It did
not reject **byte-proportional boundaries as such**. A weight computed from structure the
txid binds has neither defect, because every node derives the same value from kept data.

Item 5's second argument — that channel 1 "absorbs size variance as it absorbs everything
else" — is the premise F34 tested. Under the governing reading it does not hold at
`S = 10` in the sim (§L19g §4), pending the calibrated arm (§L19h).

This is a correction to item 5's reasoning, not a reversal of its principle. The
principle — a boundary never reads a value the skeleton cannot bind — is what `SHT-Q2`
below states as its invariant.

### 8.3 `SHT-Q2` — a byte-proportional partition — for Rick's ruling

**The question.** Should shard `k` close on cumulative **archival bytes** instead of
transaction count, and if so, measured how: by a **computed weight** — options (a) and (b)
below — or by a **declared length** bound by the txid (option (c), §8.4, which the design
owner recommends)?

**Invariant it must satisfy.** Every shard boundary is a pure function of data every node
keeps forever, under a rule pinned by height. This section tests the computed-weight form
of that rule; §8.4 tests the declared-length form:

1. **Inputs only from the kept skeleton.** Nothing from proof bodies or recorded lengths.
2. **Deterministic per class.** Each domain class's prunable + `pqc_auths` size is a
   closed function of those inputs.
3. **Pinned by height.** The weight function is consensus code. A wire change that moves a
   proof size updates it at an activation height, and closed shards never move — the
   stability clause `SHT-Q1` already carries.

**Where tree depth at a height comes from.** `curve_tree_leaf_counts[h]`: a stored,
skeleton-derived cell (CTW-Q4 RULED — "own table, storing the primitive",
`DRS_E3_CURVE_WRITER.md`; SI-18, `STORE_INVARIANT_REGISTER.md`), read through
`ChainView::depth_at` (`shekyl-chain-rules/src/view.rs`) as `layer_count_for_leaves(count)
− 1`. It is not a cache: the schema describes it as "a function of the leaf table the
digest's root already commits to" (`shekyl-chain-store/src/schema.rs`). **One gap.**
CEN-I13's equality — the declared depth equals the depth at `ref_height` (E6 slice 6 Q8) —
is `pending` in the Rust validator (`census.rs`). The C++ only range-checks
`1 ≤ depth ≤ current depth` (`blockchain.cpp`, spend arm "Step 3"). Today the depth is
pinned only **implicitly**: the proof is verified against the root at `ref_height`, and a
probe at depth + 1 returns `InvalidTreeRoot`.

**Per component, at the pin.** "Determined" means a closed function of skeleton-bound
structure.

| component | carried by | determined? | what pins it, or what breaks it |
|---|---|---|---|
| spend inputs `n_spend`, serve-credit vin count, output count `m` | prefix | **yes** | the txid binds the prefix |
| pseudo-outs | Spend, BondPost, Emission w/ fee | **yes** | `32 · n_spend` (CEN-I9 and the H21/H22 spend-subset counts) |
| BP+ | the shapes that carry one | **yes** | `nbp == 1` (`cryptonote_format_utils.cpp:151`); `|L| = |R| = log₂` of the padded generator count (`shekyl-bulletproofs/src/plus/weighted_inner_product.rs:353`), fixed by `m`. Whether a fee-less emission carries one is a shape rule this section does not settle — H22 admits `prunable: None`, `:151` asks one range proof of every non-serve-credit BP+ shape — and either way it is fixed by class and `m` |
| FCMP++ proof (full and membership-only) | Spend, BondPost, Emission w/ fee | **no — signer-paddable** (`SHT-10`) | `Fcmp::read` consumes exactly `proof_size(n, layers)` bytes and nothing checks the remainder. The closed function exists; the wire does not hold to it |
| curve-tree depth | same | **yes, via the stored cell** | `depth_at(ref_height)` above. The explicit equality (I13) is pending; the implicit one is verification |
| PQC authorization | Spend, BondPost, Emission (one per vin) | **no — not skeleton-bound** (`SHT-12`) | `scheme_id`, `n_total`, threshold and the signature count all live in the `pqc_auths` segment, which the archival prune discards (`prune.rs`). The skeleton cannot tell a single-sig input (5,389 B) from a 5-of-5 one (27,083 B) |
| serve-credit pruned record | ServeCreditOnly (one per vin) | **no — signer-paddable** (`SHT-11`) | the ML-DSA leg is fixed (3,309 B, `ML_DSA_COUNTERSIGNATURE_LEN`) and the record parses exactly (`read_exact`), but `verify_segment_path` accepts zero scalars appended to a branch layer |

**Per class:**

| class | determined today? | breaks on |
|---|---|---|
| **Spend**, single-sig | no | `SHT-12` (the skeleton cannot tell it is single-sig), `SHT-10` |
| **Spend**, multisig | no | `SHT-12`, `SHT-10` |
| **BondPost** (funding spends + the post vin) | no | `SHT-12` (every vin carries an auth), `SHT-10` |
| **Emission** with fee inputs | no | `SHT-12`, `SHT-10` |
| **Emission** without fee inputs | no | `SHT-12` (its only good is the auth). The emission vin's membership proof and hybrid signatures are in the **prefix** (`Input::ArchivalRewardEmission`'s blob), so they are skeleton, not good |
| **ServeCreditOnly** | no | `SHT-11` |

**So no class is determined at the pin, and the breaks are exactly three components:**

- **`SHT-10` and `SHT-11` are canonical-form gaps, and each has a local fix:**
  - require `fcmp_proof.len() == proof_size(n_spend, depth + 1)`;
  - require each branch layer's width to equal the canonical width for a frozen segment,
    or refuse trailing zero scalars.

  With those, both components are closed functions. Neither is a third-party malleability
  hole: every hybrid signature binds `prunable_hash` (`signing_preimage.rs`), and the
  serve-credit ML-DSA countersignature binds `encode(path)`. Only the signer can pad, and
  pays for it in fee.
- **`SHT-12` is structural, and it is the question inside `SHT-Q2`.** Three ways out, for
  Rick. The design owner recommends (c), below; (a) and (b) are kept for the
  comparison:
  - **(a) Bind a per-input scheme descriptor in the prefix** — `scheme_id`, `n_total`, and
    the signature count. This is a wire change. It makes the authorization a closed
    function, and every class is then determined once `SHT-10`/`SHT-11` are fixed and I13
    lands. **It has a privacy cost, and privacy is the product (rule 00, commitment 2).**
    An input's multisig shape is public today only while the `pqc_auths` segment
    survives. A prefix descriptor makes it permanent on every node's skeleton. The spent
    output carries no scheme marker (`Output` is amount, key and view tag), and FCMP++
    hides which output is spent, so nothing already on the skeleton reveals it.
  - **(b) Weight every authorization at the single-sig constant.** Multisig inputs then
    carry up to 21.7 KB more than their weight, so shards stay equal-cost except where
    multisig concentrates. That is the same kind of residue F34 measures, bounded to one
    component.
  - **(c) Declare the archival length in the prefix — the design owner's
    recommendation (2026-09-28).** One varint, `archival_len = |prunable region| +
    |pqc_auths|`, covered by the txid and signed, and checked at ingest against the actual
    bytes (reject on mismatch). Boundaries are then cumulative **declared length**, not a
    computed weight. §8.4 wargames it.

**What a weight function would be, given (a):**

> `w(tx) = Σ_vins A(scheme_i) + [spend-bearing] · (BP(m) + F(n_spend, depth_at(ref) + 1) + 32·n_spend + varints) + Σ_credit-vins (P + 3,309 + varints)`

- `A(single) = 5,389`.
- `A(multisig n, s) = 4 + v(3 + 2028n) + 3 + 2028n + v(1 + 3386s) + 1 + 3386s`.
- `F` is `FcmpPlusPlus::proof_size` (or the membership-only form). It is closed in
  `(n, layers)`, though not monotone in `layers`, because of IPA row padding.
- `P` is the canonical path size for a frozen segment.

**The boundary rule and its overshoot.** Transactions are indivisible, so shard `k` closes
on the first transaction that takes the cumulative weight past `(k + 1)`'s threshold,
measured from the previous boundary. A closed shard then holds between `W` and
`W + w_max`, where `w_max` is the most good one legal transaction can carry.

**`w_max` is bounded by consensus, padded or not.** A transaction's good is part of its
serialized size, and its size is at most its weight. The weight is the size plus the BP+
clawback, and CEN-H3 caps it at `TX_WEIGHT_LIMIT` = **149,400 B**
(`shekyl-wire/src/transaction.rs`; `rules/tx.rs` `max_tx_weight`). So `w_max < 149,400 B`,
about **4.5 %** of a 3.33 MB shard. `MAX_TX_SIZE` (1 MB) is only the parse and DoS cap. No
admitted transaction reaches it, and it plays no part in the bound.

The weight function's own structural maximum sits inside or beyond that cap depending on
the authorization:

- **single-sig:** 8 inputs, 16 outputs, depth `MAX_TREE_DEPTH = 24`
  (`shekyl-fcmp/src/lib.rs`) is ~78 KB. That is 43,112 B of authorizations, a
  33,728 B FCMP++ proof at 25 layers, ~835 B of BP+ and 256 B of pseudo-outs;
- **multisig:** eight 5-of-5 authorizations alone are 216,664 B, so the structural maximum
  exceeds CEN-H3, and **CEN-H3 is the binding bound**.

So `SHT-10` and `SHT-11` do not widen the overshoot. What they break is **weight = bytes**:
a padded transaction carries more good than its computed weight says, up to the same
149,400 B cap, and the signer pays fee for the padding. That is a determinism defect,
not an overshoot one.

**The `T` constraint, restated in weight:** `W ≫ TX_WEIGHT_LIMIT`, with the overshoot
fraction `TX_WEIGHT_LIMIT / W` — the bound, not a typical value — stated at the
selected `W`. A move of the full-reward zone moves this constraint with it, since
`TX_WEIGHT_LIMIT` is derived from it. This joins the §3 constraints — which were
already reasoning in bytes through `U1a` — in place of the transaction count.

**Cost, under (a) or (b):**

- the weight function, as consensus code with one home;
- `SHT-10` and `SHT-11`'s canonical-form rules;
- I13's equality, landed as ruled;
- option (a)'s prefix descriptor, if chosen;
- a cumulative-weight cell in `block_info` beside `cumulative_tx_count`, which stays
  because it feeds the fee ladder. That is +8 B per block, 104 → 112 B, and a rule-42
  schema bump;
- `SHT-Q1`'s text amended from "`T` transactions" to "weight `W`";
- the cutover census's family-1 rows re-keyed, and `SHARD_TX_COUNT` /
  `archival_shard_tx_count` renamed, because the unit is in the name.

**If ruled yes, what it removes.** Shards become equal-cost by construction up to
`w_max / W`, exactly under (c), and under (b) except for multisig. F34's composition question largely goes away,
and with it `U1a`'s heavy-end quantile and the `√T` composition bound. `T` becomes `W`,
derived in bytes directly.

**Not ruled here.**

**How the three findings were established.** `SHT-10`: the `prove_verify_roundtrip`
fixture (`shekyl-fcmp/src/proof.rs`), with the proof's data extended by 1, 64 and 4,096
zero bytes, verifies `Ok(true)` each time; the same proof at depth + 1 returns
`InvalidTreeRoot`. `SHT-11`: the `assembled_path_crosscheck` fixture
(`shekyl-archival-retention/tests/`), with its Helios branch layer widened from 5 to 6
and to 45 scalars by appending zeros, verifies `Ok(())`. Both probes were run as
uncommitted edits and reverted. The library verifiers probed are the ones the consensus
FFI calls; neither was replayed through a full block connect.

### 8.4 Option (c), wargamed — posed, not ruled

**The claim.** A transaction's archival byte length, carried as a prefix varint, is
skeleton data. The txid binds the prefix, so item 5's objection — a length nothing the
checkpoint reaches binds — does not apply. The value is exact, not a model. With it:

- no weight function is needed;
- future proof formats, multisig schemes and signer padding are covered by construction;
- a new kind of prunable data is covered too, the principle `SHT-Q1` set for the domain.

It costs ~2–3 bytes per transaction of skeleton (a varint of a value below
`TX_WEIGHT_LIMIT` = 149,400 is at most 3 bytes) and one ingest check.

**How a declared length could diverge from the bytes, and what closes each path:**

| path | what could diverge | what closes it |
|---|---|---|
| **Which bytes** | The tree has **three** encodings of the auths: the wire body (count implicit in `nvin`), the stored `txs_pqc_auths` segment (no count), and the txid component, which hashes `varint(count) ‖ auths` (`transaction/txid.rs`, `pqc_auth_hash`: "**not** `keccak256` of the stored `txs_pqc_auths` segment"). A length defined over the wrong one is off by the count varint. | Define `archival_len` as exactly the bytes a body store holds and discards: `Transaction::write_segments`' `prunable` and `pqc_auths` outputs (`TxSegments`, `transaction.rs`). One function computes it for the builder, the ingest check and the store; the rule names that function, not a formula. |
| **The ingest check** | A body whose regions are longer or shorter than declared. | A context-free transaction rule: `declared == |segments.prunable| + |segments.pqc_auths|`, refusing on mismatch. It needs the full body, so it runs where bodies are validated (connect, mempool). The domain predicate ties in: `declared > 0 ⇔ carries_archival_good` must hold, pinned by the same equivalence test that pins `SHT-Q1`'s. |
| **Re-serialization** | A relay or a second serializer re-encodes the body and its length changes. | Nothing new. The txid hashes those exact bytes (`prunable_hash` over the region; the auth component over the auths), so any re-encoding that changes the length already changes the txid. The length inherits the txid's canonical-form discipline, and nothing else. |
| **The storage-pruned path** | `get_transactions prune:true` returns a spend with `pqc_auths` and no prunable region. A consumer that re-checks the declared length against *that* form sees a mismatch. | The check is an **ingest** rule over a full body, never a property of every in-memory form. The storage-pruned form keeps its declared length and is not re-checked. A skeleton-only node below the checkpoint cannot run the check at all; it holds the length as **bound, not re-verified**, the same trust class as every other skeleton field. That is exactly the property item 5 found missing. |
| **Signing before the length is known** | The prefix carries the length, and the hybrid signatures sign the prefix (the signing preimage's `pruned` segment), so the builder must know the length before signing. | Every component length is known in advance: the authorization lengths from the scheme (5,389 B single-sig; `expected_blob_len`/`expected_sig_len` for multisig), the FCMP++ proof from `proof_size(n, layers)`, the BP+ from the output count, the pass records from the segment shape. The builder declares, signs, and then produces bytes that must match. |
| **Coinbase** | — | Declares `0` (or carries no field, if the field is typed off the non-`Null` CT). Outside the domain either way. |

**Interaction with `SHT-10` and `SHT-11`.** Under (c), padding is *counted*: a padded
proof declares its padded length, and the boundary sees real bytes. So (c) does not need
the canonical-form fixes for determinism. They are still owed for canonical form — two
valid encodings of one statement — and the design owner has directed them built now,
independently of `SHT-Q2`. A signer who pads inflates only their own transaction's
bytes, pays fee for them, and stays under `TX_WEIGHT_LIMIT`.

**Where the cumulative cell lives.** A store-derived running total in `block_info`,
beside `cumulative_tx_count`: the parent's value plus the sum of this block's declared
lengths, under `checked_add` (SI-8). Every node derives it from kept prefixes, including a
skeleton-only rebuild, and the pop journal reverts it like the transaction count. That is
+8 B per block (104 → 112), and a rule-42 schema bump. `cumulative_tx_count` stays, because
it feeds the fee ladder.

**The boundary rule — one sub-choice.**

- **(c-i) Global multiples:** a transaction belongs to shard `⌊start_offset / W⌋`, where
  `start_offset` is the cumulative declared length before it (the block cell plus a
  within-block prefix sum). This is closed-form and needs no table. A shard holds
  `(W − w_max, W + w_max)`, because overshoot carries forward.
- **(c-ii) From the previous boundary:** `PDM-Q6` item 3's corrected form. A shard holds
  `[W, W + w_max)`, a floor of `W`, but boundaries need a derived table of one `u64` per
  shard, rebuilt in one forward pass.

`w_max < TX_WEIGHT_LIMIT = 149,400 B` either way (§8.3's overshoot bound carries over
unchanged: it is CEN-H3's, not the weight function's). Item 3 chose (c-ii) for the
floor, which mattered while a whole-shard read had to mean at least `SHARD_BYTES`.
Whether anything still needs that floor is the question that picks between them.

**Privacy.** A transaction's size is visible to every peer at relay, and its bodies stay
public on archival nodes by design, so pruning was never a privacy mechanism. The
declared length makes one fact permanent on every skeleton that relay already exposed.
With the input count known, it lets a skeleton-only observer infer an aggregate
authorization shape (single-sig versus multisig inputs), which any relay capture or
archived body already shows. That is a smaller exposure than (a), which states each
input's scheme explicitly.

**Cost, under (c):** the prefix varint (a wire change, pre-genesis); the ingest rule
and its equivalence leg against `carries_archival_good`; the cumulative cell and the
schema bump; `SHT-Q1`'s text amended from "`T` transactions" to "declared length `W`";
the cutover census's family-1 rows re-keyed; and `SHARD_TX_COUNT` /
`archival_shard_tx_count` renamed. No weight function, and no prerequisite on `SHT-10`,
`SHT-11` or I13.

**Not ruled here.**

### 8.5 Where the declared length lives — prefix or txid — posed, not ruled (2026-09-29)

§8.4 put the declared length in the **prefix**. The design owner has proposed binding it
through the **txid** instead. This section answers the three questions that decide
between them, at source on `dev`, then wargames the txid placement. It poses both;
**Rick rules.**

#### 1. What each signature and proof signs today

| signer | what it signs | source |
|---|---|---|
| **PQC authorization**, per input — single and multisig, every class that carries one | `payload(i) = pruned ‖ prunable_hash ‖ header(i) ‖ key_hashes`. `pruned` is version, prefix, CT type, fee, reference block and committed base. `prunable_hash` is the digest of the whole prunable region. `header(i)` is `auth_version ‖ scheme_id ‖ flags ‖ varint(pk_len) ‖ pk`, which carries the **key**, not the signature. `key_hashes` hashes every input's key | `shekyl-wire/src/transaction/signing_preimage.rs` |
| **FCMP++ proof**, on the spend and bond-post paths | the prefix hash (`tx_prefix_hash`, the prefix only), with the pseudo-outs in the transcript | `blockchain.cpp:3371` and the two verify sites |
| **FCMP++ proof**, on an emission's fee inputs | the full prefix hash, which includes the emission input and its two hybrid signatures | `blockchain.cpp:4099` |
| **Membership-only backing proof** (emission) | the prefix hash **with the emission input removed** (F-C1c), because the input cannot be covered by a hash its own proof signs | `blockchain.cpp`, emission arm |
| **Emission input's `auth_backing` / `auth_claim`** | the input's claim fields, which are in the prefix. These are two fixed-length hybrid signatures, and they are skeleton, not good | `REWARD_EMISSION_LEG.md` §5.3.1 |
| **Serve-credit countersignature** (Ed25519 leg on the input, ML-DSA leg in the pruned record) | the **pass record only**: `p_canonical_id ‖ shard ‖ epoch ‖ R_k ‖ leaf_index ‖ leaf_bytes ‖ encode(path)`. No prefix, and nothing at transaction level | `shekyl-archival-retention/src/wire.rs` `signature_preimage` |

**Does any signed message today include data whose length depends on the signatures
themselves? No.** The PQC preimage covers keys and the prunable digest, never the
signature bytes or their lengths. The prunable region holds no PQC signatures. Its one
signature, the serve-credit ML-DSA leg, is in a form that has no PQC authorizations to
sign over it. The emission fee-input proof binds the emission input's two signatures,
but those are produced earlier and have fixed length.

**Two consequences for the placements.**

- **Prefix placement introduces the dependency that is absent today.** `archival_len`
  counts `|pqc_auths|`, and the PQC signatures sign the prefix, so every signer must know
  the final length of every signature, its own included, before signing.
- **A serve-credit transaction is signed by nothing at transaction level.** So in the
  prefix, its declared length would be bound only by the txid anyway. For that class,
  prefix placement buys no signature.

#### 2. Is every component's length fixed before signing, once `SHT-10`/`SHT-11` are fixed?

**Yes, for every current scheme.**

| component | length before signing | what fixes it |
|---|---|---|
| single-sig authorization | 5,389 B | `PQC_HYBRID_SINGLE_{KEY,SIG}_LEN`; the key length is exact under CEN-I16 |
| multisig authorization | `expected_blob_len(n_total)` + `expected_sig_len(m)` | the signature count **must equal** the key container's `m_required` (`shekyl-crypto-pq/src/multisig.rs`: `sig_container.sig_count != key_container.m_required` refuses), so `m` is fixed by the key, not by which signers answer |
| FCMP++ and membership-only proofs | `proof_size(n, depth + 1)` | exact once `SHT-10` refuses trailing bytes (#899). The depth is the one at `ref_height`, known to the builder |
| BP+ | a function of the output count | `nbp == 1`, and `|L| = |R|` pinned by the generator count |
| pseudo-outs | `32 · n_spend` | CEN-I9 |
| serve-credit pruned record | 3,309 + `|encode(path)|` + varints | the path is the frozen segment's chunks as built, and `SHT-11` refuses trailing-zero padding (#899). The ML-DSA leg signs the path, so the path exists first |

**The caveat is the future, not the present.** Under the V4 lattice-only transition (rule
00's third horizon), a scheme with **variable-length signatures** — Falcon's compressed
encoding is the standing example — cannot be sized before signing. The prefix placement
would force such a scheme into a padded encoding, or into a two-pass sign.

#### 3. The design owner's refinement: bind the length through the txid

**The proposal.** The body carries **no** length field. `archival_len` is computed from
the body's own bytes: `|segments.prunable| + |segments.pqc_auths|`, the stored segments
(§8.4's "which bytes" row). It is folded into the txid's mixer, and a skeleton node keeps
it as a row beside `txs_prunable_hash` and `txs_pqc_auth_hash`.

**The change surface** is one mixer per language:
- Rust `Transaction::hash_from_components` (`transaction/txid.rs`);
- C++ `calculate_transaction_hash` (`cryptonote_format_utils.cpp`);
- the supplied-components path (`hash_with_supplied_components`), which gains the length
  as a third supplied operand, exactly as the pruned form already supplies the prunable
  digest.

| wargame | outcome |
|---|---|
| **Malleability** | None new. The length is not a field the author chooses: a full body determines it, so there is exactly one valid value. A supplied length that disagrees with the bytes yields a different txid, and the block's transaction list refuses it. On a full body the txid computation **is** the ingest check, so no separate equality rule is needed |
| **Skeleton-sync trust path** | The same path as the two hash rows: the supplied components rebuild the txid, the txid rebuilds the block's transaction root, then proof of work and the checkpoint. A peer that lies about a length breaks the txid. Below the checkpoint the length is **bound, not re-verified** — the property item 5 found missing from stored lengths, now present |
| **Coinbase** | Unchanged. A `Null` CT keeps its 3-part form and has no length row; it is outside the domain. A `Fcmp` transaction folds the length in whether it is 3-part (serve-credit, no auth component) or 4-part. `archival_len > 0 ⇔ carries_archival_good` becomes a pinned invariant beside `SHT-Q1`'s equivalence test |
| **The storage-pruned form** (`get_transactions prune:true`) | It carries the length as a supplied component, like the prunable digest it already carries. Nothing re-derives the length from a form that lacks the bytes |
| **Variable-length signature schemes** | No constraint. The length is computed after every byte exists, so no signer needs to know it in advance. This is the property the prefix placement lacks |
| **Relay** | A full-body relay carries nothing new: the receiver computes the length. Only pruned and skeleton transports carry it |

**The cost is the same in kind as the prefix placement's.** Both change every txid, so
both regenerate the cross-language parity pins (`pruned_tx_hash_parity`,
`serve_credit_tx_parity`), the live-oracle pin (`live_oracle_spend_v1.json`) and the
captured corpora. Both need the skeleton row and the cumulative cell. The prefix
placement adds a wire field and an explicit ingest equality rule; the txid placement adds
a mixer operand and a supplied component, and needs no equality rule.

#### 4. Both placements, for the ruling

| | **prefix field** (§8.4) | **txid-bound** (design owner's refinement) |
|---|---|---|
| bound by | txid; also signed wherever a PQC signature exists (not serve-credit) | txid |
| author-chosen? | yes, so an ingest equality rule is needed | no, derived from the bytes; the txid is the check |
| lengths needed before signing | **yes**: every signature's final length | **no** |
| variable-length signature schemes (V4) | forced into padding or a two-pass sign | unaffected |
| skeleton row and cumulative cell | needed | needed |
| wire change | a prefix field | a txid-mixer operand, plus a supplied component on pruned transports |
| every txid changes | yes | yes |

**Recommendation (design owner): txid-bound.** It gets the same binding, removes the
only signing-order dependency the prefix placement would introduce, needs no author-chosen
value and so no equality rule, and survives a variable-length signature scheme at the V4
transition. The partition built on it is unchanged from §8.4: global multiples of `W`,
with `max archival length < W` as a static relation between the two constants.

**Not ruled here.**

### 8.6 `SHT-Q2` — RULED (Rick, 2026-09-29)

> **SHT-Q2 RULED (Rick, 2026-09-29): shards are cut by archival length, bound through the txid.** Each in-domain transaction's archival length (prunable + `pqc_auths` bytes) is folded into its txid and stored as a skeleton row. It is never declared or signed, and it is supplied by storage-pruned forms like the prunable hash. Shard membership is ⌊cum_before / W⌋ over the cumulative archival length: global multiples of W, no table. Static constraint: maximum archival length of one transaction < W. The domain (SHT-Q1) is unchanged. Its text changes from "T transactions" to "archival length W". F34's composition question closes by dissolution once this is built; the funding finding stands separately.

**What the ruling settles, as the design owner stated it.** Nothing is declared: the txid
mixer measures the finished bytes itself.

- **On the wire:** no new field and no added bytes. A full node computes the length from
  the bytes it holds while computing the txid, so there is no ingest check to write, and a
  wrong length cannot exist.
- **In the skeleton:** one row per transaction, beside the two digest rows. A
  storage-pruned transaction supplies its length exactly as it supplies its prunable hash.
  A wrong one produces a wrong txid and fails the Merkle check.
- **In code:** one mixer function per language.

**Ruled work:**

1. The txid mixer in both languages (`Transaction::hash_from_components`; C++
   `calculate_transaction_hash`), the stored archival-length row, and the cumulative
   archival-length cell beside `cumulative_tx_count`. The count cell stays, because it
   feeds the fee ladder (CEN-F20).
2. The boundary function `⌊cum_before / W⌋`, and the `W` constant with its static
   relation `max archival length of one transaction < W`.
3. The regenerated parity pins (`pruned_tx_hash_parity`, `serve_credit_tx_parity`,
   `live_oracle_spend_v1.json`) and the captured corpora.
4. `T`'s derivation re-based in bytes. `U1a`'s ceiling was already in bytes, and the
   composition bounds drop out.
5. The cutover census (`ARCHIVAL_SHARD_COUNT_CUTOVER.md`) updated for the new boundary
   function: the same consumers, a new function behind them.

**Consequences recorded with the ruling:**

- **The overshoot bound carries over.** A shard's archival length lies in
  `(W − max, W + max)`. Under CEN-H3 a transaction's good is below `TX_WEIGHT_LIMIT` =
  149,400 B (§8.3). The static relation `max < W` means no transaction spans a whole
  multiple of `W`, so no shard is empty.
- **The equivalence invariant changes subject.** §2's "the domain equals the non-coinbase
  transactions, read from `cumulative_tx_count`" still holds for **membership**. Boundaries
  now read the archival-length cell. `archival_len > 0 ⇔ carries_archival_good` joins the
  pinned invariants.
- **The heavy-end composition quantile is no longer owed.** Its FOLLOWUPS row asked for a
  shard-level quantile to replace L19's shape-cap multiplier in `U1a`. Equal-length shards
  have no composition spread, so `U1a` is re-based in bytes (item 4) without it. The row
  is retired in this change.
- **F34:** composition closes by dissolution **once this is built**. The funding finding
  from `STAKER_ARCHIVAL_SIM.md` §L19i–§L19j stands separately, as a gate 4/5 budget-sizing
  input: paid whole-shard challenge egress at a low SKL price outruns the archival budget
  (φ 2.9–29 in the breaching calibrated cells).
