# `T` — deriving the archival shard cardinality

**Status:** OPEN — Round 0 executed 2026-09-26 at `b72aac2fc` (the composition
arm with `origin/dev@ad557ac5a` merged in); **AMENDED on review the same day
(at `9e8c0bee0`)** — the conclusion moved. `U1a` was derived against the wrong
transport figure: W₂ has *measured* single-attempt fetch since 2026-09-16, and
on the measured numbers `U1a` is **unresolved at `T = 200`** rather than three
orders of magnitude slack. The selection rule is re-pointed at the **lower**
edge with the asymmetry argument it was missing, `SHT-Q1`'s price for the
ordinal domain is **withdrawn** (dev already does the lookup it was charged
for), and `SHT-7` is added. `SHT-Q1` (the partition domain) is
**posed, not ruled** — it is steering's, and it comes before the bounds because
it decides which constraints exist. Findings `SHT-1`…`SHT-6` are at-pin
findings of this round. Identifier families **`SHT-`** (findings) and
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

## 2. `SHT-Q1` for steering — the partition domain

**This is a question with evidence, not a ruling.** It comes first because it
decides which constraints in §3 exist at all.

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
| D2 escalation | `compute_burn_split_at(total_fees, burn_pct, n: FrozenSegmentCount)` (`burn.rs:188-191`) — and `FrozenSegmentCount` counts **J-segments**: *"Zero frozen segments (genesis / empty tree)"* (`escalation.rs:48-58`) | ⚠️ **NOT A PASS — same defect.** "Not frozen, not counted" is true of segments. See `SHT-8`: the re-key is unspecified, and specifying it wrongly hands `T` a fifth job |
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

**The ceiling stated directly**, because a falsifier is not a substitute for
the arithmetic: one bond record can hold at most

> `MAX_HOLDINGS_SHARDS × T × bytes-per-tx = 4096 × 200 × 16.7 KB ≈ 13.7 GB`

at `T = 200` — the most history a single persona can be obliged to. Whether
forcing a larger archiver into a second persona is a **feature** (gate-6
firewall cost, deliberately paid) or a **cost** (overhead on the honest
operator who wants to hold more) is **a ruling, not a measurement**, and it is
not one this round makes. Either way it couples `T` to a cap that freezes at
genesis, so it belongs in §5. Per-shard consensus state (`archival_r_market`
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
pairs ∝ shards × holders ∝ `X/T`. Same direction as `L2` and strictly weaker
than it at any `T` where `L2` is satisfied. *Domain:* both. *Grade:* **soft**.
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
`L2`/`L3` pull upward and `L2` now has a stated ceiling of its own; `U1b` still
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

> **Pick the smallest `T` that clears `L1`'s composition floor and `L2`'s
> bookkeeping floor, subject to `U1a` shown clear at the heavy end of
> composition by measurement, not by a floor.**

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
- **`L2`'s floor depends on a ruling this round does not make** — whether the
  ~13.7 GB per-bond ceiling is a feature (gate-6 firewall cost, deliberately
  paid) or an overhead on an honest operator. The two answers put the floor in
  different places.

So the rule currently has **nothing to select from**: a lower-edge rule whose
lower edges are one underived threshold and one open ruling. That is the correct
state of the work and not a defect in the rule — but the deliverable here is the
*rule plus its three owed inputs* (`L1`'s threshold, `L2`'s ruling, and `U1a`'s
two undischarged quantities), not a value for `T`.

**Pre-registered falsifiers on any `T` this round selects.**

1. W₂ at multiple object sizes resolves `t_fixed` such that the heavy-end
   single-attempt read at the selected `T` exceeds the one-block criterion —
   `U1a` violated. **This is the live one: at the pessimistic reading it is
   already true at `T = 200`.**
2. A sustained serve-throughput figure on the floor device at which `U1b` binds
   below the selected `T`.
3. A measured `CV_tx` whose `L1` bound exceeds the selected `T`.
4. An honest single-persona archiver reaching `MAX_HOLDINGS_SHARDS` inside the
   mining era at the selected `T`.
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
   which hands selection back to `L1`/`L2`. The threshold between those readings
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
- **`T` ↔ `MAX_HOLDINGS_SHARDS`** (`= 4096`, frozen in `shekyl-types`). Their
  product times bytes-per-tx is the most history one bond can carry (~13.7 GB at
  `T = 200`, §3 `L2`). A `T` re-pin moves that ceiling without touching the cap,
  so whichever of the two is intended to carry the obligation must be said out
  loud. Missing from the first pass's coupling list.
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
| **`SHT-8`** | **Two of `SHT-Q1`'s five falsifier surfaces were evaluated against the retired partition, and fixing one of them can hand `T` a fifth job.** `FrozenSegmentCount` counts **J-segments** (`escalation.rs:48-58`), and `shard_age_milli`'s no-segment branch is segment-keyed (`admission.rs:305-341`) — the leaf partition `PDM-Q12` retired. So "not frozen, not counted" and "scores `age_milli = 0`" are true of segments and say nothing about an open **T-shard**; for those two surfaces the falsifier is **unrun**, not passed. The consequence is bigger than the table: `staker_pool_share_at` saturates at `shekyl_escalation_knee_n = 100,000`, and re-keying `n` from segments to closed T-shards turns 100,000 × 25,992 leaves (~1.3 × 10⁹ txs) into 100,000 × 200 = 2 × 10⁷ storage ids — the knee **~65× sooner, with no economics changed**, and every `T` re-pin thereafter moving when the staker share saturates. **Blast radius, bounded:** per `FL-V4` the escalation splits the *burned* amount between destruction and the staker pool and **cannot move a fee rung** (miner income depends on `burn_pct` alone), so this is a clock on **monetary policy** — how much burned value is redirected rather than destroyed — a gate-1/7 concern, not a ladder one. **Also unlisted:** `n` appears in **no** row of `PDM-Q6` item 4's nine-row re-key table, and `knee_n` is named by no design doc that owns its unit — so this is a consumer of the retired geometry that the re-key census missed. Fix: re-key `n` to a `T`-independent burden quantity (§5). | CONFIRMED — found on review of this round's own falsifier table; the re-key specification is **E4 / S-ARCH's**, not this lane's |
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
