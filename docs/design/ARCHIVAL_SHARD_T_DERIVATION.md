# `T` — deriving the archival shard cardinality

**Status:** OPEN — Round 0 executed 2026-09-26 at `b72aac2fc` (the composition
arm with `origin/dev@ad557ac5a` merged in). `SHT-Q1` (the partition domain) is
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
| transport figure | **a burst floor near 180 KB/s** — "a floor from a null result, not a sustained figure" | [`ARCHIVAL_SHARD_FETCH.md`](ARCHIVAL_SHARD_FETCH.md):1079 |
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
| **Consensus touch points** | `close_height`, the serve-credit preimage terms `(k·T, (k+1)·T)`, bond admission's closed-shard predicate (ruled 2026-09-19, unbuilt), and prune's range mapping — which must already tolerate interleaved coinbases having no body rows. | Same four, **all re-keyed**. `close_height(k)` becomes the height of the block containing listed ordinal `(k+1)·T − 1`; the preimage terms are ordinals, not ids; and `prune.rs:415-416`, `:490-493` are written against (A) — `⌊id / T⌋` becomes `⌊(id − height − 1) / T⌋`, which needs the height at the id, so the mapping stops being pure arithmetic on the id. That is the price of (B): a consensus-touching change to the only production consumer of `T`. |
| **Sizing** | `SHT-2`: the shard's good scales with usage; 3.33 MB is the saturation case. | The shard's good is `T` × per-spend good in **any** era — the case the JSON comment describes. |

**Recommendation withheld.** The trade is closure liveness and a prune re-key
(favouring A) against the zero floor and a size that means something
(favouring B). Both legs are steering's call.

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
privacy cost, not a capacity one. Per-shard consensus state (`archival_r_market`
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
- Where `T` **does** enter a ruled derivation is `L = 4`: its fetch-span
  component is "two blocks of fetch-plus-retry (four minutes)", chosen against
  "~20 s for 3.33 MB" at the 180 KB/s floor
  ([`ARCHIVAL_SHARD_FETCH.md`](ARCHIVAL_SHARD_FETCH.md):1074-1090). So

> `T ≤ (span budget × throughput) / bytes-per-tx`

  The full two-block span gives 240 s × 180 KB/s = 43 MB → `T ≲ 2,600` at
  16.7 KB/tx. But the span must also absorb `SF-D6`'s bounded retries; if
  retries may take two thirds of it, the single-attempt budget is ~80 s →
  `T ≲ 860`. At the heavy end of composition (~2× the mean, L19) halve those:
  **`T ≲ 430–1,300`**. The assumed retry share is stated, not derived — it is
  `SF-D6`'s budget, which is a design quantity this round does not own.

*Domain:* both — the read is of a shard's bytes either way, though under (A)
the same `T` buys fewer bytes. *Grade:* **hard** — exceeding it makes honest
witness misses systematic, and `L`'s own ruling forbids absorbing that by
raising `L` ("the answer is **not** raise `L`"). *Falsifier:* the **W₂ /
PD-F-2 fetch-latency dispersion measurement**, already owed as `L`'s falsifier
(`config/consensus_constants.json:33`) — it is this round's falsifier too, and
it is the measurement that converts `U1a` from a floor-based estimate into a
bound.

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

**Under (A) and under (B) alike**, the only hard bound with a number is `U1a`:
`T ≲ 430–1,300` at the heavy end, `≲ 860–2,600` at the mean, resting on a
throughput *floor from a null result*. Every lower bound is soft and sits below
200 (`L1` in the low hundreds on sim-sourced parameters; `L2`/`L3` pull upward
without a floor). `U1b` has no value. So:

> **`T = 200` is inside the feasible interval, and the interval's only
> quantified edge is 2–13× away from it.** The number is defensible; what it is
> not, today, is *derived*.

That is the honest state, and it is why "200 is fine" must not be the round's
conclusion: the interval is wide because two of its edges are unmeasured, not
because the constraints are slack.

**Proposed selection rule** (steering's to accept, amend or reject). Replace
"as big as the old leaf segment" with the obligation itself:

> Pick `T` so that **one whole-shard possession read completes in a single
> attempt, at the stated transport floor, inside `SF-D6`'s single-attempt share
> of `L`'s fetch span, at the heavy end of composition, with a stated margin.**
> `T = ⌊ (span_share × throughput_floor × margin) / bytes_per_tx_heavy ⌋`.

Why this rule and not another: it is the **only** constraint that is hard, that
has a source, and that both domains share; it names `L` as the coupling rather
than hiding it; and every quantity in it is either already ratified
(`L`, `SF-D6`'s budget, 16.7 KB/tx) or is the measurement already owed
(throughput). Its margin is a judgement, stated as one, exactly as `L = 4`
states its own.

**Pre-registered falsifiers on any `T` this round selects.**
1. The W₂ / PD-F-2 dispersion measurement lands such that the single-attempt
   span at the selected `T` exceeds its share of `L` — `U1a` violated.
2. A sustained serve-throughput figure on the floor device at which `U1b` binds
   below the selected `T`.
3. A measured `CV_tx` whose `L1` bound exceeds the selected `T`.
4. An honest single-persona archiver reaching `MAX_HOLDINGS_SHARDS` inside the
   mining era at the selected `T`.
5. A second home for `T` appears, or a shard boundary is derived from anything
   but `cumulative_tx_count` and `T` — inherited from the landed row
   (`rust/shekyl-types/src/archival.rs:88-101`).

---

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
- **`T` ↔ `SEB`** only through `U3`, and only under domain (B).
- No coupling to `D_max`: `T` appears in no reorg-depth argument.

---

## 6. Findings

| id | finding | grade |
|---|---|---|
| **`SHT-1`** | `T = 200` is 3.33 MB ÷ 16.7 KB/tx, and 3.33 MB is the **retired leaf segment's** size (`SEGMENT_LEAF_COUNT × ~128 B`). `T`'s justification is inheritance from a retired geometry. 16.7 KB/tx is **not** circular — it is a component estimate predating `T` by ten days. | CONFIRMED — the round's subject |
| **`SHT-2`** | The JSON comment's *"typical shard at ~16.7 KB/tx lands near 3.33 MB"* holds only under the **non-coinbase ordinal**. Under the landed storage-id domain, 3.33 MB is the *saturation* case; at 1 listed tx/block a shard holds ~1.7 MB. The sizing rationale presumes the answer to `SHT-Q1`. | CONFIRMED |
| **`SHT-3`** | `SF-D7` still states *"`N` is also `N × SHARD_BYTES` on the Pi 4 floor (the client materialises the segment to verify `R_k`)"* ([`ARCHIVAL_SHARD_FETCH.md`](ARCHIVAL_SHARD_FETCH.md):183). Item 5 retired the whole-shard materialise and refuted F32's reason 2 on that ground. Stale premise on a RULED row, and it is the text a future reader would use to derive a memory bound on `T`. | STALE TEXT on a RULED row — owner `SF-` |
| **`SHT-4`** | `U1`'s binding coupling is to `L`, **not** to `CHALLENGE_RESPONSE_BLOCKS`. The response deadline gives ~300× slack (10.8 GB budget vs 3.34 MB); the memory leg is retired. Recorded because the expectation going in was the opposite, and the arithmetic is what makes the conclusion checkable rather than merely asserted. | CONFIRMED — inverts the round's prior |
| **`SHT-5`** | `U1b` — an honest server's sustained egress on the rule-76 floor device — **has no authority anywhere in the tree**. The only transport figure (180 KB/s) is requester-side and a burst floor from a null result. This is the one bound that cannot be closed by reasoning. | OPEN — FOLLOWUPS row, measurement owed |
| **`SHT-6`** | `rust/shekyl-economics-sim/src/burden.rs:33-39`'s `SHARD_BYTES` comment derives 3.33 MB from `SEGMENT_LEAF_COUNT × ~128 B` — the retired **leaf-segment** estimate — while presenting it as the "§2 corpus figure". Corrected in this PR (the only code this round touches). | FIXED here |

---

## 7. Out of scope — recorded and moved past

Each is a FOLLOWUPS row, not work for this round:

- The `PDM-Q-F34` coverage row and its sim arms: the heavy-era-ages-into-deep
  arm (expressible since `be785f8e6`'s size-at-birth), the `storage_unit_cost`
  sweep that would separate the cost signal from the capacity leg, and the
  per-band gate read (max over pre-registered age × cost bands, aggregate
  reported but not graded).
- The segment-geometry deletion (E3 / E4).
- Any change to channel 1.
- Composition "attacks" — A4/W9 CLEARED, §12.11.
- `SHT-5`'s measurement, and `SHT-3`'s stale-text correction in the `SF-` doc.
