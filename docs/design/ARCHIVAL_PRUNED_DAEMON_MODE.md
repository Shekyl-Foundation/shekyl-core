# Pruned-daemon mode — set-B discard (PDM)

**Status: OPEN** — round opened 2026-09-12. `PDM-Q1`…`PDM-Q8` are **OPEN**.
No question is RULED in this file. This is the design home TJ-D named; it
is not yet the design.

**Grounded at** `dev@edb35dbb1467a55c1a1dd4033966fb9fe3413080` (2026-09-12,
`origin/dev` HEAD when the round opened; PR #720 / DRS-0 slice A).
Citations below were read at that sha. Do not inherit line numbers from the
opening prompt (written at `1c6238bf8`).

**Family:** `PDM-Q` — tokens `PDM-Q1`…`PDM-Q8` (questions), `PDM-Q-F*`
(findings), `PDM-Q-S0` (sequencing constraint). Registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 at birth (rule 94).
Family cell `**PDM-Q1…PDM-Q8**` parses to `PDM-Q`. Distinct from
`**PD-A…PD-F**` (parses `PD-A`, the reopen-(d) probe).

**Process:** [`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
— retention and the archival possession test are consensus-adjacent;
design closure precedes any cut. **No C++ and no implementation in this
round** (rule 20: new daemon logic belongs in Rust; steering forbids a
C++ landing regardless — see `PDM-Q-S0`).

**What this round is.** The design home for pruned-daemon mode: ordinary
nodes collapse deep curve-tree segments to `R_k` and discard the leaves;
archivers hold the leaves. Until that exists, R2's possession test cannot
discriminate.

**What this round is not.** It does not re-derive R2, segment freeze, the
challenge/response format, or bond/slash construction. It does not land
`--prune-blockchain` deletion. It does not write `db_lmdb.cpp`.

---

## 0. Sequencing constraint — RULED 2026-09-12 (steering)

### `PDM-Q-S0` — implementation waits on the daemon C++→Rust cutover

**The rejection.** Do not implement set-B discard (or any successor of
`--prune-blockchain`) in the inherited C++ daemon. The landing site is
the Rust daemon after the store/engine swap (`DRS-E*`,
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md); engine-swap **not started**
as of this pin, banner line 11).

**Why, under current substrate.** Steering, 2026-09-12: this design will
not be implemented until after the C++→Rust daemon cutover. Independently,
rule 20 already sends new daemon logic to Rust — a C++ `prune_worker`
extension would be debt the rewrite re-creates. DRS-D5's
decompose-in-C++-first rationale is already retired (2026-09-01
countermand).

**Reopening criteria.** Steering names a C++ landing window *before*
`DRS-E*`, in writing, with a reviewer-map of the C++ surface. "The rewrite
slipped" is not a criterion.

**Re-evaluation shape.** An amendment to this section, in this file, citing
the steering note. Not a silent C++ PR. Not an allow-comment in
`db_lmdb.cpp`.

This constraint is **not** a ruling on `PDM-Q3` (consensus-scheduled vs
per-node) and **not** a ruling on TJ's already-stated claim that the
pruning *mode* is node-local and ships without coordination. Those are
still this round's to confirm or correct. `PDM-Q-S0` answers only *which
codebase the first implementation may touch*.

---

## 1. Verified substrate at the pin

Four premises, read at source. Grade: **established by reading**, unless
marked otherwise.

### 1.1 The product is set-B scarcity — established

[`ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md`](ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md)
R2 (lines 75–79): ordinary nodes collapse deep segments to their sub-root
commitment `R_k` and discard the leaves; archivers hold the leaves so deep
spend-path assembly stays possible without universal retention.

Set A (wallet-minimum: `R_k` frontiers, owned-output chunks, active
frontier segment) is held by every syncing wallet and is **not**
archiver-challenge subject. Set B (deep segment leaves + shard auxiliary)
is the archiver good (same file, lines 96–100).

### 1.2 That product does not exist — established, and currently forced

Same R2, lines 80–83: pruned-daemon mode is unbuilt; every daemon today
retains every leaf forever. Restated as freeze-pipeline fact 5
([`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md)
lines 144–148): `m_curve_tree_leaves` is deleted only by `trim_curve_tree`
(reorg). Restated as the soundness premise of the `archival_shard_leaf`
deletion at that file's §6.2 (lines 408–411).

Load-bearing enrichment, not a paraphrase (sequencing doc lines 101–106):
this retention is **consensus-required**. Serve-credit vin verification
needs leaf scalars at arbitrary challenged indices. The current challenge
does not merely coexist with an unpruned world; it structurally forces one.
No daemon can prune while verification reads arbitrary local leaves.

TJ-F's liveness face (same file, lines 291–303) already names the
dissolution: the verify entry point takes the response (leaf-layer chunk
included) and `R_k` and nothing else — no store handle. That obligation
is on TJ-A's output. This round does not re-open it; it depends on it.

### 1.3 Foundation posture is unpruned — established as policy, not a flag

[`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md) Problem 2 (lines 73–76)
and lines 1310–1311: foundation-operated `--no-prune` archival.
[`REFRESH_DESIGN_LANDSCAPE.md`](REFRESH_DESIGN_LANDSCAPE.md) lines 303–304:
Foundation reference daemons discard nothing; cold-sync clients scan
against that source.

**Drift vs colloquial wording:** there is no `--no-prune` CLI flag in
`src/` at this pin. The live knob is `--prune-blockchain` at
`src/cryptonote_core/cryptonote_core.cpp:171-174`, default `false`.
Foundation posture = do not pass that flag.

### 1.4 The possession test cannot discriminate — established in R2's words

R2 lines 84–86: until pruning exists, "do you hold set B for shard `s`"
is a question every node answers for free — **the possession test cannot
discriminate**, and "proxy" is not a coherent category.

Two-legged necessity (lines 88–92): pruning without a real test pays
proxies who re-fetch from foundation `--no-prune` nodes; a real test
without pruning pays everyone for bytes they already have.

**Not established here:** the paraphrase that bond / challenge /
settlement / slash currently "measure liveness, not possession." R2 does
not say that. Neighbouring TJ-F text uses "liveness" for a different
subject (the verify entry point's type-level obligation). Treat the
liveness/possession split as **undetermined** until the challenge and
bond docs are read in the ruling pass.

### 1.5 Three mechanisms exist; none is set-B discard — established

| Mechanism | Live site at the pin | What it deletes |
| --- | --- | --- |
| Inherited stripe prune | `BlockchainLMDB::prune_worker` in `src/blockchain_db/lmdb/db_lmdb.cpp` (definition ~2320); deletes `m_txs_prunable` when `!has_unpruned_block` below the tip window. Flag `--prune-blockchain`, default false. Seed in `src/common/pruning.{h,cpp}`. P2P/RPC/`shekyl-levin` carry `pruning_seed`. Constants `CRYPTONOTE_PRUNING_LOG_STRIPES = 3`, `CRYPTONOTE_PRUNING_TIP_BLOCKS = 5500` in `src/cryptonote_config.h` (~343–344) | tx-prunable blobs by stripe + tip. Not curve-tree leaves |
| Archival retention prune | `process_archival_epoch_close_at_height` (~8385) calls `prune_archival_epochs_before` (~7704–7739). Comment at ~7710–7712: *Deliberately NOT reverted by any pop path* | serve-credit, settlement, r_market, sigma_work, budget, accrual, attestation-witness rows below `tip − W`. Bookkeeping, not leaves |
| Intermediate-layer prune | `prune_curve_tree_intermediate_layers` (~9917); loop `layer = 1..=depth-2` | sealed upper-layer chunks. Leaves are the recompute source, not the delete target |

---

## 2. Numbered questions — all OPEN

Each ruling, when written, takes rule-21 shape: the rejection (or the
positive choice), substrate-anchored reopening criteria, and the
re-evaluation shape. None of that is filled in here.

### `PDM-Q1` OPEN — The retained set

What does an ordinary node keep, exactly? Enumerate it as a set, not as
prose: headers, `R_k` sub-roots, which intermediate layers, which leaf
window, which consensus tables. Every later question is measured against
this set.

### `PDM-Q2` OPEN — Discard trigger and depth

Segment freeze is the natural candidate; read
[`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md)
before assuming it. How deep before collapse? The number sets set-B
scarcity and interacts with the challenge draw window and the redraw
floor. Name which closed rulings the depth choice touches.

### `PDM-Q3` OPEN — Determinism: consensus-scheduled or per-node?

The retention prune is identical everywhere. The stripe prune is
seed-dependent and per-node. Which shape does leaf discard take?

Do **not** re-derive in ignorance of TJ's already-stated sequencing
resolution (index `TJ-A…TJ-G` row): *the pruning MODE is node-local and
ships post-genesis without coordination (rule 75)*. `PDM-Q3`'s job is to
confirm whether set-B leaf discard can actually take that shape: if any
consensus-relevant read can reach discarded bytes, two honest nodes at
one height legitimately differ and that is a consensus event, not a
configuration difference. Citing TJ is not answering Q3.

### `PDM-Q4` OPEN — Reconstruction path

A node that discarded and now needs a leaf fetches from archivers. Price
it: latency, failure modes, archival outage, evidence gone by design
that the network will not supply. Distinguish *needs it to verify new
blocks* (must be synchronous and must not fail) from *needs it to
assemble a spend path* (can be asynchronous). TJ-F already requires
verify-new-blocks to run on responder-supplied material + `R_k`; do not
re-open that as if it were undecided.

### `PDM-Q5` OPEN — Cold sync and bootstrap

A new node must reach tip. Does it need leaves to do so, or can it build
from `R_k` commitments carried in the chain? Today's answer is that
cold-sync clients scan against foundation `--no-prune` nodes
([`REFRESH_DESIGN_LANDSCAPE.md`](REFRESH_DESIGN_LANDSCAPE.md)). That is a
centralisation dependency wearing a pruning costume. Also
[`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) on the untrusted-peer
path, and its remaining item (b) "store-backed / pruned-tree assembly
(F5, the prune-policy PR)".

### `PDM-Q6` OPEN — The transaction-prunable side

Curve-tree leaves have a designed home; tx-prunable blobs have only the
inherited stripe scheme. No document appears to ask whether they should
be archival subject matter. They already carry per-tx `prunable_hash`
commitments — structurally the same thing `R_k` is for a leaf segment.
Rule on whether they enter the archival subject. If they do not, say
why, with reopening criteria.

### `PDM-Q7` OPEN — Disposition of `--prune-blockchain`

Keep, subsume, or delete. Deletion is p2p-visible (peers advertise and
request by pruning seed) and is the mechanism the pass-record carrier
round's premise rests on. Read
[`ARCHIVAL_PASS_RECORD_CARRIER.md`](ARCHIVAL_PASS_RECORD_CARRIER.md)
`CR-D2`. Deleting the stripe scheme while set-B discard is unbuilt
removes the only pruning that exists. Sequence accordingly, and under
`PDM-Q-S0`.

### `PDM-Q8` OPEN — Privacy

Two directions, both load-bearing under `00-mission`. Pruning lowers the
cost of running a node, which raises node density. Fetching a specific
shard on demand reveals interest in that shard — a discard-then-fetch
design leaks a query pattern that universal retention does not. Wargame
the fetch side: who observes the request, what it discloses, and whether
cover traffic, batching, or oblivious retrieval is required. Do not let
the density argument absorb the query-privacy argument.

---

## 3. Adversarial work required before any `PDM-Q*` ruling is recorded

Named so they cannot be discovered after a ruling. Not answered here.

- **Withholding.** An archiver that holds leaves but refuses selected
  requests. What distinguishes that from an offline archiver, and does
  the challenge mechanism see the difference?
- **Free-riding during the transition.** While every node still retains
  everything, an "archiver" needs no storage. Is there a cutover where
  bonds start collateralising something real, and what stops a bond
  posted in the free regime from being honoured in the scarce one?
  `PDM-Q-S0` makes this window longer, not shorter: design can close
  while the C++ daemon still retains every leaf.
- **Eclipse and fetch.** If a node must fetch to verify, an eclipsing
  adversary controls what it can verify. Compare against today, where it
  verifies locally. TJ-F's "no store handle" face is the intended
  dissolution for *new-block verify*; spend-path assembly is a different
  fetch.
- **Stripe/shard interaction.** If `--prune-blockchain` survives
  alongside set-B discard, the two partitions are unrelated. Enumerate
  what a node holding stripe *i* and having discarded set B can and
  cannot answer.
- **Sybil economics.** Does the market price scarcity in a way that
  survives an adversary who runs many cheap archivers holding overlapping
  popular shards? Build on
  [`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`](ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md)
  `r ≫ 1000`; do not re-derive.
- **Reorg.** Discarded-then-reorged. The retention prune is un-journaled.
  State revert behaviour explicitly.
  [`CONSENSUS_C2_R1_REORG.md`](../completed/CONSENSUS_C2_R1_REORG.md) is
  the precedent for how that gets argued.

---

## 4. Do not re-derive

Read, cite, build on. A disagreement is a finding, not a premise.

- Genesis-frozen decisions in `principles-and-learnings` and the
  consensus census.
- The retention prune's consensus scheduling and un-journaled deletions
  ([`CONSENSUS_C2_R1_REORG.md`](../completed/CONSENSUS_C2_R1_REORG.md)).
- Segment freeze semantics
  ([`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md)),
  including the §6.2 reversion clause this round is named to discharge
  or refine.
- Challenge / response format and deadline structure
  ([`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md),
  [`ARCHIVAL_RESPONSE_FORMAT.md`](ARCHIVAL_RESPONSE_FORMAT.md)).
- Bond construction and slashing
  ([`ARCHIVAL_BOND_CONSTRUCTION.md`](ARCHIVAL_BOND_CONSTRUCTION.md),
  [`PRINCIPAL_STAKE_LIFECYCLE.md`](PRINCIPAL_STAKE_LIFECYCLE.md)).
- R2 itself, including two-legged necessity.
- TJ-F's two faces (soundness test vs type-level "response + `R_k`, no
  store handle").
- TJ's sequencing claim that the pruning *mode* is node-local (Q3
  confirms; it does not get to pretend the claim was never made).

---

## 5. Downstream that will be disturbed

Named now so they are not discovered later.

- **`SO-D8`** — settlement writer's production wiring, still OPEN,
  assigned out of [`ARCHIVAL_SETTLEMENT_WRITER.md`](ARCHIVAL_SETTLEMENT_WRITER.md)
  to the credit-wire §5 cutover. Scope addition 2026-09-12
  (`ba4b3c73a`): promote the settlement write path onto `BlockchainDB`.
- **`DRS-0` / `DRS-D10`** — redb store port. D10 still reads universally
  at [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) line 310: *All
  non-block-corpus tables must be rebuildable by replaying local blocks
  through `apply_block`*. §11.2 (lines 1088–1123, pinned at `ba4b3c73a`)
  already records that that wording does not hold, and names a
  **node-local by prune policy** group (`txs_prunable`,
  `txs_prunable_tip`, `output_metadata`). Slice A (PR #720, this pin)
  is the cross-check instrument. A pruning design that changes what a
  node retains changes what "rebuildable by replaying local blocks" can
  mean. D10's binding sentence is not this round's to edit; Q1's
  retained set is the input that round will need.
- **The credit wire** — [`ARCHIVAL_CREDIT_WIRE.md`](ARCHIVAL_CREDIT_WIRE.md)
  prunable-residence row: *Header kept; 3.43 KB countersignature on the
  coinbase-tx prunable side*. If `PDM-Q6` rules that side into the
  archival subject, `CR-D2` reopens and the carrier decision changes.
- **`tests/unit_tests/tx_prunable_region_sole_occupant.cpp`** — the
  prunable region has exactly one occupant; blob vs re-serialize hash
  paths agree only *positionally*. Read this test before proposing
  anything that adds to or reorders that region.
- **`CURVE_TREE_CLIENT.md` remaining (b)** — store-backed / pruned-tree
  assembly (F5). A PDM ruling that wallets assemble against `R_k` +
  fetched chunks is that item's substrate.
- **Pass-record carrier `CR-D2`** — ~88 GB/year is the ML-DSA-65-only
  *floor*, already corrected in-round to whole-record arithmetic; RF-D6
  refined the kept side. Do not quote 88 GB as the number. Q7's
  "every node prunes" premise is this round's to make true or to
  withdraw from under CR-D2.

---

## 6. Findings so far

### Established by reading (this opening)

- **PDM-Q-F1.** Set-B discard is specified and unbuilt. Universal leaf
  retention is presently consensus-required.
- **PDM-Q-F2.** `--no-prune` is documentation for "do not pass
  `--prune-blockchain`". There is no such flag.
- **PDM-Q-F3.** Three live prune paths; none discards curve-tree leaves.
- **PDM-Q-F4.** D10's universal reconstructibility wording is already
  known not to hold; the prune-policy group is named; the binding
  sentence is unamended.
- **PDM-Q-F5.** Implementation is forbidden in C++ (`PDM-Q-S0`).

### Inference (not yet a ruling)

- The possession-test/liveness paraphrase is a plausible reading of the
  current challenge *deadline* machinery plus universal retention. It is
  not R2's claim.

### Undetermined (ruling pass)

- The retained set, the trigger, determinism, reconstruction, cold sync,
  tx-prunable subject-matter, `--prune-blockchain` fate, fetch privacy.
- Whether any consensus-relevant read currently reaches
  `m_curve_tree_leaves` *other than* serve-credit vin verification
  (TJ-F's dissolution target). A second reader would be a second Q3
  blocker.
- Negative-control status of any coverage number this round later quotes.
  Do not quote a coverage figure without an edit that makes the
  instrument go red.

---

## 7. Disposition summary

| ID | Question | State |
| --- | --- | --- |
| `PDM-Q-S0` | Implementation site | **RULED 2026-09-12** — after `DRS-E*`; no C++ |
| `PDM-Q1` | Retained set | OPEN |
| `PDM-Q2` | Trigger and depth | OPEN |
| `PDM-Q3` | Consensus-scheduled vs per-node | OPEN |
| `PDM-Q4` | Reconstruction path | OPEN |
| `PDM-Q5` | Cold sync and bootstrap | OPEN |
| `PDM-Q6` | Tx-prunable as archival subject | OPEN |
| `PDM-Q7` | `--prune-blockchain` | OPEN |
| `PDM-Q8` | Privacy (density vs query) | OPEN |

When this round proposes a test, it will name the edit that makes that
test red. A red test that cannot be made red by a specific edit is not
a test (rule 50 / the opening prompt).

---

## 8. What the next pass owes

Steering review of this opening. Then the ruling pass: §§2–3 answered,
each with rule-21 shape, evidence pinned at a declared sha, adversarial
items discharged or named as remaining, D10/SO-D8/CR-D2/sole-occupant
consequences stated rather than discovered.
