# Pruned-daemon mode — set-B discard (PDM)

**Status: OPEN** — round opened 2026-09-12. `PDM-Q1`…`PDM-Q6` and
`PDM-Q8` are **OPEN**. `PDM-Q3` is restated (today not node-local,
`PDM-Q-F8`). `PDM-Q7` is **PARTIAL** (opt-in flag rejected). `PDM-Q-S0`
is RULED. This is the design home TJ-D named; it is not yet the
design.

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
challenge/response format, or bond/slash construction. It does not
delete the C++ stripe engine (that waits on this design, then `DRS-E*`).
It does not write `db_lmdb.cpp`, and it does not fix `PDM-Q-F9`'s silent
zero-fill (dedicated C++ PR; `docs/FOLLOWUPS.md`).

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

**Launch sequencing.** Genesis does not precede this design's
implementation; steering, 2026-09-12. `DRS-E*` is therefore on the
critical path to launch, because the first implementation waits on it.
That may already have been true; it was not written in the documents a
reader walks, and a launch-state fork — genesis shipping while the C++
daemon still retains everything — was inferred from trajectory to fill
the gap. There is no such window to design a policy for.

This is not a claim that the pruning *mode* needs a coordinated
activation. TJ's node-local sentence is about activation not needing a
hard fork; `PDM-Q-F8` has already shown leaf discard is not node-local
*today*. The remaining `PDM-Q3` question is the residual consensus-read
set after TJ-A. It is a claim that V3 does not ship a daemon that still
cannot discard set B.

**Reopening criteria.** Two, independently:

1. Steering names a C++ landing window *before* `DRS-E*`, in writing,
   with a reviewer-map of the C++ surface.
2. Steering names, in writing, a genesis window that precedes this
   design's implementation.

"The rewrite slipped" is not a criterion for either. Trajectory inference
is how the dissolved launch-state fork was minted; it is not a
criterion.

**Re-evaluation shape.** An amendment to this section, in this file, citing
the steering note. Not a silent C++ PR. Not an allow-comment in
`db_lmdb.cpp`. Not a silent genesis that ships the C++ daemon.

This constraint is **not** a ruling on `PDM-Q3`'s residual-set question
and **not** a ruling that retracts TJ's activation sentence. `PDM-Q-S0`
answers *which codebase the first implementation may touch* and *that
genesis does not precede that implementation*. `PDM-Q-F8` has already
answered that the shape is not node-local *today*.

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
| Intermediate-layer prune | `BlockchainDB` caller `src/blockchain_db/blockchain_db.cpp:651-655`: every node, unconditionally (not gated on `--prune-blockchain`), every `FCMP_CURVE_TREE_CHECKPOINT_INTERVAL` (10,000, `src/cryptonote_config.h:313`) blocks. Definition `prune_curve_tree_intermediate_layers` at `src/blockchain_db/lmdb/db_lmdb.cpp:9917`; loop `for (uint8_t layer = 1; layer <= depth - 2; …)` at `:9974` | sealed upper-layer chunks. Layer 0 and the root layer are never pruned. The comment at `:9922-9925` that these hashes "can be recomputed from leaves" is **false** (`PDM-Q-F7`); `trim_curve_tree` recomposes from layer 0 |

---

## 2. Numbered questions

Each ruling, when written, takes rule-21 shape: the rejection (or the
positive choice), substrate-anchored reopening criteria, and the
re-evaluation shape. None of that is filled in here.

### `PDM-Q1` OPEN — The retained set

Do **not** start from a blank enumeration. `PDM-Q-F7` already places
the set-A / set-B split on exactly one table with one deletion site:

- **Set A, already retained by every node:** layer 0 of
  `m_curve_tree_layers` (`R_k` at chunk granularity). Never deleted
  except by reorg trim. The intermediate-layer prune loop starts at
  `layer = 1` (`db_lmdb.cpp:9974`); the root layer is also unpruned.
- **Set B, the discard subject:** `m_curve_tree_leaves`. Deleted today
  only by `trim_curve_tree` (reorg). That is the only table Q1's
  discard ruling has to name, plus whatever else the ruling *adds*
  (headers, consensus tables, a leaf window if Q2 keeps one).

Enumerate the rest against that boundary, not as prose: headers, which
intermediate layers *beyond* layer 0, which leaf window if any, which
consensus tables. Every later question is measured against this set.

The stale "recomputed from leaves" comments
(`db_lmdb.cpp:9922-9925`, `:9970`; `blockchain_db.h:2838`) are
corrected in the PR that rules Q1, not left for the ruling pass to
trip over.

### `PDM-Q2` OPEN — Discard trigger and depth

Segment freeze is the natural candidate; read
[`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md)
before assuming it. How deep before collapse? The number sets set-B
scarcity and interacts with the challenge draw window and the redraw
floor. Name which closed rulings the depth choice touches.

The same number sets the **free-regime duration**. Even with PDM shipped
and running at height 1, no node can have discarded anything until the
first segment reaches discard depth. Scarcity does not exist at chain
start regardless of what ships when (`PDM-Q-S0` closed the
schedule-created reading of that window; what remains is structural).
A Q2 ruling that names a depth without stating that duration — in
heights, and as wall-clock at the pinned block-time constant — and
without saying what the archival market does during it (bonds,
challenges, whether the possession test is live) has not answered Q2.
The §3 free-riding bullet is discharged against this duration, not
against the rewrite calendar.

### `PDM-Q3` OPEN — Residual consensus reads after TJ-A

"Which shape does leaf discard take?" is the wrong question.
`PDM-Q-F8` answers the shape **at this pin**: not node-local.
`src/cryptonote_core/blockchain.cpp:5327` (serve-credit vin
verification) rejects the transaction with
`SHEKYL_DROP_VERDICT_INTERNAL_FAILURE` if
`get_curve_tree_leaf_chunk` fails. A node that discarded set B does not
fail open and does not fail unknown. Two honest nodes at the same
height, differing only in prune configuration, reach opposite validity
verdicts on identical bytes. That is the consensus event Q3 was
written to go looking for, and it exists now.

Node-locality is therefore **conditional on TJ-A's rewire landing
first**, and is false before it. §1.2 already declared that
dependency; F8 is the named line.

**The remaining question, still OPEN:** given TJ-A's rewire, is the
residual set of consensus reads that can reach discarded leaves
empty, and what instrument proves it stays empty? Citing TJ is not
answering that. A grep of `get_curve_tree_leaf_chunk` /
`get_curve_tree_leaf_by_tree_position` in `src/` at this pin shows one
production consensus caller (`blockchain.cpp:5327`) and two RPC
readers (`core_rpc_server.cpp:1577`, `:1670`). RPC is not consensus.
The instrument Q3 names has to fail if a new consensus caller appears.

Do **not** re-derive in ignorance of TJ's already-stated sequencing
resolution (index `TJ-A…TJ-G` row): *the pruning MODE is node-local and
ships post-genesis without coordination (rule 75)*. That sentence is
about the mode not needing a coordinated hard-fork to *activate*; it
is not a claim that genesis ships before PDM exists (`PDM-Q-S0`), and
it is not a claim that leaf discard is node-local *today* (`PDM-Q-F8`).

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

### `PDM-Q7` PARTIAL 2026-09-12 — Disposition of the Monero-era stripe engine

The three-way "keep, subsume, or delete `--prune-blockchain`" is
underscoped and, as of steering 2026-09-12, the wrong question.

**Ruled here, as sequencing not as the standard process itself:**

- The **manual / opt-in flag is rejected.** Pruned-daemon mode is a
  standard process across all daemons, not an operator switch. That
  is what makes `CR-D2`'s "every node prunes" premise true, or what
  withdraws it.
- The **C++ stripe engine is not deleted until this design is
  complete.** It may serve as reference for the Rust cutover. Removal
  of the Monero-era mechanism (`prune_worker`, `pruning_seed`,
  `CRYPTONOTE_PRUNING_*`) happens at `DRS-E*` (`PDM-Q-S0`), not as a
  C++ deletion in this round.

**Still OPEN:** the standard process (what every daemon retains and
discards) is Q1–Q6 and Q8. Q7 does not re-derive it. Read
[`ARCHIVAL_PASS_RECORD_CARRIER.md`](ARCHIVAL_PASS_RECORD_CARRIER.md)
`CR-D2` for the p2p-visible residue the stripe scheme currently
carries; that residue dies with the engine at the cutover, or it is
named as something the standard process must still speak.

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
- **Free-riding during the free regime.** The free regime is
  structural, not a rewrite-schedule artifact. Even with PDM shipped
  at height 1, an "archiver" needs no storage until the first segment
  reaches Q2's discard depth; scarcity does not exist at chain start
  regardless of what ships when. What stops a bond posted in the free
  regime from being honoured in the scarce one? The duration of that
  question is Q2's output. Q2 must state the duration and what the
  market does during it; this bullet is discharged against that
  duration, not against `DRS-E*`'s calendar.
- **Eclipse and fetch.** If a node must fetch to verify, an eclipsing
  adversary controls what it can verify. Compare against today, where it
  verifies locally. TJ-F's "no store handle" face is the intended
  dissolution for *new-block verify*; spend-path assembly is a different
  fetch.
- **Stripe/shard interaction.** The C++ stripe engine survives until
  this design is complete and is removed at `DRS-E*` (`PDM-Q7`).
  Until then the two partitions are unrelated. Enumerate what a node
  holding stripe *i* and having discarded set B can and cannot answer.
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
- **PDM-Q-F7.** The intermediate-layer prune already runs on every node
  (`blockchain_db.cpp:651-655`), unconditionally, every
  `FCMP_CURVE_TREE_CHECKPOINT_INTERVAL` (10,000) blocks. Its soundness
  comment (`db_lmdb.cpp:9922-9925`, restated `:9970` and
  `blockchain_db.h:2838`) names leaves as the recompute source. §1.5's
  table originally read that as an all-clear ("leaves are the recompute
  source, not the delete target"). That is backwards as a risk reading:
  being the recompute source for a live deletion is what would make the
  leaves load-bearing for something other than serve-credit. **The
  comment is wrong about its own source.** There is no function that
  rebuilds layers `1..depth-2` from leaves. The only upper-layer
  rebuild is inside `trim_curve_tree` (`db_lmdb.cpp:9412` onward), and
  it recomposes from **layer 0**, the leaf-chunk hash layer, not from
  leaves. The prune loop is `for (uint8_t layer = 1; layer <= depth - 2;
  …)` (`:9974`), so layer 0 and the root layer are never pruned. Layer 0
  therefore survives and is already the thing Q1 needs: `R_k` at
  chunk granularity, retained by every node, never deleted except by
  reorg trim. The set-A / set-B split falls on exactly one table
  (`m_curve_tree_leaves`) with one deletion site. Q1 starts from that
  boundary. The stale comments are corrected in the PR that rules Q1.
- **PDM-Q-F8.** Q3 is answerable at a named line today, and the answer
  is "not node-local until TJ-A lands." `blockchain.cpp:5327`:
  `get_curve_tree_leaf_chunk` failure rejects the transaction with
  `SHEKYL_DROP_VERDICT_INTERNAL_FAILURE`. Two honest nodes at one height,
  differing only in prune configuration, reach opposite validity
  verdicts on identical bytes. That is the consensus event. Q3 is
  restated as the residual-set question after TJ-A; "which shape" is
  not open.
- **PDM-Q-F8b.** `INTERNAL_FAILURE` is the wrong verdict class for a
  local capability gap. Under pruning, a node would be telling peers
  that a valid transaction is malformed. The drop is attributable to
  the receiver's configuration, not to the sender — an attributability
  violation of PWD-B7 (P2P-2 cluster B:
  [`SHEKYL_P2P_PROTOCOL.md`](SHEKYL_P2P_PROTOCOL.md) line 3699 — a
  rejection justifies a drop only when it is attributable to the
  sender). Own row because the consensus-event finding (F8) and the
  verdict-class finding are independently load-bearing. The line also
  fires today on registry/tree disagreement; TJ-A's rewire is what
  removes the prune-configuration case, not a verdict-enum patch on
  this charter.
- **PDM-Q-F9.** Silent zero-fill that is dead today and becomes the
  default path under pruning. `core_rpc_server.cpp:1668-1672`: a
  missing leaf is inserted as 128 zero bytes, no error. Its sibling
  reader at `:1577` returns `CORE_RPC_ERROR_CODE_INTERNAL_ERROR`. On an
  unpruned node the `else` is unreachable (harmless). The moment PDM
  ships it is the ordinary path, and the node hands a wallet a
  structurally wrong membership path with no error signal. Already
  reachable through registry/tree disagreement, which `:5327` treats
  as a real condition. Two readers of the same table with opposite
  failure semantics is a defect **independent of PDM**. Fix
  independently of this round (match `:1577`); not the Q1 comment-
  correction PR (different file, different property). Carrier:
  [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) (`PDM-Q-F9`). This charter does
  not carry the C++ edit.

### Retracted

- **PDM-Q-F6 RETRACTED 2026-09-12** as a launch-state fork. Was
  premised on genesis shipping ahead of `DRS-E*` (inferred from
  trajectory, not ruled). The (a)/(b)/(c) launch-policy window does
  not exist. Surviving remainder: (i) `PDM-Q-S0` records that genesis
  does not precede this design's implementation; (ii) the free regime
  is structural — its duration is Q2's discard depth, not a
  schedule artifact.

### Inference (not yet a ruling)

- The possession-test/liveness paraphrase is a plausible reading of the
  current challenge *deadline* machinery plus universal retention. It is
  not R2's claim.

### Undetermined (ruling pass)

- The retained set (starting from layer 0 / `m_curve_tree_leaves`,
  F7), the trigger (including the free-regime duration and what the
  market does during it), residual consensus reads after TJ-A (Q3),
  reconstruction, cold sync, tx-prunable subject-matter, stripe-engine
  residue at the cutover (Q7), fetch privacy.
- Negative-control status of any coverage number this round later quotes.
  Do not quote a coverage figure without an edit that makes the
  instrument go red. Q3's residual-set instrument is the named
  instance: it must go red if a new consensus caller of discarded
  leaves appears.

---

## 7. Disposition summary

| ID | Question | State |
| --- | --- | --- |
| `PDM-Q-S0` | Implementation site + genesis sequencing | **RULED 2026-09-12** — after `DRS-E*`; no C++; genesis does not precede this design's implementation |
| `PDM-Q1` | Retained set (starts from layer 0 / `m_curve_tree_leaves`) | OPEN |
| `PDM-Q2` | Trigger, depth, and free-regime duration | OPEN |
| `PDM-Q3` | Residual consensus reads after TJ-A | OPEN — today not node-local (`PDM-Q-F8`) |
| `PDM-Q4` | Reconstruction path | OPEN |
| `PDM-Q5` | Cold sync and bootstrap | OPEN |
| `PDM-Q6` | Tx-prunable as archival subject | OPEN |
| `PDM-Q7` | Stripe engine / `--prune-blockchain` | **PARTIAL 2026-09-12** — opt-in flag rejected; C++ stays until this design is complete; removal at `DRS-E*` |
| `PDM-Q8` | Privacy (density vs query) | OPEN |

When this round proposes a test, it will name the edit that makes that
test red. A red test that cannot be made red by a specific edit is not
a test (rule 50 / the opening prompt).

---

## 8. What the next pass owes

Steering review of this opening. `PDM-Q-F6`'s launch-state fork is
retracted; `PDM-Q-S0` carries the genesis-does-not-precede sentence.
`PDM-Q-F7`…`F9` are at-the-pin code findings. Then the ruling pass:
§§2–3 answered, each with rule-21 shape, evidence pinned at a declared
sha, adversarial items discharged or named as remaining,
D10/SO-D8/CR-D2/sole-occupant consequences stated rather than discovered.

Q1 starts from F7's boundary; the PR that rules Q1 corrects
`db_lmdb.cpp:9922-9925` / `:9970` / `blockchain_db.h:2838`. Q2's
ruling must state the free-regime duration and the market's behaviour
during it. Q3 is the residual-set question after TJ-A, with an
instrument that can go red. F9 is a C++ defect independent of PDM;
the carrier is the FOLLOWUPS row, not this charter.
