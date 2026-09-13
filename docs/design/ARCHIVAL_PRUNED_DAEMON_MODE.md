# Pruned-daemon mode — set-B discard (PDM)

**Status: OPEN** — round opened 2026-09-12. `PDM-Q1`…`PDM-Q6`, `PDM-Q8`
and `PDM-Q10` are **OPEN**. `PDM-Q3` is restated (today not node-local,
`PDM-Q-F8`). `PDM-Q1` is widened and `PDM-Q6` promoted (`PDM-Q-F12`:
leaves are a cache of the block corpus; set-B scarcity as scoped does
not exist), then **`PDM-Q6` is the round's subject** (`PDM-Q-F13`: the
transaction's prunable region is scarce *and* replay-compatible, with
its verifier `txs_prunable_hash` already in the schema; `PDM-Q-F14`:
`pqc_auths`, ~60 % of tx bytes, is kept only for want of a hash row;
`PDM-Q-F15`: the `serve_credit_pruned` self-reference is benign). §9
inventories every data element at the pin. `PDM-Q7` is **PARTIAL**
(opt-in flag rejected, scoped to the universal set). `PDM-Q9` is
**PARTIAL** (shard retention is the bond process; binding and lapse
timing OPEN). `PDM-Q-S0` is RULED. This is the design home TJ-D named;
it is not yet the design.

**Grounded at** `dev@edb35dbb1467a55c1a1dd4033966fb9fe3413080` (2026-09-12,
`origin/dev` HEAD when the round opened; PR #720 / DRS-0 slice A).
Citations below were read at that sha. Do not inherit line numbers from the
opening prompt (written at `1c6238bf8`).

**Family:** `PDM-Q` — tokens `PDM-Q1`…`PDM-Q10` (questions), `PDM-Q-F*`
(findings), `PDM-Q-S0` (sequencing constraint). Registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 at birth (rule 94).
Family cell `**PDM-Q1…PDM-Q10**` parses to `PDM-Q`. Distinct from
`**PD-A…PD-F**` (parses `PD-A`, the reopen-(d) probe).

**Process:** [`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
— retention and the archival possession test are consensus-adjacent;
design closure precedes any cut. **No C++ and no implementation in this
round** (rule 20: new daemon logic belongs in Rust; steering forbids a
C++ landing regardless — see `PDM-Q-S0`).

**What this round is.** The design home for pruned-daemon mode: ordinary
nodes collapse deep curve-tree segments to `R_k` and discard the leaves;
archivers hold the leaves. Until that exists, R2's possession test cannot
discriminate. **As opened.** `PDM-Q-F12`/`F13` move the good: leaves are
a cache; what ordinary nodes discard and archivers hold is the
transaction's prunable region (and, pending Q6 item 2, its `pqc_auths`).
The sentence above is R2's framing and is kept so the drift is visible.

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

### 1.1 The product is set-B scarcity — established as R2's claim; challenged by `PDM-Q-F12`

[`ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md`](ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md)
R2 (lines 75–79): ordinary nodes collapse deep segments to their sub-root
commitment `R_k` and discard the leaves; archivers hold the leaves so deep
spend-path assembly stays possible without universal retention.

Set A (wallet-minimum: `R_k` frontiers, owned-output chunks, active
frontier segment) is held by every syncing wallet and is **not**
archiver-challenge subject. Set B (deep segment leaves + shard auxiliary)
is the archiver good (same file, lines 96–100).

**What is established is that R2 says this.** Whether discarding
`m_curve_tree_leaves` produces scarcity is a different claim, and
`PDM-Q-F12` shows it does not: every leaf scalar is a pure function of
bytes the discarding node keeps. The product is still set-B scarcity;
what set B has to *be* for that to hold is `PDM-Q6`'s question, and
`PDM-Q-F13` names the candidate: the transaction's **prunable region**
(`CtSigPrunable`, `src/fcmp/ct_types.h:333`) — original bytes nothing
derives and nothing derives from, admission-verified, hash-committed
per tx in `txs_prunable_hash`. §9 inventories every data element at
the pin against that test.

### 1.2 That product does not exist — established, and currently forced

Same R2, lines 80–83: pruned-daemon mode is unbuilt; every daemon today
retains every leaf forever. Restated as freeze-pipeline fact 5
([`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md)
lines 144–148): `m_curve_tree_leaves` is deleted only by `trim_curve_tree`
(reorg; two deletion loops in that one function, `db_lmdb.cpp:9278`
trim-to-empty and `:9392`). Restated as the soundness premise of the
`archival_shard_leaf` deletion at that file's §6.2 (lines 408–411).

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

### `PDM-Q1` OPEN — The retained set (widened 2026-09-13, `PDM-Q-F12`; downstream of Q6 per `PDM-Q-F13`)

**Q1 is answered after Q6, not beside it.** `PDM-Q-F13` puts the
scarce good in the transaction's prunable region; the retained set is
then *everything else*, and Q1's job is the enumeration in §9 made
into a ruling — which derived tables a pruned node keeps as caches,
which it drops and recomputes, and which node-local journals it
retires on a window. Do **not** start from a blank enumeration.
`PDM-Q-F7` places the set-A boundary on layer 0, and `PDM-Q-F12` shows
the set-B boundary cannot stop at the leaf table:

- **Set A, already retained by every node:** layer 0 of
  `m_curve_tree_layers` (`R_k` at chunk granularity). Never deleted
  except by reorg trim. The intermediate-layer prune loop starts at
  `layer = 1` (`db_lmdb.cpp:9974`); the root layer is also unpruned.
- **Set B, the discard subject — not one table.** `m_curve_tree_leaves`
  is where the leaf bytes live, but every leaf is a pure function of
  bytes the node keeps (`PDM-Q-F12`): `O` and `C` from `output_metadata`
  (or the tx corpus), `I = hash_to_p3(O)`, and `h_pqc` from `tx_extra`
  field `0x07` in the transaction blob. Discarding the leaf table alone
  discards a cache. Q1 must therefore rule on **each derivation input**:
  `output_metadata` (D10 §11.2 already names it node-local by prune
  policy; slice A grades it `Excluded`, `class.rs:149`), `leaf_to_output`
  / `output_to_leaf` (set-shaped, `class.rs:147,150`), and the
  transaction corpus itself — which is `PDM-Q6`'s subject. Whatever Q1
  leaves retained, set B is what is *not* recomputable from it.

Enumerate the rest against that boundary, not as prose: headers, which
intermediate layers *beyond* layer 0, which leaf window if any, which
consensus tables. Every later question is measured against this set.
A Q1 ruling that names `m_curve_tree_leaves` and stops has not
produced scarcity and has not answered Q1. Two items §9 surfaced are
now settled at the pin (review, 2026-09-13): `scan_outputkeys_for_indexes`
is rule-60 residue with no live caller, so `output_metadata` has no
post-admission consensus reader and is a cache like the leaves
(`PDM-Q-F18`); and the archival journals' horizon is not Q1's to pick
freely — the slash log's forward reader is bounded by the serve-credit
deadline on one path and by the slash-scheduler watermark plus the
failure window on the other, neither enforced on `at_height` itself,
so the horizon Q1 mints is
`tip − (CHALLENGE_RESOLUTION_BLOCKS + n·SETTLEMENT_EPOCH_BLOCKS + reorg)`
**and** lands with the check that makes it enforced (`PDM-Q-F19`).

The stale "recomputed from leaves" comments
(`db_lmdb.cpp:9922-9925`, `:9970`; `blockchain_db.h:2838`) are
corrected in the PR that rules Q1, not left for the ruling pass to
trip over. The slice A class assignments for the three curve-tree
tables (`PDM-Q-F11`) are re-graded against Q1's output by the DRS-0
lane, not here.

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

### `PDM-Q6` OPEN — The prunable region as the archival good: the round's subject (promoted 2026-09-13 `PDM-Q-F12`; made the subject 2026-09-13 `PDM-Q-F13`)

Curve-tree leaves have a designed home; tx-prunable blobs have only the
inherited stripe scheme. No document before this one asks whether they
should be archival subject matter. They already carry per-tx
`prunable_hash` commitments — structurally the same thing `R_k` is for
a leaf segment. Rule on whether they enter the archival subject. If
they do not, say why, with reopening criteria.

**Promoted (F12), then made the subject (F13).** `PDM-Q-F12` showed
that the leaf is regenerated on replay from the transaction
(`blockchain_db.cpp:598-617`), so nothing in the derived tables is
scarce. `PDM-Q-F13` then ran F12's own test against the transaction's
two halves and found the third category F12's author said could not
exist: the **prunable region** (`CtSigPrunable`,
`src/fcmp/ct_types.h:333` — `bulletproofs_plus` `:349`,
`fcmp_pp_proof` `:367`, `pseudoOuts` `:384`, `serve_credit_pruned`
`:402`) is original, non-derivable, admission-only, **and** every byte
replay needs to rebuild the derived tables lives in the *other* half
(`output_key` from `vout`, `commitment` from `outPk`, `h_pqc` from
`tx_extra` `0x07` — all in `CtSigBase` / the prefix). Discarding the
prunable region is therefore compatible with D10's replay premise
*and* produces a good an archiver can be scarce in. Its verifier is
already in the schema: `txs_prunable_hash`, 32 B per tx, written at
`db_lmdb.cpp:1166-1167` and kept by the V11 retention rule
(`db_lmdb.cpp:128-136`). Q6's ruling is the ruling on whether PDM has
a product, and it is written **before** Q1.

What Q6 must rule, in this order:

1. **The good.** Is the archival subject the prunable region of the
   transaction corpus below Q2's depth? If yes, the unit of possession
   is a transaction's `CtSigPrunable` bytes and the unit of
   verification is its `txs_prunable_hash`. If no, name what else is
   scarce — §9 finds nothing.
2. **The second occupant — `pqc_auths` (`PDM-Q-F14`).** The PQC
   authorizations are ~60 % of a typical transaction's bytes
   (`FCMP_PLUS_PLUS.md` §13: ~10.6 KB of ~17–18 KB for 2-in/2-out),
   are read by consensus only at admission (every reader is inside
   `check_tx_inputs`, `blockchain.cpp:3717-4351`), enter the txid only
   through a 32-byte `pqc_auth_hash`
   (`cryptonote_format_utils.cpp:1306-1318`), and are kept by V11
   solely because *"neither has a hash table of its own"*
   (`db_lmdb.cpp:131`). A 32-byte `txs_pqc_auth_hash` row per tx would
   make the slice archival subject on the same terms as the prunable
   body. Q6 rules whether it does — storage semantics only; the tx
   blob and txid are untouched — or names why the largest element in
   the transaction stays universally retained. Spot-checked
   2026-09-13: the `db_lmdb.cpp` access sites (`:1071-1214`,
   `:3330-3383`, table open `:1664`) are store plumbing, consistent
   with all consensus reads sitting in `check_tx_inputs`; the txid
   already commits to `pqc_auth_hash`, so a hash-table row changes no
   wire byte. **Items 1 and 2 are ruled together, not sequentially:**
   the storage case for either alone is weak (~35 % or ~60 % of the
   transaction) and strong jointly (~95 %), and a Q6 that admits the
   prunable region while keeping `pqc_auths` universally retained has
   the smaller slice in the good and the larger one out.
3. **The unit change downstream (§5).** Every closed archival ruling
   defines the good as **leaves**: `SHARD_BYTES = 25,992 × 128`
   (`ARCHIVAL_RESPONSE_FORMAT.md` `RF-D6`), `challenge_leaf_index`,
   the 128-byte `leaf_bytes` claim in the kept vin (`RF-D1`),
   `LeafStore::frozen_segment`, the freeze pipeline's segment. If the
   good is the prunable region, the shard is a set of transactions
   (by block range, most naturally), the challenge names a transaction
   and the response is its `CtSigPrunable` bytes verified against the
   retained `txs_prunable_hash`. Q6 states which closed rulings that
   reopens and which survive with the unit substituted. It does not
   quietly keep leaf-shaped challenges over a good that is not leaves.
   The candidate shard definition is on the table already: the
   inherited stripe arithmetic partitions block heights over
   `txs_prunable` — F13's good — with a `u32` holdings encoding, a
   third-party `has_unpruned_block` function and coordinator-free
   coverage (`PDM-Q-F17`). Q6 adopts it, adapts it (stripe count,
   stripe size, tip window are Monero's numbers), or names why the
   shard is shaped otherwise.
4. **Self-reference — discharged (`PDM-Q-F15`).** `serve_credit_pruned`
   is the archival system's own evidence inside the good it sells. At
   the pin it is read exactly once after parse — `blockchain.cpp:3807`,
   inside `check_tx_inputs` — and by nothing else in `src/` except the
   (de)serializers (`json_object.cpp`,
   `cryptonote_boost_serialization.h`; `rg serve_credit_pruned src`).
   Settlement, challenge verification and
   slashing read the kept vin (`RF-D1`'s ~230 B) and the archival
   tables populated from it at add time; the retention prune already
   retires those rows at `tip − W` without touching the pruned half.
   Benign, under one condition Q2 already owes: discard depth ≥ the
   reorg depth that can re-drive `check_tx_inputs` on the block.
5. **Depth floor from admission-only reads.** Everything in the good
   is re-read on a reorg re-verify and on nothing else. The inherited
   engine's `CRYPTONOTE_PRUNING_TIP_BLOCKS = 5500` is the Monero-era
   answer to this; Q2 gives Shekyl's, and F10's trim floor and this
   one are the same number or Q2 says which is larger.

Note the two readings of "prunable": the inherited `txs_prunable`
region is the `CtSigPrunable` sole occupant (§5 test); the outputs and
`tx_extra` that regenerate leaves sit in the *pruned* half
(`txs_pruned`, append-mostly) and stay. Q6 says which half every
sentence is about.

### `PDM-Q7` PARTIAL 2026-09-12 — Disposition of the Monero-era stripe engine

The three-way "keep, subsume, or delete `--prune-blockchain`" is
underscoped and, as of steering 2026-09-12, the wrong question.

**Ruled here, as sequencing not as the standard process itself:**

- The **manual / opt-in flag is rejected.** Pruned-daemon mode is a
  standard process across all daemons, not an operator switch. That
  is what makes `CR-D2`'s "every node prunes" premise true, or what
  withdraws it. **Scope (2026-09-13):** this rejection covers the
  *universal* retention set — what every daemon holds and discards.
  It does not cover the archiver's *supplementary* set (shard `s`),
  which is necessarily configured from somewhere; that source is
  `PDM-Q9`, and the answer there is the bond, not a daemon flag. An
  implementer reading this bullet as "no retention configuration of
  any kind" would produce an unbuildable archiver.
- The **C++ stripe engine is not deleted until this design is
  complete.** It may serve as reference for the Rust cutover. Removal
  of the Monero-era mechanism (`prune_worker`, `pruning_seed`,
  `CRYPTONOTE_PRUNING_*`) happens at `DRS-E*` (`PDM-Q-S0`), not as a
  C++ deletion in this round. **What "reference" means (2026-09-13,
  `PDM-Q-F17`):** not the prune worker — the seed arithmetic
  (`src/common/pruning.h`), the wire advertisement (`CORE_SYNC_DATA`,
  peerlist) and the complement-seeking peer selection. Those are read
  from; the deletion pass is what remains.

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

### `PDM-Q9` PARTIAL 2026-09-13 — The archiver's retention set: source, binding, lapse

After Q7 there are **two retention regimes**, and Q7 ruled only one:

1. The universal set — every daemon, consensus, no operator switch
   (Q1–Q6, Q7's rejection).
2. The archiver's supplementary set — shard `s`, held in addition.

**Ruled (steering, 2026-09-13): shard retention is the bond process.**
The bond already carries the shard set on-chain: `holdings` is
`ShardSetCompact{ids}` or `CompleteTree`
([`ARCHIVAL_BOND_CONSTRUCTION.md`](ARCHIVAL_BOND_CONSTRUCTION.md) line
349), stored in `archival_bond` (consensus-folded, set-shaped,
`class.rs:114`), changed by `HoldingsUpdate`, ended by `Release`. The
daemon's supplementary retention set is **read from the chain**, not
configured on the daemon. There is no second place where "which shards"
is spelled, and no daemon flag is minted for it.

**Still OPEN, in rule-21 shape when ruled:**

- **Binding.** The daemon must know which bond(s) it serves for. That
  is a public identifier (the bond's persona key), not a secret, and
  it lives on the serving host's side of the Model D boundary. Name
  where it lives and how it is set; say explicitly that no seed
  material crosses to make it work
  ([`16-architectural-inheritance`](../../.cursor/rules/16-architectural-inheritance.mdc)
  §"comment that outlived its architecture" is the precedent for
  getting this wrong).
- **Lapse timing.** Retention must outlast the bond. An archiver whose
  `Release` (or a `HoldingsUpdate` dropping shard `s`) lands at height
  `h` can still be challenged on `s` for the challenge window and
  settled for the settlement lag after `h`. If the daemon discards at
  `h`, a correct exit is slashed. State the retention tail as a
  function of the pinned constants in `shekyl-archival-retention`
  (`CHALLENGE_RESOLUTION_BLOCKS`, `SETTLEMENT_EPOCH_BLOCKS`,
  `ARCHIVAL_REORG_DEPTH_BLOCKS` = 720), and name the test that goes
  red if the tail is shorter than the window.
- **Interaction with the universal set.** Where the archiver's shard
  `s` overlaps the universal window (Q2's not-yet-discarded frontier),
  the supplementary set is empty by construction; the ruling should
  say so rather than have two mechanisms both believe they own the
  same bytes.
- **Advertisement (added 2026-09-13, `PDM-Q-F17`).** The chain is the
  source; the wire still needs to say it, because a fetching peer
  selects archivers before it has read their bonds. The inherited
  `pruning_seed` slot in `CORE_SYNC_DATA` / peerlist is the shape: a
  compact holdings encoding a third party can expand
  (`has_unpruned_block`'s role) and **check against the bond**. Rule
  whether `holdings` (`ShardSetCompact{ids}` / `CompleteTree`) is that
  encoding or is compressed to one, and state that a wire claim that
  disagrees with the chain is a drop reason attributable to the sender
  (`PWD-B7`), which the C++ engine's range-check-only validation
  (`net_node.inl:2315`) is not.

### `PDM-Q10` OPEN — The RPC contract for "not retained"

Two RPC readers of the leaf table exist (`core_rpc_server.cpp:1577`,
`:1670`). `PDM-Q-F9`'s fix for the second is "match `:1577`", and
`:1577` returns `CORE_RPC_ERROR_CODE_INTERNAL_ERROR`. Right today; under
PDM both readers then report a leaf the node has *legitimately*
discarded as an internal failure — the wallet-facing twin of
`PDM-Q-F8b`. Rule on a response that distinguishes *not retained here;
fetch from an archiver* (and, once Q9 is ruled, *which* one) from *the
store is broken*. The membership-path assembly client
([`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) remaining item (b)) is
the consumer; the shard-fetch client round (`SF-`, PR #714) is where the
fetch leg's transport is being designed and is the place this response
has to be legible.

**The privacy argument does not cut against this.**
[`RPC_TRANSPORT_POSTURE.md`](RPC_TRANSPORT_POSTURE.md) lines 22–27: every
RPC leg is operator-to-operator, both endpoints machines the same person
controls, the adversary is the network path and never the peer. `:1577`
and `:1670` are that leg. A daemon telling its own operator's wallet "I
do not hold shard `s`" discloses nothing the operator did not configure.
Q8's query-privacy concern lives on the *fetch* leg to a third-party
archiver, not here.

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
  ~~Until then the two partitions are unrelated.~~ **Refuted under
  F13 (`PDM-Q-F17`):** the stripe partitions block heights over
  `txs_prunable`, which is the good; the two partitions are unrelated
  only while the good is leaves. The bullet's remaining work is the
  inverse of the original: enumerate what an archiver whose shard is
  a stripe of the prunable region can and cannot answer to a leaf-
  shaped challenge, and what the `u32` seed does and does not commit
  it to.
- **Sybil economics.** Does the market price scarcity in a way that
  survives an adversary who runs many cheap archivers holding overlapping
  popular shards? Build on
  [`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`](ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md)
  `r ≫ 1000`; do not re-derive.
- **Reorg.** Discarded-then-reorged. The retention prune is un-journaled.
  State revert behaviour explicitly.
  [`CONSENSUS_C2_R1_REORG.md`](../completed/CONSENSUS_C2_R1_REORG.md) is
  the precedent for how that gets argued. `PDM-Q-F10` names the line:
  `trim_curve_tree` reads the removed leaves' scalars for the
  boundary-chunk `hash_trim` (`db_lmdb.cpp:9361`) and throws `DB_ERROR`
  at `:9363` inside the write txn. A reorg into a discarded segment
  aborts mid-transaction. Both halves of the constraint are owed, not
  one: Q2's discard depth is bounded below by the maximum reorg depth,
  **and** trim gets a defined failure — because the bound is only as
  good as the constant enforcing it, and no consensus-side reorg cap
  exists at this pin (`ARCHIVAL_REORG_DEPTH_BLOCKS` = 720 is
  archival-domain, `shekyl-archival-retention`;
  `NetworkSafetyConstants.max_reorg_depth` is engine-side,
  `shekyl-engine-state/src/safety_constants.rs:61`).

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
- R2 itself, including two-legged necessity. `PDM-Q-F12` is a
  disagreement with R2's premise that leaf discard is scarcity — recorded
  as a finding, per this section's first sentence, not as a re-derivation.
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
  retained set is the input that round will need. Sharper than the
  wording issue: slice A's **class assignments** for the three
  curve-tree tables assume universal leaf retention (`PDM-Q-F11`) —
  `curve_tree_leaves` append-mostly, `curve_tree_layers` and
  `curve_tree_checkpoints` derived *from the leaves*. Those three rows
  are re-graded by the DRS-0 lane once Q1 rules; this charter names
  the dependency and does not edit `class.rs`.
- **The credit wire** — [`ARCHIVAL_CREDIT_WIRE.md`](ARCHIVAL_CREDIT_WIRE.md)
  prunable-residence row: *Header kept; 3.43 KB countersignature on the
  coinbase-tx prunable side*. If `PDM-Q6` rules that side into the
  archival subject, `CR-D2` reopens and the carrier decision changes.
- **`tests/unit_tests/tx_prunable_region_sole_occupant.cpp`** — the
  prunable region has exactly one occupant; blob vs re-serialize hash
  paths agree only *positionally*. Read this test before proposing
  anything that adds to or reorders that region.
- **Every leaf-shaped archival ruling** (`PDM-Q-F13` item 3 of Q6) —
  [`ARCHIVAL_RESPONSE_FORMAT.md`](ARCHIVAL_RESPONSE_FORMAT.md) `RF-D1`
  (the 128 B `leaf_bytes` claim) and `RF-D6` (`SHARD_BYTES = 25,992 ×
  128`, `challenge_leaf_index`, `LeafStore::frozen_segment`),
  [`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md)'s
  draw, [`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md)'s
  segment as the unit of holding, and the bond's `holdings` descriptor
  ([`ARCHIVAL_BOND_CONSTRUCTION.md`](ARCHIVAL_BOND_CONSTRUCTION.md) line
  349). All define possession over a good `PDM-Q-F12` shows is not
  scarce. If Q6 rules the prunable region in, the unit of possession
  becomes a transaction's `CtSigPrunable` and the verifier its
  `txs_prunable_hash`; each of those rulings is either re-keyed with
  the unit substituted or reopened. Q6 names which.
- **V11 retention rule** (`db_lmdb.cpp:128-136`) and
  **`txs_pqc_auths`** (`PDM-Q-F14`) — the rule keeps the PQC slice
  because it lacks a hash table. A Q6 ruling that adds
  `txs_pqc_auth_hash` changes what V11 protects and is a schema bump on
  the C++ side that this round does **not** make (`PDM-Q-S0`); it is
  the Rust store's to carry at `DRS-E*`, and slice A's `AppendMostly`
  grade on `txs_pqc_auths` (`class.rs:161`) re-grades with the three
  curve-tree rows.
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
  reorg trim. The leaf bytes live in exactly one table
  (`m_curve_tree_leaves`) deleted in exactly one function
  (`trim_curve_tree`, two loops: `:9278`, `:9392`). Q1 starts from that
  boundary — and `PDM-Q-F12` then shows the boundary does not stop
  there. The stale comments are corrected in the PR that rules Q1.
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

### Established by reading (2026-09-13, same pin)

- **PDM-Q-F10.** `trim_curve_tree` reads leaves on the pop path. F7 is
  right that upper layers recompose from layer 0, but the layer-0
  **boundary chunk** is not recomposed — it is `hash_trim`'d, and that
  needs the removed leaves' scalars: `db_lmdb.cpp:9354-9365` reads
  `m_curve_tree_leaves` at `:9361` and `throw0(DB_ERROR(...))` at
  `:9363`, inside the write txn. A reorg that reaches into a discarded
  segment aborts mid-transaction. Consequence for Q2: discard depth is
  bounded below by the maximum reorg depth **and** trim needs a defined
  failure (the bound is only as good as the constant enforcing it, and
  there is no consensus-side reorg cap at this pin — see §3 *Reorg*).
  Precision fix to F7's "one deletion site": one function, two loops
  (`:9278` trim-to-empty, `:9392`).
- **PDM-Q-F11.** DRS-0 slice A's accumulator freeze contradicts set-B
  discard on three tables.
  `rust/shekyl-chain-store/src/accumulator/class.rs:140-142`:
  `curve_tree_checkpoints` and `curve_tree_layers` are `Derived`,
  `curve_tree_leaves` is `AppendMostly` (running chained hash —
  deletions are unrepresentable). The audit that defends those grades,
  [`docs/LMDB_WRITE_ATOMICITY_AUDIT.md`](../LMDB_WRITE_ATOMICITY_AUDIT.md)
  lines 1518–1531 (note: `docs/`, not `docs/design/`), is explicit that
  verifying checkpoints against `curve_tree_meta` compares a copy with
  its original and is blind to a bad tree, so verification **must**
  recompute from the leaves. Leaves being the source is the whole
  reason `Derived` is defended as legitimate rather than convenient;
  discard removes the discriminator's only input. This is F7's false
  premise (`db_lmdb.cpp:9922`) one layer up, in a document that was
  right at the time it was written and stops being right the moment PDM
  ships. Carrier: the DRS-0 lane re-grades the three rows against Q1's
  output; §5 names the dependency.
- **PDM-Q-F12.** **Leaves are a cache of a pure function of the block
  corpus. Set-B scarcity, as currently scoped, does not exist.**
  Trace the construction: `blockchain_db.cpp:608-611` calls
  `shekyl_construct_curve_tree_leaf(output_key, commitment.bytes, h_pqc,
  leaf)` — three inputs. `output_key` and `commitment` are the output's
  `O` and `C` (`:564`, `:597`). `h_pqc`, the fourth scalar, has its
  provenance at `:528-546`: `extract_leaf_hashes` pulls the
  `tx_extra_pqc_leaf_hashes` field (`0x07`) out of the transaction,
  exactly `32 · vout.size()` bytes, one per output, and `:557` indexes
  it. So the fourth scalar lives in **the transaction blob**, which is
  block corpus and retained under D10's replay premise. Every one of the
  four scalars is reconstructible from data a discarding node keeps —
  `O`, `I = hash_to_p3(O)`, `C` from `output_metadata` via
  `get_output_key(0, i)` (the RPC already does exactly this,
  `core_rpc_server.cpp:1585-1600`) or from the blocks directly if
  `output_metadata` is itself discarded (`Excluded`, `class.rs:149`);
  `h_pqc` from `tx_extra` `0x07`. The regeneration path is not
  hypothetical: it is the production code at `blockchain_db.cpp:598-617`
  running on every replay. Therefore: (i) the storage argument is close
  to nil — discard 128 B/output and keep every byte that regenerates it;
  (ii) the possession test cannot discriminate on leaves *at all* — an
  archiver storing zero leaves answers every leaf challenge correctly by
  local recompute, faster than a fetch. That is the liveness-not-
  possession failure the round was opened to fix, reproduced inside the
  fix. Scarcity would have to come from discarding the derivation
  inputs, and the input of last resort is the block corpus — `PDM-Q6`'s
  subject. Q6 is promoted to the locus of scarcity; Q1 widens as a
  consequence (must rule on `output_metadata`, `leaf_to_output`,
  `output_to_leaf`, and the tx corpus). Recorded as its own finding
  rather than a Q1 scoping note because it is a challenge to the
  round's premise (§1.1), and a reader has to hit it first: *name what
  makes set B scarce, or withdraw the claim that it is.*

### Established by reading (2026-09-13, same pin — the data-element pass)

The pass §9 tabulates. Read against F12's test: *is this element a
pure function of bytes a pruned node keeps?* — and against the
consensus question: *does anything read it after admission?*

- **PDM-Q-F13.** **The third category exists, and the code already
  designates it: the transaction's prunable region is scarce and
  D10-compatible.** F12's author asserted scarcity and
  reconstructibility were one axis — anything non-derivable is needed
  for replay, anything not needed is derivable. That was true of
  derived state and false of the transaction. `src/fcmp/ct_types.h`
  splits the ct signature at `:197` / `:333`: the **unprunable base**
  (`type`, `txnFee`, `referenceBlock`, `enc_amounts`, `enc_labels`,
  `outPk`) and the **prunable region** `CtSigPrunable`
  (`bulletproofs_plus` `:349`, `fcmp_pp_proof` `:367`, `pseudoOuts`
  `:384`, `serve_credit_pruned` `:402`). Run F12's own trace against
  the split: leaf reconstruction reads `output_key` from `vout`,
  `commitment` from `tx.ct_signatures.outPk[i].mask`
  (`blockchain_db.cpp:597`) and `h_pqc` from `tx_extra` `0x07` — all
  three in the base. Replay through `apply_block` rebuilds every
  derived table from the **pruned** corpus alone, so D10 is not in
  tension with discarding the prunable region. And the region is
  non-derivable in the strong sense: range proofs and FCMP++ proofs
  are commitments over witness data that no longer exists anywhere;
  they are original, not cached. Scarce *and* replay-compatible — the
  object F12 said could not exist. Its verifier is already in the
  schema: the V11 rule (`db_lmdb.cpp:128-136`) keeps `txs_prunable_hash`
  when `prune_tx_data` drops the body, and the row is written per tx
  at `:1166-1167`. A challenged archiver returns bytes; any node
  verifies them against a 32-byte hash it retained — non-forgeable,
  per transaction, no fetch to check, and it discriminates on
  **possession**, which was the defect that opened the round. Size:
  `FCMP_PLUS_PLUS.md` §13 puts the region at ~6.1 KB of a ~17–18 KB
  2-in/2-out transaction (~35 %). Consequence: the scarce good is not
  "the block corpus" (F12's phrasing); it is the corpus's prunable
  region. Q6 is the round's subject, not a promotion; Q1's set-B
  enumeration is downstream of Q6's ruling.
- **PDM-Q-F14.** **The largest element in a transaction is kept by
  hashing convention, not by consensus need.** `pqc_auths` — one
  hybrid public key + hybrid signature per input,
  `cryptonote_basic.h:426-433` — is ~10.6 KB of the same 2-in/2-out
  transaction (~60 %, `FCMP_PLUS_PLUS.md` §13). It is stored as its
  own slice of the unprunable half, `txs_pqc_auths`
  (`db_lmdb.cpp:1132-1149`: bytes `pqc_auths_offset..unprunable_size`).
  Every consensus reader is inside `check_tx_inputs`
  (`blockchain.cpp:3717`, `:3739`, `:3838`, `:3922`, `:3988`, `:4231`,
  `:4351`); the DB reads (`db_lmdb.cpp:3344`…`:3997`) are blob
  reassembly for serving. It enters the txid only as `pqc_auth_hash`:
  `hash(prefix, base_ct, pqc_auth_hash, prunable_hash)`,
  `cryptonote_format_utils.cpp:1306-1318`. The V11 comment says why
  it is retained: *"neither has a hash table of its own"*
  (`db_lmdb.cpp:131`). So a 32-byte `txs_pqc_auth_hash` row per tx
  would put the slice in the same category as F13's region — original,
  admission-only, hash-verifiable — with no change to the tx blob or
  the txid. Not a ruling; Q6 item 2. Recorded because a Q6 that rules
  the ~35 % in and leaves the ~60 % universally retained has answered
  the storage question backwards.
- **PDM-Q-F15.** **The self-reference is checked and benign.**
  `serve_credit_pruned` (RF-D1 pass records, the pruned half) sits
  inside F13's good. Readers in `src/` after parse: exactly one,
  `blockchain.cpp:3807`, inside `check_tx_inputs`, handing each vin
  its record for `check_archival_serve_credit_input`; the remaining
  hits are the serializers. Settlement, challenge verification and
  slashing read the **kept** vin (`RF-D1`: `p_canonical_id`,
  `shard_id`, `settlement_epoch`, `leaf_bytes`, Ed25519
  countersignature, ~230 B) and the archival tables populated from it
  at add time; `CR-D2` ruled the kept side *"identifies the record,
  cannot re-verify the opening"* — the pruned half was designed as
  admission-only. The retention prune (`db_lmdb.cpp:7704-7739`) already
  retires the credit, settlement, r_market, sigma-work, budget and
  witness rows at `tip − W` and its own comment says *"Settlement reads
  the kept tx_extra headers, never this witness"*. So the archival
  system already treats its evidence as disposable after `W`; the
  pruned half being in the good adds no reader. Condition: discard
  depth ≥ the reorg depth that can re-run `check_tx_inputs` on the
  block (Q2, same floor as F10's).
- **PDM-Q-F16.** **Seven archival tables are node-local journals that
  grow without bound and are read only inside a window.** Six —
  `archival_bond_unbond_log`, `archival_bond_holdings_update_log`,
  `archival_bond_rebond_log`, `archival_emission_claim_log`,
  `archival_slash_log`, `archival_epoch_close_log` — are referenced
  only in `db_lmdb.{h,cpp}`; their readers are the pop path
  (`revert_*_at_height`, `db_lmdb.cpp:6256`, `:6513`, `:6631`,
  `:6892`, `:7000`, `:8508`). One forward-path consensus read exists:
  `archival_slash_removed_holding_after` (`:5243`) range-scans
  `archival_slash_log` strictly above a settlement height, so rows
  older than the retention window are never reached **if** every
  caller's `at_height ≥ tip − W` — proven at the pin in `PDM-Q-F19`,
  with the bound being emergent rather than enforced. None of the seven
  is in the retention prune's list; slice A grades all six logs
  `AppendMostly` (`class.rs:116-134`). Bytes are per event, not per
  transaction, so the storage stake is small; the finding is a
  class, not a number: these are `LOCAL-BOUNDED` in §9 and Q1 owes
  them a retirement horizon (the reorg window for the six, the
  retention window for the slash log once the caller bound is shown).

### Verified by review (2026-09-13) — closes two §8 open items

- **PDM-Q-F18.** **`scan_outputkeys_for_indexes` is rule-60 residue;
  `output_metadata` has no post-admission consensus reader.** The
  function (`src/cryptonote_core/blockchain.cpp:262`) has one caller,
  `Blockchain::check_tx_input` (`:4564`, inside `:4522`), and
  `check_tx_input` has **zero callers** — `src/` and `tests/` return
  only the declaration (`blockchain.h:1355`), the definition, and a
  comment at `:3514`. The body is ring-era on its face: it branches
  on `tx_version == 1` and validates `txin.key_offsets.size()`
  against returned ring members, which FCMP++ removed. So the
  `output_metadata` grading in §9 stands as CACHE without the
  "undetermined" qualifier, and the whole
  `check_tx_input` → `scan_outputkeys_for_indexes` → `outputs_visitor`
  chain is a rule-60 deletion, recorded in `docs/FOLLOWUPS.md` for a
  dedicated C++ PR (not this charter, not the Q1 comment-correction
  PR).
- **PDM-Q-F19.** **The slash log's forward reader is bounded on every
  path, and on no path is the bound a check.** The reviewer's read
  was one path; the pin has two, and the answer is the same shape on
  both. `archival_slash_removed_holding_after` (`db_lmdb.cpp:5243`) is
  reached only via `archival_bond_holds_shard_of` (`:5328`; calls at
  `:5385`, `:5388`), whose `at_height` is always an `h_fire`:
  1. *Serve-credit consumer* (admission): `blockchain.cpp:5270`
     → `archival_bond_holds_shard` (`:5315` → `:5325`). Bounded by the
     **credit deadline**: the vin is rejected if
     `current_height > h_close` (`blockchain.cpp:5222-5226`), and
     `h_fire ∈ (0, H_close]`, so `at_height ≥ tip − SETTLEMENT_EPOCH_BLOCKS`
     at admission. Not a check on `at_height`; a consequence of a
     check on the epoch.
  2. *Slash scheduler*: `process_archival_slash_at_height`
     (`:6197`) walks epochs from the watermark `last_slash_epoch + 1`
     while `block_height > H_slash_deadline(E)`
     (`= (E+1)·SEB − 1 + CHALLENGE_RESOLUTION_BLOCKS`,
     `failure_window.rs:191`) → `archival_challenge_failed_at_height`
     (`:5892`) → `archival_baseline_observed_at_epoch` (`:5734`),
     which computes `h_fire` at `:5810` and, per its own comment at
     `:5803-5808`, applies **no range check** — `H_fire ∈ (0, H_close]`
     is asserted from well-formedness. The failure window then walks
     **back** `n − 1` epochs (`--epoch` loop, `:5860-5864`;
     `n = 13`, `config/consensus_constants.json:32`). Bounded by the
     **watermark** in steady state:
     `at_height ≥ tip − (CHALLENGE_RESOLUTION_BLOCKS + n·SETTLEMENT_EPOCH_BLOCKS)`
     = `tip − 140,000` at the pinned constants (both 10,000), plus the
     reorg depth the pop path can rewind the watermark by.

  So the horizon exists and is `tip − (CRB + n·SEB + reorg)`; Q1 can
  name it. What Q1 cannot do is name it *alone*: on both paths the
  bound is emergent (a deadline check on the epoch; a monotone counter
  catching up), and a node that scans from a cold watermark
  (`u64::MAX → next_epoch = 0`, `:6203`) evaluates every epoch at its
  historical deadline height, reading a slash log that replay itself
  has just written — fine today, and a silent read of nothing once a
  horizon retires those rows. The second-order point the reviewer
  flagged is the finding: a documented "no range check" on a value a
  prune horizon will depend on is exactly the shape where an assertion
  becomes a check. Today the only thing keeping `h_fire` above a future
  discard horizon is an argument in a comment. The horizon lands **with**
  the check — `at_height ≥ retirement_floor` asserted where the
  scan starts, going red before the scan reads a retired range — or it
  does not land. Falsify the bound by a test that advances the chain
  `CRB + n·SEB + 1` past an epoch and shows the scheduler never reads
  below the floor; falsify the *check* by removing the assertion and
  showing the test still passes, which is the current state.

### Received from the daemon cutover lane (2026-09-13), verified at the pin

- **PDM-Q-F17.** **What is transferable from the C++ stripe engine is
  not the pruning; it is the assignment / advertisement / coverage
  triple — and under F13 it already partitions the good.** The
  cutover lane's input, read at source:
  1. *Assignment.* One `u32` compresses a node's retention
     commitment: `tools::make_pruning_seed(stripe, log_stripes)`, and
     a third party computes what the node holds from it alone —
     `has_unpruned_block(height, chain_height, seed)`,
     `get_next_unpruned_block_height`, `get_pruning_stripe`
     (`src/common/pruning.h:44-51`). Partition unit: 4096-block
     stripes, 2³ of them, tip window 5500
     (`src/cryptonote_config.h:342-344`).
  2. *Advertisement.* The seed rides `CORE_SYNC_DATA` and every
     peerlist entry (`cryptonote_protocol_defs.h:200`;
     `net_node.inl:1582`, `:2915`) and is validated on ingest against
     the stripe range (`net_node.inl:2315`; `PWC-C6`,
     [`P2P_1_WIRE_CENSUS.md`](P2P_1_WIRE_CENSUS.md) line 367).
  3. *Coverage.* No coordinator: `get_next_needed_pruning_stripe`
     drives peer selection to candidates whose stripe complements the
     local gap (`net_node.inl:1714`, `:1828-1830`, `:1853-1862`), and
     `get_random_stripe` spreads self-assignment.

  Mapped onto archival, that is *which archiver holds which shard,
  advertised compactly, checkable by a third party, network-wide
  coverage with no registry* — the shape `PDM-Q`'s possession test
  needs, already solved once, in code Q7 keeps deliberately. **What
  this round adds:** the stripe is a partition of **block heights over
  `txs_prunable`** — i.e. of exactly F13's good. §3's "the two
  partitions are unrelated" was true of leaves and is false of the
  prunable region: the inherited engine is a coordinator-free
  assignment of the archival good that lacks only what the archival
  system has (a bond with economic weight, a possession verifier —
  `txs_prunable_hash` — and slashing), while the archival system has
  those and lacks what the engine has (a compact, third-party-computable
  holdings function and emergent coverage), *and* is keyed to a unit
  F12 showed is not scarce. Q6 item 3's unit change can take the
  arithmetic as the shard definition. Three things the mapping must
  not lose: (a) the seed is a **claim** — the engine catches a liar
  only when a block is requested; the bond + challenge is what turns
  the claim into a tested commitment, so the triple is the *front* of
  the mechanism and the bond is its *back* (Q9's source ruling stands
  — the chain, not the wire, is authoritative; the wire slot
  advertises what the chain already says, and a peer can check one
  against the other); (b) coverage in the engine is by random stripe
  plus peer preference, coverage in the market is by price
  (`r ≫ 1000`, §3 Sybil bullet) — Q6 says which does the work, or how
  they compose; (c) under Q7 every ordinary node's retention is
  identical, so the slot carries information **only for archivers**,
  which bounds Q8's exposure to what the bond already publishes.
  Closes the earlier repurposing note: `pruning_seed`'s wire slot is
  not merely an available successor for "advertise what you retain";
  the arithmetic behind it is the part worth taking, and it stays in
  C++ to be read from until `DRS-E*` (`PDM-Q7`).

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

- The prunable region as the archival good, the `pqc_auths` second
  occupant, and the leaf→transaction unit change it forces on the
  closed archival rulings (Q6, F13–F15) — ruled first. Then the
  retained set (starting from layer 0 / `m_curve_tree_leaves`, F7;
  widened to the leaf's derivation inputs, F12; §9's `CACHE` and
  `LOCAL-BOUNDED` rows, F16), the trigger (including the free-regime
  duration, what the market does during it, and the reorg-depth floor,
  F10 / F15), residual consensus reads after TJ-A (Q3),
  reconstruction, cold sync, stripe-engine residue at the cutover
  (Q7), fetch privacy, the archiver's bond-binding and lapse tail
  (Q9), the "not retained" RPC response (Q10).
- ~~Whether `scan_outputkeys_for_indexes` is live or residue~~ —
  settled residue, `PDM-Q-F18`. ~~Whether every caller of
  `archival_slash_removed_holding_after` passes `at_height ≥ tip − W`~~
  — both paths bounded, neither enforced, `PDM-Q-F19`; what remains
  owed is the check.
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
| `PDM-Q1` | Retained set (layer 0 boundary, F7; widened to leaf derivation inputs, F12; §9 inventory) | OPEN — widened 2026-09-13; ruled after Q6 (F13) |
| `PDM-Q2` | Trigger, depth, free-regime duration, reorg-depth floor (F10) | OPEN |
| `PDM-Q3` | Residual consensus reads after TJ-A | OPEN — today not node-local (`PDM-Q-F8`) |
| `PDM-Q4` | Reconstruction path | OPEN |
| `PDM-Q5` | Cold sync and bootstrap | OPEN |
| `PDM-Q6` | The prunable region as the archival good; `pqc_auths` second occupant; leaf→tx unit change (F13, F14, F15) | OPEN — the round's subject 2026-09-13; ruled before Q1 |
| `PDM-Q7` | Stripe engine / `--prune-blockchain` | **PARTIAL 2026-09-12** — opt-in flag rejected, scoped to the universal set (2026-09-13); C++ stays until this design is complete; removal at `DRS-E*` |
| `PDM-Q8` | Privacy (density vs query) | OPEN |
| `PDM-Q9` | Archiver's retention set: source, binding, lapse | **PARTIAL 2026-09-13** — source ruled: shard retention is the bond process (`holdings` on-chain); binding and lapse tail OPEN |
| `PDM-Q10` | RPC contract for "not retained" | OPEN |

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

Q1 starts from F7's boundary and does not stop at the leaf table
(F12); the PR that rules Q1 corrects `db_lmdb.cpp:9922-9925` / `:9970`
/ `blockchain_db.h:2838`. Q2's ruling must state the free-regime
duration, the market's behaviour during it, and the reorg-depth floor
with trim's defined failure (F10) and F15's admission-only floor. Q3
is the residual-set question after TJ-A, with an instrument that can
go red. **Q6 is answered before Q1 is closed**, and Q6 is now a
concrete question rather than a promotion: F13 names the good (the
prunable region, verified by `txs_prunable_hash`), F14 names the
second occupant (`pqc_auths`, ~60 % of the bytes, kept only for want
of a hash row), F15 discharges the self-reference, and Q6 item 3 owes
the list of closed leaf-shaped rulings the unit change reopens. A Q1
ruling written ahead of Q6 is ruling on a cache. Q1 then rules §9's
`CACHE` and `LOCAL-BOUNDED` rows (F16) and the two undetermined
readers. Q9's binding and lapse tail; Q10's response shape, legible
to the `SF-` round. F9 is a C++ defect independent of PDM; the carrier
is the FOLLOWUPS row, not this charter. F11's re-grade of the three
curve-tree rows — and now `txs_pqc_auths` — is the DRS-0 lane's, on
Q6's and Q1's output.

---

## 9. Data-element inventory at the pin (`edb35dbb1` + this round's reads)

The pass the user asked for: every element that reaches the chain
store, graded on two axes — **derivable?** (F12's test: a pure
function of bytes a pruned node keeps) and **read after admission?**
(by consensus, by wallets, by nothing). Classes:

- **KEEP-C** — consensus reads it after admission. Universal. Not
  negotiable by this round.
- **KEEP-W** — consensus does not need it after admission; **wallets
  do** (restore-from-seed scans every output ever). Universal unless a
  ruling gives wallets an archiver-served path — which is Q5's
  centralisation question wearing a different costume. Default KEEP.
- **KEEP-D** — derivation input for a `Derived` / `CACHE` table under
  D10's replay premise. Kept because dropping it makes something else
  unrebuildable.
- **CACHE** — pure function of KEEP-C/KEEP-W/KEEP-D bytes. Discard is a
  performance choice, never scarcity (F12). Q1's rows.
- **GOOD** — original, non-derivable, admission-only, hash-committed.
  The archival subject candidate (F13, F14). Q6's rows.
- **LOCAL-BOUNDED** — node-local; readable only within a window
  (reorg, retention, tip). Retire on the window; never scarce (F16).

Sizes are per unit at the pin; the transaction figures are
`FCMP_PLUS_PLUS.md` §13's 2-in/2-out budget (~17–18 KB), which does
**not** itemise the `0x06` KEM ciphertexts (1120 B/output,
`POST_QUANTUM_CRYPTOGRAPHY.md:153`) — they are in the prefix and are
added here. "Readers" lists post-admission readers only; every element
is read at admission.

### 9.1 The transaction (the block corpus, `blocks` + `txs_*`)

| Element | Wire home | Store home | Bytes (2-in/2-out) | Post-admission readers | Derivable from | Class |
| --- | --- | --- | ---: | --- | --- | --- |
| prefix: `version`, `unlock_time`, `vin` (key images, archival vins), `vout` (`O`), `extra` sans `0x06`/`0x07` | tx prefix | `txs_pruned` | ~0.5 KB | consensus (key images → `spent_keys` rebuild; archival vins → archival tables rebuild; `RF-D1` kept vin read by settlement / slash), wallets | — (original) | KEEP-C |
| `tx_extra` `0x07` PQC leaf hashes (`h_pqc`) | prefix | `txs_pruned` | 32 B/output | replay (`blockchain_db.cpp:528-557` → leaf) | — | KEEP-D |
| `tx_extra` `0x06` hybrid KEM ciphertexts | prefix | `txs_pruned` | 1120 B/output (~2.2 KB) | wallets only (scan / restore) | — | KEEP-W |
| `CtSigBase`: `type`, `txnFee`, `referenceBlock`, `enc_amounts`, `enc_labels`, `outPk` | ct base (`ct_types.h:197`) | `txs_pruned` | ~256 B | replay (`outPk` → commitment → leaf, `:597`; fee → burn / emission), wallets (`enc_amounts`, `enc_labels`) | — | KEEP-C / KEEP-D |
| `pqc_auths` (hybrid pk + hybrid sig per input) | between base and prunable (`cryptonote_basic.h:492`) | `txs_pqc_auths` | ~5.3 KB/input (~10.6 KB) | **none** — every reader is in `check_tx_inputs` (`blockchain.cpp:3717-4351`); txid uses only `pqc_auth_hash` | — (original) | **GOOD** candidate (F14) — needs a 32 B hash row it does not have |
| `CtSigPrunable`: `bulletproofs_plus` | prunable (`:349`) | `txs_prunable` | ~1.5 KB | none; hash in `txs_prunable_hash` | — (witness gone) | **GOOD** (F13) |
| `CtSigPrunable`: `fcmp_pp_proof` + `curve_trees_tree_depth` | prunable (`:367`) | `txs_prunable` | ~2.5 KB/input (~4.5 KB) | none; hash in `txs_prunable_hash` | — (witness gone) | **GOOD** (F13) |
| `CtSigPrunable`: `pseudoOuts` | prunable (`:384`) | `txs_prunable` | 32 B/input | none | — | **GOOD** (F13) |
| `CtSigPrunable`: `serve_credit_pruned` (RF-D1 pruned half: ML-DSA leg + `path` incl. the leaf chunk) | prunable (`:402`) | `txs_prunable` | ~9,965 B per serve-credit vin (`ARCHIVAL_RESPONSE_FORMAT.md:78-81`) | none (`blockchain.cpp:3807` is admission; F15) | — | **GOOD** (F13, F15) |
| `txs_prunable_hash` | — | `txs_prunable_hash` | 32 B/tx | txid recompute (`get_pruned_transaction_hash`); **the GOOD's verifier** | H(prunable) — but only if you hold the prunable | KEEP-C |
| `pqc_auth_hash` | — | **no table** (V11: *"neither has a hash table"*) | 32 B/tx if minted | would be `txs_pqc_auths`'s verifier | H(pqc_auths) | Q6 item 2 |
| `tx_indices` (hash → id, height, unlock) | — | `tx_indices` | ~56 B/tx | consensus (tx lookup, reorg), RPC | rebuild from `blocks` | CACHE (kept; index) |
| `tx_outputs` (tx → global output indices) | — | `tx_outputs` | 8 B/output | reorg pop (`remove_output`), RPC | rebuild | CACHE |
| `txs` (inherited) | — | `txs` | 0 (unused at v3; `Excluded`, `class.rs`) | none | — | deletion target (rule 60), not this round's |
| `txs_prunable_tip` | — | `txs_prunable_tip` | 8 B/tx in tip | inherited stripe engine only | — | LOCAL-BOUNDED (dies with Q7) |

Totals for the 2-in/2-out transaction, at the pin: **~20 KB on the
wire; ~3 KB is KEEP-C/KEEP-W/KEEP-D (prefix + base + KEM ct + leaf
hashes); ~6 KB is GOOD today (the prunable region); ~10.6 KB is GOOD
pending a hash row (F14).** A ruling that takes both GOOD rows retains
~15 % of transaction bytes universally.

### 9.2 Per output — the derived layer (all CACHE under F12)

| Table | Bytes/output | Post-admission readers | Derivable from | Class |
| --- | ---: | --- | --- | --- |
| `curve_tree_leaves` | 128 | serve-credit verify **today** (`blockchain.cpp:5327`, F8 — goes with TJ-A); `trim_curve_tree` boundary chunk on pop (`:9361`, F10); RPC `:1577`/`:1670` | `O`, `C`, `h_pqc` → `shekyl_construct_curve_tree_leaf` (`blockchain_db.cpp:608`) | CACHE (F12) |
| `output_metadata` (`output_data_t`: pk, unlock, height, commitment) | 80 | none in consensus — `scan_outputkeys_for_indexes` (`blockchain.cpp:262`) is rule-60 residue, its sole caller `check_tx_input` (`:4522`) has zero callers (`PDM-Q-F18`); RPC leaf reconstruction (`core_rpc_server.cpp:1585`) | `vout` + `outPk` + block height | CACHE (`Excluded` in slice A, `class.rs:149`) |
| `output_txs`, `output_amounts` | ~40, ~48 | reorg pop, RPC | rebuild | CACHE |
| `output_to_leaf`, `leaf_to_output` | 16, 16 | leaf ↔ output mapping on pop and RPC | rebuild (insertion order) | CACHE |
| `pending_tree_leaves`, `pending_tree_drain`, `block_pending_additions` | 128 + index, transient | maturity drain at unlock height (consensus) | rebuild from `unlock_time` | KEEP-C while pending; self-bounding (empties at maturity) |

### 9.3 Per block and per input — consensus state that is not a cache

| Table | Bytes/unit | Post-admission readers | Derivable | Class |
| --- | ---: | --- | --- | --- |
| `blocks` (header incl. `attestation_root` + miner tx + tx hashes) | ~0.3 KB + miner tx (KEM ct per coinbase output) | PoW / difficulty window, reorg, sync serving, replay root | — | KEEP-C |
| `block_info`, `block_heights` | ~100, 40 | difficulty, cumulative weight, hash → height | rebuild from `blocks` | CACHE (kept; index) |
| `spent_keys` | 32 B/input | **every** FCMP++ input check (double spend) | rebuild from `vin` | KEEP-C — the one permanently unbounded set; not prunable at any depth |
| `curve_tree_roots` | 32–64 B/block | every FCMP++ proof verify (`referenceBlock` → root) | rebuild from leaves… which are CACHE — root chain must stay | KEEP-C |
| `curve_tree_layers` layer 0 (`R_k` chunks) | 32 B/chunk | recompose on trim (F7); TJ-F verify target | recompute from leaves (CACHE) — kept as the set-A boundary | KEEP-C (set A) |
| `curve_tree_layers` layers 1..depth−2 | 32 B/chunk | none after seal | recompose from layer 0 | CACHE — **already pruned** by every node (`prune_curve_tree_intermediate_layers`) |
| `curve_tree_meta`, `curve_tree_checkpoints` | small | trim, integrity check (`Derived`, F11) | from leaves (F11) — re-grade | CACHE / KEEP-C (root layer) |
| `block_burn` | 8–16 B/block | emission / burn accounting | rebuild from fees | CACHE (kept; small) |
| `hf_versions`, `hf_starting_heights`, `properties` | small | consensus versioning, receipts (V12 prune watermark) | — | KEEP-C (constant size) |

### 9.4 Archival / staking state (the 18 `archival_*` tables + `block_burn`)

Everything here is **populated from kept prefix bytes** (archival vins
are opaque canonical blobs in the tx prefix, `cryptonote_basic.h:190`,
`:257`, `:288`) and is therefore rebuildable by replay from the pruned
corpus. Nothing here is GOOD; the question is only which rows a node
must keep to *verify new blocks* versus which it may retire.

| Table | Class (slice A) | Post-admission readers | Bounded by | Class (this round) |
| --- | --- | --- | --- | --- |
| `archival_bond` | SetShaped | every bond / challenge / settlement / slash rule (live bond set) | live bonds | KEEP-C |
| `archival_shard_segment` | SetShaped | freeze pipeline, challenge target (`R_k` per shard) | segments ever frozen | KEEP-C (unit changes if Q6 rules the good is transactions — §5) |
| `archival_slash_applied` | SetShaped | slash dedupe | slashes ever | KEEP-C |
| `archival_serve_credit`, `archival_settlement`, `archival_r_market`, `archival_sigma_work`, `archival_budget`, `archival_budget_accrual`, `archival_attestation_witness` | Small | settlement / epoch close within `W` | **retention prune at `tip − W`** (`db_lmdb.cpp:7704-7739`, un-journaled) | LOCAL-BOUNDED — already retired; nothing owed |
| `archival_alt_attestation_witness` | Excluded | alt-chain reconnect | alt blocks | LOCAL-BOUNDED (alt) |
| `archival_bond_unbond_log`, `archival_bond_holdings_update_log`, `archival_bond_rebond_log`, `archival_emission_claim_log`, `archival_epoch_close_log` | AppendMostly | pop path only (`revert_*_at_height`) | **nothing today** | LOCAL-BOUNDED in principle (reorg window); unbounded on disk (F16) — Q1 |
| `archival_slash_log` | AppendMostly | pop path + `archival_slash_removed_holding_after` (`:5243`, scans above `at_height`); `at_height = h_fire` on both entry paths, bounded by credit deadline / watermark + window, not by a check (F19) | **nothing today** | LOCAL-BOUNDED — horizon `tip − (CRB + n·SEB + reorg)`, minted with its check (F19) — Q1 |

### 9.5 Node-local, never chain state

`alt_blocks`, `txpool_meta`, `txpool_blob` (all `Excluded`). Bounded by
their own eviction. Not this round's.

### 9.6 What the inventory says

1. **The only scarce goods at the pin are the transaction's prunable
   region and — pending a 32-byte hash row — its `pqc_auths` slice.**
   Together ~85 % of transaction bytes. Everything else is either
   consensus-required forever (`spent_keys`, roots, headers, the
   prefix), wallet-required (KEM ciphertexts), a derivation input for
   the tree (`0x07`, `outPk`, `vout`), or a cache.
2. **Nothing in the archival / staking *tables* is prunable in the
   scarcity sense**, and nothing there needs to be: the seven
   window-bounded tables are already retired by the retention prune,
   the three set-shaped tables are live consensus state, and the seven
   journals (F16) are node-local with a window nobody has yet applied.
   The archival domain's bytes are in the **transaction**: the pass
   record's pruned half is ~10 KB per serve-credit vin against ~230 B
   kept (`RF-D1`), which is `CR-D2`'s ~88 GB/yr floor — and under F13
   that stream is GOOD, not overhead. The archival system's own
   evidence is the bulk of what it sells (F15 says that is benign).
3. **The one permanent, unbounded, unprunable table is `spent_keys`**
   — 32 B per input, forever, on every node. Any storage projection
   that omits it is wrong; any pruning design that touches it breaks
   double-spend detection.
4. **Discarding the derived layer (§9.2) saves ~340 B/output against
   ~1.3 KB/output of bytes that regenerate it.** It is a cache policy
   (Q1) and buys no scarcity (F12). Whether a pruned node keeps
   `curve_tree_leaves` is a latency question about spend-path
   assembly and TJ-A's verify path, not a product question.
