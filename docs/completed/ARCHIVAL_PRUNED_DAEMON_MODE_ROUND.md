# Pruned-daemon mode — set-B discard (PDM): the round record, 2026-09-12 → 2026-09-18

**Status: CLOSED-as-record** — the round's full argument, 2026-09-12 →
2026-09-18, frozen at the commit that contracted it. **Do not implement
from this file.** The contract of record is
[`docs/design/ARCHIVAL_PRUNED_DAEMON_MODE.md`](../design/ARCHIVAL_PRUNED_DAEMON_MODE.md)
(LIVING CONTRACT): the twelve rulings, `PDM-Q-S0`, the §3 dispositions,
the findings register, the disposition table, what carries on, and the
§9 inventory live there and are maintained there. This record keeps what
the contract dropped: the opening-phase narrative (the drift from leaves
to the prunable region), the pre-ruling analysis under every question,
the §3 adversarial walks in full, the withdrawn proposals, and the
findings' full text. Every `PDM-Q-F*` cited from the contract's register
resolves here by ID. **Line-local status:** any sentence below that reads
as a current state ("OPEN", "owed", "still") is a records-was claim at
the date the enclosing section carries; the contract is the status of
record. The banner the round carried when it closed follows, unedited,
as the record of its state:

> **Status: OPEN — every `PDM-Q*` question is RULED or CLOSED as of
> 2026-09-18 (Q1–Q3, Q5–Q12 RULED; Q4 CLOSED; `S0` RULED); the design side
> of the round is complete. Archive-or-contract (rule 95) is steering's
> call and is owed; what carries on past the round is named in §8.** Round
> opened 2026-09-12. **RULED 2026-09-17:
> `PDM-Q6` items 1–3 (the prunable region + `pqc_auths` are the good; a
> shard is a `tx_id` range; item 4 OPEN by name) and `PDM-Q11` (`D_max`:
> shape frozen, home `CEN-E2`, numeric 720 PROVISIONAL to the Round-2
> gate). Unblocked by them: Q1, Q2, Q12, `SF` sub-PR 2, F28. RULED 2026-09-18: Q6 item 4 (nine-row re-key/reopen table — the serve-credit admission verifier is reopened as **consensus**, E4's), Q6 item 3 AMENDED (`PDM-Q-F32`: byte-bounded shards over a retained length row, shard-granular discard), Q12 (freeze retires; conditional on Q9 only for where dependents re-point), Q2 (shape: shard-granular discard predicate with an epoch floor; `W` ≈ 195 days PROVISIONAL, set by the journal floor, its cost stated), Q7 (the stripe engine is removed completely — nothing survives as design; F17's "worth taking" refuted; unbonded retention permitted — in the wallet-side store), **Q9 on PR #775 (`PDM-Q-F33`: the daemon holds no archival serving state, all daemons prune uniformly; the daemon-storage candidate REJECTED and withdrawn; the specified-to-scarce window is when the wallet fills its store from the local daemon — Q2 loses its exceptions conjunct, Q12's `LeafStore` is rebuilt not deleted), Q1, Q3, Q5 (`Trust::BelowAnchor` confirmed), Q8, Q10 RULED; Q4 CLOSED.** As
> opened: `PDM-Q1`…`PDM-Q6`, `PDM-Q8` and `PDM-Q10` were **OPEN**. `PDM-Q3` is restated (today not node-local,
> `PDM-Q-F8`). `PDM-Q1` is widened and `PDM-Q6` promoted (`PDM-Q-F12`:
> leaves are a cache of the block corpus; set-B scarcity as scoped does
> not exist), then **`PDM-Q6` is the round's subject** (`PDM-Q-F13`: the
> transaction's prunable region is scarce *and* replay-compatible, with
> its verifier `txs_prunable_hash` already in the schema; `PDM-Q-F14`:
> `pqc_auths`, ~60 % of tx bytes, is kept only for want of a hash row;
> `PDM-Q-F15`: the `serve_credit_pruned` self-reference is benign). §9
> inventories every data element at the pin. `PDM-Q7` is **PARTIAL**
> (opt-in flag rejected, scoped to the universal set). `PDM-Q9` is
> **PARTIAL** (shard retention is the bond process; binding and lapse
> timing OPEN). `PDM-Q8` is **PARTIAL** (P2P body-serving is uniform
> inside the universal window on every node — ratified 2026-09-13;
> fetch-side privacy OPEN). `PDM-Q5` is restated as **the anchor
> question** (`PDM-Q-F20`/`F23`: under Q6 a fresh node's historical
> proofs are the discarded good; the horizon below which it trusts the
> skeleton must be a release-carried checkpoint on the `assumevalid`
> argument, **not** `tip − D_max` — a tip-relative horizon lets a
> heavier invalid chain split the network by sync date; three bands;
> the trust-below fallback is REJECTED). `PDM-Q4` collapses: no
> chain-following read reaches an archiver for a node with downtime
> under **`W`**, the universal bytes window — minted as Q2's ruling
> variable (`PDM-Q-F24`: it had silently inherited `D_max`, which would
> put every node with a day's downtime on the archival market; floor
> `D_max`, candidate F19's ~195-day retirement floor). `PDM-Q12` (freeze pipeline
> and wallet-side `LeafStore` under Q6's unit) is minted OPEN.
> **`PDM-Q-F26` (2026-09-16, `645d09dc3`): the Rust store's `TxIdentity` is
> `{ hash, prunable_hash }` — one of Q6's two occupants; `pqc_auth_hash`,
> the txid's third component, is owed on the identity and as a row, and
> Q6 items 1–2 are ruled before DRS-E2's first production writer or E2
> rules them by construction.** **UPDATE 2026-09-17:** DRS §7.7 items 1–2 landed on
> #768 (`TxIdentity.pqc_auth_hash` + `Transaction::txid_parts` /
> `hash_with_supplied_components`); **UPDATE 2026-09-17 (PR #772):** the store row (item 3) landed as `txs_pqc_auth_hash` on S-CHAIN-R's layout commit. **F27–F29 (same day, on review): band 1
> needs a below-anchor `RuleSet` E6 is shaping now; the skeleton wire
> needs both txid components; Q3's instrument is `ChainView`'s surface.**
> **F30–F31 (2026-09-17, `4bc378d68`): Q11's census home is `CEN-E2`, and
> F27's Rust-held anchor fires `CEN-E1`/`CEN-E2`'s recorded reopening
> trigger — re-key owed in F27's PR; S-PRUNE owes a rule-26 plan doc before
> its first increment; §3's six adversarial items now carry status and
> owner; Q6 item 2 is the second increment built on an unruled default;
> Q11's owner is unnamed at day five. §3 WALKED the same day by steering:
> all six dispositioned — three DISCHARGED (withholding, eclipse,
> free-riding on the ruled bootstrap subsidy; a `bond_duration` vs `W`
> condition was drawn and withdrawn the same day), three conditional (on
> Q6 item 3 / F17 naming one unit; on Q9 ruling the coverage floor
> structural; on Q11 existing); Sybil's economics DISCHARGED with no
> residual on the self-diluting scarcity reward; Q6's gate is open.**
> `PDM-Q-S0` is RULED. This is the design home TJ-D named; it is not
> yet the design. **What this document is for:** nothing here is built
> while DRS is in progress — the implementation waits on the C++→Rust
> daemon cutover (`DRS-E*`, `PDM-Q-S0`). This charter is the
> **reference for the DRS build**, so that the universal-discard intent
> (uniform boundary `W`, archiver exceptions above it, hash rows
> forever) is unambiguous to the agents writing the Rust store and its
> digest, and so the store trait is shaped for it rather than retrofitted.
> 

**Grounded at** `dev@edb35dbb1467a55c1a1dd4033966fb9fe3413080` (2026-09-12,
`origin/dev` HEAD when the round opened; PR #720 / DRS-0 slice A).
Citations below were read at that sha. Do not inherit line numbers from the
opening prompt (written at `1c6238bf8`).

**Family:** `PDM-Q` — tokens `PDM-Q1`…`PDM-Q12` (questions), `PDM-Q-F*`
(findings), `PDM-Q-S0` (sequencing constraint). Registered in
[`IMPLEMENTATION_INDEX.md`](../design/IMPLEMENTATION_INDEX.md) §2 at birth (rule 94).
Family cell `**PDM-Q1…PDM-Q12**` parses to `PDM-Q`. Distinct from
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
It does not write `db_lmdb.cpp`, and it did not fix `PDM-Q-F9`'s silent
zero-fill (landed separately in PR #733, 2026-09-13, with F7, F18, F23).

---

## 0. Sequencing constraint — RULED 2026-09-12 (steering)

### `PDM-Q-S0` — implementation waits on the daemon C++→Rust cutover

**The rejection.** Do not implement set-B discard (or any successor of
`--prune-blockchain`) in the inherited C++ daemon. The landing site is
the Rust daemon after the store/engine swap (`DRS-E*`,
[`DAEMON_REDB_STORE.md`](../design/DAEMON_REDB_STORE.md); engine-swap **not started**
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

[`ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md`](../design/ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md)
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
([`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](../design/ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md)
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
[`REFRESH_DESIGN_LANDSCAPE.md`](../design/REFRESH_DESIGN_LANDSCAPE.md) lines 303–304:
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

### `PDM-Q1` RULED 2026-09-18 — The retained set is §9 graded against the byte-bounded `tx_id` unit

**Grounded at** `dev@20ebdf1e5`, on Q6 (items 1–4, F32), Q2, Q11.

**Ruling.** §9 already grades every element that reaches the chain store
(KEEP-C / KEEP-W / KEEP-D / CACHE / GOOD / LOCAL-BOUNDED). Q1 applies the
ruled unit to that table, and nothing in it changes class: **GOOD** is
the prunable region and `pqc_auths` per transaction (Q6 items 1–2),
discarded per shard by Q2's predicate; **KEEP-C** gains the two hash
rows (A3, #772) and the two length rows (A4, F32) — permanent, on every
skeleton; **CACHE** rows (leaves, layers, `output_metadata`,
`output_to_leaf` / `leaf_to_output`) are rebuilt by replay from the base
(F12, F13 — load-bearing, `DRS-D10`); **LOCAL-BOUNDED** — the seven
window-retired journals (F16) — retire at the journal horizon
`tip − (CRB + n·SEB + D_max)` (F19), which Q2 made equal to `W` by ruling,
**computed through `shekyl_archival_failure_window_params`, never a
literal**. The two readers left undetermined at the opening are both
resolved (`scan_outputkeys_for_indexes` — residue, F18;
`archival_slash_removed_holding_after` — bounded on both paths, F19);
no new ones were found at this sha. **Owed as implementation, not
ruling (F19: "what remains owed is the check"):** the journal horizon
asserted at the journals' own retirement site, the same discipline as
Q2's predicate — FOLLOWUPS row.

**Reversion.** Reopens if a §9 row is shown mis-graded against the tx
unit — falsifier: a replay from the skeleton that cannot rebuild a
row graded CACHE (this is also Q6's reversion (b)).

---

*The analysis below is the ground the ruling was taken on; its OPEN
framing is superseded by the block above.*


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
  (or the tx corpus), `I = hash_to_p3(O)`, and the leaf commitment point
  from `tx_extra` field `0x07` in the transaction blob (`PL-D3`). Discarding the leaf table alone
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
(`db_lmdb.cpp:9922-9925`, `:9970`; `blockchain_db.h:2838` at the pin;
`:9932-9935`, `:9978-9980`, `:2841-2842` at `4da609cbd`) are a
PDM-independent C++ fix with their own `docs/FOLLOWUPS.md` row
(`PDM-Q-F7`, 2026-09-13), landing now with F9/F18/F23 rather than in
the PR that rules Q1 — small, grep-falsified, and it clears noise out
of the tree before the ruling pass reads it. The slice A class assignments for the three curve-tree
tables (`PDM-Q-F11`) are re-graded against Q1's output by the DRS-0
lane, not here.

### `PDM-Q2` RULED 2026-09-18 (shape; numeric PROVISIONAL) — The discard predicate and the universal window `W`

**Grounded at** `dev@20ebdf1e5`, on Q6 items 1–4 and F32 (byte-bounded
shards, shard-granular discard) and Q11 (`D_max`).

**The predicate.** Shard `k` — a byte-bounded `tx_id` range
`[b_k, b_{k+1})` (F32) — has its prunable regions and `pqc_auths`
discarded **atomically, as a whole**, iff:

> `b_{k+1} ≤ first_tx_id(tip − W)` **and** `close_height(k) + SEB < tip`

*(Amended 2026-09-18 on #775 / Q9: the `k ∉ exceptions` conjunct first
written here is **struck** — the daemon holds no retention exceptions;
all daemons prune uniformly. Archiver retention is the wallet-side
store's, Q9.)*

where `first_tx_id(h) = block_info[h−1].cumulative_tx_count` (FL-R3-STORE,
landing on #772), `close_height(k) = height(b_{k+1})` (a binary search
over the same running total — no new state). The first conjunct is the horizon on the shard's *last*
transaction, so a shard discards only when its youngest byte is `W`
old — never a transaction at a time (F32: on an ordinary node a shard
is entirely present or entirely absent). The second conjunct is an
**epoch floor** on the specified-to-scarce window: it is `≥ W` by the
first conjunct alone, and the floor exists so that guarantee does not
silently depend on `W` being large if Round-2 moves it down hard. The
predicate is **asserted where the discard is decided** — S-PRUNE's
per-epoch batch — never discovered downstream: a violated predicate is
a refused discard, not a corrupted write. Pops are unaffected: a block
within `D_max` has its transactions in shards whose last tx is above
`tip − W` (`W ≥ D_max`).

**`W` — the floor and what sets it.** Floor `D_max`: pops must re-pool
full transactions, and the undo-log floor is the same inequality on the
store side (SCW-7). No adversary-side ceiling. **`W` is set by
coincidence with the slash-log retirement floor, not by honest
downtime:** `W = CRB + n·SEB + D_max` (F19) makes bodies and journals
one horizon, and honest downtime (days to weeks) is satisfied with a
wide margin as a consequence. The price is stated as an argument, not
"priced": **no scarce byte exists until day ~195**, the bootstrap
subsidy runs that long against no possession, and the first real
possession test fires at `W`. Accepted because the subsidy is ruled
bootstrap (`DESIGN_CONCEPTS.md` Component 4), because one horizon
removes a drift pair, and because a shorter `W` buys scarcity at the
cost of putting running nodes into band 2 on ordinary outages. If the
Round-2 outage CDF shows the tail well inside a shorter window, `W` can
fall toward it and the horizons separate — that is the numeric's gate,
not the shape's.

**Candidate, PROVISIONAL: `W = CRB + n·SEB + D_max` ≈ 140,720 blocks
≈ 195 days** at the pinned constants (`n = 13`, `SEB = 10,000`,
`D_max = 720`). Computed through `shekyl_archival_failure_window_params`,
never a literal. Re-pinned at the Round-2 gate with `n` and `D_max`
(three entries). The disk cost in the Q2 row stands as the price.

**The free regime, and every shard's own.** For the first `W` blocks
nothing is scarce; bonds, challenges and the possession test are live
from block 1 and challenges are answerable by any synced node — the
ruled bootstrap subsidy, not a defect (§3 free-riding walk). Under
shard-granular discard this is not only a launch effect: **every shard
is bondable from `close_height(k)` and scarce only at `discard(k)`,
`≥ W` blocks later**, so each has its own window of being paid for
while universally held — and that window is when the archiver's
**wallet pulls `k`'s bodies from its local daemon** over the operator
leg, before the daemon discards them like every other (Q9, #775). Stated so no one re-derives §3. The one open
question it raises is the reward leg's (item 3 amendment): whether
channel 1's `1/R_market` weight applies from bond or from `discard(k)`.

**Uniformity.** `W` decides no verdict and is not consensus. It is
network-uniform under `PDM-Q8` — every daemon answers identically
inside it — so a `W` change ships as a coordinated release, and its
home is beside `D_max`'s. Two releases with different `W` are
distinguishable on the wire during a rollout: that is a **bounded Q8
uniformity exception** (retention selecting wire behaviour for the
length of the rollout), accepted and named as such, not a rule-71
matter.

**Closed rulings touched.** `RF-D6` (reopened per Q6 item 4); the
retention prune's `tip − W` for the seven window-retired journals
(`PDM-Q-F16`) — same `W`, now one constant, not two; `SF-D10`'s
organic-need lifetime (`TJ-D`'s) inherits `W` as the horizon beyond
which a need becomes band 2; the serve-credit transaction's *own*
prunable region — the pass records — falls under this predicate like
any other, so any settlement read of a pass record after `W` is band 2
(the SO contact, F26); and S-PRUNE **cannot** discard a shard while a
live verifier still derives `R_k` from its frozen segment — Q6 item 4
row 1 is a precondition of the first real discard.

**Reversion (rule 21).** Shape reverts to OPEN if the honest-downtime
argument is shown to require `W` above the economic ceiling —
falsifier: the Round-2 measured outage CDF's tail exceeds the
candidate. Numeric reverts at the gate by construction.

**Falsifiers.** A shard discarded whose `b_{k+1} > first_tx_id(tip − W)`
is red. A shard discarded before `close_height(k) + SEB` is red. A
shard *retained* past its discard on any daemon is red (#775's
corollary — there are no exceptions). A partially discarded
shard on an ordinary node is red. A second window constant in any crate
not `W` by reference is red. `W < D_max` is red.

---

*The analysis below is the ground the ruling was taken on. It predates
the ruling and the unit change; its OPEN framing, its segment-freeze
candidate and its per-segment `eligible_height` predicate (F10) are
superseded by the block above — F10's demand (assert at the decision,
defined failure) is what the block satisfies.*

Segment freeze is the natural candidate; read
[`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](../design/ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md)
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

**Reorg-depth floor (F10, restated 2026-09-13):** not a depth — a
predicate on the segment's own leaves: *discard only once the highest
`eligible_height` among the segment's leaves is below `tip − D_max`*,
asserted at the discard decision. `D_max` is `PDM-Q11`'s constant; Q2
cannot be ruled before it exists.

**`W`, the universal bytes window (minted 2026-09-13, `PDM-Q-F24`) —
Q2's actual ruling variable, and it is not `D_max`.** The charter had
let the window every daemon keeps full bodies for inherit `D_max`
silently (Q4's "uniform `D_max` window", Q5's band 3). That cannot
stand: a node down longer than the window returns with an anchored
chain — `D_max` binds, the anchor is satisfied — and needs blocks
`(old_tip, new_tip]`; bodies for `(new_tip − W, new_tip]` come from
peers, bodies for `(old_tip, new_tip − W]` are beyond the window on
**every** ordinary peer (Q8's uniformity), so it enters band 2 and
fetches from archivers to verify blocks it missed. At `W = D_max =
720` that is every node with more than a day of downtime — reboots,
ISP outages, a laptop closed for a long weekend: the population, not
an edge case. **`D_max` and `W` have opposite pressures and must not
share a value.** `D_max` is a reorg parameter derived from adversary
economics that push it *shallow*; `W` is a downtime-tolerance
parameter with **no adversary-side ceiling** — a large `W` helps no
attacker, it only reduces scarcity. Bounds:

- *Floor:* `D_max` (F10 — pops must be able to re-pool full
  transactions; F15's admission-only floor is inside this).
- *Honest-node argument:* how long an honest node may be down before
  it should need an archiver. Same shape as `D_max`'s partition
  argument but generous — days to weeks, not hours — because nothing
  on the adversary side punishes generosity.
- *Ceiling:* economic, not security — the point at which so little of
  the chain lies beyond `W` that the market has nothing to sell. This
  is the density-versus-query trade the original Q8 posed, given a
  concrete meaning: `W` sets **both** downtime tolerance and how much
  of the chain is scarce, and it *is* the free-regime duration above
  (nothing is scarce until the chain is `W` blocks old).
- *Candidate — one horizon, not two:* F19's retirement floor,
  `tip − (CRB + n·SEB + D_max)` ≈ 140,720 blocks ≈ 195 days at the
  pinned constants — the deepest thing any consensus read reaches.
  Setting `W` there makes bodies and journals retire together (Q1's
  horizon and Q2's become one), and gives ~6 months of downtime
  tolerance before a running node touches an archiver, comfortably
  past anything an honest operator does by accident. It inherits
  `n`'s PROVISIONAL status and the Round-2 re-pin gate, and is
  computed through `shekyl_archival_failure_window_params`, never a
  literal. The cost is disk: ~195 days of bodies universal, at
  ~16.7 KB/tx (§9: ~6.1 KB prunable region + ~10.6 KB `pqc_auths` of a
  ~17–18 KB 2-in/2-out) ≈ 2.35 GB per 1 tx/block, 23.5 GB per
  10 tx/block, 235 GB per 100 tx/block. Q2 prices that against the
  scarcity it removes and the free regime it lengthens.
- *Uniformity, not consensus:* `W` decides no validity verdict, but
  under Q8 the window is what every daemon answers identically inside,
  so two releases with different `W` are distinguishable on the wire
  during rollout. `W` changes are network-uniform releases, stated as
  such (rule 71), and its home is beside `D_max`'s.

Whatever the number, the convergence statement in §8 is corrected to
**unconditional for running nodes with downtime under `W`, band 2 for
the rest** — which makes `W` visible as the thing that decides how
often the market is on the liveness path, where it should be.

### `PDM-Q3` RULED 2026-09-18 — The residual set is empty in the Rust validator by construction; the C++ residual is the serve-credit verifier and dies at E4

**Grounded at** `dev@20ebdf1e5`.

**Ruling, two sentences.** *Rust:* the instrument is `PDM-Q-F29` — `ChainView`
has no recorded-body accessor (`rust/shekyl-chain-rules/src/view.rs`, the
trait surface), so every rule is one a body-less node can run; it is a
property of a type that exists in code, held as a standing property in
`CHAIN_RULES_CRATE.md` §13 with a compile-shaped falsifier. *C++:* the one
residual consensus reader is `PDM-Q-F8`'s site — the **serve-credit
admission verifier** reading the leaf chunk (`get_curve_tree_leaf_chunk` in
`blockchain.cpp`, `:5327` at the pin, `:5099` today — cite the function,
the line has moved once). That is Q6 item 4 **row 1**, reopened as
consensus and deleted at **E4 / S-ARCH** when the preimage is re-keyed —
*not* the stripe engine's deletion under Q7 at `DRS-E*`: different site,
different lane, different reason. TJ's "node-local" sentence is true once
that verifier is the Rust one, and false before it (F8), as this charter
has said since the opening.

**Falsifier.** A `ChainView` method returning recorded tx bytes without a
`CenRow` and an above-`W` mark; or the C++ leaf read still live after E4's
verifier lands.

---

*The analysis below is the ground the ruling was taken on; its OPEN
framing is superseded by the block above.*


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
production consensus caller (`blockchain.cpp:5327`) and the RPC
path assembler (`shekyl-fcmp::rpc_path`, C++ callbacks in
`curve_tree_path.cpp`). RPC is not consensus.
The instrument Q3 names has to fail if a new consensus caller appears.

Do **not** re-derive in ignorance of TJ's already-stated sequencing
resolution (index `TJ-A…TJ-G` row): *the pruning MODE is node-local and
ships post-genesis without coordination (rule 75)*. That sentence is
about the mode not needing a coordinated hard-fork to *activate*; it
is not a claim that genesis ships before PDM exists (`PDM-Q-S0`), and
it is not a claim that leaf discard is node-local *today* (`PDM-Q-F8`).

### `PDM-Q4` CLOSED 2026-09-18 — Collapsed by F20 / F23 / F24; the TJ-F re-bind is stated

Nothing left to decide. No chain-following read reaches an archiver for a
node with downtime under `W` (F24); the daemon's fetches — band-2 fill,
recovery, history read-back — are episodic and optional (#775 admits
exactly these); and TJ-F is re-bound to the per-tx verify: a body-fill
read that does not hash to the retained rows fails loudly, never skipped.
Closed as a record.

---

*The analysis below is the ground the ruling was taken on; its OPEN
framing is superseded by the block above.*


Was: a node that discarded and now needs a leaf fetches from archivers;
distinguish *needs it to verify new blocks* from *needs it to assemble
a spend path*. Under F12 there is no leaf to fetch (leaves regenerate
from the skeleton), under Q3 the residual consensus read set after
TJ-A is expected empty, and under Q5's three-band model **no
chain-following read ever reaches an archiver**: new-block
verification uses the skeleton-derived state; reorg pops need full
transactions, which are inside the uniform bytes window `W ≥ D_max`
(Q2, F10's predicate); trim's leaves regenerate. A running node whose
downtime is under `W` never contacts an archiver; one down longer
re-enters Q5's band 2 for the blocks it missed (`PDM-Q-F24` — which is
why `W` is a minted parameter and not `D_max`). What remains of Q4 is
the list of **optional-to-chain-following** fetches the daemon makes —
Q5's band-2 body fill (fresh node, or returning node past `W`), Q9's
recovery of its own retention exceptions, and history read-back
(reveal-and-check) — and the TJ-F rebinding. **TJ-F rebinds to the
per-tx verify** (sentence owed 2026-09-13, now stated): TJ-F
(`ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md:269`, "verification must fail
against a poisoned leaf store") froze a *behaviour*, not a concept.
Under Q6 there is no leaf store to poison and no responder in the
new-block path, so the behaviour re-binds one unit over: **a body-fill
read whose revealed bytes do not hash to the retained
`txs_prunable_hash` / `txs_pqc_auth_hash` row must fail, loudly, and
must not be silently skipped** — the same invariant, and the one Q5's
`fetch_prunable_range` is verified against. The membership-path
assembly client ([`CURVE_TREE_CLIENT.md`](../design/CURVE_TREE_CLIENT.md) item
(b)) is a wallet concern over the skeleton, not a daemon fetch.

### `PDM-Q5` RULED 2026-09-18 — The anchor, the bands, the launch window; `Trust::BelowAnchor` confirmed

**Grounded at** `dev@20ebdf1e5`; `connect.rs:281-329` and `error.rs:273` read
at source.

**Ruling.** The anchor model as restated 2026-09-13 stands: a release-carried
checkpoint `C` on the `assumevalid` argument; three bands (`≤ C` skeleton,
trusted with the binary; `(C, tip − W]` filled from archivers; above from
peers); the tip-relative trust horizon and the operator trust-below
fallback **REJECTED**. The items it owed:

- **Launch window** — narrowed by Q2: band 2 is empty until the chain is
  `W` old (`(0, tip − W]` is empty while `tip < W`), so the item is *first
  checkpoint release before day ~195, then release cadence `≤ W`* so `C`
  never falls more than `W` behind the tip.
- **Release-gate full-verify step** — a process sentence: the release that
  carries `C` is built from a node that verified every proof to `C` with
  `assumevalid = 0`; recorded in `SIGNING.md`'s release flow when the first
  checkpoint ships.
- **Band-2 egress** — a formula, not a decision: release gap × tx rate ×
  ~16.7 KB/tx (F24), bounded above by `W` × rate × 16.7 KB.
- **The anchor check's home** — `CEN-E1` (Q11: the equality rule is the
  anchor's own; `CEN-E2` is `D_max`'s), re-keyed in F27's PR (F30).
- **The Q11 ordering** — discharged by Q11 (the anchor is `D_max`'s
  precondition).
- **F27's mode — CONFIRMED: `Trust::Full | BelowAnchor(anchor)`, an input
  to `validate` orthogonal to `RuleSet`.** Nearly forced: `connect` refuses
  any verdict judged under a set that is not `rules_at(height)` —
  `StoreCannot::RuleSetNotInForce`, `rust/shekyl-chain-store/src/store/connect.rs:281-329`,
  `error.rs:273` — so a *below-anchor `RuleSet`* would be refused by the
  store's own check; the orthogonal input is the only shape that does not
  touch it. Under `BelowAnchor` the proof rows are not run, their absence is
  recorded in `RuleCoverage` and `connect`'s provenance (so a band-1 file is
  never parity evidence), and the `in_force` check is untouched. E6's, to
  land in slice 3 or 6 with the `CEN-E1`/`E2` re-key.

**Reversion.** As restated 2026-09-13, plus: the `Trust` shape reverts if
`connect`'s `in_force` check is shown to admit a second set per height —
falsifier: `RuleSetNotInForce` removed or widened.

---

*The analysis below is the ground the ruling was taken on; its OPEN
framing is superseded by the block above.*


A new node must reach tip. Today's answer is that cold-sync clients
scan against foundation `--no-prune` nodes
([`REFRESH_DESIGN_LANDSCAPE.md`](../design/REFRESH_DESIGN_LANDSCAPE.md)) — a
centralisation dependency wearing a pruning costume. Also
[`CURVE_TREE_CLIENT.md`](../design/CURVE_TREE_CLIENT.md) item (b).

**The fork (`PDM-Q-F20`).** At the pin a syncing node verifies every
FCMP++ proof and PQC signature in every historical block; the only
skip is the pool-admission cache (`blockchain.cpp:5978`, a tx verified
at admission is not re-verified at inclusion, structural checks still
run), and there is no checkpoint-zone or fast-sync path that trusts
old proofs (`:5681` is commented out; `:5722` is checkpoint *hash
matching*). Under Q6 the historical proofs are exactly the discarded
good, so a fresh node either (1) fetches the **entire** good from
archivers once per new node — archivers load-bearing for onboarding,
egress ∝ chain length × new nodes — or (2) trusts the skeleton below a
horizon and verifies proofs only above it. The skeleton suffices for
*state* either way (F20 (c): curve tree from `outPk` + `vout` +
`tx_extra` 0x07 per F12, `spent_keys` from the prefix, archival tables
from kept-side headers); the fork is about *proof*.

**(2) is right; the horizon is not `D_max`.** The proposed argument —
"below `tip − D_max` no verification outcome can change what the node
does" — conflates *revert* with *reject*. A running node has already
verified every block at the tip, so for it the sentence is vacuous; a
fresh node has nothing to revert and everything to reject, and
refusing a chain is the action a failed proof enables. Take proofs
away below a tip-relative depth and the only criterion left between
two histories is cumulative work. Run Q11's own adversary (rentable CPU
≫ a young chain's hashrate): build a heavier chain from any deep fork
point with an inflating invalid proof in it. Running nodes refuse it
on `D_max`; **every node that syncs fresh accepts it on work**; the
network splits by *sync date* with inflation on the new side, and no
eclipse was needed — cheapest exactly where Q11 says the chain is most
exposed. Full verification is what makes Q11's visible-split failure
mode *recoverable* (the heavier chain is heavier *and invalid*, so the
split resolves toward the checkers); a tip-relative trust horizon
deletes the recovery. **The horizon must be an anchor the node brings
with it.**

**The anchor is the release-carried checkpoint, on the `assumevalid`
argument.** The operator already trusts the binary's verifier; trusting
the same binary's assertion "block `C` has hash `H`" adds no trust
party. The machinery exists and is empty at the pin (`PDM-Q-F23`).
Three bands:

| Band | Range | Bytes from | Proofs |
| --- | --- | --- | --- |
| 1 | `≤ C` | skeleton, any peer | trusted with the binary; state built per F20 (c) |
| 2 | `(C, tip − W]` | archivers, over the fetch primitive (onion) | fetched and verified per-tx against the retained hash rows |
| 3 | `(tip − W, tip]` | ordinary peers, P2P, inside the uniform bytes window `W ≥ D_max` (Q2, `PDM-Q-F24`; `PDM-Q8`) | verified as today |

Band 2 is **the release gap** for a fresh node and **the downtime
past `W`** for a returning one (`PDM-Q-F24`): near zero on a current
binary with downtime under `W`, larger otherwise, and always **loud** ("unverified `[a, b)`", never a
silent `INTERNAL_FAILURE` per F8b, never a quiet fall-through to
trust-the-txid — `--sync-pruned-blocks`, `cryptonote_core.cpp:127-130`
/ `cryptonote_protocol_handler.inl:139-152`, is the inherited
trust-the-txid form and must not become the default). The band-2 fetch
client lives in the **daemon** (its Tor zone,
[`DAEMON_RELAY_PRIVACY.md`](../design/DAEMON_RELAY_PRIVACY.md)) so a bare daemon
can become a validator; serving stays behind the wallet. Primitive:
`fetch_prunable_range(a, b)`, verified per-tx; callers: band 2 here,
Q9's recovery fetch, history read-back. Transport is the `SF-` round's
(PR #714, RULED 2026-09-13 — `PDM-Q-F25` on what Q6 changes in it);
Q5 states what the caller needs from it.

**The anchor is disableable in one direction only.**
`assumevalid=0` (verify everything from genesis, band 2 = the whole
chain, at the operator's own cost) exists. **REJECTED 2026-09-13,
recorded so it is not re-proposed:** the opposite switch — an operator
accepting an unfillable band 2 *unverified*, "trust-below" as a
fallback for a persistently unavailable range. That override is
precisely the surface the anchor closes: the operator has re-opened
the heavier-invalid-chain vector for themselves. The correct recovery
from an unfillable band 2 is **a newer release that moves `C` up**, not
a trust switch. Reopening criterion: a proposal whose trust basis is
something other than cumulative work would be a new argument, not this
one; none is anticipated.

**What a ruling owes (the gaps, adversarially positioned):**

1. **Release cadence is a security parameter, and the genesis period
   is its worst case.** "Near zero on a current binary" holds only
   once a post-genesis release has shipped a checkpoint. Between
   genesis and that release `C = 0` and every fresh node's band 2 is
   the whole chain — small in bytes, but the property *fresh nodes do
   not need archivers* is **false for the launch window**. Name the
   window; it is where Q9's coverage floor is load-bearing rather than
   convenient, and it makes the first checkpoint release a scheduled
   launch-plan item.
2. **The checkpoint's semantics are stronger than Monero's — a
   release-gate obligation.** A Monero checkpoint pins a hash to
   forbid reorg below it. An `assumevalid` anchor additionally asserts
   *every proof below this was valid*. Someone establishes that: a
   full-verify node (`assumevalid=0`) run to `C` **before the release
   is cut**, by the release signer. That step is what the
   trust-the-binary argument silently depends on; it goes into the
   release discipline by name (`docs/SIGNING.md` / rule 06's release
   flow), not assumed.
3. **`load_checkpoints_from_json` is a deletion target, not an unused
   option.** Live at `blockchain.cpp:6635` and reloaded every ten
   minutes from `cryptonote_protocol_handler.inl:698` (the DNS half is
   already gone, per the comment there). A runtime-loadable checkpoint
   file is a trust channel that bypasses the release-carried anchor —
   the exact surface the anchor argument says is worse than
   coordination. Rule 15/60. **Landed in PR #733 (2026-09-13):**
   `load_checkpoints_from_json`, `core::update_checkpoints` and the
   ten-minute reload are deleted; the compiled-in set is enforced once at
   init by `Blockchain::enforce_checkpoints`. Populating the table is
   still the release-gate obligation in item 2.
4. **Band 2's egress number.** Bounded by release gap × tx rate, not
   chain length — but it is the one place archivers carry sync load.
   Archiver economics are stated against **band-2 sync egress +
   challenge egress + recovery egress**, not left as "near zero".
5. **Ordering with Q11.** `is_alternative_block_allowed` refuses
   reorgs below the last checkpoint; `D_max` is the rolling cap above
   it — one function, two bands. **The checkpoint is a precondition
   of `D_max`, not a sibling**: `D_max` binds only once a node has an
   anchored chain, and a node with an empty checkpoint table has no
   cap at all, which is the pin today.

### `PDM-Q6` RULED 2026-09-17 (items 1–3), item 3 AMENDED and item 4 RULED 2026-09-18 — The prunable region and `pqc_auths` are the archival good; a shard is a byte-bounded `tx_id` range, discarded whole

**Grounded at** `dev@4bc378d68` (2026-09-17); `#768` (E6 slice 1 —
`TxIdentity.pqc_auth_hash` and the wire's txid module; read at head
`245a60761` when ruled, **merged the same evening as `398d85e7b`**)
and `#770` (§3 walk; merged `071dfd2f5`) read at their heads and
treated as authoritative per steering. Cites below were re-verified on
`dev@eac99894a` after #768 and #771 merged. Items 1–3 ruled 2026-09-17;
**item 3 amended (`PDM-Q-F32`) and item 4 ruled 2026-09-18** at
`dev@20ebdf1e5`, after a source read of `wire.rs`, `codec/chain.rs` and
the serve-credit call site that the first item-4 draft had skipped.

**Item 1 — the good.** The archival subject is the transaction's
prunable region (`CtSigPrunable`, `src/fcmp/ct_types.h:333`) for every
transaction below Q2's `W`. The unit of possession is one transaction's
`CtSigPrunable` bytes; the unit of verification is its
`txs_prunable_hash`, a txid component every node retains forever.
Grounds: `PDM-Q-F12` (leaves are a cache of the base) and `PDM-Q-F13`
(the prunable region is original, admission-only, and every byte replay
needs lives in the other half). Nothing else in §9 is scarce.

**Item 2 — the second occupant.** `pqc_auths` enter the good on
identical terms, verified by `txs_pqc_auth_hash` — the txid's third
component, count-prefixed (`rust/shekyl-wire/src/transaction/txid.rs`,
`Transaction::txid_parts()` / `pqc_auth_hash()`), `Option`-shaped (`None` ⇔ 3-part txid), never a
sentinel. This **ratifies a landed default**: `TxIdentity { hash,
pqc_auth_hash: Option<PqcAuthHash>, prunable_hash }`
(`rust/shekyl-chain-rules/src/block.rs:52-59`), and the
store row `txs_pqc_auth_hash` landed by `DAEMON_REDB_STORE.md` §7.7
item 3 on S-CHAIN-R's layout commit (PR #772). Items 1 and 2 are one ruling: ~95 % of transaction
bytes jointly, neither defensible alone (`PDM-Q-F14`). No tx blob byte
and no txid changes.

**Item 3 — shard membership.** A shard is a **`tx_id` range**
`[k·T, (k+1)·T)` over the store's monotone transaction index
(`tx_id = get_tx_count()` at insert, KEEP-C). Membership is derived —
`tx ∈ s ⇔ ⌊tx_id / T⌋ = k` — and nothing joins the retained set for
it. `height(tx)` for the F10 discard predicate is one `tx_indices`
lookup. Chosen over the height range (byte size floats with
throughput, breaks per-shard pricing) and the leaf segment (needs
`output_to_leaf`, graded CACHE, to become load-bearing). Keeps
`RF-D6`'s fixed cardinality without keeping a mapping. **One unit,
three surfaces:** the bond's `holdings`, `PDM-Q-F17`'s wire echo, and
the challenge draw all name the same `tx_id` range; §3's stripe/shard
item discharges on that identity and reopens if any of the three names
a different unit.

**Item 3 AMENDED 2026-09-18 (`PDM-Q-F32`) — boundaries by bytes, from
a retained length row; discard is shard-granular.** The fixed
cardinality `T` above is **superseded** (kept for the record). It was
chosen because it was derivable for free, and that was the wrong
property to fix: `T` was never given a value, `T × MAX_TX_SIZE`
(`MAX_TX_SIZE = 1_000_000`, `rust/shekyl-wire/src/transaction.rs:135`)
makes the worst-case shard `T` megabytes and `max_body_bytes()` a
multi-gigabyte in-flight ceiling at `SF-D7`'s `N = 8`, `SF`'s `N` and
`L` were measured against a fixed 3.33 MB (§9.1 (c), PR #746), and
cardinality pricing mis-prices shard compositions by up to ~60× while
a discarded shard's true size is unrecoverable. So:

- **Length rows.** At connect the store writes, beside the hash rows
  and sparse on the same predicates, the byte length of each
  transaction's prunable region (`u32`, present ⇔ the region is
  present) and of its `pqc_auths` segment (`u32`, present ⇔ 4-part
  txid). Permanent, never discarded, journaled, SI-9-fresh. ~8 B per
  transaction against the ~16.7 KB they let a node discard. **S-CHAIN-W
  amendment A4**, same rung as A3 (the hash row); the §7.7 invariant
  gains a **fourth leg**: length row present ⇔ hash row present.
- **Boundaries.** Shard `k` is `[b_k, b_{k+1})` where `b_0 = 0` and
  `b_{k+1}` is the first `tx_id` at which the cumulative sum of the
  two length rows over `tx_id` order reaches `(k+1) · SHARD_BYTES`.
  `SHARD_BYTES` keeps `RF-D6`'s 3.33 MB; a shard's byte size is
  bounded by `SHARD_BYTES + MAX_TX_SIZE` and its *actual* size is
  known from the rows. Cardinality floats. `max_body_bytes()` is
  `SHARD_BYTES + MAX_TX_SIZE`; `SF`'s `N` and `L` stand as measured.
- **Derivability — the reason for the rows.** A first draft defined
  `b_*` over cumulative *prunable bytes* and called the table KEEP-C.
  A band-1 node never had those bytes, and replay-that-validates from
  the skeleton (DRS-D10, `S0`'s only writer) could not recompute them
  — derived consensus state the skeleton cannot rebuild, which is
  this ruling's own reversion criterion (b), written a day earlier.
  With the length rows retained, `b_*` is derivable from retained
  state on every node including skeleton-only, and (b) holds by
  construction. Membership is a binary search over `b_*`
  (recomputed or cached; either way derived, never received).
- **`height(tx)` is not a `tx_indices` lookup** — `tx_indices` is
  keyed by tx *hash* (`codec/chain.rs:126-135`), so from a `tx_id` the
  lookup needs the body it is deciding whether to delete. The
  primitive is `first_tx_id(h) = block_info[h−1].cumulative_tx_count`
  (the FL-R3-STORE running total, `BlockInfo.cumulative_tx_count`,
  landing on #772), and `tx_id` is monotone in height.
- **Shard-granular discard** (Q2 restates the predicate): shard `k` is
  discarded **atomically** when its *last* transaction crosses the
  horizon — `b_{k+1} ≤ first_tx_id(tip − W)` — never a transaction at a
  time. On an ordinary node a shard is entirely present or entirely
  absent, which is what `get_prunable_range`, Q10's "not retained"
  answer, the whole-shard read and the three-leg invariant all
  assume. Pops are unaffected: a block within `D_max` has its
  transactions in shards whose last tx is above `tip − W` (`W ≥
  D_max`, F10). **Consequence for the market:** a shard is
  **specified** when `b_{k+1}` closes (membership final, bondable from
  `close_height(k) = height(b_{k+1})`, itself a binary search over
  `cumulative_tx_count` — no new state) and becomes **scarce** only at
  `discard(k)`, `≥ W` blocks later because its last tx is the youngest
  thing in it. Between the two every ordinary daemon still holds it, so
  the archiver's **wallet pulls `k`'s bodies from its local daemon** over
  the operator leg into the wallet-side store, with nothing to fetch
  from the network (amended 2026-09-18 on #775 / Q9 — the daemon itself
  retains nothing); "shard `k` is now scarce" is one chain-derivable
  event every node agrees on; and the **open frontier shard** (no
  `b_{k+1}` yet) is **not bondable** — a clean `HoldingsUpdate`
  admission rule the per-tx model did not give. Every shard therefore
  has its own `≥ W` window of being bondable while universally held;
  the launch free regime (§3) is the first instance.

  **Routed to the reward leg (`REWARD_EMISSION_LEG.md`), with the trade
  and a proposed mechanism — not ruled here.** *Why this is not the case
  the bootstrap ruling covered:* the launch free regime is one window,
  once, and Component 4's ruling that it is a subsidy was a ruling about
  *launch*. Under shard-granular discard every shard the chain ever
  produces has its own `≥ W` window of being bondable while universally
  held — **steady state, recurring, not bootstrap** — so the §3
  `bond_duration ≥ W` withdrawal does not reach it, and the reward leg is
  asked a question the bootstrap ruling did not answer: at what weight
  does channel 1 pay a bond on an in-window shard? *The trade:* **from
  bond**, a single early bonder earns maximum scarcity weight
  (`1/R_market` with `R_market = 1`) on a good every node holds, for
  `≥ W`, on every shard — it overpays, but it is *exactly the incentive
  the specified-to-scarce window exists to create*: commit to `k` before
  it is scarce so that scarcity arrives with holders; pay nothing early
  and every shard reaches `discard(k)` with zero bonds and the Foundation
  `CompleteTree` is the first and only holder of every freshly scarce
  shard, permanently — the structural floor doing the market's job.
  **From discard**, no overpay, no early bonders, and the window is a
  window nobody uses. **The window is load-bearing on this answer:** if
  channel 1 pays from discard, shard-granular discard still buys atomic
  scarcity and clean "not retained" semantics, but the staker-window
  rationale above does not hold. *A second gap, same place:* during the
  window `R_market(k)` counts **bonders**, not holders — every node holds
  it — so the self-dilution that discharged §3's Sybil item does not
  operate on in-window shards by itself; a `k`-persona bonder dilutes
  only against other bonders, of whom there may be none. The Sybil
  argument was made for scarce shards; the reward leg confirms it holds
  in-window or says what does.

  *Proposed mechanism (for the reward leg to rule or replace): a derived
  commitment weight, the median of what scarce shards are paying this
  epoch.* At each epoch boundary, for a closed shard `k` not yet at
  `discard(k)`:

  > `w(k, E) = median_{s scarce at E} ( g(age_s) / R_market(s, E) ) · 1 / R_market(k, E)`

  It prices a new shard at what a typical scarce shard pays *this epoch*,
  so it tracks the market rather than guessing it — under-held history
  raises the median and new shards pay well; good coverage lowers both —
  and it keeps `1/R_market(k)` on the new shard, so the self-dilution
  operates in the window too: a `k`-persona bonder splits the median `k`
  ways rather than earning it `k` times, which closes the second gap.
  **Where the constant lives:** before any shard is scarce there is no
  median — that is the launch window, chain younger than `W` — and only
  there is a flat **`w_launch`** needed, superseded by the derived median
  the epoch the first shard discards. So the tweakable governs ~195 days
  once, not every shard forever. *Bounds, adversary first:* **upper** —
  `w` must not outcompete the median scarce shard or marginal capital
  flows to new shards (free to hold, no fetch) and abandons old history,
  the harm that actually matters; the median enforces this by
  construction, `w_launch` must be set below where scarce shards will
  settle, which is the part needing judgement. **Lower** — `w` must
  exceed the cost of committing (bond lock + disk) or nobody bonds early
  and the floor is first holder of everything. **Adversarial** — moving
  the median means bonding many scarce shards, which is paying to hold
  history, the honest act; low leverage. *Deriving `w_launch`:* sim for
  the band where neither failure occurs (bounding, a legitimate sim use),
  then **Round-2 pins it with `n`, `D_max` and `W` on the same gate — a
  fourth numeric there**, not a fourth entry of a different kind. *Two
  things so the reward leg does not lose them:* (a) the median is over
  **scarce** shards only, and "scarce" is now one chain-derivable event
  (`discard(k)` at `b_{k+1} ≤ first_tx_id(tip − W)`), so the set is
  unambiguous and identical on every node — computable in the settlement
  writer without a new consensus object; (b) at the epoch of the first
  `discard(k)` the scarce set is **one shard**, so the median is a single
  sample for some epochs — the leg says when `w_launch` hands over (first
  discard, or a minimum scarce-set size). *Consensus:* `w` is computed by
  the settlement writer and every node must agree, so the **shape is
  genesis-frozen and the numeric provisional**, the same discipline as
  the other three — and it lands in `shekyl-chain-rules` under DRS-D12 /
  SO-D8 Q15, never in the C++ path.
- **The preimage terms** (item 4's consensus row): the serve-credit
  signature signs `shard_id` and `(b_k, b_{k+1})`, each **read by the
  verifier** from the retained length rows and `cumulative_tx_count`,
  never carried — the discipline `wire.rs:345-360` states today for the
  leaf terms, so nobody re-argues whether the prover could have chosen
  them.

**Item 3, the credit-wire collision — not reopened.**
`ARCHIVAL_CREDIT_WIRE.md` §3's `transfer_digest` rejection stands.
Under this unit a digest over the shard's *hash rows* is
admission-reconstructible — and therefore computable by any node that
possesses nothing, so it proves nothing about possession; a digest over
the shard's *bytes* remains non-reconstructible, so the original ground
holds. For any signed digest, admission-reconstructibility and
possession-discrimination are in opposition; the only escape is
reveal-and-check, which this unit supplies per-tx and which the
whole-shard topology read ([`ARCHIVAL_CHALLENGE_MECHANISM.md`](../design/ARCHIVAL_CHALLENGE_MECHANISM.md)
§9, *"the test IS a read"*) already uses. No signed content
artifact is added to the wire. Reopens only if the credit wire abandons
the topology read for a sampled test — in which case `PC-D3`'s draw
problem returns with it, and that is the credit wire's round to rule.

**Consequences, now in force.**

- `PDM-Q1` may be ruled; it grades §9 against this unit.
- `PDM-Q12` may be ruled; the commitment exists at ingest, and the
  segment freeze has nothing left to freeze under this unit (candidate:
  retires; `LeafStore` is a deletion target).
- `SF` sub-PR 2 is unblocked: frame codec and `ContentVerify` are
  per-tx against the two hash rows; `recompute_segment_r_k` does not
  survive (`PDM-Q-F25`). `SHARD_BYTES` **does** — as the boundary
  metric (F32), no longer as a fixed body size.
- `PDM-Q-F28` (skeleton wire carries `pqc_auth_hash`) is no longer
  gated on this question.
- `DAEMON_REDB_STORE.md` §7.7's three-leg invariant is the store's
  contract for this good: hash row ⇔ 4-part txid, permanent; segment
  present ⇒ hash row present; hash row present ∧ segment absent ⇔
  discarded or never held (band 1).

**Item 4 RULED 2026-09-18 — what the unit change re-keys and what it
reopens.** Grounded at `dev@20ebdf1e5`; `wire.rs`, `codec/chain.rs`
and the serve-credit call site read at source (the first draft did
not, and was wrong where it mattered — the consensus row below).

*Rule.* A closed ruling is **re-keyed** when its argument survives
with "leaf segment" → "`tx_id` range" and "`R_k`" →
"`txs_prunable_hash` + `txs_pqc_auth_hash`"; it is **reopened** when
its argument depended on a shared root, a fixed 128-byte claim, or leaf
addressing. Re-keys land as line-local edits under rule 23 in the
owning doc with a pointer here; reopenings get a dated sub-section in
the owning doc. **"Retired by ruling" and "retired in code" are
different states and the table says which.**

| Ruling | Disposition | Substitute |
| --- | --- | --- |
| **Serve-credit admission verifier** — `CEN-J*` / `CEN-L7–L10`; `shekyl_archival_verify_serve_credit_vin`; C++ site `src/cryptonote_core/blockchain.cpp:5085-5125` | **Reopened — consensus.** The hybrid-signature preimage signs two *verifier-derived* leaf terms, `segment_subroot_rk` and `leaf_index_in_segment` (`rust/shekyl-archival-retention/src/wire.rs:345-360`): `RF-D6` took them off the wire *because* the verifier rebuilds them from `LeafStore::frozen_segment` and `challenge_leaf_index`, and the C++ site does exactly that today (reads the leaf chunk, fills `ctx.registry_segment_subroot_rk` / `segment_leaf_count`). Under the tx unit neither exists. So the signed message of every pass record changes, and the admission rule changes with it. **"The wire sees no change" was true of bytes and false of the signed message, and the signed message is the rule.** | Preimage restated over `shard_id` and `(b_k, b_{k+1})`, each read by the verifier from the length rows + `cumulative_tx_count` (item 3 amendment); FFI contract (`registry_segment_subroot_rk`, `segment_leaf_count`, `leaf_layer_scalars_*`) replaced. **Landing site: E4 / S-ARCH in `shekyl-chain-rules`** — never `blockchain.cpp` (`S0`; SO-D8 Q14). No record signed under the leaf preimage verifies under the tx preimage; a genesis-frozen rule written before genesis, not migrated. CEN rows re-keyed in that PR. |
| `RF-D1` — `leaf_bytes`, 128 B on the kept vin (`ARCHIVAL_RESPONSE_FORMAT.md` §3.5) | **Reopened.** The claim was *one leaf*; under a whole-shard read there is no claimed transaction and no `tx_id` to claim — the identifier is `shard_id`, already on the vin. Kept side loses 128 B. | `RF-D1` re-prices the kept side (~230 B → ~100 B). The pruned half is the pass record's own `CtSigPrunable`, unchanged in kind. |
| `RF-D6` — `SHARD_BYTES = 25,992 × 128`; `segment_subroot_rk`/`leaf_index_in_segment` off the wire | **Reopened, and half survives.** The fixed byte *size* survives as the boundary metric (F32: `b_*` closes at cumulative `SHARD_BYTES`); the "leaves × 128" derivation and the two off-wire leaf terms do not. | `RF-D6` restates: `SHARD_BYTES` is the boundary metric, body size bounded by `SHARD_BYTES + MAX_TX_SIZE`; the off-wire terms become `(b_k, b_{k+1})`, verifier-derived on the same argument. |
| `challenge_leaf_index` + fire schedule; `c1_layers`/`c2_layers` path in the pruned record | **Retired by ruling (`RF-D8` (i) retracted 2026-08-26) — live in code.** `challenge.rs`, `path.rs`, `segment_freeze.rs`, `serve_credit_decisions.rs`, `wire.rs` (the `c1_layers` write at `:90`), the fuzz target, and the consensus call site all carry it. | **Deleted at E4 / S-ARCH** with the verifier row above. Not "no action". |
| `LeafStore::frozen_segment` + the freeze pipeline | **Retired → Q12; the store itself is rebuilt, not deleted** (amended on #775). | Derivable membership (item 3, F32); a body store keyed by shard over `[b_k, b_{k+1})`. |
| `SF-D7` — memory floor `N × SHARD_BYTES` | **Re-keyed.** The floor is a cap on in-flight bytes; `SHARD_BYTES` survives as the metric, so `N × (SHARD_BYTES + MAX_TX_SIZE)`. `N = 8` and the `L` candidate were measured at 3.33 MB and **stand** — the F32 amendment exists so they do. | Line-local in `ARCHIVAL_SHARD_FETCH.md`. |
| `SF-D8` — verify seam "local `R_k` + countersignature" | **Reopened (content half); re-keyed (countersignature half).** Content-verify is per-tx via `Transaction::txid_parts()` against the two hash rows, plus membership against `(b_k, b_{k+1})`; the `SF-D8` request countersignature (72-byte anchor header ‖ `shard_id`) is unchanged and lives in sub-PR 1 (`PDM-Q-F25`). | Sub-PR 2's `ContentVerify`, `expected = (txs_prunable_hash, Option<txs_pqc_auth_hash>)` per `tx_id` in `[b_k, b_{k+1})`. |
| `SF-D1` — addressing clause ("no leaf addressing; materialise the segment") | **Re-keyed.** No per-tx addressing on the route either; the read is still whole-shard. The clause's *reason* (`R_k` needs the whole segment) is gone; its *conclusion* (one resource, one path) stands on `RF-R1` alone. | Line-local. |
| `CR-D2` — carrier (pass-record partition) | **Re-keyed, kept side re-priced by `RF-D1`'s row** (~230 B → ~100 B). The partition itself is unchanged; the pruned half is inside the good (`PDM-Q-F15`). | Pointer, plus the re-price. |
| `TJ-D` — this charter as design home | **Re-keyed.** TJ-D named leaves; the home is the same, the subject moved. | The two reconciliations TJ-D owes are restated against the tx unit in its own row. |

*Consequence.* SF sub-PR 2 is unblocked with its verify seam's
`expected` named; the credit wire's **bytes** need no edit and its
**signed message and admission rule do** (row 1), which is E4's.

*Reversion.* A reopened row reverts to re-keyed if its owning doc shows
the argument never depended on the leaf property — falsifier: the
owning doc's dated sub-section cites no leaf-specific premise. A
re-keyed row reverts to reopened if a line-local edit fails to
type-check against the unit — falsifier: an `SF-D7` or `RF-D6`
constant still named in bytes-of-leaves after the edit. Row 1 reverts
to "no change" only if `wire.rs`'s preimage is shown not to include the
two derived terms — falsifier: `wire.rs:345` read again.

**Reversion criteria (rule 21).** This ruling reverts to OPEN if any
of: (a) a consensus reader of the prunable region or `pqc_auths`
appears outside admission — falsifier: `PDM-Q-F29`'s `ChainView`
surface acquires a body accessor without an above-`W` mark, or a rule
in `shekyl-chain-rules` reads a recorded body; (b) replay through
`apply_block` is shown to need a byte from either region — falsifier: a
derived table that `DRS-D10` replay cannot rebuild from the skeleton
alone; (c) the `tx_id` index stops being monotone or KEEP-C in the Rust
store — falsifier: `tx_indices` graded CACHE or below in DRS's
accumulator classes.

**Falsifiers on the ruling as landed.** A `TxIdentity` whose
`pqc_auth_hash` is `Some` for a 3-part txid or `None` for a 4-part one
is red (KAT on S-CHAIN-R's row). A bond `holdings`, wire echo, or
challenge draw expressed in a unit other than `tx_id` range is red. A
shard whose byte size is used for pricing without being bounded by
`T × max_tx_size` is red.

---

*The analysis below is the ground the ruling was taken on. It predates
the ruling; its OPEN framing and its item numbering as questions are
superseded by the block above, and it is kept as the record of how the
question was argued.*

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
(`output_key` from `vout`, `commitment` from `outPk`, the leaf commitment
point from `tx_extra` `0x07` — all in `CtSigBase` / the prefix). Discarding the
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
3. **What proves shard membership once the Merkle path stops doing
   it (added 2026-09-13, review).** Under leaves, one path against
   `R_k` proved two things at once — *these bytes are the leaf at this
   position* and *this position is in shard `s`*. Under a per-tx
   `txs_prunable_hash`, the verifier proves **integrity only**: these
   bytes are that transaction's prunable region. Shard membership
   becomes a separate derivation, and whatever establishes
   `tx → shard` joins the retained set. That is a new obligation the
   leaf formulation never had, because the path was doing the work
   invisibly. Two shapes: **derived** — if the shard is a height or
   tx-index range (the `PDM-Q-F17` stripe candidate is exactly this),
   membership is `height(tx) ∈ range`, read off `tx_indices` /
   `block_info`, which are KEEP-C, and costs nothing; **stored** — if
   the shard stays a leaf-position segment (`ShardSetCompact{ids}`
   over `[k·E, (k+1)·E)`), the `tx → leaf position` mapping
   (`output_to_leaf`, graded CACHE in §9) becomes load-bearing for
   membership and either joins KEEP-D or is re-derived on every check.
   Q6 names which, and the storage arithmetic follows.

   **Third candidate (2026-09-13): a `tx_id` range.** Height ranges
   (F17's stripe) derive membership for free but a shard's byte size
   then floats with throughput, which breaks per-shard pricing; leaf
   segments have fixed cardinality but need the stored mapping. The
   store's own transaction index is monotone — `tx_id =
   get_tx_count()` at insert (`db_lmdb.cpp:1068`, written at `:1090`),
   KEEP-C — so a shard as `[k·T, (k+1)·T)` in `tx_id` has fixed
   cardinality *and* derivable membership, and `height(tx)` for the
   F10 discard predicate is one `tx_indices` lookup. Q6 weighs it
   beside the other two; it is the candidate that keeps `RF-D6`'s
   fixed-size shard without keeping `output_to_leaf`.

   **The collision this surfaces is with the credit wire, and it cuts
   the other way from the one first reported.** The report read
   [`ARCHIVAL_PER_CHALLENGE_RECORD.md`](../design/ARCHIVAL_PER_CHALLENGE_RECORD.md)
   as a round in flight ruling on a leaf opening. At the pin it is
   **RULED 2026-08-24** and implemented, and then overtaken: `RF-D8`
   (i) was **retracted 2026-08-26** and the whole leaf-opening cluster
   — `challenge_leaf_index`, the fire schedule, the path opening — is
   on [`ARCHIVAL_CREDIT_WIRE.md`](../design/ARCHIVAL_CREDIT_WIRE.md) §2's
   deletion surface (`PC-D3`'s own disposition note says so: *"this
   hardened a function that DELETES"*, kept only as `TJ-1`'s interim
   mitigation). The successor is not a leaf opening of any unit: a
   *miner* attests it read the **whole shard** from `P`, `P`
   countersigns **the nonce alone**, and `ARCHIVAL_CREDIT_WIRE.md` §3
   rejected a `transfer_digest` because *"admission could never
   reconstruct the signed message"* — the shard bytes are off-chain.
   **Q6's unit changes that premise.** If the good is the prunable
   region, every node retains `txs_prunable_hash` for every
   transaction in the shard, so a digest over what the miner read
   **is** consensus-reconstructible: `H(txs_prunable_hash[t] for t ∈
   s)` is computable at admission from kept-side data. The credit
   wire's "no content binding on the wire, read-content binding from
   §9.4's topology" ruling was made under a unit whose verifier was
   not retained; Q6 supplies one that is. Whether that reopens the
   `transfer_digest` rejection is Q6's to say — it is the difference
   between a possession test that discriminates by topology and one
   that discriminates by hash — and it is stated here so the two
   designs stop ruling on the same object from opposite ends.
   Whichever lands second inherits the other's unit.

   On the amortization hazard the report expected the unit change to
   retire: **partly.** `PC` §2's defect — three countersignatures over
   one identical opening — is a shared-root problem, and a per-tx
   verifier has no shared root; that hazard is structurally gone under
   any sampled test over the new unit. `PC-D3`'s free-ride — keep the
   ~82 KB of predictable challenged leaves, discard the shard — is a
   **draw** problem, not a unit problem, and survives any test whose
   sample is precomputable, whatever the sample's verifier. Under the
   credit wire's whole-shard read neither is live; both return the
   moment sampling does.
4. **The unit change downstream (§5).** Every closed archival ruling
   defines the good as **leaves**: `SHARD_BYTES = 25,992 × 128`
   (`ARCHIVAL_RESPONSE_FORMAT.md` `RF-D6`), `challenge_leaf_index`,
   the 128-byte `leaf_bytes` claim in the kept vin (`RF-D1`),
   `LeafStore::frozen_segment`, the freeze pipeline's segment — and,
   RULED 2026-09-13 while this round was open, the whole `SF-` fetch
   contract (`PDM-Q-F25`: request unit a whole leaf shard by `u64`
   id, response a `ServedFrameHeader` leaf frame, content-verify
   `recompute_segment_r_k`). If the
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
5. **Self-reference — discharged (`PDM-Q-F15`).** `serve_credit_pruned`
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
6. **Depth floor from admission-only reads.** Everything in the good
   is re-read on a reorg re-verify and on nothing else. The inherited
   engine's `CRYPTONOTE_PRUNING_TIP_BLOCKS = 5500` is the Monero-era
   answer to this; Q2 gives Shekyl's, and F10's trim floor and this
   one are the same number or Q2 says which is larger.

Note the two readings of "prunable": the inherited `txs_prunable`
region is the `CtSigPrunable` sole occupant (§5 test); the outputs and
`tx_extra` that regenerate leaves sit in the *pruned* half
(`txs_pruned`, append-mostly) and stay. Q6 says which half every
sentence is about.

One boundary the verifier does not cover (`PDM-Q-F22`): the coinbase's
`prunable_hash` is `null_hash` by construction, so nothing on a
coinbase prunable side is committed to by `txs_prunable_hash`. Any Q6
shape that places archival evidence there verifies it against the
credit wire's block-level `attestation_root`, not the row. The
precedent is already written; Q6 cites it rather than rediscovers it.

### `PDM-Q7` RULED 2026-09-18 — The Monero-era stripe engine is removed completely; nothing of it survives as design

**Grounded at** `dev@20ebdf1e5`; anchors re-verified at source
(`shekyl-levin/src/payload/types.rs:104,149`,
`shekyl-rpc-types/src/p2p.rs:125,241,295`, `cryptonote_core.cpp:127`,
`cryptonote_protocol_handler.inl:1979` / `:2810`).

**Ruling.** The stripe engine's purpose — a node-local, seed-assigned
partition of history with a wire advertisement and complement-seeking
peer selection — is **superseded by the archival staking system**, and
its implementation is not carried forward in any form. **Nothing of the
engine survives as design.** Its three transferable parts
(`PDM-Q-F17`'s triple) each have a successor that is not it:
**assignment is the bond** (`holdings` on-chain — Q9's source ruling:
the chain, not the wire, is authoritative); **advertisement is the
bond**; **coverage is price** (`1/R_market`, `REWARD_EMISSION_LEG.md`
channel 1). F17's "worth taking" is **refuted** as a candidate and kept
as the record of one considered and refused; Q9's
holdings-advertisement sub-question closes as *none on the wire*.

**What "completely" is, by surface.**

| Surface | What | Disposition |
| --- | --- | --- |
| C++ engine | `prune_worker`; `check_pruning`, `get_blockchain_pruning_seed`, `prune_blockchain`, `prune_tx_data`, `update_pruning` (five of S-PRUNE's six); `CRYPTONOTE_PRUNING_*`; `src/common/pruning.{h,cpp}`; `--prune-blockchain` | **Dies at `DRS-E*`** with the C++ store (`PDM-Q-S0`: no C++ deletion before the cutover). Not ported: S-PRUNE is a *refusal* to port, not merely a non-extraction. |
| C++ sync | `--sync-pruned-blocks` (`arg_sync_pruned_blocks`, `cryptonote_core.cpp:127`) | **Deleted under `PDM-Q5`'s rejection, not under this ruling's "engine"** — it is trust-the-txid-skip-the-proofs with *no anchor*: Q5 REJECTED trust-below-`D_max` as a posture *with* a reorg bound, and this flag is that posture with none — a live implementation of a rejected ruling. Band 1 under the anchor (Q5, F28) is the successor and the only skeleton-sync path the design admits. Recorded here so the reason survives the engine's deletion. |
| P2P wire | `pruning_seed` on `CORE_SYNC_DATA` and every peerlist entry; Rust mirror `shekyl-levin/src/payload/types.rs:104,149` (`opt_u32`, default 0) | **Retired, two halves:** a Rust daemon **sends `0`** — the C++ "unpruned" sentinel (`handler.inl:1979`, `:2810`), so legacy peers read it correctly through the transition — and **ignores** any non-zero it **receives** from legacy C++ peers; the ignore becomes a *drop reason* only after the C++ emitter is deleted. No framing change. A `PWC-` census row (FOLLOWUPS). Closes `PDM-Q8`'s residue: retention reaches no wire. |
| RPC | `pruning_seed`, `next_needed_pruning_seed` (`shekyl-rpc-types/src/p2p.rs:125,241,295`); methods `prune_blockchain`, `get_blockchain_pruning_seed` | Fields dropped at the `CORE_RPC_VERSION` bump the cutover already owes; the two methods **REJECTED** in the daemon method registry (rule 23 namespace protection — a refused name stays in its table; `DAEMON_RPC_KV_CUTOVER.md` RK-8 marked). |
| Rust successor | S-PRUNE ([`DRS_E1_SPRUNE.md`](../design/DRS_E1_SPRUNE.md) §1) | Reads nothing from the engine. The seed arithmetic is not the shard definition (F32's byte-bounded `tx_id` ranges are); the wire slot is not the advertisement (the bond is); peer preference is not coverage (price is). |

**The other half — unbonded retention: PERMITTED, in the wallet-side
store, never the daemon** (amended 2026-09-18 on #775 / Q9: a keep-all
*daemon* is a fingerprint under the uniformity corollary — all daemons
prune; the reasoning below stands, the home moves). Retention and
serving are different acts. An unbonded operator fills a wallet-side
store exactly as a bonded one does, reaches no wire under `PDM-Q8`, and
is the structural floor Q9 and Q5 name (Foundation `CompleteTree`
behind a Foundation persona, explorers, an altruistic keep-all store). Adversarially: a hazard would have to be
either a wire-visible difference (Q8's indistinguishability test says
no) or a way to earn without a bond (serving needs the persona and the
countersignature, so no). An unbonded full archive is a node that paid
its own disk to hold history and cannot be paid for it. That is a
floor, not a hazard. The 2026-09-12 sequencing rulings stand: the
**opt-in flag is rejected** for the *universal* set (every daemon
discards identically); *exceptions* exist above `W` and are not what
makes a node an archiver.

**Reversion (rule 21).** The engine half reopens only if a band-2
fetch path is shown to need holder discovery from anywhere other than
the on-chain bond table — falsifier: a `PFetchClient` caller that reads
a peer-advertised holdings hint. The unbonded half reopens if an
unbonded wallet-side store is shown to reach the wire — falsifier: Q8's
indistinguishability test red on a host with such a store and no bond.

**Falsifiers.** A non-zero `pruning_seed` **sent** by a Rust daemon is
red (received non-zero is *ignored*, not red, until the C++ emitter is
gone). Any `prune_worker` / stripe symbol in `rust/` is red. A
`--prune-blockchain` or `--sync-pruned-blocks` flag in the Rust
daemon's CLI is red. `prune_blockchain` or `get_blockchain_pruning_seed`
routed in the Rust daemon RPC is red. An unbonded wallet-side store distinguishable on the wire is red; an
unbonded *daemon* retaining past `W` is red (Q9, #775).

---

*The analysis below is the ground the ruling was taken on. It predates
the ruling; its PARTIAL framing, and F17's "reference" reading of the
engine, are superseded by the block above.*

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

**Still OPEN (added 2026-09-13):** under Q9's candidate — the daemon
holds shards as a *retention exception* on the universal discard
predicate — the exception list is configuration that reaches the
daemon over the operator leg, and an **unbonded** operator can set it
(a Foundation full archive, a block explorer, an altruistic keep-all
node). Q7 says whether that is permitted. The reading this charter
records as the candidate: **permitted, because retention and serving
are different acts** — the bond is what *serving* needs (persona,
countersignature, credit), and with `PDM-Q8`'s ruled P2P uniformity an
unbonded exception affects only local disk and local fetch avoidance,
reaches no wire, and is the structural coverage floor Q9 and Q5 (band 2, the launch window)
want. Q7's "not an operator switch" then reads: the *universal* set has
no switch; *exceptions* exist and are not what makes a node an
archiver. If Q7 rules the other way it names why an unbonded full
archive is a hazard and not a floor.

**Still OPEN:** the standard process (what every daemon retains and
discards) is Q1–Q6 and Q8. Q7 does not re-derive it. Read
[`ARCHIVAL_PASS_RECORD_CARRIER.md`](../design/ARCHIVAL_PASS_RECORD_CARRIER.md)
`CR-D2` for the p2p-visible residue the stripe scheme currently
carries; that residue dies with the engine at the cutover, or it is
named as something the standard process must still speak.

### `PDM-Q8` RULED 2026-09-18 — Serve-side uniformity (ruled 2026-09-13) and the fetch side, closed by citation

**Grounded at** `dev@20ebdf1e5`.

**Serve side (ruled 2026-09-13, stands, and #775 strengthens it):** P2P
body-serving is uniform inside `W` on every daemon; beyond-window serving
is wallet-fronted over onion only; retention never selects wire behaviour
— and, per #775, never selects *disk* either: no archival serving state on
any daemon, all daemons prune uniformly (Q9).

**Fetch side — walked (§3, this thread) to no standing adversary, closed by
citation.** The fetcher is a Tor client with no address (`SF-D3`, SOCKS5h);
challenge and organic reads are indistinguishable on the wire —
`ARCHIVAL_CHALLENGE_MECHANISM.md` §9 (*"the test IS a read"*) with the
`SF-D5` / `SF-D8` nonce-anchor header as the mechanism, and organic
selection a uniform memoryless draw (`SF-D10`); the **persona** never
fetches — its **daemon** does, episodically, as that Tor client, so
serve-and-fetch are co-located at the host and unjoinable on the wire;
visualiser traffic is organic cover; `P → shards` is public by design
(the bond post). Every one of those is a ruling or a code property.

**Bounded exception, named:** two releases with different `W` are
distinguishable during a rollout (Q2). **Falsifier:** Q8's
indistinguishability test red on any host — bonded or not, serving or
fetching.

---

*The analysis below is the ground the ruling was taken on; its OPEN
framing is superseded by the block above.*


Two directions, both load-bearing under `00-mission`. Pruning lowers the
cost of running a node, which raises node density. Fetching a specific
shard on demand reveals interest in that shard — a discard-then-fetch
design leaks a query pattern that universal retention does not. Wargame
the fetch side: who observes the request, what it discloses, and whether
cover traffic, batching, or oblivious retrieval is required. Do not let
the density argument absorb the query-privacy argument.

**Ruled (steering, 2026-09-13) — P2P body-serving is uniform on every
node.** The hazard it closes (`PDM-Q-F21`): the bond publishes shard
`s` on-chain; if an archiver's daemon answered P2P requests for
beyond-window bodies in `range(s)`, the one clearnet peer that serves
those bodies *is* that persona's daemon — a Model D breach by
inference, with the linking fact (`s`) supplied by the chain itself.
The rule: **every daemon serves transaction bodies over P2P only
inside the universal window, and refuses identically outside it,
regardless of what it retains locally.** Retention selects data;
it never selects wire behaviour (rule 71's shape, applied to the
serve side). Consequences, recorded as they follow:

- All beyond-window *serving* is wallet-fronted over onion, under a
  persona, as today (`shekyl-p-host`). The daemon never learns, and
  never reveals, which of its retained ranges is anyone's shard.
- The `NOTIFY_REQUEST_GET_OBJECTS` serve path
  (`cryptonote_protocol_handler.inl:963`) and its `req.prune` /
  `should_ask_for_pruned_data` negotiation (`:2343-2346`) are the
  Monero-era surface that made retention *visible* on the wire
  (`CR-D2`'s residue); under this ruling the successor has one
  answer inside the window and one refusal outside it, and no
  per-peer retention negotiation. `pruning_seed` on the wire carries
  information only for archivers (F17 (c)) — and after this ruling it
  should carry none for them either on the *daemon's* P2P identity;
  the advertisement Q9 owes belongs to the persona, not the peer.
- The fetch client for body fill therefore lives in the daemon and
  reads over onion (Q5, band 2); it is the *serving* act that stays
  behind the wallet.
- Test: an archiver daemon retaining `range(s)` and a non-archiver
  daemon must be indistinguishable to any P2P peer across every
  request in the protocol. The edit that makes it red is a serve
  path that consults the retention set outside the universal
  window.

This is the design that has been intended throughout; it had not been
stated. **Still OPEN:** the fetch-side wargame above, now over the
onion leg to archivers rather than over P2P.

### `PDM-Q9` RULED 2026-09-18 — The archiver's retention set lives in the wallet-side store; the daemon holds no archival serving state

**Grounded at** `dev@20ebdf1e5` and PR #775 (`docs/two-store-daemon-uniformity`,
head `e2b6b87f6`, **OPEN at ruling**, read in full and treated as
authoritative per steering — `PDM-Q-F33`).

**The ruling that decides it is #775's, not this round's.** The daemon
holds **archival consensus state** — bonds, serve credits, settlement,
slash — because every daemon validates those and they are uniform by
definition. It holds **no archival serving state, ever**: the daemon is
the one publicly addressed process, and any *persistent,
posture-correlated* state in it is a fingerprint for as long as a bond
lives. **Episodic** actions any daemon takes — a shard fetch to inspect
the visualiser, to confirm a transaction, or as the witness verifying a
challenge it drew — carry no posture signal and are admitted. And the
**corollary, RULED with #775: all daemons prune uniformly** — if
archiver operators tended to run full daemons, "runs a full node" would
be the fingerprint with no archival code involved. PDM owns the default
and carries that constraint.

**The candidate this charter carried is REJECTED and withdrawn.**
*"The daemon holds the shard as a retention exception on the universal
discard predicate"* (2026-09-13, Q9 body below; Q12's `FrozenSegmentPruned`
substitute; F32's staker sentence; Q2's `k ∉ exceptions` conjunct; the
skeleton's §4) is durable, bond-correlated state on the daemon — the
fast path by another name: the daemon keeps bytes so the wallet can
serve them, and every form of it makes an archiver-backed daemon differ
from a plain one. Rejected under #775's own reopening criterion (only
archival serving becoming *universal* dissolves the line). Q8's
uniformity test would have passed it because it looked only at the
wire; #775's criterion looks at the disk, and is the stronger one.

**What remains of Q9 under the line — almost everything dissolves.**

- *Source* (ruled 2026-09-13, stands): shard retention is the bond
  process; `holdings` are on-chain.
- *Binding:* **nothing.** The wallet holds the bond and the store. No
  `p_canonical_id` on the daemon, no `retain(k)` / `release(k)`, no
  operator-leg configuration of retention. The keys-versus-ranges fork
  the previous pass set up does not exist.
- *RPC:* **no new surface.** `get_prunable_range` is **withdrawn**. The
  wallet reads in-window bodies from its own daemon through the
  ordinary transaction-body read every wallet already makes
  (`get_transactions`' split form, `shekyl-daemon-rpc/src/methods.rs:552-605`)
  — uniform because every daemon serves its operator that way.
- *Lapse:* the wallet-side store's — how long a shard is held after a
  release, and what enforces it. #775 routes it: *"retention has two
  owners now"*, FOLLOWUPS row, owner named there
  (`ARCHIVAL_SERVING_ROUTE.md`; enforcing site `shekyl-curve-tree`'s
  store).
- *Coverage floor:* **structural and counts personas** (§3 Sybil walk,
  Q7) — Foundation `CompleteTree` **in a wallet-side store behind a
  Foundation persona**, never on a daemon; #775's review record folds
  archiver-store durability as an operator's trade, not the network's
  floor (`FOUNDATION_ARCHIVAL_DISCLOSURE.md:196`, `V3_STAKER_ARCHIVAL.md:120`).
- *Recovery:* the ordinary primitive. The daemon fetches
  **episodically** (`PFetchClient`, as a Tor client with no address —
  witness, visualiser, recovery are indistinguishable on the wire),
  hands the shard to its wallet over the operator leg, **retains
  nothing**.
- *Advertisement:* none on the wire (Q7 closed it; the bond is the
  advertisement).

**The one sentence Q9 still owed — the specified-to-scarce window is
when the wallet fills its store from the local daemon.** Shard `k`
closes at `b_{k+1}`; the archiver's wallet pulls `k`'s bodies over the
operator leg while its daemon still holds them in-window; the daemon
then discards `k` at `W` like every other daemon. After the window,
acquisition is a fetch from another archiver (recovery, above). That is
the grace window doing something concrete, and it replaces F32's
"retains from in-window bytes with nothing to fetch" — same mechanism,
right owner.

**Consequences this ruling forces elsewhere (amended in this pass):**
Q2's predicate loses its `k ∉ exceptions` conjunct — the daemon has no
exceptions; Q7's *permitted* unbonded retention lives in a wallet-side
store, never the daemon; Q12's `LeafStore` is **rebuilt around bodies,
not deleted** — the leaf-shaped internals go, the serving store stays,
and `StoreShardProvider` keeps reading it; the skeleton's §4 and its
exception falsifiers go.

**`PDM-Q-F33` — #775 is written against the leaf unit, and re-keys
under Q6 / Q12.** Its *architecture* (two stores by obligation; the
partition is consensus) is unit-independent and stands. Its
*consequences* re-key: the partition is `b_*` from the retained length
rows (consensus by the same argument — admission validates `shard_id`
against closed shards, a divergent partition forks at admission);
`R_k` becomes the two hash rows on the daemon's skeleton; the served
frame is per-tx; hash rows and `b_*` on the daemon (consensus,
uniform), bodies in the wallet store, frame shared. Its FOLLOWUPS
"partition tie" row (`SEGMENT_LEAF_COUNT == leaves_per_segment()`
compile-time assert; *"E3 consumes `frozen_segment_count` / `SegmentId`
and defines PDM's discard unit in them"*) is refuted by Q12 (the freeze
retires) and F32 (the unit is `b_*`); the hazard it names — a
provisional marker / config door on the partition constant — survives
unchanged and applies to **`SHARD_BYTES`**: one home, const-asserted,
not editable as a tune. #775's *"memory-only seed ring of Q10"* is
**SO-D8's** Q10, not this round's. **Whichever of #774 / #775 lands
second owes the re-key**; named in both.

**Reversion (rule 21).** Reopens only if #775's line is redrawn — its
own reopener: archival serving becomes universal. Falsifiers: any
durable archival serving state on a daemon (a shard body retained past
`W`, a persona id, a `retain(k)`); a `get_prunable_range` or any
archival-serving RPC on the daemon; an archiver-backed daemon
distinguishable from a plain one by disk or by wire.

---

*The analysis below is the ground the ruling was taken on, including the
daemon-storage candidate this ruling rejects. Its PARTIAL framing is
superseded by the block above.*

**As opened — `PDM-Q9` PARTIAL 2026-09-13 (SUPERSEDED above) — The archiver's retention set: source, binding, lapse.**

After Q7 there are **two retention regimes**, and Q7 ruled only one:

1. The universal set — every daemon, consensus, no operator switch
   (Q1–Q6, Q7's rejection).
2. The archiver's supplementary set — shard `s`, held in addition.

**Ruled (steering, 2026-09-13): shard retention is the bond process.**
The bond already carries the shard set on-chain: `holdings` is
`ShardSetCompact{ids}` or `CompleteTree`
([`ARCHIVAL_BOND_CONSTRUCTION.md`](../design/ARCHIVAL_BOND_CONSTRUCTION.md) line
349), stored in `archival_bond` (consensus-folded, set-shaped,
`class.rs:114`), changed by `HoldingsUpdate`, ended by `Release`. The
daemon's supplementary retention set is **read from the chain**, not
configured on the daemon. There is no second place where "which shards"
is spelled, and no daemon flag is minted for it.

**Candidate under review (steering discussion, 2026-09-13; not
ruled): the daemon holds the shard, as a retention exception on the
universal discard predicate.** Today `P` serves from a *second*
database — `shekyl-curve-tree`'s wallet-side redb `LeafStore`
(`PDM-Q-F21`) — holding the unit F12 retired. The daemon already has
the good at ingest (it wrote `txs_prunable` before any discard could
run), so retaining shard `s` is one thing: do not discard the prunable
regions in `range(s)`. That is a filter on the predicate every daemon
already evaluates — `retain(block) = in_window(block) ∨ block ∈
exceptions` — one code path, one deletion site, archivers differing
from other nodes by data rather than by software (rule 71's shape).
Serving path: onion request → wallet → operator-to-operator leg →
daemon reads `range(s)` → wallet streams; localhost against a Tor
circuit is not a latency question. What the candidate changes in the
open items below is recorded against each.

**Still OPEN, in rule-21 shape when ruled:**

- **Binding.** The daemon must know which bond(s) it serves for. That
  is a public identifier (the bond's persona key), not a secret, and
  it lives on the serving host's side of the Model D boundary. Name
  where it lives and how it is set; say explicitly that no seed
  material crosses to make it work
  ([`16-architectural-inheritance`](../../.cursor/rules/16-architectural-inheritance.mdc)
  §"comment that outlived its architecture" is the precedent for
  getting this wrong). **Under the candidate this item mostly
  dissolves:** the wallet holds the bond and issues `retain(s)` /
  `release(s)` over the operator leg; the daemon holds a set of ranges
  and no persona identity, cannot tell which persona a serve is for
  (the wallet countersigns), and several personas on one daemon are a
  union of exceptions. Nothing crosses the boundary but a list of
  ranges. State explicitly that the exception list on the daemon's
  disk is a persona-linking fact of the *same class* as the bond on
  the wallet's disk — operator-controlled machine, never advertised
  (`PDM-Q8` ruled) — so that daemon storage is not later misread as a
  Model D violation: Model D bounds network identity, not which local
  process holds which bytes.
- **Lapse timing.** Retention must outlast the bond. An archiver whose
  `Release` (or a `HoldingsUpdate` dropping shard `s`) lands at height
  `h` can still be challenged on `s` for the challenge window and
  settled for the settlement lag after `h`. If the daemon discards at
  `h`, a correct exit is slashed. State the retention tail as a
  function of the pinned constants in `shekyl-archival-retention`
  (`CHALLENGE_RESOLUTION_BLOCKS`, `SETTLEMENT_EPOCH_BLOCKS`,
  `ARCHIVAL_REORG_DEPTH_BLOCKS` = 720), and name the test that goes
  red if the tail is shorter than the window. **Under the candidate**
  the tail is a monotone floor the *daemon* enforces after any
  `retain(s)` — `release(s)` is accepted at once by the wallet and
  cannot shorten it — which is testable against the constants and
  cannot be defeated by a wallet bug.
- **Coverage floor (`PDM-Q-F20` as corrected).** A range with no
  archiver is a range no fresh node can *fill* in Q5's band 2. Under
  the anchor model that is load-bearing for the **launch window**
  (`C = 0` until the first checkpoint release — every fresh node's
  band 2 is the whole chain), for stale binaries, for `assumevalid=0`
  auditors and for history read-back; it is not chain liveness for
  current binaries. The market prices shards by `r`; nothing in it
  guarantees every range has *one* holder. Q9 names the floor —
  `CompleteTree` holdings as a structural fact (Foundation, explorers;
  Q7's unbonded exceptions are the same object), a minimum-holder rule
  the challenge scheduler enforces, or something else — sized to the
  launch window first, and says which instrument goes red when a
  range's holder count reaches zero. Archiver economics are stated
  against the three egress terms Q5 item 4 names (band-2 sync,
  challenge, recovery).
- **Data loss — recovery is the daemon's ordinary fetch, not an
  exception.** (Restated 2026-09-13; the earlier "single named
  exception to *P never fetches*" framing is struck.) `P` never
  fetches — the *daemon* fetches, and `P` is a wallet persona that
  serves. A daemon that loses `range(s)` (disk failure, restore from a
  pre-`retain` backup) cannot regenerate the good — nothing can; that
  is what makes it the good. Either archivers accept slashing on data
  loss, or the daemon **re-acquires `range(s)`** from other holders
  through Q5's `fetch_prunable_range` primitive — the same primitive
  band 2 and history read-back use, called by a different scheduler.
  There is no boundary being crossed and nothing to design around;
  recording one would invite exactly that. The candidate reading:
  recovery-by-fetch is right; slashing stays (the market prices
  durability) but the exposure is bounded to the recovery window. Two things it owes: the window
  (recovery must complete inside the challenge cadence or the fetch
  is pointless), and the **free-ride shape** — a recovery fetch is
  unpaid serve load on the archivers that answer it; bound it or price
  it rather than assume it is rare.
- **The serving path from the retention exception has no RPC (owed,
  2026-09-13).** Q12 names the wallet-side `LeafStore` a deletion
  target; nothing names its replacement. Today `shekyl-p-host`'s serve
  set reads `LeafStore` through `ServingReader`
  (`redb_backend.rs:164-183`). Under daemon storage the wallet must ask
  the daemon for `range(s)`'s prunable bodies over the
  operator-to-operator leg — a new RPC, `get_prunable_range(a, b)` or
  similar, and it is the **only new surface daemon storage
  introduces**. It sits on the SH-2 remainder (the wallet constructing
  `PersonaServingHost`) and is what `StoreShardProvider` swaps to.
  Without it "the daemon stores, the wallet serves" is a sentence with
  no code path. Q10's "not retained" response is this RPC's negative
  arm.
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

### `PDM-Q10` RULED 2026-09-18 — "Not retained" is the existing split transaction read; no new RPC

**Grounded at** `dev@20ebdf1e5`; `shekyl-daemon-rpc/src/methods.rs:552-605`
read at source.

**Ruling.** Decided by rulings that already exist: Q2 makes retention
per-shard and uniform; Q9 / #775 remove every daemon-side archival
serving surface (`get_prunable_range` withdrawn); `RF-R1` collapses
whatever a wallet learns to one identical 404 at the onion. So the
contract is **the ordinary transaction read's split form**:
`get_transactions` with `prune` / `split` returns, per tx, `pruned`,
`prunable`, `prunable_hash` and a `pruned_flag` (the
`(split, prune, decode_as_json)` matrix at `methods.rs:552-605`). "Not
retained" is that response with `prunable` empty, `prunable_hash` (and,
after A3, `pqc_auth_hash`) present, `pruned_flag` set — **identical on
every daemon**, inside `W` (it has the body, returns it) and outside
(no daemon has it). A discarded body and a never-held one are one
state (F32 leg (iii)) and the response does not distinguish them. The
wallet-side store answers the onion; the daemon answers its operator.
Nothing to design.

**Falsifier.** A daemon RPC that reports archival retention, holdings, or
a per-shard "not retained" variant; or two daemons at the same height
answering the same split read differently.

---

*The analysis below is the ground the ruling was taken on; its OPEN
framing is superseded by the block above.*


The leaf-table readers that serve `get_curve_tree_path` live in
`shekyl-fcmp::rpc_path` (store trait) with C++ callbacks in
`src/cryptonote_core/curve_tree_path.cpp`. A missing leaf, layer hash,
or output key is `CORE_RPC_ERROR_CODE_INTERNAL_ERROR` (PDM-Q-F9). Right
today; under PDM those readers then report a leaf the node has
*legitimately* discarded as an internal failure — the wallet-facing twin of
`PDM-Q-F8b`. Rule on a response that distinguishes *not retained here;
fetch from an archiver* (and, once Q9 is ruled, *which* one) from *the
store is broken*. The membership-path assembly client
([`CURVE_TREE_CLIENT.md`](../design/CURVE_TREE_CLIENT.md) remaining item (b)) is
the consumer; the shard-fetch client round (`SF-`, PR #714, **RULED
2026-09-13**, [`ARCHIVAL_SHARD_FETCH.md`](../design/ARCHIVAL_SHARD_FETCH.md)) owns
the fetch leg's transport and is the place this response has to be
legible — its miss/timeout taxonomy (`SF-` §"Timeout / miss / retry") is
where "not retained" lands on the wire.

**The privacy argument does not cut against this.**
[`RPC_TRANSPORT_POSTURE.md`](../design/RPC_TRANSPORT_POSTURE.md) lines 22–27: every
RPC leg is operator-to-operator, both endpoints machines the same person
controls, the adversary is the network path and never the peer. `:1577`
and `:1670` are that leg. A daemon telling its own operator's wallet "I
do not hold shard `s`" discloses nothing the operator did not configure.
Q8's query-privacy concern lives on the *fetch* leg to a third-party
archiver, not here.

### `PDM-Q11` RULED 2026-09-17 — `D_max`: shape frozen, numeric provisional, home `CEN-E2`

**Grounded at** `dev@4bc378d68`. Not archival-scoped; closes by
reference if a consensus-constants family rules it.

**What it is.** `D_max` is the maximum reorg depth a node with an
anchored chain will accept. It is a **detectability boundary**, not a
security margin: it does not raise attack cost, it converts a deep
rewrite from a silent reorg into a visible split. Any depth below
`D_max` is bought silently by an adversary who can afford it; the
requirement is `D_max < d_afford` for the rentable-RandomX adversary
positioned in the candidate derivation below.

**Home.** `CEN-E2` — `is_alternative_block_allowed` — one function,
two bands: the anchor floor (refuse any alternative at or below the
last release-carried checkpoint) and the rolling cap (refuse any
alternative deeper than `D_max` below tip). `CEN-E1` (hash equality at
a checkpointed height) is the anchor's own rule, not this one. Both
census rows are re-keyed in the PR that lands `Trust::BelowAnchor`
(`PDM-Q-F30`), because that PR moves checkpoint state into Rust and
fires the reopening trigger both rows named.

**Binding condition.** `D_max` binds only once a node has an anchored
chain. A fresh node's exposure is bounded by the anchor `C` and not by
`D_max` at any value; a node with an empty checkpoint table has no cap
at all, which is the pin today (`init_default_checkpoints` is a
rule-71-shaped no-op, `src/checkpoints/checkpoints.cpp:136-145`). The anchor
is therefore a **precondition** of `D_max`, not a sibling, and
`PDM-Q5`'s ordering item is discharged by this sentence.

**Numeric.** `D_max = 720` blocks (24 h at 120 s), **PROVISIONAL**, on
the `bond_duration` precedent. The argument for 720 is coordination
with the archival domain's frozen assumptions and is recorded as such
(below). Two independent arguments for shallower are recorded beside it
and are not overridden: (i) 720 sits at the top of the honest-partition
floor and plausibly above `d_afford` in the first year; (ii) a deep
`D_max` widens the window in which a syncing node above `C` trusts
proofs it has not verified. Re-pinned at the Round-2 testnet gate
together with `archival_failure_window_n` and `W` — **one gate item,
three numerics** at this ruling; **a fourth numeric, `w_launch`, joined
the same gate 2026-09-18** (Q6 item 3 amendment, the commitment-weight
routing note: the flat in-window weight before any shard is scarce,
superseded by the derived median once one is); a re-pin task that
names fewer than four is incomplete. *Editorial, line-local (rule 23):* the ruling as delivered
named a **fourth** entry, the relation `bond_duration ≥ W`. That
relation was drawn by the §3 free-riding walk and **withdrawn by
steering the same morning** (the free-regime reward is the ruled
bootstrap subsidy; #770 landed the gate at three). Landed here at
three, consistent with the withdrawal; if the withdrawal was not meant
to reach this block, reinstating is one sentence in this paragraph and
the gate paragraph below.

**Derivations that now bind.** Q2's discard predicate (`W ≥ D_max`,
F10); Q1's journal retirement floor `tip − (CRB + n·SEB + D_max)`,
computed through `shekyl_archival_failure_window_params`, never literal
(F19); S-PRUNE's undo-log watermark `≥ D_max` (SCW-7,
`StoreCannot::PopBelowFloor` as the refusal); and — the fourth, added
by this ruling — `Trust::BelowAnchor(anchor)` is mintable only from the
release-carried table (`PDM-Q-F27`), so `D_max` never has to defend a
node below its anchor.

**Reversion criteria (rule 21).** Numeric reverts to OPEN at the
Round-2 gate by construction. Shape reverts to OPEN if: (a) a
consensus-constants family rules a reorg cap with different semantics —
then this closes by reference and the derivers re-point; (b) the anchor
model in `PDM-Q5` is rejected, since without a precondition the
fresh-node argument returns to `D_max` and the detectability framing no
longer holds for syncing nodes.

**Falsifiers.** A fork of depth `D_max + 1` accepted on an anchored
node is red. A fork below `C` accepted on any node is red. `undo_log`
retention constant `< D_max` is red (SCW-7). A second reorg-depth
constant in any consensus or store crate that is not `D_max` by
reference is red — the drift pair the constants policy forbids.

---

*The analysis below is the ground the ruling was taken on. It predates
the ruling; its OPEN framing is superseded by the block above, and it is
kept as the record — including the candidate derivation and the
Round-2 gate paragraph the ruling's numeric refers to.*

Minted 2026-09-13 because two rulings derive from one number that
does not exist: Q2's discard floor (F10) and Q1's journal retirement
floor (F19) both carry a `D_max` term, and at this pin there is no
consensus-side bound on accepted fork depth —
`ARCHIVAL_REORG_DEPTH_BLOCKS = 720` is archival-domain
(`shekyl-archival-retention`), `max_reorg_depth` is an engine-side
preference (`shekyl-engine-prefs/src/schema.rs:425`, default 3),
neither is a rule a validator applies to a competing chain. A
constant two independent rulings derive from is a constant in its own
right; burying it in whichever question is ruled first is how it
inherits that question's scope. It is carried here until it is ruled;
**it is not archival-scoped**, and its ruling may relocate to a
consensus-constants family — if it does, this question closes by
reference.

**Store constraint (added 2026-09-15, S-CHAIN-W pre-flight SCW-7 —
[`DRS_E1_SCHAIN_W.md`](DRS_E1_SCHAIN_W.md) §5.4).** `D_max` is now a
third derivation, on the store side: in the Rust chain store a block at
height *h* can be popped **iff** its `undo_log[h]` row exists, and the
retention prune (S-PRUNE) deletes undo rows below its watermark. So the
maximum pop depth *is* the undo-log retention horizon, and the inequality
**undo-log retention ≥ `D_max`** — equivalently, S-PRUNE's watermark may
not go shallower than `D_max` blocks below the tip — is a constraint this
question's answer must satisfy, not only a discard one. Getting it wrong
makes a legal reorg return `StoreCannot::PopBelowFloor`: the correct
class (a capability limit, loud, not a defect and not a verdict), which is
why the failure is at least visible. The falsifier is mechanical once both
constants exist: `undo_log` retention constant `< D_max` is red.

**What `D_max` is, stated so the derivation is possible.** It does
not raise attack cost — an adversary who can rewrite `k` blocks can
rewrite them whether or not nodes accept the result. It changes the
*failure mode*: below `D_max` a successful rewrite lands silently as
an ordinary reorg; above it nodes refuse, the network visibly splits,
and resolution moves out of band where humans can see it. `D_max` is
a **detectability boundary**, not a security margin.

**Candidate derivation (review, 2026-09-13; not ruled):**

- *Adversary, positioned.* Anyone who can rent RandomX-capable CPU.
  Pre-genesis there is no sunk-ASIC cost and the rentable pool exceeds
  a young chain's hashrate by orders of magnitude — which is why the
  containment layer is permanently load-bearing here rather than a
  Monero carry. The adversary buys some depth `d_afford` cheaply; the
  requirement is `D_max < d_afford`, because every depth below `D_max`
  is bought silently.
- *Honest floor.* Fork races at 120 s blocks
  (`BLOCK_INTERVAL_SECS = 120`,
  `shekyl-relay-privacy/tests/f_prime_admissible_region.rs:368`) are
  1–3 blocks. The binding case is a partition where both sides mine: a
  partition of duration `T` yields at most `T / 120 s` on the losing
  side, less if that side's hashrate dropped. So
  `D_max ≥ T_tolerable / 120 s`.
- Both bounds land in **hours**. The honest floor and the adversary
  ceiling are close together and there is no wide safe band — a
  property of a CPU-mined genesis chain, not a flaw in the derivation.
- *Provisional value: `D_max = 720` (24 h at 120 s).* The argument is
  **coordination, stated as such, not dressed as security**: the
  archival domain has frozen its assumptions against 720 —
  `gf7_sealing_run.rs:91-93` premines `720 + 30`, `pscan/start.rs:93`
  trails the tip by it, `serve_set_source.rs:166` reasons "far deeper
  than" it — and a different consensus number creates the drift pair
  the constants policy rejects (`consensus_constants.json:30`, "ONE
  authority and no drift pair"). Recorded alongside: 720 sits at the
  *top* of the honest range and plausibly above `d_afford` for a chain
  in its first year; the security argument wants it shallower (180 =
  6 h is defensible on the honest side and better on the adversary
  side).
- *Re-pin gate.* Shape frozen, numeric provisional, on the
  `bond_duration` precedent — pinned to the **same Round-2 testnet
  re-pin gate as `archival_failure_window_n`**, since both are numbers
  only real network behaviour settles and both feed F19's floor.
- *The Round-2 gate is one item with three entries (consolidated
  2026-09-13).* `archival_failure_window_n` (PROVISIONAL,
  `config/consensus_constants.json`), **`D_max`** (this question) and
  **`W`** (Q2) all re-pin against the same measured outage-duration
  CDF, and F19's retirement floor `tip − (CRB + n·SEB + D_max)` is a
  sum over two of them with `W`'s candidate equal to it. They are
  tracked in three questions; the gate is **one** entry — re-pin `n`
  and the other two are downstream of the same measurement. The
  Round-2 re-pin task names all three or it is incomplete.
  *WITHDRAWN the same day it was proposed (2026-09-17):* a fourth gate
  entry, the relation `bond_duration(0) · SEB ≥ W`, was added here by
  the §3 free-riding walk and withdrawn by steering hours later — the
  free-regime reward is the ruled bootstrap subsidy
  (`DESIGN_CONCEPTS.md` Component 4), favouring early adopters by
  intent, and a bond releasing before scarcity is that subsidy working.
  **The gate is three numerics at this date** (`n`, `D_max`, `W`); the
  §3 bullet keeps the arithmetic as a record. **2026-09-18: a fourth
  numeric, `w_launch`** — the launch-window commitment weight for
  in-window shards (Q6 item 3 amendment) — joins it; a *numeric*, not a
  relation, so this is not the withdrawn entry returning.

- *Second reason it wants to be shallow (2026-09-13, from Q5).* Under
  Q5's anchor model a **synced** node trusts nothing it did not verify
  at the tip, and a **fresh** node's trust is bounded by the anchor
  `C`, not by `D_max` at any value — so `D_max` does not protect the
  fresh node and must not be argued as if it did. What it does bound
  is the synced node's *silent-reorg* exposure: a deep `D_max` is a
  window in which a bought reorg lands without a visible split.
  Shallower is better on that axis too; the honest floor is the only
  thing pushing the other way.
- *Precondition, not sibling (2026-09-13, `PDM-Q-F23`).* The inherited
  machinery is one function with two bands:
  `is_alternative_block_allowed` (`checkpoints.cpp:124`, called at
  `blockchain.cpp:2242`) refuses any reorg below the last checkpoint;
  `D_max` is the rolling cap above it. **`D_max` binds only once a
  node has an anchored chain.** A fresh node choosing between
  histories has no tip for `D_max` to be relative to; the checkpoint
  is what it brings. A node with an empty checkpoint table — the pin
  today — has **no cap at all**. Q11's home is therefore the same
  function Q5's anchor populates, and the ruling states the ordering
  explicitly.

**What a ruling owes:** the constant's home (config authority, single
read path, no generated-header twin) and its ordering with the
checkpoint table; the validator-side check that refuses a fork deeper
than `D_max` and the verdict it emits; the consequences for Q2's
predicate and F19's floor stated as recomputed values, not literals;
and the test that goes red when a fork of `D_max + 1` is accepted —
and a second that goes red when a fork below `C` is accepted on any
node.

### `PDM-Q12` RULED 2026-09-18, amended the same day on #775 — The freeze pipeline retires; `LeafStore` is rebuilt around bodies, not deleted

**Grounded at** `dev@20ebdf1e5`. A consequence of Q6 (items 1–3, F32),
not a new argument.

**Ruling.** The segment-freeze pipeline retires. It existed to commit
`R_k` over a segment so served bytes were content-verifiable. Under Q6
every txid already commits `prunable_hash` and `pqc_auth_hash` at
ingest, and membership is derivable from the retained length rows
(F32); there is no height at which a range *becomes* verifiable and
nothing left to commit. **Not a migration:** no chain, no successor
object. The freeze's retirement stands on Q6 alone; what is
*conditional* is only where its dependents re-point.

**Dependents and substitutes.**

- `TJ-D`'s "segment" → the byte-bounded `tx_id` range (Q6 item 3, F32).
- `RF-D6`'s segment → reopened per item 4 (half survives as the
  boundary metric).
- `SF-`'s serve-set pin (`StoreError::FrozenSegmentPruned`,
  `redb_backend.rs:464`) → ~~the daemon's retention exception is the
  pin~~ **SUPERSEDED (Q9 RULED on #775): the daemon holds no serving
  state.** The pin is the wallet-side store's own: a shard is present
  in it or it is not, and "pruned mid-serve" is a store fault the
  rebuilt store reports, not a segment state. The retirement itself
  does not move.
- `PDM-Q-F11`'s three curve-tree accumulator rows → unchanged; layer 0
  is still never pruned and still the tree's own commitment. The freeze
  was never the accumulator's source.

**Deletion surface — amended 2026-09-18 on #775: the store stays, its
leaf-shaped internals go.** The wallet-side store is *the* serving
store (#775: two stores by obligation) and it is **kept**; what Q6
changes is its **unit** — leaves to prunable bodies — not its
existence. *Rust, deleted:* `rust/shekyl-curve-tree/src/store/redb_backend.rs:164-183`
(`open_frozen_segment_body`, `ServingReader`, leaf-order streaming),
`StoreError::FrozenSegmentPruned`; `shekyl-archival-retention`'s
`segment_freeze.rs` and the freeze half of `challenge.rs` / `path.rs`
(item 4's "retired by ruling, live in code" row — deleted at E4 /
S-ARCH with the verifier). *Rust, rebuilt:* `LeafStore` becomes a
body store keyed by shard `k` over `[b_k, b_{k+1})`, filled from the
local daemon during the specified-to-scarce window (Q9), served per-tx;
`shekyl-p-host`'s `StoreShardProvider` **keeps reading it** — the
earlier "swaps its reader to the daemon's `get_prunable_range`" is
**withdrawn** with that method. **The rebuild has an owner (added
2026-09-18 on review): the wallet lane, as its own design round —
unbuilt by design, not by omission.** It is where the design's weight
now sits, and every one of its decisions is unmade: fill from the local
daemon during the grace window (Q9) and verify on fill against the
daemon's hash rows; key by shard over `[b_k, b_{k+1})`; serve per-tx
through `shekyl-p-serve` (`SF-D8`'s content half, sub-PR 2); carry its
own lapse tail (#775's retention row); receive recovery shards the
daemon hands across and retain them; hold the Foundation `CompleteTree`
behind a persona (Q9's floor). The round registers its family at birth
(rule 94) and cites this contract for its inputs; FOLLOWUPS row with the
falsifier. The curve tree's *verification-side*
leaf store, if any, is Q1's to grade. *C++:*
`process_archival_segment_freezes_at_height`, `archival_shard_segment`,
`frozen_segment_count`, `get_archival_shard_segment_at_height`,
`SEGMENT_LEAF_COUNT` — **die at `DRS-E*` with the stripe engine under
Q7's precedent** (`S0`: no C++ landing before the cutover), not "go
with it".

**What changes on the wire — see item 4, row 1.** The serve-credit
admission verifier derives `R_k` from the frozen-segment registry today
(`blockchain.cpp:5099-5121`); retiring the freeze retires that
derivation, so the pass record's signed message and its consensus rule
change. That is item 4's consensus row and E4's landing; this ruling
does not claim wire invariance.

**Reversion.** No reversion criterion beyond Q6's own: the only
consumer that could need a *range-level* commitment the per-tx rows
cannot supply would be one that must check "these transactions are
exactly shard `k`" without deriving it — and under F32 that derivation
is a binary search over `b_*`, so the criterion is vacuous by
construction and is recorded as such rather than dressed as a
falsifier.

---

*The analysis below is the ground the ruling was taken on. It predates
the ruling; its OPEN framing is superseded by the block above.*

Held as a question, not a claim, because the pipeline has dependents
(`TJ-D`, `RF-D6`'s segment, `SF-`'s serve-set pin).

- **Does the freeze retire?** The segment freeze
  ([`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](../design/ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md))
  exists to commit `R_k` over a segment of leaves so that served bytes
  are content-verifiable. Under a per-tx verifier the commitment
  exists at ingest — every txid already binds `prunable_hash` and
  `pqc_auth_hash` — so there is no moment at which a range *becomes*
  verifiable; it was verifiable in the block it landed. If nothing
  remains for the pipeline to commit, it retires, and Q12 names what
  its dependents bind to instead (the shard's derivable membership,
  Q6 item 3).
- **The wallet-side `LeafStore` is a deletion target, not a
  migration (`PDM-Q-F21`).** There is no chain and the unit changed:
  `open_frozen_segment_body`, `ServingReader`, leaf-order body
  streaming (`rust/shekyl-curve-tree/src/store/redb_backend.rs:164-183`)
  go, and `StoreError::FrozenSegmentPruned` (`:464`) — "the serve-set
  was not pinned before a prune ran" — is a failure mode that cannot
  occur when the daemon's retention exception *is* the pin (Q9's
  candidate). `StoreShardProvider` in `shekyl-p-host` abstracts over a
  reader, so the swap is the provider, not the endpoint.
- **What a ruling owes:** the dependents list with each one's
  substitute; the deletion surface; and a statement that the wire
  sees no change (the credit wire's whole-shard read is unit-agnostic
  on the wire, `ARCHIVAL_CREDIT_WIRE.md` §3).

---

## 3. Adversarial work required before any `PDM-Q*` ruling is recorded

Named so they cannot be discovered after a ruling. Not answered here.

**Status and owner (added 2026-09-17, `4bc378d68`; walked the same
day).** Q6 is the critical path, and its ruling is "a transcription of
F13/F14/F17 against these six items" — so the *walk of the six against
the tx-range unit* is the actual gate on Q6, not the transcription.
Owner for every row is **steering (the ruling pass)**; a row cannot be
closed by a code lane. The walk was taken by steering on 2026-09-17
against the design as it stands — tx-range unit, two hash rows, uniform
`W`, daemon retention exceptions, wallet-fronted serving, three-band
sync, `D_max` — positioning `T` before saying what `T` gains. Each
bullet below carries the original question (kept, so what was asked is
visible), then the walk. **A "DISCHARGED" here is a steering
disposition on the design's *shape*; it is not a `PDM-Q*` ruling, and
the conditions named on each row are owed to the questions named.**

| Item | Walked? | Disposition (2026-09-17) | Owes |
| --- | --- | --- | --- |
| Withholding | Yes | **DISCHARGED** on four properties: request indistinguishability, requester anonymity, per-tx verify, timeout = miss. Collapses to unreliability, which the m-of-n window prices | Per-shard detection latency on a large holder → the credit wire's draw design; honest-P-behind-flaky-Tor false positive → Round-2 numerics |
| Free-riding in the free regime | Yes | **DISCHARGED on the ruled bootstrap subsidy** (`DESIGN_CONCEPTS.md` Component 4 / `ECONOMY_EXPLAINED.md` Loop 4): the free regime is the window the staker emission share exists for; favouring early adopters is the intent; a bond releasing before scarcity is the subsidy working, and re-bonding at scarcity is the market's test. The `bond_duration(0) · SEB ≥ W` condition first written here is **WITHDRAWN** (steering, same day); arithmetic kept as record on the bullet | Nothing on `bond_duration` vs `W`. Q2 states `W` and names the regime's market behaviour as *bootstrap* |
| Eclipse and fetch | Yes | **DISCHARGED.** Running node under `W`: never fetches to verify — identical to today. Band-2 syncer: anchor below `C`, PoW + verified bodies over Tor from the bond table above; residual is nuisance (wasted egress, tip lies) and already P2P-2's | Nothing PDM-shaped |
| Stripe / shard interaction | Yes | **DISCHARGED conditional** on Q6 item 3 and F17 naming **one unit**: whatever the wire echoes as holdings commits `T` to the same unit the bond names and the challenge draws from | Q6 item 3 / F17 one-unit requirement |
| Sybil economics | Yes | **Economics DISCHARGED, no residual**, on the **self-diluting scarcity reward** — `scarcity(s,E) = (1/R_market(s,E)) · g(age)`, [`REWARD_EMISSION_LEG.md`](../design/REWARD_EMISSION_LEG.md) channel 1 — which makes same-shard Sybil and inefficiency the same act. **Correlated-failure residual DISCHARGED conditional** on Q9 ruling the coverage floor *structural* (Foundation / explorers holding `CompleteTree`, Foundation work outside `Σwork`, `:310`) — Q9 is OPEN on that item today | Q9: rule the floor structural, and say it counts **personas**, not hosts (Model D cannot see the difference) |
| Reorg | Yes | **DISCHARGED conditional** on Q11 existing (which is Q11's point): `D_max` caps depth (`CEN-E2`); discard only below `tip − W` with `W ≥ D_max` (F10); undo-log floor `≥ D_max` + `PopBelowFloor` (SCW-7); pops within `D_max` re-pool full bodies; trim's leaf reads regenerate from the skeleton (F12) and the `:9361` throw dies with the C++ | The predicate asserted where retirement is decided — S-PRUNE's row (F31), not discovered at revert |

**What falls out across the six that sits in no single item.** Q9's
coverage floor needs to be ruled **structural** and to say it **counts
personas** — a persona count can overstate hosts and Model D forbids
seeing it, which is why a market-derived floor cannot carry the Sybil
residual. (A second cross-cutting output — a `bond_duration` vs `W`
relation for the Round-2 gate — was proposed and **withdrawn** the same
day: the free-regime reward is the ruled bootstrap subsidy, and the
walk had re-derived a constraint against a decided incentive. The
free-riding bullet keeps the record.) Everything else discharges on
properties already in the design, which is evidence the shape is right
rather than a reason to stop checking.

- **Withholding.** An archiver that holds leaves but refuses selected
  requests. What distinguishes that from an offline archiver, and does
  the challenge mechanism see the difference?
  **Walk (2026-09-17) — DISCHARGED.** `T` is a bonded archiver `P`, or a
  set of them under one operator, that holds the bytes and refuses
  selected requests. `T` controls its own onion's responses (404,
  delay, serve), its bond, its published holdings. `T` cannot see who
  is asking (the requester is a Tor client with no identity) and cannot
  tell a challenge from an organic read — `SF-D8`'s one client, one
  header, one nonce is indistinguishable on the wire; a visualiser
  fetch and a challenge look identical. So there is **no dimension to
  select on**: `T` cannot withhold from anyone in particular and cannot
  withhold only organic reads. The axes left are: *by shard* (serve
  `s'`, refuse `s`) — challenges are drawn per `(P, s)`, so this is a
  per-shard failure and slashes on `s`; *by content* (serve `s` with a
  corrupted or missing tx) — the per-tx hash verify catches it (Q4's
  TJ-F sentence: a body that does not hash to the retained row fails
  loudly), and the read fails whole on one bad member, the same
  fail-whole `SO-D8e` ruled for its carrier (§7.6.2 (B)); *by latency*
  — `SF-D6`'s taxonomy scores a stall as a miss. Withholding therefore
  collapses to **unreliability at every granularity `T` can act on**,
  and unreliability is what the m-of-n failure window prices.
  Discharged on four properties: request indistinguishability,
  requester anonymity, per-tx verify, timeout = miss. **Named
  remaining, not PDM's:** (a) detection latency for per-shard
  withholding on a large holder — with `k` shards and
  `CHALLENGES_PER_PAIR_PER_EPOCH = 3`
  ([`ARCHIVAL_CHALLENGE_MECHANISM.md`](../design/ARCHIVAL_CHALLENGE_MECHANISM.md))
  a refused shard waits on average `k/3` epochs to be drawn; that is a
  draw-design parameter, routed to the credit wire; (b) the
  false-positive side — an honest `P` behind a flaky Tor path looks
  like `T`; that is the window's job and Round-2 numerics.
- **Free-riding during the free regime.** The free regime is
  structural, not a rewrite-schedule artifact. Even with PDM shipped
  at height 1, an "archiver" needs no storage until the first segment
  reaches Q2's discard depth; scarcity does not exist at chain start
  regardless of what ships when. What stops a bond posted in the free
  regime from being honoured in the scarce one? The duration of that
  question is Q2's output. Q2 must state the duration and what the
  market does during it; this bullet is discharged against that
  duration, not against `DRS-E*`'s calendar.
  **Walk (2026-09-17) — DISCHARGED on the ruled bootstrap subsidy;
  the `bond_duration(0) · SEB ≥ W` condition first written here is
  WITHDRAWN (steering, same day).**
  `T` is anyone who bonds before the first tx crosses `tip − W`. `T`
  controls when to bond, what holdings to declare, when to release. `T`
  cannot avoid being challenged, and cannot answer a challenge on bytes
  it dropped once they are scarce. The regime, precisely: for the first
  `W` blocks nothing is beyond the window, every node holds every body,
  no archiver holds anything scarce, and challenges are answerable by
  anyone with a synced node. Duration is exactly `W` (~195 days at the
  F19 candidate). What `T` gains: rewards for `W` blocks against a
  *promise*, not a possession. That is a subsidy, and a good one — it
  funds archiver capacity before it is needed. **And that subsidy is
  already ruled**, not something this walk gets to condition: the
  staker emission share — 15 % of block emission to the staker pool at
  genesis, decaying ×0.90 per year — exists precisely because early
  fee yield is ~50× short of what participation needs, and it is
  documented as the *bootstrap subsidy* that favours early adopters on
  purpose ([`DESIGN_CONCEPTS.md`](../DESIGN_CONCEPTS.md) Component 4;
  [`ECONOMY_EXPLAINED.md`](../ECONOMY_EXPLAINED.md) Loop 4). The free
  regime — the window in which no shard is scarce — is exactly the
  window that subsidy is for: staking is a new process, and the
  incentive to adopt it is the point. A bond that collects for its
  horizon and releases before scarcity is therefore the subsidy
  working, not a farm; the market's test of the promise is
  re-bonding when scarcity arrives, and the diluting reward (Sybil
  walk) prices that market once it exists. **Discharged on the
  ruling.**
  *Record, kept line-local so it is not re-derived:* this walk was
  first written (earlier the same day) as *"DISCHARGED conditional on
  `bond_duration(0) · SEB ≥ W`, violated at today's candidates"* —
  `bond_duration` is age-scaled in settlement epochs,
  `bond_duration(age) = BASE · (1 + SCALE · age)`, `BASE = 4`,
  `SCALE = 4` (`config/consensus_constants.json:37-39`,
  [`ARCHIVAL_TIMING_CONSTANTS.md`](../design/ARCHIVAL_TIMING_CONSTANTS.md) §1),
  `SEB = 10,000` (`:22`), so an age-0 bond is `40,000` blocks (~55
  days) against `W`'s F19 candidate `≈ 140,720` (~195 days). The
  arithmetic stands as a fact about the regime's length relative to
  the bond horizon; **the condition drawn from it is WITHDRAWN** —
  steering, 2026-09-17: the free regime favouring early adopters is
  decided, ruled and documented, and a charter condition against it
  would be pre-provisioning a constraint on an incentive the economics
  already chose. Nothing is owed on `bond_duration` against `W`; the
  Round-2 gate keeps its three numerics. What Q2 owes here is only
  what §2 already says: state the regime's duration (`W`) and what the
  market does during it — which is *bootstrap*.
- **Eclipse and fetch.** If a node must fetch to verify, an eclipsing
  adversary controls what it can verify. Compare against today, where it
  verifies locally. TJ-F's "no store handle" face is the intended
  dissolution for *new-block verify*; spend-path assembly is a different
  fetch.
  **Walk (2026-09-17) — DISCHARGED.** `T` controls a target node's P2P
  view — peer set, blocks seen, believed tip. `T` does not control the
  target's Tor client (host compromise is a different `T`), the chain,
  or the bond table. *Running node, downtime under `W`:* never fetches
  to verify (Q3 empty after TJ-A / F29; Q4 collapsed). `T`'s eclipse
  gets exactly what a P2P eclipse gets today — control over block
  delivery — and nothing PDM adds. Dissolved for this population;
  compare-to-today is identical. *Band-2 syncer:* `T` can feed it a
  chain. Below `C` the anchor pins the hash — `T`'s chain matches or is
  refused. Above `C`, `T` needs valid PoW **and** valid proofs, because
  bands 2/3 verify bodies, and the bodies come from onions named by the
  on-chain bond table over Tor, which `T` does not control. `T`'s only
  remaining lever is the heavier-valid-chain above `C`, which is the
  `D_max` split (Q11, Q5), not a fetch attack. What `T` can still do:
  waste the syncer's egress by making it fetch bodies for a stale range
  it will discard, and delay sync by lying about the tip. Nuisance, not
  verification compromise; the residual is P2P-2's and already there.
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
  **Walk (2026-09-17) — DISCHARGED conditional on one unit.** `T` is an
  archiver whose holdings are a height-stripe of the prunable region,
  facing a challenge drawn in a different unit. Under Q6 this dissolves
  by construction: if the challenge draws a tx-range and holdings name
  a tx-range, there is no cross-unit challenge. The inverted work
  reduces to **one consistency requirement**: whatever F17 echoes on
  the wire as the holdings advertisement must commit `T` to the same
  unit the bond's `holdings` names and the challenge draws from. If the
  echo is a `u32` stripe seed (heights) and the bond is a tx-index
  range, `T` can advertise one and be bonded to another, and a
  challenge against either finds a gap. Discharged conditional on Q6
  item 3 and F17 naming one unit; no residual once they do.
- **Sybil economics.** Does the market price scarcity in a way that
  survives an adversary who runs many cheap archivers holding overlapping
  popular shards? Build on
  [`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`](../design/ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md)
  `r ≫ 1000`; do not re-derive.
  **Walk (2026-09-17) — economics DISCHARGED with no residual on the
  self-diluting scarcity reward, cited by name so it is not re-derived;
  the correlated-failure residual DISCHARGED conditional on Q9 ruling
  the coverage floor structural (corrected on review: Q9 is OPEN on the
  floor, so the floor is a condition here, not a premise).**
  `T` is one operator running `k` personas, `k` bonds, `k` onions, and
  one disk holding shard `s` once. `T` controls persona count; `T`
  cannot make the personas look related, and Model D makes that a
  feature. The design already permits this *shape*: daemon storage
  serves many personas from one daemon with a union of exceptions (Q9
  candidate) — `T` is that shape with different intent, and storage
  cannot discriminate because it is the same storage. So the discharge
  is economic and it is the reward leg's, not PDM's:
  [`REWARD_EMISSION_LEG.md`](../design/REWARD_EMISSION_LEG.md) channel 1,
  `scarcity(s,E) = (1 / R_market(s,E)) · g(age(s))` — **self-diluting
  scarcity**, where `R_market` is the market holder count of `s`.
  Walked: *rewards* — no harm; `T` locks `k` bonds and earns `k`
  rewards, per bond identical to an honest archiver; the only free
  component is storage (stored once, paid `k` margins), and disk is the
  cheap input (~195 days of bodies is a few hundred GB) while the bond
  is the expensive one, so `T`'s return on locked capital barely
  moves — `r ≫ 1000` territory. *Possession test* — no harm; `k`
  personas answer `k` challenges from one disk, correctly; `T`
  possesses. *Privacy* — no harm; requests are anonymous and
  indistinguishable. *Chain integrity* — no harm; the skeleton is
  universal. **The one exact harm:** the network believes `s` has `k`
  independent holders and has one host; if the host dies, `s` goes
  from well-covered to zero in one event, and Model D makes the `k`
  onions unlinkable by design, so the network cannot see or price the
  correlated-failure risk. That harm is real only if redundancy for
  `s` can actually fall to one — and it cannot if the coverage floor is
  **structural**: Foundation (and explorers) holding `CompleteTree`
  regardless of the market, with Foundation work kept *out* of
  `Σwork` (`REWARD_EMISSION_LEG.md:310`) so the floor neither dilutes
  nor is diluted. Then Sybil cannot push coverage below the floor, and
  what is left is a small, bounded storage overpayment that costs `T`
  `k` bonds of locked capital to collect. Two shapes, told apart: a
  `k`-persona, one-host operator holding `k` **different** shards is a
  datacenter archiver — the professional participant the market wants,
  and daemon storage was designed to make that shape cheap; not an
  adversary. A `k`-persona, one-host operator holding the **same**
  shard `k` times is the only Sybil — and with reward per shard falling
  as `R_market` rises, that operator dilutes its own reward `k`-fold
  while paying `k` bonds. The profitable move is always `k` different
  shards, which is `k×` storage, which is honest: **the reward curve
  makes the attack and the inefficiency the same act.** It also inverts
  the "false redundancy" harm: `s` looking covered *lowers* its reward,
  which pushes honest archivers toward under-served shards — the market
  working, not being corrupted. The signal is wrong only if `T` acts
  against its own interest to make `s` look covered and then fail;
  that is griefing, priced at `k` locked bonds and a diluted reward,
  for the payoff of one range going unverifiable if the host dies —
  and a structural floor makes even that moot. **Owed to Q9, and the
  condition on this discharge:** rule the coverage floor **structural**
  (Foundation / explorers holding `CompleteTree` regardless of the
  market, outside `Σwork`), and say that any market-derived count
  **counts personas, not hosts** and cannot see the difference. Until
  Q9 rules it, the dilution argument alone leaves the one exact harm
  above open — bounded, griefing-priced, but open.
- **Reorg.** Discarded-then-reorged. The retention prune is un-journaled.
  State revert behaviour explicitly.
  [`CONSENSUS_C2_R1_REORG.md`](CONSENSUS_C2_R1_REORG.md) is
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
  `shekyl-engine-state/src/safety_constants.rs:61`). That missing cap
  is `PDM-Q11` (`D_max`), minted 2026-09-13 because F10's discard
  floor and F19's journal horizon both derive from it.
  **Walk (2026-09-17) — DISCHARGED conditional on Q11 existing, which
  is Q11's point.** `T` is Q11's adversary — rentable RandomX CPU
  exceeding a young chain's hashrate (Q11 §, *adversary, positioned*) —
  producing a reorg of depth `d`. `T` controls depth up to `d_afford`.
  `T` cannot make a node accept `d > D_max` once Q11 lands (`CEN-E2`'s
  refusal, F30). The design's response, landed or owed by name:
  `D_max` caps accepted depth (Q11, `CEN-E2`); a body discards only
  once `height(tx) < tip − W` with `W ≥ D_max` (F10 / F24 — one
  predicate); undo-log floor `≥ D_max` with `StoreCannot::PopBelowFloor`
  as the typed refusal (SCW-7, landed); pops within `D_max` re-pool
  full transactions because their bodies are inside `W`; trim's leaf
  reads regenerate from the skeleton (F12 — every leaf-derivation input
  is in the unprunable base), so the `db_lmdb.cpp:9361` throw dies with
  the C++ rather than needing a defined failure of its own. Remaining,
  as F10 already says: the predicate **asserted where retirement is
  decided** — S-PRUNE's row (F31) — not discovered at revert.

---

## 4. Do not re-derive

Read, cite, build on. A disagreement is a finding, not a premise.

- Genesis-frozen decisions in `principles-and-learnings` and the
  consensus census.
- The retention prune's consensus scheduling and un-journaled deletions
  ([`CONSENSUS_C2_R1_REORG.md`](CONSENSUS_C2_R1_REORG.md)).
- Segment freeze semantics
  ([`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](../design/ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md)),
  including the §6.2 reversion clause this round is named to discharge
  or refine.
- Challenge / response format and deadline structure
  ([`ARCHIVAL_CHALLENGE_MECHANISM.md`](../design/ARCHIVAL_CHALLENGE_MECHANISM.md),
  [`ARCHIVAL_RESPONSE_FORMAT.md`](../design/ARCHIVAL_RESPONSE_FORMAT.md)).
- Bond construction and slashing
  ([`ARCHIVAL_BOND_CONSTRUCTION.md`](../design/ARCHIVAL_BOND_CONSTRUCTION.md),
  [`PRINCIPAL_STAKE_LIFECYCLE.md`](../design/PRINCIPAL_STAKE_LIFECYCLE.md)).
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
  assigned out of [`ARCHIVAL_SETTLEMENT_WRITER.md`](../design/ARCHIVAL_SETTLEMENT_WRITER.md)
  to the credit-wire §5 cutover. Scope addition 2026-09-12
  (`ba4b3c73a`): promote the settlement write path onto `BlockchainDB`.
  **UPDATE 2026-09-16 (`PDM-Q-F26`):** the in-flight re-homing of
  SO-D8/D9 onto `shekyl-chain-rules` (DRS-D12) is the right move; what
  it inherits from this round is (a) the serve-credit tx's prunable
  region is F13's good — the witness pk + signature SO-D8's batching
  puts there is not on an ordinary node below `W`, so every settlement
  read must be stated as admission-time or not, and (b) a settlement
  write set landing on the Rust store before Q6 rules fixes by
  construction what a pruned node persists about a serve-credit tx —
  the same ordering that binds DRS-E2 binds its writer. F26 carries
  the detail.
- **`DRS-0` / `DRS-D10`** — redb store port. D10 still reads universally
  at [`DAEMON_REDB_STORE.md`](../design/DAEMON_REDB_STORE.md) line 310: *All
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
  **UPDATE 2026-09-13 (`4da609cbd`, PR #726):** the DRS lane has since
  stated *how* it will absorb the ruling
  (`DAEMON_REDB_STORE.md:1105-1275`, §11.2 amendment chain): a digest
  cares whether nodes agree, not whether bytes are present, so a
  **uniform** discard yields a floor-defined accumulator and lifts
  exclusions rather than re-pointing them. The handoff is therefore
  **the boundary, not a grade** — `W` (Q2) and Q1's journal horizon —
  and its reopening conjunct *"followed by a node-variable daemon
  discard"* does not fire under Q7/Q8: only the surplus is
  node-variable, and it is outside the digest domain by DRS's own
  definition. F11 UPDATE carries the detail; the same block
  independently confirms F18's `output_metadata` grading (its read
  chain `get_output_metadata → is_output_pruned` has no call site,
  `:1255-1266`).
- **The credit wire** — [`ARCHIVAL_CREDIT_WIRE.md`](../design/ARCHIVAL_CREDIT_WIRE.md)
  prunable-residence row: *Header kept; 3.43 KB countersignature on the
  coinbase-tx prunable side*. If `PDM-Q6` rules that side into the
  archival subject, `CR-D2` reopens and the carrier decision changes.
  Second point of contact (Q6 item 3): §3's `transfer_digest`
  rejection rests on *"admission could never reconstruct the signed
  message"* — true of off-chain shard bytes, not of a digest over
  retained `txs_prunable_hash` rows. Q6 says whether that reopens.
  Read §2's deletion surface before citing anything leaf-shaped from
  [`ARCHIVAL_PER_CHALLENGE_RECORD.md`](../design/ARCHIVAL_PER_CHALLENGE_RECORD.md):
  `PC-D1`…`PC-D7` are RULED and the leaf-opening cluster they hardened
  is on that surface (`RF-D8` (i) retracted 2026-08-26).
- **`LV-` / P2P-2 (`PWC-`) — the skeleton block payload** (`PDM-Q-F28`,
  2026-09-16). `tx_blob_entry { blob, prunable_hash }` and its
  KAT-pinned Rust mirror `shekyl-levin::payload::block::TxBlobEntry`
  carry one txid component; under Q6 item 2 a skeleton needs two. A
  wire-census row and a KAT change, owned there, gated on Q6 item 2.
- **DRS-E6 (`shekyl-chain-rules`)** — `RuleSet` issuance and `ChainView`'s
  surface (`PDM-Q-F27`, `F29`, 2026-09-16): band 1 needs an issued
  below-anchor set or it has no writer under DRS-D12; Q3's instrument
  is the trait having no recorded-body accessor without a row and an
  above-`W` marking. Both written to `CHAIN_RULES_CRATE.md` §13 and the
  DRS-E6 row.
- **`tests/unit_tests/tx_prunable_region_sole_occupant.cpp`** — the
  prunable region has exactly one occupant; blob vs re-serialize hash
  paths agree only *positionally*. Read this test before proposing
  anything that adds to or reorders that region.
- **Every leaf-shaped archival ruling** (`PDM-Q-F13` item 4 of Q6) —
  [`ARCHIVAL_RESPONSE_FORMAT.md`](../design/ARCHIVAL_RESPONSE_FORMAT.md) `RF-D1`
  (the 128 B `leaf_bytes` claim) and `RF-D6` (`SHARD_BYTES = 25,992 ×
  128`, `challenge_leaf_index`, `LeafStore::frozen_segment`),
  [`ARCHIVAL_CHALLENGE_MECHANISM.md`](../design/ARCHIVAL_CHALLENGE_MECHANISM.md)'s
  draw, [`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](../design/ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md)'s
  segment as the unit of holding, and the bond's `holdings` descriptor
  ([`ARCHIVAL_BOND_CONSTRUCTION.md`](../design/ARCHIVAL_BOND_CONSTRUCTION.md) line
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
  curve-tree rows. **UPDATE 2026-09-16 (`PDM-Q-F26`):** the Rust store
  has begun carrying the identity without it — `TxIdentity` is
  `{ hash, prunable_hash }` (S-CHAIN-W). The row is requested of the
  DRS-E lane now, on SCW-7's precedent, not at "`DRS-E*`" in general;
  the bijection-gate blocker that made it a second change has expired
  (SCW-11's `RUST_ONLY_TABLES` map).
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
  there. The stale comments were corrected in PR #733 (2026-09-13),
  not held for the Q1 ruling.
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
  [`SHEKYL_P2P_PROTOCOL.md`](../design/SHEKYL_P2P_PROTOCOL.md) line 3699 — a
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
  correction PR (different file, different property). **Landed in PR
  #733 (2026-09-13):** both the leaf read and the previously unchecked
  layer-hash read now return `CORE_RPC_ERROR_CODE_INTERNAL_ERROR`. This
  charter does not carry the C++ edit.

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
  **Restated 2026-09-13 (review): the discard floor is a predicate,
  not a depth.** Trim is height-granular (it reverts blocks, bounded
  by `D_max`); discard is leaf-granular (`SEGMENT_LEAF_COUNT = 25,992`,
  [`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](../design/ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md)
  line 84, segments spanning `[k·E, (k+1)·E)` in leaf positions).
  Converting one to the other needs an outputs-per-block rate — a
  parameter derived from a mechanism that has not run. State the
  constraint in the only unit where it is exact: *a segment may be
  discarded only once the highest `eligible_height` among its
  constituent leaves is below `tip − D_max`.* Checkable against data
  the node already holds, needs no rate estimate, and does not drift
  with throughput — under low output rates a segment spans many blocks
  and waits; under high rates it clears quickly; both are correct
  without retuning. **Enforcement point:** the predicate is asserted
  where the discard is *decided*, not where the trim discovers it —
  today `:9361` throws `DB_ERROR` mid-write-txn, so a violated floor
  would surface as a corrupted write rather than a refused discard.
  `D_max` itself is `PDM-Q11`; F10 and F19 are blocked on the same
  missing constant.
- **PDM-Q-F11.** DRS-0 slice A's accumulator freeze contradicts set-B
  discard on three tables.
  `rust/shekyl-chain-store/src/accumulator/class.rs:140-142`:
  `curve_tree_checkpoints` and `curve_tree_layers` are `Derived`,
  `curve_tree_leaves` is `AppendMostly` (running chained hash —
  deletions are unrepresentable). The audit that defends those grades,
  [`docs/LMDB_WRITE_ATOMICITY_AUDIT.md`](../LMDB_WRITE_ATOMICITY_AUDIT.md)
  lines 1681–1695 at `dev@4da609cbd` (was 1518–1531 at `edb35dbb1`;
  note: `docs/`, not `docs/design/`), is explicit that verifying
  checkpoints against `curve_tree_meta` compares a copy with its
  original and is blind to a bad tree, so verification **must**
  recompute from the leaves. Leaves being the source is the whole
  reason `Derived` is defended as legitimate rather than convenient;
  discard removes the discriminator's only input. This is F7's false
  premise (`db_lmdb.cpp:9922`) one layer up, in a document that was
  right at the time it was written and stops being right the moment PDM
  ships. Carrier: the DRS-0 lane re-grades the three rows against Q1's
  output; §5 names the dependency.
  **UPDATE 2026-09-13 (`dev@4da609cbd`, PR #726 merged): the
  contradiction is now a handoff, and the handoff's shape is DRS's,
  not this charter's.** DRS-0a ruled (`DAEMON_REDB_STORE.md:1142-1175`,
  Rick, "pruning is NOT node variable") that *a digest cares whether
  nodes AGREE, not whether bytes are PRESENT*: a uniform,
  consensus-scheduled discard leaves every node holding identical
  state at the boundary and is digestible as an accumulator **defined
  over the consensus-retained floor**, with archiver surplus
  definitionally outside the digest domain; only node-variable discard
  forces `Excluded`. That is exactly Q7/Q8/`W`'s shape (uniform
  boundary, exceptions above it), so the predicted outcome on DRS's
  side is that exclusions are **lifted, not re-pointed**. Three
  consequences for this charter. (i) What PDM hands DRS is not a list
  of re-grades but **the boundary** — `W` (Q2) for bodies, Q1's journal
  horizon — over which the floor-defined accumulator is taken; the
  "re-grade to `Excluded`" language in F22 (ii) below is **withdrawn**
  in favour of that. (ii) The `curve_tree_leaves` narrowing DRS landed
  and reverted the same day (`116b424b6`) rested on a wallet citation;
  its reversion premise — the daemon's leaves do not vary between
  honest nodes — **stays true under PDM**, because Q1's leaf discard,
  if ruled, is uniform. F11's substantive half also stands: an
  accumulator over a stored `R_k` certifies the commitment, not the
  data, so a leaf digest that survives discard is a *windowed* fold
  over the retained leaves, not a fold over `R_k`. (iii) DRS's
  reopening clause reads *"stops reading arbitrary local leaves,
  **followed by** a node-variable daemon discard"*; under PDM the
  second conjunct never fires — the trigger is the lifting, not the
  exclusion — and the charter says so where DRS will look (§5).
  `class.rs` is byte-identical at `4da609cbd` to `edb35dbb1`; the
  `:140-142` / `:149` / `:161-163` anchors hold. `:164`
  (`txs_prunable_tip`, `Excluded`) is a fourth row on the same floor,
  and under Q7 its grade is **moot rather than wrong**: it is
  stripe-engine scaffolding that dies with `prune_worker` at
  `DRS-E*`.
- **PDM-Q-F12.** **Leaves are a cache of a pure function of the block
  corpus. Set-B scarcity, as currently scoped, does not exist.**
  Trace the construction: `blockchain_db.cpp:608-611` calls
  `shekyl_construct_curve_tree_leaf(output_key, commitment.bytes, h_pqc,
  leaf)` — three inputs. `output_key` and `commitment` are the output's
  `O` and `C` (`:564`, `:597`). The fourth scalar's input (the leaf
  commitment point, `PL-D3`) has its provenance at `:528-546`:
  `extract_leaf_hashes` pulls the `tx_extra_pqc_leaf_hashes` field
  (`0x07`) out of the transaction, exactly `64 · vout.size()` bytes, one
  entry per output, and `:557` indexes it. So the fourth scalar lives in
  **the transaction blob**, which is
  block corpus and retained under D10's replay premise. Every one of the
  four scalars is reconstructible from data a discarding node keeps —
  `O`, `I = hash_to_p3(O)`, `C` from `output_metadata` via
  `get_output_key(0, i)` (the RPC already does exactly this, via
  `shekyl-fcmp::rpc_path` / `curve_tree_path.cpp`) or from the blocks directly if
  `output_metadata` is itself discarded (`Excluded`, `class.rs:149`);
  the leaf commitment from `tx_extra` `0x07`. The regeneration path is not
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
  (`blockchain_db.cpp:597`) and the leaf commitment from `tx_extra` `0x07` — all
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
  chain is a rule-60 deletion — **landed in PR #733 (2026-09-13)**. The
  disclosed `m_scan_table` residue landed in the same PR: the ring-member
  pre-fetch is gone; duplicate-tx and duplicate-key-image
  `ATTRIBUTABLE_FORM` drops remain as two `unordered_set`s over the batch.
- **PDM-Q-F19.** **The slash log's forward reader is bounded on every
  path, and on no path is the bound a check.** The reviewer's read
  was one path; the pin has two, and the answer is the same shape on
  both. `archival_slash_removed_holding_after` (`db_lmdb.cpp:5243`) is
  reached only via `archival_bond_holds_shard_of` (`:5328`; calls at
  `:5385`, `:5388`), whose `at_height` is always an `h_fire`:
  1. *Serve-credit consumer* (admission): `blockchain.cpp:5270`
     → `archival_bond_holds_shard` (`db_lmdb.cpp:5315` → `:5325`).
     Bounded by the **credit deadline**: the vin is rejected if
     `current_height > h_close` (`blockchain.cpp:5222-5226`, verdict
     `POLICY_OR_STATE` — the right class, unlike the
     `INTERNAL_FAILURE` at `:5327` that F8b flagged), and
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
     `at_height ≥ tip − (CHALLENGE_RESOLUTION_BLOCKS + n·SETTLEMENT_EPOCH_BLOCKS + D_max)`,
     where `D_max` is the depth the pop path can rewind the watermark
     by — the consensus reorg cap, which **does not exist at this pin**
     (`PDM-Q11`).

  So the horizon exists as a **formula**, `tip − (CRB + n·SEB + D_max)`,
  and Q1 can name it. Three things about the number it evaluates to:
  - **`n` is PROVISIONAL, not frozen.**
    `config/consensus_constants.json:30`: shape genesis-frozen,
    numerics re-pinned at the Round-2 testnet stressnet against the
    measured outage-duration CDF, on the `bond_duration` precedent.
    If `n` moves, the floor moves. The same comment records that C++
    already reads `m`/`n` through `shekyl_archival_failure_window_params`
    precisely so there is one authority and no drift pair — the
    horizon is **computed** through that path, never a literal.
  - **`D_max` has no constant behind it** (F10; §3 *Reorg*). It is the
    term with nothing behind it, so it is the one that must not round
    to zero. A number stated without it — `tip − 140,000` — is wrong by
    the one term that is not yet ruled.
  - At the provisional values (`CRB = SEB = 10,000`, `n = 13`,
    `D_max = 720` per the `PDM-Q11` candidate) the floor is
    `tip − 140,720`. A test pinned to that literal goes stale the
    moment Round-2 moves `n` or `D_max`; a test that recomputes goes
    red only when the formula is wrong.

  What Q1 cannot do is name the horizon *alone*: on both paths the
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
     [`P2P_1_WIRE_CENSUS.md`](../design/P2P_1_WIRE_CENSUS.md) line 367).
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
  F12 showed is not scarce. Q6 item 4's unit change can take the
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
  **UPDATE 2026-09-18 — the "worth taking" half is REFUTED by `PDM-Q7`'s
  ruling.** Each of the triple has a successor that is not the engine:
  assignment is the bond, advertisement is the bond, coverage is price.
  The arithmetic is not read from before it dies; the `pruning_seed`
  slot is retired (zero on send, ignore on receive). The *diagnosis*
  stands — the stripe partitioned F13's good and §3's "unrelated"
  was wrong — and this finding is kept as the record of a candidate
  considered and refused.

### Established by reading (2026-09-13, same pin — the serving-side and sync pass)

- **PDM-Q-F20** — (a)/(b) CORRECTED 2026-09-13, see end of entry; (c) stands. **Under Q6's unit, sync is the read — for band 2 only, after the anchor correction.** A fresh node
  verifies every proof and PQC signature in history by default; under
  Q6 no ordinary peer holds those bytes beyond `tip − W` (`W ≥ D_max`, Q2), so every
  fresh node's bootstrap is a read of the *entire* good from
  archivers. Three consequences. (a) *Coverage is chain liveness*: a
  range with no archiver is a range no new node can ever verify —
  the floor is Q9's, the loud node state is Q5's. (b) *The possession
  test gets organic demand*: TJ ruled "the test IS a read" and then
  had to manufacture readers (miner attestation); syncing nodes are
  real readers with a real need, arriving continuously, reading whole
  ranges and verifying every byte against a hash they hold — an
  archiver that drops bytes is caught by the next node that syncs, not
  by a scheduler. Whether such reads *earn* credit is the credit
  wire's; that they *exist* changes the threat model. (c) *The
  skeleton suffices for state, the body for proof*: everything a node
  needs to build current consensus state is derivable from the
  unprunable base plus the two hash rows (F12 for the tree;
  `spent_keys` from the prefix; archival tables from kept-side
  headers), so bootstrap decomposes into skeleton sync from any peer
  and body fill from archivers, and "I have verified genesis→tip" is a
  separable job. The inherited `--sync-pruned-blocks`
  (`cryptonote_core.cpp:127-130`; `cryptonote_protocol_handler.inl:139-152`
  accepts a pruned entry on the txid alone) is the Monero-era
  trust-the-txid form of body-less sync and must not become the
  default by inheritance (`00-mission` priority 1). Q5 widened.
  **CORRECTED 2026-09-13 (Q5's anchor model, `PDM-Q-F23`): (a) and
  (b) as first stated are false for current binaries and survive only
  narrowed.** Under the release-carried anchor a fresh node reads
  archivers only for band 2 — the release gap — so *coverage is chain
  liveness* holds for the **launch window** (`C = 0` until the first
  post-genesis checkpoint release), for **stale binaries**, for
  `assumevalid=0` **auditors**, and for **history read-back**; not for
  chain-following in general. Likewise the possession test does **not**
  get organic demand from sync in the steady state: it stays synthetic
  (challenges, manufactured readers), and *"an archiver that drops
  bytes is caught by the next node that syncs"* is true only of the
  gap. **The credit wire must not count organic sync reads as
  detection.** (c) stands unchanged and is what makes the anchor model
  work: state from the skeleton, proof from the body.
- **PDM-Q-F21.** **The serving side holds the retired unit, and
  serving it over P2P would unmask the persona.** Two facts. (i) `P`
  serves today from a wallet-side redb `LeafStore`
  (`rust/shekyl-curve-tree/src/store/redb_backend.rs`; `ServingReader`
  / `open_frozen_segment_body` at `:164-183`, `FrozenSegmentPruned` at
  `:464`), a second database separate from the daemon, holding leaves
  in tree order for verification against `R_k` — i.e. the unit F12
  showed is a cache. The store is not redundant; it holds the wrong
  object (Q12). (ii) If the daemon holds shards (Q9's candidate) and
  answered P2P requests for beyond-window bodies in `range(s)`, the
  chain's own publication of `s` in the bond makes the one clearnet
  peer that serves them identifiable as that persona's daemon. The
  inherited serve path negotiates retention per peer
  (`cryptonote_protocol_handler.inl:963`, `:2343-2346`,
  `pruning_seed`). **Ruled on the spot (`PDM-Q8`): P2P body-serving
  is uniform inside the universal window on every node**; beyond-
  window serving is wallet-fronted over onion only; fetching lives in
  the daemon (Q5, band 2).
- **PDM-Q-F22.** **Two boundary facts the Q6 verifier design must
  carry.** (i) The coinbase's `prunable_hash` is `null_hash` whenever
  `ct_signatures.type == CTTypeNull` (`cryptonote_format_utils.cpp:1299-1302`),
  and the coinbase is always `CTTypeNull` — so nothing on a coinbase
  prunable side is committed to by `txs_prunable_hash`. The credit
  wire already hit this and answered it with the block-level
  `attestation_root` (`ARCHIVAL_CREDIT_WIRE.md` §3.1, "why the
  coinbase's `prunable_hash` cannot carry the commitment"); Q6 cites
  the precedent. (ii) DRS-0 slice A already grades the good the way
  Q6 wants it: `txs_prunable` is `Excluded` and `txs_prunable_hash` is
  `AppendMostly` (`class.rs:162-163`) — body non-accumulator, hash
  permanent — without knowing why. The one row that is wrong under
  F14 is `txs_pqc_auths` at `AppendMostly` (`:161`); ~~it takes the
  same re-grade F11 asks for the curve-tree rows~~ — **WITHDRAWN
  2026-09-13 (F11 UPDATE): under DRS-0a's "agree, not present" ruling
  a uniform discard does not make a table `Excluded`; `txs_pqc_auths`
  and `txs_prunable` alike become floor-defined accumulators over
  `(tip − W, tip]`, and what PDM owes DRS is `W`, not a grade.** The
  per-tx permanent cost of the whole design is the two 32-byte rows.
- **PDM-Q-F23.** **The checkpoint table is empty at the pin, and the
  inherited machinery is the reorg cap and the sync anchor in one
  function.** `init_default_checkpoints` is a no-op on every network
  (`checkpoints.cpp:163-172`, shaped as per-network data under rule
  71). `is_alternative_block_allowed` (`:124`, called at
  `blockchain.cpp:2242`) refuses any reorg below the last checkpoint —
  so with an empty table the chain has **no reorg cap at all**, which
  is Q11 stated from the code side. A syncing node verifies every
  proof in every historical block: the only skip is the
  pool-admission cache (`blockchain.cpp:5978`, structural checks still
  run), `:5681`'s checkpoint-zone skip is commented out, `:5722` is
  hash matching. At the pin the JSON checkpoint channel was **live**:
  `update_checkpoints` → `load_checkpoints_from_json`
  (`blockchain.cpp:6635` at `edb35dbb1`), reloaded every ten minutes
  from `cryptonote_protocol_handler.inl:698`; the DNS half was already
  deleted (comment at the same line). Consequences: Q5's anchor
  populates this table; Q11's `D_max` is the rolling cap above it and
  binds only once a node has an anchored chain; the JSON channel was a
  runtime trust path that bypasses the release-carried anchor — a
  rule-15/60 deletion **executed in PR #733 (2026-09-13)**: the loader,
  the periodic reload and `JSON_HASH_FILE_NAME` are gone, and the
  surviving conflict rollback runs once at `core::init` as
  `Blockchain::enforce_checkpoints`.
- **PDM-Q-F24.** **The universal bytes window had silently inherited
  `D_max`, and the convergence property was true only of a node that
  never stops.** Q4's "uniform `D_max` window" and Q5's band 3
  `(tip − D_max, tip]` set the window every daemon keeps full bodies
  for to one day (Q11's candidate 720). A node returning from downtime
  longer than the window has an anchored chain, so nothing in Q5's
  argument stops it — but bodies for the blocks it missed beyond
  `tip − W` are on no ordinary peer (Q8's uniformity), so it enters
  band 2 and reads archivers to verify blocks the network has already
  accepted. At one day that is the population of running nodes, not an
  edge case. The two parameters have opposite pressures: `D_max` is
  pushed *shallow* by adversary economics (Q11); the window has no
  adversary-side ceiling and is pushed *deep* by honest downtime
  tolerance, bounded only economically by how much of the chain stays
  scarce. `W` is minted as Q2's ruling variable (floor `D_max`;
  candidate F19's retirement floor so bodies and journals share one
  horizon); §8's convergence statement corrected to *unconditional for
  running nodes with downtime under `W`*; band table and F20
  re-pointed. Steering-raised 2026-09-13.
- **PDM-Q-F25.** **The `SF-` round closed on the leaf unit while this
  round was open, and its implementation row is now sequenced ahead of
  the ruling that changes its unit.** [`ARCHIVAL_SHARD_FETCH.md`](../design/ARCHIVAL_SHARD_FETCH.md)
  is *RULED — Round 1 CLOSED 2026-09-13* (merged to `dev` in PR #714,
  `99832006c`). What it fixes is sound and survives Q6 with the unit
  substituted: one client (`shekyl-p-fetch`) in the daemon's Tor zone,
  one entry point `fetch(destination, shard_id, header)`, challenge and
  organic callers indistinguishable on the wire (`SF-D1`), tor-zone
  SOCKS, `GET /shard/{id}` on port 80, one 72-byte
  `nonce ‖ anchor_height ‖ anchor_hash` header (`SF-D5` as amended), one
  in-flight cap, one miss/timeout taxonomy. Its **organic caller** is
  *"this daemon needs shard `s` (reconstruct, IBD-after-prune, operator
  test)"* (`:96-98`) — which is Q5's band 2 and Q9's recovery fetch by
  another name, **consistent with F20 as corrected** (the reads are
  real, they are just not chain-following for a current node under
  `W`). What does *not* survive is the unit: the request names a whole
  leaf shard (`SHARD_BYTES = 3,326,976`, `:521`; `RF-R1` grammar,
  `:166`), the response is a `ServedFrameHeader` leaf frame
  (`served_frame.rs:274`, `:176`), content-verify is
  `recompute_segment_r_k` over `[[u8; 128]]` (`store/ops.rs:139`,
  `:139`), and the challenge "verifies `R_k` over the whole shard"
  (`:100`). Under Q6 the request names a transaction range, the
  response is prunable bodies, and verify is per-tx against
  `txs_prunable_hash` / `txs_pqc_auth_hash` — the TJ-F rebinding Q4
  states. `SF-D1`'s own reopen clause (`:195`, "a storage-only
  pruned-daemon path … without a fetch client") does **not** fire —
  band 2 needs the client — so Q6 item 4 is what reopens it, on the
  unit. **Sequencing — RULED (steering, 2026-09-13): split the client
  at the verify seam; neither wait for Q6 nor build the whole thing.**
  The `SF-` ruling already draws the line: everything that survives Q6
  is transport, everything that does not is the frame codec and the
  content-verify, and the serve side proved the shape
  (`StoreShardProvider` sits behind a trait so the store could change
  under it). **Sub-PR 1, now:** `shekyl-p-fetch`'s dial, header,
  envelope, SOCKS reuse, in-flight cap and miss/timeout taxonomy,
  **and the envelope's countersignature verify in full** — against a
  body type of opaque bytes and a single **content-verify** hole
  `verify(body, expected) -> Result`. There are two verifies on the
  fetch path and they have different fates: the countersignature (`P`
  signed `nonce ‖ anchor_height ‖ anchor_hash ‖ shard_id` under the
  bond-record key, `SF-D8` v2) is
  transport authenticity, unit-independent, and is sub-PR 1's in full;
  the content-verify (bytes against `R_k` today, against
  `txs_prunable_hash` under Q6) is the thing that changes with the
  unit and is the hole. The countersignature check is not inside the
  hole, and the hole's `expected` is opaque until Q6 names it.
  **Sub-PR 2, blocked on `PDM-Q6`:** the frame codec and the per-tx
  content-verify; that row carries the Q6 dependency. Rule 26's sub-PR line *is* the seam. This defuses
  the real hazard, which is not wasted work: a client built now against
  `recompute_segment_r_k` becomes the thing Q6 has to argue *against*
  instead of the thing Q6 rules *on*. **Falsifier (rule 15, so the
  split does not rot into a permanent abstraction):** sub-PR 1's body
  type is `Vec<u8>` and nothing else. A unit-aware type, a leaf/tx
  enum, or any polymorphism over the two shapes means the unit decision
  has leaked into the transport layer, and the split is reverted. The
  hole is a hole, not an interface. The `SF-` implement-row in
  `docs/FOLLOWUPS.md` carries this split (edited on steering's ruling).

### Established by reading (2026-09-16, `dev@645d09dc3` — the store-shaping pass)

Read a day past the round's pin, after DRS-E1 increment 3 (S-CHAIN-W,
PR #757) and DRS-E6 slice 1 (PR #761) landed. Nothing above is
contradicted; S-CHAIN-W's SCW-7 is exactly F10's shape — the undo-log
watermark asserted `≥ D_max` on the deletion side, `StoreCannot::PopBelowFloor`
as a typed refusal on the read side, landed in the Rust store before the
C++ is ever fixed. One finding, and it is the actionable one.

- **PDM-Q-F26.** **The Rust store is being shaped for one of Q6's two
  occupants.** `TxIdentity` (`rust/shekyl-chain-rules/src/block.rs:22-27`)
  is `{ hash, prunable_hash }`, minted once in `validate` and carried by
  `ValidatedBlock` into `connect` (SCW-10). There is no `pqc_auth_hash`
  anywhere in `rust/` — not on the identity, not as a row, not as a type
  (`rg pqc_auth_hash rust/` is empty at this sha). F14 named `pqc_auths`
  — ~60 % of spend bytes — as the good's second occupant, GOOD **only if
  its hash is a persisted per-tx row**; Q6 items 1 and 2 are ruled
  jointly because the prunable region alone is ~35 % of the bytes and
  the two together ~95 %. DRS-E1 has committed the per-tx identity to
  one hash, by default, before Q6 ruled either. This is the hazard the
  banner names — *the store trait shaped for universal discard rather
  than retrofitted* — arriving in the first increment that could carry
  it. Three things make it cheap to correct now and expensive later:
  1. **The value already exists on the write path.** The v3 spend txid
     is **4-part** — `H(prefix) · H(base) · H(pqc_auths) · H(prunable)`
     (`rust/shekyl-wire/src/transaction.rs:1624-1631`, oracle
     `format_utils.cpp:1137/1163-1182`) — so `Transaction::hash()`
     computes the `pqc_auths` component on the way to the txid
     (`:1734-1739`). Persisting it is a field on `TxIdentity` and a
     row, not a new computation and not a new consensus value: it is
     the third component the txid already commits, exactly as
     `prunable_hash` is the fourth (SCW-10's argument, applied to the
     component it skipped — SCW-10 describes the identity as *"one of
     the three component hashes"*, which is the coinbase's arity, not
     the spend's).
  2. **Which bytes the row hashes is a KAT question, and the answer is
     already forced.** The txid's `pqc_auths` component hashes
     `varint(count) ‖ auths` — the oracle's generic-vector serializer
     writes a leading count (`:1729-1737`) — while the store's
     `txs_pqc_auths` segment carries the auths with **no** length
     prefix (`TxSegments`, `:1358-1361`; `write_pqc_auths`, `:1141-1144`).
     `keccak256(txs_pqc_auths[tx_id])` is therefore **not** the txid
     component. The row that lets a node discard the segment and
     re-verify a fetched copy against something the txid commits is the
     count-prefixed component; a row over the raw segment would verify
     nothing the chain signed. The identity field should be that
     component, named for what it is (`pqc_auth_hash`, the txid's third
     part), with a KAT pinning it against `Transaction::hash()` the way
     `prunable_hash` is pinned. The C++ oracle agrees: the pruned-txid
     path serialises `std::vector<pqc_authentication>` through
     `binary_archive` — count first — before hashing
     (`cryptonote_format_utils.cpp:1319-1325`). The older FOLLOWUPS row
     that read *"computed from the raw `txs_pqc_auths` bytes"* was wrong
     on exactly this point and is folded into F26's row (one hashing
     contract in the repo, not two).
     **The component is absent from two shapes, not one.** The txid is
     3-part for the coinbase (`Ct::Null`) **and** for any spend whose
     `pqc_auths` is empty — the serve-credit form (`:1725-1726`,
     `pqc_auths.is_empty() || first_is_gen`). `TxIdentity` is also the
     miner tx's identity (`ValidatedBlock::miner_tx`), so the field is
     `Option<PqcAuthHash>`: `None` means *the txid has no such
     component*, and a sentinel — the null hash, `keccak256(varint(0))`
     — would label the miner tx with a value the chain never committed.
     `prunable_hash`'s coinbase value is a sentinel only because
     C++-store parity forced one (`keccak256("")` is the row the C++
     store writes); no C++ row exists for this hash, so nothing forces
     one here. **The store invariant has three legs** (corrected
     2026-09-16 on review — the two-leg form first written here made
     universal discard itself a violation): (i) hash row present ⇔ txid
     4-part, permanent, written at connect and never deleted, with
     `validate` rejecting the one shape (gen-first with auths) that
     could split "4-part" from "segment non-empty"; (ii) segment present
     ⇒ hash row present — a body the store cannot verify is the fault;
     (iii) hash row present ∧ segment absent ⇔ **discarded** — below `W`
     and not a retention exception, or never held (a band-1 skeleton,
     Q5). Leg (iii) is the design's steady state for every 4-part tx
     below `W`, and it is one store state with one meaning however the
     node arrived at it: post-discard and band-1 are not two conditions
     to be told apart, which is what lets the fetch primitive, band-2
     fill, recovery and read-back be the same read (§8). `None` on the
     identity is *the txid has no third component*; leg (iii) is *the
     component exists and the bytes do not*. Different facts, no shared
     representation.
  3. **The bijection blocker has expired.** The `SF-`-era note in
     `docs/FOLLOWUPS.md` (*"the first redb-only table fails CI, which is
     why F14's `txs_pqc_auths_hash` cannot be added without a second
     change"*) was true at `edb35dbb1`. S-CHAIN-W landed the first
     Rust-only table (the undo log) with a `RUST_ONLY_TABLES` `{table:
     reason}` allowlist in `check_redb_schema_bijection.py` (SCW-11), so
     a `txs_pqc_auth_hash` row is admissible today on the same map.
     Nothing outside DRS's own increment sequence blocks it.

  **Handoff (to the DRS-E lane; the shape is theirs to land, the
  requirement is this round's).** `TxIdentity` carries both hashes —
  `{ hash, pqc_auth_hash: Option<_>, prunable_hash }`, `None` ⇔ 3-part
  txid — and the store records the second beside `txs_prunable_hash`,
  present ⇔ 4-part and never deleted, at S-CHAIN-W's own standard: the
  contract written on the row **before** the implementation that would
  omit it (SCW-7's precedent, which put `D_max` on S-PRUNE's row while
  the prune had no home). The field is owed to `PDM-Q6` item 2 and is
  **not optional**: a Q6 ruling that keeps `pqc_auths` universal is a
  ruling that a per-tx row is unnecessary, not that the identity may
  omit a component the txid commits. The doc comment on `TxIdentity`
  now says so, so the lane that next touches the type reads the
  requirement at the type.

  **The deadline this names.** *"DRS-E2's replay is the store's first
  production writer."* Every DRS increment that lands while Q6 is
  unruled narrows what Q6 can rule; `TxIdentity` is the first instance,
  and E2 — which decides what happens to the prunable body and the
  `pqc_auths` slice on the write path — is the next and larger one.
  **Q6 items 1 and 2 are ruled before E2's first production writer, or
  E2 rules them by construction.** That is a date, and it is closer
  than "the ruling pass has not started" reads. Q6 items 1–3 are
  argued to the point where the ruling is a transcription of F13 / F14
  / F17 with rule-21 shape against §3's six adversarial items; nothing
  is blocked on code. Q11 is the other item with a clock: its *shape*
  is written (§7 row), what it lacks is a **named consensus-side
  owner** — a person, today, not a further round. Both are steering's.
  **Falsifier for the deadline:** an E2 replay PR opens while the Q6
  row in `IMPLEMENTATION_INDEX.md` still reads OPEN — at that point the
  deferral is void, and that PR's description must state which Q6
  items it is ruling by construction, or it does not merge.

  **Contact with `SO-`** (the settlement writer, §5 first bullet;
  `docs/so-d8-d12-reshaping` in flight re-homes SO-D8/D9 onto
  `shekyl-chain-rules` under DRS-D12). Two consequences of F13/F14 the
  SO lane should read before its Slice C: (a) the serve-credit tx's
  prunable region — where SO-D8's batching shape puts the witness pk
  and signature once per tx (`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`
  §9 batching row) — **is F13's good**: below `W` an ordinary node does
  not have those bytes. Admission-time reads survive; any settlement,
  slash or reward path that re-reads a witness signature from the store
  after `W` does not, and F15's `serve_credit_pruned` form is the
  witness that the design already assumes this. State per read which
  it is. (b) A settlement write set that lands on the Rust store before
  Q6 rules inherits F26's hazard in the same shape as `TxIdentity` — it
  fixes what a pruned node persists about a serve-credit tx by
  construction. The re-homing onto chain-rules is the right move
  (validation precedes connect, DRS-D12); the Q6 ordering applies to
  its writer the same way it applies to E2's.

Three more, read on review of F26 the same day (`ee5609cb9`), in the
order they bite. Each is a shaping request to a lane that is freezing
the relevant type *now*; none is a ruling.

- **PDM-Q-F27.** **`RuleSet` needs a below-anchor mode, and E6 is
  shaping `RuleSet` now.** DRS-D12: validation precedes connect;
  replay-that-validates is the only pre-cutover writer; every block
  passes `shekyl-chain-rules::validate` before `connect`, and a
  `ChainValid` carries a `RuleCoverage` that must cover every
  implemented row the rule set enforces
  (`rust/shekyl-chain-rules/src/verdict.rs:86-95`, a `panic!`, not a
  `debug_assert`). Q5 band 1: below the release anchor `C` a fresh
  node holds skeleton only — no prunable body, no `pqc_auths` — and
  proof validity is asserted by the anchor, not checked (§2, Q5 bands
  table). Those two meet at one type. A skeleton block cannot pass a
  `validate` that checks proofs, so under D12 it can never be connected
  — **band 1 is unbuildable against the only writer** unless the rule
  set it is validated under omits the proof rows. The type already has
  the seam: `RuleSet { id, enforced: &'static [CenRow] }`
  (`rule_set.rs:82-85`), `ISSUED` is the closed list of sets that
  exist (`:96`), and coverage is measured complete against *that set's*
  `enforced`. What is missing is (a) an issued below-anchor set whose
  `enforced` omits the proof rows, (b) a selector for it that is not
  `RuleSchedule` — the schedule is height → set per network, and
  below-anchor is a position relative to *this node's* `C`, not a
  height at which the chain's rules changed (rule 71: `C`/`H` are
  per-network *data*; the arm that consumes them is one code path),
  and (c) a home for the anchor check itself (block `C` has hash `H`):
  `CenRow` is a bijection with the census
  (`check_chain_rules_coverage.py`), so it is either a census row or a
  node-policy check outside `CenRow` — Q5 names which; either way it
  lands *with* the set. The store already persists `RuleSetId` and
  `RuleCoverage` per connected block (S-CHAIN-W), so a band-1 connect
  is legible on disk as one — that is the property, not a by-product.
  Pre-cutover replay runs over the full LMDB chain and never meets a
  skeleton, which is why E2 will not notice; `RuleSet` and
  `RuleCoverage` are being frozen in E6's slices today, and a `RuleSet`
  with no below-anchor arm is `TxIdentity` with one hash — cheap now,
  a retrofit later. **Handoff:** on the DRS-E6 row and in
  `CHAIN_RULES_CRATE.md` §13, at SCW-7's standard. Falsifier: E6
  closes `ISSUED` (declares the rule-set list complete, or lands the
  slice that consumes `RuleSetId` from the store on the read side)
  with only `GENESIS` issued and no recorded decision on the
  below-anchor arm.
- **PDM-Q-F28.** **Band-1 sync needs both hash components on the
  wire, and the payload is KAT-pinned.** A skeleton block on the wire
  is the pruned blob plus the txid components the receiver cannot
  compute. Today that is one: `tx_blob_entry { blob, prunable_hash }`
  (`src/cryptonote_protocol/cryptonote_protocol_defs.h:49-58`), mirrored
  byte-for-byte by `shekyl-levin::payload::block::TxBlobEntry`
  (`rust/shekyl-levin/src/payload/block.rs:33-38`, KATs in
  `tests/notify_kats.rs`), and the receiver rebuilds the txid with
  `Transaction::hash_with_supplied_prunable`
  (`rust/shekyl-wire/src/transaction.rs:1665`) because the pruned blob
  still carries `pqc_auths`. Under Q6 item 2 the skeleton drops the
  `pqc_auths` slice too, so the receiver cannot compute the third
  component either: **without `pqc_auth_hash` on the wire a band-1
  receiver cannot reconstruct the 4-part txid and cannot verify the
  block's tx list.** Two consequences: `TxBlobEntry` grows a field
  (`Option`-shaped on the same predicate as the identity — absent for a
  3-part tx), and `shekyl-wire` gains the two-supplied form of the
  pruned txid. Not DRS-E's to own — it is the `LV-` payload crate and a
  `PWC-` wire-census row (P2P-2) — but DRS-E's ingest has to accept it,
  and the skeleton format grew a field that nobody was named for.
  **Handoff:** FOLLOWUPS row naming `LV-` / `PWC-` as owner, gated on
  Q6 item 2 (the field exists only if the slice is discardable).
  Falsifier: Q6 item 2 rules `pqc_auths` discardable while
  `TxBlobEntry` still has one hash field and no `PWC-` row records the
  growth.
- **PDM-Q-F29.** **Q3's instrument is a property of `ChainView`'s
  surface, and it holds today by construction.** Q3 owes an instrument
  that goes red if a consensus read reaches a discarded body. D12's
  architecture makes it nearly free: `shekyl-chain-rules` has no store
  handle (`check_chain_rules_no_store.sh`, transitive) and reads the
  recorded chain only through `ChainView<'id>`, whose surface at this
  sha is `has_key_image`, `block_at` (hash + header, no bodies) and
  `root_at` (`view.rs:100-132`) — **no accessor returns recorded
  transaction bytes**, and round-1 Q3 already rules that a view field
  exists only when a named `CenRow` reads it
  (`CHAIN_RULES_CRATE.md` §3.3, `output_at` refused on exactly that
  ground). So the residual-consensus-read set Q3 asks about is empty
  *in the Rust validator* by construction, and the instrument is the
  surface itself: either `ChainView` never gains a recorded-body
  accessor, or the one that arrives returns the discarded case as a
  variant (the `AtHeight` discipline, `view.rs:61-68` — absence is a
  variant, not `None`, so a rule must match it) and every rule that
  takes the recorded arm is by construction an above-`W` rule and says
  so in its row. The falsifier is then compile-shaped — *a
  `ChainView` method returning recorded tx bytes with no `CenRow`
  justifying it, or a rule matching its recorded arm without an
  above-`W` marking* — rather than a grep over `src/`. This does not
  discharge F8: `blockchain.cpp:5327` still reads leaves in the C++
  path, which is why Q3 is conditional on TJ-A. It says where the
  instrument lives once the validator is the Rust one. **Handoff:**
  `CHAIN_RULES_CRATE.md` §13, as a standing property of the trait with
  its falsifier, at SCW-7's standard; the last time it is cheap is
  before the first body-shaped row lands.

**Deferrable without harm, named so the omission is a decision:** the
retention-exception structure and the body-discard predicate's
enforcement point (both S-PRUNE, not extracted — `DAEMON_REDB_STORE.md`
§7); and D11's digest domain — pre-cutover it is the full chain on both
sides, the `AppendMostly` running hash is already over the permanent
hash rows, so `W` enters the digest only when the prune surface does.

### Established by reading (2026-09-17, `dev@4bc378d68` — the census-consequence pass)

Read after PR #767 (E6 slice 1 `held_by_cxx`). `pqc_auth_hash` is still
absent from `rust/` as a field — it sits in the unmerged E6 `tip` branch;
#766 landed DRS §7.7 as the landing plan. F26–F29 are in this charter and
nothing in them is contradicted. Four gaps, one of them a census
consequence that no lane had recorded.

- **PDM-Q-F30.** **Q11's home is `CEN-E2`, not `CEN-E1` — and F27's
  implementation fires both rows' recorded reopening trigger.** This
  charter has said since 2026-09-13 that `D_max`'s home is
  `is_alternative_block_allowed` above the checkpoint (Q11 row; Q5 item
  5). At HEAD the census puts that function on **`CEN-E2`**
  (`CONSENSUS_RULE_CENSUS.md:369`: *an alternative block at or below the
  last checkpoint is refused*, `checkpoints.cpp:137`). **`CEN-E1`**
  (`:368`) is a different rule — *hash equality at a checkpointed
  height*, `check_block`. The E6 lane's unmerged `tip` text for F27
  says *"the anchor rule already has a row, CEN-E1"* and the 2026-09-17
  status report repeated it; both are one row off for the refusal arm.
  The anchor model uses **both**: E1 is the band-1 trust assertion
  (block `C` has hash `H`), E2 is the reorg fence `D_max` hangs from. A
  consensus-side owner pointed at E1 alone would be reading the wrong
  function for Q11. **The larger consequence:** both rows are
  ratified under the same C2-R1b premise — *existence HELD for C2-R0;
  semantics ratified **while the mechanism exists*** — and they word
  the consequence differently (corrected on review, read at `:368-369`):
  **`CEN-E1`** states the trigger explicitly — *crossing reopens when
  DRS/R8 moves checkpoint state (trigger re-checked at #595: not
  live)* — while **`CEN-E2`** records only the premise (*the alt-height
  floor stands as the checkpoint arm's admission fence*) with no
  explicit reopening clause. F27's `Trust::BelowAnchor(anchor)` sourced
  from a release-carried table in Rust **is** moving checkpoint state
  into Rust. For E1 that is the named trigger firing; for E2 it is the
  ratification premise ceasing to hold — the mechanism the row was
  ratified *while it exists* stops being the C++ one. Same event, two
  wordings, both rows reopen; E2's row should gain the explicit clause
  in the re-key so the next reader does not have to infer it from the
  premise. It fires the day E6's slice 3 or 6 lands the mode. The Q2 crossing question
  those rows closed — *derivation-free hash equality, nothing for Rust
  to hold* — was closed on the premise that the mechanism stays in C++.
  Under the anchor model it does not, and under `assumevalid`
  semantics E1 also does more than equality (it asserts validity of
  everything beneath). **Owed, in F27's landing PR, not after:** a
  re-key of `CEN-E1` and `CEN-E2` — new site (the Rust `Trust` arm and
  the store's anchor row), the Q2 crossing answered for a Rust-held
  table, and the C2-R0 existence HOLD closed one way or the other — or
  the census carries two rows whose stated trigger has fired. Also
  line-local: `CEN-E1`'s rule text still reads *"hardcoded/JSON-loaded
  checkpoint hash"*; with `CEN-E5` removed (F23, PR #733) the
  JSON-loaded half is dead text inside a ratified rule, and the re-key
  retires it. This charter does not edit census rows (the C2 lane's);
  it names the carrier. The `CEN-E1` claim in E6's `tip` text is
  flagged here as another lane's line, to be corrected when that branch
  lands.
- **PDM-Q-F31.** **S-PRUNE has no plan doc, and the store-side
  implementation items in this charter land on or adjacent to it.**
  Scoped on review (2026-09-17): not *every* §8 item — F27's
  below-anchor mode is E6's and F28's skeleton wire field is
  `LV-`/`PWC-`'s, and neither belongs in an S-PRUNE plan. What is
  S-PRUNE's: the discard predicate on `eligible_height` vs `tip − W`
  (F10), retention exceptions (`retain(s)`/`release(s)`, Q9), the
  undo-log floor (SCW-7), the `pqc_auths` discard consuming the hash
  row (F26), and `W` entering D11's digest domain. S-PRUNE is deliberately **not
  extracted** (`DAEMON_REDB_STORE.md` §7: five of six methods are the
  stripe engine, superseded before they can be ported) and already
  carries two contracts written on its row before it has a home (SCW-7,
  F26's three-leg invariant). It has no `DRS_E*_SPRUNE.md`. Rule 26:
  design closure precedes any cut; E1 got `DRS_E1_SCHAIN_W.md` before
  its writers. S-PRUNE's successor needs the same before its first
  increment — and the plan doc is the natural place for the three-leg
  invariant, the discard predicate's enforcement point, the exceptions
  structure and the reorg item's discard-side half to stop being
  scattered across F10 / F26 / SCW-7 / §3. **It can be written now
  against this charter without Q6's numeric**: the unit (a tx range),
  the predicate (`retain`), the verifier (two hash rows) and the
  invariant are all stated; only `W`'s value and the exceptions'
  binding are open, and a plan doc carries those as named inputs. This
  is compatible with `PDM-Q-S0` — S-PRUNE *is* `DRS-E*`, and a plan
  doc is design, not implementation. **Owed by the DRS-E lane**;
  FOLLOWUPS row with the falsifier.
- **Q6 item 2 is now being built on an unruled default — stated
  plainly.** F26's default (`pqc_auth_hash: Option<PqcAuthHash>`,
  count-prefixed component, three-leg invariant) is in E6's `tip`
  branch as a field and a wire form, and DRS §7.7 schedules the
  `txs_pqc_auth_hash` row on S-CHAIN-R's layout commit. That is the
  right call — the default is the cheap one to have been wrong about —
  but it is the **second** increment building on an item Q6 has not
  ruled (the first was `TxIdentity` itself). When Q6 rules item 2 it
  is **confirming** a landed shape, not deciding one, and the ruling
  should say which. Recorded so the distinction is visible at ruling
  time rather than inferred.
- **Q11 owner: day five, still unnamed.** Minted 2026-09-13. Three
  derivers (F10, F19, SCW-7) and a fourth arriving with F27 (the anchor
  is `D_max`'s precondition, and `D_max` is the fence E2 enforces).
  Two rows of the census will reopen on its account (F30). It is a
  person, not a round; the shape has been written since the 13th.
  *(Resolved the same day: Q11 RULED by steering; the owner ask is
  discharged by the ruling.)*
- **PDM-Q-F33 (2026-09-18).** **PR #775 (`docs/two-store-daemon-uniformity`,
  head `e2b6b87f6`, OPEN at ruling) draws the line this round needed and
  rejects its Q9 candidate.** The daemon holds archival *consensus* state
  only, no archival *serving* state ever; the fingerprint criterion is
  *persistent, posture-correlated*; episodic universal actions are
  admitted; **all daemons prune uniformly** (corollary, RULED there).
  The full disposition is Q9's block. Recorded here as a finding
  because it also **re-keys #775 itself**: its architecture is
  unit-independent and stands, its consequences (partition constant,
  `R_k`, `frozen_segment_count`, the E3 sentence in its partition-tie
  FOLLOWUPS row) are leaf-shaped and re-key under Q6 / Q12 / F32 to
  `SHARD_BYTES`, the two hash rows and `b_*`. Whichever of #774 / #775
  lands second owes that re-key.

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

- ~~The prunable region as the archival good, the `pqc_auths` second
  occupant, and the leaf→transaction unit change … ruled first.
  **Q11's *shape* does not wait on Q6** … The critical path is Q6
  alone.~~ **RULED 2026-09-17: Q6 items 1–3 and Q11 (shape; numeric
  PROVISIONAL) are ruled** — see their §2 blocks. Q6 item 4 (the
  re-key/reopen disposition of each closed leaf-shaped ruling, F25's
  list among them) stays OPEN by name *(as of 2026-09-17; RULED 2026-09-18 —
  see the contract's Q6 block)*. **Unblocked by the two rulings:
  Q1, Q2, Q12; `SF` sub-PR 2; `PDM-Q-F28`.** Then the
  retained set (starting from layer 0 / `m_curve_tree_leaves`, F7;
  widened to the leaf's derivation inputs, F12; §9's `CACHE` and
  `LOCAL-BOUNDED` rows, F16), the trigger (including the free-regime
  duration, what the market does during it, the reorg-depth floor,
  F10 / F15, and `W` the universal bytes window, F24), residual
  consensus reads after TJ-A (Q3), reconstruction as the list of
  optional fetches (Q4), cold sync as the anchor question —
  release-carried checkpoint, launch window, release-gate full-verify
  step, band-2 egress, JSON-channel deletion, ordering with Q11 (Q5,
  F20/F23),
  stripe-engine residue at the cutover and unbonded exceptions (Q7),
  fetch-side privacy over onion (Q8's remaining half), the archiver's
  daemon-storage candidate, lapse tail, coverage floor and recovery
  fetch (Q9), the "not retained" RPC response (Q10), the freeze
  pipeline and `LeafStore` under the new unit (Q12).
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
| `PDM-Q1` | Retained set (layer 0 boundary, F7; widened to leaf derivation inputs, F12; §9 inventory; journal horizon `tip − (CRB + n·SEB + D_max)`, F19) | **RULED 2026-09-18** — §9 graded against the byte-bounded `tx_id` unit: GOOD = prunable region + `pqc_auths` (Q6), discarded per shard (Q2); KEEP-C gains the hash rows (A3) and length rows (A4); CACHE rebuilt by replay from the base (F12/F13, D10); LOCAL-BOUNDED journals retire at F19's horizon = `W` through `shekyl_archival_failure_window_params`. Both undetermined readers resolved (F18, F19). Owed as implementation: the horizon asserted at the journals' retirement site (FOLLOWUPS) |
| `PDM-Q2` | Trigger, depth, free-regime duration, discard predicate on `eligible_height` (F10); **`W`, the universal bytes window** — floor `D_max`, honest-downtime argument, economic ceiling, candidate F19's retirement floor (~195 days) so bodies and journals retire together (F24); the free regime's market behaviour is **bootstrap** — the ruled staker emission share (`DESIGN_CONCEPTS.md` Component 4) favours early adopters by intent; the `bond_duration` vs `W` relation proposed by the §3 walk on 2026-09-17 is WITHDRAWN the same day, no gate entry | **RULED 2026-09-18 (shape; numeric PROVISIONAL)** — shard-granular predicate `b_{k+1} ≤ first_tx_id(tip − W) ∧ k ∉ exceptions ∧ close_height(k) + SEB < tip`, asserted at S-PRUNE's per-epoch batch; `W` set by coincidence with F19's journal floor (`CRB + n·SEB + D_max` ≈ 140,720 ≈ 195 days), honest downtime satisfied as a consequence, the day-195 no-scarce-byte cost stated as an argument; every shard has its own `≥ W` bondable-while-universal window; the two-`W` rollout is a bounded Q8 exception; pass records fall under the predicate; item 4 row 1 is a precondition of the first real discard. Numeric to the Round-2 gate with `n`, `D_max` |
| `PDM-Q3` | Residual consensus reads after TJ-A; **the instrument is `ChainView`'s surface (F29)** | **RULED 2026-09-18** — Rust: empty by construction (F29, `ChainView` has no body accessor; standing property in `CHAIN_RULES_CRATE.md` §13). C++: the one residual reader is the serve-credit verifier's leaf read (F8; `get_curve_tree_leaf_chunk`, `blockchain.cpp:5099` today) — Q6 item 4 row 1, dies at E4 / S-ARCH, not with the stripe engine |
| `PDM-Q4` | Reconstruction path — collapsed: no chain-following read reaches an archiver for a node with downtime under `W`; the daemon's fetches (band-2 fill, own-exception recovery, history read-back) are all optional; TJ-F rebinds to the per-tx verify (a body-fill read that does not hash to the retained row fails loudly, never skipped) | **CLOSED 2026-09-18** — collapsed (F20/F23/F24); TJ-F re-bound to the per-tx verify; the daemon's fetches are episodic and optional (#775). A record |
| `PDM-Q5` | Cold sync and bootstrap — the anchor question: release-carried checkpoint on the `assumevalid` argument, three bands (`≤ C` trusted with the binary; `(C, tip − W]` filled from archivers; above from peers, `W ≥ D_max` per F24); trust-below fallback REJECTED; owes the launch window, the release-gate full-verify step, the JSON-channel deletion, band-2 egress, and the Q11 ordering; **band 1 needs a below-anchor `RuleSet` (F27) and both txid components on the skeleton wire (F28)** | **RULED 2026-09-18** — anchor model stands; launch window = first checkpoint release before day ~195, cadence `≤ W` (band 2 empty until `tip ≥ W`); full-verify a release-flow sentence; band-2 egress a formula; anchor check at `CEN-E1`; Q11 ordering discharged; **`Trust::Full \| BelowAnchor(anchor)` CONFIRMED** — forced by `StoreCannot::RuleSetNotInForce` (`connect.rs:281-329`) |
| `PDM-Q6` | The prunable region as the archival good; `pqc_auths` second occupant; shard membership (height / leaf-segment / `tx_id` range); leaf→tx unit change (F13, F14, F15, F22); **the store identity carries both occupants' hashes (F26)**; **item 3 names one unit for bond `holdings`, F17's wire echo and the challenge draw alike (§3 stripe/shard walk, 2026-09-17)** | **RULED 2026-09-17 (items 1–3)** — the good is the prunable region + `pqc_auths` for every tx below `W`, verified by `txs_prunable_hash` + `txs_pqc_auth_hash` (item 2 ratifies F26's landed default, #768 merged `398d85e7b`); a shard is a **byte-bounded `tx_id` range** `[b_k, b_{k+1})` closing at cumulative `SHARD_BYTES` over retained per-tx length rows (**item 3 AMENDED 2026-09-18, F32** — fixed `T` superseded; S-CHAIN-W A4 length row owed; discard is shard-granular at `b_{k+1} ≤ first_tx_id(tip − W)`), one unit for bond `holdings`, wire echo and draw; the credit-wire `transfer_digest` collision is **not reopened**. **Item 4 RULED 2026-09-18**: nine-row re-key/reopen table — the serve-credit admission verifier is **reopened as consensus** (the signed preimage derives `R_k` + leaf index today, `wire.rs:345`; lands at E4 / S-ARCH); `challenge_leaf_index` is retired by ruling, live in code, deleted at S-ARCH; `RF-D1`/`RF-D6`/`SF-D8` reopened, `SF-D7`/`SF-D1`/`CR-D2`/`TJ-D` re-keyed. Before DRS-E2's first writer, as F26 required. `TxIdentity` carries both occupants' hashes since #768 (`{ hash, pqc_auth_hash: Option<_>, prunable_hash }` from `Transaction::txid_parts()`, DRS §7.7 items 1–2); the `txs_pqc_auth_hash` **row** landed on PR #772 (S-CHAIN-W amendment A3, DRS §7.7 item 3). **Item 4 OPEN by name** — re-key/reopen list in the ruling block |
| `PDM-Q7` | Stripe engine / `--prune-blockchain`; unbonded retention exceptions | **RULED 2026-09-18** — removed completely; nothing of the engine survives as design (F17's "worth taking" refuted: assignment, advertisement and coverage are the bond, the bond, and price); C++ engine dies at `DRS-E*` (`S0`), nothing ported into S-PRUNE; `--sync-pruned-blocks` deleted **under Q5's rejection** (trust-the-txid with no anchor); `pruning_seed` wire slot retired — send `0`, ignore received non-zero until the C++ emitter is gone (`PWC-` row); `prune_blockchain` / `get_blockchain_pruning_seed` REJECTED in the daemon RPC registry; RPC seed fields dropped at the cutover's `CORE_RPC_VERSION` bump. **Unbonded retention exceptions PERMITTED** — retention and serving are different acts; a floor, not a hazard |
| `PDM-Q8` | Privacy (density vs query; serve-side uniformity) | **RULED 2026-09-18** — serve side as ruled 2026-09-13, strengthened by #775 (no serving state on any daemon; all daemons prune); fetch side closed by citation: Tor client with no address (`SF-D3`), test-is-a-read indistinguishability (`ARCHIVAL_CHALLENGE_MECHANISM.md` §9; `SF-D5`/`SF-D8`; `SF-D10` draw), the persona never fetches — its daemon does, episodically; two-`W` rollout the one bounded exception |
| `PDM-Q9` | Archiver's retention set: source, binding, lapse, coverage floor, recovery fetch | **RULED 2026-09-18 on #775 (`PDM-Q-F33`)** — the daemon holds archival *consensus* state only and **no serving state, ever**; all daemons prune uniformly. **The daemon-storage candidate is REJECTED and withdrawn.** Binding: nothing (wallet holds bond + store); RPC: none new (`get_prunable_range` withdrawn); lapse: the wallet-side store's (#775 FOLLOWUPS row); floor: Foundation `CompleteTree` behind a persona, structural, counts personas; recovery: episodic daemon fetch, retains nothing; advertisement: none. **The specified-to-scarce window is when the wallet fills its store from the local daemon.** #775's leaf-shaped rows re-key under Q6/Q12 — whichever lands second |
| `PDM-Q10` | RPC contract for "not retained" | **RULED 2026-09-18** — no new RPC: "not retained" is `get_transactions`' existing split form (`methods.rs:552-605`) with `prunable` empty, hash rows present, `pruned_flag` set — identical on every daemon; discarded and never-held are one state (F32); the wallet-side store answers the onion, the daemon answers its operator |
| `PDM-Q11` | `D_max`, the consensus reorg cap — the one constant F10 (Q2), F19 (Q1) **and the store's undo-log retention (S-CHAIN-W SCW-7, 2026-09-15: retention ≥ `D_max`)** all derive from; home is `is_alternative_block_allowed` above the checkpoint — census row **`CEN-E2`** (F30; `CEN-E1` is the equality rule, the band-1 trust assertion) — so the checkpoint (Q5) is its precondition; not archival-scoped, carried here until ruled | **RULED 2026-09-17** — shape frozen (a *detectability boundary*, home `CEN-E2`, the anchor a precondition), **numeric `720` PROVISIONAL** on the `bond_duration` precedent with the two shallower arguments recorded beside it, re-pinned at the Round-2 gate with `n` and `W` (three entries); the owner ask is discharged by the ruling itself; `CEN-E1`/`CEN-E2` re-key still owed in F27's PR (F30) |
| `PDM-Q12` | The freeze pipeline and the wallet-side `LeafStore` under Q6's unit — does the freeze retire when the commitment exists at ingest; `LeafStore` as deletion target (F21) | **RULED 2026-09-18 (conditional on Q9's daemon-storage candidate for where dependents re-point; the retirement itself stands on Q6)** — the freeze retires (commitment exists at ingest; membership derivable, F32), not a migration; `LeafStore` as served store, `segment_freeze.rs`, the freeze half of `challenge.rs`/`path.rs` are a Rust deletion surface at E4 / S-ARCH; the C++ freeze symbols die at `DRS-E*` under Q7's precedent; no wire-invariance claim — the verifier change is item 4 row 1; no reversion criterion beyond Q6's own |

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
(F12); the `db_lmdb.cpp:9922-9925` / `:9970` / `blockchain_db.h:2838`
comment fix goes now as its own C++ row (F7), with F9/F18/F23. Q2's ruling must state the free-regime
duration, the market's behaviour during it, and the reorg-depth floor
with trim's defined failure (F10) and F15's admission-only floor —
and **`W`** (F24): floor `D_max`, the honest-downtime argument, the
economic ceiling, priced in disk at ~16.7 KB/tx against the scarcity
it removes; the F19 candidate makes Q1's and Q2's horizons one. Q3
is the residual-set question after TJ-A, with an instrument that can
go red. **Q6 is answered before Q1 is closed**, and Q6 is now a
concrete question rather than a promotion: F13 names the good (the
prunable region, verified by `txs_prunable_hash`), F14 names the
second occupant (`pqc_auths`, ~60 % of the bytes, kept only for want
of a hash row), F15 discharges the self-reference, and Q6 item 4 owes
the list of closed leaf-shaped rulings the unit change reopens. A Q1
ruling written ahead of Q6 is ruling on a cache. Q1 then rules §9's
`CACHE` and `LOCAL-BOUNDED` rows (F16) and the two undetermined
readers. Q9's binding and lapse tail; Q10's response shape, legible
to the `SF-` round. F9 was a C++ defect independent of PDM, landed in
PR #733 alongside F7, F18 and F23 — not this charter. F11's re-grade of the three
curve-tree rows — and now `txs_pqc_auths` (F22) — is the DRS-0 lane's,
on Q6's and Q1's output.

The serving-side pass (F20–F23) adds: Q5 rules the anchor — the
release-carried checkpoint, its `assumevalid` semantics and the
full-verify release-gate step, the launch window during which `C = 0`,
band 2's egress number, the JSON-channel deletion — and the fetch
primitive, with the `SF-` round owning transport; Q4 states the TJ-F
rebinding; Q7 rules unbonded exceptions; Q8's ruled
uniformity is carried into the daemon-cutover lane as a property of
the successor serve path (one answer inside the window, one refusal
outside, no per-peer retention negotiation) and its indistinguishability
test named; Q9 rules the daemon-storage candidate, the coverage floor
and the recovery fetch; Q12 rules whether the freeze retires and lists
the `LeafStore` deletion surface. The shape the pass converged on, for
the ruling pass to confirm or refute: one unit (a tx range), one
predicate (`retain`), one verifier (the two hash rows the txid already
commits), one primitive (fetch a range, verify per-tx), one
advertisement (the bond, echoed compactly per F17), one economic
weight (the bond) — with band-2 fill, recovery, read-back and challenge
being the same read. Nothing new is committed to by consensus. And the
property the anchor correction makes provable rather than aspired to:
**under Q6 + Q11 + the release-carried anchor + a uniform bytes
window `W ≥ D_max`, the archival market is off the chain-following path
for every running node whose downtime is under `W`, and for every
fresh node on a current release outside the launch window.** Where it
is *not* off the path — the launch window, stale binaries, downtime
past `W`, `assumevalid=0` auditors, history read-back — is named,
`W` is the parameter that decides how often (F24), and the coverage floor is sized to those
readers rather than to a liveness claim that does not hold.

**The store-shaping pass (F26, 2026-09-16) adds a clock.** Q6 items 1–2
are ruled **before DRS-E2's first production writer** — the increment
that decides what the write path does with the prunable body and the
`pqc_auths` slice — or E2 rules them by construction; `TxIdentity`
already did so for the identity. Two requests go out of this round now
rather than at the ruling pass: to the DRS-E lane, `TxIdentity` and the
store carry `pqc_auth_hash` beside `prunable_hash`, contract-on-the-row
first (SCW-7's standard); to steering, a named consensus-side owner for
Q11 — the shape is written, the person is not. **Three shaping requests
follow on review (F27–F29):** E6 issues a below-anchor `RuleSet` or
band 1 has no writer (F27); the skeleton wire entry grows the second
txid component under Q6 item 2, owner `LV-`/`PWC-` (F28); Q3's
instrument is `ChainView`'s own surface, held as a standing property
with a compile-shaped falsifier (F29). Each is cheap exactly once.

**The census-consequence pass (F30–F31, 2026-09-17) adds three items and
one clock.** F27's landing PR re-keys `CEN-E1` and `CEN-E2` — their
C2-R1b "reopens when DRS/R8 moves checkpoint state" trigger fires the
day a Rust-held anchor table exists, and E1's rule text still names the
JSON channel F23 deleted (F30). The DRS-E lane writes S-PRUNE's rule-26
plan doc before its first increment; it can be written now against this
charter (F31). And Q6 item 2 is now the second increment
built on an unruled default: when Q6 rules it, it confirms a landed
shape and says so. Q11's owner: day five.

**§3 walked (steering, 2026-09-17, same day the table was added) — Q6's
gate is now open.** All six items positioned and dispositioned against
the design as it stands: withholding and eclipse DISCHARGED outright;
free-riding DISCHARGED on the ruled bootstrap subsidy (`DESIGN_CONCEPTS.md`
Component 4 — the free regime is the window it exists for; the
`bond_duration` vs `W` condition first drawn was withdrawn by steering
the same day); stripe/shard conditional on Q6 item 3 and F17 naming
**one unit**; Sybil's economics DISCHARGED with no residual on the
self-diluting scarcity reward (`REWARD_EMISSION_LEG.md` channel 1), its
correlated-failure residual conditional on Q9 ruling the floor
structural; reorg conditional on Q11 existing. What the walk hands to
the ruling pass: Q2 states `W` and names the regime's behaviour as
bootstrap; Q6 item 3 states the unit once, for bond, wire echo and draw
alike; Q9 rules the coverage floor structural and says it counts
personas; S-PRUNE's plan doc (F31) carries the discard-side predicate
assertion. Nothing in the six requires a mechanism the design lacks.
The ruling pass for Q6 items 1–3 can now be the transcription it was
said to be.

**Rulings taken (2026-09-17, same day, grounded `4bc378d68` + #768/#770
heads).** `PDM-Q6` items 1–3 and `PDM-Q11` are RULED — the blocks sit
at the head of their §2 sections. What the next pass owes is therefore
re-ordered: **Q6 item 4** (the re-key/reopen list, OPEN by name), then
**Q1** (grade §9 against the `tx_id`-range unit), **Q2** (`W`'s number
to the Round-2 gate; the regime's behaviour is bootstrap), **Q12**
(candidate: the freeze retires, `LeafStore` is a deletion target), then
Q3 / Q5 (launch window, release-gate step, band-2 egress — the Q11
ordering item is discharged) / Q7 / Q8 / Q9 (floor structural, counts
personas) / Q10. Cross-lane: `SF` sub-PR 2 and F28 are unblocked;
the `CEN-E1`/`CEN-E2` re-key rides F27's PR (F30); S-PRUNE's plan doc
(F31) now has its unit and its cap. The "Q6 first, Q11 in parallel"
ordering in §6 is struck.

**Second ruling pass (2026-09-18, `20ebdf1e5`) — Q6 item 4, F32, Q12.**
Taken after an adversarial read that opened `wire.rs`,
`codec/chain.rs` and `blockchain.cpp:5085-5125`, which the first
drafts had not; three of the four blocks changed on what those files
said. What it hands on: **E4 / S-ARCH** owns the serve-credit admission
verifier's re-key (preimage over `shard_id` + `(b_k, b_{k+1})`, FFI
contract replaced, `CEN-J*`/`L7–L10` re-keyed, the leaf cluster
deleted) — a consensus change, written before genesis; **S-CHAIN-W A4**
(the per-tx length rows, same rung as A3) is owed to the DRS lane, and
the §7.7 invariant's fourth leg with it; the **reward leg** owes one
decision — does channel 1's `1/R_market` weight apply from bond or from
`discard(k)`; **Q2** — RULED the same pass, shape only: the predicate shard-granular on
`b_{k+1}` with an epoch floor, `W` PROVISIONAL at F19's floor; **Q9** gains "the specified-to-scarce window is the `retain`
window" and Q12's dependents re-point on its ruling; `SF` sub-PR 2 has
its `expected` and its unchanged `N`/`L`. **Q7 RULED the same day**: the stripe engine is removed completely,
nothing of it survives as design (F17's triple refuted — the bond, the
bond, price); `--sync-pruned-blocks` goes under Q5's rejection; the
`pruning_seed` slot is retired with the send-`0`/ignore-receive
transition; the two prune RPC methods are REJECTED in the registry;
unbonded retention is permitted, in the wallet-side store.

**Third pass, same day — the round closes on the design side.** PR #775
(`PDM-Q-F33`) drew the daemon line and **Q9** is ruled on it: the
daemon-storage candidate is REJECTED and withdrawn, the wallet-side store
is the archiver's, the daemon retains nothing durable, and the
specified-to-scarce window is when the wallet fills its store from the
local daemon. That forced amendments to Q2 (no exceptions conjunct — all
daemons prune), Q7 (unbonded retention in the wallet-side store), Q12
(`LeafStore` rebuilt, not deleted; `get_prunable_range` withdrawn) and
F32. **Q1, Q3, Q5, Q8, Q10 RULED and Q4 CLOSED** as transcriptions of
what was already landed, with three corrections made at source before
writing: Q10 has no typed refusal (discarded and never-held are one
state; the existing split read is the contract), Q3's C++ residual is the
serve-credit verifier and dies at E4, not the stripe engine at `DRS-E*`,
and Q8's fetch half cites §9 of the challenge mechanism, not `SF-D10`,
for indistinguishability. **Q5's one confirmation** — `Trust::Full |
BelowAnchor(anchor)` — is forced by `StoreCannot::RuleSetNotInForce`.
**Every `PDM-Q*` is now RULED or CLOSED.** What carries on past the
round, by owner: **the wallet lane** — the **archiver serving-store
rebuild** (Q12: `LeafStore` around bodies — fill-from-daemon in the grace
window, verify-on-fill against the hash rows, shard-keyed, per-tx serve,
lapse tail, recovery intake, the Foundation floor), a design round of its
own, to be opened and registered — **the largest unbuilt thing this
charter names**; **DRS-E** — S-PRUNE's plan on the skeleton (after Q1's
horizon check lands), A3 (#772), A4, the daemon-uniformity constraint in
`DAEMON_REDB_STORE.md` (#775's row); **E4 / S-ARCH** — the serve-credit
verifier re-key (consensus) and the leaf-cluster deletion; **E6** — the
`Trust` mode and the `CEN-E1`/`E2` re-key; **the reward leg** — the
in-window commitment weight and `w_launch`; **`LV-`/`PWC-`** — the
skeleton wire field (F28) and the `pruning_seed` retirement (Q7);
**`RK-`** — the two REJECTED methods; **RF-/SF-/TJ- lanes** — item 4's
line-local re-keys; **#774 / #775** — the mutual re-key (F33); **Round-2**
— `n`, `D_max`, `W`, `w_launch`. **Steering** — archive-or-contract for
this document (rule 95): it is the design home TJ-D named and it now
holds twelve rulings; whether it flips to `LIVING CONTRACT` or a
contract-of-record is extracted and the round archived is the last
decision the round itself does not make.

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
| `tx_extra` `0x07` PQC leaf entries (`CM ‖ record`, `PL-D3`) | prefix | `txs_pruned` | 64 B/output | replay (`blockchain_db.cpp:528-557` → leaf) | — | KEEP-D |
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
| `curve_tree_leaves` | 128 | serve-credit verify **today** (`blockchain.cpp:5327`, F8 — goes with TJ-A); `trim_curve_tree` boundary chunk on pop (`:9361`, F10); RPC `shekyl-fcmp::rpc_path` | `O`, `C`, `CM` → `shekyl_construct_curve_tree_leaf` (`blockchain_db.cpp:608`) | CACHE (F12) |
| `output_metadata` (`output_data_t`: pk, unlock, height, commitment) | 80 | none in consensus — `scan_outputkeys_for_indexes` deleted with `check_tx_input` (`PDM-Q-F18`); RPC `chunk_outputs` via `shekyl-fcmp::rpc_path` | `vout` + `outPk` + block height | CACHE (`Excluded` in slice A, `class.rs:149`) |
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
