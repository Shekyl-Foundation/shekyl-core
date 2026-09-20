# The wallet-side store — one contract over two obligations: umbrella and Round-0 pre-flight

**Status:** OPEN — **round opened 2026-09-18**, **Round 0 (pre-flight)
executed** at `dev` = `8494f2a27` (the #779 merge). **Round 1 RULED 2026-09-19**
(maintainer; §6's table, each ruling line-local): **every question is
ruled**; what remains open is only the **daemon-lane halves** of `WSS-Q6` /
`WSS-Q10`, which ride `WSS-22`'s question, and `WSS-Q1`(b)'s four measurements,
which are now **gradable** and owed as bench work rather than as a decision. **Substrate re-swept at
`dev` = `306af9bae`** — `8494f2a27` is an ancestor; every file cited here is
unchanged or cosmetically changed, so no finding moves, and the one substantive
landed change (`SOK-10` Q7 → A) **strengthens** `WSS-Q1`(b). This document is the
umbrella contract for the wallet-side store lane, opened as the deliberate
parallel of the daemon's DRS lane ([`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md)).
**Nothing is built by this document.** Its product is a contract, a work
breakdown, and a question list; every implementation PR under it is
separately authorized ([`06-branching`](../../.cursor/rules/06-branching.mdc)).
**`WSS-Q1` and every other question are RULED — see §6's table and §14.**
Rule-26 sub-PR discipline is invoked
([`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)):
multi-round, privacy-load-bearing, and FFI-adjacent through
`shekyl-ffi`'s curve-tree replica family.

**Identifier family:** `WSS-1…WSS-N` (findings), `WSS-Q1…WSS-QN` (round
questions) — registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 by this PR
([`94-tracking-index`](../../.cursor/rules/94-tracking-index.mdc) §1, at birth).

**Mission hierarchy** ([`00-mission`](../../.cursor/rules/00-mission.mdc)):
security/PQC → privacy → longevity. Where this round invokes it, the binding
commitment is **privacy** — the two-store split exists because *elective
behaviour in a publicly addressed process is a fingerprint*
([`V3_WALLET_DECISION_LOG.md`](../V3_WALLET_DECISION_LOG.md), 2026-09-17,
amended 09-18) — and **longevity**, because the store this round shapes is the
one a wallet opens at every launch for the life of the chain.

---

## 0. Problem statement

`shekyl-curve-tree`'s redb `LeafStore` carries **two obligations that are not
the same obligation**, and every open question in this lane is a consequence
of their being in one file.

- **Obligation A — proving.** Membership-path assembly for FCMP++ spends.
  Universal: every Shekyl wallet needs it to spend at all. The unit is the
  **leaf**, by the curve tree's construction.
- **Obligation B — serving.** The archiver's shard bodies, read by
  `shekyl-p-serve`'s provider and `shekyl-p-host`'s witness. Elective: only a
  bonded archiver (and the structural floor) has it. Under `PDM-Q6`/`Q12` the
  unit is the **prunable body**, keyed by shard `k` over `[b_k, b_{k+1})`.

The two-store ruling
([`V3_WALLET_DECISION_LOG.md`](../V3_WALLET_DECISION_LOG.md), 2026-09-17)
already names both — *"`shekyl-curve-tree` carries two purposes:
membership-path assembly, and `serving_route`"* — and rules that neither
lives on the daemon. What it did not decide is **which identity owns which
state** — that is `WSS-Q1`, and every other question in §6 inherits its answer.
*(The round first posed it as "one file or two"; §6.1 records why that axis was
wrong and what replaced it.)* **Ruled 2026-09-19:** the serving store is `P`'s
and is the wallet's only redb; the proving state is the principal's and is not
a store at all.

Two rounds are pointed at this file from different pins, and the collision is
recorded but undecided: `PDM-Q12` says *"The `CTS-` round is the natural home
for it and owes either a scope amendment naming the body unit or a successor
round; **this ruling does not decide which**"*
([`ARCHIVAL_PRUNED_DAEMON_MODE.md`](ARCHIVAL_PRUNED_DAEMON_MODE.md):1030).
This round decides it (§7) and partitions the surviving work by unit (§8).

---

## 1. Binding decisions inherited — cited, never restated

A second copy of a ruling drifts and then lies. Each row below is **read from
its owning document**, with the falsifier that says the citation has gone
stale. Re-pin every row at the head of each increment's Round-0.

| Inherited decision | Owner | What this round takes from it | Re-pin falsifier |
| --- | --- | --- | --- |
| **Two stores by obligation**; the daemon holds no archival serving state, ever; all daemons prune uniformly | [`V3_WALLET_DECISION_LOG.md`](../V3_WALLET_DECISION_LOG.md) 2026-09-17 (amended 09-18), criterion's source PR #775 | The wallet-side store exists and is *the* serving store. Nothing here proposes moving any of it to the daemon | The entry's *persistent-and-posture-correlated* criterion is refuted |
| **The good is the prunable region + `pqc_auths`**; a shard is a byte-bounded `tx_id` range closing at `SHARD_BYTES` | `PDM-Q6` items 1–3, amended by `PDM-Q-F32` ([`ARCHIVAL_PRUNED_DAEMON_MODE.md`](ARCHIVAL_PRUNED_DAEMON_MODE.md):327) | Obligation B's unit and key | A bond `holdings`, wire echo or challenge draw expressed in another unit |
| **The freeze pipeline retires; `LeafStore` is rebuilt around bodies, not deleted** | `PDM-Q12` (:966) | The B-side rebuild is this round's largest increment | A successor object for the range commitment appears |
| **The archiver's retention set lives in the wallet-side store; no new RPC; fill through the ordinary split tx read** | `PDM-Q9` (:722) | §5's fill path and the no-new-RPC constraint | Any archival-serving RPC appears on the daemon |
| **`b_*` is derived once by S-PRUNE's forward pass; this store reads it and mints no partition** | `PDM-Q9` (iii) | §5 row 1 | This store computes a boundary of its own |
| **CT-1 — redb; a valid store is ACID + oracle-validated leaf encoding, not daemon layout parity** | [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) §3.6 | The engine choice. **Not reopened** (§4.3 states the one clause `WSS-Q1` touches) | — |
| **CT-5 — the single-writer actor owns the store** | [`CT5_ENGINE_WIRING.md`](../completed/CT5_ENGINE_WIRING.md) §3.1 | A `WSS-Q1` input, and the reason `ServingReader` exists (`WSS-6`) | — |
| **§11.1(f) value-shape policy** — `Coded<V>` / `Blob<K>` / `Present` / `Unshaped`, one codec per meaning, distinct `TypeName`s | [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §11.1(f) | The format policy for **both** obligations, by citation. This document does not restate it | §11.1(f)'s shapes change without this row moving |

### 1.1 Steering's answers, recorded as ground (Rick, 2026-09-18)

Quoted rather than paraphrased, because each is the premise of a §6 question
and a reader must be able to check the paraphrase.

1. *"Agreed that the design rounds can run concurrently. We will not build to
   the C++ daemon, and I can't GUARANTEE that the daemon responses and overall
   shape won't change during the daemon build. However, it is not going to be
   a seismic shift, so this is not an absolute ban on building, it is simply a
   warning that we will build the things that are very WALLET and properly
   decouple the daemon elements that are either not in Rust or are in flux."*
2. *"Per the above, we CAN build PR A first."*
3. *"CTS as-is was an initial design, but the daemon DRS series has refined
   that design. In essence, the daemon is canon, and the wallet store serves
   to securely serve a SLICE of that canonical data."*

### 1.2 Steering rulings, 2026-09-19 — `R-A` and `R-B`

Recorded as **rulings**, not proposals. Everything in §6.7 below them is
design-review material awaiting a ruling, and is marked so.

- **`R-A` — `P`'s height comes from the configured daemon.** `P`'s store holds
  only closed, final shards, which are **old by construction**, so it cannot
  know the current tip. `P` asks **the daemon the wallet is configured to
  use**. *There is no alternative mechanism to weigh — this is forced, not
  chosen.* `P`'s transport (`PersonaIsolatedTransport`,
  `engine/prpc.rs`) resolves to that same configured daemon: `LocalNodeRpc`
  (loopback) by default, `PRpc` being `P`'s own circuit to its configured
  remote daemon. **Never a random peer.** *A "tip follower over `P`'s own
  transport" was floated in review and is **withdrawn**; it is not a mechanism
  and is not recorded as one.*
- **`R-B` — this applies to every consensus-derived task.** Anything the wallet
  decides from consensus state is read from the configured daemon. **While the
  daemon reports it is syncing the answer is *unknown*, and unknown fails
  toward the safe side: do not erase, do not post, do not sign.** A daemon that
  is behind reports it — `synchronized: bool` and `target_height`
  (`shekyl-daemon-rpc/src/chain_facts.rs:52-55`), with `target_height == 0`
  once caught up (`methods.rs:112-115`).

**What each of steering's earlier answers rules, and what it does not.**

- **(1) rules the round's concurrency and the *build* criterion**, not
  `WSS-Q1`. Its operational content is §5: every daemon-owned input this store
  consumes is named there **by citation with a re-pin falsifier**, so a
  daemon-side change is a re-pin rather than a rewrite. It is a `WSS-Q1`
  *input* and leans toward two lifecycles — obligation A is "very WALLET" and
  buildable today; obligation B is gated on daemon elements still in flux (the
  A4 length rows, the hash rows, S-PRUNE's `b_*`). It does not decide one file
  or two, and is not read as deciding it.
- **(2) rules the sequencing question** in the brief's §11 item 2: PR A
  (`shekyl-store-codec`) may land ahead of the round. The disclosed departure
  from §11.1(f)'s "first commit of *that* PR" sequencing stands as disclosed;
  it is a mechanical move with re-exports, no behaviour change, and a
  byte-identical `tables.snap`.
- **(3) rules `CTS-`'s disposition** (§7): successor round, not scope
  amendment. **It does not rule `WSS-Q1`.** "Serves a slice of canonical
  daemon data" is exactly true of obligation **B** and is *not* true of
  obligation **A**: the proving store is not a slice of anything the daemon
  serves — it is the wallet's own tree state, opened unconditionally for every
  wallet (`WSS-1`), and the daemon's `curve_tree_leaves` is graded **CACHE**
  and is the *daemon's* verification-side store, not this one (`WSS-3`).
  Reading (3) as "the wallet store is a serving cache" would delete obligation
  A by construction, and §3 is the evidence that it cannot be deleted. But
  obligation A **is** derived from canon: it is built by replaying the daemon's
  blocks, and the code checks it against the **header root on every ingested
  block** (`verify_root`, `engine/merge.rs:651`). What distinguishes it from
  obligation B is not independence from canon but **`R3`: it is derived,
  self-checking against canon, and therefore never needs a migration, ever** —
  a divergence is caught at the next block and repaired by replay, not by a
  schema version.

---

## 2. Goals and non-goals

### 2.1 Goals

1. **Name the two obligations and rule where they live** (`WSS-Q1`), once,
   with the attribution pre-flight in §4 as the evidence rather than taste.
2. **Give the surviving `CTS-` work a home that does not lie** — a partition
   by unit (§8), so no leaf-unit implementation lands that the body-unit
   rebuild must then unbuild.
3. **State the shared surface with the daemon by citation** (§5), so a daemon
   change is a re-pin, not a redesign — the operational form of steering's
   answer (1).
4. **Carry `PDM-Q12`'s unmade decisions to a ruling** (§6), each with its
   named input.
5. **Leave no open residue unowned** — §10 disposes each inherited FOLLOWUPS
   row explicitly.

### 2.2 Non-goals — named, so they are not shed by omission

- **The `SO-` round** (settlement writer / `SO-D8`). Daemon consensus; Slice
  C's home is `shekyl-chain-rules` and `shekyl-archival-retention` at DRS-E4,
  and Slice C is not authorized.
  [`ARCHIVAL_SETTLEMENT_WRITER.md`](ARCHIVAL_SETTLEMENT_WRITER.md) §12's
  rule-22 hold on the writer's call site stands. Its one open item — Q9's
  set-commitment bytes, §7.6.1 — is a maintainer ruling, not a round item here.
- **The curve-tree math** — `ops.rs`, `recon.rs`, `assemble.rs`, `client.rs`'s
  tree arithmetic. The store KATs are the denominator, not the subject.
  (`ops.rs`'s *consumption* of `frozen_segments` is in scope as a **finding**,
  `WSS-4`; its math is not.)
- **Daemon-side `curve_tree_*` tables** — `Unshaped` in `shekyl-chain-store`;
  DRS-E3's.
- **A flat-mmap leaf array** — CT-1's rejected alternative with its reversion
  clause. Not reopened.
- **The serve-credit admission verifier re-key** — `PDM-Q6` item 4 row 1;
  consensus, and it lands at **E4 / S-ARCH** in `shekyl-chain-rules`, not here
  (§5, row 7).
- **Any C++ deletion.** `PDM-Q-S0`: no C++ landing before the cutover.
- **The `PDM` propagation sweep** — **named here because it is the reason this
  round exists, and refused here because it is not this round's.** `PDM-Q6` /
  `PDM-Q12` never propagated: `grep -c PDM` returns **0** for
  [`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md),
  [`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md),
  [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) and
  [`PRINCIPAL_STAKE_LIFECYCLE.md`](PRINCIPAL_STAKE_LIFECYCLE.md) at
  `8494f2a27`, and all four still design against the **leaf unit**. This is
  the same failure that produced the `CTS-`/`PDM-Q12` collision this round was
  opened to resolve, and folding it in here would repeat the error in the
  other direction — a store round silently editing the archival design home.
  **It needs its own owner** (FOLLOWUPS row). What it must sweep, verified at
  `8494f2a27`:
  - `V3_STAKER_ARCHIVAL.md` — "Problem 2" (`:70-77`) says proof construction
    needs historical tree state served by archival nodes; `WSS-1` shows the
    wallet holds its own complete tree and spending never touches the pruned
    regions. The data-scope pin's Set B (segment leaves proven against `R_k`,
    non-stakers pruning to `R_k`) is re-keyed by `PDM-Q6` and retired by
    `PDM-Q12`. "V3 architectural requirements" is **claim-era throughout**
    (`staker_pool_share`, `is_active_staker`, `stake_tier`, tier-weighted
    rewards) and routes wallet archival queries to staker peers through a
    multi-source `assemble_tree_path_for_output` RPC — which contradicts
    `EU-D1` ([`ARCHIVAL_ENDPOINT_UPDATE.md`](ARCHIVAL_ENDPOINT_UPDATE.md) §2,
    "no wallet talks to a wallet"), the claim-era retirement, and the
    tier-neutral pricing later in the same document. **Highest priority:** the
    ship-timing banner's *"The design is unchanged by this correction — only
    the ship timing"* (`:18`) is **no longer true**, and it is the sentence an
    agent will trust.
  - `ARCHIVAL_CHALLENGE_MECHANISM.md` — §1 (`:87`) and `:1421` define a shard
    as a *"3,326,976-byte deterministic partition"*, which is 25,992 leaves ×
    128. **Wrong on "deterministic" as well as on the derivation:** under
    `PDM-Q-F32` shards are **no longer fixed-size** — a closed shard's size
    lies in `[SHARD_BYTES, SHARD_BYTES + MAX_TX_SIZE)`
    ([`ARCHIVAL_PRUNED_DAEMON_MODE.md`](ARCHIVAL_PRUNED_DAEMON_MODE.md):411).
    **The figure survives as the boundary metric and its derivation does not** (`PDM-Q6` item 4's `RF-D6` row:
    `SHARD_BYTES` survives as the *boundary metric*; the leaves × 128
    derivation does not) — so this is a re-derivation, not a find-and-replace.
    §2 step 2 (`:134`) has the witness verify against `R_k`; under `PDM-Q12`
    the check is per transaction against `txs_prunable_hash` /
    `txs_pqc_auth_hash`. The banner's "live remainder" still carries a nonce
    that §2 step 3 and `SF-D8` deleted with (a0) — **a banner contradicting
    its own body.**
  - `CURVE_TREE_CLIENT.md` §7.2–§7.6 — still design-of-record for the retired
    model (`R_k` as a content address, a minimal wallet pruning to `R_k`,
    archivers holding full leaves), and §7.2.1 #5 carries a **standing
    uncorrected error**: "`R_k` plus owned chunks suffice" to build a spend
    path. They do not.
  - `PRINCIPAL_STAKE_LIFECYCLE.md` — §0.1's cites have drifted (`Engine` is
    `mod.rs:585` not L403; `key` `:630` not L452; `stake` `:885` not L681 —
    **verified**). §5 gate 1 still presents the `GF-4` output-count rule as an
    open design gate with its retirement appended as an `UPDATE`, and the
    `GF-4b` note of 2026-09-11 says outright that it was *"annotated rather
    than edited"* — the pattern the current-only principle forbids. *(One row
    checked and **sound**: §5 item 2 is still accurate — rebond and
    `HoldingsUpdate` have verify arms at `bond_post.rs:255`, `:324`, `:440`
    and no builder; `shekyl-archival-bond-builder` has only
    `build_join_market_vin` and `build_release_vin`.)*

---

## 3. The substrate finding that shapes the round — obligation A is universal

Stated first because it is what says most of the existing store is not built
for no reason, and because it is the premise `WSS-Q1` is decided against.
Every line is at `8494f2a27`.

**Obligation A reaches every wallet, unconditionally.**

- `Engine` holds `curve_tree: CurveTreeHandle` as a **non-optional** field
  (`rust/shekyl-engine-core/src/engine/mod.rs:647`), whose own doc comment
  records that its former `#[allow(dead_code)]` was deleted because it is read
  on the merge ingest path and the spend-gate cursor read (`:641-646`).
- It is opened and spawned for **every** wallet during assembly
  (`rust/shekyl-engine-core/src/engine/lifecycle/assemble.rs:245-259`) — a
  store-open failure is a wallet-file boundary failure, i.e. the wallet does
  not open.
- Path assembly is `CurveTreeClient::assemble_path`
  (`rust/shekyl-curve-tree/src/assemble.rs:72`), reached through the actor at
  `rust/shekyl-engine-core/src/engine/curve_tree_actor.rs:501`, and used by
  the ordinary spend path and by the staking paths.

So the store is not archiver machinery with a wallet attached. It is how a
Shekyl wallet spends, with archiver machinery attached. **A round that treated
`PDM-Q12`'s rebuild as a replacement of the whole store would delete the spend
path.** `PDM-Q12` does not say that — its deletion surface is narrow and
B-shaped (§4.2) — but the reading is available, and this section forecloses it.

**And the two obligations already conflict on one file, observably.** This is
not a forecast; it is the state of the tree (`WSS-4`, `WSS-5`, `WSS-6`).

---

## 4. Round-0 pre-flight — the attribution that `WSS-Q1` is decided against

Per the brief: enumerate the external API, attribute each element to
obligation **A**, **B**, or **both**, across the dependents. **A method that
serves both is the interesting row; a clean split is the argument for two
files.** The evidence is here; the ruling it produced is in §6's table.

### 4.1 Attribution by dependent — what each crate actually imports

Measured at `8494f2a27` by the items each crate names through
`shekyl_curve_tree::` in `src/` and `tests/`. The nine "dependents" of the
`CTS-` §1 precondition table are not nine store consumers:

| Crate | Imports from `shekyl-curve-tree` | Obligation |
| --- | --- | --- |
| `shekyl-engine-core` | `CurveTreeClient`, `assemble_path`, `AssembleInput`, `TreeContext`, `ReferenceBlock`, `select_reference_height`, `REF_ANCHOR_AGE`, `should_reanchor`, `BlockLeaves`, `TxLeafInputs`, `LeafStore`, `serving_route` | **Both** — A dominant; `serving_route` and the serve-set source are B |
| `shekyl-p-host` | `ServingReader`, `SegmentId`, `served_frame`, `serving_route`, `StoreError` | **B only** |
| `shekyl-p-serve` | `served_frame`, `ServedFrameHeader`, `serving_route`, `leaves_per_segment` | **B only** |
| `shekyl-p-fetch` | `serving_route`, `ServedFrameHeader`, `leaves_per_segment` | **B only** (client side of the route) |
| `shekyl-ffi` | `CurveTreeClient`, `client`, `types` | **A only** |
| `shekyl-wire` | `CurveTreeClient` (e2e spend tests) | **A only** |
| `shekyl-archival-retention` | `LEAF_BYTES`, `SEGMENT_FREEZE_REORG_MARGIN_BLOCKS` — **constants, no store handle** | Neither (consensus constants) |
| `shekyl-daemon-rpc` | `CommitmentBytes`, `OneTimePubkey` — **vocabulary re-exports only** | Neither |
| `shekyl-economics-sim` | `segment` (model constants) | Neither |

**What the table says, before any ruling.** Six of the nine touch exactly one
obligation, and three touch the store not at all. `ServingReader` is imported
by **one** crate (`p-host`); `LeafStore` by **one** (`engine-core`). The
**type** split already tracks the obligation split. The only genuine
both-consumer is `engine-core`, which is the wallet — and the wallet is both
the prover and, when bonded, the serving host's owner. That is a property of
the *process*, not necessarily of the *file*.

### 4.2 Attribution by method — the tables each touches

The discriminator is tables touched, not caller. `A` = proving tables
(`leaves`, `owned_identities`, `leaf_meta`, `pending`, the A-side `meta`
cells); `B` = serving tables (`frozen_segments`, `pinned_segments`, the
B-side `meta` cells).

| Method | Tables | Obligation | Note |
| --- | --- | --- | --- |
| `open`, `open_ephemeral`, `clear` | all | both | File lifecycle; the `WSS-Q1` subject itself |
| `leaf_count`, `sync_tip_height` | `meta` (A cells) | **A** | |
| `append_drained`, `append_block_deltas` | `leaves`, `leaf_meta`, `pending`, `meta` | **A** | The ingest path |
| `read_pending_candidates`, `read_drained_entries` | `pending`, `leaves`, `leaf_meta` | **A** | The resume path (`WSS-5`) |
| `root_at_count` | `leaves` + **`frozen_segments`** | **A, reading a B table** | `WSS-4` — the interesting row |
| `truncate_from_tree_position`, `rollback_to_fork` | **all seven** | both | The reorg path; `WSS-7` |
| `maybe_freeze_segments`, `next_freeze_seg` | `leaves` → `frozen_segments`, `meta` | **A→B** | Reads A, writes B; retired by `PDM-Q12` |
| `frozen_segment`, `open_frozen_segment_body` | `frozen_segments`, `leaves` | **B, reading an A table** | Leaf-order streaming; on Q12's deletion surface |
| `pin_segment_for_serving`, `pin_serve_set`, `pinned_shard_ids`, `release_pins`, `members_missing_pins` | `pinned_segments`, `frozen_segments` | **B** | The serve-set concept (§8 (ii)) |
| `prune_frozen`, `pruned_frozen_segments` | deletes `leaves`/`leaf_meta`, keeps `owned_identities`; reads `frozen_segments`/`pinned_segments` | **B posture mutating A tables** | `WSS-5`, `WSS-8` |
| `prune_disabled`, `set_prune_disabled` | `meta` (B cell) | **B** | One-way declaration; `WSS-8` |
| `same_store` | none — `Arc::ptr_eq` | **neither** | `WSS-6` — exists only because one file has two handles |

**Four both-rows, and each is a different kind of thing.** `open`/`clear` are
the question. `rollback_to_fork` is essential under one file and becomes two
coordinated rollbacks (or one, if B does not reorg) under two. `root_at_count`
and `prune_frozen`/`open_frozen_segment_body` are the **leaf-unit accidents**:
they cross only because today one partition (the leaf segment) serves both
obligations, and `PDM-Q12` dissolves exactly that shared partition. `WSS-9`
states what survives the dissolution.

### 4.3 Round-0 findings

Each is a substrate fact at `8494f2a27`, with its file and line.

| ID | Finding | Bears on |
| --- | --- | --- |
| **WSS-1** | **Obligation A is universal and unconditional.** `Engine.curve_tree: CurveTreeHandle` is non-optional (`engine/mod.rs:647`) and opened for every wallet at `lifecycle/assemble.rs:245`. A wallet that cannot open the curve-tree store does not open. | §3; `WSS-Q1`; the refutation of "the wallet store is only a serving cache" |
| **WSS-2** | **The sender-side handle is `Option`, the engine's is not.** `LocalPendingTx.curve_tree: Option<CurveTreeHandle>` (`engine/transfer/engine.rs:156`), matched at `transfer/trait_impl.rs:195` (`None => TreeSpendGate::Unenforced`) and `:280`. So there is already one seam where "no tree" is a representable state — a **composition seam**, not a production posture, since the engine always holds one. Recorded so `WSS-Q1` is not argued from this `Option` as if it were a wallet without a tree. | `WSS-Q1` inputs; the spend-gate contract |
| **WSS-3** | **`PDM-Q12`'s sentence *"The curve tree's verification-side leaf store, if any, is Q1's to grade"* does not refer to this store.** `PDM-Q1` (:117) grades **§9** — the daemon's chain-store inventory — and §9.2 grades `curve_tree_leaves` **CACHE** (:1421). The daemon verifies FCMP++ too (`curve_tree_roots`, CEN-I12). So the referent is the **daemon's** leaf table, already graded; **the wallet-side proving store is ungraded by PDM and is this round's.** | Forecloses reading that sentence as license over obligation A |
| **WSS-4** | **`root_at_count` — a pure obligation-A method — reads the `frozen_segments` table.** `redb_backend.rs:1214`, reading `r_k` per complete segment at `:1235-1247` and falling back to `recompute_segment_r_k` from leaves when a row is absent (`:1241-1245`); composition is `ops.rs:39` `mixed_composition_root(leaf_count, &frozen_r, &tail)`, documented at `ops.rs:6` as *"frozen `R_k` + partial tail"*. **The freeze is therefore not serving-only: it is also the proving path's root-composition cache.** `PDM-Q12`'s deletion surface does not name this consumer. | `WSS-Q1`; §8 bucket (iii); the freeze retirement's true blast radius |
| **WSS-5** | **A pruned store cannot be reopened as a proving client.** `CurveTreeClient::rebuild_from_store` (`client.rs:628`) refuses with `ClientError::ResumeFromPrunedStore` (`client.rs:200`) when readable drained rows are fewer than `leaf_count` — *"Pruning dropped frozen leaf bytes: the in-memory vec would undercount and every root would be silently wrong"* (`:631-639`). So obligation B's size discipline and obligation A's resume **cannot both be satisfied by one file**. The conflict is **latent, not realized**: `WSS-8` says nothing prunes in production, so no store is in this state today and the refusal is a guard that has never fired. Its axis is **one identity's storage policy destroying another identity's state** (`WSS-13`), not two obligations colliding over storage — which makes it evidence for `WSS-Q1`'s firewall framing (§6.1), not the ground of it. | `WSS-Q1` (supporting, not decisive) |
| **WSS-6** | **`ServingReader` and `same_store` exist because redb takes an exclusive file lock.** `client.rs:283-290` — the `Arc<LeafStore>` is shared *"because redb takes an exclusive file lock, so a second open would simply be refused"*; `redb_backend.rs:160-177` — the serving side gets a narrowed handle because *"handing it the store itself would put a second writer beside the one the actor exists to be… the two would contend on the write lock"*; `same_store` is `Arc::ptr_eq` (`:325`). **One file is a consequence of the engine's file lock, not of a ruling.** Under two files each obligation has its own writer, and `same_store`'s subject ("pins applied to one are not pins in the other") cannot arise. This is *mechanics*: it says the one-file arrangement was never chosen, which removes an argument for keeping it, and says nothing about what should replace it. The replacement is decided on the firewall (§6.1), not here. | `WSS-Q1` (mechanics); CT-5 §3.1's single-writer actor |
| **WSS-7** | **The reorg path touches all seven tables.** `truncate_from_tree_position` / `rollback_to_fork` (`redb_backend.rs`, the `delete_*_batched` trio at `:1950-2011` per `CTS-11`) span proving and serving tables in one write transaction. Under two files this is the one genuinely hard row: either B does not reorg (it is filled from below the horizon, `PDM-Q2`'s `W ≥ D_max`), or two rollbacks need an ordering rule. | `WSS-Q1`; `WSS-Q3` |
| **WSS-8** | **`prune_frozen` has no production caller at this sha.** Every call site is a test (`shekyl-p-host/tests/composition.rs` ×7, `shekyl-p-serve/tests/store_axis.rs:125`) or a doc comment reasoning *about* it as a hazard (`p-host/src/serve_set/{report,staleness,witness}.rs`, `shekyl-operator-alarm/src/lib.rs:341`). The one-way prune-disabled posture is **not** the general answer: `set_prune_disabled` is reached only on the `PinCompleteTreePrefix` path (`curve_tree_actor.rs:391-402`, inside `impl Message<PinCompleteTreePrefix>`) — the **Foundation `CompleteTree` posture**. The ordinary archiver pins its serve set instead (`pin_serve_set`) and **declares nothing**; its store is unpruned only because nothing calls the discard. **"Unused" is a hypothesis, not a verdict:** the capability is designed-for and guarded by live detectors (`PostureDeclaration`, pins, staleness, witness), so the finding is *the discard has no caller*, not *the machinery is dead*. **Provenance, per the dead-code discipline (`git log -S'prune_frozen(' -- rust/shekyl-{p-host,p-serve,engine-core}/src` returns nothing): the discard was never wired**, not wired and later removed. So `WSS-Q2` is "design the size discipline", not "reinstate or delete a caller". What follows is a question, not a deletion: **does the rebuilt store prune at all, and what bounds obligation A's growth if it does not?** | `WSS-Q2`; §8 bucket (ii)'s scope; the size discipline nobody has ruled |
| **WSS-9** | **The composition boundary and the shard partition are different objects, and cannot be tied.** The tie today is `SEGMENT_LEAF_COUNT == leaves_per_segment()` (`PDM-Q-F33` (ii)); under `PDM-Q6`/`F32` the consensus partition becomes `b_*`, a **byte-bounded `tx_id` range**, while `root_at_count`'s composition boundary is a **leaf-count geometry** (`outputs_per_node(SEGMENT_LAYER_J)`, `segment.rs`). **Verified consequence:** the `F33` (ii) interim assert must die with the freeze and must **not** be re-pointed at `SHARD_BYTES` — the two constants would be asserting a relation that does not exist. **Not verified, and therefore `WSS-Q2`'s to rule:** whether obligation A keeps *any* segment-subroot cache after the freeze retires. `WSS-4`'s `r_k` read has a recompute-from-leaves fallback (`redb_backend.rs:1241-1245`), so the cache is **dispensable for correctness and load-bearing for cost**: `verify_root` runs on **every ingested block** (`engine/merge.rs:651`, inside the per-block pre-pass), so without the cache every complete segment is recomputed from its leaves once per block and **sync becomes quadratic** (`WSS-14`). Dropping it, keeping it, and replacing it with a different checkpoint scheme are all open — and **the option that drops it owes a cost answer**. | §5 rows 1–2; §8; `WSS-Q2`; the interim-tie PR's scope |
| **WSS-10** | **`PDM-Q12`'s code cites have drifted ~6–50 lines at this pin.** `StoreError::FrozenSegmentPruned` is at `redb_backend.rs:470` (cited `:464`); `ServingReader`'s doc block spans `:160-183` and its `open_frozen_segment_body` is at `:216`, while `LeafStore::open_frozen_segment_body` is at `:1877` (cited as `:164-183` for all three). The **symbols** named are correct; the **ranges** are stale. Recorded as a re-pin, not a defect. | Every increment's Round-0 re-pins rather than inheriting |
| **WSS-11** | **`redb_backend.rs` is still 4 196 lines** — nothing of `CTS-` is built. The file holds the schema, six codecs, `StoreError` (17 variants), three handle types, every operation, and ~2 000 lines of tests. | §8; the decomposition principle survives any `WSS-Q1` answer |
| **WSS-13** | **`P`'s serving state is written through the *principal's* curve-tree actor, into the principal's file — a firewall-layering defect.** `EngineServeSetPinner` holds a `CurveTreeHandle` and a `p_id` side by side (`stake_engine/serve_set_source.rs:79`, `:101`) and calls `pin_serve_set` on that handle (`:254-257`); the handle it is given in production is the **engine's own** — `g.curve_tree.clone()` at `stake_engine/serving/start.rs:158`, passed at `:203-206`. So the serve set — which is `P`'s bonded obligation, and whose membership is `P`-correlated — is persisted by the actor that owns the principal's proving state, in the same `.curvetree` file. [`PRINCIPAL_STAKE_LIFECYCLE.md`](PRINCIPAL_STAKE_LIFECYCLE.md) §0 treats keeping `P`'s material inside the `StakeEngine` actor as load-bearing; this path routes around that. **This, not `WSS-5` or `WSS-6`, is what makes `WSS-Q1` urgent**, and it re-poses it as an *ownership* question rather than a storage one (§6.1). | `WSS-Q1` — the ground; the firewall stack |
| **WSS-18** | **The plaintext `.curvetree` file is an at-rest route to `P`, beside an encrypted `.wallet` — verified.** The store is a **sibling of the wallet file** (`shekyl-engine-file/src/paths.rs:117-121`: `primary.wallet` → `primary.wallet.curvetree`) and `shekyl-curve-tree` contains **no encryption at all** — the only `chacha` hits in the crate are a test RNG (`store/ops.rs:148-158`). The serve-set pins that `WSS-13` routes into it are therefore **`P`'s holdings in plaintext next to an encrypted wallet**, which is the gap on its own: the wallet already ruled that no-password disk access is worth defending against, and a plaintext companion undoes that ruling for exactly the adversaries it was made for. **Verified negative that bounds the problem:** the onion key is *not* a second route — `Detach` is unrepresentable, the onion dies with its control connection, and the identity holds re-mintable expanded bytes behind `Zeroizing` (`shekyl-tor-control-client/src/onion_identity.rs:74-83`, `:148-152`), so Tor never writes it to disk. | §6.2 — the whole at-rest case rests on this row |
| **WSS-24** | **`P`'s anchor gate runs on the *principal's* ingest height, so an honest `P` refuses valid challenges whenever the principal's scan is more than 4 blocks behind. Live in today's code, independent of this round.** `HostSigner::own_height` reads `sync_tip_height()` from the shared curve-tree store (`shekyl-p-host/src/signer.rs:97-101`) — its own doc calls it *"the store's synced tip"*, which is how far the **principal's block scan** has ingested, **not the daemon's tip**. The pre-sign gate accepts only `anchor ∈ [own_height − 720 − L, own_height − 720 + L]` with `L = PASS_ANCHOR_LAG_BLOCKS = 4`, **provisional** (`shekyl-p-serve/src/countersign.rs:145-151`; `shekyl-archival-retention/src/pass_anchor.rs:34`). **Nothing bounds the ingest lag below `L`.** The one freshness check, `caught_up` with `CAUGHT_UP_SLACK_BLOCKS = 64` (`serving/task.rs:568-572`, `:45`), feeds **health reporting only** (its single consumer is `:482`). **Consequence:** more than 4 blocks of scan lag ⇒ rejected valid challenges ⇒ missed passes ⇒ slashing, with the operator honest throughout. The unwind removes the source anyway, because `P`'s store ingests no blocks. | §6.7; `R-A` |
| **WSS-25** | **The release gate would erase every holding during a daemon resync — and `caught_up` cannot prevent it even in principle.** `releasable(owed, pinned, as_of)` (`serve_set_source.rs:170-190`) derives `now_epoch = as_of / SETTLEMENT_EPOCH_BLOCKS` from the height the bond record answered at, notes `first_absent = as_of` for every held-but-not-owed shard, and releases at `now_epoch − absent_epoch ≥ 2` (`:284`). **It never checks whether the daemon is synchronized.** *Scenario — a daemon rebuilding its chain, which the C++→Rust cutover forces on **every** daemon:* mid-resync the record reads at a height before `P` bonded, so the owed set is empty and every held shard is noted absent at that early height; as the resync advances the answering height crosses two epoch boundaries (20 000 blocks — minutes to hours of sync); the gate fires for **every** held shard. **Today this is harmless** — a release only unpins, and `prune_frozen` has no production caller (`WSS-8`). **After the unwind a release deletes**, so an honest archiver wipes everything it holds, misses every subsequent challenge, and is slashed while refilling by recovery. **`caught_up` is the wrong instrument:** it compares the record's `as_of_height` with the wallet's *own* ingest, i.e. **wallet-vs-daemon** lag — during a daemon resync both are low and in step, so it reports caught up. It cannot see **daemon-vs-network** lag, which is the axis that matters. **Adversary: nobody.** An ordinary operational event, near-certain per operator at the cutover, with severe harm. | §6.7; `R-B`; `WSS-Q14` |
| **WSS-23** | **`PDM` made *verification* per-transaction and left the *read* whole-shard; this round conflated them.** `PDM-Q6` item 4 re-keys `SF-D1` as *"No per-tx addressing on the route either; the read is still whole-shard"* — the one-resource-one-path conclusion standing on `RF-R1` alone — while `SF-D8`'s content half is what became per-transaction: *"Content-verify is per-tx via `Transaction::txid_parts()` against the two hash rows, plus membership against `(b_k, b_{k+1})`"*. **The conflation entered through the opening brief's §8 row** (*"Serve per-tx through `shekyl-p-serve` — `SF-D8` content half"*), which named the verification ruling as the authority for a serving granularity, and `WSS-Q7` inherited it verbatim. **Consequence if it had gone unfixed:** the store would have been designed with a per-transaction index it does not need, and the route would have grown addressing `SF-D1` forbids. | §6.6; `WSS-Q7` |
| **WSS-22** | **Nothing checks that a bonded `shard_id` exists or is closed, and the inherited claim that something does is unsupported at the call sites.** `ShardSet::new` — *"the one fallible constructor — every decoder / FFI marshal / builder routes through it"* (`shekyl-archival-retention/src/bond_wire.rs:210-227`) — enforces **only** `MAX_HOLDINGS_SHARDS` and duplicate-freeness. Nothing in `bond_post.rs` / `bond_connect.rs` / `bond_floor.rs` bounds a `shard_id` against chain state, so a bond may name a shard that does not exist yet. **And the inherited claim needs correcting:** the two-store entry ([`V3_WALLET_DECISION_LOG.md`](../V3_WALLET_DECISION_LOG.md), 2026-09-17) says *"bond admission reads it to decide which `shard_id`s are admissible"* of `frozen_segment_count` — but its three consumers are the **D2 escalation operand** (`blockchain.cpp:1502`, and its comment names it as such), the **coverage RPC** (`archival_shard_coverage.cpp:34`) and the **freeze / pop-revert** path (`db_lmdb.cpp:7997`). **None is bond admission.** So the successor rule is not a re-key of an existing check — it is unbuilt, and a reader who believes it exists will not build it. | §6.5.5; a question owed to the DRS lane, not assumed here |
| **WSS-21** | **The two hash rows are the last two components of the txid, and the txid is committed in the block the wallet already syncs.** A spend's txid is 4-part — `H(prefix) · H(base) · H(pqc_auths) · H(prunable)` (`shekyl-wire/src/transaction/txid.rs:52-58`; the coinbase is 3-part with a null prunable component, so it carries no archival good) — and `TxidParts { hash, pqc_auth_hash, prunable_hash }` (`:43-50`) is precisely the txid **plus** the two store rows, computed in one pass. Block-level commitment: the tree root is `merkle(miner_tx_hash ‖ tx_hashes)` inside the PoW blob (`shekyl-chain-rules/src/rules/header.rs:173`). **So a holder of the full bytes can verify them against consensus directly**, without the rows. The rows exist for the party that *cannot* — `hash_with_supplied_components(pqc_auth, prunable_hash)` (`txid.rs:194-201`) is the skeleton path, and its existence is the evidence that the rows' consumer is the discarding daemon, not the filling wallet. | §6.4; `WSS-Q5` |
| **WSS-20** | **A `tracing` log line puts `P` in a plaintext file — a second at-rest route, and a new gap.** `serve_set_source.rs:261-263` **emitted** `shard_ids = ?releasable` at **`info`** level on every pin release. Released shard ids matched against the chain's public bond history **identify `P`**. The sink is a plaintext file (`--log-file`, `shekyl-wallet-rpc/src/main.rs:87-89`; created mode `0600`, `shekyl-logging/src/appender.rs:119-124`) and persists exactly as `.curvetree` does — as does journald. **So encrypting `P`'s store does not close the at-rest route on its own** (`WSS-18`): this line reaches the same adversaries — no-password forensics, offline VPS snapshots, shared machines. **Fixed in PR #793:** the line logs the released **count** (and the epoch gate's `releasable` count), never the ids, and the spent-watch quarantine's `GlobalOutputIndex` went the same way. The standing half is `rust/shekyl-logging/tests/p_correlated_ids_absent_from_logs.rs`, which refuses a `P`-correlated identifier at any level across `stake_engine/` and the four crates on `P`'s serving path. | §6.2; `WSS-19`; it gates the same claim |
| **WSS-19** | **`P`'s *other* persisted state is unaudited, and the audit gates the claim that encrypting the store closes the gap.** `WSS-18` establishes one plaintext route to `P`; it does not establish that it is the only one. **Audit executed 2026-09-19** over the per-wallet siblings in `shekyl-engine-file/src/paths.rs` (`.keys` `:59`, `.curvetree` `:98`, `.tor` `:126`, `.pscan` `:170`, `.pending` `:198`) — see §6.2.5 for the table. Result: **one new route found** (`WSS-20`, the log line), **one accepted residual** (the *existence* of `.pscan` / `.pending` says the wallet has staked — not which persona; same class as the store's multi-gigabyte footprint, `WSS-15`), and **one factual check, now run and negative** (§6.2.7: the pinned Tor records nothing per hosted service — measured against the pin's own digest, with the service confirmed published and still live at clean shutdown). **`WSS-19`'s remaining work was therefore exactly `WSS-20`**, discharged by PR #793; until the log ids were stripped it could not claim closure — a fix that closes one of several routes and is described as closing "the" route is worse than none, because it retires the question. | §6.2.5; it gates the at-rest claim |
| **WSS-14** | **The subroot cache's role is cost, and the cost is per block.** `verify_root` is called on **every ingested block** (`engine/merge.rs:651`, in the per-block pre-pass that refuses to advance past tree state the wallet cannot reproduce). `root_at_count` under it reads `frozen_segments.r_k` per complete segment (`WSS-4`); without the cache each block recomputes every complete segment from leaves, so **sync cost becomes quadratic in chain length**. Correctness has a fallback; throughput does not. | `WSS-9`; `WSS-Q2`; the proving-side arm in §6.1 |
| **WSS-15** | **Per-shard file sizes are a fingerprint, and encryption does not hide them.** Under `PDM-Q-F32` a closed shard's size lies in **`[SHARD_BYTES, SHARD_BYTES + MAX_TX_SIZE)`** (`ARCHIVAL_PRUNED_DAEMON_MODE.md:411`) — **variable, not fixed** — and every shard's exact size is **public**, because the A4 length rows are consensus. So a per-shard file layout would map file size → `shard_id` → `P`, and a file vanishing at drop time would line up with the drop's on-chain timestamp. Encryption hides content; it hides neither sizes nor the times sizes change. **Disposition: ACCEPTED RESIDUAL, not a design constraint.** Exploiting it needs a forensic adversary who cannot get the password but *will* compute every persona's holdings count from the chain and match it against disk capacity; the payoff is modest (holdings counts are probably shared by many archivers, and multiple gigabytes of archival data already says "archiver", padded or not) against 15–30 % of storage plus complexity. **Reopening criteria (rule 21):** evidence that holdings counts are near-unique across the market — the sim can measure the distribution — or forensic tooling that actually targets this. | `WSS-Q12` (residual); the #775 criterion applied to disk |
| **WSS-16** | **`WSS-Q8` is already answered by landed code, and the landed rule is stronger than any horizon derived from documents.** `EngineServeSetPinner` releases a pin only after the shard has been **absent from the bond record at two consecutive epoch opens** (`EPOCHS_BEFORE_PIN_RELEASE = 2`, `stake_engine/serve_set_source.rs:284`), and `releasable`'s doc comment (`:140-169`) carries the whole argument: a pair is drawable in epoch `E` iff it held the shard at `E`'s open, so a mid-epoch drop does not end the obligation; one epoch is too tight because a challenge issued in the last drawable block still has to **resolve**; and **`W₂` is deliberately not an operand** because it has no landed constant (§9.7 item 6, UNDERIVED) — a full epoch of slack covers any `W₂` below `SETTLEMENT_EPOCH_BLOCKS`, with a **rule-21 reopening criterion** if the rig ever derives `W₂ ≥ one epoch`. Two epoch boundaries also sit far deeper than `ARCHIVAL_REORG_DEPTH_BLOCKS`, so reorg protection is subsumed. **The consumer this round found is covered by it:** the recovery fetch draws from the epoch's drawable set, and the pair stops being drawable before release. *The consumer itself, recorded because it is what makes the horizon non-trivial:* The leaf-era motivation is gone (the FOLLOWUPS row's *"path-assembly serving purpose"* dies with `PDM-Q6`), and the challenge path does filter — the witness skips a pair not held at fire height. **But recovery fetches draw from the epoch's *drawable set*, which is deliberately not filtered at the tip.** `SF-D10` makes organic selection *"a uniform memoryless draw over the drawable holder set of shard `s`"* performed by the organic scheduler, which *"consumes the drawable snapshot and draws"* (`ARCHIVAL_SHARD_FETCH.md:184`, `:1232-1257`); and `SO-D8` Q3 §7.4 ruled that `D` must **not** be filtered by `holds_shard_of` at tip, because a later drop would retroactively falsify the point query and make `D` time-varying — *"A dropped pair stays in `D` for `E`; the filter lives at settlement and at the witness"* (`ARCHIVAL_CHALLENGE_MECHANISM.md:197-203`). With `settlement_epoch_blocks = 10000` (`consensus_constants.json:22`) that is up to ~10 000 blocks in which a recovery fetch can draw a dropped `P` for that shard — against a `D_max` of 720. **Cost of the miss is small but real and lands on someone else:** nothing is lost and nobody is penalised (organic misses are not slashed, per-need exclusion re-draws another holder, and the drop is public so "not held" reveals nothing), but each unlucky draw wastes a Tor circuit belonging to **the daemon that needed the data**. | `WSS-Q8` — answered by the landed gate |
| **WSS-17** | **`R1`'s invariant holds today and is mechanically checkable.** The store never talks to the daemon: `shekyl-curve-tree`'s dependencies are `redb`, `shekyl-fcmp`, `shekyl-crypto-pq`, `shekyl-consensus`, `shekyl-types` (`Cargo.toml`) — no daemon-RPC edge, and the edge that exists runs the other way (`shekyl-daemon-rpc` imports vocabulary from it, §4.1). **Falsifier: any dependency edge from the store crate to a daemon-RPC crate, checkable with `cargo tree`.** Stated as an invariant with a falsifier rather than left as an accident of the current graph — the fill path (`WSS-Q4`) is exactly the pressure that would add one. | `WSS-Q4`; the increment gates in §9 |
| **WSS-12** | **`CurveTreeClient` holds the full leaf set in memory.** `entries: Vec<LeafEntry>` (`client.rs:293`) beside `store: Arc<LeafStore>` (`:290`); the store is the durable mirror and `rebuild_from_store` reloads it wholesale at open. Obligation A's working set is therefore RAM-resident and grows with the chain — a device-floor question at the Pi-4 provisioning floor ([`76-device-provisioning-floor`](../../.cursor/rules/76-device-provisioning-floor.mdc)) that no round has asked. | `WSS-Q2`; out of scope for increment 1, named so it is not shed |

---

## 5. The shared surface with the daemon — what this store reads and never mints

This is the section steering's answer (1) asks for in operational form: every
daemon-owned input named **by citation**, so a daemon-side change is a re-pin
of one row rather than a redesign.

| # | Input | Owner (mints it) | This store's relation | Falsifier |
| --- | --- | --- | --- | --- |
| 1 | **The shard partition `b_*`** | S-PRUNE's forward pass over the A4 length rows, once (`PDM-Q9` (iii)) | **Reads. Never mints.** E3 S-CURVE, this store and the verifier all read it | This store computes a boundary. A divergent partition **forks at admission** — consensus, not a local convention |
| 2 | **`SHARD_BYTES`** | One home, const-asserted, not editable as a tune (`PDM-Q-F33` (i)) | Reads. Production scope is `BuildRust.cmake`'s roots; `shekyl-sp-t3-spike`'s fixture constant and `shekyl-economics-sim`'s `f64` model constant are **intentional exclusions** | A production `SHARD_BYTES` in a second shipped crate, or in `consensus_constants.json` |
| 3 | **The txid**, committed through `merkle(miner_tx_hash ‖ tx_hashes)` in the PoW blob | Consensus; the wallet already holds it from the blocks it syncs | **Verify-on-fill is against the txid** (§6.4, `WSS-21`), recomputed from the bytes just fetched. `txs_prunable_hash` / `txs_pqc_auth_hash` stay the **daemon's** need for `DRS-D10` skeleton replay and are **not** an input here | A verify-on-fill that trusts a supplied digest rather than recomputing the commitment |
| 4 | **Fill transport** | The **ordinary split transaction read every wallet already makes** — `shekyl-daemon-rpc/src/methods.rs:552-605` (`PDM-Q9`/`Q10`) | Consumes. `get_prunable_range` is **withdrawn** | **Any archival-serving RPC on the daemon is a falsifier of `PDM-Q9`**, not a convenience |
| 5 | **The specified-to-scarce window** | `PDM-Q6` item 3 / `PDM-Q9` — shard `k` is bondable from `close_height(k)`, scarce at `discard(k)`, `≥ W` later | The window is **when** this store fills, from the local daemon over the operator leg | A fill outside the window with no recovery-fetch path |
| 6 | **Codecs** | `shekyl-store-codec` (§8 (i), PR A) | Shares one **encoding contract** with the daemon store **without sharing a schema** | The two stores' `Canonical` impls diverge for one vocabulary type |
| 7 | **The serve-credit admission verifier** | **E4 / S-ARCH in `shekyl-chain-rules`** (`PDM-Q6` item 4 row 1) | **Not this round's.** Named here only so the lane is not assumed | A preimage change landing in this lane |
| 8 | **Format policy** | [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §11.1(f) | Adopted **by citation**; not restated here | §11.1(f) changes and this row does not move |

### 5.1 Three properties of the new shard unit, put on the record (**open**, not this round's to rule)

Consequences of `PDM-Q6` / `F32` that the byte-bounded unit acquires and that
no document states. Recorded here because this store is the first consumer to
meet them; each is owed to the lane named, not settled here.

1. **A bond no longer buys a uniform amount of work.** The per-shard bond is
   flat, but a closed shard's size varies over
   `[SHARD_BYTES, SHARD_BYTES + MAX_TX_SIZE)` — **up to ~30 % more storage for
   the same collateral**, and scarcity pricing per shard inherits the same
   unevenness. Probably tolerable; **the sim should confirm it holds rather
   than assume it**. Owner: [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md)
   / `shekyl-economics-sim`.
2. **Boundaries can be influenced.** Anyone paying fees can place
   large-prunable transactions to shift where `b_*` falls and which
   transactions share a shard. **No exploit is identified** — it costs fees,
   and challenge assignment derives from `h−1`'s hash anyway — but it is an
   adversary-controlled input to a consensus partition and belongs on the
   **wargame list**, not in a footnote.
3. **`SHARD_BYTES = 3.33 MB` is inherited, not derived.** It was set by the
   *leaf* geometry (25,992 × 128) and `PDM` kept it so `SF`'s measured `N = 8`
   and the anchor-lag `L` candidate stay valid — a reasonable engineering
   choice, **and the record should say so**. Otherwise a future reader assumes
   the number has a first-principles basis in the new unit, which is exactly
   the unexamined inheritance [`16-architectural-inheritance`](../../.cursor/rules/16-architectural-inheritance.mdc)
   exists to catch.

**`PDM-Q6` item 4's rows whose enforcing site is this store.** Enumerated
rather than assumed, per the brief. Of item 4's nine rows, exactly **one** has
its enforcing site here: `LeafStore::frozen_segment` + the freeze pipeline →
a body store keyed by shard over `[b_k, b_{k+1})`. `SF-D8`'s content half is
this store's *supplier* (sub-PR 2's `ContentVerify` consumes what row 3
supplies) but its landing site is `shekyl-p-serve`. The remaining seven —
serve-credit verifier, `RF-D1`, `RF-D6`, `challenge_leaf_index`, `SF-D7`,
`SF-D1`, `CR-D2`, `TJ-D` — land in `shekyl-chain-rules`,
`shekyl-archival-retention`, the fetch/response-format docs, or E4. **No row
is claimed by this lane that its owning doc does not assign here.**

---

## 6. The question list — `PDM-Q12`'s decisions, made

`WSS-Q1` is the axis; the rest inherit its answer. **All fourteen are RULED
(2026-09-19, PR #790)** — each row's last column carries its disposition, and
what is still open is named there too: the daemon-lane halves of `WSS-Q6` /
`WSS-Q10`, and `WSS-Q1`(b)'s four measurements as bench work.

| Q | Question | Input | Default proposed |
| --- | --- | --- | --- |
| **WSS-Q1** | **Which identity owns which state** (§6.1 — *not* "one file or two", which was the wrong axis) | §4's attribution; `WSS-13` (the ground), `WSS-4`, `WSS-5`, `WSS-6`, `WSS-7`; CT-1 §3.6; CT-5 §3.1; steering (1) | **Split by identity, in two parts of unequal weight.** **(a) RULED 2026-09-19** — `P`'s serving store is its own file, owned by the `StakeEngine`, and is **the wallet's only redb**; rests on verified code (`WSS-13`) and the firewall. **(b) RULED 2026-09-19 — adopted, subject to §6.3.4's four measurements, all now gradable:** the principal's proving state **is not a store at all** (§6.3) — a public frontier at `F`, a buffer of recent blocks, and per-output membership paths in each identity's existing sealed file . The two budgets §6.3.4 owed were set with this ruling: **spend edge `delta ≤ max(2 s, 15 % of proving)`**, **open edge `≤ 5 s` absolute at local posture**. **The case for (b) strengthened while the round was staged:** `SOK-10` Q7 → A **deleted the daemon's per-output path assembler** — `get_curve_tree_path` removed as spend-revealing at `CORE_RPC_VERSION` 3.34 (`shekyl-rpc-types/src/chain.rs:46`), `rpc_path` gone from `rust/` — so **the wallet is now the only path assembler in the system, with no daemon fallback for paths at all.** §6.3's design is load-bearing by construction, not merely cheaper than a leaf store |
| **WSS-Q2** | **Does the rebuilt store prune, what bounds obligation A's growth, and does it keep a segment-subroot cache?** **Conditional on §6.3** — if the proving state is not a store, the A-side half of this question does not arise | `WSS-8` (the discard was never wired; prune-disabled is only the `CompleteTree` posture), `WSS-9` / `WSS-14` (the cache is dispensable for correctness and **load-bearing for cost** — `verify_root` runs on every block, `engine/merge.rs:651` — and its boundary cannot be tied to `b_*`), `WSS-12` (full leaf set in RAM), `76-device-provisioning-floor` | **RULED 2026-09-19.** **If A stays a store** (i.e. if `WSS-Q1`(b) is not adopted): B prunes by shard lapse; A does not prune and owes a stated growth bound at the Pi-4 floor. A growth bound is owed either way, and whoever drops the subroot cache owes a sync-cost answer |
| **WSS-Q3** | **Reorg under the answer to Q1** | `WSS-7`; §6.5.4's finality rule; §6.3's recent-block buffer | **RULED 2026-09-19.** **`P`'s store never reorgs, because it fills only *final* shards** — `close_height(k) + D_max ≤ tip` (§6.5.4). **Not "shards at least `W` old": the daemon discards at `W`, so that would make every fill a recovery fetch** and defeat the in-window local fill that is `PDM-Q9`'s whole mechanism. The reorg path stays with the **principal**, in §6.3's recent-block buffer over `D_max` plus the reference-height window |
| **WSS-Q4** | **When the fill runs, and from where** | `PDM-Q9`; §5 rows 4–5; Pin 5; `WSS-22` | **RULED 2026-09-19.** **Fill first, then post the bond** (§6.5). The deadline is the **next epoch's open** (Pin 5), which may be one block away; filling before the post removes the race and makes "bonded but not held" unreachable from the normal path. Source is the local daemon over the operator leg before `W`, a recovery fetch after; both verify by txid (`WSS-Q5`), so the source is not a correctness variable |
| **WSS-Q5** | **What a fill is verified against** | `PDM-Q6`; §5 row 3; `WSS-21` | **RULED 2026-09-19.** **The txid, not the hash rows** (§6.4) — recompute each transaction's txid from the bytes just fetched and compare it with the txid committed in the block. A **recorded difference from `PDM-Q6`'s wording**, with its argument at §6.4: it verifies against the consensus commitment rather than the daemon's cache of two of its components, it needs no DRS row that has not landed, and recovery shards verify identically. **`PDM-Q6`'s superseded sentences are amended in this PR** (`ARCHIVAL_PRUNED_DAEMON_MODE.md:1014`, `:1360`), so the two contracts do not disagree — the rule-16 pattern of a contract left asserting a superseded decision |
| **WSS-Q6** | **Key by shard over `[b_k, b_{k+1})`** | `PDM-Q-F32`, `PDM-Q9` (iii); §5 rows 1–2 | **Wallet half RULED 2026-09-19:** yes; the store **reads** `b_*` and mints nothing, and refuses a fill that fails §6.4.3's boundary check. **And the boundary is the one input the wallet cannot fully verify** — §6.4.3 states what it can check, what it cannot, and how a wrong `b_k` fails. **The read path is not rulable here:** `b_*` and `close_height(k)` must become **readable daemon facts**, which rides `WSS-22`'s question to the daemon lane |
| **WSS-Q7** | **The store's read for `shekyl-p-serve` — whole-shard, not per transaction** | `SF-D1` re-key (`PDM-Q6` item 4); `SF-D8` content half; `WSS-23` | **RULED 2026-09-19.** **A whole-shard byte stream** (§6.6). `PDM` made **verification** per-transaction and left the **read** whole-shard; "serve per-tx" conflated the two. `ShardProvider`'s contract carries over almost exactly; the store needs **no per-transaction index at all** |
| **WSS-Q8** | **The lapse tail** — how long an archiver serves a shard it no longer bonds | [`FOLLOWUPS.md`](../FOLLOWUPS.md) (the archiver retention-horizon row), owner [`ARCHIVAL_SERVING_ROUTE.md`](ARCHIVAL_SERVING_ROUTE.md), **enforcing site this store**. **The rule has a builder** — `stake_engine/serve_set_source.rs` | **RULED 2026-09-19, conditional on `WSS-Q14` landing first** — the release gate is **the one piece of this design that deletes data**, and `WSS-25` shows it is unsafe until "synced" is a type, which is also §6.7.4's PR order. **Then: erase at the second consecutive epoch open at which the shard is absent from the bond record** (`EPOCHS_BEFORE_PIN_RELEASE = 2`, `WSS-16`). It already covers the recovery-fetch consumer, because the pair stops being drawable before release, and it carries its own rule-21 reopening criterion. **Rejected — and it was this round's own proposal:** *"erase at the close of the epoch in which the drop connected, plus `D_max`"*. It looks equivalent and is weaker: it silently assumes `W₂ < D_max` (~720 blocks), i.e. it **smuggles in an operand that has no value yet**, which is precisely what the landed gate was written to avoid. **Also rejected:** filtering `D` against holdings at tip, which reopens `SF-D10` **and** `SO-D8` Q3 to save ~4 MB; and accepting the misses, which exports an avoidable cost to the daemon that needed the data. The rule stays the serving route's; the enforcement and its test are this round's |
| **WSS-Q9** | **Recovery intake** — the daemon's episodic fetch hands a shard across and retains nothing | `PDM-Q9` recovery clause; §6.4.2, §6.6.5 | **RULED 2026-09-19.** Intake is the **same write and verify path as a fill** — whole-shard, verified by txid, so **no trust in the sender** and no separate verification design (§6.4.2 item 3); the handoff is whole-shard like the serve (§6.6.5). The daemon side is episodic and stateless by `PDM-Q9` |
| **WSS-Q10** | **The Foundation `CompleteTree` behind a persona, never on a daemon** | `PDM-Q9` coverage floor; [`FOUNDATION_ARCHIVAL_DISCLOSURE.md`](FOUNDATION_ARCHIVAL_DISCLOSURE.md):196, [`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md):120 | **Wallet half RULED 2026-09-19:** a `CompleteTree` is **a reconcile whose *owed* set is every closed, final shard** — **a configuration of the same store, not a fourth store type**. *The prune-disabled posture is **not** part of it:* §6.7.1 deletes the posture, which existed only to stop a prune the new store does not have, and the store does not care about holdings kind — only the **owed computation** does (`COMPLETETREE_ACTIVATION` D-1/D-5). **The wallet side is rulable now; the admission semantics are not:** the *owed* set needs `b_*` and `close_height(k)` as readable daemon facts, and **how `CompleteTree` admission works** is part of the bond-add question owed to the daemon lane (`WSS-22`) |
| **WSS-Q12** | **Where the `P`-store's encryption key lives** — the question the withdrawal (§6.2) shrank this to | `WSS-18`; `WSS-19`; [`35-secure-memory`](../../.cursor/rules/35-secure-memory.mdc), [`36-secret-locality`](../../.cursor/rules/36-secret-locality.mdc) | **RULED 2026-09-19.** **One** store key from the wallet's existing key hierarchy. It must stay **out of the Tor-facing serving task**, which follows from rule 36 anyway and is `WSS-Q13`. Per-shard keys, wrapping, crypto-shredding and a size-hiding layout are rejected (§6.2.3; `WSS-15` is an accepted residual). |
| **WSS-Q14** | **Should "synced" be a type rather than a call-site check?** | `R-B`; `WSS-25`; [`05-system-thinking`](../../.cursor/rules/05-system-thinking.mdc) | **RULED 2026-09-19.** One type — say `SyncedChainFacts` — whose only constructor refuses unless the daemon reports synchronized, so acting on an unsynced view is a **compile error**. Today only the submit watchdog honours sync state (`submit_watchdog.rs:218-221`: synced iff `target_height == 0 \|\| height ≥ target_height`), and its predicate becomes the constructor. **Consumers that must take it:** the release gate, fill finality (`close_height(k) + D_max ≤ tip`), fill-then-post and the bond builders, `P`'s anchor-gate height (`WSS-24`), and any epoch arithmetic feeding those. **Sweep owed:** every read of a daemon height, the bond record, or chain facts in `shekyl-engine-core`, `shekyl-p-host`, `shekyl-p-serve`, listed with `file:line` and classified as through-the-type or not — **a site that cannot be classified is a finding**. **R1 seam:** the type lives wallet-side and is built from the engine's daemon client, so a DRS response-shape change touches only the constructor |
| **WSS-Q13** | **Secret locality on the serving path** — `shekyl-p-serve` needs plaintext bodies but must not hold the store key | [`36-secret-locality`](../../.cursor/rules/36-secret-locality.mdc); §6.2.4 | **RULED 2026-09-19.** Plain rule 36 — **the store's owning actor decrypts, the serving path receives bodies, and the key never leaves the actor.** Nothing more is claimed: the bodies are public, so this is key locality, not a confidentiality boundary, and "a dropped shard cannot be served" is enforced by the held-slot token and row deletion (§6.2.3), not by this |
| **WSS-Q11** | **What happens to the landed `SEGMENT_LEAF_COUNT` / `leaves_per_segment()` tie at E4** | `PDM-Q-F33` (ii); `WSS-9`; the FOLLOWUPS partition row | **RULED 2026-09-19.** **The tie is LANDED, not owed** — #780 put one home in `shekyl_fcmp::tree` with the consensus-side compile-time assert in `shekyl-archival-retention`'s production lib, red-checked at `segment_leaf_count = 26030`, and the CT-1 row closed with its dedup. What is open: it **dies at E4 / S-ARCH with the freeze** and is **not re-pointed at `SHARD_BYTES`** (`WSS-9`: one is a leaf count, the other a byte threshold). Its one possible survival is as the boundary of a proving-side subroot cache, which is `WSS-Q2`'s |

### 6.1 `WSS-Q1` — re-grounded on the firewall (steering review, 2026-09-18)

**The question was posed on the wrong axis.** As first written, `WSS-Q1` asked
"one file or two" and argued it from storage mechanics — the shared file lock
(`WSS-6`) and the prune/resume collision (`WSS-5`). Steering's reading
re-grounds it, and the substrate agrees (`WSS-13`):

> **`WSS-Q1` is not a storage question. It is a question of which identity
> owns which state.**

- **The serving store is `P`'s.** The serve set is a persona's bonded
  obligation; its membership is `P`-correlated. It should be owned by `P`'s
  side — the `StakeEngine` and the serving task — live in its **own file**, be
  **encrypted at rest under a key from the wallet's existing key hierarchy**,
  and be **erased on the landed pin-release gate** — the second consecutive
  epoch open at which the shard is absent from the bond record (§6.2).
- **The proving state is the principal's.** Opened unconditionally (`WSS-1`),
  carrying no persona correlation, and — `R3` — **derived from canon and
  self-checking against it on every block**, so it never needs a migration.
  Whether it needs to be a **store** at all is §6.3.

**Why this is the right axis and the mechanics were not.** The firewall is a
stack — network, timing, output, bond funding — and
[`PRINCIPAL_STAKE_LIFECYCLE.md`](PRINCIPAL_STAKE_LIFECYCLE.md) §0 treats
keeping `P`'s material inside the `StakeEngine` actor as load-bearing. A
question answered on file-lock mechanics can be re-answered by a future change
to redb; a question answered on the firewall cannot, because the firewall is
the mission commitment (`00-mission` #2, privacy). It is also the axis that
**names a defect in the code today** rather than only a preference about
tomorrow: `WSS-13` shows `P`'s serve-set pins passing through the principal's
actor into the principal's file. Under the storage framing that is invisible;
under this one it is the finding.

**Why one file is not an option.** It is the arrangement that puts two
identities' state in one artifact, which is what `WSS-13` reports as a defect.
So `WSS-Q1` was never *whether* to separate but **what each side becomes** —
both now ruled:

| Side | Open question | Written up in |
| --- | --- | --- |
| **`P`'s serving store** | Its own file, encrypted at rest, erased on the landed pin-release gate — what writes it (the `StakeEngine`, not the curve-tree actor), the fill path (`WSS-Q4`), **where the store key lives** (`WSS-Q12`, the question the withdrawal shrank this to), the serving path's read capability (`WSS-Q13`), and how `WSS-13`'s current routing is unwound | §6.2 |
| **The principal's proving state** | **Resolved: it is not a store.** A public frontier at `F` plus a buffer, shared; private per-output paths in each identity's existing sealed file. Open on four measurements and the ingest-path firewall answer | §6.3 |

**What is still open after the ruling:** nothing on this axis — both sides are
ruled (`WSS-Q1`(a) and (b)), and `WSS-Q3` with them. What remains is bench work
(§6.3.4) and the daemon-lane halves of `WSS-Q6` / `WSS-Q10`. **The mechanics
findings are retained as supporting evidence, not as grounds** — `WSS-6` says
the one-file arrangement was never chosen, and `WSS-5` says it cannot be made
to satisfy both storage policies; neither is why the answer is what it is.

### 6.2 `P`'s serving store — what the disk reveals, and what that justifies (**`WSS-Q8` / `Q12` / `Q13` RULED 2026-09-19**)

**Erasure is per shard, and later than the drop.** Granularity is **per
shard** — a `HoldingsUpdate` drop
releases one shard while the bond continues. Timing is the **landed pin-release gate** — the
second consecutive epoch open at which the shard is absent from the bond record
(`WSS-Q8`) — and **not** `drop-connect + D_max`, which this round proposed and
then rejected, because a dropped pair stays **drawable** for the rest of its
epoch. The reorg reasoning that formula rested on is subsumed rather than lost:
under [`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md)
Pin 3 (`:488-497`) the slash scheduler challenges **currently-held** shards and
exit forgiveness applies only once the drop **connects**, and a connected drop
can be **reorged out**, which puts the obligation back — and two epoch
boundaries sit far deeper than that. Erasing at *post* time
would risk a slash for a shard `P` destroyed and was then obligated for again.
**And the erasure point is later still, and is already implemented:** a dropped
pair stays in the epoch's drawable set until that epoch closes, and a challenge
issued in its last drawable block still has to resolve — so the horizon is the
**second consecutive epoch open at which the shard is absent from the bond
record** (`EPOCHS_BEFORE_PIN_RELEASE = 2`, `WSS-16`). Two epoch boundaries sit
far deeper than `ARCHIVAL_REORG_DEPTH_BLOCKS`, so Pin 3's reorg protection is
subsumed rather than replaced.

#### 6.2.1 What the disk actually reveals

The shard contents are **public chain data**, so reading them does no harm.
**The only secret on the disk is the link between this device and persona
`P`** — which shards are held, matched against `P`'s public holdings.
Everything bad follows from that link: it says the person is an archiver, it
gives their bonded capital (public as shards × rate), and it gives their reward
history and timing. That is **financial-participation disclosure**, the same
kind of harm as someone learning a wallet balance.

So the question per adversary is what the disk gives them that they could not
get otherwise.

| Adversary | Realistic capability | What the store adds | Assessment |
| --- | --- | --- | --- |
| **State forensics, device seized, password compellable** | Full image **and** the password | Nothing — the decrypted `.wallet` already contains `P` | **Out of scope** for any at-rest measure |
| **State forensics, password not compellable** (jurisdiction, 5th Amendment, border search without compulsion) | Offline image only | Today, the **plaintext `.curvetree` pins give them `P`** despite the encrypted `.wallet` (`WSS-18`) | **Real — and the one that matters** |
| **VPS / cloud host** (archivers are storage-heavy and will rent) | Snapshots and backups offline; memory if they choose | Same as the row above for offline images; nothing extra if they read live memory | **Real** for offline images and snapshot leaks |
| **Thief** | Device, no password | `P` — marks the owner as holding bonded capital | Low: a marginal extortion signal; they already know who they robbed |
| **Malware on the host** | Live memory, keylogging | Nothing — it gets the keys and the funds | Irrelevant: theft dwarfs any at-rest measure |
| **Shared machine / employer IT / disposed drive** | Offline file access | `P` | Low to moderate |

#### 6.2.2 What is justified

1. **Encrypt `P`'s serving store at rest, under a single key from the wallet's
   existing key hierarchy.** **The reason is consistency, not a new threat.**
   The wallet already decided that no-password disk access is worth defending
   against — that is why `.wallet` is encrypted — and a plaintext companion
   file that reveals `P` **undoes that decision** for rows 2, 3 and 6 above.
   The gap is real today (`WSS-18`) and the fix is cheap.
2. **Erase on the landed pin-release gate — the second consecutive epoch open
   at which the shard is absent from the bond record** (`WSS-Q8`, `WSS-16`).
   The tail is not zero: a recovery fetch draws from an epoch-open snapshot
   that `SO-D8` Q3 deliberately leaves unfiltered at the tip, so a dropped pair
   stays drawable for the rest of its epoch and a challenge from its last
   drawable block still has to resolve. **This rule is already implemented**
   (`serve_set_source.rs:284`), names no underived operand, and carries its own
   rule-21 reopening criterion. **The new store must erase on this gate and
   nothing earlier** — see §6.2.5, which is a constraint on the `WSS-13`
   unwind, not only on erasure. This reclaims storage and makes "not held" true. With the store
   encrypted, whatever survives in freed pages is recoverable only by someone
   holding the password — and that person already knows `P`'s history from the
   chain.

#### 6.2.3 What is WITHDRAWN, and why each ground failed

**Per-shard keys and crypto-shredding — REJECTED.** Three grounds were
offered for them; none survives, and they are recorded so the alternative is
not re-proposed:

- *Remnants* (redb copy-on-write, SSD wear levelling, snapshots and swap) —
  **covered by 6.2.2 item 1.** Once the store is encrypted, remnants are inert
  to everyone who lacks the password, and everyone who has it already knows.
- *Scoping a compromised serving task* — **protects nothing confidential.**
  The data the task could read is **public**. Its real assets are `P`'s
  countersigning capability and a route into `StakeEngine`, and per-shard keys
  touch neither.
- *Unrepresentability of serving a dropped shard* — **a correctness property,
  and it has a cheaper mechanism.** A **type-level held-slot token** plus
  deleting the rows gives it **without key management**.

**A single store key is sufficient.** The whole apparatus of random per-shard
keys, wrapping under a `P`-derived key, wrapping-key rotation on every drop,
and the TPM/secure-enclave discussion goes with it.

**Size padding and slot preallocation — REJECTED**, recorded as an **accepted
residual with reopening criteria** (`WSS-15`).

*What the rejection does not sanitise:* `WSS-15`'s underlying observation
stands — shard sizes are variable and public, and encryption hides neither
sizes nor when they change. It is accepted because the adversary who could use
it is narrow and the cost is 15–30 % of storage, **not because the channel
closed**.

#### 6.2.5 What `P` leaves on disk — the `WSS-19` audit

Per-wallet siblings, from `shekyl-engine-file/src/paths.rs`.

| File | State | What it reveals **without the password** |
| --- | --- | --- |
| `.wallet.keys`, `.wallet` | Sealed | Nothing about `P` |
| `.wallet.pscan`, `.wallet.pending` | Sealed, **same** region-2 envelope with distinct `PayloadKind`s (`handle.rs:641`, `:712`) | *Contents:* nothing. **Existence:** written only once `P`-scan starts (`pscan/start.rs:331`, `:454`), so their presence says **"this wallet has staked"** — not which persona |
| `.wallet.curvetree` | **Plaintext** | **`P`**, through the pins (`WSS-18`). The known gap |
| **Log file** (`--log-file`, mode `0600`) | **Plaintext** | **Nothing about `P`** — the released shard ids at `info` (`serve_set_source.rs:261-263`) that matched the chain's bond history were replaced by counts in PR #793, which also added the standing guard that keeps them out (`WSS-20`). **Closed** |
| `.wallet.tor/` | Tor's own persistent state (entry guards, DQ-T0.7) | **Nothing about `P` — measured, not assumed (§6.2.7).** The pinned Tor records **no per-hosted-service data**: `state` holds only `Guard`, `CircuitBuildTimeBin`, `TotalBuildTimes`, `Dormant`, `LastWritten`, `TorVersion`; `keys/` stays empty; and the onion address appears nowhere under the data directory, nor in Tor's own log at `notice` **or** `info`. Residual: the directory's **existence** says the wallet ran Tor — `WSS-15`'s class |

**Three dispositions.**

1. **Encrypting `P`'s store does not close the gap on its own.** `WSS-20` was
   a second route to `P` for the same adversaries, so both actions are needed:
   **strip the ids from the log** (count only, plus a test that no
   `P`-correlated id reaches a log at any level) and **seal the store**. The
   first landed in PR #793; **the store's seal is still owed.**
2. **The existence of `.pscan` / `.pending` is an accepted residual.** It
   reveals that the wallet has staked, not which persona — the same class as a
   multi-gigabyte store's existence, already accepted at `WSS-15`. **Recorded,
   not mitigated.**
3. **The Tor `state` file question is CLOSED — the check was run** (§6.2.7):
   the pinned Tor persists nothing per hosted service.

**So `WSS-19`'s remaining work was exactly `WSS-20`, and PR #793 discharges
it.** With the ids stripped, **sealing `P`'s store closes the at-rest route to
`P`**,
and the remaining work is the store's own design — fill, verify-on-fill,
whole-shard serve, recovery intake, and the `WSS-13` unwind.

#### 6.2.7 The Tor `state`-file check — run, 2026-09-19

`WSS-19` named this a factual check rather than a design question. It was run
on this box; the result is **negative**, and the method is recorded so it can
be re-run when the Tor pin moves.

**Instrument.** The **pinned binary itself**, not a system Tor: the bundled
`tor` at `tor-expert-bundle-15.0.17` hashes to
`660a8c54…6d16fb`, which is `CURRENT_PIN.sha256` exactly
(`shekyl-tor-control-client/src/binary.rs:113`) — the pin's own comment records
that 15.0.17 and the 15.0.19 label ship a byte-identical `tor 0.4.9.11`, and
the digest match is the evidence. Launched with the **spawn arguments the
wallet uses** (`control/actor.rs:891-900`: `--DataDirectory`, `--ControlPort
auto`, `--ControlPortWriteToFile`, `--CookieAuthentication 1`, `--SocksPort
auto`), bootstrapped to 100 % on the live network.

**Procedure.** `ADD_ONION NEW:ED25519-V3` over the control port — **ephemeral,
no `Detach`**, the wallet's posture — then `SETEVENTS HS_DESC` to confirm the
service **actually published** (`HS_DESC CREATED` → `UPLOAD` → **`UPLOADED`**);
a service that never published would have made the result vacuous. Then
`SIGNAL HALT` **with the service still live**, which is the strongest case for
persistence, since Tor rewrites `state` on clean shutdown.

**Result.**

| Check | Outcome |
| --- | --- |
| Service id anywhere under the data directory, **while published** | **Not found** |
| Service id anywhere under the data directory, **after clean shutdown** | **Not found** |
| `state` keys after shutdown | `CircuitBuildTimeBin`, `Dormant`, `Guard`, `LastWritten`, `TorVersion`, `TotalBuildTimes` — **no onion or hidden-service key** |
| `keys/` directory | **empty** |
| Onion address in Tor's own log | **absent at `notice`** (what the wallet configures) **and at `info`** |

**What *is* persisted** is entry guards (20 `Guard` lines, `in=default`),
circuit-build timings and dormancy — required by DQ-T0.7, identical for any Tor
client, and carrying nothing that distinguishes a serving wallet from a
fetching one. **Re-run trigger:** the check is pinned to a Tor version, so
moving `CURRENT_PIN` re-opens it.

#### 6.2.6 A constraint the `WSS-13` unwind must keep

`StoreShardProvider::shard_bytes(shard_id)` takes **only a shard id**
(`shekyl-p-serve/src/provider.rs:255`): the provider **has no notion of the
serve set** and answers for **any bytes that are present**. Today that is
load-bearing rather than accidental — a dropped-but-still-pinned shard stays
served, **and that is what keeps the obligation met** while the pair is still
drawable.

So the new store **erases on the pin-release gate and nothing earlier**
(§6.2.2 item 2). An unwind that moves erasure ahead of that gate — or that
makes the provider serve-set-aware and refuse before release — would break the
obligation the current blindness is quietly satisfying.

#### 6.2.4 What remains open

- **`WSS-Q12` — where the store key lives.** It must stay **out of the
  Tor-facing serving task**, which gets a **read capability through the actor**
  — and that follows from [`36-secret-locality`](../../.cursor/rules/36-secret-locality.mdc)
  anyway, so it is `WSS-Q13` rather than a new constraint.
- **`WSS-19` — the audit of `P`'s other persisted state** (`P`-scan records,
  serving counters, logs). **This is a Round-0 item, and it gates the claim
  that encrypting the store closes the gap** rather than one of several routes.
  `WSS-18` records the one verified negative that bounds it: the onion key does
  not reach disk.

### 6.3 The proving side is **not a store** — resolved (steering, 2026-09-18); **open** on four measurements

**Resolution.** The principal's proving state is **not a leaf store**. It is:

- a **public frontier at `F = tip − W`** plus a **block buffer** below the tip,
  **shared by both identities** because it is derived from the chain and
  reveals nothing about ownership;
- **private membership paths per owned output**, kept in **that identity's
  existing sealed file** — the principal's in the sealed ledger beside
  `TransferDetails`, `P`'s in `P`'s sealed state.

**The wallet's only redb is then `P`'s serving store**, which makes this
round's opening description — *"the wallet's redb exists for serving from `P`
when bonded"* — literally true.

#### 6.3.1 Why the leaf store is not required — the premise, at source

Zero knowledge hides which leaf is spent **from the verifier**, not from the
prover, which knows its own leaf. The two sides need different things: the
**verifier** needs only the root (the daemon holds it in `curve_tree_roots`
and the header commits to it); the **prover** needs only **its own output's
path** — the full child chunk at each layer from its leaf to the root, plus
the root. That is pinned to the FCMP++ prover's `Path` type at
`assemble.rs:18-35` (`shekyl-oxide/crypto/fcmps/src/prover/mod.rs`): the
prover consumes `c1_layers` / `c2_layers` chunks and a `tree_root`, and
nothing else.

**The anonymity set is unchanged.** The proof ranges over everything under the
root however little the wallet stores. Today's full-leaf retention is an
implementation choice — `assemble.rs` says so in its own module doc
(*"branch extraction rebuilds layers from replay-held `CurveTreeClient::entries`"*,
`:14-16`) — not something FCMP++ requires.

#### 6.3.2 The six attacks, answered at source

Each row was **verified at `8494f2a27`** by this round; the fourth column says
what verification changed.

| # | Answer | Anchors | Verified / amended |
| --- | --- | --- | --- |
| 1 | **Pending set is bounded at 60 blocks.** Maturity is creation height + `COINBASE_LOCK_WINDOW` (miner) or + `DEFAULT_LOCK_WINDOW` (otherwise); `TargetKind::Other` returns `None` and never becomes a leaf | `recon.rs:116-126`; `shekyl-consensus/src/lib.rs:28,:31` (10 / 60) | **Verified**, including the load-bearing negative: `unlock_time` appears **nowhere** in `shekyl-curve-tree/src/`, so maturity is the only drain gate. This check could have sunk the design and does not |
| 2 | **Finalized state at `F = tip − W`, `W = 730`, plus a buffer replayed to the reference height.** Reorgs shallower than `W` never touch persisted state, so **no undo log** | `consensus_constants.json:4-5` (min age 5, max 100), `:26` (`archival_reorg_depth_blocks = 720`); `segment.rs:37,:69-71` — `segment_freeze_eligible` requires `SPENDABLE_AGE_BLOCKS + SEGMENT_FREEZE_REORG_MARGIN_BLOCKS` = 10 + 720 = **730**, the same margin | **Verified**, with one **amendment: the buffer is `W + 60` blocks, not `W`.** To replay drains over `[F, ref]` the wallet needs outputs **created** from `F − 60` (coinbase maturity). Either the buffer extends 60 blocks below `F`, or the state at `F` carries the pending set. The design must say which |
| 3 | **Late discovery costs the rescan that was already required.** Today's tree is always rebuilt from genesis (`refresh/task.rs:337-358`'s "rebuilding membership" backfill); a late output is handled by streaming again and capturing its path along the way, at tree-depth memory instead of chain-size | `refresh/task.rs:337-358` | **Verified with one narrowing.** For an imported key or a lowered restore height the rescan is needed *anyway* — the scanner needs the block data — so the path rides it free and the row is right. **The exception is an output the wallet already scanned but did not mark path-worthy** (a multisig member learning of an output under a shared view key): today that is free from `entries`, here it needs a fresh stream. **Remedy, and it is cheap:** define path-worthy as *"in the ledger"* rather than *"currently spendable"*, and the exception disappears |
| 4 | **Per-block update cost is essentially none.** In an append-only tree only the rightmost node at each layer is incomplete, so every chunk on an owned path is either **final forever** or **identical to the frontier's chunk at that layer**. Each output stores its final lower chunks; the upper part is read from the frontier at spend time. The only per-output work is one chunk copy when a layer finalizes | widths 38 / 18 at `fcmps/src/lib.rs:61,:63`; `SELENE_CHUNK_WIDTH = LAYER_ONE_LEN` at `shekyl-fcmp/src/tree.rs:47`; leaf-chunk read at `assemble.rs:137-141` | **Verified, arithmetic included.** At ~100 M leaves the tree is ~6 layers (38 → 18 → 38 → 18 → 38 → 18). A path is **~9 KB**: 38 × 128 B = 4 864 B leaf chunk, 18 × 32 = 576 B per Helios layer, 38 × 32 = 1 216 B per Selene layer. The frontier is the same size. Against **~12.8 GB** of leaves (100 M × 128 B) held on disk *and* in RAM today |
| 5 | **The persistence pattern already exists.** `save_state` seals the whole `.wallet` atomically; `save_pscan_state` is the precedent — `P`'s scan state in its own sealed `.wallet.pscan` under the **same** region-2 envelope with a **distinct `PayloadKind`**, so a swapped file is refused on load | `handle.rs:611-617`, `:641-647`; `payload.rs:117-126` (`WalletLedgerPostcard = 0x01`, `PScanStatePostcard = 0x02`) | **Verified, and the precedent is exact** — `payload.rs:123-126` says in its own words that the distinct kind byte is what makes a swapped file *"a loud refusal, not a postcard decode at a random offset"*. Private state changes only when an owned output drains or a layer finalizes, and those rides saves that already happen. **What it does and does not answer for `WSS-Q12`.** What carries over is the **key hierarchy** — one key from the wallet's existing region-2 hierarchy — and the **distinct-domain discipline** that makes a swapped artifact a loud refusal. **The layout does not carry over:** `save_pscan_state` seals a **whole body and replaces the file atomically**, whereas `P`'s serving store needs **random-access, independently sealed chunks inside redb** (§6.6.5). A `PayloadKind` names a domain; it does not define a chunk format. **Treating these as one precedent would be the error** — the envelope is reused, the write pattern is not. **It does answer part of `WSS-19`** (`P`'s scan state is already encrypted) |
| 6 | **Blast radius is bounded by the actor's interface.** Eight messages: six proving (`IngestBlock`, `RollbackToFork`, `IngestedTipHeight`, `VerifyRoot`, `RootAndDepthAt`, `AssembleTx`) and two that move to `P`'s store anyway (`PinServeSet`, `PinCompleteTreePrefix`, `WSS-13`). `shekyl-ffi/src/curve_tree_replica_ffi.rs` is the **C++ test generator** and stays as the full-tree oracle beside `build_layers` | `curve_tree_actor.rs:336,:362,:391,:412,:424,:437,:462,:476` — **exactly eight**; `curve_tree_replica_ffi.rs:6-14` | **Verified exactly.** See §6.3.3 for the one interface change and the firewall question it raises |

#### 6.3.3 The one interface change, and the firewall answer it needs

`IngestBlock` must learn **which drained leaves are owned, and by which
identity**. Today the tree has no notion of ownership, and **that neutrality is
exactly what let one store serve both identities**.

**The risk this creates, named because it is `WSS-13` in a new location:** if
one ingest path must know both the principal's and `P`'s ownership, a single
component again sees both identities' material — the defect §6.1 was opened to
remove, relocated rather than fixed.

**The answer is available and should be built in rather than left to
discipline:** the **frontier advance is public and identity-free**, and **path
capture is a per-identity filter over the same public stream**. One public
ingest; two private capture sides, each seeing only its own outputs, each
writing into its own sealed file. The shared part is then public data only —
the frontier and the buffer — and the path sets split by identity, which is
`WSS-Q1`'s ownership rule applied inside the proving side.

#### 6.3.4 What remains open — four measurements, each with its reopening threshold

**`WSS-Q1`(b) wants ruling *as adopted subject to these*, not on the reading
alone.** A threshold that cannot be stated yet is marked as owing a value
rather than given an invented one — the `WSS-Q8` lesson: a horizon that names
an operand with no value smuggles in an assumption.

| # | Measurement | Reopening threshold |
| --- | --- | --- |
| 1 | What `rollback_to_fork` does on a reorg **deeper than `W`** | **Statable now, and behavioural rather than numeric: it must *refuse*, not silently produce a wrong tree.** If it corrupts rather than refusing, (b) reopens — a proving state that can be silently wrong is worse than one that is large. **And it carries a rule-82 failure mode**: the remedy is a full resync, and the wallet must say so in those terms |
| 2 | **Spend-time replay** of the buffer on a **Pi 4**, over the ≤ ~725 blocks between `F` and the reference height. **Measure at a stated worst-case leaf rate, not an average one:** the cost scales with **drained leaves** in the window, not with blocks — an empty window replays free and a busy one does not, so a measurement taken on a quiet chain would grade green and reopen on a busy one | **RULED 2026-09-19: `delta ≤ max(2 s, 15 % of proving time)`** — same rig, same run, same canonical tx shape. *Why this shape:* the relative arm carries the grading at realistic proving times; the **2 s absolute floor** stops a small denominator failing prep no human could perceive; and slow-prover laundering is capped because 15 % of a genuinely long prove is still a tolerable fraction of a wait the user is already committed to. **Re-graded on a material prover-pin change.** **Miss response unchanged:** amortized replay first, and `WSS-Q1`(b) reopens only if the amortized form still fails |
| 3 | **Refetching the buffer on open**, and whether it needs its own companion file | **RULED 2026-09-19: `≤ 5 s` absolute, local-daemon posture.** Absolute rather than relative because **there is nothing to be relative to** at open. **Scope is part of the ruling:** it grades the **local** posture only — a remote daemon over Tor refetches more slowly and is **not graded by this threshold**, which is a stated scope, not an omission. **Miss response — AMENDED 2026-09-20: attribute the cost to a term before firing a remedy.** The original response (*the buffer gets its own companion file*, which §6.3.1 attack 5 anticipates) was pre-registered on a **volume** theory of the cost. Reading the landed fetch path refuted that premise before any measurement: `fetch_scannable_block_with_form` (`block_fetch.rs:132`) is strictly per-block and issues **2–3 sequential round trips per block** — `get_block`, `get_transactions`, and `get_o_indexes` inside `compute_first_output_index` (`:491`) — so ~1 600–2 400 serialized round trips over the 790-block buffer, with no pipelining. So: a **volume-bound** miss fires the companion file as pre-registered; a **round-trip-bound** miss fires **bulk or pipelined fetch**, which is the proportionate remedy for that term; a miss that attributes to neither is the maintainer's to place. The bench reports the attribution **in the same record as the measurement** ([`WSS_Q1B_BENCH_SPEC.md`](WSS_Q1B_BENCH_SPEC.md) §4.2). *Why amend now rather than at miss time:* a remedy discovered mid-grading not to match its cause is exactly what pre-registration exists to prevent. **Corpus density — AMENDED 2026-09-20, and it differs from row 2's:** this row grades at a **stated nominal density, the full-reward zone (`MIN_BLOCK_WEIGHT` = 300 000 weight/block)**, and the adversarial window is an **accepted long-tail** covered by [rule 80](../../.cursor/rules/80-usability.mdc) progress indication. *Why:* 790 blocks at the 2 400 000 sustained ceiling is **≈ 1.9 GB decoded**, which no hardware refetches in 5 s — so grading at row 2's density would **write the companion-file response before measuring it**, the same failure this row's miss-attribution amendment was made to avoid, reached from the other side. The zone is the density at which the measurement can still surprise you (≈ 237 MB in 5 s ⇒ ~47 MB/s decoded, an open question on a Pi 4 over JSON-RPC). **The asymmetry with row 2 is the ruling, not an oversight:** row 2 decides an **architecture** and its cost is paid **on every spend**, so a quiet-chain measurement would grade green and reopen busy; this row decides a **local mitigation** — persist the buffer or refetch it — paid **once per launch**, where a slow path is a progress bar rather than a broken design. The nominal is a **stated judgment** in the class of this section's 2 s and 15 % budgets, with a rule-21 reopening criterion: a measured distribution of real block weights, or a crossover showing 5 s breaks below the zone. **Enforced rather than written:** `open_edge` withholds its verdict when the sampled corpus falls below half the graded density, so a thin-corpus run cannot read as a pass |
| 4 | **Property tests against `build_layers`** over every edge where a layer finalizes | **Statable now, and binary: any mismatch reopens (b) outright.** The existing full-tree implementation is the oracle, which is what makes this replaceable rather than rewritten blind |

**All four are now gradable — the two budgets were set with `WSS-Q1`(b)'s
ruling** (2026-09-19), which is what the FOLLOWUPS row asked for and what
discharges it. They were maintainer judgments, not derivations.

**The corpus and protocol for rows 2 and 3 are specified in
[`WSS_Q1B_BENCH_SPEC.md`](WSS_Q1B_BENCH_SPEC.md)**, and built as
`rust/shekyl-wss-q1b-bench`. What follows in this section is the *authority*;
that document carries the derivations it leaves to the bench — the worst-case
leaf rate, the depth ladder, the rig gate's enforced/attested split, and the run
record's schema.

**The rig, pinned here because it was not pinned anywhere.** The measurements
are only comparable across runs if the machine is fixed, and
[`76-device-provisioning-floor`](../../.cursor/rules/76-device-provisioning-floor.mdc)
fixes only the **device class** — *"`Raspberry Pi 4 Model B` (Cortex-A72,
aarch64, 64-bit userland)"* — which is the floor's whole point but not a bench
spec. The rest is stated here:

| Pin | Value | Why it must be stated |
| --- | --- | --- |
| Device | Pi 4 Model B, Cortex-A72, **aarch64 64-bit userland** | Rule 76's floor. A 32-bit userland on the same board is a different machine for this work |
| RAM | **8 GB** | The Pi 4 ships in 1/2/4/8 GB. A replay measured at 8 GB and graded as the floor would understate every smaller board |
| Storage | **USB-SSD**, not microSD | Buffer refetch and replay are I/O-bound; microSD and SSD differ by more than the thresholds do |
| Thermals | **sustained**, not burst — run to steady state before measuring | The A72 throttles. A burst measurement grades a machine that does not exist after a minute |
| Leaf rate | **worst case**, per row 2 | The cost scales with drained leaves, not blocks |

**And three more the bench owes.**

1. **The canonical tx shape is 2-in/2-out** — **reused, not minted**:
   [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §13 already fixes it as this
   project's budget shape, and `PDM` §9 and the firewall round both cite it.
   Per-input proving makes the denominator shape-dependent, so the shape must
   be stated; minting a second canonical shape beside §13's would be the
   duplicate-source error.
2. **The boundary between *delta* and *proving* is the prover API call**
   (**RULED 2026-09-19**, drawn here rather than left to the bench):
   - **delta** = spend-intent through **constructed `Path`** — the state copy
     at `F`, the buffer replay, the path read-off, and `Path` construction;
   - **the denominator** = the **prover invocation**, `Path` in, proof bytes
     out;
   - **proof serialization is charged to neither.**

   It sits at the `assemble_tx` → prover seam, which is what makes it hold:
   **work cannot migrate across it without a visible signature change.** A
   boundary drawn anywhere inside either side would be a convention the bench
   could drift; this one is a type boundary the compiler enforces. Stated once
   here, not per run.
3. **Report the absolute delta alongside the ratio.** 15 % of an unknown
   denominator is an unknown number of seconds, and the denominator does not
   exist yet — so a pass on the ratio should still be read against the seconds
   it represents the first time the bench runs.

**One thing this bench yields for free and the project should keep:** it must
execute proving to obtain the denominator, so the same session produces
**FCMP++ proving time on a Cortex-A72** — a figure this project does not have
and will want for rule-80 progress-indication decisions regardless of
`WSS-Q1`(b).

**A failure mode, not a measurement, and it sits under row 1:** a reorg deeper
than `W` is expected to be the same class as crossing a frozen segment today —
**unverified**.

**One consequence worth stating, because it inverts an earlier finding:**
under this design `verify_root` (`engine/merge.rs:651`, every block) becomes an
**O(depth) frontier advance** rather than a tree read. So `WSS-14`'s quadratic
risk does not merely go away with the subroot cache — **the per-block check
gets cheaper than it is today**, and `WSS-Q2`'s A-side half stops arising at
all (`WSS-12` with it).

### 6.4 How `P`'s store verifies what it fills (**`WSS-Q5` RULED 2026-09-19**)

**Proposed: verify against the txid, not against the daemon's hash rows.** A
recorded difference from `PDM-Q6`'s wording, with the argument here — which is
what `R3` requires of a divergence.

#### 6.4.1 The mechanism

Fetch the whole transaction — prefix, base, `pqc_auths`, prunable region —
recompute its **txid**, and compare with the txid committed in the block.
A match proves the archived bytes are exactly the committed ones.

The chain of trust is already whole for a party holding the bytes:

```text
PoW blob  ⊃  merkle(miner_tx_hash ‖ tx_hashes)      header.rs:173
                         │
                      txid of each tx
                         │
   H(prefix) · H(base) · H(pqc_auths) · H(prunable)  txid.rs:52-58
                                  │          │
                          the archived good ─┘
```

The two hash rows are the **last two components of that txid**, cached
(`TxidParts`, `txid.rs:43-50`). A party that holds the bytes recomputes them;
it does not need them supplied.

#### 6.4.2 Why this is better for the wallet — three reasons, in order

1. **It removes the dependency on the daemon rewrite.** The hash rows are DRS
   work that has not landed (A3 landed on #772; **A4 is still owed**). Verifying
   against the txid needs only the ordinary full-transaction read that exists
   today (§5 row 4) plus txids the wallet already holds. **The fill path becomes
   buildable now**, and verification does not break if the row format moves
   during DRS — which is steering's "properly decouple the daemon elements that
   are in flux" (§1.1 (1)) applied to the store's first decision.
2. **It checks against the root of trust rather than a cache of it.** Under
   `R3` the wallet adopts canon and never mints its own. The txid **is** the
   consensus commitment; the rows are the daemon's copy of two of its
   components. Verifying against the txid is adopting canon **more** directly,
   not diverging from it — so the difference from `PDM-Q6` narrows the trusted
   surface rather than widening it.
3. **Recovery shards verify identically.** A shard handed over by another
   archiver is checked the same way: recompute each txid from the bytes,
   compare with the block. **No trust in the sender is required**, and
   `WSS-Q9`'s intake needs no separate verification design.

**Why the daemon still needs the rows — so this is not read as retiring them.**
After a daemon discards a shard it can no longer recompute those txids from
what it retains, but replaying and validating its own skeleton (`DRS-D10`)
still needs them. That is the rows' job and it stays daemon-side. The API says
so itself: `hash_with_supplied_components(pqc_auth, prunable_hash)`
(`txid.rs:194-201`) exists for the party without the bytes. The wallet **has**
the bytes at the moment it verifies, so it does not share that need.

#### 6.4.3 The one input the wallet cannot fully verify — shard boundaries

Membership is `[b_k, b_{k+1})`, derived from the daemon's A4 length rows. Under
`R3` the wallet **adopts** `b_*` and mints none of its own (§5 row 1), so this
is a trust edge by design rather than an oversight. What the wallet can and
cannot check, stated precisely:

- **Checkable — the end boundary, given the start.** Once shard `k` is filled,
  the running byte total over its transactions must cross `SHARD_BYTES` **at
  the last transaction and not before** (`PDM-Q-F32`'s closing rule). That
  confirms `b_{k+1}`.
- **Not checkable — the start.** `b_k` cannot be confirmed without the previous
  shard's bytes, which the store does not hold. It rests on trusting the
  **local daemon over the operator leg** — the existing trust model (§5 row 4),
  not a new hole.

**How it fails, stated because a trust edge without a failure mode is an
unexamined one.** A wrong `b_k` from the local daemon means the store holds the
**wrong set of transactions** for shard `k`. Nothing detects it at fill time.
The **first challenge on that shard misses**, and the operator is **slashed**.
That is a loud, attributable, operator-local failure with no consensus effect
and no privacy effect — acceptable, and the design should say that is how it
fails rather than leave a reader to discover it. (It is also an argument for
the checkable half: a `b_{k+1}` that does not close at `SHARD_BYTES` is a
refusable fill, and refusing it costs nothing.)

#### 6.4.4 What comes after this, in order

1. **When the fill runs** — inside the specified-to-scarce window while the
   local daemon still holds the bytes, triggered by a shard joining `P`'s
   holdings (`WSS-Q4`).
2. **The serving interface** — a **whole-shard** byte stream to
   `shekyl-p-serve`, **keeping the serve-set blindness** of §6.2.6
   (`WSS-Q7`, §6.6).
3. **Unwinding `WSS-13`** — the serve set and the posture move out of the
   curve-tree actor into the `StakeEngine`.

### 6.5 When the fill runs — `WSS-Q4` (**RULED 2026-09-19**)

#### 6.5.1 The deadline is the next epoch's open, and it can be one block away

A pair is drawable in epoch `E` **iff it held the shard at `E`'s open**, so a
mid-epoch add is not drawable until `E+1` — that is **Pin 5**, enforced in the
draw-set derivation rather than checked at settlement
([`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md):274-279).
The gap between an add connecting and `E+1` opening is therefore **anything
from one block to 10 000**. An add posted near an epoch boundary leaves almost
no time to fetch several megabytes over Tor.

#### 6.5.2 So: fill first, then post the bond

`P`'s `StakeEngine` decides which shards to add, so it can **fetch, verify and
store a shard before posting the bond that obligates it**. That makes
**"bonded but not held" unreachable from the normal path** and removes the
epoch-boundary race entirely. A failed fill simply means the post is not made,
and the operator is told.

The ordering fits both entry points:

- **JoinMarket** has a builder (`build_join_market_vin`,
  `shekyl-archival-bond-builder/src/lib.rs:158`): fill the whole initial serve
  set, then post.
- **A `HoldingsUpdate` add has verify arms but no builder** — the crate has
  only `build_join_market_vin` and `build_release_vin` (`:158`, `:310`),
  confirming `PRINCIPAL_STAKE_LIFECYCLE.md` §5 item 2. **So this ordering can
  be designed into it from the start** rather than retrofitted.

**This is also what makes §6.4.3's boundary refusal free.** A fill refused
because shard `k` does not close at `SHARD_BYTES` happens **before anything is
bonded**, so the refusal costs nothing. Per
[`82-failure-mode-ux`](../../.cursor/rules/82-failure-mode-ux.mdc) it is a
**loud operator-facing error — never a silent retry**: the operator needs to
know their daemon handed them a boundary that does not close, because the
alternative is bonding against it and being slashed.

#### 6.5.3 Where the bytes come from

The local daemon discards shard `k` only once **both** conjuncts of `PDM-Q2`'s
predicate hold (`ARCHIVAL_PRUNED_DAEMON_MODE.md:150-154`):
`b_{k+1} ≤ first_tx_id(tip − W)` **and** `close_height(k) + SEB < tip`, with
`W = CRB + n·SEB + D_max` ≈ 195 days (provisional).

- **Before that:** the **local daemon** over the operator leg (§5 row 4).
- **After that:** a **recovery fetch** to a drawable holder (`WSS-Q9`).

Both verify against the txid identically (§6.4), **so the source is not a
correctness variable** — only a latency and availability one. At genesis
nothing is discarded until the chain passes `W`, so **every early archiver
fills locally**.

#### 6.5.4 Only fill shards that can no longer change

A shard that closed within `D_max` of the tip can still have its contents
replaced by a reorg, and the **open frontier shard has no end yet** (`PDM-Q6`
item 3 already makes it non-bondable). The wallet-side rule:

> Fill — and therefore bond — only shards with `close_height(k) + D_max ≤ tip`.

#### 6.5.5 A gap this surfaces, owed to the DRS lane as a question

**Nothing on the consensus side checks that a bonded `shard_id` exists or is
closed** (`WSS-22`). `ShardSet::new` enforces cardinality and
duplicate-freeness and nothing else, so a `P` can bond a shard that does not
exist yet.

**This is not merely a re-key.** The claim that bond admission already bounds
`shard_id` via `frozen_segment_count` is **unsupported at the call sites** —
those consumers are the D2 escalation operand, the coverage RPC, and the
freeze / pop-revert path (`WSS-22`). So the byte-range successor has **no
predecessor to re-key**; it is unbuilt.

**Consequence, and why this is a question rather than an assumption.** Without
such a check a `P` bonding a nonexistent shard is mostly hurting itself — the
first challenge misses and it is slashed — but **the settlement verifier still
has to behave sanely when challenged on a shard that does not exist**, and that
is consensus. Under the byte-range unit the check belongs to the daemon lane
(**S-ARCH / E4**), not here. **This round raises it and does not assume either
way.**

#### 6.5.6 Two residuals, both answered

- **Does filling before posting leak anything? No.** A fill from the local
  daemon is entirely over the operator leg, so nothing reaches the network. A
  **recovery** fill lets a serving archiver observe an anonymous Tor fetch of
  shard `k`, and later an on-chain add of shard `k` by some persona — but the
  add is public anyway, and the fetcher is a circuit, not an identity. The most
  it links is *"the new holder of `k` fetched `k`"*. **No mitigation
  warranted.**
- **Losing a bonded shard** (disk failure, corruption) uses the **same path**:
  refill by recovery fetch, verify by txid. The slash exposure in between is
  the operator's trade, which is how `PDM-Q9` already frames archiver-store
  durability.

#### 6.5.7 Where the fill driver lives

**On the `StakeEngine` side, with `P`'s store.** It asks the daemon for full
transactions through the engine's existing daemon client, verifies them, and
hands **verified bytes** to the store. **The store never talks to the daemon**
(`R1`, `WSS-17`), and nothing here depends on a DRS row format — only on the
ordinary full-transaction read that exists today.

### 6.6 The serving read — `WSS-Q7` (**RULED 2026-09-19**)

#### 6.6.1 The granularity correction

`WSS-Q7` as posed said *"serve per-tx"*. That is wrong, and `WSS-23` traces
where it came from. **`PDM` made verification per-transaction and left the read
whole-shard:** `SF-D1` re-keys to *"No per-tx addressing on the route either;
the read is still whole-shard"*, while `SF-D8`'s content half is the per-tx
part — `txid_parts()` per transaction plus membership in `[b_k, b_{k+1})`.
**So `WSS-Q7` is the store's whole-shard read.**

#### 6.6.2 What `P` serves, and why it needs no framing of its own

The body is the **canonical concatenation, in `tx_id` order, of
`prunable ‖ pqc_auths`** for each transaction in `[b_k, b_{k+1})` that carries
a region. **`P` adds no per-transaction framing**, because:

- the requester is **always a daemon** (a witness, or a recovery fetch);
- every daemon keeps the **two A4 length rows per transaction permanently** —
  *"Permanent, never discarded, journaled"* (`PDM-Q6` item 3 amendment);
- so the requester **splits the stream at each boundary from its own trusted
  rows**.

Framing from `P` would therefore be **redundant and untrusted**. The same rows
give the requester the shard's **total length before the first byte arrives**,
so a response whose length disagrees is refusable at the header.

#### 6.6.3 The frame re-key — owed to the RF/SF lane, not to this round

`RF-D4`'s inner frame is **leaf-typed**: `leaf_count` varint ≤
`leaves_per_segment`, then exactly `leaf_count × LEAF_BYTES`
(`shekyl-curve-tree/src/served_frame.rs:18-21`). Under the byte unit:

- **`leaf_count` becomes a byte length**, bounded by
  `SHARD_BYTES + MAX_TX_SIZE`.
- **The padding rule survives unchanged.** *"Write zero, read anything"* is
  argued with **no leaf-specific premise** — the reason given is that a
  parameter every caller must remember to pass `0` for *"would make a rule out
  of what can instead be a fact"* (`served_frame.rs:162-169`) — so under
  `PDM` item 4's own reversion test it **re-keys rather than reopens**. *(Its
  cap is expressed as `≤ leaf_count × LEAF_BYTES` and that expression re-keys
  to the byte length; the rule does not.)*
- **The countersignature half is untouched** — still the 72-byte anchor header
  ‖ `shard_id`.

**The frame is a shared contract** between `p-serve`, the `p-host` witness and
the fetch client, so **this re-key belongs to the RF/SF lane (SF sub-PR 2)**.
**WSS supplies the byte stream and does not re-key the frame.**

#### 6.6.4 What the store owes the provider — the landed contract, carried over

`ShardProvider`'s properties (`shekyl-p-serve/src/provider.rs:118-257`) survive
the unit change almost exactly, and the store must keep every one:

1. **Servability is settled at open, before any byte is written**, so store
   health stays off the wire: failures collapse to one shared 404 and only
   local counters distinguish them.
2. **Exact length is known at open**, so `content-length` is emitted before the
   store is touched.
3. **Bodies stream in bounded chunks, never materialised.** The doc comment
   states the bill this avoids: `MAX_INFLIGHT × 3.33 MB` resident *"a bill the
   rule-76 provisioning floor cannot pay"* (`:120-125`). **Peak cost stays one
   chunk per connection.**
4. **It is blind to the serve set** (§6.2.6) — it answers for any shard
   present, and erasing is the release gate's job alone.

#### 6.6.5 What this simplifies, and what it deletes

**No per-transaction index at all.** Serving is a straight stream, the
requester delimits it, and recovery handoff is whole-shard too. The store keeps
each shard **exactly as the verified concatenation produced by the fill**, so
opening it is *"look up the slot and stream"*.

**Encrypt chunk by chunk.** The single store key (§6.2.2 item 1) seals **each
storage chunk independently**, with the **slot and chunk index bound in as
associated data**. Decrypting one chunk per read keeps peak memory at one chunk
— i.e. the at-rest decision and property 3 above are compatible **only** at
this granularity. A chunk failing authentication after the head has been sent
**closes the connection and bumps the counter**, exactly as a mid-stream store
error does today.

**And the nonce rule, because one key over many chunks is where AEAD fails.**
The associated data authenticates **where** a chunk belongs; it does **not**
make a nonce unique. Under one store key a repeated `(slot, chunk index)` — a
shard erased and later **refilled into the same slot**, or a recovery intake
replacing one — would reuse a nonce derived from those alone, which is
catastrophic for any AEAD, not merely untidy. **The invariant, stated so the
implementing PR cannot omit it:**

> **No nonce may repeat under the store key, across the store's whole
> lifetime, including refills and recovery intake.**

*Proposed mechanism* (the primitive is the implementing PR's, reviewed under
[`30-cryptography`](../../.cursor/rules/30-cryptography.mdc)): a **random
per-shard salt minted at fill and stored with the shard**, with
`nonce = salt ‖ chunk_index`. A refill mints a **fresh** salt, so slot reuse
cannot reproduce a nonce; the cost is one salt per shard rather than a nonce
per chunk. **A persisted counter is deliberately not proposed** — it is durable
state that can be rolled back or corrupted, and a rollback there is silent
nonce reuse, which is the failure this rule exists to prevent.

**Deleted with the leaf unit:**

- `ProviderError::FrozenSegmentPruned`;
- `ServedFrameHeader::for_segment`;
- `flat_header`'s whole-number-of-leaves rule (`provider.rs:111-116`) —
  `ShardBody::flat`'s validity check becomes **"length within the closed-shard
  range"**, `[SHARD_BYTES, SHARD_BYTES + MAX_TX_SIZE)`.

#### 6.6.6 Does whole-shard serving leak anything? No

Shard sizes vary and are public (`WSS-15`), but **the requester already knows
which shard it asked for**, so the size tells it nothing it did not supply; and
Tor relays know neither endpoint. `RF`'s padding reservation stays for any
future scheme that turns out to need it. **Nothing to mitigate.**

### 6.7 The `WSS-13` unwind (**its questions ruled; the table still design review**)

`R-A` / `R-B` (§1.2), `WSS-Q14` and `WSS-Q8` are **ruled**, and §6.7.4's PRs 1
and 2 are **authorized** (2026-09-19). The **unwind table below is still design
review** — it is the shape the later PRs would take, and each needs its own
authorization.

#### 6.7.1 The unwind, surface by surface

| Today | After |
| --- | --- |
| `PinServeSet` on the curve-tree actor (`engine/curve_tree_actor.rs:362-389`) | A **reconcile** message on `P`'s store actor under `StakeEngine`. *Held but not owed* → the release gate, then erasure. *Owed but not held* should be **unreachable** under fill-then-post (§6.5.2), so it means **data loss**: refill by recovery, surfaced as a **loud operator-facing error** (rule 82) |
| The `absent_since` ledger and the two-epoch gate (`serve_set_source.rs:79-190`, `:284`) | **Moves unchanged** — in memory, failing toward *retention* on restart. Becomes **safety-critical**, because release now deletes. **Takes `SyncedChainFacts`** (`WSS-25`, `WSS-Q14`) |
| `PinCompleteTreePrefix` and the prune-disabled posture (`curve_tree_actor.rs:391-402`) | **Deleted.** The posture existed to stop a prune the new store does not have. `CompleteTree` becomes a reconcile whose *owed* set is **every closed, final shard**, derived from `b_*` over `P`'s transport — keeping the existing `COMPLETETREE_ACTIVATION` D-1/D-5 split: the **store** does not care about holdings kind, only the **owed computation** does |
| `ServingReader`, `same_store` | **Deleted.** They exist only because two actors shared one redb lock (`WSS-6`). `P`'s store gives the provider its own read handle |
| `pinned_segments`, `prune_disabled` in `.curvetree` | **Gone. `.curvetree` then carries no `P` state, which closes `WSS-18`** |
| `HostSigner::own_height` (`shekyl-p-host/src/signer.rs:97-101`) | **Re-sourced** (§6.7.2) |
| `caught_up` (`serving/task.rs:568-572`) | **Re-derived as two checks:** is the bond record fresh relative to the **synced daemon tip**, and is every owed shard held. The current form measures the wrong axis (`WSS-25`) |

**Unchanged constraints, restated because the unwind is where they would be
lost:** §6.2.6 (the provider stays blind to the serve set; **the release gate
is the only path that ever erases**), the chunk-sealed at-rest layout
(§6.2.2 / §6.6.5), and `R1` — **the store never talks to the daemon**
(`WSS-17`).

#### 6.7.2 The `own_height` fix, and the measurement it owes

`own_height` becomes **the configured daemon's tip, read on `P`'s transport**
(`R-A`), cached with an age **well under `L` blocks** — refreshed every ~30 s
or on each block — and **`None` while the daemon reports syncing** (`R-B`).

`None` already has correct handling and needs no new path: the serve loop
renders the shared 404 and counts a lookup failure in `ServeCounters`
(`signer.rs:93-96`).

**Owed as a measurement, not an estimate:** the principal's refresh cadence in
production and the resulting **distribution of lag at signing time**, which is
what quantifies how often today's code refuses honest challenges.

#### 6.7.3 The constraint `WSS-25` puts on the gate

> The release gate **records no absence observations and releases nothing while
> the daemon is unsynced.**

And it owes a **property test**: no shard is erased while the pair can still be
drawn, **including across a simulated resync**. A test that only exercises a
synced timeline cannot fail on `WSS-25`'s scenario, which is the one that
matters.

#### 6.7.4 Proposed order — five PRs, each separately authorized (rule 06)

1. **`own_height` re-source** (§6.7.2). Small; **closes a slash exposure in
   today's code**.
2. **`SyncedChainFacts` and the sweep** (`WSS-Q14`). Small, engine-wide. Must
   land **before or with** PR 3, because the release gate must never delete on
   an unsynced view.
3. **`P`'s store, the fill driver and reconcile**, with the release gate moved
   in and taking the synced type.
4. **Switch the provider** (`shekyl-p-serve`) to `P`'s store.
5. **Delete** the pin messages, `ServingReader` and the posture tables from
   `shekyl-curve-tree`.

**Rule-22 note.** PRs 1 and 2 are **scoped as separate PRs with a named
reason — they do not depend on this round** — and are **not deferrals**: PR 1
fixes a live slash exposure that exists without the unwind, and PR 2 is an
engine-wide type whose consumers extend past this lane. Under *"fit the
existing mechanism now; design the proper one as its own round"*, each is the
existing mechanism's own fix.

---

## 7. `CTS-`'s disposition — successor round, **disposed** on steering's answer (3)

*"CTS as-is was an initial design, but the daemon DRS series has refined that
design. In essence, the daemon is canon, and the wallet store serves to
securely serve a SLICE of that canonical data."* (Rick, 2026-09-18.)

**Disposed: `CTS-` closes as record; this document is its successor.** Not a
scope amendment. Steering's answer (3) names the *ground* — the daemon is
canon, `CTS-` was an initial design the DRS series has refined — and this
round reads close-as-record off it; it does not quote a ruling to that effect,
so **Rick confirms the disposition on review** and the banner flip is written
to be reversible by one edit if he prefers a scope amendment. Amending `CTS-` in place would leave one document holding a
ruled leaf-unit design *and* a body-unit supersession of it, which is how a
contract starts lying — and the leaf-unit design is not wrong, it is **pinned
to a superseded unit**, which is a different thing and is worth keeping
legible as a record.

**What moves, and what stays where it is.**

- `CTS-`'s **unit-independent** content lifts into this umbrella as
  **increment 1** (§8 (i), §9). It is not rewritten; it is cited and
  re-scoped.
- `CTS-Q1…Q6`'s rulings stay in
  [`CURVE_TREE_STORE_SHAPES.md`](CURVE_TREE_STORE_SHAPES.md) as the record of
  what was ruled on 2026-09-18 against the leaf unit, with a status banner
  saying so. **`CTS-Q1`'s ruling is not re-litigated; it is superseded by
  unit**, and §8 (ii) says so explicitly rather than by silence.
- The `CTS-` family stays registered and is **not** reused. Its index row
  gains the successor pointer.
- **No `CTS-` implementation PR lands** — the "Implementation may start, PR A
  first" line in its banner is narrowed by this round to PR A alone (§9), on
  steering's answer (2).

---

## 8. The partition of `CTS-` by unit

Three buckets. Every `CTS-1…CTS-13` and `CTS-Q1…CTS-Q6` is placed.

### (i) Unit-independent — survives any answer to `WSS-Q1`

| `CTS-` item | Why it survives |
| --- | --- |
| **PR A — `shekyl-store-codec`** (§2.1 A, §2.3, `CTS-13`, `CTS-Q2`, `CTS-Q6`) | Both stores need one encoding contract whatever the unit or the file count. §11.1(f)'s last bullet names this PR as the thing that discharges it, and DRS-E3 wants it for the daemon's `curve_tree_*` tables |
| **`CTS-Q3`** — `Leaf` as a newtype over `shekyl_fcmp::ShekylLeaf` | An orphan-rule fact about where a `Canonical` impl may live. Unit-neutral |
| **The absence-is-a-case class** (§3.1) and `MetaCell` (`CTS-8`) | Three recorded instances (CEN-I12, SCR-4, CTS-8) and a discriminator already written in `shekyl-chain-rules/src/view.rs`. A `meta` cell is a cell under any unit |
| **One codec per meaning, distinct `TypeName`s** (`CTS-1`) | `leaves` and `owned_identities` are the same Rust type today — the exact hazard §11.1(f) exists against, and both tables are obligation **A**, untouched by the unit change |
| **`SCHEMA_VERSION` refuse-not-migrate + the `LayoutForeign` open path** (`CTS-9`) | The open contract. Under two files it applies twice |
| **The decomposition principle** (`CTS-10`, `CTS-11`, `CTS-Q4`, §4's module tree) | 4 196 lines is not a module (`WSS-11`). The module *names* re-key with the unit; the ratchet and the two DRY collapses do not |
| **`CTS-12`** | Records that the vocabulary types are already shared. No action, and none needed under any unit |

### (ii) Superseded by the body unit — do not build as scoped

| `CTS-` item | Disposition |
| --- | --- |
| **`CTS-4`, `CTS-Q5`** — `FrozenSegmentRecord`'s codec and its BE→LE move | The record is retired with the freeze (`PDM-Q12`). **But see `WSS-4`/`WSS-9`:** *if* `WSS-Q2` keeps a segment-subroot cache for obligation A it needs *a* record — one designed against the leaf geometry, not `CTS-4`'s consensus-shaped one. Whether it keeps one is open |
| **`CTS-7`** — `pinned_segments` as `Present` | Superseded **in its leaf-unit key only**. `SegmentId`-keyed pins die with the freeze; the **serve-set concept** (`ServeSet` / `PinnedServeSet` in `shekyl-p-host`, `pin_serve_set` / `pinned_shard_ids`) **re-keys to shard `k` and survives**. *Do not delete the concept with the key* |
| **`CTS-Q1`** — `SegmentAvailability` typing the return of `open_frozen_segment_body` | Superseded: it types a method on `PDM-Q12`'s deletion surface, and `StoreError::FrozenSegmentPruned` (`redb_backend.rs:470`) goes with it. **The shape argument survives the method** — "retry later" and "rebuild required" are two instructions a caller must write arms for — and is carried forward to whatever the body store's read returns. The ruling is not reversed; its subject is retired |
| **§4's `freeze.rs` / `serving.rs` modules; §2.1 F's `p-serve` / `p-host` call-site changes** | Scoped against methods that retire. The modules re-key; the call sites change under `WSS-Q7`, not under `CTS-`'s §2.1 F |

### (iii) Was pending `WSS-Q1` — **closed by the ruling, not inherited**

`WSS-Q1`(b) rules that the principal's proving state is **not a store**, so
these items have **no subject**: they type tables of a leaf store the ruling
removes. They are **not** carried into any increment. What survives of their
substance is the *observation* that motivated `CTS-2` — a layout nobody
designed — which is now moot rather than owed.

| `CTS-` item | Disposition |
| --- | --- |
| **`CTS-2`, `CTS-3`, `CTS-5`, `CTS-6`** — `LeafMeta`'s dense 122-byte redesign, `Leaf`, `PendingLeaf`, the retired `TargetKind` tag | **Closed — no subject.** All four typed obligation-**A** table redesigns and all four are *right*. They wait only because `WSS-Q1` decides which **file** they land in and therefore which `SCHEMA_VERSION` their layout commit bumps |
| **`ingest.rs`, `reorg.rs`, `root.rs`** (§4) | **Closed — no subject.** They decompose a leaf store the ruling removes; `WSS-Q3` puts the reorg path in the principal's recent-block buffer (§6.3) and `WSS-14`'s subroot cache question goes with `WSS-Q2`'s A-side half |

**`CTS-2` deserves a note, because it is the clearest thing in the sweep and
it is in bucket (iii):** `leaf_meta` is 192 bytes of which 70 are dead, with
BE integers and `creation_height` at `[122..130)` *because that range happened
to be free at schema v2*. That is a layout nobody designed, on a table no
ruling has touched. It is not deferred for a reason of its own — only
`WSS-Q1` stands between it and a commit.

---

## 9. Work breakdown

The dependency graph, not a schedule. Each increment gets its own plan
document with a Round-0 pre-flight and numbered findings, in the shape of
[`DRS_E1_SOUT_KI.md`](../completed/DRS_E1_SOUT_KI.md); each is separately authorized.

```text
PR A         shekyl-store-codec                    [AUTHORIZED 2026-09-19]
                 │  mechanical move + re-exports; no behaviour change
                 │  tables.snap byte-identical; unblocks DRS-E3 S-CURVE too
                 │  move list RE-DERIVED at branch time (S-OUT-KI churned codec/)
                 ▼
         ┌───────┴────────────────────────────────┐
         ▼                                        ▼
  the proving state                         P's serving store
  (NOT a store — WSS-Q1(b))                 (WSS-Q1(a))
  frontier at F + recent-block buffer       own file, StakeEngine-owned,
  per-output paths in each identity's       encrypted, chunk-sealed
  sealed file                               fill · verify · serve · erase
  §6.3; bench measurements §6.3.4           §6.2, §6.4–6.6
  NO daemon input beyond the codec          GATED on daemon elements:
  contract — buildable independently          · A4 length rows (S-CHAIN-W)
                                               · b_* (S-PRUNE forward pass)
                                             and on WSS-22's bond-add answer
         └───────┬────────────────────────────────┘
                 ▼
  the WSS-13 unwind  (§6.7.4 PRs 1–5)
    PR 1  own_height re-source          [AUTHORIZED 2026-09-19]
    PR 2  SyncedChainFacts + sweep      [AUTHORIZED 2026-09-19]
    PR 3  P's store, fill driver, reconcile — release gate takes the type
    PR 4  switch the provider to P's store
    PR 5  delete the pin messages, ServingReader, posture tables
                 ▼
  the leaf-cluster deletion   [E4 / S-ARCH — NOT this lane's:
    freeze pipeline, challenge_leaf_index, the verifier re-key.
    Coordinated, not owned; this lane owns only the store half]
```

*Superseded by `WSS-Q1`: the "one file or two" branch point and an
"increment 2 proving store" built from `CTS-2/3/5/6`'s typed records. Those
records are `CTS-`'s leaf-unit design, and under the ruling the proving state
is not a store, so there is nothing for them to type. §8 bucket (iii) is
closed by the ruling rather than waiting on it.*

**Sequencing constraints, stated as constraints rather than dates.**

- **PR A lands first and alone.** A move mixed with a rewrite is unreviewable,
  and it is the only piece that survived every answer to `WSS-Q1` — which is
  why it was cleared ahead of the ruling.
- **The proving state does not wait on the daemon.** It reads no daemon-owned
  input from §5 except the codec contract (row 6) and the format policy
  (row 8), both this lane's own.
- **`P`'s store is gated on §5 rows 1–5**, per row so a partial gate is
  visible: the hash rows landed (#772), the A4 length rows are owed by
  S-CHAIN-W, `b_*` by S-PRUNE's forward pass — plus `WSS-22`'s bond-add
  question, which the daemon lane owes before `WSS-Q6` / `WSS-Q10`'s read path
  exists.
- **`WSS-13`'s unwind PRs 3–5 follow `P`'s store**, and **PR 2 must precede
  PR 3** — the release gate must never delete on an unsynced view (`WSS-25`).
- **The leaf-cluster deletion is not this lane's to land.** The verifier re-key
  is consensus and lands at E4 / S-ARCH; this lane owns the store-side half and
  coordinates.
- **The `WSS-Q11` interim tie** is one line in `shekyl-archival-retention`,
  landing with the CT-1 dedup assert as its own small PR — not folded into any
  increment above ("fit the existing mechanism now; design the proper one as
  its own round").

---

## 10. Open residue — inherited or disposed, none left unowned

| Row | Disposition |
| --- | --- |
| [`FOLLOWUPS.md`](../FOLLOWUPS.md) — **the archiver's retention horizon** (the serving purpose's lapse tail; owner `ARCHIVAL_SERVING_ROUTE.md`, enforcing site this store; *"no builder today"*) | **Inherited** as `WSS-Q8`. The rule stays the serving route's; **this round takes the enforcement and the test**. The row is updated to name this document as the enforcing site's owner |
| [`FOLLOWUPS.md`](../FOLLOWUPS.md) — **DRS-D3c, the cross-store leaf/position KAT** (daemon vs wallet `LeafStore`) | **Inherited, and re-scoped by `WSS-Q1`(b) as ruled.** The proving state is **not a leaf store**, so this is **no longer a cross-store leaf/position KAT**: its subject is **root-and-frontier parity** between the wallet's frontier at `F` and DRS-E3's `curve_tree_*`. It lands with the proving-state increment. Its leaf/position shape is recorded as superseded so the queue cannot direct a future increment to build a KAT for a store the ruling removes |
| [`FOLLOWUPS.md`](../FOLLOWUPS.md) — **the archiver serving-store rebuild row** (`PDM-Q12`, owner "the wallet lane") | **Discharged as to ownership by this document**, which is the round it asks for. The row is updated: the successor round exists, the family is registered, and the row's remaining content is the *increment 3 gate*, not the absence of a round |
| `PDM-Q-F33` (ii) — the interim partition tie | **Inherited** as `WSS-Q11`, with `WSS-9`'s correction: it dies with the freeze and is **not** re-pointed at `SHARD_BYTES` |
| [`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md) — archive-or-contract under rule 95, now that the freeze is retired by `PDM-Q12` | **Owned by this round.** Its status banner is updated by this PR to record *retired by ruling, live in code until E4 / S-ARCH*; the **archive move lands with increment 4**, when the code goes, not before — archiving a document whose subject is still live would lower the citation ratchet on a live surface |

---

## 11. Genesis-gate checklist

What must be true before genesis for this lane, in mission order.

1. **Security.** No secret reaches this store: `Leaf` / `LeafMeta` are public
   tree state and `owned_identities` marks ownership *positions*, not keys —
   so the security property here is **integrity**, and the §11.1(f) adoption
   is what buys it (a file the engine accepts is one whose every row decodes
   under exactly one codec). Verify-on-fill (`WSS-Q5`) against the daemon's
   hash rows is the second leg, and it is the one that must not be skipped
   for a shard received from another archiver.
2. **Privacy.** The two-store line holds: nothing this lane builds puts
   persistent, posture-correlated state on the daemon. **Under `WSS-Q1` as ruled,
   a non-archiver's disk carries no serving artifact at all**, which
   is strictly stronger than tables it never writes — that is a privacy
   argument for the ruling, not merely an engineering one.
3. **Longevity.** `SCHEMA_VERSION` refuse-not-migrate; the layout carries its
   own version cell from creation; no `IMPLICIT_SCHEMA_VERSION` fallback
   (`CTS-9`). A growth bound for obligation A stated at the Pi-4 floor
   (`WSS-Q2`, `WSS-12`) — an unbounded RAM-resident leaf set is a longevity
   defect whether or not it is a correctness one.
4. **Consensus.** This store **mints no partition and no boundary** (§5 rows
   1–2). A divergent partition forks at admission, so this is a consensus
   property enforced by not computing.

---

## 12. Test strategy

- **The denominator.** `cargo test -p shekyl-curve-tree` including
  `tests/{store_kat,recon_kat,recon_tier_b,assemble_kat}.rs` — these pin
  **roots and reconstructions**, not on-disk bytes, so they survive a layout
  change unchanged and are the oracle that says a rewrite did not move the
  math. Plus the dependents of §4.1 that hold a store handle.
- **One layout test per record**, pinning width, field offsets, and one
  strict-refusal per field that has one.
- **The pre-version refusal at open**, with the file unmodified.
- **Verify-on-fill negative**: a body whose **recomputed txid** disagrees with
  the txid committed in the block is refused (`WSS-Q5` — *not* a supplied
  `txs_prunable_hash`, which is the superseded path), and the refusal names
  **which transaction** failed
  ([`82-failure-mode-ux`](../../.cursor/rules/82-failure-mode-ux.mdc)).
- **The lapse-tail test** (`WSS-Q8`): the serving reader's answer past the
  horizon, which the FOLLOWUPS row names as the discharge condition.
- **DRS-D3c**, now **root-and-frontier parity** with the daemon rather than a
  leaf/position KAT (§10), with the proving-state increment.
- **A module-size ratchet** for the crate (`CTS-Q4`) — a decomposition that is
  not held decomposes again.
- **Every gate asserts its own subject exists**
  ([`47-gate-subject-assertion`](../../.cursor/rules/47-gate-subject-assertion.mdc)):
  a store test that passes against a store with no rows is not a test.

---

## 13. Documentation owed (rule 91)

- [`CURVE_TREE_STORE_SHAPES.md`](CURVE_TREE_STORE_SHAPES.md) — status banner:
  closed as record, superseded by unit, successor named (this PR).
- [`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md)
  — retirement banner (this PR); archive move at increment 4 (§10).
- [`ARCHIVAL_PRUNED_DAEMON_MODE.md`](ARCHIVAL_PRUNED_DAEMON_MODE.md) — `Q12`'s
  collision paragraph and §8's "the lane's active `CTS-` round … does not yet
  scope it" gain the successor pointer (this PR).
- [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) — `WSS-` family row and
  §7 document row (this PR); `CTS-` row gains its successor pointer.
- [`FOLLOWUPS.md`](../FOLLOWUPS.md) — the three rows of §10 (this PR).
- [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) §3.6 and
  [`CT5_ENGINE_WIRING.md`](../completed/CT5_ENGINE_WIRING.md) §3.1 —
  **reopened by `WSS-Q1` as ruled**, and the edits are owed: CT-1's *engine*
  choice (redb) and its validity definition are **not** reopened; what the
  ruling touches is CT-1 §3.6's implicit "the store" (singular) and CT-5
  §3.1's "one writer" — under the ruling `P`'s serving store is the wallet's
  only redb and the principal's proving state is not a store at all, so both
  phrases need restating. Line-local edits, owed by the increment that builds
  each side, **not by this document**.
- `docs/CHANGELOG.md` — **no line at this PR** (design-round opener, no
  user-visible change); one line per implementation increment.

---

## 14. Decision log

| Date | Decision |
| --- | --- |
| 2026-09-20 | **`WSS-Q1`(b)'s first real measurements, and one more ruled row moved.** *Spend edge, x86 dev box:* the worst-case window (765 600 leaves over 725 blocks) replays in **73.9 s** on a quiet box (**96.8 s** on a contended one — both reported, §7.1) against a **1.113 s** denominator, so the **2 s absolute floor** binds (the 15 % arm is 0.17 s) and the delta misses by **~48×** on hardware far faster than the rig — the direction is settled even though the Cortex-A72 magnitude is not, so row 2's pre-registered *amortized replay first* is the landing, and (b) reopens only if the amortized form also fails. **The number that decides what that miss means:** the same replay amortized is **102 ms per block** against a 120 s cadence — under 0.1 %, ~1 % at a 10× A72 multiplier — so the refresh side is affordable and the amortized form's real costs are the deep-reorg recompute (rare, rule-82) and the state discipline. Now emitted as `per_block_advance_worst_case_s` rather than left to a reader's calculator. *First proving denominator for the project:* **1.113 s**, 2-in canonical, depth 6, x86; the rig run yields the A72 figure free. *Open edge, live against `shekyld --regtest`:* 224 µs round-trip floor, **0.19 s** projected over the 790-block buffer, **round-trip bound** — the model correction is now empirical, with `2.0` round trips per block **measured** (`get_transactions` never fires on coinbase-only blocks). **Row 3's corpus density is amended above** as a consequence: grading at row 2's adversarial density would have pre-written the companion file, so this row grades at the full-reward zone and the adversarial window is an accepted rule-80 long-tail. The thin-corpus problem is **enforced away**, not noted: `open_edge` withholds its verdict below half the graded density, and the live run reads *"0.5 % — TOO THIN TO GRADE"*. |
| 2026-09-20 | **The `WSS-Q1`(b) bench is built, and building it moved one ruled row.** [`WSS_Q1B_BENCH_SPEC.md`](WSS_Q1B_BENCH_SPEC.md) + `rust/shekyl-wss-q1b-bench` (bins `spend_edge`, `open_edge`). **Row 3's miss response is amended above**: the original *companion file* remedy was pre-registered on a volume theory of the open-edge cost, and the landed fetch path is **per-block with 2–3 sequential round trips** (`block_fetch.rs:132`, `:491`) — so the cost is attributed to a term before a remedy fires. **Four things the build pinned that this section had left to the bench, each read from a landed owner rather than restated:** (i) the **three block counts are three numbers** — replay window **725**, held buffer **790** (`W + 60`, §6.3.2 row 2), `W` **730** — const-asserted, after a draft used them interchangeably; (ii) the **worst-case leaf rate is 1 056 leaves/block at depth 6** (hence a 765 600-leaf window), derived by *calling* `block_weight_limit` + the `S = 4` surge clamp + `predict_weight`, because `config/consensus_constants.json` **carries no block-weight ceiling** — a draft that derived one from it repeated `WSS-Q8`'s operand-with-no-value error; (iii) **depth and window are independent axes** — a dense depth-6 corpus is **17 778 529 leaves / 2.28 GB**, out of reach on the 8 GB rig, so the denominator is proved on a **synthesized sparse path licensed by a same-depth control** (dense-vs-sparse at one depth), not by citing the prover's padding comment; (iv) the **rig gate splits into enforced and attested** — arch, userland and RAM are checked, storage and thermals are operator attestations recorded verbatim, because a gate advertising five checks while enforcing three passes for the wrong reason (rule 47). **The denominator is `proof::prove` directly** — the function `sign.rs:171` calls — since driving `sign_transaction` would fold BP+ and PQC signing into it and silently loosen the 15 % arm. |
| 2026-09-19 | **The bench rig is pinned in §6.3.4 — it was not pinned anywhere, and this document had said it was.** A self-check found `§6.3.4`'s phrase *"beyond the rig / storage / thermals / leaf rate already pinned"* to be an **inherited claim recorded as a property**: only the leaf rate was actually pinned, and [`76-device-provisioning-floor`](../../.cursor/rules/76-device-provisioning-floor.mdc) fixes the **device class** (*"Pi 4 Model B, Cortex-A72, aarch64"*) and nothing else — which is the floor's purpose, not a bench spec. Now stated as a table: device **with 64-bit userland** (a 32-bit userland on the same board is a different machine for this work), **8 GB** RAM (the Pi 4 ships 1–8 GB, and a measurement taken at 8 GB but graded as *the floor* understates every smaller board), **USB-SSD not microSD** (both measurements are I/O-bound, and the media differ by more than the thresholds do), **sustained not burst** thermals (the A72 throttles, so a burst run grades a machine that does not exist after a minute), and worst-case leaf rate. Without these the two thresholds are not reproducible, and an unreproducible threshold cannot fail. |
| 2026-09-19 | **`WSS-20` FIXED and guarded (PR #793); `WSS-19`'s remaining work is discharged.** The two call sites now log **counts, never ids** — `serve_set_source.rs`'s pin release (`released` plus the epoch gate's `releasable` count, where it had emitted `shard_ids = ?releasable` at **`info`**) and `actor.rs`'s spent-watch quarantine (the held-set size, where it had emitted a `GlobalOutputIndex` at **`error`**). The standing half is `rust/shekyl-logging/tests/p_correlated_ids_absent_from_logs.rs`: a source scan, chosen over a `tracing` capture layer because **four of the five audited paths have no `tracing` dependency at all** — there is nothing for a layer to attach to, and no way to assert "and it stays zero". It refuses a `P`-correlated or wallet-correlating identifier as a field name, a field value or an inline format capture under `stake_engine/`, and refuses `shekyl-p-host` / `shekyl-p-serve` / `shekyl-tor-control-client` / `shekyl-tor-control-wallet` growing **any** logging surface, since a denylist over their zero log sites would be vacuously green (`47-gate-subject-assertion`). Site detection reads a token stream, so no spelling of a macro call evades it, and the three ways to rename what the gate matches on — a `use` alias, a forwarding `macro_rules!`, and Cargo's own `package = "tracing"` — are each refused. **Residue named rather than implied** (module doc): an innocuous binding name, a `Display` that embeds an id (`EmissionVerifyError` admits `shard_id` in three variants, unreachable from the two logged legs today), a wrapper macro defined out of path, `Span::record`, and the framework API. **Still owed:** the store's own seal — `WSS-18` is untouched by this. **Open for a ruling:** `claim.rs:152-157` logs `skipped = ?derived.skipped` at `debug` (the epochs a persona did not claim in, with a verdict each); `AlreadyClaimed` against the public bond record narrows which persona this is — the same channel in kind, weaker in degree — and it is **not** in `WSS-20`'s enumeration. |
| 2026-09-19 | **`WSS-Q1`(b) RULED — adopted subject to §6.3.4's four measurements, and both budgets set, so all four are now gradable.** **Spend edge: `delta ≤ max(2 s, 15 % of proving time)`**, same rig, same run, same canonical shape — the relative arm grades at realistic proving times, the 2 s floor stops a small denominator failing prep nobody could perceive, and slow-prover laundering is capped because 15 % of a long prove stays a tolerable fraction of a wait already committed to; re-graded on a material prover-pin change. **Open edge: `≤ 5 s` absolute, local-daemon posture** — absolute because there is nothing to be relative to, and the **local scope is part of the ruling**: a remote daemon over Tor is *not* graded by it. Miss responses **as stated on that date**: amortized replay first, then reopen; companion file. *The open-edge half of that sentence no longer holds — §6.3.4 row 3's miss response was amended 2026-09-20 to attribute the cost to a term before firing a remedy, and the companion file is now the **volume-bound** branch of it. Recorded here rather than rewritten, because this row is dated: it says what was ruled that day, and the row above says what is true now.* **Three pins the bench owes were added rather than left implicit:** the canonical tx shape is **2-in/2-out, reused from [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §13 rather than minted** — `PDM` §9 and the firewall round already cite it, so a second canonical shape would be a duplicate source; the **delta/proving boundary must be stated once in the corpus spec**, because the relative arm is undefined until it is and work moving across that line changes the verdict with nothing else changing; and the **absolute delta is reported beside the ratio**, since 15 % of a denominator that does not exist yet is an unknown number of seconds. **One byproduct worth keeping:** the bench must run proving to get its denominator, so it also yields **FCMP++ proving time on a Cortex-A72** — a figure this project lacks and will want for rule-80 progress indication regardless. The FOLLOWUPS row that tracked the missing budgets is **removed** with this ruling (rule 95: resolved items are removed; git history is the archive). |
| 2026-09-19 | **Round 1 RULED (maintainer), on a clean substrate re-sweep at `dev@306af9bae`.** **Ruled as proposed:** `WSS-Q1`(a), `Q2`–`Q5`, `Q7`, `Q9`, `Q11`–`Q13`, `Q14`, and the **wallet halves** of `Q6` / `Q10`. **`Q8` ruled conditional on `Q14` landing first** — the release gate is the one piece of this design that deletes data, and `WSS-25` shows it is unsafe until "synced" is a type. **`Q5`'s ruling discharged its amendment in this PR:** `PDM-Q6`'s *"verify on fill against the hash rows"* sentences (`ARCHIVAL_PRUNED_DAEMON_MODE.md:1014`, `:1360`) now name the txid, so the two contracts do not disagree. **Still open:** `Q1`(b), pending the two latency budgets (§6.3.4), and the daemon-lane halves of `Q6` / `Q10`, which ride `WSS-22`'s question. **Re-sweep result:** every file this document cites is unchanged or cosmetic since `8494f2a27`; `client.rs` / `engine/signer.rs` are `BlockHash::NULL` only, `fcmp/tree.rs` doc comments only with `SEGMENT_LAYER_J` untouched, `daemon-rpc/methods.rs` a version-vector bump with `chain_facts` (`Q14`'s substrate) untouched. **The one substantive change strengthens `Q1`(b):** `SOK-10` Q7 → A deleted the daemon's per-output path assembler — `get_curve_tree_path` removed as spend-revealing at `CORE_RPC_VERSION` 3.34, `rpc_path` gone from `rust/` — so **the wallet is the only path assembler in the system, with no daemon fallback**, and §6.3's design is load-bearing by construction. The PDM-sweep row's evidence re-checked: `grep -c PDM` still 0 across all four documents. |
| 2026-09-19 | **Question rows staged for Round 1; `WSS-Q3`'s correction restated in the present tense.** `WSS-Q3` drops the historical "an earlier form said" phrasing for a present-tense rejected alternative — *"Not 'shards at least `W` old': the daemon discards at `W`, so that would make every fill a recovery fetch"* — which keeps the contradiction with `WSS-Q4` named without narrating the edit. **`WSS-Q1` splits into two parts of unequal weight:** (a) `P`'s store as the wallet's only redb rests on verified code and the firewall and is rulable outright; (b) the proving side not being a store rests on code reading **plus four unmeasured things**, so it wants ruling **as adopted subject to** them. **§6.3.4 rewritten to carry a reopening threshold per measurement — and only two of four can be stated.** Rows 1 and 4 are statable now (`rollback_to_fork` must **refuse** rather than silently produce a wrong tree, with a rule-82 remedy; any `build_layers` property-test mismatch reopens outright). **Rows 2 and 3 owe a value:** there is **no landed spend-latency or open-latency budget anywhere in the tree** to grade a Pi-4 replay or a buffer refetch against, so they can be *taken* but not *graded*, and naming a number would repeat the operand-with-no-value error `WSS-Q8` was corrected for. That asymmetry is recorded as the finding rather than smoothed over. **`WSS-Q5` gains the amendment it owes:** ruling it requires amending `PDM-Q6`'s *"against the hash rows"* sentence **in the same PR**, the rule-16 pattern of a contract left asserting a superseded decision. **`WSS-Q8` is made conditional on `WSS-Q14`** — the release gate is the one piece of this design that deletes, and `WSS-25` shows it is unsafe until "synced" is a type, matching §6.7.4's PR order. **`WSS-Q6` and `WSS-Q10` now say which half waits on the daemon lane:** the wallet side is rulable now, while the read path and `CompleteTree` admission semantics need `b_*` and `close_height(k)` as readable daemon facts and ride `WSS-22`'s question. |
| 2026-09-19 | **§1.2 records steering's rulings `R-A` / `R-B`; §6.7 opens the `WSS-13` unwind as design review; two live findings.** **`R-A` (RULED):** `P`'s height comes from the **configured daemon** — `P`'s store holds only closed, final shards and cannot know the tip, and `P`'s transport resolves to that same daemon (loopback by default, `PRpc` to its configured remote), never a random peer; the "tip follower" phrasing is **withdrawn** and not recorded as a mechanism. **`R-B` (RULED):** every consensus-derived decision reads the configured daemon, and while it reports syncing the answer is **unknown**, failing safe — do not erase, post or sign. **`WSS-24`:** `HostSigner::own_height` reads the curve-tree store's `sync_tip_height` — the **principal's ingest**, not the daemon's tip — while the pre-sign gate admits only `±L = 4` around `own_height − 720`, and nothing bounds the ingest lag below `L`; `caught_up` feeds health reporting only. So more than 4 blocks of scan lag makes an honest `P` refuse valid challenges and be slashed, **live in today's code**. **`WSS-25`:** the release gate derives its epoch from the height the bond record answered at and **never checks synchronization**, so a resync — which the C++→Rust cutover forces on every daemon — notes every held shard absent at an early height, crosses two epoch boundaries as it advances, and fires for all of them; harmless today because release only unpins, **catastrophic after the unwind, when release deletes**. `caught_up` cannot help: it measures **wallet-vs-daemon** lag, and during a resync both are low and in step, so it reports caught up while **daemon-vs-network** lag is the axis that matters. **`WSS-Q14` proposed (not ruled):** make "synced" a type whose constructor refuses an unsynced view, with the submit watchdog's predicate as that constructor and a sweep of every daemon-height / bond-record / chain-facts read, an unclassifiable site being a finding. §6.7's table, the gate constraint and its resync property test, and a five-PR order follow, with PRs 1–2 **scoped separately under rule 22 with a named reason** — they fix live exposure and an engine-wide type, and do not depend on this round. |
| 2026-09-19 | **§6.6 — `WSS-Q7` restated as the store's *whole-shard* read; the per-tx framing was a conflation this round inherited (`WSS-23`).** `PDM-Q6` item 4 re-keyed `SF-D1` to *"No per-tx addressing on the route either; the read is still whole-shard"*; what became per-transaction is `SF-D8`'s **verification**. The conflation entered through the opening brief's §8 row, which cited the verification ruling as authority for a serving granularity — and had it survived, the store would have carried a per-transaction index it does not need and the route would have grown addressing `SF-D1` forbids. **What `P` serves:** the canonical `tx_id`-ordered concatenation of `prunable ‖ pqc_auths`, **with no framing of its own** — the requester is always a daemon, every daemon keeps the A4 length rows permanently, so it splits the stream from its own trusted rows and knows the total length before the first byte; framing from `P` would be redundant and untrusted. **Frame re-key owed to the RF/SF lane, not here:** `RF-D4`'s `leaf_count` becomes a byte length bounded by `SHARD_BYTES + MAX_TX_SIZE`; the write-zero padding rule **survives** because its argument names no leaf premise (`served_frame.rs:162-169`), passing `PDM` item 4's own reversion test; the countersignature half is untouched. **The landed `ShardProvider` contract carries over entire** — servability settled at open, exact length before the store is touched, bounded chunks (the comment names `MAX_INFLIGHT × 3.33 MB` as the rule-76 bill chunking avoids), and serve-set blindness. **Simplification:** no per-transaction index at all; the store holds the verified concatenation and streams it. **Encryption is chunk-by-chunk** with slot and chunk index as associated data — the only granularity at which the at-rest decision and the one-chunk memory bound are compatible. **Deleted:** `ProviderError::FrozenSegmentPruned`, `ServedFrameHeader::for_segment`, and `flat_header`'s whole-leaves rule, whose validity check becomes the closed-shard byte range. No leak: the requester already knows which shard it asked for. |
| 2026-09-19 | **§6.5 — `WSS-Q4` proposed: fill first, then post the bond.** The deadline is the **next epoch's open** (Pin 5, `ARCHIVAL_CHALLENGE_MECHANISM.md:274-279`), which can be one block or 10 000 away, so filling before the post removes the race and makes "bonded but not held" unreachable from the normal path. It also makes §6.4.3's boundary refusal free — it fires before anything is bonded — and rule 82 makes it a **loud operator-facing error, never a silent retry**. Source is the local daemon over the operator leg until `PDM-Q2`'s predicate discards the shard, a recovery fetch after; both verify by txid, so the source is not a correctness variable, and at genesis every early archiver fills locally. Only shards with `close_height(k) + D_max ≤ tip` are filled. Ordering fits both entry points, and since a `HoldingsUpdate` add has **no builder** (only `build_join_market_vin` / `build_release_vin` exist, `lib.rs:158`, `:310`) it can be designed in rather than retrofitted. **`WSS-22` raised and sharpened:** nothing checks that a bonded `shard_id` exists or is closed — `ShardSet::new` enforces only cardinality and duplicate-freeness — **and the inherited claim that `frozen_segment_count` bounds admission is unsupported at the call sites** (its three consumers are the D2 escalation operand, the coverage RPC, and freeze / pop-revert). So the byte-range successor has no predecessor to re-key; it is unbuilt, and a reader trusting the inherited claim would not build it. Owed to **S-ARCH / E4** as a question, not assumed here, because the settlement verifier must behave sanely when challenged on a shard that does not exist. Two residuals answered: filling before posting leaks nothing worth mitigating, and losing a bonded shard refills on the same path as the operator's own trade. |
| 2026-09-19 | **`WSS-19`'s Tor check RUN — negative; the pinned Tor persists nothing per hosted service (§6.2.7).** Measured rather than reasoned, on the **pinned binary itself**: the bundled `tor` at `tor-expert-bundle-15.0.17` hashes to `CURRENT_PIN.sha256` exactly (`binary.rs:113`), which is what makes this the right instrument rather than a system Tor. Launched with the wallet's own spawn arguments (`control/actor.rs:891-900`), bootstrapped on the live network, `ADD_ONION NEW:ED25519-V3` with **no `Detach`**, publication **confirmed** via `HS_DESC UPLOADED` (a service that never published would make the result vacuous), then `SIGNAL HALT` **with the service still live** — the strongest case for persistence, since Tor rewrites `state` on clean shutdown. **Result: the service id appears nowhere under the data directory, before or after shutdown; `state` carries only `Guard` / `CircuitBuildTimeBin` / `TotalBuildTimes` / `Dormant` / `LastWritten` / `TorVersion`; `keys/` is empty; and the onion address is absent from Tor's own log at `notice` and `info`.** What is persisted — entry guards and circuit timings — is required by DQ-T0.7, identical for any Tor client, and does not distinguish a serving wallet from a fetching one. The directory's **existence** stays an accepted residual of `WSS-15`'s class. **Re-run trigger: moving `CURRENT_PIN`.** `WSS-19`'s remaining work is now exactly `WSS-20` — strip the shard ids from the log line. |
| 2026-09-19 | **§6.4 — `WSS-Q5` proposed against the txid rather than the daemon's hash rows; a recorded difference from `PDM-Q6`'s wording, with its argument.** Verified at source (`WSS-21`): a spend's txid is `H(prefix) · H(base) · H(pqc_auths) · H(prunable)` (`txid.rs:52-58`), `TxidParts` is that txid plus the two rows in one pass (`:43-50`), and the block commits every txid through `merkle(miner_tx_hash ‖ tx_hashes)` in the PoW blob (`header.rs:173`). So a holder of the bytes recomputes the commitment instead of being handed a cache of two of its components. **Three reasons, in order:** it removes the dependency on unlanded DRS work (A4 is still owed) so the fill path is buildable now and survives row-format churn — steering's "decouple what is in flux", applied; it checks the **root of trust** rather than a cache of it, which under `R3` narrows the trusted surface rather than widening it; and recovery shards verify identically, so `WSS-Q9` needs no separate design and no trust in the sender. **The rows are not retired** — they remain the discarding daemon's own need for `DRS-D10` skeleton replay, and `hash_with_supplied_components` (`txid.rs:194-201`) exists for exactly that party. **§6.4.3 states the one unverifiable input:** `b_k`. The wallet can confirm the **end** boundary (the running total must cross `SHARD_BYTES` at the last transaction and not before) but not the **start**, which rests on the local daemon over the operator leg — the existing trust model. **Failure mode recorded:** a wrong `b_k` means the wrong transaction set, nothing detects it at fill, the first challenge misses and the operator is slashed — loud, attributable, operator-local, with no consensus or privacy effect. |
| 2026-09-19 | **`WSS-Q8` is answered by landed code, and the answer this round proposed was weaker.** `EPOCHS_BEFORE_PIN_RELEASE = 2` (`serve_set_source.rs:284`) already releases a pin only after two consecutive epoch opens with the shard absent from the bond record, and `releasable`'s doc comment carries the argument — drawability is evaluated at epoch open, one epoch is too tight because a challenge from the last drawable block must still **resolve**, and **`W₂` is deliberately not an operand** because it is UNDERIVED (§9.7 item 6), with a rule-21 reopening criterion if it ever reaches one epoch. **This round's "epoch-close + `D_max`" is rejected as its own proposal:** it looks equivalent and silently assumes `W₂ < D_max`, smuggling in an operand with no value — exactly what the landed gate was written to avoid. The recovery-fetch consumer found the previous day is covered, because the pair stops being drawable before release. **The FOLLOWUPS row's "no builder today" was false.** **`WSS-19` audit executed** over the per-wallet siblings (§6.2.5): **`WSS-20` found** — `serve_set_source.rs:261-263` logs released `shard_ids` at `info` into a plaintext file (`--log-file`, mode `0600`), and those ids against the public bond history **identify `P`**, so sealing the store does **not** close the at-rest route alone; fix is count-not-ids plus a lint. The *existence* of `.pscan` / `.pending` is an **accepted residual** (says the wallet staked, not which persona — `WSS-15`'s class). One factual check still owed: whether the pinned Tor version records per-service state. **§6.2.6 added:** `StoreShardProvider` takes only a shard id and has no serve-set notion, so a dropped-but-still-pinned shard staying served is what keeps the obligation met — the `WSS-13` unwind must erase on the pin-release gate and **nothing earlier**. |
| 2026-09-18 | **`WSS-Q8`'s pending check ran and failed: the lapse tail is not zero.** Recovery fetches draw from the epoch's **drawable set**, and `SO-D8` Q3 §7.4 deliberately does **not** filter `D` at the tip — filtering would let a later drop retroactively falsify the point query and make `D` time-varying — so *"a dropped pair stays in `D` for `E`"* (`ARCHIVAL_CHALLENGE_MECHANISM.md:197-203`), while `SF-D10` makes organic selection a uniform draw over that snapshot with the scheduler doing no filtering of its own (`ARCHIVAL_SHARD_FETCH.md:184`, `:1232-1257`). At `settlement_epoch_blocks = 10000` that is ~10 000 blocks against a `D_max` of 720, so erasure at drop-connect + `D_max` would delete data that is still drawable. **Answer: erase at the close of the epoch in which the drop connected, plus `D_max`** — no new tunable (`E` and `D_max` are both ruled), never earlier than the previous answer so Pin 3's reorg protection is preserved, ≤ 4.33 MB for ≤ one epoch + 720 blocks, and it leaks nothing because the data is public and the drop is on-chain. It also makes the drawable set honest for recovery rather than only for challenges. **Rejected:** filtering `D` at tip (reopens `SF-D10` and `SO-D8` Q3, both ruled, to save ~4 MB) and accepting the misses (pushes a known avoidable cost onto the daemon that needed the data). **The record is that the check found a consumer**, not that a new policy was adopted. |
| 2026-09-18 | **§6.3 resolved: the proving side is not a store — verified at source, with three amendments.** A public frontier at `F = tip − W` plus a buffer (shared, ownership-free) and private per-output membership paths in each identity's existing sealed file; the wallet's only redb is then `P`'s serving store. **Premise verified:** ZK hides the leaf from the *verifier*, not the prover, which needs only its own path — pinned to the FCMP++ prover's `Path` at `assemble.rs:18-35`; the anonymity set is unchanged, and today's full-leaf retention is an implementation choice the module doc states itself. **All six attacks answered at source** (`recon.rs:116-126` + `shekyl-consensus:28,:31`; `consensus_constants.json:4-5,:26` + `segment.rs:69-71` giving `W = 730` exactly; `refresh/task.rs:337-358`; widths at `fcmps/src/lib.rs:61,:63`; `handle.rs:611,:641` + `payload.rs:117-126`; the actor's **exactly eight** messages). **Three amendments from verification:** the buffer is **`W + 60`** blocks, not `W`, because replaying drains over `[F, ref]` needs outputs created from `F − 60` (coinbase maturity); late discovery is free **except** for an output already scanned but not marked path-worthy, whose remedy is to define path-worthy as *"in the ledger"* rather than *"currently spendable"*; and `IngestBlock` learning ownership would relocate `WSS-13` unless the **frontier advance stays public and identity-free with path capture as a per-identity filter** (§6.3.3). **One inversion:** `verify_root` becomes an O(depth) frontier advance, so the per-block check gets **cheaper than today** and `WSS-14`'s quadratic risk, `WSS-Q2`'s A-side half and `WSS-12` all stop arising. Open on four measurements (§6.3.4), one of which — a reorg deeper than `W` — carries a rule-82 user-facing failure mode, not only a technical one. |
| 2026-09-18 | **Steering worked the at-rest threat model properly and withdrew most of the previous turn's proposal; §6.2 rewritten around what the disk actually reveals.** The only secret on disk is the **device ↔ `P` link**; the shard contents are public. An adversary table prices six positions and finds **one that matters**: forensics with an offline image but no password, where today's **plaintext `.curvetree` gives `P` despite the encrypted `.wallet`** (`WSS-18`, verified — the store is a sibling of the wallet file and the crate contains no encryption; and the onion key is *not* a second route, `Detach` being unrepresentable). **Justified:** encrypt the store under **one** key from the wallet's existing hierarchy — *for consistency, not a new threat*, since a plaintext companion undoes a decision `.wallet` already made — and delete at **drop-connect + `D_max`** with a **zero** lapse tail. **WITHDRAWN:** per-shard keys and crypto-shredding, with each of its three grounds failed on the record (remnants are covered by encryption; scoping a compromised serving task protects public data while its real assets are the countersigning capability and the `StakeEngine` route; unrepresentability is a correctness property a **type-level held-slot token** buys without key management). **WITHDRAWN:** size padding and slot preallocation — `WSS-15` becomes an **accepted residual** with reopening criteria (near-unique holdings counts measured by the sim, or forensic tooling that targets it); the underlying channel is unchanged, only its disposition. `WSS-Q12` shrinks to **where the one key lives**; `WSS-Q13` survives unchanged because rule 36 already requires it. **`WSS-19` added:** `P`'s other persisted state is unaudited, and that audit **gates** any claim that encrypting the store closes the gap. |
| 2026-09-18 | **Amendment on steering's second review — five carryover corrections, the `P`-store erasure lifecycle, and the proving-side arm. No rulings; every clause is a proposal Round 1 rules on.** *Corrections:* `WSS-9` / PDM's correction (b) called the subroot cache "dispensable" — true for correctness, **false for cost**: `verify_root` runs per ingested block (`merge.rs:651`), so dropping the cache makes sync **quadratic** (`WSS-14`). "The wallet's own tree state, not a slice" overstated it — the proving state **is** derived from canon and self-checks against the header root every block; `R3`'s property is that it therefore **never needs a migration, ever**. `R1`'s invariant recorded with its falsifier (`WSS-17`: no daemon-RPC edge from the store crate, `cargo tree`). `WSS-Q11` proposed landing a tie **#780 already landed** — corrected to what is actually open (it dies at E4, and is not re-pointed at `SHARD_BYTES`). `WSS-8` overstated: `set_prune_disabled` is reached only on the `PinCompleteTreePrefix` / Foundation-`CompleteTree` path (`curve_tree_actor.rs:391-402`), so most archivers declare nothing. *New:* §6.2 — "destroyed when the bond ends" was wrong on granularity (**per shard**) and timing (**drop-connect + `D_max`**, per `PHASE_2B_FSM_RETOOL.md` Pin 3, because a connected drop can be reorged out); erasure means **crypto-shred** with **random** per-shard keys wrapped under a `P`-derived key, with the four reasons to destroy public data, the redb-CoW / wear-levelling / snapshot reasons delete does not work, and what it does not buy. §6.3 — steering's **"A is not a store"** argument recorded as the proving-side arm with its six attacks. `WSS-15` (variable shard sizes make file sizes a fingerprint; encryption hides neither sizes nor when they change), `WSS-16` (the lapse tail may have **no consumer**, so `WSS-Q8`'s answer may be zero), `WSS-Q12` (at-rest shape), `WSS-Q13` (rule-36 decrypting read capability). §5.1 puts three properties of the new shard unit on the record: bonds no longer buy uniform work, boundaries are fee-influenceable, and `SHARD_BYTES` is inherited rather than derived. |
| 2026-09-18 | **`WSS-Q1` re-grounded on the firewall (steering review).** The question was posed on the wrong axis: "one file or two", argued from the shared file lock (`WSS-6`) and the prune/resume collision (`WSS-5`). It is an **ownership** question — the serving store is `P`'s (own file, `P`-derived keys, bond-lifetime scope, owned by the `StakeEngine`), the proving state is the principal's. **`WSS-13` added**, and it is the ground: `P`'s serve-set pins are written through the *principal's* curve-tree actor into the principal's file (`serve_set_source.rs:254-257` on the handle from `serving/start.rs:158`), routing around `PRINCIPAL_STAKE_LIFECYCLE.md` §0's load-bearing containment of `P`'s material — a firewall-layering defect visible only on this axis. `WSS-5` corrected twice over: its conflict is **latent** (nothing prunes in production, `WSS-8`) and its axis was mis-stated — it is one identity's storage policy destroying another's state, not two obligations colliding. `WSS-6` demoted to mechanics. §6.1 rewritten; the "Arm A / Arm B" pair is superseded. The proving side's "is it a store at all" arm is **owed to Round 1 from steering** — this round does not hold that argument's text and does not reconstruct it. **`PDM` propagation is not this round's** (§2.2, FOLLOWUPS): four documents never received `PDM-Q6`/`Q12` and are the next agent's trap. |
| 2026-09-18 | **Round opened** at `dev@8494f2a27`, Round 0 executed. `WSS-` family registered at birth. Twelve findings; `WSS-4` (`root_at_count` reads `frozen_segments` — the freeze is also the proving path's root cache), `WSS-5` (a pruned store cannot be reopened as a proving client — the two obligations already conflict, observably) and `WSS-6` (`ServingReader` and `same_store` exist because redb takes an exclusive file lock) are the three that reframe `WSS-Q1` from an architectural preference into a question about a conflict the tree already has. `WSS-9` is split into its verified half (the composition boundary cannot be tied to `b_*`, so the `F33` (ii) assert dies with the freeze) and its open half (whether any subroot cache survives — `WSS-Q2`'s). `WSS-3` resolves `PDM-Q12`'s "verification-side leaf store" to the **daemon's** `curve_tree_leaves` (graded CACHE by `PDM-Q1` over §9), so the wallet-side proving store is ungraded and is this round's. **`CTS-` closes as record with this document as its successor** (disposed on steering's answer 3, confirmed by Rick on review); its work is partitioned by unit in §8, and no `CTS-` implementation PR lands beyond PR A. **PR A is cleared ahead of the round** (steering, answer 2), with the §11.1(f) sequencing departure disclosed. `WSS-Q1…Q11` posed; **none ruled**. |
