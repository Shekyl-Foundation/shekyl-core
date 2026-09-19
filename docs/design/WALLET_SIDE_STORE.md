# The wallet-side store — one contract over two obligations: umbrella and Round-0 pre-flight

**Status:** OPEN — **round opened 2026-09-18**, **Round 0 (pre-flight)
executed** at `dev` = `8494f2a27` (the #779 merge). This document is the
umbrella contract for the wallet-side store lane, opened as the deliberate
parallel of the daemon's DRS lane ([`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md)).
**Nothing is built by this document.** Its product is a contract, a work
breakdown, and a question list; every implementation PR under it is
separately authorized ([`06-branching`](../../.cursor/rules/06-branching.mdc)).
**`WSS-Q1` is posed here and ruled in Round 1 — not in this commit.**
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
lives on the daemon. What it did not decide, and what nothing since has
decided, is whether they live in **one file or two**. That is `WSS-Q1`, and
every other question in §6 inherits its answer.

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

**What each rules, and what it does not.**

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
  A by construction, and §3 is the evidence that it cannot be deleted.
  **Corrected 2026-09-18 (steering review): "not a slice" overstated it.** The
  proving state **is** derived from canon — it is built by replaying the
  daemon's blocks, and the code checks it against the **header root on every
  ingested block** (`verify_root`, `engine/merge.rs:651`). What distinguishes
  it from obligation B is not independence from canon but **`R3`: it is
  derived, self-checking against canon, and therefore never needs a migration,
  ever** — a divergence is caught at the next block and repaired by replay, not
  by a schema version. That is a stronger property than "the wallet's own", and
  it is the one to state.

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
files.** The ruling is Round 1's; the evidence is here.

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
| **WSS-5** | **A pruned store cannot be reopened as a proving client.** `CurveTreeClient::rebuild_from_store` (`client.rs:628`) refuses with `ClientError::ResumeFromPrunedStore` (`client.rs:200`) when readable drained rows are fewer than `leaf_count` — *"Pruning dropped frozen leaf bytes: the in-memory vec would undercount and every root would be silently wrong"* (`:631-639`). So obligation B's size discipline and obligation A's resume **cannot both be satisfied by one file**. **Corrected 2026-09-18 (steering review): the conflict is *latent*, not realized** — `WSS-8` says nothing prunes in production, so no store is in this state today, and the refusal is a guard that has never fired. And its axis was mis-stated: this is not two *obligations* colliding over storage, it is **one identity's storage policy destroying another identity's state** (`WSS-13`). It is evidence for `WSS-Q1`'s firewall framing (§6.1), not the ground of it. | `WSS-Q1` (supporting, not decisive) |
| **WSS-6** | **`ServingReader` and `same_store` exist because redb takes an exclusive file lock.** `client.rs:283-290` — the `Arc<LeafStore>` is shared *"because redb takes an exclusive file lock, so a second open would simply be refused"*; `redb_backend.rs:160-177` — the serving side gets a narrowed handle because *"handing it the store itself would put a second writer beside the one the actor exists to be… the two would contend on the write lock"*; `same_store` is `Arc::ptr_eq` (`:325`). **One file is a consequence of the engine's file lock, not of a ruling.** Under two files each obligation has its own writer, and `same_store`'s subject ("pins applied to one are not pins in the other") cannot arise. **Weight, corrected 2026-09-18:** this is *mechanics*. It says the one-file arrangement was never chosen, which removes an argument for keeping it; it does not say what should replace it. The replacement is decided on the firewall (§6.1), not here. | `WSS-Q1` (mechanics); CT-5 §3.1's single-writer actor |
| **WSS-7** | **The reorg path touches all seven tables.** `truncate_from_tree_position` / `rollback_to_fork` (`redb_backend.rs`, the `delete_*_batched` trio at `:1950-2011` per `CTS-11`) span proving and serving tables in one write transaction. Under two files this is the one genuinely hard row: either B does not reorg (it is filled from below the horizon, `PDM-Q2`'s `W ≥ D_max`), or two rollbacks need an ordering rule. | `WSS-Q1`; `WSS-Q3` |
| **WSS-8** | **`prune_frozen` has no production caller at this sha, and the archiving wallet disables pruning outright.** Every call site is a test (`shekyl-p-host/tests/composition.rs` ×7, `shekyl-p-serve/tests/store_axis.rs:125`) or a doc comment reasoning *about* it as a hazard (`p-host/src/serve_set/{report,staleness,witness}.rs`, `shekyl-operator-alarm/src/lib.rs:341`). Production instead declares the one-way prune-disabled posture — `curve_tree_actor.rs:402` calls `set_prune_disabled` — so that wallet never prunes. **Narrowed 2026-09-18 (steering review): `set_prune_disabled` is reached only on the `PinCompleteTreePrefix` path** (`curve_tree_actor.rs:391-402`, inside `impl Message<PinCompleteTreePrefix>`) — the **Foundation `CompleteTree` posture**, not the ordinary archiver, which pins its serve set instead (`pin_serve_set`). So "the archiving wallet declares prune-disabled" was too broad: **most archivers declare nothing**, and their stores are unpruned only because nothing calls the discard. **"Unused" is a hypothesis, not a verdict:** the capability is designed-for and guarded by live detectors (`PostureDeclaration`, pins, staleness, witness), so the finding is *the discard has no caller*, not *the machinery is dead*. **Provenance, per the dead-code discipline (`git log -S'prune_frozen(' -- rust/shekyl-{p-host,p-serve,engine-core}/src` returns nothing): the discard was never wired**, not wired and later removed. So `WSS-Q2` is "design the size discipline", not "reinstate or delete a caller". What follows is a question, not a deletion: **does the rebuilt store prune at all, and what bounds obligation A's growth if it does not?** | `WSS-Q2`; §8 bucket (ii)'s scope; the size discipline nobody has ruled |
| **WSS-9** | **The composition boundary and the shard partition are different objects, and cannot be tied.** The tie today is `SEGMENT_LEAF_COUNT == leaves_per_segment()` (`PDM-Q-F33` (ii)); under `PDM-Q6`/`F32` the consensus partition becomes `b_*`, a **byte-bounded `tx_id` range**, while `root_at_count`'s composition boundary is a **leaf-count geometry** (`outputs_per_node(SEGMENT_LAYER_J)`, `segment.rs`). **Verified consequence:** the `F33` (ii) interim assert must die with the freeze and must **not** be re-pointed at `SHARD_BYTES` — the two constants would be asserting a relation that does not exist. **Not verified, and therefore `WSS-Q2`'s to rule:** whether obligation A keeps *any* segment-subroot cache after the freeze retires. `WSS-4`'s `r_k` read has a recompute-from-leaves fallback (`redb_backend.rs:1241-1245`), so the cache is **dispensable for correctness**. **Corrected 2026-09-18 (steering review): it is load-bearing for *cost*.** `verify_root` runs on **every ingested block** (`engine/merge.rs:651`, inside the per-block pre-pass), so without the cache every complete segment is recomputed from its leaves once per block and **sync becomes quadratic** (`WSS-14`). Dropping it, keeping it, and replacing it with a different checkpoint scheme are all still open — but "dispensable" alone was wrong, and the option that drops it owes a cost answer. | §5 rows 1–2; §8; `WSS-Q2`; the interim-tie PR's scope |
| **WSS-10** | **`PDM-Q12`'s code cites have drifted ~6–50 lines at this pin.** `StoreError::FrozenSegmentPruned` is at `redb_backend.rs:470` (cited `:464`); `ServingReader`'s doc block spans `:160-183` and its `open_frozen_segment_body` is at `:216`, while `LeafStore::open_frozen_segment_body` is at `:1877` (cited as `:164-183` for all three). The **symbols** named are correct; the **ranges** are stale. Recorded as a re-pin, not a defect. | Every increment's Round-0 re-pins rather than inheriting |
| **WSS-11** | **`redb_backend.rs` is still 4 196 lines** — nothing of `CTS-` is built. The file holds the schema, six codecs, `StoreError` (17 variants), three handle types, every operation, and ~2 000 lines of tests. | §8; the decomposition principle survives any `WSS-Q1` answer |
| **WSS-13** | **`P`'s serving state is written through the *principal's* curve-tree actor, into the principal's file — a firewall-layering defect.** `EngineServeSetPinner` holds a `CurveTreeHandle` and a `p_id` side by side (`stake_engine/serve_set_source.rs:79`, `:101`) and calls `pin_serve_set` on that handle (`:254-257`); the handle it is given in production is the **engine's own** — `g.curve_tree.clone()` at `stake_engine/serving/start.rs:158`, passed at `:203-206`. So the serve set — which is `P`'s bonded obligation, and whose membership is `P`-correlated — is persisted by the actor that owns the principal's proving state, in the same `.curvetree` file. [`PRINCIPAL_STAKE_LIFECYCLE.md`](PRINCIPAL_STAKE_LIFECYCLE.md) §0 treats keeping `P`'s material inside the `StakeEngine` actor as load-bearing; this path routes around that. **This, not `WSS-5` or `WSS-6`, is what makes `WSS-Q1` urgent**, and it re-poses it as an *ownership* question rather than a storage one (§6.1). | `WSS-Q1` — the ground; the firewall stack |
| **WSS-18** | **The plaintext `.curvetree` file is an at-rest route to `P`, beside an encrypted `.wallet` — verified.** The store is a **sibling of the wallet file** (`shekyl-engine-file/src/paths.rs:117-121`: `primary.wallet` → `primary.wallet.curvetree`) and `shekyl-curve-tree` contains **no encryption at all** — the only `chacha` hits in the crate are a test RNG (`store/ops.rs:148-158`). The serve-set pins that `WSS-13` routes into it are therefore **`P`'s holdings in plaintext next to an encrypted wallet**, which is the gap on its own: the wallet already ruled that no-password disk access is worth defending against, and a plaintext companion undoes that ruling for exactly the adversaries it was made for. **Verified negative that bounds the problem:** the onion key is *not* a second route — `Detach` is unrepresentable, the onion dies with its control connection, and the identity holds re-mintable expanded bytes behind `Zeroizing` (`shekyl-tor-control-client/src/onion_identity.rs:74-83`, `:148-152`), so Tor never writes it to disk. | §6.2 — the whole at-rest case rests on this row |
| **WSS-19** | **`P`'s *other* persisted state is unaudited, and the audit gates the claim that encrypting the store closes the gap.** `WSS-18` establishes one plaintext route to `P`; it does not establish that it is the only one. `P`-scan records, serving counters and logs are **not audited at this pin**. **Owed as a Round-0 item before any increment claims the hole is closed** — a fix that closes one of several routes and is described as closing "the" route is worse than none, because it retires the question. | §6.2; the serving increment's Round-0 |
| **WSS-14** | **The subroot cache's role is cost, and the cost is per block.** `verify_root` is called on **every ingested block** (`engine/merge.rs:651`, in the per-block pre-pass that refuses to advance past tree state the wallet cannot reproduce). `root_at_count` under it reads `frozen_segments.r_k` per complete segment (`WSS-4`); without the cache each block recomputes every complete segment from leaves, so **sync cost becomes quadratic in chain length**. Correctness has a fallback; throughput does not. | `WSS-9`; `WSS-Q2`; the proving-side arm in §6.1 |
| **WSS-15** | **Per-shard file sizes are a fingerprint, and encryption does not hide them.** Under `PDM-Q-F32` a closed shard's size lies in **`[SHARD_BYTES, SHARD_BYTES + MAX_TX_SIZE)`** (`ARCHIVAL_PRUNED_DAEMON_MODE.md:411`) — **variable, not fixed** — and every shard's exact size is **public**, because the A4 length rows are consensus. So a per-shard file layout would map file size → `shard_id` → `P`, and a file vanishing at drop time would line up with the drop's on-chain timestamp. Encryption hides content; it hides neither sizes nor the times sizes change. **Disposition 2026-09-18 (steering): ACCEPTED RESIDUAL, not a design constraint.** Exploiting it needs a forensic adversary who cannot get the password but *will* compute every persona's holdings count from the chain and match it against disk capacity; the payoff is modest (holdings counts are probably shared by many archivers, and multiple gigabytes of archival data already says "archiver", padded or not) against 15–30 % of storage plus complexity. **Reopening criteria (rule 21):** evidence that holdings counts are near-unique across the market — the sim can measure the distribution — or forensic tooling that actually targets this. | `WSS-Q12` (residual); the #775 criterion applied to disk |
| **WSS-16** | **`WSS-Q8`'s lapse tail may have no consumer.** Serving is daemon→`P` only (`EU-D1`, [`ARCHIVAL_ENDPOINT_UPDATE.md`](ARCHIVAL_ENDPOINT_UPDATE.md) §2); the witness skips the fetch for a pair not held at fire height (the FOLLOWUPS retention row, `SO-D8` Q3 §7.4); and a dropped `P` no longer advertises the shard. The FOLLOWUPS row motivates the tail with *"the path-assembly serving purpose"* — **which is leaf-era and gone under `PDM-Q6`**. If nothing consumes it the tail is **zero**. Not verified: whether any episodic recovery fetch expects dropped holders to answer. | `WSS-Q8` — its proposed answer, and the check that answer needs |
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
| 3 | **`txs_prunable_hash` / `txs_pqc_auth_hash`** | The daemon, uniform, forever (`PDM-Q6` items 1–2; rows landed on #772) | **Verify-on-fill is against them.** Never recomputed here as an authority | A verify-on-fill that trusts anything else |
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

## 6. The question list — `PDM-Q12`'s unmade decisions, each with its input

`WSS-Q1` is the axis; the rest inherit its answer. **None is ruled in this
commit.**

| Q | Question | Input | Default proposed |
| --- | --- | --- | --- |
| **WSS-Q1** | **One wallet store with two obligations, or two files?** | §4's attribution; `WSS-4`, `WSS-5`, `WSS-6`, `WSS-7`; CT-1 §3.6; CT-5 §3.1; steering (1) | **No default offered.** The pre-flight is the evidence; the ruling is Round 1's. §6.1 states the two arms so the ruling is a choice between written positions |
| **WSS-Q2** | **Does the rebuilt store prune, what bounds obligation A's growth, and does it keep a segment-subroot cache?** | `WSS-8` (the discard was never wired; prune-disabled is the archiver posture), `WSS-9` (the cache is dispensable on today's store, and its boundary cannot be tied to `b_*`), `WSS-12` (full leaf set in RAM), `76-device-provisioning-floor` | Proposed: **B prunes by shard lapse; A does not prune and owes a stated growth bound at the Pi-4 floor.** A growth bound is owed either way |
| **WSS-Q3** | **Reorg under the answer to Q1** | `WSS-7`; `PDM-Q2`'s `W ≥ D_max` (B fills from below the horizon) | Proposed: **B does not reorg** — it is filled only from shards whose last transaction is `≥ W` old — so A keeps the reorg path alone |
| **WSS-Q4** | **Fill from the local daemon in the specified-to-scarce window** | `PDM-Q9`, "the one sentence Q9 still owed"; §5 rows 4–5 | Proposed: yes, over the operator leg, through the existing split read; no new RPC |
| **WSS-Q5** | **Verify-on-fill against the daemon's hash rows** | `PDM-Q6`; §5 row 3 | Proposed: yes, per transaction, `expected = (txs_prunable_hash, Option<txs_pqc_auth_hash>)` |
| **WSS-Q6** | **Key by shard over `[b_k, b_{k+1})`** | `PDM-Q-F32`, `PDM-Q9` (iii); §5 rows 1–2 | Proposed: yes; the store **reads** `b_*` and mints nothing |
| **WSS-Q7** | **Serve per-tx through `shekyl-p-serve`** | `SF-D8` content half, sub-PR 2 | Proposed: yes; `ShardProvider` unchanged in kind, its unit re-keyed |
| **WSS-Q8** | **The lapse tail** — how long an archiver serves a shard it no longer bonds | [`FOLLOWUPS.md`](../FOLLOWUPS.md) (the archiver retention-horizon row), owner [`ARCHIVAL_SERVING_ROUTE.md`](ARCHIVAL_SERVING_ROUTE.md), **enforcing site this store**. **This row has no builder today** | **Proposed: zero** (`WSS-16`, steering 2026-09-18). Serving is daemon→`P` only, the witness skips unheld pairs, and a dropped `P` stops advertising — so there is no identified consumer, and the row's stated motivation (*"the path-assembly serving purpose"*) is leaf-era and gone under `PDM-Q6`. **Pending one check:** that no episodic recovery fetch expects dropped holders to answer. The rule stays the serving route's; the enforcement and its test are this round's |
| **WSS-Q9** | **Recovery intake** — the daemon's episodic fetch hands a shard across and retains nothing | `PDM-Q9` recovery clause | Proposed: intake is the same write path as fill, with the same verify; the daemon side is episodic and stateless by `PDM-Q9` |
| **WSS-Q10** | **The Foundation `CompleteTree` behind a persona, never on a daemon** | `PDM-Q9` coverage floor; [`FOUNDATION_ARCHIVAL_DISCLOSURE.md`](FOUNDATION_ARCHIVAL_DISCLOSURE.md):196, [`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md):120 | Proposed: a `CompleteTree` is this store with **every** shard held and the prune-disabled posture declared — a configuration, not a fourth store type |
| **WSS-Q12** | **Where the `P`-store's encryption key lives** — the question the withdrawal (§6.2) shrank this to | `WSS-18`; `WSS-19`; [`35-secure-memory`](../../.cursor/rules/35-secure-memory.mdc), [`36-secret-locality`](../../.cursor/rules/36-secret-locality.mdc) | Proposed: **one** store key from the wallet's existing key hierarchy — not per-shard, not `P`-derived-per-shard (both withdrawn). It must stay **out of the Tor-facing serving task**, which follows from rule 36 anyway and is `WSS-Q13`. *Withdrawn from this row: per-shard keys, wrapping, crypto-shredding, size-hiding layout (`WSS-15` is an accepted residual).* |
| **WSS-Q13** | **Secret locality on the serving path** — `shekyl-p-serve` needs plaintext bodies but must not hold `P`-derived keys | [`36-secret-locality`](../../.cursor/rules/36-secret-locality.mdc); §6.1 | Proposed: the serving path gets a **decrypting read capability scoped to currently-held shards**, never the key. The capability's scope is the enforcement point for "a dropped shard cannot be served" |
| **WSS-Q11** | **What happens to the landed `SEGMENT_LEAF_COUNT` / `leaves_per_segment()` tie at E4** | `PDM-Q-F33` (ii); `WSS-9`; the FOLLOWUPS partition row | **Corrected 2026-09-18 (steering review): the tie is LANDED, not owed.** #780 put one home in `shekyl_fcmp::tree` with the consensus-side compile-time assert in `shekyl-archival-retention`'s production lib, red-checked at `segment_leaf_count = 26030`; the CT-1 row closed with its dedup. This round proposed landing it again — wrong. What is actually open: it **dies at E4 / S-ARCH with the freeze**, and is **not re-pointed at `SHARD_BYTES`** (`WSS-9`: one is a leaf count, the other a byte threshold). Its one possible survival is as the boundary of a proving-side subroot cache, which is `WSS-Q2`'s |

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
  and be **deleted at drop-connect + `D_max`** with a **zero lapse tail**
  (§6.2). *Superseded 2026-09-18: "`P`-derived per-shard keys, crypto-shredded"
  — withdrawn by steering, §6.2.*
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

**What this does to the two arms.** "One file" is no longer a neutral
alternative — it is the arrangement that puts two identities' state in one
artifact, which is what `WSS-13` reports as a defect. So the round's remaining
work on `WSS-Q1` is not *whether* to separate but **what each side becomes**:

| Side | Open question | Written up in |
| --- | --- | --- |
| **`P`'s serving store** | Its own file, encrypted at rest, deleted at drop-connect + `D_max` — what writes it (the `StakeEngine`, not the curve-tree actor), the fill path (`WSS-Q4`), **where the store key lives** (`WSS-Q12`, the question the withdrawal shrank this to), the serving path's read capability (`WSS-Q13`), and how `WSS-13`'s current routing is unwound | §6.2 |
| **The principal's proving state** | **Whether it is a store at all** — steering's "A is not a store" argument, now recorded | §6.3 |

**What is still genuinely open, and is Round 1's:** the two questions in that
table, plus `WSS-Q3` (reorg, which under this framing is the principal's alone
if `P`'s store is filled only from below the horizon). **The mechanics
findings are retained as supporting evidence, not as grounds** — `WSS-6` says
the one-file arrangement was never chosen, and `WSS-5` says it cannot be made
to satisfy both storage policies; neither is why the answer is what it is.

*Superseded: the "Arm A / Arm B" pair as first written, which argued the
question on storage mechanics and treated one file as a live option on equal
footing. Retained in the git history of this document, not restated here.*

### 6.2 `P`'s serving store — what the disk reveals, and what that justifies (steering, 2026-09-18; **open**)

**This section was rewritten on 2026-09-18 after steering worked the threat
model properly and withdrew most of its own previous proposal.** The withdrawn
material is recorded as withdrawn, with the reason each ground failed — it was
in a pushed commit and a reviewer may have read it.

**Correction that stands, from the previous pass: "destroyed when the bond
ends" was wrong twice.** Granularity is **per shard** — a `HoldingsUpdate` drop
releases one shard while the bond continues. Timing is **drop-connect +
`D_max`**, not the drop: under [`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md)
Pin 3 (`:488-497`) the slash scheduler challenges **currently-held** shards and
exit forgiveness applies only once the drop **connects**, and a connected drop
can be **reorged out**, which puts the obligation back. Erasing at *post* time
would risk a slash for a shard `P` destroyed and was then obligated for again.

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
2. **Delete at drop-connect + `D_max`, with a zero lapse tail** (`WSS-Q8`,
   `WSS-16`). This reclaims storage and makes "not held" true. With the store
   encrypted, whatever survives in freed pages is recoverable only by someone
   holding the password — and that person already knows `P`'s history from the
   chain.

#### 6.2.3 What is WITHDRAWN, and why each ground failed

**Per-shard keys and crypto-shredding — WITHDRAWN (steering, 2026-09-18).**
Defended the previous turn on three grounds, none of which survives:

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

**Size padding and slot preallocation — WITHDRAWN**, recorded as an **accepted
residual with reopening criteria** (`WSS-15`).

*What the withdrawal does not sanitise:* `WSS-15`'s underlying observation is
**still true** — shard sizes are variable and public, and encryption hides
neither sizes nor when they change. What changed is the **disposition**, not
the fact. It is accepted because the adversary who could use it is narrow and
the cost is 15–30 % of storage, not because the channel closed.

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

### 6.3 The proving side — "A is not a store" (steering's argument, recorded; **open**)

Recorded as received, as the proving-side arm. **Not ruled**, and not endorsed
by this document — §6.3.1 lists the attacks it must survive, each a Round-0
item for whichever increment takes it up. If it holds, the wallet's **only**
redb is `P`'s serving store, which makes this round's original framing —
*"the wallet's redb exists for serving from `P` when bonded"* — literally true
rather than the overstatement it was.

**Claim.** The principal's proving state does not need a **leaf store**. To
spend, a wallet needs a membership path from each owned output to the root at
the reference height; to verify each block (`merge.rs:651`) it needs the
current root. The tree is append-only by `hash_grow`, so both come from:

1. **the frontier** — the partial chunk at each layer, O(depth × width);
2. **one witness per owned output** — its chunk at each layer, started at
   drain, updated as right-siblings fill;
3. **pending candidates** until drain;
4. **a reorg undo log** over `D_max` plus the reference-height window.

State then scales **with the wallet, not the chain**.

**What it dissolves.** `WSS-12` (RAM growing with the chain); `WSS-9` /
`WSS-Q2` (no proving-side subroot cache, so the freeze keeps no proving-side
consumer at all — and `WSS-14`'s quadratic-sync cost goes with the recompute it
was avoiding); the at-rest leak (the state is small and private, so it lives
encrypted); and `WSS-Q1`'s proving arm. `R3` becomes literal, and **DRS-D3c
becomes root-and-frontier parity with the daemon** rather than a leaf/position
KAT (§10). The existing full-tree `build_layers` becomes the **property-test
oracle** for every witness path — the denominator survives as the oracle.

#### 6.3.1 Attacks the claim must survive — each a Round-0 item, none answered here

1. **Pending-set bound.** The largest drain delay per leaf class
   (`CT2_DRAIN_ORDER`). *The tier-lock concern raised earlier was claim-era and
   is **withdrawn**;* verify no rebased-era class has a long pre-drain delay.
2. **Reference-height witnesses.** Proofs anchor `REFERENCE_BLOCK_MIN_AGE`
   behind tip, so this needs lagged witness state or checkpoints across that
   window. **The part to design most carefully.**
3. **Late discovery.** Restore mid-chain, a newly imported key, or a multisig
   member learning of an output all mean no historic leaves. The answer is a
   bulk rescan from that height; the **user-facing failure mode is rule 82's**.
4. **Chunk-width update cost.** Selene/Helios widths mean a witness update
   rewrites a chunk. **Measure it; do not assume it.**
5. **Persistence write model.** Frontier and witnesses change every block. If
   `.wallet` is rewritten whole on save, per-block updates are write
   amplification on the encrypted file — which may argue for a small encrypted
   companion with an append-only undo log (still "not a leaf store", but still
   a file). **Check `shekyl-engine-file`'s save path before choosing.**
6. **Blast radius.** Every `CurveTreeHandle` consumer enumerated before
   anything is proposed — the spend gate, `assemble_tx` (C1 single-snapshot),
   the claim and drain orchestrators, and the `shekyl-ffi` curve-tree replica
   family.

**Failure mode, stated because it is the reason this is attemptable.** A
witness bug produces proofs that fail to verify: **the user's own spend fails,
nothing leaks, no funds are at risk.** Check the witness-derived root against
the reference root before proving — the same shape as today's integrity gate
(`assemble.rs:80-89`).

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

### (iii) Depends on `WSS-Q1`

| `CTS-` item | Why it waits |
| --- | --- |
| **`CTS-2`, `CTS-3`, `CTS-5`, `CTS-6`** — `LeafMeta`'s dense 122-byte redesign, `Leaf`, `PendingLeaf`, the retired `TargetKind` tag | All four are obligation-**A** table redesigns and all four are *right*. They wait only because `WSS-Q1` decides which **file** they land in and therefore which `SCHEMA_VERSION` their layout commit bumps |
| **`ingest.rs`, `reorg.rs`, `root.rs`** (§4) | `reorg.rs` is `WSS-7`/`WSS-Q3`; `root.rs` is `WSS-4` |

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
[`DRS_E1_SOUT_KI.md`](DRS_E1_SOUT_KI.md); each is separately authorized.

```text
increment 1  PR A — shekyl-store-codec            [CLEARED by steering (2)]
                 │  no behaviour change; tables.snap byte-identical
                 │  unblocks DRS-E3 S-CURVE as well as this lane
                 ▼
             WSS-Q1 RULING  (Round 1 — one file or two)
                 │
     ┌───────────┴────────────────────────────┐
     ▼                                        ▼
increment 2  the proving store            increment 3  the serving store
  (obligation A)                            (obligation B)
  CTS-2/3/5/6 typed records                 body unit, shard-keyed
  meta cells, decomposition                 fill · verify · serve · lapse
  root composition (WSS-4, WSS-Q2)          WSS-Q4…Q10
  BUILDABLE NOW — "very WALLET"             GATED on daemon elements:
                                              · A4 length rows (S-CHAIN-W)
                                              · b_* (S-PRUNE forward pass)
                                              · hash rows (landed, #772)
                                            and on E4/S-ARCH for the
                                            leaf-cluster deletion
     └───────────┬────────────────────────────┘
                 ▼
increment 4  the leaf-cluster deletion    [E4 / S-ARCH — NOT this lane's
             (freeze pipeline, challenge_leaf_index, the verifier re-key)
              coordinated, not owned; this lane owns only the store half]
```

**Sequencing constraints, stated as constraints rather than dates.**

- **Increment 1 lands first and alone.** A move mixed with a rewrite is
  unreviewable. It is also the only piece that survives every answer to
  `WSS-Q1`, which is why steering cleared it ahead of the ruling.
- **Increment 2 does not wait on the daemon.** This is steering's answer (1)
  applied: obligation A reads no daemon-owned input from §5 except the codec
  contract (row 6) and the format policy (row 8), both of which are this
  lane's own. If `WSS-Q1` rules two files, increment 2 can proceed while
  increment 3's inputs are still in flux.
- **Increment 3 is gated on §5 rows 1–5**, and the gate is named per row so a
  partial gate is visible: the hash rows landed (#772), the A4 length rows are
  owed by S-CHAIN-W, `b_*` is owed by S-PRUNE's forward pass.
- **Increment 4 is not this lane's to land.** The verifier re-key is consensus
  and lands at E4 / S-ARCH; this lane owns the store-side half and coordinates.
- **The `WSS-Q11` interim tie** is one line in `shekyl-archival-retention`,
  landing with the CT-1 dedup assert as its own small PR — not folded into any
  increment above ("fit the existing mechanism now; design the proper one as
  its own round").

---

## 10. Open residue — inherited or disposed, none left unowned

| Row | Disposition |
| --- | --- |
| [`FOLLOWUPS.md`](../FOLLOWUPS.md) — **the archiver's retention horizon** (the serving purpose's lapse tail; owner `ARCHIVAL_SERVING_ROUTE.md`, enforcing site this store; *"no builder today"*) | **Inherited** as `WSS-Q8`. The rule stays the serving route's; **this round takes the enforcement and the test**. The row is updated to name this document as the enforcing site's owner |
| [`FOLLOWUPS.md`](../FOLLOWUPS.md) — **DRS-D3c, the cross-store leaf/position KAT** (daemon vs wallet `LeafStore`) | **Inherited, and re-scoped by `WSS-9`.** Under the unit change the daemon's leaf table and this store's leaves are both still leaves, so the KAT's subject survives; what changes is that it is a **proving-store** KAT (obligation A ↔ DRS-E3's `curve_tree_*`), not a serving-store one. Lands with increment 2. Recorded here so it is not carried into increment 3 and then found to have no subject. **And its shape is contingent on §6.3:** if the proving state is not a leaf store, this becomes **root-and-frontier parity** with the daemon rather than a leaf/position KAT |
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
   persistent, posture-correlated state on the daemon. **Under Arm B of
   `WSS-Q1` a non-archiver's disk carries no serving artifact at all**, which
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
- **Verify-on-fill negative** (increment 3): a body whose `txs_prunable_hash`
  disagrees is refused, and the refusal names which hash disagreed
  ([`82-failure-mode-ux`](../../.cursor/rules/82-failure-mode-ux.mdc)).
- **The lapse-tail test** (`WSS-Q8`): the serving reader's answer past the
  horizon, which the FOLLOWUPS row names as the discharge condition.
- **DRS-D3c**, the cross-store leaf/position KAT, with increment 2 (§10).
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
  **reopened conditionally on `WSS-Q1` only**, and stated as such rather than
  left ambiguous: CT-1's *engine* choice (redb) and its validity definition
  are **not** reopened; what `WSS-Q1` touches is CT-1 §3.6's implicit "the
  store" (singular) and CT-5 §3.1's "one writer" — under Arm B there are two
  stores and two writers. If Round 1 rules Arm A, neither document changes.
  Whichever way it rules, the edit is line-local and lands with the ruling.
- `docs/CHANGELOG.md` — **no line at this PR** (design-round opener, no
  user-visible change); one line per implementation increment.

---

## 14. Decision log

| Date | Decision |
| --- | --- |
| 2026-09-18 | **Steering worked the at-rest threat model properly and withdrew most of the previous turn's proposal; §6.2 rewritten around what the disk actually reveals.** The only secret on disk is the **device ↔ `P` link**; the shard contents are public. An adversary table prices six positions and finds **one that matters**: forensics with an offline image but no password, where today's **plaintext `.curvetree` gives `P` despite the encrypted `.wallet`** (`WSS-18`, verified — the store is a sibling of the wallet file and the crate contains no encryption; and the onion key is *not* a second route, `Detach` being unrepresentable). **Justified:** encrypt the store under **one** key from the wallet's existing hierarchy — *for consistency, not a new threat*, since a plaintext companion undoes a decision `.wallet` already made — and delete at **drop-connect + `D_max`** with a **zero** lapse tail. **WITHDRAWN:** per-shard keys and crypto-shredding, with each of its three grounds failed on the record (remnants are covered by encryption; scoping a compromised serving task protects public data while its real assets are the countersigning capability and the `StakeEngine` route; unrepresentability is a correctness property a **type-level held-slot token** buys without key management). **WITHDRAWN:** size padding and slot preallocation — `WSS-15` becomes an **accepted residual** with reopening criteria (near-unique holdings counts measured by the sim, or forensic tooling that targets it); the underlying channel is unchanged, only its disposition. `WSS-Q12` shrinks to **where the one key lives**; `WSS-Q13` survives unchanged because rule 36 already requires it. **`WSS-19` added:** `P`'s other persisted state is unaudited, and that audit **gates** any claim that encrypting the store closes the gap. |
| 2026-09-18 | **Amendment on steering's second review — five carryover corrections, the `P`-store erasure lifecycle, and the proving-side arm. No rulings; every clause is a proposal Round 1 rules on.** *Corrections:* `WSS-9` / PDM's correction (b) called the subroot cache "dispensable" — true for correctness, **false for cost**: `verify_root` runs per ingested block (`merge.rs:651`), so dropping the cache makes sync **quadratic** (`WSS-14`). "The wallet's own tree state, not a slice" overstated it — the proving state **is** derived from canon and self-checks against the header root every block; `R3`'s property is that it therefore **never needs a migration, ever**. `R1`'s invariant recorded with its falsifier (`WSS-17`: no daemon-RPC edge from the store crate, `cargo tree`). `WSS-Q11` proposed landing a tie **#780 already landed** — corrected to what is actually open (it dies at E4, and is not re-pointed at `SHARD_BYTES`). `WSS-8` overstated: `set_prune_disabled` is reached only on the `PinCompleteTreePrefix` / Foundation-`CompleteTree` path (`curve_tree_actor.rs:391-402`), so most archivers declare nothing. *New:* §6.2 — "destroyed when the bond ends" was wrong on granularity (**per shard**) and timing (**drop-connect + `D_max`**, per `PHASE_2B_FSM_RETOOL.md` Pin 3, because a connected drop can be reorged out); erasure means **crypto-shred** with **random** per-shard keys wrapped under a `P`-derived key, with the four reasons to destroy public data, the redb-CoW / wear-levelling / snapshot reasons delete does not work, and what it does not buy. §6.3 — steering's **"A is not a store"** argument recorded as the proving-side arm with its six attacks. `WSS-15` (variable shard sizes make file sizes a fingerprint; encryption hides neither sizes nor when they change), `WSS-16` (the lapse tail may have **no consumer**, so `WSS-Q8`'s answer may be zero), `WSS-Q12` (at-rest shape), `WSS-Q13` (rule-36 decrypting read capability). §5.1 puts three properties of the new shard unit on the record: bonds no longer buy uniform work, boundaries are fee-influenceable, and `SHARD_BYTES` is inherited rather than derived. |
| 2026-09-18 | **`WSS-Q1` re-grounded on the firewall (steering review).** The question was posed on the wrong axis: "one file or two", argued from the shared file lock (`WSS-6`) and the prune/resume collision (`WSS-5`). It is an **ownership** question — the serving store is `P`'s (own file, `P`-derived keys, bond-lifetime scope, owned by the `StakeEngine`), the proving state is the principal's. **`WSS-13` added**, and it is the ground: `P`'s serve-set pins are written through the *principal's* curve-tree actor into the principal's file (`serve_set_source.rs:254-257` on the handle from `serving/start.rs:158`), routing around `PRINCIPAL_STAKE_LIFECYCLE.md` §0's load-bearing containment of `P`'s material — a firewall-layering defect visible only on this axis. `WSS-5` corrected twice over: its conflict is **latent** (nothing prunes in production, `WSS-8`) and its axis was mis-stated — it is one identity's storage policy destroying another's state, not two obligations colliding. `WSS-6` demoted to mechanics. §6.1 rewritten; the "Arm A / Arm B" pair is superseded. The proving side's "is it a store at all" arm is **owed to Round 1 from steering** — this round does not hold that argument's text and does not reconstruct it. **`PDM` propagation is not this round's** (§2.2, FOLLOWUPS): four documents never received `PDM-Q6`/`Q12` and are the next agent's trap. |
| 2026-09-18 | **Round opened** at `dev@8494f2a27`, Round 0 executed. `WSS-` family registered at birth. Twelve findings; `WSS-4` (`root_at_count` reads `frozen_segments` — the freeze is also the proving path's root cache), `WSS-5` (a pruned store cannot be reopened as a proving client — the two obligations already conflict, observably) and `WSS-6` (`ServingReader` and `same_store` exist because redb takes an exclusive file lock) are the three that reframe `WSS-Q1` from an architectural preference into a question about a conflict the tree already has. `WSS-9` is split into its verified half (the composition boundary cannot be tied to `b_*`, so the `F33` (ii) assert dies with the freeze) and its open half (whether any subroot cache survives — `WSS-Q2`'s). `WSS-3` resolves `PDM-Q12`'s "verification-side leaf store" to the **daemon's** `curve_tree_leaves` (graded CACHE by `PDM-Q1` over §9), so the wallet-side proving store is ungraded and is this round's. **`CTS-` closes as record with this document as its successor** (disposed on steering's answer 3, confirmed by Rick on review); its work is partitioned by unit in §8, and no `CTS-` implementation PR lands beyond PR A. **PR A is cleared ahead of the round** (steering, answer 2), with the §11.1(f) sequencing departure disclosed. `WSS-Q1…Q11` posed; **none ruled**. |
