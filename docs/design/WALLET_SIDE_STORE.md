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
| **WSS-5** | **A pruned store cannot be reopened as a proving client.** `CurveTreeClient::rebuild_from_store` (`client.rs:628`) refuses with `ClientError::ResumeFromPrunedStore` (`client.rs:200`) when readable drained rows are fewer than `leaf_count` — *"Pruning dropped frozen leaf bytes: the in-memory vec would undercount and every root would be silently wrong"* (`:631-639`). So **obligation B's size discipline and obligation A's resume are already mutually exclusive on one file**, and the conflict is realized today as a refuse-to-open. This is the strongest single argument in the tree that the two obligations have different lifecycles. | `WSS-Q1` — the decisive row |
| **WSS-6** | **`ServingReader` and `same_store` exist because redb takes an exclusive file lock.** `client.rs:283-290` — the `Arc<LeafStore>` is shared *"because redb takes an exclusive file lock, so a second open would simply be refused"*; `redb_backend.rs:160-177` — the serving side gets a narrowed handle because *"handing it the store itself would put a second writer beside the one the actor exists to be… the two would contend on the write lock"*; `same_store` is `Arc::ptr_eq` (`:325`). **One file is a consequence of the engine's file lock, not of a ruling.** Under two files each obligation has its own writer, and `same_store`'s subject ("pins applied to one are not pins in the other") cannot arise. | `WSS-Q1`; CT-5 §3.1's single-writer actor |
| **WSS-7** | **The reorg path touches all seven tables.** `truncate_from_tree_position` / `rollback_to_fork` (`redb_backend.rs`, the `delete_*_batched` trio at `:1950-2011` per `CTS-11`) span proving and serving tables in one write transaction. Under two files this is the one genuinely hard row: either B does not reorg (it is filled from below the horizon, `PDM-Q2`'s `W ≥ D_max`), or two rollbacks need an ordering rule. | `WSS-Q1`; `WSS-Q3` |
| **WSS-8** | **`prune_frozen` has no production caller at this sha, and the archiving wallet disables pruning outright.** Every call site is a test (`shekyl-p-host/tests/composition.rs` ×7, `shekyl-p-serve/tests/store_axis.rs:125`) or a doc comment reasoning *about* it as a hazard (`p-host/src/serve_set/{report,staleness,witness}.rs`, `shekyl-operator-alarm/src/lib.rs:341`). Production instead declares the one-way prune-disabled posture — `curve_tree_actor.rs:402` calls `set_prune_disabled` — so an archiving wallet **never prunes**. **"Unused" is a hypothesis, not a verdict:** the capability is designed-for and guarded by live detectors (`PostureDeclaration`, pins, staleness, witness), so the finding is *the discard has no caller*, not *the machinery is dead*. **Provenance, per the dead-code discipline (`git log -S'prune_frozen(' -- rust/shekyl-{p-host,p-serve,engine-core}/src` returns nothing): the discard was never wired**, not wired and later removed. So `WSS-Q2` is "design the size discipline", not "reinstate or delete a caller". What follows is a question, not a deletion: **does the rebuilt store prune at all, and what bounds obligation A's growth if it does not?** | `WSS-Q2`; §8 bucket (ii)'s scope; the size discipline nobody has ruled |
| **WSS-9** | **The composition boundary and the shard partition are different objects, and cannot be tied.** The tie today is `SEGMENT_LEAF_COUNT == leaves_per_segment()` (`PDM-Q-F33` (ii)); under `PDM-Q6`/`F32` the consensus partition becomes `b_*`, a **byte-bounded `tx_id` range**, while `root_at_count`'s composition boundary is a **leaf-count geometry** (`outputs_per_node(SEGMENT_LAYER_J)`, `segment.rs`). **Verified consequence:** the `F33` (ii) interim assert must die with the freeze and must **not** be re-pointed at `SHARD_BYTES` — the two constants would be asserting a relation that does not exist. **Not verified, and therefore `WSS-Q2`'s to rule:** whether obligation A keeps *any* segment-subroot cache after the freeze retires. `WSS-4`'s `r_k` read has a recompute-from-leaves fallback (`redb_backend.rs:1241-1245`) and `WSS-8` says nothing prunes in production, so on today's store the cache is **dispensable, not load-bearing** — dropping it, keeping it, or replacing it with a different checkpoint scheme are all open, and this finding does not choose. | §5 rows 1–2; §8; `WSS-Q2`; the interim-tie PR's scope |
| **WSS-10** | **`PDM-Q12`'s code cites have drifted ~6–50 lines at this pin.** `StoreError::FrozenSegmentPruned` is at `redb_backend.rs:470` (cited `:464`); `ServingReader`'s doc block spans `:160-183` and its `open_frozen_segment_body` is at `:216`, while `LeafStore::open_frozen_segment_body` is at `:1877` (cited as `:164-183` for all three). The **symbols** named are correct; the **ranges** are stale. Recorded as a re-pin, not a defect. | Every increment's Round-0 re-pins rather than inheriting |
| **WSS-11** | **`redb_backend.rs` is still 4 196 lines** — nothing of `CTS-` is built. The file holds the schema, six codecs, `StoreError` (17 variants), three handle types, every operation, and ~2 000 lines of tests. | §8; the decomposition principle survives any `WSS-Q1` answer |
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
| **WSS-Q8** | **The lapse tail** — how long an archiver serves a shard it no longer bonds | [`FOLLOWUPS.md`](../FOLLOWUPS.md) (the archiver retention-horizon row), owner [`ARCHIVAL_SERVING_ROUTE.md`](ARCHIVAL_SERVING_ROUTE.md), **enforcing site this store**. **This row has no builder today** | No default. The rule is the serving route's; the *enforcement* is this store's, and the round owes the test |
| **WSS-Q9** | **Recovery intake** — the daemon's episodic fetch hands a shard across and retains nothing | `PDM-Q9` recovery clause | Proposed: intake is the same write path as fill, with the same verify; the daemon side is episodic and stateless by `PDM-Q9` |
| **WSS-Q10** | **The Foundation `CompleteTree` behind a persona, never on a daemon** | `PDM-Q9` coverage floor; [`FOUNDATION_ARCHIVAL_DISCLOSURE.md`](FOUNDATION_ARCHIVAL_DISCLOSURE.md):196, [`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md):120 | Proposed: a `CompleteTree` is this store with **every** shard held and the prune-disabled posture declared — a configuration, not a fourth store type |
| **WSS-Q11** | **`SEGMENT_LEAF_COUNT` / `leaves_per_segment()`'s interim tie** | `PDM-Q-F33` (ii), assigned to this lane; `WSS-9` | Proposed: land as scoped — **one line that dies with the freeze**, same PR as the CT-1 dedup assert — and **do not re-point it at `SHARD_BYTES`**, because `WSS-9` says the two are different objects |

### 6.1 `WSS-Q1` — the two arms, written out

Posed, not answered, so Round 1 chooses between positions rather than drafting
one.

**Arm A — one file, two obligations.** One redb file, one `SCHEMA_VERSION`,
one writer (the CT-5 actor), one open/refuse path. *For:* no cross-file
consistency rule; the reorg path stays in one transaction (`WSS-7`); no second
file to lose, back up, or leave behind; `same_store` keeps meaning.
*Against:* a non-archiver wallet — the overwhelming majority — carries
serving tables it never writes; `WSS-5`'s refuse-to-open says the two
lifecycles already contradict each other; every `WSS-Q2` answer must hold for
both obligations at once; and the serving loop's narrowing apparatus
(`WSS-6`) exists only to manage the shared lock.

**Arm B — two files.** The archiver's serving store is a separate artifact
with its own lifecycle, lapse tail, fill path and writer; the proving store
stays what every wallet has always had. *For:* §4.1's type split already
tracks it (`ServingReader` in one crate, `LeafStore` in one); `WSS-5`'s
conflict dissolves — A never prunes, B prunes by lapse, neither refuses to
open because of the other; `WSS-6`'s lock contention and `same_store` both
disappear; a wallet that is not an archiver has no serving file at all, which
is the **privacy-shaped** answer (the disk of a non-archiver looks like the
disk of a non-archiver); steering (1) is satisfied — A is "very WALLET" and
buildable now, B is gated on daemon elements still in flux. *Against:* two
schema versions and two refuse paths; `WSS-7`'s reorg needs `WSS-Q3` ruled
first; the `CompleteTree` floor holds both files; two-file atomicity is a
property nothing asserts today.

**What the pre-flight does not settle.** The attribution is clean at the type
and crate level and messy at exactly three methods (`root_at_count`,
`prune_frozen`, `open_frozen_segment_body`), each of which crosses **only
through the leaf segment** — the object `PDM-Q12` retires. Whether that makes
Arm B nearly free or merely cheaper depends on `WSS-Q3`, which is why Q3 is
listed as a separate question rather than folded in.

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
| [`FOLLOWUPS.md`](../FOLLOWUPS.md) — **DRS-D3c, the cross-store leaf/position KAT** (daemon vs wallet `LeafStore`) | **Inherited, and re-scoped by `WSS-9`.** Under the unit change the daemon's leaf table and this store's leaves are both still leaves, so the KAT's subject survives; what changes is that it is a **proving-store** KAT (obligation A ↔ DRS-E3's `curve_tree_*`), not a serving-store one. Lands with increment 2. Recorded here so it is not carried into increment 3 and then found to have no subject |
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
| 2026-09-18 | **Round opened** at `dev@8494f2a27`, Round 0 executed. `WSS-` family registered at birth. Twelve findings; `WSS-4` (`root_at_count` reads `frozen_segments` — the freeze is also the proving path's root cache), `WSS-5` (a pruned store cannot be reopened as a proving client — the two obligations already conflict, observably) and `WSS-6` (`ServingReader` and `same_store` exist because redb takes an exclusive file lock) are the three that reframe `WSS-Q1` from an architectural preference into a question about a conflict the tree already has. `WSS-9` is split into its verified half (the composition boundary cannot be tied to `b_*`, so the `F33` (ii) assert dies with the freeze) and its open half (whether any subroot cache survives — `WSS-Q2`'s). `WSS-3` resolves `PDM-Q12`'s "verification-side leaf store" to the **daemon's** `curve_tree_leaves` (graded CACHE by `PDM-Q1` over §9), so the wallet-side proving store is ungraded and is this round's. **`CTS-` closes as record with this document as its successor** (disposed on steering's answer 3, confirmed by Rick on review); its work is partitioned by unit in §8, and no `CTS-` implementation PR lands beyond PR A. **PR A is cleared ahead of the round** (steering, answer 2), with the §11.1(f) sequencing departure disclosed. `WSS-Q1…Q11` posed; **none ruled**. |
