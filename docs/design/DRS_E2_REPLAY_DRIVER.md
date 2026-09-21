# DRS-E2 — the ingest spine and its first source, the replay driver (pre-flight)

**Status:** OPEN — **implementation: increment 1 (§7 commits 0, 1, 2, 3,
4a, 6) LANDED via #804 (2026-09-20); increment 2 (4b, 5, 6b, 7, 7b, 8b, 8c,
and commit 8's regtest leg) LANDED on the branch 2026-09-20 — ported from
the parallel #806 onto #804's APIs (rule 95: code on `dev` wins) after the
two lanes were found to have built the same increment 1 independently.
Open: commit 8's testnet leg and LWMA-past-N run (§7 item 8, blockers
named), the mutation family (§7 item 8d, next E2 PR), commit 9's archive.** Round 1 RULED 2026-09-19 (RD-Q9–RD-Q12). Round 1 opened with the sweep of #785 as
merged (`dev` @ `93f91b0d4`; §3.7); ground re-pinned to `306af9bae` (§0.1). Round 0 REVIEWED and RULED 2026-09-19
(maintainer). Round-0 text was written against `dev` @ `14f8dc739` with #785
in flight; §3.7 records what the merged tree changed, and every citation
below is read against `93f91b0d4` unless it says otherwise.
Template: [`CHAIN_RULES_CRATE.md`](CHAIN_RULES_CRATE.md) §7.5.1's slice shape,
applied to a *program* increment. Parent plan:
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) — **DRS-D10** (replayable derived
state), **DRS-D11** (the logical-state digest as oracle), **DRS-D12 (ii)**
(*"every block the Rust store connects before cutover is validated by that
crate first: D10's replay with the validator attached, which is also the E2
harness"*), and the **DRS-E2** row (§6.1: acceptance per conformance state,
CSR-3a). Identifier families **RD-Q** (questions) and **RD-F** (findings),
registered in `IMPLEMENTATION_INDEX.md` §2 with this file.

## 0. The ruling (2026-09-19, ruled by Rick; direction memo of 2026-09-19, ground `origin/dev@306af9bae`, #788 at `91a20216`)

> **The C++ daemon is a non-canonical reference: divergences adjudicate
> against the spec, never resolve toward C++, and C++ is never fixed. All C++
> written for E2 is harvest shims that die at cutover. The sole surviving C++
> is the `external/randomx-v2` JIT behind the existing `randomx-v2-sys`
> boundary, its parity vectors promoted to a permanent gate re-run on either
> pin's move. The ingest pipeline is production code shared by E2 and E3, with
> the replay driver as its first source — and #788 is amended before merge so
> its pre-flight doesn't land asserting the superseded scope.**

### 0.1 How this file records the memo

The memo carries **two kinds** of content and this file marks them
differently: what is **RULED** (§0 verbatim; the memo's §2 amendments — the
"is not" clause, RD-Q1, RD-Q2 with typed doors, the grader's law, the
adjudication sentence) is tagged `RULED (memo §2)` where it lands; what is
**design review feeding Round 1** (the memo's §3 — pipeline stage shape,
mutation and reorg corpus families, `Stale::Seed` grounding, JIT
consequences — and its §4 questions Q-A–Q-D) is tagged `REVIEW INPUT` and is
answered or posed in §4, never recorded as ruled. The memo was written against
#788 at `91a20216` (Round 0 as first pushed); commits `1c31927f8` … `156bbb60b`
had already amended most of its §2 from the same reviewer's earlier rounds.
This revision (`e80cdbf23` onward, re-pinned to `306af9bae`) brings the
wording into conformity with the memo and adds what was net-new: the typed
doors, the corpus/trace contents, the two corpus families, Q-B and Q-D, and
the `randomx-v2-sys` correction to RD-F12.

**Why this file exists now.** Six pieces of landed or planned work route to
"the driver" and, until this file, no document, branch or PR owned it —
"owner: the E2 lane" named a lane that did not exist in any form (caught
2026-09-19 on #785's review; rule 22's queue-that-accumulated). DRS-D12
ratified the driver as the Rust store's *only* pre-cutover writer, so this is
not new scope. It is also the first time the validator runs against a real
chain — slices 1 and 2 stood in for that with mock views and fixtures, and
the fixture ceiling is visible in the conformance harness itself (the store
fixtures' `0xc0 + h` root bytes cap chains at 63; no LWMA-1 window past `N`).

---

## 1. What this increment builds

### 1.1 The inversion (RULED, §0) — and the stage shape (REVIEW INPUT, memo §3)

Round 0 wrote *"the driver is not the daemon's live connect path (that is
cutover, DRS-E3+)."* **Superseded.** The C++ codebase's deepest defect is
exactly there: `core_tests` / `chaingen` construct and admit blocks through a
path the network never runs, so its tests exercise code production does not.
An E2 bench tool followed by a separately built E3 live path would reproduce
that in Rust on day one. Instead the **block-ingest pipeline is built once, as
production code**, and the E2 driver *is* that pipeline with a different
source and an extra sink. That much is ruled. The stage decomposition below
is the memo's design input for Round 1 (composition is RD-Q11):

```text
Source ──► Form (N workers) ──► Sequencer ──► Validate+Connect ──► Sinks
(corpus │  (stateless; real     (reorder to   (single writer;      (digest/grader,
 now,   │   RandomX, VM pool)    height        owns the redb        checkpoints,
 p2p at │                        order)        batch; the only      metrics)
 E3)    │                                      state)
```

- **Source** is a trait yielding an **ordered event stream, not a
  height-ordered block stream**: a reorg is a `Rewind { to }` followed by
  `Extend`s, and a source that cannot say *rewind* cannot express a fork —
  so "E3 swaps the source" is only true if the event model carries pop
  (RD-Q13). E2 plugs in the corpus reader (Extend-only); the mutation family
  is Extend-only too; the reorg family and E3's p2p feed emit `Rewind`.
- **Form** is stateless by design (slice 2 Q1) and dominated by RandomX, so it
  parallelises across N workers, each holding an `Arc<PreparedCache>` for the
  current seed epoch and calling the production surface
  `compute_hash(&PreparedCache, &[u8])` — a bounded window of speculative
  formation, re-sequenced before validate. **Not** over `VmStatePool`: that
  pool and `compute_hash_with_pool` are compiled only under
  `cfg(any(test, feature = "internal-pool-bench"))`
  (`shekyl-pow-randomx/src/lib.rs:190`, `:204`) and are not a production
  API (RD-F14). Whether a bounded scratchpad pool should *become* production
  is the RandomX lane's call, decided on the benchmark this pipeline emits
  (RD-F11), not assumed here.
- **Validate+Connect** is one actor — the single-writer discipline the
  wallet's CT-5 actor established, and what redb's exclusive lock makes the
  only honest shape. **What the actor owns is the `ChainStore`, not a
  `WriteBatch`:** a batch exists only inside `ChainStore::write`'s
  higher-ranked closure (`for<'id> FnOnce(&mut WriteBatch<'_, 'id>)`,
  `store/mod.rs:28`–`:35`, `:439`–`:447`) and cannot be held across mailbox
  messages — that is the brand doing its job. So the transaction boundary is
  **one `write` closure per handler invocation**: a `Rewind` is one closure
  (pops to `to`); a bounded run of consecutive `Extend`s is one closure
  (`connect` may be called repeatedly on one batch — `connect.rs` doc — and
  the run's length is the checkpoint granularity, so a checkpoint is a
  transaction boundary). "The only state is the batch" reads: the only
  *mutable* state is inside the closure while it runs; between messages the
  actor holds the store handle and the sequencer's cursor, nothing else. `kameo` is the workspace
  actor stack (exact-pinned `=0.20.0`, `shekyl-engine-core/Cargo.toml:113`),
  so the daemon composing the same way is consistency, not novelty.
- **Supervision** maps **every** non-verdict outcome the public contracts
  can return to a lifecycle, so none inherits an actor framework's default
  restart (RD-Q11: the actor is no-restart, tested). The complete map:

  | Outcome | Contract | Lifecycle |
  | --- | --- | --- |
  | `Verdict::Err(InvalidBlock)` from `form` or `validate` | the block is refused | **not a fault**: recorded by the grader sink as the verdict (spec-first expected verdicts in the mutation family); the run continues with the next event |
  | `S::Fault` from `form` (the substrate could not compute: cache derivation, clock) | `form -> Result<Verdict<_>, S::Fault>` | **terminal for the run**, surfaced — a verifier that cannot compute is a fault, never a verdict (slice 2 Q1); in the live daemon it is the node's own outage, not the block's |
  | `Fault::View(store error)` from `validate` | *"the caller halts"* (`validate.rs:141`) | **halt**: if the store already poisoned the batch (`InvariantViolated`) the writer is halted and the run ends; an engine error ends the run — never retried, never a verdict |
  | `Fault::Corrupt` | RD-Q4 | `refuse_corrupt`, batch poisoned, **halt**, terminal (RD-Q11) |
  | `Fault::Stale(Stale::Seed { retry: Again, .. })` | RD-Q5 | in replay a **driver defect**: recorded and surfaced on first occurrence; the bounded re-`form` runs so the live-mode bound is exercised, not as a cure |
  | `Fault::Stale(Stale::Seed { retry: Exhausted, .. })` | RD-Q5 | **terminal run error**, surfaced |
  | `Fault::Stale(Stale::RuleSet { .. })` | `form` and `validate` were handed different sets | in replay a **driver defect** (the schedule must hand both stages one `&RuleSet`, §3.7): recorded and surfaced, **not retried** — there is no honest re-`form` for it; in the live daemon the same arm marks a schedule boundary crossed mid-formation and the block is re-formed under the in-force set once |

  Checkpoints at digest heights make long replays resumable.

E3's cutover then stops being "build the live connect path" and becomes
"swap the source and drop the grader." There is no C++ ingest to fall back to
at cutover (§1.3), so the pipeline E2 hardens is not merely shared with
production — it is the only ingest the daemon will ever have.

### 1.2 What it is not (RULED, memo §2)

**Not a second connect path** — the pipeline the driver drives *is* the
production ingest spine; E3's cutover swaps its source and drops the grader.
(This replaces Round 0's *"not the daemon's live connect path (that is
cutover, DRS-E3+)"*, superseded before merge so the pre-flight does not land
asserting the old scope.) The other three stand and are strengthened: not a
second validator (D12 (i): one crate, now also one ingest path); not an FFI
shim minting `ChainValid` from the C++ verdict (rejected, D12 (ii)); not a
place where any consensus value is computed outside `shekyl-chain-rules`
(C2-R8 Q4 — borrowed facts are *read* from the LMDB record, never computed).
And not a consumer of the mining JIT for validation (§1.3).

### 1.3 The C++ posture (RULED 2026-09-19)

- **Adjudication has two outcomes, not three.** When Rust and C++ disagree:
  *Rust is wrong → fix Rust*; *C++ is wrong → record a `ReviewedDivergence`
  with the Rust behaviour canonical*. A third arm — "fix C++ if the divergence
  would corrupt the traces" — was proposed and **retracted**: when C++'s
  wrongness taints a trace row, the row is *annotated as adjudicated*, not
  repaired at the source; once Rust derives that value, the fixture is
  re-baselined from Rust. The C++ is a quarry: extracted from, never renovated.
  *Spec silent* is not a third outcome but a design finding — rule it, then
  one of the two outcomes applies.
- **The C++ trace is evidence, not a target.** A run's goal is not "match
  C++"; it is **no unadjudicated disagreement**. CSR-3a's grader already has
  the states (`CheckedConformant`, `Divergent`, `Unreviewed`); this is the one
  sentence of semantics it lacked. After cutover the traces are re-baselined
  from Rust — they stop being "what C++ said" and become "what Shekyl says",
  which is what makes them permanent regression fixtures rather than a shrine
  to the retired implementation.
- **The only C++ permitted in E2 is harvest shims, and they die at cutover.**
  The corpus needs *zero* C++ (`/get_blocks_by_height.bin` against an unpruned
  daemon, §3.4). The trace needs one exporter walking LMDB and handing bytes
  to the Rust writer (RD-Q2). Mutation verdicts need a *running* regtest
  daemon, not a modified one. Every C++ line written for E2 must be deletable
  in the same commit that deletes the daemon — written here so nobody
  "improves" the exporter into something with a future.
- **RandomX plays two roles and the rewrite splits them.** *Verification* is
  `shekyl-pow-randomx` — everywhere, forever: the daemon's connect path, this
  driver, the wallet. The JIT is never consulted for validation, **and is not
  used to speed up replay**: E2 must validate with the hasher production
  validates with or it tests a different daemon. *Mining* calls the JIT
  because it is fastest — so the miner can produce work the verifier rejects
  if the two ever disagree on one hash, silent until a block is orphaned. The
  parity corpus (`shekyl-pow-randomx/tests/vectors/reference/`, generated
  against `external/randomx-v2`; workflow `randomx-v2-differential.yml`) is
  today rewrite scaffolding; **under this ruling it is a permanent gate** — the
  Rust verifier and the pinned JIT agree on the full vector set, re-run
  whenever either pin moves, plus ongoing fuzz of `longhash` across the
  boundary (RD-F12). At cutover the FFI direction flips for exactly this one
  dependency: today C++ links `libshekyl_ffi.a`; after, the Rust daemon links
  the JIT as a vendored C library behind an adapter crate (rule 40), its W^X
  executable-page machinery confined to the mining path and nowhere near
  consensus, and shaped so a future Rust JIT is a swap behind the adapter.

## 2. The inventory this increment resolves

| # | Item | Where it was deferred | What the pipeline must do |
| --- | --- | --- | --- |
| 1 | `Fault::Corrupt` → writer halt | `CHAIN_RULES_SLICE_2.md` §4.3; FOLLOWUPS row | Receive a `Corrupt` from `validate` and arm the store's halt at the noted height, as a belt does; the store API is **minted here, with its caller** (RD-Q4). |
| 2 | `Stale::Seed` → bounded retry — **BUILT, increment 2 (commit 5): surfaced as the run's refusal; the wrong-seed test** | `fault.rs` (`FormAttempt`, `Retry`, `MAX_FORM_ATTEMPTS`); slice 2 Q8 (the ruling that minted the arm and its bound) | Run the loop with the bound; in replay any `Stale::Seed` is a **driver defect** — record and surface the first occurrence (RD-Q5, RULED). |
| 3 | The production `Substrate` — **BUILT, increment 1 (#804); metrics + `EpochPin` added in increment 2 (RD-F20)** | `substrate.rs`; slice 2 Q1 | Real `longhash` through `shekyl-pow-randomx`'s production surface (`PreparedCache::derive` + `compute_hash`; `CacheStore`), a real clock; the seed claim from the chain (RD-Q3). |
| 4 | `RuleSet::fakechain` wiring — **BUILT, increment 2 (commit 6b)** | slice 2 Q10 / F10; FOLLOWUPS row | `--regtest` / `--fixed-difficulty` reach `RuleSet::fakechain` through the driver (RD-Q7). |
| 5 | The test-deviation register's first consumer — **§5 carries it; the grader's `Borrowed` clause is the consumer** | F12; FOLLOWUPS row (falsifier: *this* pre-flight) | §5 carries the section F12's falsifier demands. |
| 6 | LWMA-1 conformance past `N` — **NOT YET: the regtest runs were fixed-difficulty (D4 ran under `Fixed`); a regtest chain mined without `--fixed-difficulty` ramps past CPU mining within 20 blocks (§7 item 8), so this leg is testnet's** | `conformance_tests.rs` header; `CHAIN_RULES_CRATE.md` §8.8 | The first replay past 91 blocks exercises D4's window against a real store. |
| 7 | **The verifier dataset-mode measurement** — **MEASURED, increment 2 (§7 item 7b): 0.60 s CPU/hash light mode on x86_64, ~40× the C JIT baseline** | `RANDOMX_V2_RUST.md` §9 (unbuilt pending measured need); `RANDOMX_V2_MINING_ASYMMETRY.md` option (a) | The pipeline is the first instrument able to run RandomX verification at volume over a real chain; **the benchmark is part of its deliverable** (RD-F11): light-mode wall-clock per hash / per block, on the provisioning floor, as a sink artifact. A deferred decision's input arrives with the driver instead of being argued for. |

## 3. Round-0 sweep — what exists, verified at source

### 3.1 The store side (`shekyl-chain-store`, at `dev`)

- `ChainStore::create(path, epoch)` / `open_read_only`; `ChainStore::write(|batch| …)`
  runs one exclusive write transaction; `WriteBatch::chain_view()` yields the
  branded `BatchView<'_, 'id>`; `WriteBatch::connect(ChainValid<'id, BatchView>,
  ConnectFacts, RuleSetId)`; `pop`. Halt: `ConnectState::{Live, Halted{height,
  row}}` (`halt.rs`), armed by `Poison::arm(StoreInvariant)` — **`pub(super)`**,
  reachable only from the store's own belts (`write.rs:95`). No public way for
  a caller to hand in a violation it observed: item 1's API, absent by design
  until now.
- `ConnectFacts` after #785: six passed-through fields — `weight`,
  `long_term_weight`, `coins_generated`, `burned`, `root_after`,
  `long_term_effective_median` (`cumulative_difficulty` is derived). The
  pipeline must **source** all six per block (§3.4), and **`connect` writes
  `curve_tree_roots[h+1] = facts.root_after`** (`store/connect.rs:23, :184`) —
  the root component of the redb digest is therefore LMDB's root copied in
  (RD-F7).
- `Provenance` records `PassedThroughFacts` and `CoverageGaps`; only all-empty
  is parity evidence. The pipeline's output file is NOT-PARITY-EVIDENCE for as
  long as any fact is passed through or any enforced row unimplemented — the
  honest state E2 grades against.
- `conformance.rs`: the CSR-3a grader exists as pure logic —
  `ConformanceState::{CheckedConformant, Divergent, Unreviewed}`, `Acceptance`,
  `FailureReason`, `ReviewedDivergence`, `FinalVerdict`, truth-table tested.
  **No caller assembles rows from the register into it.**
- `digest_v0.rs`: `digest_v0(block_hashes, spent_keys, root)`,
  `chain_component`, `spent_accumulator`. `ReadSnapshot::key_images` (read.rs
  K2) exists *for* the digest's `spent_keys` scan. **No redb-side assembly**
  walks `block_info` hashes + `key_images` + the live root into `digest_v0`;
  the only caller is the C++-fed FFI (`chain_digest_ffi.rs:69`). Owed (RD-F5).

### 3.2 The rules side (`shekyl-chain-rules`, at #785)

- `form(candidate, &RuleSet, &impl Substrate, seed: BlockHash, FormAttempt)
  -> Result<Verdict<StructurallyValid>, S::Fault>`; `validate(StructurallyValid,
  &V, &RuleSet) -> Result<Verdict<ChainValid<'id, V>>, Fault<V::Fault>>`;
  `Fault::{View, Stale(Stale::{Seed{..}, RuleSet{..}}), Corrupt(Corrupt::{…})}`;
  `FormAttempt::FIRST`, `Retry::{Again, Exhausted}`, `MAX_FORM_ATTEMPTS`.
- `Candidate { block, transactions }` — *"the listed transactions' bodies, in
  the header's order"* (`block.rs:88`–`:93`). Spent keys, outputs and leaves
  come from the **bodies**, not the block blob (RD-F8).
- `Substrate { type Fault; local_clock(); longhash(pow_blob, seed) }`; only
  `MockSubstrate` / `FixtureSubstrate` implement it.
- `RuleSet::GENESIS`, `RuleSet::for_network(Network)` (three public nets),
  `RuleSet::fakechain(NonZeroU128)` — no `Network::Fakechain` witness (slice 2 F10).
- Seed schedule: `shekyl_difficulty::{seedheight, next_seedheight,
  SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG}` after #785 (on `dev` still
  `shekyl_pow_randomx::seed_epoch`; RD-F6).

### 3.3 RandomX (`shekyl-pow-randomx`, at `dev`)

`PreparedCache::derive(Seedhash)` (the 256 MiB Argon2d fill),
`compute_hash(&PreparedCache, &[u8]) -> [u8;32]`, `CacheStore::{lookup,
lookup_or_derive, set_canonical}` (the daemon's two-epoch cache). `VmStatePool`
+ `compute_hash_with_pool` exist but only under `cfg(any(test, feature =
"internal-pool-bench"))` — bench scaffolding, not production (RD-F14). **Cache-only today, as a measure-first staging —
not a foreclosure** (RD-F11, corrected 2026-09-19): `Cache::derive_item` is
the per-item path (`cache.rs:449`, ~16 µs/item) and nothing public builds a
dataset; `RANDOMX_V2_RUST.md` §4 lists `Dataset::derive(cache)` as a planned
transform, and `RANDOMX_V2_MINING_ASYMMETRY.md` names the no-dataset verifier
as *"the thing disposition option (a) would revisit"* once its measurement
exists — and no measurement exists yet. The replay throughput levers are
**parallel `form`** (§1.1) and, if the measurement says so, **the Rust dataset
mode**; never the JIT (§1.3). E2 is the first real verification workload, so
the pipeline **emits the measurement** (RD-Q3).

### 3.4 Block, body and fact sources — the load-bearing finding

Per height the pipeline needs the block blob, **the full bodies of the listed
transactions** (RD-F8), and the six passed-through facts.

| Input | LMDB | RPC (unpruned daemon) | Derivable by the driver? |
| --- | --- | --- | --- |
| block blob | `blocks[h]` | `/get_blocks_by_height.bin` (`bin_commands.rs:160`) ✔ | — |
| **tx bodies** (`Candidate.transactions`) | `txs_pruned` + `txs_prunable` (+ `txs_pqc_auths`) | `/get_blocks_by_height.bin` carries them **only from an unpruned node** — and a pruned node does **not** announce it: `BlockEntry` is `{ block, txs }` only (`bin_commands.rs:201`–`:220`) and the handler drops `missed` (`rpc_facts_ffi.cpp:1053`–`:1061`), so what arrives is a block with **fewer transaction blobs than its header lists**, not hash-only rows. The corpus writer therefore **verifies, not declares**: parse the block, and require the returned bodies to match `block.tx_hashes` in **count, order and hash** before the height is written as unpruned; a shortfall is a refusal naming the height (RD-F15) | — |
| `weight` | `block_info.bi_weight` | `block_weight` ✔ | no (CEN-G6, slice 7) |
| `long_term_weight` | `block_info.bi_long_term_block_weight` | `long_term_weight` ✔ | no |
| `coins_generated` | `block_info.bi_coins` | **✘** (`reward` per block; the fold is CEN-F13/F14, slice 4 — not the driver's, C2-R8 Q4) | no |
| `burned` | `block_burn[h]` | **✘** (`total_burned` on `get_info` only) | no |
| `root_after` | `curve_tree_roots[h+1]` | header `h+1`'s `curve_tree_root` (SCW-19) — ✔ with lookahead, ✘ at the tip | no (S-CURVE) |
| `long_term_effective_median` | `block_info` (S-CHAIN-R A1) | **✘** | no |

Two sources, two shapes (RD-Q2, RULED): the **corpus** (blocks + bodies) comes
from RPC against an **unpruned** daemon with zero C++; the **trace** (the
LMDB-only facts, and the LMDB digests at checkpoint heights) comes from one
exporter walking LMDB and handing bytes across the FFI to a Rust writer. **The
corpus writer verifies completeness per height — count, order and hash of the
bodies against the header's `tx_hashes` — and only then records the artifact
as unpruned; the reader refuses an artifact whose recorded state it cannot
re-verify** (RD-F8, RD-F15). A declaration alone would trust the source; a
pruned-source run is not a permitted deviation (§5).

### 3.5 Tooling that already exists around E2

`scripts/bench/drs_bench.py` (runs the C++ daemon under measurement
conditions; §7.4) and `drs_artifact.py` (artifact schema, §1.3 comparator,
refuses ratios across differing conditions); `check_drs_p0d_digest_coverage.py`;
the P0f register (`CONSENSUS_STORE_RECONCILIATION.md`; **the count is the
gate's, not a literal kept here** — `check_conformance_coverage.py` at
`6c41bf820`: 131 ratified rules, 131 recorded, tally 126 CHECKED-CONFORMANT /
2 DIVERGENT / 3 UNREVIEWED). The register is prose; the grader takes typed
states. The row extractor RD-Q6 owes reuses that gate's derivation so the E2
denominator is never a hand-copied figure.


### 3.7 Round-1 sweep — what #785 landed that Round 0 did not see (2026-09-19)

Two review commits landed on #785 after Round 0's sweep and are in the merged
tree (`93f91b0d4`). Swept the way slice 2 swept #783/#784, before any Round-1
question is answered.

**`5e3c2982a` — `chain-rules: Target, connecting height, and honest D4
overflow`.**
- `Target` wraps `NonZeroU128`; D6 records on **every** production path
  (`D6::mint` for LWMA-1, `D6::record` for the genesis block's 1 and for
  Fakechain `Fixed`). Consequence for RD-Q7: **`RuleSet::fakechain` can now
  mint a `ChainValid`** — before this commit the `Fixed` arm returned a target
  without inserting D6 and `covers_landed` panicked at mint, so the wiring
  RD-Q7 owes had no working target to wire to. Fixture-pinned (fakechain
  genesis and past-`N` mint).
- `StructurallyValid` carries the **`RuleSet`**, not only its id, and
  `Stale::RuleSet { formed_under: RuleSet, in_force: RuleSet, retry }` compares
  **by value**, because Fakechain reuses `RuleSetId::GENESIS` (slice 2 Q10's caveat,
  now load-bearing). Consequence for the pipeline: `form` and `validate` are
  handed the same `&RuleSet`; the id is not a proxy for the set anywhere in
  the loop.
- `BlockContext` is the connect's derived facts (connecting height, tip, MTP
  window, target). Internal to the rules crate; no pipeline consequence.
- D4's window walk is the SI-8 observer; `lwma1_next`'s `Overflow` after a
  monotone `N+1` window is **unreachable** at the ratified `(N, T)` (pinned by a
  `u128::MAX` fixture). `Corrupt` had three variants at that point; **RD-F17
  (2026-09-20) deleted `ZeroTarget`** — zero is CEN-D6's refusal, a verdict —
  so RD-Q4's arm→SI-row mapping covers two, and records the overflow arm as
  unreachable-by-fixture rather than dropping it.
- Crate description: *"form (stateless) then validate (view-bound)"*.

**`d6ba4d98f` — `chain-store: connect compares the rule set, not only its
id`.** `ChainValid` now carries the `RuleSet` (`verdict.rs:115`
`rule_set()`, `:122 rule_set_id()`); `connect` resolves `in_force: RuleSetId`
through `RuleSet::for_id` over `ISSUED` and compares **by value**
(`connect.rs:347`–`:362`). Fixture: `fakechain(7)` handed to `connect` with
`GENESIS` in force is refused `RuleSetNotInForce`. Correct for that case — and
it exposes **RD-F13**: as merged, **a Fakechain verdict can never connect at
all.** `for_id(GENESIS)` yields the public GENESIS set, which compares unequal
to any `Fixed` set, and there is no id that names a Fakechain set because
Fakechain reuses `RuleSetId::GENESIS` by design. `RuleSchedule::rules_at(h)
-> RuleSetId` (`rule_set.rs:283`) cannot name it either. So RD-Q7's owed
wiring has a blocked leg on the *store* side, not only the daemon's: the
`in_force` parameter's type cannot express the set the driver's schedule
names. **RD-Q10** poses the fix. The conversion-ban gate's clause 3 now
matches an unqualified `Corrupt(_)` arm (`FAULT_ARM_TOKEN`); the ingest crate
is outside the store path, so it is not subject to clause 2, but clause 3's
discipline applies to it by intent — the pipeline never maps a fault onto a
verdict.

**RD-F6 discharged:** `rust/shekyl-difficulty/src/seed_epoch.rs` exists on
`dev`; `shekyl-pow-randomx/src/seed_epoch.rs` is gone. §3.2's citation is now
the tree's.

**Swept at `fbc92287a` (#786 S-TX, #795–#798 PDM sweeps; Rust/C++ tree
unchanged since `6c41bf820`):** `DRS_E1_STX.md` records that #788 answered
S-TX's E2 question — E2 projects **no tx table** (its redb-side reads are
`block_info` hashes, `key_images`, the live root; RD-F5) — and states the
coupled reopen criterion: a later E2 increment that projects tx tables names
*together* the row it needs and the order it needs it in. Acknowledged here;
nothing in this plan projects one. #786 also put `shekyl-chain-rules`'
`harness` feature under `check_test_only_features.py` as a TEST_ONLY row
(dev-dependency edges only) — the contract §8.8 of `CHAIN_RULES_CRATE.md`
states is now gated, and the ingest crate must not enable it.


### 3.8 Design inputs from the memo (REVIEW INPUT — not ruled; feed Round 1)

- **Pipeline stage shape** — §1.1's diagram and supervision map; composition
  is RD-Q11; the source event model (the diagram's height-ordered stream
  cannot express a reorg) is RD-Q13.
- **Two more corpus families.** *Mutations*: systematic invalidations of a
  valid corpus — header flips, wrong reward, reordered transactions, double
  spend, bad seed, **future timestamp** (which closes §5's FTL row) — with
  **spec-first expected verdicts**, a regtest C++ daemon as *secondary*
  evidence only (§1.3: evidence, not target). *Reorgs*: forked branches
  through `pop` + `connect`, digests after each switch — the only family that
  exercises the pop path. Both are `Source` implementors (§1.1); both land
  after the corpus source proves the loop (RD-Q8's sequencing).
- **`Stale::Seed`, grounded** (the RD-Q3/RD-Q5 fix): `fault.rs:70` (the arm),
  `block.rs:132` (the claimed seed on `StructurallyValid`) — verified at
  `306af9bae`. In replay of a fixed chain any occurrence is a driver defect:
  record and surface the first; exercise the retry path by an
  injected-wrong-seed test; the live-mode DoS bound (slice 2 Q8) is untouched.
- **JIT consequences.** Verification is `shekyl-pow-randomx` everywhere
  including the driver — never the JIT in replay, or E2 tests a hasher
  production doesn't run. **`PowHash`'s distinctness from `BlockHash`** (#785)
  is the type seam the parity gate asserts across (RD-Q12).

### 3.9 The trace artifact — layout (increment 2, §7 commit 4b)

The corpus's layout is the corpus module's (`corpus.rs`, format v2 with the
`rewind` record). The trace is the LMDB side's contribution, Rust-minted
and versioned like the corpus; little-endian, fixed widths; every violation
a `TraceFault` naming what it found.

| Field | Layout | Notes |
| --- | --- | --- |
| header | magic `"SHKTRACE"` ‖ version u8 ‖ reserved[7] = 0 | version bump on any layout change; a reader refuses every other value |
| **facts** × n | tag `0x01` ‖ `height` u64 ‖ `weight` u64 ‖ `long_term_weight` u64 ‖ `coins_generated` u64 ‖ `burned` u64 ‖ `root_after`[32] ‖ `long_term_effective_median` u64 ‖ `cumulative_difficulty` u128 | one 88-byte row per height, consecutive from the first; the six passed-through `ConnectFacts` fields + the accumulator SI-10 reads; `Trace::borrow(h)` yields `Borrowed<Facts>`, convertible only into `ConnectFacts` with every origin `PassedThrough` |
| **checkpoint** × k | tag `0x02` ‖ `height` u64 ‖ `digest`[32] | the **outer** `digest_v0` of the LMDB state at `height` — `TraceWriter::push_checkpoint_families` computes it from the three families with the function the redb read uses, so the C++ never hashes; anchored (its height has a facts row), unique; `Trace::expect(h)` yields `Expected<Digest>` for the grader only. The exporter writes one, at the tip (RD-F18) |
| trailer | tag `0xFF` ‖ `n_facts` u64 ‖ `n_checkpoints` u64 | both counts re-derived by the reader |

Tag `0x03` (**Verdict**, the mutation family's expected verdicts, §7 item 8d)
is RESERVED: named here so the byte is not re-minted, no code until that PR
(rule 23).

## 4. Questions — Round 0 defaults, with the 2026-09-19 rulings in-line

| Q | Question | Disposition | Why |
| --- | --- | --- | --- |
| **RD-Q1** | **Home.** | **RULED (memo §2): the new crate is the production ingest crate**, depending on rules + store + `shekyl-pow-randomx`, with the replay driver as its first `src/bin/`; corpus/trace format types live in this crate (or `shekyl-store-codec` once CTS PR A lands), never in a binary. **Its name is Q-A → default `shekyl-chain-ingest`** (REVIEW INPUT; adopted unless Round 1 objects). *Round-0 default was `shekyl-chain-replay`, "a test tool" — same dependency shape, different life expectancy.* | The store crate is `#![deny(unsafe_code)]`; it names `ChainValid` (the accepted verdict is `connect`'s input) but **neither RandomX, nor the refusal type `InvalidBlock` (conversion ban clause 2), nor the validator's `Substrate` types**. The one `Fault` payload it names is `Corrupt`, at `WriteBatch::refuse_corrupt` (RD-Q4) — the halt consequence of a store invariant the validator observed. It names no other `Fault` arm, never `Stale`, never `InvalidBlock`. The pipeline keeps hashing and the rest of the fault taxonomy out of the store, and G1 trivially true. |
| **RD-Q2** | **Block, body and fact source** (§3.4). | **RULED (memo §2): corpus + trace, with typed doors.** **Corpus** — *network-shaped only*: per height, the block plus full transaction bodies in header order (what `Candidate` consumes, `block.rs:88`–`:93`), taken from an **unpruned** node, its completeness **verified per height** against the header's `tx_hashes` (count, order, hash — RD-F15) and refused on a shortfall; format minted in Rust, versioned — the Monero bootstrap/epee container is **not** extended (rules 42/16); **zero C++** — the existing block-by-height read suffices. **Trace** — the six facts, cumulative difficulty, digest checkpoints, and (later) verdicts — produced by **one** C++ exporter shim that walks LMDB and hands bytes to a Rust writer, deletable in the same commit that deletes the daemon. **The doors are the grader's law:** `expect(h)` feeds *only* the grader; `borrow(h)` feeds `connect` for facts Rust does not derive yet, keyed off `Fact::origin` — a borrowed value is never evidence (RD-Q6). RD-F1's option matrix collapses to this; RD-F2 dissolves — no LMDB crate enters the workspace. *Round-0 default (c) withdrawn (RD-F9).* | Byte transport across the FFI is what D12 allows; verdicts are what it rejected. The digest walker (`logical_state_digest.cpp` → FFI) is the existing shape. Two doors with different types make "the grader read a borrowed fact as evidence" a compile error, not a review catch. |
| **RD-Q3** | **Production `Substrate`.** | **Default holds with one correction:** two-cache `CacheStore` keyed by the chain's seed at `seedheight(h)`, swapped at epoch boundaries; wall clock. *Round 0 called the retry loop "load-bearing" at the boundary; **withdrawn** (RD-F10) — the driver takes the seed from the chain it replays, so a `Stale::Seed` cannot arise from a correct driver; it is a defect signal (RD-Q5).* Throughput: parallel `form` workers over per-worker `compute_hash` (§1.1; the pool is not production, RD-F14) now; the Rust dataset mode is an **open option gated on a measurement E2 itself produces** — the pipeline's metrics sink records light-mode wall-clock per hash and per block, which is the number `RANDOMX_V2_MINING_ASYMMETRY.md` option (a) has been waiting for (RD-F11); never the JIT (§1.3). **Memo Q-C answered here:** checked at source — `shekyl-pow-randomx` does not expose full-dataset verification (`Cache::derive_item`, `cache.rs:449`; no public dataset builder) and cannot "cheaply" grow one inside this increment (it is the RandomX lane's and a 2 GiB-per-epoch provisioning question, rule 76); so parallel `form` is the win now, and the benchmark this pipeline emits is what decides the rest. **Caveat:** C1's FTL leg reads the clock and a historical block is always below `now + FTL`, so replay cannot exercise C1's refusal — recorded in §5. | Reuses the daemon's cache lifecycle; the epoch boundary is where a stale cache would silently produce wrong longhashes, and that now surfaces as a defect, not a retry. |
| **RD-Q4** | **`Fault::Corrupt` at the store.** | **RULED as defaulted:** `WriteBatch::refuse_corrupt(Corrupt) -> StoreError`, inside the batch, arming the poison at the noted height with a `StoreInvariant` row mapped from the `Corrupt` arm (new SI rows minted with it), returning the `InvariantViolated` the pipeline propagates. Minted here **with its caller** — the commit-9 scope #785 shed, as ruled 2026-09-19. | The validator saw what a belt would have; the store's halt is the consequence and must poison *this* batch. Taking the value keeps the store from naming `CenRow`s it does not own. |
| **RD-Q5** | **The retry loop and `Stale::Seed` in replay.** | **RULED:** the loop lives in the pipeline (`form` → `validate`; on `Stale::Seed` re-`form` with the expected seed and `attempt.next()`; `Exhausted` → terminal run error). **In replay every `Stale::Seed` is a driver defect: the run records and surfaces the first occurrence rather than retrying it away**, and **the retry path is exercised by a test that injects a wrong seed**, not by waiting for a bug. The live-daemon role (slice 2 Q8's DoS bound) is unaffected. | Resolves the RD-Q3/RD-Q5 contradiction Round 0 carried (RD-F10). |
| **RD-Q6** | **Grading.** | **RULED as defaulted, plus the grader's law (memo §2):** Python extractor → JSON → the pure Rust grader, reusing `drs_artifact.py`'s schema discipline. **A borrowed value is never evidence** — a row sourced from a borrowed fact (`Fact::origin == PassedThrough`, reached through `borrow(h)`) grades not-evidence, never CHECKED-CONFORMANT (RD-F7). As slices derive facts, rows flip to real evidence **with no harness change**; **progress is the count of derived-and-conformant rows.** Adjudication semantics (one sentence, also in the grader doc — `CONSENSUS_STORE_RECONCILIATION.md` §5.4.1): the trace is evidence, not a target; a divergence resolves to *fix Rust* or *`ReviewedDivergence` with Rust canonical* — no third arm; tainted trace rows are annotated; fixtures re-baseline from Rust after cutover, becoming permanent regression gates. RD-Q9's producer/consumer split refines *which* rows the law reaches. **BUILT 2026-09-20 (increment 2, §7 commit 7):** the extractor is the coverage gate's own parse serialized and self-tested against its tally; the grader emits both RD-Q9 clauses per row; `passes()` is §1.3's condition; the first real runs graded 11 rows derived-and-conformant with 0 unadjudicated. | The register is prose Python already parses (`check_conformance_coverage.py`); the grade is reproducible from the artifact alone. |
| **RD-Q7** | **Fakechain wiring.** | **RULED as defaulted:** the driver takes `--fixed-difficulty n` → `RuleSet::fakechain(n)`, refused unless the nettype is regtest; the `Network::Fakechain` witness stays its own change (12 files / 9 crates; slice 2 F10). **BUILT 2026-09-20 (increment 2, §7 commit 6b):** `schedule::ChainRules`; the flag refused off regtest by construction; a fakechain corpus replays and connects; the 2301-block regtest run ran under `fakechain(1)`. | The consumers need the lever, not the witness. |
| **RD-Q8** | **First chains.** | **RULED as defaulted:** regtest (the `e2e_fcmp_spend_accepted_by_daemon` fixture, ~80 s), then a testnet snapshot past `N` **and** a seed epoch (≥ 2113 blocks). | Only a chain past 2112 exercises the cache swap and D3's roll-over against real data. |
| **RD-Q9** *(Round 1 question, posed 2026-09-19 — must be answered before commit 7, grading)* | **RD-F7's edge: producing a borrowed value vs consuming one as an oracle.** `root_after` is passed through, so the digest's `curve_root` component is worthless as evidence — but CEN-B5's equality check (candidate header root == recorded root at `h`) still **refuses a wrong header** against that borrowed value. Does "rows sourced from passed-through facts grade not-evidence" apply to rows that *produce* the borrowed value (the SCW-19 root write, the weight folds, the coin fold) only, or also to rows that *consume* one as an oracle (B5's equality; C-rows reading recorded timestamps are unaffected since timestamps are real)? | **RULED 2026-09-19 — producers only, stated as two clauses so both subjects are in the sentence: (1) the rule's verdict grades on its own evidence; (2) the digest component it feeds grades not-evidence.** "Producers only" alone would be quoted as *B5 grades as evidence*, which is false on the parity axis — B5's *refusal* is real (a wrong header is refused against the borrowed oracle), B5's *root component* in the digest is a copy. A consumer row is a real check whose oracle happens to be borrowed; producers (the rows whose output *is* the passed-through value) grade not-evidence until Rust derives them. The grader carries both subjects as typed fields on the row — verdict-evidence and component-evidence — not one recoverable from the other. **BUILT 2026-09-20 (increment 2, §7 commit 7)** as `VerdictEvidence` / `ComponentEvidence` on `GradedRow`; B5 shows both at once — its verdict counts (a consumer's real check) while its component is `Borrowed { field: "root_after" }`. | This split decides how many rows actually grade not-evidence — under "producers only" it is the six facts' deriving rows (CEN-G6/G6b, F13/F14/F14b, F17/G11, B5's write half via S-CURVE, I12); under "consumers too" B5 and every rule reading a recorded fact joins them. The grader needs the distinction as a typed origin on each row's oracle, not a comment. |
| **RD-Q10** *(Round 1, posed 2026-09-19 from the sweep; decides RD-Q7's store leg)* | **`connect`'s `in_force` cannot name a Fakechain set** (RD-F13). `connect(valid, facts, in_force: RuleSetId)` resolves the id through `for_id` over `ISSUED`; Fakechain reuses `RuleSetId::GENESIS`, so no id reaches a `Fixed` set and a Fakechain verdict is always refused `RuleSetNotInForce`. What does the driver's schedule hand `connect`? | **Default: `connect` takes the in-force `RuleSet` by value — `in_force: RuleSet` — and compares by `PartialEq` exactly as `d6ba4d98f` already does after resolution; `RuleSetUnknown` moves to where the id is resolved (the schedule, `RuleSchedule::rules_at`), which is the layer that owns the id→set mapping.** The CEN-B3 belt (`hf_versions[h] = in_force`, `connect.rs:441`) stores `in_force.id()`, unchanged on disk. A schedule that can *name* Fakechain (a `RuleSchedule::fakechain(n)` whose `rules_at` yields the set, or `rules_at -> RuleSet`) is the driver-side half and lands with RD-Q7's flag. **RULED 2026-09-19 as defaulted, plus a pointer at the belt:** under `DifficultyRule::Fixed` two different Fakechain sets both carry `RuleSetId::GENESIS` — the caveat already on `Fixed`'s doc (`rule_set.rs:111`–`:116`: id equality is not a proxy for set equality) — and the belt is the single most likely site for someone to use it as one. Commit 6 cross-references the caveat **from the belt's comment**, not only from the variant. | Rule 71 holds: the store still carries no schedule and no `Network`; it receives a value and compares. The alternative — minting a distinct `RuleSetId` for each Fakechain set — was already refused when slice 2 Q10 chose to reuse `GENESIS` (an id space for operator-chosen difficulties is nonsense), and a `RuleSetId::FAKECHAIN` sentinel would need the id→set resolution to consult something other than `ISSUED`, i.e. exactly the value the default passes. Falsify the finding's premise by `rg 'RuleSetId::FAKECHAIN\|fakechain' rust/shekyl-chain-rules/src/rule_set.rs` showing an id that `for_id` resolves to a `Fixed` set — none does at `93f91b0d4`. |
| **RD-Q11** *(memo Q-B, REVIEW INPUT → posed for Round 1)* | **Composition.** `kameo` (the workspace precedent, exact-pinned `=0.20.0` in engine-core) vs plain `tokio` stages; rule 25 is silent on actor frameworks. | **Default (memo's): `kameo` for the one stateful actor — Validate+Connect, which owns the write transaction — and plain tasks + bounded channels for Form workers (each over its own `compute_hash` call, RD-F14), the Sequencer and the Sinks.** | The only state in the pipeline is the batch; an actor earns its keep exactly there (mailbox = the single-writer queue; supervision = the halt). Stateless stages under an actor framework would be ceremony. Rule 17: `kameo` is already a workspace dependency at a pinned version; no new edge. **RULED 2026-09-19 as defaulted, with the supervision policy stated as terminal:** actor frameworks default to restart-on-failure, and a `Fault::Corrupt` halt must be **terminal** — the writer stops and stays stopped. An actor that restarted after a halt would silently convert a store-invariant violation into a retry loop, the same failure shape as mapping it onto `InvalidBlock`. The Validate+Connect actor's supervision policy is **no-restart**, and commit 5 tests it: halt, then assert the actor does not come back. |
| **RD-Q13** *(Round 1, posed 2026-09-19 from review — a height-ordered stream cannot represent a reorg)* | **The `Source` event model.** §1.1 as first drawn showed blocks flowing in height order into a sequencer and a single connect actor, with no pop or branch-switch event; yet the reorg family is said to exercise `pop`, and E3 is said to need only a source swap. What does a source emit, how are events ordered, and how does `form` get the *fork's* seed context? | **Default: `IngestEvent::{Extend(CorpusBlock), Rewind { to: BlockHeight }}`, totally ordered by a source-assigned sequence number.** The Sequencer restores that order after parallel `form` (it never reorders across a `Rewind`; a `Rewind` is a barrier — formation of `Extend`s after it waits for it to commit, because their seed context depends on it). The actor executes `Rewind { to }` as `pop` until the tip is `to`, then `Extend`s connect at `to + 1…`. **Seed context:** `form`'s seed claim for an `Extend` after a `Rewind` is the block at `seedheight(h)` on the **post-rewind** chain — the driver knows the fork it is replaying and claims accordingly; a `Stale::Seed` here is still a driver defect (RD-Q5). Sinks observe both event kinds: the digest sink records after each `Rewind` commit (the "digest after each switch" the reorg family needs). Who *decides* a rewind is the source's business — the reorg fixture scripts it; E3's p2p source computes the heavier-chain switch (the daemon's alt-chain logic) and emits it; the pipeline only executes. **BUILT 2026-09-20 (increment 2, §7 commits 5 and 8c):** barrier in the pipeline, `Rewind` message on the actor, the corpus `rewind` record (format v2), `RunReport::switches` with the post-pop digest; the reorg fixture replays through the real reader. | Without `Rewind` the reorg family has no way to drive `pop`, and E3 would need a second ingest path — exactly the disease §1.1 exists to prevent. Two variants, one barrier rule, is the smallest model that makes the source-swap claim true. |
| **RD-Q12** *(memo Q-D, REVIEW INPUT → posed for Round 1; owner the RandomX lane, recorded here because §0 created the obligation)* | **The parity gate's CI home** for §0's "permanent gate re-run on either pin's move, plus `longhash` fuzz across `randomx-v2-sys`." | **Default: `randomx-v2-differential.yml` is already the home** — verified at `306af9bae`: its `push`/`pull_request` `paths` include `external/randomx-v2/**`, `rust/randomx-v2-sys/**`, `rust/shekyl-pow-randomx/**`, `Cargo.lock` (`:82`–`:88`, `:96`–`:100`), so the re-run-on-either-pin half is **mechanically true today**. What promotion adds: (i) the workflow's header, which frames the vector set as rewrite scaffolding with a V3.0 deferral, re-framed as the permanent verifier↔JIT parity obligation with §0 as its authority; (ii) a `longhash` fuzz job across `randomx-v2-sys` (random blobs × pinned seeds, both sides, asserting equality) on the daily cron; (iii) the type seam it asserts across is `PowHash` (distinct from `BlockHash` since #785) — the fuzz compares `PowHash`es, not bytes. **BUILT 2026-09-20 (increment 2, §7 commit 8b):** the workflow header states the permanent obligation; the rotating lanes are the fuzz job; `three_leg_verdict` compares `PowHash`es. "The RandomX lane" existed in no form (rule 22's owner test), so it landed in E2. | The gate exists and fires; only its *meaning* and one job are missing. A second workflow would split the record. **RULED 2026-09-19 as defaulted, plus fuzz hygiene:** random blobs on a daily cron produce failures nobody can reproduce unless the generator's seed is logged and the failing input is emitted as an artifact — without that it is an alarm, not a gate, and a parity obligation that fires irreproducibly gets muted. The fuzz job **logs its seed on every run and dumps the blob and both `PowHash`es as a workflow artifact on mismatch**, so an inequality is actionable, not merely alarming. |

## 5. Test deviations (F12's first live section)

| Deviation | Reason | Reopen / falsify |
| --- | --- | --- |
| C1's FTL refusal is not exercised by corpus replay | historical blocks are always below `now + FTL` | **closed by the mutation corpus family's future-timestamp case** (§3.8, REVIEW INPUT) once that family lands; until then the row stands open |
| `--fixed-difficulty` on regtest runs (RD-Q7) | the bench needs real RandomX cost at a reachable target | production nets refuse the flag by type (`for_network` cannot yield `Fixed`, pinned) |
| `drs_bench.py`'s lowered target | benchmark reproducibility on the provisioning floor | the artifact records the target; `drs_artifact.py` refuses cross-condition ratios |
| The redb file's `Provenance` is NOT-PARITY-EVIDENCE throughout E2 | six facts passed through; enforced rows unimplemented | `passed_through().count() == 0 && coverage_gaps().is_empty()` — the genesis gate |
| **Pruned corpus source — NOT PERMITTED** | bodies are the validator's input (RD-F8); a pruned source silently yields **fewer bodies than the header lists** (RD-F15) | the corpus writer verifies count / order / hash against `block.tx_hashes` per height and refuses a shortfall naming the height; the reader re-verifies the recorded state. If a pruned-source run is ever allowed, it enters this table as a deviation with its own reopener first. |

## 6. Findings

- **RD-F1 — the daemon RPC cannot source the driver's facts.** `coins_generated`,
  `burned`, `long_term_effective_median` are LMDB-only (§3.4); computing them
  in the driver is a C2-R8 Q4 violation. Its option matrix **collapsed** to
  RD-Q2's corpus + trace (memo §2).
- **RD-F2 (DISSOLVED, memo §2) — no LMDB crate in the workspace.** A Rust
  LMDB reader would have been a new dependency needing rule-17 verification
  first; under RD-Q2 the one exporter reads LMDB in C++ and hands bytes, so
  no LMDB crate enters the workspace. Closed, not deferred.
- **RD-F3 — six items routed to a lane that did not exist.** Individually
  legitimate deferrals; in aggregate an unchosen queue (rule 22). This file is
  the repair; the generalization is RD-F4.
- **RD-F4 (LANDED, §7 commit 0, 2026-09-20) — the gate: a deferral's owner
  must resolve.** `scripts/ci/check_followups_owners.py`: every FOLLOWUPS row
  carries `Owner:` resolving to a live `docs/design/` document or a
  registered index-§2 family (read through the prefix gate's own registry
  reader); pre-existing rows grandfathered by exact heading in a list that
  only burns down — **338 at the gate's birth, 340 after the merge with
  #792/#800 landed three pre-gate rows** — under a `GRANDFATHER_CEILING`
  ratchet in the script (a longer list is refused; a ceiling more than five
  above the list is refused, so the burn-down locks in); doc paths are
  canonicalised beneath `docs/design/` so `design/../completed/` cannot pass
  as live; selftest of sixteen cases; wired in `docs-gates.yml`.
  **One narrowing of the memo, stated so it is reviewable:** the memo listed
  "an open PR" among resolvable owners; the gate does not accept a PR number
  alone — PRs merge and close, and a row whose only owner is a merged PR is
  the shape the gate exists to catch; a PR may be cited beside the doc or
  family it lands in. Rules 95 and 22 amended to carry the cell. *(As
  proposed:)* endorsed 2026-09-19 as a standing check. Every `FOLLOWUPS.md` row's owner must
  resolve to a live `docs/design/` doc, an open PR, or an index-§2 family.
  Same family as `held_by_cxx` asserting its holder exists. **Falsify by**
  `scripts/ci/check_followups_owners.py` existing and refusing a row whose
  owner is "the E2 lane" with no `DRS_E2_*.md` present. **Carrier (rule 22 —
  a slot in this ruled plan, not "a small PR later"): §7 commit 0**, the
  first commit of the implementation phase, ahead of `refuse_corrupt`. What
  it must settle first, named so the slot is not a hiding place: FOLLOWUPS
  owners are prose today (*"owner **the X lane**"*), so the gate's first job
  is the parse — an `Owner:` sub-bullet beside `Target:` — with existing rows
  grandfathered by exact hit and burned down, the shape `check_test_only_
  features.py`'s `GOVERNED_OWNERS` grandfather list took in #786. Target
  pre-genesis.
- **RD-F5 — the redb-side digest assembly does not exist.** `digest_v0` has one
  caller, fed by C++. E2 needs the same three families read from the redb
  file — `ReadSnapshot::logical_state_digest_v0()` or a pipeline-side assembly
  over the existing reads. Owed to this increment.
- **RD-F6 (DISCHARGED 2026-09-19) — the seed schedule's home moved under this
  file** (#785). Merged; `shekyl-difficulty/src/seed_epoch.rs` is the tree's
  (§3.7).
- **RD-F7 (review, 2026-09-19) — one of the digest's three components compares
  a value with a copy of itself.** `connect` writes `curve_tree_roots[h+1] =
  facts.root_after`, a passed-through fact read from LMDB, so the redb digest's
  `curve_root` is LMDB's root copied in; identity there is guaranteed and
  carries no evidence. Only block hashes and spent keys come from real replay.
  **Generalises:** any register row sourced from a passed-through fact
  (weight, `coins_generated`, burned, the median, the root) cannot be graded
  CHECKED-CONFORMANT by E2 — the grader rule in RD-Q6, and §8 names which
  components and rows are real.
- **RD-F8 (review) — the source must carry the transaction bodies, from an
  unpruned node.** `Candidate.transactions` is the validator's input; spent
  keys, outputs and leaves come from bodies. The corpus artifact declares its
  prune state and is refused on mismatch (§3.4, §5).
- **RD-F9 (review) — Round 0's RD-Q2 default extended an inherited format.**
  `bootstrap_file.cpp` is Monero's epee-serialized container; a Rust reader
  of it plus facts is a second parser of an inherited format (rule 16).
  Withdrawn for the Rust-minted trace format (RD-Q2).
- **RD-F10 (review) — RD-Q3 and RD-Q5 contradicted each other on
  `Stale::Seed`.** Q5 was right: in replay a seed change is impossible from a
  correct driver, so the arm is a defect signal, recorded and surfaced, with an
  injected-wrong-seed test exercising the path (RD-Q5).
- **RD-F11 (review's throughput item; corrected 2026-09-19, then RULED) —
  dataset mode unbuilt pending measured need; the replay driver is the first
  instrument capable of measuring it; the benchmark is part of its
  deliverable.** What stands as fact about the code: `Cache::derive_item`
  (`cache.rs:449`) is the per-item path and no public dataset builder exists.
  What this finding first got wrong: it read `RANDOMX_V2_RUST.md:544`
  (*"verifier code does not use the full 2 GiB dataset"*) as a ruling and
  wrote a rule-21 reopener — a description of current implementation read as
  a prescription (rule 16's corollary, the family's *mood* variant, recorded
  there). The dataset path was left unbuilt to **measure** whether the daemon
  needed it (§4 of that plan lists `Dataset::derive(cache)` as planned;
  `RANDOMX_V2_MINING_ASYMMETRY.md` option (a) revisits on the measurement, and
  none exists). **Disposition — stronger than a reopener:** the postponed
  decision's input is exactly what this increment produces. Replay-that-
  validates is the first workload that runs RandomX verification at volume
  over a real chain, so the measurement arrives *with* the driver: the
  pipeline's metrics sink records light-mode wall-clock per hash and per block
  on the provisioning floor, and that artifact is inventory item 7 and part
  of §8's record. Upstream's full-memory mode is ~10× faster per hash for a
  ~2 GiB init that amortises over a long replay; whether Shekyl wants it is
  decided on the number, by the RandomX lane. Line 544 amended so it no longer
  reads as a ruling. The JIT is never the lever (§1.3). *Same correction the
  driver deferral itself just received, one level up: an item pointed at
  nobody becoming an item pointed at the thing being built.*
- **RD-F17 (increment 1 review, 2026-09-20) — LWMA-1 has no output floor;
  zero is reachable from a conforming chain; slice 2 mis-filed it as
  corruption.** The reviewer's strict SI-10 walk (`0476a22ab`) made slice 2's
  zero-target fixture unreachable *as written* (an all-zero window is now a
  `NotMonotone` before LWMA runs), which forced the question the fixture had
  been standing in front of: can the formula itself derive zero? It can.
  `lwma1_next`'s tail is `avg_D · 99·N·(N+1)·T / 200·L` with no floor
  (`lwma1.rs:176`–`:206`); with every solvetime at the `+6T` clamp,
  `L = 6T·N(N+1)/2 = 2 948 400` and the output is **zero for `avg_D ≤ 6`**,
  `400 → 66` per maximally slow window — a conforming chain walks there in
  a few windows (computed 2026-09-20; fixture
  `cen_d6_a_slow_window_of_minimal_work_derives_zero_and_refuses_the_block`).
  Three consequences. (1) The census CEN-D6 row's premise — *"the value can
  only be 0 via a difficulty-function sentinel return"* — is false of the
  implementation; amended on the row. (2) Slice 2 classified zero as
  `Corrupt::ZeroTarget`, and this increment's commit 1 mapped it to SI-10 —
  which would have **halted the redb writer on a chain whose work strictly
  increased**, while the C++ merely refuses the block (`blockchain.cpp:5494`).
  A misclassification, repaired: `Corrupt::ZeroTarget` deleted, `D6::mint`
  returns the CEN-D6 verdict, `refuse_corrupt` maps two arms; the store never
  sees a zero target. Parity restored; the premise slice 2 Q4 rested on is
  refuted, not superseded (rule 16). (3) **The consensus finding itself is
  not this lane's to rule:** a DAA that can derive zero, at which point every
  successor block is refused, is a chain-death mode in the ratified
  algorithm. Whether CEN-D6 becomes a floor of 1 (a consensus change to a
  CLOSED plan, `docs/completed/DAA_LWMA1.md`) or stays a refusal is the DAA
  owner's ruling — FOLLOWUPS row, `Owner:` the census document that holds the
  rule, falsifier the fixture above (`lwma1_next` returning zero over a
  strictly-increasing window). Rule-47 lesson recorded in
  `CHAIN_RULES_CRATE.md` §4.4: beside "fold into a type" and "keep the
  refusal", the adversarial-input test has a third outcome — **re-classify**.
- **RD-F20 (first real run, 2026-09-20) — the derive counter counted
  callers, and the driver never pinned a canonical epoch.**
  `CacheStore::lookup_or_derive` dedups a novel seed's contenders into one
  leader and waiting followers; an instrument that wrapped the call recorded
  32 "derives" of ~370 ms on a chain with two seeds — one fill and 31 waits
  for it. `CacheStore::lookup_or_derive_reporting` now says how a call was
  served (`CacheOutcome::{Hit, Derived, Waited}`) and the substrate counts a
  derive only on `Derived`, waits apart. Second half: `CacheStore` has two
  slots and the driver used only the transient one, so the two live seeds of
  a lag window fought over it and window 16 re-derived; `EpochPin` pins the
  claimed seed as canonical whenever it changes. After both: 2 derives on
  301 blocks, 3 on 2301 (one per seed), 0 waits, at every window.
- **RD-F19 (commit 6b, 2026-09-20) — there is no Fakechain seed-epoch
  override for the driver to take, and a regtest daemon run with one produces
  a chain the validator refuses by design.** The validator derives the seed
  height with the mainnet constants at every nettype and reads no environment
  (slice 2 F5, CEN-D3); the `SEEDHASH_EPOCH_*` fast-epoch lever lives only at
  the C++ FFI boundary. So the driver claims seeds on `SeedSchedule::MAINNET`
  unconditionally — a faster claim would earn `Stale::Seed` at every block —
  and the seed schedule is not a `PipelineConfig` knob (rule 21: a knob no
  honest run can use). Commit 8's regtest daemon was started without
  `SEEDHASH_EPOCH_*`, and the 2301-block run crossed the real 2112 boundary.
  Falsify by `rg 'SEEDHASH_EPOCH' rust/shekyl-chain-rules/` finding a read.
- **RD-F18 (commit 4b, 2026-09-20) — LMDB holds the spent-key set only as of
  the tip, so a trace checkpoint can be taken only at the tip.** The C++
  `spent_keys` table is the live set; there is no per-height snapshot to
  digest at an interior height, and a checkpoint written there would carry a
  set the C++ never had at that height. The exporter writes one checkpoint,
  at the tip (observed: `--block-stop 300` on a 2301-block chain wrote none
  and the replay digested nothing); the pipeline compares a checkpoint the
  first time its height is the tip, which under reorgs means a fixture's
  checkpoint sits beyond every pre-switch tip (8c).
- **RD-F16 (implementation, 2026-09-20) — the rules harness's blocks do not
  round-trip through bytes.** `harness::fixture::coinbase` builds a miner tx
  with **no inputs**; `Block::read` refuses it (*"block miner tx must have a
  sole gen input (coinbase, §2.5)"*). Every rule fixture passes blocks as
  values, so nothing noticed; the corpus reader — the first consumer that
  parses harness blocks from bytes — would refuse all of them. Not a defect
  in what the harness tests (rules never read the miner tx's inputs at this
  pin), but a gap the store's fixtures do not share (`connect_fixtures::
  coinbase` carries `Input::Gen`). Owner: the rules crate; falsify by
  `Block::read(&harness::fixture::candidate(vec![]).block.serialize())`
  returning `Ok`. Recorded, not repaired here (rule 15's scope discipline);
  the corpus tests build wire-valid fixtures of their own.
- **RD-F15 (review, 2026-09-19) — a pruned RPC source fails silently, so the
  corpus writer verifies rather than declares.** `BlockEntry { block, txs }`
  carries no prune flag (`bin_commands.rs:201`–`:220`) and the handler drops
  `get_transactions`' `missed` vector (`rpc_facts_ffi.cpp:1053`–`:1061`), so a
  pruned node returns a block with fewer bodies than its header lists and no
  signal. RD-F8's "declares its prune state" was insufficient: the writer
  parses the block and requires count, order and hash of the returned bodies
  to match `block.tx_hashes` before recording the height as unpruned; a
  shortfall refuses, naming the height. Same shape as RD-F14 — a Round-0
  claim about a source, corrected by reading the source.
- **RD-F14 (review, 2026-09-19) — `VmStatePool` is not a production API.**
  `shekyl-pow-randomx` compiles and re-exports `VmStatePool` /
  `compute_hash_with_pool` only under `cfg(any(test, feature =
  "internal-pool-bench"))` (`lib.rs:190`, `:204`; the feature is bench
  scaffolding per `RANDOMX_V2_PHASE2F_PLAN.md` §3.3). Round 0's pipeline
  sketch leaned on it as the parallel-`form` mechanism; as written that stage
  could not be built. Corrected: workers call `compute_hash` on a shared
  `Arc<PreparedCache>`; whether a bounded pool should become production is an
  explicit `shekyl-pow-randomx` change for the RandomX lane, decided on the
  benchmark this pipeline emits (RD-F11) — the same measure-first shape as the
  dataset mode.
- **RD-F13 (Round-1 sweep, `d6ba4d98f`) — as merged, a Fakechain verdict can
  never connect.** `connect` resolves `in_force: RuleSetId` through
  `RuleSet::for_id` over `ISSUED` and compares the set by value; Fakechain
  reuses `RuleSetId::GENESIS`, so the resolution always yields the public set
  and every `Fixed` verdict is refused `RuleSetNotInForce` — the fixture that
  proves the refusal is also the proof that no path accepts. `RuleSchedule::
  rules_at -> RuleSetId` cannot name a Fakechain set either. RD-Q7's owed
  wiring therefore has a store-side leg the review commit created while
  closing a real hole; **RD-Q10** poses the repair (the in-force `RuleSet` by
  value). The two consumers slice 2 Q10 named (`drs_bench.py`,
  `curve_tree_header_root_check.cpp`) are blocked on this as much as on the
  flag. Falsifier as in RD-Q10.
- **RD-F12 (ruling) — the mining JIT is the one permanent C++↔Rust boundary,
  with a standing obligation.** The RandomX parity corpus and
  `randomx-v2-differential.yml` become a **permanent gate** (full vector set on
  every pin move of either side; ongoing `longhash` fuzz across the boundary),
  and at cutover the FFI direction flips for this dependency alone — **behind
  the existing `randomx-v2-sys` boundary** (`rust/randomx-v2-sys`, a workspace
  member whose sole consumer today is `shekyl-randomx-differential`; memo §1
  corrects this finding's first text, which spoke of an adapter crate to be
  created), W^X confined to mining. Owner: the RandomX lane; recorded here
  because §0 created the obligation. CI home and what promotion adds: RD-Q12.
  Falsify by the workflow's header no longer reading as rewrite scaffolding
  and a `longhash` fuzz job existing across `randomx-v2-sys`.

## 7. Commit plan (Round 1 fixed it; increments marked)

**Increment 1 (this branch, 2026-09-20): commits 0, 1, 2, 3, 4a, 6** — the
gate, the two store APIs the pipeline calls (`refuse_corrupt`, the redb
digest), the crate with its event model and production substrate, the corpus
artifact, and the `in_force: RuleSet` repair. Each is a unit with its own
tests; none depends on an unbuilt stage. **Increment 2 (next PR): 4b, 5, 6b,
7, 7b, 8, 8b, 8c, 9** — the trace, the pipeline stages and actor, the flag,
grading, metrics, first runs, the reorg family, closing docs. The split is
by review size (rule 06), inside one ruled plan; every item keeps its slot.

0. `ci: check_followups_owners.py — a deferral's owner must resolve (live doc or index family; a PR alone is not an owner); Owner: sub-bullet convention; existing rows grandfathered by exact hit` (RD-F4) — **LANDED** (built alongside commits 1–6 while #792 held the FOLLOWUPS file; ordered first in this list because the lane it protects against is the one this plan was opened to repair).
1. **LANDED (`05ed7ac13`)** `chain-store: WriteBatch::refuse_corrupt — the validator's Corrupt arms the halt` (RD-Q4; SI-10 minted `built`; `CumulativeDifficultyOverflow` → SI-8; the FOLLOWUPS row now carries the owner and closes when the actor calls it). **Its commit message states that this is the API #785's commit 9 shed and why it waited: the deferral was circular ("no caller") until the caller was scheduled, and the API arrives with the driver that shapes it — value in, inside the batch — rather than guessed at from the store side.** A reader landing here from #785's FOLLOWUPS row gets the reason, not a reconstruction.
2. **LANDED (`bf0e020fd`)** `chain-store: ReadSnapshot::logical_state_digest_v0 — the redb half of E2` (RD-F5; live root = `curve_tree_roots[tip + 1]`, EMPTY on an empty chain; negative control).
3. **LANDED (`440ace308`)** `ingest: shekyl-chain-ingest scaffold — Source event model (Extend/Rewind, SequenceNo, barrier), production Substrate over compute_hash (no pool; RD-F14)` (RD-Q1, RD-Q3, RD-Q13). Stages land with their tests (increment 2).
4a. **LANDED (`d7c4c0631`)** `ingest: the corpus — Rust-minted, versioned; writer verifies count/order/hash against the header (RD-F15), reader re-verifies and is a Source` (RD-Q2, RD-F8, RD-F9). **En route, RD-F16:** the rules harness's `fixture::coinbase` has no inputs and does not survive `Block::read` — the harness's blocks never round-trip through bytes; the corpus tests build wire-valid fixtures of their own.
4b. **LANDED (increment 2)** `ingest: the trace — the six facts, cumulative difficulty, digest checkpoints; Rust-minted format; the LMDB exporter as a C++ harvest shim handing bytes across the FFI; the RPC corpus fetch feeding CorpusWriter` (RD-Q2). Trace layout §3.9. A checkpoint is the **outer** `digest_v0` (32 bytes) — the redb read returns no components, so a DIVERGE names the height, not the family; widening both sides is the diagnosis step (reopen on the first DIVERGE at a checkpoint on a real chain). The exporter writes **one checkpoint, at the tip** (RD-F18) and takes the daemon's `--regtest`; `--block-stop` below the tip writes no checkpoint (observed: 0 digested when heights 0–300 were exported from a 2301-block chain).
5. **LANDED (increment 2)** `ingest: form workers → sequencer → validate+connect actor (kameo, no-restart); Corrupt → halt, terminal — halt-then-assert-not-restarted test; Stale::Seed surfaced; injected-wrong-seed test` (RD-Q5, RD-Q11). The pipeline assigns heights (the source's `Extend` carries none); the ledger claims the mainnet seed schedule at every nettype (RD-F19); `RunReport::switches` carries the digest after each committed pop (§3.8). **Test order inside the commit: the no-restart test is written first, while the actor is three lines** — it is cheap then and awkward once supervision is configured and a channel is plumbed through; it is also the test most likely to be deferred as obvious, and the failure it guards (a halt laundered into a retry) is silent by construction.
6. **LANDED (`63aebab0f`)** `chain-store: connect takes the in-force RuleSet by value; RuleSetUnknown deleted (its consumer left the crate); RuleSetNotInForce carries the sets; the caveat at the CEN-B3 belt` (RD-Q10, RD-F13) — a Fakechain verdict now connects under the Fakechain set, fixture-pinned.
6b. **LANDED (increment 2)** `ingest: --fixed-difficulty → RuleSet::fakechain on regtest; a schedule that names it` (RD-Q7): `schedule::ChainRules` — `Scheduled(Network)` through `RuleSchedule::for_network(..).rules_at(h)` → `RuleSet::for_id`, or `Regtest { fixed_difficulty }` → `fakechain(n)` / `GENESIS` (the daemon's own default: `--fixed-difficulty 0` is *not fixed*); the flag refused off regtest by construction; read per block by `form` and `validate`. The binary `shekyl-chain-replay` (`fetch --chain`, `replay --chain --fixed-difficulty`) carries it.
7. **LANDED (increment 2)** `ingest: CSR-3a grading — extractor, artifact, the two-clause evidence rule (verdict-evidence and component-evidence as typed row fields, RD-Q9), grader wiring` (RD-Q6, RD-F7): `scripts/ci/export_conformance_register.py` serializes the coverage gate's own parse (`--selftest` in `docs-gates.yml` holds the tally equal to the gate's); `grader.rs` emits `shekyl_e2_grade_v1` with `VerdictEvidence` / `ComponentEvidence` per row, producers from `ConnectFacts::DELETED_BY`; `passes()` = no `Failed(..)` on either clause; `replay --register --grade-out` exits non-zero on an open adjudication. The inversion is live in the tests.
7b. **LANDED (increment 2)** `ingest: metrics sink — light-mode RandomX wall-clock per hash / per block; the dataset-mode measurement artifact` (RD-F11, item 7): `metrics::Metrics` / `MetricsArtifact` (`shekyl_e2_metrics_v1`), derives timed apart from hashes, waits apart from derives (RD-F20), the measuring host recorded; `replay --metrics-out`. **The number** (item 8 below): light mode, Rust interpreter, x86_64 16 threads (not the provisioning floor) — **0.60 s CPU per hash**; 0.64 s wall per hash at 16-wide (0.34 s at 1-wide: light mode is memory-bound and the per-hash wall grows with concurrency while throughput still rises); a cache derive 0.39–0.46 s; 2301 blocks in 93 s wall. Against the C light-VM-JIT baseline of 10–15 ms/hash (`RANDOMX_V2_RUST.md` §9) that is ~40×; `BENCH_RESULTS.md`'s single-thread interpreter median (~300 ms) agrees. Recorded, not judged: the dataset-mode decision reads this artifact.
8. `ingest: first runs — regtest fixture; testnet past N and a seed epoch` (RD-Q8); LWMA-window conformance recorded. **Regtest leg RUN 2026-09-20** (recipe below): `shekyld --regtest --fixed-difficulty 1` (from #803's build; **without** `SEEDHASH_EPOCH_*`, RD-F19), 2301 blocks mined by `generateblocks`; `shekyl-chain-replay fetch` → corpus (3.3 MB); `shekyl-e2-trace-export --regtest` → trace (223 KB, one checkpoint at 2300); `replay --chain regtest --fixed-difficulty 1 --register --grade-out --metrics-out --window 16` → **2301 connected, digest MATCH at 2300, 0 unadjudicated; 11 rows derived-and-conformant (A2, B1, B5, C1–C3, D1–D4, D6), 9 borrowed (the `DELETED_BY` producers), 120 not exercised; 3 cache derives** (genesis's NULL seed, block 0's for heights 1–2111, block 2048's from 2112 — the seed-epoch boundary crossed against real data, D3's roll-over and the canonical pin exercised), 0 waits. The 301-block prefix replays identically. **Testnet leg DEFERRED** — blocker: no testnet chain reachable from this host. Attempted 2026-09-21 against the Foundation seed fleet (`net_node.inl`'s six hosts, testnet P2P port): a `dev`-built daemon cannot handshake (the fleet runs alpha.8; `cryptonote_config.h` and `db_lmdb.cpp` moved since), and a daemon built from the `v3.1.0-alpha.8` tag has every handshake torn down by the peer too (`LEVIN_ERROR_CONNECTION_DESTROYED`, 178 attempts in 15 minutes, zero peers) — whatever the fleet runs, it is not reachable from either build. **Then, 2026-09-21, the LAN route:** the tag-built alpha.8 daemon peered with `skl-foundation` and `skl-miner-test` (`--add-exclusive-node …:12021`) and synced testnet to **7108** in eight minutes; `shekyl-chain-replay fetch --chain testnet` took all 7108 blocks (the corpus side is schema-free). The trace side is not: this branch's exporter refused the LMDB (*"Please run shekyld once to convert the database"*), and a current `shekyld --testnet --offline` over a copy refused harder — *"Database schema is pre-V14; no pre-genesis migration path exists. Delete the data directory and resync"* (rule 15, by design). A current daemon pointed at the same LAN peers connects and is then refused at the chain, not the schema: *"Client sent wrong NOTIFY_REQUEST_CHAIN: genesis block mismatch"* — `dev`'s testnet genesis is not the block the running testnet was launched from. **So the blocker is a regenesis, not an upgrade:** no build of `dev` can join the fleet's testnet until that chain is relaunched from `dev`'s genesis; the leg runs on the first testnet a ≥ V14 daemon can sync. (Observed in passing: `skl-foundation` reported top 2741 and `skl-miner-test` 7111 — the two fleet hosts are not in sync with each other.) Falsify by a `shekyld --testnet` at height > 2112 answering `get_info` on this host, then run the recipe with `--testnet` on the exporter and `--chain testnet`. **LWMA past N** is not exercised by a fixed-difficulty chain (D4 ran under `Fixed`); it needs a chain with a live target. **Attempted 2026-09-20:** `shekyld --regtest` without `--fixed-difficulty`, `generateblocks` in 20-block batches — 20 blocks in 30 minutes, difficulty 400 and rising; LWMA-1 against one-second block intervals ramps past what CPU mining reaches in the time a fixture may take. So this leg is **testnet's** (the same blocker as the testnet leg); falsify by a testnet chain past 91 blocks replaying with `CEN-D4` in the exercised set under `Scheduled(Testnet)`.

    Recipe (regtest): start `shekyld --regtest --fixed-difficulty 1 --offline --no-igd --rpc-bind-port P --data-dir D` with no `SEEDHASH_EPOCH_*` in the environment; mine with `generateblocks` to a mineable address (the e2e harness's fixed-seed wallet prints one); `shekyl-chain-replay fetch --daemon http://127.0.0.1:P --chain regtest --to H --out corpus.bin`; `shekyl-e2-trace-export --regtest --data-dir D --out trace.bin` (built with `-DBUILD_E2_TRACE_EXPORT=ON`; build target `shekyl_rust` first — the Makefile generator's custom-command scope); `python3 scripts/ci/export_conformance_register.py --out register.json`; `shekyl-chain-replay replay --corpus corpus.bin --trace trace.bin --store S --chain regtest --fixed-difficulty 1 --register register.json --grade-out grade.json --metrics-out metrics.json`.
8c. **LANDED (increment 2)** `ingest: Rewind — the reorg source family; pop + connect through the actor with the barrier rule; digest after each switch` (RD-Q13; §3.8): the corpus gains the `rewind` record (format v2, tag byte per record — writer and reader apply one law, `to ∈ [first_height, tip)`); `CorpusReader` emits `IngestEvent::Rewind`, so the family is corpus files, not a second `Source` type; `RunReport::switches` carries the post-pop digest (pop symmetry through the actor); fixture `test_support::reorg`. Checkpoints under reorgs: compared the first time a height is the tip, so a fixture's checkpoint sits beyond every pre-switch tip and a C++ trace is tip-only by RD-F18.
8d. `ingest: the mutation family — systematic invalidations of a valid corpus with spec-first expected verdicts` (§3.8: header flips, wrong reward, reordered transactions, double spend, bad seed, future timestamp closing §5's FTL row). **Next E2 PR** — deferred from increment 2 (rule 22: the PR is past the rule-06 ceiling; the family is Extend-only and separable; owner this plan, which stays in `design/` until it lands). Falsify by `rg 'mutation' rust/shekyl-chain-ingest/src/` finding a `Source`.
8b. **LANDED (increment 2)** `ci: randomx-v2-differential — header re-framed as the permanent verifier↔JIT parity gate; longhash fuzz across randomx-v2-sys with the seed logged and the mismatching blob + both PowHashes emitted as an artifact` (RD-Q12, RD-F12). "The RandomX lane" existed in no form (rule 22's owner test), so it landed here: the workflow's header states the permanent obligation; the fuzz job already existed in substance as the rotating lanes; `three_leg_verdict` compares `PowHash`es (the #785 type seam asserted across the gate).
9. `docs` — DRS-E2 row, index, FOLLOWUPS sweep (items 1–7 of §2), this file to `completed/`. **Partial (increment 2):** index and FOLLOWUPS swept; this file stays in `design/` while 8d and item 8's open legs are owed.

## 8. Expected record at close

The redb file for a replayed chain carries `Provenance` with
`passed_through = [weight, long_term_weight, coins_generated, burned,
root_after, long_term_effective_median]` and E6's open coverage gaps —
NOT-PARITY-EVIDENCE, honestly. **Of the digest's three components, two are
evidence (block hashes; spent keys — both from real `form` → `validate` →
`connect`) and one is borrowed (`curve_root`, copied from LMDB through
`root_after`) and is graded as such** (RD-F7). Register rows grade under RD-Q9's two
clauses: a rule's **verdict** grades on its own evidence even against a
borrowed oracle; the digest **component** a borrowed fact feeds grades
not-evidence; a *producer* of a borrowed value grades not-evidence on both
until Rust derives it — carried as two typed fields per row, and the artifact
names them. **The dataset-mode
measurement is part of the record** (inventory item 7): light-mode wall-clock
per hash and per block on the provisioning floor, as an artifact the RandomX
lane's option (a) decision reads.
The graded artifact reports, per register row, CHECKED-CONFORMANT identity
held / DIVERGENT rows not reproduced / UNREVIEWED observed-only, with **every**
disagreement adjudicated to one of §1.3's two outcomes or named as
outstanding — the run's success condition is *no unadjudicated
disagreement*, not "matches C++". The six items of §2 each resolve to landed
code or a re-pointed FOLLOWUPS row with a live owner.

---

## Round log

| Date | Entry |
| --- | --- |
| 2026-09-19 | **Round 0.** Opened on #785's review after "owner: the E2 lane" was found to name nothing. Sweep at source; eight questions with defaults; six findings, one a proposed gate (RD-F4). Opens before #785 merges so #785's deferrals point at a document under review. |
| 2026-09-19 | **Round 0 REVIEWED and RULED (maintainer).** Substrate claims confirmed at `dev` `14f8dc739`. Four findings taken: RD-F7 (the root component compares a copy of itself → borrowed-is-never-evidence grader rule; §8 names the real components), RD-F8 (tx bodies; unpruned source; prune state declared and refused), RD-F9 (bootstrap format inherited → Rust-minted trace format), RD-F10 (Q3/Q5 contradiction → `Stale::Seed` is a defect signal in replay; injected-seed test). **The ruling (§0):** C++ is a non-canonical reference, adjudicated against the spec with two outcomes, extracted from and never fixed; all E2 C++ is harvest shims that die at cutover; the ingest pipeline is production code shared by E2 and E3 (§1.1 — RD-Q1 → `shekyl-chain-ingest`); the mining JIT is the sole surviving C++ behind a permanent parity gate (RD-F12). Throughput item checked at source: cache-only today; the dataset mode is measurement-gated, not ruled out (RD-F11 as first written said "by ruling" — corrected the same day). RD-Q4/Q6/Q7/Q8 as defaulted; RD-F4 endorsed as a standing check. Round 1 opens after #785 merges. |
| 2026-09-19 | **RD-F11 RULED as a scheduled input** (dataset mode unbuilt pending measured need; the driver is the first instrument able to measure it; the benchmark is part of its deliverable — inventory item 7, commit 7b). The mood variant of the wrong-subject family recorded in rule 16's corollary. **RD-Q9 posed** (RD-F7's produce/consume split; default producers-only; must be answered before commit 7). |
| 2026-09-19 | **Round 1 OPENED with the sweep of #785 as merged** (`93f91b0d4`; §3.7). Two review commits Round 0 never saw: `5e3c2982a` (`Target` is `NonZeroU128`, D6 records on every path so `RuleSet::fakechain` can mint; `StructurallyValid` and `Stale::RuleSet` carry the set by value; D4 overflow unreachable-by-fixture) and `d6ba4d98f` (`ChainValid` carries the set; `connect` compares by value after `for_id`). The second exposes **RD-F13**: a Fakechain verdict can never connect as merged, because no id resolves to a `Fixed` set — **RD-Q10** posed (default: `connect` takes the in-force `RuleSet` by value). RD-F6 discharged. Branch synced to `dev` (`d5d418f5b`). |
| 2026-09-19 | **Direction memo received and recorded (§0 verbatim, §0.1 provenance).** Re-pinned to `origin/dev@306af9bae` (`e80cdbf23`). RULED (memo §2) landed: the "is not" clause (§1.2 — not a second connect path), RD-Q1 (the production ingest crate; name is Q-A), RD-Q2 (corpus + trace with **typed doors** `expect(h)` / `borrow(h)` keyed off `Fact::origin`; RD-F1 collapsed, RD-F2 dissolved), the grader's law and adjudication sentence (RD-Q6; also `CONSENSUS_STORE_RECONCILIATION.md` §5.4.1), RD-F12 corrected to the existing `randomx-v2-sys` boundary. REVIEW INPUT recorded, not ruled (§3.8): stage shape, mutation and reorg corpus families (the FTL §5 row's closer), `Stale::Seed` grounding verified at `fault.rs:70` / `block.rs:132`, `PowHash` as the parity seam. Memo §4: Q-A → RD-Q1 default; Q-B → **RD-Q11** posed (kameo for the one stateful actor); Q-C → answered under RD-Q3/RD-F11 (no dataset mode exposed; parallel `form`; benchmark in the deliverable); Q-D → **RD-Q12** posed (the differential workflow already triggers on both pins — promotion is the framing and a `longhash` fuzz job). Memo §5 honoured: RD-F5 stands, the FOLLOWUPS rows stand, the wallet-store lane untouched. |
| 2026-09-19 | **Round 1 RULED** (all four verified against the plan text). RD-Q9 producers-only as **two clauses** — the rule's verdict grades on its own evidence; the digest component it feeds grades not-evidence — so "producers only" is not quoted as *B5 grades as evidence*. RD-Q10 as defaulted, plus the `Fixed` id-is-not-set caveat cross-referenced **from the CEN-B3 belt** (`connect.rs:441`), the likeliest site to use id equality as a proxy. RD-Q11 as defaulted, with the Validate+Connect actor's supervision **no-restart** — a `Corrupt` halt is terminal, and a restart would be the `InvalidBlock`-mapping failure in another shape; tested by halt-then-assert-not-back. RD-Q12 as defaulted, plus fuzz hygiene — seed logged, mismatching blob and both `PowHash`es emitted as an artifact, or the gate is an alarm that gets muted. Commit plan §7 updated (5, 6, 7, 8b). Implementation may begin. |
| 2026-09-19 | Two implementation carry-forwards pinned on §7 so they outlive the review thread: commit 1's message names itself as what #785 shed and why it waited; commit 5 writes the no-restart test first. Ground confirmed: `dev` at `6c41bf820` with #785 in — no stale ground left in this file. |
| 2026-09-20 | **Increment 1 LANDED on the branch** (§7 commits 0, 1, 2, 3, 4a, 6): the owner gate (RD-F4, 338 grandfathered, PR-alone narrowed and stated), `refuse_corrupt` + SI-10, the redb digest read, `shekyl-chain-ingest` with `Extend`/`Rewind` and the production substrate, the verifying corpus, `in_force: RuleSet`. Built while #792 held `FOLLOWUPS.md`; commit 0 landed once its rows were seen not to collide. **RD-F16** found en route (harness blocks do not round-trip). Increment 2 = the remaining §7 items, next PR — a split inside the plan. |
| 2026-09-20 | **Increment 1 review (three commits by the maintainer, one CI failure, RD-F17).** `0476a22ab` made D4's window walk strict (equal adjacent work is Corrupt — SI-10 as written); `760e9a2d8` parses corpus blobs with `from_bytes` (exact consumption; a padded blob is `Malformed`); `f7326d9ab` names SI-10 as read-armed and the store's one `Corrupt` exception. The strict walk broke slice 2's zero-target fixture and exposed **RD-F17**: LWMA-1 has no floor, zero is reachable from a conforming slow chain, and filing it as `Corrupt` would have halted the writer where the C++ refuses a block. `Corrupt::ZeroTarget` deleted; `D6::mint` → the CEN-D6 verdict; census row amended; FOLLOWUPS row for the DAA owner. |
| 2026-09-20 | **Two lanes built increment 1 independently; #804's stands.** PR #806 (`feat/drs-e2-ingest-spine`) carried §7 commits 0–8c as a second implementation of the same plan while #804 was in flight; neither saw the other. Reconciled per rule 95 (code on `dev` wins): #804's `source` / `corpus` / `substrate` / `refuse_corrupt` / digest read / `connect(in_force)` stand; #806's 4b, 5, 6b, 7, 7b, 8b, 8c and the RD-F20 fixes were **re-ported onto those APIs** as increment 2 on a fresh branch, and #806 was archive-tagged and closed. Two design deltas that port forced are stated rather than smuggled: the corpus `rewind` record (format v2, tag byte per record — 8c) and the trace checkpoint as the outer `digest_v0` only (the redb read returns no components — 4b). The identifier collision (both lanes minted RD-F16/RD-F17) is resolved by renumbering #806's findings RD-F18–RD-F20 here; rule 94 §6 names this failure and the fix is the plan's own banner saying which commits are in flight and where. |
| 2026-09-20 | **Increment 2 LANDED on the branch** (§7 commits 4b, 5, 6b, 7, 7b, 8b, 8c, and commit 8's regtest leg): the trace + FFI + LMDB exporter (RD-F18: one checkpoint, at the tip); the pipeline with the no-restart actor, the barrier rule and heights assigned by the pipeline (RD-F19: the mainnet seed schedule at every nettype); `ChainRules`; the two-clause grader over the extractor's register; the metrics sink (RD-F20: derives counted at the source, the canonical epoch pinned); the parity-gate header; the `rewind` record and the reorg fixture. **First real runs:** a 301- and a 2301-block regtest chain (`--fixed-difficulty 1`, no `SEEDHASH_EPOCH_*`) fetched over RPC, traced from LMDB, replayed — **digest MATCH at the tip both times, 0 unadjudicated, 11 rows derived-and-conformant, 9 borrowed; the 2301-block run crossed the 2112 seed-epoch boundary (3 derives, 0 waits)**. RD-F11's number: 0.60 s CPU per hash, light mode, x86_64/16 threads. The FOLLOWUPS row *E2 comparator negative control* (one forced-red case per redb table) closed: its per-table premise was superseded by RD-F5's single digest, and the control in that form is one wrong checkpoint going DIVERGE and failing the grade — `a_wrong_checkpoint_goes_red_and_the_graded_run_does_not_pass`. Open after this PR: the testnet leg and LWMA past N (one blocker: no testnet chain on this host), the mutation family (8d, next PR), commit 9's archive. |
| 2026-09-20 | **Increment 1 review (code-quality).** Corpus reader parses the block first so the header bounds `tx_count` (wire's no-prealloc discipline); writer emits one record per `write_all` and `finish` consumes (no finished flag). Digest assembly is exhaustive over `AtHeight` with an `n_blocks == tip+1` belt. `SequenceNo::next` panics on exhaustion rather than saturating. SI-10 tests extracted from `connect_tests`. Register §1 records the validator-read enforcement site; RD-Q1 names `Corrupt` at `refuse_corrupt` as the one Fault payload the store takes. |
| 2026-09-19 | **PR review (Copilot, nine threads) taken.** RD-F14: `VmStatePool` is `cfg(test)`/bench-only — the parallel-`form` stage now rests on `compute_hash` per worker, the pool's promotion the RandomX lane's measure-first call. **RD-Q13 posed and defaulted:** a height-ordered stream cannot represent a reorg; the `Source` yields `Extend`/`Rewind` under a barrier rule, or E3 needs a second ingest path — commit 8c. The register count is the gate's (131 recorded, 126/2/3), not a literal; bare slice-2 `Q…` tokens qualified (rule 94 §2); RD-Q1's boundary sentence corrected (the store names `ChainValid`, never `InvalidBlock`/`Fault`/RandomX); the RD-Q9 two-clause rule restored in the CSR §5.4.1 and DRS-E2 restatements; the index documents-row and stamp brought current. |
| 2026-09-19 | **Second PR review round (Copilot, eight threads) taken; merged `dev` `fbc92287a`.** The actor owns the `ChainStore`, not a `WriteBatch` — a batch is closure-scoped by the brand, so the transaction boundary is one `write` closure per handler (a `Rewind`; a bounded run of `Extend`s = the checkpoint granularity). The supervision map is now **complete** over every non-verdict outcome (`S::Fault`, `Fault::View`, `Corrupt`, both `Stale` arms, `Exhausted`), so nothing inherits a default restart. **RD-F15:** a pruned RPC source is silent (`missed` dropped; no flag on `BlockEntry`) — the corpus writer verifies count/order/hash against `tx_hashes`, not a declaration. RD-F4's gate gets a concrete carrier: **§7 commit 0**, with the owner-cell convention and grandfather shape named. §8's stale "RD-Q9 decides whether" removed; index header, RD-F range and documents-row brought to the current state; stamp moved to `fbc92287a` with the checks re-run. S-TX's coupled E2 reopen criterion acknowledged (E2 projects no tx table). |
