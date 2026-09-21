# DRS-E2 — the ingest spine and its first source, the replay driver (pre-flight)

**Status:** OPEN — **Round 1 RULED 2026-09-19 (RD-Q9–RD-Q12; implementation
may begin on the commit plan §7).** Round 1 opened with the sweep of #785 as
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
| 1 | `Fault::Corrupt` → writer halt | `CHAIN_RULES_SLICE_2.md` §4.3; FOLLOWUPS row (withdrawn 2026-09-20) | Receive a `Corrupt` from `validate` and arm the store's halt at the noted height, as a belt does; the store API is **minted here, with its caller** (RD-Q4). **Store half BUILT** commit 1 (`refuse_corrupt`, SI-10); the actor that calls it is commit 5. |
| 2 | `Stale::Seed` → bounded retry | `fault.rs` (`FormAttempt`, `Retry`, `MAX_FORM_ATTEMPTS`); slice 2 Q8 (the ruling that minted the arm and its bound) | Run the loop with the bound; in replay any `Stale::Seed` is a **driver defect** — record and surface the first occurrence (RD-Q5, RULED). |
| 3 | The production `Substrate` | `substrate.rs`; slice 2 Q1 | Real `longhash` through `shekyl-pow-randomx`'s production surface (`PreparedCache::derive` + `compute_hash`; `CacheStore`), a real clock; the seed claim from the chain (RD-Q3). |
| 4 | `RuleSet::fakechain` wiring | slice 2 Q10 / F10; FOLLOWUPS row | `--regtest` / `--fixed-difficulty` reach `RuleSet::fakechain` through the driver (RD-Q7). |
| 5 | The test-deviation register's first consumer | F12; FOLLOWUPS row (falsifier: *this* pre-flight) | §5 carries the section F12's falsifier demands. |
| 6 | LWMA-1 conformance past `N` | `conformance_tests.rs` header; `CHAIN_RULES_CRATE.md` §8.8 | The first replay past 91 blocks exercises D4's window against a real store. |
| 7 | **The verifier dataset-mode measurement** | `RANDOMX_V2_RUST.md` §9 (unbuilt pending measured need); `RANDOMX_V2_MINING_ASYMMETRY.md` option (a) | The pipeline is the first instrument able to run RandomX verification at volume over a real chain; **the benchmark is part of its deliverable** (RD-F11): light-mode wall-clock per hash / per block, on the provisioning floor, as a sink artifact. A deferred decision's input arrives with the driver instead of being argued for. |

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
  `u128::MAX` fixture). `Corrupt` still has three variants
  (`CumulativeDifficultyNotMonotone`, `CumulativeDifficultyOverflow`,
  `ZeroTarget`); RD-Q4's arm→SI-row mapping covers all three and records the
  second as unreachable-by-fixture rather than dropping it.
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

### 3.9 Artifact formats — the commit-4 specification (written 2026-09-20, before the code; rule 05)

Two artifacts, two producers, one discipline: **Rust-minted, versioned,
fixed-layout, self-verifying on read**. Neither extends an inherited container
(RD-F9); neither carries a flag a reader would have to trust (RD-F15). Both
live in `shekyl-chain-ingest` (`corpus`, `trace`), never in a binary (RD-Q1).
Every multi-byte integer is little-endian. Every layout change bumps the
version byte; a reader refuses any version but its own — a stale artifact
fails loudly, it does not decode to something plausible.

**Corpus** (`corpus::CORPUS_MAGIC` = `SHKCORP\0`, version `0x00`) — what the
network carries, from an unpruned node over `/get_blocks_by_height.bin`; zero
C++. Height-ordered, consecutive from the header's first height.

| Field | Width | Notes |
| --- | --- | --- |
| magic | 8 | `SHKCORP\0` |
| version | 1 | `0x00` |
| reserved | 7 | zero; a reader refuses non-zero |
| first_height | 8 | u64 — the height of the first record |
| **record** × n | | tag `0x01` **Extend**: `height` u64 (must equal first_height + i), `block_len` u32, block bytes, `tx_count` u32, then `tx_count` × (`tx_len` u32, body bytes). Tag `0x02` **Rewind** is RESERVED for the reorg family (RD-Q13, commit 8c): `to` u64, no payload — named in the table so the byte is not re-minted; no code until that commit (rule 23). |
| trailer | | tag `0xFF`, `count` u64 (records), `tip_hash` 32 (the last block's hash) |

**The record is verified, not declared** (RD-F15), by writer and reader
alike: parse the block (`Block::from_bytes`), parse each body
(`Transaction::from_bytes`), and require `tx_count == block.transaction_hashes.len()`
and `body[i].hash() == block.transaction_hashes[i]` for every `i`. A shortfall,
a surplus, a reorder or a wrong body is `CorpusFault::Incomplete { height, .. }`
naming the height; a block whose `previous` is not the prior record's hash is
`CorpusFault::Unchained { height }`. There is no "unpruned" field because the
property is re-established on every read; an artifact the reader cannot
re-verify is refused, whatever its writer believed.

**Trace** (`trace::TRACE_MAGIC` = `SHKTRAC\0`, version `0x00`) — the LMDB-only
facts and the digest checkpoints, produced by **one** C++ exporter walking LMDB
and handing bytes across the FFI to the Rust writer (`shekyl_e2_trace_*`), the
whole of which dies with the daemon (§1.3).

| Field | Width | Notes |
| --- | --- | --- |
| magic | 8 | `SHKTRAC\0` |
| version | 1 | `0x00` |
| reserved | 7 | zero |
| **record** × n | | tag `0x01` **Facts** at `height` u64: `weight` u64, `long_term_weight` u64, `coins_generated` u64, `burned` u64, `root_after` 32, `long_term_effective_median` u64, `cumulative_difficulty` u128 — the six passed-through facts (`ConnectFacts`' order) plus the accumulator D4 reads; **72 + 16 = 88 bytes after the height**, fixed. Tag `0x02` **Checkpoint** after `height` u64: `n_blocks` u64, `n_spent` u64, `chain` 32, `spent` 32, `curve_root` 32, `digest` 32 — the `LogicalStateDigestV0` shape (commit 2), **computed in Rust** from the families the exporter hands over (block hashes, spent keys, root), never by the C++: the grader compares component to component (RD-Q9) and the two sides must have hashed them the same way. Tag `0x03` **Verdict** is RESERVED for the mutation family (§3.8): no code until it lands. |
| trailer | | tag `0xFF`, `facts` u64, `checkpoints` u64 |

Facts records are consecutive by height from the first; a checkpoint's height
must equal the height of a facts record already written (a digest after a
block that is not in the trace is unanchored). The exporter can take a
checkpoint **only at the tip** of the LMDB it reads (RD-F16). The reader exposes the two typed
doors RD-Q2 ruled: `borrow(h) -> Borrowed<Facts>` for `connect` (the `Fact::origin`
is `PassedThrough` by construction of the type — a borrowed fact cannot be
constructed as derived) and `expect(h) -> Expected<Checkpoint>` for the grader
only. Both doors are `Option`: a height the trace does not cover is an ordinary
absence, not a fault (the corpus may run past the trace; the run then grades
nothing there and says so).

**What is deliberately not in either artifact.** No `Network` byte — a corpus
fed to the wrong schedule fails at genesis (block 0's hash is the schedule's),
loudly, so a field would be pre-provisioning (rule 21). No per-record digest —
the block is self-verifying (its bodies hash to its list, its `previous` to the
prior record) and the trailer's `tip_hash` plus counts bound truncation. No
compression — a corpus is read once per run and the bodies are already compact.

**Landing shape.** Commit 4 splits (a split inside the plan, rule 22): **4a**
formats + writers + readers + verification, with pinned byte fixtures; **4b**
the RPC corpus fetcher over `shekyl-rpc-client`'s `Rpc` trait (testable against
a mock; `shekyl-rpc-transport::HttpRpc` in the binary); **4c** the trace
writer's FFI and the C++ exporter shim. 4c cannot be built or run on the
implementation host (no C++ build, no LMDB) — it lands compiled against the
header only and is exercised by the first run (commit 8), which is where the
plan already puts the first real chain.

## 4. Questions — Round 0 defaults, with the 2026-09-19 rulings in-line

| Q | Question | Disposition | Why |
| --- | --- | --- | --- |
| **RD-Q1** | **Home.** | **RULED (memo §2): the new crate is the production ingest crate**, depending on rules + store + `shekyl-pow-randomx`, with the replay driver as its first `src/bin/`; corpus/trace format types live in this crate (or `shekyl-store-codec` once CTS PR A lands), never in a binary. **Its name is Q-A → default `shekyl-chain-ingest`** (REVIEW INPUT; adopted unless Round 1 objects). *Round-0 default was `shekyl-chain-replay`, "a test tool" — same dependency shape, different life expectancy.* | The store crate is `#![deny(unsafe_code)]`; it names `ChainValid` (the accepted verdict is `connect`'s input, `connect.rs:314`–`:318`) but **neither RandomX, nor the refusal type `InvalidBlock` (conversion ban clause 2), nor the validator's `Fault`/`Substrate` types** — and it must stay that way: the pipeline keeps the store ignorant of faults and of hashing, and G1 trivially true. |
| **RD-Q2** | **Block, body and fact source** (§3.4). | **RULED (memo §2): corpus + trace, with typed doors.** **Corpus** — *network-shaped only*: per height, the block plus full transaction bodies in header order (what `Candidate` consumes, `block.rs:88`–`:93`), taken from an **unpruned** node, its completeness **verified per height** against the header's `tx_hashes` (count, order, hash — RD-F15) and refused on a shortfall; format minted in Rust, versioned — the Monero bootstrap/epee container is **not** extended (rules 42/16); **zero C++** — the existing block-by-height read suffices. **Trace** — the six facts, cumulative difficulty, digest checkpoints, and (later) verdicts — produced by **one** C++ exporter shim that walks LMDB and hands bytes to a Rust writer, deletable in the same commit that deletes the daemon. **The doors are the grader's law:** `expect(h)` feeds *only* the grader; `borrow(h)` feeds `connect` for facts Rust does not derive yet, keyed off `Fact::origin` — a borrowed value is never evidence (RD-Q6). RD-F1's option matrix collapses to this; RD-F2 dissolves — no LMDB crate enters the workspace. *Round-0 default (c) withdrawn (RD-F9).* | Byte transport across the FFI is what D12 allows; verdicts are what it rejected. The digest walker (`logical_state_digest.cpp` → FFI) is the existing shape. Two doors with different types make "the grader read a borrowed fact as evidence" a compile error, not a review catch. |
| **RD-Q3** | **Production `Substrate`.** | **Default holds with one correction:** two-cache `CacheStore` keyed by the chain's seed at `seedheight(h)`, swapped at epoch boundaries; wall clock. *Round 0 called the retry loop "load-bearing" at the boundary; **withdrawn** (RD-F10) — the driver takes the seed from the chain it replays, so a `Stale::Seed` cannot arise from a correct driver; it is a defect signal (RD-Q5).* Throughput: parallel `form` workers over per-worker `compute_hash` (§1.1; the pool is not production, RD-F14) now; the Rust dataset mode is an **open option gated on a measurement E2 itself produces** — the pipeline's metrics sink records light-mode wall-clock per hash and per block, which is the number `RANDOMX_V2_MINING_ASYMMETRY.md` option (a) has been waiting for (RD-F11); never the JIT (§1.3). **Memo Q-C answered here:** checked at source — `shekyl-pow-randomx` does not expose full-dataset verification (`Cache::derive_item`, `cache.rs:449`; no public dataset builder) and cannot "cheaply" grow one inside this increment (it is the RandomX lane's and a 2 GiB-per-epoch provisioning question, rule 76); so parallel `form` is the win now, and the benchmark this pipeline emits is what decides the rest. **Caveat:** C1's FTL leg reads the clock and a historical block is always below `now + FTL`, so replay cannot exercise C1's refusal — recorded in §5. | Reuses the daemon's cache lifecycle; the epoch boundary is where a stale cache would silently produce wrong longhashes, and that now surfaces as a defect, not a retry. |
| **RD-Q4** | **`Fault::Corrupt` at the store.** | **RULED as defaulted:** `WriteBatch::refuse_corrupt(Corrupt) -> StoreError`, inside the batch, arming the poison at the noted height with a `StoreInvariant` row mapped from the `Corrupt` arm (new SI rows minted with it), returning the `InvariantViolated` the pipeline propagates. Minted here **with its caller** — the commit-9 scope #785 shed, as ruled 2026-09-19. **BUILT 2026-09-20 (commit 1):** `WriteBatch::refuse_corrupt(Corrupt) -> StoreError`; **SI-10** `StoreInvariant::DifficultyRecordIncoherent(Corrupt)` — one row for the three arms, carrying the validator's value rather than a store enum mirroring it; the halt lands at `tip + 1` whether or not the caller opened the view; first-wins against a belt holds both ways. The caller is commit 5's actor. | The validator saw what a belt would have; the store's halt is the consequence and must poison *this* batch. Taking the value keeps the store from naming `CenRow`s it does not own. |
| **RD-Q5** | **The retry loop and `Stale::Seed` in replay.** | **RULED:** the loop lives in the pipeline (`form` → `validate`; on `Stale::Seed` re-`form` with the expected seed and `attempt.next()`; `Exhausted` → terminal run error). **In replay every `Stale::Seed` is a driver defect: the run records and surfaces the first occurrence rather than retrying it away**, and **the retry path is exercised by a test that injects a wrong seed**, not by waiting for a bug. The live-daemon role (slice 2 Q8's DoS bound) is unaffected. | Resolves the RD-Q3/RD-Q5 contradiction Round 0 carried (RD-F10). |
| **RD-Q6** | **Grading.** | **RULED as defaulted, plus the grader's law (memo §2):** Python extractor → JSON → the pure Rust grader, reusing `drs_artifact.py`'s schema discipline. **A borrowed value is never evidence** — a row sourced from a borrowed fact (`Fact::origin == PassedThrough`, reached through `borrow(h)`) grades not-evidence, never CHECKED-CONFORMANT (RD-F7). As slices derive facts, rows flip to real evidence **with no harness change**; **progress is the count of derived-and-conformant rows.** Adjudication semantics (one sentence, also in the grader doc — `CONSENSUS_STORE_RECONCILIATION.md` §5.4.1): the trace is evidence, not a target; a divergence resolves to *fix Rust* or *`ReviewedDivergence` with Rust canonical* — no third arm; tainted trace rows are annotated; fixtures re-baseline from Rust after cutover, becoming permanent regression gates. RD-Q9's producer/consumer split refines *which* rows the law reaches. **BUILT 2026-09-20 (commit 7):** `scripts/ci/export_conformance_register.py` serializes the coverage gate's own parse (it imports the gate; a `--selftest` in `docs-gates.yml` holds the emitted tally equal to the gate's) to `shekyl_e2_register_v1` JSON; `shekyl-chain-ingest::grader` reads it, takes the run's `Observations` (the union of every connected `ChainValid`'s coverage, the refusing row if a verdict ended the run, digest agreement at the checkpoints) and emits `shekyl_e2_grade_v1` with RD-Q9's **two typed clauses per row** — `VerdictEvidence` and `ComponentEvidence`, each with its own `grade(state, identical)` acceptance. Producers are read from `ConnectFacts::DELETED_BY`, so a slice that derives a fact flips its rows to real evidence with no harness change. `GradedRun::passes()` is §1.3's condition: no `Failed(..)` acceptance on either clause; `NeedsReviewedDivergence` is listed as owed. `shekyl-chain-replay replay --register --grade-out` grades and exits non-zero on an open adjudication. The inversion is live in the tests: a DIVERGENT non-producer row whose digest *matches* is the one unadjudicated item of an otherwise clean run. |
| **RD-Q7** | **Fakechain wiring.** | **RULED as defaulted:** the driver takes `--fixed-difficulty n` → `RuleSet::fakechain(n)`, refused unless the nettype is regtest; the `Network::Fakechain` witness stays its own change (12 files / 9 crates; slice 2 F10). **BUILT 2026-09-20 (commit 6b):** `schedule::ChainRules` is the driver's height → set resolution (RD-Q10's other half) — `Scheduled(Network)` through `RuleSchedule::for_network(..).rules_at(h)` → `RuleSet::for_id`, or `Regtest { fixed_difficulty }` → `fakechain(n)` / `GENESIS` (the daemon's own default: `--fixed-difficulty 0` is *not fixed*); `ChainRules::new` refuses the flag off regtest by construction, so §5's "production nets refuse the flag by type" is a typed fact. `form` and `validate` read `in_force(height)` per block. The binary `shekyl-chain-replay` (`fetch` / `replay`) carries the flag; a fakechain corpus replays end to end and connects (RD-F13's repair through the pipeline, cumulative work 1 + 7·h). | The consumers need the lever, not the witness. |
| **RD-Q8** | **First chains.** | **RULED as defaulted:** regtest (the `e2e_fcmp_spend_accepted_by_daemon` fixture, ~80 s), then a testnet snapshot past `N` **and** a seed epoch (≥ 2113 blocks). | Only a chain past 2112 exercises the cache swap and D3's roll-over against real data. |
| **RD-Q9** *(Round 1 question, posed 2026-09-19 — must be answered before commit 7, grading)* | **RD-F7's edge: producing a borrowed value vs consuming one as an oracle.** `root_after` is passed through, so the digest's `curve_root` component is worthless as evidence — but CEN-B5's equality check (candidate header root == recorded root at `h`) still **refuses a wrong header** against that borrowed value. Does "rows sourced from passed-through facts grade not-evidence" apply to rows that *produce* the borrowed value (the SCW-19 root write, the weight folds, the coin fold) only, or also to rows that *consume* one as an oracle (B5's equality; C-rows reading recorded timestamps are unaffected since timestamps are real)? | **RULED 2026-09-19 — producers only, stated as two clauses so both subjects are in the sentence: (1) the rule's verdict grades on its own evidence; (2) the digest component it feeds grades not-evidence.** "Producers only" alone would be quoted as *B5 grades as evidence*, which is false on the parity axis — B5's *refusal* is real (a wrong header is refused against the borrowed oracle), B5's *root component* in the digest is a copy. A consumer row is a real check whose oracle happens to be borrowed; producers (the rows whose output *is* the passed-through value) grade not-evidence until Rust derives them. The grader carries both subjects as typed fields on the row — verdict-evidence and component-evidence — not one recoverable from the other. **BUILT 2026-09-20 (commit 7)** as `VerdictEvidence` / `ComponentEvidence` on `GradedRow`; B5's row in the test shows both at once — its verdict counts (a consumer's real check) while its component is `Borrowed { field: "root_after" }`. | This split decides how many rows actually grade not-evidence — under "producers only" it is the six facts' deriving rows (CEN-G6/G6b, F13/F14/F14b, F17/G11, B5's write half via S-CURVE, I12); under "consumers too" B5 and every rule reading a recorded fact joins them. The grader needs the distinction as a typed origin on each row's oracle, not a comment. |
| **RD-Q10** *(Round 1, posed 2026-09-19 from the sweep; decides RD-Q7's store leg)* | **`connect`'s `in_force` cannot name a Fakechain set** (RD-F13). `connect(valid, facts, in_force: RuleSetId)` resolves the id through `for_id` over `ISSUED`; Fakechain reuses `RuleSetId::GENESIS`, so no id reaches a `Fixed` set and a Fakechain verdict is always refused `RuleSetNotInForce`. What does the driver's schedule hand `connect`? | **Default: `connect` takes the in-force `RuleSet` by value — `in_force: RuleSet` — and compares by `PartialEq` exactly as `d6ba4d98f` already does after resolution; `RuleSetUnknown` moves to where the id is resolved (the schedule, `RuleSchedule::rules_at`), which is the layer that owns the id→set mapping.** The CEN-B3 belt (`hf_versions[h] = in_force`, `connect.rs:441`) stores `in_force.id()`, unchanged on disk. A schedule that can *name* Fakechain (a `RuleSchedule::fakechain(n)` whose `rules_at` yields the set, or `rules_at -> RuleSet`) is the driver-side half and lands with RD-Q7's flag. **RULED 2026-09-19 as defaulted, plus a pointer at the belt:** under `DifficultyRule::Fixed` two different Fakechain sets both carry `RuleSetId::GENESIS` — the caveat already on `Fixed`'s doc (`rule_set.rs:111`–`:116`: id equality is not a proxy for set equality) — and the belt is the single most likely site for someone to use it as one. Commit 6 cross-references the caveat **from the belt's comment**, not only from the variant. **BUILT 2026-09-20 (commit 6):** `connect(valid, facts, in_force: RuleSet)` compares by value and writes `in_force.id()` at the CEN-B3 belt under the caveat's comment; `StoreCannot::RuleSetUnknown` is deleted — with the set arriving resolved there is no unissued id for the store to refuse, and no honest fixture could construct one (every `RuleSet` constructor is issued or Fakechain); `RuleSetNotInForce` keeps the two ids and its `Display` names the equal-id case. The fixture RD-F13 asked for exists: `fakechain(7)` connects under `fakechain(7)` and the belt lands GENESIS's id. | Rule 71 holds: the store still carries no schedule and no `Network`; it receives a value and compares. The alternative — minting a distinct `RuleSetId` for each Fakechain set — was already refused when slice 2 Q10 chose to reuse `GENESIS` (an id space for operator-chosen difficulties is nonsense), and a `RuleSetId::FAKECHAIN` sentinel would need the id→set resolution to consult something other than `ISSUED`, i.e. exactly the value the default passes. Falsify the finding's premise by `rg 'RuleSetId::FAKECHAIN\|fakechain' rust/shekyl-chain-rules/src/rule_set.rs` showing an id that `for_id` resolves to a `Fixed` set — none does at `93f91b0d4`. |
| **RD-Q11** *(memo Q-B, REVIEW INPUT → posed for Round 1)* | **Composition.** `kameo` (the workspace precedent, exact-pinned `=0.20.0` in engine-core) vs plain `tokio` stages; rule 25 is silent on actor frameworks. | **Default (memo's): `kameo` for the one stateful actor — Validate+Connect, which owns the write transaction — and plain tasks + bounded channels for Form workers (each over its own `compute_hash` call, RD-F14), the Sequencer and the Sinks.** | The only state in the pipeline is the batch; an actor earns its keep exactly there (mailbox = the single-writer queue; supervision = the halt). Stateless stages under an actor framework would be ceremony. Rule 17: `kameo` is already a workspace dependency at a pinned version; no new edge. **RULED 2026-09-19 as defaulted, with the supervision policy stated as terminal:** actor frameworks default to restart-on-failure, and a `Fault::Corrupt` halt must be **terminal** — the writer stops and stays stopped. An actor that restarted after a halt would silently convert a store-invariant violation into a retry loop, the same failure shape as mapping it onto `InvalidBlock`. The Validate+Connect actor's supervision policy is **no-restart**, and commit 5 tests it: halt, then assert the actor does not come back. |
| **RD-Q13** *(Round 1, posed 2026-09-19 from review — a height-ordered stream cannot represent a reorg)* | **The `Source` event model.** §1.1 as first drawn showed blocks flowing in height order into a sequencer and a single connect actor, with no pop or branch-switch event; yet the reorg family is said to exercise `pop`, and E3 is said to need only a source swap. What does a source emit, how are events ordered, and how does `form` get the *fork's* seed context? | **Default: `IngestEvent::{Extend(CorpusBlock), Rewind { to: BlockHeight }}`, totally ordered by a source-assigned sequence number.** The Sequencer restores that order after parallel `form` (it never reorders across a `Rewind`; a `Rewind` is a barrier — formation of `Extend`s after it waits for it to commit, because their seed context depends on it). The actor executes `Rewind { to }` as `pop` until the tip is `to`, then `Extend`s connect at `to + 1…`. **Seed context:** `form`'s seed claim for an `Extend` after a `Rewind` is the block at `seedheight(h)` on the **post-rewind** chain — the driver knows the fork it is replaying and claims accordingly; a `Stale::Seed` here is still a driver defect (RD-Q5). Sinks observe both event kinds: the digest sink records after each `Rewind` commit (the "digest after each switch" the reorg family needs). Who *decides* a rewind is the source's business — the reorg fixture scripts it; E3's p2p source computes the heavier-chain switch (the daemon's alt-chain logic) and emits it; the pipeline only executes. | Without `Rewind` the reorg family has no way to drive `pop`, and E3 would need a second ingest path — exactly the disease §1.1 exists to prevent. Two variants, one barrier rule, is the smallest model that makes the source-swap claim true. |
| **RD-Q12** *(memo Q-D, REVIEW INPUT → posed for Round 1; owner the RandomX lane, recorded here because §0 created the obligation)* | **The parity gate's CI home** for §0's "permanent gate re-run on either pin's move, plus `longhash` fuzz across `randomx-v2-sys`." | **Default: `randomx-v2-differential.yml` is already the home** — verified at `306af9bae`: its `push`/`pull_request` `paths` include `external/randomx-v2/**`, `rust/randomx-v2-sys/**`, `rust/shekyl-pow-randomx/**`, `Cargo.lock` (`:82`–`:88`, `:96`–`:100`), so the re-run-on-either-pin half is **mechanically true today**. What promotion adds: (i) the workflow's header, which frames the vector set as rewrite scaffolding with a V3.0 deferral, re-framed as the permanent verifier↔JIT parity obligation with §0 as its authority; (ii) a `longhash` fuzz job across `randomx-v2-sys` (random blobs × pinned seeds, both sides, asserting equality) on the daily cron; (iii) the type seam it asserts across is `PowHash` (distinct from `BlockHash` since #785) — the fuzz compares `PowHash`es, not bytes. | The gate exists and fires; only its *meaning* and one job are missing. A second workflow would split the record. **RULED 2026-09-19 as defaulted, plus fuzz hygiene:** random blobs on a daily cron produce failures nobody can reproduce unless the generator's seed is logged and the failing input is emitted as an artifact — without that it is an alarm, not a gate, and a parity obligation that fires irreproducibly gets muted. The fuzz job **logs its seed on every run and dumps the blob and both `PowHash`es as a workflow artifact on mismatch**, so an inequality is actionable, not merely alarming. **LANDED 2026-09-20 (commit 8b, in this PR — not handed to "the RandomX lane", which exists in no worktree or PR and is exactly the owner RD-F4's gate refuses).** Checked at source before writing: (ii) already existed in substance — the `rotating` lanes (`--mode=rotating`, daily cron on both branches, per-PR tripwire; `RANDOMX_V2_MUTATION_REGIME.md` §7.5 item 2) fuzz non-pinned inputs against the C oracle, derive the input set from a **logged rotation index** (reproducible from one integer, provenance-labelled), and upload `failure_output`'s seedhash / data blob / `rust_hash` / `c_hash` as an artifact on divergence — the Round-1 default had verified only the `paths:` filters and would have had a second fuzz job built beside the first. What was missing and landed: (i) the workflow header now opens with the obligation and §0 as its authority, the Phase 2g history demoted to how the gate was built; (iii) `three_leg_verdict` compares `PowHash::from_bytes(rust) != PowHash::from_bytes(c)` — the seam named at the one comparison site (MR-F10), payloads unchanged. Verified against a locally built `librandomx.a`: harness + sys clippy clean, the verdict's ten negative tests green. |

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
- **RD-F4 — proposed gate: a deferral's owner must resolve** (endorsed
  2026-09-19 as a standing check). Every `FOLLOWUPS.md` row's owner must
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
  pre-genesis. **DISCHARGED 2026-09-20 (commit 0 of this plan):** the gate
  exists, reads the Target gate's item grammar and the prefix gate's registry
  (one population, one family set), resolves the three owner forms — a live
  `docs/design/` doc, an *open* PR through `gh`, an index family — and
  refuses a closed record, a merged/closed PR, and prose; 28 rows whose
  owners were already unambiguous in their prose (a doc link, `RK-`, `DRS-`,
  this plan) gained `Owner:` with it, 316 predate the convention and sit in
  `followups_owner_grandfather.txt` by exact title, shrink-only. The
  falsifier held: "owner: the E2 lane" with no `DRS_E2_*.md` is refused as
  prose (not one of the three forms), and an owner linking into `docs/completed/` is
  refused as a closed record.
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
- **RD-F16 (commit 4c, 2026-09-20) — LMDB holds the spent-key set as of
  the tip only, so a trace checkpoint can be taken at the tip of an
  export and nowhere else.** `for_all_key_images` walks the live set; there
  is no as-of-height view of `spent_keys` (nothing records when a key image
  was spent). A checkpoint at a non-tip height would pair a past chain
  (hashes `0..=h`, `curve_tree_roots[h+1]`) with the present set and be
  wrong by construction. The exporter therefore writes **one** checkpoint,
  after the last exported height, and only when that height is the recorded
  tip; several checkpoints mean several snapshots (or one long-running
  export interleaved with the daemon's growth — not done). §1.1's
  "checkpoints at digest heights make long replays resumable" is a redb-side
  statement (the replay can digest itself at any height, commit 2) and
  stands; what this finding bounds is where an LMDB *expectation* exists to
  grade against. Falsify by an LMDB table keyed by height that yields the
  spent set at `h` — none exists at `11929805d`.
- **RD-F17 (commit 6b, 2026-09-20) — there is no Fakechain seed-epoch
  override for the driver to take, and a regtest daemon that runs with one
  produces a chain the validator refuses by design.** The validator derives
  the seed height with the mainnet constants at every nettype and reads no
  environment (slice 2 F5, CEN-D3); the `SEEDHASH_EPOCH_*` fast-epoch lever
  lives only at the C++ FFI boundary. So the driver claims seeds on
  `SeedSchedule::MAINNET` unconditionally — a faster claim would earn
  `Stale::Seed` at every block — and the `PipelineConfig::schedule` knob
  commit 5 had pencilled in (this plan's own §1.1 wording, "Fakechain
  overrides") is deleted as a knob no honest run can use (rule 21).
  Consequence for commit 8's regtest fixture: harvest the corpus from a
  daemon started **without** `SEEDHASH_EPOCH_*`, or the PoW seed the C++
  hashed under is not the one D2/D3 verify under and the run refuses at
  block `blocks + lag + 1`. Falsify by `rg 'SEEDHASH_EPOCH' rust/shekyl-chain-rules/`
  finding a read — none at `11929805d`.
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
  flag. Falsifier as in RD-Q10. **Store leg REPAIRED 2026-09-20 (commit 6)** —
  a Fakechain verdict connects under its own set (fixture in
  `connect_tests.rs`); the driver-side schedule that names one is 6b.
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
  and a `longhash` fuzz job existing across `randomx-v2-sys`. **DISCHARGED
  2026-09-20 (commit 8b): both halves hold — the header states the
  obligation, and the fuzz job is the pre-existing `rotating` lane, named as
  such (RD-Q12).** "Owner: the RandomX lane" above is retired: no such lane
  exists, and the obligation is CI's from here.

## 7. Commit plan (sketch; Round 1 fixes it)

0. `ci: check_followups_owners.py — a deferral's owner must resolve (live doc, open PR, or index family); Owner: sub-bullet convention; existing rows grandfathered by exact hit` (RD-F4). First, because the lane it protects against is the one this plan was opened to repair.
1. `chain-store: WriteBatch::refuse_corrupt — the validator's Corrupt arms the halt` (RD-Q4; new SI rows; withdraws the FOLLOWUPS row). **Its commit message states that this is the API #785's commit 9 shed and why it waited: the deferral was circular ("no caller") until the caller was scheduled, and the API arrives with the driver that shapes it — value in, inside the batch — rather than guessed at from the store side.** A reader landing here from #785's FOLLOWUPS row gets the reason, not a reconstruction.
2. `chain-store: ReadSnapshot::logical_state_digest_v0 — the redb half of E2` (RD-F5).
3. `ingest: shekyl-chain-ingest scaffold — Source trait, pipeline stages, production Substrate over shekyl-pow-randomx's compute_hash (no pool; RD-F14)` (RD-Q1, RD-Q3).
4. `ingest: corpus + trace formats (Rust-minted, versioned); RPC corpus reader with prune-state refusal; LMDB trace exporter as a C++ harvest shim` (RD-Q2, RD-F8, RD-F9).
5. `ingest: form workers → sequencer → validate+connect actor (kameo, no-restart); Corrupt → halt, terminal — halt-then-assert-not-restarted test; Stale::Seed surfaced; injected-wrong-seed test` (RD-Q5, RD-Q11). **Test order inside the commit: the no-restart test is written first, while the actor is three lines** — it is cheap then and awkward once supervision is configured and a channel is plumbed through; it is also the test most likely to be deferred as obvious, and the failure it guards (a halt laundered into a retry) is silent by construction.
6. `chain-store: connect takes the in-force RuleSet by value; RuleSetUnknown moves to schedule resolution; the CEN-B3 belt's comment cross-references Fixed's id-is-not-set caveat` (RD-Q10, RD-F13) — precedes 6b.
6b. `ingest: --fixed-difficulty → RuleSet::fakechain on regtest; a schedule that names it` (RD-Q7) — **LANDED 2026-09-20** (`schedule::ChainRules`, the `shekyl-chain-replay` binary; RD-F17 found).
7. `ingest: CSR-3a grading — extractor, artifact, the two-clause evidence rule (verdict-evidence and component-evidence as typed row fields, RD-Q9), grader wiring` (RD-Q6, RD-F7) — **LANDED 2026-09-20.**
7b. `ingest: metrics sink — light-mode RandomX wall-clock per hash / per block; the dataset-mode measurement artifact` (RD-F11, item 7) — **LANDED 2026-09-20**: `metrics::Metrics` (lock-free counters shared by the N `form` workers) records each `compute_hash` and each cache derive apart (the 256 MiB fill would otherwise misstate the per-hash mean) and each block's whole stateless stage; `MetricsArtifact` (`shekyl_e2_metrics_v1`) carries counts, totals, means and extremes plus the measuring host (arch, OS, threads) — a reader compares against the provisioning floor, never assumes it; `shekyl-chain-replay replay --metrics-out` writes it and prints the summary.
8. `ingest: first runs — regtest fixture; testnet past N and a seed epoch` (RD-Q8); LWMA-window conformance recorded.
8c. `ingest: Rewind — the reorg source family; pop + connect through the actor with the barrier rule; digest after each switch` (RD-Q13; §3.8). The mutation family lands with it or after, Extend-only.
8b. `ci: randomx-v2-differential — header re-framed as the permanent verifier↔JIT parity gate; three_leg_verdict compares PowHashes` (RD-Q12, RD-F12) — **LANDED in this PR** after the fuzz half was found already present as the `rotating` lane. First written as "(RandomX lane, handed off)": a hand-off to a lane that does not exist, caught on the question "why not here?".
9. `docs` — DRS-E2 row, index, FOLLOWUPS sweep (items 1–7 of §2), this file to `completed/`.

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
| 2026-09-20 | **§7 commit 7b landed — the RandomX measurement (RD-F11, inventory item 7).** `ChainSubstrate::longhash` looks the cache up first and times a derive apart from the hash; the pipeline times each block's `form`; the artifact records the host beside the numbers. The number `RANDOMX_V2_MINING_ASYMMETRY.md` option (a) waits for arrives with the first real run (commit 8), not before — this commit is the instrument. |
| 2026-09-20 | **§7 commit 7 landed — grading.** The extractor is the coverage gate's parse serialized (self-tested against the gate's tally in `docs-gates.yml`); the grader takes the run's observations and emits both RD-Q9 clauses per row with `conformance::grade` applied to each; producers come from `ConnectFacts::DELETED_BY`; `passes()` is no unadjudicated disagreement; the binary grades with `--register` and exits non-zero on one. Pipeline-level test: a replayed run grades every exercised row correct and every producer borrowed. |
| 2026-09-20 | **§7 commits 8b and 6b landed.** 8b: the differential workflow is the permanent verifier↔JIT parity gate (see RD-Q12; landed here, "the RandomX lane" retired as an owner). 6b: `schedule::ChainRules` resolves height → `RuleSet` (public schedule, or regtest with `fakechain(n)` / `GENESIS`), refuses `--fixed-difficulty` off regtest by construction, and is read per block by `form` and `validate`; the `shekyl-chain-replay` binary (`fetch`, `replay`) carries the flag; a fakechain corpus replays and connects. **RD-F17**: the validator reads no seed-epoch environment, so the driver claims on the mainnet schedule at every nettype and the config knob is gone; commit 8's regtest daemon must run without `SEEDHASH_EPOCH_*`. |
| 2026-09-20 | **§7 commit 5 landed — the pipeline runs.** `connector.rs`: the Validate+Connect actor (kameo, RD-Q11) owning the `ChainStore`; one write closure per message (`Apply` = a bounded run of `Extend`s, `Rewind` = pops); §1.1's supervision table as the `Apply` handler — a refusal is data on the reply and ends the run of `Extend`s, `Fault::View` and `Fault::Corrupt` (through `refuse_corrupt`, SI-10) halt, both `Stale` arms are driver defects surfaced on first occurrence, a missing trace fact is `NoFacts`; after a terminal fault every message is `Over` and `on_panic` breaks — no restart. `seed.rs`: the driver's seed claim from a ledger of the blocks it has read (`SeedSchedule` a value, mainnet by default; Fakechain overrides in 6b); a disagreement with the store is RD-Q5's defect. `stage.rs`: `Staged`, `form_extend`. `pipeline.rs`: `run` — fill the window from the source, `spawn_blocking` forms, `Sequencer` releases in order, runs go to the actor, digests taken at the trace's checkpoint heights, `Rewind` is a barrier; the actor task is joined on every path so the store is released before `run` returns. **Tests, no-restart first as ruled**: halt → `Over` → stopped stays stopped; a five-block corpus replays and the redb digest equals the trace's checkpoint and the state computed from the chain; a wrong seed surfaces `StaleSeed` with `Retry::Again(2)`; **SI-10 end to end** — 91 blocks, a planted cumulative-difficulty decrease at 50, block 91's validation observes it and the run ends with `DifficultyRecordIncoherent(NotMonotone { at: 50 })`; a scripted reorg pops behind the barrier and the fork connects with the digest after the switch. One design consequence recorded: `ChainStore::write` makes an `InvariantViolated` win over the closure's own error, so the SI-10 row — carrying the validator's value — *is* the connector's fault, with no second wrapper to drift from it. A refusal ends the run because the refused block's child cannot connect; the mutation family (8c) revisits when each mutation is its own fork. |
| 2026-09-20 | **§7 commits 1, 6, 4a, 4b, 4c landed** (after #794 merged and was merged in). Commit 1: `WriteBatch::refuse_corrupt(Corrupt)`, SI-10 (RD-Q4); commit 6: `connect(…, in_force: RuleSet)`, `RuleSetUnknown` deleted, RD-F13's acceptance fixture (RD-Q10); 4a: the corpus and trace artifacts per §3.9, `CorpusReader` as the first `Source`, RD-Q2's two typed doors; 4b: `fetch_corpus` over the `Rpc` trait against a scripted transport, the pruned answer caught by the writer at its height; 4c: `shekyl_e2_trace_*` FFI (Rust writes and hashes; the C++ never does) and `shekyl_e2_trace_export.cpp`, opt-in `BUILD_E2_TRACE_EXPORT`, syntax-checked against the tree's headers with generated params (no C++ build on the host) — **RD-F16** found writing it: LMDB yields the spent set only at the tip, so a checkpoint exists only there. |
| 2026-09-20 | **§7 commits 2 and 3 landed.** Commit 2: `ReadSnapshot::logical_state_digest_v0` (RD-F5) — `store/digest_reads.rs` assembles `block_info` hashes over `0..=tip`, the `spent_keys` set (K2) and the live root `curve_tree_roots[tip + 1]` (`EMPTY` when nothing is recorded; a hole is SI-7) into `LogicalStateDigestV0`, which carries its **components** beside the outer digest because the root component is borrowed (RD-F7) and grades differently under RD-Q9; `digest_v0` gained `outer_preimage`/`outer_digest` so the assembly hashes once and the pinned fixture is unchanged; the live-root read is private (S-CURVE shapes the public surface). Pop-symmetry and independent-inputs tests. Commit 3: the `shekyl-chain-ingest` crate — `Source`/`IngestEvent::{Extend, Rewind}`/`Seq` (RD-Q13; `CorpusBlock` network-shaped, no facts on the event), `Sequencer` (in order, never past a gap, refuses released/pending positions), `ChainSubstrate<C: Clock>` over `compute_hash` + a shared `CacheStore` (RD-Q3, RD-F14; the hasher is total, the fault is the clock's). Alongside: `tx_reads::hash_row` (#800) was a duplicate of `chain_reads::cell` and is gone, the name↔table debug assertion moving into `cell`. |
| 2026-09-20 | **Implementation opened; §7 commit 0 landed** (`check_followups_owners.py`, RD-F4 discharged). Worktree cut from `dev` `c0b2bb12a`; the sweep since `fbc92287a` found only #800 under this plan's ground (S-TX: `read.rs` T1–T6, `lmdb_order/hash.rs`; rules, RandomX and difficulty crates unchanged), so §3's citations hold. CTS PR A (#794, `shekyl-store-codec`) is in flight and touches `store/connect.rs`; commits 1 and 6 wait for it, commits 2–4 do not. |
| 2026-09-19 | Two implementation carry-forwards pinned on §7 so they outlive the review thread: commit 1's message names itself as what #785 shed and why it waited; commit 5 writes the no-restart test first. Ground confirmed: `dev` at `6c41bf820` with #785 in — no stale ground left in this file. |
| 2026-09-19 | **PR review (Copilot, nine threads) taken.** RD-F14: `VmStatePool` is `cfg(test)`/bench-only — the parallel-`form` stage now rests on `compute_hash` per worker, the pool's promotion the RandomX lane's measure-first call. **RD-Q13 posed and defaulted:** a height-ordered stream cannot represent a reorg; the `Source` yields `Extend`/`Rewind` under a barrier rule, or E3 needs a second ingest path — commit 8c. The register count is the gate's (131 recorded, 126/2/3), not a literal; bare slice-2 `Q…` tokens qualified (rule 94 §2); RD-Q1's boundary sentence corrected (the store names `ChainValid`, never `InvalidBlock`/`Fault`/RandomX); the RD-Q9 two-clause rule restored in the CSR §5.4.1 and DRS-E2 restatements; the index documents-row and stamp brought current. |
| 2026-09-19 | **Second PR review round (Copilot, eight threads) taken; merged `dev` `fbc92287a`.** The actor owns the `ChainStore`, not a `WriteBatch` — a batch is closure-scoped by the brand, so the transaction boundary is one `write` closure per handler (a `Rewind`; a bounded run of `Extend`s = the checkpoint granularity). The supervision map is now **complete** over every non-verdict outcome (`S::Fault`, `Fault::View`, `Corrupt`, both `Stale` arms, `Exhausted`), so nothing inherits a default restart. **RD-F15:** a pruned RPC source is silent (`missed` dropped; no flag on `BlockEntry`) — the corpus writer verifies count/order/hash against `tx_hashes`, not a declaration. RD-F4's gate gets a concrete carrier: **§7 commit 0**, with the owner-cell convention and grandfather shape named. §8's stale "RD-Q9 decides whether" removed; index header, RD-F range and documents-row brought to the current state; stamp moved to `fbc92287a` with the checks re-run. S-TX's coupled E2 reopen criterion acknowledged (E2 projects no tx table). |
