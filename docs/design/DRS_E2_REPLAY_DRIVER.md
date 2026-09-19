# DRS-E2 — the ingest spine and its first source, the replay driver (pre-flight)

**Status:** OPEN — **Round 0 REVIEWED and RULED 2026-09-19 (maintainer);
Round 1 opens after #785 merges** (RD-F6). Written against `dev` @ `14f8dc739`
(post-#787) with #785 (E6 slice 2) in flight and read as landed where named.
Template: [`CHAIN_RULES_CRATE.md`](CHAIN_RULES_CRATE.md) §7.5.1's slice shape,
applied to a *program* increment. Parent plan:
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) — **DRS-D10** (replayable derived
state), **DRS-D11** (the logical-state digest as oracle), **DRS-D12 (ii)**
(*"every block the Rust store connects before cutover is validated by that
crate first: D10's replay with the validator attached, which is also the E2
harness"*), and the **DRS-E2** row (§6.1: acceptance per conformance state,
CSR-3a). Identifier families **RD-Q** (questions) and **RD-F** (findings),
registered in `IMPLEMENTATION_INDEX.md` §2 with this file.

## 0. The ruling (2026-09-19)

> **The C++ daemon is a non-canonical reference — divergences are adjudicated
> against the spec, never resolved toward C++; it is extracted from and never
> fixed. All C++ written for E2 is harvest shims that die at cutover. The
> ingest pipeline is production code shared by E2 and E3, with the replay
> driver as its first source. The sole surviving C++ is the mining JIT, behind
> a permanent parity gate.**

Everything below is derivable from that sentence; the Round-0 text that it
superseded is kept where the change is instructive and marked in-line.

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

### 1.1 The inversion (RULED 2026-09-19)

Round 0 wrote *"the driver is not the daemon's live connect path (that is
cutover, DRS-E3+)."* **Superseded.** The C++ codebase's deepest defect is
exactly there: `core_tests` / `chaingen` construct and admit blocks through a
path the network never runs, so its tests exercise code production does not.
An E2 bench tool followed by a separately built E3 live path would reproduce
that in Rust on day one. Instead the **block-ingest pipeline is built once, as
production code**, and the E2 driver *is* that pipeline with a different
source and an extra sink:

```text
Source ──► Form (N workers) ──► Sequencer ──► Validate+Connect ──► Sinks
(corpus │  (stateless; real     (reorder to   (single writer;      (digest/grader,
 now,   │   RandomX, VM pool)    height        owns the redb        checkpoints,
 p2p at │                        order)        batch; the only      metrics)
 E3)    │                                      state)
```

- **Source** is a trait. E2 plugs in the corpus reader; E3 plugs in the
  p2p/relay feed; the mutation and reorg fixture families are further sources.
- **Form** is stateless by design (slice 2 Q1) and dominated by RandomX, so it
  parallelises across workers over the existing `VmStatePool` — a bounded
  window of speculative formation, re-sequenced before validate.
- **Validate+Connect** is one actor owning the store's write transaction: the
  single-writer discipline the wallet's CT-5 actor established, and what
  redb's exclusive lock makes the only honest shape. `kameo` is the workspace
  actor stack (exact-pinned `=0.20.0`, `shekyl-engine-core/Cargo.toml:113`),
  so the daemon composing the same way is consistency, not novelty.
- **Supervision** maps the fault arms to lifecycle: `Corrupt` →
  `refuse_corrupt`, batch poisoned, pipeline halts (RD-Q4); `Retry::Exhausted`
  → terminal run error, surfaced not retried (RD-Q5); checkpoints at digest
  heights make long replays resumable.

E3's cutover then stops being "build the live connect path" and becomes
"swap the source and drop the grader." There is no C++ ingest to fall back to
at cutover (§1.3), so the pipeline E2 hardens is not merely shared with
production — it is the only ingest the daemon will ever have.

### 1.2 What it is not

A second validator (D12 (i): one crate); an FFI shim minting `ChainValid`
from the C++ verdict (rejected, D12 (ii)); a place where any consensus value
is computed outside `shekyl-chain-rules` (C2-R8 Q4 — the facts it passes
through are *read* from the LMDB record, never computed); a consumer of the
mining JIT for validation (§1.3).

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
| 2 | `Stale::Seed` → bounded retry | `fault.rs` (`FormAttempt`, `Retry`, `MAX_FORM_ATTEMPTS`); Q8 | Run the loop with the bound; in replay any `Stale::Seed` is a **driver defect** — record and surface the first occurrence (RD-Q5, RULED). |
| 3 | The production `Substrate` | `substrate.rs`; Q1 | Real `longhash` through `shekyl-pow-randomx` (`PreparedCache::derive` + `compute_hash`; `CacheStore`), a real clock; the seed claim from the chain (RD-Q3). |
| 4 | `RuleSet::fakechain` wiring | Q10 / F10; FOLLOWUPS row | `--regtest` / `--fixed-difficulty` reach `RuleSet::fakechain` through the driver (RD-Q7). |
| 5 | The test-deviation register's first consumer | F12; FOLLOWUPS row (falsifier: *this* pre-flight) | §5 carries the section F12's falsifier demands. |
| 6 | LWMA-1 conformance past `N` | `conformance_tests.rs` header; `CHAIN_RULES_CRATE.md` §8.8 | The first replay past 91 blocks exercises D4's window against a real store. |

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
  `RuleSet::fakechain(NonZeroU128)` — no `Network::Fakechain` witness (F10).
- Seed schedule: `shekyl_difficulty::{seedheight, next_seedheight,
  SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG}` after #785 (on `dev` still
  `shekyl_pow_randomx::seed_epoch`; RD-F6).

### 3.3 RandomX (`shekyl-pow-randomx`, at `dev`)

`PreparedCache::derive(Seedhash)` (the 256 MiB Argon2d fill),
`compute_hash(&PreparedCache, &[u8]) -> [u8;32]`, `CacheStore::{lookup,
lookup_or_derive, set_canonical}` (the daemon's two-epoch cache), `VmStatePool`
+ `compute_hash_with_pool`. **Cache-only today, as a measure-first staging —
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
| **tx bodies** (`Candidate.transactions`) | `txs_pruned` + `txs_prunable` (+ `txs_pqc_auths`) | `/get_blocks_by_height.bin` carries them **only from an unpruned node**; a pruned source has hash rows without segments (`block.rs`'s "band-1 skeleton") | — |
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
corpus artifact declares its prune state and is refused on read if it does
not match** (RD-F8); a pruned-source run is not a permitted deviation (§5).

### 3.5 Tooling that already exists around E2

`scripts/bench/drs_bench.py` (runs the C++ daemon under measurement
conditions; §7.4) and `drs_artifact.py` (artifact schema, §1.3 comparator,
refuses ratios across differing conditions); `check_drs_p0d_digest_coverage.py`;
the P0f register (`CONSENSUS_STORE_RECONCILIATION.md`, 124 `CEN-` rows). The
register is prose; the grader takes typed states. A row extractor is owed
(RD-Q6).

## 4. Questions — Round 0 defaults, with the 2026-09-19 rulings in-line

| Q | Question | Disposition | Why |
| --- | --- | --- | --- |
| **RD-Q1** | **Home.** | **RULED: a new crate, `shekyl-chain-ingest`** — the production ingest pipeline (§1.1), depending on rules + store + `shekyl-pow-randomx`, with the replay driver as its first `src/bin/`. *Round-0 default was `shekyl-chain-replay`, "a test tool"; same dependency shape, different name and life expectancy.* Rule 18: the corpus/trace format types live in the ingest crate (or `shekyl-store-codec` once CTS PR A lands), never in a binary. | The store crate is `#![deny(unsafe_code)]` and names neither RandomX nor the verdict type (conversion ban clause 2); the pipeline keeps the store ignorant of the validator's faults and G1 trivially true. |
| **RD-Q2** | **Block, body and fact source** (§3.4). | **RULED: corpus from RPC, trace from one LMDB exporter → bytes across the FFI → a Rust writer; the format minted in Rust with a version constant, one serializer shared by writer and reader.** *Round-0 default (c) — extend `blockchain_export`'s bootstrap file — is **withdrawn** (RD-F9): that container is Monero's, serialized with epee, and a Rust reader of it is a second parser of an inherited format, rule 16's pattern.* Keeps everything that made (c) attractive (offline, one artifact per chain, no LMDB crate) and keeps the C++ change a transport shim that dies at cutover (§1.3). | Byte transport across the FFI is what D12 allows; verdicts are what it rejected. The digest walker (`logical_state_digest.cpp` → FFI) is the existing shape. |
| **RD-Q3** | **Production `Substrate`.** | **Default holds with one correction:** two-cache `CacheStore` keyed by the chain's seed at `seedheight(h)`, swapped at epoch boundaries; wall clock. *Round 0 called the retry loop "load-bearing" at the boundary; **withdrawn** (RD-F10) — the driver takes the seed from the chain it replays, so a `Stale::Seed` cannot arise from a correct driver; it is a defect signal (RD-Q5).* Throughput: parallel `form` workers over `VmStatePool` (§1.1) now; the Rust dataset mode is an **open option gated on a measurement E2 itself produces** — the pipeline's metrics sink records light-mode wall-clock per hash and per block, which is the number `RANDOMX_V2_MINING_ASYMMETRY.md` option (a) has been waiting for (RD-F11); never the JIT (§1.3). **Caveat:** C1's FTL leg reads the clock and a historical block is always below `now + FTL`, so replay cannot exercise C1's refusal — recorded in §5. | Reuses the daemon's cache lifecycle; the epoch boundary is where a stale cache would silently produce wrong longhashes, and that now surfaces as a defect, not a retry. |
| **RD-Q4** | **`Fault::Corrupt` at the store.** | **RULED as defaulted:** `WriteBatch::refuse_corrupt(Corrupt) -> StoreError`, inside the batch, arming the poison at the noted height with a `StoreInvariant` row mapped from the `Corrupt` arm (new SI rows minted with it), returning the `InvariantViolated` the pipeline propagates. Minted here **with its caller** — the commit-9 scope #785 shed, as ruled 2026-09-19. | The validator saw what a belt would have; the store's halt is the consequence and must poison *this* batch. Taking the value keeps the store from naming `CenRow`s it does not own. |
| **RD-Q5** | **The retry loop and `Stale::Seed` in replay.** | **RULED:** the loop lives in the pipeline (`form` → `validate`; on `Stale::Seed` re-`form` with the expected seed and `attempt.next()`; `Exhausted` → terminal run error). **In replay every `Stale::Seed` is a driver defect: the run records and surfaces the first occurrence rather than retrying it away**, and **the retry path is exercised by a test that injects a wrong seed**, not by waiting for a bug. The live-daemon role (Q8's DoS bound) is unaffected. | Resolves the RD-Q3/RD-Q5 contradiction Round 0 carried (RD-F10). |
| **RD-Q6** | **Grading.** | **RULED as defaulted, plus one rule:** Python extractor → JSON → the pure Rust grader, reusing `drs_artifact.py`'s schema discipline. **Rows whose value is sourced from a passed-through fact grade as not-evidence** ("borrowed is never evidence", RD-F7): identity there is copying, not conformance. Under §1.3 the rule's point is honesty about progress toward Rust deriving everything, not fidelity to C++. | The register is prose Python already parses (`check_conformance_coverage.py`); the grade is reproducible from the artifact alone. |
| **RD-Q7** | **Fakechain wiring.** | **RULED as defaulted:** the driver takes `--fixed-difficulty n` → `RuleSet::fakechain(n)`, refused unless the nettype is regtest; the `Network::Fakechain` witness stays its own change (12 files / 9 crates). | The consumers need the lever, not the witness. |
| **RD-Q8** | **First chains.** | **RULED as defaulted:** regtest (the `e2e_fcmp_spend_accepted_by_daemon` fixture, ~80 s), then a testnet snapshot past `N` **and** a seed epoch (≥ 2113 blocks). | Only a chain past 2112 exercises the cache swap and D3's roll-over against real data. |

## 5. Test deviations (F12's first live section)

| Deviation | Reason | Reopen / falsify |
| --- | --- | --- |
| C1's FTL refusal is not exercised by replay | historical blocks are always below `now + FTL` | a synthetic future-stamped block appended to a regtest replay; owed as an E2 fixture |
| `--fixed-difficulty` on regtest runs (RD-Q7) | the bench needs real RandomX cost at a reachable target | production nets refuse the flag by type (`for_network` cannot yield `Fixed`, pinned) |
| `drs_bench.py`'s lowered target | benchmark reproducibility on the provisioning floor | the artifact records the target; `drs_artifact.py` refuses cross-condition ratios |
| The redb file's `Provenance` is NOT-PARITY-EVIDENCE throughout E2 | six facts passed through; enforced rows unimplemented | `passed_through().count() == 0 && coverage_gaps().is_empty()` — the genesis gate |
| **Pruned corpus source — NOT PERMITTED** | bodies are the validator's input (RD-F8); a pruned source yields skeletons | the corpus artifact declares `prune_state`; the reader refuses a mismatch. If a pruned-source run is ever allowed, it enters this table as a deviation with its own reopener first. |

## 6. Findings

- **RD-F1 — the daemon RPC cannot source the driver's facts.** `coins_generated`,
  `burned`, `long_term_effective_median` are LMDB-only (§3.4); computing them
  in the driver is a C2-R8 Q4 violation. Decides RD-Q2's trace half.
- **RD-F2 — no LMDB crate in the workspace.** A Rust LMDB reader is a new
  dependency; rule 17's verification at source is owed before it can be
  *proposed*. Moot under RD-Q2's ruling (the exporter reads LMDB in C++).
- **RD-F3 — six items routed to a lane that did not exist.** Individually
  legitimate deferrals; in aggregate an unchosen queue (rule 22). This file is
  the repair; the generalization is RD-F4.
- **RD-F4 — proposed gate: a deferral's owner must resolve** (endorsed
  2026-09-19 as a standing check). Every `FOLLOWUPS.md` row's owner must
  resolve to a live `docs/design/` doc, an open PR, or an index-§2 family.
  Same family as `held_by_cxx` asserting its holder exists. **Falsify by**
  `scripts/ci/check_followups_owners.py` existing and refusing a row whose
  owner is "the E2 lane" with no `DRS_E2_*.md` present. Owner: this lane, its
  own small PR after Round 1; target pre-genesis.
- **RD-F5 — the redb-side digest assembly does not exist.** `digest_v0` has one
  caller, fed by C++. E2 needs the same three families read from the redb
  file — `ReadSnapshot::logical_state_digest_v0()` or a pipeline-side assembly
  over the existing reads. Owed to this increment.
- **RD-F6 — the seed schedule's home moves under this file** (#785). Round 1
  opens after it merges.
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
- **RD-F11 (review's throughput item, checked at source; corrected
  2026-09-19) — the verifier is cache-only as a measure-first staging, not by
  ruling.** This finding first read `RANDOMX_V2_RUST.md:544` (*"verifier code
  does not use the full 2 GiB dataset"*) as a foreclosure requiring a
  reopening. **Wrong:** the dataset path was left unbuilt to measure whether
  the daemon needed it — §4 of that plan lists `Dataset::derive(cache)` as a
  planned transform, and `RANDOMX_V2_MINING_ASYMMETRY.md` names the
  no-dataset verifier as the thing its option (a) revisits once Phases 1–3
  produce a number; none has. Upstream's full-memory mode is ~10× faster per
  hash for a ~2 GiB init that amortises over a long replay. So: the dataset
  mode is an **open option whose trigger is the measurement**, and E2 is the
  first real verification workload able to produce it — the pipeline emits
  light-mode wall-clock per hash / per block as a sink metric, feeding that
  study rather than deciding for it. Line 544 amended in the same commit so
  it no longer reads as a ruling (sibling-lane write, disclosed). The JIT is
  never the lever (§1.3).
- **RD-F12 (ruling) — the mining JIT is the one permanent C++↔Rust boundary,
  with a standing obligation.** The RandomX parity corpus and
  `randomx-v2-differential.yml` become a **permanent gate** (full vector set on
  every pin move of either side; ongoing `longhash` fuzz across the boundary),
  and at cutover the FFI direction flips for this dependency alone — a vendored
  C library behind a rule-40 adapter crate, W^X confined to mining. Owner: the
  RandomX lane; recorded here because E2's ruling created the obligation.
  Falsify by the workflow's description no longer reading as rewrite
  scaffolding and its trigger including the JIT pin.

## 7. Commit plan (sketch; Round 1 fixes it)

1. `chain-store: WriteBatch::refuse_corrupt — the validator's Corrupt arms the halt` (RD-Q4; new SI rows; withdraws the FOLLOWUPS row).
2. `chain-store: ReadSnapshot::logical_state_digest_v0 — the redb half of E2` (RD-F5).
3. `ingest: shekyl-chain-ingest scaffold — Source trait, pipeline stages, production Substrate over shekyl-pow-randomx` (RD-Q1, RD-Q3).
4. `ingest: corpus + trace formats (Rust-minted, versioned); RPC corpus reader with prune-state refusal; LMDB trace exporter as a C++ harvest shim` (RD-Q2, RD-F8, RD-F9).
5. `ingest: form workers → sequencer → validate+connect actor; Corrupt → halt; Stale::Seed surfaced; injected-wrong-seed test` (RD-Q5).
6. `ingest: --fixed-difficulty → RuleSet::fakechain on regtest` (RD-Q7).
7. `ingest: CSR-3a grading — extractor, artifact, borrowed-is-not-evidence rule, grader wiring` (RD-Q6, RD-F7).
8. `ingest: first runs — regtest fixture; testnet past N and a seed epoch` (RD-Q8); LWMA-window conformance recorded.
9. `docs` — DRS-E2 row, index, FOLLOWUPS sweep (items 1–6 of §2), the RandomX parity-gate obligation handed to its lane (RD-F12), this file to `completed/`.

## 8. Expected record at close

The redb file for a replayed chain carries `Provenance` with
`passed_through = [weight, long_term_weight, coins_generated, burned,
root_after, long_term_effective_median]` and E6's open coverage gaps —
NOT-PARITY-EVIDENCE, honestly. **Of the digest's three components, two are
evidence (block hashes; spent keys — both from real `form` → `validate` →
`connect`) and one is borrowed (`curve_root`, copied from LMDB through
`root_after`) and is graded as such** (RD-F7). Register rows sourced from a
passed-through fact grade not-evidence by rule, and the artifact names them.
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
| 2026-09-19 | **Round 0 REVIEWED and RULED (maintainer).** Substrate claims confirmed at `dev` `14f8dc739`. Four findings taken: RD-F7 (the root component compares a copy of itself → borrowed-is-never-evidence grader rule; §8 names the real components), RD-F8 (tx bodies; unpruned source; prune state declared and refused), RD-F9 (bootstrap format inherited → Rust-minted trace format), RD-F10 (Q3/Q5 contradiction → `Stale::Seed` is a defect signal in replay; injected-seed test). **The ruling (§0):** C++ is a non-canonical reference, adjudicated against the spec with two outcomes, extracted from and never fixed; all E2 C++ is harvest shims that die at cutover; the ingest pipeline is production code shared by E2 and E3 (§1.1 — RD-Q1 → `shekyl-chain-ingest`); the mining JIT is the sole surviving C++ behind a permanent parity gate (RD-F12). Throughput item checked at source: cache-only today; the dataset mode is measurement-gated, not ruled out (RD-F11 as first written said "by ruling" — corrected the same day; E2 emits the measurement). RD-Q4/Q6/Q7/Q8 as defaulted; RD-F4 endorsed as a standing check. Round 1 opens after #785 merges. |
