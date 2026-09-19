# DRS-E2 — the replay-that-validates driver (pre-flight)

**Status:** OPEN — **Round 0 (sweep and questions), 2026-09-19.** Written
against `dev` @ `14f8dc739` (post-#787) with #785 (E6 slice 2) in flight and
read as landed where named. Template: [`CHAIN_RULES_CRATE.md`](CHAIN_RULES_CRATE.md)
§7.5.1's slice shape, applied to a *program* increment rather than a rules
slice. Parent plan: [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) — **DRS-D10**
(replayable derived state), **DRS-D11** (the logical-state digest as oracle),
**DRS-D12 (ii)** (*"every block the Rust store connects before cutover is
validated by that crate first: D10's replay with the validator attached, which
is also the E2 harness"*), and the **DRS-E2** row (§6.1: acceptance per
conformance state, CSR-3a). Identifier families **RD-Q** (questions) and
**RD-F** (findings), registered in `IMPLEMENTATION_INDEX.md` §2 with this
file.

**Why this file exists now, stated plainly.** Six pieces of landed or planned
work route to "the driver" and, until this file, no document, branch or PR
owned it — "owner: the E2 lane" named a lane that did not exist in any form
(caught 2026-09-19 on #785's review; rule 22's queue-that-accumulated). DRS-D12
ratified the driver as the Rust store's *only* pre-cutover writer, so this is
not new scope: it is the scheduled work the plan assumed would arrive and
nobody assigned. It is also the first time the validator runs against a real
chain — slices 1 and 2 stood in for that with mock views and fixtures, and the
fixture ceiling is now visible in the conformance harness itself (the store
fixtures' `0xc0 + h` root bytes cap chains at 63; a full LWMA-1 window past
`N` cannot be built). Replay-that-validates *is* the production pathway;
everything before it was the theoretical version.

---

## 1. What the driver is, and is not

**Is:** a loop that, for each block of an existing chain, runs
`shekyl_chain_rules::form` (stateless, real RandomX, outside the write
transaction) → `validate` over the redb `BatchView` (inside it) →
`ChainStore::connect` with the passed-through facts the validator does not yet
derive → and, at chosen heights, assembles the redb-side logical-state digest
and grades it against the LMDB digest **per row's conformance state** (CSR-3a,
`conformance.rs`). Its outputs are (a) a redb file whose `Provenance` is
honest about coverage gaps and passed-through facts, and (b) a graded
comparison artifact.

**Is not:** the daemon's live connect path (that is cutover, DRS-E3+); a
second validator (D12 (i): one crate); an FFI shim minting `ChainValid` from
the C++ verdict (rejected, D12 (ii)); or a place where any consensus value is
computed outside `shekyl-chain-rules` (C2-R8 Q4 — the facts it passes through
are *read* from the LMDB record, never computed by the driver).

## 2. The inventory this increment resolves

Every item below was deferred to "the driver" with a falsifier that needs a
driver to fire. They are this increment's owed list, in one place.

| # | Item | Where it was deferred | What the driver must do |
| --- | --- | --- | --- |
| 1 | `Fault::Corrupt` → writer halt | `CHAIN_RULES_SLICE_2.md` §4.3; FOLLOWUPS row | Receive a `Corrupt` from `validate` and arm the store's halt at the noted height, as a belt does; the store API is **minted here, with its caller** (RD-Q4). |
| 2 | `Stale::Seed` → bounded retry | `fault.rs` (`FormAttempt`, `Retry`, `MAX_FORM_ATTEMPTS`); Q8 | Run the `form` → `validate` → `Stale` → re-`form` loop with the bound, and take `Retry::Exhausted` to a named terminal state (RD-Q5). |
| 3 | The production `Substrate` | `substrate.rs`; Q1 | Real `longhash` through `shekyl-pow-randomx` (`PreparedCache::derive(seedhash)` + `compute_hash`; `CacheStore::lookup_or_derive`), a real clock; the seed claim from the chain (RD-Q3). |
| 4 | `RuleSet::fakechain` wiring | Q10 / F10; FOLLOWUPS row | The two consumers (`drs_bench.py`, `curve_tree_header_root_check.cpp`) need `--regtest` / `--fixed-difficulty` to reach `RuleSet::fakechain` through the driver (RD-Q7). |
| 5 | The test-deviation register's first consumer | F12; FOLLOWUPS row (falsifier: *this* pre-flight) | §5 below — this file carries the section F12's falsifier demands. |
| 6 | LWMA-1 conformance past `N` | `conformance_tests.rs` header; `CHAIN_RULES_CRATE.md` §8.8 | The first replay past 91 blocks exercises D4's window against a real store. |

## 3. Round-0 sweep — what exists, verified at source

### 3.1 The store side (`shekyl-chain-store`, at `dev`)

- `ChainStore::create(path, epoch)` / `open_read_only`; `ChainStore::write(|batch| …)`
  runs one exclusive write transaction; `WriteBatch::chain_view()` yields the
  branded `BatchView<'_, 'id>`; `WriteBatch::connect(ChainValid<'id, BatchView>,
  ConnectFacts, RuleSetId)`; `pop`. Halt: `ConnectState::{Live, Halted{height,
  row}}` (`halt.rs`), armed by `Poison::arm(StoreInvariant)` — **`pub(super)`**,
  reachable only from the store's own belts (`write.rs:95`). There is no
  public way for a caller to hand in a violation it observed: that is item 1's
  API, absent by design until now.
- `ConnectFacts` after #785: six passed-through fields — `weight`,
  `long_term_weight`, `coins_generated`, `burned`, `root_after`,
  `long_term_effective_median` (`cumulative_difficulty` is derived). The driver
  must **source** all six per block (§3.4).
- `Provenance` records `PassedThroughFacts` and `CoverageGaps`; only all-empty
  is parity evidence (`is_parity_evidence`). The driver's output file will be
  NOT-PARITY-EVIDENCE for as long as any fact is passed through or any
  enforced row unimplemented — which is the honest state, and the record E2
  grades against.
- `conformance.rs`: the CSR-3a grader exists as pure logic —
  `ConformanceState::{CheckedConformant, Divergent, Unreviewed}`,
  `Acceptance`, `FailureReason`, `ReviewedDivergence`, `FinalVerdict`, with a
  truth-table test. **No caller assembles rows from the register into it.**
- `digest_v0.rs`: `digest_v0(block_hashes, spent_keys, root)`,
  `chain_component`, `spent_accumulator` — the hasher. `ReadSnapshot::key_images`
  (read.rs K2) exists *for* the digest's `spent_keys` scan. **No redb-side
  assembly** walks `block_info` hashes + `key_images` + the live root into
  `digest_v0` — the only caller is the C++-fed FFI (`chain_digest_ffi.rs:69`).
  The redb half of E2's comparison is owed here (RD-F5).

### 3.2 The rules side (`shekyl-chain-rules`, at #785)

- `form(candidate, &RuleSet, &impl Substrate, seed: BlockHash, FormAttempt)
  -> Result<Verdict<StructurallyValid>, S::Fault>`; `validate(StructurallyValid,
  &V, &RuleSet) -> Result<Verdict<ChainValid<'id, V>>, Fault<V::Fault>>`;
  `Fault::{View, Stale(Stale::{Seed{..}, RuleSet{..}}), Corrupt(Corrupt::{…})}`;
  `FormAttempt::FIRST`, `Retry::{Again, Exhausted}`, `MAX_FORM_ATTEMPTS`.
- `Substrate { type Fault; local_clock(); longhash(pow_blob, seed) }` — the
  trait; only `MockSubstrate` / `FixtureSubstrate` implement it.
- `RuleSet::GENESIS`, `RuleSet::for_network(Network)` (three public nets),
  `RuleSet::fakechain(NonZeroU128)` — the Fakechain constructor with no
  `Network::Fakechain` witness (F10).
- Seed schedule: `shekyl_difficulty::{seedheight, next_seedheight,
  SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG}` (moved from `shekyl-pow-randomx`
  by #785 commit 6a; on `dev` today it is still `shekyl_pow_randomx::seed_epoch`
  — this file cites the post-#785 home).

### 3.3 RandomX (`shekyl-pow-randomx`, at `dev`)

`PreparedCache::derive(Seedhash)` (the 256 MB Argon2d fill; seconds on the
provisioning floor, rule 76), `compute_hash(&PreparedCache, &[u8]) -> [u8;32]`,
`CacheStore::{lookup, lookup_or_derive, set_canonical}` (the daemon's
two-epoch cache), `VmStatePool` + `compute_hash_with_pool`. The production
`Substrate::longhash` is a thin adapter over these; the design question is
cache lifecycle across the seed-epoch boundary during a long replay (RD-Q3).

### 3.4 Block and fact sources — the load-bearing finding

The driver needs, per height: the block blob, and the six passed-through
facts. What each candidate source provides:

| Fact | LMDB | RPC (`get_block_header_by_height`, `shekyl-rpc-types::chain`) | Derivable by the driver? |
| --- | --- | --- | --- |
| block blob | `blocks[h]` | `/get_blocks_by_height.bin` (`bin_commands.rs:160`) | — |
| `weight` | `block_info.bi_weight` | `block_weight` ✔ | no (CEN-G6, slice 7) |
| `long_term_weight` | `block_info.bi_long_term_block_weight` | `long_term_weight` ✔ | no |
| `coins_generated` | `block_info.bi_coins` | **✘** (`reward` per block only; the fold is CEN-F13/F14, slice 4 — the driver may not compute it, C2-R8 Q4) | no |
| `burned` | `block_burn[h]` | **✘** (`total_burned` only, on `get_info`) | no |
| `root_after` | `curve_tree_roots[h+1]` | header `h+1`'s `curve_tree_root` (SCW-19) — ✔ with a one-block lookahead, ✘ at the tip | no (S-CURVE) |
| `long_term_effective_median` | `block_info` (S-CHAIN-R A1) | **✘** | no |

**So the daemon RPC cannot feed the driver** (RD-F1): three of six facts are
LMDB-only, and computing them in the driver is exactly what C2-R8 forbids.
The source is LMDB, read one of three ways (RD-Q2): (a) a C++ exporter that
walks `for_blocks_range` + `block_info` and hands `(blob, facts)` per height
across an FFI to a Rust step — the digest walker's shape
(`logical_state_digest.cpp` → `shekyl_logical_state_digest_v0`), with the
loop's *logic* in Rust and the C++ a transport shim (rule 20); (b) a Rust LMDB
reader against `LMDB_SCHEMA.md` — **no LMDB crate is in the workspace**
(RD-F2; rule 17 verification owed before it is proposed); (c) an extension of
the existing `blockchain_export` bootstrap file
(`src/blockchain_utilities/bootstrap_file.cpp`) to carry the facts, consumed
offline by a Rust reader — no live daemon needed, one artifact per chain.

### 3.5 Tooling that already exists around E2

`scripts/bench/drs_bench.py` (runs the C++ daemon under measurement
conditions; §7.4) and `drs_artifact.py` (artifact schema, §1.3 comparator,
refuses ratios across differing conditions); `check_drs_p0d_digest_coverage.py`;
the P0f register (`CONSENSUS_STORE_RECONCILIATION.md`, 124 `CEN-` rows, 150
`CHECKED-CONFORMANT` tokens at this pin). The register is prose; the grader
takes typed states. A row extractor is owed (RD-Q6).

## 4. Questions for Round 1

| Q | Question | Default | Why the default |
| --- | --- | --- | --- |
| **RD-Q1** | **Home.** A `src/bin/` in `shekyl-chain-store`, or a new crate `shekyl-chain-replay` depending on rules + store + `shekyl-pow-randomx` + the block source? | **New crate.** | The store crate is `#![deny(unsafe_code)]` and names neither RandomX nor the verdict type (conversion ban clause 2); a binary inside it would have to. A driver crate keeps the store ignorant of the validator's fault arms and G1 trivially true, and is where the FFI edge for source (a) or the reader for (b)/(c) lives without touching either library. |
| **RD-Q2** | **Block + fact source** (§3.4): (a) C++ walker → FFI step, (b) Rust LMDB reader, (c) fact-bearing bootstrap export. | **(c), with (a) as the fallback if the export format fight is larger than it looks.** | (c) needs no live daemon, produces one reviewable artifact per chain (the same artifact the comparator reads), keeps the C++ change to an exporter (Rust-forward: the reader and the loop are Rust), and avoids a new LMDB dependency (b) whose rule-17 verification has not been done. (a) runs the loop across an FFI per block — the shape D12 rejected for verdicts, tolerable for bytes, but it ties every replay to a running daemon. |
| **RD-Q3** | **Production `Substrate`.** One `PreparedCache` derived per seed epoch, swapped at `seedheight` boundaries; clock = system time (replay is not time-sensitive except C1, which is exempt below FTL for historical blocks by construction — but see the caveat). | **Two-cache `CacheStore` as the daemon uses, keyed by the chain's seed at `seedheight(h)`; wall clock.** | Reuses the daemon's lifecycle; a replay crossing an epoch boundary is the one place a stale cache would silently produce wrong longhashes, and `Stale::Seed` is exactly the arm that catches a seed/cache mismatch — so the retry loop (RD-Q5) is load-bearing here, not decorative. **Caveat to rule:** C1's FTL leg reads the clock; a historical block is always below `now + FTL`, so replay cannot exercise C1's refusal — record it as a gap the E2 run does not grade (§5). |
| **RD-Q4** | **`Fault::Corrupt` at the store.** Shape of the halt API the driver calls: hand in the `Corrupt` value; or a `(row, height)`; inside the batch (poison it) or outside (a store-level halt)? | **Inside the batch, taking the `Corrupt` value: `WriteBatch::refuse_corrupt(Corrupt) -> StoreError`** that arms the poison at the noted height with a `StoreInvariant` row mapped from the `Corrupt` arm (`CumulativeDifficultyNotMonotone` → an SI row; `ZeroTarget` → an SI row) and returns the `InvariantViolated` the driver propagates. | The validator saw what a belt would have seen; the store's halt is the right consequence, and it must poison *this* batch so the connect that follows cannot run. Mapping arms to SI rows keeps `STORE_INVARIANT_REGISTER.md` the one register of store-side violations (new SI rows minted with it). Taking the value, not a triple, keeps the store from naming `CenRow`s it does not own. **This is the API commit 9 shed; it lands here with its caller, as ruled 2026-09-19.** |
| **RD-Q5** | **The retry loop.** Where `FormAttempt` iterates, and what `Retry::Exhausted` becomes. | **In the driver: `form` → `validate`; on `Stale::Seed { expected, .. }` re-`form` with the expected seed and `attempt.next()`; on `Exhausted`, the driver halts the run with a named terminal error (not a verdict, not a store halt).** | Exhaustion means the chain's seed changed under the driver more times than the bound — impossible in replay of a fixed chain, so hitting it is a driver bug, and a run-level error is the right severity. In the live daemon (E3+) the same arm is the DoS bound Q8 ruled. |
| **RD-Q6** | **Grading.** How the register's rows reach `conformance.rs`: a Python extractor emitting typed states the Rust grader reads, or a Rust parser of the register? | **Python extractor → JSON → Rust grader**, reusing `drs_artifact.py`'s schema discipline; the grader stays pure. | The register is a document and Python already parses it for gates (`check_conformance_coverage.py`); a Rust markdown parser is a second parser of one file. The artifact carries the row states with the digests so a grade is reproducible from the artifact alone. |
| **RD-Q7** | **Fakechain wiring.** Does the driver take `--fixed-difficulty n` and build `RuleSet::fakechain(n)`, closing Q10's owed consumers? And does `Network::Fakechain` get minted here or stay owed? | **Yes to the flag; the witness stays owed to its own change** (12 files / 9 crates), with the driver's discipline — the flag is refused unless the nettype is regtest — as the interim guard, named as such. | The consumers need the lever, not the witness; the witness is a type-level improvement whose ripple is out of this increment's scope, and pretending otherwise would be the "while we're here" rule 15 forbids. Falsifier unchanged. |
| **RD-Q8** | **What the first run replays.** A regtest chain from `e2e_fcmp_spend_accepted_by_daemon`'s fixture, or a testnet snapshot? | **Regtest first (the fixture exists, 80 s), then a testnet snapshot long enough to cross `N` and a seed epoch (≥ 2113 blocks).** | Regtest proves the loop; only a chain past 2112 exercises RD-Q3's cache swap and D3's roll-over against real data, which nothing has yet. |

## 5. Test deviations (F12's first live section)

Every way the E2 run differs from production configuration, as a row with a
reason and a reopening criterion — the shape `docs/FOLLOWUPS.md`'s
test-deviation register row asks for, carried here until that register exists
(and this section becomes its first import).

| Deviation | Reason | Reopen / falsify |
| --- | --- | --- |
| C1's FTL refusal is not exercised by replay | historical blocks are always below `now + FTL` | a synthetic future-stamped block appended to a regtest replay; owed as an E2 fixture |
| `--fixed-difficulty` on regtest runs (RD-Q7) | the bench needs real RandomX cost at a reachable target | production nets refuse the flag by type (`for_network` cannot yield `Fixed`, pinned) |
| `drs_bench.py`'s lowered target | benchmark reproducibility on the provisioning floor | the artifact records the target; `drs_artifact.py` refuses cross-condition ratios |
| The redb file's `Provenance` is NOT-PARITY-EVIDENCE throughout E2 | six facts passed through; enforced rows unimplemented | `passed_through().count() == 0 && coverage_gaps().is_empty()` — the genesis gate |

## 6. Findings

- **RD-F1 — the daemon RPC cannot source the driver's facts.** `coins_generated`,
  `burned`, `long_term_effective_median` are LMDB-only (§3.4); computing them
  in the driver is a C2-R8 Q4 violation. Decides RD-Q2's option space.
- **RD-F2 — no LMDB crate in the workspace.** A Rust reader (RD-Q2 (b)) is a
  new dependency; rule 17's verification at source (crate, version, feature
  plumbing, unsafe posture) is owed before it can be *proposed*, not after.
- **RD-F3 — six items routed to a lane that did not exist.** Rows in
  `FOLLOWUPS.md` and slice docs named "the E2 lane" as owner with no doc,
  branch or PR. Individually legitimate deferrals; in aggregate an unchosen
  queue (rule 22). This file is the repair; the generalization is RD-F4.
- **RD-F4 — proposed gate: a deferral's owner must resolve.** For every
  `FOLLOWUPS.md` row (and every `held_by_cxx`-style status), the named owner
  must resolve to a live plan doc under `docs/design/`, an open PR, or a
  registered lane — mechanically: an `owner:`/`Owner:` cell whose target is a
  path that exists, a `#NNN` that `gh pr view` reports OPEN, or an index-§2
  family. Same family as `held_by_cxx` asserting its holder exists and rule
  47's subject assertion. **Falsify by** `scripts/ci/check_followups_owners.py`
  existing and refusing a row whose owner is "the E2 lane" with no
  `DRS_E2_*.md` present. Owner: this lane, as its own small PR after Round 1;
  target pre-genesis.
- **RD-F5 — the redb-side digest assembly does not exist.** `digest_v0` has one
  caller, fed by C++ walking LMDB. E2's comparison needs the same three
  families read from the redb file (`block_info` hashes in height order,
  `key_images`, the live root) — a `ReadSnapshot::logical_state_digest_v0()`
  or a driver-side assembly over the existing reads. Owed to this increment.
- **RD-F6 — the seed schedule's home moves under this file.** `dev` has it in
  `shekyl-pow-randomx::seed_epoch`; #785 moves it to
  `shekyl-difficulty::seed_epoch`. Round 1 opens after #785 merges so the
  citations here are read against one tree.

## 7. Commit plan (sketch; Round 1 fixes it)

1. `chain-store: WriteBatch::refuse_corrupt — the validator's Corrupt arms the halt` (RD-Q4; new SI rows; withdraws the FOLLOWUPS row).
2. `chain-store: ReadSnapshot::logical_state_digest_v0 — the redb half of E2` (RD-F5).
3. `replay: crate scaffold; production Substrate over shekyl-pow-randomx` (RD-Q1, RD-Q3).
4. `replay: block + fact source` per RD-Q2 (the exporter side in C++ as a shim if (c)/(a)).
5. `replay: the loop — form → validate → connect with the bounded retry; Corrupt → halt` (RD-Q5).
6. `replay: --fixed-difficulty → RuleSet::fakechain on regtest` (RD-Q7).
7. `replay: CSR-3a grading — register extractor, artifact, grader wiring` (RD-Q6).
8. `replay: first runs — regtest fixture; testnet past N and a seed epoch` (RD-Q8); the LWMA-window conformance recorded.
9. `docs` — DRS-E2 row, index, FOLLOWUPS sweep (items 1–6 of §2), this file to `completed/`.

## 8. Expected record at close

The redb file for a replayed chain carries `Provenance` with
`passed_through = [weight, long_term_weight, coins_generated, burned,
root_after, long_term_effective_median]` and the coverage gaps E6 has not yet
closed — NOT-PARITY-EVIDENCE, honestly. The graded artifact reports, per
register row, CHECKED-CONFORMANT identity held / DIVERGENT rows not
reproduced / UNREVIEWED observed-only, with **every** disagreement named. The
six items of §2 each resolve to landed code or a re-pointed FOLLOWUPS row with
a live owner.

---

## Round log

| Date | Entry |
| --- | --- |
| 2026-09-19 | **Round 0.** Opened on #785's review after "owner: the E2 lane" was found to name nothing. Sweep at source: store, rules, RandomX, digest, grader, block/fact sources (RD-F1: RPC cannot feed the facts). Eight questions with defaults; six findings, one a proposed gate (RD-F4). Opens **before** #785 merges so #785's deferrals point at a document under review rather than a hypothesis; Round 1 opens after #785 merges (RD-F6). |
