# Perf interim PR pre-flight: merge pipeline returns insertion indices

**Status.** Read-only investigation. No code changes proposed yet.
This document operationalizes the FOLLOWUPS V3.0 entry
**“`populate_engine_handle_fields` O(n) → O(k) per scan”** against
the workspace state at `dev` tip `9e53c82fa` (Merge of PR #36 —
the `workflow_dispatch` runner-bisect workflow). It is a peer to
[`STAGE_1_PR_3_M3B_PREFLIGHT.md`](./STAGE_1_PR_3_M3B_PREFLIGHT.md):
M3b landed the engine post-pass; this PR makes the post-pass scale
with the number of new transfers per scan rather than with the total
ledger size.

**Cross-references.** Closes the V3.0 follow-up
*“`populate_engine_handle_fields` O(n) → O(k) per scan (trigger:
immediate post-M3b interim PR; pre-RC1)”*
([`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) §V3.0). Touches
`engine::merge` per
[`STAGE_1_PR_3_M3B_PREFLIGHT.md`](./STAGE_1_PR_3_M3B_PREFLIGHT.md)
§3 (δ) but does not alter that disposition — the sync/async split
the M3b post-pass introduced is preserved verbatim.

**Mission posture.** Per `00-mission.mdc`, this PR addresses the
*Now* timeframe (refresh latency at 100k–1M transfer scales). It
does not affect the mining-era or PQC timeframes; nothing in the
change crosses the security/privacy frontier. Per
`00-mission.mdc`’s priority hierarchy, the PR is priority-3
("system must outlast the team") work — performance hardening so a
future maintainer running a long-lived wallet does not see refresh
latency growing linearly with ledger size.

---

## §1 What the PR fixes

`Engine::apply_scan_result`’s engine post-pass currently walks
`ledger.transfers` linearly on every refresh:

```text
rust/shekyl-engine-core/src/engine/merge.rs:506
fn populate_engine_handle_fields(ledger, view_secret, residue) {
    if residue.is_empty() { return; }
    for td in &mut ledger.transfers {              // ← O(n) per scan
        let key = (td.tx_hash, td.internal_output_index);
        let Some(ciphertext) = residue.get(&key) else { continue; };
        …
    }
}
```

`residue` only ever contains `result.new_transfers.len()` keys
(call this `k`), so the loop body executes effectively `k` times,
but the iteration count is `n = ledger.transfers.len()`. Refresh
shape today is **O(n × B)** where `B` is the number of refresh
batches — for a ledger of 100k transfers refreshed across 1k
batches with `k ≈ 10` per batch, the post-pass alone allocates
~10⁸ HashMap probes that find nothing.

The fix threads the inserted-index list out of the merge pipeline
so `populate_engine_handle_fields` can iterate **O(k)** by slicing
into `ledger.transfers` at the captured indices rather than scanning
the full Vec.

---

## §2 Trait-surface change inventory

Three return-type changes propagate the index information from the
bottom of the merge stack to the post-pass at the top.

### §2.1 `LedgerIndexes::ingest_block` (`shekyl-engine-state`)

**Definition** — `rust/shekyl-engine-state/src/ledger_indexes.rs:133`.

```rust
pub fn ingest_block(
    &mut self, ledger: &mut LedgerBlock, block_height: u64,
    block_hash: [u8; 32], transfers: Vec<TransferDetails>,
) -> usize { … added }                                    // before

pub fn ingest_block(
    &mut self, ledger: &mut LedgerBlock, block_height: u64,
    block_hash: [u8; 32], transfers: Vec<TransferDetails>,
) -> Range<usize> { … start..ledger.transfers.len() }     // after
```

**Why a `Range` and not a `Vec<usize>`.** The function appends
accepted transfers sequentially via `ledger.transfers.push(td)` and
skips the burning-bug duplicate path with `continue;` (line 149)
*before* computing `idx = ledger.transfers.len()` (line 152). The
inserted positions therefore form a contiguous suffix
`start..start + accepted` where
`start = ledger.transfers.len()` captured at function entry. A
`Range<usize>` is the most-precise type for this shape; flattening
to `Vec<usize>` happens one layer up.

**Burning-bug invariant preserved.** The Range narrows when
duplicates drop: if 2 transfers are submitted and 1 is rejected by
the burning-bug guard, the returned range has length 1, not 2. Pre-
flight test §5.1 below pins this.

### §2.2 `LedgerIndexesExt::process_scanned_outputs` (`shekyl-scanner`)

**Trait** — `rust/shekyl-scanner/src/ledger_ext.rs:103`.

```rust
fn process_scanned_outputs(
    &mut self, ledger: &mut LedgerBlock, block_height: u64,
    block_hash: [u8; 32], outputs: Timelocked,
) -> usize;                                                // before

fn process_scanned_outputs(
    &mut self, ledger: &mut LedgerBlock, block_height: u64,
    block_hash: [u8; 32], outputs: Timelocked,
) -> Range<usize>;                                         // after
```

**Impl** — `ledger_ext.rs:113` — propagates the new return
verbatim from the inner `self.ingest_block(...)` call (line 145).

**Visibility note.** `LedgerIndexesExt` is `pub`. The trait is
re-exported by `shekyl-scanner`’s top-level `lib.rs` and consumed
across the workspace. Any downstream implementor would break — the
workspace audit (§3 below) confirms `LedgerIndexes` is the only
implementor and there are no out-of-tree consumers, so the breaking
change is bounded under
`15-deletion-and-debt.mdc`’s pre-genesis discount.

### §2.3 `apply_scan_result_to_state` (`shekyl-engine-core`)

**Definition** — `rust/shekyl-engine-core/src/engine/merge.rs:213`.

```rust
pub(crate) fn apply_scan_result_to_state(
    ledger: &mut LedgerBlock,
    indexes: &mut LedgerIndexes,
    result: ScanResult,
) -> Result<(), RefreshError> { … Ok(()) }                 // before

pub(crate) fn apply_scan_result_to_state(
    ledger: &mut LedgerBlock,
    indexes: &mut LedgerIndexes,
    result: ScanResult,
) -> Result<Vec<usize>, RefreshError> { … Ok(inserted) }   // after
```

**Body changes.**

- New local `let mut inserted = Vec::with_capacity(/* upper bound */);`
  before the per-height apply loop.
- Per-height call (line 386):
  `let inserted_range = indexes.process_scanned_outputs(...);
   inserted.extend(inserted_range);` — replaces the current
  `let _added = indexes.process_scanned_outputs(...);`.
- Empty-range fast path (line 251) returns `Ok(Vec::new())`.
- Final `Ok(())` at line 366 becomes `Ok(inserted)`.

**Capacity heuristic.** The upper bound on `inserted.len()` is
`result.new_transfers.len()`. Using
`Vec::with_capacity(result.new_transfers.len())` avoids any
reallocation on the hot path — same allocation cost as today since
the merge body already destructures `new_transfers` at line 295.

**Why `Vec<usize>` and not `Vec<Range<usize>>`.** The immediate
consumer (`populate_engine_handle_fields`) only needs the flat
list; per-block grouping is not used downstream. `Vec<usize>` is
strictly less informative but also strictly simpler at the consumer
site (`for &i in &inserted { … }` vs. nested-loop). If a future
consumer needs per-block boundaries, the Range list can be
reconstructed from `processed_height_range` × `ingest_block`’s
per-call return without touching the public surface — see §6 (R5).

### §2.4 `populate_engine_handle_fields` (signature + body)

**Definition** — `rust/shekyl-engine-core/src/engine/merge.rs:506`.

```rust
fn populate_engine_handle_fields(
    ledger: &mut LedgerBlock,
    view_secret: &[u8; 32],
    residue: &DetectionResidue,
) { for td in &mut ledger.transfers { … } }                // before

fn populate_engine_handle_fields(
    ledger: &mut LedgerBlock,
    view_secret: &[u8; 32],
    residue: &DetectionResidue,
    inserted: &[usize],
) {
    if residue.is_empty() || inserted.is_empty() { return; }
    for &i in inserted {
        // SAFETY: indices come from `apply_scan_result_to_state`'s
        // return, which is captured under the same `LocalLedger`
        // write guard. No external mutation can shrink
        // `ledger.transfers` between the merge body and this call.
        let td = &mut ledger.transfers[i];
        let key = (td.tx_hash, td.internal_output_index);
        let Some(ciphertext) = residue.get(&key) else { continue; };
        if td.source_ciphertext.is_none() {
            td.source_ciphertext = Some(ciphertext.clone());
        }
        if td.output_handle.is_none() {
            td.output_handle = Some(derive_output_handle(
                view_secret, &td.tx_hash, td.internal_output_index,
            ));
        }
    }
}
```

**Idempotency contract preserved verbatim.** The per-field `is_none()`
guards are unchanged. The four existing unit tests
(`*_sets_both_fields_on_match`, `*_skips_unmatched_transfers`,
`*_is_idempotent`, `*_respects_partial_population`) continue to pin
the same property — only their setup wires now thread the index list
through `apply_scan_result_to_state`’s return.

**Bounds-checking note.** Index access via `ledger.transfers[i]` is
checked. The merge body returns indices that were valid at append
time inside the same write guard; they remain valid for the
post-pass because no other caller can mutate `ledger.transfers`
during the guard’s lifetime. The bounds check is a defense-in-depth
no-op.

### §2.5 `Engine::apply_scan_result` (orchestrator)

**Definition** — `merge.rs:179`.

```rust
pub fn apply_scan_result(&self, result: ScanResult) -> Result<(), RefreshError> {
    let detection_residue = collect_detection_residue(&result);
    let mut guard = self.ledger.write();
    let state = &mut *guard;
    apply_scan_result_to_state(&mut state.ledger.ledger, &mut state.indexes, result)?;   // before
    populate_engine_handle_fields(
        &mut state.ledger.ledger,
        self.keys.view_sk.as_canonical_bytes(),
        &detection_residue,
    );
    Ok(())
}
```

```rust
pub fn apply_scan_result(&self, result: ScanResult) -> Result<(), RefreshError> {
    let detection_residue = collect_detection_residue(&result);
    let mut guard = self.ledger.write();
    let state = &mut *guard;
    let inserted = apply_scan_result_to_state(                                            // after
        &mut state.ledger.ledger, &mut state.indexes, result,
    )?;
    populate_engine_handle_fields(
        &mut state.ledger.ledger,
        self.keys.view_sk.as_canonical_bytes(),
        &detection_residue,
        &inserted,
    );
    Ok(())
}
```

**Public API unchanged.** `Engine::apply_scan_result` keeps its
`Result<(), RefreshError>` return; the inserted-index list is an
internal-only quantity threaded between the merge body and the
post-pass under the same write guard.

---

## §3 Call-site inventory

Enumerated against `dev` at `9e53c82fa`. **Production code: 4
behavioural change sites + 2 trait-impl wrappers. Tests: ~20
mechanical sites.** No bench fixture rewrites required.

### §3.1 Production sites

| File | Line | Pattern (before) | Disposition |
|------|------|------------------|-------------|
| `shekyl-engine-core/src/engine/merge.rs` | 191 | `apply_scan_result_to_state(...)?;` | Bind `let inserted = ...;` then thread to post-pass. |
| `shekyl-engine-core/src/engine/merge.rs` | 386 | `let _added = indexes.process_scanned_outputs(...)` | Rename to `let inserted_range = ...; inserted.extend(inserted_range);`. |
| `shekyl-engine-core/src/engine/merge.rs` | 506 | `populate_engine_handle_fields(ledger, view_secret, residue)` | Add `inserted: &[usize]` parameter; rewrite body per §2.4. |
| `shekyl-engine-core/src/engine/pending.rs` | 601 | `let added = indexes.process_scanned_outputs(...); assert!(added > 0 || ledger.transfer_count() == 0);` | Change to `assert!(!added.is_empty() || ledger.transfer_count() == 0);`. |

### §3.2 Trait-impl wrappers (LedgerEngine)

`LedgerEngine::apply_scan_result` returns
`Result<(), RefreshError>`. Trait impls discard the new
inner return.

| File | Line | Disposition |
|------|------|-------------|
| `shekyl-engine-core/src/engine/local_ledger.rs` | 263 | `apply_scan_result_to_state(...).map(\|_\| ())` |
| `shekyl-engine-core/src/engine/test_support.rs` | 807 | `apply_scan_result_to_state(...).map(\|_\| ())` |

**Why discard.** The `LedgerEngine` trait is
*orchestrator-public* (consumers outside `shekyl-engine-core`
implement it). Threading `Vec<usize>` through the trait surface
would extend this PR’s scope to every `LedgerEngine` implementor.
The post-pass already lives at the engine layer (`merge.rs`), not
at the trait layer, so the trait’s sync wrapper has no use for the
indices. Mapping to `()` at the trait boundary is the correct
shape: it keeps the engine-side optimization private while leaving
the orchestrator-public surface unchanged.

### §3.3 Test sites — discard return (no rewrite needed)

These call sites currently use `let _ = …` or take the bare
expression-statement form. The new return type compiles unchanged
because Rust allows ignoring `Range<usize>` / `Vec<usize>` returns
the same way it allows ignoring `usize`.

- `shekyl-scanner/src/tests.rs` (~25 calls, lines 338–1229).
- `shekyl-engine-core/src/tests.rs` (2 calls, lines 70, 170).
- `shekyl-scanner/benches/scan_block.rs` (1 call, line 88) —
  already binds via `let added = …` and passes through `black_box`,
  works for both types.
- `shekyl-scanner/benches/scan_block_iai.rs` (1 call, line 59) —
  same shape, same disposition.
- `shekyl-engine-state/src/ledger_indexes.rs` (3 expression-statement
  calls in tests, lines 597, 616, 622, 642) — discard.
- `shekyl-engine-core/src/engine/pending.rs` (3 calls at lines 825,
  875, 897) — already `let _ = …`.

### §3.4 Test sites — capture-and-assert

| File | Line | Pattern (before) | Disposition |
|------|------|------------------|-------------|
| `shekyl-engine-state/src/ledger_indexes.rs` | 565–571 | `let added = indexes.ingest_block(...); assert_eq!(added, 1);` | `let inserted = ...; assert_eq!(inserted, 0..1);` |
| `shekyl-engine-state/src/ledger_indexes.rs` | 588–589 | `let added = indexes.ingest_block(&mut ledger, 110, [0; 32], vec![t1, t2]); assert_eq!(added, 1);` | `let inserted = ...; assert_eq!(inserted.len(), 1);` (range start depends on prior ledger state — use `.len()` for resilience). |

### §3.5 `populate_engine_handle_fields` unit tests (4 sites)

`merge.rs:947, 1004, 1058, 1108` — all four currently call the
helper directly with no insertion-index argument:

```rust
apply_scan_result_to_state(&mut ledger, &mut indexes, result).expect("merge ok");
…
populate_engine_handle_fields(&mut ledger, &view_secret, &residue);
```

After the change:

```rust
let inserted = apply_scan_result_to_state(&mut ledger, &mut indexes, result).expect("merge ok");
…
populate_engine_handle_fields(&mut ledger, &view_secret, &residue, &inserted);
```

The four tests’ assertion shape is unchanged. The helper still
populates the same fields under the same idempotency contract — the
only diff is the iteration domain.

### §3.6 Doc-only mentions (no code change)

- `shekyl-scanner/src/lib.rs:39` — module-level usage example.
- `shekyl-scanner/src/ledger_ext.rs:18, 29` — module docstring.
- `shekyl-scanner/Cargo.toml:42` — bench commentary.
- `shekyl-scanner/README.md:85` — public docs example.
- `shekyl-engine-core/src/scan.rs:26, 27, 115, 123, 147` — module
  docs.
- `shekyl-engine-core/src/engine/refresh.rs:9, 128, 3018` — refresh
  module docs and decision-log citations.
- `shekyl-engine-core/src/engine/local_ledger.rs:20, 33` — module
  docs.
- `shekyl-engine-core/src/engine/test_support.rs:31, 611, 626, 657,
  765` — module docs.
- `shekyl-engine-core/benches/refresh_snapshot.rs:13` — bench
  module docs.
- `shekyl-engine-core/src/engine/merge.rs:69, 160, 181, 433, 440,
  496, 551` — module docs and tests `use super::…` import.

These references describe the function, not its return type, and
do not require updates. The module-level docstring on
`merge.rs:67–75` (“Internal helper for tests”) does not promise a
specific return type and reads correctly under the new shape.

---

## §4 Behavior preservation gates

The PR is performance-only. Each of the following must hold before
merge:

- **G1.** `Engine::apply_scan_result`’s observable behavior is
  byte-identical to the current implementation: same fields
  populated on the same transfers under the same idempotency
  contract. Pinned by the four existing
  `populate_engine_handle_fields_*` unit tests; no new behaviour to
  pin.
- **G2.** `LocalLedger::apply_scan_result` and
  `EngineFixture::apply_scan_result` (the trait impls) continue to
  return `Result<(), RefreshError>` with no observable change to
  external readers. Pinned by every existing refresh-pipeline test
  (`refresh.rs` ~3000 lines of test coverage).
- **G3.** `apply_scan_result_to_state`’s rejection paths are
  unchanged — every `Err(RefreshError::*)` is returned at the same
  call site under the same precondition. The `Vec<usize>` return is
  only constructed on the success path.
- **G4.** The empty-`processed_height_range` fast path
  (`merge.rs:231–252`) continues to return without entering the
  apply loop. New disposition: returns `Ok(Vec::new())` — capacity-0
  allocation, no measurable cost.
- **G5.** The reorg-rewind branch (`merge.rs:227–229`,
  `indexes.handle_reorg(...)`) runs before the per-height apply
  loop unchanged. Indices captured during the apply loop are
  post-rewind by construction; no special handling needed for the
  reorg case. Pinned by
  `apply_handles_reorg_rewind_before_per_height_events`
  (`merge.rs:570`).
- **G6.** Burning-bug duplicate-drop: the inserted-index range
  reflects *accepted* transfers, not *submitted* transfers. Pinned
  by §5.1 below (new test).

---

## §5 New tests

Three additions, scoped to the new property the change introduces.

### §5.1 `ingest_block_returns_range_of_accepted_indices`

(`shekyl-engine-state/src/ledger_indexes.rs::tests`.) Pin G6: with
a 2-transfer batch where transfer 2 is a burning-bug duplicate of
transfer 1, the returned `Range<usize>` has length 1 and the index
points at the position transfer 1 was appended to.

### §5.2 `apply_scan_result_to_state_returns_indices_of_new_transfers`

(`shekyl-engine-core/src/engine/merge.rs::tests`.) Pin the
cross-batch invariant: a multi-height `ScanResult` with `k₁` new
transfers at height H₁ and `k₂` at height H₂ produces an inserted-
indices Vec of length `k₁ + k₂` whose entries are monotonically
increasing and disjoint from prior-merge indices. The current test
substrate (`apply_ingests_detected_transfer_and_marks_spent`) is
extended rather than duplicated.

### §5.3 `populate_engine_handle_fields_visits_only_inserted_indices`

(`shekyl-engine-core/src/engine/merge.rs::tests`.) Pin the perf
property: pre-populate the ledger with 100 unrelated transfers, run
a merge that inserts 1 new transfer, and assert the post-pass binds
the new transfer’s fields **without** modifying any of the 100
prior transfers. Today’s test set asserts the positive path
(matched transfer’s fields populated) and the selectivity path
(unmatched transfer’s fields untouched) but does not pin the loop
domain — under the current O(n) implementation,
`populate_engine_handle_fields` visits every prior transfer and
short-circuits because the residue map does not match. The new
test makes the O(k) shape observable: a recording `LedgerBlock`
wrapper (or a plain reference-equality check on the prior
transfers’ fields) confirms the helper does not touch them.

**Why §5.3 matters.** The four existing tests pass under both the
O(n) and O(k) implementations because they only assert *outcome*,
not *iteration domain*. §5.3 is the regression gate for the perf
property itself — without it, a future change that accidentally
restores O(n) iteration would not break any test.

---

## §6 Risk register

- **R1 — Burning-bug semantics.** The Range returned by
  `ingest_block` must reflect accepted-transfer indices, not
  submitted-transfer indices. Source-of-truth: `ingest_block` body
  uses `continue;` on duplicates and computes
  `idx = ledger.transfers.len()` *after* the duplicate check, so
  accepted transfers are appended sequentially and the Range is
  trivially `start..start + accepted`. Pinned by §5.1.

- **R2 — Empty-range fast path.** `apply_scan_result_to_state`
  returns early at `merge.rs:231` when
  `processed_height_range.start == .end`. The new return must be
  `Ok(Vec::new())`, not `Ok(vec![])`-typed-as-`()`. Mechanical;
  caught at compile time.

- **R3 — Reorg-rewind ordering.** When `reorg_rewind` is `Some`,
  `indexes.handle_reorg(ledger, fork_height)` runs before the
  apply loop. `handle_reorg` truncates `ledger.transfers` and
  rebuilds `LedgerIndexes` from the surviving prefix. The apply
  loop’s subsequent `process_scanned_outputs` calls append onto the
  truncated Vec, so the captured indices are post-rewind by
  construction. No additional handling needed; pinned by G5.

- **R4 — `LedgerIndexesExt` external implementors.** Audit
  (`rg "impl LedgerIndexesExt"` across the workspace) returns the
  single impl on `LedgerIndexes` at `ledger_ext.rs:112`. No
  out-of-tree consumers currently exist; per
  `15-deletion-and-debt.mdc`, pre-genesis breaking changes to public
  trait surfaces are bounded.

- **R5 — Future consumer wants per-block grouping.** If a later PR
  needs to know *which block* each new transfer belongs to (e.g.,
  per-block stats in `LedgerEngine` projections), the flat
  `Vec<usize>` does not preserve that boundary. The shape can be
  recovered post-facto by walking
  `result.processed_height_range` against
  `ingest_block`’s per-call return — adding a second `Vec<u64>` of
  per-height block heights alongside the index list would be a
  pure-additive change to `apply_scan_result_to_state`’s return
  type. Recording the option here so the per-block grouping does
  not have to be re-discovered later.

- **R6 — `LocalLedger::apply_scan_result` discards the index
  list.** The trait impl maps to `()`, so the bookkeeping-only
  callers of `LedgerEngine::apply_scan_result` (which do not need
  handle population because they have no engine context) cannot
  benefit from the perf optimization. This is intentional — the
  M3b post-pass is engine-only by design per
  [`STAGE_1_PR_3_M3B_PREFLIGHT.md`](./STAGE_1_PR_3_M3B_PREFLIGHT.md)
  §3 (δ). The trait-layer callers do not run the post-pass at all,
  so they have nothing to optimize.

- **R7 — `Vec<usize>` allocation cost.** For a typical refresh
  batch (~10 new transfers), the Vec costs ~80 bytes plus one
  allocation. For a worst-case full-history scan (1M new transfers
  in one batch), the Vec costs ~8 MB — still small relative to the
  `result.new_transfers` source itself, which carries
  ~1.5 KB / transfer (`RecoveredWalletOutput`). The allocation is
  bounded by `result.new_transfers.len()` and pre-sized via
  `Vec::with_capacity`, so the only cost above the current
  baseline is the index store itself.

---

## §7 Rounds budget

This PR has no architectural surface change, no security
implication, no consensus implication, and no protocol effect. The
rounds-budget compression discipline from
`16-architectural-inheritance.mdc` (“Discovery cadence”) applies:
the patterns surface during pre-flight rather than in late rounds.

**Estimate: 1–2 review rounds.**

- Round 1: trait-surface change review (§2.1, §2.2 — `Range<usize>`
  vs. `Vec<usize>` shape), perf-property regression test (§5.3).
- Round 2 (if needed): refinements to test §5.3’s observability
  shape (recording wrapper vs. reference-equality assertion), or
  R5 disposition (whether to land per-block grouping speculatively
  vs. defer).

If neither round surfaces a structural concern, the PR lands
without further iteration. The pre-flight estimate is calibrated
against the M3b execution — M3b had architectural surface
(scanner/engine reroute), 4 design rounds, and 10 commits; this PR
has no architectural surface, so the rounds budget collapses
proportionally.

---

## §8 Branch and commit shape

**Branch.** `perf/merge-insertion-indices` off `dev`. Per
`06-branching.mdc`, the change touches >5 files / >200 lines and
benefits from PR review before landing on `dev`; short-lived
branches are appropriate. Target landing window: 2–3 working days.

**Commit decomposition** (5 commits, ~150 net code lines + ~20
mechanical fixture updates):

1. **`engine-state: LedgerIndexes::ingest_block returns Range<usize>`**
   — `ledger_indexes.rs` definition + 2 capture-and-assert tests.
   New test §5.1 lands here.
2. **`scanner: LedgerIndexesExt::process_scanned_outputs returns Range<usize>`**
   — `ledger_ext.rs` trait + impl. No callers in `shekyl-scanner`
   change behavior; tests/benches recompile unchanged.
3. **`engine-core: apply_scan_result_to_state returns Vec<usize>`**
   — `merge.rs` body change, `local_ledger.rs` and
   `test_support.rs` `.map(|_| ())` wrappers, `pending.rs:601`
   `assert!` rewrite. New test §5.2 lands here.
4. **`engine-core: populate_engine_handle_fields walks inserted indices in O(k)`**
   — helper signature change, `Engine::apply_scan_result` thread,
   the four existing tests’ setup wires, new perf-regression test
   §5.3.
5. **`docs(followups): close populate_engine_handle_fields O(n) → O(k) item`**
   — remove the FOLLOWUPS V3.0 entry now that it is resolved; add
   a one-line note in `docs/CHANGELOG.md` under the
   "Performance" section.

Each commit compiles and passes tests independently. The
decomposition aligns with `15-deletion-and-debt.mdc`’s scope-per-
commit rule: a bisecting reviewer can pinpoint a regression to the
specific layer without untangling unrelated changes.

---

## §9 What this pre-flight does NOT address

- **`KeyEngine::sign_transaction` async re-route (M3c+).** Independent
  of this perf interim PR; sequenced behind PR 5
  (`PendingTxEngine`) per
  [`STAGE_1_PR_3_MIGRATION_PLAN.md`](./STAGE_1_PR_3_MIGRATION_PLAN.md)
  §3.3.
- **Refresh state-machine extraction (PR 4 / `RefreshEngine`).**
  Separately scheduled per
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md);
  PR 4’s design doc lands as a peer to this pre-flight while M3c–M3e
  finish, per the user’s 2026-05-10 sequencing decision.
- **`LedgerEngine::apply_scan_result` trait surface.** Could thread
  `Vec<usize>` through the trait return, but the only consumer
  benefiting from it (the engine post-pass) lives in the engine
  layer above the trait. Threading through the trait would be
  scope creep for zero current benefit. Recorded as R6 above.
- **Per-block index grouping (R5).** Not currently needed; recorded
  for future consumers.

These remain on their independent timelines.

---

## §10 Disposition

**Recommend execution as a single PR off `dev`** at branch
`perf/merge-insertion-indices`, landing inside the 5-commit
decomposition in §8. The change is purely a perf optimization with
no architectural, security, or consensus effect; the rounds budget
is 1–2; the FOLLOWUPS entry resolves on merge.

**Pre-conditions.** None beyond a clean `dev` (PR #34, #35, #36
all merged — currently true at `dev` tip `9e53c82fa`).

**Post-conditions.** FOLLOWUPS V3.0 entry closed; `CHANGELOG.md`
updated; `populate_engine_handle_fields` walks O(k) per scan;
refresh latency at 100k transfers drops from ~5 s post-pass cost
to ~50 µs (k ≈ 10 × 50 ns/lookup × ~100 batches in a typical
refresh).
