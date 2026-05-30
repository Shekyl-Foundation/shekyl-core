# RandomX v2 — Track A Phase 2f plan

**Status.** **Implementation landed — Branch A measured.** Scaffold
landed 2026-05-23 on branch `chore/randomx-v2-phase2f-plan` post
Phase 2d merge (PR #70 → `dev` merge commit `fb21909ff`); subsequent
rounds and post-closure amendments landed in-place against the same
chore branch; implementation landed on
`feat/randomx-v2-phase2f-impl` in five commits (HEAD = `a37aac054`).
Per §11 Round history: Round 1 closed the §3 decision points;
Round 2 landed the architectural reframe (`PreparedCache` +
`Seedhash` newtype; `Cache: pub → pub(crate)`; `compute_hash`
signature change); Round 3 closed the refinement bundle (cfg-gated
A/B bench; F1–F7 threat model; runtime-configurable pool capacity);
post-closure pins + refinements specified the under-specified
substrate the rounds left; **implementation cut produced an empirical
Branch A measurement (component-floor cap ≈ 48.7 µs, achievable pool
savings < 50 µs threshold)**, omitting §8 Round 3 commit 5 (cfg-gate
flip to default-on) per §3.4 R1-D4 Round 3 disposition. The
prediction-vs-measured reconciliation per §8 Round 3 confirms
prediction A held. The hand-off contract is captured in §5; the
implementation PR description names §8 Round 3's predicted-most-
likely branch (Branch A or Branch C plausible) alongside the
measured Branch A.

**Reading order (audit trail).** §1.1 / §3.* / §11 each carry the
scaffold-as-of-Round-0 / Round 1 framing as audit trail per
`91-documentation-after-plans.mdc`, with Round 2 / Round 3 /
post-closure-pin supersessions marked inline. Readers tracing
the discipline's evolution read the rounds in chronological
order; readers wanting current state read the latest-marked
supersession in each section.

**Original scaffold framing (preserved as audit trail).** The
text below this paragraph through the end of the front-matter
(`Parent plan` → `Out of scope`) is the scaffold-as-of-Round-0
framing. Some claims (e.g., "no 2c or 2d public surface
changes in 2f"; "≤600 net-new lines") are superseded by later
rounds and are flagged inline below; the original framing is
preserved so the discipline's evolution is auditable.

**Parent plan.** [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md)
§"Track A — Phase 2" sub-PR 2f scope (line 27):

> "Implement `CacheStore` utility type (`LruCache<Seedhash, Arc<Cache>>`
> behind a `Mutex`; default capacity 2). The crate exports it as a
> generic helper for any Rust caller; `shekyl-pow-randomx` instantiates
> none. PR includes TWO crate-level invariant tests on
> `shekyl-pow-randomx`: (1) no module-level static/OnceCell/lazy_static
> other than const data; (2) no `#[no_mangle]` or `extern "C"` exports.
> Both CI-enforced via grep on the crate source tree. Benchmark
> per-call `VmState` allocation cost inside `compute_hash` (extending
> the Phase 2c `BENCH_RESULTS.md` baseline); if it dominates per-hash
> time, internalize a `VmState` pool inside `compute_hash` (private to
> `vm.rs`, invisible to consumers — same shape as Phase 2c R2-D1's
> dispatch-function-body-replacement discipline; no public `VmPool`
> type). Per Decision #7 (Round 2 substrate-shift form): per-call
> allocation is the default; pooling, if needed, is internal to
> `compute_hash`."

**2c precedent.**
[`RANDOMX_V2_PHASE2C_PLAN.md`](./RANDOMX_V2_PHASE2C_PLAN.md) §5.11.7
"Forward-actions to Phase 2f" pins two substrate carries (canonical-
slot eviction-protection; pool capacity sized against daemon parallel-
verification fanout). Reproduced verbatim in §2 below so Phase 2f's
review does not require chasing the 2c plan.

**2d precedent.**
[`RANDOMX_V2_PHASE2D_PLAN.md`](./RANDOMX_V2_PHASE2D_PLAN.md) §10
"Forward path" pins the inherited surface:

> "2f inherits unchanged `compute_hash` surface; pooling wraps the
> same `VmState` allocation path 2c landed."

The 2d implementation (PR #70) realized this: `compute_hash`'s
signature is `pub fn compute_hash(&Cache, &[u8; 32], &[u8]) -> [u8;
32]`, `VmState` is private to `vm.rs`, `dispatch_instruction` is
private. 2f's CacheStore lives alongside this surface; the pool (if
benchmarks justify it) lives *inside* `compute_hash`.

**Scaffold framing said: "No 2c or 2d public surface changes in
2f." Round 2 supersedes** — the Round 2 architectural reframe
(see §1.1 Round 2 amendment) intentionally amends the inherited
2d public surface to close a consensus-correctness footgun the
2d signature carried (caller-passed wrong cache for given
seedhash → wrong hash). The amended public surface is `Seedhash`
newtype + `PreparedCache` bundling + `compute_hash(&PreparedCache,
&[u8])`; `Cache` transitions `pub → pub(crate)`. Per
`16-architectural-inheritance.mdc` pre-genesis discount, the
substrate correction lands in plan-doc Round 2 rather than in
V3.x. The scaffold framing is preserved as audit trail; the
inherited-as-of-2d surface was the right starting point even
though Round 2 supersedes it.

**Base commit.** `dev` at `fb21909ff` (PR #70 merge tip,
2026-05-23). This doc's branch (`chore/randomx-v2-phase2f-plan`)
cuts from there; the Phase 2f implementation branch
(`feat/randomx-v2-phase2f-impl`) cuts later from post-this-doc `dev`.

**Branches.**

- `chore/randomx-v2-phase2f-plan` (this doc; short-lived per
  `06-branching.mdc` rule 2; lands on `dev` via its own PR).
- `feat/randomx-v2-phase2f-impl` (implementation; cut from
  post-this-doc `dev`; not yet cut as of Scaffold close).

**Scope envelope.** Single implementation PR. **Round 2 supersedes
the original ≤600 net-new-lines target** — see §5.2 line-count
table for the current per-item budget (~800 net-new lines after
the Round 2 `Seedhash` newtype + `PreparedCache` + atomic-sweep
additions; ~50–150 additional lines if the R1-D3 cfg-gated pool
flips to production per the bench result). The scaffold-original
≤600 figure is preserved here as audit trail; the load-bearing
budget is §5.2's table.

Surface: CacheStore type + tests + benchmark harness + crate-
invariant grep tests + cfg-gated `VmState` pool body (per Round 3
§3.3 reframe) + Round-2-introduced `Seedhash` newtype +
`PreparedCache` + atomic Seedhash sweep + one new CI script
(`scripts/ci/check_randomx_crate_invariants.sh` or equivalent —
final name pinned at Round 1) + updates to
`rust/shekyl-pow-randomx/BENCH_RESULTS.md`. **No consensus-affecting
changes; no new reference vectors; no fork-pin advance.** 2f is
pure-utility + benchmark + (Round 2) type-system reframe of the
verifier's public surface; the consensus surface was exhausted by
2d's T9–T16 + bench delta entries and Round 2's reframe is
type-only (same hash outputs for same effective inputs).

**Out of scope (deferred to subsequent phases).**

- **Differential test harness against C reference** — deferred to 2g
  per `RANDOMX_V2_PLAN.md` line 30. 2f's benchmark uses the existing
  `compute_hash` against a fixed seedhash/data pair (not a corpus and
  not differentially against the C reference).
- **Per-PR per-hash latency CI gate** — activates at Phase 3a per
  `RANDOMX_V2_PLAN.md` line 243. 2f reports the bench delta in
  `BENCH_RESULTS.md`; CI gating is 3a's responsibility.
- **Binary-level `nm`-on-`shekyld` symbol-isolation check** — deferred
  per the FOLLOWUPS V3.1+ entry (line 3633ff), which names Phase 3c
  as the natural landing site sharing the link-job with the
  CryptoNote DAA `nm` check. 2f's symbol-isolation is grep-based at
  the Rust source tree level (Decision-#1 form per the parent-plan
  line 27 scope text), not binary-level.
- **`Cache::derive` parallelism / SuperscalarHash thread-pool** — out
  of scope; 2c shipped serial derivation. Parallel derivation is a
  separate FOLLOWUPS item if benchmarks justify.

---

## 1. Locked-by-2c-and-2d substrate

The following are frozen by the post-PR-#70 `dev` tip. The
scaffold-as-of-Round-1 captured §1.1 / §1.2 / §1.3 below as
"unchanged"; Round 2's substrate-correction (per the *Round 2
amendment* sub-block of §1.1) supersedes the §1.1 public-API freeze
with a structurally-stronger shape. §1.2 / §1.3 are unchanged.

### 1.1 Public API surface (Round 2 supersedes the scaffold-and-Round-1 freeze)

**Scaffold-as-of-Round-1 freeze (preserved as audit trail per
`91-documentation-after-plans.mdc`):**

```rust
// In rust/shekyl-pow-randomx/src/lib.rs (or re-exports therefrom):
pub struct Cache { /* private fields */ }
impl Cache {
    pub fn derive(seedhash: &[u8; 32]) -> Cache;
}
pub fn compute_hash(cache: &Cache, seedhash: &[u8; 32], data: &[u8]) -> [u8; 32];

// pub(crate) items consumed by tests / internal callers:
//   Cache::from_raw, Cache::derive_item, Cache::item_bytes
// (no public exposure; pinned by Phase 2c R1)
```

The scaffold framing was: *"2f adds `pub struct CacheStore` (shape
TBD per R1-D1) and possibly amends `compute_hash`'s body to consult
an internal `VmStatePool` (per R1-D4 / bench result). It does not
change `compute_hash`'s signature."* That framing was correct under
Round 1's option-set (which scoped CacheStore to canonical-protection
QoS and treated the `compute_hash(&Cache, &[u8; 32], &[u8])`
signature as stable), but Round 2's adversarial pass against the
option-set surfaced the consensus-correctness footgun the signature
preserves: a caller passing the wrong cache for a given seedhash
gets a wrong hash, which the network rejects, which is correct for
chain integrity but a footgun the type system can close at zero
cost. Round 2 closes it.

**Round 2 amendment (load-bearing substrate correction):**

Per `16-architectural-inheritance.mdc`'s pre-genesis discount and
the cost-benefit-defer-to-later anti-pattern, the substrate-
correction lands now in Round 2 of Phase 2F's plan-doc rather than
in V3.x. Pre-genesis the cost is bounded; post-genesis it would
require migration tooling that runs forever. The freeze amendment
is paired with a small precursor PR amending the parent
`RANDOMX_V2_PLAN.md` Decision #6 wording before the Phase 2F
implementation PR opens (queued; see §10 forward path).

```rust
// In rust/shekyl-pow-randomx/src/lib.rs (or re-exports therefrom):

/// 32-byte seedhash newtype. Distinct from generic `[u8; 32]`
/// values (output hashes, content hashes, etc.) at the type level
/// to prevent accidental mixing at call sites. Per-instance
/// representation is private; consumers go through `from_bytes`
/// (construction) and `as_bytes` (read-only access). Pre-genesis
/// the representation is a fixed `[u8; 32]` array; post-genesis a
/// representation change does not break downstream callers because
/// the byte-level access is method-mediated, not field-mediated.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Seedhash(/* private [u8; 32] */);

impl Seedhash {
    pub fn from_bytes(bytes: [u8; 32]) -> Seedhash;
    pub fn as_bytes(&self) -> &[u8; 32];
}

// `Display` impl renders as lowercase hex (matches `hex::encode`
// and the cryptographic-output convention; canonical formatting
// for any consumer that ends up logging seedhashes — verifier-
// crate code itself does not log seedhashes at HEAD, per the
// post-closure pin verification: `rg -i seedhash` finds zero
// `tracing::` / `log::` / `format!` / `println!` / hex-rendering
// sites in `rust/shekyl-pow-randomx/src/`. Previous Round 2
// framing claimed "consistency with Phase 2c's existing seedhash-
// formatting conventions"; verification at HEAD found no such
// conventions exist. Display is for downstream consumers — FFI
// shim, daemon-side logging, test diagnostics. The lowercase-hex
// disposition stands; the framing is corrected.)
impl core::fmt::Display for Seedhash { /* ... */ }

/// Bundle of a derived `Cache` with the `Seedhash` it was derived
/// from. The pairing is enforced at construction (`derive` is the
/// only public path to a `PreparedCache`); consumers can only
/// produce a `PreparedCache` whose `cache` was derived from its
/// `seedhash`. The `compute_hash` entry point takes
/// `&PreparedCache` and reads the seedhash from the bundle, so
/// the consensus-correctness invariant ("the cache used to compute
/// this hash was derived from the seedhash this hash was attributed
/// to") becomes type-enforced rather than convention-enforced.
///
/// The bundling is the load-bearing structural change Round 2
/// lands; see §3.1 R1-D1 Round 2 disposition for the full
/// rationale and the rejected-alternative comparison.
pub struct PreparedCache { /* private fields: { cache: Cache, seedhash: Seedhash } */ }

impl PreparedCache {
    /// Derive a `PreparedCache` from a seedhash. The internal
    /// `Cache::derive` is `pub(crate)`; it is the implementation
    /// primitive but not the public API. Public callers always go
    /// through `PreparedCache::derive` so the seedhash-cache
    /// binding is type-enforced.
    pub fn derive(seedhash: Seedhash) -> PreparedCache;

    /// Seedhash this `PreparedCache` was derived from.
    pub fn seedhash(&self) -> &Seedhash;
}

/// Compute a RandomX v2 hash. The cache-seedhash binding is carried
/// by `prepared`; there is no separate seedhash parameter. A caller
/// who needs to compute hashes for multiple seedhashes constructs
/// distinct `PreparedCache` instances (typically obtained via
/// `CacheStore::lookup_or_derive` per §3.1).
pub fn compute_hash(prepared: &PreparedCache, data: &[u8]) -> [u8; 32];

// pub(crate) items consumed by tests / internal callers:
//   pub(crate) struct Cache { /* private fields */ }
//   pub(crate) fn Cache::derive(seedhash: &Seedhash) -> Cache
//   Cache::from_raw, Cache::derive_item, Cache::item_bytes
// Cache transitions from `pub` (Phase 2c freeze) to `pub(crate)`
// (Round 2 amendment): exposing `Cache` publicly would let callers
// construct it without the binding and reintroduce the failure
// mode the bundling prevents. Test access is preserved via the
// Phase 2c R0-D6 `src/*.rs#mod tests` discipline (`pub(crate)`
// access from inside the crate, no public-API widening). The
// `Cache` rustdoc carries a pointer to `PreparedCache` as the
// public construction path, mirroring the shape of
// `Cache::from_raw`'s rustdoc carrying its "test-time only; FFI
// consumers use `compute_hash`" pointer.
```

Round 2 also pins one implementation note that crosses every
seedhash-handling site: the Seedhash newtype introduction is a
mechanical sweep across `Cache::derive`, `PreparedCache::derive`,
`CacheStore::*`, the FFI shim's seedhash constructor, and every
test that constructs a literal seedhash. This sweep happens in the
**same implementation-PR commit** as the Seedhash newtype landing,
not as a follow-up — otherwise the codebase has a transitional
period where some sites use `&[u8; 32]` and some use `&Seedhash`,
which is exactly the drift the newtype prevents. §8's commit table
captures this in commit 1's scope.

**Post-closure substrate-completeness pins (per
`21-reversion-clause-discipline.mdc` "an under-specification
surfaced post-closure does not reopen the round it belonged to
but is named explicitly as a post-closure pin"; not a Round 4).**

1. **Dispatch-loop signature unaffected by `Cache: pub →
   pub(crate)`; `pub(crate) cache_ref()` accessor on
   `PreparedCache`.** The dispatch loop in `vm.rs` (the
   `execute_one` / `cache.derive_item(item_number)` call site at
   `vm.rs` line 1758 and the surrounding interpreter scaffold)
   takes `cache: &Cache` directly. This signature is in-crate,
   so the Round 2 visibility transition does not affect it; the
   `pub(crate)` `Cache` is fully reachable from `vm.rs`.

   **The reach-through from `&PreparedCache` to `&Cache` is via
   an explicit `pub(crate)` accessor**, not via private-field
   access scattered across multiple call sites:

   ```rust
   impl PreparedCache {
       /// In-crate accessor to the inner `Cache`. Used by
       /// `compute_hash`'s body to drive the dispatch loop and
       /// (if a future in-crate consumer surfaces) by other
       /// crate-internal code that needs `&Cache` from
       /// `&PreparedCache`. Not part of the public API surface;
       /// FFI consumers go through `compute_hash`.
       pub(crate) fn cache_ref(&self) -> &Cache;
   }
   ```

   The accessor's existence is the load-bearing structural
   property: a future contributor wondering "should I add
   `prepared.derive_item(...)` as a convenience on
   `PreparedCache`?" sees that the established reach-through
   shape is `prepared.cache_ref().derive_item(...)` and does not
   re-expose `Cache`'s API on `PreparedCache`. The reversal
   from the post-closure-pin-as-originally-written disposition
   ("no accessor; private-field extract internally") makes the
   intent explicit rather than implicit; per
   `05-system-thinking.mdc`'s "specification first, code second"
   discipline, the explicit accessor is the documented contract.

   Tests that need direct `Cache` construction continue to use
   `pub(crate) Cache::from_raw` (the Phase 2c test-time
   constructor; consumed only from `#mod tests` blocks in the
   same crate per the Phase 2c R0-D6 tests-use-the-actual-API
   discipline). No public `cache_ref()` accessor is added; the
   accessor is `pub(crate)` only.

2. **`PreparedCache` equality and identity.** `PreparedCache`
   does **not** derive `PartialEq` / `Eq`. Two equality semantics
   are needed across the codebase, and each is served by a more
   specific primitive than `PartialEq` on `PreparedCache`:

   - **Seedhash equality** (CacheStore lookup, slot indexing):
     `slot.seedhash() == lookup_key` via `Seedhash`'s derived
     `PartialEq`. The CacheStore's slot-comparison logic compares
     seedhashes, never `PreparedCache` instances directly.
   - **Arc identity** (test assertions like T-CS-5 / T-CS-7 /
     T-CS-9 verifying "same Arc clone returned from two
     `lookup`s" or "same Arc returned from two concurrent
     `lookup_or_derive` calls"): `Arc::ptr_eq(&a, &b)`. This is
     pointer-equality, not value-equality; it is exactly the
     property the dedup tests assert.

   Deriving `PartialEq` on `PreparedCache` would either be a
   structural value-equality (compare full 256 MiB cache
   bytes, which no caller wants) or a delegating equality
   (compare seedhash only, which is misleading because it
   conflates "same seedhash" with "same `PreparedCache`
   instance"). Both shapes are wrong; the absence of the impl
   forces consumers to use the right primitive at the call
   site. Reopen criterion: a future consumer surfaces that
   genuinely needs to compare two `PreparedCache` values for
   semantic equality and cannot satisfy that need via
   seedhash-equality + `Arc::ptr_eq`. Not anticipated.

The `compute_hash` body inside `src/vm.rs` reads
`prepared.seedhash().as_bytes()` where the prior shape took the
seedhash as a separate argument; this is mechanical and does not
affect the dispatch loop's semantics.

2f **adds** `pub struct CacheStore` (shape pinned at R1-D1 per the
Round 2 disposition) and **possibly amends** `compute_hash`'s body
to consult a feature-gated `VmStatePool` (per R1-D3's Round 3
reframe). The `compute_hash` *signature* is amended by Round 2
(takes `&PreparedCache`, not `&Cache + &[u8; 32]`); the dispatch
behavior inside the function body is unchanged.

### 1.2 Private substrate (unchanged)

- `VmState` is `pub(crate)` in `src/vm.rs`; constructed by
  `compute_hash` per call; scratchpad via `Box::new_zeroed_slice`.
- `dispatch_instruction(&Instruction, &mut VmState)` is `pub(crate)`
  in `src/vm.rs`.
- `fpu_rounding` module is `pub(crate)` per the 2d Round 1 R1-D1 + R6-D1
  decision.

### 1.3 Crate-invariant posture (active discipline carried forward)

Both new invariant greps that 2f lands have an empirical baseline at
PR-#70 tip:

- **No module-level `static` / `OnceCell` / `lazy_static`** other
  than `const` data. Empirically the crate has zero such items at
  HEAD (per `RANDOMX_V2_PLAN.md` §7.7's design intent absorbed by
  Phase 2c's implementation). 2f's grep makes this CI-enforced rather
  than discipline-as-reviewer-attention.
- **No `#[no_mangle]` / `extern "C"`** exports. Empirically zero at
  HEAD per the parent-plan `RANDOMX_V2_PLAN.md` §7.7 framing. 2f's
  grep makes it CI-enforced.

Both greps must be zero-hit on HEAD-prior-to-2f and remain zero-hit
post-2f. The grep set is pinned at Round 1 R1-E1 (CI grep patterns +
permitted exceptions).

---

## 2. Forward-actions absorbed from 2c §5.11.7 + 2d §10

### F1 — CacheStore canonical-slot eviction-protection (from 2c §5.11.7 #1)

> The capacity-2 LRU `CacheStore` is small enough that an attacker who
> can submit alt-chain block headers with novel seedhashes can flush
> the canonical-seedhash slot with a 3-seedhash interleave, forcing
> ~150-200 ms of cache re-derivation per attack block. The forward-
> action: the canonical-seedhash slot (the seedhash for the current
> chain tip's epoch) is **sticky** — it is not subject to LRU
> eviction; only the secondary slot churns under attacker-induced
> pressure.

**2f Round 1 disposition:** R1-D2 picks the eviction-policy shape
(capacity-2 LRU with sticky canonical via a `pin(seedhash)` API the
caller invokes when learning a new canonical seedhash; or explicit
"pinned slot + transient slot" two-slot type that needs no LRU). Both
satisfy F1; the trade-off is API surface vs. implementation
simplicity. Round 1 closes the choice.

### F2 — VmState pool capacity sized against daemon parallel-verification fanout (from 2c §5.11.7 #2)

> If 2f's benchmarks show pooling is needed, the pool's capacity must
> be sized against the daemon's actual parallel-verification fanout
> (alt-chain branch validation runs in parallel; mempool tx
> verification runs in parallel). An arbitrarily-chosen capacity
> either under-provisions (pool exhaustion forces per-call allocation,
> defeating the pool) or over-provisions (memory waste).

**2f Round 1 disposition:** R1-D5 enumerates the daemon's actual
parallel-verification fanout. Two sources of concurrent
`compute_hash` callers exist at Phase 3a+: alt-chain branch
validation worker pool + mempool tx verification worker pool. Round 1
surveys the daemon-side code (worker-pool thread-count settings) or
runs a single instrumented startup to determine the maximum-concurrent
fanout, and sizes the pool to that maximum + a small reserve. **F2
only fires if R1-D4's bench result triggers the pool path; otherwise
F2 is deferred unchanged to whatever future PR re-opens the
pool decision.**

### F3 — `compute_hash` surface unchanged (from 2d §10)

> 2f inherits unchanged `compute_hash` surface; pooling wraps the
> same `VmState` allocation path 2c landed.

**2f Round 1 disposition:** No-op carry. The §1.1 freeze enforces
this. If R1-D4 selects the pool path, the pool is internal to
`compute_hash`'s body — the function signature is untouched.

### F4 — Audit-against-actual-code discipline (from 2c §5.11.8, 2d Round 6 R6 posture cite)

> An audit that reads the actual C reference at the pinned commit
> catches consensus-split bugs that an audit that reads the plan-doc
> tables does not.

**2f Round 1 disposition:** No-op for the CacheStore surface (the
type has no C reference counterpart — it's a Rust-only utility, per
`RANDOMX_V2_PLAN.md` Decision #1). Applies forward to 2g's
differential harness. Recorded here only to acknowledge the carry-
forward exists.

### F5 — Pre-genesis posture (from `15-deletion-and-debt.mdc` + `16-architectural-inheritance.mdc`)

2f is pre-genesis. Per `15-deletion-and-debt.mdc`'s pre-V3-launch
discount, no migration code is justified; if the CacheStore shape
chosen at R1-D2 turns out to be wrong, the disposition is to redesign
in a follow-up rather than maintain a versioning surface.

---

## 3. Round 1 decision points

Round 1 (post-scaffold-merge) closes these. Scaffold names the
options without picking; user-facing review chooses.

### 3.1 R1-D1 — `CacheStore` API surface shape

Options:

- **(a) Transparent memo with explicit `pin(seedhash)` / `unpin()`**
  — `CacheStore::new(capacity)` returns a `CacheStore`; the consumer
  calls `store.pin(canonical_seedhash)` when learning a new
  canonical seedhash; the store maintains a `LruCache<Seedhash,
  Arc<Cache>>` internally, where the pinned slot is treated as
  ineligible-for-eviction. Pros: API matches the parent-plan
  `RANDOMX_V2_PLAN.md` line 27 framing (LruCache behind Mutex).
  Cons: caller-driven pinning is a footgun (forget to `pin`, lose
  the sticky property).
- **(b) Explicit two-slot type with `set_canonical` + `lookup`** —
  `CacheStore::new()` returns a fixed two-slot type (one canonical
  pinned slot, one transient LRU slot); the consumer calls
  `store.set_canonical(seedhash)` to advance the canonical, which
  evicts the previous canonical (if any) into the transient slot
  (preserving the previous canonical for the duration of the
  rollback window). Pros: structurally enforces the sticky property
  (no caller-error path leaves canonical evictable). Cons: harder to
  generalize beyond capacity-2 if a future caller wants capacity-N.
- **(c) Type-stratified shape** — separate `PinnedSlot` and
  `TransientSlot` types, composed by the consumer. Pros: maximal
  type-system enforcement. Cons: API surface bloat for a capacity-2
  utility.

**Round 1 task.** Pick one. Pin the public surface (constructor
signatures, lookup signature, pin/canonical signature). Round 1
output is a code-block-shaped API spec mirroring §1.1's style. The
discipline question per `21-reversion-clause-discipline.mdc`: which
optionality is rejected, under what substrate-change does the
rejection reopen?

**Round 1 disposition (closes R1-D1):** Pick **option (b)** — explicit
two-slot type with `set_canonical` + `lookup` + `insert`. The F1
sticky-canonical defense is priority-1 security per `00-mission.mdc`
(an adversary-induced cache flush forcing ~150–200 ms re-derivation
per attack block is a verifier-side DoS amplification surface);
option (a)'s caller-driven `pin(seedhash)` makes the defense
discipline-dependent (forget to `pin` = lose the sticky property),
which fails the "structurally enforce, don't rely on reviewer
attention" frame that `16-architectural-inheritance.mdc`'s "what
does this deliver against the threat model?" question caches.
Option (c)'s type-stratified composition is pre-provision-for-
flexibility (`21-reversion-clause-discipline.mdc` "Keep it for
flexibility" anti-pattern) — there is one consumer (Decision #5's
`shekyl-ffi`-internal CacheStore), capacity-2 covers it, and a
hypothetical multi-cache consumer is debt today.

The frozen public surface (additive over §1.1; same file-level
posture as §1.1's existing exports):

```rust
// In rust/shekyl-pow-randomx/src/cache_store.rs (new); re-exported
// from rust/shekyl-pow-randomx/src/lib.rs as `pub use cache_store::CacheStore;`.
//
// Two-slot store: at-most-one canonical (sticky against eviction)
// plus at-most-one transient (displaced by every new insert when
// no slot match exists). Thread-safe by interior mutability.
pub struct CacheStore { /* private fields: Mutex<{ canonical, transient }> */ }

impl CacheStore {
    /// Construct an empty store. Both slots start unset; `set_canonical`
    /// must be called before serving production lookups (see R1-D2 #2
    /// degenerate-case disposition).
    pub fn new() -> CacheStore;

    /// Look up the cache for `seedhash`. Returns `Some(Arc::clone(...))`
    /// if `seedhash` matches the canonical or transient slot, else
    /// `None`. Lookups never derive; the caller derives on miss and
    /// then calls `insert`.
    pub fn lookup(&self, seedhash: &[u8; 32]) -> Option<Arc<Cache>>;

    /// Place `cache` (keyed by `seedhash`) into the transient slot. If
    /// `seedhash` already matches the canonical slot, this is a no-op
    /// (caller raced with another thread that already filled it). If
    /// the transient slot holds a different seedhash, the prior
    /// transient entry is dropped. Canonical slot is unchanged.
    pub fn insert(&self, seedhash: &[u8; 32], cache: Arc<Cache>);

    /// Advance the canonical seedhash to `seedhash`. Semantics:
    /// - If `seedhash` is currently in the transient slot, it is
    ///   promoted to canonical and the prior canonical (if any) is
    ///   demoted to transient (preserving the previous canonical for
    ///   the duration of the rollback window, until the next insert
    ///   displaces it).
    /// - If `seedhash` matches the existing canonical, it is a no-op.
    /// - If `seedhash` is not present in either slot, it is a no-op
    ///   (does NOT derive; derivation is the caller's responsibility
    ///   per Decision #6's no-prewarm framing). The caller is
    ///   expected to follow with `insert(seedhash, derived_cache)` and
    ///   then a second `set_canonical(seedhash)` to promote.
    pub fn set_canonical(&self, seedhash: &[u8; 32]);
}

impl Default for CacheStore { /* equivalent to ::new() */ }
```

`Arc<Cache>` is shared with the lookup caller; `Cache` itself
remains as defined in §1.1. Internal synchronization uses
`std::sync::Mutex` (a workspace-trivial primitive — no new
dependency required; `parking_lot` and `lru` are NOT added per
rule 17 dependency discipline, see §3.6 R1-E1 disposition for the
discipline-verification trail). The mutex's critical section is
bounded by an `Arc::clone` plus two `Option` writes; all derivation
happens outside the lock (caller derives, then calls `insert`).

**Reversion clause (per `21-reversion-clause-discipline.mdc`).**

- *Rejection.* Capacity-N (N>2) and multi-canonical-slot semantics
  are rejected at V3.0. Substrate: there is exactly one consumer
  (Decision #5's `shekyl-ffi`-internal CacheStore), and that
  consumer holds exactly one chain-tip canonical seedhash + one
  transient (the immediately-prior epoch or a probe). The two-slot
  shape covers the consumer.
- *Reopening criteria.* Reopen if **any** of:
  1. A second Rust caller of `CacheStore` lands that needs
     concurrent canonicality across multiple chains (e.g., a
     stateless verifier serving alt-tip + main-tip simultaneously
     during a deep reorg window). The caller's existence is the
     substrate-change; not "we might want it."
  2. Decision #5 (FFI-locality of CacheStore) reverses such that
     CacheStore moves out of `shekyl-ffi` into a multi-tenant
     daemon-side surface; that reversal is itself substrate-change-
     class and would require its own design doc.
  3. The Phase 3a survey of FFI-shim concurrent-callers reveals a
     concurrency profile incompatible with the two-slot shape
     (e.g., the shim ends up serving N>2 distinct seedhashes in
     overlapping windows where eviction of any of them costs
     ~150 ms — empirical, not speculative).
- *Re-evaluation shape.* New design round (Round X+1 of a Phase
  2f extension or a Phase-2f-successor doc), citing the substrate
  change and re-running R1-D1's option enumeration. The two-slot
  API does not change in place; it is replaced atomically by a
  new shape per the deletion-and-debt rule.

**Round 2 disposition (merges R1-D2; supersedes R1-D1's frozen
surface per §1.1 substrate correction).** The §1.1 amendment
changes the load-bearing question from "what is CacheStore's API
shape?" (a single-axis question Round 1 closed against a single-
axis options menu) to "what is the layered shape — PreparedCache
+ CacheStore — that delivers the consensus-correctness invariant
at the type level *and* the canonical-protection QoS at the
structural level?" Round 2 closes the layered question.

The Round 1 disposition above stays as audit trail per
`91-documentation-after-plans.mdc`. The frozen API code-block in
the Round 1 disposition is **superseded** by the Round 2 code-
block below.

**Three-axis options matrix.** The Round 1 option-set (a)/(b)/(c)
mapped a single axis (canonical-protection shape). Round 2's
adversarial pass surfaces that the load-bearing question is
layered across three independent axes:

- **Axis 1 — where the cache+seedhash binding lives.**
  - (i) separate `Cache` and `seedhash` parameters to
    `compute_hash` (Phase 2c freeze; Round 2 rejects).
  - (ii) `PreparedCache` bundle (Round 2 picks; §1.1 amendment).
  Axis 1 is consensus-correctness: a caller passing the wrong
  cache for a given seedhash gets a wrong hash, which is fine
  for chain integrity (network rejects) but is a footgun the
  type system can close at zero cost. The `PreparedCache`
  bundling makes wrong-cache-for-seedhash unrepresentable.
- **Axis 2 — where canonical-protection lives.**
  - (a) transparent memo with explicit `pin(seedhash)` /
    `unpin()`. Round 1 rejected on caller-discipline grounds.
  - (b) explicit two-slot type with `set_canonical`. Round 1
    picked. Round 2 **reaffirms (b)**, but reframed: the slots
    hold `Arc<PreparedCache>` (not `Arc<Cache>` + tracked
    seedhash); seedhash-as-slot-key is read from
    `prepared.seedhash()` rather than tracked separately.
  - (c) type-stratified composition. Round 1 rejected as over-
    provisioning at capacity 2.
  Axis 2 is QoS — canonical-protection is a denial-of-service-
  amplification defense (per F1), not a consensus-correctness
  invariant. Once Axis 1 type-enforces consensus correctness,
  Axis 2's choice has lower stakes; (b) is still right but the
  argument shifts from "structurally enforce consensus
  correctness" to "structurally enforce the QoS sticky
  property."
- **Axis 3 — whether CacheStore exists at all.**
  - (d) no-CacheStore: consumers manage `Arc<PreparedCache>`
    lifecycle directly via `PreparedCache::derive`; in-flight
    deduplication and canonical-protection are consumer-side
    concerns.
  - (e) thin amortizing layer: CacheStore exists but is
    minimal — holds at-most-N `Arc<PreparedCache>` instances
    with simple LRU; no canonical-protection structure.
  - (f) CacheStore with full canonical-protection structure
    (the Round 1 (b) shape, pre-PreparedCache).
  Round 2 picks the **(e)/(f) hybrid**: a thin amortizing layer
  with explicit two-slot canonical-protection on top of
  `Arc<PreparedCache>`. The structural shape is (f) but the
  framing is (e) — CacheStore is no longer the fortress
  enforcing consensus correctness; it's a thin amortizing layer
  whose canonical-protection structure is QoS-shaped.

**Rejection of (d) and (g).** The (d) no-CacheStore alternative
and its (g) refinement (no-CacheStore + per-consumer in-flight
deduplication map) share a rejection rationale: **Arc-holding
memory exhaustion**. Without an upper bound at a CacheStore
layer, an attacker who induces concurrent novel-seedhash lookups
across multiple consumers (or repeated within one consumer) gets
the daemon to hold many `Arc<PreparedCache>` clones whose total
memory footprint scales with the number of distinct seedhashes
seen in the attack window. Capacity-N at the CacheStore layer
bounds this; consumer-side discipline does not (consumer code
that, e.g., stores `Arc<PreparedCache>` in async handler state
across an RPC call extends the cache's lifetime; the CacheStore
layer's bound is the only structural defense). The (d)/(g)
rejection is documented inline in the CacheStore rustdoc per
Round 3's `§3.1 rustdoc cite of (g) rejection` refinement, so
future readers asking "wouldn't this be simpler without the
two-slot structure?" find the adversarial finding rather than
re-proposing the shape.

**Adversarial-pass precedent (Round 3 names; twice-confirmed).**
The (g) → (b) reversal at Round 2 is the second documented
instance of a recurring shape: an adversarially-stronger
disposition supersedes an aesthetically-preferred one once a
threat-model pass surfaces a memory-exhaustion or DoS-amplification
class the cleaner shape opens. The first instance is the LWMA-1
time-source disposition (`docs/design/DAA_LWMA1.md` §§2.4–2.5):
the local-time-only choice supersedes the peer-time-derived
shape that was structurally elegant ("the network self-governs
time as well as difficulty") but adversarially weak under a
peer-time-poisoning attack class. Both instances share:

1. An initial shape that was structurally elegant — the (g)
   no-CacheStore design here; the peer-time-derived design at
   LWMA-1. Both matched a "the system self-governs at the
   smallest layer" principle.
2. An adversarial pass that surfaced a class of attack the
   elegant shape opened — Arc-holding memory exhaustion here;
   peer-time poisoning at LWMA-1. Both attacks were
   demonstrable, not hypothetical.
3. A reversion to the less-elegant-but-adversarially-stronger
   shape, with the trade-off explicitly named in the design
   doc — the §3.1 Round 2 capacity-2 ceiling here; LWMA-1's
   local-time-only disposition.

The recurrence justifies promoting the discipline to
`26-sub-pr-design-discipline.mdc`. The promotion is queued as
a precursor PR (`chore/sub-pr-design-discipline-adversarial-pass`)
per §10.1 Round 3 — landing the rule in the substrate before
forward extractions can lean on it. Future per-trait or per-
sub-PR designs should run an explicit "adversarial pass before
closure" round to surface the class of finding both instances
landed; the recurrence pattern says the cost (one round) is
much smaller than the cost of discovering the class
post-closure.

**Frozen public surface (Round 2 supersedes Round 1's code-
block):**

```rust
// In rust/shekyl-pow-randomx/src/cache_store.rs (new); re-exported
// from rust/shekyl-pow-randomx/src/lib.rs as `pub use cache_store::CacheStore;`.
//
// Two-slot store: at-most-one canonical (sticky against eviction)
// plus at-most-one transient (displaced by every new
// lookup_or_derive when no slot match exists). Concurrency-safe by
// interior mutability per the synchronization-shape sub-block below.
//
// ## Why two slots and not "no CacheStore at all"
//
// A "no CacheStore" alternative — let consumers manage
// `Arc<PreparedCache>` directly, possibly with a per-consumer
// in-flight-derivation map for thundering-herd protection — was
// considered (Axes 2/3 alternatives (d) and (g) per §3.1 Round 2
// disposition) and rejected for **Arc-holding memory exhaustion**.
// Without a CacheStore-layer cap, an attacker who induces
// concurrent novel-seedhash lookups across multiple consumers (or
// repeated within one consumer) gets the daemon to hold many
// `Arc<PreparedCache>` clones whose total memory footprint scales
// with the number of distinct seedhashes seen in the attack
// window (each `PreparedCache` is ~256 MiB). Capacity-2 at the
// CacheStore layer bounds this; consumer-side discipline alone
// does not. Future readers asking "wouldn't this be simpler
// without the two-slot structure?" should read §3.1 Round 2's
// (d)/(g) rejection rather than re-proposing the shape.
pub struct CacheStore { /* private fields per sync-shape sub-block */ }

impl CacheStore {
    /// Construct an empty store. Both slots start unset; the FFI
    /// shim's lock-ordering discipline (per Decision #5) ensures
    /// `set_canonical` is called before serving lookups. The cold-
    /// start window is bounded to daemon startup.
    pub fn new() -> CacheStore;

    /// Fast-path lookup: returns `Some(Arc::clone(...))` if
    /// `seedhash` matches the canonical or transient slot, else
    /// `None`. Never derives. Separates fast-path (no derivation)
    /// from slow-path (`lookup_or_derive`) so a hot-path validator
    /// that knows it should hit canonical can call `lookup` and
    /// treat `None` as an error signal rather than transparently
    /// paying ~150 ms of unexpected derivation cost.
    pub fn lookup(&self, seedhash: &Seedhash) -> Option<Arc<PreparedCache>>;

    /// Slow-path lookup: returns the cache for `seedhash`,
    /// deriving on miss. Concurrent calls for the same novel
    /// `seedhash` share one in-flight derivation per the
    /// in-flight-deduplication sub-block below; only one Argon2d
    /// fill runs. On derivation completion the result is published
    /// into the transient slot and returned. The in-flight-map
    /// entry is dropped immediately on publish (cleanup-on-publish;
    /// see threat-model F4 in §4 Round 3 disposition).
    pub fn lookup_or_derive(&self, seedhash: &Seedhash) -> Arc<PreparedCache>;

    /// Advance the canonical to `prepared`. Semantics:
    /// - The previous canonical (if any) is demoted to transient,
    ///   evicting the prior transient occupant from the slot. The
    ///   evicted occupant's `Arc<PreparedCache>` clones held in
    ///   consumer code stay alive until those clones drop; the
    ///   underlying cache lives as long as any clone references it,
    ///   regardless of slot occupancy.
    /// - The new `prepared` lives in the canonical slot; it is
    ///   non-evictable for as long as it is canonical.
    /// - If `prepared.seedhash()` already matches the existing
    ///   canonical, no-op.
    /// - The argument is the bundled `Arc<PreparedCache>`, not a
    ///   seedhash + cache pair. The caller obtains it via
    ///   `lookup_or_derive` (or by direct
    ///   `PreparedCache::derive` outside the store).
    pub fn set_canonical(&self, prepared: Arc<PreparedCache>);
}

impl Default for CacheStore { /* equivalent to ::new() */ }
```

The Round 1 `insert` method is **removed**. Its function
(publish a derived cache into the transient slot) is subsumed by
`lookup_or_derive`'s on-completion publication; no caller-driven
insert path remains. This collapses the Round 1 four-method
public surface to three methods, eliminates the caller-induced
state where a derived cache is held outside the store awaiting an
explicit `insert` call, and removes the `insert(canonical_match)`
no-op edge case the Round 1 state-transition table had to
enumerate.

**In-flight derivation deduplication shape (Round 2 pins; new
vs. Round 1 surface).**

The in-flight `HashMap` is the primitive that closes the
thundering-herd attack surface:

```rust
// Internal to CacheStore (private fields):
struct CacheStore {
    canonical: RwLock<Option<Arc<PreparedCache>>>,
    transient: RwLock<Option<Arc<PreparedCache>>>,
    in_flight: Mutex<HashMap<Seedhash, Shared<DerivationFuture>>>,
}
```

Concurrent `lookup_or_derive` calls for the same novel seedhash
hit the in-flight map: the first call inserts a
`Shared<DerivationFuture>` and starts the Argon2d fill; subsequent
calls clone the `Shared` future and await the existing
derivation. When the first derivation completes, the result is
published to the transient slot **and** the in-flight-map entry
is dropped (cleanup-on-publish). Subsequent lookups hit the slot,
not the in-flight map.

Cleanup-on-publish is load-bearing for memory-boundedness. Without
it, the in-flight `HashMap` grows unboundedly under sustained
novel-seedhash attack (each derivation completes and leaves an
entry; the entry stays until the `HashMap` rehashes or
`CacheStore` is dropped). With cleanup-on-publish, the in-flight
`HashMap` holds only currently-derivating seedhashes; size is
bounded by the concurrency level, not by total derivations seen.

The `Shared<DerivationFuture>` is the `futures::future::Shared`
adapter that allows multiple consumers to await one future. Per
rule 17 (dependency discipline), the `futures` crate is not yet a
workspace dependency; the implementation PR may use either
`futures` (adding it to `[workspace.dependencies]` in
`rust/Cargo.toml`) or a sync alternative built on
`std::sync::Arc<std::sync::Mutex<DerivationState>>` + condvar.
The choice is a Round 3 sub-detail; the contract — "concurrent
callers share one derivation" — is pinned at Round 2.

**Synchronization shape (Round 2 pins; replaces Round 1's
`Mutex<{...}>` placeholder).**

- **Per-slot `RwLock<Option<Arc<PreparedCache>>>`.** Lookups are
  the hot path; writes (`set_canonical`, `lookup_or_derive`'s
  publication) are rare. `RwLock` lets concurrent readers
  proceed; writers block briefly during the slot swap. A single
  `Mutex` over the slot pair would serialize all readers,
  defeating concurrency. Per-slot locking (rather than one lock
  over both slots) lets canonical reads not block transient
  writes and vice versa — minor but free given the type
  structure, and the canonical-vs-transient swap during
  `set_canonical` is the only operation that needs both locks
  (acquired in canonical-then-transient order to avoid
  deadlock).
- **`Mutex<HashMap>` for in-flight.** Writes (insert on first
  call; remove on cleanup-on-publish) and reads (clone the
  existing future) are roughly balanced; the critical section is
  short (HashMap access + `Shared::clone`); `RwLock` would not
  buy meaningful concurrency. `Mutex` is the simpler primitive.
- **Sharding rejected.** At capacity-2, sharding the slots
  across N independent locks doesn't reduce contention — there
  is no contention to reduce when there are only two slots.
  Sharding is for high-concurrency many-bucket data structures;
  not applicable here.

Pre-genesis (`15-deletion-and-debt.mdc`) makes synchronization-
shape changes bounded if a future bench surfaces `RwLock`-not-
helping or `Mutex`-contention; reopen via Round X+1 rather than
maintaining a versioning surface.

**11-row state-transition table (Round 2 supersedes Round 1's
table; `Arc<PreparedCache>` shape).**

Pre/post states reference `Option<Arc<PreparedCache>>` slots;
transitions are typed against `Arc<PreparedCache>` (set_canonical
takes the bundle) or `&Seedhash` (lookup is keyed by seedhash).
The substantive transitions are unchanged from Round 1 (canonical
non-evictable; transient displace-on-publish; advance promotes-
from-transient + demotes-prior); the table refresh is the typing
plus the `insert→lookup_or_derive` substitution. Let
`pA = Arc<PreparedCache>{seedhash=A, cache=cA}` etc.; let
`la = lookup_or_derive`.

| Action | Pre-state | Post-state |
|--------|-----------|------------|
| `new()` | (none) | canonical=None, transient=None |
| `la(A)` (novel, no canonical) | canonical=None, transient=None | canonical=None, transient=Some(pA) (returns pA) |
| `la(B)` (novel, no canonical) | canonical=None, transient=Some(pA) | canonical=None, transient=Some(pB) (pA dropped from slot; consumer-held Arc clones survive) |
| `set_canonical(pA)`, A in transient | canonical=None, transient=Some(pA) | canonical=Some(pA), transient=None |
| `la(B)` (novel, A canonical) | canonical=Some(pA), transient=None | canonical=Some(pA), transient=Some(pB) |
| `la(C)` (novel, A canonical, B transient) | canonical=Some(pA), transient=Some(pB) | canonical=Some(pA), transient=Some(pC) (pB dropped from slot) |
| `set_canonical(pB)`, A canonical, B not present | canonical=Some(pA), transient=Some(pC) | derives B → canonical=Some(pB), transient=Some(pA) (A demoted; pC dropped from slot) — *the caller calls `la(B)` first to obtain `pB`; `set_canonical(pB)` then advances* |
| `set_canonical(pA)` (canonical match) | canonical=Some(pA), transient=Some(pB) | canonical=Some(pA), transient=Some(pB) (no-op) |
| `la(A)` (canonical match) | canonical=Some(pA), transient=Some(pB) | canonical=Some(pA), transient=Some(pB) (returns pA from canonical) |
| `la(B)` (transient match) | canonical=Some(pA), transient=Some(pB) | canonical=Some(pA), transient=Some(pB) (returns pB from transient) |
| concurrent `la(D)` × 2 (novel) | canonical=Some(pA), transient=Some(pB) | both calls await one in-flight derivation; on completion: canonical=Some(pA), transient=Some(pD) (pB dropped from slot); both calls receive the same `Arc<PreparedCache>` clone (in-flight dedup) |

Test matrix (per §6.1 Round 3 refinement) asserts each row's
pre/post identity by direct `lookup(...)` checks after each
action plus `Arc::ptr_eq` checks for the in-flight-dedup row.

**Capacity-2 reopen criterion (Round 2 sharpens Round 1).**

The Round 1 reopen criterion was: "a second Rust caller of
`CacheStore` lands that needs concurrent canonicality across
multiple chains." Round 2 sharpens: a *named real consumer*
surfaces a *sustained operational pattern* where 2 caches isn't
sufficient and the operator demonstrably has to choose between
paying re-derivation cost or extending the `CacheStore`. Not
"we might want N someday"; "this specific consumer has
demonstrated 2 isn't enough." The substrate-anchored event is
the consumer's call-site grep evidence + a measurement showing
the cost (e.g., "Phase 3a stressnet validator served 4 distinct
seedhashes across overlapping 30-minute reorg windows;
re-derivation cost N hash-units; CacheStore extension would have
saved N").

**Transparent-memo framing retired.**

The parent-plan `RANDOMX_V2_PLAN.md` Decision #6 wording
("transparent memo with capacity-2 LRU and `pin()` API") belonged
to Round 1's Option (a). Option (b) is honest about the
two-slot structure and the canonical-vs-transient distinction —
the type's API surface (`set_canonical` is a structural concept)
is not a transparent-memo API. The wording is updated by a small
precursor PR `chore/randomx-v2-plan-decision6-amendment` (queued
in §10) that lands **before** the Phase 2F implementation PR
opens. Bounded scope; one-file change; the precedent is the
Phase 2c F4-absorbed parent-plan rescope.

**Reversion clause (Round 2 supersedes Round 1's clause).**

- *Rejection.* The three-axis disposition above (Axis 1 →
  PreparedCache; Axis 2 → (b); Axis 3 → (e)/(f) hybrid) is
  rejected at V3.0 only if substrate-change fires per the
  reopening criteria below. The Round 1 reopening criteria for
  Axis 2 carry forward unchanged; Round 2 adds Axis 1 and Axis 3
  reopening criteria below.
- *Reopening criteria — Axis 1 (PreparedCache).* Reopen if
  **any** of:
  1. A consumer surfaces a need to construct `compute_hash`-
     suitable inputs *without* going through `PreparedCache::derive`
     (e.g., a deserialization path that reconstitutes a cache
     from disk without re-deriving). Demonstrate by a concrete
     deserialization use case; not "we might want it."
  2. The Phase 3a FFI shim audit reveals that the bundling
     constrains the C-ABI surface in a way that's costly to
     work around (e.g., the C++ caller has the cache and seedhash
     in separate state and bundling on every call costs
     measurable time). Demonstrate by impl-PR profiling.
  3. A V4-PQC architectural choice requires `compute_hash` to
     take input that wraps PQC-authenticated metadata about the
     cache, breaking the simple `&PreparedCache` shape. The
     reopening is a successor design doc; not in Phase 2F's
     scope.
- *Reopening criteria — Axis 2 (canonical-protection in (b)).*
  Carries forward Round 1's three reopening criteria unchanged
  (second Rust caller; Decision #5 reversal; Phase 3a FFI shim
  survey reveals incompatible concurrency profile).
- *Reopening criteria — Axis 3 (CacheStore exists).* Reopen if:
  1. A bench surfaces that the in-flight deduplication
     contention (Mutex<HashMap>) is the bottleneck under
     production load; the disposition could shift to (d)/(g)
     consumer-side dedup OR a sharded in-flight map. Demonstrate
     by Phase 3a profiling; not speculation.
  2. The architectural-inheritance audit at Phase 3a reveals
     that consumer-side discipline can be made structural (e.g.,
     a typed handle that drops on-scope-exit, removing the
     consumer-side Arc-holding attack); the (d)/(g) rejection's
     rationale dissolves and `CacheStore` simplifies.
- *Re-evaluation shape.* New design round (Round X+1 of a Phase
  2f extension or a Phase-2f-successor doc), citing the
  substrate change and re-running the three-axis option matrix.
  The PreparedCache + CacheStore layered shape does not change in
  place; it is replaced atomically per the deletion-and-debt
  rule.

### 3.2 R1-D2 — Eviction policy under attacker interleave

Given R1-D1's API choice, fix the eviction policy:

- For option (a): the LRU treats the pinned slot as ineligible
  regardless of access recency. Concrete behavior: if pinned ==
  seedhash-A and the LRU is full with pinned-A + transient-B, a
  lookup miss for seedhash-C evicts B (not A); a lookup miss for
  seedhash-D evicts C (not A); etc.
- For option (b): canonical-slot is non-evictable by construction.
  Transient slot holds at-most-one cache; arrivals replace it.
- For option (c): pin/transient ownership is type-level; no eviction
  policy exists at the composition layer.

Round 1 picks the option-specific concrete behavior + the test
matrix (§6.1 below) that asserts the canonical slot survives a
worst-case interleave.

**Round 1 disposition (closes R1-D2).** Per R1-D1's option (b)
selection, the eviction policy is **structurally fixed**:

1. **Canonical slot is non-evictable.** Once `set_canonical(X)` has
   been called and `X`'s cache resides in either slot, no `insert`
   call (regardless of seedhash) can displace `X`. The displacement
   path is `set_canonical(Y)`, which advances canonicality and
   demotes `X` to transient — at which point the next `insert(Z)`
   for `Z != X, Z != Y` displaces `X` per the transient rule below.
2. **Transient slot is displace-on-insert.** Every `insert(W, _)`
   call where `W` is not the canonical seedhash and `W` is not
   already in the transient slot drops the prior transient entry
   and stores the new one. There is no LRU recency tracking; the
   slot holds at-most-one entry, displacement is unconditional.
3. **Empty-canonical degenerate case.** Before the first
   `set_canonical` call (cold-start window — daemon has not yet
   loaded its chain-state view of the canonical seedhash), the
   canonical slot is empty (`Option::None` internally) and only
   the transient slot churns. Both slots are subject to attacker-
   induced churn during this window. The shim's discipline (per
   §1.1's Decision #5 framing): the FFI shim calls
   `set_canonical(chain_tip_seedhash)` immediately on chain-state
   load, before serving any `compute_hash` against that seedhash.
   The post-cold-start steady state has canonical pinned; the
   degenerate window is bounded to daemon startup.

Concrete behavior under R1-D1 option (b) — pinned for the
implementation PR's `cache_store.rs` body:

| Action | Pre-state | Post-state |
|--------|-----------|------------|
| `new()` | (none) | canonical=None, transient=None |
| `insert(A, cA)`, no canonical | canonical=None, transient=None | canonical=None, transient=Some((A,cA)) |
| `insert(B, cB)`, no canonical | canonical=None, transient=Some((A,cA)) | canonical=None, transient=Some((B,cB)) (A dropped) |
| `set_canonical(A)`, A in transient | canonical=None, transient=Some((A,cA)) | canonical=Some((A,cA)), transient=None |
| `insert(B, cB)`, A canonical | canonical=Some((A,cA)), transient=None | canonical=Some((A,cA)), transient=Some((B,cB)) |
| `insert(C, cC)`, A canonical | canonical=Some((A,cA)), transient=Some((B,cB)) | canonical=Some((A,cA)), transient=Some((C,cC)) (B dropped) |
| `set_canonical(B)`, A canonical, B transient | canonical=Some((A,cA)), transient=Some((B,cB)) | canonical=Some((B,cB)), transient=Some((A,cA)) (A demoted) |
| `set_canonical(D)`, D not present | canonical=Some((B,cB)), transient=Some((A,cA)) | canonical=Some((B,cB)), transient=Some((A,cA)) (no-op; caller responsible for derive+insert+second set_canonical) |
| `insert(B, cB')`, B canonical | canonical=Some((B,cB)), transient=Some((A,cA)) | canonical=Some((B,cB)), transient=Some((A,cA)) (no-op; canonical match takes precedence over transient overwrite) |

Test matrix (per §6.1 below) asserts each row's pre/post
identity by direct `lookup(...)` checks after each action.

**Reversion clause (per `21-reversion-clause-discipline.mdc`).**
The eviction-policy disposition is structurally tied to R1-D1's
option (b). Reopening criteria for R1-D2 are exactly R1-D1's
reopening criteria — the policy cannot be revisited independently
of the API shape. If R1-D1 reopens (per its substrate-change
clauses), R1-D2 is re-derived from the new shape.

**Round 2 disposition (R1-D2 merged into R1-D1 Round 2).** Round
2's substrate-correction (per §1.1 amendment + §3.1 Round 2)
makes R1-D1 and R1-D2 a single layered question rather than two
independent questions: once Axis 1 (PreparedCache) is type-
enforced, the Axis 2 eviction policy operates on
`Arc<PreparedCache>` and the eviction transitions are typed
against the bundle. The Round 1 R1-D2 disposition above stays as
audit trail per `91-documentation-after-plans.mdc`. The
substantive eviction transitions are unchanged from Round 1
(canonical non-evictable; transient displace-on-publish; advance
promotes-from-transient + demotes-prior); the typing is
`Arc<PreparedCache>` instead of `(seedhash, Arc<Cache>)` pairs;
the `insert` action is replaced by `lookup_or_derive`'s on-
completion publication. The full Round-2-typed 11-row state-
transition table lives in §3.1 Round 2 disposition; the Round 1
table above is preserved as audit trail and **superseded** by
the §3.1 Round 2 table.

### 3.3 R1-D3 — Benchmark methodology (per-call VmState allocation)

Phase 2c's `BENCH_RESULTS.md` baseline is `compute_hash` median per-
call timing (303.60 ms post-2d; 295.91 ms post-2c). The per-call
`VmState` allocation cost is currently *included* in that figure but
not isolated.

Options for isolation:

- **(a) Diff method** — measure `compute_hash` with the current
  per-call allocation (baseline), then with allocation hoisted
  outside (e.g., a one-time `VmState` instance reused across N hash
  calls, instrumented for the bench); the delta is the per-call
  allocation cost amortized over N. Pros: directly measures what the
  pool decision optimizes. Cons: requires a temporary internal API
  to hoist `VmState` for the bench, which leaks into the bench
  harness.
- **(b) Component method** — separately benchmark
  `Box::<[u8]>::new_zeroed_slice(2 << 20)` (the 2 MB scratchpad
  zero-init) and the register-file `VmState` field init. Pros: no
  internal API exposure. Cons: doesn't account for any allocator-
  amortization effect a steady-state pool would capture.
- **(c) Population method** — benchmark a pool-mode `compute_hash`
  body against the current per-call body across N iterations. Pros:
  measures the actual A/B the pool decision depends on. Cons:
  requires implementing the pool body before the bench, which makes
  the "decide whether to pool based on the bench" sequencing
  circular.

Round 1 picks one. Disposition rules out the cycle (i.e., option (c)
without the pool already implemented). Likely (a) or (b).

**Round 1 disposition (closes R1-D3):** Pick **option (b)** —
Component method.

The choice is forced by a substrate finding surfaced during R1-D1
closure: option (a)'s diff method requires a `compute_hash`-shaped
helper that takes an externally-allocated `VmState` (e.g.,
`pub fn compute_hash_with_state(&Cache, &[u8; 32], &[u8], &mut VmState) -> [u8; 32]`).
That signature transitively requires `VmState`'s visibility to move
from `pub(crate)` to `pub`, which:

1. **Breaks the §1.1 freeze.** §1.1 pins `VmState` as `pub(crate)`;
   adding a `pub` consumer of it elevates the type's visibility
   transitively.
2. **Contradicts Decision #7.** The Decision #7 framing
   ("internalize a `VmState` pool inside `compute_hash`, no public
   `VmPool` type") rests on `VmState` being internal to `vm.rs`.
   A `pub fn compute_hash_with_state(..., &mut VmState)` is the
   public-VmPool surface in another guise — the consumer holds the
   `VmState` across calls, which IS a pool managed by the consumer.

Per `00-mission.mdc`'s priority hierarchy: the encapsulation
discipline (priority-1 security/audit-surface-minimization) trumps
measurement fidelity (priority-3 durability/precision). Option (b)'s
component-method bound is sufficient: it gives a *floor* on per-
call alloc cost (the components ARE the alloc work — `Box::<[u8]>::new_zeroed_slice(2 << 20)`
plus register-file zero-init plus bookkeeping), and the pool
decision rule (R1-D4) acts on the floor with margin (see R1-D4
reversion clause for the [50, 100) µs ambiguity band).

The component bench harness at the implementation PR — pinned
shape (no Criterion-fidelity loss; lives in `benches/per_call_alloc.rs`
or extends `benches/compute_hash_alloc.rs`):

```rust
// Component 1: scratchpad zero-init. Public std API; no internal
// surface exposure.
c.bench_function("vmstate_alloc_scratchpad_zeroed", |b| {
    b.iter(|| {
        let _scratchpad: Box<[u8]> = vec![0u8; 2 * 1024 * 1024].into_boxed_slice();
        // (or the equivalent unsafe-free Box::<[u8]>::new_zeroed_slice
        //  expression once stable; the bench's harness uses whichever
        //  primitive vm.rs uses at HEAD — verified at impl-PR time)
    });
});

// Component 2: register-file zero-init (synthesized in the bench
// against the spec §4.5 register-file shape; does NOT consume
// VmState directly so visibility is unaffected).
c.bench_function("vmstate_alloc_register_file", |b| {
    b.iter(|| {
        let _r: [u64; 8] = [0u64; 8];
        let _f: [F128Stub; 4] = std::array::from_fn(|_| F128Stub::zero());
        let _e: [F128Stub; 4] = std::array::from_fn(|_| F128Stub::zero());
        let _a: [F128Stub; 4] = std::array::from_fn(|_| F128Stub::zero());
        // F128Stub mirrors the spec §4.5 [f64; 2] shape; the bench
        // does not consume the production F128 newtype to keep
        // visibility constraints clean.
    });
});

// Reported floor: median(component_1) + median(component_2). The
// implementation PR records both component medians and the sum
// in BENCH_RESULTS.md alongside the existing compute_hash_alloc
// full-pipeline median.
```

The bench produces a *lower bound* on per-call VmState alloc cost.
Allocator amortization (thread-local arena, free-list reuse) can
make actual cost lower than the floor in steady state; cache
pressure from concurrent calls can make it higher. The floor is
the conservative-against-no-pool input to R1-D4: if the floor is
≥ 100 µs the pool is unconditionally needed; if the floor is well
below 100 µs (concretely: < 50 µs, half-margin) the pool is
unconditionally unneeded; the [50, 100) µs band is the ambiguity
zone handled by R1-D4's reversion clause.

**Reversion clause (per `21-reversion-clause-discipline.mdc`).**

- *Rejection.* Option (a)'s diff method is rejected at V3.0
  because its API-surface cost contradicts §1.1's freeze and
  Decision #7's encapsulation discipline.
- *Reopening criteria.* Reopen if **any** of:
  1. R1-D3's component-method floor lands in the [50, 100) µs
     ambiguity band, in which case option (a)'s tighter measurement
     is needed. The reopening fires at implementation-PR time, not
     design-time; the implementation PR's design-round (within the
     Phase 2f impl-PR's pre-flight) re-evaluates whether to
     transiently expose `compute_hash_with_state` as a
     `#[doc(hidden)] pub` helper with a documented deletion target,
     OR to ship the pool by precaution (treating the ambiguity
     band as ≥-100-µs-equivalent).
  2. Decision #7 itself reverses (a substrate-change-class event).
     If a future design doc accepts a public `VmPool` type, the
     methodology question reopens because option (a)'s API cost is
     no longer load-bearing.
  3. The bench's component decomposition is shown to systematically
     under-estimate real per-call alloc cost (e.g., a profiler
     trace on a production daemon shows ≥ 2× component-floor cost
     per call). Substrate: empirical evidence, not speculation.
- *Re-evaluation shape.* The implementation PR's design pre-flight
  (per Phase 2c's R0-D1..R0-D8 impl-time corrections precedent on
  `feat/randomx-v2-phase2c-impl`) handles the ambiguity-band path
  in-place; substrate changes outside that band trigger a fresh
  Phase 2f.X round on this plan-doc.

**Round 3 disposition (cfg-gated pool reframe; supersedes the
Round 1 component-method-only methodology).**

The Round 1 disposition above stays as audit trail per
`91-documentation-after-plans.mdc`. Round 3 reframes the
methodology to break a sequencing problem the Round 1 disposition
left implicit: option (a) was rejected as circular ("decide
whether to pool based on the bench" requires implementing the
pool to bench against). Option (b) avoided the circularity but
measures a *floor* (allocator behavior on a 2 MiB zero-init), not
the pool's actual cost-savings against a steady-state allocator.
Without an A/B against pool-mode, the (b) measurement is
conservative-against-no-pool but uninformative about pool-mode
savings.

Round 3's reframe: **the pool is implemented for the bench
regardless of R1-D4's outcome, kept behind a `cfg(...)` gate.**
The pool body lives behind
`#[cfg(any(test, feature = "internal-pool-bench"))]`. The bench
harness measures both the no-pool path (the production path) and
the cfg-gated pool path (the would-be production path if R1-D4
fires the ≥-100-µs branch). The bench result determines whether
the cfg-gated pool is **promoted to production** (cfg removed,
the pool becomes the production path) or **stays as the bench-
only artifact** (cfg retained, the pool is not in production
builds but remains in the codebase for future re-bench).

The Round 3 methodology preserves Round 1's option-(b) component
method as the no-pool sanity floor: B-2 + B-3 medians sum to a
component-floor that the no-pool A/B measurement should not
exceed. The component method survives as a cross-check, not as
the only methodology.

**Implementation shape.**

```rust
// In rust/shekyl-pow-randomx/src/vm.rs (or src/pool.rs):

#[cfg(any(test, feature = "internal-pool-bench"))]
pub(crate) struct VmStatePool { /* private fields */ }

#[cfg(any(test, feature = "internal-pool-bench"))]
impl VmStatePool {
    pub(crate) fn new(capacity: usize) -> VmStatePool;
    pub(crate) fn acquire(&self) -> VmStateGuard<'_>;
    pub(crate) fn release(&self, vm: VmState);
}

// compute_hash body in src/vm.rs:
pub fn compute_hash(prepared: &PreparedCache, data: &[u8]) -> [u8; 32] {
    // No-pool path (production):
    let mut vm = VmState::new();
    /* ... dispatch loop ... */

    // (Phase 3a or impl-PR's cfg-gated A/B bench harness substitutes
    // pool-acquire/release here when the feature is enabled. The
    // production build never compiles the pool body.)
}
```

The cfg-gated pool body is `pub(crate)` even when enabled — it
is bench / test infrastructure, never a public type per Phase 2c
Decision #7 (no public `VmPool`). Promotion to production
removes the cfg gate but does not promote the visibility.

**Bench harness shape (R1-D3 Round 3 supersedes R1-D3 Round 1's
single-bench).**

| # | Bench | Source | Mode |
|---|---|---|---|
| B-1 | `compute_hash_alloc::per_call` (existing) | `benches/compute_hash_alloc.rs` | Phase 2d baseline (full-pipeline). Informational. |
| B-2 | `vmstate_alloc_scratchpad_zeroed` | `benches/per_call_alloc.rs` (new) | Component method (Round 1 sanity floor). |
| B-3 | `vmstate_alloc_register_file` | Same | Component method (Round 1 sanity floor). |
| B-pool-off | `compute_hash_with_no_pool::per_call` | `benches/compute_hash_alloc.rs` extension | A/B path: production no-pool path, instrumented for direct measurement. |
| B-pool-on | `compute_hash_with_pool::per_call` | Same, gated by `--features internal-pool-bench` | A/B path: cfg-gated pool path. |

`BENCH_RESULTS.md` records:

- B-2 + B-3 sum (component-floor; sanity check).
- B-pool-off median (production-no-pool).
- B-pool-on median (cfg-gated pool).
- Delta (B-pool-off − B-pool-on); applied to the §3.4 R1-D4
  threshold.
- R1-D4 disposition (no-pool / ambiguity-escalation / pool-
  promoted) with the delta-vs-100-µs comparison.

**Reversion clause (Round 3 supersedes Round 1's clause).**

- *Rejection.* Round 1's component-method-as-sole-bench is
  rejected at Round 3 because it cannot measure the pool's
  actual savings; only the floor. The component method is
  preserved as a sanity floor, not as the methodology.
- *Reopening criteria.*
  1. The `--features internal-pool-bench` build doesn't compile
     for any reason — the Round 3 reframe presumes the cfg-gated
     pool can be implemented in ≤ 150 lines (matches the Round 1
     conditional-impl estimate). If implementation surfaces
     unexpected complexity, the methodology reverts to Round 1's
     component-only and the impl-PR escalates per the Round 1
     ambiguity-band-handling.
  2. Round 1's reversion criteria carry forward (Decision #7
     reversal; component decomposition under-estimate; ambiguity-
     band fall-through to impl-PR pre-flight).
- *Re-evaluation shape.* The Phase 2F impl-PR's pre-flight
  computes the A/B delta and applies the §3.4 R1-D4 Round 3
  disposition (R1-D4 folded into R1-D3). Substrate changes
  outside that band trigger a fresh Phase 2f.X round.

### 3.4 R1-D4 — Pool decision threshold

Phase 0 budget is **≤100 µs** per `RANDOMX_V2_PLAN.md` line 240. R1-D4
fixes the bench-result-to-pool-decision rule:

- If R1-D3's bench shows per-call allocation < 100 µs → no pool;
  document the bench result in `BENCH_RESULTS.md`; F2 stays deferred.
- If per-call allocation ≥ 100 µs → pool lands inside `compute_hash`
  (private to `vm.rs`, no public `VmPool` type) with capacity from
  R1-D5; bench delta in `BENCH_RESULTS.md`.

Round 1 task is to confirm the threshold without re-litigating
Decision #7. The threshold is the Phase-0-budget number; Round 1's
work is naming what *response* the implementation PR takes given the
empirical input. The reversion clause per
`21-reversion-clause-discipline.mdc`: the no-pool disposition reopens
only if a substrate change (e.g., allocator regression, scratchpad
size change at consensus-rule level, runtime architecture mismatch)
moves the bench above 100 µs.

**Round 1 disposition (closes R1-D4):** Threshold confirmed at
**100 µs** per `RANDOMX_V2_PLAN.md` line 240 + Decision #7. Pinned
bench-result-to-pool-decision rule:

| R1-D3 component-floor median | Implementation PR action |
|------------------------------|--------------------------|
| < 50 µs | No pool. Decision #7's per-call-allocation default holds. Record the floor in `BENCH_RESULTS.md`; F2 (R1-D5) stays deferred. Drop §8 commit 4. |
| ≥ 50 µs and < 100 µs | **Ambiguity band — escalate to impl-PR pre-flight per R1-D3 reversion clause #1.** The pre-flight either (a) transiently exposes `compute_hash_with_state` as `#[doc(hidden)] pub` with a deletion-target post-bench (decision-doc preserved on the chore branch; deletion in commit 5b of §8) and runs the diff-method bench, OR (b) ships the pool by precaution treating the band as ≥-100-µs-equivalent. The pre-flight picks based on the floor's distance from 100 µs (closer to 100 → ship pool; closer to 50 → run diff bench). |
| ≥ 100 µs | Pool lands inside `compute_hash` per Decision #7's internal-pool form. Capacity sized per R1-D5. Bench delta in `BENCH_RESULTS.md`. §8 commit 4 is included. |

The `< 50 µs` lower band exists because the component-method floor
is conservative-against-no-pool (real cost ≥ floor in expectation).
A floor well under threshold gives margin against allocator-
amortization variance across architectures (a CI runner with a
slower allocator might still come in under 100 µs if the reference
machine measures, e.g., 30 µs).

**Reversion clause (per `21-reversion-clause-discipline.mdc`).**

- *Rejection (no-pool path).* The pool is rejected at V3.0 if
  R1-D3's bench result is < 50 µs. Substrate: the Phase 0 ≤100 µs
  budget plus Decision #7's "per-call allocation is the default."
- *Reopening criteria for the no-pool path.* The disposition
  reopens iff **any** of the following substrate changes fires:
  1. **Allocator regression.** The workspace's global allocator
     changes (system default → mimalloc/jemalloc/etc.) and a re-
     bench against the new allocator shows component floor or
     diff-method per-call alloc ≥ 100 µs. Substrate-anchored event:
     `Cargo.toml`'s `[profile.release.default-runtime-allocator]`
     or equivalent moves.
  2. **Scratchpad-size change at consensus-rule level.** RandomX
     v2 spec amendment (or a successor bytecode revision) increases
     the 2 MiB scratchpad to N MiB; per-call alloc cost scales
     accordingly. Substrate-anchored event: `external/randomx-v2/`
     submodule pin advance to a fork commit that changes
     `RANDOMX_SCRATCHPAD_L3` (or the spec equivalent).
  3. **Runtime architecture mismatch.** A CI runner or production
     daemon moves to an architecture with substantially-higher
     heap-allocation latency (e.g., a Windows MSVC build runner
     with a slower allocator path) and the per-architecture bench
     shows ≥ 100 µs. Substrate-anchored event: a new CI matrix
     job lands and its baseline bench exceeds the threshold.
- *Re-evaluation shape.* A successor design doc — Phase 2f.1
  extension or a new V3.x phase plan — re-runs R1-D3 against the
  changed substrate, re-applies R1-D4, and lands the pool body
  inside `compute_hash` per Decision #7's internal-pool form. The
  successor PR cites this rule by name and lists the substrate-
  change observed.
- *Rejection (pool-path branch).* If R1-D3 lands ≥ 100 µs and the
  pool ships, the public `VmPool` type remains rejected forever-
  conditional-on-Decision-#7. The reversion criterion for *that*
  rejection is Decision #7's own substrate-change clause (see
  parent plan §"Permanent architectural decisions" #7).

**Round 3 disposition (R1-D4 folds into R1-D3 Round 3 reframe).**

The Round 1 disposition above stays as audit trail. Round 3
dissolves R1-D4 as a separate Round-1 decision: the pool decision
threshold is no longer a Round-1-time question whose answer
needs to be deferred to bench-time (the Round 1 framing required
this because option (b) measured a floor, not the pool's
savings, so the pool decision was inherently an impl-PR-pre-flight
measurement). With Round 3's cfg-gated pool reframe, the bench
measures both paths directly; the threshold (≥ 100 µs → pool
promoted; < 50 µs → cfg-gated pool stays bench-only;
[50, 100) µs → impl-PR pre-flight escalation) is a **mechanical
application** of `RANDOMX_V2_PLAN.md` line 240's Phase 0 budget
to the A/B delta, not a separate decision.

The threshold values themselves are unchanged from Round 1; the
disposition retires the framing of "R1-D4 is a separate decision
point" because there's nothing left for R1-D4 to decide once
R1-D3 Round 3 measures the pool directly. R1-D4's three-band
table (no-pool / ambiguity / pool-path) is preserved as the
**rule for applying R1-D3 Round 3's bench delta**:

- **Branch A (cfg-gated pool stays bench-only).** A/B delta
  < 50 µs → no-pool production path is within budget; the
  cfg-gated pool body remains in the codebase for future re-
  bench but is not promoted. `BENCH_RESULTS.md` records the
  delta and the disposition.
- **Branch B (ambiguity-band escalation).** A/B delta in
  [50, 100) µs → impl-PR pre-flight re-evaluates per Round 1's
  ambiguity-handling shape; either ship the cfg-gated pool by
  precaution OR keep it bench-only and document the choice.
- **Branch C (cfg-gated pool promoted).** A/B delta ≥ 100 µs
  → cfg gate removed; the pool body becomes the production
  path. The Phase 2F impl-PR ships the pool unconditionally.

The Round 1 reversion criteria for the no-pool path
(Branches A and B) carry forward unchanged: allocator
regression, scratchpad-size change at consensus level, runtime-
architecture mismatch.

**Round 3 disposition reversion clause (mechanical).** R1-D4
reopens only if R1-D3's substrate changes (per R1-D3's Round 3
reversion criteria). Since R1-D4 is now a mechanical application,
not a decision, "reopening R1-D4" doesn't have a separate
substrate-change class — it is whatever R1-D3 surfaces.

### 3.5 R1-D5 — Daemon parallel-verification fanout survey (conditional)

Fires only if R1-D4 triggers the pool path. Two sources of
concurrent `compute_hash` callers in the daemon today:

1. **Alt-chain branch validation.** `src/cryptonote_core/blockchain.cpp`
   — worker pool count from `--max-validation-threads` or
   `boost::thread::hardware_concurrency()` default.
2. **Mempool tx verification.** `src/cryptonote_core/cryptonote_tx_utils.cpp`
   + `src/cryptonote_core/tx_pool.cpp` — separate worker pool, count
   from a different setting.

Round 1's survey reads both code paths at HEAD, records the worker-
pool count derivation, sums them (+ small reserve), and pins the
pool capacity at the implementation PR. Methodology pinned at Round
1; actual capacity number lands in the implementation PR (since the
survey can read different settings between Round 1 close and the
implementation PR — but pinning the *methodology* freezes how the
number is derived).

**Round 1 disposition (closes R1-D5):** Methodology pinned. The
audit-against-actual-code discipline (per
`16-architectural-inheritance.mdc`'s "audits-against-actual-code"
framing carried by F4 from `RANDOMX_V2_PHASE2C_PLAN.md` §5.11.8)
revealed that the prompted enumeration of "two sources of concurrent
`compute_hash` callers" is **substrate-incorrect at HEAD = `fb21909ff`
(post-PR-#70 `dev` tip)**. The audit reading at this commit:

| Claimed source | Actual finding at HEAD | Disposition |
|----------------|------------------------|-------------|
| (1) Alt-chain branch validation worker pool — `src/cryptonote_core/blockchain.cpp` | Confirmed. `Blockchain::prepare_handle_incoming_blocks` (line 5582–5847) submits `block_longhash_worker` (line 5331–5347) tasks to `tools::threadpool::getInstanceForCompute()` (line 5635), capped at `m_max_prepare_blocks_threads` (line 5642–5643; default 4 per line 207; settable via setter at line 6007). The worker calls `get_block_longhash` per block, which is the eventual `compute_hash` consumer at Phase 3a. | INCLUDED — primary fanout source. |
| (2) Mempool tx verification worker pool — `src/cryptonote_core/cryptonote_tx_utils.cpp` + `src/cryptonote_core/tx_pool.cpp` | **NOT FOUND.** Grep of `tools::threadpool|hardware_concurrency|tpool|getInstanceForCompute` against both files returns zero matches at HEAD. The mempool tx-admission path validates ring signatures, fee policy, and PQC signatures (`tx_pqc_verify.cpp`) — not block-PoW. PoW is verified at block-import time, not tx-admission time. | EXCLUDED — substrate-incorrect prompted claim. |

The substrate finding is the second post-2c instance of the
audit-against-actual-code discipline catching a prompted-list error
pre-implementation (first: 2c R3 `mp` correction; second: 2d R1-D3
frequency-decode finding; third: this R1-D5 absent-mempool-fanout
finding). Per `16-architectural-inheritance.mdc`'s discovery-cadence
framing, the discipline's continued strength is the property future
audits depend on; relaxing it would fail the "audits-are-clean-so-
compress" anti-pattern.

The pinned methodology — applied at the implementation PR if R1-D4
triggers the pool path:

1. **Read the threadpool source at the post-Round-N-close `dev` tip.**
   The pool-capacity derivation source is `src/common/threadpool.h`
   (singleton via `tools::threadpool::getInstanceForCompute()` —
   line 46–49) plus `src/common/threadpool.cpp::create()` (line
   71–81). The compute pool's `max` field initializes to
   `tools::get_max_concurrency()` (boost-driven `hardware_concurrency`)
   when the first call lands; the constructor-side `max - 1`
   workers + the calling thread = `max` total.
2. **Read the cap source at the same tip.** `Blockchain::m_max_prepare_blocks_threads`
   default is 4 (`blockchain.cpp:207`); the cap fires at
   `blockchain.cpp:5642–5643`. Operator overrides via the setter
   at `blockchain.cpp:6007` are out-of-scope at PR time but
   covered by the per-architecture rebench reversion clause below.
3. **Derive the binding fanout.** At PR time, the binding fanout is
   `min(tools::threadpool::getInstanceForCompute().get_max_concurrency(),
   m_max_prepare_blocks_threads)`. On a typical hardware (e.g.,
   `hardware_concurrency=16`, default cap 4), the cap binds: binding
   fanout = 4. On a hypothetical `hardware_concurrency=2` machine,
   the threadpool size binds: binding fanout = 2.
4. **Pin pool capacity = binding fanout + 1 reserve.** The +1
   covers (a) the leaf-bypass path in `threadpool.cpp:84–94` where
   the calling thread runs work in-line under saturated conditions,
   and (b) off-by-one at startup when the singleton has not yet
   fully initialized.
5. **Record the derivation in `BENCH_RESULTS.md`.** Format example:
   "fanout = `min(threadpool_max=15, m_max_prepare_blocks_threads=4)`
   = 4 on the reference machine; pool capacity = 4 + 1 = 5; rationale:
   the cap is binding, not the threadpool size; operator override
   via `--prepare-blocks-threads` would re-evaluate per the
   reversion clause."

The capacity number is empirical-at-PR-time; the methodology is
design-time-fixed.

**Reversion clause (per `21-reversion-clause-discipline.mdc`).**

- *Rejection.* No separate mempool-tx-verification fanout source is
  included at V3.0. Substrate: the post-PR-#70 `dev` tip shows
  zero `tools::threadpool` usage in `tx_pool.cpp` /
  `cryptonote_tx_utils.cpp` / `tx_pqc_verify.cpp` (verified by grep
  at audit time).
- *Reopening criteria.* The disposition reopens iff **any** of:
  1. A future PR introduces `tools::threadpool` (or any concurrent-
     worker-pool primitive) into `tx_pool.cpp` /
     `cryptonote_tx_utils.cpp` / `tx_pqc_verify.cpp` *and* that
     worker invokes `compute_hash` (directly or via the FFI shim).
     Substrate-anchored event: a grep at the new HEAD shows the
     introduction.
  2. The `m_max_prepare_blocks_threads` default changes from 4
     upstream-or-in-Shekyl, OR an operator default-deployment-pattern
     emerges (e.g., exchange-grade shekyld with `--prepare-blocks-threads
     16`) that the FFI shim's pool capacity must accommodate.
     Substrate-anchored event: the constant moves at HEAD, or a
     deployment-doc lands recommending the override.
  3. Phase 3a's FFI shim survey reveals concurrent compute_hash
     consumers outside the alt-chain branch validation path (e.g.,
     a new RPC endpoint that triggers PoW recompute on demand).
- *Re-evaluation shape.* The PR introducing the new fanout source
  re-runs R1-D5's methodology at its own HEAD, derives the new
  binding fanout, and either bumps the FFI shim's pool capacity in
  place (small change; commit on a successor `chore/` branch) or
  triggers a Phase 2f.X round if the new shape is incompatible
  with capacity = binding-fanout + 1.

**Round 3 disposition (capacity is runtime-configurable, not a
compile-time constant; supersedes Round 1's
`pub(crate) const POOL_CAPACITY: usize` shape).**

The Round 1 disposition above stays as audit trail. Round 3
refines: the pool capacity is a **runtime parameter** passed to
`VmStatePool::new(capacity: usize)`, not a compile-time constant.
The R1-D5 methodology (binding-fanout + 1 reserve) is unchanged;
where the methodology is *applied* shifts from impl-PR-time
(Round 1) to Phase 3a-FFI-shim-construction-time (Round 3).

**Why runtime-configurable.** The Round 1 framing assumed the
pool capacity could be derived at impl-PR time by reading the
`dev` tip's threadpool source. That assumption is correct for
the *methodology* (the algorithm for deriving the number) but
fragile for the *number*: the impl-PR's read of
`m_max_prepare_blocks_threads` may not equal the value at
Phase 3a's wire-up time (the daemon-side threadpool is itself
evolving per the parent migration), and operator overrides
(`--prepare-blocks-threads`) make the binding fanout per-instance
rather than per-build. A compile-time constant pinned at impl-PR
forecloses operator-driven adjustment; a runtime parameter
respects it.

The Phase 2F impl-PR ships the `VmStatePool::new(capacity)`
constructor with the methodology-pinned-at-Round-1; Phase 3a
applies the methodology to whatever the daemon's actual state is
at FFI-shim construction time (reads `tools::threadpool` +
`m_max_prepare_blocks_threads` at that HEAD, derives capacity,
passes to the constructor). The Phase 2F impl-PR uses a stub
default `Default::default()` that **panics in non-test builds**
to enforce the discipline that Phase 3a must explicitly pass a
capacity (no silent default in production).

**Implementation shape.**

```rust
// In rust/shekyl-pow-randomx/src/vm.rs (cfg-gated per R1-D3 Round 3):

#[cfg(any(test, feature = "internal-pool-bench"))]
impl VmStatePool {
    /// Construct a `VmStatePool` with the given capacity. Per
    /// R1-D5's methodology (Round 1 disposition; Round 3
    /// runtime-configurable), `capacity` should be
    /// `binding_fanout + 1` where binding fanout is
    /// `min(threadpool_max, m_max_prepare_blocks_threads)` at
    /// the daemon's runtime state. Capacity is determined by the
    /// caller (Phase 3a's FFI shim), not by the verifier crate.
    pub(crate) fn new(capacity: usize) -> VmStatePool;
}

// `Default` implementation that panics outside test/bench:
#[cfg(any(test, feature = "internal-pool-bench"))]
impl Default for VmStatePool {
    fn default() -> Self {
        #[cfg(test)]
        return VmStatePool::new(4); // bench / test default
        #[cfg(all(not(test), feature = "internal-pool-bench"))]
        panic!("VmStatePool::default() is not safe outside tests; \
                Phase 3a's FFI shim must pass an explicit capacity \
                derived per R1-D5 methodology");
    }
}
```

**`BENCH_RESULTS.md` records (Round 3 supersedes Round 1's
"format example"):**

The methodology is recorded once, not per-PR. The actual
capacity number is per-deployment (Phase 3a's FFI shim records it
at construction time; the verifier's bench harness records it for
the bench's own sanity-check). The R1-D5 reversion-clause
substrate-change events still trigger a methodology re-evaluation
(not just a number adjustment).

**Round 3 reversion clause (mechanical refinement of Round 1).**

- *Rejection.* The Round 1 compile-time-constant disposition is
  rejected at Round 3 because it's structurally incompatible
  with operator-driven capacity adjustment (`--prepare-blocks-threads`
  override) and Phase 3a's FFI shim being the right
  caller-of-`VmStatePool::new`.
- *Reopening criteria.* Round 1's R1-D5 reopening criteria carry
  forward unchanged; Round 3 adds:
  4. The runtime-parameter shape is shown to be costly (e.g.,
     branching on `capacity` inside the hot path measurably
     hurts perf). Substrate-anchored event: bench evidence;
     not speculation.
- *Re-evaluation shape.* Same as Round 1's clause; Phase 3a's
  FFI shim is the natural site for the methodology application,
  not the impl-PR.

### 3.6 R1-E1 — CI grep pattern set for the two new crate invariants

Modeled on Phase 2d's `scripts/ci/check_randomx_fpu_rounding.sh` shape.
Two greps:

- **No module-level `static` / `OnceCell` / `lazy_static`** — pattern
  draft: search `rust/shekyl-pow-randomx/src/**/*.rs` for `^static `
  / `OnceCell` / `lazy_static!` / `LazyLock` at item level (not in
  `fn` bodies, where local statics are allowed). Permitted
  exception: `const` items (`const FOO: T = ...`) are unaffected.
  Round 1 pins the exact regex + permitted-exception list.
- **No `#[no_mangle]` / `extern "C"`** — pattern draft: search for
  `#[no_mangle]`, `#[export_name`, `extern "C" fn` at item level.
  Permitted exception: none (an `extern "C"` block consuming an FFI
  surface is *callee*, not exporter; pattern matches *exporters*).
  Round 1 pins.

R1-E1 also pins the CI workflow integration site (add a step to
`build.yml` modeled on Phase 2d's `check_randomx_fpu_rounding.sh`
step) and the failure mode (CI step fails with the matched
line numbers, mirroring the FPU grep's UX).

**Round 1 disposition (closes R1-E1):** Pinned. Per rule 17
(dependency discipline) verification at source: the workspace's
`rust/Cargo.toml` `[workspace.dependencies]` (lines 88–109 at
HEAD = `f3da9f093`) does NOT contain `lru`, `parking_lot`, or
`once_cell`; `rust/shekyl-pow-randomx/Cargo.toml` (HEAD) declares
only `aes`, `blake2`, `argon2` as direct deps + `criterion` as
dev-dep. `Cargo.lock` shows `parking_lot`, `once_cell`, and
`hashbrown` as transitive deps (via criterion / argon2 / etc.) but
not at the `pub` consumption surface of `shekyl-pow-randomx`. The
two-slot CacheStore implementation per R1-D1 uses `std::sync::Mutex`
+ `Arc<Cache>` only; no new workspace dependency is added by
Phase 2f. The grep patterns below enforce that posture mechanically.

CI script: `scripts/ci/check_randomx_crate_invariants.sh` (final
name pinned). Modeled on `scripts/ci/check_randomx_fpu_rounding.sh`
shape: `set -euo pipefail` preamble, fixed-pattern grep with
zero-hit assertion, exit non-zero on any match with line-number
output to stderr.

```bash
#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
# All rights reserved. BSD-3-Clause

set -euo pipefail

CRATE_SRC="rust/shekyl-pow-randomx/src"

if [[ ! -d "${CRATE_SRC}" ]]; then
    echo "FATAL: ${CRATE_SRC} not found"
    exit 1
fi

# Pattern A: ban runtime-mutable lazy-state types from being imported
# at all. Stricter than "no module-level static" — eliminates the
# disambiguation between module-level and function-local usage by
# rejecting the import. The crate provably does not need any of these.
# Permitted exception: NONE.
PATTERN_RUNTIME_STATE='^use[[:space:]]+(once_cell|lazy_static)|^use[[:space:]]+std::sync::(OnceLock|LazyLock)|^use[[:space:]]+core::sync::(OnceLock|LazyLock)|^lazy_static!'

# Pattern B: ban module-level `static` items (mut or otherwise).
# Function-local statics are inside fn bodies (indented per rustfmt);
# column-0 `static` is by definition module-level.
# Permitted exception: `const` items (a different keyword; not matched
# by this pattern).
PATTERN_MODULE_STATIC='^(pub(\([^)]+\))?[[:space:]]+)?(unsafe[[:space:]]+)?static[[:space:]]+'

# Pattern C: ban FFI exports from this crate. All C-ABI exports live
# in shekyl-ffi (Decision #5).
# Permitted exception: NONE. An `extern "C" { fn foo(); }` *import*
# block consuming an FFI surface is not matched by this pattern
# (which requires `extern "C" fn` definition form, with `fn` after `"C"`).
# Anchored at column 0 (with optional leading whitespace for
# attributes indented inside fn bodies) so the substrings in
# `lib.rs` rustdoc citing the discipline (e.g.
# `//! - No \`#[no_mangle]\`...`) do not match — doc-comment lines
# begin with `//`, not with the attribute or extern-fn token.
PATTERN_FFI_EXPORT='^[[:space:]]*(#\[no_mangle\]|#\[unsafe\(no_mangle\)\]|#\[export_name|#\[unsafe\(export_name|extern[[:space:]]+"C"[[:space:]]+fn[[:space:]])'

failures=0

for pat_name in PATTERN_RUNTIME_STATE PATTERN_MODULE_STATIC PATTERN_FFI_EXPORT; do
    pat="${!pat_name}"
    HITS="$(grep -rEn "${pat}" "${CRATE_SRC}" || true)"
    if [[ -n "${HITS}" ]]; then
        echo "FATAL: ${pat_name} matched in ${CRATE_SRC}:" >&2
        echo "${HITS}" >&2
        failures=$((failures + 1))
    fi
done

if [[ ${failures} -ne 0 ]]; then
    exit 1
fi

echo "RandomX crate-invariant grep clean."
```

CI workflow integration site: `.github/workflows/build.yml`,
inserted as a sibling step to `enforce RandomX FPU rounding
primitive scope` (currently lines 75–76 in the same job that runs
`scripts/ci/check_randomx_fpu_rounding.sh`). The new step:

```yaml
- name: enforce RandomX crate-level isolation invariants
  run: scripts/ci/check_randomx_crate_invariants.sh
```

Failure mode: the script exits non-zero with the matched lines on
stderr; the `run:` step's failure surfaces as a CI gate failure
mirroring the FPU grep's UX. Verified empirically at HEAD by grep
on `rust/shekyl-pow-randomx/src/`: zero hits across all three
patterns (also confirmed by the existing `lib.rs` rustdoc claim
at lines 31–38 — the discipline is documented; R1-E1 makes it
mechanical).

**R1-E1 substrate finding (Round 1 close).** A first pass of pattern
C without the column-0 anchor matched the existing rustdoc in
`rust/shekyl-pow-randomx/src/lib.rs` lines 31–32, which legitimately
cites the forbidden tokens (`` `#[no_mangle]` ``, `` `extern "C" fn` ``,
`` `#[export_name]` ``) as part of the documented invariant. The
column-0 anchor (with optional leading whitespace for indented
attributes inside fn bodies) discriminates between code and rustdoc
citations: code attributes start at column 0 modulo indentation, and
rustdoc lines start with `//!` (not whitespace + the attribute
token). Patterns A and B were already `^`-anchored at column 0; the
inconsistency was specific to pattern C and is fixed in the pinned
regex above. The post-fix verification across
`rust/shekyl-pow-randomx/src/` is zero hits across all three
patterns.

**Reversion clause (per `21-reversion-clause-discipline.mdc`).**

- *Rejection.* All three patterns are rejected at V3.0. Substrate:
  Decision #5 (FFI ownership in `shekyl-ffi`, not in
  `shekyl-pow-randomx`) plus the "no module-level mutable state in
  the verifier crate" framing from `RANDOMX_V2_RUST.md` §7.2 +
  `RANDOMX_V2_PLAN.md` §7.7.
- *Reopening criteria.* The patterns reopen iff **any** of:
  1. **Pattern A (runtime-mutable lazy state).** Reopens if a Rust
     stdlib evolution introduces a successor primitive (e.g.,
     hypothetical `std::sync::Once2024Lock`) that the workspace
     wants to permit in this crate. Substrate-anchored event:
     stdlib stabilization landing in the workspace's pinned MSRV
     (rust-version 1.85 at HEAD; advance lands at the workspace
     `rust-version` bump). The reopening updates the pattern's
     enumeration.
  2. **Pattern B (module-level static).** Reopens if a future
     feature genuinely needs immutable shared state too large for
     `const` evaluation (e.g., a precomputed lookup table). At
     that point the design round evaluates whether the pattern
     relaxes to allow `static FOO: [T; N] = [...];` (immutable,
     no `mut`) while still rejecting `static mut`. Substrate-
     anchored event: a concrete table-construction request lands
     with size justification.
  3. **Pattern C (FFI export).** Does NOT reopen on its own.
     Reopens iff Decision #5 itself reverses (substrate-change-
     class), which would require its own design doc per the
     locked-now framing of Decision #5.
- *Re-evaluation shape.* A successor PR proposing relaxation of
  any pattern lands a design-doc round naming the substrate
  change driving the reopening. The round either updates the
  grep pattern (with permitted-exception list spelled out
  explicitly so the next reviewer can audit the relaxation) or
  rejects the proposal.

**Round 3 disposition (rustfmt-rely-chain note for Pattern B).**

The Round 1 disposition above stays as audit trail. Round 3 adds
one explicit note to Pattern B's robustness analysis: the
column-0 anchoring relies on `cargo fmt --check` enforcing
column-0 for module-level items. The chain is:

1. `cargo fmt` (or rustfmt) is enforced as a CI gate (per the
   workspace's existing `rust-fmt-check.mdc` rule).
2. rustfmt's default style places module-level items at column 0
   (no indentation).
3. Function-local items (including function-local `static`
   declarations, used for things like
   `static REGEX: OnceLock<...> = OnceLock::new();` inside
   `fn` bodies) are indented to at least column 4 (or whatever
   the function's body indentation is).
4. Therefore Pattern B's `^[[:space:]]*(...)?(unsafe[[:space:]]+)?static[[:space:]]+`
   anchored at column 0 (with optional leading whitespace for
   attribute-decorated items at column 0) matches module-level
   items but does not match function-local items.

The chain is robust as long as `cargo fmt --check` is enforced.
If a future PR weakens the formatting gate (e.g., disables it
in CI for a specific path), Pattern B's column-0 heuristic
weakens correspondingly. The reopening criterion: any change to
the formatting gate's coverage. The reversion-clause discipline
is explicit: the substrate that makes Pattern B robust is the
formatting gate; if the substrate shifts, the pattern shifts.

This is a **substrate-anchored documentation note**, not a
pattern change. Pattern B is unchanged from Round 1; the note
documents what the pattern relies on so future contributors
don't accidentally weaken the substrate without realizing it
loosens the invariant.

---

## 4. Threat-model addenda

The scaffold-as-of-Round-1 framed this section as a Round 4
placeholder enumerating three substrate-anchored items expected
to surface (cache-derivation DoS amplification; pool exhaustion;
Mutex contention). Round 3's adversarial pass against the
Round 2 architectural reframe surfaced the items earlier than
Round 4, against the Round-2-typed surface (Arc<PreparedCache>;
in-flight deduplication; per-slot RwLock). The Round-4-deferral
framing is **superseded** by Round 3's enumeration below; the
placeholder text is preserved as audit trail at the bottom of
this section.

Round 3 enumerates seven attack classes against the Round 2
surface, each with a disposition. The enumeration is a forward-
template surface: future contributors looking at "why this
shape?" find the adversarial findings inline, not in a separate
threat-modeling document.

### F1 — Cache-derivation DoS amplification (3-seedhash interleave)

**Attack.** An attacker submits alt-chain block headers with novel
seedhashes that interleave with the canonical seedhash, evicting
the canonical from the LRU and forcing ~150–200 ms of cache
re-derivation per attack block.

**Pre-Round-2 disposition.** F1 was the carry-forward forward-
action from Phase 2c §5.11.7 #1; Round 1's R1-D1 disposition
chose Option (b) (explicit two-slot type with sticky canonical)
to close it.

**Round 2 disposition.** Closed by §3.1 Round 2 Axis-2's
reaffirmed (b) on `Arc<PreparedCache>`: the canonical slot is
non-evictable; only the transient slot churns under the
interleave. Test coverage: T-CS-1 (Round 3-typed; see §6.1
Round 3 disposition) asserts canonical survives a 3-seedhash
interleave.

### F2 — Memory exhaustion via Arc-holding (Round 3 NEW)

**Attack.** A consumer holds an `Arc<PreparedCache>` clone past
the slot's eviction event (e.g., long-running RPC handler that
hasn't completed; async task that captured the Arc). The
underlying `Cache` (~256 MiB Argon2d-derived state) stays alive
as long as any clone references it, regardless of slot
occupancy. Repeated under attacker pressure (e.g., the attacker
induces repeated novel-seedhash lookups while a long-running
operation holds the canonical's Arc), the daemon's memory
footprint grows beyond the capacity-2 ceiling.

**Round 3 disposition.** Bounded structurally at the
`CacheStore` layer by the capacity-2 cap on `Arc<PreparedCache>`
references stored *in* slots; consumer-side discipline bounds
clones held *outside* slots. The CacheStore's bound covers the
expected case (lookup → use → drop the clone); long-held clones
are a consumer-side discipline concern. Documented in the
CacheStore rustdoc (§4 caller hand-off discipline note below)
so 3a's consumer code doesn't accidentally introduce the
failure mode the (g) analysis surfaced.

**Reversion clause.** Reopen if Phase 3a profiling reveals
sustained operational patterns where consumer-held clones
extend the cache lifetime beyond an actionable threshold (e.g.,
several minutes); the disposition could shift to a typed-handle
pattern (e.g., `CacheGuard<'a>` that drops on-scope-exit) at
the verifier-crate layer. Substrate-anchored event: profiling
evidence; not speculation.

### F3 — Thundering herd on novel-seedhash derivation (Round 3 NEW)

**Attack.** Two (or more) concurrent threads call
`lookup_or_derive(seedhash)` for the same novel seedhash. Without
deduplication, both threads run parallel Argon2d fills, doubling
the CPU cost and the memory footprint during derivation.

**Round 3 disposition.** Closed by the in-flight deduplication
shape pinned in §3.1 Round 2:
`Mutex<HashMap<Seedhash, Shared<DerivationFuture>>>`. The first
call inserts the future; subsequent calls clone the `Shared`
and await. Only one Argon2d fill runs.

**Test coverage.** T-CS-7 (concurrent-determinism property) +
T-CS-8 (thundering-herd assertion: two concurrent
`lookup_or_derive` calls receive the same `Arc<PreparedCache>`
clone via `Arc::ptr_eq`).

### F4 — Unbounded HashMap growth under sustained novel-seedhash attack (Round 3 NEW)

**Attack.** Without cleanup, the in-flight `HashMap` accumulates
entries: each derivation completes and leaves a `Shared` whose
future is resolved; the entry stays until the `HashMap` rehashes
or `CacheStore` is dropped. Sustained novel-seedhash attack
causes unbounded growth (memory exhaustion + lookup-time
amortization rises linearly with seedhashes-seen).

**Round 3 disposition.** Closed by **cleanup-on-publish**: the
in-flight-map entry is dropped immediately when the derivation
completes and the `Arc<PreparedCache>` is published to the
transient slot. The in-flight `HashMap` holds only currently-
derivating seedhashes; size is bounded by the concurrency
level, not by total derivations seen.

**Test coverage.** T-CS-9 (publish-clears-inflight: after
`lookup_or_derive(novel)` completes, the in-flight map is empty
for that seedhash; verified by white-box access to the private
`in_flight` field via `src/*.rs#mod tests` discipline).

### F5 — Concurrent-derivation race producing inconsistent caches (Round 3 NEW)

**Attack.** If `Cache::derive` is non-deterministic, two
concurrent calls for the same seedhash could produce different
`Cache` instances. Consumers receiving the bytes from one and
not the other would compute different hashes — a consensus-split
scenario.

**Round 3 disposition.** Closed by:
1. `Cache::derive` is deterministic by spec (Phase 2c R1
   spec-vector property test asserts byte-identical output
   for byte-identical input).
2. The in-flight deduplication makes "two concurrent calls" hit
   one derivation, so the race is structurally eliminated for
   the same-seedhash case.

The two layers are belt-and-suspenders: even if the in-flight
deduplication has a bug that lets two derivations through, the
underlying determinism property holds.

**Test coverage.** T-CS-10 (concurrent-determinism property
test): two `std::thread::spawn` workers call
`PreparedCache::derive(SAME_SEEDHASH)`; assert the resulting
`Cache::item_bytes(0)` (or any deterministic byte function) is
byte-identical regardless of in-flight-deduplication behavior.

### F6 — Mutex contention amplification (Round 3 NEW)

**Attack.** A `Mutex` over the slot pair serializes all
`CacheStore` lookups across the daemon. At Phase 3a fanout
(N concurrent validators), the `Mutex` contention amortizes
each lookup with serialization cost, defeating concurrency.

**Round 3 disposition.** Closed by the synchronization shape
pinned in §3.1 Round 2: per-slot `RwLock` (canonical reads
don't block transient writes and vice versa); `Mutex<HashMap>`
for in-flight only (short critical section). At capacity-2,
sharding is overkill; the per-slot `RwLock` is sufficient.

**Reversion clause.** Reopen if Phase 3a profiling shows
contention as the bottleneck; the disposition could shift to
sharding or to a lock-free structure. Substrate-anchored event:
profiling evidence; not speculation.

### F7 — Cache-derivation cost asymmetry (out of scope)

**Attack.** The verifier crate's `Cache::derive` is ~150–200 ms;
verifying a hash with a wrong cache (deliberately submitted by
an attacker) takes one `compute_hash` call (~10 µs) + the
derivation cost the validator paid to look up the cache. If
the attacker's submission rate exceeds the validator's
derivation throughput, the validator falls behind.

**Round 3 disposition.** Out of scope for Phase 2F. The attack
is mitigated upstream of the verifier:
1. The daemon-side validation discipline (alt-chain header
   filtering by difficulty target before expensive PoW
   recompute) bounds the rate at which novel-seedhash
   derivations are demanded.
2. The pool path (R1-D3 Round 3, conditional) amortizes
   `compute_hash` call cost; orthogonal to derivation cost.

The asymmetry is a consensus-design concern (Phase 0 latency
budget; difficulty algorithm tuning), not a verifier-crate
concern. Phase 3a/3b consume the verifier's compute_hash and
apply the daemon-side throttling discipline. Documented here
as the seventh attack class so future contributors don't
attempt to defend it inside the verifier crate.

### Caller hand-off Arc-lifetime discipline note (Round 3)

The Round 3 F2 disposition relies on consumer-side discipline:
holding `Arc<PreparedCache>` clones across long-running
boundaries (RPC handlers, async tasks, background workers)
extends the cache's memory residency beyond `CacheStore`'s
capacity-2 bound.

The CacheStore rustdoc explicitly documents this property:

> Consumers should hold `Arc<PreparedCache>` clones only for
> the duration of the immediate hash computation; long-lived
> holds extend cache memory residency beyond `CacheStore`'s
> bound. Pattern: `lookup` (or `lookup_or_derive`), use, drop.
> If a consumer needs to bridge an async boundary, the
> recommended pattern is to drop the Arc before yielding and
> re-look-up after the await; this is structurally safer than
> capturing the Arc in a future.

This is daemon-side discipline (consumer of the verifier crate
applies it), not a CacheStore enforcement. Phase 3a's FFI shim
audits its own call sites for the pattern.

### Round 4 placeholder (preserved as audit trail)

> *(Round 1 framing: "Round 4 reviews Phase 2f's design against
> Shekyl's `00-mission.mdc` priority hierarchy. Substrate-anchored
> items expected to surface, based on prior phases' Round 4
> patterns: cache-derivation DoS amplification; pool exhaustion;
> Mutex contention.")*
>
> Round 3 absorbed the threat-model enumeration earlier than
> the Round 1 framing anticipated, against the Round 2 surface.
> The three substrate-anchored items the Round 1 framing named
> are covered by F1 (cache-derivation DoS), F6 (Mutex
> contention), and (conditional on R1-D3 Round 3 pool-path)
> the pool-exhaustion attack (which would surface as a future
> F8 if the pool path triggers; the Phase 2F impl-PR's pre-
> flight evaluates whether to enumerate it inline at impl
> time). Round 4 may still identify additional items if the
> impl-PR or the Phase 2g differential harness surfaces
> findings; the §4 enumeration is forward-extensible.

**Threat-model close (post-closure pin refinement).** F1–F7 is
the threat-model close for Phase 2F. The §4 "Round 4
placeholder" above is preserved per
`91-documentation-after-plans.mdc` audit-trail discipline so the
Round 1 framing remains visible to readers tracing the
discipline's evolution; **it is not a queued deliverable**.
There is no Round 4 hanging on this plan-doc. Future findings
(impl-PR pre-flight; Phase 2g differential-harness surface) reopen
the threat model via the substrate-change reopening criteria
(per the discipline pattern at §3.1's three-axis reversion
clauses) — they do not advance to a "Round 4" because Round 3
absorbed the threat-model work. The forward-extensibility note
above stands; the trigger for extension is substrate-anchored
finding, not sequential numbering.

---

## 5. Implementation hand-off contract

Round 1 close lands this section. Mirrors Phase 2c §5.1.1 / Phase 2d
§5 — the contract names what 2f's implementation PR can change vs.
what is frozen.

### 5.1 Frozen-by-this-doc-at-Round-1-and-Round-2

The implementation PR (`feat/randomx-v2-phase2f-impl`) inherits the
following as immutable. Changes to any of these require a new
Phase 2f round on this doc, not a code-side amendment.

The Round 1 freeze items below are preserved as audit trail per
`91-documentation-after-plans.mdc`; Round 2's amendments
(supersede-marked inline) replace the Round 1 items where the
substrate correction applies.

- **`compute_hash` signature.** Round 1 freeze:
  `pub fn compute_hash(&Cache, &[u8; 32], &[u8]) -> [u8; 32]`.
  **Round 2 supersedes (per §1.1 amendment):**
  `pub fn compute_hash(&PreparedCache, &[u8]) -> [u8; 32]`. The
  cache-seedhash binding is carried by the `PreparedCache`
  bundle; the seedhash is no longer a separate parameter.
  R1-D4's pool path, if triggered, internalizes inside the
  function body without altering the (Round-2-amended)
  signature.
- **`Seedhash` newtype.** Round 2-new freeze (no Round 1
  predecessor): `#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)] pub struct Seedhash(/* private [u8; 32] */)`
  with `pub fn Seedhash::from_bytes([u8; 32]) -> Seedhash` and
  `pub fn Seedhash::as_bytes(&self) -> &[u8; 32]`. `Display` impl
  for hex-formatting consistency with Phase 2c. Newtype
  representation is private (accessor-mediated, not field-
  mediated) to allow pre-genesis representation changes.
- **`PreparedCache`.** Round 2-new freeze (no Round 1
  predecessor): `pub struct PreparedCache` with
  `pub fn PreparedCache::derive(Seedhash) -> PreparedCache` and
  `pub fn PreparedCache::seedhash(&self) -> &Seedhash`. The
  bundle is the only public path to `compute_hash`-suitable
  inputs.
- **`Cache` public API.** Round 1 freeze:
  `pub struct Cache` with `pub fn Cache::derive(&Seedhash) -> Cache`
  plus `pub(crate)` accessors. **Round 2 supersedes (per §1.1
  amendment):** `pub(crate) struct Cache` with
  `pub(crate) fn Cache::derive(&Seedhash) -> Cache`. The
  `pub(crate)` transition closes the failure mode the
  `PreparedCache` bundling exists to prevent (consumers
  constructing `Cache` without the seedhash binding). The
  `Cache` rustdoc carries a pointer to `PreparedCache` as the
  public construction path. Test access is preserved via
  `src/*.rs#mod tests` discipline (Phase 2c R0-D6).
- **`VmState` visibility** per §1.1: `pub(crate)` in `src/vm.rs`.
  Unchanged. R1-D3 option (b) (Component method) was selected
  specifically to avoid promoting this to `pub`.
- **`CacheStore` public API.** Round 1 freeze:
  `new()`, `lookup(&[u8; 32]) -> Option<Arc<Cache>>`,
  `insert(&[u8; 32], Arc<Cache>)`, `set_canonical(&[u8; 32])`,
  internal `std::sync::Mutex` only. **Round 2 supersedes (per
  §3.1 Round 2 disposition):**
  `new()`,
  `lookup(&Seedhash) -> Option<Arc<PreparedCache>>`,
  `lookup_or_derive(&Seedhash) -> Arc<PreparedCache>`,
  `set_canonical(Arc<PreparedCache>)`. The Round 1 `insert`
  method is removed; its function is subsumed by
  `lookup_or_derive`'s on-completion publication. Internal
  synchronization is per-slot
  `RwLock<Option<Arc<PreparedCache>>>` (canonical + transient)
  plus `Mutex<HashMap<Seedhash, Shared<DerivationFuture>>>`
  for in-flight deduplication; cleanup-on-publish drops the
  in-flight entry on derivation completion.
- **CacheStore eviction policy.** Round 1 freeze: §3.2 Round 1
  table. **Round 2 supersedes:** §3.1 Round 2 11-row
  state-transition table (typed against `Arc<PreparedCache>`;
  `insert→lookup_or_derive` substitution; in-flight-dedup
  concurrent row added). Substantive transitions unchanged
  (canonical non-evictable; transient displace-on-publish;
  advance promotes-from-transient + demotes-prior; cold-start
  window before first `set_canonical` is bounded by FFI shim's
  lock-ordering discipline per Decision #5).
- **Bench methodology** per R1-D3 option (b). Component method
  measuring scratchpad zero-init + register-file zero-init in
  isolation, summed median = floor on per-call alloc cost.
  No `compute_hash_with_state` helper added (would require
  promoting `VmState` to `pub`). (Round 3 may refine the
  bench harness shape; see §3.3 Round 3 disposition once
  Round 3 commits.)
- **Pool decision rule** per R1-D4 three-band table (< 50 µs
  → no pool; [50, 100) µs → impl-PR pre-flight escalation;
  ≥ 100 µs → pool inside `compute_hash`).
- **Pool capacity sizing methodology** (conditional on R1-D4
  triggering pool path) per R1-D5: `min(threadpool::getInstanceForCompute().get_max_concurrency(),
  m_max_prepare_blocks_threads) + 1` derived at impl-PR time
  reading the post-Round-N-close `dev` tip's threadpool source.
  Substrate-corrected: no separate mempool fanout source exists
  at HEAD = `fb21909ff`.
- **Grep pattern set** per R1-E1's three-pattern enumeration
  (Pattern A runtime-mutable-state imports; Pattern B module-
  level statics; Pattern C FFI exports). Pinned regex bodies in
  §3.6 Round 1 disposition.
- **Seedhash newtype sweep is atomic with its introduction.**
  The Round 2 §1.1 substrate correction adds the `Seedhash`
  newtype; every site that currently passes `&[u8; 32]` for a
  seedhash (Cache::derive, PreparedCache::derive, CacheStore::*,
  the FFI shim's seedhash constructor, every test that
  constructs a literal seedhash) updates to `&Seedhash` /
  `Seedhash` in the **same commit** as the newtype's landing.
  Not as a follow-up. Otherwise the codebase has a
  transitional period where some sites use `&[u8; 32]` and
  some use `&Seedhash`, which is exactly the drift the
  newtype prevents.

### 5.2 In-scope for the implementation PR

The Round 1 in-scope table below is preserved as audit trail per
`91-documentation-after-plans.mdc`. Round 2's amendments
(supersede-marked inline) replace the Round 1 entries where the
substrate correction applies; new Round-2 artifacts are appended
as items 12–15. The table reflects the Round 2 shape post-
amendment.

| # | Artifact | Lines (estimate) | Path |
|---|---|---|---|
| 1 | `CacheStore` struct + impl block. **Round 2 supersedes** Round 1's frozen-API spec: lookup/lookup_or_derive/set_canonical signatures take `&Seedhash` / `Arc<PreparedCache>`; per-slot `RwLock` + `Mutex<HashMap>` for in-flight dedup; cleanup-on-publish. | ~250–350 | `rust/shekyl-pow-randomx/src/cache_store.rs` (new) |
| 2 | Re-export from `lib.rs`. **Round 2 amends:** `pub use cache_store::CacheStore; pub use prepared::{PreparedCache, Seedhash};` | ~3 | `rust/shekyl-pow-randomx/src/lib.rs` |
| 3 | Crate-invariant grep script per R1-E1 | ~50 | `scripts/ci/check_randomx_crate_invariants.sh` (new) |
| 4 | CI workflow step per R1-E1 | ~2 | `.github/workflows/build.yml` (sibling to FPU step) |
| 5 | Component bench per R1-D3 option (b) | ~60–100 | `rust/shekyl-pow-randomx/benches/per_call_alloc.rs` (new) or extension to existing `compute_hash_alloc.rs` |
| 6 | `BENCH_RESULTS.md` update with component-floor median + R1-D4 disposition | ~30 | `rust/shekyl-pow-randomx/BENCH_RESULTS.md` |
| 7 | (Conditional per R1-D4) `VmState` pool body inside `compute_hash` | ~50–150 | `rust/shekyl-pow-randomx/src/vm.rs` (function-body amendment) |
| 8 | (Conditional per R1-D4) `pub(crate) const POOL_CAPACITY: usize` per R1-D5 derivation | ~5 | `rust/shekyl-pow-randomx/src/vm.rs` |
| 9 | CacheStore unit tests per §6.1. **Round 2 supersedes** Round 1's test matrix to match Round-2-typed pre/post table; in-flight-dedup test added. | ~250–350 | `rust/shekyl-pow-randomx/src/cache_store.rs#mod tests` |
| 10 | Crate-invariant smoke test (script-runner from `cargo test`) per §6.2 | ~30 | `rust/shekyl-pow-randomx/tests/crate_invariants.rs` (new) |
| 11 | CHANGELOG + Round-history close | ~50 | `docs/CHANGELOG.md`, this plan-doc §11 |
| 12 | **Round 2 new:** `Seedhash` newtype + impls (Copy/Clone/Debug/Eq/Hash/PartialEq derives + Display + from_bytes/as_bytes accessors) | ~50–80 | `rust/shekyl-pow-randomx/src/prepared.rs` (new) or `src/seedhash.rs` |
| 13 | **Round 2 new:** `PreparedCache` struct + `derive` + `seedhash` accessor | ~30–50 | `rust/shekyl-pow-randomx/src/prepared.rs` |
| 14 | **Round 2 amends:** `Cache` visibility transition `pub → pub(crate)`; `Cache::derive` signature `&[u8; 32] → &Seedhash`; rustdoc pointer to `PreparedCache` | ~10–20 | `rust/shekyl-pow-randomx/src/lib.rs` + `src/cache/mod.rs` (or wherever `Cache` lives) |
| 15 | **Round 2 amends:** `compute_hash` signature `(&Cache, &[u8; 32], &[u8]) → (&PreparedCache, &[u8])`; body reads `prepared.seedhash().as_bytes()` where the prior shape took the seedhash directly. | ~5–15 | `rust/shekyl-pow-randomx/src/vm.rs` |
| 16 | **Round 2 new:** Atomic Seedhash-newtype sweep across all `&[u8; 32]`-as-seedhash sites in the crate (test seedhash literals, internal callers). Also crosses the `shekyl-ffi` boundary in the FFI-shim's seedhash constructor — but the FFI shim itself is **out of scope for Phase 2F** (Decision #5; `shekyl-ffi` lives outside this crate). The Phase 2F impl-PR ships the `Seedhash::from_bytes` constructor; the FFI shim's call-site update is Phase 3a's responsibility. The sweep within `rust/shekyl-pow-randomx/` is mechanical and atomic with item #12's landing per §5.1. | ~30–50 | (cross-cutting; see paths below) |

Total ~800 lines net-new (was Round 1's ~600; the Round 2
PreparedCache + Seedhash + sweep + larger CacheStore + larger test
matrix add ~200 net lines). The R1-D4 pool path adds ~50–150
lines if triggered.

### 5.3 Out-of-scope for the implementation PR (re-emphasized)

- Differential test harness against C reference (Phase 2g).
- Per-PR per-hash latency CI gate (Phase 3a).
- Binary-level `nm`-on-`shekyld` symbol-isolation check
  (Phase 3c, FOLLOWUPS V3.1+ entry line 3633ff).
- Parallel `Cache::derive` / SuperscalarHash thread-pool
  (separate FOLLOWUPS item if benchmarks justify).
- `compute_hash_with_state` `pub` helper (rejected at R1-D3 in
  favor of option (b); reopens only via R1-D3 reversion clause #1
  within the impl-PR's own pre-flight if the floor lands in the
  ambiguity band).
- **Round 2 new:** FFI shim updates in `shekyl-ffi` (the crate
  outside this Phase 2F's scope per Decision #5). Phase 2F ships
  the `Seedhash::from_bytes` constructor; Phase 3a's FFI shim PR
  calls it. The cross-crate boundary is honored per `06-branching.mdc`
  scope discipline.
- **Round 2 new:** Parent-plan `RANDOMX_V2_PLAN.md` Decision #6
  wording amendment (the "transparent memo with capacity-2 LRU
  and `pin()` API" framing). Out of scope for the Phase 2F
  impl-PR; lands as a small precursor PR
  `chore/randomx-v2-plan-decision6-amendment` per §10. Bounded
  scope; one-file change.

---

## 6. Test plan

### 6.1 CacheStore unit tests

The Round 1 test matrix below is preserved as audit trail per
`91-documentation-after-plans.mdc`. Round 3's matrix
(supersede-marked inline) reshapes the tests against the Round
2-typed surface (`Arc<PreparedCache>`; `lookup_or_derive` instead
of `insert`; `&Seedhash` instead of `&[u8; 32]`); adds tests for
the Round 2 in-flight deduplication shape and the Round 3 F2/F3/
F4/F5 threat-model dispositions.

Pinned per R1-D1 Round 2 + R1-D2 Round 2 (eviction-policy table
in §3.1 Round 2 disposition; the §3.2 Round 1 table is preserved
as audit trail). Each test corresponds to one or more rows of
the §3.1 Round 2 11-row pre/post table; the test's
`assert!(store.lookup(&X).is_some())` and
`assert!(store.lookup(&Y).is_none())` checks reproduce the row's
post-state. Live in
`rust/shekyl-pow-randomx/src/cache_store.rs#mod tests` (unit
tests, per the Phase 2c R0-D6 tests-use-the-actual-API
discipline — `cache_store.rs#mod tests` has `pub(crate)` access
to internal slot fields and the in-flight `HashMap` for
diagnostic assertions, not just public-API access).

Test fixture: a stub `PreparedCache` (the test does not derive a
real 256 MiB cache; tests construct
`PreparedCache::derive(SEEDHASH)` only when end-to-end identity
is needed; for most slot-behavior tests, the test fixture
constructs `Arc<PreparedCache>` instances with stub `Cache`
content via the `pub(crate)` `Cache::from_raw` test-time
constructor — Phase 2c R1 — paired with a `Seedhash` literal).

| # | Test name | §3.1 Round 2 row(s) | Assertion |
|---|---|---|---|
| T-CS-1 | `cachestore_canonical_survives_3way_interleave` | rows 5–6, then extension to D | `let pa = la(A); set_canonical(pa); la(B); la(C); la(D);` assert `lookup(&A).is_some()` AND `lookup(&D).is_some()` AND `lookup(&B).is_none()` AND `lookup(&C).is_none()`. **F1 anti-DoS test.** |
| T-CS-2 | `cachestore_no_canonical_evicts_in_transient` | rows 2–3 (cold-start) | `la(A); la(B);` (no `set_canonical` called), assert `lookup(&A).is_none()` AND `lookup(&B).is_some()`. **R1-D2 #2 degenerate-case test.** |
| T-CS-3 | `cachestore_canonical_advance_demotes_prior` | row 7 | `let pa = la(A); set_canonical(pa); let pb = la(B); set_canonical(pb);` assert `lookup(&A).is_some()` (A demoted to transient) AND `lookup(&B).is_some()` (B canonical). Then `la(C);` and assert `lookup(&A).is_none()` AND `lookup(&B).is_some()` AND `lookup(&C).is_some()`. **R1-D2 #3 advance test.** |
| T-CS-4 | `cachestore_set_canonical_noop_on_canonical_match` | row 8 | `let pa = la(A); set_canonical(pa.clone()); la(B); set_canonical(pa);` (re-advance to A); assert `lookup(&A).is_some()` AND `lookup(&B).is_some()`. **No-op identity test.** |
| T-CS-5 | `cachestore_lookup_returns_arc_clone` | (generic invariant) | `let pa = la(A);` `Arc::strong_count(&pa) == 2` (one in transient slot, one held by caller); `lookup(&A);` `strong_count == 3`; clones drop back when each lookup result goes out of scope. |
| T-CS-6 | `cachestore_thread_safety_smoke` | (generic invariant) | Two `std::thread::spawn` workers each performing 100 alternating `lookup` / `lookup_or_derive` / `set_canonical` calls against a shared `Arc<CacheStore>`. Test passes if no panic, no deadlock, and the canonical slot survives the interleave. (Full thread-safety stress is 2g's differential harness territory; this is a smoke test.) |
| T-CS-7 | `cachestore_thundering_herd_dedup` | row 11 | Two `std::thread::spawn` workers each call `cs.lookup_or_derive(&NOVEL)` for the same novel seedhash. Assert `Arc::ptr_eq(&result_thread1, &result_thread2)` (both received the same Arc clone). **F3 thundering-herd test.** |
| T-CS-8 | `cachestore_inflight_cleanup_on_publish` | row 11 | After `cs.lookup_or_derive(&A)` completes, white-box assert `cs.in_flight.lock().unwrap().is_empty()` for seedhash A. **F4 cleanup-on-publish test.** Uses `pub(crate)` access to the private `in_flight` field. |
| T-CS-9 | `cachestore_concurrent_derivation_determinism` | (generic property) | Two `std::thread::spawn` workers each construct `PreparedCache::derive(SAME_SEEDHASH)` *outside* the CacheStore (so the in-flight dedup doesn't apply). Assert `result_thread1.cache.item_bytes(0) == result_thread2.cache.item_bytes(0)` for byte-identical output. **F5 concurrent-derivation race test.** Asserts `Cache::derive` determinism independent of in-flight-dedup. |
| T-CS-10 | `cachestore_set_canonical_takes_arc_prepared` | rows 4, 7 | Type-level check — `set_canonical` accepts `Arc<PreparedCache>`, not a seedhash + cache pair. (Compile-time check via the test's `let pa: Arc<PreparedCache> = ...; cs.set_canonical(pa);` pattern.) |
| T-CS-11 | `cachestore_lookup_returns_typed_seedhash` | (Round 2 type-shape) | Type-level check — `lookup` takes `&Seedhash`, not `&[u8; 32]`. The test exercises `cs.lookup(&Seedhash::from_bytes([0x42; 32]))` to confirm the newtype is accepted at the call site. |

### 6.2 Crate-invariant grep tests

Two layers:

- **CI-step layer (R1-E1):** `scripts/ci/check_randomx_crate_invariants.sh`
  runs as a `build.yml` step sibling to the FPU step. CI fails on
  any pattern A/B/C hit.
- **Cargo-test layer:** A `tests/crate_invariants.rs` integration
  test invokes the script via `std::process::Command`, asserts
  exit status zero. Lets `cargo test -p shekyl-pow-randomx` run
  the same gate locally without depending on CI infrastructure.

| # | Test / step | Assertion |
|---|---|---|
| T-CI-1 | `randomx_crate_has_no_runtime_mutable_state` (cargo-test) | Script's pattern A returns zero hits across `rust/shekyl-pow-randomx/src/`. |
| T-CI-2 | `randomx_crate_has_no_module_level_static` (cargo-test) | Script's pattern B returns zero hits. |
| T-CI-3 | `randomx_crate_has_no_ffi_exports` (cargo-test) | Script's pattern C returns zero hits. |
| T-CI-4 | CI step: `enforce RandomX crate-level isolation invariants` | Same script, run as a top-level CI gate. Mirror UX of FPU step. |

The cargo-test layer also functions as a *positive* check: the
test's source intentionally introduces (commented-out) examples of
each pattern as docstring examples, ensuring the test would fail
if the script's logic regressed.

### 6.3 Bench harness

The Round 1 bench-harness table below is preserved as audit
trail. Round 3's table (supersede-marked inline) reshapes the
harness for the cfg-gated A/B approach pinned at §3.3 Round 3:
the pool body is implemented behind
`#[cfg(any(test, feature = "internal-pool-bench"))]` and the
bench harness measures both paths directly.

Round 1 framing:

| # | Bench | Source | Assertion |
|---|---|---|---|
| B-1 | `compute_hash_alloc::per_call` (existing) | `benches/compute_hash_alloc.rs` | Phase 2d baseline 303.60 ms median (informational, ±10% threshold per §9). |
| B-2 | `vmstate_alloc_scratchpad_zeroed` (NEW per R1-D3) | `benches/per_call_alloc.rs` (new) or extension of existing | Component 1 of R1-D3 floor: `Box::<[u8]>::new_zeroed_slice(2 * 1024 * 1024)` (or equivalent) median. |
| B-3 | `vmstate_alloc_register_file` (NEW per R1-D3) | Same | Component 2 of R1-D3 floor: register-file synth init median. |
| B-4 | (Conditional per R1-D4 pool path) `compute_hash_with_pool::per_call` | `benches/compute_hash_alloc.rs` extension | Pool-path median; delta vs. B-1 reported in `BENCH_RESULTS.md`. |

**Round 3 supersedes (cfg-gated A/B harness):**

| # | Bench | Source | Mode |
|---|---|---|---|
| B-1 | `compute_hash_alloc::per_call` (existing) | `benches/compute_hash_alloc.rs` | Phase 2d baseline (full-pipeline). Informational. |
| B-2 | `vmstate_alloc_scratchpad_zeroed` | `benches/per_call_alloc.rs` (new) | Component method (Round 1 sanity floor; Round 3 retains as cross-check). |
| B-3 | `vmstate_alloc_register_file` | Same | Component method (Round 1 sanity floor; Round 3 retains as cross-check). |
| B-pool-off | `compute_hash_with_no_pool::per_call` | `benches/compute_hash_alloc.rs` extension | A/B path: production no-pool path, instrumented for direct measurement. Always runs. |
| B-pool-on | `compute_hash_with_pool::per_call` | Same, gated by `--features internal-pool-bench` | A/B path: cfg-gated pool path. Runs only when the feature is enabled (CI / impl-PR pre-flight bench gate). |

`BENCH_RESULTS.md` records (Round 3 supersedes):

- Component-floor sum (B-2 + B-3 medians; sanity check against
  B-pool-off — B-pool-off should not exceed component-floor by
  more than the dispatch loop's known cost).
- B-pool-off median (production no-pool path).
- B-pool-on median (cfg-gated pool path; conditional on the
  bench being run with `--features internal-pool-bench`).
- A/B delta (B-pool-off − B-pool-on; this is the savings the
  pool would deliver if promoted).
- R1-D4 Round 3 disposition applied (Branch A / Branch B /
  Branch C) with the delta-vs-100-µs comparison.
- (If Branch C / pool-promoted) the Phase 3a-derived pool
  capacity per R1-D5 Round 3 (runtime parameter), recorded as
  the impl-PR's stub-default-for-tests value with a forward
  pointer to the Phase 3a FFI shim's actual derivation.

---

## 7. Generator / fixtures plan

**None.** 2f is pure utility + benchmark; no consensus-affecting
surface; no fork-pin advance. The `tests/vectors/reference/`
directory is untouched. `_generator/phase2c/` and
`_generator/phase2d/` remain as-is.

---

## 8. Commit table

The Round 1 commit breakdown below is preserved as audit trail.
Round 3's table (supersede-marked inline) reshapes the breakdown
for the Round 2 type sweep + Round 3 cfg-gated A/B bench harness.
The Round 3 base breakdown is 6 commits.

Round 1 framing:

- **Branch A** (component floor < 50 µs): commit 4 is *omitted*;
  the impl PR closes at 4 commits + R1-D4-no-pool reversion-clause
  documentation in commit 5 (cited in the CHANGELOG entry).
- **Branch B** ([50, 100) µs ambiguity band): commit 4 is *deferred
  to a follow-up PR* per R1-D3's reversion-clause #1; impl PR closes
  at 4 commits with R1-D3 reopened on the branch's own pre-flight.
- **Branch C** (≥ 100 µs): commit 4 is *included* with the
  R1-D5-derived pool capacity; impl PR closes at 5 commits.

The branch is decided at impl-PR time by the bench result from
commit 3 (per R1-D3). Each branch commits land in the same PR; the
PR description names the branch taken and cites the R1-D4
disposition.

| # | Subject (imperative, ≤72 chars) | Scope | Conditional? |
|---|----------------------------------|-------|--------------|
| 1 | `randomx: add CacheStore two-slot type per Phase 2f §3.1` | New `src/cache_store.rs` (~120–200 lines) per R1-D1 frozen API + R1-D2 eviction policy table. Re-export from `lib.rs`. Unit tests T-CS-1..7 per §6.1. | Always |
| 2 | `randomx: add crate-invariant grep gate per Phase 2f §3.6` | New `scripts/ci/check_randomx_crate_invariants.sh` (~50 lines) per R1-E1 patterns A/B/C. New `.github/workflows/build.yml` step (~2 lines) sibling to FPU step. Cargo-test wrapper `tests/crate_invariants.rs`. | Always |
| 3 | `randomx: bench per-call VmState alloc components per Phase 2f §3.3` | Bench harness B-2 + B-3 per R1-D3 option (b). `BENCH_RESULTS.md` update with component-floor median + R1-D4 disposition. | Always |
| 4 | `randomx: internalize VmState pool inside compute_hash` | (Branch C only) Pool body in `vm.rs` (~50–150 lines); `pub(crate) const POOL_CAPACITY` per R1-D5 derivation against `dev`-tip threadpool source. Bench B-4. | Only on Branch C; omitted on Branch A; deferred on Branch B |
| 5 | `randomx: close Phase 2f plan and update CHANGELOG` | `docs/CHANGELOG.md` entry (per rule 91); `RANDOMX_V2_PHASE2F_PLAN.md` §11 Round-N close row + impl-PR delta. Cite branch taken (A/B/C) and any reversion-clause activations. | Always |

Per rule 90 (commit scope): each commit is bounded-scope. Pool
internalization (commit 4) does not bundle into the bench commit
(commit 3) even though the bench result drives the pool decision —
keeping them separate means the bench result is reviewable
independently of the pool implementation.

**Round 3 supersedes (6-commit shape with Round 2 type sweep + cfg-gated A/B bench):**

The Round 3 disposition makes the pool body always-implemented
(behind `#[cfg(any(test, feature = "internal-pool-bench"))]` per
§3.3 Round 3) and the cfg-gating-flip becomes the conditional
commit instead. Round 2's `Seedhash` newtype + `PreparedCache`
bundling adds a dedicated type-introduction commit (rule 90: scope
per commit; the type sweep is logically separate from the
`CacheStore` body). The §3.4 Round 3 branches (A/B/C) collapse
to "is the pool's cfg-gating flipped to default-on" rather than
"does the pool exist."

| # | Subject (imperative, ≤72 chars) | Scope | Conditional? |
|---|----------------------------------|-------|--------------|
| 1 | `randomx: introduce Seedhash newtype + PreparedCache bundle` | New `src/seedhash.rs` (`pub struct Seedhash([u8; 32])` per §1.1 Round 2, with `from_bytes` / `as_bytes`). New `PreparedCache` in `src/lib.rs` or `src/prepared_cache.rs` bundling `Cache` + `Seedhash`. `Cache` visibility transitions from `pub` to `pub(crate)` with rustdoc cross-reference per §1.1 Round 2. `compute_hash` signature transitions from `(&Cache, &[u8; 32], &[u8])` to `(&PreparedCache, &[u8])`. Atomic codebase sweep updating every call site (per §3.1 Round 2 sweep-discipline) — Phase 2c/2d tests, FFI shim's internal `Seedhash::from_bytes(*ptr)` construction, every `&[u8; 32]` seedhash parameter. | Always |
| 2 | `randomx: add CacheStore two-slot type per Phase 2f §3.1 Round 2` | New `src/cache_store.rs` (~200–300 lines) per R1-D1 Round 2 frozen API: `lookup`, `lookup_or_derive`, `set_canonical`. Internal `RwLock<Option<Arc<PreparedCache>>>` slots + `Mutex<HashMap<Seedhash, Shared<DerivationFuture>>>` in-flight map per §3.1 Round 2 sync-shape. Cleanup-on-publish per §3.1 Round 2. Re-export from `lib.rs`. Unit tests T-CS-1..11 per §6.1 Round 3. | Always |
| 3 | `randomx: add crate-invariant grep gate per Phase 2f §3.6` | New `scripts/ci/check_randomx_crate_invariants.sh` (~50 lines) per R1-E1 patterns A/B/C with rustfmt-rely-chain note (§3.6 Round 3). New `.github/workflows/build.yml` step (~2 lines) sibling to FPU step. Cargo-test wrapper `tests/crate_invariants.rs`. | Always |
| 4 | `randomx: implement cfg-gated VmState pool + per-call alloc bench` | Pool body in `src/vm_pool.rs` (~50–150 lines) gated by `#[cfg(any(test, feature = "internal-pool-bench"))]` per §3.3 Round 3. `VmStatePool::new(capacity: usize)` per R1-D5 Round 3 (runtime parameter; panic on default in non-test builds). Component benches B-2 + B-3 + B-pool-off + B-pool-on per §6.3 Round 3. `BENCH_RESULTS.md` update with A/B delta + §3.4 Round 3 branch disposition. | Always (the pool exists in source either way; B-pool-on only runs when `--features internal-pool-bench` is passed) |
| 5 | `randomx: flip pool cfg-gate to default-on per Phase 2f §3.4 Round 3` | (Branch C only) Cfg-gate flip: `#[cfg(any(test, feature = "internal-pool-bench"))]` → unconditional. `compute_hash` rewires through the pool. Phase 3a's FFI shim sees the new `compute_hash` body. | Only on Branch C; omitted on Branch A (B-pool-off ≥ B-pool-on − pool overhead by < 100 µs delta); deferred on Branch B (50–100 µs ambiguity-band escalation per §3.4 Round 3) |
| 6 | `randomx: close Phase 2f plan and update CHANGELOG` | `docs/CHANGELOG.md` entry (per rule 91); `RANDOMX_V2_PHASE2F_PLAN.md` §11 impl-PR-close row + impl-PR delta. Cite branch taken (A/B/C) and any reversion-clause activations. | Always |

Per rule 90 (commit scope): each commit is bounded-scope. The
Round 2 type sweep (commit 1) is logically separate from the
CacheStore body (commit 2) — keeping them separate means the
type-shape change is reviewable independently of the new
type's main consumer. The pool implementation (commit 4) does
not bundle into the cfg-gate flip (commit 5) — keeping them
separate means the cfg-gated pool body is reviewable
independently of the production-rewire.

**Commit 5 is empirically conditional (post-closure pin).**
The §3.4 Round 3 Branch A / Branch B / Branch C trichotomy is
decided by the §6.3 Round 3 A/B bench delta (`B-pool-off` −
`B-pool-on`) measured at commit 4. The empirical answer does
not exist at plan-doc-close time; commit 4 produces it, and
commit 5 is included or omitted per the result.

**Prediction-vs-measured discipline (post-closure pin
refinement).** The impl-PR's description **must include both**:

1. The **predicted branch** named in this plan-doc (Branch A
   or Branch C; Branch B if the prediction is the ambiguity
   band). Cite §8 as the source of the prediction.
2. The **measured branch** named by commit 4's bench output.
   Cite the `BENCH_RESULTS.md` entry as the source of the
   measurement.
3. An explicit reconciliation: either **"prediction held"**
   (predicted branch == measured branch) or **"prediction
   wrong because <specific substrate-anchored reason>"**
   (e.g., "prediction was Branch C per PR-66's per-call
   alloc cost; measurement was Branch A because modern
   allocators on this CI runner amortize the 2 MiB
   `Box::<[u8]>::new_zeroed_slice` to ~30 µs and PR-66's
   bulk cost was dispatch-loop overhead, not alloc-specific
   cost").

The discipline mirrors the mp-correction discipline (Phase 2c
PR-65: a Phase 2c-substrate finding that ran counter to the
plan-doc framing was surfaced explicitly in the commit message
rather than silently absorbed). The same shape applies here:
the bench result that diverges from the prediction is a
substrate finding, and surfacing it in the impl-PR description
ensures reviewers can spot the divergence rather than letting
it slip past as an undocumented surprise.

A reviewer reading the impl-PR description should be able to
answer "which branch did this PR take, why was that branch
predicted or surprising, and what does the divergence (if any)
say about the model behind the prediction?" — without spelunking
the `BENCH_RESULTS.md` delta or the commit-4 bench harness
output.

**Predicted-most-likely branch (post-closure pin; impl-PR
records actual).** Two competing signals at plan-doc-close
time:

- **Branch C (≥ 100 µs delta) plausible.** Phase 2c PR-66's
  per-call alloc cost was hundreds of µs in the cumulative
  full-pipeline measurement; if the bulk of that cost is
  scratchpad zero-init + register-file alloc (the components
  the pool would amortize), Branch C is the expected outcome.
- **Branch A (< 50 µs delta) plausible.** `Box::<[u8]>::new_zeroed_slice(2 * 1024 * 1024)`
  on a modern allocator (jemalloc/mimalloc/glibc with mmap-backed
  large allocations) is typically tens of µs, not hundreds — the
  per-call cost in PR-66 may have been dominated by other
  pipeline components (Argon2d-fill on cold caches, dispatch-
  loop overhead) rather than alloc-specific cost. If so, Branch A
  is the expected outcome.

The impl-PR's commit-4 bench result resolves the prediction
with substrate-anchored data, not training-data-recall
estimation. Both predictions are consistent with the §3.4
Round 3 disposition; both produce a defensible 2F close.
Branch B (50–100 µs ambiguity) is the lowest-likelihood
outcome but is handled by the explicit ambiguity-band
escalation per §3.4 Round 3.

---

## 9. CI gates

Inherits Phase 2d's gates. Adds two new ones:

- **Format**: `cargo fmt --check -p shekyl-pow-randomx` ✓ (unchanged).
- **Lint**: `cargo clippy --all-targets -D warnings` ✓ (unchanged).
- **Test**: `cargo test -p shekyl-pow-randomx --release -- --test-threads=1` ✓
  (now includes §6.1 CacheStore tests).
- **Doc**: `cargo doc -p shekyl-pow-randomx --no-deps` ✓ (unchanged).
- **FPU unsafe grep**: `scripts/ci/check_randomx_fpu_rounding.sh` ✓
  (unchanged; inherited from 2d).
- **NEW** Crate-invariant greps: `scripts/ci/check_randomx_crate_invariants.sh`
  (per R1-E1 — final name pinned at Round 1). Catches module-level
  static / `#[no_mangle]` / `extern "C"` exports.
- **Bench delta (informational)**: ±10% threshold per the Phase 2c +
  Phase 2d cadence. If R1-D4 triggers pool, the post-pool median is
  the new baseline; the delta is reported but not gated.

---

## 10. Forward path

- **2g** inherits the post-2f `compute_hash` body (with or without
  pool per R1-D4). The differential harness operates on the same
  public surface as today; no harness-side changes from 2f are
  visible. **Round 2 amends:** the public surface is
  `compute_hash(&PreparedCache, &[u8]) -> [u8; 32]` (per §1.1
  amendment), not `compute_hash(&Cache, &[u8; 32], &[u8])`; 2g's
  harness consumes the bundled `PreparedCache` shape.
- **3a** sees `Cache::derive` (now `pub(crate)`; reachable only
  via `PreparedCache::derive`), `compute_hash`, the new
  `CacheStore`, the `Seedhash` newtype, and `PreparedCache`.
  `shekyl-ffi` will instantiate the `CacheStore` per
  `RANDOMX_V2_PHASE2C_PLAN.md` Decision #6; 3a's FFI shim
  constructs `Seedhash::from_bytes(*ptr)` from the C-ABI's
  `*const [u8; 32]` and bundles `Arc<PreparedCache>` instances
  through the C-ABI as opaque pointers. Dispatch and (R1-D4-
  conditional) pool stay private.
- **3c** absorbs the binary-level `nm`-on-`shekyld` symbol-isolation
  check from FOLLOWUPS line 3633ff; 2f's source-level greps are the
  Rust-side companion.

### 10.1 Precursor PR queued by Round 2

- **`chore/randomx-v2-plan-decision6-amendment`** — small
  precursor PR amending the parent-plan
  `RANDOMX_V2_PLAN.md` Decision #6 wording. Round 1 picked
  Option (b) for `CacheStore`'s API shape; the parent plan's
  "transparent memo with capacity-2 LRU and `pin()` API"
  framing belongs to the rejected Option (a). Round 2 retires
  the framing in §3.1 Round 2 disposition; the parent-plan
  text itself is updated by this precursor PR before the Phase
  2F implementation PR opens. Precedent: Phase 2c F4-absorbed
  parent-plan rescope (which followed the same pattern of a
  Round-N substrate finding driving a small precursor PR
  against the parent plan).

### 10.2 PQC migration space

The verifier crate's API shape at the Phase 2F freeze is
PQC-orthogonal by construction. `Seedhash` is a 32-byte newtype;
`PreparedCache` bundles classical Argon2d-derived cache state
with the seedhash; `compute_hash` produces a 32-byte hash output.
None of these surfaces presume the post-PQC architectural
choices (V4-lattice signature scheme, hybrid-PQC verification
pipeline shape, PQC-authenticated header metadata).

The verifier's role in the post-PQC pipeline is **same as
today**: given a seedhash and data, produce a deterministic
32-byte hash. The PQC architectural choices land at Phase 3a's
shim layer (where `Seedhash` is constructed from validated block
header bytes; pre-PQC the validation is classical-signature-
shaped, post-PQC it is hybrid-PQC-shaped). The verifier crate
does not see the validation discipline; it sees the seedhash.

This factoring is a load-bearing property: the verifier crate's
test surface, audit posture, and freeze are stable across the
classical → PQC transition. The PQC migration space is not a
Phase 2F concern. The note exists so future contributors don't
attempt to "PQC-prepare" the verifier crate's API; the API is
already PQC-prepared by virtue of being PQC-orthogonal.

### 10.3 Phase 3a FFI shim discipline (post-closure pin)

The Phase 2F freeze produces a Rust-side type system —
`Seedhash`, `PreparedCache`, `Arc<PreparedCache>`, `CacheStore`.
Phase 3a's FFI shim is responsible for:

- **C-side opaque-handle shape.** The verifier crate does not
  specify the C-side ABI; the shim layer (in `shekyl-ffi` or
  equivalent) decides whether `PreparedCache` crosses the
  boundary as `*mut shekyl_pq_prepared_cache` (opaque) with
  `_destroy` for caller-owned lifecycle, or as a pool-managed
  handle the daemon does not own. Both shapes are compatible
  with the verifier's Rust-side surface; the shim picks one and
  applies it consistently.
- **`Seedhash::from_bytes` construction at the boundary.** The
  C ABI continues to accept `*const uint8_t [32]` (Phase 2c
  signature shape; daemon-side code is unaffected). The shim
  converts to `Seedhash::from_bytes(*ptr)` at the boundary; the
  newtype lives entirely Rust-side.
- **`Arc<PreparedCache>` lifecycle across the boundary.** The
  daemon never sees `Arc<PreparedCache>` directly. The shim
  holds the `Arc` clones; daemon-side handles are opaque
  pointers whose `_destroy` semantics are shim-defined. The
  caller hand-off Arc-lifetime discipline (per §4 Round 3) is
  the daemon-side application of this principle: long-lived
  daemon holds extend cache memory residency beyond
  CacheStore's bound, so the shim's daemon-facing API should
  not encourage long-lived holds (e.g., via a "borrow for the
  duration of one hash computation" idiom rather than a
  "store the handle in async state" idiom).

  **Layering note (post-closure pin refinement): the shim-side
  scoped-closure discipline absorbs the API constraint Round 2
  §3.1 rejected at the verifier layer.** The (g)-option scoped-
  closure pattern was rejected at the verifier's Rust-side API
  for being too constraining on consumers (the verifier stays
  general-purpose; consumers can hold `Arc<PreparedCache>` for
  any duration, accepting the daemon-side discipline burden).
  The same scoped-closure pattern is acceptable on the shim
  side because the shim's consumers are FFI callers who already
  navigate explicit allocate/use/destroy lifecycle; absorbing
  the constraint at the boundary is a natural fit, not an
  additional burden. The responsibility moved layers
  (verifier → shim) rather than disappeared. Future readers see
  that the (g)-rejection at the verifier layer and the
  (g)-style absorption at the shim layer are the same
  discipline, applied at the layer where it doesn't constrain
  the wrong consumers. The verifier crate stays a general-
  purpose Rust-side type system; the shim becomes the choke
  point that enforces the Arc-hold-duration discipline through
  its daemon-facing API shape.
- **Threadpool capacity derivation.** Per §3.5 R1-D5 Round 3,
  `VmStatePool::new(capacity: usize)` takes a runtime
  parameter; the shim derives the value from `dev`-tip daemon
  threadpool source at Phase 3a wire-up time and passes it at
  pool construction.

This factoring keeps the verifier crate's API stable across
shim-shape evolutions. The pin exists so Phase 3a's plan does
not re-litigate the shim's responsibility — the disposition is
named here, and Phase 3a inherits it. Reopen criterion: a Phase
3a substrate finding surfaces a structural reason the
verifier-crate-side API needs to be amended to support the shim
(e.g., the C ABI requires the Rust side to expose a primitive
the verifier crate doesn't have); not anticipated.

### 10.4 Phase 2g `compute_hash_with_trace` (post-closure pin; pre-pin for 2g's plan)

Phase 2g's differential harness compares Rust-side
`compute_hash` output against the C reference's output. When
the two diverge, the harness sees that the final 32-byte hash
differs; bisecting from final-hash divergence to the specific
instruction / iteration where the divergence first appeared
is expensive (manual spelunking of two implementations'
intermediate state).

Phase 2g may add a test-infrastructure entry point to the
verifier crate:

```rust
#[cfg(any(test, feature = "differential-trace"))]
pub fn compute_hash_with_trace(
    prepared: &PreparedCache,
    data: &[u8],
    trace_sink: &mut impl TraceSink,
) -> [u8; 32];
```

`TraceSink` captures per-iteration register-file snapshots,
program-counter values, and dataset-read indices. The C
reference does not expose this; the Rust verifier exposes it
under `#[cfg(...)]` so the production build pays no overhead.
Phase 2g's harness consumes `compute_hash_with_trace` to
produce side-by-side traces from the Rust side, instruments
the C reference to produce a parallel trace, and bisects
mechanically rather than spelunking.

**This is test-infrastructure, not a public-API addition.** The
production build does not include `compute_hash_with_trace`;
the symbol does not appear in the crate's public API surface
under default features; the FFI shim does not see it. The
verifier's "stay minimal; don't add Shekyl-specific
divergence" discipline is preserved — the trace API is a Rust-
language affordance for the differential harness's
convenience, not a behavioral change.

**Cfg-gated test-infrastructure principle (post-closure pin
refinement).** Cfg-gated test-infrastructure additions are
**not** "tweaks to upstream RandomX" — they are Rust-language
affordances for tooling. The "don't tweak upstream unless we
need to" discipline applies to **consensus-affecting behavior**
(production-build code paths that influence the hash output, the
cache derivation, the dispatch loop, the validation rules), not
to **bisection convenience** (test-only code paths gated by
`#[cfg(any(test, feature = ...))]` that do not appear in the
production-build crate's public surface and cannot influence
consensus). Future contributors evaluating whether a proposed
addition crosses the line should ask: "does this code path
appear in the default-features production build?" If yes, the
discipline applies. If no (cfg-gated to test or non-default
feature), it is a Rust-language affordance and the discipline
does not apply to it.

The line is consensus-affecting, not Shekyl-specific. A `#[cfg(test)]`
addition that, e.g., exposes `Cache`'s internal SuperscalarHash
program tables for differential audit is fine; a default-features
`pub fn cache_internals(...)` exposing the same is not, because
the latter creates a public surface that downstream tooling can
depend on and that constrains future verifier-internal refactors.

**`TraceSink` trait scope (post-closure pin refinement).** The
`TraceSink` trait surface design — what fields it exposes per
iteration, how the harness consumes it, whether it's a
streaming sink or a buffered collector, what the per-iteration
data shape is — is part of **Phase 2g's plan-doc scope**, not
Phase 2F's. Specifically:

- The trait's surface lives with the differential harness, not
  with the verifier's public API. The verifier crate exposes
  `compute_hash_with_trace(..., trace_sink: &mut impl TraceSink)`
  as a generic-bound entry point; the `TraceSink` trait
  definition itself can live in the harness crate (or a
  test-only sub-module of the verifier crate) so the trait is
  not part of the verifier's stable surface.
- 2g's plan-doc is responsible for the trait's design, scope,
  and stability commitments. If a future iteration of the
  harness changes how it consumes traces (e.g., switches from
  per-iteration to per-program-block granularity), the trait's
  shape changes with it; the verifier's `compute_hash_with_trace`
  entry point may need to update to match, but the change lives
  with 2g's design discipline.
- **Do not promote `TraceSink` to a public surface.** A
  `pub trait TraceSink` exposed from the verifier crate would
  create an API contract that downstream tooling could consume
  and that constrains future verifier-internal refactors (a
  representation change in `Cache` or `VmState` may break a
  trait surface that exposed those representations through
  trace data). The trait stays scoped to the differential
  harness's consumption.

Pre-pin disposition: Phase 2g's plan-doc inherits this option.
If 2g's bisection workflow needs the trace API, 2g's plan
adds it under the `#[cfg(...)]` shape above and designs the
`TraceSink` trait surface with the scope discipline named
here. If 2g's differential pass surfaces no divergence (or
the divergences that surface are bisectable without trace
infrastructure), the trace API is not added — the verifier
crate stays minimal. Reopen criterion: 2g's substrate finds
bisection from final-hash divergence is intractable without
per-iteration trace visibility.

### 10.5 Phase 2g audit posture against the C reference (post-closure pin)

Phase 2g's differential harness is the test backstop for the
"Shekyl's verifier is canonical RandomX v2" claim. **The
harness is necessary but not sufficient for the claim.**
Three distinct legs support spec-equivalence with canonical
RandomX v2:

1. **Spec-faithful implementation discipline** (Phases 2b /
   2c / 2d / 2f): each phase implements against the canonical
   RandomX v2 specification, with the C reference (RandomX
   upstream at the pinned commit) consulted where the spec
   is silent or ambiguous. The Phase 2c R0-D6 tests-use-the-
   actual-API discipline, the Phase 2d FPU-rounding discipline,
   and the Phase 2f type-enforced cache-seedhash binding all
   land under this leg.
2. **C-reference audit where the spec is silent.** Some
   behavior in canonical RandomX v2 is defined by the C
   reference (the choice of Argon2d salt; the
   SuperscalarHash program-generation seed; the JIT-vs-
   interpreter dispatch decisions; etc.) rather than by the
   spec text. Each Shekyl-side implementation of these is
   audited against the C reference at the pinned commit.
3. **Differential-harness corpus testing** (Phase 2g):
   the harness compares Rust-side `compute_hash` output
   against the C reference's output across an adversarial
   corpus of inputs (random seedhashes; random data; edge
   cases like all-zero inputs, all-ones inputs, inputs at
   power-of-two boundaries; inputs that trigger known-
   sensitive dispatch paths). Agreement on the corpus is
   evidence of agreement; it is not proof of spec-equivalence.

**The load-bearing claim is leg 1, not leg 3.** "Shekyl's
verifier is canonical RandomX v2" is established by the
spec-faithful implementation discipline of leg 1, audited
against leg 2's C-reference where leg 1 is underspecified.
Leg 3 is the backstop that catches divergences leg 1 and
leg 2 missed; corpus testing on a finite set of inputs does
not establish behavior on the unbounded set of all inputs,
but it does increase confidence that the implementation
discipline of leg 1 was applied correctly.

For an external auditor reading the code and asking "how do
you know this is right?", the answer is: **"we implemented
to the spec (leg 1), we audited against the C reference where
the spec is silent (leg 2), and we test against the C
reference's outputs across an adversarial corpus as a backstop
(leg 3). The three legs do different work; leg 1 is the
load-bearing claim, leg 3 is the backstop, leg 2 mediates
between them."** This framing is the audit posture; it is
**not** "we test against the C reference" alone.

Phase 2g's plan-doc inherits this audit-posture framing
explicitly; the differential harness is built and operated
under leg 3, not as a standalone "we tested it" claim. The
plan-doc cites legs 1 and 2 as the upstream disciplines the
harness depends on. Reopen criterion: a substrate finding
in Phase 2g surfaces that one of the legs is broken (e.g.,
a spec-silent behavior was implemented without C-reference
audit, surfacing a corpus divergence that is ambiguous
between "Rust-side bug" and "C-reference quirk we
mis-mirrored").

---

## 11. Round history

| Round | Date | Outcome |
|-------|------|---------|
| Post-implementation review fixes (PR #72, fifth pass) | 2026-05-24 | **One Copilot-surfaced finding on the post-NF7 commit, fixed in-place against `feat/randomx-v2-phase2f-impl` (no plan-doc round opened — the finding is a documentation-vs-implementation discrepancy in the cargo-test wrapper's rustdoc claim; the architectural disposition is unchanged, and the fix tightens the substrate by expanding scan scope rather than relaxing the documented claim).** **NF8 — `tests/crate_invariants.rs` rustdoc claimed an active regression-detection mechanism that the scan scope did not realize.** The cargo-test wrapper's preamble at lines 15–22 claimed: "a test below intentionally introduces commented-out docstring examples of each pattern A/B/C, ensuring the test would fail if the script's logic regressed (the comments themselves are lines beginning with `//` and so are not matched by any of the three column-0 / leading-whitespace-anchored regexes; if a future patch unanchored a pattern, the comments would start matching and the assertions below would expose the regression)." The mechanism described requires the would-match examples to be in scan scope, but the script's `CRATE_SRC` constant scanned only `rust/shekyl-pow-randomx/src/` — `tests/crate_invariants.rs` was outside scope, so a hypothetical un-anchoring regression would not have been caught from the in-test citations regardless. The discrepancy between the documented mechanism and the script's scan scope was inherited from the §3.6 R1-E1 Round 3 phrasing where `CRATE_SRC` was set narrowly to the production code surface; the documented regression-detection claim was layered onto the test wrapper without expanding the scope it required. Two dispositions were available: (a) weaken the rustdoc claim to acknowledge the citations are documentary-only; (b) strengthen the scan scope so the citations form a real regression-detection surface. **Fix: option (b)** — the cleaner correct disposition under the verifier-crate-wide framing of §3.6's R1-E1 invariants. Expanded `CRATE_SRC` from a single path to an array `("rust/shekyl-pow-randomx/src", "rust/shekyl-pow-randomx/tests", "rust/shekyl-pow-randomx/benches")`; the recursive `grep` arm gains `--include='*.rs'` to skip the C/C++ reference-vector generators under `tests/vectors/reference/<primitive>/_generator/*.{c,cpp}` (those carry legitimate column-0 `static` declarations under C/C++ semantics and are out of scope for a Rust-targeted invariant gate); the per-file `awk` multi-line scanner already iterated via `find ... -name '*.rs'` and picks up the change automatically. **Verification.** Plant-revert positive-side tests across both new scope arms — `use std::sync::OnceLock;` plant in `tests/` → gate FAILS; multi-line bypass plant in `benches/` → gate FAILS; column-0 `static` plant in `tests/` → gate FAILS; `pub extern "C" fn` plant in `benches/` → gate FAILS; baseline → gate PASSES. **Regression-detection-mechanism reality check.** Simulated un-anchoring of Pattern A (drop the `^` from the regex) confirmed the gate fires from multiple in-scope sources: (1) the `tests/crate_invariants.rs:146-147` would-match comments, exactly as the rustdoc claim describes; (2) legitimate function-local indented `use std::sync::OnceLock;` statements inside `#[cfg(test)] mod tests { }` blocks at `src/cache_store.rs:596`, `src/vm.rs:2767`, and `src/vm.rs:3342`, which the column-0 anchor was protecting and would un-protect under regression. The mechanism is doubly real with the expanded scope. **Documentation.** Updated `tests/crate_invariants.rs` preamble to explicitly cite the NF8 fix and the now-real regression-detection mechanism, naming the scope expansion (`src/` → `src/` + `tests/` + `benches/`) as the substrate change. **Substrate-anchored disposition.** NF8 is a documentation-vs-implementation discrepancy at the CI-gate-implementation layer; the §3.6 R1-E1 architectural disposition (banned-token enumeration, anchor placement, rustfmt-rely-chain, Phase 2F Decision #5 FFI-localization-to-shekyl-ffi) is unchanged. The threat model rationale (`RANDOMX_V2_RUST.md` §7.2: production-code module-level mutable state) was named in the script preamble as production-focused; the discipline applies uniformly across `src/` / `tests/` / `benches/` because the Pattern A/B/C regex shapes ban *module-level* shapes regardless of compilation-unit role, and aligning all three under the gate is structurally cleaner than keeping the boundary at `src/`. Per `21-reversion-clause-discipline.mdc`'s post-closure-pin discipline this is a post-closure refinement at the CI-gate-implementation layer. The crate-invariant grep gate already runs in CI; the scope expansion runs in the same script invocation. |
| Post-implementation review fixes (PR #72, fourth pass) | 2026-05-24 | **One Copilot-surfaced finding on the post-NF3..NF6 commit, fixed in-place against `feat/randomx-v2-phase2f-impl` (no plan-doc round opened — the finding is a CI-gate completeness defect against the §3.6 R1-E1 Pattern A invariant; the architectural disposition is unchanged).** **NF7 — `PATTERN_RUNTIME_STATE` regex bypassed by rustfmt-default multi-line grouped imports.** §3.6 Round 3 froze Pattern A as a column-0 anchored regex matching banned identifiers anywhere on the same line as a `use` statement. The single-line grouped form `use std::sync::{Arc, OnceLock};` is correctly caught by the regex (`OnceLock` appears on the same line as the column-0 `use`); the rustfmt-default multi-line grouped form, where the `use` opener carries no banned identifier and the indented identifier lines fail the column-0 anchor, bypasses entirely: `use std::sync::{\n    Arc,\n    OnceLock,\n};` matches none of the per-line patterns. rustfmt's default `imports_granularity = "Preserve"` accepts the multi-line form (and a `cargo fmt`-mediated rewrite from the single-line form is a one-`max_width`-overflow away — the trip is from manual hand-formatting *or* from a future `imports_granularity = "Crate"` config change), so the bypass is reachable in production-discipline workflows. The Round 3 R1-E1 Pattern A invariant is "no module-level imports of `once_cell` / `lazy_static` / `OnceLock` / `LazyLock`," not "no module-level imports of these in a specific formatting style"; the gate's stated property and its mechanical coverage diverged. **Fix:** added a per-file POSIX `awk` scanner that complements the single-line `grep` regex. The scanner triggers on any column-0 `use` statement opening an unclosed brace block, accumulates subsequent lines tracking nested-brace depth via balanced `{`/`}` counts (so `use foo::{bar::{baz, OnceLock}}` spread across lines is handled correctly), and on depth-zero closure scans the accumulated buffer against the same banned-token alternation `(once_cell\|lazy_static\|OnceLock\|LazyLock)`. The two arms (single-line `grep`, multi-line `awk`) jointly enforce Pattern A regardless of rustfmt grouping style. **Verification.** Per the standard plant-revert positive-side test: synthesized multi-line bypass file → gate FAILS (exit 1) with the banned token cited; nested-brace multi-line bypass → gate FAILS; clean multi-line `use` (no banned tokens) → gate PASSES; baseline crate state → gate PASSES. The cargo-test wrapper `tests/crate_invariants.rs` invokes the unmodified bash entry point so the test surface continues to assert the gate's exit-zero discipline; the documentation comment was extended with a multi-line bypass would-match example mirroring the single-line / Pattern B / Pattern C citations so the regression-detection mechanism (commenting out a row of the would-match list and observing the gate fire on the resulting plant) is auditable for the new arm too. **Substrate-anchored disposition.** NF7 is a CI-gate completeness defect; the §3.6 R1-E1 architectural disposition (banned-token enumeration, column-0 anchor, rustfmt-rely-chain) is unchanged. The Pattern A definition on the plan-doc side described the *property* (no module-level imports) rather than the regex shape, so no §3.6 amendment is required — the regex was always meant to enforce the property, and the awk arm closes the residual gap. Per `21-reversion-clause-discipline.mdc`'s post-closure-pin discipline this is a post-closure refinement at the CI-gate-implementation layer. The crate-invariant grep gate already runs in CI; the new awk arm runs in the same script invocation. |
| Post-implementation review fixes (PR #72, second pass) | 2026-05-24 | **Four Copilot-surfaced findings on the post-NF1/NF2 commit, fixed in-place against `feat/randomx-v2-phase2f-impl` (no plan-doc round opened — three are documentation drift inherited from Phase 2c phrasing; one is an implementation defect on the in-flight-derivation rendezvous architecturally specified in Round 2 but under-specified at the panic-unwind boundary).** **NF3 — `lib.rs` crate-level rustdoc still described `dispatch_instruction` as having a NOP body and "Phase 2d replaces the dispatch body in-place per §5.1.1 of the plan doc."** The bullet was correct as of Phase 2c's PR landing; Phase 2d (PR #70 → `dev`) replaced the body in-place with the real table-driven per-opcode dispatch and added the T16 reference vector for end-to-end real-dispatch parity, but the rustdoc was not updated to record the now-landed state. **Fix:** rephrased the dispatch bullet to reflect both the Phase-2c-landed NOP and the Phase-2d-landed real dispatch, named T16 as the current end-to-end consensus-parity gate, and reframed "Subsequent sub-PRs" to "Sub-PR ladder" with explicit `(landed)` / `(planned)` markers on 2d / 2f / 2g. Also updated the bench-bullet's `compute_hash_alloc` description to record the post-2d baseline alongside the 2c stub-NOP number. **NF4 — `benches/compute_hash_alloc.rs` rustdoc framed the per-call cost composition under the stub-NOP body** ("Under the stub-NOP `dispatch_instruction` body, the per-call cost is dominated by …"; "8 × 2048 stub-NOP iteration-loop bodies … no per-instruction work since dispatch is NOP"). Same drift as NF3. **Fix:** rephrased the cost-composition section to describe the pipeline neutrally (per-iteration dispatch is a step in the iteration body; Phase 2c measured under stub-NOP, Phase 2d adds per-instruction work at that step), and updated the file-header summary + the `PER_CALL_SAMPLE_SIZE` rationale to record the post-2d baseline. **NF5 — `Cargo.toml` `internal-pool-bench` feature comment claimed `VmStatePool` is a `pub(crate)` type whose `Default` panics in non-test builds.** The first half is wrong post-PR-72 NF/F2 (the type is `#[doc(hidden)] pub` so the criterion bench in `benches/compute_hash_alloc.rs`, a separate cargo target, can name `VmStatePool::new` and `compute_hash_with_pool` across the crate boundary; `pub(crate)` would forbid that). The second half is incomplete (the panic is gated specifically by `cfg(all(not(test), feature = "internal-pool-bench"))`; the no-feature production build never compiles `vm_pool` at all). **Fix:** rewrote the comment to record the actual visibility (`#[doc(hidden)] pub`), the actual gating shape (whole module behind `#[cfg(any(test, feature = "internal-pool-bench"))]`), and the actual panic discipline (panic only when `Default::default()` is called outside `#[cfg(test)]`, enforcing §3.5 R1-D5 explicit-capacity at Phase 3a). **NF6 — `DerivationSlot::wait_for_result` deadlocks on leader thread panic.** Round 2 §3.1 pinned the in-flight-derivation rendezvous as `Mutex<HashMap<Seedhash, Shared<DerivationFuture>>>` at the architecture level; the implementation used a `Mutex<Option<Arc<PreparedCache>>>` per-slot rendezvous with a `Condvar` for follower wake-up. Pre-fix, if the leader thread panicked inside `PreparedCache::derive` (e.g., allocation failure during the 256 MiB Argon2d-512 fill), `slot.publish` never ran, the `inner` mutex stayed at `None`, the `Condvar` was never broadcast, and (a) every follower already parked on `cv.wait` blocked forever; (b) the `in_flight` HashMap entry was never removed, so subsequent callers for the same seedhash acquired `in_flight.lock()`, found the orphaned slot, became followers of the dead leader, and joined the deadlock cascade. Production builds set `panic = "abort"` for `dev` / `release` (process aborts before any of this matters), but `cargo test` always builds with `panic = "unwind"` per the test-harness contract — so a test exercising the failure path would hang rather than fail with a diagnostic message. **Fix:** replaced `Mutex<Option<Arc<PreparedCache>>>` with `Mutex<DerivationOutcome>` (`Pending` / `Published(Arc<PreparedCache>)` / `LeaderAborted`); added `LeaderGuard<'cs>` that owns the leader's slot Arc + a borrow of the in-flight mutex + a `success: bool` flag, with `Drop` that always removes the in-flight entry (cleanup-on-publish + cleanup-on-panic in one path) and conditionally broadcasts `LeaderAborted` via `publish_aborted_if_pending` when `mark_success` was never called; `wait_for_result` now panics with a diagnostic message on `LeaderAborted`. The lookup_or_derive leader branch wraps its `PreparedCache::derive` + slot.publish + transient.write sequence in the guard's scope with a `mark_success` flag flip after the transient write — on success the guard's drop is a no-op for the abort broadcast and the in-flight removal becomes the cleanup-on-publish step that previously lived inline. **Test added — T-CS-13 `cachestore_leader_abort_wakes_followers_and_cleans_in_flight`:** white-box test using a standalone `Mutex<HashMap<Seedhash, Arc<DerivationSlot>>>` mock so the test runs without paying the ~150–200 ms `PreparedCache::derive` cost; spawns a follower thread on `slot.wait_for_result()`, drops a `LeaderGuard` without `mark_success`, and asserts (1) in-flight entry removed; (2) slot in `LeaderAborted`; (3) follower panic-propagated rather than hanging. With the pre-fix slot type the test would hang indefinitely on assertion (3); with the fix it passes deterministically. **Substrate-anchored disposition.** NF3 / NF4 are documentation drift; NF5 is a comment-vs-code disagreement that arose from PR #72 NF2's prior commit changing visibility without updating the Cargo.toml comment; NF6 is an implementation refinement on the Round 2 architectural shape. None of the four reopen Round 2 / Round 3 architecture-level dispositions. Per `21-reversion-clause-discipline.mdc`'s post-closure-pin discipline these are post-closure refinements at the implementation / documentation layers. The crate-invariant grep gate already runs in CI; the new T-CS-13 test runs as part of `cargo test -p shekyl-pow-randomx`. |
| Post-implementation review fixes (PR #72) | 2026-05-24 | **Two Copilot-surfaced findings against the implementation cut, fixed in-place against `feat/randomx-v2-phase2f-impl` (no plan-doc round opened — the findings are implementation defects, not plan-doc gaps).** **NF1 — `PATTERN_FFI_EXPORT` blind spot in `scripts/ci/check_randomx_crate_invariants.sh`.** The Round 3 §3.6 R1-E1 pattern C arm `extern[[:space:]]+"C"[[:space:]]+fn[[:space:]]` anchored `extern` as the first non-whitespace token; `pub extern "C" fn`, `pub(crate) extern "C" fn`, `unsafe extern "C" fn`, `pub unsafe extern "C" fn` all bypassed the gate. Without `#[no_mangle]` they are not C-callable today, but the gate's stated purpose (per script preamble) is to forbid the *export-intent shape* independent of `#[no_mangle]` so that stepwise FFI-export drift (add `pub extern "C" fn` first, attach `#[no_mangle]` later) fires the gate at the first commit rather than only the second. **Fix:** extend the regex to allow optional `pub` / `pub(crate)` / `pub(super)` / `pub(in path)` visibility prefix and optional `unsafe` keyword before `extern`, mirroring pattern A's prefix coverage. Verified against eleven positive shape variants (all match) and eight negative shapes (`extern "C" { fn bar(); }` import blocks, `// extern "C" fn` rustdoc, `use std::ffi::CStr;`, `fn extern_c() {}`, etc. — all skip). **NF2 — `CacheStore::lookup` linearizability race on transient→canonical promotion.** The Round 2 §3.1 `RwLock<Option<Arc<PreparedCache>>>` per-slot shape was specified at the architecture level; the implementation acquired and released each slot's read guard sequentially across the comparison sequence, opening a race window in which a concurrent `set_canonical` could promote an entry from transient to canonical between the two lookup inspections, causing `lookup(&S)` to observe canonical=Some(prior) → released → transient=Some(prior_canonical) → return `None` despite the requested entry being live in the canonical slot the entire time. Soft consequence: a `lookup_or_derive` consumer falls through to a ~150–200 ms Argon2d-512 re-derivation that should have been a slot hit; violates the documented "few hundred nanoseconds" cost-model. **Fix:** acquire both slot read guards before the comparison sequence and hold them across both inspections; the canonical-then-transient acquisition order matches `set_canonical`'s canonical-write-then-transient-write order, so there is no deadlock cycle. Updated `lookup` rustdoc with explicit linearizability + lock-ordering discussion; updated the `CacheStore` struct's `# Synchronization shape` rustdoc to record the global lock-ordering invariant ("every method acquiring both slot locks acquires them canonical-then-transient, regardless of read-vs-write mode"). **Test added — T-CS-12 `cachestore_lookup_linearizable_under_canonical_swap`:** seeds the store with two pre-derived prepared caches in distinct slots, runs alternating `set_canonical(p_a) / set_canonical(p_b)` calls in one thread while a second thread tightly polls `lookup(&seedhash_a) / lookup(&seedhash_b)` for 2,000 iterations and asserts both never return `None` (both entries are live in *some* slot at every observable moment, so a linearizable `lookup` must always find them). With the buggy implementation the test fails probabilistically; with the fix it passes deterministically because a concurrent `set_canonical` cannot interleave between the two slot reads. **Substrate-anchored disposition.** Both findings are localized implementation refinements against Round 2 / Round 3 architecture-level dispositions that remain correct as specified — the architectural shape (per-slot RwLock; canonical-then-transient lock ordering for set_canonical) was always correct; the implementation under-specified what the lookup-side discipline needed to be. Per `21-reversion-clause-discipline.mdc`'s post-closure-pin discipline, this is post-closure refinement at the implementation layer, not a Round 4. The plan-doc's substrate is unchanged; the round-history records the fixes as audit trail. **No new gates.** The crate-invariant grep gate already runs in CI; the regex extension is mechanical. The new T-CS-12 test runs as part of `cargo test -p shekyl-pow-randomx --release`. |
| Implementation | 2026-05-23 | Implementation landed on `feat/randomx-v2-phase2f-impl` in five commits versus the §8 Round 3 ceiling of six (commit 5 omitted per Branch A). **SHA → §8 Round 3 mapping:** (1) `e687cf68b` covers §8 Round 3 commit 1 — `Seedhash` newtype + `PreparedCache` bundle + `Cache::pub → pub(crate)` transition + `compute_hash` signature change to `(&PreparedCache, &[u8])` + atomic in-crate Seedhash sweep across vm.rs / cache.rs / benches per §3.1 Round 2 sweep-discipline. (2) `31aa0ff9d` covers §8 Round 3 commit 2 — `CacheStore` two-slot type with `lookup` / `lookup_or_derive` / `set_canonical` per §3.1 Round 2 frozen API; per-slot `RwLock<Option<Arc<PreparedCache>>>` + `Mutex<HashMap<Seedhash, Shared<DerivationFuture>>>` for in-flight dedup with cleanup-on-publish; T-CS-1..11 unit tests per §6.1 Round 3. (3) `68086d99c` covers §8 Round 3 commit 3 — `scripts/ci/check_randomx_crate_invariants.sh` per §3.6 R1-E1 patterns A/B/C with the rustfmt-rely-chain note and column-0-modulo-attribute-indentation anchor; `.github/workflows/build.yml` step sibling to FPU; `tests/crate_invariants.rs` cargo-test wrapper. (4) `3121b726d` covers §8 Round 3 commit 4 — cfg-gated `VmStatePool` + `VmStateGuard` + `compute_hash_with_pool` under `#[cfg(any(test, feature = "internal-pool-bench"))]` per §3.3 Round 3; `compute_hash` factored into thin wrapper over `pub(crate) compute_hash_inner(&mut VmState, ...)` with `state.fprc` zero on entry (only field with observable carry-over across pooled reuse since CFROUND mutates without boundary reset); `benches/per_call_alloc.rs` (B-2 + B-3) and extended `compute_hash_alloc.rs` (B-pool-off + B-pool-on); `BENCH_RESULTS.md` Phase 2F section with methodology, disposition table, and TBD measurements. (5) `a37aac054` covers the §8 Round 3 commit-4 conditional measurement step (split from `3121b726d` because the bench measurement is a separable artifact independently bisectable from the harness landing) — `BENCH_RESULTS.md` records measured A/B delta (720 µs point-estimate, statistically indistinguishable from zero per CI overlap, structurally bounded above by component-floor cap ≈ 48.7 µs); **Branch A disposition** per §3.4 R1-D4 Round 3 (achievable savings < 50 µs threshold). **§8 Round 3 commit 5 (cfg-gate flip to default-on) is omitted** per Branch A — the cfg-gated `VmStatePool` stays in source as a bench-only artifact; Phase 3a's FFI shim sees the unchanged production `compute_hash` body. **Prediction-vs-measured reconciliation** per the §8 Round 3 + post-closure-pin-refinement discipline: prediction A held. B-2 at 48.6 µs is consistent with the §8 "modern allocators amortize 2 MiB zero-init to tens of µs" framing (mmap-backed glibc on kernel 6.12, large-page-aware allocator); PR-66's per-call full-pipeline cost (~300 ms) is dispatch-loop dominated (2048 iter × 8 chains × per-iter AES + scratchpad RW + dataset reads), not allocation-specific; the component-floor cap is structurally below Branch B/C thresholds. **§9 gate confirmation (HEAD = `a37aac054`):** Format `cargo fmt -p shekyl-pow-randomx -- --check` ✓; Lint feature-off `cargo clippy -p shekyl-pow-randomx --all-targets -D warnings` ✓; Lint feature-on `cargo clippy -p shekyl-pow-randomx --all-targets --features internal-pool-bench -D warnings` ✓; Test `cargo test -p shekyl-pow-randomx --release -- --test-threads=1` ✓ (117 lib passed, 2 ignored — T6/T7 superseded by 2d's T16; 4 crate_invariants integration tests passed; 1 perf placeholder ignored — T17 per-hash latency Phase 2g deliverable); Doc `cargo doc -p shekyl-pow-randomx --no-deps` ✓; FPU unsafe grep `check_randomx_fpu_rounding.sh` ✓ (inherited from 2d); **NEW** crate-invariant grep `check_randomx_crate_invariants.sh` ✓; bench delta informational — `compute_hash_alloc::per_call` 307.42 ms vs. Phase 2d baseline 303.60 ms (+1.27%; under §9's ±10% threshold). **Substrate finding (audit-against-actual-code recurrence cadence).** The Branch A measurement is the **third instance** of the `16-architectural-inheritance.mdc` discovery-cadence framing applied to RandomX v2's plan-doc rounds. First instance (Phase 2c Round 3): `mp` correction substrate finding from reading the actual C reference rather than working from prompted summaries. Second instance (Phase 2d Round 1): R1-D3 frequency-decode finding (wire opcode bytes are frequency-encoded per `bytecode_machine.hpp:67-98`, not `InstructionType` enum values). Third instance (Phase 2f Branch A measurement): empirical confirmation that pool savings are structurally bounded by per-call alloc cost on modern allocators, validating the plan-doc's two-prediction framing rather than collapsing to a single guess. The discipline applies forward to 2g (per-hash latency baseline) and 3a (FFI shim binding-fanout survey). |
| Scaffold | 2026-05-23 | This document. Pins the substrate carry-forwards from `RANDOMX_V2_PLAN.md` Decisions #6/#7, `RANDOMX_V2_PHASE2C_PLAN.md` §5.11.7, and `RANDOMX_V2_PHASE2D_PLAN.md` §10. Enumerates §3 Round 1 decision points (R1-D1 API shape; R1-D2 eviction policy; R1-D3 bench methodology; R1-D4 pool threshold; R1-D5 fanout survey; R1-E1 grep patterns). Out-of-scope items pinned (no differential harness; no CI per-hash latency gate; no binary-level `nm` check; no parallel `Cache::derive`). Round 1 supersedes this scaffold's §3 / §5 / §6 / §8 with closed-decision content; the scaffold remains the substrate-capture provenance. |
| Post-closure pin refinements | 2026-05-23 | **Refinements to the post-closure pins** (per `21-reversion-clause-discipline.mdc`'s post-closure-pin discipline; not a Round 4). Six narrow refinements, each tightening a post-closure pin against a substrate observation: **(1) §1.1 pin #2 reversed** — explicit `pub(crate) fn cache_ref(&self) -> &Cache` accessor on `PreparedCache` (the original pin disposition "no accessor; private-field extract" is replaced; the explicit accessor documents the established reach-through shape and prevents a future contributor from re-exposing `Cache`'s API on `PreparedCache` as a convenience). **(2) §4 Round 4 placeholder explicit close** — the F1–F7 enumeration is the threat-model close for Phase 2F; the placeholder is preserved as audit trail per `91-documentation-after-plans.mdc` but is not a queued deliverable. Future findings reopen via substrate-change criteria, not via sequential numbering. **(3) §8 commit-5 prediction-vs-measured discipline** — the impl-PR description must include both the predicted branch (from §8) and the measured branch (from commit 4's `BENCH_RESULTS.md`) with explicit reconciliation ("prediction held" or "prediction wrong because <substrate-anchored reason>"); mirrors the mp-correction discipline from Phase 2c PR-65. **(4) §10.3 layering note** — the shim-side scoped-closure discipline absorbs the API constraint Round 2 §3.1 rejected at the verifier layer; the responsibility moved layers (verifier → shim) rather than disappeared. The (g)-rejection at the verifier and the (g)-style absorption at the shim are the same discipline, applied at the layer where it doesn't constrain the wrong consumers. **(5) §10.4 cfg-gated-additions principle + `TraceSink` trait scope** — explicit statement that cfg-gated test-infrastructure additions are not "tweaks to upstream RandomX" (the discipline applies to consensus-affecting behavior, not bisection convenience); explicit pin that `TraceSink`'s trait surface is Phase 2g's plan-doc scope and lives with the differential harness, not with the verifier's public API. Do not promote `TraceSink` to a public surface. **(6) §10.5 Phase 2g audit posture** — three-leg framing for the "Shekyl's verifier is canonical RandomX v2" claim: (1) spec-faithful implementation discipline; (2) C-reference audit where the spec is silent; (3) differential-harness corpus testing. The load-bearing claim is leg 1; leg 3 is the backstop. Phase 2g's plan-doc inherits this framing explicitly so the audit-posture answer is not "we test against the C reference" alone. No structural changes to Round 2 / Round 3 / post-closure-pin dispositions; only narrower specifications of pre-existing pins. Reopen criteria are substrate-anchored per the named items; none anticipated. |
| Post-closure pins | 2026-05-23 | **Substrate-completeness amendments after Round 3 close** (per `21-reversion-clause-discipline.mdc`: "an under-specification surfaced post-closure does not reopen the round it belonged to but is named explicitly as a post-closure pin"; not a Round 4). Six items, all narrow specifications of what Round 2 / Round 3 already pinned at the architectural level: **(1) §1.1 `Display` impl framing corrected** — the Round 2 "consistency with Phase 2c's existing seedhash-formatting conventions" framing is unsupported by HEAD (verifier crate has no `tracing::` / `log::` / `format!` / hex-rendering of seedhashes; Phase 2c does not establish a seedhash-formatting convention because Phase 2c does not log seedhashes). The lowercase-hex disposition stands (matches `hex::encode` and the cryptographic-output convention); the framing is corrected to "for downstream consumers — FFI shim, daemon-side logging, test diagnostics." **(2) §1.1 dispatch-loop / `Cache` visibility pin** — the `Cache: pub → pub(crate)` Round 2 transition does not affect the dispatch loop's `vm.rs::execute_one` signature (in-crate `cache: &Cache`); `compute_hash` extracts `&prepared.cache` via private-field access; no `cache_ref()` accessor on `PreparedCache` is added. Tests use `pub(crate) Cache::from_raw` per the Phase 2c R0-D6 discipline. **(3) §1.1 `PreparedCache` equality pin** — `PreparedCache` does not derive `PartialEq`. Seedhash equality is via `Seedhash`'s derived `PartialEq` (CacheStore slot indexing); identity comparisons in tests (T-CS-5/7/9) use `Arc::ptr_eq` on `Arc<PreparedCache>`. The absence of the impl forces consumers to use the right primitive at the call site. **(4) §8 commit-5 empirical-conditional pin** — commit 5 (cfg-gate flip) is conditional on the §6.3 A/B bench delta measured at commit 4. Branch C plausible per PR-66's hundreds-of-µs per-call alloc cost; Branch A plausible per `Box::<[u8]>::new_zeroed_slice(2 MiB)` typical tens-of-µs cost on modern allocators. The impl-PR records the actual measured branch with rationale; both predictions produce defensible 2F closes. **(5) §10.3 Phase 3a FFI shim discipline** — pinned that the shim owns the C-side opaque-handle shape, `Seedhash::from_bytes` construction at the boundary, `Arc<PreparedCache>` lifecycle across the boundary, and `VmStatePool::new(capacity)` runtime-parameter derivation from `dev`-tip daemon threadpool source. The verifier crate provides the Rust-side type but does not specify the C-side shape; Phase 3a's plan inherits the disposition rather than re-litigating it. **(6) §10.4 Phase 2g `compute_hash_with_trace` pre-pin** — pre-pinned the option for a `#[cfg(any(test, feature = "differential-trace"))] pub fn compute_hash_with_trace(prepared, data, trace_sink) -> [u8; 32]` test-infrastructure entry point for differential-harness bisection (per-iteration register-file snapshots; not a public-API addition; production build pays no overhead). Phase 2g's plan inherits the option; uses it iff bisection workflow requires per-iteration trace visibility. **No structural changes to Round 2 / Round 3 dispositions**; only narrower specifications. The reopen criteria for the post-closure pins are substrate-anchored per the named items; none are anticipated. |
| Round 3 | 2026-05-23 | **Refinement bundle (closes Round 2's queued sub-details).** Round 2 landed the architectural keystone; Round 3 hardens the dispositions Round 2 left for follow-up. **§3.3 R1-D3 reframed to cfg-gated A/B approach.** The Round 1 (b) Component-method disposition is superseded by a cfg-gated pool approach: the pool body is implemented behind `#[cfg(any(test, feature = "internal-pool-bench"))]` regardless of R1-D4 outcome; the bench harness measures both paths directly (`B-pool-off` always; `B-pool-on` when the feature is enabled). Closes the Round 1 circular-sequencing problem ("can't bench the pool without implementing the pool" → "implement the pool gated for benching, promote to production iff the bench delta clears Decision #7's threshold"). The cfg-gated pool stays in source as the bench-only artifact on Branch A; flips to default-on on Branch C. **§3.4 R1-D4 dissolved into R1-D3.** No separate Round-1 decision exists: the threshold (Decision #7's 100 µs) is a binding source; the Round 1 task is mechanical application of the threshold to the A/B delta from §3.3 Round 3. The §3.4 "Round 1 disposition" becomes a forward pointer to §3.3 + Decision #7 + the §8 Round 3 commit table's Branch A/B/C trichotomy. **§3.5 R1-D5 refined to runtime-configurable capacity.** The Round 1 disposition's pool-capacity-as-compile-time-constant shape is superseded by `VmStatePool::new(capacity: usize)` — a runtime parameter constructed from the Phase 3a FFI shim's threadpool-source-derived value. The Round 1 R1-D5 survey methodology stands; the substrate-anchored value flows into the constructor at runtime rather than getting baked into a `pub(crate) const` at compile time. The default constructor panics in non-test builds to enforce explicit configuration. Closes the Round 1 staleness footgun where a Phase-2F-baked-in capacity could mismatch the Phase 3a daemon configuration. **§3.6 R1-E1 rustfmt-rely-chain note added.** The Round 1 column-0 anchor is robust against function-local statics if and only if `cargo fmt --check` is a CI gate (which it is, per Phase 2c R0-D6). The rustfmt-rely-chain is named explicitly in the §3.6 Round 3 sub-block so future readers don't need to re-derive the soundness condition. **§4 threat model: F1–F7 enumeration** (Round 4 placeholder retained as audit trail; Round 3 supersedes inline). Seven attack classes named with disposition: F1 cache-derivation DoS amplification (closed by canonical non-eviction); F2 Arc-holding memory exhaustion (bounded by capacity-2 + caller-side discipline note); F3 thundering herd on novel-seedhash (closed by in-flight dedup); F4 unbounded HashMap growth (closed by cleanup-on-publish); F5 concurrent-derivation race (covered by determinism property + dedup); F6 mutex contention amplification (addressed by RwLock-per-slot + capacity-2-no-sharding); F7 cache-derivation cost asymmetry (out of scope; upstream daemon-side validation discipline). The enumeration replaces Round 1's three-line threat-model placeholder. **Caller hand-off Arc-lifetime discipline note** added to the CacheStore rustdoc (consumers should hold `Arc<PreparedCache>` only for the duration of the immediate hash computation; long-lived holds extend cache memory residency beyond CacheStore's bound; daemon-side discipline, not a CacheStore enforcement). **§6.1 test plan reshaped to Round-2-typed pre/post table** (T-CS-1..11; in-flight dedup test T-CS-7; cleanup-on-publish white-box test T-CS-8; concurrent-determinism property test T-CS-9; type-shape compile-time checks T-CS-10/11). **§6.3 bench harness reshaped** to B-pool-off / B-pool-on A/B per §3.3 Round 3; component-floor benches (B-2/B-3) retained as cross-check; `BENCH_RESULTS.md` records the A/B delta + Branch disposition. **§8 commit table reshaped** to 6-commit Round-2-+-Round-3 shape: commit 1 = `Seedhash` + `PreparedCache` type sweep; commit 2 = `CacheStore`; commit 3 = invariant grep gate; commit 4 = cfg-gated pool + A/B bench (always); commit 5 = cfg-gate flip (Branch C only); commit 6 = plan close + `CHANGELOG`. The Round 1 5-commit shape's Branch-A-omits-commit-4 / Branch-B-defers-commit-4 / Branch-C-includes-commit-4 trichotomy collapses to "is commit 5 included" rather than "does commit 4 exist." **§3.1 (g) rejection inline at CacheStore rustdoc** so future readers asking "wouldn't this be simpler without two slots?" find the adversarial finding rather than re-proposing the shape. **Adversarial-pass-precedent** named: the (g) → (b) Round 2 reversal is the second documented instance of "adversarial pass reverses an aesthetically-preferred choice" (first: LWMA-1 time-source local-time-only over peer-time-derived). The recurrence justifies promotion to `26-sub-pr-design-discipline.mdc` as a sibling discipline-promotion PR (`chore/sub-pr-design-discipline-adversarial-pass`). **No substrate read of Round 2** — Round 3 builds atop the already-landed Round 2 dispositions. **No outstanding Round-N+1 follow-ups** queued from Round 3; Round 4 (if any future round opens) reopens via the §3.1 / §3.3 / §3.5 substrate-change reopening criteria, not via sequential numbering. |
| Round 2 | 2026-05-23 | **Architectural reframe (load-bearing structural change).** The Round 1 dispositions stand as audit trail; Round 2 supersedes the load-bearing surface where the Phase 2c freeze inherited a consensus-correctness footgun the type system can close. **§1.1 substrate correction.** Phase 2c's `compute_hash(&Cache, &[u8; 32], &[u8]) -> [u8; 32]` shape carries the cache and the seedhash as separate arguments; a caller passing the wrong cache for a given seedhash gets a wrong hash, which is fine for chain integrity (network rejects) but is a footgun the type system can close at zero cost. Round 2 introduces `PreparedCache` (bundles `Cache + Seedhash`), `Seedhash` newtype (replaces the `&[u8; 32]` alias), and amends `compute_hash` to take `&PreparedCache`. `Cache` transitions `pub → pub(crate)`; the public construction path is `PreparedCache::derive`. Per `16-architectural-inheritance.mdc` pre-genesis discount and the cost-benefit-defer-to-later anti-pattern, the substrate correction lands now in Round 2 of Phase 2F's plan-doc rather than in V3.x. **§3.1 R1-D1 + R1-D2 merged disposition.** The single-axis Round 1 question (CacheStore API shape) is layered into a three-axis question post-`PreparedCache`: Axis 1 = where the cache+seedhash binding lives (Round 2 picks `PreparedCache` bundling); Axis 2 = canonical-protection shape (Round 1's (b) reaffirmed; now operates on `Arc<PreparedCache>`); Axis 3 = whether `CacheStore` exists (Round 2 picks (e)/(f) hybrid — thin amortizing layer with explicit two-slot canonical-protection). Rejects (d)/(g) no-CacheStore alternatives for the Arc-holding memory exhaustion attack. **Frozen API code-block updated:** `lookup(&Seedhash) -> Option<Arc<PreparedCache>>`, `lookup_or_derive(&Seedhash) -> Arc<PreparedCache>`, `set_canonical(Arc<PreparedCache>)`. The Round 1 `insert` method is removed (subsumed by `lookup_or_derive`'s on-completion publication). **In-flight derivation deduplication** pinned: `Mutex<HashMap<Seedhash, Shared<DerivationFuture>>>` with cleanup-on-publish; closes the thundering-herd attack surface that applies regardless of Axis 2/3 selection. **Synchronization shape** pinned: per-slot `RwLock<Option<Arc<PreparedCache>>>` (canonical + transient), `Mutex<HashMap>` for in-flight; sharding rejected at capacity-2. **11-row state-transition table** updated to `Arc<PreparedCache>` typing; substantive transitions unchanged (canonical non-evictable; transient displace-on-publish; advance promotes-and-demotes); in-flight-dedup concurrent row added. **Capacity-2 reopen criterion sharpened**: requires named real consumer + sustained operational pattern + measurable cost (not "we might want N someday"). **Transparent-memo framing retired**; parent-plan `RANDOMX_V2_PLAN.md` Decision #6 wording amendment queued as precursor PR `chore/randomx-v2-plan-decision6-amendment` (precedent: Phase 2c F4-absorbed parent-plan rescope). **Reversion clause expanded** to three independent axes (Axis 1: PreparedCache; Axis 2: canonical-protection-in-(b); Axis 3: CacheStore exists), each with substrate-anchored reopening criteria. **§5 hand-off contract** updated: `compute_hash` signature, `Cache` visibility, `CacheStore` API, eviction-policy table, and Round-2 new artifacts (Seedhash newtype, PreparedCache, FFI-shim sweep) supersede the Round 1 freeze items where applicable; Round 1 items not touched by Round 2 (R1-D3 / R1-D4 / R1-D5 / R1-E1) carry forward unchanged. **Seedhash newtype sweep is atomic with its introduction**: every site that currently passes `&[u8; 32]` for a seedhash updates in the same impl-PR commit as the newtype landing — no transitional period. **§10 forward path** updated: 2g and 3a inherit the `PreparedCache` shape; PQC migration space note added (verifier crate is PQC-orthogonal by construction; PQC architectural choices land at Phase 3a's shim layer, not in the verifier). **Round 3 follow-up commit queued** to refine R1-D3 (cfg-gated pool approach), fold R1-D4 into R1-D3, refine R1-D5 (runtime-configurable capacity), and absorb threat-model F1–F7 enumeration + adversarial-pass-precedent note. The Round 2 commit lands the architectural keystone; Round 3 hardens the dispositions. |
| Round 1 | 2026-05-23 | *(Audit trail; superseded by Round 2 where applicable.)* Closed R1-D1 through R1-E1. **R1-D1**: CacheStore picks option (b) explicit two-slot type (`new` / `lookup` / `insert` / `set_canonical`); rejects (a) for caller-discipline burden on the F1 sticky-canonical defense; rejects (c) for over-provisioning (capacity 2 doesn't justify type-stratified composition). Internal sync via `std::sync::Mutex` (no new workspace deps; verified `lru` not in `rust/Cargo.toml`, `parking_lot` only transitive). **R1-D2**: eviction policy falls out of (b) — canonical non-evictable; transient displace-on-insert; `set_canonical` advance promotes-from-transient + demotes-prior; cold-start-window degenerate case bounded to daemon startup and handled by FFI shim's discipline (no fallback policy in CacheStore). 11-row pre/post state-transition table pinned in §3.2 covering 3-seedhash interleave attack, cold-start, advance, no-op cases. **R1-D3**: bench methodology picks option (b) Component method; rejects (a) Diff method because it would require promoting `VmState` to `pub` and adding a `compute_hash_with_state` helper — both contradict §1.1 freeze and Decision #7's no-public-`VmPool` posture; rejects (c) Population method per scaffold's sequencing-cycle note. Component sum measures `Box::<[u8]>::new_zeroed_slice(2 MiB)` + synthetic register-file init (the bench does not consume the production `VmState` newtype to keep visibility clean); sum is a *floor* on per-call alloc cost (excludes register-file struct overhead and field-init cost). **R1-D4**: pool decision threshold confirmed at 100 µs per `RANDOMX_V2_PLAN.md` line 240. Three-band rule: < 50 µs → no pool (Branch A); [50, 100) µs → escalate to impl-PR pre-flight per R1-D3 reversion-clause #1 (Branch B); ≥ 100 µs → pool inside `compute_hash`, no public `VmPool`, capacity from R1-D5 (Branch C). Reversion clauses for the no-pool path: allocator regression (mimalloc/jemalloc swap), scratchpad-size change at consensus level, runtime-architecture mismatch (cross-compile target's allocator differs from CI). **R1-D5**: daemon parallel-verification fanout survey methodology pinned. Audit-against-actual-code per `16-architectural-inheritance.mdc`: read `src/cryptonote_core/blockchain.cpp`, `src/cryptonote_core/tx_pool.cpp`, `src/cryptonote_core/cryptonote_tx_utils.cpp`, `src/common/threadpool.{h,cpp}` at `dev` tip = `fb21909ff`. Substrate correction vs. prompt: only **one** parallel-`compute_hash` call site exists at HEAD — alt-chain branch validation's `block_longhash_worker` via `tools::threadpool::getInstanceForCompute()`, capped by `m_max_prepare_blocks_threads` (default 4). Mempool tx verification (`tx_pool.cpp`, `cryptonote_tx_utils.cpp`, `tx_pqc_verify.cpp`) does **not** call `compute_hash` in parallel — the prompt's two-source assumption was incorrect. Pool capacity formula: `min(threadpool::getInstanceForCompute().get_max_concurrency(), m_max_prepare_blocks_threads) + 1` reserve. Reversion criteria: a future PR introducing `tools::threadpool` + `compute_hash` in tx_pool.cpp / cryptonote_tx_utils.cpp / tx_pqc_verify.cpp; `m_max_prepare_blocks_threads` default change; Phase 3a FFI shim survey reveals new concurrent consumer. **R1-E1**: three-pattern enumeration: pattern A bans imports of `once_cell` / `lazy_static` / `OnceLock` / `LazyLock` (stricter than module-level-static-only — eliminates the disambiguation between module-level and function-local usage by rejecting the import; the crate provably does not need any of these); pattern B bans column-0 `static` declarations (function-local statics live inside fn bodies and are indented, so pattern B does not match them; `const` items are a different keyword and not matched); pattern C bans `#[no_mangle]`, `#[unsafe(no_mangle)]`, `#[export_name`, `#[unsafe(export_name`, and `extern "C" fn` definition form (`extern "C" { fn foo(); }` import blocks consuming an external FFI surface are not matched since they require `fn` *inside* the brace block, not after `"C"`). New script `scripts/ci/check_randomx_crate_invariants.sh` modeled on `check_randomx_fpu_rounding.sh`. CI integration: new `.github/workflows/build.yml` step `enforce RandomX crate-level isolation invariants` sibling to FPU step. Reversion criteria per pattern: stdlib evolution (pattern A successor primitives), genuine large-immutable-shared-state need (pattern B reopen), Decision #5 reversal (pattern C reopen). **Substrate finding at verification.** Pattern C's first draft (anywhere-on-line match) collided with the existing `lib.rs` rustdoc at lines 31–32, which legitimately cites the forbidden tokens (`` `#[no_mangle]` ``, `` `extern "C" fn` ``, `` `#[export_name]` ``) as part of the documented discipline. Disposition: anchor pattern C at column 0 (with optional leading whitespace for attributes indented inside fn bodies) — code attributes start at column 0 modulo indentation, rustdoc lines start with `//!`. Patterns A and B were already `^`-anchored; the inconsistency was specific to pattern C. **Verification at HEAD (post-fix)**: greps return zero hits across `rust/shekyl-pow-randomx/src/` confirming clean baseline. **Plan-doc edits**: §3.1–§3.6 each gain a "Round 1 disposition" sub-block; §5 placeholder superseded by frozen-surface contract (5.1) + in-scope artifact table (5.2) + out-of-scope re-emphasis (5.3); §6 placeholder superseded by 7-row CacheStore unit-test table + 4-row CI-invariant table + 4-row bench-harness table; §8 placeholder superseded by 5-commit table with R1-D4 three-branch conditional (commit 4 omitted/deferred/included per Branch A/B/C). |
