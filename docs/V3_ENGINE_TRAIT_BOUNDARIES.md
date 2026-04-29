# V3 Engine Trait Boundaries (Stage 1)

**Status.** Round 3 of 4–6 design-review rounds (markdown-only,
against `dev`). PR [#20](https://github.com/Shekyl-Foundation/shekyl-core/pull/20)
is the live review surface; each round appends a commit, the PR
absorbs the diff, and the merge to `dev` happens when the spec is
accepted. **No code changes are gated on this document yet.**

- **Round 1 record:** `d387bff1d` (initial draft on this branch);
  content originally landed on `dev` outside the review-round
  workflow as `c0a3b75ec` and was reverted by `3ed7ff2c7` to put the
  spec on the markdown-only PR-review path required by
  [`.cursor/rules/20-rust-vs-cpp-policy.mdc`](../.cursor/rules/20-rust-vs-cpp-policy.mdc).
- **Round 2 record:** `7bd91f402` (substantive revisions: §1.4
  actor-shape discipline, §2.3 `RefreshEngine` collapse to
  producer/driver, §2.5 two-trait `DaemonEngine`, §3.2 async-cascade
  framing, §6.2 deterministic RNG injection).
- **Round 3 record:** the commit landing this state on the chore
  branch; commit message captures the structural gap closures.

**Planned trajectory.** Round 3 closes structural gaps (lifecycle
methods §2.8, concurrency model §3.3, cancellation discipline §3.4,
the trait-surface sweep `&mut self → &self` across §2, per-trait
`RuntimeFailure` error variant in §5, idempotency-column in §4's
async story table, plus the §1.4 / §2.5 / §3.2 refinements from
Round 2 review). Round 4 is framework fill-in — per-method
classification tables (drop-cancellation class, idempotency
conditions), policy pins (`pub(crate)` visibility, mocks-vs-contract,
panic-rustdoc requirement), and a §10 "Out of scope / Deferred"
subsection. Round 5 is acceptance, near-empty outside fallout from
Round 4 review. The "what are we missing" check runs between every
round; the check between Round 3 and Round 4 is framed as *"what
did writing Round 3 surface that we didn't anticipate?"* rather
than *"what general gaps remain?"* The first framing catches
drafting-induced discoveries; the second misses them.

**Round 3 trait-count expansion (within Round 3, pre-commit).**
The "what are we missing" check applied during Round 3 drafting
(not at the round-to-round boundary, but mid-round) surfaced
**EconomicsEngine** as a missing 7th trait. The bug class produced
by economics scattered across consumers (Bugs 2 / 7 / 13 in the
audit findings) and the Component 3 governance / adaptive-burn
mutability story argued for a centralized canonical-derivation
trait surface at V3.0 rather than deferring to Phase 2b alongside
StakeEngine. Round 3 expanded scope from six traits to seven
before the §2 trait-surface sweep committed; surfacing the gap
at this point is dramatically cheaper than landing six and
amending in Round 4. EconomicsEngine ships at V3.0 with a small
canonical-derivation surface; Phase 2b's StakeEngine and V3.x's
ArchivalEngine ship as separate traits that consume EconomicsEngine
for parameters and derived values. See §2.7 for the trait surface;
§9 for the procedural framing of the in-round expansion.

**Scope.** Stage 1 of the staged migration pinned in
[`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md) §*"Engine
architecture: actor model with staged migration from composition"*
(2026-04-27). Stage 1 lands **trait abstractions only** — the
`Engine<S>` composition shape persists, no actor framework
dependency is added, no message-passing protocol is built. The
traits exist so Stage 2+ migrations are mechanical: the implementing
types swap from concrete fields on `Engine<S>` to `kameo` actors
with a thin `ActorRef`-shaped wrapper, and the trait surface itself
does not move.

**Audience.** Anyone writing or reviewing Stage 2/3/4 code in the
future. The trait surface in this document is the contract Stage 4
must preserve.

---

## 1. Charter and non-charter

### 1.1 In charter

- Define seven trait surfaces: `KeyEngine`, `LedgerEngine`,
  `RefreshEngine`, `PendingTxEngine`, `DaemonEngine`,
  `PersistenceEngine`, `EconomicsEngine`.
- Pin per-trait ownership, error model, async story, and the
  invariants that survive the Stage 4 actor cutover.
- Define how `Engine<S>` composes these traits in Stage 1 (concrete
  fields, generic-bounded methods, no `Box<dyn>`).
- Specify the test boundary: which Stage 1 trait shapes unlock a
  fully-mocked `Engine<S>` for `start_refresh` integration coverage.
- Pin migration order so Stage 2 starts with `KeyEngine` against a
  trait surface that already has reviewer agreement.

### 1.2 Out of charter (deferred to later stages)

| Concern | Lands in |
|---|---|
| `kameo` dependency in `Cargo.toml` | Stage 2 (`KeyEngine` migration) |
| Mailbox sizing, backpressure policy, supervision strategy | Stage 2 onwards, per actor |
| Message-type definitions (`enum KeyEngineMsg { ... }`) | Stage 2 onwards, per actor |
| `ActorRef` wiring on `Engine<S>` | Stage 4 (replaces concrete fields) |
| Removal of the outer `Arc<RwLock<Engine<S>>>` at the binary boundary | Stage 4 (Path B decision; coordinated with `shekyl-engine-rpc` cutover) |
| `RefreshSummary::stake_events` going non-zero | Phase 2b (`StakeEngine`; consumes `EconomicsEngine` per §2.7) |
| `StakeEngine` trait surface (per-stake state, FSM, claim/unstake) | Phase 2b — separate trait that *consumes* `EconomicsEngine` for parameters and derived values; not a sub-trait of it (per §2.7's dependency-not-subsumption framing) |
| `ArchivalEngine` trait surface (per-shard state, archival operations) | V3.x — separate trait that consumes `EconomicsEngine` |
| Anonymity-network-coordination trait (Tor/I2P transport for archival queries) | V3.x — currently flagged in §9 as a future-trait candidate; trait shape not designed |
| View-only / hardware-offload `open_*` bodies | V3.0 follow-up; orthogonal |
| Generic `DaemonClient` *implementation* | V3.1 — but its trait shape is pinned here so Stage 1's mocked-`Engine` test surface is not blocked on it |

### 1.3 Why "concrete fields + generic-bounded methods" is the Stage 1 shape

`Box<dyn KeyEngine>` would dispatch through a vtable on every key
operation, which (a) defeats the inlining the secret-handling code
relies on for compile-time auditing of every key access, and (b)
requires `dyn`-safe trait shapes that constrain Stage 4's actor
surface for no Stage 1 win. The alternative — `Engine<S, K, L, E, D, F, R, P>`
with default type parameters and trait-bounded `impl` blocks — keeps
production call sites unchanged (`Engine<SoloSigner>`), keeps the
trait surface free to use generic methods / associated types if Stage
4 needs them, and lets tests substitute mocks per-trait without
touching the rest of the composition.

**The rationale's strength varies across traits** (refined Round 2).
The inlining-for-audit argument is load-bearing at `KeyEngine` —
every key access should inline into a single audited compilation
unit so that the compiler's cross-function analysis sees the entire
secret-handling path. The argument is materially weaker at
`PersistenceEngine::save_prefs`, `LedgerEngine::balance`, or
`EconomicsEngine::current_emission`, where `dyn`-dispatch overhead
is irrelevant and the auditing bar is lower. We choose the same
generic-bounded shape across all seven traits anyway, because (a)
consistency makes the §3 composition section's mental model
uniform, and (b) the cost of generics where they're not
load-bearing is one type parameter and turbofish ergonomics in
tests. Where the rationale is materially stronger or weaker
per-trait, the relevant §2 section says so.

### 1.4 Design discipline: actor-shaped from Stage 1 (new in Round 2)

Every trait method in §2 is shaped as if its implementation were
already a `kameo` actor at Stage 1 — even though the Stage 1
implementing types are concrete in-process structs. This is the
operational expression of Path B (*"Engine binary boundary: pure
message-passing over shared handle"*, 2026-04-27): **let actors be
actors; don't pass the talking stick around between them.**

The discipline test for any trait method:

- ✅ **`&self` + values in / values out** — actor-friendly. The
  Stage 4 implementor sends a message and awaits a reply with the
  same signature; the surface doesn't change.
- ✅ **`&mut self` + values in / values out** — actor-friendly
  *in principle*. The Stage 4 actor's mailbox owns the mutation;
  the message carries the input value, the reply carries the
  output value. **Round 3 policy: §2 traits use `&self` with
  interior mutability instead.** Reason: Stage 4's
  `ActorRef<…>: Clone` cannot satisfy `&mut self` at the
  trait-impl level, because `&mut ActorRef` would preclude the
  cheap-clone-for-concurrent-orchestration pattern Stage 4
  needs. `&self` with interior mutability in Stage 1 implementing
  types (per §2.2 / §2.4 / §2.6 lock-choice rationales) matches
  Stage 4's actor-handle reality. The `&mut self` shape passes
  the talking-stick test conceptually but loses the §3.3
  cross-trait orchestration ergonomics.
- ⚠️ **`&self` + `&mut OtherTrait` parameter** — the trait is
  *passing the talking stick*. The implementor mutates state
  through a reference that, at Stage 4, would have crossed an
  actor boundary. Avoid: shape the method to take or return values
  instead, and let the orchestrator coordinate.
- ⚠️ **Trait method that holds `&OtherTrait` across a long await
  point** — borderline. At Stage 4, `&OtherTrait` is
  `&ActorRef<…>`, which is `Clone + Send + Sync + 'static`; the
  borrow can be cloned to an owned handle internally without cost.
  Acceptable when the borrow is to a trait whose impl is
  guaranteed `Clone + Send + Sync + 'static` (today: `DaemonEngine`
  per §2.5). Not acceptable for `&mut` references to other traits.
- ⚠️ **Trait method takes `Box<dyn …>` or a closure-callback that
  captures other-trait references** — the closure / box is itself
  passing the talking stick under syntactic cover. Avoid.
- ⚠️ **Trait method returns a handle whose own methods reopen
  mutable access to other-trait state** — e.g., a hypothetical
  `RefreshEngine::start_scan(...) -> ScanInProgress` whose
  `await_next_block()` method secretly calls into the ledger. The
  builder pattern hides the talking-stick handoff inside the
  returned type's method surface. Avoid.

**Underlying principle (Round 3).** *The talking-stick smell is
fundamentally about who owns the mutation.* If the trait method's
caller has to provide mutable access — directly via
`&mut OtherTrait`, indirectly via a callback that captures
`&mut OtherTrait`, indirectly via a returned handle whose methods
reopen mutable access, indirectly via any other syntactic shape —
the trait is passing the stick. The bullets above catch the
surface cases; the principle catches the subtler ones. Round 3+
reviewers should apply the principle, not just the syntactic
check, because Stage 4 actor implementations have no "implicit
talking stick" path: every cross-actor mutation is an explicit
message, and the trait shape that admits an implicit stick handoff
is the trait shape that breaks at Stage 4.

**Return-value discipline (Round 3).** Trait method return values
that survive past the call frame (stored in a struct, joined into
a future, sent to another task) must be `Send + 'static` — no
borrows on `Self`'s internal state. At Stage 4, returns that
borrow internal state cannot cross the actor boundary because the
data is owned by the actor, not by the caller; the actor has no
stable address from which to vend a borrow. Stage 4 implementations
satisfy the bound by cloning or `Arc`-wrapping internal state
before returning; the trait surface should make the requirement
visible at declaration time. Examples in §2: `LedgerEngine::snapshot()`
returns an owned `LedgerSnapshot`, not `&LedgerSnapshot`;
`KeyEngine::account_public_address()` returns
`&AccountPublicAddress` only because the address is read-only and
stable for the engine's lifetime — at Stage 4 the actor vends a
static `Arc<AccountPublicAddress>` whose `&` reference is
`Send + 'static` for the engine's lifetime. References that don't
satisfy this property (transient, internal-state-borrowing, or
mutation-implying borrows) cannot appear in returns.

Stage 4 makes the discipline operational: an `&self` trait method
against a `kameo` actor is a `tell`/`ask`-shaped message
round-trip; an `&mut OtherTrait` parameter has no Stage-4
equivalent; a return that borrows internal state has no Stage-4
representation across the actor boundary.

**Applying the test to §2's traits.** `KeyEngine`, `LedgerEngine`,
`PendingTxEngine`, `DaemonEngine`, `PersistenceEngine`,
`EconomicsEngine` clear the test trivially (values in, values
out). `RefreshEngine` clears it via the §2.3 design — owned
`LedgerSnapshot` in, owned `ScanResult` out, `&D: DaemonEngine`
held across the scan await but the trait's
`Clone + Send + Sync + 'static` bound makes the borrow
Stage-4-equivalent to a cloned `ActorRef<DaemonActor>`. The
snapshot-merge-with-retry loop lives on `Engine<S>` (the
orchestrator), not on `RefreshEngine`, because the loop needs both
ledger and refresh — a trait method that took `&mut LedgerEngine`
to drive merging would fail the test.

This discipline is the design lens for Stage 1 traits. Round 3+
reviewers should apply it to any new method proposed for any
trait; any "passing the talking stick" smell is grounds for
re-shaping the method or splitting orchestration off into
`Engine<S>`.

---

## 2. The seven traits (Stage 1 surface, pinned for Stage 4)

Every trait below states three things the Stage 4 cutover must
preserve:

1. **Ownership** — what state the implementor owns exclusively.
2. **Surface** — methods, signatures, async-ness, error type.
3. **Invariant** — the Stage 4 implementor (a `kameo` actor)
   preserves the trait surface verbatim. New methods may be added;
   existing methods may not change signature without a new design
   round.

**Round 3 — `&mut self` → `&self` sweep across §2.** Originally
some trait methods took `&mut self` (`LedgerEngine::apply_scan_result`,
`PendingTxEngine::build` / `submit` / `discard`,
`PersistenceEngine::rotate_password`); Round 3 revises them all to
`&self`. The sweep is uniform across the §2 surface; the
implementing-type changes per trait (which fields go behind locks;
`Mutex` vs `RwLock` choice) are documented per-trait in the
relevant subsection. `KeyEngine`, `RefreshEngine`, `DaemonEngine`,
and `EconomicsEngine` were already `&self`-only and have no
trait-surface change in this sweep; their per-trait sections note
the no-op explicitly.

*Rationale.* Stage 4's `ActorRef<Actor>` is `Clone + Send + Sync +
'static`. A trait method that takes `&mut self` requires the
caller to hold `&mut ActorRef`, which precludes the
cheap-clone-for-concurrent-orchestration pattern Stage 4 needs:
the orchestrator on `Engine<S>` (the Engine actor itself, at
Stage 4) issues messages to multiple actor handles concurrently,
which requires `&self` access to the handles, which requires
`&self` on the trait methods. `&self` with interior mutability in
Stage 1 implementing types — `RwLock<LedgerState>` for
`LocalLedger`, `Mutex<ReservationTracker>` for `LocalPendingTx`,
`Mutex<WalletFileState>` for `WalletFile` — matches Stage 4's
actor-handle reality. The borrow-checker enforcement that
compile-time `&mut` provided at Stage 1 moves to runtime via the
interior locks; Stage 4's mailbox replaces those runtime locks
with message FIFO. Round 3 is a uniform shift across stages, not
a Stage-4-only concern.

*Stage 1 cost.* The interior locks are redundant against the
outer `Arc<RwLock<Engine<S>>>` lock today (per §3.3's
over-serialization framing). The redundancy is bounded — one
extra lock acquisition per call — and the Stage 1 → Stage 4
transition is a no-op for this concern (the redundancy
disappears when the outer lock retires at Path B).

### 2.1 `KeyEngine`

**Ownership.** The full `AllKeysBlob`: spend secret, view secret,
ML-KEM-768 decap key, and the cached classical / PQC public keys.
No other actor sees raw key material in Stage 4; key access goes
through this trait surface only. **The §1.3 inlining-for-audit
rationale is at its strongest here**: every key operation should
inline into one audited compilation unit.

**Stage 1 surface.**

```rust
pub trait KeyEngine {
    type Error: Into<KeyError>;

    /// Public address material for this engine's account. Cheap;
    /// does not touch secrets. Stable for the wallet's lifetime.
    fn account_public_address(&self) -> &AccountPublicAddress;

    /// Sign an Ed25519 challenge with the spend secret. The
    /// `domain` argument selects the HKDF context (output-secret
    /// derivation, multisig witness, etc.) so this trait cannot
    /// be coerced into a generic signing oracle.
    async fn sign_with_spend(
        &self,
        domain: SignDomain,
        message: &[u8],
    ) -> Result<Ed25519Signature, Self::Error>;

    /// Compute the view-side ECDH shared secret for an output's
    /// transaction-key. Used by the scanner; never returns the
    /// raw view scalar.
    async fn view_ecdh(
        &self,
        tx_pub_key: &EdwardsPoint,
    ) -> Result<SharedSecret, Self::Error>;

    /// ML-KEM-768 decapsulate against an incoming output's
    /// encapsulated key. Returns the shared secret only; the
    /// decap key itself does not leave the implementor.
    async fn ml_kem_decapsulate(
        &self,
        enc_key: &MlKemEncapsulation,
    ) -> Result<MlKemSharedSecret, Self::Error>;

    /// Derive a subaddress public-key triple. Pure derivation;
    /// reads the view secret but produces only public material.
    fn derive_subaddress_public(
        &self,
        index: SubaddressIndex,
    ) -> Result<SubaddressPublic, Self::Error>;
}
```

**Round 2 dispositions.**

- **Q9.1 (signing async-ness): closed.** `sign_with_spend`,
  `view_ecdh`, `ml_kem_decapsulate` are `async fn`. Stage 1
  implementations against `AllKeysBlob` are pure-CPU and return
  ready futures; Stage 4 actor implementations cross a task
  boundary. The trait is async to avoid breaking the surface at
  Stage 4. Pure-derivation methods (`account_public_address`,
  `derive_subaddress_public`) stay sync — they don't touch a
  task boundary even at Stage 4.
- **Q9.2 (`SignDomain` enumeration): closed `#[non_exhaustive]`.**
  V3.0 enumerates the four current domains (output-secret
  derivation, transaction signature, FCMP++ witness, ml-kem
  challenge); Stage 4 adds multisig witness / partial signature
  variants additively without re-opening the trait.
- **Q9.3 (explicit `wipe()` method): closed no.** `AllKeysBlob:
  ZeroizeOnDrop`; the Stage 4 actor's `Drop` inherits the wipe.
  The trait contract is "the implementor zeroizes on drop and on
  process-explicit lock"; no method is needed.

### 2.2 `LedgerEngine`

**Ownership.** `WalletLedger` (the persistent ledger),
`LedgerIndexes` (the runtime-only derived indexes rebuilt at every
open per the *RuntimeWalletState audit* decision-log entry,
2026-04-25), and the runtime-only `BTreeMap<ReservationId,
Reservation>` reservation tracker.

**Stage 1 surface.**

```rust
pub trait LedgerEngine {
    type Error: Into<LedgerError>;

    fn synced_height(&self) -> u64;
    fn snapshot(&self) -> LedgerSnapshot;
    fn balance(&self, filter: BalanceFilter) -> Balance;
    fn transfers(&self, filter: TransferFilter) -> Vec<TransferDetails>;

    /// Apply a producer-emitted `ScanResult`. Returns
    /// `RefreshError::ConcurrentMutation` iff the scan result's
    /// `start_height` no longer matches `synced_height + 1`
    /// (somebody else merged between the snapshot and now); the
    /// refresh driver retries with a fresh snapshot.
    async fn apply_scan_result(
        &self,
        scan_result: ScanResult,
    ) -> Result<(), RefreshError>;
}
```

**Stage 1 implementing-type note (Round 3).** `LocalLedger` (the
default Stage 1 type) holds `RwLock<LedgerState>` for interior
mutability. `apply_scan_result(&self, …)` acquires the write lock
internally; `synced_height`, `snapshot`, `balance`, `transfers`
acquire the read lock. The choice is `RwLock` (not `Mutex`)
because `LedgerEngine` has many readers and one writer (read
methods outnumber `apply_scan_result` calls by a wide margin in
production, and at Stage 4 the same pattern holds — many concurrent
readers of `Arc<LedgerSnapshot>` against one mutating actor
handler). The Stage 1 `RwLock` is redundant against the outer
`Arc<RwLock<Engine<S>>>` lock today (per §3.3's Stage-1
over-serialization framing), but the redundancy is bounded — one
extra lock acquisition per call — and the borrow-checker
enforcement that the redundancy replaces moves to runtime, which
is exactly where Stage 4's mailbox puts it. Stage 1 → Stage 4
transition is a no-op for this concern.

**Round 3 disposition (the &mut → & sweep).** Originally `&mut
self`; revised to `&self` because Stage 4's `ActorRef<LedgerActor>`
implementation cannot satisfy `&mut self` (`ActorRef` is `Clone`,
the mailbox handles mutation, holding `&mut ActorRef` would
preclude the cheap-clone-for-concurrent-orchestration pattern that
Stage 4 needs). The `&self` shape with interior mutability matches
Stage 4's actor-handle reality and works at Stage 1 with
`RwLock<LedgerState>`. See §2's Round 3 note on the trait-surface
sweep for the full rationale.

**Round 2 dispositions.**

- **Q9.4 (`snapshot()` location): closed on `LedgerEngine`.** It's
  a read against ledger state; the loop using it is the
  orchestrator's concern (§2.3, §7).
- **Q9.5 (cross-trait `RefreshError` on `apply_scan_result`):
  closed keep, with explicit justification.** The
  `ConcurrentMutation` variant is the contract signal between
  ledger and refresh — "another writer interleaved between your
  snapshot and your merge; retry with a fresh snapshot." Putting
  that variant on a `LedgerError` family would hide a refresh-loop
  concern under a ledger error type; the orchestrator (on `Engine`)
  needs to discriminate this case from terminal ledger errors.
  Explicit cross-trait error type for an explicit cross-trait
  contract.
- **Q9.13 (mutations async at Stage 1): closed yes for mutations,
  reads stay sync.** Refined from the Round 1 framing. Reads
  (`synced_height`, `snapshot`, `balance`, `transfers`) stay sync
  because Stage 4 implements them via an `Arc<LedgerSnapshot>` the
  actor publishes — readers dereference without queueing on the
  mailbox. Mutations (`apply_scan_result`) are async because
  Stage 4 mutations route through the mailbox and are
  intrinsically async; making them async at Stage 1 locks the
  Stage 4 surface verbatim.

### 2.3 `RefreshEngine` (revised in Round 2)

**Reframed in Round 2.** Originally proposed as the public refresh
surface (`start`, `refresh_once`); revised to cover only the
producer/driver primitive. The orchestration that wraps `Self`,
owns the slot, drives the retry loop, and observes the
inter-attempt cancellation checkpoints stays as **inherent methods
on `Engine<S>`** (`Engine::start_refresh`, `Engine::refresh`).

Reasons (collapsing what were Q9.6 and Q9.7 into one resolution):

- **Orchestration is plumbing; the trait is contract.**
  `start_refresh` wraps `Self` (today `Arc<RwLock<Engine>>`,
  Stage 4 actor messaging), spawns the task, builds the
  cancellation/progress channels. None of that is the producer's
  contract; all of it changes between Stage 1 and Stage 4. The
  trait should not name the sharing mechanism.
- **Q9.6 (single trait or split) and Q9.7 (sharing mechanism)
  dissolve under this shape.** Stage 4's eventual horizontal-
  scaling target (`BlockScannerActor` worker pool per the
  architecture decision-log entry) lines up with this trait
  directly: a producer pool serves the orchestrator's spawn
  requests.
- **Cancellation checkpoints split between trait and orchestrator,
  and the split is part of the contract.** §7 invariant 4 makes
  the split explicit.

**Ownership.** The producer logic (`produce_scan_result`'s body,
the four-checkpoint cancellation discipline within it, the scanner
construction). Does **not** own the slot, the retry loop, or the
inter-attempt cancellation observation — those live on `Engine<S>`.

**Stage 1 surface.**

```rust
pub trait RefreshEngine {
    type Error: Into<RefreshError>;

    /// Produce a `ScanResult` against the given ledger snapshot
    /// and daemon. Owns cancellation checkpoints **2** (post-tip-
    /// fetch) and **3** (mid-scan, between blocks); returns
    /// `RefreshError::Cancelled` on observation. Checkpoints 1
    /// (top-of-attempt) and 4 (pre-merge) are observed by the
    /// orchestrator on `Engine<S>`, not here.
    ///
    /// `daemon` is borrowed for the duration of one attempt. The
    /// `&D` borrow lives only for this call; if the implementor
    /// needs an owned handle to move into a spawned future (e.g.,
    /// the parallel block-fetch a future scaling refinement might
    /// add), it clones internally. The §2.5
    /// `Clone + Send + Sync + 'static` bound on `D` makes this
    /// cheap and Stage-4-actor-compatible
    /// (`ActorRef<DaemonActor>` clones in O(1)). Implementors
    /// MUST NOT borrow `&D` across a `tokio::spawn` boundary; the
    /// borrow-then-spawn pattern would hold the caller's reference
    /// past the call frame, which fails the §1.4 return-value
    /// discipline at Stage 4.
    async fn produce_scan_result<D: DaemonEngine>(
        &self,
        snapshot: LedgerSnapshot,
        daemon: &D,
        opts: &RefreshOptions,
        cancel: &CancellationToken,
        progress: &watch::Sender<RefreshProgress>,
    ) -> Result<ScanResult, Self::Error>;
}
```

The orchestration layer (`Engine::start_refresh` async, sync
`Engine::refresh` for sync callers) drives the loop:

```rust
// Sketch of the orchestration body — not part of the trait surface.
loop {
    cancel.check_cancelled()?;          // checkpoint 1: top-of-attempt
    let snapshot = self.ledger.snapshot();
    let daemon = self.daemon.clone();
    drop(read_lock);

    let scan_result = self
        .refresh
        .produce_scan_result(snapshot, &daemon, opts, &cancel, &progress)
        .await?;
    // checkpoints 2 and 3 observed inside produce_scan_result.

    cancel.check_cancelled()?;          // checkpoint 4: pre-merge
    match self.ledger.apply_scan_result(scan_result).await {
        Ok(())                                   => return Ok(summary),
        Err(RefreshError::ConcurrentMutation)    => continue,
        Err(other)                                => return Err(other),
    }
}
```

**Borrow-checking story.** This shape sidesteps the original Q9.7
problem cleanly. The producer takes:

- An owned `LedgerSnapshot` (cheap clone of reorg-window
  descriptors; not a borrow on the ledger).
- A borrowed `&D: DaemonEngine` (lives for one attempt; the
  implementor clones internally if it needs an owned handle).
- Borrowed cancel/progress channels.

No `&mut LedgerEngine` is held anywhere on the trait surface
(per Round 3's §2 sweep: all trait methods are `&self` with
interior mutability in implementing types). The orchestrator
holds `&LedgerEngine` for the brief snapshot read and the brief
merge call; both calls acquire the implementing type's internal
lock for the duration of one method invocation. No long-held
borrow across the unlocked scan phase, no caller-provided
mutation handle, no talking-stick handoff — exactly the discipline
§1.4 enforces, now expressed at the trait boundary.

### 2.4 `PendingTxEngine`

**Ownership.** The reservation tracker (`BTreeMap<ReservationId,
Reservation>`), the monotonic `next_reservation_id` counter, and
the two-phase build/submit/discard state machine pinned in the
*Pending-tx protocol* decision-log entry (2026-04-27).

**Stage 1 surface.**

```rust
pub trait PendingTxEngine {
    type Error: Into<PendingTxError>;

    async fn build(
        &self,
        request: TxRequest,
    ) -> Result<PendingTx, SendError>;

    async fn submit(
        &self,
        id: ReservationId,
    ) -> Result<TxHash, Self::Error>;

    async fn discard(
        &self,
        id: ReservationId,
    ) -> Result<(), Self::Error>;

    fn outstanding(&self) -> usize;
}
```

**Stage 1 implementing-type note (Round 3).** `LocalPendingTx`
holds `Mutex<ReservationTracker>` for interior mutability. All
mutating calls (`build`, `submit`, `discard`) acquire the mutex
internally; `outstanding` reads through the mutex briefly. The
choice is `Mutex` (not `RwLock`) because `PendingTxEngine`'s
operations are predominantly write-style — even `outstanding` is a
read against state that mutates on every other call, so the
many-readers-one-writer pattern that justified `RwLock` for
`LedgerEngine` does not apply here. Stage 4's `ActorRef<PendingTxActor>`
provides equivalent serialization through its mailbox.

**Round 3 disposition (the &mut → & sweep).** Originally `&mut
self` on `build`, `submit`, `discard`; revised to `&self` per the
Round 3 trait-surface sweep. Same rationale as §2.2's
`apply_scan_result` change: Stage 4's `ActorRef<…>` cannot satisfy
`&mut self`. Interior mutability in `LocalPendingTx` (the Stage 1
type) replaces compile-time borrow checking with runtime mutex
serialization; Stage 4's mailbox replaces the runtime mutex with
message FIFO. The trait surface is identical across both stages.

**Round 2 dispositions.**

- **Q9.8 (`build` returns `SendError` vs. `Self::Error`): closed
  keep `SendError`.** The split exists today because `SendError`
  covers build-time validation (insufficient funds, no spendable
  outputs); `PendingTxError` covers runtime invariants. The two
  vocabularies are distinct domains; collapsing them would force
  callers to discriminate by variant rather than by error type.
- **Q9.9 (V3.1 multisig methods inclusion): closed not in Stage 1
  surface; additive at Stage 4.** `inspect`, `adjust_fee`,
  `sign_partial` from the *Pending-tx protocol* decision-log entry
  are V3.1+ multisig concerns; Stage 4's actor-shaped trait
  implementation can add them without re-opening the §2.4 surface.

### 2.5 `DaemonEngine` (revised in Round 2)

**Reframed in Round 2.** Originally proposed as a single trait
folding wallet-side methods into `shekyl_rpc::Rpc`; revised to a
two-trait shape that respects the upstream/downstream boundary.
`Rpc` lives in `shekyl-oxide` (the vendored upstream fork tracking
`monero-oxide`); adding wallet-specific methods to it would either
modify upstream-vendored code (increasing divergence pressure on
the canary tracked in [`docs/CI_BASELINE.md`](CI_BASELINE.md)) or
be defined as an extension trait — which *is* the two-trait shape
under a different name.

**Ownership.** The RPC client (today: `SimpleRequestRpc` wrapped
in `DaemonClient`), connection state, retry policy.

**Stage 1 surface.**

```rust
pub trait DaemonEngine: shekyl_rpc::Rpc + Clone + Send + Sync + 'static {
    type Error: Into<IoError>;

    async fn get_fee_estimates(&self) -> Result<FeeEstimates, Self::Error>;
    async fn submit_transaction(
        &self,
        tx_bytes: Vec<u8>,
    ) -> Result<TxSubmitOutcome, Self::Error>;
}
```

`DaemonEngine` is a supertrait extension of `Rpc`. Any
`DaemonEngine` impl is also an `Rpc` impl, so the producer/scanner
code that uses `Rpc` methods (`get_height`,
`get_scannable_block_by_number`) gets them through this constraint
without re-importing. The wallet-specific methods
(`get_fee_estimates`, `submit_transaction`) live on `DaemonEngine`
itself, never on `Rpc`. `MockRpc` already implements `Rpc`; tests
add `impl DaemonEngine for MockRpc` with the two extra methods.

**Why `Clone + Send + Sync + 'static`** — same as Round 1: the
daemon handle is shared by clone with the producer task in
`run_refresh_task`'s `tokio::spawn`'d future. Bound holds for
`DaemonClient`/`SimpleRequestRpc` already; Stage-4-actor-compatible
(`ActorRef<DaemonActor>` satisfies the bound).

**Stage 4 framing (per §1.4).** At Stage 4, `DaemonEngine` is
implemented by an `ActorRef<DaemonActor>`; the trait's async
methods are message round-trips against that actor. Stage 1
implementations are direct in-process calls against
`DaemonClient`; the surface is identical. Callers (`Engine<S>`'s
orchestration, `RefreshEngine::produce_scan_result`,
`PendingTxEngine::submit`) bind against the trait, not against the
concrete type, so Stage 4 swaps the implementor without touching
call sites.

**Stage 4 glue-layer cost (Round 3).** Implementing `Rpc` for
`ActorRef<DaemonActor>` is mechanical but non-trivial. Every
`Rpc` method in upstream `shekyl-oxide` requires:

1. A corresponding message variant on `DaemonActor` (e.g.,
   `enum DaemonMsg { GetHeight { reply: oneshot::Sender<…> }, …
   }`).
2. A handler on `DaemonActor` that dispatches to the wrapped
   `DaemonClient`.
3. Error mapping — `DaemonClient`'s error type is upstream-shaped;
   the actor's reply type may need to remap into Shekyl-shaped
   error variants where the wallet has its own error vocabulary.

`Rpc` currently exposes ~10 methods (block fetch, height query,
output fetch, mempool query, etc.); the glue layer is roughly
that many message variants + that many handlers + per-variant
error mapping. The work is paid once at Stage 4 and is the price
of preserving the upstream/downstream boundary (vs. absorbing
wallet methods into upstream-vendored code, which would increase
divergence pressure on the canary). Equivalent to §3.2's
async-cascade framing: cost paid once in service of long-term
boundary discipline.

**Operational link with the divergence canary (Round 3).** New
upstream `Rpc` methods entering `shekyl-oxide` via a divergence
sync (per [`docs/CI_BASELINE.md`](CI_BASELINE.md)) require
corresponding `DaemonActor` glue-layer additions before Stage 4
can absorb them. The Track-0d spot-check policy gains a check
item:

> *Did the upstream sync window add new `Rpc` methods? If yes,
> the `DaemonActor` glue layer needs corresponding message variants
> and handlers as a Stage-4 follow-up before the next divergence
> sync can land cleanly.*

This is a bidirectional cross-doc reference: the trait spec
acknowledges its operational tail; the canary policy gains a
concrete additional check the spot-check operator runs against
upstream `Rpc` trait diffs.

**Round 2 dispositions.**

- **Q9.10 (`DaemonEngine` shape): closed two-trait supertrait.**
  The upstream/downstream boundary argument is decisive:
  `shekyl-oxide` should not absorb wallet-specific methods. The
  "two mocks" cost the original framing was avoiding doesn't
  actually exist — it's two extra method impls on one mock, which
  is what we'd write anyway.

This closes [`docs/FOLLOWUPS.md`](FOLLOWUPS.md) "Generic
`DaemonClient`" *in spec*; the implementation lands in V3.1 per
the existing follow-up.

### 2.6 `PersistenceEngine`

**Ownership.** The `WalletFile` handle, advisory lock on
`<base>.keys`, KEK rewrap on password rotation, atomic file writes.

**Stage 1 surface.**

```rust
pub trait PersistenceEngine {
    type Error: Into<OpenError>;

    fn base_path(&self) -> &Path;
    fn network(&self) -> Network;
    fn capability(&self) -> Capability;

    async fn save_state(
        &self,
        ledger: &WalletLedger,
    ) -> Result<(), Self::Error>;

    async fn save_prefs(
        &self,
        prefs: &WalletPrefs,
    ) -> Result<(), Self::Error>;

    async fn rotate_password(
        &self,
        old: &Credentials<'_>,
        new: &Credentials<'_>,
        new_kdf: KdfParams,
    ) -> Result<(), Self::Error>;
}
```

**Stage 1 implementing-type note (Round 3).** `WalletFile` (the
default Stage 1 type) holds two distinct categories of state:

1. **Immutable cached metadata** — `base_path`, `network`,
   `capability`. Set at construction; never mutated. Reads are
   lock-free; the field types support `&` access without
   coordination.
2. **Mutable file state** — the KEK rewrap state and the
   atomic-write coordination for `save_state` / `save_prefs` /
   `rotate_password`. Held behind `Mutex<WalletFileState>`. All
   mutating async methods acquire the mutex internally.

The choice is `Mutex` (not `RwLock`) because the mutable state's
read pattern is "read and immediately mutate" (KEK rotation reads
the current KEK and replaces it), not "many concurrent readers,
occasional writer." `Mutex` is the right primitive for that
access pattern; `RwLock` would add complexity without benefit.

**Round 3 disposition (the &mut → & sweep).** Originally `&mut
self` on `rotate_password`; revised to `&self` per the Round 3
trait-surface sweep. Same rationale as §2.2 and §2.4: Stage 4's
`ActorRef<PersistenceActor>` cannot satisfy `&mut self`. Interior
mutability via `Mutex<WalletFileState>` replaces compile-time
borrow checking; Stage 4's mailbox replaces the mutex.

**Round 2 disposition.**

- **Q9.11 (`load_state()` method): closed no.** Loading is
  exclusively a one-shot at construction (lifecycle constructors:
  `Engine::create`, `Engine::open_full`, `Engine::open_view_only`,
  `Engine::open_hardware_offload`). Those run before any trait
  surface is in scope and stay as inherent constructors on
  `Engine<S>`. The trait covers the ongoing save/rotate surface
  only. See §2.8 for the full lifecycle treatment.

### 2.7 `EconomicsEngine` (new in Round 3)

**Why a separate trait surface.** The audit findings on the V2
codebase (Bugs 2, 7, 13) trace to different code paths computing
the same conceptual derived value differently — the bug class
produced by *canonical derivation* of economic values being
scattered across consumer sites. Bug 2 wasn't different
parameter sources (both code paths read the same lock-tier
multipliers); it was different applications of those parameters
in different sites, producing two computations of
`total_weighted_stake` that disagreed. Centralizing the
*canonical-derivation surface* in a trait creates a single
source of truth for derived values; consumers call into the
trait rather than re-deriving locally.

The Component 3 governance / adaptive-burn design (V3.x)
compounds the scattered-derivation risk: parameters become
mutable, every consumer needs to re-read after parameter
changes, and any consumer that caches a derivation locally
drifts from the authoritative value. The V3.0 shape pre-empts
this by putting the canonical-derivation surface on a trait
whose Stage 4 implementation owns the (possibly stateful)
derivation.

**Ownership.** The static economics parameters (lock tier
multipliers, base burn rate, ESF, release bounds, pool-share
constants, emission-decay constants) and the canonical
derivations of values from those parameters and from chain
state (current emission, burn fraction for a given fee,
pool-weighted stake total). At V3.0 these are pure functions
over `shekyl-economics` constants; at V3.x Component 3 they
gain internal state for adaptive-burn observation, but the
trait surface is unchanged.

`EconomicsEngine` does **not** own per-stake state (that's
Phase 2b's `StakeEngine`, a separate trait that consumes
`EconomicsEngine`), per-archival-shard state (V3.x's
`ArchivalEngine`, similarly separate), or any state machines.
The trait is canonical-derivation only.

**Stage 1 surface.**

```rust
pub trait EconomicsEngine {
    type Error: Into<EconomicsError>;

    /// Per-block emission at the given height. Reads from
    /// chain-state-derived parameters; pure given the height
    /// at V3.0; at V3.x with adaptive burn the value depends
    /// on the implementor's observed activity state but the
    /// caller's interface does not change.
    fn current_emission(&self, height: u64) -> Result<u64, Self::Error>;

    /// Burn fraction for a transaction with the given fee at
    /// the activity metric reported by the caller (or, at
    /// V3.x, observed by the implementor). Pure given the
    /// inputs at V3.0; stateful at V3.x with the surface
    /// preserved.
    fn burn_fraction(
        &self,
        fee: u64,
        activity: ActivityMetric,
    ) -> Result<u64, Self::Error>;

    /// Total weighted stake across the principal pool,
    /// computed canonically from current pool state. `u128`
    /// per the audit Bug 7 fix that promoted aggregation
    /// arithmetic to `u128` to prevent overflow at large
    /// pool sizes.
    fn pool_weighted_total(&self) -> u128;

    /// Parameter snapshot for governance / display. At V3.0
    /// the snapshot is constants-derived and stable; at V3.x
    /// Component 3 the snapshot reflects the current
    /// adaptive-burn state.
    fn parameters_snapshot(&self) -> EconomicsParametersSnapshot;
}
```

Four methods at V3.0; small surface. All reads, all idempotent
(per §4's idempotency column), all sync (no actor mailbox at
V3.0; no async cascade). Phase 2b's `StakeEngine` and V3.x's
`ArchivalEngine` consume these methods; they don't extend
`EconomicsEngine`.

**Stage 1 implementing-type note.** `LocalEconomics` is the
V3.0 default. It holds **no mutable state at V3.0**: methods
are pure-function wrappers around `shekyl-economics` constants
and caller-provided inputs. At V3.x with Component 3
adaptive-burn, `LocalEconomics` gains
`Mutex<AdaptiveBurnState>` (or `RwLock` if read-heavy access
patterns surface) for observed-activity tracking; the trait
surface is unchanged across V3.0 and V3.x. At Stage 4,
`EconomicsActor` owns the state; queries route through the
actor mailbox. The Stage 1 → Stage 4 transition preserves the
surface verbatim per §7's invariants.

**Why a leaf in the spawn graph.** `EconomicsEngine` has no
inter-engine dependencies for state hydration: parameters are
constants; derived values are functions of parameters and
call-time inputs (height, fee, activity). At V3.x with
adaptive burn, the implementor's internal state derives from
chain state observed via the wallet's existing `LedgerEngine`
or `DaemonEngine` *call sites*, not from in-process state
ownership — the wallet feeds the economics actor activity
observations as input to its derivations. The §2.8 spawn
graph's Group A (independent) gains `EconomicsEngine` alongside
`DaemonEngine` and `PersistenceEngine`.

**Future extension (Phase 2b, V3.x): consumers, not subsumes.**
`StakeEngine` (Phase 2b) and `ArchivalEngine` (V3.x) are
separate traits that consume `EconomicsEngine`:

- `StakeEngine::projected_yield(stake, horizon)` calls
  `EconomicsEngine::pool_weighted_total()` to get the pool
  denominator and reads stake's lock-tier multiplier from
  `EconomicsEngine::parameters_snapshot()` to compute the
  yield. The canonical derivation lives on `EconomicsEngine`;
  `StakeEngine` composes it with per-stake state.
- `ArchivalEngine::archival_yield_history()` reads yield-rate
  parameters from `EconomicsEngine::parameters_snapshot()`
  and composes them with per-shard archival state.

The relationship is *dependency, not inheritance*:
`StakeEngine` and `ArchivalEngine` depend on `EconomicsEngine`
for canonical derivation; neither subsumes `EconomicsEngine`,
and `EconomicsEngine` does not subsume them. This matches the
existing six-trait pattern (e.g., `RefreshEngine` consumes
both `LedgerEngine` and `DaemonEngine` but is not a sub-trait
of either) and avoids the supertrait-composition complexity
that a sub-trait approach would require at Stage 4 (each
sub-trait would need its own actor with an aggregator/router
on the supertrait, which is a kameo-foreign pattern with
manual glue layer cost).

The dependency relationship also preserves the actor-topology
discipline pinned by the *Sibling actors with separate slashing
state* decision-log entry (2026-04-27): `StakeEngine` and
`ArchivalEngine` remain sibling actors at Stage 4 with
separate state ownership and separate failure-isolation
boundaries, even as both consume `EconomicsEngine`'s
canonical derivation surface. The unification is at the
*consumed-trait* layer; the state-ownership / actor-topology
layer keeps the existing sibling-actor model.

**Discipline test for new methods on `EconomicsEngine`.** New
methods proposed for this trait must satisfy:

1. **Read-only from caller's perspective** — no mutation
   visible across the call boundary.
2. **Canonical derivation from parameters and / or chain
   state** — the method's return value should be uniquely
   determined by economic parameters plus call-time inputs;
   no per-entity state.
3. **No per-entity state** — per-stake records, per-shard
   tracking, per-account economic history all live on
   `StakeEngine` / `ArchivalEngine` / `LedgerEngine`, not
   here.

This discipline prevents `EconomicsEngine` from accreting
domain-specific state (per-stake, per-shard,
per-archival-portfolio) that would defeat the
dependency-not-subsumption shape and re-introduce the Bug 2 /
7 / 13 class via "this method combines economics with
X-specific state" surface pollution. Reviewers proposing
methods that fail any of the three criteria should re-target
the proposal to whichever consuming trait owns the
per-entity state.

**Round 3 dispositions.**

- **`EconomicsEngine` ships at V3.0** as the 7th trait, with
  the small canonical-derivation surface above. Surfaced
  during Round 3 drafting via the "what are we missing"
  check (§9 procedural framing); folded in pre-commit so the
  §2 trait-surface sweep covers seven traits, not six.
- **`StakeEngine` (Phase 2b) and `ArchivalEngine` (V3.x) are
  separate consumers, not sub-traits.** The conceptual
  unity ("staking and archival are economic operations") is
  preserved as dependency through call sites in `Engine<S>`'s
  orchestration, not as supertrait composition. This matches
  the existing six-trait pattern and avoids
  multi-actor-per-trait implementation complexity at Stage 4.
- **No `&mut self` to convert.** `EconomicsEngine` is
  `&self` throughout; the Round 3 trait-surface sweep is a
  no-op for this trait.
- **The discipline test** above is part of the spec; new
  methods are reviewed against it.

### 2.8 Lifecycle and construction (new in Round 3)

Lifecycle methods (`Engine::create`, `Engine::open_full`,
`Engine::open_view_only`, `Engine::open_hardware_offload`,
`Engine::change_password`, `Engine::close`) stay as inherent
methods on `Engine<S>` (Q9.11). The construction protocol they
implement is itself part of the spec: at Stage 1 it is mostly
trivial (concrete fields constructed inline), but at Stage 4 it is
an actor-spawning orchestration with non-trivial dependency,
timeout, and partial-failure semantics that the trait surface
itself does not directly express.

#### 2.8.1 Three graphs

Three distinct dependency graphs apply across the lifecycle. They
share structure but differ in detail; reviewers should not
conflate them.

| Graph | Question it answers | Direction | Used at |
|---|---|---|---|
| **Landing graph** (§8.1) | What order do Stage 1 PRs land in? | `DaemonEngine` first, then chain-with-parallelism | PR review / planning |
| **Spawn graph** (§2.8.3) | What order do Stage 4 actors spawn? | Independent group → Persistence-dependent group → composite group | Runtime construction at `Engine::create` |
| **Teardown graph** (§2.8.5) | What order do Stage 4 actors stop? | Reverse of spawn graph | Runtime teardown at `Engine::close` |

The landing graph is about **type-and-test dependency** (you can't
land `LedgerEngine`'s PR without `DaemonEngine` being defined
because `produce_scan_result` references it; and integration tests
for `LedgerEngine` benefit from `DaemonEngine` being available to
generate `ScanResult`s). The spawn graph is about
**state-construction dependency** (`KeyEngine`'s actor needs the
decrypted key blob, which `PersistenceEngine` produces; `LedgerEngine`'s
actor needs hydration state from `PersistenceEngine`). The teardown
graph is the spawn graph reversed — actors that depend on others
must finish before their dependencies stop.

The graphs share structure (both involve `PersistenceEngine` as a
late-bound prerequisite for `LedgerEngine` and `KeyEngine`), but
the parallelism differs: the landing graph is a strict chain
(PRs land sequentially by definition); the spawn graph admits
parallelism within groups. **Reviewers reading "this depends on
that" must check which graph the dependency is from.**

#### 2.8.2 Stage 1 lifecycle

At Stage 1 the lifecycle methods are sync; trait fields are
constructed inline in the existing pattern (per current
`Engine::create` / `Engine::open_full` / etc. bodies). Drop is
sufficient for cleanup — all trait fields hold owned state
(`WalletFile`, `AllKeysBlob`, `LocalLedger`, `LocalPendingTx`,
`LocalRefresh`, `DaemonClient`, `LocalEconomics`). Drop runs in
field declaration order; declaration order on `Engine<S>` mirrors
dependency-reverse (traits that depend on others declared first,
traits depended on declared last) so that drop matches the
teardown graph.

`Engine::close` at Stage 1 is functionally equivalent to drop
with explicit ordering; no actor coordination needed.

#### 2.8.3 Stage 4 lifecycle

At Stage 4 the lifecycle methods are intrinsically async because
actor spawning is async. Two options for the public API:

- **Async-public**: `Engine::create` returns `impl Future<Output =
  Result<Engine<S>, EngineError>>`. V3.0 wallet-CLI absorbs
  `block_on` at the binary entry point.
- **Sync-public via `Handle::block_on`**: `Engine::create` stays
  sync, takes `&Handle` like `Engine::refresh`, internally
  `block_on`s the async construction. Mirrors §4.2's pattern;
  multi-thread runtime precondition applies.

**Lean (Round 3): sync-public via `Handle::block_on`.** Keeps the
public API surface stable across Stage 1 → Stage 4 (callers don't
absorb async at construction); leverages the existing
multi-thread-runtime discipline already required for
`Engine::refresh`. Trade-off: the `Handle::block_on` is paid once
at construction (cheap) and its precondition is documented in the
same place as `Engine::refresh`'s. Re-opens for Round 5+ if
review surfaces a stronger case for async-public.

`Engine::create` at Stage 4 implements the spawn graph as
`tokio::join!`-ed independent groups in topological order:

```rust
// Stage 4 sketch — not part of the trait surface.
async fn create_inner(/* … */) -> Result<Engine<S>, EngineError> {
    // Group A — independent: spawn in parallel.
    let (daemon, persist, economics) = tokio::try_join!(
        spawn_with_timeout(DaemonActor::spawn,      DAEMON_SPAWN_TIMEOUT),
        spawn_with_timeout(PersistenceActor::spawn, PERSIST_SPAWN_TIMEOUT),
        spawn_with_timeout(EconomicsActor::spawn,   ECONOMICS_SPAWN_TIMEOUT),
    )?;

    // Group B — depend on Persistence: spawn in parallel within the group.
    let (key, ledger) = tokio::try_join!(
        spawn_with_timeout(|s| KeyActor::spawn(s, &persist),    KEY_SPAWN_TIMEOUT),
        spawn_with_timeout(|s| LedgerActor::spawn(s, &persist), LEDGER_SPAWN_TIMEOUT),
    ).map_err(|e| { cleanup(&daemon, &persist, &economics); e })?;

    // Group C — depend on Ledger + Daemon (and Key for PendingTx):
    //         spawn in parallel within the group.
    let (refresh, pending) = tokio::try_join!(
        spawn_with_timeout(
            |s| RefreshActor::spawn(s, &ledger, &daemon),
            REFRESH_SPAWN_TIMEOUT,
        ),
        spawn_with_timeout(
            |s| PendingTxActor::spawn(s, &key, &ledger, &daemon),
            PENDING_SPAWN_TIMEOUT,
        ),
    ).map_err(|e| { cleanup(&daemon, &persist, &economics, &key, &ledger); e })?;

    Ok(Engine {
        keys: key, daemon, file: persist, economics, ledger,
        refresh, pending, /* … */
    })
}
```

The spawn graph for the seven traits:

| Group | Members | Depends on |
|---|---|---|
| A | `DaemonEngine`, `PersistenceEngine`, `EconomicsEngine` | (nothing) |
| B | `KeyEngine`, `LedgerEngine` | Group A's `PersistenceEngine` |
| C | `RefreshEngine`, `PendingTxEngine` | Groups A and B (Ledger + Daemon for Refresh; Key + Ledger + Daemon for PendingTx) |

`EconomicsEngine` is in Group A because at V3.0 its
implementation is constants-only (no state hydration); at V3.x
Component 3 the actor self-hydrates adaptive-burn state from
`shekyl-economics` defaults at spawn time without inter-engine
dependencies. Group-A membership preserves the leaf-actor
property even after Component 3.

Note the asymmetry with §8.1's landing graph: the landing graph
puts `KeyEngine` and `PersistenceEngine` off-the-critical-path
(both can land any time after Stage 1 begins) because their trait
*signatures* don't reference other traits. The spawn graph puts
`PersistenceEngine` in Group A (independent at runtime) and
`KeyEngine` in Group B (needs decrypted key material from
Persistence). The two graphs answer different questions; both
are correct.

#### 2.8.4 Timeout discipline

Per-actor spawn timeouts are configurable; default 5 seconds per
actor. Spawn timeout exceeded → partial-construction failure →
cleanup cascade per §2.8.5.

**Why 5s default**: covers slow file I/O for `PersistenceEngine`
(a cold-cache disk read of an encrypted wallet file may take
seconds), slow daemon connection establishment for `DaemonEngine`
(TLS handshake against an unreachable peer), slow KEK derivation
for `KeyEngine` (Argon2id with conservative parameters). Pathological
cases (network outage, disk failure) should fail in bounded time
rather than appear-to-hang; 5s is the minimum that doesn't
false-positive on legitimate slow paths and is bounded enough that
the user-visible failure mode is a clear "couldn't open" rather
than an indefinite spinner.

V3.x revisits if real-world latency surfaces longer-than-5s
legitimate paths.

#### 2.8.5 Partial-failure cleanup

If actor N of M fails to spawn (or times out per §2.8.4), actors
1..N-1 must be torn down cleanly. Cleanup runs the teardown graph
in dependency-reverse order, calling `stop_gracefully` on each
previously-spawned actor.

The teardown graph for the seven traits:

| Group | Members | Stops before |
|---|---|---|
| C′ | `RefreshEngine`, `PendingTxEngine` | (these stop first; they hold Ledger / Daemon / Key references) |
| B′ | `KeyEngine`, `LedgerEngine` | (after C′ completes; Ledger flushes saved state to Persistence at this point) |
| A′ | `DaemonEngine`, `PersistenceEngine`, `EconomicsEngine` | (last; Persistence absorbs Ledger's final flush before closing; Economics has no flush surface at V3.0 and at V3.x its adaptive-burn state is not durable) |

Cleanup is best-effort: if a cleanup-time `stop_gracefully` fails
(rare but possible — actor mailbox full, actor panic during
shutdown), the failure is logged and the original
partial-construction error returned takes precedence. Cleanup
does not retry indefinitely.

#### 2.8.6 Drop vs. close asymmetry

| | Stage 1 | Stage 4 |
|---|---|---|
| `drop(engine)` | Sufficient — all state owned, drops in declaration order, declaration order matches teardown graph | **Best-effort** — `ActorRef` drop only decrements refcount; actors continue processing pending messages until the runtime tears down |
| `engine.close()` | Functionally equivalent to drop, with explicit ordering | **Required** — orchestrates `stop_gracefully` cascade per teardown graph |

At Stage 1, callers don't have to call `close`; drop suffices. At
Stage 4, callers SHOULD call `close`, or accept that pending
messages may produce surprising side effects after the engine
appears destroyed: a Persistence actor commits pending writes; a
Daemon actor submits a transaction the user thought was abandoned;
a Refresh actor publishes one more progress update before its
mailbox drains.

This asymmetry is what makes `Engine::close` semantically
*different* at Stage 4 from Stage 1, not just "the same thing but
more explicit." Stage 4 reviewers thinking "drop is fine, we don't
need close" will hit the same surprising-side-effect failure mode
that the discipline exists to prevent.

#### 2.8.7 Round 3 dispositions

- **The trait surface in §2 does not change for lifecycle
  concerns.** Lifecycle stays inherent on `Engine<S>`; the trait
  surface only sees the actors after they're alive. (Q9.11 closed
  no for `load_state()` on `PersistenceEngine`; lifecycle
  construction is the orchestrator's concern.)
- **The spawn graph is part of the spec (§2.8.3); the landing
  graph is a separate concern (§8.1).** Both graphs are pinned;
  reviewers conflating them risk arguing for the wrong
  parallelism in either context.
- **Default per-actor spawn timeout: 5 seconds.** Configurable via
  `EngineConfig`; documented as such in `Engine::create`'s
  rustdoc at Stage 4.
- **Drop semantics are best-effort at Stage 4; explicit
  `Engine::close` is required.** Pinned in §2.8.6.

---

## 3. Composition: how `Engine<S>` holds the traits in Stage 1

```rust
pub struct Engine<
    S: EngineSignerKind,
    K: KeyEngine        = AllKeysBlob,
    L: LedgerEngine     = LocalLedger,
    E: EconomicsEngine  = LocalEconomics,
    D: DaemonEngine     = DaemonClient,
    F: PersistenceEngine = WalletFile,
    R: RefreshEngine    = LocalRefresh,
    P: PendingTxEngine  = LocalPendingTx,
> {
    keys:       K,
    ledger:     L,
    economics:  E,
    daemon:     D,
    file:       F,
    refresh:    R,
    pending:    P,
    network:    Network,
    capability: Capability,
    _signer:    PhantomData<S>,
}
```

Production code writes `Engine<SoloSigner>` and the defaults plug
in; test code writes `Engine<SoloSigner, MockKey, MockLedger, …>`
with whatever subset it needs. Default type parameters carry the
production ergonomics; the generic surface unlocks the test
boundary in §6.

The `Arc<RwLock<Engine<S, …>>>` self-arc that
`Engine::start_refresh` takes today is unaffected by Stage 1 — it
stays a transitional shape on the way to the Path B
`HashMap<EngineId, ActorRef<EngineActor>>` boundary that Stage 4
introduces. The `RefreshEngine` trait surface in §2.3 does not
name `Arc<RwLock<…>>`; that's an implementation detail of
`LocalRefresh`'s caller (the orchestrator on `Engine`), not part
of the contract.

**Type parameter ordering principle (Round 2 — Q9.12 closed;
Round 3 — `E` slot inserted for `EconomicsEngine`).** The order
is `<S, K, L, E, D, F, R, P>`: dependency-leaves first (`K`, `L`,
`E`, `D`, `F` — none of these traits' Stage 1 contracts call
into other traits), compound traits last (`R` depends on `L` and
`D`; `P` depends on `K`, `L`, `D`). Within the leaf group,
narrative grouping: `K` (identity) → `L` (state) → `E`
(economics, canonical-derivation surface adjacent to ledger
state) → `D` (peer) → `F` (storage); then `R` (driver) → `P`
(action). `E` slots between `L` and `D` because `EconomicsEngine`
derives values from chain state's economic parameters
conceptually adjacent to `LedgerEngine`'s state surface, even
though the V3.0 implementation reads from constants only. This
ordering does double duty as both dependency-leaves-first and
narrative-coherent.

`E` is a *consumed* trait at V3.0 (no callers in `Engine<S>`'s
own methods at V3.0 — orchestration relevance comes via Phase 2b
`StakeEngine` and V3.x `ArchivalEngine`). The slot is added at
V3.0 to avoid breaking the type-parameter ordering when those
traits land. Stage 4 actor wiring (`ActorRef<EconomicsActor>`)
slots in at the same position.

### 3.1 Stage 1 implementing types ("default" types above)

| Trait | Stage 1 type | Stage 4 type |
|---|---|---|
| `KeyEngine` | `AllKeysBlob` (existing) | `kameo`-managed actor wrapping `AllKeysBlob` |
| `LedgerEngine` | `LocalLedger` (new struct wrapping `WalletLedger` + `LedgerIndexes`) | `kameo` actor |
| `EconomicsEngine` | `LocalEconomics` (new — V3.0 stateless wrapper around `shekyl-economics` constants; gains `Mutex<AdaptiveBurnState>` at V3.x Component 3) | `kameo` actor (`EconomicsActor`) |
| `DaemonEngine` | `DaemonClient` (existing) | `kameo` actor wrapping `DaemonClient` |
| `PersistenceEngine` | `WalletFile` (existing) | `kameo` actor wrapping `WalletFile` |
| `RefreshEngine` | `LocalRefresh` (new struct wrapping `RefreshSlot` + the producer driver) | `kameo` actor |
| `PendingTxEngine` | `LocalPendingTx` (new struct wrapping the reservation tracker) | `kameo` actor |

### 3.2 "Moves not rewrites" is incomplete framing (new in Round 2)

Round 1 framed the new `Local*` types as *moves* — existing fields
on `Engine<S>` (`ledger`, `indexes`, `reservations`,
`next_reservation_id`, `refresh_slot`) move into the corresponding
`Local*` structs; existing methods move to `impl Trait for
Local*`. That framing is comforting but slightly understates the
work. Two costs the "moves" framing hides:

1. **Some method signatures change.** Per §4's async lift,
   `LedgerEngine::apply_scan_result` becomes `async fn`. The body
   moves; the signature changes; every call site of the old sync
   `apply_scan_result` must either become async or interpose a
   `block_on`. See §4 for the sync `Engine::refresh` resolution.
2. **Async cascades through transitive callers.** A method that
   gains an `.await` propagates `async fn` upward. Stage 1's
   call-site impact is not zero: the public sync API surface
   (`Engine::refresh`) is preserved by an internal `block_on`,
   but every other path that touches `apply_scan_result` —
   integration tests, future migration helpers, any V3.0 follow-up
   that calls into the merge — absorbs either an `.await` or a
   `block_on`.

   The concrete call-site disposition for `apply_scan_result`:

   | Caller of `apply_scan_result` | Stage 1 disposition |
   |---|---|
   | `Engine::refresh` (sync orchestration) | `Handle::block_on` per §4.2 |
   | `Engine::start_refresh` producer task (async) | natural `.await` |
   | Existing integration tests | become `async fn` or `block_on` per the test's needs |
   | V3.0 follow-up paths that call into merge | absorb `async fn` propagation |

   The same shape applies to other traits whose mutating methods
   become async at Stage 1 (`PendingTxEngine::build` /
   `submit` / `discard`, `PersistenceEngine::rotate_password`):
   sync orchestration paths absorb `Handle::block_on`; async
   paths absorb natural `.await`; tests follow the pattern of
   whichever path they exercise.

Stage 1 still works; the trait extraction is still mechanical at
the implementation level. But "mechanical" applies to the
extraction, not necessarily to the call-site adjustments. Honest
about the cost so reviewers don't read "moves" and budget zero
work for callers.

**The async cascade is preparatory, not waste.** The work Stage 1
introduces (async lift on `LedgerEngine` mutations, `Handle::block_on`
in sync `Engine::refresh`, async-cascade through transitive callers)
is exactly the surface Stage 4 needs against actor-handle
implementations. The cost is paid once at Stage 1; Stage 4 reuses
the same async surface against `kameo` actors with no further
signature churn. Per §1.4's discipline, the trait surface that
emerges at Stage 1 *is* the message-passing surface at Stage 4.

### 3.3 Concurrency model: Stage 1 vs Stage 4 (new in Round 3)

The trait surface in §2 is identical at Stage 1 and Stage 4. The
concurrency model that callers can rely on across that surface is
not. The trait *signatures* don't change; the *semantics callers
can rely on across cross-trait calls* do.

#### 3.3.1 Stage 1: outer-lock sequential consistency

Stage 1's `Arc<RwLock<Engine<S, …>>>` (Path B's transitional
shape, per the *RefreshHandle ships transitional Arc-RwLock-Engine
under Path B* decision-log entry, 2026-04-27) serializes every
trait call against the outer lock. Cross-trait operations are
sequentially consistent because they all hold the same write lock
or two-phase the read/write transition.

**Stage 1 over-serializes** relative to what the trait surface
actually requires: calls that don't logically conflict still
serialize because they all go through the outer lock.
`engine.daemon.get_fee_estimates()` and
`engine.keys.sign_with_spend(…)` could in principle run
concurrently — they share no state — but Stage 1's outer lock
serializes them anyway. The over-serialization is invisible to
correctness; it just leaves performance on the table.

#### 3.3.2 Stage 4: per-actor mailbox FIFO, no cross-actor ordering

Stage 4's per-actor mailboxes give each actor FIFO ordering for
its own calls. Cross-actor operations have no ordering guarantee:
two messages to two different actors can interleave at their
respective receivers in any order relative to other concurrent
senders.

This is **finer-grained concurrency** than Stage 1: independent
operations actually run concurrently because the actors process
their own mailboxes in parallel. It is also **weaker semantics**
than Stage 1: callers cannot rely on accidental serialization
that the outer lock provided for free.

#### 3.3.3 The discipline that survives both stages

**Negative discipline.** Trait callers do not rely on cross-trait
sequencing without explicit synchronization. If two operations on
different traits must be ordered, the caller awaits the first's
completion before issuing the second.

**Positive discipline.** Write Stage 1 code as if the trait calls
were already actor-handle-shaped. Use explicit `.await` points to
sequence operations even when Stage 1's locking would serialize
them anyway. Stage 1 code that follows this discipline is Stage
4-ready by construction; Stage 1 code that doesn't is Stage
4-vulnerable by default.

The positive discipline is the one that does the work. The
negative discipline tells reviewers what to flag; the positive
discipline tells contributors what to write.

#### 3.3.4 Concrete examples

**Unsafe pattern (silently broken at Stage 4):**

```rust
// Safe at Stage 1 (outer lock serializes the join);
// unsafe at Stage 4 (separate mailboxes, no cross-actor ordering).
let (apply_result, persist_result) = tokio::join!(
    engine.ledger.apply_scan_result(scan),
    engine.persist.save_state(&engine.ledger.snapshot()),
    // The persist call reads ledger state. At Stage 4 the
    // snapshot read can land before, during, or after the apply
    // completes — race condition that Stage 1 silently prevents.
);
```

At Stage 1, the outer `RwLock` means `tokio::join!`'d operations
actually serialize — one acquires the write lock, the other
waits, no race. At Stage 4, `LedgerEngine` and `PersistenceEngine`
are separate actors with separate mailboxes; the persist call's
internal `snapshot()` read goes through `LedgerEngine`'s mailbox
on a separate channel; the read may observe pre-apply or
post-apply state non-deterministically.

**Safe pattern (works identically at Stage 1 and Stage 4):**

```rust
// Sequence explicitly when ordering matters.
engine.ledger.apply_scan_result(scan).await?;
let snapshot = engine.ledger.snapshot();
engine.persist.save_state(&snapshot).await?;
```

The `.await` before the `snapshot()` call is the synchronization
point at both Stage 1 and Stage 4. At Stage 4, the snapshot read
goes through `LedgerEngine`'s mailbox after the apply's reply has
been observed; at Stage 1, the outer lock makes the explicit
sequencing redundant but correct.

**Concurrent-safe pattern (no shared state):**

```rust
// Operations on different traits with no shared state can run
// concurrently — Stage 1 serializes them via the outer lock as
// overhead; Stage 4 actually runs them in parallel.
let (fee_estimates, signature) = tokio::join!(
    engine.daemon.get_fee_estimates(),
    engine.keys.sign_with_spend(domain, message),
);
```

`get_fee_estimates` and `sign_with_spend` target different traits
with no shared state. Concurrent execution is safe at both stages
— Stage 1 serializes them but that's overhead, not correctness;
Stage 4 actually runs them in parallel through separate
mailboxes.

#### 3.3.5 Code-review check item

Cross-trait `tokio::join!` / `futures::join!` /
`tokio::select!` of *mutating* operations (or operations whose
joined futures internally read/write shared state) requires
explicit justification in the PR description. The justification
documents what would happen at Stage 4 when the operations
actually overlap — specifically, whether the joined operations
share state (like the `apply` + `save_state` example above) or
are independent (like the `fee_estimates` + `sign_with_spend`
example).

This is a code-review checklist item, not a lint. Lighter than
tooling, heavier than vibes. Reviewers reading PRs that touch
trait orchestration apply this check; PR descriptions that don't
address it are sent back for amendment.

#### 3.3.6 EconomicsEngine reads at Stage 4

`EconomicsEngine` reads (`current_emission`, `burn_fraction`,
`pool_weighted_total`, `parameters_snapshot`) are pure-function
or pure-snapshot at V3.0; at Stage 4 callers may bypass the
actor mailbox by holding an `Arc<EconomicsParametersSnapshot>`
captured at construction (analogous to `LedgerEngine` snapshot
patterns). The `parameters_snapshot()` call returns an owned
`Arc<EconomicsParametersSnapshot>`; callers can clone the `Arc`
freely without re-entering the actor. This avoids
serializing-through-the-mailbox for the hot read path while
preserving authoritative-source semantics for snapshot
acquisition.

V3.x Component 3 adaptive-burn changes the actor's *internal
state* (it observes activity and updates derivation parameters)
but the snapshot-bypass pattern preserves: callers either ask
for a fresh snapshot (re-entering the mailbox once) or work
from a stale snapshot they hold. The read pattern stays
identical across V3.0 and V3.x.

### 3.4 Cancellation discipline (new in Round 3)

#### 3.4.1 Drop-cancellation as the default

All async trait methods are cancel-safe via future-drop by
Tokio's standard discipline: the caller drops the awaited future
before completion, the underlying operation cancels.
Implementors are responsible for ensuring drop-during-await
leaves persistent state consistent — no half-written
`WalletFile`, no orphaned daemon connection, no torn ledger
state.

Operations that cannot satisfy the consistency guarantee on
drop — e.g., a hypothetical persistence write that spans multiple
file-system operations and would corrupt on partial completion —
MUST document the constraint in their rustdoc. The default
contract is "drop is safe"; deviations are explicit, documented
exceptions.

#### 3.4.2 Stage 1 vs Stage 4 drop semantics differ

**Stage 1:** dropping the awaited future before completion
cancels the underlying operation. Tokio aborts the task driving
the future; any in-flight HTTP request to the daemon, any
in-progress computation, any I/O operation that hasn't completed
is aborted at the next yield point.

**Stage 4:** dropping the awaited future before completion is
**observation-only**. By the time the caller has a future to
drop, the message is already in the actor's mailbox; the actor
will process it; the reply is enqueued; the only thing the drop
affects is whether the caller observes the reply (the reply
channel is closed; the actor's reply send fails silently and the
side effect occurs anyway).

Concrete illustration:

```rust
// Stage 1: daemon submission is aborted; tx never reaches mempool.
let f = engine.daemon.submit_transaction(tx);
drop(f); // before await — the HTTP request is aborted at next yield.

// Stage 4: tx is in mailbox; actor will process it; the reply is
//          discarded but the side effect (mempool submission)
//          happens anyway.
let f = engine.daemon.submit_transaction(tx);
drop(f); // before await — the message is already enqueued.
```

This is a real semantic gap, and it informs the discipline:

- **Operations that must NOT have side effects if the caller
  drops** require *in-band cancellation tokens*, not drop
  semantics. `RefreshEngine::produce_scan_result` is the model:
  its `CancellationToken` parameter signals cancellation through
  the trait's contract, observable at controlled checkpoints
  (per §7's four-checkpoint discipline).
- **Operations whose side effects are idempotent or whose
  post-drop continuation is acceptable** can rely on drop
  semantics. `KeyEngine::sign_with_spend` is acceptable to drop —
  even if the signature gets computed by the actor, the
  signature itself has no external side effect (it's not sent
  anywhere; the reply just gets discarded).

#### 3.4.3 Per-method classification framework

Three classes:

| Class | Description | Drop at Stage 1 | Drop at Stage 4 |
|---|---|---|---|
| **a** | Drop-cancellable, side-effect-free | Cancels (no side effect either way) | Observation-only (no side effect either way) |
| **b** | Drop-cancellable at Stage 1, side-effect-eventual at Stage 4 | Cancels (side effect prevented) | Observation-only (side effect occurs) |
| **c** | Explicitly cancellable via in-band token | Token-driven (drop is observation-only) | Token-driven (drop is observation-only) |

- **Class a** is most read-style methods: `balance`, `transfers`,
  `synced_height`, `get_fee_estimates`,
  `current_emission`, `burn_fraction`, `pool_weighted_total`,
  `parameters_snapshot`. Reading these has no observable effect;
  dropping them at any stage is a no-op. All four
  `EconomicsEngine` methods are class a at V3.0; V3.x's
  adaptive-burn observation is internal to the actor and not
  caller-visible, preserving the class-a classification.
- **Class b** is most mutating methods without in-band
  cancellation tokens: `apply_scan_result`, `save_state`,
  `submit_transaction`, `rotate_password`. Stage 1 drop cancels
  the side effect; Stage 4 drop allows the side effect to occur
  silently. This is the class where the Stage 1 → Stage 4
  semantic gap matters.
- **Class c** is in-band cancellable: today, only
  `RefreshEngine::produce_scan_result`. Cancellation requires
  signaling the token; drop alone is not observable to the
  implementor. This class works identically across Stage 1 and
  Stage 4.

**The framework lands in Round 3; the per-method classification
table (which methods are class a / b / c) lands in Round 4** as
an additional column on §4's async-story table. The reason for
the split: classifying every method requires examining every
method's side-effect surface and Stage 4 behavior, which is
mechanical fill-in once the framework is pinned.

#### 3.4.4 Round 3 dispositions

- **Drop-cancellation is the default contract** for async trait
  methods (per §3.4.1). Implementors document deviations.
- **Stage 4 drop is observation-only**, not cancellation, for
  Class b methods (per §3.4.2). Operations that must not
  side-effect on drop use in-band cancellation tokens.
- **Three-class framework** (a / b / c) is pinned (per §3.4.3);
  the per-method classification table is a Round 4 fill-in.

---

## 4. Async story

The table below replaces the Round 1/2 sync-vs-async split with a
fuller per-method view. Round 3 adds the **Idempotency** column;
Round 4 adds a *Cancel class* column (a / b / c per §3.4.3) once
the per-method classifications are filled in.

| Trait | Method | Async/Sync | Idempotent? |
|---|---|---|---|
| `KeyEngine` | `account_public_address` | sync | yes (read-only) |
| `KeyEngine` | `derive_subaddress_public` | sync | yes (deterministic; pure derivation) |
| `KeyEngine` | `sign_with_spend` | async | no (RNG-driven; each call yields a fresh signature) |
| `KeyEngine` | `view_ecdh` | async | yes (deterministic ECDH; same `tx_pub_key` → same shared secret) |
| `KeyEngine` | `ml_kem_decapsulate` | async | yes (deterministic decap; same encapsulation → same shared secret) |
| `LedgerEngine` | `synced_height` | sync | yes (read-only) |
| `LedgerEngine` | `snapshot` | sync | yes (read-only; returns owned snapshot) |
| `LedgerEngine` | `balance` | sync | yes (read-only) |
| `LedgerEngine` | `transfers` | sync | yes (read-only) |
| `LedgerEngine` | `apply_scan_result` | async | **conditionally** — idempotent given the same `ScanResult` against the same starting `synced_height`; if the height has advanced (because a concurrent merge landed), the second apply returns `RefreshError::ConcurrentMutation` deterministically. Never produces a double-applied state. |
| `RefreshEngine` | `produce_scan_result` | async | no (each call observes the daemon's current tip; tip advances over time) |
| `PendingTxEngine` | `build` | async | no (each build picks fresh decoys; reservation IDs are monotonic) |
| `PendingTxEngine` | `submit` | async | **conditionally** — daemon dedupes by tx hash; calling `submit` twice on the same `ReservationId` produces one mempool submission |
| `PendingTxEngine` | `discard` | async | yes (discarding an already-discarded reservation is a no-op error variant the caller can treat as success) |
| `PendingTxEngine` | `outstanding` | sync | yes (read-only) |
| `DaemonEngine` | `get_fee_estimates` | async | yes (read-only; fee state is a snapshot at call time) |
| `DaemonEngine` | `submit_transaction` | async | **conditionally** — daemon dedupes by tx hash (same tx bytes → same submission outcome) |
| `DaemonEngine` | `Rpc` supertrait methods | async | per-method (inherits `Rpc`'s spec) |
| `PersistenceEngine` | `base_path` | sync | yes (read-only; returns immutable cached path) |
| `PersistenceEngine` | `network` | sync | yes (read-only) |
| `PersistenceEngine` | `capability` | sync | yes (read-only) |
| `PersistenceEngine` | `save_state` | async | yes (last-write-wins; saving the same state twice yields the same final on-disk bytes) |
| `PersistenceEngine` | `save_prefs` | async | yes (last-write-wins) |
| `PersistenceEngine` | `rotate_password` | async | no (state changes per call; old credentials are no longer valid after a successful rotation) |
| `EconomicsEngine` | `current_emission` | sync | yes (read-only; deterministic given height at V3.0; deterministic given height plus observed-activity state at V3.x — observable via `parameters_snapshot`) |
| `EconomicsEngine` | `burn_fraction` | sync | yes (read-only; deterministic given inputs at V3.0; deterministic given inputs plus state at V3.x) |
| `EconomicsEngine` | `pool_weighted_total` | sync | yes (read-only; canonical derivation from current pool state) |
| `EconomicsEngine` | `parameters_snapshot` | sync | yes (read-only; returns owned snapshot) |

The "**conditionally**" entries name the explicit condition for
Stage 4 retry safety. Per §5.1's supervisor strategy
(restart-and-fail-pending; no automatic retry), trait-level
idempotency matters only for caller-driven retry — a caller seeing
a `RuntimeFailure` who chooses to retry needs to know whether
retry is safe. The conditions above give caller-driven retry
logic concrete safety properties:

- `apply_scan_result`: retry is safe; if the scan result was
  already merged, the retry returns `ConcurrentMutation`
  deterministically rather than double-applying.
- `submit_transaction` and `PendingTxEngine::submit`: retry is
  safe; the daemon de-duplicates by tx hash.
- Read-only methods: trivially retry-safe.
- `sign_with_spend`, `produce_scan_result`,
  `PendingTxEngine::build`, `rotate_password`: retry is
  *semantically distinct* from the original call (different
  signature, different scan window, different reservation,
  different password). Callers must reason about the operation's
  effect, not just its result.

### 4.1 LedgerEngine: reads sync, mutations async

Refined from Round 1's framing. Reads stay sync at Stage 1
because Stage 4 implements them via an `Arc<LedgerSnapshot>` the
actor publishes — readers dereference the Arc without queueing on
the mailbox. Sync at Stage 1 → sync at Stage 4 via Arc-snapshot
bypass; the surface doesn't break.

Mutations are pre-emptively async because Stage 4 mutations route
through the mailbox and are intrinsically async; locking the
async surface at Stage 1 avoids breaking the trait between Stage
1 and Stage 4.

### 4.2 Sync `Engine::refresh` resolution (Round 2)

`LedgerEngine::apply_scan_result` is `async fn`; sync
`Engine::refresh` calls it via `Handle::block_on` against the
existing `&Handle` parameter on `Engine::refresh`'s signature:

```rust
// Inside Engine::refresh (sync orchestration):
let merge_outcome = handle.block_on(self.ledger.apply_scan_result(scan_result));
```

Sync API surface preserved; cost is one `Handle::block_on` per
merge in the sync path. Async `Engine::start_refresh`'s producer
task awaits `apply_scan_result` naturally.

**Multi-thread runtime precondition.** `Handle::block_on` does
not re-enter a runtime, but it can deadlock when the calling
thread is the only worker driving the runtime. Specifically, a
`RuntimeFlavor::CurrentThread` runtime has exactly one driver
thread; calling `Handle::block_on(future)` from that thread
blocks the thread, the runtime cannot make progress, the future
never completes, and the call hangs.

`Engine::refresh`'s rustdoc states the precondition explicitly:

> *Sync `Engine::refresh` requires a multi-thread tokio runtime
> via the `&Handle` parameter. Calling it with a
> `RuntimeFlavor::CurrentThread` handle (or wrapping the call in
> an outer `runtime.block_on(async { … })` on a single-threaded
> runtime) deadlocks at the internal `Handle::block_on` for the
> merge. Multi-thread runtime
> (`tokio::runtime::Builder::new_multi_thread()`) is the
> supported configuration.*

Round 2 also pins a `debug_assert!` at the top of
`Engine::refresh`'s body checking
`handle.runtime_flavor() == RuntimeFlavor::MultiThread`. The
assertion converts the deadlock into a clear panic at the right
call site with negligible runtime cost. Production builds skip
the assertion; debug builds catch the misconfiguration before the
hang.

---

## 5. Error model

**Decision.** Per-trait error families, with a single shared
`EngineError` aggregate at the `Engine<S>` boundary. Each trait
defines `type Error: Into<…>` so call sites can `?` through layers
without naming intermediate types.

```rust
pub enum EngineError {
    Key(KeyError),
    Open(OpenError),
    Refresh(RefreshError),
    Send(SendError),
    PendingTx(PendingTxError),
    Io(IoError),
    Tx(TxError),
    Economics(EconomicsError),
}
```

Existing error enums (`KeyError`, `OpenError`, `RefreshError`,
`SendError`, `PendingTxError`, `IoError`, `TxError`) stay where
they are in [`engine/error.rs`](../rust/shekyl-engine-core/src/engine/error.rs).
The `EngineError` aggregate is new; it's the type that
`Engine<S>`-level methods return and that the JSON-RPC server
converts to wire errors. `EconomicsError` is new alongside
`EconomicsEngine` (§2.7); at V3.0 the only constructed variant
is `RuntimeFailure { actor, reason }` (per §5.1) since the V3.0
`LocalEconomics` is stateless and pure-function. Variants for
adaptive-burn / parameter-update failure paths land at V3.x with
Component 3.

`RefreshError::ConcurrentMutation` stays on `LedgerEngine`'s
`apply_scan_result` return — it's the contract signal between
ledger and refresh, not a refresh-private error (see §2.2's Q9.5
disposition).

**Round 2 disposition.**

- **Q9.14 (`#[from]` policy): closed hybrid.** `#[from]` for the
  four straight-line lifts (`KeyError`, `OpenError`,
  `PendingTxError`, `IoError` → `EngineError`); explicit
  `From`/`TryFrom` impls for the cross-domain ones (`Send →
  PendingTx`, `Refresh → Send`) so error-flow at audit time
  matches the variant boundary rather than being inferred from
  ergonomics. Reviewer-readable provenance for the cross-domain
  ones; ergonomic ergonomics for the straight-line ones.

### 5.1 `RuntimeFailure` variant for Stage 4 (new in Round 3)

At Stage 4, every actor backing a trait can crash (panic, OOM,
runtime kill). The supervisor restarts the actor per its
supervision strategy, but the *caller* of a trait method whose
actor crashed mid-handler needs to observe the failure
explicitly — silently restarting and re-running the message
would risk double-applied side effects (a double mempool
submission, a double KEK rotation, a double persistence write).

**Decision.** Each per-trait error family gains a
`RuntimeFailure { actor: &'static str, reason: ActorCrashReason }`
variant. The variant is `#[non_exhaustive]` so future
actor-failure modes can extend it without breaking callers:

```rust
#[non_exhaustive]
pub enum ActorCrashReason {
    /// Actor panicked during message handling; supervisor
    /// restarted the actor; this message did not complete.
    PanickedDuringHandler,

    /// Actor's mailbox closed (actor permanently stopped).
    /// Subsequent calls on the trait surface will surface the
    /// same variant until the engine is reconstructed.
    Permanent,
}
```

**Supervisor strategy: restart-and-fail-pending, no automatic
retry.** When an actor crashes mid-handler:

1. The pending message returns `RuntimeFailure { actor: …,
   reason: PanickedDuringHandler }` to its caller.
2. All other pending messages on the same actor's mailbox are
   drained and returned as `RuntimeFailure` to their respective
   callers — the supervisor does not re-deliver them after
   restart, because re-delivery would risk message-level
   non-idempotency cascading into observable double-effects.
3. The supervisor restarts the actor in a clean state.
4. New messages sent after the restart are processed normally.

Idempotency at the trait level (per §4's Idempotency column)
governs whether *callers* can safely retry on
`RuntimeFailure`. The actor framework does not retry on the
caller's behalf; idempotency is not a system-wide guarantee, it
is a per-method property documented per §4 that callers consult
before deciding to retry.

**Recoverable vs non-recoverable crashes.** The recoverable /
non-recoverable distinction is encoded in the supervision
strategy declared per-actor at spawn time, not in ad-hoc runtime
checks:

- **Recoverable** (default): actor panic → restart →
  `PanickedDuringHandler` to the failed message's caller.
  Subsequent messages succeed.
- **Non-recoverable**: actor panic → permanent stop →
  `Permanent` to the failed message's caller and to all future
  callers of that trait until the engine is reconstructed.
  Used for invariant-violation panics where restart cannot
  restore consistent state (e.g., a key actor whose memory has
  been corrupted; restarting cannot reload secrets that have
  been wiped on the panic).

The choice between recoverable and non-recoverable per actor is
declared in the actor's `kameo` `SupervisorStrategy` at Stage 4.

**No `Engine::is_healthy()` method.** The discipline is
error-driven: permanent actor death surfaces as
`RuntimeFailure { reason: Permanent }` on every subsequent call
to that trait. The engine continues to function for traits
whose actors are alive (e.g., a permanently-dead `RefreshEngine`
doesn't take down the read-only `LedgerEngine`); callers
inspecting the error variant determine reparable vs not. A
separate health-check API would be redundant with this
error-driven surface and would invite TOCTOU patterns
("`is_healthy()` returned true; call returned `RuntimeFailure`
anyway"). Pinned out of charter.

**Stage 1 implications.** `RuntimeFailure` variants exist in the
error enums at Stage 1 (so the surface doesn't change at
Stage 4), but Stage 1 implementations never produce them — the
concrete types in §3.1 don't have actors, can't crash in the
actor sense, and the variant is unreachable at Stage 1.
Production builds that observe a `RuntimeFailure` from a Stage 1
implementor have hit a logic error. A clippy-warnable
`unreachable!()` or `debug_assert!(false)` in Stage 1 impls'
error-construction paths catches this in debug builds.

---

## 6. Test boundary

The trait abstractions unlock a category of test that is not
possible today: a **fully-mocked `Engine<SoloSigner, MockKey,
MockLedger, MockDaemon, …>`** that drives `start_refresh`
end-to-end with deterministic chain state, deterministic key
material, and no filesystem.

Today's test coverage:

- **Producer-only:** `MockRpc` in [`engine/test_support.rs`](../rust/shekyl-engine-core/src/engine/test_support.rs)
  drives `produce_scan_result` directly. Twelve producer tests
  cover the linear-scan / reorg / RPC-failure / cancellation paths.
- **Driver-only with partial mocking:** the driver-side tests in
  `engine/refresh.rs` build a real `Engine<SoloSigner>` against an
  unreachable `SimpleRequestRpc` URL and assert error-path
  behavior. No tests exercise `start_refresh` against a synthetic
  chain end-to-end because there is no way to plug a `MockRpc`
  into `DaemonClient`.

Stage 1 closes this gap. With `DaemonEngine` as a trait
(`MockRpc: DaemonEngine`), the existing chain-injection harness
(`replace_chain_from`, `queue_height_error`, `queue_block_error`)
becomes available to `start_refresh` integration tests directly.
`MockKey` and `MockPersistence` in particular let tests skip the
`AllKeysBlob` rederivation cost and the file-open advisory-lock
ceremony, which today add ~50–200 ms per test.

### 6.1 Pinned commitments for Stage 1

- Each trait gets a `Mock*` implementor in `engine::test_support`
  (`#[cfg(test)] pub(crate)`). The list as of Round 3:
  `MockKey`, `MockLedger`, `MockEconomics`, `MockDaemon`,
  `MockPersistence`, `MockRefresh`, `MockPendingTx`.
- `start_refresh` integration tests against a fully-mocked engine
  ship in the same Stage 1 commit that lands the trait surfaces.
- `MockEconomics` is constants-driven: the V3.0
  `LocalEconomics`-equivalent test double returns
  caller-configured emission / burn-fraction / pool-total /
  parameter-snapshot values. This isolates economics-consuming
  test scenarios (Phase 2b `StakeEngine` precursor tests, V3.x
  `ArchivalEngine` precursor tests) from `shekyl-economics`
  constant changes.

### 6.2 Deterministic RNG injection (Round 2 — pinned)

Every `Mock*` constructor takes an explicit 32-byte seed:

```rust
let key = MockKey::with_seed([0xde, 0xad, 0xbe, 0xef, /* … */]);
let ledger = MockLedger::with_seed([0x42; 32]);
let daemon = MockDaemon::with_seed([0xa5; 32]);
```

The seed initializes a `ChaCha20Rng` internal to the mock; all
RNG-driven decisions (synthetic chain forks, fee jitter, ML-KEM
encapsulation in test-controlled paths) draw from that source. No
global state, no `tokio::task_local!` overrides, no trait-level
`rng()` accessor.

Test authors are responsible for seed selection and recording. CI
test names that depend on byte-stable output include the seed as
a literal so reproduction across runs and across platforms is
unambiguous (`test_refresh_reorg_at_height_42_seed_0xdeadbeef…`).
Random or auto-generated seeds are not used; every snapshot test
commits its seed.

Parallel-test safety follows from no-shared-state by
construction: each test's `Mock*` has its own seed, its own
`ChaCha20Rng`, no cross-test interaction.

---

## 7. Stage 4 transition guarantee

Each trait's invariant for the Stage 4 cutover, stated explicitly
so Stage 4 implementors cannot argue for redesign:

1. **The trait method signatures in §2 do not change at Stage 4.**
   Implementations change: trait methods become message round-trips
   against `kameo` actors (per §1.4's discipline). Orchestration
   logic on `Engine<S>` itself (slot management, retry loop,
   channel construction in `Engine::start_refresh` and
   `Engine::refresh`) becomes a message handler on the engine actor
   that issues those round-trips. The trait/orchestrator split
   itself is preserved; only what each side runs against changes
   (concrete fields → actor handles on the trait side; in-process
   methods → message-handler bodies on the orchestrator side).
   Stage 4 may add methods to traits additively, but no existing
   method changes signature, async-ness, error type, or ownership
   semantics.
2. **`Engine<S, K, L, E, D, F, R, P>` retains its generic shape.**
   Only the default types change (from `AllKeysBlob` to the actor
   type, `LocalEconomics` to `EconomicsActor`, etc.). Production
   call sites continue to write `Engine<SoloSigner>`.
3. **The `Mock*` test scaffolding remains valid.** Stage 4 does
   not rewrite the test surface; the same mocks drive the same
   trait methods against the actor-backed types.
4. **Cancellation semantics are preserved verbatim, with the
   trait/orchestrator split itself part of the contract** (Round
   2 refinement). The four checkpoints are:

   1. **Top-of-attempt** — owned by the orchestrator
      (`Engine::start_refresh`, `Engine::refresh`). Covers the
      boundary between attempts, including the gap between a
      `Retrying` publish and the next snapshot.
   2. **Post-tip-fetch** — owned by
      `RefreshEngine::produce_scan_result`. Covers cancels that
      fire during the daemon `get_height()` call. The RPC isn't
      cancel-aware; the await runs to completion; this checkpoint
      is what makes a cancel-during-tip-fetch deterministically
      surface as `Cancelled`.
   3. **Mid-scan** — owned by
      `RefreshEngine::produce_scan_result`. Covers cancels
      between blocks during the long scan phase, where the bulk
      of elapsed time lives.
   4. **Pre-merge** — owned by the orchestrator. Covers the
      post-scan window where a valid `ScanResult` has been
      returned but the write borrow for `apply_scan_result` has
      not yet been acquired.

   No post-merge checkpoint by design. Once `apply_scan_result`
   commits, the merge is authoritative and a cancel observed
   afterward cannot un-mutate the wallet.

   The Stage 4 actor for `RefreshEngine` and the Stage 4
   orchestration on `Engine` observe the same checkpoints in the
   same order with the same ownership split between trait
   (checkpoints 2, 3) and orchestrator (checkpoints 1, 4).

If any Stage 4 PR proposes violating one of the above, the PR's
review surface is *this document*, not the PR's diff: the
violation either re-opens this spec for a new round, or the
proposal is rejected.

---

## 8. Migration order and gates

| # | Stage | Lands on | Gates |
|---|---|---|---|
| 1 | Stage 1 traits + Stage 1 default impls + `Mock*` test scaffolding | `dev` (per-trait PR series) | This spec accepted (rounds closed); per-PR unit tests green; no FFI changes; no `Cargo.toml` changes beyond intra-workspace. |
| 2 | Stage 2: `KeyEngine` migration to `kameo` actor | `dev` | Stage 1 landed; `kameo` framework decision committed; MSRV ≥ kameo's required version (≥1.88 per the architecture decision-log entry). |
| 3 | Stage 3 (Phase 2b): `StakeEngine` actor-from-inception | Phase 2b branch | Stage 2 landed; `kameo` validated against `KeyEngine`. |
| 4 | Stage 4: remaining trait migrations + Path B binary boundary | post-Phase-2b | Stage 3 landed; the architecture decision-log entry's no-cycle DAG / bounded-mailbox / cross-leaf-immutable-data disciplines applied. |

### 8.1 Within-Stage-1 ordering (Round 2 — refined per dependency graph)

The dependency graph dictates the strict-prerequisite chain:

| Trait | Depends on | When can it land? |
|---|---|---|
| `DaemonEngine` | (none) | First. Closes the test-boundary gap (§6); unlocks integration tests for every other trait. |
| `LedgerEngine` | (none) | Second. Required by `RefreshEngine` (snapshot/merge) and `PendingTxEngine` (balance/transfers). |
| `KeyEngine` | (none) | Any time after Stage 1 begins. Wallet-level methods that compose `KeyEngine` with other traits are on `Engine<S>`, not on `KeyEngine` itself. |
| `PersistenceEngine` | (none) | Any time after Stage 1 begins. |
| `EconomicsEngine` | (none) | Any time after Stage 1 begins. Off-the-critical-path: `EconomicsEngine`'s consumers (Phase 2b `StakeEngine`, V3.x `ArchivalEngine`) are out-of-charter for Stage 1, so the surface is established without a downstream-trait blocker. Landing it alongside the others establishes the type-parameter slot in `Engine<S, K, L, E, D, F, R, P>` so V3.x consumers find it pre-wired. |
| `RefreshEngine` | `LedgerEngine`, `DaemonEngine` | After both prerequisites have landed. |
| `PendingTxEngine` | `KeyEngine`, `LedgerEngine`, `DaemonEngine` | After all three prerequisites have landed. |

So the strict-prerequisite chain is `DaemonEngine` →
`LedgerEngine` → (`RefreshEngine` ∥ `PendingTxEngine`).
`KeyEngine`, `PersistenceEngine`, and `EconomicsEngine` are
off-the-critical-path and can interleave wherever convenient.
`RefreshEngine` and `PendingTxEngine` can land in parallel with
each other once their prerequisites are met, but there is no
dependency justifying parallel-with-each-other landing of any
other pair.

---

## 9. Open questions (remaining for Round 4+)

Rounds 1–3 closed Q9.1 through Q9.17 (dispositions captured in
the relevant section bodies above and in each round's commit
message). The single Round 1 open item still pending is:

- **9.15 — Operational form of the Stage-4 trait-contract
  enforcement.** §7 asserts that any Stage 4 PR violating the
  trait surface is reviewed against this document, not its own
  diff. The *operational form* of that gate (PR-template
  checkbox citing this document; CI rule; manual reviewer
  discipline; some combination) is not pinned. Likely a Round
  5–6 closure item; closing it earlier would over-design before
  reviewer practice has informed the right shape.

**Round 3 closures.**

- **In-round trait-count expansion.** The "what are we missing"
  check applied during Round 3 drafting (mid-round, not at a
  round boundary) surfaced `EconomicsEngine` as a missing 7th
  trait. The spec scope expanded from six traits to seven before
  the §2 trait-surface sweep committed; surfacing the gap at
  drafting cost one section addition (§2.7) and several
  small per-section augmentations (§§1.2, 1.3, 1.4, 2 preamble,
  2.8 lifecycle, 3, 3.1, 3.3, 3.4, 4, 5, 6, 7, 8.1) rather than
  a Round 4 amendment. Discipline retained: the next Round 3 →
  Round 4 transition runs the *same* "what did writing this
  round surface" check.
- **9.16 (raised Round 2) — Debug-assert vs. pure-rustdoc for
  the `Engine::refresh` multi-thread-runtime precondition:
  closed retain `debug_assert!`.** Round 2's Critique 2 (the
  `#[tokio::test]` deadlock case) decides this implicitly: pure
  rustdoc lets a developer hit silent deadlock at runtime when
  they unwittingly use the default current-thread runtime;
  `debug_assert!` surfaces the misconfiguration as a clear panic
  at the call site. Pure-rustdoc retains the deadlock as the
  failure mode; assertion converts it to a developer-visible
  error. Round 4 adds the `#[tokio::test]` rustdoc clarification
  per Round 2's Critique 2 acceptance.
- **9.17 (raised Round 2) — `produce_scan_result` daemon-cloning
  expectation in §2.3's rustdoc: closed rustdoc tightened.**
  §2.3's `produce_scan_result` rustdoc now includes the
  daemon-cloning expectation explicitly: the `&D` borrow lives
  for one attempt; if the implementor needs an owned handle to
  move into a spawned future, it clones internally; the §2.5
  `Clone + Send + Sync + 'static` bound makes this cheap and
  Stage-4-actor-compatible. The rustdoc also forbids
  borrow-then-spawn patterns that would hold `&D` past the call
  frame.

**Round 4 agenda (pinned in the PR description; tracked here
only by category):**

- Per-method drop-cancellation classification (a / b / c per
  §3.4.3) added as a column to §4's async-story table.
- `pub(crate)` visibility pin in §2 preamble.
- Stage-1-amendment co-landing rule (separate-commit form) in
  §8.
- Mocks-vs-contract pin in §6.
- Seven-traits-Stage-1-only / Phase-2b-additive pin in §1.2.
- Observability scope pin in §3.
- `#[tokio::test]` rustdoc clarification in §4.2.
- Panic-rustdoc requirement pin in §1 or §3.
- New §10 "Out of scope / Deferred" subsection consolidating
  the deferred items: Stage 1→2 transition mechanics, JSON-RPC
  implications, multi-engine server, V3.1 multisig assumption,
  FCMP++ progress trigger, bounded-mailbox conditions,
  Stage-4 behavioral-equivalence verification,
  tracing/observability tooling, anonymity-network-coordination
  trait (Tor/I2P transport for `ArchivalEngine` queries; V3.x).

Round 5 is acceptance; near-empty outside fallout from Round 4
review.

---

## Cross-references

- [`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md) §*"Engine architecture: actor model with staged migration from composition"* (2026-04-27) — the architectural commitment this spec realizes.
- [`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md) §*"Engine binary boundary: pure message-passing over shared handle"* (2026-04-27) — Path B, retires the outer `Arc<RwLock<Engine>>` at Stage 4.
- [`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md) §*"`RefreshHandle` (Phase 2a Branch 2) ships transitional `Arc<RwLock<Engine>>` under Path B"* (2026-04-27) — explicit pin that the current self-arc is transitional.
- [`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md) §*"Pending-tx protocol: two-phase build/submit/discard over single-phase callback"* (2026-04-27) — the `PendingTxEngine` surface.
- [`rust/shekyl-engine-core/src/engine/refresh.rs`](../rust/shekyl-engine-core/src/engine/refresh.rs) `run_refresh_task` rustdoc — the four-checkpoint cancellation contract reproduced inline in §7.
- [`rust/shekyl-engine-core/src/engine/refresh.rs`](../rust/shekyl-engine-core/src/engine/refresh.rs) `Engine::refresh` rustdoc (post-2026-04-28) — the sync-vs-async cancellation split.
- [`rust/shekyl-engine-core/src/engine/test_support.rs`](../rust/shekyl-engine-core/src/engine/test_support.rs) — current `MockRpc` and `make_synthetic_block` scaffolding.
- [`docs/FOLLOWUPS.md`](FOLLOWUPS.md) "Generic `DaemonClient`" — closed in spec by §2.5 (two-trait shape); implementation V3.1.
- [`docs/CI_BASELINE.md`](CI_BASELINE.md) — `shekyl-oxide` divergence-canary policy referenced in §2.5's upstream/downstream rationale.
- [`.cursor/rules/20-rust-vs-cpp-policy.mdc`](../.cursor/rules/20-rust-vs-cpp-policy.mdc) — the "4–6 review rounds before any Rust" rule this document is run against.
- [PR #20](https://github.com/Shekyl-Foundation/shekyl-core/pull/20) — the live review surface for this spec (Interpretation D: linear-append commits per round).
