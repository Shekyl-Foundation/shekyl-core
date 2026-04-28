# V3 Engine Trait Boundaries (Stage 1)

**Status.** Round 2 of 4–6 design-review rounds (markdown-only,
against `dev`). PR [#20](https://github.com/Shekyl-Foundation/shekyl-core/pull/20)
is the live review surface; each round appends a commit, the PR
absorbs the diff, and the merge to `dev` happens when the spec is
accepted (Round 5 or 6). **No code changes are gated on this
document yet.**

- **Round 1 record:** `d387bff1d` (initial draft on this branch);
  content originally landed on `dev` outside the review-round
  workflow as `c0a3b75ec` and was reverted by `3ed7ff2c7` to put the
  spec on the markdown-only PR-review path required by
  [`.cursor/rules/20-rust-vs-cpp-policy.mdc`](../.cursor/rules/20-rust-vs-cpp-policy.mdc).
- **Round 2 record:** the commit landing this state on the chore
  branch; commit message captures Q9.x dispositions.

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

- Define six trait surfaces: `KeyEngine`, `LedgerEngine`,
  `RefreshEngine`, `PendingTxEngine`, `DaemonEngine`,
  `PersistenceEngine`.
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
| `RefreshSummary::stake_events` going non-zero | Phase 2b (`StakeEngine`) |
| View-only / hardware-offload `open_*` bodies | V3.0 follow-up; orthogonal |
| Generic `DaemonClient` *implementation* | V3.1 — but its trait shape is pinned here so Stage 1's mocked-`Engine` test surface is not blocked on it |

### 1.3 Why "concrete fields + generic-bounded methods" is the Stage 1 shape

`Box<dyn KeyEngine>` would dispatch through a vtable on every key
operation, which (a) defeats the inlining the secret-handling code
relies on for compile-time auditing of every key access, and (b)
requires `dyn`-safe trait shapes that constrain Stage 4's actor
surface for no Stage 1 win. The alternative — `Engine<S, K, L, D, F, R, P>`
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
`PersistenceEngine::save_prefs` or `LedgerEngine::balance`, where
`dyn`-dispatch overhead is irrelevant and the auditing bar is
lower. We choose the same generic-bounded shape across all six
traits anyway, because (a) consistency makes the §3 composition
section's mental model uniform, and (b) the cost of generics where
they're not load-bearing is one type parameter and turbofish
ergonomics in tests. Where the rationale is materially stronger or
weaker per-trait, the relevant §2 section says so.

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
- ✅ **`&mut self` + values in / values out** — actor-friendly.
  The Stage 4 actor's mailbox owns the mutation; the message
  carries the input value, the reply carries the output value.
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

Stage 4 makes the discipline operational: an `&self` trait method
against a `kameo` actor is a `tell`/`ask`-shaped message
round-trip; an `&mut OtherTrait` parameter has no Stage-4
equivalent.

**Applying the test to §2's traits.** `KeyEngine`, `LedgerEngine`,
`PendingTxEngine`, `DaemonEngine`, `PersistenceEngine` clear the
test trivially (values in, values out). `RefreshEngine` clears it
via the §2.3 design — owned `LedgerSnapshot` in, owned `ScanResult`
out, `&D: DaemonEngine` held across the scan await but the
trait's `Clone + Send + Sync + 'static` bound makes the borrow
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

## 2. The six traits (Stage 1 surface, pinned for Stage 4)

Every trait below states three things the Stage 4 cutover must
preserve:

1. **Ownership** — what state the implementor owns exclusively.
2. **Surface** — methods, signatures, async-ness, error type.
3. **Invariant** — the Stage 4 implementor (a `kameo` actor)
   preserves the trait surface verbatim. New methods may be added;
   existing methods may not change signature without a new design
   round.

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
        &mut self,
        scan_result: ScanResult,
    ) -> Result<(), RefreshError>;
}
```

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
    /// `daemon` is borrowed for the duration of the scan; the
    /// implementor clones it internally (the §2.5 `Clone + Send +
    /// Sync + 'static` bound makes this cheap) if scanner
    /// construction needs an owned handle.
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

No `&mut LedgerEngine` is held across the long unlocked scan
phase. The orchestrator re-acquires the ledger borrow only for the
brief snapshot read and the brief merge call — exactly today's
locking pattern, now expressed at the trait boundary.

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
        &mut self,
        request: TxRequest,
    ) -> Result<PendingTx, SendError>;

    async fn submit(
        &mut self,
        id: ReservationId,
    ) -> Result<TxHash, Self::Error>;

    async fn discard(
        &mut self,
        id: ReservationId,
    ) -> Result<(), Self::Error>;

    fn outstanding(&self) -> usize;
}
```

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
        &mut self,
        old: &Credentials<'_>,
        new: &Credentials<'_>,
        new_kdf: KdfParams,
    ) -> Result<(), Self::Error>;
}
```

**Round 2 disposition.**

- **Q9.11 (`load_state()` method): closed no.** Loading is
  exclusively a one-shot at construction (lifecycle constructors:
  `Engine::create`, `Engine::open_full`, `Engine::open_view_only`,
  `Engine::open_hardware_offload`). Those run before any trait
  surface is in scope and stay as inherent constructors on
  `Engine<S>`. The trait covers the ongoing save/rotate surface
  only.

---

## 3. Composition: how `Engine<S>` holds the traits in Stage 1

```rust
pub struct Engine<
    S: EngineSignerKind,
    K: KeyEngine        = AllKeysBlob,
    L: LedgerEngine     = LocalLedger,
    D: DaemonEngine     = DaemonClient,
    F: PersistenceEngine = WalletFile,
    R: RefreshEngine    = LocalRefresh,
    P: PendingTxEngine  = LocalPendingTx,
> {
    keys:       K,
    ledger:     L,
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

**Type parameter ordering principle (Round 2 — Q9.12 closed).**
The order is `<S, K, L, D, F, R, P>`: dependency-leaves first
(`K`, `L`, `D`, `F` — none of these traits' Stage 1 contracts
call into other traits), compound traits last (`R` depends on `L`
and `D`; `P` depends on `K`, `L`, `D`). Within the leaf group,
narrative grouping: `K` (identity) → `L` (state) → `D` (peer) →
`F` (storage); then `R` (driver) → `P` (action). This ordering
does double duty as both dependency-leaves-first and
narrative-coherent.

### 3.1 Stage 1 implementing types ("default" types above)

| Trait | Stage 1 type | Stage 4 type |
|---|---|---|
| `KeyEngine` | `AllKeysBlob` (existing) | `kameo`-managed actor wrapping `AllKeysBlob` |
| `LedgerEngine` | `LocalLedger` (new struct wrapping `WalletLedger` + `LedgerIndexes`) | `kameo` actor |
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

---

## 4. Async story

| Trait | Sync methods | Async methods |
|---|---|---|
| `KeyEngine` | `account_public_address`, `derive_subaddress_public` | `sign_with_spend`, `view_ecdh`, `ml_kem_decapsulate` |
| `LedgerEngine` | `synced_height`, `snapshot`, `balance`, `transfers` | `apply_scan_result` |
| `RefreshEngine` | none | `produce_scan_result` |
| `PendingTxEngine` | `outstanding` | `build`, `submit`, `discard` |
| `DaemonEngine` | none | all wallet-side methods (`Rpc` supertrait methods follow `Rpc`'s own async contract) |
| `PersistenceEngine` | `base_path`, `network`, `capability` | `save_state`, `save_prefs`, `rotate_password` |

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
}
```

Existing error enums (`KeyError`, `OpenError`, `RefreshError`,
`SendError`, `PendingTxError`, `IoError`, `TxError`) stay where
they are in [`engine/error.rs`](../rust/shekyl-engine-core/src/engine/error.rs).
The `EngineError` aggregate is new; it's the type that
`Engine<S>`-level methods return and that the JSON-RPC server
converts to wire errors.

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
  (`#[cfg(test)] pub(crate)`).
- `start_refresh` integration tests against a fully-mocked engine
  ship in the same Stage 1 commit that lands the trait surfaces.

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
2. **`Engine<S, K, L, D, F, R, P>` retains its generic shape.**
   Only the default types change (from `AllKeysBlob` to the actor
   type, etc.). Production call sites continue to write
   `Engine<SoloSigner>`.
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
| `RefreshEngine` | `LedgerEngine`, `DaemonEngine` | After both prerequisites have landed. |
| `PendingTxEngine` | `KeyEngine`, `LedgerEngine`, `DaemonEngine` | After all three prerequisites have landed. |

So the strict-prerequisite chain is `DaemonEngine` →
`LedgerEngine` → (`RefreshEngine` ∥ `PendingTxEngine`).
`KeyEngine` and `PersistenceEngine` are off-the-critical-path and
can interleave wherever convenient. `RefreshEngine` and
`PendingTxEngine` can land in parallel with each other once their
prerequisites are met, but there is no dependency justifying
parallel-with-each-other landing of any other pair.

---

## 9. Open questions (remaining for Round 3+)

Rounds 1–2 closed Q9.1 through Q9.14 (dispositions captured in
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

Items raised by Round 2 that may surface in Round 3:

- **9.16 (new) — Debug-assert vs. pure-rustdoc for the
  `Engine::refresh` multi-thread-runtime precondition.** Round
  2 leans toward `debug_assert!(handle.runtime_flavor() ==
  RuntimeFlavor::MultiThread, …)` (§4.2). If Round 3 reviewers
  prefer pure-rustdoc, revisit.
- **9.17 (new) — `produce_scan_result` daemon-cloning expectation
  in §2.3's rustdoc.** The trait method takes `&D` for one
  attempt. The §2.5 `Clone + Send + Sync + 'static` bound makes
  the implementor cloning internally cheap, but the rustdoc on
  `produce_scan_result` itself should make the expectation
  explicit so implementors don't borrow `&D` across a `tokio::spawn`
  boundary by accident. Round 3+ tightens the rustdoc.

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
