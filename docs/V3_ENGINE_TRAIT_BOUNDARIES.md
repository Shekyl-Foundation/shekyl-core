# V3 Engine Trait Boundaries (Stage 1)

**Status:** Round 1 design draft. **No code changes are gated on this
document yet.** Per [`.cursor/rules/20-rust-vs-cpp-policy.mdc`](../.cursor/rules/20-rust-vs-cpp-policy.mdc),
this spec runs through 4–6 review rounds against `dev` (markdown-only
PRs) before any Rust lands. Each round either tightens an existing
section, closes an open question, or rejects a thesis with reasons.

**Scope:** Stage 1 of the staged migration pinned in
[`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md) §*"Engine
architecture: actor model with staged migration from composition"*
(2026-04-27). Stage 1 lands **trait abstractions only** — the `Engine<S>`
composition shape persists, no actor framework dependency is added,
no message-passing protocol is built. The traits exist so that Stage 2+
migrations are mechanical: the implementing types swap from concrete
fields on `Engine<S>` to `kameo` actors with a thin `ActorRef`-shaped
wrapper, and the trait surface itself does not move.

**Audience:** anyone writing or reviewing Stage 2/3/4 code in the
future. The trait surface in this document is the contract Stage 4
must preserve.

---

## 1. Charter and non-charter

### 1.1 In charter

- Define six trait surfaces: `KeyEngine`, `LedgerEngine`, `RefreshEngine`,
  `PendingTxEngine`, `DaemonEngine`, `PersistenceEngine`.
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
surface for no Stage 1 win. The alternative — `Engine<S, K, L, D, P, R>`
with default type parameters and trait-bounded `impl` blocks — keeps
production call sites unchanged (`Engine<SoloSigner>`), keeps the
trait surface free to use generic methods / associated types if Stage
4 needs them, and lets tests substitute mocks per-trait without
touching the rest of the composition.

---

## 2. The six traits (Stage 1 surface, pinned for Stage 4)

Every trait below states three things the Stage 4 cutover must preserve:

1. **Ownership** — what state the implementor owns exclusively.
2. **Surface** — methods, signatures, async-ness, error type.
3. **Invariant** — the Stage 4 implementor (a `kameo` actor) preserves
   the trait surface verbatim. New methods may be added; existing
   methods may not change signature without a new design round.

### 2.1 `KeyEngine`

**Ownership.** The full `AllKeysBlob`: spend secret, view secret,
ML-KEM-768 decap key, and the cached classical / PQC public keys. No
other actor sees raw key material in Stage 4; key access goes through
this trait surface only.

**Stage 1 surface (proposed).**

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
    fn sign_with_spend(
        &self,
        domain: SignDomain,
        message: &[u8],
    ) -> Result<Ed25519Signature, Self::Error>;

    /// Compute the view-side ECDH shared secret for an output's
    /// transaction-key. Used by the scanner; never returns the
    /// raw view scalar.
    fn view_ecdh(
        &self,
        tx_pub_key: &EdwardsPoint,
    ) -> Result<SharedSecret, Self::Error>;

    /// ML-KEM-768 decapsulate against an incoming output's
    /// encapsulated key. Returns the shared secret only; the decap
    /// key itself does not leave the implementor.
    fn ml_kem_decapsulate(
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

**Open questions for Round 2.**

- Should `sign_with_spend` be `async fn`? Stage 4 actor signing
  involves a message round-trip; making the trait sync forces every
  call site to block-on, which is wrong for the actor migration. But
  Stage 1's `AllKeysBlob` impl is purely CPU. Tentative answer: **the
  trait is `async`; Stage 1 implementations spell out `async fn` and
  return `Ready` futures.**
- `SignDomain` — do we enumerate every domain at Stage 1, or is the
  enum `#[non_exhaustive]` for additive Stage-2-onwards growth? The
  multisig V3.1 path adds at least two new domains (witness commit,
  partial signature). Tentative: **`#[non_exhaustive]`, V3.0 enumerates
  the four current domains.**
- Does `KeyEngine` need a `wipe()` method, or does `Drop` on the
  implementor cover it? Today `AllKeysBlob: ZeroizeOnDrop`. If the
  Stage 4 actor wraps the keys in its own task, the actor's `Drop`
  inherits the wipe. Tentative: **no `wipe()` method; the trait
  contract is "the implementor zeroizes on drop and on
  process-explicit lock."**

### 2.2 `LedgerEngine`

**Ownership.** `WalletLedger` (the persistent ledger), `LedgerIndexes`
(the runtime-only derived indexes rebuilt at every open per the
*RuntimeWalletState audit* decision-log entry, 2026-04-25), and the
runtime-only `BTreeMap<ReservationId, Reservation>` reservation
tracker.

**Stage 1 surface (proposed).**

```rust
pub trait LedgerEngine {
    type Error: Into<LedgerError>;

    /// Synced height as of the last successful merge. The
    /// snapshot taken below uses this as its `synced_height`
    /// field.
    fn synced_height(&self) -> u64;

    /// Take a fresh `LedgerSnapshot` for refresh's
    /// snapshot-merge-with-retry loop. Cheap (clones the
    /// reorg-window descriptors, not the full ledger).
    fn snapshot(&self) -> LedgerSnapshot;

    /// Apply a producer-emitted `ScanResult`. Returns
    /// `RefreshError::ConcurrentMutation` iff the scan result's
    /// `start_height` no longer matches `synced_height + 1`
    /// (somebody else merged between the snapshot and now); the
    /// refresh driver retries with a fresh snapshot.
    fn apply_scan_result(
        &mut self,
        scan_result: ScanResult,
    ) -> Result<(), RefreshError>;

    /// Read-only balance computation. Stage 4 makes this a
    /// snapshot-bypass-the-mailbox path per the architecture
    /// decision-log entry's "snapshot reads bypassing the actor
    /// message queue where safe" refinement.
    fn balance(&self, filter: BalanceFilter) -> Balance;

    /// Read-only transfer query.
    fn transfers(&self, filter: TransferFilter) -> Vec<TransferDetails>;
}
```

**Open questions for Round 2.**

- Does `snapshot()` belong on `LedgerEngine` or on `RefreshEngine`?
  Today the snapshot is taken inside `Engine::refresh` against the
  ledger directly. The decision turns on whether the scanner-side
  cancellation contract (four checkpoints) is owned by `LedgerEngine`
  or `RefreshEngine`. **Tentative: `snapshot()` is on `LedgerEngine`
  because it's a read against ledger state; the scan loop using it
  is `RefreshEngine`'s concern.**
- `apply_scan_result` returns `RefreshError`, not `Self::Error`. Is
  the error type cross-trait, or does each trait have its own family?
  See §5.

### 2.3 `RefreshEngine`

**Ownership.** The single-flight slot (`RefreshSlot`), the producer
loop (`run_refresh_task`), and the cancellation token plumbing. Does
**not** own ledger or daemon state — it borrows both.

**Stage 1 surface (proposed).**

```rust
pub trait RefreshEngine {
    type Error: Into<RefreshError>;

    /// Spawn the refresh loop. Returns a `RefreshHandle` whose
    /// `cancel()` and cancel-on-drop semantics drive the four
    /// cancellation checkpoints documented in `run_refresh_task`'s
    /// rustdoc (top-of-attempt, post-tip-fetch, mid-scan,
    /// pre-merge — no post-merge checkpoint by design).
    ///
    /// The handle's `progress()` watcher is a cloneable observer.
    /// `is_running()` / `join()` semantics are unchanged from the
    /// Phase 2a Branch 2 surface.
    async fn start(
        &self,
        opts: RefreshOptions,
    ) -> Result<RefreshHandle, Self::Error>;

    /// Synchronous one-shot variant. Cancel-internal: the token is
    /// created fresh per call and never fires. Equivalent to
    /// `start().await.join().await` from a sync context, modulo
    /// the token plumbing. Pinned by the
    /// 2026-04-28 docstring rewrite at refresh.rs:1815-…
    fn refresh_once(
        &mut self,
        opts: &RefreshOptions,
        runtime: &tokio::runtime::Handle,
    ) -> Result<RefreshSummary, Self::Error>;
}
```

**Open questions for Round 2.**

- **Single trait or split?** `RefreshEngine` arguably has two
  responsibilities: the *driver* (snapshot-merge-with-retry, slot
  ownership) and the *producer* (`produce_scan_result`, scanner
  ownership). Today both live in `engine::refresh`. Splitting would
  give `RefreshDriver` (owns slot + driver loop + retry) and
  `ScanProducer` (owns scanner + `produce_scan_result` + cancel
  checkpoints 2 and 3). The producer is the more obvious
  parallelization target (a Stage 4 worker pool of `BlockScannerActor`s).
  **Tentative: keep one trait at Stage 1, split at Stage 4 if the
  worker-pool implementation needs the boundary. The trait surface
  is unchanged either way; only the implementing type shape moves.**
- `start()` requires a way to share state across the spawn boundary.
  Today this is `Arc<RwLock<Engine<S>>>`. The trait can either
  encode the share through a `Self`-shaped type-param or sidestep
  the question by saying "the implementor owns whatever sharing
  mechanism it needs; the trait surface is `start(&self, opts)`."
  **Tentative: latter.** The Stage 4 actor implementation uses an
  `ActorRef` clone, which fits the `&self` signature naturally.

### 2.4 `PendingTxEngine`

**Ownership.** The reservation tracker (`BTreeMap<ReservationId,
Reservation>`), the monotonic `next_reservation_id` counter, and the
two-phase build/submit/discard state machine pinned in the *Pending-tx
protocol* decision-log entry (2026-04-27).

**Stage 1 surface (proposed).**

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

**Open questions for Round 2.**

- `build` returns `SendError`, not `Self::Error`. The split exists
  today because `SendError` covers both build-time validation
  (insufficient funds, no spendable outputs) and runtime
  invariants. Decision: keep the existing split or unify? **Tentative:
  keep — `SendError` is the build-side error vocabulary;
  `PendingTxError` is the runtime-invariant error vocabulary.**
- The `inspect`, `adjust_fee`, `sign_partial` methods listed in the
  Pending-tx protocol decision-log entry are V3.1+ (multisig). They
  do not appear in Stage 1's trait surface; Stage 4 adds them
  additively. Confirm via §7's invariant.

### 2.5 `DaemonEngine`

**Ownership.** The RPC client (today: `SimpleRequestRpc` wrapped in
`DaemonClient`), connection state, retry policy.

**Stage 1 surface (proposed).**

```rust
pub trait DaemonEngine: Clone + Send + Sync + 'static {
    type Error: Into<IoError>;

    async fn get_height(&self) -> Result<u64, Self::Error>;

    async fn get_scannable_block(
        &self,
        height: u64,
    ) -> Result<ScannableBlock, Self::Error>;

    async fn get_fee_estimates(&self) -> Result<FeeEstimates, Self::Error>;

    async fn submit_transaction(
        &self,
        tx_bytes: Vec<u8>,
    ) -> Result<TxSubmitOutcome, Self::Error>;
}
```

**Why `Clone + Send + Sync + 'static`.** The daemon handle is
shared by clone with the producer task (`run_refresh_task` requires
moving a `DaemonClient` into a `tokio::spawn`'d future). That bound
already holds for `DaemonClient`/`SimpleRequestRpc`; pinning it on the
trait makes the requirement explicit and Stage-4-actor-compatible
(an `ActorRef<DaemonActor>` is also `Clone + Send + Sync + 'static`).

**Open questions for Round 2.**

- Is `DaemonEngine` distinct from `shekyl_rpc::Rpc`? Today
  `MockRpc: Rpc` and `DaemonClient` wraps `SimpleRequestRpc: Rpc`,
  so `Rpc` already plays the test-mocking role at the producer
  level. Two views:
  1. `DaemonEngine` is exactly `Rpc` re-exported with the
     wallet-specific extra methods (`get_fee_estimates`,
     `submit_transaction`) added.
  2. `DaemonEngine` is a wallet-side trait that *contains* an `Rpc`
     impl, layering wallet-specific operations on top.
  **Tentative: (1).** Single trait; the wallet-side methods are
  added to `Rpc` (which lives in `shekyl-oxide`'s rpc crate, but
  Shekyl is the only consumer). The alternative makes the test
  scaffolding write two mocks for one thing.
- Closes [`docs/FOLLOWUPS.md`](FOLLOWUPS.md) "Generic `DaemonClient`"
  in *spec*. The implementation lands in V3.1 per the existing
  follow-up; Stage 1 only requires the trait shape.

### 2.6 `PersistenceEngine`

**Ownership.** The `WalletFile` handle, advisory lock on
`<base>.keys`, KEK rewrap on password rotation, atomic file writes.

**Stage 1 surface (proposed).**

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

**Open question for Round 2.**

- Does `PersistenceEngine` need a `load_state()` method, or is
  loading handled exclusively by the lifecycle constructors
  (`Engine::create` / `Engine::open_full`) which run before any
  trait surface is in scope? **Tentative: no `load_state()` —
  loading is a one-shot at construction, the trait covers the
  ongoing save/rotate surface only.**

---

## 3. Composition: how `Engine<S>` holds the traits in Stage 1

```rust
pub struct Engine<
    S: EngineSignerKind,
    K: KeyEngine = AllKeysBlob,
    L: LedgerEngine = LocalLedger,
    R: RefreshEngine = LocalRefresh,
    P: PendingTxEngine = LocalPendingTx,
    D: DaemonEngine = DaemonClient,
    F: PersistenceEngine = WalletFile,
> {
    keys: K,
    ledger: L,
    refresh: R,
    pending: P,
    daemon: D,
    file: F,
    network: Network,
    capability: Capability,
    _signer: PhantomData<S>,
}
```

Production code writes `Engine<SoloSigner>` and the defaults plug in;
test code writes `Engine<SoloSigner, MockKey, MockLedger, …>` with
whatever subset it needs. Default type parameters carry the production
ergonomics; the generic surface unlocks the test boundary in §6.

The `Arc<RwLock<Engine<S, …>>>` self-arc that `Engine::start_refresh`
takes today is unaffected by Stage 1 — it stays a transitional shape
on the way to the Path B `HashMap<EngineId, ActorRef<EngineActor>>`
boundary that Stage 4 introduces. The trait surface for `RefreshEngine`
above does not name `Arc<RwLock<…>>`; that's an implementation detail
of the Stage 1 `LocalRefresh` type, not part of the contract.

**Stage 1 implementing types (the "default" types above).**

| Trait | Stage 1 type | Stage 4 type |
|---|---|---|
| `KeyEngine` | `AllKeysBlob` (existing) | `kameo`-managed actor wrapping `AllKeysBlob` |
| `LedgerEngine` | `LocalLedger` (new struct wrapping `WalletLedger` + `LedgerIndexes`) | `kameo` actor |
| `RefreshEngine` | `LocalRefresh` (new struct wrapping `RefreshSlot` + the producer driver) | `kameo` actor |
| `PendingTxEngine` | `LocalPendingTx` (new struct wrapping the reservation tracker) | `kameo` actor |
| `DaemonEngine` | `DaemonClient` (existing) | `kameo` actor wrapping `DaemonClient` |
| `PersistenceEngine` | `WalletFile` (existing) | `kameo` actor wrapping `WalletFile` |

The new `Local*` types are **moves**, not rewrites: existing fields on
`Engine<S>` (`ledger: WalletLedger`, `indexes: LedgerIndexes`,
`reservations: BTreeMap<…>`, `next_reservation_id: u64`,
`refresh_slot: RefreshSlot`) move into the corresponding `Local*`
structs. The current methods on `Engine<S>` move to `impl LedgerEngine
for LocalLedger` / `impl RefreshEngine for LocalRefresh` / etc.,
preserving existing test coverage.

---

## 4. Async story

| Trait | Sync methods | Async methods | Reasoning |
|---|---|---|---|
| `KeyEngine` | `account_public_address`, `derive_subaddress_public` | `sign_with_spend`, `view_ecdh`, `ml_kem_decapsulate` | Pure-CPU but Stage 4 actor crosses a task boundary; async surface is forward-compatible. Stage 1 impls are `async fn` returning ready futures. |
| `LedgerEngine` | `synced_height`, `snapshot`, `apply_scan_result`, `balance`, `transfers` | none | Stage 1 mutations are `&mut self` synchronous against in-memory state; Stage 4 dispatches via the actor mailbox which the trait re-exports as `async`. The `async` lift happens at Stage 4, not Stage 1, because Stage 1's read paths are the snapshot-bypass-the-mailbox refinements pinned in the architecture decision. |
| `RefreshEngine` | `refresh_once` | `start` | Pinned by the 2026-04-28 cancellation-contract docstring: sync path stays cancel-internal, async path owns cancellation. |
| `PendingTxEngine` | `outstanding` | `build`, `submit`, `discard` | `submit` calls `daemon.submit_transaction()` which is async; the trait propagates the async boundary upward. `outstanding` is a count accessor with no await. |
| `DaemonEngine` | none | all methods | Network I/O is intrinsically async. |
| `PersistenceEngine` | `base_path`, `network`, `capability` | `save_state`, `save_prefs`, `rotate_password` | File I/O is async (`tokio::fs`). The accessors are cached values that don't need `await`. |

**Open question for Round 2.** `LedgerEngine::apply_scan_result` is
sync today; should the trait pre-emptively make it `async fn` so
Stage 4 doesn't have to break the surface? Counter-argument: the
"snapshot reads bypassing the actor message queue" refinement
specifically lands as accessor methods returning cloned immutable
state, and `apply_scan_result` is the *write* path which always
goes through the mailbox; the surface is `async` either way. **Tentative:
make all `LedgerEngine` mutations `async` at Stage 1 to lock the
Stage 4 surface verbatim.** Re-examining in Round 2.

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
`SendError`, `PendingTxError`, `IoError`, `TxError`) stay where they
are in [`engine/error.rs`](../rust/shekyl-engine-core/src/engine/error.rs).
The `EngineError` aggregate is new; it's the type that
`Engine<S>`-level methods return and that the JSON-RPC server
converts to wire errors.

`RefreshError::ConcurrentMutation` stays on `LedgerEngine`'s
`apply_scan_result` return — it's the contract signal between
ledger and refresh, not a refresh-private error.

**Open question for Round 2.** Should `EngineError` use `#[from]`
impls per variant, or explicit conversions only? `#[from]` is
ergonomic but obscures error-flow at audit time. Tentative:
**`#[from]` for the four straight-line lifts, explicit conversions
for the `Send → PendingTx` and `Refresh → Send` cross-domain ones**.

---

## 6. Test boundary

The trait abstractions unlock a category of test that is not possible
today: a **fully-mocked `Engine<SoloSigner, MockKey, MockLedger,
MockDaemon, …>`** that drives `start_refresh` end-to-end with
deterministic chain state, deterministic key material, and no
filesystem.

Today's test coverage:

- **Producer-only:** `MockRpc` in [`engine/test_support.rs`](../rust/shekyl-engine-core/src/engine/test_support.rs)
  drives `produce_scan_result` directly. Twelve producer tests cover
  the linear-scan / reorg / RPC-failure / cancellation paths.
- **Driver-only with partial mocking:** the driver-side tests in
  `engine/refresh.rs` build a real `Engine<SoloSigner>` against an
  unreachable `SimpleRequestRpc` URL and assert error-path behavior.
  No tests exercise `start_refresh` against a synthetic chain
  end-to-end because there's no way to plug a `MockRpc` into
  `DaemonClient`.

Stage 1 closes this gap. With `DaemonEngine` as a trait,
`MockRpc: DaemonEngine` and the existing chain-injection harness
(`replace_chain_from`, `queue_height_error`, `queue_block_error`)
becomes available to `start_refresh` integration tests directly.

`MockKey` and `MockPersistence` in particular let tests skip the
`AllKeysBlob` rederivation cost and the file-open advisory-lock
ceremony, which today add ~50–200 ms per test.

**Pinned commitments for Stage 1:**

- Each trait gets a `Mock*` implementor in `engine::test_support` (`#[cfg(test)] pub(crate)`).
- The mocks share a deterministic-RNG injection surface so reorg /
  failure-injection scenarios are byte-stable across CI runs.
- `start_refresh` integration tests against a fully-mocked engine
  ship in the same Stage 1 commit that lands the trait surfaces.

---

## 7. Stage 4 transition guarantee

Each trait's invariant for the Stage 4 cutover, stated explicitly so
Stage 4 implementors cannot argue for redesign:

1. **The trait surface in §2 does not change.** Stage 4 may add
   methods (additively), but no existing method changes signature,
   async-ness, error type, or ownership semantics.
2. **`Engine<S, K, L, R, P, D, F>` retains its generic shape.** Only
   the default types change (from `AllKeysBlob` to the actor type,
   etc.). Production call sites continue to write `Engine<SoloSigner>`.
3. **The `Mock*` test scaffolding remains valid.** Stage 4 does not
   rewrite the test surface; the same mocks drive the same trait
   methods against the actor-backed types.
4. **Cancellation semantics are preserved verbatim.** The four-checkpoint
   contract documented in `run_refresh_task`'s rustdoc and the sync /
   async split documented in `Engine::refresh`'s rustdoc are part of
   the trait contract, not implementation details. The Stage 4 actor
   for `RefreshEngine` observes the same checkpoints in the same order.

If any Stage 4 PR proposes violating one of the above, the PR's
review surface is *this document*, not the PR's diff: the violation
either re-opens this spec for a new round, or the proposal is
rejected.

---

## 8. Migration order and gates

| # | Stage | Lands on | Gates |
|---|---|---|---|
| 1 | Stage 1 traits + Stage 1 default impls + `Mock*` test scaffolding | `dev` (single PR or short-branch series) | This spec accepted (rounds closed); `cargo test -p shekyl-engine-core` green; no FFI changes; no `Cargo.toml` changes beyond intra-workspace. |
| 2 | Stage 2: `KeyEngine` migration to `kameo` actor | `dev` | Stage 1 landed; `kameo` framework decision committed; MSRV ≥ kameo's required version (≥1.88 per the architecture decision). |
| 3 | Stage 3 (Phase 2b): `StakeEngine` actor-from-inception | Phase 2b branch | Stage 2 landed; `kameo` validated against `KeyEngine`. |
| 4 | Stage 4: remaining trait migrations + Path B binary boundary | post-Phase-2b | Stage 3 landed; the architecture decision's "no-cycle DAG" / "bounded mailboxes" / "cross-leaf immutable-data" disciplines applied. |

**Within Stage 1**, the recommended landing order is:

1. `DaemonEngine` first — closes the test-boundary gap (§6) and
   unlocks every other trait's integration tests.
2. `LedgerEngine` second — large surface but mechanical extraction
   from existing `Engine<S>` methods.
3. `RefreshEngine`, `PendingTxEngine`, `KeyEngine` in parallel —
   each is bounded; ordering is reviewer convenience.
4. `PersistenceEngine` last — has the smallest current call-site
   density and the least Stage 4 pressure.

---

## 9. Open questions (consolidated)

This list is the Round 2+ agenda. Each item either gets a written
answer in a subsequent round or is explicitly deferred to Stage 2+.

**§2.1 KeyEngine**
- 9.1 `sign_with_spend` async-ness (tentative: async).
- 9.2 `SignDomain` `#[non_exhaustive]` (tentative: yes).
- 9.3 Explicit `wipe()` method (tentative: no).

**§2.2 LedgerEngine**
- 9.4 `snapshot()` location (tentative: `LedgerEngine`).
- 9.5 Cross-trait `RefreshError` on `apply_scan_result` (tentative: keep).

**§2.3 RefreshEngine**
- 9.6 Single trait vs. driver/producer split (tentative: single, split at Stage 4 if needed).
- 9.7 Trait-level expression of `Arc<RwLock<…>>` self-arc (tentative: not expressed).

**§2.4 PendingTxEngine**
- 9.8 `build` returns `SendError` vs. `Self::Error` (tentative: keep `SendError`).
- 9.9 V3.1 multisig methods inclusion (tentative: not in Stage 1 surface; additive at Stage 4).

**§2.5 DaemonEngine**
- 9.10 Subset/superset of `shekyl_rpc::Rpc` (tentative: superset; `DaemonEngine = Rpc + wallet-side methods`).

**§2.6 PersistenceEngine**
- 9.11 `load_state()` method (tentative: no; loading is lifecycle-only).

**§3 Composition**
- 9.12 Default type parameter ordering (`<S, K, L, R, P, D, F>` vs.
  alphabetical vs. dependency-order). Cosmetic but affects every
  test fixture's turbofish.

**§4 Async story**
- 9.13 `LedgerEngine` mutations async at Stage 1 vs. Stage 4 (tentative: Stage 1).

**§5 Error model**
- 9.14 `#[from]` vs. explicit conversions on `EngineError` (tentative: hybrid).

**§7 Stage 4 guarantee**
- 9.15 Where does the "trait contract is part of the spec" claim get
  enforced operationally? (Tentative: PR-template checkbox citing
  this document; Round 6 closes the operational form.)

---

## Cross-references

- [`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md) §*"Engine architecture: actor model with staged migration from composition"* (2026-04-27) — the architectural commitment this spec realizes.
- [`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md) §*"Engine binary boundary: pure message-passing over shared handle"* (2026-04-27) — Path B, retires the outer `Arc<RwLock<Engine>>` at Stage 4.
- [`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md) §*"`RefreshHandle` (Phase 2a Branch 2) ships transitional `Arc<RwLock<Engine>>` under Path B"* (2026-04-27) — explicit pin that the current self-arc is transitional.
- [`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md) §*"Pending-tx protocol: two-phase build/submit/discard over single-phase callback"* (2026-04-27) — the `PendingTxEngine` surface.
- [`rust/shekyl-engine-core/src/engine/refresh.rs`](../rust/shekyl-engine-core/src/engine/refresh.rs) `run_refresh_task` rustdoc — the four-checkpoint cancellation contract.
- [`rust/shekyl-engine-core/src/engine/refresh.rs`](../rust/shekyl-engine-core/src/engine/refresh.rs) `Engine::refresh` rustdoc (post-2026-04-28) — the sync-vs-async cancellation split.
- [`rust/shekyl-engine-core/src/engine/test_support.rs`](../rust/shekyl-engine-core/src/engine/test_support.rs) — current `MockRpc` and `make_synthetic_block` scaffolding.
- [`docs/FOLLOWUPS.md`](FOLLOWUPS.md) "Generic `DaemonClient`" — closed in spec by §2.5 DaemonEngine; implementation V3.1.
- [`.cursor/rules/20-rust-vs-cpp-policy.mdc`](../.cursor/rules/20-rust-vs-cpp-policy.mdc) — the "4–6 review rounds before any Rust" rule this document is run against.
