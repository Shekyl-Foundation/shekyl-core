# Stage 2 — `KeyEngine` → `kameo` actor migration (design)

**Status:** design-only. No implementation, no wiring, no field edits to
`Engine`. This document and its §9 round record are the deliverable; the
implementation lands as its own PR(s) per
[`06-branching.mdc`](../../.cursor/rules/06-branching.mdc) once this design
closes.

**Process discipline:** authored under
[`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
— Round 0 pre-flight (A2 substrate re-audit at source, B6 numeric-constant
verification, B9 bench plan), adversarial rounds 1–5, a late-round
threat-model addenda pass (A3, §7), and two external-critique passes
(Rounds 6–7, §9). Specification-first per
[`05-system-thinking.mdc`](../../.cursor/rules/05-system-thinking.mdc): the
message protocol (§2) falls out of the trait spec, not the reverse.

**Binding constraint when arbitrating:**
[`00-mission.mdc`](../../.cursor/rules/00-mission.mdc) priority-1
(security/PQC). The load-bearing property is *no secret material crosses the
trait boundary* (M3-series). This migration must preserve it **by
construction**, not by discipline: the full `AllKeysBlob` lives only inside
the actor task; the mailbox carries non-secret request/reply values only.

---

## 0. Round 0 pre-flight — substrate audit and prerequisite findings

All claims below were re-read at source on the `dev` tip
(`91f8c66db`, post-PR #98). `path:line` citations are to that tip.

### 0.1 Frozen trait surface (verified)

`pub(crate) trait KeyEngine: Send + Sync + 'static`
(`rust/shekyl-engine-core/src/engine/traits/key.rs:616`). Four methods, with
the exact shapes the migration must preserve:

| Method | Signature (verbatim shape) | Sync/async | Return ownership |
|---|---|---|---|
| `account_public_address` | `fn account_public_address(&self) -> &AccountPublicAddress` (`key.rs:645`) | sync | **borrowed `&`** |
| `derive_subaddress` | `fn derive_subaddress(&self, idx: SubaddressIndex, purpose: SubaddressPurpose) -> Result<SubaddressFor, Self::Error>` (`key.rs:693`) | **sync** | owned |
| `try_claim_output` | `async fn try_claim_output(&self, input: &OutputDetectionInput) -> Result<OutputClaimResult, Self::Error>` (`key.rs:764`) | async | owned |
| `sign_transaction` | `async fn sign_transaction(&self, tx: &TxToSign) -> Result<TxSignatures, Self::Error>` | async | owned |

Plus `type Error: Into<KeyEngineError>` (`key.rs:617`).

Two surface facts that drive the spec (§2):

- `AccountPublicAddress` is `#[derive(Clone, Debug)]` and public-only —
  "the 1216-byte ML-KEM-768 PK and the 65-byte classical address bytes"
  (`key.rs:113-117`). The trait doc already states the implementor "returns a
  borrowed reference to an `AccountPublicAddress` field cached at construction
  (`&self.account_public_address`), acquiring no lock" (`key.rs:642-644`).
- `derive_subaddress` is **synchronous**. The `Audit` purpose is a pure
  function of public spend/view keys (`local_keys.rs:459-460`, the primary-
  vs-derived branch); the `Recipient` purpose is a **stub** returning
  `KeyEngineError::RecipientSubaddressKemKeygenNotImplemented`
  (`local_keys.rs` `derive_subaddress` `_ => Err(...)` arm; `error.rs`).

### 0.2 Current composition and the true blast radius (verified)

`Engine` holds `keys: Arc<AllKeysBlob>` (`mod.rs:344`). The DoD says replace
this with a `KeyEngineHandle`. The pre-flight question A2 forces is *what
actually reads the blob today* — the trait surface being actor-ready does not
mean the data flow is. Audit of every `keys` / `AllKeysBlob` reader inside
`rust/shekyl-engine-core/src/engine/`:

1. **`Engine::keys()` accessor** (`mod.rs:728`) — `#[allow(dead_code)]`. The
   in-code comment (`mod.rs:711-716`) states the only live consumer is the
   **test-only** `Engine::replace_refresh` setter; the `refresh.rs:3160/3329`
   readers are inside `#[cfg(test)]`. **No production caller.** Removal is
   clean.
2. **`merge.rs:218-223`** — `populate_engine_handle_fields(&mut …,
   self.keys.view_sk.as_canonical_bytes(), &detection_residue, &inserted)`.
   This is a **production reader of raw `view_sk`** on the scanner-merge post-
   pass (the `derive_output_handle` path the task brief names). The merge.rs
   comment (`merge.rs:213-215`) already records the planned disposition:
   *"becomes async at M3c+ when re-routed through `KeyEngine::try_claim_output`."*
3. **`LocalSigner.keys: Arc<AllKeysBlob>`** (`signer.rs:292-298`) — the
   pending-tx signer holds a second strong `Arc` of the full blob. Its
   `sign_transfer` is a **Phase-1 stub** returning an empty body
   (`signer.rs:329-343`); it does not yet touch the blob.
4. **`ViewMaterial`** (`view_material.rs`) — a *view-and-spend secret bundle*
   (`view_scalar: Zeroizing<Scalar>`, `x25519_sk: Zeroizing<[u8;32]>`, …)
   derived from `&AllKeysBlob` at `assemble` (`lifecycle.rs:698`,
   `ViewMaterial::try_from_keys`) and **moved** into `LocalRefresh`
   (`lifecycle.rs:715`). Non-`Clone`; wipe-on-drop. Its module doc explicitly
   commits to the actor future: *"the Stage 4 actor-mesh cutover preserves
   this contract: `LocalRefresh` migrates from orchestrator-owned to
   actor-owned; `ViewMaterial` crosses the actor envelope at construction and
   drops with the actor body"* (`view_material.rs:31-34`).
5. **`LocalKeys`** internals (`local_keys.rs:396-552`) — `self.keys.*`
   everywhere; this *is* the would-be actor body and is in-scope by design.

**Finding (the load-bearing pre-flight result).** The trait surface is
actor-ready, but "`Engine<S>` holds a `KeyEngineHandle` … no `&AllKeysBlob`
escapes" is **not** a one-field swap. It requires disposing of three non-actor
key holders (#2 merge view_sk, #3 `LocalSigner` blob) and reconciling the
sanctioned construction-time view projection (#4 `ViewMaterial`). This is the
"trait surface is correct but the data flow contradicts it" shape that
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
§"Discovery cadence" predicts; the per-trait migration is the fix, and §6
decomposes it. The architecturally-integral-now disposition is preferred
(pre-genesis, bounded cost).

### 0.3 Prerequisite: "Stage 1 actor-friendly trait-boundary refactor" — landed?

`FOLLOWUPS.md:1022-1024` lists Stage 2 as blocking on the *"Stage 1
actor-friendly trait boundaries (the framework-agnostic refactor that lands
between Branch 2 closing and Phase 2b cutting)."*

**Disposition (b): the current trait surface is already actor-ready; no
separate precursor refactor PR is outstanding.** Evidence:

- The decision-log stage sequence names item 4 *"Stage 1 — framework-agnostic
  trait abstractions … defined as trait boundaries with owned-or-borrowed
  inputs and owned returns … **No actor framework dependency yet**"*
  (`V3_WALLET_DECISION_LOG.md:2703-2711`). This **is** the "actor-friendly
  refactor."
- `FOLLOWUPS.md:50-59` (closeout audit) records the Stage 1 trait-extraction
  chain as landed on `dev` through PR #94; the orchestrator is the
  seven-parameter `Engine<S, D, L, E, R, P, F>`.
- A repository grep for any un-landed "actor-friendly / framework-agnostic
  refactor" PR returns **only documentation references** (`FOLLOWUPS.md`,
  `V3_ENGINE_TRAIT_BOUNDARIES.md`), not an open branch.
- The trait methods already return owned values (`OutputClaimResult`,
  `SubaddressFor`, `TxSignatures`) or take owned/borrowed inputs — actor-ready
  by construction. The **one** residual is `account_public_address`'s borrowed
  return, which §2.3 resolves at the handle layer with **no trait change**.

So the design does **not** scope a precursor refactor PR (option (a)). It
proceeds against the landed trait surface, with the borrowed-return handled in
the handle and the data-flow migration (§0.2) scoped in §6.

### 0.4 Prerequisite: no production work to dispatch yet (verified)

- `sign_transaction` / `LocalSigner::sign_transfer` are stubs
  (`signer.rs:329-343`; `KeyEngineError::SignTransactionTraitSurfaceIncomplete`).
- Output-claim is served in production by `populate_engine_handle_fields` /
  `derive_output_handle` on the merge path (`merge.rs:218`), **not** by
  `try_claim_output` (whose live wiring is the planned M3c+ re-route).

**Consequence for validation (§5):** the actor cannot be benchmarked against
real FCMP++ signing (it does not exist). The bench is therefore anchored to
`try_claim_output`'s **real** cryptographic cost (X25519 view-tag pre-filter +
hybrid ML-KEM-768 decap + HKDF chain + key-image computation,
`local_keys.rs:504-552`), which is live, deterministic, and dominates the
mailbox round-trip. §5.3 specifies the bench-vs-bench threshold against that
baseline. No Phase-2 functionality is invented.

### 0.5 `kameo` 0.20.0 API — verified at source (dependency-discipline)

Per [`17-dependency-discipline.mdc`](../../.cursor/rules/17-dependency-discipline.mdc),
the `kameo = "=0.20.0"` pin (`rust/Cargo.toml:226`, MSRV 1.88 at `:117`) is
declared-only; this is the first design to consume it, so the
supervision/mailbox/lifecycle surface was read at the pinned version
(docs.rs `kameo/0.20.0`), not from training-data recall. Load-bearing facts:

- **`Actor` trait** (`kameo::actor::Actor`):
  `type Args: Send`; `type Error: ReplyError`;
  `async fn on_start(args: Self::Args, actor_ref: ActorRef<Self>) -> Result<Self, Self::Error>` (**required** — the actor builds `Self` *inside its own task* from `Args`);
  provided `on_stop(&mut self, WeakActorRef<Self>, ActorStopReason) -> Result<(), Self::Error>`,
  `on_panic(&mut self, WeakActorRef<Self>, PanicError) -> Result<ControlFlow<ActorStopReason>, Self::Error>`,
  `supervision_strategy() -> SupervisionStrategy`.
- **`Spawn` trait** (blanket-impl'd): `spawn(args) -> ActorRef<Self>` uses **a
  bounded mailbox of capacity 64 by default** (docs: *"By default, a bounded
  mailbox with capacity 64 is used to provide backpressure"*).
  `spawn_with_mailbox(args, kameo::mailbox::bounded(n) | ::unbounded())` for
  overrides. `supervise(sup, args)` requires **`Args: Clone + Sync`**;
  `supervise_with(sup, factory)` retains an `Fn() -> Args` closure (requires
  `Args: Send`).
- **`Message<M>`**: `type Reply`;
  `async fn handle(&mut self, msg, ctx: &mut Context<Self, Self::Reply>) -> Self::Reply`.
  Dispatched via `ActorRef::ask` / `::tell`. The handler takes **`&mut self`**;
  kameo processes one message at a time (single-consumer mailbox).
- **`ActorRef<T>`** is `Clone` (a sender handle), `Send + Sync`.
- **Issue #306** (multi-hop `ctx.forward` panics on error) and the no-cycle
  DAG are recorded in `V3_WALLET_DECISION_LOG.md:3428-3445`; KeyEngine is a
  leaf, so neither bites here (no downward `ask` from KeyEngine).

**Dependency-discipline finding (B6 / convention drift).** The workspace
convention text says actors declare a bound at a `#[actor(mailbox = …)]` site
(`Cargo.toml:223-225`; `FOLLOWUPS.md:918-925`). **kameo 0.20.0 has no such
attribute** — mailbox capacity is a `spawn_with_mailbox` argument, and the
default `spawn` is already bounded at 64. The convention's *intent* (every
actor is bounded; 64 default; documented per-actor overrides) is satisfiable,
but the *mechanism* in the prose is aspirational. §4 specifies the real API
usage; the implementation PR should correct the `Cargo.toml` convention note
when it adds the first live consumer (it is the FOLLOWUP-closing commit).

---

## 1. Objective and shape

Migrate `KeyEngine` from a composed `Arc<AllKeysBlob>` field on `Engine<S>`
into a `kameo` actor (`KeyActor`) owning `AllKeysBlob` privately in its own
task, addressed through a `KeyEngineHandle`. The trait method signatures are
unchanged; the handle implements `KeyEngine` by dispatching to the actor
(async, state-evolving methods) or by serving from a handle-owned immutable
public projection (sync / borrowed methods). End-state for this stage:

- `KeyActor` runs as a `kameo` actor with its own task; sole owner of the full
  `AllKeysBlob`.
- `Engine<S>` holds `key: KeyEngineHandle` in place of `keys: Arc<AllKeysBlob>`
  (`mod.rs:344`). **No inline `K: KeyEngine` generic parameter is introduced**
  (`FOLLOWUPS.md:88-94` reversion clause; `mod.rs` stays seven-parameter
  `Engine<S, D, L, E, R, P, F>`).
- The three non-actor key holders from §0.2 are disposed of per §6.
- No `&AllKeysBlob` (or raw spend/view/decap bytes) crosses the mailbox.

---

## 2. Spec — the message protocol

### 2.1 Which methods are actor messages vs handle-resolved

The decision log's free-function-vs-message boundary
(`V3_WALLET_DECISION_LOG.md:3307-3350`) and cross-leaf immutable-data pattern
(`:3381-3426`) give the mechanical rule: a method is an **actor message** iff
it reads or mutates *mutable, secret-bearing* engine state at call time; a
method that depends only on *immutable construction-time* material (or returns
a stub) is **handle-resolved** without a mailbox round-trip.

| Trait method | Stage-2 routing | Justification |
|---|---|---|
| `account_public_address` | **handle-resolved** | Public, immutable, cached at construction (`key.rs:642-644`). Cross-leaf immutable pattern → no mailbox. §2.3. |
| `derive_subaddress` (Audit) | **handle-resolved** | Pure function of immutable public spend/view keys (`local_keys.rs:459-460`); listed as a *free function* in the decision log (`:3326`). §2.4. |
| `derive_subaddress` (Recipient) | **handle-resolved stub** | Returns `RecipientSubaddressKemKeygenNotImplemented` synchronously; no actor needed for an error. §2.4 / forward-action §8.2. |
| `try_claim_output` | **actor message** (`ClaimOutput`) | Async, reads view+spend secret, mutates the handle-table; secret-bearing, state-evolving. §2.2. |
| `sign_transaction` | **actor message** (`SignTransaction`) — stub reply | Async, reads spend secret. Stub today; the message variant exists so the protocol does not foreclose it. §2.2. |

This is the honest reading of "one request/reply pair per frozen method": the
two async, secret-touching methods become messages; the two sync methods are
satisfied by the handle from immutable material, which is *stronger* than a
message (no round-trip, no chance for secrets to enter a reply). The protocol
is complete — every method is reachable — without inventing dispatch the
substrate does not have.

### 2.2 Actor message types

```rust
// Crate-internal; non-secret request/reply only.
pub(crate) enum KeyActorMsg { /* one zero-or-more-field struct per variant */ }

// try_claim_output(&self, input: &OutputDetectionInput)
struct ClaimOutput { input: OutputDetectionInput }      // owned, non-secret
//   reply: Result<OutputClaimResult, KeyEngineError>
//   OutputClaimResult::Mine(OutputClaim { handle: OutputHandle, key_image,
//                                         amount_atomic_units }) — opaque
//   handle + non-secret on-chain metadata only (key.rs:721-734).

// sign_transaction(&self, tx: &TxToSign)
struct SignTransaction { tx: TxToSign }                 // owned, public-data carriers
//   reply: Result<TxSignatures, KeyEngineError>  (stub today)
```

`OutputDetectionInput` is `#[derive(Clone, Debug)] #[non_exhaustive]` and
documented as carrying no `Zeroize`-required material (`key.rs:142-146`);
`OutputClaim` carries the opaque `OutputHandle` plus public metadata. Both are
`Send` (plain data) and cross the mailbox by value. The actor's `handle`
takes `&mut self`; kameo serialization means the Stage-1 interior-mutability
handle-table (`RwLock`-guarded, for the `&self` trait surface) **collapses to
plain `&mut self` ownership inside the actor** — a simplification the actor
model buys (no lock; the mailbox is the serialization point). The Stage-1
`RwLock`-poisoning panic paths (`key.rs:685-692`, `:753-763`) disappear with
the lock.

`ask` (request/reply) is used for both — the caller needs the reply. `tell`
is not used inbound (no fire-and-forget key op). Per the DAG, KeyEngine is a
leaf and never `ask`s upward, so issue #306 (forward chains) does not apply.

### 2.3 Reconciling `account_public_address`'s borrowed return — **no trait change**

The trait method returns `&AccountPublicAddress`. An actor cannot return a
borrow across a mailbox (the reply is an owned value sent down a channel). The
resolution does **not** touch the trait signature and is not a reopening:

- `AccountPublicAddress` is `Clone`, public-only, and immutable for the
  engine's lifetime epoch (`key.rs:113-117`).
- `KeyEngineHandle` **owns a cached `AccountPublicAddress`** (cloned out of the
  blob's public side at construction — see §3.2). Its `KeyEngine` impl returns
  `&self.account_public_address`, byte-identical to the Stage-1 `LocalKeys`
  body (`key.rs:642-644`).
- No mailbox round-trip; no borrow crosses the actor envelope; the actor
  protocol has **no** `AccountPublicAddress` message variant.

This is the cross-leaf immutable-data pattern applied at the handle layer:
immutable public material is resolved at construction, not via `ask`
(`V3_WALLET_DECISION_LOG.md:3385-3394`). Non-actor `KeyEngine` implementors
(e.g. `LocalKeys` in tests) are unaffected — their bodies are unchanged.

**Concurrent-read safety (handle-resolved vs actor `ask`).** Because
`KeyEngineHandle` is `Clone + Send + Sync` (§3.1), a caller may invoke a
handle-resolved method (`account_public_address`, `derive_subaddress(Audit)`)
concurrently with another caller's `try_claim_output` `ask`. This is safe
**by construction, not by lock**: the handle-resolved methods read only
`self.public: Arc<KeyPublicProjection>`, which is **immutable after
construction** and shared by `Arc` (shared-reference reads are `Sync` by the
type system); the `ask` path touches only the actor's private `&mut self`
inside the actor task. There is **no shared mutable state** between the two
paths — the cached projection and the actor's blob/handle-table are disjoint
allocations — so no ordering constraint exists to violate and no data race is
possible. The property the design relies on (cached projections are immutable
and concurrent-read-safe) is therefore type-enforced, and the §5.2 tests
exercise a handle-resolved read after the actor is stopped to prove the read
path is independent of actor liveness.

### 2.4 `derive_subaddress` — sync method, no async dispatch

`derive_subaddress` is **synchronous** (`key.rs:693`); a sync method cannot
`.await` a mailbox `ask`. Disposition that preserves the signature:

- **Audit purpose** — pure function of immutable public spend/view keys
  (`local_keys.rs:459-460`). The handle owns the public-key projection
  (§3.2) and computes the audit subaddress synchronously, no actor round-trip.
  (The Stage-1 `LocalKeys` also registers the derived subaddress in a reverse-
  lookup registry under a write lock, `key.rs:685-692`; that registry is
  scan-side bookkeeping, not key material, and is addressed in §6/§8.3 — it is
  *not* a reason to route the public derivation through the secret-owning
  actor.)
- **Recipient purpose** — returns `RecipientSubaddressKemKeygenNotImplemented`
  synchronously (stub; `error.rs`). No actor needed to return an error.

The tension this defers: when the Recipient stub lands, ML-KEM-768 keygen
seeded by `HKDF-Expand(view_secret, …)` (`key.rs:659-671`) is **secret-
touching** and belongs in the actor — but the trait method is **sync** and
cannot `ask`. That is a genuine future reopening (async signature, or a
precompute-at-construction cache). It is **out of scope for Stage 2** (the
method is a stub; inventing the keygen is inventing Phase-2-adjacent
functionality). Recorded as forward-action §8.2 with explicit reopening
criteria.

### 2.5 Error mapping across the mailbox

`type Error: Into<KeyEngineError>`; `KeyEngineError` is
`#[non_exhaustive] #[derive(Debug, thiserror::Error)]` (`error.rs`). It is
plain data (no secrets — variants are stub markers and a `CryptoError`
wrapper), therefore `Send` and safe to carry as the `Err` arm of an `ask`
reply. kameo's `ask` returns `Result<Reply, SendError<…>>`; the actor's
`Reply` is itself `Result<T, KeyEngineError>`, so the handle sees a nested
`Result`. The handle collapses kameo transport failures
(`SendError::ActorNotRunning` / mailbox closed) into a dedicated
`KeyEngineError` variant added by the implementation PR (e.g.
`KeyActorUnavailable`) — a transport failure is an engine-lifecycle fault, not
a crypto fault, and the orchestrator must distinguish them. F3-style
discipline (`signer.rs:184-205`): `KeyEngineError`'s `Debug`/`Display` must
carry no secret material; the existing variants already comply and the new
transport variant carries only a discriminant.

### 2.6 `KeyActorUnavailable` — terminal-fault contract

Because the actor is **fail-stop** (§4.5), a `KeyActorUnavailable` is not a
transient condition: the only thing that produces it is a stopped/panicked
actor, and a stopped key actor is unrecoverable in-session (the blob is
already zeroized; nothing can re-spawn it without re-deriving from the
encrypted envelope, which is the `open_full` re-open path). The contract the
implementation PR must honor:

```rust
/// The key actor task has stopped (clean shutdown, panic, or fail-stop
/// `on_panic` → `Break`). The wallet session's key operations are
/// **unrecoverable in-session**: the only recovery is a full wallet close +
/// re-open (`open_full` re-derives the blob from the encrypted envelope).
/// This is **terminal and non-retryable** — callers must abort the in-flight
/// operation rather than retry the `ask`, because every subsequent `ask` on
/// the same handle returns this same error.
KeyActorUnavailable,
```

- **Terminal, not retryable.** A retry loop against a dead actor spins
  forever; callers propagate, they do not retry. This is the inverse of the
  bounded-mailbox backpressure case (§4.4 / §7 T4), where a *live* actor's full
  mailbox blocks the *sender* — that is recoverable; `KeyActorUnavailable` is
  not.
- **Distinguishable by the orchestrator.** It is a distinct
  `KeyEngineError` variant (not folded into a generic crypto error), so the
  refresh/RPC tier can branch on "session-ended" vs "operation-failed."
- **Auto-close vs surface-to-caller is an orchestrator-policy decision, pinned
  by the implementation PR, not here.** Whether a `KeyActorUnavailable` on the
  refresh path auto-triggers `Engine::close` or surfaces to the RPC caller for
  a user-driven re-open touches the lifecycle/RPC tier (partly Stage 4 actor-
  mesh territory). The Stage-2 design pins only the *error contract* (terminal,
  non-retryable, distinguishable); the propagation policy and its test
  (§5.2 test 4) land with the wiring PR that owns the propagation path. Naming
  a specific policy here would over-commit a surface this design does not own
  (`16-architectural-inheritance.mdc`: do not pre-provision the policy before
  its owning PR).

---

## 3. `KeyEngineHandle` design

### 3.1 Shape and bounds

```rust
#[derive(Clone)]
pub(crate) struct KeyEngineHandle {
    actor: kameo::actor::ActorRef<KeyActor>,   // Clone + Send + Sync
    public: Arc<KeyPublicProjection>,          // immutable, public-only
}
```

- `ActorRef<KeyActor>` is `Clone + Send + Sync` (verified §0.5), so
  `KeyEngineHandle` is `Clone + Send + Sync` for free — it can be handed to
  multiple call sites (e.g. a future `LocalSigner` adapter, the merge path)
  without copying secret bytes.
- `KeyPublicProjection` is a **dedicated `pub(crate)` type, not a bare field**,
  so the no-secret contract is enforced *syntactically* — a future edit that
  tries to stash a secret in the handle's public side is a compile-time type
  error at the projection boundary, not a discipline violation that slips
  review. It holds **only public, immutable** material needed by the handle-
  resolved methods (§2.3/§2.4):

  ```rust
  #[derive(Clone, Debug)]   // Clone+Debug are sound: public-only, no secret bytes
  pub(crate) struct KeyPublicProjection {
      account_public_address: AccountPublicAddress, // cached &-return source (§2.3)
      spend_pub: EdwardsPoint,                       // audit-subaddress derivation (§2.4)
      view_pub: EdwardsPoint,                        // audit-subaddress derivation (§2.4)
  }
  ```

  (Exact field set is pinned by what `local_keys.rs:459-460`'s audit branch
  reads; the load-bearing point is *public-only*.) It contains **no secret
  bytes**, derives `Clone + Debug` *because* it is public-only, and is
  `Arc`-shared in the handle (cheap clone). It is deliberately **not**
  `ViewMaterial` (which is secret-bearing, non-`Clone`, wipe-on-drop) and not
  the §6 merge view-secret projection — the three are distinct types precisely
  so the public/secret boundary is type-checked.
- `KeyEngineHandle` implements `pub(crate) trait KeyEngine` (the same trait
  `LocalKeys` implements) with `type Error = KeyEngineError`:
  - `account_public_address` → `&self.public.account_public_address` (sync).
  - `derive_subaddress` → sync, from `self.public` (Audit) / stub (Recipient).
  - `try_claim_output` → `self.actor.ask(ClaimOutput { … }).await` then flatten.
  - `sign_transaction` → `self.actor.ask(SignTransaction { … }).await` (stub).

### 3.2 How `Engine<S>` stores it; no inline `K`

`Engine`'s `keys: Arc<AllKeysBlob>` field (`mod.rs:344`) becomes
`key: KeyEngineHandle`. The generic parameter list is **unchanged** — no
`K: KeyEngine` is added. This honors the reversion clause
(`FOLLOWUPS.md:88-109`): the end-state is a handle field, never an inline
generic. `Engine` keeps `Engine<S, D, L, E, R, P, F>`.

`KeyEngineHandle` is `pub(crate)` (matches `KeyEngine`'s `pub(crate)`
visibility and the "not re-exported from `traits/mod.rs`" disposition); no
external implementor can materialize before the trust-model framework is
concrete (`STAGE_1_PR_3_KEY_ENGINE.md:527`).

**The handle is a crate-internal capability / trust object — never exported.**
Holding a `KeyEngineHandle` *is* the authority to query the key actor: a holder
can call `account_public_address` (learn the address), `derive_subaddress`
(learn derived addresses), and `try_claim_output` (a per-input ownership
oracle — "does this wallet own this output?"). That capability is exactly why
the handle's `pub(crate)` confinement is load-bearing, not incidental: the
trusted holders are the orchestrator, the refresh task, and the (future)
pending-tx adapter — all inside `shekyl-engine-core`. The handle is **never**
handed to the RPC layer or any untrusted caller; the RPC tier is the actual
authentication/authorization boundary and sits *above* the engine, gating who
can drive the orchestrator that holds the handle. This is recorded as a
threat-model line (§7 T9): the handle is a capability, its confinement is the
control, and exporting it would be a privilege-escalation surface. The
`pub(crate)` bound makes "do not export the handle" a compile-time guarantee,
not a review-time discipline.

### 3.3 Drop / refcount semantics

`KeyEngineHandle: Clone` wraps `ActorRef`, which is a strong reference. In
kameo, the actor stops when its last strong `ActorRef` drops (or on explicit
`stop`/`kill`). The `KeyPublicProjection` `Arc` drops independently and
carries no secret. Lifecycle/zeroization is §3 below / §4.

### 3.4 `Signer` and `KeyEngine` are orthogonal layers, not overlapping owners

The codebase carries two key-touching traits, and after Stage 2 their
relationship must be unambiguous so a future maintainer does not read them as
two competing owners of the spend secret:

- **`KeyEngine`** (`traits/key.rs`) is the **secret-owning engine**. After
  Stage 2 the only impl that holds `AllKeysBlob` is `KeyActor` (reached via
  `KeyEngineHandle`); `KeyEngine::sign_transaction` is the canonical spend-
  signing entry point.
- **`Signer`** (`signer.rs`) is a **thin, `PendingTx`-specific adapter
  boundary**, not a second key owner. It exists so `PendingTxEngine` can
  request a spend signature without depending on the full `KeyEngine` surface
  (the R11(b) secret-locality contract: the pending-tx pipeline never touches
  `AllKeysBlob`). It is the seam where an external `HardwareSigner` /
  offload adapter plugs in.

The load-bearing invariant Stage 2 establishes: **after step 4 (§6),
`LocalSigner` no longer holds `Arc<AllKeysBlob>`.** It holds a
`KeyEngineHandle` (or nothing, while `sign_transfer` is a stub), and its
eventual `sign_transfer` body delegates to the actor's `SignTransaction`
message. So `Signer` becomes an *adapter over `KeyEngineHandle`*, not a
parallel blob holder — the two traits are stacked (adapter → engine), never
side-by-side owners. This orthogonality should be stated in a one-line module
note on `signer.rs` (and/or `traits/mod.rs`) when step 4 lands, so the
"why are there two key traits?" question has a recorded answer per
`05-system-thinking.mdc`.

### 3.5 Contention and resource bounds

A first-actor design should state its contention model rather than assume
"bounded mailbox = safe." Two facts, both verified at source, set the model:

**(1) In Stage 2 the actor is cold on the hot scan path.** A grep for
`try_claim_output` callers finds only the trait definition, `merge.rs`
*comments* about the M3c+ future, and `#[tokio::test]` cases — **zero
production callers**. The live scan-merge path uses the (6-i) construction-time
view-secret projection (§6), which is a **synchronous** read, not an `ask`. The
only inbound message a production Stage-2 actor can receive is
`SignTransaction`, which is a stub and rare (one per user-initiated send). So
in Stage 2 the 64-deep mailbox is effectively never pressured; there is no
scan-driven `ask` storm, and no orchestrator-starvation risk. The contention
question is therefore **a property of the deferred (6-ii) re-route, not of
Stage 2** — which is consistent with (6-ii) being foreclosed until Stage 4
(§6).

**(2) The request/reply pattern bounds a *sequential* producer to one
outstanding `ask`.** `ActorRef::ask(msg).await` sends *and awaits the reply*
before returning. A single task issuing N back-to-back `try_claim_output`
calls (the reviewer's "500 outputs/block from the refresh task") therefore
holds **at most one** outstanding `ask` at a time — it cannot fill a 64-deep
mailbox by itself, because it blocks on each reply before sending the next.
The 64-depth backpressure (T4) is a defense against **concurrent or
pathological producers** (multiple tasks, or a non-awaiting `tell` flood), not
against a sequential scan loop. The real cost of a sequential scan loop is
**throughput**: the sum of per-output crypto serialized through one
single-consumer actor — a latency-tail question, not a saturation/starvation
question.

**Consequence for the (6-ii) gate.** When the merge re-route is reconsidered
(§8.1, Stage 4), the contention model it must satisfy is the throughput one:
per-output ML-KEM-768 decap serialized through a single `KeyActor`. If that
tail is unacceptable, the escape hatch is the §8.3 view/spend split — a
*view* sub-actor can be pooled or spawned per-attempt (the view path does not
touch the spend secret), parallelizing scan-time claims without replicating
the spend secret. The §5.3 merge-path bench is the measurement that decides
whether this is needed. Recorded so the M3c+ PR inherits the model rather than
re-deriving it.

**Resource bound.** The mailbox is bounded (64) and never unbounded (Path B
memory-pressure rule, `V3_WALLET_DECISION_LOG.md:3439-3442`); an over-eager
producer blocks on send rather than growing memory without limit.

---

## 4. Actor lifecycle, supervision, zeroization

### 4.1 `Args` and where the blob is built

kameo's `on_start(args) -> Result<Self, Error>` builds the actor inside its
task. Two `Args` candidates, both move-once (no `Clone` of secrets):

- **(A) `Args = AllKeysBlob`** — `assemble` (`lifecycle.rs:673`) already holds
  an owned `AllKeysBlob`; it is *moved* into `KeyActor::spawn(blob)`. The blob
  transits the `assemble` stack frame as the `Args` value (identical exposure
  to today's `Arc::new(keys)` at `lifecycle.rs:720`), then lives solely in the
  task as `self.blob`.
- **(B) `Args = RederivationInputs`** — `on_start` runs `rederive_account`
  *inside* the task, so `AllKeysBlob` is *constructed* in the task and never
  exists on the spawning thread. Stronger by one notch, but the seed material
  in `Args` is itself secret, so it relocates rather than removes the transit;
  and it re-runs rederivation (cost) the open path already paid.

**Disposition: (A).** The blob already exists at `assemble`; moving it in is a
single transfer with no clone, and `AllKeysBlob`'s `ZeroizeOnDrop` covers the
brief `Args` lifetime. (B) is recorded as a reopening option if a future
threat-model review wants the blob to never exist outside the task at all
(§8.4).

**Critical ordering at `assemble`:** all three construction-time projections
borrow `&keys`, so each must be derived **before** the blob is moved into the
actor. Sequence: derive `ViewMaterial` (for `LocalRefresh`),
`KeyPublicProjection` (public, for the handle), and the §6
`HandleDerivationViewSecret` (view-secret, for the merge path) — all from
`&keys` — → *then* `KeyActor::spawn(blob)` (which **consumes** the blob, §6
step 3) → store the resulting `KeyEngineHandle`. After the spawn, the only
owner of the full blob is the actor task. The ordering is forced by
*borrow-before-move*, not by the projections' `Clone`-ness:
`KeyPublicProjection` is `Clone` (public-only), the two view-secret projections
are non-`Clone` (`Zeroizing`), but all three must be computed while `keys` is
still borrowable.

**Projection-derivation failure is permanent — fail closed, no retry.** Each
`try_from_keys` returns a `Result`; the reviewer-raised question is whether a
failure could be *transient* (retry the open) vs *permanent* (close). The
disposition rejects the transient/permanent taxonomy as not-load-bearing here,
with reason: (1) a derivation failure is a deterministic function of an
already-decrypted, immutable blob — retrying the *same* blob yields the *same*
failure, so there is no retry that recovers; (2) Rust allocation failure
**aborts** via the OOM handler rather than surfacing a retryable `Err`, so the
"alloc failed, retry works" case does not exist on this path. Therefore any
`assemble`-time projection-derivation failure propagates as a **permanent
open-failure**: the wallet open fails closed and loudly, no retry path is
provided. This is the pre-genesis fail-closed posture
(`16-architectural-inheritance.mdc` §"user-protection defaults in user-absent
contexts": graceful-degradation/retry defaults invert pre-genesis to
loud-failure). Recorded so the implementation does not invent a retry shim for
a non-recoverable condition.

### 4.2 Spawn point

`Engine::create` (`lifecycle.rs:418`) and `Engine::open_full`
(`lifecycle.rs:537`) both flow through `assemble` (`lifecycle.rs:673`). The
spawn happens in `assemble`, in exactly one place, so future open paths
(`open_view_only`, `open_hardware_offload`, today stubs at `lifecycle.rs:638`)
inherit it. `KeyActor::spawn(blob)` (default bounded-64 mailbox, §4.4) is
called after the view/public projections are derived (§4.1).

### 4.3 Shutdown, drop ordering, and zeroization

The load-bearing property is that `AllKeysBlob`'s `Drop`
(`ZeroizeOnDrop`: wipes `spend_sk`, `view_sk`, `ml_kem_dk` — `mod.rs:336-339`,
`lifecycle.rs:997-998`) runs on every termination path:

- **Clean wallet close** — `Engine` drop / `engine_lock`. Dropping the
  `KeyEngineHandle` (last `ActorRef`) signals the actor to stop; the task ends,
  `self.blob` drops, zeroizing. The implementation should issue an explicit
  `actor.stop_gracefully().await` (or equivalent) on the close path so the
  zeroize completes deterministically before the close returns, rather than
  relying on async-task teardown timing.
- **`on_stop(&mut self, …)`** — kameo calls this before the task ends. The
  blob is dropped *after* `on_stop` returns (it takes `&mut self`, cannot
  consume `self`). Use `on_stop` as a belt-and-suspenders explicit
  `self.blob.zeroize()` + assertion point, and return `Ok(())` always — the
  docs warn a returned error "causes a panic in the tokio task." The actual
  wipe is `Drop`; `on_stop` is defense-in-depth.
- **Panic** — see §4.5.

Drop ordering relative to `WalletFile` (`lifecycle.rs:996-998`) is unchanged:
the actor's blob is independent of the file handle; both zeroize on their own
`Drop`.

### 4.4 Mailbox sizing

**Default `mailbox(64)` (kameo `spawn` default), no override.** Rationale,
reconciled against the workspace convention (`Cargo.toml:219-225`):

- KeyEngine is low-throughput: the only live message is `try_claim_output`,
  driven by the scanner-merge post-pass over *inserted* indices (O(k) per
  merge, `merge.rs:215-217`), not per-block-output. `sign_transaction` is rare
  (one per user-initiated send) and stubbed today.
- 64 outstanding `ask`s of bounded, non-secret request values is a trivial
  memory footprint; backpressure at 64 protects against a pathological
  producer (§7 mailbox-DoS).
- The implementation uses `KeyActor::spawn(blob)` (default 64). If the future
  merge → actor re-route (§8.1) makes `try_claim_output` a hot per-output
  path, *that* PR re-measures and may switch to
  `spawn_with_mailbox(blob, kameo::mailbox::bounded(N))` with an inline
  rationale naming the throughput measurement (per the convention's per-actor-
  override clause). Unbounded is forbidden (Path B memory-pressure rule,
  `V3_WALLET_DECISION_LOG.md:3439-3442`).

**Serialization-through-the-actor implication.** All `try_claim_output` calls
serialize through one mailbox. For batch scan-merge this is acceptable (the
crypto cost per output — ML-KEM-768 decap — dominates the dispatch, §5.3) and
the Stage-1 path already serialized on the `RwLock`. If profiling later shows
the single mailbox is a scan bottleneck, the view-key scan path is a candidate
for the view/spend actor split (§8.3) — a *view* sub-actor can be pooled or
spawned per-attempt without touching the spend secret. The protocol does not
foreclose this.

### 4.5 Supervision / restart disposition — **fail-stop, not restart**

A key-owning actor that restarts must re-establish its secrets. kameo's
restart mechanisms make this structurally hostile to secret-locality, and the
verified API (§0.5) forecloses both:

- **`supervise(sup, args)` requires `Args: Clone + Sync`.** With `Args =
  AllKeysBlob` (§4.1), this requires `AllKeysBlob: Clone` — but `AllKeysBlob`
  is deliberately **not `Clone`** (V3.0 not-clone discipline;
  `21-reversion-clause-discipline.mdc` §"Type-derivation"). `supervise` is
  therefore *uncompilable* for `KeyActor`. Adding `Clone` to defeat this is
  rejected: a cloneable key blob is a second copy of every secret.
- **`supervise_with(sup, factory)`** sidesteps `Clone` with an
  `Fn() -> Args + Send + Sync + 'static` closure retained for the actor's
  lifetime. For a key actor the factory must close over the seed/blob to
  regenerate `Args` on restart — i.e. **secret material is retained outside
  the actor task, in the supervisor's closure, for the whole lifetime.** This
  directly violates "the full blob lives only in the actor task."

Both restart paths force a retained second copy of secrets. The
architecturally-integral answer (`16-architectural-inheritance.mdc`: prefer
the structural answer; pre-genesis, bounded cost) is **fail-stop**:

- `KeyActor` is **not** spawned under a restarting supervisor. It is spawned
  plain (`spawn` / `spawn_with_mailbox`) or `spawn_link`ed for *liveness
  notification only* (the parent learns it died) — **never** `supervise`d for
  restart.
- `on_panic` is overridden to **always** return
  `ControlFlow::Break(ActorStopReason::Panicked(..))` — never continue
  processing after a panic, because post-panic `self` (and its in-flight
  crypto state) is suspect. Stopping drops `self.blob` → zeroize.
- A dead `KeyActor` ends the wallet session. Recovery is **re-open** (the
  existing `open_full` path re-derives the blob from the encrypted envelope) —
  a user-driven lifecycle event, not an automatic restart. `ask`s after death
  surface as the `KeyActorUnavailable` error (§2.5), which the orchestrator
  maps to a session-ended condition.

This is the strongest possible disposition for the security-first hierarchy:
*restart is impossible without replicating secrets, so restart is forbidden by
construction.* Recorded as a reversion clause: reopen only if a future kameo
version offers a restart that re-runs `on_start` from in-task state without a
retained external `Args`/factory (substrate change), reviewed against
`35-secure-memory.mdc`.

---

## 5. Test strategy and benchmark plan

### 5.1 No-Mock substrate

Per the project's no-Mock discipline, tests spawn a **real `KeyActor`** over a
real `AllKeysBlob` (`rederive_account` against a deterministic fakechain seed,
the existing fixture pattern — `signer.rs:371-388`) and exercise it through
real messages. No mock `KeyEngine` is introduced. kameo's type-erased
`Recipient<M>` / `ReplyRecipient` (verified §0.5,
`kameo::actor::Recipient`) is available for tests that want to address the
actor by a single message type, but the contract tests address `ActorRef`
directly.

### 5.2 Contract / protocol tests

1. **Equivalence:** `KeyActor`-via-`ask` `try_claim_output(input)` produces a
   result equivalent to direct `LocalKeys::try_claim_output(input)` for the
   same blob and input — both `Mine` (handle resolves to the same key-image /
   amount) and `NotMine` cases. This pins "the actor is the same engine,
   reached differently."
2. **No-secret-crosses (structural):** a test asserts the message and reply
   types (`ClaimOutput`, `OutputClaimResult`, `OutputClaim`) contain no
   secret-bearing field — enforced by a `static_assertions`-style check that
   the reply is `Send` *and* a doc-pinned review that `OutputClaim` carries
   only `OutputHandle` + public metadata (`key.rs:721-734`). The opaque
   `OutputHandle` is meaningless without the actor's internal table
   (`STAGE_1_PR_3_KEY_ENGINE.md:1069-1077`).
3. **Handle-resolved methods:** `account_public_address` returns the cached
   public address with no actor interaction (assert by exercising the handle
   after the actor is `stop`ped — the address still resolves; an `ask` would
   fail). `derive_subaddress(Audit)` likewise resolves post-stop;
   `derive_subaddress(Recipient)` returns the stub error.
4. **Lifecycle + terminal-fault path:**
   - **Clean stop** drops the blob — zeroize observable via a test-only drop
     counter on the fixture (not on production `AllKeysBlob`).
   - **Panic → fail-stop → zeroize** (T2/T8): inject a panic in a test message
     handler; assert (a) the actor is dead, (b) the fixture drop counter fired
     (blob zeroized on unwind, §4.5), and (c) the next `ask` returns
     `KeyActorUnavailable`.
   - **Terminal, non-retryable** (§2.6 contract): assert that *repeated* `ask`s
     after death all return `KeyActorUnavailable` (a retry never recovers),
     pinning the "abort, don't retry" contract.
   - The orchestrator-side propagation/close policy test (does a
     `KeyActorUnavailable` on the refresh path surface to the caller or
     auto-close?) lands with the wiring PR that owns the propagation path
     (§2.6), not the actor-unit tests here.

### 5.3 Benchmark plan (B9, bench-vs-bench)

The DoD's "within 5% of the composition baseline" is **bench-vs-bench against
a measured baseline**, not an absolute latency gate. Because signing does not
exist (§0.4), the baseline is `try_claim_output`'s real cryptographic cost:

- **Baseline bench:** direct `LocalKeys::try_claim_output(input)` on a `Mine`
  output (full path: X25519 view-tag + hybrid ML-KEM-768 decap + HKDF +
  key-image + handle insertion, `local_keys.rs:504-552`).
- **Actor bench:** the same call via `KeyEngineHandle::try_claim_output`
  (`ask` round-trip on a spawned `KeyActor`).
- **Threshold:** `actor_path ≤ 1.05 × baseline_path` (messaging overhead lost
  in the ML-KEM-768 decap noise). Also report the absolute `ask` round-trip on
  a `NotMine` (X25519 pre-filter only — the cheap, common case) so the
  dispatch overhead is visible against the *cheapest* real op, where the 5%
  envelope is hardest to hold; if the cheap-case dispatch is material, that is
  evidence for the §8.3 view-scan split, recorded rather than gated.
- No `sign_transaction` bench (stub). When signing lands, the bench re-anchors
  to FCMP++ signing cost, where dispatch is even more thoroughly dominated.

**Merge-path bench (decision evidence for 6-i vs 6-ii, §8.1).** Separately from
the dispatch-overhead bench above, benchmark `apply_scan_result` end-to-end
exercising the **6-i construction-time view-secret projection** over a batch of
inserted outputs (the real merge post-pass, `merge.rs:215-223`). This is not a
pass/fail gate — it is the **measurement that makes the 6-ii deferral
evidence-based** (B9). If the per-output handle-derivation cost under 6-i is in
the noise of the merge itself, the record reads "6-ii async re-route is
optimization, not correctness — the sync projection is not a bottleneck," and
the §8.1 reopening criterion stays unmet. If 6-i shows material merge-path
cost, that is recorded as positive evidence *toward* the 6-ii re-route (which
must still wait for the Ledger-actor lock cutover, per §6). Either way the
number is captured, not guessed.

Benches live under the existing engine bench harness; the baseline is captured
in the same run as the actor path (same machine, same seed) so the ratio is
machine-independent.

---

## 6. Implementation decomposition (for the eventual PR(s))

Per §0.2 this is not a one-field swap. Suggested commit/PR sequence under
`06-branching.mdc` (each independently reviewable; the whole may be one
short-lived branch if it stays within the size guidance, else split):

1. **`KeyActor` + `KeyEngineHandle`, off the live path.** Define `KeyActor`
   (impl `kameo::Actor`, `Message<ClaimOutput>`, `Message<SignTransaction>`),
   `KeyEngineHandle`, `KeyPublicProjection`, the `KeyActorMsg` types, and the
   `KeyEngineError::KeyActorUnavailable` variant. Move the `LocalKeys` crypto
   bodies into the actor handlers (the handle-table loses its `RwLock`,
   §2.2). Tests §5.2. **`Engine` untouched.**
2. **(Optional, off the live path) Standalone projection types + derive
   functions.** Define `KeyPublicProjection` and `HandleDerivationViewSecret`
   and their `try_from(&AllKeysBlob)`-shaped derive functions, with unit tests,
   **without touching `assemble` or `Engine`**. This is splittable from step 3
   only because it is pure type/function introduction; it does **not** spawn or
   reorder anything. If the branch stays small it folds into step 3.
3. **Atomic: reorder `assemble`, spawn, swap field, rewire merge — one
   commit.** This cannot be decomposed further, because **`KeyActor::spawn(keys)`
   consumes the owned `AllKeysBlob`** (kameo `Args` is taken by value): the
   moment the actor is spawned there is no blob left to retain in a `keys`
   field, so a `keys`-and-`key`-both-present intermediate is not merely
   forbidden — it is *uncompilable*. The single atomic commit therefore: (a)
   reorders `assemble` (`lifecycle.rs:673`) to derive `ViewMaterial`,
   `KeyPublicProjection`, and `HandleDerivationViewSecret` from `&keys` while it
   is still borrowable; (b) `KeyActor::spawn(keys)` (consuming the blob) → the
   `KeyEngineHandle`; (c) constructs `Engine` with `key: KeyEngineHandle` in
   place of `keys: Arc<AllKeysBlob>` (`mod.rs:344`), removing the dead
   `Engine::keys()` accessor (`mod.rs:728`); (d) rewires `merge.rs:218-223`'s
   `self.keys.view_sk` to read the construction-time `HandleDerivationViewSecret`
   stored on the merge/ledger owner (the (6-i) disposition — **not** a live
   choice; see below). The field swap, the spawn, and the merge rewire are one
   unit because the blob-consuming spawn makes them so.
4. **Sever `LocalSigner`'s blob.** `LocalSigner` (`signer.rs:292-298`) stops
   holding `Arc<AllKeysBlob>`; since `sign_transfer` is a stub it holds the
   `KeyEngineHandle` (or nothing) and the future signing routes through the
   `SignTransaction` message. Rewrite the `local_signer_holds_keys` refcount
   test (`signer.rs:391-403`).
5. **Close the FOLLOWUPS** (`kameo` pin entry `:884`; Stage 2 entry `:995`;
   inline-integration reversion `:74`), update `CHANGELOG.md`, decision-log
   cross-ref, and correct the `Cargo.toml` `#[actor(mailbox=…)]` convention
   note (§0.5).

**§6 merge-rewire disposition.** `merge.rs:220` reads view *secret*
(`view_sk`), not public material, so it cannot be served from a public
projection. Two options:

- **(6-i) Construction-time view-secret projection (Stage-2 minimal).** Give
  the merge/ledger path a construction-time view-secret projection, the same
  cross-leaf-immutable shape `LocalRefresh` already gets via `ViewMaterial`
  (sanctioned by `V3_WALLET_DECISION_LOG.md:3396-3404`, which lists *view keys
  (private and public)* as construction-time-passed). The full blob still
  lives only in the actor; the merge path holds a derived view-secret bundle,
  not `&AllKeysBlob`. Does **not** invent the async hot-path dispatch.
- **(6-ii) Route through the actor's `ClaimOutput` (the planned M3c+
  re-route).** Architecturally cleanest (one secret locus) but makes
  `try_claim_output` a hot per-output mailbox path **and confronts a concrete
  structural obstacle** (below) that makes it a genuinely larger change, not
  merely a bigger diff.

**Locked Stage-2 disposition: (6-i). (6-ii) is not deferred-by-preference — it
is foreclosed in Stage 2 by the substrate** (the lock obstacle below), and is
reopened only under the §8.1 gates. There is **no merge-time fork** for the
implementation PR to leave open: the PR implements (6-i) — the
`HandleDerivationViewSecret` projection and the `assemble` reordering land *in
the same atomic commit as the field swap* (step 3 below) — and does **not**
leave `merge.rs:220` reading `self.keys.view_sk`. Step 3's prose
"…construction-time projection **or** route through the actor" is the
*explanation* of why (6-i) is chosen, not a live choice the implementer makes;
read it as "(6-i), because (6-ii) is foreclosed per the disposition below." A
reversion clause (`21-reversion-clause-discipline.mdc`) governs the lock:
reject (6-ii) now; reopen only when §8.1's two gates (Ledger actor exists +
measurement justifies) both clear.

**Why (6-i) is the architecturally-correct Stage-2 minimal, not just the
smaller one.** `apply_scan_result` is a **synchronous** `pub fn`
(`merge.rs:191`) that holds a `std::sync::RwLock` write guard
(`merge.rs:201`, `self.ledger.write()`) across the post-pass — and
`LocalLedger` uses `std::sync::RwLock` *specifically because nothing awaits
under it*: the module doc states it is synchronous "(not `tokio::sync::RwLock`)
because … holding a `std::sync::RwLock` guard across `.await` would risk a"
deadlock, and explicitly flags "when [a future step] needs to `await` …, swap
to `tokio::sync::RwLock` at that time" (`local_ledger.rs:30-54`). Routing the
post-pass through the actor (6-ii) means awaiting an `ask` **inside the write-
guarded critical section** — which is exactly the forbidden pattern. So 6-ii
is not "6-i plus an await"; it forces *either* a `std::sync::RwLock` →
`tokio::sync::RwLock` swap on `LocalLedger` (`local_ledger.rs:74` already
anticipates the lock's removal "because the actor mailbox serializes access")
*or* a restructure that derives handles **outside** the guard while preserving
the merge/post-pass atomicity the merge.rs doc guarantees (`merge.rs:185-190`:
a concurrent reader sees pre-merge or post-population, never an intermediate
state). That lock-discipline restructure is a Ledger-actor concern (Stage 4),
which is why the merge.rs comment defers it to M3c+ (`merge.rs:213-215`).
(6-i), by contrast, is fully synchronous — a construction-time snapshot read
under the existing guard with zero await — so it delivers the DoD ("full
`AllKeysBlob` contained in the actor; no `&AllKeysBlob` escapes") *without*
touching the lock discipline. This is the architecturally-integral-now answer
(`16-architectural-inheritance.mdc`): 6-i is correct under the current
substrate, and 6-ii's correct home is the Ledger-actor stage that owns the
lock cutover.

**Name the merge projection distinctly — not `ViewMaterial`.** The merge
projection and `LocalRefresh`'s `ViewMaterial` carry overlapping secret bytes
but are *different types* by intent, so no one mistakes one for a clone-able
alias of the other:

- It is **narrower** than `ViewMaterial`. `ViewMaterial` is a five-field
  view-and-spend bundle (`view_scalar`, `x25519_sk`, plus public material for
  view-tag pre-filtering, `view_material.rs`); the merge post-pass passes only
  `self.keys.view_sk.as_canonical_bytes()` to `derive_output_handle`
  (`merge.rs:220`). The merge projection therefore carries **only the view
  secret needed for handle derivation**, nothing more.
- It must be its **own non-`Clone`, `Zeroizing`, wipe-on-drop type** (e.g.
  `HandleDerivationViewSecret` / `MergeViewSecret` — exact name pinned at
  implementation), distinct from `ViewMaterial`, so the type system forbids the
  "it's just a `ViewMaterial`, I'll clone it" mistake. Two construction-time
  view-secret holders with the *same* type would invite exactly that.
- It is derived in `assemble` (§4.1) from `&keys` **before** the blob moves
  into the actor, alongside `ViewMaterial` and `KeyPublicProjection`, and is
  stored on the merge/ledger owner. A comment at `lifecycle.rs` §assemble must
  record *why two view-secret projections exist* (refresh-scanning vs handle-
  derivation) and that both are Stage-2-minimal pending the 6-ii re-route.

(6-ii) remains a clean follow-on whose cost is bounded because only one actor
exists; it retires this merge projection when it lands.

---

## 7. Threat-model addenda (A3 — late-round pass)

Attacker objectives against the key actor, each routed to in-scope /
discipline-note / forward-action.

| # | Attacker objective | Vector | Disposition |
|---|---|---|---|
| T1 | **Secret exfiltration via the mailbox** | Read a secret out of a request/reply value. | **In-scope, closed by construction.** Only non-secret types cross (`OutputDetectionInput`, `OutputClaim`+opaque `OutputHandle`, `TxToSign`/`TxSignatures` public-data carriers, `KeyEngineError`). The full blob and the handle-table never leave the task. §2.2 / §5.2 test 2. |
| T2 | **Panic-leak** | A handler panic leaves secret bytes in a recoverable/loggable state, or `PanicError` carries secret bytes. | **In-scope.** `on_panic` → `Break` (fail-stop, §4.5); `self.blob` drops → zeroize. `KeyEngineError`/panic payloads carry no secret (F3 discipline, §2.5). Discipline-note: the implementation must not `panic!` with secret-bearing context. |
| T3 | **Restart-leak** | Supervisor restart re-runs `on_start`, requiring a retained secret `Args`/factory the attacker can target. | **In-scope, closed by construction.** Fail-stop, not restart (§4.5): `supervise` needs `AllKeysBlob: Clone` (rejected), `supervise_with` retains a secret closure (rejected). No retained external secret exists to target. |
| T4 | **Mailbox DoS** | Flood `ask`s to exhaust memory or stall the actor. | **In-scope (bounded).** Bounded mailbox (64) provides backpressure (§4.4); a flooder blocks on send rather than growing memory. Cross-actor flooding is the orchestrator/RPC tier's concern (DAG root rate-limits), not the leaf's. |
| T5 | **Handle forgery / cross-context misuse** | Forge an `OutputHandle` to make the actor sign with the wrong output's secret. | **Forward-action (inherited).** Handle unforgeability (counter vs UUID vs crypto-random) is the open Round-4 item from `STAGE_1_PR_3_KEY_ENGINE.md:1088-1090` (A7); the actor migration neither closes nor worsens it (the table moves into the actor unchanged). Tracked there. |
| T6 | **Handle-table memory-pressure** | Adversarial scan load grows the in-actor table unboundedly. | **Forward-action (inherited), with a new migration-introduced design constraint.** A6 eviction discipline, `STAGE_1_PR_3_KEY_ENGINE.md:1085-1087`; **no eviction is implemented today** (verified: grep for `evict`/`lru`/`prune` in `local_keys.rs` finds only `Vec::with_capacity`). The table's *bound* is unchanged by the migration. What **is** new: post-migration the table lives in the actor and is mutated only inside `&mut self` message handlers, so when A6's eviction lands it runs **serialized with `ask`s** — an O(table) eviction sweep inside a handler would block all other claims for its duration. **Constraint A6 inherits from this design:** eviction must be incremental/amortized (bounded per-handler work, e.g. evict-one-on-insert or a size-triggered bounded batch), never an unbounded sweep under the handler, so it does not introduce latency-tail jitter into the §3.5 throughput model. Recorded as a refinement to A6, not a Stage-2 blocker. |
| T7 | **Side-channel via cross-call timing** | Correlate `ask` latencies to infer match/no-match. | **Discipline-note.** The X25519 view-tag pre-filter already creates a Mine/NotMine timing difference at the crypto layer (pre-actor); the mailbox does not add a *new* secret-dependent branch. Constant-time work is the crypto layer's responsibility (`30-cryptography.mdc`), not the actor's. No new surface. |
| T8 | **Mid-crypto panic leaves partial secret state** | A panic *during* a handler's crypto (e.g. mid-HKDF, mid-decap) leaves partially-derived secret bytes in `self` / stack temporaries. | **In-scope, closed by construction.** A handler panic triggers `on_panic` → `Break` (fail-stop, §4.5); the actor stops and `self.blob` — and any handler-local secret temporaries, which are `Zeroizing`/wipe-on-drop per `35-secure-memory.mdc` — drop and zeroize as the task unwinds. No partial state survives, because there is no post-panic continuation (`Break`, never continue) and no restart to re-read it (T3). This is the per-operation refinement of T2: T2 is "a panic leaves the blob recoverable"; T8 is "a panic *mid-derivation* leaves a fragment recoverable." Both close on the same fail-stop-+-zeroize-on-unwind mechanism; T8 additionally requires that handler-local crypto temporaries are themselves wipe-on-drop (a `35-secure-memory.mdc` obligation on the moved-in `LocalKeys` bodies, verified at impl, §6 step 1). |
| T9 | **Attacker holding a `KeyEngineHandle`** | A caller in possession of a handle uses it as an oracle: `try_claim_output` (per-input "do I own this?" membership probe), `account_public_address` / `derive_subaddress` (address disclosure), or repeated `ask`s to confirm liveness. | **In-scope, controlled by confinement.** The handle is a **capability**: holding it *is* the authority to query the actor (§3.2). The control is that `KeyEngineHandle` is `pub(crate)` — it cannot leave `shekyl-engine-core`, so the only holders are trusted in-crate components (orchestrator, refresh task, future pending-tx adapter). It is **never** exported to the RPC layer or untrusted callers; the RPC tier sits above the engine and is the actual auth/authz boundary, gating who can drive the holder. The `pub(crate)` bound makes "do not export the handle" a **compile-time** guarantee, not a discipline. Two residuals route to existing trackers: the membership-oracle's *handle-forgery* sub-case is T5 (A7), and the *timing* sub-case is T7. No new in-crate exfiltration surface — the handle exposes only the trait methods, which already carry no secret across the boundary (T1). |

---

## 8. Forward-actions (what Stage 2 sets up but defers)

### 8.1 Merge-path async re-route (M3c+)
Route `merge.rs`'s per-output handle derivation through the actor's
`ClaimOutput` message (option 6-ii), retiring the merge view-secret projection.
**This is optimization toward a single secret locus, not a correctness fix** —
6-i already satisfies the DoD ("no `&AllKeysBlob` escapes"). Two gates must
both clear before it is worth doing, and the Stage-2 PR description should say
so explicitly:

1. **Lock-discipline gate (the real blocker).** 6-ii awaits an `ask` inside
   `apply_scan_result`'s `std::sync::RwLock` write guard (§6), which is
   forbidden. It cannot land until `LocalLedger` moves to the actor model (the
   `local_ledger.rs:74` "RwLock removed because the actor mailbox serializes
   access" cutover) or the merge is restructured to derive handles outside the
   guard without breaking post-pass atomicity. This is a **Stage-4 / Ledger-
   actor** prerequisite, not a Stage-2-or-3 toggle.
2. **Measurement gate.** The §5.3 merge-path bench shows the 6-i sync
   projection is (or is not) a material cost. If it is in the noise, 6-ii buys
   only architectural tidiness (one secret locus instead of two) and waits for
   gate 1 regardless; if it is material, that is positive evidence the re-route
   is worth the gate-1 work.

**Reopen when:** gate 1 clears (Ledger actor exists) **and** the §5.3 evidence
or the §8.3 view/spend split makes the per-output dispatch cost acceptable.
Already named in `merge.rs:213-215`. The contention model the re-route must
satisfy — per-output crypto serialized through one single-consumer actor, a
throughput/tail question, not a mailbox-saturation one — is specified in §3.5
so this PR inherits it rather than re-deriving it.

### 8.2 `derive_subaddress(Recipient)` async tension
When the Recipient ML-KEM-768 keygen stub lands (`key.rs:659-671`;
`error.rs` `RecipientSubaddressKemKeygenNotImplemented`), it is secret-touching
and belongs in the actor, but `derive_subaddress` is **sync** and cannot
`ask`. **Reopen via:** a design round that chooses (a) make the trait method
`async` (a frozen-surface reopening with its own justification), or (b)
precompute per-subaddress KEM keypairs at construction and serve from the
projection. The protocol does not foreclose either. Out of scope now (stub).

### 8.3 View-key vs spend-key separation (Stage 4 sub-decision)
The decision log lists *view keys (private and public)* as construction-time-
passed to scan-side leaves (`V3_WALLET_DECISION_LOG.md:3396-3404`), and
`ViewMaterial` already realizes this for `LocalRefresh`. Stage 2 keeps the
**full** blob in one `KeyActor` but **does not foreclose** splitting view-key
operations (scan-time, used by Ledger/Refresh) from spend-key operations
(rare, sign-time) into separate sub-actors in Stage 4. The `KeyPublicProjection`
(public) and the construction-time view projection (secret, option 6-i) are
already separate from the spend-secret-owning actor surface, so the split is
additive, not a rewrite. **Reopen at:** Stage 4, when the actor mesh is built.

### 8.4 `Args = RederivationInputs` (blob never on the spawning thread)
§4.1 option (B). **Reopen if:** a threat-model review requires the blob to
never exist outside the task even transiently (current disposition: (A), the
transit is identical to today's `Arc::new(keys)` exposure).

### 8.5 Stage-4 actor-composition rules — decision points Stage 2 flags but does not own

`KeyActor` is Shekyl's **first** actor; Monero (and CryptoNote) have no actor
boundaries at all, so there is no inherited composition model to carry forward
— Shekyl is building one. Stage 2 must not *solve* the multi-actor mesh (that
is Stage 4's design, and inventing it here is the scope creep
`16-architectural-inheritance.mdc` warns against), but it should **flag the
decision points and point at where partial answers already live**, so Stage 4
does not re-litigate them:

- **Actors interact only through the message protocol.** This is the Path B
  commitment (`V3_WALLET_DECISION_LOG.md` 2026-04-27); no shared-memory
  back-channel. Stage 4 inherits it.
- **The actor graph is a no-cycle DAG.** Recorded with the kameo issue-#306
  caveat (`V3_WALLET_DECISION_LOG.md:3428-3445`): multi-hop `ctx.forward`
  panics on error, so the mesh is kept acyclic and `KeyActor` is a **leaf** —
  it never `ask`s another actor downward. The "what if `KeyActor` needs the
  chain height from a `LedgerActor`?" question is answered *by construction* in
  Stage 2: it doesn't — `try_claim_output`/`sign_transaction` take all needed
  on-chain context as message inputs (`OutputDetectionInput`, `TxToSign`),
  resolved by the *caller* before the `ask`. Stage 4 must preserve "secrets-
  owning actors are leaves that pull no dependencies downward," or justify a
  departure.
- **Deadlock prevention** = the acyclic-DAG + leaf-position rule above, plus
  the request/reply bound from §3.5 (a sequential `ask`er holds ≤1 outstanding
  request). A cycle would be the deadlock risk; the DAG rule forecloses it.
- **Panic isolation** = the per-actor **fail-stop** discipline this design
  establishes (§4.5). Stage 2's answer ("a key actor that dies ends the
  session; recovery is re-open, never restart") is the *strict* end of the
  spectrum because the actor owns the spend secret; a non-secret leaf (e.g. a
  future `DaemonEngine` actor) may tolerate restart. Stage 4 decides each
  actor's restart posture against `35-secure-memory.mdc` using the **template
  this design sets**: restart is permissible only for an actor that retains no
  secret across `on_start` and needs no `Clone`/factory of secret `Args`.

**Principles Stage 2 establishes for the actor program** (the reusable output,
not just "a field moved"):

1. **Trait-boundary = actor-boundary.** The sync/async and public/secret splits
   in the Stage-1 trait surface already fall exactly where the actor envelope
   belongs (§2.1) — handle-resolved for immutable public material, `ask` for
   async secret-touching work. This is the Round-3 trait-extraction discipline
   paying out, not luck; Stage 4's per-engine traits should be extracted to the
   same standard *before* their actors are built.
2. **Fail-stop-by-construction for secret-owning actors** (§4.5): if restart
   cannot be done without replicating secrets, restart is forbidden, not merely
   discouraged. The kameo-API-verified template generalizes to every future
   secret-owning actor.
3. **Lock-discipline gates actor sequencing** (§6 write-guard finding): an
   actor re-route cannot land while a synchronous-`RwLock` critical section
   would have to `await` across it. This is why the Ledger-actor cutover
   *precedes* the merge→`KeyActor` re-route, and is the load-bearing ordering
   constraint Stage 4 inherits.

These three are recorded here so Stage 4's design opens from them rather than
rediscovering them. **Reopen at:** Stage 4 design kickoff.

---

## 9. Round-based design record

Authored per `26-sub-pr-design-discipline.mdc`. Target 4–6 adversarial rounds
with a late threat-model pass; rounds close on substrate-finding exhaustion,
not a fixed count (`21-reversion-clause-discipline.mdc` §"Design-round
closure"). This record is the design's audit trail; the implementation PR
cites the closed rounds rather than re-litigating them.

### Round 0 — pre-flight (A2 substrate, B6 constants, B9 bench plan)
- Re-read the frozen trait, composition, lifecycle, signer, view-material,
  merge, error, and `Cargo.toml` at `dev` `91f8c66db`; citations in §0.
- **B6:** verified `kameo` 0.20.0 pin / MSRV 1.88 (`Cargo.toml:117,226`) and
  the default mailbox capacity **64** at source (docs.rs), reconciling it with
  the workspace `mailbox(64)` convention; flagged the `#[actor(mailbox=…)]`
  convention-prose drift (§0.5).
- **B9:** bench plan anchored to the real `try_claim_output` crypto cost,
  not to non-existent signing (§5.3).
- **Prerequisite findings:** trait already actor-ready (§0.3, disposition (b));
  no production dispatch (§0.4); three non-actor key holders surfaced (§0.2).
- Output: the migration is data-flow, not one-field; §6 decomposition.

### Round 1 — protocol shape
- Derived the message/handle split from the free-function-vs-message boundary
  and cross-leaf immutable pattern (§2.1). Established that only the two async
  secret-touching methods become messages; the two sync methods are handle-
  resolved (§2.3/§2.4). Closed: "one pair per method" reconciled honestly.

### Round 2 — borrowed-return and sync-method reconciliation
- Resolved `account_public_address`'s `&` return with a handle-owned cached
  public projection, **no trait change** (§2.3). Surfaced the
  `derive_subaddress` sync-vs-async-Recipient tension; scoped it out (stub) to
  forward-action §8.2. Closed: trait surface stays frozen.

### Round 3 — lifecycle / supervision (the structural round)
- `Args = AllKeysBlob` move-in; `assemble` ordering (derive projections before
  move), §4.1–4.2. **Fail-stop disposition** derived from the verified kameo
  restart API: `supervise` needs `Clone` (rejected), `supervise_with` retains a
  secret closure (rejected) → restart forbidden by construction (§4.5). This is
  the cost-benefit-defer-to-later inversion done right: the structural answer
  now. Closed with a reversion clause.

### Round 4 — data-flow blast radius and decomposition
- Pinned the merge-path `view_sk` and `LocalSigner` blob dispositions (§6);
  chose (6-i) construction-time view projection as the Stage-2 minimal,
  (6-ii) actor re-route as forward-action §8.1. Confirmed `Engine::keys()` is
  dead (no production caller). Closed: §6 sequence.

### Round 5 — threat-model addenda (A3) and forward-actions
- §7 attacker table (T1 exfiltration, T2 panic-leak, T3 restart-leak closed by
  construction; T4 DoS bounded; T5/T6 inherited Round-4 items unchanged; T7
  no new side-channel). §8 forward-actions, each with reopening criteria.
- **Closure check:** no open substrate finding contradicts the security-first
  hierarchy; the "no secret crosses the boundary" property holds by
  construction across all termination paths. Design closes pending review.

### Round 6 — external adversarial critique pass (2026-05-31)
A code-grounded external critique (read at `91f8c66db` + HEAD) affirmed the
design as security-first and raised three design-pattern tensions plus one
contract gap. Dispositions, each verified at source before folding in (no
recommendation accepted on assertion alone, per `17-dependency-discipline.mdc`
/ A2):

- **Accepted, with a substrate finding the critique did not have:** the merge
  6-i-vs-6-ii disposition is now grounded on the **`std::sync::RwLock`-across-
  `.await`** obstacle. `apply_scan_result` is a sync `pub fn` (`merge.rs:191`)
  holding the ledger write guard (`merge.rs:201`) across the post-pass, and
  `LocalLedger` is deliberately `std::sync::RwLock` because nothing awaits
  under it (`local_ledger.rs:30-54,74`). This upgrades 6-i from "smaller" to
  "architecturally-correct under the current substrate," and relocates 6-ii's
  home to the Ledger-actor lock cutover (§6, §8.1). This is the round's
  load-bearing new finding.
- **Accepted (design-clarity):** the merge view-secret projection is a
  **distinct narrow non-`Clone` `Zeroizing` type**, not a second `ViewMaterial`
  (§6); `KeyPublicProjection` is shown as an explicit public-only **type**, not
  a bare field (§3.1); a `Signer`/`KeyEngine` **orthogonality** section pins
  adapter-over-engine layering and the step-4 `LocalSigner` blob severance
  (§3.4).
- **Accepted (contract):** §2.6 pins the `KeyActorUnavailable`
  **terminal / non-retryable / distinguishable** contract, with the
  panic→terminal test strengthened (§5.2 test 4) and a merge-path decision-
  evidence bench added (§5.3). T8 (mid-crypto-panic partial-state) added to §7,
  closing on the same fail-stop-+-zeroize-on-unwind mechanism as T2 plus a
  handler-local-temporary wipe obligation.
- **Bounded against over-commitment (reversion-clause discipline):** the
  critique's suggested `KeyActorUnavailable` doc-comment implied an automatic
  wallet-close. The design pins only the *error contract* and explicitly defers
  the **auto-close-vs-surface propagation policy** to the wiring PR that owns
  the RPC/lifecycle path (§2.6) — naming that policy here would pre-provision a
  surface this design does not own (`16-architectural-inheritance.mdc`).
- **Already-satisfied (no change):** "`KeyPublicProjection` as a type" was
  already a type; the §8.4 `RederivationInputs` link already exists; the
  `Cargo.toml` convention-drift fix was already scoped to the FOLLOWUP-closing
  commit (§0.5). Confirmed rather than re-added.
- **§6 disposition locked (follow-up):** a reviewer asked whether the impl PR
  should commit to (6-i) or leave the merge disposition open. Locked to (6-i)
  (§6) — the Round-6 write-guard finding means (6-ii) is *foreclosed* in
  Stage 2 (not deferred-by-preference), so there is no merge-time fork to leave
  open; the reversion clause (§8.1 gates) governs reopening. Same follow-up
  surfaced a **commit-atomicity correction**: `KeyActor::spawn(keys)` consumes
  the owned blob (kameo `Args` by-value), so a `keys`-and-`key`-both-present
  intermediate is uncompilable, not merely forbidden — the reorder/spawn/swap/
  merge-rewire is an indivisible single commit (§6 step 3), with only the
  standalone projection types (§6 step 2) splittable ahead of it.
- **Closure check:** no disposition reopened a closed round; the security-first
  "no secret crosses the boundary by construction" property is unchanged and
  strengthened (T8, the narrow merge type). Round closes; the open items below
  remain implementation-time, not design-blocking.

### Round 7 — second external critique: contention, trust-boundary, composition (2026-05-31)
A second code-grounded critique challenged whether the design *establishes
principles* or merely "moves a field," and raised five potential gaps plus a
composition meta-question. Each was verified at source before disposition; two
premises were flipped by the substrate.

- **Contention model — accepted, premise corrected (§3.5).** The critique
  modeled a 64-mailbox under "500 `try_claim_output` asks/block from the
  refresh task." Grep verification: `try_claim_output` has **zero production
  callers** (only the trait def, `merge.rs` comments, and `#[tokio::test]`), so
  in Stage 2 the actor is **cold on the hot path** — scan-merge uses the (6-i)
  *sync* projection, not asks. Further, `ask` is request/reply, so a sequential
  ask-loop holds ≤1 outstanding request and cannot saturate the mailbox by
  itself; saturation needs concurrent producers (T4). The real (6-ii)/Stage-4
  cost is **throughput** (serialized per-output crypto), not saturation — added
  as the model the §8.1 re-route inherits. This *reinforces* the Round-6
  foreclosure rather than opening a Stage-2 risk.
- **Handle as trust boundary — accepted (§3.2, T9).** Made explicit that
  `KeyEngineHandle` is a **capability** (holding it = authority to query the
  oracle), that its `pub(crate)` bound is a **compile-time** "never exported to
  RPC/untrusted callers" guarantee, and that the RPC tier is the real auth
  boundary. Added T9; routed the forgery/timing sub-cases to the existing T5/T7.
- **Concurrent-read-safety — accepted (§2.3).** Made explicit that
  handle-resolved reads (`Arc<KeyPublicProjection>`, immutable) and actor `ask`s
  share no mutable state, so concurrency is safe *by the type system*, not by
  lock — the property the design had assumed is now verified.
- **Eviction-under-serialization — accepted as an A6 refinement (T6).** Grep
  verified **no eviction exists today** (only `Vec::with_capacity`), so the
  critique's "eviction blocks asks" is not a current risk; but post-migration
  eviction will run inside `&mut self` handlers, so A6 inherits a **new
  constraint**: eviction must be incremental/amortized, never an unbounded
  sweep under the handler (else it jitters the §3.5 throughput model).
- **Projection-derivation failure — accepted, taxonomy rejected with reason
  (§4.1).** The transient-vs-permanent distinction is not load-bearing: a
  derivation failure is deterministic over an immutable blob (retry recovers
  nothing), and Rust alloc failure *aborts* rather than returning a retryable
  `Err`. Disposition: **permanent, fail-closed-loud, no retry** — the
  pre-genesis posture (`16-architectural-inheritance.mdc`). Recorded so the impl
  does not invent a retry shim for a non-recoverable condition.
- **Composition meta-question — accepted as flag-not-solve (§8.5).** Added a
  Stage-4 composition preview that *points to existing partial decisions*
  (Path-B message-only interaction; acyclic-DAG + issue-#306 caveat at
  `V3_WALLET_DECISION_LOG.md:3428-3445`; `KeyActor`-is-a-leaf-that-pulls-nothing-
  downward by construction; per-actor fail-stop spectrum) **without inventing
  the Stage-4 mesh** (which would be the scope creep this design must avoid).
  Named the three reusable principles Stage 2 establishes (trait-boundary =
  actor-boundary; fail-stop-by-construction for secret owners; lock-discipline
  gates actor sequencing) so Stage 4 opens from them.
- **Closure check:** every accepted item strengthened an existing property or
  named a forward constraint; none reopened a closed round or weakened the
  security-first invariant. The two substrate-flipped premises (cold path; no
  eviction today) were corrections, not new risks. Round closes.

### Open items carried to implementation (not design-blocking)
- Exact `KeyEngineError::KeyActorUnavailable` variant wording / `From` glue
  (§2.5, §2.6) — contract pinned; wording is an implementation detail.
- Exact name + field set of the merge view-secret projection (§6) and the
  `KeyPublicProjection` field set (§3.1) — pinned as *public-only* / *view-
  secret-only narrow types*; precise shapes fall out of what `local_keys.rs`
  reads, at implementation.
- The orchestrator `KeyActorUnavailable` propagation/close policy and its test
  (§2.6, §5.2) — owned by the wiring PR, partly Stage-4.
- Whether the §6 sequence lands as one branch or splits — sized at
  implementation time against `06-branching.mdc`. Note the §6 step-3 atomicity
  floor: the spawn-consumes-blob constraint means the reorder/spawn/swap/merge-
  rewire cannot split below one commit, regardless of branch decomposition.
- `Cargo.toml` mailbox-convention note correction (§0.5) — rides the FOLLOWUP-
  closing commit.

---

## 10. Definition of done (design targets these — `FOLLOWUPS.md:1028-1040`)

- [ ] `KeyActor` runs as a `kameo` actor with its own task (§1, §4).
- [ ] `Engine<S>` holds `KeyEngineHandle`, not `keys: AllKeysBlob`; no inline
      `K` generic (§3.2).
- [ ] All cross-subsystem key access routes through the message protocol or a
      sanctioned construction-time projection (§2.1, §6).
- [ ] Full `AllKeysBlob` contained in the actor task; no `&AllKeysBlob` escapes
      (§0.2 holders disposed in §6).
- [ ] Actor-protocol tests (real actor + recorded messages; receivers) (§5).
- [ ] Message-overhead bench within 5% of the `try_claim_output` crypto
      baseline, bench-vs-bench, no absolute gate (§5.3).
